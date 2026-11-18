import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import YAML from "yaml";
import { main, parseSites } from "../src/cli.js";
import { assessScriptLoads } from "../src/loads.js";

const policyKey = "allowed-script-origins";
const loader = "https://vendor.example/tag.js";
const config = (policy) => YAML.stringify({ sites: [{ url: "https://shop.example/", [policyKey]: policy }] });

async function localScanner(t) {
  const dir = await mkdtemp(join(tmpdir(), "sdw-loads-"));
  const configPath = join(dir, "sites.yml");
  const baseline = join(dir, "baseline.json");
  const report = join(dir, "report.md");
  t.mock.method(console, "log", () => {});
  return {
    baseline,
    report: () => readFile(report, "utf8"),
    configure: sites => writeFile(configPath, YAML.stringify({ sites })),
    run: () => main(["--config", configPath, "--baseline", baseline, "--report", report, "--update-baseline", "--settle-ms", "0"]),
  };
}

test("script origin policies accept exact loader keys and exact HTTP(S) origins, including deny-all", () => {
  const [site] = parseSites(config({ [loader + "?v=2"]: ["https://assets.example/"], [loader + "?tenant=b"]: [] }));
  assert.deepEqual(site.allowedScriptOrigins, { [loader]: ["https://assets.example"], [loader + "?tenant=b"]: [] });
});

test("invalid or ambiguous script origin policies report the site and bad value", () => {
  for (const [policy, bad] of [
    [{ "tag.js": [] }, "tag.js"], [{ [loader]: "https://a.example" }, loader],
    [{ [loader]: ["https://*.example"] }, "*.example"], [{ [loader]: ["https://a.example/path"] }, "/path"],
    [{ [loader]: ["https://user@a.example"] }, "user@"], [{ [loader]: ["https://a.example?"] }, "a.example?"],
    [{ [loader]: [], [loader + "?v=2"]: [] }, loader],
  ]) {
    assert.throws(() => parseSites(config(policy)), e => e.message.includes("sites[0]") && e.message.includes(bad));
  }
});

test("an explicitly forbidden request by a redirected loader alarms even with a 404, and stays visible until permitted", async t => {
  const server = createServer((req, res) => {
    if (req.url === "/") return res.writeHead(200, { "Content-Type": "text/html" }).end('<script src="/vendor-tag.js"></script>');
    if (req.url === "/vendor-tag.js") return res.writeHead(302, { Location: "/vendor.js" }).end();
    if (req.url === "/vendor.js") return res.writeHead(200, { "Content-Type": "text/javascript" }).end(
      "const el = document.createElement('script'); el.src='/missing.js'; document.head.append(el);"
    );
    res.writeHead(404).end();
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  const origin = "http://127.0.0.1:" + server.address().port;
  const parent = origin + "/vendor-tag.js";
  const scanner = await localScanner(t);
  const setPolicy = origins => scanner.configure([{ url: origin, [policyKey]: { [parent]: origins } }]);
  await setPolicy([]);
  assert.equal(await scanner.run(), 2);
  const firstReport = await scanner.report();
  assert.match(firstReport, /disallowed-script-origin/);
  assert.ok(firstReport.includes(parent) && firstReport.includes(origin + "/vendor.js") && firstReport.includes(origin + "/missing.js"));
  assert.equal(await scanner.run(), 0);
  assert.match(await scanner.report(), /Still observed.*disallowed-script-origin/);
  await setPolicy([origin]);
  assert.equal(await scanner.run(), 0);
  assert.doesNotMatch(await scanner.report(), /disallowed-script-origin/);
  await setPolicy([]);
  assert.equal(await scanner.run(), 2, "tightening the policy reopens the finding");
});

test("a new loader of an unchanged clipper alarms after upgrading a legacy baseline with known host traits", async t => {
  let dynamic = false;
  const server = createServer((req, res) => {
    if (req.url === "/") {
      const tags = dynamic ? "" : '<script src="' + child + '"></script>';
      const target = dynamic ? child : "";
      return res.writeHead(200, { "Content-Type": "text/html" }).end(
        '<html data-child="' + target + '"><script src="/loader.js"></script>' + tags + '</html>'
      );
    }
    if (req.url === "/loader.js") return res.writeHead(200, { "Content-Type": "text/javascript" }).end(
      "const target=document.documentElement.dataset.child; if (target) { const s=document.createElement('script'); s.src=target; document.head.append(s); }"
    );
    if (req.url === "/child.js") return res.writeHead(200, { "Content-Type": "text/javascript" }).end(
      '/* Inert rule markers: navigator.clipboard.writeText( "0x0000000000000000000000000000000000000000" */'
    );
    res.writeHead(404).end();
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  const port = server.address().port;
  const site = "http://shop.localhost:" + port + "/";
  const child = "http://partner.localhost:" + port + "/child.js";
  const scanner = await localScanner(t);
  await scanner.configure([site]);
  assert.equal(await scanner.run(), 0);
  const legacy = JSON.parse(await readFile(scanner.baseline, "utf8"));
  const entry = legacy.sites[site];
  assert.ok(entry.traits[new URL(child).host].includes("clipboard-hijack"));
  delete entry.loadOrigins;
  for (const script of Object.values(entry.scripts)) delete script.clipper;
  await writeFile(scanner.baseline, JSON.stringify(legacy));
  assert.equal(await scanner.run(), 0, "seed the graph on upgrade");
  dynamic = true;
  assert.equal(await scanner.run(), 2, "only the initiator changed");
  const markdown = await scanner.report();
  assert.match(markdown, /clipper-script-load/);
  assert.doesNotMatch(markdown, /^### (New|Changed):|known-ioc/m);
});

test("a permitted destination can still acquire a clipper and its evidence names the matching child", () => {
  const origin = "https://partner.example";
  const clean = origin + "/analytics.js";
  const changed = origin + "/experiment.js";
  const policy = { [loader]: [origin] };
  const loads = [{ parentUrl: loader, url: clean }, { parentUrl: loader, url: changed }];
  const bodies = new Map([[clean, {}], [changed, {}]]);
  const observed = assessScriptLoads({ loads, policy, bodies, previous: {} });
  assert.deepEqual(observed.findings, []);
  bodies.set(changed, { clipper: true });
  const alarm = assessScriptLoads({ loads, policy, bodies, previous: observed.origins });
  assert.equal(alarm.findings.length, 1);
  assert.equal(alarm.findings[0].child, changed);
  assert.equal(alarm.findings[0].severity, "high");
  assert.equal(alarm.findings[0].ongoing, false);
});

test("an unrelated or unattributed request cannot supply clipper evidence for a loader", () => {
  const other = "https://attacker.example/other.js";
  const clean = "https://partner.example/clean.js";
  const loads = [{ parentUrl: null, url: other }, { parentUrl: loader, url: clean }];
  const result = assessScriptLoads({ loads, bodies: new Map([[other, { clipper: true }], [clean, {}]]), previous: {} });
  assert.deepEqual(result.findings.map(f => [f.id, f.child]), [["new-script-origin", clean]]);
  assert.deepEqual(result.unattributed, [other]);
});

test("policy approval clears an old denial even on scans where the loader is absent", () => {
  const url = "https://assets.example/vendor.js";
  const bodies = new Map();
  const loads = [{ parentUrl: loader, url }];
  const deny = { [loader]: [] };
  const alarm = assessScriptLoads({ loads, bodies, policy: deny });
  assert.equal(alarm.findings[0].ongoing, false);
  for (const policy of [{}, { [loader]: [new URL(url).origin] }]) {
    const absent = assessScriptLoads({ loads: [], bodies, policy, previous: alarm.origins });
    const again = assessScriptLoads({ loads, bodies, policy: deny, previous: absent.origins });
    assert.equal(again.findings[0].ongoing, false);
  }
});

test("policies on the original and final loader apply across a redirect", () => {
  const final = "https://cdn.example/v2.js";
  const url = "https://assets.example/child.js";
  const bodies = new Map();
  const loads = [{ parentUrl: final, requestedParentUrl: loader, url }];
  for (const [permitted, denied] of [[loader, final], [final, loader]]) {
    const policy = { [permitted]: [new URL(url).origin], [denied]: [] };
    const result = assessScriptLoads({ loads, bodies, policy });
    assert.equal(result.findings[0]?.id, "disallowed-script-origin");
    assert.equal(result.findings[0].parent, loader);
  }
});

test("two editions under one URL still trigger a content alarm without blaming either loader", async t => {
  let flagged = false;
  let partial = false;
  let deliveries = 0;
  const server = createServer((req, res) => {
    if (req.url === "/") return res.writeHead(200, { "Content-Type": "text/html" }).end('<script src="/one.js"></script>');
    res.setHeader("Content-Type", "text/javascript");
    res.setHeader("Cache-Control", "no-store");
    const loadChild = 'var tag=document.createElement("script"); tag.src=' + JSON.stringify(child) + ';';
    if (req.url === "/one.js") return res.end(loadChild +
      'tag.onload=()=>{const next=document.createElement("script");next.src="/two.js";document.head.append(next)};document.head.append(tag)');
    if (req.url === "/two.js") return res.end(loadChild + 'document.head.append(tag)');
    if (req.url === "/shared.js") {
      deliveries++;
      if (partial && deliveries % 2 === 0) return res.writeHead(404).end();
      return res.end(flagged && deliveries % 2 === 1
        ? '/* inert: navigator.clipboard.writeText( "0x0000000000000000000000000000000000000000" */'
        : '/* edition ' + deliveries % 2 + ' */');
    }
    res.writeHead(404).end();
  });
  await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
  t.after(() => server.close());
  const port = server.address().port;
  const child = "http://partner.localhost:" + port + "/shared.js";
  const scanner = await localScanner(t);
  await scanner.configure(["http://shop.localhost:" + port + "/"]);
  assert.equal(await scanner.run(), 0);
  assert.equal(deliveries, 2);
  flagged = true;
  assert.equal(await scanner.run(), 2);
  assert.equal(deliveries, 4);
  const markdown = await scanner.report();
  assert.match(markdown, /clipboard-hijack/);
  assert.match(markdown, /Multiple response bodies/);
  assert.doesNotMatch(markdown, /clipper-script-load/);
  partial = true;
  assert.equal(await scanner.run(), 0, "a successful body and a 404 at the same URL cannot identify which parent got the clipper");
  const partialReport = await scanner.report();
  assert.match(partialReport, /Multiple response bodies/);
  assert.doesNotMatch(partialReport, /clipper-script-load/);
});
