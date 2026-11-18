import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { main, nextBaseline, parseSites, classifyFindings, mergeTraits, stableScripts, serializeBaseline } from "../src/cli.js";

const entry = (scripts, traits = {}) => ({ scripts, traits });

test("nextBaseline keeps the old entry of a site that failed to scan", () => {
  const old = { "https://a.example/": entry({ k1: { hash: "h", url: "k1" } }) };
  const results = [{ site: "https://a.example/", error: "timeout", entry: null }];
  assert.deepEqual(nextBaseline(old, results), old);
});

test("nextBaseline replaces the entry of a successfully scanned site", () => {
  const old = { "https://a.example/": entry({ k1: { hash: "h", url: "k1" } }) };
  const fresh = entry({ k2: { hash: "x", url: "k2" } }, { "a.example": ["wallet-pattern"] });
  const results = [{ site: "https://a.example/", entry: fresh }];
  assert.deepEqual(nextBaseline(old, results), { "https://a.example/": fresh });
});

// ---- Open review points: baseline lifecycle ----
test("on update, sites no longer in sites.yml (incl. a dropped iPhone variant) leave the baseline", () => {
  const a = entry({ k: { hash: "a", url: "k" } });
  const old = { "https://a.example/": a, "https://a.example/ [iPhone]": a, "https://gone.example/": a };
  const fresh = entry({ k: { hash: "a2", url: "k" } });
  const results = [{ site: "https://a.example/", entry: fresh }];
  assert.deepEqual(nextBaseline(old, results, { update: true }), { "https://a.example/": fresh });
});

test("without update, existing entries stay untouched and only sites seen for the first time are added", () => {
  const oldA = entry({ k: { hash: "a", url: "k" } });
  const oldGone = entry({ g: { hash: "g", url: "g" } });
  const newB = entry({ b: { hash: "b", url: "b" } });
  const results = [
    { site: "https://a.example/", firstRun: false, entry: entry({ k: { hash: "CHANGED", url: "k" } }) },
    { site: "https://b.example/", firstRun: true, entry: newB },
  ];
  assert.deepEqual(nextBaseline({ "https://a.example/": oldA, "https://gone.example/": oldGone }, results, { update: false }), {
    "https://a.example/": oldA,
    "https://b.example/": newB,
    "https://gone.example/": oldGone,
  });
});

test("parseSites reads urls, ignore lists and the ios flag", () => {
  const sites = parseSites(`sites:\n  - url: https://a.example/\n    ignore: ["googletagmanager"]\n  - url: https://b.example/\n    ios: true\n`);
  assert.deepEqual(sites, [
    { url: "https://a.example/", ignore: ["googletagmanager"], ios: false },
    { url: "https://b.example/", ignore: [], ios: true },
  ]);
});

test("parseSites rejects a config without sites", () => {
  assert.throws(() => parseSites("foo: bar\n"), /sites/);
});

// ---- Open review point: validate sites.yml instead of silently misreading it ----
const parseError = (text) => {
  try {
    parseSites(text);
  } catch (e) {
    return e.message;
  }
  return assert.fail(`expected the config to be rejected:\n${text}`);
};
const oneSite = (extra) => `sites:\n  - url: https://a.example/\n${extra}\n`;

test("an empty ignore pattern is rejected instead of silently ignoring every script", () => {
  for (const ignore of [`    ignore: [""]`, `    ignore: ["  "]`, `    ignore:\n      -`]) {
    const msg = parseError(oneSite(ignore));
    assert.match(msg, /sites\[0\]/, ignore);
    assert.match(msg, /ignore/, ignore);
  }
});

test("a single ignore pattern may be written without a list", () => {
  assert.deepEqual(parseSites(oneSite("    ignore: gtm.js"))[0].ignore, ["gtm.js"]);
});

test("ios must be a real boolean, not a string like \"true\" or yes", () => {
  for (const value of [`"true"`, "yes", "1"]) {
    const msg = parseError(oneSite(`    ios: ${value}`));
    assert.match(msg, /sites\[0\]/, value);
    assert.match(msg, /true or false/, value);
  }
});

test("an unknown key is rejected and the intended key is suggested", () => {
  assert.match(parseError(oneSite("    ignores: [gtm]")), /'ignores'.*did you mean 'ignore'/);
  assert.match(parseError(oneSite("    iOS: true")), /'iOS'.*did you mean 'ios'/);
});

test("a url without http(s):// is rejected with a hint", () => {
  const msg = parseError("sites:\n  - url: www.example.com\n");
  assert.match(msg, /www\.example\.com/);
  assert.match(msg, /https:\/\//);
});

test("a url with spaces around it is rejected instead of being used as written", () => {
  const msg = parseError('sites:\n  - url: " https://a.example/ "\n');
  assert.match(msg, /sites\[0\]/);
  assert.match(msg, /spaces/);
});

test("an entry that is neither a URL nor a mapping with url is rejected", () => {
  assert.match(parseError("sites:\n  - 42\n"), /sites\[0\]/);
  assert.match(parseError("sites:\n  - [https://a.example/]\n"), /sites\[0\]/);
});

test("the same page listed twice is rejected, also with and without a trailing slash", () => {
  const msg = parseError("sites:\n  - https://a.example/\n  - url: https://a.example\n");
  assert.match(msg, /sites\[1\]/);
  assert.match(msg, /sites\[0\]/);
});

test("each problem names the line of its entry in sites.yml", () => {
  const msg = parseError("# my pages\nsites:\n  - url: https://a.example/\n\n  - url: www.b.example\n");
  assert.match(msg, /line 5\b[^\n]*sites\[1\]/);
});

test("all problems in the config are reported at once", () => {
  const msg = parseError("sites:\n  - url: www.example.com\n  - url: https://b.example/\n    ios: yes\n");
  assert.match(msg, /sites\[0\]/);
  assert.match(msg, /sites\[1\]/);
});

/** Runs the CLI against files in a temp dir; never reaches the browser for broken input. */
async function runMain(t, files, extra = []) {
  const dir = await mkdtemp(join(tmpdir(), "sdw-cli-"));
  for (const [name, content] of Object.entries(files)) await writeFile(join(dir, name), content);
  t.mock.method(console, "error", () => {});
  t.mock.method(console, "log", () => {});
  const code = await main(["--config", join(dir, "sites.yml"), "--baseline", join(dir, "baseline.json"),
    "--report", join(dir, "report.md"), "--settle-ms", "0", "--timeout-ms", "2000", ...extra]);
  const report = await readFile(join(dir, "report.md"), "utf8").catch(() => "");
  return { code, report };
}

test("an invalid sites.yml exits 1 and explains the problem in the report (job summary)", async (t) => {
  const { code, report } = await runMain(t, { "sites.yml": oneSite("    ios: yes") });
  assert.equal(code, 1);
  assert.match(report, /sites\[0\]/);
  assert.match(report, /true or false/);
});

test("a YAML syntax error names the config file in the report", async (t) => {
  const { code, report } = await runMain(t, { "sites.yml": "sites:\n  - url: https://a.example/\n   ios: true\n" });
  assert.equal(code, 1);
  assert.match(report, /sites\.yml/);
});

// ---- Review findings: CLI arguments (the Action passes its `args` input straight through) ----
const SITES = { "sites.yml": "sites:\n  - https://a.example/\n" };

test("a malformed --settle-ms or --timeout-ms is rejected instead of silently changing the scan", async (t) => {
  for (const extra of [["--settle-ms", "5s"], ["--timeout-ms", "30s"], ["--timeout-ms", "0"], ["--settle-ms=-1"]]) {
    const { code, report } = await runMain(t, SITES, extra);
    assert.equal(code, 1, extra.join(" "));
    assert.match(report, /did not run/i, extra.join(" "));
    assert.match(report, extra[0].startsWith("--settle") ? /--settle-ms/ : /--timeout-ms/, extra.join(" "));
  }
});

test("an unknown option exits 1 and the report names it and lists the valid options", async (t) => {
  const { code, report } = await runMain(t, SITES, ["--settle", "5000"]);
  assert.equal(code, 1);
  assert.match(report, /'--settle'/);
  assert.match(report, /--settle-ms <n>/);
});

test("an unreadable baseline exits 1 and explains the problem in the report", async (t) => {
  const { code, report } = await runMain(t, { "sites.yml": "sites:\n  - https://a.example/\n", "baseline.json": "{ not json" });
  assert.equal(code, 1);
  assert.match(report, /baseline\.json/);
});

// ---- Final review I1: alarm when a host *gains* a trait, not when it has one ----
const F = (id, severity = "high") => ({ id, severity, title: id, evidence: id });
const PAY = "https://js.pay.example/v3/pay.js";

test("a trait the host already had is known (info), not an alarm", () => {
  const { fresh, known } = classifyFindings({ [PAY]: [F("card-field-access")] }, { "js.pay.example": ["card-field-access"] }, false);
  assert.deepEqual(fresh, {});
  assert.deepEqual(known[PAY].map((f) => f.id), ["card-field-access"]);
});

test("a trait the host never had is fresh (alarm)", () => {
  const { fresh } = classifyFindings({ [PAY]: [F("clipboard-hijack")] }, { "js.pay.example": ["card-field-access"] }, false);
  assert.deepEqual(fresh[PAY].map((f) => f.id), ["clipboard-hijack"]);
});

test("on the first run everything is recorded as known, except known IoCs", () => {
  const { fresh, known } = classifyFindings({ [PAY]: [F("card-field-access"), F("known-ioc")] }, {}, true);
  assert.deepEqual(fresh[PAY].map((f) => f.id), ["known-ioc"]);
  assert.deepEqual(known[PAY].map((f) => f.id), ["card-field-access"]);
});

test("known IoCs alarm even when already recorded for the host", () => {
  const { fresh } = classifyFindings({ [PAY]: [F("known-ioc")] }, { "js.pay.example": ["known-ioc"] }, false);
  assert.deepEqual(fresh[PAY].map((f) => f.id), ["known-ioc"]);
});

// Review finding: blob: scripts must not inherit the traits of the page's own scripts, or a skimmer
// laundered through a blob on a checkout page (whose own code references card fields) is only info.
const BLOB = "blob:https://shop.example/sha256-abcdef0123456789";

test("a blob: script does not inherit the traits of the page's own scripts", () => {
  const { fresh } = classifyFindings({ [BLOB]: [F("card-field-access")] }, { "shop.example": ["card-field-access"] }, false);
  assert.deepEqual(fresh[BLOB]?.map((f) => f.id), ["card-field-access"]);
});

test("trait memory for blob: scripts is kept per page host in a separate blob: bucket", () => {
  assert.deepEqual(classifyFindings({ [BLOB]: [F("card-field-access")] }, { "blob:shop.example": ["card-field-access"] }, false).fresh, {});
  assert.deepEqual(mergeTraits({}, { [BLOB]: [F("exfil-sink")] }), { "blob:shop.example": ["exfil-sink"] });
});

test("blob: scripts from an opaque origin share one stable bucket instead of one per content", () => {
  const traits = mergeTraits({}, { "blob:null/sha256-aaaaaaaaaaaaaaaa": [F("exfil-sink", "medium")] });
  assert.deepEqual(traits, { "blob:null": ["exfil-sink"] });
  assert.deepEqual(classifyFindings({ "blob:null/sha256-bbbbbbbbbbbbbbbb": [F("exfil-sink", "medium")] }, traits, false).fresh, {});
});

test("mergeTraits unions finding ids per host, sorted", () => {
  const traits = mergeTraits({ "js.pay.example": ["wallet-pattern"] }, { [PAY]: [F("card-field-access")], "https://cdn.x.example/a.js": [F("exfil-sink")] });
  assert.deepEqual(traits, { "cdn.x.example": ["exfil-sink"], "js.pay.example": ["card-field-access", "wallet-pattern"] });
});

// ---- Final review I3: the baseline must be byte-stable when nothing changed ----
test("stableScripts keeps the old url when only a cache-buster changed", () => {
  const old = { "https://x.example/a.js": { hash: "h", url: "https://x.example/a.js?_=1" } };
  const cur = { "https://x.example/a.js": { hash: "h", url: "https://x.example/a.js?_=2" } };
  assert.deepEqual(stableScripts(old, cur), old);
});

test("serializeBaseline is independent of insertion order", () => {
  const a = { "https://s/": entry({ b: { hash: "2", url: "b" }, a: { hash: "1", url: "a" } }, { y: ["2"], x: ["1"] }) };
  const b = { "https://s/": entry({ a: { hash: "1", url: "a" }, b: { hash: "2", url: "b" } }, { x: ["1"], y: ["2"] }) };
  assert.equal(serializeBaseline(a), serializeBaseline(b));
});
