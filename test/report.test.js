import { test } from "node:test";
import assert from "node:assert/strict";
import { buildReport, buildErrorReport } from "../src/report.js";

const noDiff = { added: [], changed: [], removed: [] };
const high = { id: "clipboard-hijack", severity: "high", title: "Clipper", evidence: "navigator.clipboard.writeText(x)" };
const medium = { id: "clipboard-access", severity: "medium", title: "Clipboard", evidence: "navigator.clipboard.writeText(y)" };
const SCRIPT = "https://cdn.optimizely.com/js/123.js";

test("a high-severity finding yields exit code 2 and names site, script and rule", () => {
  const r = buildReport([
    { site: "https://shop.example", firstRun: false, diff: { ...noDiff, changed: [SCRIPT] }, findings: { [SCRIPT]: [high] } },
  ]);
  assert.equal(r.exitCode, 2);
  assert.equal(r.hasFindings, true);
  assert.match(r.markdown, /https:\/\/shop\.example/);
  assert.match(r.markdown, /cdn\.optimizely\.com\/js\/123\.js/);
  assert.match(r.markdown, /clipboard-hijack/);
});

test("only medium findings are reported but keep exit code 0", () => {
  const r = buildReport([
    { site: "https://shop.example", firstRun: false, diff: { ...noDiff, changed: [SCRIPT] }, findings: { [SCRIPT]: [medium] } },
  ]);
  assert.equal(r.exitCode, 0);
  assert.equal(r.hasFindings, true);
  assert.match(r.markdown, /clipboard-access/);
});

test("a changed script without findings is listed as info with exit code 0", () => {
  const r = buildReport([
    { site: "https://shop.example", firstRun: false, diff: { ...noDiff, changed: [SCRIPT] }, findings: {} },
  ]);
  assert.equal(r.exitCode, 0);
  assert.equal(r.hasFindings, false);
  assert.match(r.markdown, /changed/i);
  assert.match(r.markdown, /123\.js/);
});

test("first run says the baseline was created and never alarms", () => {
  const r = buildReport([
    { site: "https://shop.example", firstRun: true, diff: { ...noDiff, added: [SCRIPT] }, findings: {} },
  ]);
  assert.equal(r.exitCode, 0);
  assert.match(r.markdown, /baseline created/i);
});

test("a site that failed to load is listed with its error and does not stop the report", () => {
  const r = buildReport([
    { site: "https://down.example", firstRun: false, error: "net::ERR_NAME_NOT_RESOLVED", diff: noDiff, findings: {} },
    { site: "https://shop.example", firstRun: false, diff: { ...noDiff, changed: [SCRIPT] }, findings: { [SCRIPT]: [high] } },
  ]);
  assert.equal(r.hasErrors, true);
  assert.equal(r.exitCode, 2);
  assert.match(r.markdown, /down\.example/);
  assert.match(r.markdown, /ERR_NAME_NOT_RESOLVED/);
});

test("attacker-controlled evidence cannot break out of its code block", () => {
  const evil = { ...high, evidence: "````\n# Owned @octocat [click](https://evil.example)" };
  const r = buildReport([
    { site: "https://shop.example", firstRun: false, diff: { ...noDiff, changed: [SCRIPT] }, findings: { [SCRIPT]: [evil] } },
  ]);
  const lines = r.markdown.split("\n");
  assert.ok(!lines.includes("# Owned @octocat [click](https://evil.example)"), "evidence escaped its fence");
  assert.ok(!/(^|[^`])@octocat/.test(r.markdown.replace(/```[\s\S]*?```/g, "")), "mention outside code");
});

// ---- Final review C1 / I1 ----
test("the headline counts sites that could not be scanned instead of claiming all is fine", () => {
  const r = buildReport([
    { site: "https://down.example", firstRun: false, error: "Timeout", diff: noDiff, findings: {} },
  ]);
  assert.match(r.markdown.split("\n").slice(0, 4).join("\n"), /1 site\(s\) could not be scanned/);
  assert.doesNotMatch(r.markdown, /No suspicious findings/);
});

test("a page that did not finish loading is flagged as partially scanned", () => {
  const r = buildReport([
    { site: "https://slow.example", firstRun: false, warnings: ["load-timeout"], diff: noDiff, findings: {} },
  ]);
  assert.match(r.markdown, /did not finish loading/i);
});

test("known traits are listed as info and do not raise the exit code", () => {
  const r = buildReport([
    { site: "https://shop.example", firstRun: false, diff: { ...noDiff, changed: [SCRIPT] }, findings: {}, known: { [SCRIPT]: [high] } },
  ]);
  assert.equal(r.exitCode, 0);
  assert.match(r.markdown, /known/i);
  assert.match(r.markdown, /clipboard-hijack/);
});

test("first-run findings are shown as recorded traits", () => {
  const r = buildReport([
    { site: "https://shop.example", firstRun: true, diff: { ...noDiff, added: [SCRIPT] }, findings: {}, known: { [SCRIPT]: [high] } },
  ]);
  assert.equal(r.exitCode, 0);
  assert.match(r.markdown, /baseline created/i);
  assert.match(r.markdown, /clipboard-hijack/);
});

test("sites dropped from the baseline are named in the report without changing the exit code", () => {
  const r = buildReport([{ site: "https://shop.example", firstRun: false, diff: noDiff, findings: {} }], { pruned: ["https://old.example/"] });
  assert.equal(r.exitCode, 0);
  assert.match(r.markdown, /no longer in sites\.yml/i);
  assert.match(r.markdown, /`https:\/\/old\.example\/`/);
});

test("the error report says the scan did not run and keeps the message inside its code block", () => {
  const md = buildErrorReport("sites.yml: bad\n```\n# Injected heading");
  assert.match(md, /did not run/i);
  const lines = md.split("\n");
  const fences = lines.flatMap((l, i) => (l.startsWith("```") ? [i] : []));
  assert.equal(fences.length, 2, "exactly one fenced block");
  const injected = lines.indexOf("# Injected heading");
  assert.ok(fences[0] < injected && injected < fences[1], "message escaped its fence");
});

test("a known IoC on the first run still alarms", () => {
  const ioc = { id: "known-ioc", severity: "high", title: "IoC", evidence: "1688360.cc" };
  const r = buildReport([
    { site: "https://shop.example", firstRun: true, diff: { ...noDiff, added: [SCRIPT] }, findings: { [SCRIPT]: [ioc] } },
  ]);
  assert.equal(r.exitCode, 2);
  assert.match(r.markdown, /known-ioc/);
});
