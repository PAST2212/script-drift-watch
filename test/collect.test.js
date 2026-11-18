// Final review C1 / I2 / M1: collector robustness against hostile or flaky pages.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { collectScripts, launchBrowser, IPHONE_UA } from "../src/collect.js";

let server, base, browser;
const seen = { ua: [], probe: [], chUa: [], brands: [], touch: [] };

const pages = {
  "/hang.html": `<script src="/vendor.js"></script><script src="/hangs.js"></script>`,
  "/probe.html": `<script>var s=document.createElement('script');s.src='/probe.js?wd='+navigator.webdriver
    +'&brands='+encodeURIComponent(((navigator.userAgentData||{}).brands||[]).map(function(b){return b.brand;}).join('|'))
    +'&touch='+navigator.maxTouchPoints;document.head.appendChild(s);</script>`,
};

before(async () => {
  server = http.createServer((req, res) => {
    const u = new URL(req.url, "http://x");
    seen.ua.push(req.headers["user-agent"]);
    seen.chUa.push(req.headers["sec-ch-ua"]);
    if (u.pathname === "/probe.js") {
      seen.brands.push(u.searchParams.get("brands"));
      seen.touch.push(u.searchParams.get("touch"));
    }
    if (u.pathname === "/never") return; // never answers: keeps `load` from firing
    if (u.pathname === "/maintenance.html") {
      res.writeHead(503, { "content-type": "text/html" });
      return res.end(`<script src="/challenge.js"></script>`);
    }
    if (pages[u.pathname]) {
      res.writeHead(200, { "content-type": "text/html" });
      return res.end(pages[u.pathname]);
    }
    if (u.pathname === "/probe.js") seen.probe.push(u.searchParams.get("wd"));
    res.writeHead(200, { "content-type": "text/javascript" });
    if (u.pathname === "/hangs.js") {
      return res.end(`var f=document.createElement('iframe');f.src='/never';(document.body||document.documentElement).appendChild(f);`);
    }
    res.end(`/* ${u.pathname} */`);
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${server.address().port}`;
  browser = await launchBrowser();
});

after(async () => {
  await browser?.close();
  server?.closeAllConnections();
  server?.close();
});

const opts = { timeoutMs: 2000, settleMs: 100 };

test("a page whose load event never fires still returns the scripts captured so far", async () => {
  const { scripts, loadTimedOut } = await collectScripts(browser, `${base}/hang.html`, opts);
  const urls = scripts.map((s) => s.url);
  assert.ok(urls.includes(`${base}/vendor.js`), urls.join());
  assert.ok(urls.includes(`${base}/hangs.js`), urls.join());
  assert.equal(loadTimedOut, true);
});

test("a non-2xx main document is an error, so the old baseline is kept", async () => {
  await assert.rejects(collectScripts(browser, `${base}/maintenance.html`, opts), /HTTP 503/);
});

test("the scanner does not announce itself as headless or automated", async () => {
  seen.ua.length = 0;
  seen.probe.length = 0;
  await collectScripts(browser, `${base}/probe.html`, opts);
  assert.ok(seen.ua.length > 0);
  for (const ua of seen.ua) assert.doesNotMatch(ua, /Headless/i);
  assert.deepEqual(seen.probe, ["false"]);
});

// Verified 2026-11-17: the headless shell sends `Sec-CH-UA: "HeadlessChrome"` despite the UA override.
test("client hints (Sec-CH-UA header, navigator.userAgentData) do not reveal headless either", async () => {
  seen.chUa.length = 0;
  seen.brands.length = 0;
  await collectScripts(browser, `${base}/probe.html`, opts);
  const hints = seen.chUa.filter(Boolean);
  assert.ok(hints.length > 0, "no Sec-CH-UA header seen, so this test would prove nothing");
  for (const h of hints) assert.doesNotMatch(h, /Headless/i);
  assert.equal(seen.brands.length, 1);
  assert.doesNotMatch(seen.brands[0], /Headless/i);
});

test("the iPhone variant presents itself as a touch iPhone", async () => {
  seen.ua.length = 0;
  seen.touch.length = 0;
  await collectScripts(browser, `${base}/probe.html`, { ...opts, userAgent: IPHONE_UA });
  for (const ua of seen.ua) assert.match(ua, /iPhone/);
  assert.ok(Number(seen.touch[0]) > 0, `maxTouchPoints=${seen.touch[0]}`);
});
