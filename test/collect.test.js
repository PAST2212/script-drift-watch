// Final review C1 / I2 / M1: collector robustness against hostile or flaky pages.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { collectScripts, launchBrowser, IPHONE_UA } from "../src/collect.js";

let server, base, browser;
const seen = { ua: [], probe: [], chUa: [], brands: [], touch: [] };

const pages = {
  "/loads.html": '<script src="/loader.js"></script><iframe src="/frame.html"></iframe>',
  "/frame.html": '<script src="/frame-loader.js"></script>',
  "/debug.html": '<script src="/debug.js"></script>',
  "/fragment.html": '<script src="/loader.js#release"></script>',
  "/label.html": '<script src="/label.js"></script>',
  "/redirect-parent.html": '<script src="/tag.js"></script>',
  "/variants.html": `<iframe src="/first.html" onload="const f=document.createElement('iframe');f.src='/second.html';document.body.appendChild(f)"></iframe>`,
  "/first.html": '<script src="/variant.js"></script><script src="/select.js"></script>',
  "/second.html": '<script src="/variant.js"></script><script src="/select.js"></script>',
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
    if (u.pathname === "/embedded.html") {
      res.writeHead(200, { "content-type": "text/html" });
      return res.end(`<iframe src="${base.replace("127.0.0.1", "localhost")}/frame.html"></iframe>`);
    }
    if (u.pathname === "/redirect.js") {
      res.writeHead(302, { location: "/final.js" });
      return res.end();
    }
    if (u.pathname === "/tag.js") return res.writeHead(302, { location: "/loader.js" }).end();
    if (u.pathname === "/select.js" || u.pathname === "/variant.js") {
      const version = new URL(req.headers.referer).pathname === "/first.html" ? "first" : "second";
      if (u.pathname === "/select.js") {
        return res.writeHead(302, { location: "/" + version + ".js", "cache-control": "no-store" }).end();
      }
      res.writeHead(200, { "content-type": "text/javascript", "cache-control": "no-store" });
      return res.end("/* " + version + " */");
    }
    if (u.pathname === "/first.js" || u.pathname === "/second.js") {
      res.writeHead(200, { "content-type": "text/javascript" });
      return res.end(`document.head.appendChild(Object.assign(document.createElement("script"), { src: "${u.pathname}/child.js" }));`);
    }
    if (u.pathname === "/missing.js") return res.writeHead(404).end();
    if (u.pathname === "/loader.js" || u.pathname === "/frame-loader.js") {
      const paths = u.pathname === "/loader.js" ? ["/redirect.js", "/missing.js"] : ["/frame-child.js"];
      res.writeHead(200, { "content-type": "text/javascript" });
      return res.end(`for (const path of ${JSON.stringify(paths)}) {
        const script = document.createElement("script");
        script.src = path;
        document.head.appendChild(script);
      }`);
    }
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
    if (u.pathname === "/debug.js") {
      return res.end('debugger; document.head.appendChild(Object.assign(document.createElement("script"), { src: "/after-debug.js" }));');
    }
    if (u.pathname === "/label.js") {
      return res.end('document.head.appendChild(Object.assign(document.createElement("script"), { src: "/child.js" }));\n//# sourceURL=debug-label.js');
    }
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

test("collecting initiator stacks never pauses the page on a debugger statement", async () => {
  const { loads } = await collectScripts(browser, `${base}/debug.html`, opts);
  assert.ok(loads.some(({ url, parentUrl }) => url === base + "/after-debug.js" && parentUrl === base + "/debug.js"));
});

test("script loads retain their external initiator across redirection and unsuccessful responses", async () => {
  const { loads, scripts } = await collectScripts(browser, `${base}/loads.html`, opts);
  assert.ok(Array.isArray(loads), "the collector should return script request attempts");
  const parentsOf = (path) => loads.filter((load) => load.url === base + path).map((load) => load.parentUrl);
  assert.deepEqual(parentsOf("/loader.js"), [null], "parser-inserted script has no external initiating script");
  for (const path of ["/redirect.js", "/final.js", "/missing.js"]) {
    assert.deepEqual(parentsOf(path), [base + "/loader.js"], path);
  }
  assert.ok(!scripts.some((s) => s.url === base + "/missing.js"), "404 has no analyzable script body");
  assert.deepEqual(parentsOf("/frame-child.js"), [base + "/frame-loader.js"]);
});

test("a fragment on the parent script URL preserves attribution", async () => {
  const { loads } = await collectScripts(browser, base + "/fragment.html", opts);
  assert.ok(loads.some(({ url, parentUrl }) => url === base + "/missing.js" && parentUrl === base + "/loader.js"));
});

test("a sourceURL debugging label preserves the external parent script identity", async () => {
  const { loads } = await collectScripts(browser, base + "/label.html", opts);
  assert.ok(loads.some(({ url, parentUrl }) => url === base + "/child.js" && parentUrl === base + "/label.js"));
});

test("early script requests in a cross-site iframe remain visible", async () => {
  const { loads } = await collectScripts(browser, base + "/embedded.html", opts);
  const iframeOrigin = base.replace("127.0.0.1", "localhost");
  assert.ok(loads.some(({ url, parentUrl }) => url === iframeOrigin + "/frame-loader.js" && parentUrl === null));
  assert.ok(loads.some(({ url }) => url === iframeOrigin + "/frame-child.js"));
});

test("a redirected parent retains both the executed script and the originally requested policy URL", async () => {
  const { loads } = await collectScripts(browser, base + "/redirect-parent.html", opts);
  assert.deepEqual(loads.filter(load => load.url === base + "/missing.js"), [{
    url: base + "/missing.js", parentUrl: base + "/loader.js", requestedParentUrl: base + "/tag.js",
  }]);
});

test("different responses at one exact URL in two frames preserve both fingerprints", async () => {
  const { scripts, ambiguousUrls, loads } = await collectScripts(browser, base + "/variants.html", opts);
  const variants = scripts.filter(script => script.url === base + "/variant.js");
  assert.deepEqual(variants.map(s => s.content).sort(), ["/* first */", "/* second */"]);
  assert.equal(new Set(variants.map(s => s.hash)).size, 2);
  assert.deepEqual(ambiguousUrls, [base + "/variant.js"]);
  for (const name of ["first", "second"]) {
    // One input URL served two different redirect targets. Never attribute one frame's child to the other.
    const edges = loads.filter(edge => edge.url === base + "/" + name + ".js/child.js");
    assert.ok(edges.length);
    assert.ok(edges.every(edge => edge.parentUrl === null || edge.parentUrl === base + "/" + name + ".js"));
  }
});

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
