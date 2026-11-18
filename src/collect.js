// Loads a page in headless Chromium and captures every external script it
// executes, including scripts injected at runtime (A/B testing, tag managers).
import { createHash } from "node:crypto";
import { chromium } from "playwright";

export const IPHONE_UA =
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1";

export const sha256 = (text) => createHash("sha256").update(text).digest("hex");

/**
 * Launch one browser for the whole run (without the navigator.webdriver automation flag).
 * `channel: "chromium"` is Chromium's "new headless" mode, i.e. the real browser. Playwright's
 * default headless shell announces itself as "HeadlessChrome" in the Sec-CH-UA header and in
 * navigator.userAgentData (which the UA override does not change), and lacks plugins and
 * window.chrome, so payloads that hide from bots could spot it. Install with
 * `npx playwright install --no-shell chromium`.
 */
export function launchBrowser() {
  return chromium.launch({ channel: "chromium", headless: true, args: ["--disable-blink-features=AutomationControlled"] });
}

/** A regular desktop Chrome UA, so servers cannot trivially cloak payloads from "HeadlessChrome". */
export function desktopUserAgent(version) {
  const major = String(version).split(".")[0] || "150";
  return `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${major}.0.0.0 Safari/537.36`;
}

/**
 * Await every queued body read, including reads queued while waiting (a late response).
 * Promise.all alone only covers the reads queued when it was called.
 */
export async function drainPending(pending) {
  while (pending.length) await Promise.all(pending.splice(0));
}

/** Async stack depth the debugger records, so string timers and promise callbacks keep their caller. */
const ASYNC_STACK_DEPTH = 8;

/**
 * The innermost stack frame that belongs to an external script. Frames of eval'd, Function-built
 * or string-timer code have no script URL (or only a self-chosen sourceURL label), so walk outward,
 * including async parents, to the script that ran that code. Inline page code is skipped too.
 */
function parentFromStack(stack, sourceUrls, documentURL) {
  for (let s = stack; s; s = s.parent) {
    for (const frame of s.callFrames ?? []) {
      const url = sourceUrls.has(frame.scriptId) ? sourceUrls.get(frame.scriptId) : frame.url;
      if (url && url !== documentURL) return url;
    }
  }
  return null;
}

// Keep the browser's attributed parent for each request, including every hop of a redirect.
// An HTML parser or inline script does not identify an external parent script.
export async function observeInitiators(session, record) {
  const requests = new Map();
  const sourceUrls = new Map();
  session.on("Debugger.scriptParsed", ({ scriptId, hasSourceURL, embedderName }) => {
    if (hasSourceURL) sourceUrls.set(scriptId, embedderName || null);
  });
  // Deactivated breakpoints do not always hold: after a cross-process navigation Chromium can pause
  // on `debugger;` (seen in about 1 of 25 runs), which would hang the page until the scan times out.
  session.on("Debugger.paused", () => {
    session.send("Debugger.resume").catch(() => {});
  });
  session.on("Network.requestWillBeSent", ({ requestId, type, request, initiator, redirectResponse, documentURL }) => {
    if (type !== "Script" || !/^https?:\/\//i.test(request.url)) return;
    let parent = null;
    if (redirectResponse && requests.has(requestId)) {
      parent = requests.get(requestId);
    } else if (initiator.type === "script") {
      parent = parentFromStack(initiator.stack, sourceUrls, documentURL)
        ?? (initiator.url && initiator.url !== documentURL ? initiator.url : null);
    }
    requests.set(requestId, parent);
    record(request.url, parent);
  });
  // The debugger supplies initiator stacks. Pages containing a debugger statement must keep running.
  await Promise.all([
    session.send("Debugger.enable"),
    session.send("Debugger.setBreakpointsActive", { active: false }),
    session.send("Debugger.setSkipAllPauses", { skip: true }),
    session.send("Debugger.setAsyncCallStackDepth", { maxDepth: ASYNC_STACK_DEPTH }),
    session.send("Network.enable"),
  ]);
}

// Chromium can name the requested URL in a call frame even when Playwright delivered
// the script body at the end of a redirect chain. Only retain unambiguous identities.
function rememberRedirectChain(sources, request) {
  const chain = [];
  for (let hop = request; hop; hop = hop.redirectedFrom()) chain.push(hop.url());
  const parentUrl = chain[0];
  const requestedParentUrl = chain.at(-1);
  for (const alias of chain) {
    const previous = sources.get(alias);
    sources.set(alias, {
      parentUrl: previous && previous.parentUrl !== parentUrl ? null : parentUrl,
      requestedParentUrl: previous && previous.requestedParentUrl !== requestedParentUrl ? null : requestedParentUrl,
    });
  }
}

/**
 * @param {import('playwright').Browser} browser
 * @param {string} url
 * @param {{timeoutMs:number, settleMs:number, userAgent?:string}} opts
 * @returns {Promise<{scripts:{url:string, content:string, hash:string}[], ambiguousUrls:string[],
 *   loads:{parentUrl:string|null,requestedParentUrl?:string,url:string}[], loadTimedOut:boolean}>}
 *   Throws only when the main document itself fails (network error or non-2xx status).
 */
export async function collectScripts(browser, url, { timeoutMs, settleMs, userAgent }) {
  const context = await browser.newContext({
    ...(userAgent
      ? { userAgent, isMobile: true, hasTouch: true, viewport: { width: 390, height: 844 } }
      : { userAgent: desktopUserAgent(browser.version()) }),
    serviceWorkers: "block",
  });
  const pending = [];
  const scripts = new Map();
  const sources = new Map();
  const attempts = new Map();
  const unreadRequests = new Set();
  const record = (url, parent) => {
    if (!attempts.has(url)) attempts.set(url, new Set());
    if (parent !== undefined) attempts.get(url).add(parent);
  };
  try {
    const page = await context.newPage();
    page.on("request", (req) => {
      // Playwright also sees requests from out-of-process frames before a CDP session can attach.
      if (req.resourceType() === "script" && /^https?:\/\//i.test(req.url())) {
        record(req.url());
        unreadRequests.add(req);
      }
    });
    await observeInitiators(await context.newCDPSession(page), record);
    const observedFrames = new WeakSet();
    page.on("framenavigated", async (frame) => {
      if (frame === page.mainFrame() || observedFrames.has(frame)) return;
      observedFrames.add(frame);
      try {
        const session = await context.newCDPSession(frame);
        session.once("close", () => observedFrames.delete(frame));
        await observeInitiators(session, record);
      } catch {
        // Same-process frames share the page's session. A detaching frame may have no session.
        observedFrames.delete(frame);
      }
    });
    page.on("response", (res) => {
      if (res.request().resourceType() !== "script" || res.status() >= 300) return;
      pending.push(
        res.text().then(
          (content) => {
            const url = res.url();
            const hash = sha256(content);
            if (!scripts.has(url)) scripts.set(url, new Map());
            scripts.get(url).set(hash, { url, content, hash });
            unreadRequests.delete(res.request());
            rememberRedirectChain(sources, res.request());
          },
          () => {}, // body unavailable (aborted/redirected) – skip
        ),
      );
    });
    // Only the main document may fail the scan. A page that never fires `load`
    // (slow ads, or a payload that deliberately hangs it) is still scanned.
    const response = await page.goto(url, { waitUntil: "domcontentloaded", timeout: timeoutMs });
    if (!response) throw new Error(`no response for ${url}`);
    if (!response.ok()) throw new Error(`HTTP ${response.status()} for ${url}`);
    const loadTimedOut = await page.waitForLoadState("load", { timeout: timeoutMs }).then(() => false, () => true);
    if (!loadTimedOut) await page.waitForLoadState("networkidle", { timeout: timeoutMs }).catch(() => {});
    await page.waitForTimeout(settleMs);
    await drainPending(pending);
    const loads = [];
    for (const [url, parents] of attempts) {
      // A script stack can also name an inline/evaluated source. Attribute only captured scripts.
      if (!parents.size) parents.add(null);
      for (const raw of parents) {
        const source = sources.get(raw);
        const parentUrl = source?.parentUrl ?? null;
        const edge = { url, parentUrl };
        if (parentUrl && source.requestedParentUrl && source.requestedParentUrl !== parentUrl) {
          edge.requestedParentUrl = source.requestedParentUrl;
        }
        loads.push(edge);
      }
    }
    // A body from one frame cannot establish what another loader received at the
    // same URL when that other request failed, redirected, or never finished.
    const unreadUrls = new Set([...unreadRequests].map(req => req.url()));
    const ambiguousUrls = [...scripts.keys()].filter(url => scripts.get(url).size > 1 || unreadUrls.has(url)).sort();
    return { scripts: [...scripts.values()].flatMap(variants => [...variants.values()]), ambiguousUrls, loads, loadTimedOut };
  } finally {
    await context.close();
  }
}
