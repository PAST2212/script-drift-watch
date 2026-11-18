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
 * @param {import('playwright').Browser} browser
 * @param {string} url
 * @param {{timeoutMs:number, settleMs:number, userAgent?:string}} opts
 * @returns {Promise<{scripts:{url:string, content:string, hash:string}[], loadTimedOut:boolean}>}
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
  try {
    const page = await context.newPage();
    page.on("response", (res) => {
      if (res.request().resourceType() !== "script" || res.status() >= 300) return;
      pending.push(
        res.text().then(
          (content) => scripts.set(res.url(), { url: res.url(), content, hash: sha256(content) }),
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
    await Promise.all(pending);
    return { scripts: [...scripts.values()], loadTimedOut };
  } finally {
    await context.close();
  }
}
