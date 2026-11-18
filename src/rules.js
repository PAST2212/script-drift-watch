// Heuristic rules that flag suspicious behaviour in a (changed) script.
// They are deliberately simple regexes: the goal is to raise a hand when a
// trusted vendor script suddenly gains clipper/skimmer/loader traits, not to
// be a full JS malware analyser.

/** Domains/IPs published as indicators of compromise in recent attacks. */
export const KNOWN_IOCS = [
  "1688360.cc", // Optimizely Web supply-chain attack, 2026-11-16
  "84.32.102.230", // Adform trackpoint-async.js clipper C2, 2026-07
];

/**
 * Shared hosting domains where anyone can get their own subdomain (a small, hand-picked part of
 * the Public Suffix List's private section). Each tenant counts as its own registrable domain,
 * so `attacker.cloudfront.net` is foreign to a script served from `vendor.cloudfront.net`.
 */
const SHARED_HOSTING_SUFFIXES = [
  "cloudfront.net", "s3.amazonaws.com", "azureedge.net", "azurewebsites.net", "blob.core.windows.net",
  "web.app", "firebaseapp.com", "appspot.com", "workers.dev", "pages.dev", "r2.dev", "trycloudflare.com",
  "github.io", "githubusercontent.com", "netlify.app", "vercel.app", "herokuapp.com", "onrender.com",
  "fly.dev", "glitch.me", "surge.sh", "ngrok.io", "ngrok-free.app", "b-cdn.net", "myshopify.com",
];

/** Second-level labels under a two-letter ccTLD that act as public suffixes (co.uk, com.au, co.kr, or.jp, …). */
const CCTLD_SECOND_LEVELS = new Set([
  "co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go", "gob", "gv", "mil", "ltd", "plc", "sch", "nic",
]);

/**
 * Naive registrable domain ("eTLD+1"); good enough to tell vendor from foreign hosts.
 * Errs towards "foreign" (more medium exfil-sink findings) rather than hiding a destination.
 */
export function registrableDomain(host) {
  const h = String(host).toLowerCase().replace(/:\d+$/, "").replace(/\.$/, "");
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.includes(":")) return h;
  const parts = h.split(".");
  const shared = SHARED_HOSTING_SUFFIXES.find((s) => h.endsWith(`.${s}`));
  if (shared) return parts.slice(-(shared.split(".").length + 1)).join(".");
  if (parts.length <= 2) return h;
  const [second, tld] = parts.slice(-2);
  return tld.length === 2 && CCTLD_SECOND_LEVELS.has(second) ? parts.slice(-3).join(".") : parts.slice(-2).join(".");
}

function snippet(content, index, length = 0) {
  const start = Math.max(0, index - 40);
  const end = Math.min(content.length, index + Math.max(length, 0) + 40);
  return content.slice(start, end).replace(/\s+/g, " ").trim().slice(0, 200);
}

/** atob and eval/Function must be this close (chars) to count as one loader. */
const LOADER_WINDOW = 300;

/** First match of `re` that has a match of `near` within `window` characters (linear two-pointer scan). */
function findNear(content, re, near, window) {
  const nearIdx = [...content.matchAll(near)].map((m) => m.index); // ascending
  if (!nearIdx.length) return null;
  let j = 0;
  for (const m of content.matchAll(re)) {
    while (j < nearIdx.length && nearIdx[j] < m.index - window) j++;
    if (j < nearIdx.length && nearIdx[j] <= m.index + window) return { index: m.index, length: m[0].length };
  }
  return null;
}

function firstMatch(content, re) {
  re.lastIndex = 0;
  const m = re.exec(content);
  return m ? { index: m.index, length: m[0].length } : null;
}

const RE = {
  clipboard: /navigator\.clipboard\.(?:writeText|readText|write|read)\s*\(|clipboardData\.(?:setData|getData)\s*\(|addEventListener\(\s*["'`](?:copy|cut|paste)["'`]|\.oncopy\s*=|execCommand\s{0,16}\(\s{0,16}["'`](?:copy|cut|paste)["'`]/,
  wallet: new RegExp(
    [
      // Boundaries exclude base64 characters so blobs (fonts, images) don't match.
      /(?<![A-Za-z0-9+/=])0x[a-fA-F0-9]{40}(?![A-Za-z0-9+/=])/.source, // ETH address
      /(?<![A-Za-z0-9+/=])bc1[a-z0-9]{25,59}(?![A-Za-z0-9+/=])/.source, // BTC bech32
      /(?<![A-Za-z0-9+/=])[13][a-km-zA-HJ-NP-Z1-9]{25,34}(?![A-Za-z0-9+/=])/.source, // BTC legacy
      /(?<![A-Za-z0-9+/=])T[1-9A-HJ-NP-Za-km-z]{33}(?![A-Za-z0-9+/=])/.source, // TRON
      /0x\[a-fA-F0-9\]\{40\}/.source, // a regex *for* ETH addresses
    ].join("|"),
  ),
  atob: /\batob\s*\(/g,
  // eval(, new Function(, Function(atob, indirect eval (0,eval)( and window["eval"](,
  // and string timers fed straight from atob: setTimeout(atob(…)).
  dynamicCode: /\beval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\(\s*atob|\(\s{0,16}\d{1,4}\s{0,16},\s{0,16}eval\s{0,16}\)\s{0,16}\(|\[\s{0,16}["'`]eval["'`]\s{0,16}\]\s{0,16}\(|\b(?:setTimeout|setInterval)\s{0,16}\(\s{0,16}atob\s{0,16}\(/g,
  // Field names in strings, selectors and regexes ("cvc", [name=cvc], #cvc, /cvv|cvc/), not
  // identifiers: no whitespace prefix (`new Cvc`, `return cvc`) and no call (`=Cvc(`).
  cardField: /["'`\[=#/|](?:cc-number|cc-csc|cc-exp(?:-month|-year)?|cardnumber|card[-_]number|cvv2?|cvc)\b(?!\s{0,16}\()/i,
  inputHook: /(?:getOwnPropertyDescriptor|defineProperty)\s*\(\s*(?:window\.)?HTMLInputElement\.prototype\s*,\s*["'`]value["'`]/,
  iosDevice: /\b(?:iPhone|iPad|iPod)\b/,
  uaSniff: /navigator\.(?:userAgent|platform|maxTouchPoints)/,
  // Bounded whitespace ({0,16}) keeps this linear on hostile input (no catastrophic backtracking).
  sinkUrl: /(?:sendBeacon|fetch|\.open|\.src\s{0,16}=|\.action\s{0,16}=|new\s{1,16}WebSocket|new\s{1,16}EventSource)\s{0,16}(?:\(\s{0,16})?(?:["'`]\s{0,16}[A-Z]{1,10}\s{0,16}["'`]\s{0,16},\s{0,16})?["'`](?:https?:|wss?:)?\/\/([^/"'`\s?#]{1,253})/gi,
};

/**
 * Scan one script for suspicious traits.
 * @param {string} content  script source
 * @param {string} scriptHost  host the script was served from (to tell vendor from foreign destinations)
 * @returns {{id:string, severity:'high'|'medium', title:string, evidence:string}[]}
 */
export function scanScript(content, scriptHost) {
  const src = String(content ?? "");
  const findings = [];
  const add = (id, severity, title, m) =>
    findings.push({ id, severity, title, evidence: snippet(src, m.index, m.length) });

  const clip = firstMatch(src, RE.clipboard);
  const wallet = firstMatch(src, RE.wallet);
  if (clip && wallet) {
    add("clipboard-hijack", "high", "Clipboard access combined with crypto wallet addresses (clipper)", clip);
  } else if (clip) {
    add("clipboard-access", "medium", "Script reads or writes the clipboard", clip);
  }
  if (wallet) add("wallet-pattern", "medium", "Crypto wallet address or wallet regex in script", wallet);

  const loader = findNear(src, RE.dynamicCode, RE.atob, LOADER_WINDOW);
  if (loader) add("obfuscated-loader", "high", "Base64-decoded code is executed (atob + eval/Function)", loader);

  const card = firstMatch(src, RE.cardField);
  if (card) add("card-field-access", "high", "Script references payment card form fields", card);

  const hook = firstMatch(src, RE.inputHook);
  if (hook) add("input-value-hook", "high", "Script hooks the value property of input fields", hook);

  const ios = firstMatch(src, RE.iosDevice);
  if (ios && RE.uaSniff.test(src)) add("ios-only-branch", "medium", "Script branches on iPhone/iPad user agents", ios);

  const ownDomain = registrableDomain(scriptHost);
  const foreign = new Map();
  for (const m of src.matchAll(RE.sinkUrl)) {
    const host = m[1].toLowerCase();
    if (registrableDomain(host) !== ownDomain && !foreign.has(host)) foreign.set(host, m);
  }
  if (foreign.size) {
    const hosts = [...foreign.keys()];
    const first = foreign.get(hosts[0]);
    findings.push({
      id: "exfil-sink",
      severity: "medium",
      title: "Script sends data to or loads code from a foreign domain",
      evidence: `${hosts.join(", ")} :: ${snippet(src, first.index, first[0].length)}`.slice(0, 200),
    });
  }

  const ioc = KNOWN_IOCS.map((d) => ({ d, i: src.indexOf(d) })).find((x) => x.i >= 0);
  if (ioc) add("known-ioc", "high", `Known indicator of compromise: ${ioc.d}`, { index: ioc.i, length: ioc.d.length });

  return findings;
}
