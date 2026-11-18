/** Query parameters that only bust caches and must not change a script's identity. */
export const CACHE_BUSTER_PARAMS = new Set([
  "v", "ver", "version", "t", "ts", "_", "cb", "rnd", "rand", "rev", "hash", "build",
  "timestamp", "cachebust", "cachebuster", "nocache", "bust",
]);

/**
 * Identity of a script: URL without fragment and cache-buster parameters, remaining params sorted.
 * A blob: script gets a new random URL on every page load, so it is identified by the page origin
 * that created it plus its content hash instead.
 */
export function scriptKey(url, contentHash = "") {
  if (String(url).startsWith("blob:")) {
    let origin = "null";
    try {
      origin = new URL(url).origin;
    } catch {}
    return `blob:${origin}/sha256-${String(contentHash).slice(0, 16)}`;
  }
  try {
    const u = new URL(url);
    const params = [...u.searchParams].filter(([k]) => !CACHE_BUSTER_PARAMS.has(k.toLowerCase()));
    params.sort(([a, x], [b, y]) => (a === b ? (x < y ? -1 : x > y ? 1 : 0) : a < b ? -1 : 1));
    const query = new URLSearchParams(params).toString();
    return `${u.origin}${u.pathname}${query ? `?${query}` : ""}`;
  } catch {
    return String(url).split(/[?#]/)[0];
  }
}

/** Host a script belongs to; for a blob: script the host of the page origin that created it. */
export function scriptHost(url) {
  try {
    const u = new URL(url);
    return u.protocol === "blob:" ? new URL(u.origin).host : u.host;
  } catch {
    return "";
  }
}

/** The sites.yml ignore pattern (a substring of the script URL) that matches `url`, if any. */
export const ignoredBy = (url, ignore = []) => (url ? ignore.find((pattern) => url.includes(pattern)) : undefined);

export function sameScriptContent(a, b) {
  return a?.hash === b.hash && JSON.stringify(a?.hashes) === JSON.stringify(b.hashes);
}

/**
 * Compare the scripts of one site against its baseline.
 * @param {Record<string,{hash:string,url:string}>|undefined} baseline
 * @param {Record<string,{hash:string,url:string}>} current
 */
export function diffSite(baseline = {}, current = {}) {
  const base = baseline ?? {};
  const added = [];
  const changed = [];
  for (const [key, entry] of Object.entries(current)) {
    if (!(key in base)) added.push(key);
    else if (!sameScriptContent(base[key], entry)) changed.push(key);
  }
  const removed = Object.keys(base).filter((key) => !(key in current));
  return { added: added.sort(), changed: changed.sort(), removed: removed.sort() };
}
