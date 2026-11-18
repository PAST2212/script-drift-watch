import { readFile, writeFile } from "node:fs/promises";
import { parseArgs } from "node:util";
import YAML, { LineCounter } from "yaml";
import { scanScript } from "./rules.js";
import { scriptKey, scriptHost, diffSite } from "./diff.js";
import { buildReport, buildErrorReport } from "./report.js";
import { collectScripts, launchBrowser, IPHONE_UA } from "./collect.js";

const USAGE = `Usage: script-drift-watch [options]

  --config <file>       sites file (default: sites.yml)
  --baseline <file>     baseline file (default: baseline.json)
  --report <file>       markdown report output (default: report.md)
  --update-baseline     write the current state as new baseline and drop sites
                        no longer in the config (without it, only new sites are added)
  --timeout-ms <n>      page load timeout (default: 30000)
  --settle-ms <n>       extra wait for late scripts (default: 3000)
  -h, --help

Exit codes: 0 = ok/info, 2 = high-severity finding, 1 = error`;

const SITE_KEYS = ["url", "ignore", "ios"];

function editDistance(a, b) {
  let prev = Array.from({ length: b.length + 1 }, (_, j) => j);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    for (let j = 1; j <= b.length; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    prev = cur;
  }
  return prev[b.length];
}

/** The allowed key a typo most likely meant (`ignores` → `ignore`, `iOS` → `ios`), if any. */
const suggestKey = (key) =>
  SITE_KEYS.find((known) => editDistance(key.toLowerCase(), known) <= (known.length >= 5 ? 2 : 1));

/** Same page despite spelling differences (`https://a.example` = `https://a.example/`), or null. */
function pageId(url) {
  try {
    const u = new URL(url);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    u.hash = "";
    return u.href;
  } catch {
    return null;
  }
}

/**
 * Parse sites.yml into normalised entries. Every mistake that would otherwise be misread
 * silently (a typo'd key, `ios: yes`, an empty ignore pattern that skips every script) is
 * collected and reported at once, naming the entry.
 */
export function parseSites(text) {
  const lineCounter = new LineCounter();
  const yamlDoc = YAML.parseDocument(text, { lineCounter });
  if (yamlDoc.errors.length) throw yamlDoc.errors[0];
  const doc = yamlDoc.toJS() ?? {};
  if (!Array.isArray(doc.sites) || !doc.sites.length) {
    throw new Error("config must contain a non-empty 'sites' list");
  }
  const items = yamlDoc.get("sites")?.items ?? [];
  const where = (i) => {
    const start = items[i]?.range?.[0];
    return start === undefined ? `sites[${i}]` : `line ${lineCounter.linePos(start).line}, sites[${i}]`;
  };
  const problems = [];
  const firstIndex = new Map();
  const sites = doc.sites.map((raw, i) => {
    const entry = typeof raw === "string" ? { url: raw } : raw;
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      problems.push(`${where(i)}: expected a URL or a mapping with 'url', got ${JSON.stringify(raw)}`);
      return null;
    }
    const at = typeof entry.url === "string" ? `${where(i)} (${entry.url})` : where(i);
    for (const key of Object.keys(entry).filter((k) => !SITE_KEYS.includes(k))) {
      const hint = suggestKey(key);
      problems.push(`${at}: unknown key '${key}'${hint ? ` (did you mean '${hint}'?)` : ""}; allowed keys: ${SITE_KEYS.join(", ")}`);
    }

    const id = typeof entry.url === "string" ? pageId(entry.url) : null;
    if (!id) {
      problems.push(`${at}: url must be a full address starting with https:// or http://, e.g. https://www.example.com/`);
    } else if (entry.url !== entry.url.trim()) {
      // The URL would be accepted (URL parsing trims) but used verbatim as the baseline key.
      problems.push(`${where(i)}: url ${JSON.stringify(entry.url)} has spaces at the start or end; remove them`);
    } else if (firstIndex.has(id)) {
      problems.push(`${at}: same page as sites[${firstIndex.get(id)}]; list each page once (ios: true adds the iPhone variant)`);
    } else {
      firstIndex.set(id, i);
    }

    const ignore = typeof entry.ignore === "string" ? [entry.ignore] : entry.ignore ?? [];
    if (!Array.isArray(ignore)) {
      problems.push(`${at}: 'ignore' must be a list of pieces of script URLs, e.g. ["googletagmanager.com/gtm.js"]`);
    } else {
      ignore.forEach((pattern, j) => {
        if (typeof pattern !== "string" || !pattern.trim()) {
          problems.push(`${at}: ignore[${j}] must be a non-empty piece of a script URL in quotes (an empty one would ignore every script)`);
        }
      });
    }

    if (entry.ios !== undefined && typeof entry.ios !== "boolean") {
      problems.push(`${at}: ios must be true or false, got ${JSON.stringify(entry.ios)}`);
    }
    return { url: String(entry.url), ignore: Array.isArray(ignore) ? ignore.map(String) : [], ios: entry.ios === true };
  });
  if (problems.length) {
    throw new Error(`the sites list has ${problems.length} problem(s):\n${problems.map((p) => `  - ${p}`).join("\n")}`);
  }
  return sites;
}

/**
 * New baseline.
 * update: successfully scanned sites are replaced, failed ones keep their old entry, and sites
 *   that are no longer scan targets (removed from sites.yml, or `ios: true` dropped) are pruned.
 * no update: existing entries stay untouched; only sites seen for the first time are added
 *   (there is nothing to compare them against, so recording them hides nothing).
 */
export function nextBaseline(oldSites, results, { update = true } = {}) {
  if (!update) {
    const next = { ...oldSites };
    for (const r of results) if (r.firstRun && !r.error && r.entry) next[r.site] = r.entry;
    return next;
  }
  const next = {};
  for (const r of results) {
    if (!r.error && r.entry) next[r.site] = r.entry;
    else if (oldSites[r.site]) next[r.site] = oldSites[r.site];
  }
  return next;
}

/**
 * Where trait memory for a script lives: its host. blob: scripts get a separate `blob:<page host>`
 * bucket (`blob:null` for opaque origins), so runtime-generated code cannot inherit the traits of
 * the page's own scripts, e.g. a skimmer injected as a blob on a checkout page whose own code
 * already references card fields.
 */
const hostOf = (key) => (key.startsWith("blob:") ? `blob:${scriptHost(key) || "null"}` : scriptHost(key) || key);

/**
 * Split findings into fresh (the script's host never showed this trait before → alarm)
 * and known (already recorded for the host → info). Known IoCs are always fresh.
 * On the first run everything except known IoCs is recorded as known.
 */
export function classifyFindings(findingsByKey, oldTraits, firstRun) {
  const fresh = {};
  const known = {};
  for (const [key, findings] of Object.entries(findingsByKey)) {
    const seen = new Set(oldTraits?.[hostOf(key)] ?? []);
    for (const f of findings) {
      const isFresh = f.id === "known-ioc" || (!firstRun && !seen.has(f.id));
      (isFresh ? fresh : known)[key] ??= [];
      (isFresh ? fresh : known)[key].push(f);
    }
  }
  return { fresh, known };
}

/** Union of finding ids per script host, sorted (traits never shrink). */
export function mergeTraits(oldTraits, findingsByKey) {
  const traits = Object.fromEntries(Object.entries(oldTraits ?? {}).map(([h, ids]) => [h, new Set(ids)]));
  for (const [key, findings] of Object.entries(findingsByKey)) {
    const host = hostOf(key);
    traits[host] ??= new Set();
    for (const f of findings) traits[host].add(f.id);
  }
  return Object.fromEntries(Object.keys(traits).sort().map((h) => [h, [...traits[h]].sort()]));
}

/** Keep the previous entry when the content hash is unchanged (e.g. only a cache-buster rotated). */
export function stableScripts(oldScripts, scripts) {
  const out = {};
  for (const key of Object.keys(scripts).sort()) {
    out[key] = oldScripts?.[key]?.hash === scripts[key].hash ? oldScripts[key] : scripts[key];
  }
  return out;
}

const sortKeys = (value) =>
  value && typeof value === "object" && !Array.isArray(value)
    ? Object.fromEntries(Object.keys(value).sort().map((k) => [k, sortKeys(value[k])]))
    : value;

/** Canonical, byte-stable baseline file content. */
export function serializeBaseline(sites) {
  return JSON.stringify({ version: 1, sites: sortKeys(sites) }, null, 2) + "\n";
}

async function readBaseline(path) {
  try {
    return JSON.parse(await readFile(path, "utf8"));
  } catch (e) {
    if (e.code === "ENOENT") return null;
    throw new Error(`cannot read baseline ${path}: ${e.message}`);
  }
}

async function scanTarget(browser, target, oldEntry, opts) {
  const { site, url, ignore, userAgent } = target;
  try {
    const { scripts: collected, loadTimedOut } = await collectScripts(browser, url, { ...opts, userAgent });
    const scripts = {};
    const contents = {};
    for (const s of collected) {
      if (ignore.some((pattern) => s.url.includes(pattern))) continue;
      const key = scriptKey(s.url, s.hash);
      scripts[key] = { hash: s.hash, url: s.url };
      contents[key] = s;
    }
    const firstRun = oldEntry === undefined;
    const diff = diffSite(oldEntry?.scripts, scripts);
    const all = {};
    for (const key of firstRun ? Object.keys(scripts) : [...diff.added, ...diff.changed]) {
      const found = scanScript(contents[key].content, scriptHost(contents[key].url));
      if (found.length) all[key] = found;
    }
    const { fresh, known } = classifyFindings(all, oldEntry?.traits, firstRun);
    const entry = { scripts: stableScripts(oldEntry?.scripts, scripts), traits: mergeTraits(oldEntry?.traits, all) };
    const warnings = loadTimedOut ? ["load-timeout"] : [];
    return { site, firstRun, diff, findings: fresh, known, warnings, entry };
  } catch (e) {
    return { site, firstRun: false, error: e.message.split("\n")[0], diff: { added: [], changed: [], removed: [] }, findings: {}, entry: null };
  }
}

const OPTIONS = {
  config: { type: "string", default: "sites.yml" },
  baseline: { type: "string", default: "baseline.json" },
  report: { type: "string", default: "report.md" },
  "update-baseline": { type: "boolean", default: false },
  "timeout-ms": { type: "string", default: "30000" },
  "settle-ms": { type: "string", default: "3000" },
  help: { type: "boolean", short: "h", default: false },
};

/** Milliseconds options: whole numbers only, so "30s" fails instead of silently becoming NaN. */
const MS_OPTIONS = { "timeout-ms": 1, "settle-ms": 0 };

/** Report path even when the arguments are invalid, so argument errors reach the job summary too. */
function reportPathOf(argv) {
  try {
    const { values } = parseArgs({ args: argv, options: OPTIONS, strict: false });
    return typeof values.report === "string" ? values.report : OPTIONS.report.default;
  } catch {
    return OPTIONS.report.default;
  }
}

/** @returns {Promise<number>} exit code */
export async function main(argv) {
  let args;
  try {
    ({ values: args } = parseArgs({ args: argv, options: OPTIONS }));
    for (const [name, min] of Object.entries(MS_OPTIONS)) {
      if (!/^\d+$/.test(args[name]) || Number(args[name]) < min) {
        throw new Error(`--${name} must be a whole number of milliseconds of at least ${min}, e.g. ${OPTIONS[name].default}; got "${args[name]}"`);
      }
    }
  } catch (e) {
    const message = `${e.message}\n\n${USAGE}`;
    console.error(message);
    await writeFile(reportPathOf(argv), buildErrorReport(message)).catch(() => {});
    return 1;
  }
  if (args.help) {
    console.log(USAGE);
    return 0;
  }

  let sites;
  let baseline;
  try {
    try {
      sites = parseSites(await readFile(args.config, "utf8"));
    } catch (e) {
      throw new Error(`${args.config}: ${e.message}`);
    }
    baseline = await readBaseline(args.baseline);
  } catch (e) {
    console.error(`script-drift-watch: ${e.message}`);
    // Also into the report, so the Action's job summary explains why the run failed.
    await writeFile(args.report, buildErrorReport(e.message)).catch(() => {});
    return 1;
  }

  const targets = sites.flatMap((s) => [
    { site: s.url, url: s.url, ignore: s.ignore },
    ...(s.ios ? [{ site: `${s.url} [iPhone]`, url: s.url, ignore: s.ignore, userAgent: IPHONE_UA }] : []),
  ]);
  const opts = { timeoutMs: Number(args["timeout-ms"]), settleMs: Number(args["settle-ms"]) };

  const browser = await launchBrowser();
  const results = [];
  try {
    for (const t of targets) results.push(await scanTarget(browser, t, baseline?.sites?.[t.site], opts));
  } finally {
    await browser.close();
  }

  const update = args["update-baseline"] || !baseline;
  const oldSites = baseline?.sites ?? {};
  const gone = Object.keys(oldSites).filter((site) => !results.some((r) => r.site === site)).sort();

  const report = buildReport(results, update ? { pruned: gone } : { stale: gone });
  await writeFile(args.report, report.markdown);
  console.log(report.markdown);

  const next = serializeBaseline(nextBaseline(oldSites, results, { update }));
  if (!baseline || next !== serializeBaseline(oldSites)) await writeFile(args.baseline, next);
  return report.exitCode;
}
