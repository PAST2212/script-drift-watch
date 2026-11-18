import { scriptKey } from "./diff.js";

// Policy is operator input. Observations in the baseline never grant permission.
export function parseOriginPolicy(value, at, problems) {
  const name = at + ": allowed-script-origins";
  const policy = {};
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    problems.push(name + " must map absolute script URLs to lists of allowed HTTP(S) origins");
    return policy;
  }
  for (const [raw, origins] of Object.entries(value)) {
    if (!httpUrl(raw) || raw.includes("#")) {
      problems.push(name + " has an invalid loader URL: " + raw);
      continue;
    }
    const parent = scriptKey(raw);
    if (Object.hasOwn(policy, parent) || !Array.isArray(origins)) {
      problems.push(name + " needs one list of origins per loader: " + raw);
      continue;
    }
    const normalized = new Set();
    for (const item of origins) {
      const url = httpUrl(item);
      if (!url || !/^https?:\/\/[^/?#]+\/?$/i.test(item)) {
        problems.push(name + " has an invalid origin for " + raw + ": " + JSON.stringify(item));
      } else {
        normalized.add(url.origin);
      }
    }
    policy[parent] = [...normalized].sort();
  }
  return policy;
}

function httpUrl(raw) {
  if (typeof raw !== "string" || !/^https?:\/\//i.test(raw) || /[\s\\*]/.test(raw)) return null;
  try {
    const url = new URL(raw);
    return url.username || url.password ? null : url;
  } catch {
    return null;
  }
}

// Each group is one normalized initiating script and one exact destination origin.
// Keep the concrete child URL for evidence. Two children at the same origin may have
// entirely different contents, so clipper evidence must come from the attributed child.
function groupLoads(loads, policy, bodies, ignore, previous) {
  const groups = new Map();
  const unattributed = new Set();
  for (const { parentUrl, requestedParentUrl, url } of loads) {
    if (ignore.some(p => url.includes(p) || parentUrl?.includes(p) || requestedParentUrl?.includes(p))) continue;
    if (!parentUrl) {
      unattributed.add(scriptKey(url));
      continue;
    }
    const source = scriptKey(parentUrl, bodies.get(parentUrl)?.hash);
    const parent = requestedParentUrl ? scriptKey(requestedParentUrl) : source;
    const origin = new URL(url).origin;
    const foreign = origin !== new URL(parentUrl).origin;
    const governed = [...new Set([parent, source])].filter(key => Object.hasOwn(policy, key));
    if (!foreign && !governed.length && !previous?.[parent]?.[origin]) continue;
    const groupKey = JSON.stringify([parent, origin]);
    if (!groups.has(groupKey)) groups.set(groupKey, { parent, origin, requests: [] });
    groups.get(groupKey).requests.push({ url, source, foreign, governed });
  }
  return { groups, unattributed };
}

export function assessScriptLoads({ loads, previous, policy = {}, bodies, ignore = [] }) {
  const { groups, unattributed } = groupLoads(loads, policy, bodies, ignore, previous);
  const origins = structuredClone(previous ?? {});
  // Operator approval (or removal of a policy) resolves its old denial, even when
  // an intermittent experiment happens to be absent during that scan.
  for (const history of Object.values(origins)) {
    for (const [origin, state] of Object.entries(history)) {
      if (!state.deniedBy) continue;
      state.deniedBy = state.deniedBy.filter(key => policy[key] && !policy[key].includes(origin));
      if (!state.deniedBy.length) delete state.deniedBy;
    }
  }
  const findings = [];
  for (const { parent, origin, requests } of groups.values()) {
    origins[parent] ??= {};
    const old = origins[parent][origin];
    const state = {};
    requests.sort((a, b) => a.url.localeCompare(b.url) || a.source.localeCompare(b.source));
    const add = (id, severity, request, ongoing = false) => {
      const f = { id, severity, parent, child: request.url, ongoing };
      if (request.source !== parent) f.resolvedParent = request.source;
      findings.push(f);
    };

    const denied = requests.filter(r => r.governed.some(key => !policy[key].includes(origin)));
    if (denied.length) {
      state.deniedBy = [...new Set(denied.flatMap(r => r.governed).filter(key => !policy[key].includes(origin)))].sort();
      add("disallowed-script-origin", "high", denied[0], Boolean(old?.deniedBy?.length));
    }
    const clipper = requests.find(r => r.foreign && bodies.get(r.url)?.clipper);
    if (clipper) {
      // Seed the first graph, including upgrades. A later change to the relationship
      // can alarm even when the destination host already has the content trait.
      state.clipper = previous === undefined || old?.clipper === "initial" ? "initial" : "alert";
      if (state.clipper === "alert") add("clipper-script-load", "high", clipper, old?.clipper === "alert");
    } else if (old?.clipper && requests.some(r => !bodies.has(r.url))) {
      state.clipper = old.clipper;
    }
    const unexpected = requests.find(r => r.foreign && !r.governed.length);
    if (unexpected && previous !== undefined && !old && !clipper && !denied.length) {
      add("new-script-origin", "medium", unexpected);
    }
    origins[parent][origin] = state;
  }
  findings.sort((a, b) => a.parent.localeCompare(b.parent) || a.child.localeCompare(b.child) || a.id.localeCompare(b.id));
  return { origins, findings, unattributed: [...unattributed] };
}
