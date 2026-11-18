// Builds the Markdown report (used as GitHub issue body and job summary).
// Script content is attacker-controlled: everything taken from it goes into
// code blocks with backticks and newlines neutralised.

const ICON = { high: "🔴", medium: "🟠" };

const safeCode = (s) => String(s ?? "").replace(/`/g, "'").replace(/[\r\n]+/g, " ");
const code = (s) => `\`${safeCode(s)}\``;

/**
 * Report for a run that could not start (invalid sites.yml or baseline), so the job summary
 * explains the problem instead of staying empty. The message can quote file contents.
 */
export function buildErrorReport(message) {
  const body = String(message ?? "").replace(/`/g, "'");
  return [
    "# Script Drift Watch report",
    "",
    "⚠️ **The scan did not run.** Fix the problem below and run it again.",
    "",
    "```text",
    body,
    "```",
    "",
  ].join("\n");
}

/**
 * @typedef {{id:string, severity:'high'|'medium', title:string, evidence:string}} Finding
 * @param {{site:string, error?:string, firstRun:boolean, warnings?:string[],
 *          diff:{added:string[],changed:string[],removed:string[]},
 *          findings:Record<string,Finding[]>,   // fresh: alarm-relevant
 *          loadFindings?:{parent:string,resolvedParent?:string,child:string,id:string,severity:string,ongoing:boolean}[],
 *          unattributed?:string[], ambiguousUrls?:string[],
 *          known?:Record<string,Finding[]>}[]} results   // traits the host already had (info)
 * @param {{pruned?:string[], stale?:string[]}} [options]  sites no longer in sites.yml: dropped from
 *   the baseline (pruned, with --update-baseline) or still kept in it (stale, without the flag)
 * @returns {{markdown:string, exitCode:0|2, hasFindings:boolean, hasErrors:boolean}}
 */
export function buildReport(results, { pruned = [], stale = [] } = {}) {
  let highCount = 0;
  let findingCount = 0;
  let errorCount = 0;
  let ongoingCount = 0;
  const out = ["# Script Drift Watch report", ""];

  const renderScript = (label, key, fresh, known) => {
    findingCount += fresh.length;
    highCount += fresh.filter((f) => f.severity === "high").length;
    out.push(`### ${label}: ${code(key)}`, "");
    for (const f of fresh) {
      out.push(`- ${ICON[f.severity] ?? ""} **${f.severity}** ${code(f.id)}: ${f.title}`);
      out.push("", "  ```text", `  ${safeCode(f.evidence)}`, "  ```", "");
    }
    if (known.length) {
      out.push(`ℹ️ Known traits for this host (seen before, no alarm): ${known.map((f) => code(f.id)).join(", ")}`, "");
    } else if (!fresh.length && label !== "Recorded") {
      out.push("ℹ️ Content changed, no suspicious traits found.", "");
    }
  };

  for (const r of results) {
    out.push(`## ${r.site}`, "");
    if (r.error) {
      errorCount++;
      out.push(`⚠️ Could not scan this site: ${code(r.error)}`, "");
      continue;
    }
    if (r.warnings?.includes("load-timeout")) {
      out.push("⚠️ The page did not finish loading within the timeout. The scripts that did load were scanned.", "");
    }
    const fresh = r.findings ?? {};
    const known = r.known ?? {};
    if (r.ambiguousUrls?.length) {
      out.push(`Multiple response bodies or delivery outcomes for the same URL. Individual responses could not be attributed to a loader: ${r.ambiguousUrls.map(code).join(", ")}`, "");
    }
    const loads = r.loadFindings ?? [];
    if (loads.length) {
      out.push("### Script load findings", "");
      for (const f of loads) {
        if (f.ongoing) ongoingCount++;
        else {
          findingCount++;
          if (f.severity === "high") highCount++;
        }
        const label = f.ongoing ? "Still observed" : f.severity;
        const loader = f.resolvedParent ? `${code(f.parent)} (resolved to ${code(f.resolvedParent)})` : code(f.parent);
        out.push(`- ${ICON[f.severity]} **${label}** ${code(f.id)}: ${loader} → ${code(f.child)}`);
      }
      out.push("");
    }

    if (r.firstRun) {
      out.push(`Baseline created with ${r.diff.added.length} script(s). Known IoCs and explicit origin policy violations can alarm on this run.`, "");
      for (const key of r.diff.added) {
        if (fresh[key]?.length || known[key]?.length) renderScript("Recorded", key, fresh[key] ?? [], known[key] ?? []);
      }
      continue;
    }

    const { added, changed, removed } = r.diff;
    if (!added.length && !changed.length && !removed.length) {
      if (!loads.length) out.push("No changes.", "");
      continue;
    }
    for (const [label, keys] of [["New", added], ["Changed", changed]]) {
      for (const key of keys) renderScript(label, key, fresh[key] ?? [], known[key] ?? []);
    }
    const unattributed = new Set(r.unattributed);
    const unknown = [...added, ...changed].filter(key => unattributed.has(key));
    if (unknown.length) out.push(`External initiator unknown or loaded by page markup: ${unknown.map(code).join(", ")}`, "");
    if (removed.length) out.push(`Removed: ${removed.map(code).join(", ")}`, "");
  }

  if (pruned.length) {
    out.push("## No longer in sites.yml", "", `Baseline entries dropped: ${pruned.map(code).join(", ")}`, "");
  }
  if (stale.length) {
    out.push("## No longer in sites.yml", "",
      `Still in the baseline (run with \`--update-baseline\` to drop them): ${stale.map(code).join(", ")}`, "");
  }

  const headline = [];
  if (highCount) headline.push(`**${highCount} high-severity finding(s)** – review the scripts below now.`);
  else if (findingCount) headline.push(`${findingCount} medium-severity finding(s).`);
  if (ongoingCount) headline.push(`${ongoingCount} previously reported high-severity script load(s) still observed.`);
  if (errorCount) headline.push(`⚠️ ${errorCount} site(s) could not be scanned.`);
  if (!headline.length) headline.push("No suspicious findings.");
  out.splice(2, 0, headline.join(" "), "");

  return {
    markdown: out.join("\n"),
    exitCode: highCount ? 2 : 0,
    hasFindings: findingCount > 0,
    hasErrors: errorCount > 0,
  };
}
