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
 *          known?:Record<string,Finding[]>}[]} results   // traits the host already had (info)
 * @param {{pruned?:string[]}} [options]  sites dropped from the baseline (no longer in sites.yml)
 * @returns {{markdown:string, exitCode:0|2, hasFindings:boolean, hasErrors:boolean}}
 */
export function buildReport(results, { pruned = [] } = {}) {
  let highCount = 0;
  let findingCount = 0;
  let errorCount = 0;
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

    if (r.firstRun) {
      out.push(`✅ Baseline created with ${r.diff.added.length} script(s). No alarms on the first run except known IoCs.`, "");
      for (const key of r.diff.added) {
        if (fresh[key]?.length || known[key]?.length) renderScript("Recorded", key, fresh[key] ?? [], known[key] ?? []);
      }
      continue;
    }

    const { added, changed, removed } = r.diff;
    if (!added.length && !changed.length && !removed.length) {
      out.push("No changes.", "");
      continue;
    }
    for (const [label, keys] of [["New", added], ["Changed", changed]]) {
      for (const key of keys) renderScript(label, key, fresh[key] ?? [], known[key] ?? []);
    }
    if (removed.length) out.push(`Removed: ${removed.map(code).join(", ")}`, "");
  }

  if (pruned.length) {
    out.push("## No longer in sites.yml", "", `Baseline entries dropped: ${pruned.map(code).join(", ")}`, "");
  }

  const headline = [];
  if (highCount) headline.push(`**${highCount} high-severity finding(s)** – review the scripts below now.`);
  else if (findingCount) headline.push(`${findingCount} medium-severity finding(s).`);
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
