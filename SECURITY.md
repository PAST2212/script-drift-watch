# Security policy

Please report vulnerabilities in script-drift-watch privately via
GitHub's "Report a vulnerability" (Security tab → Advisories), not in public issues.

For new indicators of compromise or script-content detections, submit a pull request
with the rule and a focused test. [Content rules](src/rules.js) · [Rule tests](test/rules.test.js)

For detections based on which script requested another script, include a local
test of the load relationship. If the change affects notifications, cover both the
suspicious load and a legitimate update in the Action test. [Load rules](src/loads.js) · [Policy tests](test/load-policy.test.js) · [Action tests](test/action.test.js)
