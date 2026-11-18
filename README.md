# script-drift-watch

**Watch the scripts your website delivers. Get an alert when a trusted loader starts serving code with signs of clipboard hijacking or card skimming.**

On 16 November 2026, attackers abused Optimizely Web Experimentation to push a card skimmer,
a crypto clipper and iOS exploit kits through the official Optimizely snippet. Report URI found the
injected code in snippets belonging to 178 organisations ([sources](#sources)). In July 2026,
Adform's tracking script was turned into a crypto clipper the same way.

In the Optimizely incident, the vendor URL and its certificate stayed valid while the script
changed. In one documented variant, the trusted snippet instructed the browser to fetch a
second script from another domain. The scanner watches both parts of that sequence.

1. Loads your pages in real headless Chromium (so runtime-injected scripts from A/B testing tools
   and tag managers are included). An optional second Chromium visit uses an iPhone profile.
2. Hashes the external script bodies the browser can read and compares them to a baseline stored in your repository.
3. Checks new or changed scripts for clipper, skimmer and loader traits.
4. Records which external script requested each new script origin. Opens a GitHub issue and
   fails the job for a fresh high-severity content or script-load finding.

You can run the scanner locally or schedule it in your own GitHub repository. Chromium contacts
the configured pages and their resources. The Action writes its report to the job summary and,
by default, opens an issue for a fresh high-severity finding.

## Quick start (GitHub Action)

**1.** Create a (private) repository, e.g. `my-script-watch`, and add `sites.yml`:

```yaml
sites:
  - url: https://www.example.com/
  - url: https://shop.example.com/checkout
    ios: true                       # also load as iPhone (iOS-targeted payloads)
    ignore:                         # substrings of script URLs to skip
      - "googletagmanager.com/gtm.js"
```

A single ignore pattern can also be written as `ignore: "googletagmanager.com/gtm.js"`. Mistakes in
`sites.yml` stop the run instead of being silently misread, and the job summary lists every
problem with its line number. Examples: an unknown key such as `ignores:` (with a "did you mean"),
`ios: yes` instead of `true`, an empty ignore pattern (which would skip every script), a URL
without `https://` or with spaces around it, or the same page listed twice. Invalid extra
arguments in `args` (an unknown option, `--settle-ms 5s` instead of `5000`) are reported the same way.

**2.** Add `.github/workflows/script-drift-watch.yml`:

Replace `OWNER/script-drift-watch@v1` with the repository and tag or commit that contain your
copy of the Action. For a checkout of the scanner repository itself, use `uses: ./` after checkout.

```yaml
name: Script Drift Watch
on:
  schedule:
    - cron: "17 * * * *"   # hourly
  workflow_dispatch:
permissions:
  contents: write          # commit the updated baseline.json
  issues: write            # open an issue on high-severity findings
concurrency:
  group: script-drift-watch
  cancel-in-progress: false
jobs:
  watch:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: OWNER/script-drift-watch@v1
        with:
          config: sites.yml
```

**3.** Run it once via *Actions → Script Drift Watch → Run workflow*. The first run creates and
commits `baseline.json` and records the traits and script origins already present. Known IoCs
and explicit script-origin policy violations alarm even on the first run.

For a content finding, the report shows the matching rule and a source excerpt. For a load
finding, it shows the rule, the initiating script and the requested URL. If issue creation
fails, the Action skips the baseline commit so the next run can retry the alert.

### Action inputs

| Input | Default | Description |
|---|---|---|
| `config` | `sites.yml` | Sites file |
| `baseline` | `baseline.json` | Baseline file, created on first run |
| `commit-baseline` | `true` | Commit + push the updated baseline so the same change is not reported twice |
| `open-issue` | `true` | Open an issue on high-severity findings |
| `fail-on-high` | `true` | Fail the job on high-severity findings |
| `args` | | Extra CLI arguments, e.g. `--settle-ms 5000` |
| `node-version` | `24` | Node.js version for the scanner |
| `token` | `github.token` | Token used to open issues |

Outputs: `exit-code` (`0`, `2` or `1`) and `report` (path to the Markdown report).

Each run installs the scanner from its lockfile (`npm ci`) and a fresh Chromium. Browsers are
deliberately not cached: Playwright advises against it, because restoring the cache takes about as
long as downloading and the Linux system dependencies cannot be cached.

## Command line

Requires Node.js 22 or newer.

```bash
npm ci
npx playwright install --no-shell chromium
node bin/script-drift-watch.js --config sites.yml --update-baseline
```

| Option | Default | |
|---|---|---|
| `--config` | `sites.yml` | Sites file |
| `--baseline` | `baseline.json` | Baseline file |
| `--report` | `report.md` | Markdown report output |
| `--update-baseline` | off | Write the current state as the new baseline and drop sites that are no longer in the sites file. Without it, existing entries are never changed; only sites scanned for the first time are added, and sites no longer in the file are named in the report |
| `--timeout-ms` | `30000` | Page load timeout in whole milliseconds (at least 1) |
| `--settle-ms` | `3000` | Extra wait for late-loading scripts in whole milliseconds |

Exit codes: `0` no fresh high-severity finding, `2` fresh high-severity finding, `1` error
(for invalid arguments, sites file or baseline, the report explains the problem).
A site that cannot be loaded (network error or non-2xx status) keeps its old baseline and is
counted in the report headline, but does not change the exit code. A page that never finishes
loading is still scanned with the scripts that did load.

Script identity is the URL without the fragment and without common cache-buster parameters
(`v`, `t`, `_`, `cb`, `ts`, `rev`, …). Other parameters such as `gtag/js?id=G-…` stay part of the
identity. Scripts created at runtime from `blob:` URLs get a random URL on every load, so they are
identified by their page's origin and content hash instead (`blob:https://shop.example/sha256-…`).
Their traits are remembered separately from the page's own scripts (as `blob:shop.example`), so
a skimmer injected as a blob on a checkout page cannot hide behind the card-field trait of the
shop's own code. The baseline records observed load relationships per page and browser profile.
It is written in a canonical order so identical observations produce identical files.

## Rules

Content rules check **new or changed** scripts. A content finding alarms if the script's host never showed
that trait before, so a payment SDK update that still reads card fields, or a new hashed bundle from
your own domain, is listed as "known trait" info instead of opening an issue. `known-ioc` always alarms.
A changed script without findings is listed as info.

### Script loads

Chromium records the external script that initiated an HTTP(S) script request when it can
attribute it. Each relationship uses the initiating script's normalized URL and the destination's
exact origin (scheme, hostname and port). The report includes the observed child URL.

| Rule | Severity | Trigger |
|---|---|---|
| `new-script-origin` | medium | A loader without an explicit origin policy requests code from an external origin it has never used on this target. |
| `clipper-script-load` | high | A cross-origin load relationship is new or newly delivers a child with both clipboard and wallet indicators. The indicators must occur in that child's source. |
| `disallowed-script-origin` | high | A script with an explicit origin policy attempts to load code outside that policy, including a failed request or a redirect hop. |

For sensitive pages, set `allowed-script-origins` in `sites.yml`. Keys are exact HTTP(S) loader
URLs, normalized like baseline script keys. Values are lists of HTTP(S) origins. An empty list
forbids every attributable HTTP(S) script load by that loader, including same-origin requests.
For an attributable redirected loader, policies on the original request URL and the final
script URL both apply. The report shows both when they differ.

```yaml
sites:
  - url: https://shop.example.com/checkout
    allowed-script-origins:
      "https://cdn.vendor.example/experiment.js":
        - "https://assets.vendor.example"
```

The policy grants permission only for the destination. A permitted child can still raise a
content or clipper alarm. Without a policy, a new benign origin produces a report entry and
exit code 0. A loader hash update with the same behavior also stays informational.
Only the configuration grants approval. Saving a baseline remembers observations. On repeat
scans of an ongoing high-severity load, the summary shows **Still observed** and the load
does not create another issue. Independent fresh high findings can still open one.
A scan that misses an intermittent load retains its history. A clean observed response can
clear a clipper finding, and an explicit policy change can clear a destination violation.

Existing baselines seed the new relationship history on their next update. Ordinary content
checks and explicit policies still run during that scan. For a trial on production pages, use a
separate baseline with `open-issue: false` and `fail-on-high: false`. Review the summaries against
known vendor releases before enabling notifications.

### Script content

| Rule | Severity | Fires when a script… |
|---|---|---|
| `clipboard-hijack` | high | accesses the clipboard **and** contains wallet addresses / wallet regexes |
| `obfuscated-loader` | high | runs base64-decoded code (`atob` close to `eval` / `new Function`, also `eval.call(…)`, `(0,eval)(…)`, `(0, window.eval)(…)`, `window["eval"](…)` and `setTimeout(atob(…))`) |
| `card-field-access` | high | names card fields in strings, selectors or regexes (`"cc-number"`, `[name=cardnumber]`, Magento's `payment[cc_number]` / `cc_cid`, `.cc-number`, `/^cvc$/`, `/cvv\|cvc/`, …), not mere identifiers like `new Cvc()` |
| `input-value-hook` | high | hooks the `value` property of `HTMLInputElement` |
| `known-ioc` | high | contains a published IoC (`1688360.cc`, Adform C2 IP) |
| `clipboard-access` | medium | reads or writes the clipboard (Clipboard API, copy/cut/paste events, `execCommand("copy")` in any letter case) |
| `wallet-pattern` | medium | contains a BTC/ETH/TRON address or an ETH address regex |
| `ios-only-branch` | medium | branches on iPhone/iPad user agents |
| `exfil-sink` | medium | sends data to / loads code from a different registrable domain (each tenant of shared hosts such as `cloudfront.net` or `workers.dev`, and every `*.amazonaws.com` host, counts as its own domain) |

The rules are deliberately simple regex heuristics, tuned against real libraries (pdf.js, pdf-lib,
mermaid, docx) to keep noise low. They will not catch every payload. Their job is to make sure
that a trusted vendor script gaining clipper/skimmer traits does not go unnoticed for hours.

## Limitations

- **Heuristics, not a sandbox.** Heavily obfuscated payloads can evade the rules, but the content
  change is still reported as info.
- **Targeted payloads.** Code served only to some countries, referrers or real users may not be
  visible to the scanner. It runs real Chromium (not Playwright's headless shell, which announces
  "HeadlessChrome" in its client hints) and presents itself as desktop Chrome, or as iPhone Safari
  with `ios: true`. But it runs from cloud IP addresses, and in iPhone mode it still sends
  Chromium client hints (`Sec-CH-UA`), which real Safari does not.
- **Known traits.** A host that already showed a trait (e.g. a payment SDK reading card fields) can
  change without a high alarm for that same trait. The content change is still listed.
- **Inline and `data:` scripts are ignored.** Only scripts loaded from a URL (including `blob:`) are
  tracked. A `blob:` script whose content differs on every load shows up as new on every run;
  skip those with `ignore: ["blob:"]`.
- **Attribution can be unavailable.** Parser loads, inline scripts and early requests from an
  isolated frame can lack a verifiable external initiator. Their available script bodies still
  receive the usual content checks. If one URL returns multiple bodies, or a body on one request
  and a failed request on another, the scanner reports the ambiguity. It checks available editions
  for content findings and attributes a clipper to a loader only when the child body is identifiable.
  Origin policies still apply to requests with a verified initiator. Load rules honor URL ignore patterns on either end.
- **Baseline moves on.** After an alarm the baseline is updated, so the issue is your record.
  With `commit-baseline: false` you must commit an initial `baseline.json` yourself (e.g. made with
  the CLI), otherwise every run is a first run; the action warns about this.
- **Removed sites are forgotten.** A site you delete from `sites.yml` (or whose `ios: true` you
  remove) is dropped from the baseline at the next update (every Action run, or the CLI with
  `--update-baseline`) and named in the report. If you add it back later, that run is a first run
  for it again.
- **Scheduled workflows** in public repositories are disabled by GitHub after 60 days without
  repository activity. Use a private repo or re-enable the workflow when GitHub asks.
- **Protected branches** block the baseline push; use a branch without protection or a token
  that may push.

## Hardening tips

Monitoring tells you *that* something happened. To limit the damage:

- Restrict `script-src` and `connect-src` in your CSP to the hosts your pages really talk to, so
  injected code cannot load stage 2 or send data to an attacker's domain.
- Send CSP violation reports (`report-to`) somewhere you read them.
- Load payment fields from your payment provider's iframes instead of your own form fields.
- Document an emergency switch-off for every third-party script.

## Development

```bash
npm ci
npx playwright install --no-shell chromium
npm test
```

To verify the issue decision with real Chromium, run the focused Action test. It uses loopback
sites and a local `gh` stand-in. An ordinary vendor update and a new benign origin produce zero
issues. An unknown-domain test script with inert clipper indicators produces one issue with the
loader and child URLs. On the next identical scan the finding stays visible and the issue count
stays at one.

```bash
node --test --test-name-pattern="unknown-domain clipper" test/action.test.js
```

On Windows, the action test needs Git Bash ahead of the WSL `bash.exe` launcher on `PATH`
(PowerShell: `$env:PATH = "C:\Program Files\Git\bin;" + $env:PATH`).
The rule tests and fixtures contain malware-like strings on purpose; antivirus software may
quarantine them.

### Releasing the action

```bash
git tag -a v1.0.0 -m "v1.0.0" && git tag -f v1 && git push origin v1.0.0 && git push -f origin v1
```

## Sources

- [Optimizely's initial customer incident report](https://pages.optimizely.com/rs/947-RKE-048/images/Security%20Incident%20Report%20-%20Optimizely%20Web%20Experimentation%20-%20Nov%2017%202026.pdf)
- [Report URI's investigation and published loader excerpt](https://blog.report-uri.com/worlds-largest-brands-infected-with-malware-via-optimizely/)
- heise online: [Große Marken lieferten Malware-Skript durch Lieferkettenangriff aus](https://www.heise.de/news/Grosse-Marken-lieferten-Malware-Skript-durch-Lieferkettenangriff-aus-11527514.html) (17 Nov 2026)
- The Hacker News: [Hijacked Optimizely Scripts Served Card Skimmer and iOS Exploit Kits](https://thehackernews.com/2026/11/hijacked-optimizely-scripts-served-card.html)
- SOCRadar: [Optimizely Attack Hits Zoom, BBC, CNN With Skimmer, iOS Kits](https://socradar.io/blog/optimizely-attack-hits-zoom-bbc-cnn-with-skimmer-ios-kits/)
- BleepingComputer: [Online ad firm Adform's script compromised to steal cryptocurrency](https://www.bleepingcomputer.com/news/security/online-ad-firm-adforms-script-compromised-to-steal-cryptocurrency/)

## License

MIT, see [LICENSE](LICENSE).
