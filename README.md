# script-drift-watch

**Get an alert when a trusted third-party script on your website suddenly starts stealing.**

On 16 November 2026, attackers abused Optimizely Web Experimentation to push a card skimmer,
a crypto clipper and iOS exploit kits through the official Optimizely snippet. Report URI found the
injected code in snippets belonging to 178 organisations ([sources](#sources)). In July 2026,
Adform's tracking script was turned into a crypto clipper the same way.

In both cases the malicious code came **from the vendor's own, allow-listed domain with a valid
certificate**. A Content Security Policy that allows the vendor did not help, and per-customer
snippets that change all the time cannot be pinned with Subresource Integrity.

What *did* change was the script's content and behaviour. `script-drift-watch` watches exactly that:

1. Loads your pages in real headless Chromium (so runtime-injected scripts from A/B testing tools
   and tag managers are included). Optionally a second time as an iPhone.
2. Hashes every external script and compares it to a baseline stored in your repository.
3. Checks new or changed scripts for clipper, skimmer and loader traits.
4. Opens a GitHub issue (and fails the job) when a script host **gains** a high-severity trait
   it never showed before.

No server, no account, nothing sent to third parties. It runs as a scheduled GitHub Action in your own repo.

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
without `https://`, or the same page listed twice.

**2.** Add `.github/workflows/script-drift-watch.yml`:

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
commits `baseline.json` and records the traits each script host already has (only known IoCs
alarm on the first run). From then on every run compares against it.

When something suspicious shows up, you get an issue (GitHub e-mails you) and the job summary
shows the script URL, the rule that fired and a short code excerpt.

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
| `--update-baseline` | off | Write the current state as the new baseline and drop sites that are no longer in the sites file. Without it, existing entries are never changed; only sites scanned for the first time are added |
| `--timeout-ms` | `30000` | Page load timeout |
| `--settle-ms` | `3000` | Extra wait for late-loading scripts |

Exit codes: `0` nothing or only informational/medium findings, `2` new high-severity finding, `1` error
(for an invalid sites file or baseline, the report explains the problem).
A site that cannot be loaded (network error or non-2xx status) keeps its old baseline and is
counted in the report headline, but does not change the exit code. A page that never finishes
loading is still scanned with the scripts that did load.

Script identity is the URL without the fragment and without common cache-buster parameters
(`v`, `t`, `_`, `cb`, `ts`, `rev`, …). Other parameters such as `gtag/js?id=G-…` stay part of the
identity. Scripts created at runtime from `blob:` URLs get a random URL on every load, so they are
identified by their page's origin and content hash instead (`blob:https://shop.example/sha256-…`),
and their traits count for the page's host. The baseline file is written in a canonical order, so
it only changes when your scripts do.

## Rules

Only **new or changed** scripts are checked. A finding alarms only if the script's host never showed
that trait before, so a payment SDK update that still reads card fields, or a new hashed bundle from
your own domain, is listed as "known trait" info instead of opening an issue. `known-ioc` always alarms.
A changed script without findings is listed as info.

| Rule | Severity | Fires when a script… |
|---|---|---|
| `clipboard-hijack` | high | accesses the clipboard **and** contains wallet addresses / wallet regexes |
| `obfuscated-loader` | high | runs base64-decoded code (`atob` close to `eval` / `new Function`, also `(0,eval)(…)`, `window["eval"](…)` and `setTimeout(atob(…))`) |
| `card-field-access` | high | names card fields in strings, selectors or regexes (`"cc-number"`, `[name=cardnumber]`, `/cvv\|cvc/`, …), not mere identifiers like `new Cvc()` |
| `input-value-hook` | high | hooks the `value` property of `HTMLInputElement` |
| `known-ioc` | high | contains a published IoC (`1688360.cc`, Adform C2 IP) |
| `clipboard-access` | medium | reads or writes the clipboard (Clipboard API, copy/cut/paste events, `execCommand("copy")`) |
| `wallet-pattern` | medium | contains a BTC/ETH/TRON address or an ETH address regex |
| `ios-only-branch` | medium | branches on iPhone/iPad user agents |
| `exfil-sink` | medium | sends data to / loads code from a different registrable domain (each tenant of shared hosts such as `cloudfront.net` or `workers.dev` counts as its own domain) |

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

Tests are written test-first with `node:test`: unit tests for the rules, diff and report, an end-to-end
test with a local site and real Chromium, and a test that runs the action's shell steps against a
local git remote and a fake `gh`.

On Windows, the action test needs Git Bash ahead of the WSL `bash.exe` launcher on `PATH`
(PowerShell: `$env:PATH = "C:\Program Files\Git\bin;" + $env:PATH`).
The rule tests and fixtures contain malware-like strings on purpose; antivirus software may
quarantine them.

### Releasing the action

```bash
git tag -a v1.0.0 -m "v1.0.0" && git tag -f v1 && git push origin v1.0.0 && git push -f origin v1
```

## Sources

- heise online: [Große Marken lieferten Malware-Skript durch Lieferkettenangriff aus](https://www.heise.de/news/Grosse-Marken-lieferten-Malware-Skript-durch-Lieferkettenangriff-aus-11527514.html) (17 Nov 2026)
- The Hacker News: [Hijacked Optimizely Scripts Served Card Skimmer and iOS Exploit Kits](https://thehackernews.com/2026/11/hijacked-optimizely-scripts-served-card.html)
- SOCRadar: [Optimizely Attack Hits Zoom, BBC, CNN With Skimmer, iOS Kits](https://socradar.io/blog/optimizely-attack-hits-zoom-bbc-cnn-with-skimmer-ios-kits/)
- BleepingComputer: [Online ad firm Adform's script compromised to steal cryptocurrency](https://www.bleepingcomputer.com/news/security/online-ad-firm-adforms-script-compromised-to-steal-cryptocurrency/)

## License

MIT, see [LICENSE](LICENSE).
