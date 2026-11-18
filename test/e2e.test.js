// End-to-end: real HTTP server + real Chromium via the CLI.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const run = promisify(execFile);
const BIN = fileURLToPath(new URL("../bin/script-drift-watch.js", import.meta.url));
const SITE_DIR = new URL("../fixtures/site/", import.meta.url);
const CLIPPER = new URL("../fixtures/clipper.js", import.meta.url);

let server;
let base;
let dir;
const overrides = new Map(); // path -> file URL to serve instead

before(async () => {
  server = http.createServer(async (req, res) => {
    const path = new URL(req.url, "http://x").pathname;
    const name = path === "/" ? "index.html" : path.slice(1);
    try {
      const body = await readFile(overrides.get(path) ?? new URL(name, SITE_DIR));
      res.writeHead(200, { "content-type": name.endsWith(".html") ? "text/html" : "text/javascript" });
      res.end(body);
    } catch {
      res.writeHead(404).end();
    }
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${server.address().port}/`;
  dir = await mkdtemp(join(tmpdir(), "sdw-e2e-"));
  await writeFile(
    join(dir, "sites.yml"),
    `sites:\n  - url: ${base}\n  - url: http://127.0.0.1:1/\n`,
  );
});

after(() => server?.close());

async function cli(...extra) {
  const args = [BIN, "--config", join(dir, "sites.yml"), "--baseline", join(dir, "baseline.json"),
    "--report", join(dir, "report.md"), "--settle-ms", "300", "--timeout-ms", "10000", ...extra];
  try {
    await run(process.execPath, args);
    return 0;
  } catch (e) {
    if (typeof e.code !== "number") throw e;
    return e.code;
  }
}

test("first run creates a baseline including dynamically loaded scripts", async () => {
  assert.equal(await cli("--update-baseline"), 0);
  const baseline = JSON.parse(await readFile(join(dir, "baseline.json"), "utf8"));
  const keys = Object.keys(baseline.sites[base].scripts);
  assert.ok(keys.includes(`${base}vendor.js`), keys.join());
  assert.ok(keys.includes(`${base}exp.js`), "dynamically injected exp.js missing: " + keys.join());
  assert.equal(keys.length, 3, "inline scripts must be ignored: " + keys.join());
  assert.match(await readFile(join(dir, "report.md"), "utf8"), /baseline created/i);
});

test("swapping the experiment code for a clipper raises a high alarm (exit 2)", async () => {
  overrides.set("/exp.js", CLIPPER);
  assert.equal(await cli("--update-baseline"), 2);
  const report = await readFile(join(dir, "report.md"), "utf8");
  assert.match(report, /clipboard-hijack/);
  assert.match(report, /exp\.js/);
});

test("an unreachable site is reported as an error without stopping the run", async () => {
  const report = await readFile(join(dir, "report.md"), "utf8");
  assert.match(report, /127\.0\.0\.1:1/);
  assert.match(report, /Could not scan/);
});

test("after the baseline was updated, the same state is quiet again", async () => {
  assert.equal(await cli("--update-baseline"), 0);
  assert.match(await readFile(join(dir, "report.md"), "utf8"), /No changes/);
});

test("without --update-baseline the baseline file is left untouched", async () => {
  overrides.delete("/exp.js");
  const before = await readFile(join(dir, "baseline.json"), "utf8");
  await cli();
  assert.equal(await readFile(join(dir, "baseline.json"), "utf8"), before);
});

// Final review I3: an unchanged site must not rewrite the baseline (no hourly commits).
test("repeated runs on an unchanged site leave baseline.json byte-identical", async () => {
  overrides.delete("/exp.js");
  await cli("--update-baseline");
  const first = await readFile(join(dir, "baseline.json"), "utf8");
  await cli("--update-baseline");
  assert.equal(await readFile(join(dir, "baseline.json"), "utf8"), first);
});

// ---- Open review points: baseline lifecycle (own temp dirs, harmless experiment code) ----
async function cliIn(d, sites, ...extra) {
  await writeFile(join(d, "sites.yml"), `sites:\n${sites.map((u) => `  - url: ${u}\n`).join("")}`);
  try {
    await run(process.execPath, [BIN, "--config", join(d, "sites.yml"), "--baseline", join(d, "baseline.json"),
      "--report", join(d, "report.md"), "--settle-ms", "300", "--timeout-ms", "10000", ...extra]);
    return 0;
  } catch (e) {
    if (typeof e.code !== "number") throw e;
    return e.code;
  }
}
const baselineSites = async (d) => Object.keys(JSON.parse(await readFile(join(d, "baseline.json"), "utf8")).sites).sort();

test("a site added to sites.yml is recorded even without --update-baseline", async () => {
  overrides.clear();
  const d = await mkdtemp(join(tmpdir(), "sdw-e2e-add-"));
  assert.equal(await cliIn(d, [base], "--update-baseline"), 0);
  assert.equal(await cliIn(d, [base, `${base}index.html`]), 0);
  assert.deepEqual(await baselineSites(d), [base, `${base}index.html`]);
});

test("with --update-baseline a site removed from sites.yml is dropped and named in the report", async () => {
  overrides.clear();
  const d = await mkdtemp(join(tmpdir(), "sdw-e2e-prune-"));
  assert.equal(await cliIn(d, [base, `${base}index.html`], "--update-baseline"), 0);
  assert.equal(await cliIn(d, [`${base}index.html`], "--update-baseline"), 0);
  assert.deepEqual(await baselineSites(d), [`${base}index.html`]);
  const report = await readFile(join(d, "report.md"), "utf8");
  assert.match(report, /no longer in sites\.yml/i);
  assert.ok(report.includes(`\`${base}\``), report);
});

// ---- Open review point: blob: scripts ----
test("a runtime-generated blob: script keeps one identity, so the second run is quiet", async () => {
  overrides.clear();
  const d = await mkdtemp(join(tmpdir(), "sdw-e2e-blob-"));
  assert.equal(await cliIn(d, [`${base}blob.html`], "--update-baseline"), 0);
  const first = await readFile(join(d, "baseline.json"), "utf8");
  assert.ok(Object.keys(JSON.parse(first).sites[`${base}blob.html`].scripts).some((k) => k.startsWith("blob:")), first);
  assert.equal(await cliIn(d, [`${base}blob.html`], "--update-baseline"), 0);
  assert.match(await readFile(join(d, "report.md"), "utf8"), /No changes/);
  assert.equal(await readFile(join(d, "baseline.json"), "utf8"), first);
});

test("a blob: script talking to its own page origin is not an exfil-sink", async () => {
  overrides.clear();
  const d = await mkdtemp(join(tmpdir(), "sdw-e2e-blobhost-"));
  assert.equal(await cliIn(d, [`${base}blob.html`], "--update-baseline"), 0);
  assert.doesNotMatch(await readFile(join(d, "report.md"), "utf8"), /exfil-sink/);
});

// Final review I1: the clipper host is now known; the same trait returning is info, not an alarm.
test("a trait the host already showed does not alarm again", async () => {
  overrides.set("/exp.js", CLIPPER);
  assert.equal(await cli("--update-baseline"), 0);
  assert.match(await readFile(join(dir, "report.md"), "utf8"), /Known traits for this host/);
});
