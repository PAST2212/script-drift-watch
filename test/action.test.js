// Verifies action.yml: structure, injection-safety, and that its shell steps
// really work (scan → commit baseline → open issue → fail) against a local
// site, a local bare git remote and a fake `gh` binary.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, readFile, writeFile, chmod, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, delimiter } from "node:path";
import { fileURLToPath } from "node:url";
import YAML from "yaml";

const exec = promisify(execFile);
const ROOT = fileURLToPath(new URL("..", import.meta.url));
const action = YAML.parse(await readFile(join(ROOT, "action.yml"), "utf8"));
const workflow = YAML.parse(await readFile(join(ROOT, "examples/workflow.yml"), "utf8"));
const step = (id) => action.runs.steps.find((s) => s.id === id);

test("action.yml is a composite action with the documented inputs", () => {
  assert.equal(action.runs.using, "composite");
  for (const name of ["config", "baseline", "args", "open-issue", "fail-on-high", "commit-baseline", "node-version", "token"]) {
    assert.ok(action.inputs[name], `missing input ${name}`);
  }
  assert.ok(action.outputs["exit-code"]);
});

test("every run step declares bash and never interpolates ${{ }} into the script (injection-safe)", () => {
  for (const s of action.runs.steps.filter((s) => s.run)) {
    assert.equal(s.shell, "bash", s.name);
    assert.ok(!s.run.includes("${{"), `expression inside run: of "${s.name}"`);
  }
});

test("example workflow only uses inputs that exist and grants the needed permissions", () => {
  const job = Object.values(workflow.jobs)[0];
  const use = job.steps.find((s) => String(s.uses).includes("script-drift-watch"));
  for (const key of Object.keys(use.with ?? {})) assert.ok(action.inputs[key], `unknown input ${key}`);
  assert.equal(workflow.permissions.contents, "write");
  assert.equal(workflow.permissions.issues, "write");
  assert.ok(workflow.on.schedule?.[0]?.cron);
});

// ---- simulate a run on a GitHub runner -------------------------------------
let server, base, ws, remote, ghLog, envBase;
let exp = "harmless";

before(async () => {
  server = http.createServer(async (req, res) => {
    const path = new URL(req.url, "http://x").pathname;
    const file = path === "/" ? "site/index.html"
      : path === "/exp.js" && exp === "clipper" ? "clipper.js" : `site${path}`;
    // Read before writing headers: a missing file (e.g. the /favicon.ico real Chromium asks for)
    // must become a clean 404, not a second writeHead.
    let body;
    try { body = await readFile(join(ROOT, "fixtures", file)); } catch { return res.writeHead(404).end(); }
    res.writeHead(200, { "content-type": file.endsWith(".html") ? "text/html" : "text/javascript" });
    res.end(body);
  });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${server.address().port}/`;

  const tmp = await mkdtemp(join(tmpdir(), "sdw-action-"));
  remote = join(tmp, "remote.git");
  ws = join(tmp, "ws");
  const bin = join(tmp, "bin");
  ghLog = join(tmp, "gh.log");
  await exec("git", ["init", "-q", "--bare", "-b", "main", remote]);
  await exec("git", ["init", "-q", "-b", "main", ws]);
  await writeFile(join(ws, "sites.yml"), `sites:\n  - url: ${base}\n`);
  const git = (...a) => exec("git", ["-C", ws, ...a]);
  await git("-c", "user.name=t", "-c", "user.email=t@t", "add", ".");
  await git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q", "-m", "init");
  await git("remote", "add", "origin", remote);
  await git("push", "-q", "-u", "origin", "main");
  await mkdir(bin);
  await writeFile(join(bin, "gh"), `#!/bin/bash\nprintf '%s\\n' "$@" >> "${ghLog}"\nprintf 'GH_TOKEN=%s\\n' "$GH_TOKEN" >> "${ghLog}"\n`);
  await chmod(join(bin, "gh"), 0o755);
  await mkdir(join(tmp, "runner"));
  envBase = {
    ...process.env,
    PATH: `${bin}${delimiter}${process.env.PATH}`, // ";" on Windows (Git Bash), ":" elsewhere
    GITHUB_ACTION_PATH: ROOT,
    RUNNER_TEMP: join(tmp, "runner"),
    GITHUB_OUTPUT: join(tmp, "runner", "output"),
    GITHUB_STEP_SUMMARY: join(tmp, "runner", "summary"),
  };
});
after(() => server?.close());

const ctx = (outputs) => ({
  "inputs.commit-baseline": "true",
  "inputs.config": "sites.yml", "inputs.baseline": "baseline.json", "inputs.token": "tok123", "inputs.args": "--settle-ms 300 --timeout-ms 10000",
  "github.repository": "owner/site", "steps.scan.outputs.exit-code": outputs["exit-code"],
  "steps.scan.outputs.report": outputs.report,
});
const evalExpr = (v, c) => String(v).replace(/\$\{\{\s*([\w.-]+)\s*\}\}/g, (_, k) => c[k] ?? "");

let lastStdout = "";
async function runStep(id, outputs = {}, extraCtx = {}) {
  const s = step(id);
  const env = { ...envBase };
  for (const [k, v] of Object.entries(s.env ?? {})) env[k] = evalExpr(v, { ...ctx(outputs), ...extraCtx });
  try {
    ({ stdout: lastStdout } = await exec("bash", ["--noprofile", "--norc", "-eo", "pipefail", "-c", s.run], { cwd: ws, env }));
    return 0;
  } catch (e) { lastStdout = e.stdout ?? ""; return e.code; }
}
async function outputs() {
  const text = await readFile(envBase.GITHUB_OUTPUT, "utf8").catch(() => "");
  return Object.fromEntries(text.trim().split("\n").filter(Boolean).map((l) => l.split(/=(.*)/s).slice(0, 2)));
}

test("first scheduled run: scan succeeds and the baseline is committed and pushed", async () => {
  assert.equal(await runStep("scan"), 0);
  const out = await outputs();
  assert.equal(out["exit-code"], "0");
  assert.match(await readFile(envBase.GITHUB_STEP_SUMMARY, "utf8"), /baseline created/i);
  assert.equal(await runStep("commit"), 0);
  const { stdout } = await exec("git", ["--git-dir", remote, "log", "--oneline", "-1", "--", "baseline.json"]);
  assert.match(stdout, /baseline/i);
});

test("compromised vendor script: exit-code 2, issue opened with token, step fails", async () => {
  exp = "clipper";
  await writeFile(envBase.GITHUB_OUTPUT, "");
  assert.equal(await runStep("scan"), 0, "scan step itself must not fail, so commit/issue still run");
  const out = await outputs();
  assert.equal(out["exit-code"], "2");
  assert.equal(await runStep("commit", out), 0);
  assert.equal(await runStep("issue", out), 0);
  const log = await readFile(ghLog, "utf8");
  assert.match(log, /issue\ncreate/);
  assert.match(log, /--body-file/);
  assert.match(log, /GH_TOKEN=tok123/);
  assert.notEqual(await runStep("fail", out), 0);
});

test("the action's if-conditions gate issue and fail on exit-code 2", () => {
  assert.match(step("issue").if, /steps\.scan\.outputs\.exit-code\s*==\s*'2'/);
  assert.match(step("issue").if, /inputs\.open-issue\s*==\s*'true'/);
  assert.match(step("fail").if, /steps\.scan\.outputs\.exit-code\s*==\s*'2'/);
  assert.match(step("commit").if, /inputs\.commit-baseline\s*==\s*'true'/);
});

// ---- Final review fixes --------------------------------------------------
test("I5: the issue is opened before the baseline push, and issue/fail survive a failed push", () => {
  const ids = action.runs.steps.map((s) => s.id);
  assert.ok(ids.indexOf("issue") < ids.indexOf("commit"), ids.join());
  assert.match(step("issue").if, /!cancelled\(\)/);
  assert.match(step("fail").if, /!cancelled\(\)/);
});

test("I5: a failed baseline push is reported as an error, not silently ignored", async () => {
  await writeFile(join(ws, "baseline.json"), "{}\n");
  await exec("git", ["-C", ws, "remote", "set-url", "origin", "/nonexistent/remote.git"]);
  try {
    assert.notEqual(await runStep("commit"), 0);
    assert.match(lastStdout, /::error::.*push/i);
  } finally {
    await exec("git", ["-C", ws, "remote", "set-url", "origin", remote]);
    await exec("git", ["-C", ws, "reset", "-q", "--hard", "origin/main"]);
  }
});

test("I6: with commit-baseline false and no baseline, the scan warns that monitoring cannot start", async () => {
  const saved = await readFile(join(ws, "baseline.json"), "utf8");
  await exec("git", ["-C", ws, "rm", "-q", "baseline.json"]);
  try {
    assert.equal(await runStep("scan", {}, { "inputs.commit-baseline": "false" }), 0);
    assert.match(lastStdout, /::warning::.*baseline/i);
  } finally {
    await exec("git", ["-C", ws, "reset", "-q", "--hard", "origin/main"]);
    assert.equal(await readFile(join(ws, "baseline.json"), "utf8"), saved);
  }
});

test("M2: the echoed report cannot inject workflow commands (stop-commands wrapper)", async () => {
  await runStep("scan");
  const m = lastStdout.match(/::stop-commands::([A-Za-z0-9]{16,})/);
  assert.ok(m, "no stop-commands token");
  const start = lastStdout.indexOf(m[0]);
  const end = lastStdout.indexOf(`::${m[1]}::`);
  const report = lastStdout.indexOf("Script Drift Watch report");
  assert.ok(start < report && report < end, "report not inside the stop-commands block");
});

test("an invalid sites.yml fails the scan step and the job summary says why", async () => {
  await writeFile(join(ws, "sites.yml"), "sites:\n  - url: www.example.com\n");
  await writeFile(envBase.GITHUB_STEP_SUMMARY, "");
  try {
    assert.notEqual(await runStep("scan"), 0);
    const summary = await readFile(envBase.GITHUB_STEP_SUMMARY, "utf8");
    assert.match(summary, /did not run/i);
    assert.match(summary, /line 2, sites\[0\]/);
  } finally {
    await exec("git", ["-C", ws, "checkout", "-q", "--", "sites.yml"]);
  }
});

test("package.json engines claims only Node versions that CI tests", async () => {
  const pkg = JSON.parse(await readFile(join(ROOT, "package.json"), "utf8"));
  const ci = YAML.parse(await readFile(join(ROOT, ".github/workflows/test.yml"), "utf8"));
  const tested = Object.values(ci.jobs).flatMap((j) => j.strategy?.matrix?.node ?? []).map(Number);
  assert.ok(tested.length, "no Node version matrix in .github/workflows/test.yml");
  assert.equal(pkg.engines.node, `>=${Math.min(...tested)}`);
});

test("CI installs dependencies without lifecycle scripts too, like the action", async () => {
  const ci = YAML.parse(await readFile(join(ROOT, ".github/workflows/test.yml"), "utf8"));
  const installs = Object.values(ci.jobs).flatMap((j) => j.steps ?? []).map((s) => s.run ?? "").filter((r) => /\bnpm (ci|install)\b/.test(r));
  assert.ok(installs.length, "no npm install step in .github/workflows/test.yml");
  for (const r of installs) assert.match(r, /npm ci\b[^\n]*--ignore-scripts/, r);
});

test("I7: runtime dependencies are pinned exactly, locked with integrity hashes, and installed with npm ci without lifecycle scripts", async () => {
  const pkg = JSON.parse(await readFile(join(ROOT, "package.json"), "utf8"));
  const lock = JSON.parse(await readFile(join(ROOT, "package-lock.json"), "utf8"));
  for (const [name, range] of Object.entries(pkg.dependencies)) {
    assert.match(range, /^\d+\.\d+\.\d+$/, name);
    const locked = lock.packages?.[`node_modules/${name}`];
    assert.equal(locked?.version, range, `${name} in package-lock.json`);
    assert.match(locked?.integrity ?? "", /^sha512-/, `${name} integrity`);
  }
  assert.match(step("install").run, /npm ci\b[^\n]*--ignore-scripts/);
});
