/**
 * Chaos hunt regression tests (overnight flywheel, 2026-10-22).
 *
 * P-077: a FIFO (named pipe) planted at .github/workflows/pipe.yml hung
 * the audit forever, because workflow discovery opened every .yml or
 * .yaml name without a stat-type check, and opening a FIFO blocks until
 * a writer appears. The same shape applies to a FIFO named action.yml
 * anywhere the composite scan looks. Discovery must skip non-regular
 * files (FIFO, socket, device) by stat type before any open, the way
 * injectcheck stats before opening.
 *
 * P-078: `actionpin audit /nonexistent --json` returned verdict PINNED,
 * total 0, exit 0, so CI wired to a mistyped path went green on nothing.
 * A nonexistent target is a usage error (exit 2, clear stderr, no
 * success verdict), matching hookcheck and injectcheck. A regular-file
 * target keeps single-file audit only for .yml and .yaml files (the
 * README contract: passing an action.yml file path directly parses it);
 * any other regular file is a usage error exit 2. The P-014
 * empty-estate note for a real but empty directory is unchanged.
 *
 * Fixtures only, no network. CLI tests spawn the real CLI with piped
 * stdio, the shape CI actually uses.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { execFileSync, spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { auditWorkflows, buildPinPlan, discoverWorkflows } from "../src/core.js";

const SHA_CHECKOUT = "11d5960a326750d5838078e36cf38b85af677262";
const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

const BENIGN_WORKFLOW = [
  "name: ci",
  "on: [push]",
  "jobs:",
  "  a:",
  "    runs-on: ubuntu-latest",
  "    steps:",
  `      - uses: actions/checkout@${SHA_CHECKOUT}`,
].join("\n") + "\n";

let dir: string;
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "actionpin-chaos-")); });
afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

function writeWorkflow(name: string, content: string): string {
  const wfDir = join(dir, ".github", "workflows");
  mkdirSync(wfDir, { recursive: true });
  const p = join(wfDir, name);
  writeFileSync(p, content, "utf8");
  return p;
}

function mkfifoAt(p: string): void {
  mkdirSync(dirname(p), { recursive: true });
  execFileSync("mkfifo", [p]);
}

interface CliResult { code: number | null; signal: NodeJS.Signals | null; stdout: string; stderr: string }

function runCli(args: string[], timeoutMs = 20000): Promise<CliResult> {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(process.execPath, ["--import", "tsx", "src/cli.ts", ...args], {
      cwd: REPO_ROOT,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "";
    let err = "";
    const timer = setTimeout(() => { child.kill("SIGKILL"); rejectPromise(new Error(`CLI timed out after ${timeoutMs}ms: ${args.join(" ")}`)); }, timeoutMs);
    child.stdout.on("data", (c: Buffer) => { out += c.toString("utf8"); });
    child.stderr.on("data", (c: Buffer) => { err += c.toString("utf8"); });
    child.on("error", (e) => { clearTimeout(timer); rejectPromise(e); });
    child.on("close", (code, signal) => { clearTimeout(timer); resolvePromise({ code, signal, stdout: out, stderr: err }); });
  });
}

describe("P-077: non-regular files are skipped by stat type before any open", () => {
  it("a FIFO in the workflows directory next to a benign workflow completes and audits the benign workflow", { timeout: 20000 }, () => {
    const benign = writeWorkflow("ci.yml", BENIGN_WORKFLOW);
    mkfifoAt(join(dir, ".github", "workflows", "pipe.yml"));
    const r = auditWorkflows(dir);
    assert.equal(r.counts.total, 1);
    assert.equal(r.verdict, "PINNED");
    assert.deepEqual(r.workflows, [benign]);
  });

  it("discoverWorkflows never returns the FIFO", { timeout: 20000 }, () => {
    const benign = writeWorkflow("ci.yml", BENIGN_WORKFLOW);
    mkfifoAt(join(dir, ".github", "workflows", "pipe.yaml"));
    assert.deepEqual(discoverWorkflows(dir), [benign]);
  });

  it("a FIFO named action.yml under .github/actions is skipped, not opened as a composite", { timeout: 20000 }, () => {
    writeWorkflow("ci.yml", BENIGN_WORKFLOW);
    mkfifoAt(join(dir, ".github", "actions", "helper", "action.yml"));
    const r = auditWorkflows(dir);
    assert.equal(r.counts.total, 1);
    assert.equal(r.verdict, "PINNED");
    assert.deepEqual(r.composites, []);
  });

  it("a FIFO at the root action.yml position is skipped, not opened", { timeout: 20000 }, () => {
    writeWorkflow("ci.yml", BENIGN_WORKFLOW);
    mkfifoAt(join(dir, "action.yml"));
    const r = auditWorkflows(dir);
    assert.equal(r.counts.total, 1);
    assert.deepEqual(r.composites, []);
    assert.ok(!r.unscannedComposites || r.unscannedComposites.length === 0, "a FIFO is not a composite file and must not be listed as unscanned");
  });

  it("a FIFO elsewhere in the tree (a referenced local action path) is skipped", { timeout: 20000 }, () => {
    writeWorkflow("ci.yml", "name: ci\njobs:\n  a:\n    steps:\n      - uses: ./.github/actions/helper\n");
    mkfifoAt(join(dir, ".github", "actions", "helper", "action.yml"));
    const r = auditWorkflows(dir);
    assert.equal(r.counts.total, 1);
    assert.equal(r.actions[0].classification, "LOCAL");
    assert.deepEqual(r.composites, []);
  });

  it("the CLI audits a FIFO-bearing tree promptly", { timeout: 30000 }, async () => {
    writeWorkflow("ci.yml", BENIGN_WORKFLOW);
    mkfifoAt(join(dir, ".github", "workflows", "pipe.yml"));
    const res = await runCli(["audit", dir, "--json"]);
    assert.equal(res.code, 0, `expected exit 0, got ${res.code} (stderr: ${res.stderr.slice(0, 200)})`);
    const parsed = JSON.parse(res.stdout) as { verdict: string; counts: { total: number } };
    assert.equal(parsed.verdict, "PINNED");
    assert.equal(parsed.counts.total, 1);
  });
});

describe("P-078: a target that is not an auditable estate is a usage error", () => {
  it("auditWorkflows throws on a nonexistent path", () => {
    assert.throws(() => auditWorkflows(join(dir, "does-not-exist")), /does not exist/i);
  });

  it("buildPinPlan throws on a nonexistent path instead of planning over nothing", async () => {
    await assert.rejects(
      () => buildPinPlan(join(dir, "does-not-exist"), async () => { throw new Error("fetch must not run"); }),
      /does not exist/i,
    );
  });

  it("the CLI exits 2 on a nonexistent path, with a stderr message and no verdict on stdout", { timeout: 30000 }, async () => {
    const missing = join(dir, "does-not-exist");
    const res = await runCli(["audit", missing, "--json"]);
    assert.equal(res.code, 2, `expected exit 2, got ${res.code} (stdout: ${res.stdout.slice(0, 200)})`);
    assert.match(res.stderr, /does not exist/i);
    assert.doesNotMatch(res.stdout, /PINNED/);
  });

  it("the fix command exits 2 on a nonexistent path too", { timeout: 30000 }, async () => {
    const res = await runCli(["fix", join(dir, "does-not-exist"), "--dry-run", "--json"]);
    assert.equal(res.code, 2, `expected exit 2, got ${res.code} (stdout: ${res.stdout.slice(0, 200)})`);
    assert.match(res.stderr, /does not exist/i);
  });

  it("auditWorkflows throws on a regular file that is not a workflow file", () => {
    const p = join(dir, "package.json");
    writeFileSync(p, '{"name":"x"}\n', "utf8");
    assert.throws(() => auditWorkflows(p), /not a workflow file|\.yml/i);
  });

  it("the CLI exits 2 on a .json file target, with a clear message and no verdict", { timeout: 30000 }, async () => {
    const p = join(dir, "package.json");
    writeFileSync(p, '{"name":"x"}\n', "utf8");
    const res = await runCli(["audit", p, "--json"]);
    assert.equal(res.code, 2, `expected exit 2, got ${res.code} (stdout: ${res.stdout.slice(0, 200)})`);
    assert.match(res.stderr, /\.yml|workflow file/i);
    assert.doesNotMatch(res.stdout, /PINNED/);
  });

  it("a FIFO as the direct audit target is a usage error, not a hang", { timeout: 30000 }, async () => {
    const fifo = join(dir, "pipe.yml");
    mkfifoAt(fifo);
    const res = await runCli(["audit", fifo, "--json"]);
    assert.equal(res.code, 2, `expected exit 2, got ${res.code} (stdout: ${res.stdout.slice(0, 200)})`);
  });

  it("a single .yml workflow file target still audits (kept behavior)", { timeout: 30000 }, async () => {
    const p = writeWorkflow("solo.yml", "      - uses: actions/checkout@v4\n");
    const r = auditWorkflows(p);
    assert.equal(r.counts.total, 1);
    assert.equal(r.verdict, "PARTIAL");
    const res = await runCli(["audit", p, "--json"]);
    assert.equal(res.code, 1);
    const parsed = JSON.parse(res.stdout) as { verdict: string; counts: { total: number } };
    assert.equal(parsed.verdict, "PARTIAL");
    assert.equal(parsed.counts.total, 1);
  });

  it("a single .yaml action file target still audits (kept behavior)", () => {
    const p = join(dir, "action.yaml");
    writeFileSync(p, "name: x\nruns:\n  using: composite\n  steps:\n    - uses: evil-corp/tool@v1\n", "utf8");
    const r = auditWorkflows(p);
    assert.equal(r.counts.total, 1);
    assert.equal(r.verdict, "EXPOSED");
  });

  it("an empty directory still gets the P-014 note with its current exit behavior", { timeout: 30000 }, async () => {
    const res = await runCli(["audit", dir, "--json"]);
    assert.equal(res.code, 0, `expected exit 0, got ${res.code} (stderr: ${res.stderr.slice(0, 200)})`);
    const parsed = JSON.parse(res.stdout) as { verdict: string; counts: { total: number }; note?: string };
    assert.equal(parsed.verdict, "PINNED");
    assert.equal(parsed.counts.total, 0);
    assert.match(parsed.note ?? "", /no workflows found/i);
  });
});
