/**
 * Pipe regression tests for P-001 (and the P-014 empty-estate note).
 *
 * P-001: `actionpin audit --json` with stdout attached to a pipe truncated
 * the report at exactly 65,536 bytes and still exited 0, because the CLI
 * called process.exit() immediately after console.log() and exit does not
 * wait for a piped stream to drain. File redirection flushed fully, which
 * is why the bug only shows up for the consumers that matter most: agents,
 * scripts, and CI reading through pipes.
 *
 * These tests spawn the real CLI with piped stdio, the exact shape that
 * failed, and assert on the bytes that come through the pipe.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { auditWorkflows, buildPinPlan, renderReport } from "../src/core.js";
import type { FetchFn } from "../src/types.js";

const SHA = "0123456789abcdef0123456789abcdef01234567";
const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

let dir: string;
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "actionpin-pipe-")); });
afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

/** A large estate of fully pinned actions: 24 files x 40 steps = 960 actions. */
function writeBigPinnedRepo(root: string): void {
  const wfDir = join(root, ".github", "workflows");
  mkdirSync(wfDir, { recursive: true });
  for (let f = 0; f < 24; f++) {
    const lines = [`name: big-${f}`, "on: [push]", "jobs:"];
    for (let j = 0; j < 40; j++) {
      lines.push(`  job${j}:`);
      lines.push("    runs-on: ubuntu-latest");
      lines.push("    steps:");
      lines.push(`      - uses: actions/checkout@${SHA} # v4`);
    }
    writeFileSync(join(wfDir, `wf${String(f).padStart(2, "0")}.yml`), lines.join("\n") + "\n", "utf8");
  }
}

interface CliResult {
  code: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
}

function runCli(args: string[], opts: { destroyStdoutOnFirstChunk?: boolean } = {}): Promise<CliResult> {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(process.execPath, ["--import", "tsx", "src/cli.ts", ...args], {
      cwd: REPO_ROOT,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let out = "";
    let err = "";
    const timer = setTimeout(() => { child.kill("SIGKILL"); rejectPromise(new Error("CLI timed out")); }, 60000);
    child.stdout.on("data", (c: Buffer) => {
      out += c.toString("utf8");
      if (opts.destroyStdoutOnFirstChunk) child.stdout.destroy();
    });
    child.stderr.on("data", (c: Buffer) => { err += c.toString("utf8"); });
    child.on("error", (e) => { clearTimeout(timer); rejectPromise(e); });
    child.on("close", (code, signal) => { clearTimeout(timer); resolvePromise({ code, signal, stdout: out, stderr: err }); });
  });
}

describe("P-001: piped output is delivered whole", () => {
  it("piped --json audit over 200 KiB parses and matches the in-process counts", { timeout: 90000 }, async () => {
    writeBigPinnedRepo(dir);
    const direct = auditWorkflows(dir);
    const directJson = JSON.stringify(direct, null, 2);
    assert.ok(directJson.length > 200_000, `fixture must exceed 200 KiB of JSON, got ${directJson.length}`);
    assert.ok(direct.counts.total >= 900, `fixture must hold 900+ actions, got ${direct.counts.total}`);

    const res = await runCli(["audit", dir, "--json"]);
    assert.equal(res.code, 0, `expected exit 0, got ${res.code} (stderr: ${res.stderr.slice(0, 200)})`);
    assert.equal(res.stdout.length, directJson.length + 1, "piped bytes must equal the full report plus the trailing newline, not a 64 KiB prefix");
    const parsed = JSON.parse(res.stdout) as { counts: { total: number }; actions: unknown[]; verdict: string };
    assert.equal(parsed.counts.total, direct.counts.total);
    assert.equal(parsed.actions.length, direct.actions.length);
    assert.equal(parsed.verdict, direct.verdict);
  });

  it("piped human audit output is not truncated", { timeout: 90000 }, async () => {
    writeBigPinnedRepo(dir);
    const direct = auditWorkflows(dir);
    const expected = renderReport(direct) + "\n";
    assert.ok(expected.length > 65_536, `human fixture must exceed one pipe buffer, got ${expected.length}`);

    const res = await runCli(["audit", dir]);
    assert.equal(res.code, 0);
    assert.equal(res.stdout, expected);
    assert.ok(res.stdout.trimEnd().endsWith("PINNED: every non-local action is pinned to a full commit SHA."));
  });

  it("piped fix --dry-run --json on a large pinned estate is complete", { timeout: 90000 }, async () => {
    writeBigPinnedRepo(dir);
    const noNetwork: FetchFn = async () => { throw new Error("network must not be used for already-pinned actions"); };
    const plan = await buildPinPlan(dir, noNetwork);
    assert.equal(plan.entries.length, auditWorkflows(dir).counts.total);

    const res = await runCli(["fix", dir, "--dry-run", "--json"]);
    assert.equal(res.code, 0, `expected exit 0, got ${res.code} (stderr: ${res.stderr.slice(0, 200)})`);
    const parsed = JSON.parse(res.stdout) as { entries: unknown[]; changes: number };
    assert.equal(parsed.entries.length, plan.entries.length);
    assert.equal(parsed.changes, 0);
  });

  it("piped verdict exit code survives on a failing (mutable) estate", { timeout: 90000 }, async () => {
    const wfDir = join(dir, ".github", "workflows");
    mkdirSync(wfDir, { recursive: true });
    writeFileSync(join(wfDir, "ci.yml"), "      - uses: actions/checkout@v4\n", "utf8");
    const res = await runCli(["audit", dir, "--json"]);
    assert.equal(res.code, 1);
    const parsed = JSON.parse(res.stdout) as { verdict: string };
    assert.equal(parsed.verdict, "PARTIAL");
  });

  it("a reader that closes the pipe early never sees a success exit", { timeout: 90000 }, async () => {
    writeBigPinnedRepo(dir);
    const res = await runCli(["audit", dir, "--json"], { destroyStdoutOnFirstChunk: true });
    // Implemented behavior: the writer dies the way a Unix writer dies on
    // SIGPIPE, surfaced as exit code 141 (128 + 13), or the process is
    // killed by SIGPIPE itself. Exit 0 with undelivered output is the bug.
    assert.notEqual(res.code, 0, "exit 0 means success was reported for output that was never delivered");
    assert.ok(res.signal === "SIGPIPE" || res.code === 141, `expected SIGPIPE or exit 141, got code ${res.code} signal ${res.signal}`);
  });
});

describe("P-014: an estate with no workflows says so plainly", () => {
  it("in-process report carries a no-workflows note when discovery finds nothing", () => {
    const r = auditWorkflows(dir);
    assert.equal(r.workflows.length, 0);
    assert.match(r.note ?? "", /no workflows found/i);
    assert.match(renderReport(r), /no workflows found/i);
  });

  it("CLI JSON and human output both state that no workflows were found", { timeout: 90000 }, async () => {
    const json = await runCli(["audit", dir, "--json"]);
    const parsed = JSON.parse(json.stdout) as { note?: string };
    assert.match(parsed.note ?? "", /no workflows found/i);
    const human = await runCli(["audit", dir]);
    assert.match(human.stdout, /no workflows found/i);
  });

  it("a repo with workflows carries no empty-estate note", () => {
    const wfDir = join(dir, ".github", "workflows");
    mkdirSync(wfDir, { recursive: true });
    writeFileSync(join(wfDir, "ci.yml"), `      - uses: actions/checkout@${SHA}\n`, "utf8");
    const r = auditWorkflows(dir);
    assert.equal(r.note, undefined);
  });
});
