/**
 * Adversarial hardening battery for actionpin.
 * Written against v0.1.0 behavior expectations first; every case here is a
 * shape or ref seen in real workflows. Fixtures only, no network: fetch is
 * always injected.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import {
  applyPinPlan,
  auditWorkflows,
  buildPinPlan,
  classifyRef,
  parseUsesLine,
  parseWorkflowContent,
} from "../src/core.js";
import type { FetchFn, FetchResponse } from "../src/types.js";

const SHA_A = "a".repeat(40);
const SHA_B = "0123456789abcdef0123456789abcdef01234567";
const SHA_C = "f".repeat(40);
const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

function jsonRes(status: number, body: unknown): FetchResponse {
  return { ok: status >= 200 && status < 300, status, json: async () => body, text: async () => JSON.stringify(body) };
}

function fixtureFetch(map: Record<string, string>): FetchFn {
  return async (url: string) => {
    for (const [needle, sha] of Object.entries(map)) {
      if (url.includes(needle)) return jsonRes(200, { object: { sha, type: "commit" } });
    }
    return jsonRes(404, { message: "not found" });
  };
}

let dir: string;
function writeWorkflow(name: string, content: string): string {
  const wfDir = join(dir, ".github", "workflows");
  mkdirSync(wfDir, { recursive: true });
  const p = join(wfDir, name);
  writeFileSync(p, content, "utf8");
  return p;
}
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "actionpin-hard-")); });
afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

describe("hardening: YAML shapes", () => {
  it("parses a single-quoted uses value", () => {
    const p = parseUsesLine("      - uses: 'actions/checkout@v4'");
    assert.equal(p?.action, "actions/checkout");
    assert.equal(p?.ref, "v4");
  });
  it("parses uses with extra spaces before the value", () => {
    const p = parseUsesLine("      - uses:    actions/setup-node@v4");
    assert.equal(p?.action, "actions/setup-node");
    assert.equal(p?.ref, "v4");
  });
  it("parses uses with an inline trailing comment and keeps the ref clean", () => {
    const refs = parseWorkflowContent("      - uses: actions/checkout@v4 # keep this comment\n", "ci.yml");
    assert.equal(refs.length, 1);
    assert.equal(refs[0].ref, "v4");
    assert.equal(refs[0].classification, "MUTABLE");
  });
  it("parses a job-level uses (reusable workflow call, no dash, deeper path)", () => {
    const content = ["jobs:", "  call:", "    uses: octo-org/octo-repo/.github/workflows/reusable.yml@v1"].join("\n");
    const refs = parseWorkflowContent(content, "caller.yml");
    assert.equal(refs.length, 1);
    assert.equal(refs[0].action, "octo-org/octo-repo/.github/workflows/reusable.yml");
    assert.equal(refs[0].ref, "v1");
    assert.equal(refs[0].classification, "MUTABLE");
  });
  it("skips a matrix-defined uses expression instead of inventing an action", () => {
    const refs = parseWorkflowContent("      - uses: ${{ matrix.action }}\n", "ci.yml");
    assert.equal(refs.length, 0);
  });
  it("skips a uses whose ref is a dynamic expression", () => {
    const refs = parseWorkflowContent("      - uses: actions/checkout@${{ inputs.ref }}\n", "ci.yml");
    assert.equal(refs.length, 0);
  });
  it("parses uses with a space before the colon", () => {
    const p = parseUsesLine("      - uses : actions/checkout@v4");
    assert.equal(p?.action, "actions/checkout");
    assert.equal(p?.ref, "v4");
  });
  it("scans a composite action.yml at a repo root during a directory audit (P-067 supersedes the old documented scope limit)", () => {
    writeFileSync(join(dir, "action.yml"), "runs:\n  using: composite\n  steps:\n    - uses: actions/checkout@v4\n", "utf8");
    writeWorkflow("ci.yml", "      - uses: actions/checkout@v4\n");
    const r = auditWorkflows(dir);
    assert.equal(r.counts.total, 2);
    assert.equal(r.workflows.length, 1);
    assert.equal(r.composites?.length, 1);
  });
  it("parses a composite action.yml correctly when the file is passed directly", () => {
    const p = join(dir, "action.yml");
    writeFileSync(p, "runs:\n  using: composite\n  steps:\n    - uses: actions/checkout@v4\n", "utf8");
    const r = auditWorkflows(p);
    assert.equal(r.counts.total, 1);
    assert.equal(r.actions[0].action, "actions/checkout");
    assert.equal(r.actions[0].classification, "MUTABLE");
  });
});

describe("hardening: refs", () => {
  it("classifies an uppercase 40-char SHA as PINNED", () => {
    assert.equal(classifyRef(SHA_B.toUpperCase()), "PINNED");
  });
  it("never classifies a short SHA as PINNED", () => {
    assert.notEqual(classifyRef("abc1234"), "PINNED");
    assert.notEqual(classifyRef("deadbeef"), "PINNED");
    const r = auditWorkflows(dir);
    assert.equal(r.verdict, "PINNED"); // empty repo baseline stays honest
    writeWorkflow("ci.yml", "      - uses: actions/checkout@abc1234\n");
    assert.notEqual(auditWorkflows(dir).verdict, "PINNED");
    assert.equal(auditWorkflows(dir).counts.pinned, 0);
  });
  it("classifies semver with leading zeros as MUTABLE", () => {
    assert.equal(classifyRef("v01.02"), "MUTABLE");
    assert.equal(classifyRef("v01"), "MUTABLE");
  });
  it("classifies a prerelease semver tag as MUTABLE", () => {
    assert.equal(classifyRef("v1.2.3-beta.1"), "MUTABLE");
  });
  it("never classifies HEAD or latest as PINNED", () => {
    assert.equal(classifyRef("HEAD"), "BRANCH");
    assert.notEqual(classifyRef("latest"), "PINNED");
  });
  it("classifies a ref with a slash as not pinned", () => {
    assert.notEqual(classifyRef("release/v1"), "PINNED");
  });
  it("classifies an empty ref and a missing ref as MUTABLE", () => {
    const a = parseWorkflowContent("      - uses: actions/checkout@\n", "x.yml");
    assert.equal(a[0].classification, "MUTABLE");
    const b = parseWorkflowContent("      - uses: actions/checkout\n", "x.yml");
    assert.equal(b[0].classification, "MUTABLE");
  });
});

describe("hardening: files", () => {
  it("audits a CRLF workflow with correct counts and lines", () => {
    writeWorkflow("ci.yml", "name: ci\r\njobs:\r\n  a:\r\n    steps:\r\n      - uses: actions/checkout@v4\r\n      - uses: actions/setup-node@v4\r\n");
    const r = auditWorkflows(dir);
    assert.equal(r.counts.total, 2);
    assert.equal(r.actions[0].line, 5);
  });
  it("audits a workflow with no trailing newline", () => {
    writeWorkflow("ci.yml", "      - uses: actions/checkout@v4");
    assert.equal(auditWorkflows(dir).counts.total, 1);
  });
  it("audits an empty workflow file as zero actions", () => {
    writeWorkflow("empty.yml", "");
    const r = auditWorkflows(dir);
    assert.equal(r.counts.total, 0);
    assert.equal(r.verdict, "PINNED");
  });
  it("audits a comments-only workflow file as zero actions", () => {
    writeWorkflow("comments.yml", "# just a comment\n# - uses: actions/checkout@v4\n");
    assert.equal(auditWorkflows(dir).counts.total, 0);
  });
  it("follows a symlinked workflows directory", () => {
    const real = join(dir, "real-workflows");
    mkdirSync(real, { recursive: true });
    writeFileSync(join(real, "ci.yml"), "      - uses: actions/checkout@v4\n", "utf8");
    mkdirSync(join(dir, ".github"), { recursive: true });
    symlinkSync(real, join(dir, ".github", "workflows"), "dir");
    const r = auditWorkflows(dir);
    assert.equal(r.counts.total, 1);
  });
  it("handles a huge workflow with 200 jobs", () => {
    const jobs: string[] = ["name: huge", "jobs:"];
    for (let i = 0; i < 200; i++) {
      jobs.push(`  job${i}:`, "    steps:", "      - uses: actions/checkout@v4");
    }
    writeWorkflow("huge.yml", jobs.join("\n") + "\n");
    const r = auditWorkflows(dir);
    assert.equal(r.counts.total, 200);
    assert.equal(r.actions[199].action, "actions/checkout");
  });
});

describe("hardening: fix mode", () => {
  it("partial failure changes only the resolved line and reports the other", async () => {
    const p = writeWorkflow("ci.yml", "      - uses: actions/checkout@v4\n      - uses: unknown/tool@v9\n");
    const result = await applyPinPlan(dir, fixtureFetch({ "actions/checkout": SHA_A }));
    const after = readFileSync(p, "utf8");
    assert.ok(after.includes(`actions/checkout@${SHA_A} # v4`));
    assert.ok(after.includes("unknown/tool@v9"));
    assert.ok(!after.includes(`unknown/tool@${SHA_A}`));
    assert.equal(result.entries.find((e) => e.action === "actions/checkout")?.status, "pinned");
    assert.equal(result.entries.find((e) => e.action === "unknown/tool")?.status, "failed");
    assert.equal(result.filesChanged.length, 1);
  });
  it("fix on a double-quoted uses keeps the comment outside the quotes and round-trips", async () => {
    const p = writeWorkflow("ci.yml", '      - uses: "actions/checkout@v4"\n');
    await applyPinPlan(dir, fixtureFetch({ "actions/checkout": SHA_C }));
    const after = readFileSync(p, "utf8");
    assert.ok(after.includes(`"actions/checkout@${SHA_C}" # v4`), `unexpected line: ${after}`);
    const refs = parseWorkflowContent(after, "ci.yml");
    assert.equal(refs[0].action, "actions/checkout");
    assert.equal(refs[0].classification, "PINNED");
  });
  it("fix on a single-quoted uses keeps the comment outside the quotes and round-trips", async () => {
    const p = writeWorkflow("ci.yml", "      - uses: 'actions/checkout@v4'\n");
    await applyPinPlan(dir, fixtureFetch({ "actions/checkout": SHA_C }));
    const after = readFileSync(p, "utf8");
    assert.ok(after.includes(`'actions/checkout@${SHA_C}' # v4`), `unexpected line: ${after}`);
    const refs = parseWorkflowContent(after, "ci.yml");
    assert.equal(refs[0].action, "actions/checkout");
    assert.equal(refs[0].classification, "PINNED");
  });
  it("fix on a quoted uses is idempotent", async () => {
    const p = writeWorkflow("ci.yml", '      - uses: "actions/checkout@v4"\n');
    const fetchFn = fixtureFetch({ "actions/checkout": SHA_C });
    await applyPinPlan(dir, fetchFn);
    const once = readFileSync(p, "utf8");
    const second = await applyPinPlan(dir, fetchFn);
    assert.equal(second.changes, 0);
    assert.equal(readFileSync(p, "utf8"), once);
  });
  it("fix preserves an existing trailing comment", async () => {
    const p = writeWorkflow("ci.yml", "      - uses: actions/checkout@v4 # keep me\n");
    await applyPinPlan(dir, fixtureFetch({ "actions/checkout": SHA_A }));
    const after = readFileSync(p, "utf8");
    assert.ok(after.includes("# keep me"), `comment lost: ${after}`);
    assert.equal(parseWorkflowContent(after, "ci.yml")[0].classification, "PINNED");
  });
  it("fix preserves CRLF line endings on the rewritten line", async () => {
    const p = writeWorkflow("ci.yml", "name: ci\r\n    steps:\r\n      - uses: actions/checkout@v4\r\n");
    await applyPinPlan(dir, fixtureFetch({ "actions/checkout": SHA_A }));
    const after = readFileSync(p, "utf8");
    assert.ok(after.includes(`actions/checkout@${SHA_A} # v4\r\n`), `CRLF lost: ${JSON.stringify(after)}`);
    assert.ok(!after.includes("# v4\n"), "a bare LF line ending appeared");
  });
  it("fix preserves a missing trailing newline", async () => {
    const p = writeWorkflow("ci.yml", "      - uses: actions/checkout@v4");
    await applyPinPlan(dir, fixtureFetch({ "actions/checkout": SHA_A }));
    const after = readFileSync(p, "utf8");
    assert.ok(after.includes(`@${SHA_A}`));
    assert.ok(!after.endsWith("\n"));
  });
  it("resolves a ref containing a slash without encoding the slash away", async () => {
    writeWorkflow("ci.yml", "      - uses: some/tool@release/v1\n");
    const seen: string[] = [];
    const slashFetch: FetchFn = async (url: string) => {
      seen.push(url);
      if (url.includes("/git/ref/tags/release/v1") || url.includes("/git/ref/heads/release/v1")) {
        return jsonRes(200, { object: { sha: SHA_B, type: "commit" } });
      }
      return jsonRes(404, { message: "not found" });
    };
    const plan = await buildPinPlan(dir, slashFetch);
    assert.equal(plan.entries[0].status, "pinned");
    assert.equal(plan.entries[0].sha, SHA_B);
    assert.ok(seen.some((u) => u.includes("release/v1") && !u.includes("release%2Fv1")), `slash was encoded: ${seen[0]}`);
  });
});

describe("hardening: CLI and MCP parity", () => {
  function runJsonRpcServer(args: string[], requests: string[], wantId: number): Promise<Record<string, unknown>> {
    return new Promise((resolvePromise, rejectPromise) => {
      const child = spawn(process.execPath, ["--import", "tsx", ...args], { cwd: REPO_ROOT, stdio: ["pipe", "pipe", "pipe"] });
      let buf = "";
      const timer = setTimeout(() => { child.kill("SIGKILL"); rejectPromise(new Error("MCP server timed out")); }, 30000);
      child.stdout.on("data", (chunk: Buffer) => {
        buf += chunk.toString("utf8");
        for (const line of buf.split("\n")) {
          if (!line.trim().startsWith("{")) continue;
          try {
            const msg = JSON.parse(line) as { id?: number };
            if (msg.id === wantId) {
              clearTimeout(timer);
              child.kill("SIGKILL");
              resolvePromise(msg as Record<string, unknown>);
              return;
            }
          } catch { /* partial line, keep buffering */ }
        }
      });
      child.on("error", (err) => { clearTimeout(timer); rejectPromise(err); });
      for (const r of requests) child.stdin.write(r + "\n");
    });
  }

  it("CLI audit and MCP audit_workflows return identical counts for the same fixture", async () => {
    writeWorkflow("ci.yml", ["      - uses: actions/checkout@v4", `      - uses: actions/setup-node@${SHA_A}`, "      - uses: some/tool@main", "      - uses: ./local/action"].join("\n") + "\n");
    const direct = auditWorkflows(dir);

    // CLI through a child process, machine readable output.
    const cliOut = await new Promise<string>((resolvePromise, rejectPromise) => {
      const child = spawn(process.execPath, ["--import", "tsx", "src/cli.ts", "audit", dir, "--json"], { cwd: REPO_ROOT, stdio: ["ignore", "pipe", "pipe"] });
      let out = "";
      child.stdout.on("data", (c: Buffer) => { out += c.toString("utf8"); });
      child.on("error", rejectPromise);
      child.on("close", () => resolvePromise(out));
    });
    const cliReport = JSON.parse(cliOut) as { counts: unknown; verdict: string };
    assert.deepEqual(cliReport.counts, direct.counts);
    assert.equal(cliReport.verdict, direct.verdict);

    // MCP through a real stdio JSON-RPC session.
    const init = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "hardening", version: "0" } } });
    const initialized = JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" });
    const call = JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "audit_workflows", arguments: { path: dir } } });
    const resp = await runJsonRpcServer(["src/cli.ts", "mcp"], [init, initialized, call], 2);
    const result = resp.result as { content: Array<{ text: string }> };
    const mcpReport = JSON.parse(result.content[0].text) as { counts: unknown; verdict: string };
    assert.deepEqual(mcpReport.counts, direct.counts);
    assert.equal(mcpReport.verdict, direct.verdict);
  });
});
