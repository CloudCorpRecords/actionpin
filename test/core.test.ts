import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  applyPinPlan,
  auditWorkflows,
  buildPinPlan,
  buildPinnedLine,
  classifyRef,
  computeVerdict,
  discoverWorkflows,
  ownerTypeFor,
  parseUsesLine,
  parseWorkflowContent,
  resolveRefToSha,
} from "../src/core.js";
import type { FetchFn, FetchResponse } from "../src/types.js";

const SHA_A = "a".repeat(40);
const SHA_B = "0123456789abcdef0123456789abcdef01234567";
const SHA_C = "f".repeat(40);

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
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "actionpin-")); });
afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

describe("classifyRef", () => {
  it("classifies a full 40-char SHA as PINNED", () => { assert.equal(classifyRef(SHA_B), "PINNED"); });
  it("classifies version tags as MUTABLE", () => {
    assert.equal(classifyRef("v4"), "MUTABLE");
    assert.equal(classifyRef("v4.2.1"), "MUTABLE");
    assert.equal(classifyRef("4.2.1"), "MUTABLE");
    assert.equal(classifyRef("v3"), "MUTABLE");
  });
  it("classifies branch names as BRANCH", () => {
    assert.equal(classifyRef("main"), "BRANCH");
    assert.equal(classifyRef("master"), "BRANCH");
    assert.equal(classifyRef("HEAD"), "BRANCH");
    assert.equal(classifyRef("feature/new-thing"), "BRANCH");
  });
  it("classifies a short SHA as not pinned", () => { assert.notEqual(classifyRef("abc1234"), "PINNED"); });
});

describe("ownerTypeFor", () => {
  it("marks actions and github owners official", () => {
    assert.equal(ownerTypeFor("actions/checkout", "actions/checkout@v4"), "official");
    assert.equal(ownerTypeFor("github/codeql-action", "github/codeql-action@v3"), "official");
  });
  it("marks other owners third-party", () => { assert.equal(ownerTypeFor("docker/build-push-action", "docker/build-push-action@v6"), "third-party"); });
  it("marks local and docker refs", () => {
    assert.equal(ownerTypeFor("./local", "./local"), "local");
    assert.equal(ownerTypeFor("docker://alpine", "docker://alpine:3.19"), "docker");
  });
});

describe("parseUsesLine and parseWorkflowContent", () => {
  it("parses a simple uses line", () => {
    const p = parseUsesLine("      - uses: actions/checkout@v4");
    assert.equal(p?.action, "actions/checkout"); assert.equal(p?.ref, "v4");
  });
  it("parses uses without dash and with quotes", () => {
    const p = parseUsesLine('        uses: "actions/setup-node@v4"');
    assert.equal(p?.action, "actions/setup-node"); assert.equal(p?.ref, "v4");
  });
  it("ignores non-uses lines", () => { assert.equal(parseUsesLine("      - run: npm test"), null); });
  it("parses pinned, mutable, branch, local and docker in one workflow", () => {
    const content = ["name: x", "jobs:", "  a:", "    steps:", `      - uses: actions/checkout@${SHA_B}`, "      - uses: actions/setup-node@v4", "      - uses: some/tool@main", "      - uses: ./local/action", "      - uses: docker://alpine:3.19"].join("\n");
    const refs = parseWorkflowContent(content, "ci.yml");
    assert.equal(refs.length, 5);
    assert.equal(refs[0].classification, "PINNED");
    assert.equal(refs[1].classification, "MUTABLE");
    assert.equal(refs[2].classification, "BRANCH"); assert.equal(refs[2].ownerType, "third-party");
    assert.equal(refs[3].classification, "LOCAL");
    assert.equal(refs[4].ownerType, "docker"); assert.equal(refs[4].classification, "MUTABLE");
  });
  it("records correct 1-based line numbers", () => {
    const refs = parseWorkflowContent("name: x\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n", "ci.yml");
    assert.equal(refs[0].line, 5);
  });
  it("handles sub-path actions", () => {
    const refs = parseWorkflowContent("      - uses: github/codeql-action/init@v3\n", "q.yml");
    assert.equal(refs[0].action, "github/codeql-action/init"); assert.equal(refs[0].ownerType, "official");
  });
  it("counts a sha256 docker digest as pinned", () => {
    const digest = "sha256:" + "a".repeat(64);
    const refs = parseWorkflowContent(`      - uses: docker://alpine@${digest}\n`, "d.yml");
    assert.equal(refs[0].classification, "PINNED");
  });
  it("handles multi-job workflows", () => {
    const content = ["jobs:", "  a:", "    steps:", "      - uses: actions/checkout@v4", "  b:", "    steps:", `      - uses: actions/checkout@${SHA_A}`].join("\n");
    const refs = parseWorkflowContent(content, "multi.yml");
    assert.equal(refs.length, 2); assert.equal(refs[1].classification, "PINNED");
  });
});

describe("computeVerdict", () => {
  it("PINNED when all pinned or local", () => {
    assert.equal(computeVerdict([
      { workflow: "f", line: 1, uses: "a/b@" + SHA_A, action: "a/b", ref: SHA_A, classification: "PINNED", ownerType: "third-party", rawLine: "" },
      { workflow: "f", line: 2, uses: "./x", action: "./x", ref: "", classification: "LOCAL", ownerType: "local", rawLine: "" },
    ]), "PINNED");
  });
  it("EXPOSED when a third-party action is mutable", () => {
    assert.equal(computeVerdict([{ workflow: "f", line: 1, uses: "x/y@v1", action: "x/y", ref: "v1", classification: "MUTABLE", ownerType: "third-party", rawLine: "" }]), "EXPOSED");
  });
  it("PARTIAL when only official actions are mutable", () => {
    assert.equal(computeVerdict([{ workflow: "f", line: 1, uses: "actions/checkout@v4", action: "actions/checkout", ref: "v4", classification: "MUTABLE", ownerType: "official", rawLine: "" }]), "PARTIAL");
  });
});

describe("auditWorkflows", () => {
  it("audits a fixture repo and reports EXPOSED for third-party mutable", () => {
    writeWorkflow("ci.yml", "name: ci\njobs:\n  a:\n    steps:\n      - uses: docker/build-push-action@v6\n");
    const r = auditWorkflows(dir);
    assert.equal(r.verdict, "EXPOSED"); assert.equal(r.counts.total, 1); assert.equal(r.counts.thirdParty, 1);
  });
  it("reports PINNED for a fully pinned repo", () => {
    writeWorkflow("ci.yml", `      - uses: actions/checkout@${SHA_B}\n`);
    assert.equal(auditWorkflows(dir).verdict, "PINNED");
  });
  it("handles a missing workflows directory without throwing", () => {
    const r = auditWorkflows(join(dir, "does-not-exist"));
    assert.equal(r.actions.length, 0); assert.equal(r.verdict, "PINNED"); assert.equal(r.workflows.length, 0);
  });
  it("handles an existing repo with no workflows directory", () => {
    const r = auditWorkflows(dir);
    assert.equal(r.actions.length, 0);
  });
  it("discovers both yml and yaml files", () => {
    writeWorkflow("a.yml", "      - uses: actions/checkout@v4\n");
    writeWorkflow("b.yaml", "      - uses: actions/checkout@v4\n");
    assert.equal(discoverWorkflows(dir).length, 2);
    assert.equal(auditWorkflows(dir).counts.total, 2);
  });
  it("audits a single workflow file path directly", () => {
    const p = writeWorkflow("solo.yml", "      - uses: actions/checkout@v4\n");
    const r = auditWorkflows(p);
    assert.equal(r.counts.total, 1);
  });
});

describe("resolve and fix", () => {
  it("resolves a tag to a SHA through the injected fetch", async () => {
    const sha = await resolveRefToSha(fixtureFetch({ "/git/ref/tags/v4": SHA_A }), "actions", "checkout", "v4");
    assert.equal(sha, SHA_A);
  });
  it("throws when resolution fails", async () => {
    await assert.rejects(() => resolveRefToSha(fixtureFetch({}), "x", "y", "v9"));
  });
  it("buildPinnedLine preserves indentation and appends the version comment", () => {
    const line = "      - uses: actions/checkout@v4";
    const ref = parseWorkflowContent(line + "\n", "f")[0];
    assert.equal(buildPinnedLine(line, ref, SHA_A), `      - uses: actions/checkout@${SHA_A} # v4`);
  });
  it("builds a pin plan with fixture fetch without writing", async () => {
    const p = writeWorkflow("ci.yml", "      - uses: actions/checkout@v4\n      - uses: ./local/action\n");
    const before = readFileSync(p, "utf8");
    const plan = await buildPinPlan(dir, fixtureFetch({ "actions/checkout": SHA_A }));
    assert.equal(plan.changes, 1);
    assert.equal(plan.entries.find((e) => e.action === "actions/checkout")?.status, "pinned");
    assert.equal(plan.entries.find((e) => e.status === "local")?.action, "./local/action");
    assert.equal(readFileSync(p, "utf8"), before);
  });
  it("fix rewrites mutable refs to SHA with a version comment", async () => {
    const p = writeWorkflow("ci.yml", "name: ci\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n");
    const result = await applyPinPlan(dir, fixtureFetch({ "actions/checkout": SHA_C }));
    assert.equal(result.filesChanged.length, 1);
    const after = readFileSync(p, "utf8");
    assert.ok(after.includes(`actions/checkout@${SHA_C} # v4`));
    assert.equal(auditWorkflows(dir).verdict, "PINNED");
  });
  it("fix is idempotent: a second fix changes nothing", async () => {
    const p = writeWorkflow("ci.yml", "      - uses: actions/checkout@v4\n");
    const fetchFn = fixtureFetch({ "actions/checkout": SHA_C });
    await applyPinPlan(dir, fetchFn);
    const once = readFileSync(p, "utf8");
    const second = await applyPinPlan(dir, fetchFn);
    assert.equal(second.changes, 0);
    assert.equal(readFileSync(p, "utf8"), once);
  });
  it("fix never rewrites local refs", async () => {
    const p = writeWorkflow("ci.yml", "      - uses: ./local/action\n      - uses: actions/checkout@v4\n");
    await applyPinPlan(dir, fixtureFetch({ "actions/checkout": SHA_C }));
    assert.ok(readFileSync(p, "utf8").includes("./local/action"));
  });
  it("failed resolution leaves the line unchanged and reports the failure", async () => {
    const p = writeWorkflow("ci.yml", "      - uses: unknown/tool@v9\n");
    const before = readFileSync(p, "utf8");
    const result = await applyPinPlan(dir, fixtureFetch({}));
    assert.equal(readFileSync(p, "utf8"), before);
    assert.equal(result.entries[0].status, "failed");
    assert.ok(result.entries[0].error);
  });
  it("fix handles a branch ref", async () => {
    const p = writeWorkflow("ci.yml", "      - uses: some/tool@main\n");
    await applyPinPlan(dir, fixtureFetch({ "some/tool": SHA_B }));
    assert.ok(readFileSync(p, "utf8").includes(`some/tool@${SHA_B} # main`));
  });
});
