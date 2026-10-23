/**
 * P-174 regression tests (Round 5): flow-style workflow uses entries
 * were invisible. A workflow written in YAML flow style (jobs, steps,
 * and uses all in flow mappings and sequences on shared lines) listed
 * the file but inventoried zero actions and verdicted PINNED, while a
 * step used actions/checkout@v4 (mutable). Flow style is valid,
 * GitHub-accepted YAML, and flowcheck parses the same file correctly.
 *
 * These tests were written before the fix and failed against the
 * 0.1.6 code: every flow inventory test returned zero refs, the audit
 * tests verdicted PINNED over total 0, the unparsed-file tests found
 * no unparsedWorkflows field and no note, and the fix tests could not
 * pin a flow line at all.
 *
 * Fixtures only, fetch always injected, no network.
 */
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
  parseWorkflowContent,
  renderReport,
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
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "actionpin-p174-")); });
afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

const REPRO = [
  "name: CI",
  "on: {push: {branches: [main]}}",
  "jobs: {b: {runs-on: ubuntu-latest, steps: [{uses: 'actions/checkout@v4'}, {run: 'echo hi'}]}}",
  "",
].join("\n");

describe("P-174 flow-style uses inventory", () => {
  it("P-174: the exact repro workflow yields the checkout ref as MUTABLE", () => {
    const refs = parseWorkflowContent(REPRO, "ci.yml");
    assert.equal(refs.length, 1);
    assert.equal(refs[0].action, "actions/checkout");
    assert.equal(refs[0].ref, "v4");
    assert.equal(refs[0].classification, "MUTABLE");
    assert.equal(refs[0].ownerType, "official");
    assert.equal(refs[0].line, 3);
  });

  it("P-174: audit of the repro repo verdicts PARTIAL with total 1", () => {
    writeWorkflow("ci.yml", REPRO);
    const r = auditWorkflows(dir);
    assert.equal(r.verdict, "PARTIAL");
    assert.equal(r.counts.total, 1);
    assert.equal(r.counts.mutable, 1);
    assert.equal(r.actions[0].uses, "actions/checkout@v4");
    assert.equal(r.unparsedWorkflows, undefined);
  });

  it("P-174: multiple flow uses on one shared line are all inventoried in order", () => {
    const content = "jobs: {b: {runs-on: ubuntu-latest, steps: [{uses: 'actions/checkout@v4'}, {uses: 'docker/build-push-action@v6'}]}}\n";
    const refs = parseWorkflowContent(content, "ci.yml");
    assert.equal(refs.length, 2);
    assert.equal(refs[0].action, "actions/checkout");
    assert.equal(refs[1].action, "docker/build-push-action");
    assert.equal(refs[1].ownerType, "third-party");
    writeWorkflow("ci.yml", content);
    assert.equal(auditWorkflows(dir).verdict, "EXPOSED");
  });

  it("P-174: an unquoted flow value stops at the comma and ignores sibling keys", () => {
    const content = "jobs: {b: {steps: [{uses: actions/checkout@v4, with: {fetch-depth: 0}}, {run: 'echo hi'}]}}\n";
    const refs = parseWorkflowContent(content, "ci.yml");
    assert.equal(refs.length, 1);
    assert.equal(refs[0].uses, "actions/checkout@v4");
    assert.equal(refs[0].classification, "MUTABLE");
  });

  it("P-174: double-quoted flow values are inventoried", () => {
    const refs = parseWorkflowContent('jobs: {b: {steps: [{uses: "actions/setup-node@v4"}]}}\n', "ci.yml");
    assert.equal(refs.length, 1);
    assert.equal(refs[0].action, "actions/setup-node");
    assert.equal(refs[0].classification, "MUTABLE");
  });

  it("P-174: a flow step on a dash line is inventoried", () => {
    const content = ["jobs:", "  b:", "    steps:", "      - {uses: 'actions/checkout@v4'}", "      - run: echo hi", ""].join("\n");
    const refs = parseWorkflowContent(content, "ci.yml");
    assert.equal(refs.length, 1);
    assert.equal(refs[0].line, 4);
    assert.equal(refs[0].classification, "MUTABLE");
  });

  it("P-174: flow sequences split across lines are inventoried with their own lines", () => {
    const content = [
      "jobs:",
      "  b:",
      "    runs-on: ubuntu-latest",
      "    steps: [",
      "      {uses: 'actions/checkout@v4'},",
      `      {uses: 'actions/setup-node@${SHA_B}'}]`,
      "",
    ].join("\n");
    const refs = parseWorkflowContent(content, "ci.yml");
    assert.equal(refs.length, 2);
    assert.equal(refs[0].line, 5);
    assert.equal(refs[0].classification, "MUTABLE");
    assert.equal(refs[1].line, 6);
    assert.equal(refs[1].classification, "PINNED");
  });

  it("P-174: a pinned flow ref verdicts PINNED with no unparsed flag", () => {
    writeWorkflow("ci.yml", `jobs: {b: {steps: [{uses: 'actions/checkout@${SHA_B}'}]}}\n`);
    const r = auditWorkflows(dir);
    assert.equal(r.verdict, "PINNED");
    assert.equal(r.counts.total, 1);
    assert.equal(r.counts.pinned, 1);
    assert.equal(r.unparsedWorkflows, undefined);
    assert.equal(r.note, undefined);
  });

  it("P-174: a flow job-level reusable workflow call is inventoried", () => {
    const content = "jobs: {call: {uses: 'octo-org/octo-repo/.github/workflows/reuse.yml@v1'}}\n";
    const refs = parseWorkflowContent(content, "caller.yml");
    assert.equal(refs.length, 1);
    assert.equal(refs[0].action, "octo-org/octo-repo/.github/workflows/reuse.yml");
    assert.equal(refs[0].classification, "MUTABLE");
  });

  it("P-174: block and flow steps in one file are both inventoried", () => {
    const content = [
      "jobs:",
      "  a:",
      "    steps:",
      "      - uses: actions/checkout@v4",
      "  b: {steps: [{uses: 'actions/setup-node@v4'}]}",
      "",
    ].join("\n");
    const refs = parseWorkflowContent(content, "ci.yml");
    assert.equal(refs.length, 2);
    assert.equal(refs[0].line, 4);
    assert.equal(refs[1].line, 5);
  });

  it("P-174: a uses string inside a quoted run value invents no action", () => {
    const content = [
      "jobs:",
      "  a:",
      "    steps:",
      `      - uses: actions/checkout@${SHA_B}`,
      '      - run: echo "uses: fake/action@v9"',
      "",
    ].join("\n");
    const refs = parseWorkflowContent(content, "ci.yml");
    assert.equal(refs.length, 1);
    assert.equal(refs[0].action, "actions/checkout");
  });

  it("P-174: a uses mention in a trailing comment invents no action", () => {
    const content = "jobs: {b: {steps: [{uses: 'actions/checkout@v4'}]}} # uses: fake/action@v9\n";
    const refs = parseWorkflowContent(content, "ci.yml");
    assert.equal(refs.length, 1);
    assert.equal(refs[0].action, "actions/checkout");
  });

  it("P-174: a commented-out flow line invents no action", () => {
    const content = [
      "# jobs: {b: {steps: [{uses: 'fake/action@v9'}]}}",
      `jobs: {b: {steps: [{uses: 'actions/checkout@${SHA_B}'}]}}`,
      "",
    ].join("\n");
    const refs = parseWorkflowContent(content, "ci.yml");
    assert.equal(refs.length, 1);
    assert.equal(refs[0].classification, "PINNED");
  });

  it("P-174: flow anchors and aliases resolve like block ones", () => {
    const content = "jobs: {b: {steps: [{uses: &co actions/checkout@v4}, {uses: *co}]}}\n";
    const refs = parseWorkflowContent(content, "ci.yml");
    assert.equal(refs.length, 2);
    assert.equal(refs[0].classification, "MUTABLE");
    assert.equal(refs[1].classification, "MUTABLE");
    assert.equal(refs[1].viaAlias, true);
  });

  it("P-174: a dynamic flow uses is skipped and is not flagged unparsed", () => {
    writeWorkflow("ci.yml", "jobs: {b: {steps: [{uses: '${{ matrix.action }}'}]}}\n");
    const r = auditWorkflows(dir);
    assert.equal(r.counts.total, 0);
    assert.equal(r.unparsedWorkflows, undefined);
  });
});

describe("P-174 unparsed workflow files never floor silently", () => {
  it("P-174: a flow uses with an empty value floors the verdict and is named", () => {
    writeWorkflow("broken.yml", "jobs: {b: {runs-on: ubuntu-latest, steps: [{uses: }]}}\n");
    writeWorkflow("good.yml", ["jobs:", "  a:", "    steps:", `      - uses: actions/checkout@${SHA_B}`, ""].join("\n"));
    const r = auditWorkflows(dir);
    assert.equal(r.counts.total, 1);
    assert.equal(r.verdict, "PARTIAL");
    assert.equal(r.unparsedWorkflows?.length, 1);
    assert.match(r.unparsedWorkflows![0], /broken\.yml$/);
    assert.match(r.note ?? "", /could not be fully parsed/);
    const human = renderReport(r);
    assert.match(human, /broken\.yml/);
    assert.match(human, /PARTIAL/);
    assert.doesNotMatch(human, /No workflows were audited/);
  });

  it("P-174: a repo whose only workflow is unparsed does not verdict PINNED", () => {
    writeWorkflow("broken.yml", "jobs: {b: {steps: [{uses: }]}}\n");
    const r = auditWorkflows(dir);
    assert.equal(r.counts.total, 0);
    assert.notEqual(r.verdict, "PINNED");
    assert.equal(r.unparsedWorkflows?.length, 1);
    assert.match(r.note ?? "", /could not be fully parsed/);
  });
});

describe("P-174 fix mode on flow lines", () => {
  it("P-174: buildPinnedLine on a flow line adds no comment that would eat the rest of the line", () => {
    const line = "jobs: {b: {steps: [{uses: 'actions/checkout@v4'}, {run: 'echo hi'}]}}";
    const ref = parseWorkflowContent(line + "\n", "ci.yml")[0];
    const pinned = buildPinnedLine(line, ref, SHA_A);
    assert.ok(!pinned.includes("#"), `flow pinned line carries a comment: ${pinned}`);
    assert.ok(pinned.includes(`actions/checkout@${SHA_A}`));
    assert.ok(pinned.includes("{run: 'echo hi'}"));
  });

  it("P-174: pin plan and fix pin every flow action on a shared line", async () => {
    const p = writeWorkflow("ci.yml", "jobs: {b: {steps: [{uses: 'actions/checkout@v4'}, {uses: 'actions/setup-node@v4'}]}}\n");
    const fetchFn = fixtureFetch({ "actions/checkout": SHA_A, "actions/setup-node": SHA_C });
    const plan = await buildPinPlan(dir, fetchFn);
    const pinned = plan.entries.filter((e) => e.status === "pinned");
    assert.equal(pinned.length, 2);
    const lastLine = pinned[pinned.length - 1].newLine ?? "";
    assert.ok(lastLine.includes(`actions/checkout@${SHA_A}`), `chained line lost the first pin: ${lastLine}`);
    assert.ok(lastLine.includes(`actions/setup-node@${SHA_C}`), `chained line lost the second pin: ${lastLine}`);
    const result = await applyPinPlan(dir, fetchFn);
    assert.equal(result.filesChanged.length, 1);
    const after = readFileSync(p, "utf8");
    assert.ok(after.includes(`actions/checkout@${SHA_A}`));
    assert.ok(after.includes(`actions/setup-node@${SHA_C}`));
    assert.equal(auditWorkflows(dir).verdict, "PINNED");
    assert.equal(auditWorkflows(dir).counts.total, 2);
  });
});
