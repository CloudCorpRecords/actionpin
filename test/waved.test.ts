/**
 * Wave D self-dogfood regression (overnight flywheel, 2026-10-22).
 * P-067: a root-level action.yml or action.yaml, the canonical location
 * for a published GitHub Action, was only listed under
 * unscannedComposites in a directory audit and none of its internal
 * refs were inventoried, so a repo shipping an action whose internals
 * float verdicted PINNED (the CloudCorpRecords/greenlight shape: the
 * guard workflow pins the action by SHA while the action itself runs
 * actions/setup-node@v4 internally). The P-058 machinery scanned
 * composites under .github/actions and local actions referenced via
 * ./ uses paths, but never the scanned repo's own root action.
 * Fixtures only, fetch always injected, no network.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { auditWorkflows, buildPinPlan, renderReport } from "../src/core.js";
import type { FetchFn, FetchResponse } from "../src/types.js";

const SHA_CHECKOUT = "11d5960a326750d5838078e36cf38b85af677262";
const SHA_SELF = "634cef11599766c8385d994135255b6749b09bc8";
const SHA_GS = "3a2844b7e9c422d3c10d287c895573f7108da1b3";
const SHA_NODE = "49933ea5288caeca8642d1e84afbd3f7d6820020";

function jsonRes(status: number, body: unknown): FetchResponse {
  return { ok: status >= 200 && status < 300, status, json: async () => body, text: async () => JSON.stringify(body) };
}

let dir: string;
function writeWorkflow(name: string, content: string): string {
  const wfDir = join(dir, ".github", "workflows");
  mkdirSync(wfDir, { recursive: true });
  const p = join(wfDir, name);
  writeFileSync(p, content, "utf8");
  return p;
}
function writeAction(rel: string, content: string): string {
  const p = join(dir, rel);
  mkdirSync(join(p, ".."), { recursive: true });
  writeFileSync(p, content, "utf8");
  return p;
}
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "actionpin-waved-")); });
afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

// The greenlight guard shape, distilled in the corpus fixture
// waved-root-composite-selfref: a pinned workflow consuming the repo's
// own action by remote self ref at a full SHA.
const GUARD_WORKFLOW = [
  "name: guard",
  "on: [pull_request]",
  "jobs:",
  "  guard:",
  "    runs-on: ubuntu-latest",
  "    steps:",
  `      - uses: actions/checkout@${SHA_CHECKOUT} # v4`,
  `      - uses: CloudCorpRecords/greenlight@${SHA_SELF} # v0.3.9`,
].join("\n") + "\n";

const ROOT_COMPOSITE_MUTABLE_OFFICIAL = [
  "name: self-guard",
  "description: distilled from the greenlight repo root action.yml shape",
  "runs:",
  "  using: composite",
  "  steps:",
  "    - name: Set up Node.js",
  "      uses: actions/setup-node@v4",
  "      with:",
  '        node-version: "20"',
  "    - name: Run guard",
  "      shell: bash",
  "      run: echo guard",
].join("\n") + "\n";

describe("waveD P-067: root-level action definition is scanned in a directory audit", () => {
  it("the corpus fixture shape: the internal mutable ref is inventoried and the verdict is no longer PINNED", () => {
    writeWorkflow("guard.yml", GUARD_WORKFLOW);
    const rootFile = writeAction("action.yml", ROOT_COMPOSITE_MUTABLE_OFFICIAL);
    const r = auditWorkflows(dir);
    assert.equal(r.counts.total, 3);
    assert.equal(r.counts.pinned, 2);
    assert.equal(r.counts.mutable, 1);
    // actions/setup-node is an official action, so a mutable ref is the
    // PARTIAL rung of the verdict scale (the same way a P-058 composite
    // internal drives the verdict); the estate no longer reads PINNED.
    assert.equal(r.verdict, "PARTIAL");
    const inner = r.actions.find((a) => a.action === "actions/setup-node");
    assert.ok(inner, "root composite internal ref missing");
    assert.equal(inner!.composite, true);
    assert.equal(inner!.workflow, rootFile);
    assert.deepEqual(r.composites, [rootFile]);
    assert.ok(!r.unscannedComposites || r.unscannedComposites.length === 0, "scanned root action still listed as unscanned");
  });

  it("a third-party mutable ref inside the root composite verdicts EXPOSED", () => {
    writeWorkflow("guard.yml", GUARD_WORKFLOW);
    writeAction("action.yml", [
      "name: self-guard",
      "runs:",
      "  using: composite",
      "  steps:",
      "    - uses: evil-corp/tool@v1",
    ].join("\n") + "\n");
    const r = auditWorkflows(dir);
    assert.equal(r.counts.total, 3);
    assert.equal(r.counts.mutable, 1);
    assert.equal(r.verdict, "EXPOSED");
    assert.equal(r.actions.find((a) => a.action === "evil-corp/tool")?.composite, true);
  });

  it("a root action.yaml is scanned the same way", () => {
    writeWorkflow("guard.yml", GUARD_WORKFLOW);
    const rootFile = writeAction("action.yaml", ROOT_COMPOSITE_MUTABLE_OFFICIAL);
    const r = auditWorkflows(dir);
    assert.equal(r.counts.total, 3);
    assert.equal(r.counts.mutable, 1);
    assert.deepEqual(r.composites, [rootFile]);
    assert.ok(!r.unscannedComposites || r.unscannedComposites.length === 0);
  });

  it("a root composite whose internals are all pinned keeps the estate PINNED", () => {
    writeWorkflow("guard.yml", GUARD_WORKFLOW);
    writeAction("action.yml", [
      "name: self-guard",
      "runs:",
      "  using: composite",
      "  steps:",
      `    - uses: actions/setup-node@${SHA_NODE} # v4`,
      `    - uses: actions/github-script@${SHA_GS}`,
    ].join("\n") + "\n");
    const r = auditWorkflows(dir);
    assert.equal(r.counts.total, 4);
    assert.equal(r.counts.pinned, 4);
    assert.equal(r.counts.mutable, 0);
    assert.equal(r.verdict, "PINNED");
    assert.equal(r.actions.filter((a) => a.composite).length, 2);
  });

  it("a root JavaScript action with no steps is scanned and adds no refs", () => {
    writeWorkflow("guard.yml", GUARD_WORKFLOW);
    const rootFile = writeAction("action.yml", [
      "name: jsact",
      "runs:",
      "  using: node20",
      "  main: index.js",
    ].join("\n") + "\n");
    const r = auditWorkflows(dir);
    assert.equal(r.counts.total, 2);
    assert.deepEqual(r.composites, [rootFile]);
    assert.equal(r.verdict, "PINNED");
    assert.ok(!r.unscannedComposites || r.unscannedComposites.length === 0);
  });

  it("a root Docker action with no steps is scanned and adds no refs", () => {
    writeWorkflow("guard.yml", GUARD_WORKFLOW);
    const rootFile = writeAction("action.yml", [
      "name: dockact",
      "runs:",
      "  using: docker",
      "  image: Dockerfile",
    ].join("\n") + "\n");
    const r = auditWorkflows(dir);
    assert.equal(r.counts.total, 2);
    assert.deepEqual(r.composites, [rootFile]);
    assert.equal(r.verdict, "PINNED");
  });

  it("the root action is scanned even when no workflow references it at all", () => {
    writeWorkflow("ci.yml", `    steps:\n      - uses: actions/checkout@${SHA_CHECKOUT}\n`);
    writeAction("action.yml", ROOT_COMPOSITE_MUTABLE_OFFICIAL);
    const r = auditWorkflows(dir);
    assert.equal(r.counts.total, 2);
    assert.equal(r.counts.mutable, 1);
    assert.equal(r.composites?.length, 1);
  });

  it("a root action in a repo with no workflows is still the repo's own action definition", () => {
    writeAction("action.yml", [
      "name: self-guard",
      "runs:",
      "  using: composite",
      "  steps:",
      "    - uses: evil-corp/tool@v1",
    ].join("\n") + "\n");
    const r = auditWorkflows(dir);
    assert.equal(r.counts.total, 1);
    assert.equal(r.verdict, "EXPOSED");
    assert.equal(r.actions[0].composite, true);
    // Something was audited, so the empty-estate note must not claim
    // that nothing was.
    assert.equal(r.note, undefined);
  });

  it("self-reference via ./ inside the root action does not recurse or double count", () => {
    writeWorkflow("guard.yml", GUARD_WORKFLOW);
    const rootFile = writeAction("action.yml", [
      "name: self-guard",
      "runs:",
      "  using: composite",
      "  steps:",
      "    - uses: ./",
      `    - uses: actions/github-script@${SHA_GS}`,
    ].join("\n") + "\n");
    const r = auditWorkflows(dir);
    assert.deepEqual(r.composites, [rootFile]);
    // Workflow 2 refs plus the root composite's own 2 step refs, each once.
    assert.equal(r.counts.total, 4);
    assert.equal(r.actions.filter((a) => a.composite).length, 2);
    assert.equal(r.actions.filter((a) => a.uses === "./").length, 1);
    assert.equal(r.verdict, "PINNED");
  });

  it("self-reference via the published name inside the root action is inventoried once and does not rescan", () => {
    writeWorkflow("guard.yml", GUARD_WORKFLOW);
    writeAction("action.yml", [
      "name: self-guard",
      "runs:",
      "  using: composite",
      "  steps:",
      `    - uses: CloudCorpRecords/greenlight@${SHA_SELF}`,
    ].join("\n") + "\n");
    const r = auditWorkflows(dir);
    assert.equal(r.composites?.length, 1);
    assert.equal(r.counts.total, 3);
    const selfRefs = r.actions.filter((a) => a.action === "CloudCorpRecords/greenlight");
    assert.equal(selfRefs.length, 2);
    assert.equal(selfRefs.filter((a) => a.composite).length, 1);
    assert.equal(r.verdict, "PINNED");
  });

  it("a workflow referencing the root action via ./ does not double count it", () => {
    writeWorkflow("ci.yml", "    steps:\n      - uses: ./\n");
    const rootFile = writeAction("action.yml", ROOT_COMPOSITE_MUTABLE_OFFICIAL);
    const r = auditWorkflows(dir);
    assert.deepEqual(r.composites, [rootFile]);
    assert.equal(r.counts.total, 2);
    assert.equal(r.counts.mutable, 1);
    assert.equal(r.actions.filter((a) => a.composite).length, 1);
  });

  it("the root composite's own local references are followed transitively", () => {
    writeWorkflow("guard.yml", GUARD_WORKFLOW);
    writeAction("action.yml", [
      "name: self-guard",
      "runs:",
      "  using: composite",
      "  steps:",
      "    - uses: ./.github/actions/helper",
    ].join("\n") + "\n");
    writeAction(join(".github", "actions", "helper", "action.yml"), [
      "name: helper",
      "runs:",
      "  using: composite",
      "  steps:",
      "    - uses: evil-corp/tool@v2",
    ].join("\n") + "\n");
    const r = auditWorkflows(dir);
    assert.equal(r.composites?.length, 2);
    assert.equal(r.counts.total, 4);
    assert.equal(r.verdict, "EXPOSED");
    assert.equal(r.actions.find((a) => a.action === "evil-corp/tool")?.composite, true);
  });

  it("human output flags the root composite refs and counts the file as scanned", () => {
    writeWorkflow("guard.yml", GUARD_WORKFLOW);
    writeAction("action.yml", ROOT_COMPOSITE_MUTABLE_OFFICIAL);
    const r = auditWorkflows(dir);
    const text = renderReport(r);
    assert.match(text, /1 composite file\(s\) scanned/);
    assert.match(text, /actions\/setup-node@v4 \(official\) \[composite action\]/);
    assert.doesNotMatch(text, /not scanned/);
  });

  it("an unreferenced action file elsewhere in the repo is still named as unscanned", () => {
    writeWorkflow("guard.yml", GUARD_WORKFLOW);
    writeAction("action.yml", ROOT_COMPOSITE_MUTABLE_OFFICIAL);
    const orphan = writeAction(join("tools", "orphan", "action.yml"), [
      "name: orphan",
      "runs:",
      "  using: composite",
      "  steps:",
      "    - uses: evil-corp/tool@v1",
    ].join("\n") + "\n");
    const r = auditWorkflows(dir);
    assert.deepEqual(r.unscannedComposites, [orphan]);
    assert.match(renderReport(r), /not scanned/);
    // The orphan's internals stay uncounted; only the disclosure moved.
    assert.equal(r.actions.find((a) => a.action === "evil-corp/tool"), undefined);
  });

  it("the pin plan covers the root composite internal refs like workflow refs", async () => {
    writeWorkflow("guard.yml", GUARD_WORKFLOW);
    writeAction("action.yml", ROOT_COMPOSITE_MUTABLE_OFFICIAL);
    const fetchFn: FetchFn = async (url: string) => {
      if (url.includes("actions/setup-node")) return jsonRes(200, { object: { sha: SHA_NODE, type: "commit" } });
      return jsonRes(404, { message: "not found" });
    };
    const plan = await buildPinPlan(dir, fetchFn);
    const entry = plan.entries.find((e) => e.action === "actions/setup-node");
    assert.ok(entry, "pin plan has no entry for the root composite internal ref");
    assert.equal(entry!.status, "pinned");
    assert.equal(entry!.sha, SHA_NODE);
    assert.ok(entry!.workflow.endsWith("action.yml"));
  });
});
