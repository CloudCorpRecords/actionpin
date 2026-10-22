/**
 * Wave B corpus expansion regressions (overnight flywheel, 2026-10-21).
 * P-057: a local action path with a stray $/ prefix (the vitejs/vite
 * issues-helper shape) was classified MUTABLE third-party, drove the
 * verdict, and was sent to the GitHub API by fix.
 * P-058: composite action internals inside the scanned repo were never
 * audited in directory scans.
 * P-046: the audit report carried no composite coverage statement.
 * P-059: the fix plan header counted only PIN entries while the body
 * also listed ALREADY-PINNED lines.
 * Fixtures only, fetch always injected, no network.
 */
import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  auditWorkflows,
  buildPinPlan,
  ownerTypeFor,
  parseWorkflowContent,
  renderPlan,
  renderReport,
} from "../src/core.js";
import type { FetchFn, FetchResponse } from "../src/types.js";

const SHA_B = "0123456789abcdef0123456789abcdef01234567";
const SHA_GS = "3a2844b7e9c422d3c10d287c895573f7108da1b3";

function jsonRes(status: number, body: unknown): FetchResponse {
  return { ok: status >= 200 && status < 300, status, json: async () => body, text: async () => JSON.stringify(body) };
}
function recordingFetch(calls: string[]): FetchFn {
  return async (url: string) => {
    calls.push(url);
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
function writeAction(rel: string, content: string): string {
  const p = join(dir, rel);
  mkdirSync(join(p, ".."), { recursive: true });
  writeFileSync(p, content, "utf8");
  return p;
}
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "actionpin-waveb-")); });
afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

const VITE_BOT = [
  "name: bot",
  "on: [push]",
  "jobs:",
  "  a:",
  "    runs-on: ubuntu-latest",
  "    steps:",
  `      - uses: actions/checkout@${SHA_B}`,
  "      - uses: $/.github/actions/issues-helper",
  "      - uses: $/.github/actions/issues-helper",
].join("\n") + "\n";

const ISSUES_HELPER = [
  "name: issues-helper",
  "runs:",
  "  using: composite",
  "  steps:",
  `    - uses: actions/github-script@${SHA_GS}`,
].join("\n") + "\n";

describe("waveB P-057: malformed local path prefix", () => {
  it("classifies the $/.github/actions shape as LOCAL, never third-party", () => {
    const refs = parseWorkflowContent("      - uses: $/.github/actions/issues-helper\n", "bot.yml");
    assert.equal(refs.length, 1);
    assert.equal(refs[0].classification, "LOCAL");
    assert.equal(refs[0].ownerType, "local");
    assert.equal(refs[0].ref, "");
  });
  it("ownerTypeFor agrees the shape is local", () => {
    assert.equal(ownerTypeFor("$/.github/actions/issues-helper", "$/.github/actions/issues-helper"), "local");
  });
  it("keeps the malformed prefix visible as a note on the finding", () => {
    const refs = parseWorkflowContent("      - uses: $/.github/actions/issues-helper\n", "bot.yml");
    assert.ok(refs[0].note, "finding carries no note");
    assert.match(refs[0].note!, /not a valid remote/);
    assert.match(refs[0].note!, /local path/);
    const rendered = renderReport(auditWorkflows(dir));
    assert.ok(rendered.length >= 0);
  });
  it("the vite fixture estate verdicts PINNED, driven by its real refs", () => {
    writeWorkflow("bot.yml", VITE_BOT);
    writeAction(join(".github", "actions", "issues-helper", "action.yml"), ISSUES_HELPER);
    const r = auditWorkflows(dir);
    assert.equal(r.counts.mutable, 0);
    assert.equal(r.counts.thirdParty, 0);
    assert.equal(r.counts.local, 2);
    assert.equal(r.verdict, "PINNED");
    for (const a of r.actions.filter((x) => x.uses.startsWith("$/"))) {
      assert.equal(a.classification, "LOCAL");
      assert.ok(a.note && /local path/.test(a.note), "malformed note missing from audit evidence");
    }
    assert.match(renderReport(r), /local path/);
  });
  it("fix never attempts API resolution for the shape and emits no FAIL for it", async () => {
    writeWorkflow("bot.yml", VITE_BOT);
    writeAction(join(".github", "actions", "issues-helper", "action.yml"), ISSUES_HELPER);
    const calls: string[] = [];
    const plan = await buildPinPlan(dir, recordingFetch(calls));
    assert.equal(calls.length, 0, `fix attempted network resolution: ${calls.join(", ")}`);
    const dollarEntries = plan.entries.filter((e) => e.action.includes("issues-helper") && !e.action.includes("github-script"));
    assert.ok(dollarEntries.length >= 2);
    assert.ok(dollarEntries.every((e) => e.status === "local"));
    assert.equal(plan.entries.filter((e) => e.status === "failed").length, 0);
    assert.ok(!renderPlan(plan, false).includes("[FAIL]"));
  });
});

describe("waveB P-058: composite action internals in directory scans", () => {
  it("a mutable ref inside a .github/actions composite is inventoried and verdicts EXPOSED", () => {
    writeWorkflow("ci.yml", `    steps:\n      - uses: actions/checkout@${SHA_B}\n      - uses: ./.github/actions/helper\n`);
    writeAction(join(".github", "actions", "helper", "action.yml"), [
      "name: helper",
      "runs:",
      "  using: composite",
      "  steps:",
      "    - uses: evil-corp/tool@v1",
      `    - uses: actions/github-script@${SHA_GS}`,
    ].join("\n") + "\n");
    const r = auditWorkflows(dir);
    assert.equal(r.counts.total, 4);
    assert.equal(r.counts.mutable, 1);
    assert.equal(r.counts.local, 1);
    assert.equal(r.verdict, "EXPOSED");
    const inner = r.actions.find((a) => a.action === "evil-corp/tool");
    assert.ok(inner, "composite internal ref missing");
    assert.equal(inner!.composite, true);
    assert.ok(inner!.workflow.endsWith(join("helper", "action.yml")));
  });
  it("scans action.yaml under .github/actions even when no workflow references it", () => {
    writeWorkflow("ci.yml", `    steps:\n      - uses: actions/checkout@${SHA_B}\n`);
    writeAction(join(".github", "actions", "orphan", "action.yaml"), [
      "name: orphan",
      "runs:",
      "  using: composite",
      "  steps:",
      "    - uses: evil-corp/tool@v2",
    ].join("\n") + "\n");
    const r = auditWorkflows(dir);
    assert.equal(r.counts.total, 2);
    assert.equal(r.verdict, "EXPOSED");
    assert.equal(r.composites?.length, 1);
  });
  it("scans a referenced local action outside .github/actions (action.yaml)", () => {
    writeWorkflow("ci.yml", "    steps:\n      - uses: ./tools/my-action\n");
    writeAction(join("tools", "my-action", "action.yaml"), [
      "name: mine",
      "runs:",
      "  using: composite",
      "  steps:",
      "    - uses: actions/setup-node@v4",
    ].join("\n") + "\n");
    const r = auditWorkflows(dir);
    assert.equal(r.counts.total, 2);
    assert.equal(r.counts.mutable, 1);
    assert.equal(r.verdict, "PARTIAL");
    assert.equal(r.actions.find((a) => a.action === "actions/setup-node")?.composite, true);
  });
  it("does not double-count a composite that is both under .github/actions and referenced", () => {
    writeWorkflow("ci.yml", "    steps:\n      - uses: ./.github/actions/helper\n");
    writeAction(join(".github", "actions", "helper", "action.yml"), [
      "name: helper",
      "runs:",
      "  using: composite",
      "  steps:",
      `    - uses: actions/github-script@${SHA_GS}`,
    ].join("\n") + "\n");
    const r = auditWorkflows(dir);
    assert.equal(r.counts.total, 2);
    assert.equal(r.composites?.length, 1);
  });
  it("a JavaScript local action with no internal steps adds no refs but counts as scanned", () => {
    writeWorkflow("ci.yml", "    steps:\n      - uses: ./.github/actions/jsact\n");
    writeAction(join(".github", "actions", "jsact", "action.yml"), [
      "name: jsact",
      "runs:",
      "  using: node20",
      "  main: index.js",
    ].join("\n") + "\n");
    const r = auditWorkflows(dir);
    assert.equal(r.counts.total, 1);
    assert.equal(r.composites?.length, 1);
    assert.equal(r.verdict, "PINNED");
  });
});

describe("waveB P-046: composite coverage is stated in the report", () => {
  it("the report states how many composite files were scanned", () => {
    writeWorkflow("ci.yml", "    steps:\n      - uses: ./.github/actions/helper\n");
    writeAction(join(".github", "actions", "helper", "action.yml"), ISSUES_HELPER.replace("issues-helper", "helper"));
    const r = auditWorkflows(dir);
    assert.equal(r.composites?.length, 1);
    assert.match(renderReport(r), /composite/);
    assert.match(renderReport(r), /1 composite/);
  });
  it("an unreferenced action file outside .github/actions is named as unscanned", () => {
    writeWorkflow("ci.yml", `    steps:\n      - uses: actions/checkout@${SHA_B}\n`);
    // Since P-067 the root-level action.yml is the scanned repo's own
    // action definition and is always scanned, so the unscanned
    // remainder is an unreferenced action file elsewhere in the tree.
    writeAction(join("tools", "orphan", "action.yml"), [
      "name: orphanact",
      "runs:",
      "  using: composite",
      "  steps:",
      "    - uses: evil-corp/tool@v1",
    ].join("\n") + "\n");
    const r = auditWorkflows(dir);
    assert.equal(r.counts.total, 1);
    assert.ok(r.unscannedComposites && r.unscannedComposites.length === 1, "unscanned remainder not recorded");
    assert.match(renderReport(r), /not scanned/);
  });
});

describe("waveB P-059: fix plan header states both counts", () => {
  it("header states to-pin and already-pinned numbers that match the body", async () => {
    writeWorkflow("ci.yml", [
      "    steps:",
      "      - uses: actions/checkout@v4",
      `      - uses: actions/setup-node@${SHA_B}`,
      `      - uses: actions/github-script@${SHA_GS}`,
    ].join("\n") + "\n");
    const fetchFn: FetchFn = async (url: string) => {
      if (url.includes("actions/checkout")) return jsonRes(200, { object: { sha: SHA_B, type: "commit" } });
      return jsonRes(404, { message: "not found" });
    };
    const plan = await buildPinPlan(dir, fetchFn);
    const header = renderPlan(plan, false).split("\n")[0];
    assert.match(header, /1 to pin/);
    assert.match(header, /2 already pinned/);
    assert.equal(plan.entries.filter((e) => e.status === "pinned").length, 1);
    assert.equal(plan.entries.filter((e) => e.status === "already-pinned").length, 2);
  });
  it("header agrees on a fully pinned estate (zero to pin)", async () => {
    writeWorkflow("bot.yml", VITE_BOT);
    writeAction(join(".github", "actions", "issues-helper", "action.yml"), ISSUES_HELPER);
    const plan = await buildPinPlan(dir, recordingFetch([]));
    const header = renderPlan(plan, false).split("\n")[0];
    assert.match(header, /0 to pin/);
    assert.match(header, /2 already pinned/);
  });
});
