/**
 * Wave A evasion hunt regressions (overnight flywheel, 2026-10-21).
 * Every case here failed against the published v0.1.2 binary first;
 * the hunt report is at ~/workspace/security-wave/overnight/waves/waveA-actionpin/HUNT.md.
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
  classifyRef,
  parseUsesLine,
  parseWorkflowContent,
} from "../src/core.js";
import type { FetchFn, FetchResponse } from "../src/types.js";

const SHA_B = "0123456789abcdef0123456789abcdef01234567";
const SHA_C = "f".repeat(40);
const DIGEST = "sha256:" + "a".repeat(64);

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
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), "actionpin-wavea-")); });
afterEach(() => { rmSync(dir, { recursive: true, force: true }); });

describe("waveA: docker digest validation", () => {
  it("a truncated sha256 digest is not a pin", () => {
    const refs = parseWorkflowContent("      - uses: docker://alpine@sha256:abcd1234\n", "d.yml");
    assert.equal(refs[0].classification, "MUTABLE");
  });
  it("a non-hex sha256 digest is not a pin", () => {
    const bad = "sha256:" + "z".repeat(64);
    const refs = parseWorkflowContent(`      - uses: docker://alpine@${bad}\n`, "d.yml");
    assert.equal(refs[0].classification, "MUTABLE");
  });
  it("a docker tag spelled as 40 hex chars is a mutable tag, not a pin", () => {
    const refs = parseWorkflowContent(`      - uses: docker://myimage:${SHA_B}\n`, "d.yml");
    assert.equal(refs[0].classification, "MUTABLE");
  });
  it("a repo whose only docker line has an invalid digest is EXPOSED, not PINNED", () => {
    writeWorkflow("d.yml", "      - uses: docker://alpine@sha256:abcd1234\n");
    const r = auditWorkflows(dir);
    assert.equal(r.verdict, "EXPOSED");
    assert.equal(r.counts.pinned, 0);
  });
  it("a full sha256 digest still counts as pinned (control)", () => {
    const refs = parseWorkflowContent(`      - uses: docker://alpine@${DIGEST}\n`, "d.yml");
    assert.equal(refs[0].classification, "PINNED");
  });
  it("a full sha512 digest counts as pinned", () => {
    const d512 = "sha512:" + "a".repeat(128);
    const refs = parseWorkflowContent(`      - uses: docker://alpine@${d512}\n`, "d.yml");
    assert.equal(refs[0].classification, "PINNED");
  });
});

describe("waveA: YAML anchors and aliases on uses values", () => {
  it("parses the real action behind a value anchor", () => {
    const p = parseUsesLine("      - uses: &anchored actions/setup-node@v4");
    assert.equal(p?.action, "actions/setup-node");
    assert.equal(p?.ref, "v4");
  });
  it("an anchored pinned action and its alias verdict PINNED", () => {
    const content = [
      "    steps:",
      `      - uses: &pin actions/checkout@${SHA_B}`,
      "      - uses: *pin",
    ].join("\n");
    const refs = parseWorkflowContent(content, "a.yml");
    assert.equal(refs.length, 2);
    assert.ok(refs.every((r) => r.action === "actions/checkout"));
    assert.ok(refs.every((r) => r.classification === "PINNED"));
    assert.ok(refs.every((r) => r.ownerType === "official"));
  });
  it("an alias inherits the anchored classification in a full audit", () => {
    writeWorkflow("a.yml", `    steps:\n      - uses: &m actions/checkout@v4\n      - uses: *m\n`);
    const r = auditWorkflows(dir);
    assert.equal(r.verdict, "PARTIAL");
    assert.equal(r.counts.total, 2);
    assert.equal(r.counts.mutable, 2);
    assert.equal(r.counts.official, 2);
    assert.equal(r.counts.thirdParty, 0);
  });
  it("an alias to an undefined anchor is skipped, never fabricated", () => {
    const refs = parseWorkflowContent("      - uses: *missing\n", "a.yml");
    assert.equal(refs.length, 0);
  });
  it("anchors and aliases resolve inside a composite action.yml parsed as a file", () => {
    const content = ["runs:", "  using: composite", "  steps:", "    - uses: &av actions/checkout@v4", "    - uses: *av"].join("\n");
    const refs = parseWorkflowContent(content, "action.yml");
    assert.equal(refs.length, 2);
    assert.ok(refs.every((r) => r.action === "actions/checkout" && r.classification === "MUTABLE"));
  });
});

describe("waveA: step anchors", () => {
  it("a step anchor between the dash and the uses key is inventoried", () => {
    writeWorkflow("a.yml", "    steps:\n      - &step uses: evil-corp/tool@v1\n");
    const r = auditWorkflows(dir);
    assert.equal(r.counts.total, 1);
    assert.equal(r.verdict, "EXPOSED");
    assert.equal(r.actions[0].action, "evil-corp/tool");
  });
  it("a step alias reuses the anchored step", () => {
    const content = [
      "    steps:",
      "      - &ownline",
      "        uses: actions/checkout@v4",
      "      - *ownline",
    ].join("\n");
    const refs = parseWorkflowContent(content, "a.yml");
    assert.equal(refs.length, 2);
    assert.ok(refs.every((r) => r.action === "actions/checkout" && r.classification === "MUTABLE"));
    assert.equal(refs[1].line, 4);
  });
});

describe("waveA: quoted values with spaces", () => {
  it("a trailing space inside quotes does not corrupt the action or owner", () => {
    const p = parseUsesLine('      - uses: "actions/setup-node@v4 "');
    assert.equal(p?.action, "actions/setup-node");
    assert.equal(p?.ref, "v4");
    writeWorkflow("q.yml", '    steps:\n      - uses: "actions/setup-node@v4 "\n');
    const r = auditWorkflows(dir);
    assert.equal(r.verdict, "PARTIAL");
    assert.equal(r.counts.official, 1);
    assert.equal(r.counts.thirdParty, 0);
  });
  it("a comment inside the quotes does not corrupt a pinned action", () => {
    const refs = parseWorkflowContent(`      - uses: "actions/checkout@${SHA_B} # v4"\n`, "q.yml");
    assert.equal(refs[0].action, "actions/checkout");
    assert.equal(refs[0].classification, "PINNED");
    assert.equal(refs[0].ownerType, "official");
  });
  it("a trailing space inside quotes on a pinned action stays PINNED and official", () => {
    const refs = parseWorkflowContent(`      - uses: "actions/checkout@${SHA_B} "\n`, "q.yml");
    assert.equal(refs[0].action, "actions/checkout");
    assert.equal(refs[0].classification, "PINNED");
    assert.equal(refs[0].ownerType, "official");
  });
});

describe("waveA: uppercase version tags", () => {
  it("classifies V4 and V6 as MUTABLE version tags, not branches", () => {
    assert.equal(classifyRef("V4"), "MUTABLE");
    assert.equal(classifyRef("V6"), "MUTABLE");
    assert.equal(classifyRef("V1.2.3"), "MUTABLE");
  });
  it("audit counts uppercase tags in the mutable bucket", () => {
    writeWorkflow("u.yml", "    steps:\n      - uses: actions/checkout@V4\n      - uses: docker/build-push-action@V6\n");
    const r = auditWorkflows(dir);
    assert.equal(r.counts.mutable, 2);
    assert.equal(r.counts.branch, 0);
    assert.equal(r.verdict, "EXPOSED");
  });
});

describe("waveA: corpus-shaped integration", () => {
  it("matches the waveA anchors corpus fixture expectations", () => {
    const content = [
      "name: waveA anchors",
      "on: [push]",
      "jobs:",
      "  a:",
      "    runs-on: ubuntu-latest",
      "    steps:",
      `      - uses: &pin actions/checkout@${SHA_B}`,
      "      - uses: *pin",
      "      - uses: &mut actions/setup-node@v4",
      "      - uses: *mut",
      "      - &step uses: evil-corp/tool@v1",
      "      - &ownline",
      "        uses: actions/checkout@v4",
    ].join("\n") + "\n";
    writeWorkflow("w.yml", content);
    const r = auditWorkflows(dir);
    assert.equal(r.verdict, "EXPOSED");
    assert.deepEqual(
      { total: r.counts.total, pinned: r.counts.pinned, mutable: r.counts.mutable, official: r.counts.official, thirdParty: r.counts.thirdParty },
      { total: 6, pinned: 2, mutable: 4, official: 5, thirdParty: 1 },
    );
  });
});

describe("waveA: fix mode with anchors", () => {
  it("fix pins the anchor definition line, leaves alias lines untouched, and re-audits PINNED", async () => {
    const p = writeWorkflow("a.yml", `    steps:\n      - uses: &m actions/checkout@v4\n      - uses: *m\n`);
    const result = await applyPinPlan(dir, fixtureFetch({ "actions/checkout": SHA_C }));
    const after = readFileSync(p, "utf8");
    assert.ok(after.includes(`&m actions/checkout@${SHA_C} # v4`), `definition line not pinned: ${after}`);
    assert.ok(after.includes("- uses: *m"), `alias line was rewritten: ${after}`);
    assert.equal(result.changes, 1);
    const aliasEntry = result.entries.find((e) => e.line === 3);
    assert.equal(aliasEntry?.status, "failed");
    assert.match(aliasEntry?.error ?? "", /anchor/);
    assert.equal(auditWorkflows(dir).verdict, "PINNED");
  });
  it("pin plan for an anchored mutable action resolves through the definition line only", async () => {
    writeWorkflow("a.yml", `    steps:\n      - uses: &m actions/checkout@v4\n      - uses: *m\n`);
    const plan = await buildPinPlan(dir, fixtureFetch({ "actions/checkout": SHA_C }));
    assert.equal(plan.changes, 1);
    assert.equal(plan.entries.filter((e) => e.status === "pinned").length, 1);
  });
});
