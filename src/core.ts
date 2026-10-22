/**
 * actionpin core: line-wise parsing of GitHub workflow files, classification
 * of every uses: reference, verdict computation, and SHA pin planning.
 *
 * Parsing is deliberately line-wise with no YAML library. Fix mode must
 * preserve the author's formatting exactly, so the file is never parsed
 * into a document and re-emitted. All network access (resolving a tag or
 * branch to a commit SHA) goes through an injectable FetchFn; unit tests
 * use fixtures and never touch the network.
 */
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { basename, join } from "node:path";
import type {
  ActionRef,
  AuditReport,
  Classification,
  FetchFn,
  FixResult,
  OwnerType,
  PinPlan,
  PinPlanEntry,
  Verdict,
} from "./types.js";

export const VERSION = "0.1.2";

const SHA_RE = /^[0-9a-f]{40}$/i;
const VERSION_RE = /^v?\d+(\.\d+){0,2}([-.+][0-9A-Za-z.-]+)?$/;
const BRANCH_NAMES = new Set(["main", "master", "head", "develop", "dev", "trunk", "release"]);

export function classifyRef(ref: string): Classification {
  if (!ref) return "MUTABLE";
  if (SHA_RE.test(ref)) return "PINNED";
  const lower = ref.toLowerCase();
  if (BRANCH_NAMES.has(lower) || ref.includes("/")) return "BRANCH";
  if (VERSION_RE.test(ref)) return "MUTABLE";
  // Anything that is not a version tag and not a SHA is a moving branch name.
  return "BRANCH";
}

export function ownerTypeFor(action: string, uses: string): OwnerType {
  if (uses.startsWith("./") || uses.startsWith("../")) return "local";
  if (uses.startsWith("docker://")) return "docker";
  const owner = action.split("/")[0]?.toLowerCase() ?? "";
  if (owner === "actions" || owner === "github") return "official";
  return "third-party";
}

/** Strip surrounding quotes and a trailing YAML comment from a uses value token. */
function cleanToken(raw: string): string {
  let v = raw.trim();
  // A trailing comment starts with a space-hash outside quotes; the uses
  // value itself never contains a space, so take the first token.
  v = v.split(/\s+/)[0] ?? "";
  if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
    v = v.slice(1, -1);
  }
  return v;
}

export function parseUsesLine(rawLine: string): { uses: string; action: string; ref: string } | null {
  const m = /^\s*-?\s*uses\s*:\s*(.+?)\s*$/.exec(rawLine);
  if (!m) return null;
  const uses = cleanToken(m[1]);
  if (!uses) return null;
  // A value that contains a GitHub expression is decided at workflow run
  // time (matrix, inputs, vars). It cannot be classified statically, so it
  // is skipped rather than reported as a fabricated action or ref.
  if (uses.includes("${{")) return null;
  if (uses.startsWith("./") || uses.startsWith("../")) {
    return { uses, action: uses, ref: "" };
  }
  if (uses.startsWith("docker://")) {
    // docker://image:tag or docker://image@sha256:digest
    const rest = uses.slice("docker://".length);
    const at = rest.lastIndexOf("@");
    if (at > 0) return { uses, action: `docker://${rest.slice(0, at)}`, ref: rest.slice(at + 1) };
    const colon = rest.lastIndexOf(":");
    if (colon > 0 && !rest.slice(colon + 1).includes("/")) {
      return { uses, action: `docker://${rest.slice(0, colon)}`, ref: rest.slice(colon + 1) };
    }
    return { uses, action: uses, ref: "" };
  }
  const at = uses.lastIndexOf("@");
  if (at <= 0) return { uses, action: uses, ref: "" };
  return { uses, action: uses.slice(0, at), ref: uses.slice(at + 1) };
}

export function parseWorkflowContent(content: string, workflow: string): ActionRef[] {
  const out: ActionRef[] = [];
  const lines = content.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const parsed = parseUsesLine(lines[i]);
    if (!parsed) continue;
    const ownerType = ownerTypeFor(parsed.action, parsed.uses);
    let classification: Classification;
    if (ownerType === "local") classification = "LOCAL";
    else if (ownerType === "docker") {
      // A docker image pinned by sha256 digest counts as pinned; a tag does not.
      classification = parsed.ref.startsWith("sha256:") || SHA_RE.test(parsed.ref) ? "PINNED" : parsed.ref ? classifyRef(parsed.ref) === "PINNED" ? "PINNED" : "MUTABLE" : "MUTABLE";
      if (parsed.ref && /^sha256:[0-9a-f]{64}$/i.test(parsed.ref)) classification = "PINNED";
    } else if (!parsed.ref) classification = "MUTABLE";
    else classification = classifyRef(parsed.ref);
    out.push({
      workflow,
      line: i + 1,
      uses: parsed.uses,
      action: parsed.action,
      ref: parsed.ref,
      classification,
      ownerType,
      rawLine: lines[i],
    });
  }
  return out;
}

export function computeVerdict(actions: ActionRef[]): Verdict {
  let hasPartial = false;
  for (const a of actions) {
    if (a.classification === "LOCAL" || a.classification === "PINNED") continue;
    if (a.ownerType === "third-party" || a.ownerType === "docker") return "EXPOSED";
    hasPartial = true;
  }
  return hasPartial ? "PARTIAL" : "PINNED";
}

export function discoverWorkflows(rootPath: string): string[] {
  try {
    const st = statSync(rootPath);
    if (st.isFile()) return [rootPath];
  } catch {
    return [];
  }
  const candidates = [
    join(rootPath, ".github", "workflows"),
    ...(basename(rootPath) === "workflows" ? [rootPath] : []),
    ...(basename(rootPath) === ".github" ? [join(rootPath, "workflows")] : []),
  ];
  for (const dir of candidates) {
    if (existsSync(dir) && statSync(dir).isDirectory()) {
      return readdirSync(dir)
        .filter((f) => /\.ya?ml$/i.test(f))
        .sort()
        .map((f) => join(dir, f));
    }
  }
  return [];
}

export function auditWorkflows(rootPath: string): AuditReport {
  const files = discoverWorkflows(rootPath);
  const actions: ActionRef[] = [];
  for (const f of files) {
    actions.push(...parseWorkflowContent(readFileSync(f, "utf8"), f));
  }
  const counts = {
    total: actions.length,
    pinned: actions.filter((a) => a.classification === "PINNED").length,
    mutable: actions.filter((a) => a.classification === "MUTABLE").length,
    branch: actions.filter((a) => a.classification === "BRANCH").length,
    local: actions.filter((a) => a.classification === "LOCAL").length,
    official: actions.filter((a) => a.ownerType === "official").length,
    thirdParty: actions.filter((a) => a.ownerType === "third-party").length,
    docker: actions.filter((a) => a.ownerType === "docker").length,
  };
  const report: AuditReport = {
    path: rootPath,
    verdict: computeVerdict(actions),
    actions,
    counts,
    workflows: files,
    checkedAt: new Date().toISOString(),
  };
  if (files.length === 0) {
    // P-014: PINNED over zero workflows is vacuously true and was read as
    // an all-clear on real repos with no workflows directory at all
    // (kubernetes/kubernetes in Round 1 validation). Say so in the report
    // itself, so every consumer sees the caveat next to the verdict.
    report.note =
      `No workflows found under ${rootPath}: there is no .github/workflows directory with .yml or .yaml files there, ` +
      "so nothing was audited. The verdict above covers an empty estate and is not an all-clear; " +
      "point actionpin at the repo root or at a workflows directory.";
  }
  return report;
}

function ghHeaders(): Record<string, string> {
  const h: Record<string, string> = {
    "User-Agent": `actionpin/${VERSION}`,
    Accept: "application/vnd.github+json",
  };
  const token = process.env.GITHUB_TOKEN;
  if (token) h.Authorization = `Bearer ${token}`;
  return h;
}

/**
 * Resolve a tag or branch ref to a commit SHA via the GitHub API.
 * Tries git refs for tags, then heads, then a direct commit lookup.
 * Annotated tags are dereferenced to their commit.
 */
export async function resolveRefToSha(
  fetchFn: FetchFn,
  owner: string,
  repo: string,
  ref: string,
): Promise<string> {
  // Encode each ref segment separately: the GitHub git-ref API takes the
  // ref as a path, so a slash inside a tag or branch name (release/v1,
  // feature/new-thing) must survive as a slash, not become %2F.
  const encRef = ref.split("/").map(encodeURIComponent).join("/");
  const attempts: Array<{ url: string; kind: "tag" | "head" | "commit" }> = [
    { url: `https://api.github.com/repos/${owner}/${repo}/git/ref/tags/${encRef}`, kind: "tag" },
    { url: `https://api.github.com/repos/${owner}/${repo}/git/ref/heads/${encRef}`, kind: "head" },
    { url: `https://api.github.com/repos/${owner}/${repo}/commits/${encRef}`, kind: "commit" },
  ];
  let lastStatus = 0;
  for (const attempt of attempts) {
    const res = await fetchFn(attempt.url, { headers: ghHeaders() });
    lastStatus = res.status;
    if (!res.ok) continue;
    const data = (await res.json().catch(() => null)) as Record<string, unknown> | null;
    if (!data) continue;
    if (attempt.kind === "commit") {
      if (typeof data.sha === "string" && SHA_RE.test(data.sha)) return data.sha;
      continue;
    }
    const obj = data.object as { sha?: string; type?: string } | undefined;
    if (!obj?.sha) continue;
    if (obj.type === "commit" && SHA_RE.test(obj.sha)) return obj.sha;
    if (obj.type === "tag") {
      const tagRes = await fetchFn(
        `https://api.github.com/repos/${owner}/${repo}/git/tags/${obj.sha}`,
        { headers: ghHeaders() },
      );
      if (tagRes.ok) {
        const tagData = (await tagRes.json().catch(() => null)) as Record<string, unknown> | null;
        const inner = tagData?.object as { sha?: string } | undefined;
        if (inner?.sha && SHA_RE.test(inner.sha)) return inner.sha;
      }
    }
  }
  throw new Error(`Could not resolve ${owner}/${repo}@${ref} to a commit SHA (GitHub API status ${lastStatus})`);
}

/** Split an action into owner/repo, dropping any sub-path beyond repo. */
export function actionRepo(action: string): { owner: string; repo: string } | null {
  const parts = action.split("/");
  if (parts.length < 2) return null;
  return { owner: parts[0], repo: parts[1] };
}

/** Build the rewritten line for a pinned action, preserving indentation and content. */
export function buildPinnedLine(rawLine: string, actionRef: ActionRef, sha: string): string {
  const needle = `${actionRef.action}@${actionRef.ref}`;
  // A quoted uses value must keep its closing quote before the version
  // comment, or the comment becomes part of the quoted string and corrupts
  // the action reference.
  for (const q of ['"', "'"]) {
    const quoted = `${q}${needle}${q}`;
    if (rawLine.includes(quoted)) {
      return rawLine.replace(quoted, `${q}${actionRef.action}@${sha}${q} # ${actionRef.ref}`);
    }
  }
  const replacement = `${actionRef.action}@${sha} # ${actionRef.ref}`;
  if (rawLine.includes(needle)) return rawLine.replace(needle, replacement);
  // Fallback: replace the uses value token.
  return rawLine.replace(actionRef.uses, replacement);
}

export async function buildPinPlan(rootPath: string, fetchFn: FetchFn): Promise<PinPlan> {
  const report = auditWorkflows(rootPath);
  const entries: PinPlanEntry[] = [];
  // Cache resolutions per owner/repo@ref.
  const cache = new Map<string, string>();
  for (const a of report.actions) {
    if (a.classification === "LOCAL") {
      entries.push({ workflow: a.workflow, line: a.line, action: a.action, oldRef: a.ref, originalLine: a.rawLine, status: "local" });
      continue;
    }
    if (a.classification === "PINNED") {
      entries.push({ workflow: a.workflow, line: a.line, action: a.action, oldRef: a.ref, originalLine: a.rawLine, status: "already-pinned" });
      continue;
    }
    if (a.ownerType === "docker") {
      entries.push({ workflow: a.workflow, line: a.line, action: a.action, oldRef: a.ref, originalLine: a.rawLine, status: "failed", error: "Docker image refs are reported but not rewritten by actionpin; pin by digest manually" });
      continue;
    }
    const repoRef = actionRepo(a.action);
    if (!repoRef) {
      entries.push({ workflow: a.workflow, line: a.line, action: a.action, oldRef: a.ref, originalLine: a.rawLine, status: "failed", error: `Cannot parse owner/repo from action ${a.action}` });
      continue;
    }
    const key = `${repoRef.owner}/${repoRef.repo}@${a.ref}`;
    try {
      let sha = cache.get(key);
      if (!sha) {
        sha = await resolveRefToSha(fetchFn, repoRef.owner, repoRef.repo, a.ref);
        cache.set(key, sha);
      }
      const newLine = buildPinnedLine(a.rawLine, a, sha);
      entries.push({ workflow: a.workflow, line: a.line, action: a.action, oldRef: a.ref, newRef: sha, sha, originalLine: a.rawLine, newLine, status: "pinned" });
    } catch (err) {
      entries.push({ workflow: a.workflow, line: a.line, action: a.action, oldRef: a.ref, originalLine: a.rawLine, status: "failed", error: err instanceof Error ? err.message : String(err) });
    }
  }
  const plan: PinPlan = {
    path: rootPath,
    entries,
    changes: entries.filter((e) => e.status === "pinned" && e.newLine && e.newLine !== e.originalLine).length,
    checkedAt: new Date().toISOString(),
  };
  if (report.note) plan.note = report.note;
  return plan;
}

export async function applyPinPlan(rootPath: string, fetchFn: FetchFn): Promise<FixResult> {
  const plan = await buildPinPlan(rootPath, fetchFn);
  const byFile = new Map<string, PinPlanEntry[]>();
  for (const e of plan.entries) {
    if (e.status !== "pinned" || !e.newLine) continue;
    const list = byFile.get(e.workflow) ?? [];
    list.push(e);
    byFile.set(e.workflow, list);
  }
  const filesChanged: string[] = [];
  for (const [file, entriesForFile] of byFile) {
    const original = readFileSync(file, "utf8");
    const lines = original.split("\n");
    let changed = false;
    for (const e of entriesForFile) {
      const idx = e.line - 1;
      if (idx >= 0 && idx < lines.length && e.newLine) {
        // The file was split on \n, so a CRLF file keeps a trailing \r on
        // each untouched line. The planned new line was built from a
        // \r-stripped raw line, so restore the \r or the rewritten line
        // would silently switch the file to mixed line endings.
        let newLine = e.newLine;
        if (lines[idx].endsWith("\r") && !newLine.endsWith("\r")) newLine += "\r";
        if (lines[idx] !== newLine) {
          lines[idx] = newLine;
          changed = true;
        }
      }
    }
    if (changed) {
      writeFileSync(file, lines.join("\n"), "utf8");
      filesChanged.push(file);
    }
  }
  return { ...plan, applied: true, filesChanged };
}

export function renderReport(report: AuditReport): string {
  const lines: string[] = [];
  lines.push(`actionpin audit ${report.path}: ${report.verdict}`);
  if (report.note) lines.push(`  NOTE: ${report.note}`);
  lines.push(`  workflows: ${report.workflows.length}, actions: ${report.counts.total}, pinned: ${report.counts.pinned}, mutable: ${report.counts.mutable}, branch: ${report.counts.branch}, local: ${report.counts.local}`);
  for (const a of report.actions) {
    lines.push(`  [${a.classification}] ${a.workflow}:${a.line} ${a.uses} (${a.ownerType})`);
  }
  if (report.note) lines.push("No workflows were audited, so no pinning conclusion applies to this path.");
  else if (report.verdict === "PINNED") lines.push("PINNED: every non-local action is pinned to a full commit SHA.");
  else if (report.verdict === "EXPOSED") lines.push("EXPOSED: at least one third-party or container action uses a mutable tag or branch ref.");
  else lines.push("PARTIAL: some official actions use mutable or branch refs, no third-party exposure found.");
  return lines.join("\n");
}

export function renderPlan(plan: PinPlan, applied: boolean): string {
  const lines: string[] = [];
  lines.push(`actionpin ${applied ? "fix" : "pin plan"} ${plan.path}: ${plan.changes} change(s)`);
  if (plan.note) lines.push(`  NOTE: ${plan.note}`);
  for (const e of plan.entries) {
    if (e.status === "pinned") lines.push(`  [PIN] ${e.workflow}:${e.line} ${e.action}@${e.oldRef} -> ${e.sha} # ${e.oldRef}`);
    else if (e.status === "failed") lines.push(`  [FAIL] ${e.workflow}:${e.line} ${e.action}@${e.oldRef}: ${e.error ?? "resolution failed, line left unchanged"}`);
    else lines.push(`  [${e.status.toUpperCase()}] ${e.workflow}:${e.line} ${e.action}${e.oldRef ? `@${e.oldRef}` : ""}`);
  }
  return lines.join("\n");
}
