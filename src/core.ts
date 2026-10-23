/**
 * actionpin core: line-wise parsing of GitHub workflow files, classification
 * of every uses: reference, verdict computation, and SHA pin planning.
 *
 * Parsing is deliberately line-wise with no YAML library. Fix mode must
 * preserve the author's formatting exactly, so the file is never parsed
 * into a document and re-emitted. A quote-aware flow scanner covers
 * YAML flow style on top of the block parser (P-174). All network
 * access (resolving a tag or branch to a commit SHA) goes through an
 * injectable FetchFn; unit tests use fixtures and never touch the
 * network.
 */
import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
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

export const VERSION = "0.1.7";

const SHA_RE = /^[0-9a-f]{40}$/i;
const VERSION_RE = /^v?\d+(\.\d+){0,2}([-.+][0-9A-Za-z.-]+)?$/i;
/** A container image is pinned only by a full content digest, never by a tag. */
const DOCKER_DIGEST_RE = /^(?:sha256:[0-9a-f]{64}|sha512:[0-9a-f]{128})$/i;
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

/**
 * A uses value whose path looks like a local .github/actions (or
 * .github/workflows) path behind a malformed prefix, the vitejs/vite
 * shape `uses: $/.github/actions/issues-helper` (P-057): a stray
 * character where the dot of the ./ prefix belongs. It names no remote
 * repository, so it is a local path with a typo, never a third-party
 * action, and it must never be resolved against the GitHub API.
 */
const MALFORMED_LOCAL_RE = /^[^A-Za-z0-9]+\/.github\/(?:actions|workflows)\//;

export function isMalformedLocalUses(uses: string): boolean {
  if (uses.startsWith("./") || uses.startsWith("../")) return false;
  return MALFORMED_LOCAL_RE.test(uses);
}

export function isLocalUses(uses: string): boolean {
  return uses.startsWith("./") || uses.startsWith("../") || isMalformedLocalUses(uses);
}

export function ownerTypeFor(action: string, uses: string): OwnerType {
  if (isLocalUses(uses)) return "local";
  if (uses.startsWith("docker://")) return "docker";
  const owner = action.split("/")[0]?.toLowerCase() ?? "";
  if (owner === "actions" || owner === "github") return "official";
  return "third-party";
}

/** Strip surrounding quotes and a trailing YAML comment from a uses value token. */
function cleanToken(raw: string): string {
  let v = raw.trim();
  const q = v[0];
  if (q === '"' || q === "'") {
    const end = v.indexOf(q, 1);
    if (end > 0) {
      // Take the quoted scalar itself rather than the first whitespace
      // token: a space before the closing quote, or a comment written
      // inside the quotes, used to cut the value at the space and leave
      // the action carrying a stray leading quote and a wrong owner.
      // A uses value never contains a space-hash segment, so a trailing
      // one inside the quotes is author commentary, not part of the ref.
      return v.slice(1, end).split(/\s+#/)[0].trim();
    }
  }
  // A trailing comment starts with a space-hash outside quotes; the uses
  // value itself never contains a space, so take the first token.
  v = v.split(/\s+/)[0] ?? "";
  if ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'"))) {
    v = v.slice(1, -1);
  }
  return v;
}

/** Split a cleaned uses value into action and ref. */
function splitUses(uses: string): { action: string; ref: string } {
  if (isLocalUses(uses)) {
    return { action: uses, ref: "" };
  }
  if (uses.startsWith("docker://")) {
    // docker://image:tag or docker://image@sha256:digest
    const rest = uses.slice("docker://".length);
    const at = rest.lastIndexOf("@");
    if (at > 0) return { action: `docker://${rest.slice(0, at)}`, ref: rest.slice(at + 1) };
    const colon = rest.lastIndexOf(":");
    if (colon > 0 && !rest.slice(colon + 1).includes("/")) {
      return { action: `docker://${rest.slice(0, colon)}`, ref: rest.slice(colon + 1) };
    }
    return { action: uses, ref: "" };
  }
  const at = uses.lastIndexOf("@");
  if (at <= 0) return { action: uses, ref: "" };
  return { action: uses.slice(0, at), ref: uses.slice(at + 1) };
}

export interface ParsedUses {
  uses: string;
  action: string;
  ref: string;
  /** Anchor name when the uses value itself carries one: uses: &name owner/repo@ref. */
  anchor?: string;
  /** Alias name when the uses value is an alias: uses: *name. Action and ref are empty until the alias is resolved against its anchor. */
  alias?: string;
  /** Anchor name when an anchor sits between the step dash and the uses key: - &name uses: owner/repo@ref. */
  stepAnchor?: string;
}

export function parseUsesLine(rawLine: string): ParsedUses | null {
  // A step anchor can sit between the dash and the key (- &step uses: ...)
  // and was previously enough to make the whole line invisible.
  const m = /^\s*(?:-\s*)?(?:&(\S+)\s+)?uses\s*:\s*(.+?)\s*$/.exec(rawLine);
  if (!m) return null;
  let rawValue = m[2].trim();
  // A value anchor (uses: &name owner/repo@ref) names the scalar that
  // follows it; the anchor token is not the action.
  let anchor: string | undefined;
  const am = /^&(\S+)\s+(.+)$/.exec(rawValue);
  if (am) {
    anchor = am[1];
    rawValue = am[2];
  }
  const uses = cleanToken(rawValue);
  if (!uses) return null;
  // A value that contains a GitHub expression is decided at workflow run
  // time (matrix, inputs, vars). It cannot be classified statically, so it
  // is skipped rather than reported as a fabricated action or ref.
  if (uses.includes("${{")) return null;
  if (uses.startsWith("*")) {
    // An alias reuses an anchored value defined earlier in the same file;
    // parseWorkflowContent resolves it. Reported on its own it would be a
    // fabricated action named after the alias token.
    return { uses, action: "", ref: "", anchor, alias: uses.slice(1), stepAnchor: m[1] };
  }
  const { action, ref } = splitUses(uses);
  return { uses, action, ref, anchor, stepAnchor: m[1] };
}

function buildActionRef(uses: string, workflow: string, line: number, rawLine: string, viaAlias: boolean): ActionRef {
  const { action, ref } = splitUses(uses);
  const ownerType = ownerTypeFor(action, uses);
  let classification: Classification;
  if (ownerType === "local") classification = "LOCAL";
  else if (ownerType === "docker") {
    // A container image is pinned only by a full sha256 or sha512 content
    // digest. Anything else is a tag, including a tag spelled as 40 hex
    // characters and a digest that is truncated or not hex at all; tags
    // can be re-pushed, so they never count as pinned.
    classification = DOCKER_DIGEST_RE.test(ref) ? "PINNED" : "MUTABLE";
  } else if (!ref) classification = "MUTABLE";
  else classification = classifyRef(ref);
  const out: ActionRef = { workflow, line, uses, action, ref, classification, ownerType, rawLine };
  if (viaAlias) out.viaAlias = true;
  if (isMalformedLocalUses(uses)) {
    // P-057: classify LOCAL, but keep the defect visible. Silently
    // reclassifying would hide a real typo in the target repo: the
    // prefix is not a valid remote reference and reads as a mistyped
    // local path, which GitHub itself would not run as written.
    out.note =
      `Malformed local path: ${uses} is not a valid remote action reference; ` +
      "the prefix before the .github path is not a repository owner and looks like a local path typo " +
      "(a local action path starts with ./). Classified LOCAL and never resolved against the GitHub API.";
  }
  return out;
}

/**
 * P-174: one uses occurrence found by the flow scanner. The scanner
 * walks a line outside quotes and comments and records every uses key
 * that sits in a key position (after a flow opener, a flow comma, or
 * at the start of a line that continues a flow collection opened on an
 * earlier line). A uses word inside a quoted string, a run command, or
 * a comment is not an occurrence.
 */
interface UsesOccurrence {
  /** Index of the uses key on its line, used to dedupe the block parser's entry. */
  start: number;
  /** The value token as written, quotes included when quoted; empty when the key carries no value. */
  valueToken: string;
  /** Anchor name when the value carries one: uses: &name owner/repo@ref. */
  anchor?: string;
  /** Anchor name when an anchor sits immediately before the uses key. */
  stepAnchor?: string;
}

/** Read a quoted scalar starting at line[start]; returns the token (quotes included) and the index just past it. */
function readQuotedToken(line: string, start: number): { token: string; end: number } {
  const q = line[start];
  let i = start + 1;
  while (i < line.length) {
    const c = line[i];
    if (q === '"' && c === "\\") { i += 2; continue; }
    if (c === q) {
      if (q === "'" && line[i + 1] === "'") { i += 2; continue; }
      return { token: line.slice(start, i + 1), end: i + 1 };
    }
    i++;
  }
  return { token: line.slice(start), end: line.length };
}

function scanUsesOccurrences(line: string, flowDepthAtStart: number): UsesOccurrence[] {
  const occs: UsesOccurrence[] = [];
  let inSingle = false;
  let inDouble = false;
  let seenFlowOpen = false;
  let i = 0;
  const isBoundaryBefore = (pos: number): boolean => {
    // A uses key is a candidate when the last non-space character
    // before it opens a flow entry or separates flow entries, or when
    // the key starts a line that continues a flow collection.
    let j = pos - 1;
    while (j >= 0 && (line[j] === " " || line[j] === "\t")) j--;
    if (j < 0) return true;
    const prev = line[j];
    if (prev === "{" || prev === "[") return true;
    if (prev === ",") return seenFlowOpen || flowDepthAtStart > 0;
    if (prev === "-") return line.slice(0, j).trim() === "" || seenFlowOpen || flowDepthAtStart > 0;
    return false;
  };
  while (i < line.length) {
    const c = line[i];
    if (inSingle) {
      if (c === "'" && line[i + 1] === "'") { i += 2; continue; }
      if (c === "'") inSingle = false;
      i++;
      continue;
    }
    if (inDouble) {
      if (c === "\\") { i += 2; continue; }
      if (c === '"') inDouble = false;
      i++;
      continue;
    }
    if (c === "#" && (i === 0 || /[\s{[,;]/.test(line[i - 1]))) break;
    if (c === "{" || c === "[") { seenFlowOpen = true; i++; continue; }
    // A quoted key ("uses": or 'uses':), the JSON-shaped flow form.
    if ((c === '"' || c === "'") && isBoundaryBefore(i)) {
      const km = /^["']uses["']\s*:\s*/.exec(line.slice(i));
      if (km) {
        const keyStart = i;
        i += km[0].length;
        i = pushFlowValue(line, i, occs, line.slice(0, keyStart), keyStart);
        continue;
      }
    }
    if (c === "'") { inSingle = true; i++; continue; }
    if (c === '"') { inDouble = true; i++; continue; }
    if (c === "u" && isBoundaryBefore(i)) {
      const km = /^uses\s*:\s*/.exec(line.slice(i));
      if (km) {
        const keyStart = i;
        i += km[0].length;
        i = pushFlowValue(line, i, occs, line.slice(0, keyStart), keyStart);
        continue;
      }
    }
    i++;
  }
  return occs;
}

/** Parse the value after a flow uses colon at line[pos], record the occurrence, and return the index just past the value. */
function pushFlowValue(line: string, pos: number, occs: UsesOccurrence[], prefix: string, start: number): number {
  let i = pos;
  let anchor: string | undefined;
  const am = /^&(\S+)\s+/.exec(line.slice(i));
  if (am) {
    anchor = am[1];
    i += am[0].length;
  }
  let valueToken = "";
  if (i < line.length && (line[i] === '"' || line[i] === "'")) {
    const r = readQuotedToken(line, i);
    valueToken = r.token;
    i = r.end;
  } else {
    let j = i;
    while (j < line.length && !/[\s,\]}]/.test(line[j])) j++;
    valueToken = line.slice(i, j);
    i = j;
  }
  const stepAnchorM = /&([A-Za-z0-9_-]+)[\s{[,]*$/.exec(prefix);
  occs.push({ start, valueToken, anchor, stepAnchor: stepAnchorM ? stepAnchorM[1] : undefined });
  return i;
}

/** Net flow-collection depth change of one line, counted outside quotes and comments. */
function flowDepthDelta(line: string): number {
  let delta = 0;
  let inSingle = false;
  let inDouble = false;
  for (let i = 0; i < line.length; i++) {
    const c = line[i];
    if (inSingle) {
      if (c === "'" && line[i + 1] === "'") { i++; continue; }
      if (c === "'") inSingle = false;
      continue;
    }
    if (inDouble) {
      if (c === "\\") { i++; continue; }
      if (c === '"') inDouble = false;
      continue;
    }
    if (c === "#" && (i === 0 || /[\s{[,;]/.test(line[i - 1]))) break;
    if (c === "'") { inSingle = true; continue; }
    if (c === '"') { inDouble = true; continue; }
    if (c === "{" || c === "[") delta++;
    else if (c === "}" || c === "]") delta--;
  }
  return delta;
}

type FlowValueParse =
  | { kind: "ok"; parsed: ParsedUses }
  | { kind: "dynamic" }
  | { kind: "empty" };

/** Build a ParsedUses from a flow value token, mirroring parseUsesLine's value handling. */
function parseFlowValue(occ: UsesOccurrence): FlowValueParse {
  const rawValue = occ.valueToken.trim();
  if (!rawValue) return { kind: "empty" };
  const uses = cleanToken(rawValue);
  if (!uses) return { kind: "empty" };
  if (uses.includes("${{")) return { kind: "dynamic" };
  if (uses.startsWith("*")) {
    return { kind: "ok", parsed: { uses, action: "", ref: "", anchor: occ.anchor, alias: uses.slice(1), stepAnchor: occ.stepAnchor } };
  }
  const { action, ref } = splitUses(uses);
  return { kind: "ok", parsed: { uses, action, ref, anchor: occ.anchor, stepAnchor: occ.stepAnchor } };
}

export interface WorkflowParse {
  refs: ActionRef[];
  /** True when the file carries a uses key whose value could not be extracted, so its inventory may be incomplete (P-174). */
  unparsed: boolean;
}

export function parseWorkflowDetailed(content: string, workflow: string): WorkflowParse {
  const out: ActionRef[] = [];
  let unparsed = false;
  const lines = content.split(/\r?\n/);
  // YAML anchors and aliases (supported by GitHub Actions since September
  // 2025) are file-local and defined before use. Track both scalar anchors
  // on uses values and anchors on whole steps so an alias line resolves to
  // the anchored action instead of being reported as a fabricated one.
  const scalarAnchors = new Map<string, string>();
  const stepAnchors = new Map<string, string>();
  let pendingStepAnchor: string | undefined;
  let flowDepth = 0;
  const emitParsed = (parsed: ParsedUses, line: string, lineNo: number): void => {
    // Resolve an alias value to its anchored uses string. An alias whose
    // anchor is not defined earlier in this file is invalid YAML for
    // GitHub and is skipped rather than fabricated.
    let effectiveUses = parsed.uses;
    let viaAlias = false;
    if (parsed.alias) {
      const target = scalarAnchors.get(parsed.alias);
      if (!target) {
        pendingStepAnchor = undefined;
        return;
      }
      effectiveUses = target;
      viaAlias = true;
    }
    if (parsed.anchor) scalarAnchors.set(parsed.anchor, effectiveUses);
    if (parsed.stepAnchor) stepAnchors.set(parsed.stepAnchor, effectiveUses);
    else if (pendingStepAnchor) {
      stepAnchors.set(pendingStepAnchor, effectiveUses);
      pendingStepAnchor = undefined;
    }
    out.push(buildActionRef(effectiveUses, workflow, lineNo, line, viaAlias));
  };
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    const depthAtStart = flowDepth;
    flowDepth = Math.max(0, flowDepth + flowDepthDelta(line));
    // A step alias (- *name on its own line) reuses an anchored step.
    const stepAlias = /^\s*-\s*\*(\S+)\s*$/.exec(line);
    if (stepAlias) {
      const target = stepAnchors.get(stepAlias[1]);
      if (target) out.push(buildActionRef(target, workflow, i + 1, line, true));
      pendingStepAnchor = undefined;
      continue;
    }
    // A step anchor alone on the dash line (- &name) names the step whose
    // uses key follows on a later line of the same step.
    const stepAnchorOnly = /^\s*-\s*&(\S+)\s*$/.exec(line);
    if (stepAnchorOnly) {
      pendingStepAnchor = stepAnchorOnly[1];
      continue;
    }
    const isStepStart = /^\s*-\s/.test(line);
    const parsed = parseUsesLine(line);
    const occs = scanUsesOccurrences(line, depthAtStart);
    // The block parser's key position on this line, when it matched, so
    // its scanner occurrence can be deduped against the flow entries.
    let blockOcc: UsesOccurrence | undefined;
    if (parsed) {
      const bm = /^(\s*(?:-\s*)?(?:&\S+\s+)?)uses/.exec(line);
      if (bm) blockOcc = occs.find((o) => o.start === bm[1].length);
    }
    const flowOccs = blockOcc ? occs.filter((o) => o !== blockOcc) : occs;
    if (parsed && flowOccs.length === 0) {
      // The established block-style path, unchanged: the only uses key
      // on the line sits at a block position.
      emitParsed(parsed, line, i + 1);
      continue;
    }
    if (!parsed && occs.length === 0) {
      // A block-position uses key with no extractable value: the block
      // parser returned null. That is a dynamic value (explained and
      // documented) unless the value is simply absent, which is a file
      // the audit cannot inventory.
      const blockKey = /^\s*(?:-\s*)?(?:&\S+\s+)?uses\s*:\s*(.*)$/.exec(line);
      if (blockKey) {
        const rest = blockKey[1].trim();
        if (!rest) unparsed = true;
      }
      // A new step dash ends the previous step, so a pending step anchor
      // that never reached a uses line is dead.
      if (isStepStart) pendingStepAnchor = undefined;
      continue;
    }
    // P-174 flow path: every remaining candidate uses occurrence on
    // the line is inventoried, in order, with the same anchor, alias,
    // and dynamic handling as block entries. The block entry, when
    // present, sits at the line start and is emitted first.
    if (parsed) emitParsed(parsed, line, i + 1);
    for (const occ of flowOccs) {
      const fv = parseFlowValue(occ);
      if (fv.kind === "empty") {
        unparsed = true;
        continue;
      }
      if (fv.kind === "dynamic") continue;
      emitParsed(fv.parsed, line, i + 1);
    }
  }
  return { refs: out, unparsed };
}

export function parseWorkflowContent(content: string, workflow: string): ActionRef[] {
  return parseWorkflowDetailed(content, workflow).refs;
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

/**
 * True only when p exists and is a regular file. Every path actionpin
 * opens goes through a stat-type check first (P-077): opening a FIFO
 * blocks until a writer appears, so a name with a workflow extension
 * is never enough on its own, the way injectcheck stats before opening.
 */
function isRegularFile(p: string): boolean {
  try {
    return statSync(p).isFile();
  } catch {
    return false;
  }
}

export function discoverWorkflows(rootPath: string): string[] {
  let rootStat;
  try {
    rootStat = statSync(rootPath);
  } catch {
    return [];
  }
  if (rootStat.isFile()) {
    // Single-file discovery is for workflow files only (P-078);
    // auditWorkflows rejects other regular files as usage errors
    // before discovery runs.
    return /\.ya?ml$/i.test(rootPath) ? [rootPath] : [];
  }
  if (!rootStat.isDirectory()) return [];
  const candidates = [
    join(rootPath, ".github", "workflows"),
    ...(basename(rootPath) === "workflows" ? [rootPath] : []),
    ...(basename(rootPath) === ".github" ? [join(rootPath, "workflows")] : []),
  ];
  for (const dir of candidates) {
    let dirStat;
    try {
      dirStat = statSync(dir);
    } catch {
      continue;
    }
    if (!dirStat.isDirectory()) continue;
    let names: string[];
    try {
      names = readdirSync(dir);
    } catch {
      return [];
    }
    // P-077: only regular files, by stat type, are returned for
    // opening. A FIFO named pipe.yml and a directory named x.yml are
    // both skipped here, before any open can block or fail.
    return names
      .filter((f) => /\.ya?ml$/i.test(f))
      .filter((f) => isRegularFile(join(dir, f)))
      .sort()
      .map((f) => join(dir, f));
  }
  return [];
}

/** Recursively collect action.yml and action.yaml files under a directory. */
function collectActionFiles(dir: string, out: string[], depth = 0): void {
  if (depth > 12) return;
  let names: string[];
  try {
    names = readdirSync(dir).sort();
  } catch {
    return;
  }
  for (const name of names) {
    if (name === ".git" || name === "node_modules") continue;
    const p = join(dir, name);
    let st;
    try {
      st = statSync(p);
    } catch {
      continue;
    }
    if (st.isDirectory()) collectActionFiles(p, out, depth + 1);
    // P-077: only a regular file can be an action definition; a FIFO,
    // socket, or device named action.yml is skipped, never collected.
    else if (st.isFile() && /^action\.ya?ml$/i.test(name)) out.push(p);
  }
}

/** The repo root an audit path points at, for resolving local action paths (which GitHub resolves from the repo root). */
function repoRootFor(rootPath: string): string {
  const base = basename(rootPath);
  if (base === "workflows") return join(rootPath, "..", "..");
  if (base === ".github") return join(rootPath, "..");
  return rootPath;
}

/**
 * Resolve a local uses path to the action definition file inside the
 * scanned repo, or null when there is none on disk. A malformed prefix
 * (P-057) is read as the ./ path it evidently means, so the vite shape
 * still finds its composite on disk.
 */
function resolveLocalActionFile(repoRoot: string, uses: string): string | null {
  if (!isLocalUses(uses)) return null;
  const rel = isMalformedLocalUses(uses) ? uses.replace(/^[^A-Za-z0-9]+\//, "./") : uses;
  const abs = join(repoRoot, rel);
  try {
    const st = statSync(abs);
    if (st.isFile()) return /^action\.ya?ml$/i.test(basename(abs)) ? abs : null;
    if (st.isDirectory()) {
      for (const name of ["action.yml", "action.yaml"]) {
        const cand = join(abs, name);
        if (isRegularFile(cand)) return cand;
      }
    }
  } catch {
    return null;
  }
  return null;
}

export function auditWorkflows(rootPath: string): AuditReport {
  // P-078: a target that is not an auditable estate is a usage error,
  // never a vacuous PINNED over zero actions. The CLI maps this throw
  // to exit 2 with the message on stderr (the same contract as
  // hookcheck and injectcheck on a nonexistent path), and the MCP
  // tools surface it as an error instead of a success verdict.
  let targetStat;
  try {
    targetStat = statSync(rootPath);
  } catch {
    throw new Error(`Path does not exist: ${rootPath}`);
  }
  let singleFile = false;
  if (targetStat.isFile()) {
    // Single-file audit stays available for workflow and action files
    // only (the README contract: passing an action.yml path directly
    // parses it). Any other regular file was previously treated as a
    // workflow itself and verdicted PINNED over zero actions with no
    // note at all.
    if (!/\.ya?ml$/i.test(rootPath)) {
      throw new Error(`Not a workflow file: ${rootPath} (a single-file audit target must be a .yml or .yaml file)`);
    }
    singleFile = true;
  } else if (!targetStat.isDirectory()) {
    // A FIFO, socket, or device is not an auditable estate, and
    // opening one can block forever (P-077).
    throw new Error(`Path is neither a file nor a directory: ${rootPath}`);
  }
  const files = discoverWorkflows(rootPath);
  const actions: ActionRef[] = [];
  // P-174: a file whose uses entries could not all be extracted is
  // named in unparsedWorkflows, carries a note, and floors the
  // verdict at PARTIAL, so it never silently contributes zero actions
  // to a PINNED verdict.
  const unparsedWorkflows: string[] = [];
  for (const f of files) {
    // Defense in depth behind discovery (P-077): never open a path
    // whose stat type is not a regular file.
    if (!isRegularFile(f)) continue;
    const parsedFile = parseWorkflowDetailed(readFileSync(f, "utf8"), f);
    actions.push(...parsedFile.refs);
    if (parsedFile.unparsed) unparsedWorkflows.push(f);
  }
  // P-058: a directory audit also audits the composite action
  // definitions that live inside the scanned repo: every action file
  // under .github/actions, plus any local action directory a workflow
  // (or a composite already being scanned) references with a local
  // uses path. Their internal steps are inventoried and classified
  // like workflow steps and drive the verdict the same way; each such
  // ref is flagged composite so counts stay interpretable.
  // P-067: the root-level action.yml or action.yaml is the scanned
  // repo's own action definition, the canonical location for a
  // published GitHub Action, so a directory audit scans it on the
  // same terms whether or not any workflow references it (the usual
  // shape is a workflow consuming it by remote self ref at a pinned
  // SHA, which the local-path machinery never follows). The seen set
  // below dedupes it against every other discovery path, so a root
  // action whose steps reference the repo's own action via ./ or via
  // its published name is scanned exactly once and cannot recurse.
  const composites: string[] = [];
  let unscannedComposites: string[] = [];
  if (!singleFile) {
    const repoRoot = repoRootFor(rootPath);
    const workflowSet = new Set(files.map((f) => resolve(f)));
    const queue: string[] = [];
    for (const name of ["action.yml", "action.yaml"]) {
      const rootAction = join(repoRoot, name);
      if (isRegularFile(rootAction)) queue.push(rootAction);
    }
    collectActionFiles(join(repoRoot, ".github", "actions"), queue);
    for (const a of actions) {
      const cf = resolveLocalActionFile(repoRoot, a.uses);
      if (cf) queue.push(cf);
    }
    const seen = new Set<string>();
    while (queue.length > 0) {
      const file = queue.shift()!;
      const key = resolve(file);
      if (seen.has(key) || workflowSet.has(key)) continue;
      // P-077: a queued composite path is opened only when it is a
      // regular file; existence alone does not make a FIFO safe.
      if (!isRegularFile(file)) continue;
      seen.add(key);
      composites.push(file);
      const parsedComposite = parseWorkflowDetailed(readFileSync(file, "utf8"), file);
      if (parsedComposite.unparsed && !unparsedWorkflows.includes(file)) unparsedWorkflows.push(file);
      const refs = parsedComposite.refs;
      for (const r of refs) {
        r.composite = true;
        actions.push(r);
        const cf = resolveLocalActionFile(repoRoot, r.uses);
        if (cf) queue.push(cf);
      }
    }
    // P-046: name the remainder. Action files anywhere else in the
    // repo that no workflow references are not scanned, and the report
    // says which ones they are instead of implying full coverage.
    const allActionFiles: string[] = [];
    collectActionFiles(repoRoot, allActionFiles);
    unscannedComposites = allActionFiles.filter((p) => !seen.has(resolve(p)) && !workflowSet.has(resolve(p)));
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
  let verdict = computeVerdict(actions);
  if (unparsedWorkflows.length > 0 && verdict === "PINNED") verdict = "PARTIAL";
  const report: AuditReport = {
    path: rootPath,
    verdict,
    actions,
    counts,
    workflows: files,
    composites,
    checkedAt: new Date().toISOString(),
  };
  if (unscannedComposites.length > 0) report.unscannedComposites = unscannedComposites;
  if (unparsedWorkflows.length > 0) {
    report.unparsedWorkflows = unparsedWorkflows;
    report.note =
      `${unparsedWorkflows.length} workflow file(s) could not be fully parsed and may contain uses entries that were not inventoried: ${unparsedWorkflows.join(", ")}. ` +
      "The verdict is floored at PARTIAL and does not cover those files; fix the file or rewrite it in block style and audit again.";
  } else if (files.length === 0 && composites.length === 0) {
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
  // P-174: on a flow-style line, content follows the uses value on the
  // same line (a comma, a closing brace or bracket, or a sibling
  // entry). The usual trailing version comment is a YAML comment there:
  // it would comment out the rest of the line and corrupt the flow
  // collection, so a flow line is pinned without a comment.
  const isFlowTail = (tail: string): boolean => /^\s*[,}\]]/.test(tail);
  // A quoted uses value must keep its closing quote before the version
  // comment, or the comment becomes part of the quoted string and corrupts
  // the action reference.
  for (const q of ['"', "'"]) {
    const quoted = `${q}${needle}${q}`;
    const at = rawLine.indexOf(quoted);
    if (at >= 0) {
      const tail = rawLine.slice(at + quoted.length);
      if (isFlowTail(tail)) return rawLine.replace(quoted, `${q}${actionRef.action}@${sha}${q}`);
      return rawLine.replace(quoted, `${q}${actionRef.action}@${sha}${q} # ${actionRef.ref}`);
    }
  }
  const at = rawLine.indexOf(needle);
  if (at >= 0) {
    const tail = rawLine.slice(at + needle.length);
    if (isFlowTail(tail)) return rawLine.replace(needle, `${actionRef.action}@${sha}`);
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
  // Planned text per workflow line, chained for shared flow lines.
  const lineState = new Map<string, string>();
  for (const a of report.actions) {
    if (a.classification === "LOCAL") {
      entries.push({ workflow: a.workflow, line: a.line, action: a.action, oldRef: a.ref, originalLine: a.rawLine, status: "local" });
      continue;
    }
    if (a.classification === "PINNED") {
      entries.push({ workflow: a.workflow, line: a.line, action: a.action, oldRef: a.ref, originalLine: a.rawLine, status: "already-pinned" });
      continue;
    }
    if (a.viaAlias) {
      // An alias line carries no ref of its own: it is pinned when the
      // anchor definition line is pinned, and rewriting the alias token
      // would break the YAML, so the line is always left unchanged.
      entries.push({ workflow: a.workflow, line: a.line, action: a.action, oldRef: a.ref, originalLine: a.rawLine, status: "failed", error: "Alias line: it reuses an anchored uses value and is pinned when its anchor definition line is pinned; alias lines are never rewritten directly" });
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
      // P-174: several flow entries can share one line. Chain the
      // rewrite through the line's current planned text so each
      // entry's newLine carries every earlier pin on that line, and
      // applying the entries in order leaves all of them pinned.
      const lineKey = `${a.workflow}:${a.line}`;
      const baseLine = lineState.get(lineKey) ?? a.rawLine;
      const newLine = buildPinnedLine(baseLine, a, sha);
      lineState.set(lineKey, newLine);
      entries.push({ workflow: a.workflow, line: a.line, action: a.action, oldRef: a.ref, newRef: sha, sha, originalLine: a.rawLine, newLine, status: "pinned" });
    } catch (err) {
      entries.push({ workflow: a.workflow, line: a.line, action: a.action, oldRef: a.ref, originalLine: a.rawLine, status: "failed", error: err instanceof Error ? err.message : String(err) });
    }
  }
  const plan: PinPlan = {
    path: rootPath,
    entries,
    changes: entries.filter((e) => e.status === "pinned" && e.newLine && e.newLine !== e.originalLine).length,
    alreadyPinned: entries.filter((e) => e.status === "already-pinned").length,
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
  if (report.composites) lines.push(`  composites: ${report.composites.length} composite file(s) scanned`);
  if (report.unscannedComposites && report.unscannedComposites.length > 0) {
    lines.push(`  NOTE: ${report.unscannedComposites.length} composite action file(s) not scanned (outside .github/actions and not referenced by a workflow): ${report.unscannedComposites.join(", ")}`);
  }
  for (const a of report.actions) {
    lines.push(`  [${a.classification}] ${a.workflow}:${a.line} ${a.uses} (${a.ownerType})${a.composite ? " [composite action]" : ""}`);
    if (a.note) lines.push(`    NOTE: ${a.note}`);
  }
  if (report.workflows.length === 0 && (!report.composites || report.composites.length === 0)) lines.push("No workflows were audited, so no pinning conclusion applies to this path.");
  else if (report.verdict === "PINNED") lines.push("PINNED: every non-local action is pinned to a full commit SHA.");
  else if (report.verdict === "EXPOSED") lines.push("EXPOSED: at least one third-party or container action uses a mutable tag or branch ref.");
  else lines.push("PARTIAL: some official actions use mutable or branch refs, no third-party exposure found.");
  return lines.join("\n");
}

export function renderPlan(plan: PinPlan, applied: boolean): string {
  const lines: string[] = [];
  // P-059: the header states both numbers the body lists, so a reader
  // comparing header to body never has to guess what was counted.
  const alreadyPinned = plan.entries.filter((e) => e.status === "already-pinned").length;
  lines.push(`actionpin ${applied ? "fix" : "pin plan"} ${plan.path}: ${plan.changes} to pin, ${alreadyPinned} already pinned`);
  if (plan.note) lines.push(`  NOTE: ${plan.note}`);
  for (const e of plan.entries) {
    if (e.status === "pinned") lines.push(`  [PIN] ${e.workflow}:${e.line} ${e.action}@${e.oldRef} -> ${e.sha} # ${e.oldRef}`);
    else if (e.status === "failed") lines.push(`  [FAIL] ${e.workflow}:${e.line} ${e.action}@${e.oldRef}: ${e.error ?? "resolution failed, line left unchanged"}`);
    else lines.push(`  [${e.status.toUpperCase()}] ${e.workflow}:${e.line} ${e.action}${e.oldRef ? `@${e.oldRef}` : ""}`);
  }
  return lines.join("\n");
}
