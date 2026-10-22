/**
 * actionpin types.
 *
 * Every finding carries the workflow file, the 1-based line, the raw
 * action reference, its classification and its owner type, so a report
 * never asks the reader to trust a summary without evidence.
 */

export type Classification = "PINNED" | "MUTABLE" | "BRANCH" | "LOCAL";
export type OwnerType = "official" | "third-party" | "docker" | "local";
export type Verdict = "PINNED" | "EXPOSED" | "PARTIAL";

export interface ActionRef {
  /** Workflow file path as given or discovered, using forward slashes. */
  workflow: string;
  /** 1-based line number of the uses: line. */
  line: number;
  /** Full uses value, e.g. actions/checkout@v4 or ./local/action. */
  uses: string;
  /** Action name without the ref, e.g. actions/checkout. Empty for local paths the parser keeps whole in uses. */
  action: string;
  /** Ref after @, empty string when there is no @ ref (local actions). */
  ref: string;
  classification: Classification;
  ownerType: OwnerType;
  /** The raw source line, preserved exactly. */
  rawLine: string;
  /** True when this line is a YAML alias (*name) that reuses an anchored uses value or step defined earlier in the same file. The classification is inherited from the anchor definition; fix mode never rewrites an alias line directly. */
  viaAlias?: boolean;
}

export interface AuditReport {
  path: string;
  verdict: Verdict;
  /** Plain-language caveat when the estate is empty (P-014): a verdict on zero workflows is vacuous, not an all-clear. Absent when workflows were found. */
  note?: string;
  actions: ActionRef[];
  counts: {
    total: number;
    pinned: number;
    mutable: number;
    branch: number;
    local: number;
    official: number;
    thirdParty: number;
    docker: number;
  };
  workflows: string[];
  checkedAt: string;
}

export interface PinPlanEntry {
  workflow: string;
  line: number;
  action: string;
  oldRef: string;
  newRef?: string;
  sha?: string;
  originalLine: string;
  newLine?: string;
  status: "pinned" | "already-pinned" | "local" | "failed";
  error?: string;
}

export interface PinPlan {
  path: string;
  /** Same empty-estate caveat as AuditReport.note, propagated so a plan on zero workflows cannot read as a clean pass. */
  note?: string;
  entries: PinPlanEntry[];
  /** Number of lines that would change (or did change in apply mode). */
  changes: number;
  checkedAt: string;
}

export interface FixResult extends PinPlan {
  applied: boolean;
  filesChanged: string[];
}

/** Minimal fetch surface so tests can inject fixtures, never live network. */
export interface FetchResponse {
  ok: boolean;
  status: number;
  json(): Promise<unknown>;
  text(): Promise<string>;
}

export type FetchFn = (
  url: string,
  init?: { headers?: Record<string, string> },
) => Promise<FetchResponse>;
