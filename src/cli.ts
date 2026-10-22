#!/usr/bin/env node
/**
 * actionpin CLI.
 *
 *   actionpin audit [path] [--json]
 *   actionpin fix [path] [--dry-run] [--json]
 *   actionpin mcp
 *   actionpin --version
 *
 * Exit codes: 0 PINNED, 1 EXPOSED or PARTIAL, 2 usage error.
 * The fix command only writes local files. A failed SHA resolution
 * leaves that line unchanged and is reported in the plan.
 */
import { applyPinPlan, auditWorkflows, buildPinPlan, renderPlan, renderReport, VERSION } from "./core.js";

function usage(): never {
  console.error(`Usage:
  actionpin audit [path] [--json]
  actionpin fix [path] [--dry-run] [--json]
  actionpin mcp
  actionpin --version`);
  process.exit(2);
}

function has(args: string[], name: string): boolean {
  return args.includes(name);
}

function positional(args: string[]): string[] {
  return args.filter((a) => !a.startsWith("--"));
}

async function main(): Promise<void> {
  const [cmd, ...rest] = process.argv.slice(2);
  if (cmd === "--version" || cmd === "-v" || cmd === "version") {
    console.log(VERSION);
    return;
  }
  if (cmd === "mcp") {
    await import("./mcp.js");
    return;
  }
  if (!cmd) usage();
  try {
    if (cmd === "audit") {
      const [target] = positional(rest);
      const report = auditWorkflows(target ?? ".");
      if (has(rest, "--json")) console.log(JSON.stringify(report, null, 2));
      else console.log(renderReport(report));
      process.exit(report.verdict === "PINNED" ? 0 : 1);
    } else if (cmd === "fix") {
      const [target] = positional(rest);
      const root = target ?? ".";
      if (has(rest, "--dry-run")) {
        const plan = await buildPinPlan(root, fetch);
        if (has(rest, "--json")) console.log(JSON.stringify(plan, null, 2));
        else console.log(renderPlan(plan, false));
        const remaining = plan.entries.some((e) => e.status === "failed" || e.status === "pinned");
        process.exit(remaining ? 1 : 0);
      } else {
        const result = await applyPinPlan(root, fetch);
        if (has(rest, "--json")) console.log(JSON.stringify(result, null, 2));
        else console.log(renderPlan(result, true));
        const after = auditWorkflows(root);
        process.exit(after.verdict === "PINNED" ? 0 : 1);
      }
    } else {
      usage();
    }
  } catch (err) {
    console.error(`error: ${err instanceof Error ? err.message : String(err)}`);
    process.exit(2);
  }
}

void main();
