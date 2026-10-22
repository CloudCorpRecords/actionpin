#!/usr/bin/env node
/**
 * actionpin CLI.
 *
 *   actionpin audit [path] [--json]
 *   actionpin fix [path] [--dry-run] [--json]
 *   actionpin mcp
 *   actionpin --version
 *
 * Exit codes: 0 PINNED, 1 EXPOSED or PARTIAL, 2 usage error,
 * 141 when the reader closed the output pipe before the report was
 * delivered (the shell-visible equivalent of death by SIGPIPE).
 * The fix command only writes local files. A failed SHA resolution
 * leaves that line unchanged and is reported in the plan.
 *
 * Every report goes through emit(), which waits for stdout to flush
 * before the exit code takes effect. Calling process.exit() right after
 * console.log() truncates piped output once it passes one pipe buffer
 * (64 KiB on Linux), which is validation problem P-001: agents, scripts,
 * and CI read through pipes, so they are exactly the consumers that were
 * silently handed a corrupt prefix and a success exit code.
 */
import { applyPinPlan, auditWorkflows, buildPinPlan, renderPlan, renderReport, VERSION } from "./core.js";

function exitBrokenPipe(): never {
  // The reader closed the pipe before the report was delivered. A Unix
  // writer in this position dies from SIGPIPE; exit 141 (128 + 13) is the
  // equivalent a shell reports, and it guarantees an undelivered report is
  // never mistaken for a successful run.
  process.exit(141);
}

process.stdout.on("error", (err: NodeJS.ErrnoException) => {
  if (err.code === "EPIPE") exitBrokenPipe();
  throw err;
});

/** Write one full report and resolve only after stdout has flushed it. */
async function emit(text: string, code: number): Promise<void> {
  process.exitCode = code;
  await new Promise<void>((resolve, reject) => {
    process.stdout.write(`${text}\n`, (err) => {
      if (!err) {
        resolve();
        return;
      }
      if ((err as NodeJS.ErrnoException).code === "EPIPE") exitBrokenPipe();
      reject(err);
    });
  });
}

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
      const text = has(rest, "--json") ? JSON.stringify(report, null, 2) : renderReport(report);
      await emit(text, report.verdict === "PINNED" ? 0 : 1);
    } else if (cmd === "fix") {
      const [target] = positional(rest);
      const root = target ?? ".";
      if (has(rest, "--dry-run")) {
        const plan = await buildPinPlan(root, fetch);
        const text = has(rest, "--json") ? JSON.stringify(plan, null, 2) : renderPlan(plan, false);
        const remaining = plan.entries.some((e) => e.status === "failed" || e.status === "pinned");
        await emit(text, remaining ? 1 : 0);
      } else {
        const result = await applyPinPlan(root, fetch);
        const text = has(rest, "--json") ? JSON.stringify(result, null, 2) : renderPlan(result, true);
        const after = auditWorkflows(root);
        await emit(text, after.verdict === "PINNED" ? 0 : 1);
      }
    } else {
      usage();
    }
  } catch (err) {
    console.error(`error: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 2;
  }
}

void main();
