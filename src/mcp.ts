/**
 * actionpin MCP server. Tools: audit_workflows, pin_plan.
 */
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { auditWorkflows, buildPinPlan, VERSION } from "./core.js";

const server = new McpServer({ name: "actionpin", version: VERSION });

server.tool(
  "audit_workflows",
  "Audit GitHub workflow files under a repo path for action pinning. Finds every uses: reference, classifies it as PINNED (full 40-char SHA), MUTABLE (version tag), BRANCH, or LOCAL, labels the owner as official, third-party, docker, or local, and returns a PINNED, EXPOSED, or PARTIAL verdict with the file and line for every action.",
  {
    path: z.string().describe("Repo root, a .github/workflows directory, or a single workflow file"),
  },
  async ({ path }) => {
    const report = auditWorkflows(path);
    return { content: [{ type: "text" as const, text: JSON.stringify(report, null, 2) }] };
  },
);

server.tool(
  "pin_plan",
  "Build the SHA pinning plan for workflows under a repo path without writing any files. Resolves each mutable or branch ref to a commit SHA through the GitHub API and returns the exact rewritten line per action, or a failed entry with the reason when resolution is not possible. Local refs are never rewritten.",
  {
    path: z.string().describe("Repo root, a .github/workflows directory, or a single workflow file"),
  },
  async ({ path }) => {
    const plan = await buildPinPlan(path, fetch);
    return { content: [{ type: "text" as const, text: JSON.stringify(plan, null, 2) }] };
  },
);

async function main(): Promise<void> {
  await server.connect(new StdioServerTransport());
}

void main();
