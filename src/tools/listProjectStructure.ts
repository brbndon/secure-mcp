/**
 * Tool: secure_mcp_list_project_structure
 * Inventory the target codebase tree for defensive secure-code-review scoping.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import {
  normalizeProjectRoot,
  profileProject,
  toolError,
  toolSuccess,
  walkProject,
} from "../lib/filesystem.js";
import { ProjectRootInput } from "../knowledge/findings-schema.js";

const InputSchema = ProjectRootInput.extend({
  max_depth: z
    .number()
    .int()
    .min(1)
    .max(20)
    .optional()
    .describe("Maximum directory depth to walk (default 12)"),
  include_extensions: z
    .array(z.string())
    .optional()
    .describe('Optional extension filter, e.g. [".ts", ".swift"]. Include the dot.'),
}).strict();

type Input = z.infer<typeof InputSchema>;

function toMarkdown(data: {
  project_root: string;
  profile: Awaited<ReturnType<typeof profileProject>>;
  file_count: number;
  by_extension: Record<string, number>;
  sample_files: string[];
  truncated: boolean;
}): string {
  const lines: string[] = [
    `# Project structure: ${data.project_root}`,
    "",
    "## Profile",
    `- Stacks: ${data.profile.likelyStacks.join(", ")}`,
    `- TypeScript files: ${data.profile.hasTypeScriptFiles}`,
    `- Next.js signals: ${data.profile.hasNextConfig}`,
    `- Swift signals: ${data.profile.hasSwiftFiles}`,
    "",
    "## Top-level entries",
    ...data.profile.topLevelEntries.map((e) => `- ${e}`),
    "",
    `## Files scanned: ${data.file_count}${data.truncated ? " (truncated)" : ""}`,
    "",
    "### By extension",
  ];
  for (const [ext, count] of Object.entries(data.by_extension).sort((a, b) => b[1] - a[1])) {
    lines.push(`- \`${ext || "(none)"}\`: ${count}`);
  }
  lines.push("", "### Sample paths");
  for (const f of data.sample_files.slice(0, 40)) {
    lines.push(`- ${f}`);
  }
  return lines.join("\n");
}

export function registerListProjectStructure(server: McpServer): void {
  server.registerTool(
    "secure_mcp_list_project_structure",
    {
      title: "List project structure for secure review",
      description: `Defensive secure-code-review tool: inventory a local codebase so the development team can scope a thorough hardening review.

PURPOSE (defensive only)
- Produce a read-only map of the repository (stacks, layout, file samples) used as phase-1 input for multi-step secure code review.
- Enable later category-by-category analysis (authentication, injection-risk, secrets) and remediation planning.
- Not for offensive reconnaissance; only for reviewing code the team owns or is authorized to harden.

MANDATORY AGENT WORKFLOW
1. Call this tool first on project_root (prefer absolute paths).
2. Save intermediate inventory (stacks, hot paths) as an artifact.
3. Proceed to secure_mcp_analyze_architecture, then category tools, then remediation report.
4. Thorough reviews are multi-phase and may run for a long time — do not stop after inventory alone.

Args:
  - project_root (string): Path to the repository root under review
  - stack (enum, optional): auto|common|typescript|nextjs|swift
  - max_files (number, optional): Cap on files to list
  - max_depth (number, optional): Directory depth limit
  - include_extensions (string[], optional): Limit to these extensions
  - response_format (json|markdown): Default json

Returns:
  Structured inventory with profile, extension histogram, and sample file paths.

Examples:
  - Start of any defensive review: project_root="/path/to/repo"
  - Swift-focused inventory: include_extensions=[".swift", ".plist", ".entitlements"]

Error Handling:
  - Missing/invalid project_root returns a clear error with a fix hint`,
      inputSchema: InputSchema,
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async (params: Input) => {
      try {
        const root = await normalizeProjectRoot(params.project_root);
        const profile = await profileProject(root);
        const extensions =
          params.include_extensions && params.include_extensions.length > 0
            ? new Set(params.include_extensions.map((e) => (e.startsWith(".") ? e : `.${e}`)))
            : undefined;

        const { files, truncated } = await walkProject(root, {
          maxFiles: params.max_files,
          maxDepth: params.max_depth,
          extensions: extensions ?? undefined,
        });

        const by_extension: Record<string, number> = {};
        for (const f of files) {
          const key = f.ext || "(none)";
          by_extension[key] = (by_extension[key] ?? 0) + 1;
        }

        const sample_files = files.slice(0, 100).map((f) => f.relativePath);

        const data = {
          ok: true as const,
          project_root: root,
          summary: `Found ${files.length} files under ${root}${truncated ? " (hit max_files)" : ""}. Likely stacks: ${profile.likelyStacks.join(", ")}.`,
          profile: {
            likelyStacks: profile.likelyStacks,
            hasPackageJson: profile.hasPackageJson,
            hasNextConfig: profile.hasNextConfig,
            hasTsConfig: profile.hasTsConfig,
            hasPackageSwift: profile.hasPackageSwift,
            hasXcodeProject: profile.hasXcodeProject,
            hasSwiftFiles: profile.hasSwiftFiles,
            hasTypeScriptFiles: profile.hasTypeScriptFiles,
            topLevelEntries: profile.topLevelEntries,
          },
          file_count: files.length,
          by_extension,
          sample_files,
          truncated,
        };

        return toolSuccess(data, {
          responseFormat: params.response_format,
          markdown: toMarkdown({
            project_root: root,
            profile,
            file_count: files.length,
            by_extension,
            sample_files,
            truncated,
          }),
        });
      } catch (error) {
        return toolError(
          error,
          "Pass an absolute project_root that exists on the machine running the MCP server.",
        );
      }
    },
  );
}
