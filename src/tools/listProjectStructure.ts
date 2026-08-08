/**
 * Tool: secure_mcp_list_project_structure
 * Inventory the target codebase tree for defensive secure-code-review scoping.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { loadConfig, type ServerConfig } from "../config.js";
import {
  finalizeInventoryCoverage,
  normalizeAuthorizedProjectRoot,
  profileProject,
  toolError,
  toolSuccess,
  walkProject,
} from "../lib/filesystem.js";
import { redactCoverageReport, redactedSecretPaths } from "../lib/redact.js";
import { escapeMarkdown, markdownCode } from "../lib/markdown.js";
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
    .array(z.string().min(1).max(20))
    .max(50)
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
    `# Project structure: ${escapeMarkdown(data.project_root)}`,
    "",
    "## Profile",
    `- Stacks: ${data.profile.likelyStacks.join(", ")}`,
    `- TypeScript files: ${data.profile.hasTypeScriptFiles}`,
    `- Next.js signals: ${data.profile.hasNextConfig}`,
    `- Swift signals: ${data.profile.hasSwiftFiles}`,
    `- Top-level entry preview truncated: ${data.profile.topLevelEntriesTruncated}`,
    "",
    "## Top-level entries",
    ...redactedSecretPaths(data.profile.topLevelEntries).map((e) => `- ${escapeMarkdown(e)}`),
    "",
    `## Files scanned: ${data.file_count}${data.truncated ? " (truncated)" : ""}`,
    "",
    "### By extension",
  ];
  for (const [ext, count] of Object.entries(data.by_extension).sort((a, b) => b[1] - a[1])) {
    lines.push(`- ${markdownCode(ext || "(none)")}: ${count}`);
  }
  lines.push("", "### Sample paths");
  for (const f of redactedSecretPaths(data.sample_files).slice(0, 40)) {
    lines.push(`- ${escapeMarkdown(f)}`);
  }
  return lines.join("\n");
}

export function registerListProjectStructure(
  server: McpServer,
  config: ServerConfig = loadConfig(),
): void {
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
  - stack (enum, optional): auto|common|typescript|nextjs|swift|expo
  - max_files (number, optional): Cap on files to list
  - max_depth (number, optional): Directory depth limit
  - include_extensions (string[], optional): Limit to these extensions
  - focus_paths (string[], optional): Relative path prefixes for scoped drill-down
  - response_format (json|markdown): Default json

Returns:
  Structured inventory with profile, extension histogram, and sample file paths.

Guidance: Call secure_mcp_get_audit_guidance for the full workflow and guardrails.

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
        const root = await normalizeAuthorizedProjectRoot(params.project_root, config.allowedRoots);
        const effectiveMaxFiles = params.max_files ?? config.defaultMaxFiles;
        const effectiveMaxDepth = Math.min(
          params.max_depth ?? config.maxDepth,
          config.maxDepth,
        );
        const profile = await profileProject(root, {
          focusPrefixes: params.focus_paths,
          maxFiles: effectiveMaxFiles,
          maxDepth: effectiveMaxDepth,
          maxFileBytes: config.maxFileBytes,
          maxTotalBytes: config.maxTotalBytes,
          allowedRoots: config.allowedRoots,
        });
        const extensions =
          params.include_extensions && params.include_extensions.length > 0
            ? new Set(params.include_extensions.map((e) => (e.startsWith(".") ? e : `.${e}`)))
            : undefined;

        const { files, truncated, coverage } = await walkProject(root, {
          maxFiles: effectiveMaxFiles,
          maxDepth: effectiveMaxDepth,
          maxFileBytes: config.maxFileBytes,
          maxTotalBytes: config.maxTotalBytes,
          allowedRoots: config.allowedRoots,
          extensions: extensions ?? undefined,
          focusPrefixes: params.focus_paths,
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
            topLevelEntries: redactedSecretPaths(profile.topLevelEntries),
            topLevelEntriesTruncated: profile.topLevelEntriesTruncated,
          },
          file_count: files.length,
          by_extension,
          sample_files: redactedSecretPaths(sample_files),
          truncated,
          coverage: redactCoverageReport(
            finalizeInventoryCoverage(coverage, files.map((file) => file.relativePath)),
          ),
          files_reviewed: [],
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
