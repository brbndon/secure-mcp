/**
 * Tool: secure_mcp_list_projects
 * Depth-capped discovery of project roots (package manifests) under a single
 * allowlisted parent. Read-only, hard-capped, and fail-closed on the allowlist.
 */

import path from "node:path";
import type { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import { loadConfig, type ServerConfig } from "../config.js";
import { toolError, toolSuccess } from "../lib/envelope.js";
import {
  CODE_EXTENSIONS,
  normalizeAuthorizedProjectRoot,
  walkProject,
} from "../lib/filesystem.js";
import { redactCoverageReport, redactedSecretPaths } from "../lib/redact.js";
import { renderMarkdownDocument } from "../lib/markdown.js";
import { MAX_PROJECT_ROOT_LENGTH } from "../knowledge/findings-schema.js";

/** Manifest filenames that mark a directory as a project root. */
const PROJECT_MARKER_BASENAMES = new Set([
  "package.json",
  "pyproject.toml",
  "Cargo.toml",
  "go.mod",
  "requirements.txt",
  "setup.py",
  "Pipfile",
  "build.gradle",
  "build.gradle.kts",
  "settings.gradle",
  "settings.gradle.kts",
  "pom.xml",
  "Package.swift",
  "Gemfile",
  "composer.json",
]);

const DISCOVERY_EXTENSIONS = new Set([
  ...CODE_EXTENSIONS,
  ".mod",
  ".py",
  ".go",
  ".gradle",
  ".kts",
  ".xml",
  ".cs",
  ".csproj",
  ".rb",
  ".php",
  ".txt",
]);

const MAX_DISCOVERY_DEPTH = 10;
const MAX_DISCOVERY_PROJECTS = 100;

const InputSchema = z
  .object({
    parent_root: z
      .string()
      .min(1)
      .max(MAX_PROJECT_ROOT_LENGTH)
      .describe(
        "Absolute path of an allowlisted parent root to scan for nested project roots (package manifests).",
      ),
    max_depth: z
      .number()
      .int()
      .min(1)
      .max(MAX_DISCOVERY_DEPTH)
      .default(4)
      .describe(`Maximum directory depth to scan (default 4, hard max ${MAX_DISCOVERY_DEPTH})`),
    max_projects: z
      .number()
      .int()
      .min(1)
      .max(MAX_DISCOVERY_PROJECTS)
      .default(25)
      .describe(`Cap on discovered project roots (default 25, hard max ${MAX_DISCOVERY_PROJECTS})`),
    response_format: z
      .enum(["json", "markdown"])
      .default("json")
      .describe("json for structured agent processing; markdown for human-readable summaries"),
  })
  .strict();

type Input = z.infer<typeof InputSchema>;

function markerBasename(relativePath: string): string | null {
  const base = relativePath.split("/").pop() ?? relativePath;
  if (PROJECT_MARKER_BASENAMES.has(base)) return base;
  if (base.endsWith(".csproj") || base.endsWith(".sln")) return base;
  return null;
}

/** Join a posix-relative discovery path onto the canonical parent root. */
function projectRootFor(parent: string, relativeDir: string): string {
  return relativeDir === "." ? parent : path.join(parent, ...relativeDir.split("/"));
}

export function registerListProjects(server: McpServer, config: ServerConfig = loadConfig()): void {
  server.registerTool(
    "secure_mcp_list_projects",
    {
      title: "List projects under an authorized root",
      description: `Defensive secure-code-review tool: depth-capped discovery of project roots (package manifests) under a single allowlisted parent.

PURPOSE (defensive only)
- Discover deployable packages in a monorepo or multi-repo checkout before choosing project_root for a scoped review.
- Hard caps (depth, project count, file count) and ignore rules keep discovery bounded and cheap.
- Fail-closed: parent_root must resolve under SECURE_MCP_ALLOWED_ROOTS; symlink escapes are rejected.

Args:
  - parent_root (string): allowlisted parent to scan
  - max_depth (number): default 4, hard max ${MAX_DISCOVERY_DEPTH}
  - max_projects (number): default 25, hard max ${MAX_DISCOVERY_PROJECTS}
  - response_format (json|markdown): default json

Returns:
  parent_root, project_count, truncated, projects[] (path, project_root, markers), coverage, notes.

Only manifests are used to identify projects; contents are not opened. Pass project_root (absolute) to other tools — path is the parent-relative posix form.`,
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
        const parent = await normalizeAuthorizedProjectRoot(params.parent_root, config.allowedRoots);
        const effectiveDepth = Math.min(params.max_depth, config.maxDepth);

        const { files, truncated: walkTruncated, coverageSession } = await walkProject(
          parent,
          {
            maxFiles: config.defaultMaxFiles,
            maxDepth: effectiveDepth,
            maxFileBytes: config.maxFileBytes,
            maxTotalBytes: config.maxTotalBytes,
            allowedRoots: config.allowedRoots,
            extensions: DISCOVERY_EXTENSIONS,
          },
        );

        const markersByRoot = new Map<string, string[]>();
        for (const file of files) {
          const marker = markerBasename(file.relativePath);
          if (!marker) continue;
          const dir = path.posix.dirname(file.relativePath);
          const key = dir === "." ? "." : dir;
          const markers = markersByRoot.get(key) ?? [];
          if (!markers.includes(marker)) markers.push(marker);
          markersByRoot.set(key, markers);
        }

        const sorted = [...markersByRoot.entries()].sort((a, b) =>
          a[0] === "." ? -1 : b[0] === "." ? 1 : a[0].localeCompare(b[0]),
        );
        const projectTruncated = sorted.length > params.max_projects;
        const projects = sorted.slice(0, params.max_projects).map(([dir, markers]) => ({
          path: dir,
          project_root: projectRootFor(parent, dir),
          markers: [...markers].sort(),
        }));

        const data = {
          ok: true as const,
          parent_root: parent,
          project_count: projects.length,
          truncated: walkTruncated || projectTruncated,
          projects,
          coverage: redactCoverageReport(coverageSession.finish()),
          notes: [
            "Discovery is marker-file based (package manifests only); a directory with no manifest is not listed.",
            projectTruncated
              ? `More than max_projects (${params.max_projects}) manifests found; lower the parent or raise max_projects.`
              : `Found ${projects.length} project root(s) under ${parent}.`,
            walkTruncated
              ? "File walk was truncated by max_files/max_depth; raise the parent scope or lower expectations for deep trees."
              : `Scanned to depth ${effectiveDepth}; raise max_depth for deeper monorepos.`,
            "Pass a listed project's project_root (absolute) to the other tools for a package-scoped review.",
          ],
        };

        return toolSuccess(data, {
          responseFormat: params.response_format,
          markdown: renderMarkdownDocument({
            title: `Projects under ${parent}`,
            metadata: [
              { label: "Project count", value: String(projects.length) },
              { label: "Truncated", value: String(walkTruncated || projectTruncated) },
            ],
            sections: [
              {
                heading: "Project roots",
                bullets: redactedSecretPaths(
                  projects.map((p) => `${p.project_root} [${p.markers.join(", ")}]`),
                ),
              },
            ],
          }),
        });
      } catch (error) {
        return toolError(
          error,
          "Pass an absolute parent_root that resolves under SECURE_MCP_ALLOWED_ROOTS.",
        );
      }
    },
  );
}
