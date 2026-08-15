/**
 * Tool: secure_mcp_list_authorized_roots
 * Report the server's allowlisted roots so agents can discover what they may
 * inspect before choosing a project_root. Read-only and fail-closed: it never
 * reveals or reads paths outside the configured allowlist.
 */

import path from "node:path";
import type { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import { loadConfig, type ServerConfig } from "../config.js";
import { toolError, toolSuccess } from "../lib/envelope.js";
import { normalizeProjectRoot, readProjectFileIfExists } from "../lib/filesystem.js";
import { renderMarkdownDocument } from "../lib/markdown.js";

const InputSchema = z
  .object({
    include_metadata: z
      .boolean()
      .default(false)
      .describe(
        "If true, include a shallow name (directory basename) and package.json name for each existing root. Reads metadata only within the allowlisted root — no tree walk.",
      ),
    response_format: z
      .enum(["json", "markdown"])
      .default("json")
      .describe("json for structured agent processing; markdown for human-readable summaries"),
  })
  .strict();

type Input = z.infer<typeof InputSchema>;

interface AuthorizedRootEntry {
  path: string;
  exists: boolean;
  name?: string;
  package_name?: string;
}

export function registerListAuthorizedRoots(
  server: McpServer,
  config: ServerConfig = loadConfig(),
): void {
  server.registerTool(
    "secure_mcp_list_authorized_roots",
    {
      title: "List authorized roots",
      description: `Defensive secure-code-review tool: list the server's configured allowlist roots and whether each exists on disk.

PURPOSE (defensive only)
- Help agents discover which absolute roots they are permitted to inspect before choosing a project_root.
- Fail-closed: this tool only reports the operator-configured SECURE_MCP_ALLOWED_ROOTS; it never reveals or reads paths outside that allowlist.
- Optional shallow metadata (directory basename, package.json name) is read only within an allowlisted root.

Args:
  - include_metadata (boolean): default false — include name/package_name per root
  - response_format (json|markdown): default json

Returns:
  configured, root_count, roots[] (path, exists, optional name/package_name).

Use when you do not yet know which root to pass to the other filesystem tools.`,
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
        const configured = config.allowedRoots;
        const roots: AuthorizedRootEntry[] = [];

        if (configured && configured.length > 0) {
          for (const raw of configured) {
            let canonical: string | undefined;
            let exists = false;
            try {
              canonical = await normalizeProjectRoot(raw);
              exists = true;
            } catch {
              exists = false;
            }
            const entry: AuthorizedRootEntry = { path: canonical ?? raw, exists };
            if (exists && canonical && params.include_metadata) {
              entry.name = path.basename(canonical);
              try {
                const pkg = await readProjectFileIfExists(
                  canonical,
                  "package.json",
                  config.maxFileBytes,
                  config.allowedRoots,
                );
                if (pkg) {
                  const parsed = JSON.parse(pkg.content) as { name?: unknown };
                  if (typeof parsed.name === "string" && parsed.name.trim().length > 0) {
                    entry.package_name = parsed.name;
                  }
                }
              } catch {
                // ignore unreadable/invalid package.json
              }
            }
            roots.push(entry);
          }
        }

        const data = {
          ok: true as const,
          configured: Boolean(configured && configured.length > 0),
          root_count: roots.length,
          roots,
          notes: [
            "Only the operator-configured SECURE_MCP_ALLOWED_ROOTS are listed; this tool never escapes the allowlist.",
            configured && configured.length === 0
              ? "No allowlist roots are configured — filesystem tools will reject project_root values."
              : "Pass one of these roots (or a path under one) as project_root to the other tools.",
            params.include_metadata
              ? "Metadata is read only within the allowlisted root (package.json only)."
              : "Set include_metadata=true to include directory/package names per root.",
          ],
        };

        return toolSuccess(data, {
          responseFormat: params.response_format,
          markdown: renderMarkdownDocument({
            title: "Authorized roots",
            sections: [
              {
                heading: `Roots (${roots.length})`,
                bullets: roots.map((r) =>
                  r.exists
                    ? `${r.path}${r.package_name ? ` (${r.package_name})` : ""}`
                    : `${r.path} (missing)`,
                ),
              },
              ...(roots.length === 0
                ? [{ heading: "Notice", bullets: ["No allowlist roots configured."] }]
                : []),
            ],
          }),
        });
      } catch (error) {
        return toolError(error, "Reading the allowlist should never fail; check server configuration.");
      }
    },
  );
}
