/**
 * Tool: secure_mcp_analyze_architecture
 * High-level architecture overview for defensive hardening and control placement.
 * Returns recommended_packs for progressive knowledge loading (not a full checklist dump).
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { z } from "zod";
import {
  normalizeProjectRoot,
  profileProject,
  readProjectFileIfExists,
  toolError,
  toolSuccess,
  walkProject,
} from "../lib/filesystem.js";
import { ProjectRootInput } from "../knowledge/findings-schema.js";
import {
  checklistFromPackIds,
  recommendPackPlan,
} from "../knowledge/packs/registry.js";

const InputSchema = ProjectRootInput;
type Input = z.infer<typeof InputSchema>;

interface SurfaceArea {
  entrypoints: string[];
  auth_related: string[];
  config_files: string[];
  api_routes: string[];
  data_layer_hints: string[];
}

async function detectSurface(root: string, maxFiles?: number): Promise<SurfaceArea> {
  const { files } = await walkProject(root, { maxFiles: maxFiles ?? 400 });
  const entrypoints: string[] = [];
  const auth_related: string[] = [];
  const config_files: string[] = [];
  const api_routes: string[] = [];
  const data_layer_hints: string[] = [];

  for (const f of files) {
    const p = f.relativePath.toLowerCase();
    const base = p.split("/").pop() ?? p;

    if (
      base === "package.json" ||
      base === "package.swift" ||
      base.startsWith("next.config") ||
      base === "tsconfig.json" ||
      base.endsWith(".entitlements") ||
      base === "info.plist" ||
      base === "dockerfile" ||
      base === "vercel.json" ||
      base === "middleware.ts" ||
      base === "middleware.js" ||
      base === "app.json" ||
      base.startsWith("app.config")
    ) {
      config_files.push(f.relativePath);
    }

    if (
      p.includes("auth") ||
      p.includes("session") ||
      p.includes("login") ||
      p.includes("clerk") ||
      p.includes("nextauth") ||
      p.includes("keychain") ||
      p.includes("credential") ||
      p.includes("securestore") ||
      p.includes("secure-store")
    ) {
      auth_related.push(f.relativePath);
    }

    if (
      p.includes("/api/") ||
      p.includes("route.ts") ||
      p.includes("route.js") ||
      p.includes("server action") ||
      /actions?\.(ts|js|swift)$/.test(base)
    ) {
      api_routes.push(f.relativePath);
    }

    if (
      p.includes("prisma") ||
      p.includes("drizzle") ||
      p.includes("supabase") ||
      p.includes("repository") ||
      p.includes("swiftdata") ||
      p.includes("coredata") ||
      p.includes("model/") ||
      base.includes("schema")
    ) {
      data_layer_hints.push(f.relativePath);
    }

    if (
      base === "main.swift" ||
      base === "app.swift" ||
      base === "page.tsx" ||
      base === "layout.tsx" ||
      base === "index.ts" ||
      base === "index.tsx" ||
      p === "src/index.ts" ||
      p === "app/page.tsx" ||
      base === "app.tsx" ||
      base === "_layout.tsx"
    ) {
      entrypoints.push(f.relativePath);
    }
  }

  const uniq = (arr: string[]) => [...new Set(arr)].slice(0, 50);
  return {
    entrypoints: uniq(entrypoints),
    auth_related: uniq(auth_related),
    config_files: uniq(config_files),
    api_routes: uniq(api_routes),
    data_layer_hints: uniq(data_layer_hints),
  };
}

export function registerAnalyzeArchitecture(server: McpServer): void {
  server.registerTool(
    "secure_mcp_analyze_architecture",
    {
      title: "Analyze architecture for hardening",
      description: `Defensive secure-code-review tool: produce an architecture overview that helps place security controls and plan remediation.

PURPOSE (defensive only)
- Map likely stacks, auth-related paths, API/route surfaces, config files, data-layer hints, and trust boundaries.
- Return recommended_packs and pack_batches so the agent can load stack-relevant checklists via secure_mcp_get_knowledge_pack (progressive disclosure — not a full encyclopedia dump).
- Support multi-phase review: inventory → architecture → knowledge packs → deep category analysis → remediation report.
- Never frame results as offensive targeting guidance.

MANDATORY AGENT WORKFLOW
1. Prefer secure_mcp_list_project_structure first.
2. Call this tool and retain stacks, surface, trust_boundaries, recommended_packs, and pack_batches.
3. Call secure_mcp_get_knowledge_pack with pack_batches[0] (detail=summary first). If pack_batches has more entries, load them in later calls only as needed.
4. Use next_tools: authentication, injection-risks, secrets, remediation threat model.
5. Trace data flows for high-value components before writing findings.
6. Continue until major classes relevant to the stack are examined with evidence; then produce_findings.

Args:
  - project_root (string): Repository root
  - stack (enum): auto or a specific focus
  - max_files / response_format: standard options

Returns:
  Architecture summary, surface maps, trust boundaries, recommended_packs, pack_batches, a small checklist_seed (secondary), and suggested next tools.`,
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
        const surface = await detectSurface(root, params.max_files);

        const packageJson = await readProjectFileIfExists(root, "package.json", 64 * 1024);
        let dependencies: string[] = [];
        if (packageJson) {
          try {
            const pkg = JSON.parse(packageJson.content) as {
              dependencies?: Record<string, string>;
              devDependencies?: Record<string, string>;
            };
            dependencies = [
              ...Object.keys(pkg.dependencies ?? {}),
              ...Object.keys(pkg.devDependencies ?? {}),
            ].sort();
          } catch {
            // ignore invalid package.json
          }
        }

        const stacks =
          params.stack && params.stack !== "auto"
            ? [params.stack]
            : profile.likelyStacks;

        const packPlan = recommendPackPlan(stacks, profile);
        const { recommended_packs, pack_batches } = packPlan;

        // Tiny secondary seed only — full checklists come from get_knowledge_pack
        const checklist_seed = checklistFromPackIds(recommended_packs)
          .slice(0, 8)
          .map((c) => ({
            id: c.id,
            title: c.title,
            category: c.category,
            severityHint: c.severityHint,
          }));

        const trust_boundaries: string[] = [];
        if (stacks.includes("nextjs")) {
          trust_boundaries.push(
            "Browser client vs Next.js server (Server Components / Route Handlers / Server Actions)",
            "Middleware edge vs Node server runtime",
            "Third-party auth provider callbacks",
          );
        }
        if (stacks.includes("expo")) {
          trust_boundaries.push(
            "Mobile client JS bundle vs backend APIs",
            "SecureStore / Keychain vs AsyncStorage preferences",
            "Deep-link / AuthSession entry points vs privileged screens",
          );
        }
        if (stacks.includes("swift")) {
          trust_boundaries.push(
            "Device UI vs local secure storage (Keychain / Secure Enclave)",
            "App process vs network backends",
            "WebView / deep-link entry points vs privileged app features",
          );
          if (profile.hasMacOS) {
            trust_boundaries.push(
              "App Sandbox / XPC helpers vs privileged desktop operations",
            );
          }
        }
        if (trust_boundaries.length === 0) {
          trust_boundaries.push(
            "Untrusted client input vs trusted server/core logic",
            "Secrets/config vs application code",
          );
        }

        const data = {
          ok: true as const,
          project_root: root,
          summary: `Architecture profile for ${root}: stacks=${stacks.join(", ")}; recommended_packs=${recommended_packs.join(", ")}; auth paths=${surface.auth_related.length}; api routes=${surface.api_routes.length}.`,
          stacks,
          detection: {
            hasExpo: profile.hasExpo,
            hasMacOS: profile.hasMacOS,
            hasNextConfig: profile.hasNextConfig,
            hasSwiftFiles: profile.hasSwiftFiles,
          },
          top_level: profile.topLevelEntries,
          surface,
          trust_boundaries,
          notable_dependencies: dependencies.filter((d) =>
            /next|react|expo|auth|clerk|prisma|drizzle|supabase|stripe|swift|firebase|aws|openai/i.test(
              d,
            ),
          ),
          recommended_packs,
          /**
           * Batches sized for secure_mcp_get_knowledge_pack (max 6 ids per call).
           * Load pack_batches[0] first with detail=summary; load later batches only if needed.
           */
          pack_batches,
          /** Compact seed for orientation only — prefer get_knowledge_pack for checklists. */
          checklist_seed,
          next_tools: [
            "secure_mcp_get_knowledge_pack",
            "secure_mcp_check_authentication",
            "secure_mcp_analyze_injection_risks",
            "secure_mcp_review_secrets",
            "secure_mcp_build_remediation_threat_model",
          ],
          notes: [
            "Defensive architecture review for control placement and remediation planning.",
            pack_batches.length > 1
              ? `Load knowledge in ${pack_batches.length} get_knowledge_pack calls using pack_batches (max 6 ids each); start with pack_batches[0], detail=summary.`
              : "Load knowledge via secure_mcp_get_knowledge_pack(pack_ids=pack_batches[0] or recommended_packs) with detail=summary first.",
            "Do not request every pack; do not use surface maps for offensive targeting.",
          ],
        };

        const md = [
          `# Architecture overview`,
          "",
          `**Root:** ${root}`,
          `**Stacks:** ${stacks.join(", ")}`,
          `**Recommended packs:** ${recommended_packs.join(", ")}`,
          `**Pack batches:** ${pack_batches.map((b, i) => `[${i}] ${b.join(", ")}`).join(" · ")}`,
          "",
          `## Trust boundaries`,
          ...trust_boundaries.map((t) => `- ${t}`),
          "",
          `## Auth-related paths (${surface.auth_related.length})`,
          ...surface.auth_related.slice(0, 20).map((p) => `- ${p}`),
          "",
          `## API / route surface (${surface.api_routes.length})`,
          ...surface.api_routes.slice(0, 20).map((p) => `- ${p}`),
          "",
          `## Next: load packs then category tools`,
          ...pack_batches.map(
            (batch, i) =>
              `- \`secure_mcp_get_knowledge_pack\` batch ${i}: pack_ids=[${batch.map((p) => `"${p}"`).join(", ")}]`,
          ),
          ...data.next_tools.slice(1).map((t) => `- \`${t}\``),
        ].join("\n");

        return toolSuccess(data, {
          responseFormat: params.response_format,
          markdown: md,
        });
      } catch (error) {
        return toolError(error, "Ensure project_root is readable by the MCP server process.");
      }
    },
  );
}
