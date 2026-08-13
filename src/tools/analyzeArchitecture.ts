/**
 * Tool: secure_mcp_analyze_architecture
 * High-level architecture overview for defensive hardening and control placement.
 * Returns recommended_packs for progressive knowledge loading (not a full checklist dump).
 */

import type { McpServer } from "@modelcontextprotocol/server";
import type { z } from "zod";
import { loadConfig, type ServerConfig } from "../config.js";
import { toolError, toolSuccess } from "../lib/envelope.js";
import {
  normalizeAuthorizedProjectRoot,
  profileProject,
  readProjectFileIfExists,
  walkProject,
} from "../lib/filesystem.js";
import type { CoverageReport, StackFocus } from "../lib/types.js";
import { redactCoverageReport, redactedSecretPaths } from "../lib/redact.js";
import { renderMarkdownDocument } from "../lib/markdown.js";
import { ProjectRootInput } from "../knowledge/findings-schema.js";
import {
  checklistFromPackIds,
  focusedProfileForStack,
  recommendPackPlan,
} from "../knowledge/packs/registry.js";

const InputSchema = ProjectRootInput;
type Input = z.infer<typeof InputSchema>;

/** Legacy path-bucket surface kept for compatibility with existing agents. */
interface SurfaceBuckets {
  entrypoints: string[];
  auth_related: string[];
  config_files: string[];
  api_routes: string[];
  data_layer_hints: string[];
}

/**
 * Stack-honest high-value surface kinds. Only kinds that match detected stacks
 * are emitted — never invent Next-only surfaces for non-Next roots.
 */
export type SurfaceKind =
  | "http_route"
  | "server_action"
  | "middleware"
  | "page_entry"
  | "app_entry"
  | "auth_surface"
  | "deep_link"
  | "webview"
  | "secure_storage"
  | "config"
  | "data_layer";

export type SurfaceExposure = "public" | "authenticated" | "internal" | "unknown";

export interface TypedSurface {
  id: string;
  kind: SurfaceKind;
  exposure: SurfaceExposure;
  paths: string[];
  auth_expectation: string;
  stacks: StackFocus[];
  evidence_basis: "path_inventory";
}

export interface CoverageGap {
  surface_id: string;
  kind: SurfaceKind;
  paths: string[];
  reason: string;
  suggested_tools: string[];
}

export interface SecurityBrief {
  stacks: string[];
  trust_boundaries: string[];
  high_value_surfaces: Array<{
    kind: SurfaceKind;
    exposure: SurfaceExposure;
    path_count: number;
    sample_paths: string[];
  }>;
  coverage_gap_count: number;
  recommended_packs: string[];
  priority_paths: string[];
  notes: string[];
}

const SURFACE_PATH_CAP = 12;
const SURFACE_KIND_CAP = 20;
const PRIORITY_PATH_CAP = 24;
const COVERAGE_GAP_CAP = 16;

const HIGH_VALUE_KINDS = new Set<SurfaceKind>([
  "http_route",
  "server_action",
  "middleware",
  "auth_surface",
  "deep_link",
  "webview",
  "secure_storage",
  "data_layer",
]);

function baseName(relativePath: string): string {
  const lower = relativePath.toLowerCase();
  return lower.split("/").pop() ?? lower;
}

function uniqPaths(paths: string[], cap = SURFACE_PATH_CAP): string[] {
  return [...new Set(paths)].slice(0, cap);
}

function classifyBuckets(relativePaths: string[]): SurfaceBuckets {
  const entrypoints: string[] = [];
  const auth_related: string[] = [];
  const config_files: string[] = [];
  const api_routes: string[] = [];
  const data_layer_hints: string[] = [];

  for (const relativePath of relativePaths) {
    const p = relativePath.toLowerCase();
    const base = baseName(relativePath);

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
      config_files.push(relativePath);
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
      auth_related.push(relativePath);
    }

    if (
      p.includes("/api/") ||
      p.includes("route.ts") ||
      p.includes("route.js") ||
      p.includes("server action") ||
      /actions?\.(ts|js|swift)$/.test(base)
    ) {
      api_routes.push(relativePath);
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
      data_layer_hints.push(relativePath);
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
      entrypoints.push(relativePath);
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

function collectKindPaths(
  relativePaths: string[],
  matcher: (relativePath: string, base: string) => boolean,
): string[] {
  const matches: string[] = [];
  for (const relativePath of relativePaths) {
    if (matcher(relativePath, baseName(relativePath))) {
      matches.push(relativePath);
    }
  }
  return uniqPaths(matches);
}

function isJavaScriptOrTypeScriptPath(relativePath: string): boolean {
  return /\.(?:[cm]?[jt]sx?)$/i.test(relativePath);
}

function isSwiftPath(relativePath: string): boolean {
  return /\.swift$/i.test(relativePath);
}

function isNextRouteRoot(relativePath: string, root: "app" | "pages"): boolean {
  return new RegExp(`^(?:src/)?${root}/`, "i").test(relativePath);
}

function isNamedSurfacePath(relativePath: string, pattern: RegExp): boolean {
  return pattern.test(relativePath) && isJavaScriptOrTypeScriptPath(relativePath);
}

function buildTypedSurfaces(
  relativePaths: string[],
  stacks: StackFocus[],
): TypedSurface[] {
  const surfaces: TypedSurface[] = [];

  const push = (
    kind: SurfaceKind,
    paths: string[],
    exposure: SurfaceExposure,
    auth_expectation: string,
    kindStacks: StackFocus[],
  ): void => {
    if (paths.length === 0 || kindStacks.length === 0) return;
    if (surfaces.length >= SURFACE_KIND_CAP) return;
    surfaces.push({
      id: `surf-${kind}-${surfaces.length + 1}`,
      kind,
      exposure,
      paths,
      auth_expectation,
      stacks: kindStacks,
      evidence_basis: "path_inventory",
    });
  };

  const authName = /auth|session|login|clerk|nextauth|credential|keychain|securestore|secure-store/i;
  const deepLinkName = /deep.?link|universal.?link|onopenurl|linking|authsession|redirect/i;
  const webviewName = /webview|wkwebview|wkscript|javascriptbridge|react-native-webview/i;
  const secureStorageName = /keychain|securestore|secure-store|secentitlement|ksecattr/i;
  const dataName = /prisma|drizzle|supabase|repository|swiftdata|coredata|model\//i;

  // When Next is detected, its TS/JS paths are represented by the more precise
  // Next surfaces. Avoid duplicating them as generic TypeScript surfaces.
  const activeStacks = [...new Set(stacks)].filter(
    (stack) =>
      !(stack === "typescript" && stacks.includes("nextjs")) &&
      !(stack === "common" && stacks.some((candidate) => candidate !== "common")),
  );

  for (const stack of activeStacks) {
    const stackPaths = (matcher: (path: string, base: string) => boolean): string[] =>
      collectKindPaths(relativePaths, matcher);

    if (stack === "nextjs") {
      push(
        "http_route",
        stackPaths((path, base) =>
          isJavaScriptOrTypeScriptPath(path) &&
          ((isNextRouteRoot(path, "app") && /^route\.[cm]?[jt]sx?$/i.test(base)) ||
            (isNextRouteRoot(path, "pages") && /^(?:src\/)?pages\/api\//i.test(path))),
        ),
        "public",
        "Authenticate and authorize every method; do not rely on middleware alone.",
        [stack],
      );
      push(
        "server_action",
        stackPaths((path, base) =>
          isJavaScriptOrTypeScriptPath(path) &&
          (/^actions?\.[cm]?[jt]sx?$/i.test(base) || /(^|\/)actions?\//i.test(path)),
        ),
        "public",
        "Treat as HTTP-invocable: schema-validate inputs and enforce object-level authz.",
        [stack],
      );
      push(
        "middleware",
        stackPaths((_path, base) => /^middleware\.[cm]?[jt]s$/i.test(base)),
        "public",
        "Matcher coverage is incomplete by design; re-check authz at each sensitive entrypoint.",
        [stack],
      );
      push(
        "page_entry",
        stackPaths((path, base) => {
          if (!isJavaScriptOrTypeScriptPath(path)) return false;
          if (isNextRouteRoot(path, "app")) return /^(?:page|layout)\.[cm]?[jt]sx?$/i.test(base);
          return isNextRouteRoot(path, "pages") && !/^(?:src\/)?pages\/api\//i.test(path);
        }),
        "unknown",
        "Confirm server-side data loaders enforce session/ownership before rendering sensitive data.",
        [stack],
      );
    } else if (stack === "typescript") {
      push(
        "http_route",
        stackPaths((path, base) =>
          isJavaScriptOrTypeScriptPath(path) &&
          (/\/(?:api|routes?)\//i.test(`/${path}`) || /^route\.[cm]?[jt]sx?$/i.test(base)),
        ),
        "public",
        "Authenticate, authorize, and validate every externally reachable handler.",
        [stack],
      );
      push(
        "app_entry",
        stackPaths((path, base) =>
          isJavaScriptOrTypeScriptPath(path) &&
          (/^(?:index|main|app)\.[cm]?[jt]sx?$/i.test(base) || /^src\/index\.[cm]?[jt]s$/i.test(path)),
        ),
        "internal",
        "Confirm process entrypoints do not expose privileged operations without auth checks.",
        [stack],
      );
    } else if (stack === "swift") {
      push(
        "app_entry",
        stackPaths((path, base) =>
          isSwiftPath(path) &&
          (base === "main.swift" || base === "app.swift" || /appdelegate\.swift$/i.test(path)),
        ),
        "internal",
        "Confirm launch/deep-link handlers do not grant privileged state before auth.",
        [stack],
      );
      push(
        "deep_link",
        stackPaths((path) => isSwiftPath(path) && deepLinkName.test(path)),
        "public",
        "Validate deep-link targets before elevating session or navigation privileges.",
        [stack],
      );
      push(
        "webview",
        stackPaths((path) => isSwiftPath(path) && webviewName.test(path)),
        "public",
        "Restrict script bridges and navigation allowlists; treat WebView content as untrusted.",
        [stack],
      );
      push(
        "secure_storage",
        stackPaths(
          (path) =>
            (isSwiftPath(path) && secureStorageName.test(path)) || /\.entitlements$/i.test(path),
        ),
        "internal",
        "Use Keychain with least accessibility; never store tokens in plain preferences.",
        [stack],
      );
    } else if (stack === "expo") {
      push(
        "app_entry",
        stackPaths((path, base) =>
          isJavaScriptOrTypeScriptPath(path) &&
          (/^(?:app|_layout|index)\.[cm]?[jt]sx?$/i.test(base) || /^src\/index\.[cm]?[jt]s$/i.test(path)),
        ),
        "internal",
        "Confirm launch/deep-link handlers do not grant privileged state before auth.",
        [stack],
      );
      push(
        "deep_link",
        stackPaths((path) => isNamedSurfacePath(path, deepLinkName)),
        "public",
        "Validate deep-link/AuthSession targets before elevating session or navigation privileges.",
        [stack],
      );
      push(
        "webview",
        stackPaths((path) => isNamedSurfacePath(path, webviewName)),
        "public",
        "Restrict script bridges and navigation allowlists; treat WebView content as untrusted.",
        [stack],
      );
      push(
        "secure_storage",
        stackPaths((path) => isNamedSurfacePath(path, secureStorageName)),
        "internal",
        "Use SecureStore with least accessibility; never store tokens in plain preferences.",
        [stack],
      );
    }

    const sourceMatchesStack = (path: string): boolean =>
      stack === "swift"
        ? isSwiftPath(path)
        : stack === "common"
          ? false
          : isJavaScriptOrTypeScriptPath(path);
    push(
      "auth_surface",
      stackPaths((path) => sourceMatchesStack(path) && authName.test(path)),
      "unknown",
      "Verify session establishment, refresh, logout, and object-level authorization together.",
      [stack],
    );

    push(
      "config",
      stackPaths((_path, base) => {
        switch (stack) {
          case "nextjs":
            return (
              base === "package.json" ||
              base === "tsconfig.json" ||
              base.startsWith("next.config") ||
              base === "vercel.json" ||
              /^middleware\.[cm]?[jt]s$/i.test(base)
            );
          case "typescript":
            return (
              base === "package.json" ||
              base === "tsconfig.json" ||
              base === "dockerfile" ||
              base === "vercel.json"
            );
          case "swift":
            return base === "package.swift" || base === "info.plist" || base.endsWith(".entitlements");
          case "expo":
            return (
              base === "package.json" ||
              base === "tsconfig.json" ||
              base === "app.json" ||
              base.startsWith("app.config") ||
              base === "eas.json"
            );
          case "common":
            return base === "dockerfile" || base === "makefile";
        }
      }),
      "internal",
      "Review public env, entitlements, and deploy config for over-broad exposure.",
      [stack],
    );

    push(
      "data_layer",
      stackPaths((path, base) =>
        sourceMatchesStack(path) && (dataName.test(path) || base.includes("schema")),
      ),
      "internal",
      "Enforce authorization at the data access boundary; avoid trusting client-supplied ids.",
      [stack],
    );
  }

  return surfaces;
}

function toolsForSurfaceKind(kind: SurfaceKind): string[] {
  switch (kind) {
    case "http_route":
    case "server_action":
    case "middleware":
    case "auth_surface":
    case "deep_link":
    case "webview":
      return [
        "secure_mcp_check_authentication",
        "secure_mcp_analyze_injection_risks",
      ];
    case "secure_storage":
      return ["secure_mcp_check_authentication", "secure_mcp_review_secrets"];
    case "data_layer":
      return [
        "secure_mcp_analyze_injection_risks",
        "secure_mcp_check_authentication",
      ];
    case "page_entry":
    case "app_entry":
      return ["secure_mcp_check_authentication"];
    case "config":
      return ["secure_mcp_review_secrets", "secure_mcp_check_authentication"];
  }
}

function buildCoverageGaps(surfaces: TypedSurface[]): CoverageGap[] {
  const gaps: CoverageGap[] = [];
  for (const surface of surfaces) {
    if (!HIGH_VALUE_KINDS.has(surface.kind)) continue;
    gaps.push({
      surface_id: surface.id,
      kind: surface.kind,
      paths: surface.paths.slice(0, 6),
      reason:
        "Architecture inventory only — no category detector evidence yet. Sample these paths after auth/injection/secrets tools and reconcile zero-hit high-value surfaces.",
      suggested_tools: toolsForSurfaceKind(surface.kind),
    });
    if (gaps.length >= COVERAGE_GAP_CAP) break;
  }
  return gaps;
}

function buildPriorityPaths(
  surfaces: TypedSurface[],
  focusPaths: string[] | undefined,
): string[] {
  const ranked = [...surfaces].sort((a, b) => {
    const aHigh = HIGH_VALUE_KINDS.has(a.kind) ? 1 : 0;
    const bHigh = HIGH_VALUE_KINDS.has(b.kind) ? 1 : 0;
    if (aHigh !== bHigh) return bHigh - aHigh;
    return a.kind.localeCompare(b.kind);
  });
  const paths: string[] = [];
  for (const surface of ranked) {
    for (const p of surface.paths) {
      if (!paths.includes(p)) paths.push(p);
      if (paths.length >= PRIORITY_PATH_CAP) {
        return paths;
      }
    }
  }
  if (focusPaths) {
    for (const focus of focusPaths) {
      if (!paths.includes(focus)) paths.push(focus);
      if (paths.length >= PRIORITY_PATH_CAP) break;
    }
  }
  return paths;
}

function buildSecurityBrief(input: {
  stacks: string[];
  trust_boundaries: string[];
  surfaces: TypedSurface[];
  coverage_gaps: CoverageGap[];
  recommended_packs: string[];
  priority_paths: string[];
}): SecurityBrief {
  return {
    stacks: input.stacks,
    trust_boundaries: input.trust_boundaries.slice(0, 8),
    high_value_surfaces: input.surfaces
      .filter((s) => HIGH_VALUE_KINDS.has(s.kind))
      .slice(0, 12)
      .map((s) => ({
        kind: s.kind,
        exposure: s.exposure,
        path_count: s.paths.length,
        sample_paths: s.paths.slice(0, 3),
      })),
    coverage_gap_count: input.coverage_gaps.length,
    recommended_packs: input.recommended_packs,
    priority_paths: input.priority_paths.slice(0, 12),
    notes: [
      "Derived from architecture path inventory and pack routing — not a separate project walk.",
      "Treat as the security brief for this root; retain through category tools and revalidation.",
      "Reconcile coverage_gaps after category detectors: sample zero-hit high-value surfaces manually.",
    ],
  };
}

async function detectSurface(
  root: string,
  maxFiles: number | undefined,
  focusPaths: string[] | undefined,
  stacks: StackFocus[],
  config: ServerConfig = loadConfig(),
): Promise<{
  surface: SurfaceBuckets;
  surfaces: TypedSurface[];
  coverage_gaps: CoverageGap[];
  priority_paths: string[];
  coverage: CoverageReport;
}> {
  const { files, coverageSession } = await walkProject(root, {
    maxFiles: maxFiles ?? config.defaultMaxFiles,
    maxDepth: config.maxDepth,
    maxFileBytes: config.maxFileBytes,
    maxTotalBytes: config.maxTotalBytes,
    allowedRoots: config.allowedRoots,
    focusPrefixes: focusPaths,
  });
  const relativePaths = files.map((f) => f.relativePath);
  const surface = classifyBuckets(relativePaths);
  const surfaces = buildTypedSurfaces(relativePaths, stacks);
  const coverage_gaps = buildCoverageGaps(surfaces);
  const priority_paths = buildPriorityPaths(surfaces, focusPaths);
  return {
    surface,
    surfaces,
    coverage_gaps,
    priority_paths,
    coverage: coverageSession.finish(),
  };
}

function redactTypedSurfaces(surfaces: TypedSurface[]): TypedSurface[] {
  return surfaces.map((surface) => ({
    ...surface,
    paths: redactedSecretPaths(surface.paths),
  }));
}

function redactCoverageGaps(gaps: CoverageGap[]): CoverageGap[] {
  return gaps.map((gap) => ({
    ...gap,
    paths: redactedSecretPaths(gap.paths),
  }));
}

function redactSecurityBrief(brief: SecurityBrief): SecurityBrief {
  return {
    ...brief,
    high_value_surfaces: brief.high_value_surfaces.map((item) => ({
      ...item,
      sample_paths: redactedSecretPaths(item.sample_paths),
    })),
    priority_paths: redactedSecretPaths(brief.priority_paths),
  };
}

export function registerAnalyzeArchitecture(
  server: McpServer,
  config: ServerConfig = loadConfig(),
): void {
  server.registerTool(
    "secure_mcp_analyze_architecture",
    {
      title: "Analyze architecture for hardening",
      description: `Defensive secure-code-review tool: high-level architecture map (stacks, typed surfaces, coverage gaps, trust boundaries) and recommended knowledge packs for progressive loading.

Args: project_root, stack?, max_files?, focus_paths?, response_format.
Returns: stacks, surface (legacy path buckets), surfaces (typed), coverage_gaps, priority_paths, security_brief, trust_boundaries, recommended_packs, pack_batches, checklist_seed, next_tools.

Guidance: Call secure_mcp_get_audit_guidance for the full workflow and guardrails.`,
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
        const profile = await profileProject(root, {
          focusPrefixes: params.focus_paths,
          maxFiles: effectiveMaxFiles,
          maxDepth: config.maxDepth,
          maxFileBytes: config.maxFileBytes,
          maxTotalBytes: config.maxTotalBytes,
          allowedRoots: config.allowedRoots,
        });
        const forcedStack =
          params.stack && params.stack !== "auto" ? params.stack : undefined;
        const stacks = forcedStack ? [forcedStack] : profile.likelyStacks;
        const detected = await detectSurface(
          root,
          effectiveMaxFiles,
          params.focus_paths,
          stacks,
          config,
        );
        const { surface, surfaces, coverage_gaps, priority_paths } = detected;
        const safeSurface = {
          entrypoints: redactedSecretPaths(surface.entrypoints),
          auth_related: redactedSecretPaths(surface.auth_related),
          config_files: redactedSecretPaths(surface.config_files),
          api_routes: redactedSecretPaths(surface.api_routes),
          data_layer_hints: redactedSecretPaths(surface.data_layer_hints),
        };
        const safeSurfaces = redactTypedSurfaces(surfaces);
        const safeGaps = redactCoverageGaps(coverage_gaps);
        const safePriorityPaths = redactedSecretPaths(priority_paths);

        const packageJson = await readProjectFileIfExists(
          root,
          "package.json",
          config.maxFileBytes,
          config.allowedRoots,
        );
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

        // auto: union of profile detection. Forced stack: exclusive focus (no unrelated flags).
        const packPlan = forcedStack
          ? recommendPackPlan(stacks, focusedProfileForStack(forcedStack, profile))
          : recommendPackPlan(stacks, profile);
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

        const security_brief = redactSecurityBrief(
          buildSecurityBrief({
            stacks,
            trust_boundaries,
            surfaces: safeSurfaces,
            coverage_gaps: safeGaps,
            recommended_packs,
            priority_paths: safePriorityPaths,
          }),
        );

        const data = {
          ok: true as const,
          project_root: root,
          summary: `Architecture profile for ${root}: stacks=${stacks.join(", ")}; recommended_packs=${recommended_packs.join(", ")}; surfaces=${safeSurfaces.length}; coverage_gaps=${safeGaps.length}; auth paths=${surface.auth_related.length}; api routes=${surface.api_routes.length}.`,
          stacks,
          detection: {
            hasExpo: profile.hasExpo,
            hasMacOS: profile.hasMacOS,
            hasNextConfig: profile.hasNextConfig,
            hasSwiftFiles: profile.hasSwiftFiles,
          },
          top_level: redactedSecretPaths(profile.topLevelEntries),
          top_level_truncated: profile.topLevelEntriesTruncated,
          /** Legacy path buckets for existing agents. Prefer `surfaces` for prioritization. */
          surface: safeSurface,
          /** Typed high-value surface inventory (kind, exposure, auth expectation, paths). */
          surfaces: safeSurfaces,
          /**
           * High-value surfaces without category-detector evidence yet.
           * After auth/injection/secrets tools, sample zero-hit surface files and reconcile.
           */
          coverage_gaps: safeGaps,
          /** Suggested focus_paths / manual sample order for follow-up category or revalidation work. */
          priority_paths: safePriorityPaths,
          /**
           * Compact security brief derived from architecture fields only (no extra walks).
           * Retain this as the agent-side project brief through the rest of the audit.
           */
          security_brief,
          coverage: redactCoverageReport(detected.coverage),
          files_reviewed: [],
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
            "Retain surfaces, coverage_gaps, priority_paths, and security_brief as the architecture-as-brief artifact.",
            pack_batches.length > 1
              ? `Load knowledge in ${pack_batches.length} get_knowledge_pack calls using pack_batches (max 6 ids each); start with pack_batches[0], detail=summary.`
              : "Load knowledge via secure_mcp_get_knowledge_pack(pack_ids=pack_batches[0] or recommended_packs) with detail=summary first.",
            "Do not request every pack; do not use surface maps for offensive targeting.",
          ],
        };

        const md = renderMarkdownDocument({
          title: "Architecture overview",
          metadata: [
            { label: "Root", value: root },
            { label: "Stacks", value: stacks.join(", ") },
            { label: "Recommended packs", value: recommended_packs.join(", ") },
            {
              label: "Pack batches",
              value: pack_batches.map((batch, i) => `[${i}] ${batch.join(", ")}`).join(" · "),
            },
            {
              label: "Typed surfaces",
              value: String(safeSurfaces.length),
            },
            {
              label: "Coverage gaps",
              value: String(safeGaps.length),
            },
          ],
          sections: [
            { heading: "Trust boundaries", bullets: trust_boundaries },
            {
              heading: `High-value surfaces (${safeSurfaces.filter((s) => HIGH_VALUE_KINDS.has(s.kind)).length})`,
              bullets: safeSurfaces
                .filter((s) => HIGH_VALUE_KINDS.has(s.kind))
                .slice(0, 12)
                .map(
                  (s) =>
                    `${s.kind} (${s.exposure}): ${s.paths.slice(0, 3).join(", ") || "(no paths)"} — ${s.auth_expectation}`,
                ),
            },
            {
              heading: `Coverage gaps (${safeGaps.length})`,
              bullets: safeGaps.slice(0, 12).map(
                (g) =>
                  `${g.kind}: ${g.paths.slice(0, 2).join(", ") || "(none)"} — sample after category tools (${g.suggested_tools.join(", ")})`,
              ),
            },
            {
              heading: `Priority paths (${safePriorityPaths.length})`,
              bullets: safePriorityPaths.slice(0, 16),
            },
            {
              heading: "Security brief",
              bullets: [
                `High-value surface count: ${security_brief.high_value_surfaces.length}`,
                `Coverage gap count: ${security_brief.coverage_gap_count}`,
                ...security_brief.notes,
              ],
            },
            {
              heading: `Auth-related paths (${surface.auth_related.length})`,
              bullets: safeSurface.auth_related.slice(0, 20),
            },
            {
              heading: `API / route surface (${surface.api_routes.length})`,
              bullets: safeSurface.api_routes.slice(0, 20),
            },
            {
              heading: "Next: load packs then category tools",
              bullets: [
                ...pack_batches.map(
                  (batch, i) =>
                    `secure_mcp_get_knowledge_pack batch ${i}: pack_ids=[${batch.map((pack) => `"${pack}"`).join(", ")}]`,
                ),
                ...data.next_tools.slice(1),
              ],
            },
          ],
        });

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
