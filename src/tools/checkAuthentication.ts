/**
 * Tool: secure_mcp_check_authentication
 * Defensive authentication / authorization review for remediation.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { z } from "zod";
import { loadConfig, type ServerConfig } from "../config.js";
import {
  detectWithBudget,
  finalizeCoverage,
  findLineNumber,
  normalizeProjectRoot,
  profileProject,
  recordCoverageExclusion,
  readProjectFile,
  snippetAround,
  toolError,
  toolSuccess,
  walkProject,
} from "../lib/filesystem.js";
import {
  redactCoverageReport,
  redactFinding,
  redactFindings,
  redactedSecretPaths,
} from "../lib/redact.js";
import { escapeMarkdown } from "../lib/markdown.js";
import type { Finding, ProjectProfile, StackFocus } from "../lib/types.js";
import {
  buildFinding,
  createFindingIdFactory,
  ProjectRootInput,
} from "../knowledge/findings-schema.js";
import { NEXTJS_AUTH_FILE_HINTS } from "../knowledge/nextjs.js";
import {
  focusedProfileForStack,
  packIdsWithCategories,
  recommendPackIds,
  type PackId,
} from "../knowledge/packs/registry.js";
import { SWIFT_AUTH_PATTERNS } from "../knowledge/swift.js";

const InputSchema = ProjectRootInput;
type Input = z.infer<typeof InputSchema>;

const AUTH_NAME_RE =
  /auth|session|login|logout|signin|signout|password|credential|middleware|guard|permission|role|oauth|jwt|token|keychain|biometric|faceid|touchid|localauthentication|securestore|secure-store|async-?storage|mmkv|webview|urlsession|network|pasteboard|deeplink|openurl|transport|secur/i;

const SWIFT_AUTH_PATH_RE =
  /keychain|session|auth|token|network|url|trust|webview|pasteboard|storage|secur|credential|challenge|delegate|bridge/i;

/** Exported for tests: path looks like auth / session / mobile secure-storage code. */
export function isAuthCandidatePath(relativePath: string): boolean {
  if (AUTH_NAME_RE.test(relativePath)) return true;
  return NEXTJS_AUTH_FILE_HINTS.some((h) =>
    relativePath.toLowerCase().includes(h.toLowerCase()),
  );
}

/**
 * Whether a Swift file should be scanned for auth sinks.
 * Forced `stack=swift` scans all `.swift` files (capped by the tool budget);
 * auto-detect still prefers path keywords so monorepos stay within limits.
 */
export function shouldScanSwiftAuthFile(
  relativePath: string,
  ext: string,
  stack: StackFocus | "auto",
): boolean {
  if (ext !== ".swift") return false;
  if (stack === "swift") return true;
  return SWIFT_AUTH_PATH_RE.test(relativePath);
}

interface AuthPattern {
  id: string;
  title: string;
  regex: RegExp;
  severity: Finding["severity"];
  confidence: Finding["confidence"];
  description: string;
  remediation: string;
  impact_if_unremediated: string;
  cwe?: string;
  stack?: Finding["stack"];
  filter?: (match: string, content: string) => boolean;
}

/** Stable traceability family for an auth detector, independent of report ids. */
export function authDetectorFamily(stack: AuthPattern["stack"]): string {
  return stack === "swift"
    ? "swift-ios.authentication"
    : stack === "expo"
      ? "expo-rn.authentication"
      : stack === "nextjs"
        ? "web-next.authentication"
        : "auth-web.authentication";
}

/**
 * Which pattern stacks apply when the caller forces a stack focus.
 * JS stacks share generic TypeScript patterns; Swift stays separate.
 */
const PATTERN_STACKS_BY_FOCUS: Record<StackFocus, StackFocus[]> = {
  common: ["common"],
  typescript: ["common", "typescript"],
  nextjs: ["common", "typescript", "nextjs"],
  expo: ["common", "typescript", "expo"],
  swift: ["common", "swift"],
};

/** Exported for tests: does a pattern apply under the requested stack focus? */
export function authPatternAppliesToStack(
  patternStack: Finding["stack"] | undefined,
  focus?: StackFocus | "auto",
): boolean {
  if (!focus || focus === "auto") return true;
  return PATTERN_STACKS_BY_FOCUS[focus].includes(patternStack ?? "common");
}

/**
 * Exported for tests: profile informational findings follow the same forced-stack
 * exclusivity as patterns and packs.
 */
export function shouldEmitProfileAuthFinding(
  profileStack: Finding["stack"],
  profileSignal: boolean,
  focus?: StackFocus | "auto",
): boolean {
  return profileSignal && authPatternAppliesToStack(profileStack, focus);
}

/**
 * Pack ids behind this tool's heuristics, derived from the routed packs for the
 * detected (or forced) stacks and narrowed to authn/authz content. Keeps an
 * Expo-only project from claiming web cookie/CSRF guidance it never used.
 */
export function authPackIdsForProfile(
  profile: Pick<ProjectProfile, "hasExpo" | "hasMacOS" | "hasNextConfig" | "hasSwiftFiles" | "likelyStacks">,
  stack?: StackFocus | "auto",
): PackId[] {
  const forced = stack && stack !== "auto" ? stack : undefined;
  const stacks = forced ? [forced] : profile.likelyStacks;
  const routed = recommendPackIds(
    stacks,
    forced ? focusedProfileForStack(forced, profile) : profile,
  );
  return packIdsWithCategories(routed, ["authentication", "authorization"]);
}

/** Exported for tests; heuristics only — every hit needs manual confirmation. */
export const AUTH_PATTERNS: AuthPattern[] = [
  {
    id: "AUTH-HARDCODED-JWT-SECRET",
    title: "Hardcoded JWT / signing secret",
    regex:
      /\b(jwt|JWT|sign|secret|NEXTAUTH_SECRET)\b[^;\n]{0,40}[:=]\s*['"][^'"]{8,}['"]/g,
    severity: "critical",
    confidence: "medium",
    description: "Possible hardcoded signing secret or JWT secret in source — should be externalized.",
    remediation: "Load secrets from environment or a secret manager; rotate if committed.",
    impact_if_unremediated:
      "Anyone with repository access may forge or validate sessions if the secret is still active.",
    cwe: "CWE-798",
    stack: "typescript",
  },
  {
    id: "AUTH-DISABLE-VERIFY",
    title: "Disabled TLS / certificate verification",
    regex: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0/g,
    severity: "high",
    confidence: "high",
    description: "TLS certificate verification appears disabled in configuration or code.",
    remediation: "Enable certificate verification in production; fix trust-store issues properly.",
    impact_if_unremediated:
      "Network peers may not be authenticated, weakening confidentiality and integrity of traffic.",
    cwe: "CWE-295",
  },
  {
    id: "AUTH-MIDDLEWARE-ONLY",
    title: "Auth check concentrated in middleware-like layer",
    regex: /export\s+(async\s+)?function\s+middleware[\s\S]{0,200}\b(auth|getToken|session)\b/g,
    severity: "medium",
    confidence: "low",
    description:
      "Middleware performs auth checks. Confirm the same checks exist in Server Actions, Route Handlers, and data loaders for defense in depth.",
    remediation:
      "Re-validate sessions and authorization at each sensitive server boundary, not only middleware.",
    impact_if_unremediated:
      "Sensitive server entrypoints outside the middleware matcher may lack authentication or authorization.",
    stack: "nextjs",
  },
  {
    id: "AUTH-MISSING-ROLE-CHECK",
    title: "Session helper usage without nearby ownership check",
    regex: /getServerSession|auth\(\)|currentUser\(|requireAuth/g,
    severity: "info",
    confidence: "low",
    description:
      "Authentication helper usage detected. Manually verify object-level authorization on the resources being accessed.",
    remediation: "Pair authentication with explicit authorization (roles, ownership, tenants).",
    impact_if_unremediated:
      "Authenticated users may access resources they should not if object-level checks are missing.",
    cwe: "CWE-285",
  },
  ...SWIFT_AUTH_PATTERNS.map(
    (p): AuthPattern => ({
      id: p.id === "SWIFT-USERDEFAULTS-TOKEN" ? "AUTH-USERDEFAULTS-TOKEN" : `AUTH-${p.id}`,
      title: p.title,
      regex: p.regex,
      severity: p.severity === "info" ? "info" : p.severity,
      confidence: p.confidence,
      description: `${p.title}. Confirm the sink handles credentials or session material insecurely before treating as confirmed.`,
      remediation: p.recommendation,
      impact_if_unremediated: p.impact_if_unremediated,
      cwe: p.cwe,
      stack: "swift",
      filter: p.filter,
    }),
  ),
  {
    id: "AUTH-RN-INSECURE-TOKEN-STORE",
    title: "Token-like value in AsyncStorage / MMKV",
    regex:
      /(AsyncStorage|MMKV|createMMKV|useMMKVString)[\s\S]{0,120}(token|refreshToken|refresh_token|password|session|credential|jwt)/gi,
    severity: "high",
    confidence: "medium",
    description:
      "Session material appears to be written to AsyncStorage or MMKV, which are not encrypted stores by default (see expo-rn pack item EXPO-SECURE-STORE).",
    remediation:
      "Move tokens to expo-secure-store (or a Keychain/Keystore-backed wrapper); keep AsyncStorage/MMKV for non-sensitive preferences.",
    impact_if_unremediated:
      "Tokens in unencrypted device storage are easier to recover from a compromised or backed-up device.",
    cwe: "CWE-922",
    stack: "expo",
  },
  {
    id: "AUTH-EXPO-PUBLIC-CREDENTIAL",
    title: "Credential-like EXPO_PUBLIC_ variable",
    // Match credential suffixes after EXPO_PUBLIC_. Bare KEY is omitted so
    // intentional public client keys (API_KEY, MAPS_API_KEY, PUBLISHABLE_KEY)
    // do not fire. The name is a bounded tempered token (max 64 chars, and the
    // identifier may not contain PUBLISHABLE/ANON anywhere), so the check is
    // linear in input length instead of an unbounded negative lookahead.
    regex:
      /EXPO_PUBLIC_((?:(?!PUBLISHABLE|ANON)[A-Z0-9_]){0,64})(?:SECRET|TOKEN|PASSWORD|CREDENTIAL|PRIVATE_KEY)\b/g,
    severity: "critical",
    confidence: "medium",
    description:
      "EXPO_PUBLIC_* values are embedded in the shipped JS bundle, so credential-shaped names there are effectively public (see expo-rn pack item EXPO-PUBLIC-ENV).",
    remediation:
      "Rename to a server-only variable, proxy the call through a backend, and rotate any key that shipped with a public prefix.",
    impact_if_unremediated:
      "Any user of the app can read the value from the bundle, so the credential must be treated as disclosed.",
    cwe: "CWE-200",
    stack: "expo",
  },
  {
    id: "AUTH-RN-SECURESTORE-WEAK-ACCESS",
    title: "SecureStore write without access control",
    // Only flag writes whose args omit keychainAccessible / requireAuthentication.
    regex:
      /SecureStore\.setItemAsync\s*\((?:(?!keychainAccessible|requireAuthentication)[^)])*\)/g,
    severity: "info",
    confidence: "low",
    description:
      "SecureStore write detected. Confirm keychainAccessible / requireAuthentication options match the sensitivity of the stored credential.",
    remediation:
      "Set keychainAccessible (e.g. WHEN_UNLOCKED_THIS_DEVICE_ONLY) and consider requireAuthentication for high-value secrets.",
    impact_if_unremediated:
      "Default accessibility may keep credentials reachable in states the product does not intend.",
    stack: "expo",
  },
  {
    id: "AUTH-HTTP-BASIC-OR-BEARER-HARDCODE",
    title: "Hardcoded Authorization header",
    regex: /Authorization['"]?\s*:\s*['"]?(Bearer|Basic)\s+[A-Za-z0-9._\-+/=]{8,}/gi,
    severity: "critical",
    confidence: "high",
    description: "Hardcoded Authorization header value found in source.",
    remediation: "Remove hardcoded credentials; load at runtime from secure storage or a secret manager.",
    impact_if_unremediated:
      "Embedded credentials may grant ongoing API access to anyone with source or binary access.",
    cwe: "CWE-798",
  },
];

const TOOL_DESCRIPTION = `Defensive secure-code-review tool: identify potential authentication and authorization weaknesses so the development team can harden access control.

Args: project_root, stack?, max_files?, focus_paths?, response_format.

Returns: findings[] (shared Finding schema), applied_pack_ids, files_reviewed, notes.

Guidance: Call secure_mcp_get_audit_guidance for the full workflow and guardrails.`;

export function registerCheckAuthentication(
  server: McpServer,
  config: ServerConfig = loadConfig(),
): void {
  server.registerTool(
    "secure_mcp_check_authentication",
    {
      title: "Review authentication for remediation",
      description: TOOL_DESCRIPTION,
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
        const effectiveMaxFiles = params.max_files ?? config.defaultMaxFiles;
        const profile = await profileProject(root, {
          focusPrefixes: params.focus_paths,
          maxFiles: effectiveMaxFiles,
          maxDepth: config.maxDepth,
          maxFileBytes: config.maxFileBytes,
        });
        const nextId = createFindingIdFactory("AUTH");
        const findings: Finding[] = [];
        const filesReviewed: string[] = [];
        const detectorFamiliesRun = new Set<string>();

        const { files, coverage } = await walkProject(root, {
          maxFiles: params.max_files ?? config.defaultMaxFiles,
          maxDepth: config.maxDepth,
          maxFileBytes: config.maxFileBytes,
          extensions: new Set([
            ".ts",
            ".tsx",
            ".js",
            ".jsx",
            ".swift",
            ".json",
            ".plist",
            ".entitlements",
            ".mjs",
            ".cjs",
          ]),
          focusPrefixes: params.focus_paths,
        });

        const candidates = files.filter((f) => isAuthCandidatePath(f.relativePath));

        const always = files.filter((f) =>
          /middleware\.(ts|js)$|auth\.(ts|js)$|Package\.swift$|Info\.plist$|\.entitlements$/i.test(
            f.relativePath,
          ),
        );
        const swiftExtra =
          params.stack === "swift" || profile.hasSwiftFiles
            ? files.filter((f) =>
                shouldScanSwiftAuthFile(f.relativePath, f.ext, params.stack),
              )
            : [];
        const toScan = [
          ...new Map(
            [...always, ...candidates, ...swiftExtra].map((f) => [f.relativePath, f]),
          ).values(),
        ].slice(0, 80);

        const scanPaths = new Set(toScan.map((file) => file.relativePath));
        for (const file of files) {
          if (!scanPaths.has(file.relativePath)) {
            recordCoverageExclusion(coverage, {
              path: file.relativePath,
              kind: "file",
              reason: "authentication_candidate_filter_or_budget",
            });
          }
        }

        for (const file of toScan) {
          if (file.size > config.maxFileBytes) {
            recordCoverageExclusion(coverage, {
              path: file.relativePath,
              kind: "file",
              reason: "max_file_bytes",
            });
            continue;
          }
          let content: string;
          try {
            content = (await readProjectFile(root, file.relativePath, config.maxFileBytes)).content;
          } catch {
            recordCoverageExclusion(coverage, {
              path: file.relativePath,
              kind: "file",
              reason: "file_read_error",
            });
            continue;
          }
          filesReviewed.push(file.relativePath);

          for (const pattern of AUTH_PATTERNS) {
            if (!authPatternAppliesToStack(pattern.stack, params.stack)) continue;

            const detectorFamily = authDetectorFamily(pattern.stack);
            detectorFamiliesRun.add(detectorFamily);

            let hits = 0;
            for (const hit of detectWithBudget(pattern.regex, content)) {
              if (pattern.filter && !pattern.filter(hit.match, content)) continue;
              if (hits >= 5) break;
              hits++;
              const rawEvidence = snippetAround(content, hit.index);
              findings.push(
                redactFinding(
                  buildFinding({
                  id: nextId(),
                  title: pattern.title,
                  description: pattern.description,
                  severity: pattern.severity,
                  confidence: pattern.confidence,
                  category: "authentication",
                  stack: pattern.stack ?? "common",
                  rule_family: detectorFamily,
                  root_control: pattern.id,
                  file: file.relativePath,
                  line: findLineNumber(content, hit.index),
                  evidence: rawEvidence,
                  source: "Request, session, credential, or device-storage path identified by the detector.",
                  control: pattern.remediation,
                  sink: `${file.relativePath}:${findLineNumber(content, hit.index)}`,
                  proof_gap: [
                    "Confirm the sensitive operation and its authorization/ownership checks in context.",
                  ],
                  validation: [
                    "Add negative tests for unauthenticated and unauthorized access, then re-run the category review.",
                  ],
                  impact_if_unremediated: pattern.impact_if_unremediated,
                  remediation: pattern.remediation,
                  residual_risk:
                    "Related auth paths may need the same control; re-review after fixes.",
                  verification_suggestion:
                    "Add automated tests for unauthenticated/unauthorized access; re-run this tool after remediation.",
                  cwe: pattern.cwe,
                  tags: ["authentication", pattern.id, "remediation"],
                  }),
                ),
              );
            }
          }
        }

        const nextProfileSignal =
          profile.hasNextConfig || profile.likelyStacks.includes("nextjs");
        const hasMiddleware = files.some((f) => /middleware\.(ts|js)$/.test(f.relativePath));
        if (shouldEmitProfileAuthFinding("nextjs", nextProfileSignal, params.stack)) {
          if (hasMiddleware) {
            detectorFamiliesRun.add("web-next.profile-auth-boundary");
            findings.push(
              buildFinding({
                id: nextId(),
                title: "Verify middleware matcher coverage and server-side re-checks",
                description:
                  "Next.js middleware was detected. Incomplete matchers can leave Route Handlers or Server Actions without shared auth checks unless re-enforced server-side.",
                severity: "info",
                confidence: "medium",
                category: "authentication",
                stack: "nextjs",
                rule_family: "web-next.profile-auth-boundary",
                root_control: "AUTH-MIDDLEWARE-MATCHER-COVERAGE",
                evidence: "middleware file present in project tree",
                source: "Next.js middleware entrypoint detected in the reviewed tree.",
                control: "Repeat authentication and authorization at each sensitive server entrypoint.",
                sink: "Next.js middleware matcher and server entrypoints",
                impact_if_unremediated:
                  "Sensitive server entrypoints may lack authentication or authorization if only middleware is relied upon.",
                remediation:
                  "Review the middleware matcher and enforce authz inside each sensitive server entrypoint.",
                residual_risk: "New routes may omit shared helpers unless codified in review checklists.",
                verification_suggestion:
                  "Maintain a checklist of server entrypoints and tests that unauthenticated calls fail closed.",
                tags: ["middleware", "nextjs", "remediation"],
              }),
            );
          }
        }

        if (shouldEmitProfileAuthFinding("expo", profile.hasExpo, params.stack)) {
          detectorFamiliesRun.add("expo-rn.profile-auth-storage");
          findings.push(
            buildFinding({
              id: nextId(),
              title: "Review mobile token storage and auth redirects",
              description:
                "Expo / React Native signals detected. Confirm session tokens live in SecureStore (not AsyncStorage/MMKV), that AuthSession redirect URIs are exact, and that no credential ships via EXPO_PUBLIC_ env.",
              severity: "info",
              confidence: "low",
              category: "authentication",
              stack: "expo",
              rule_family: "expo-rn.profile-auth-storage",
              root_control: "AUTH-EXPO-STORAGE-REDIRECTS",
              evidence: "Expo / React Native signals present in project profile",
              source: "Expo / React Native project signals in package/configuration files.",
              control: "Use platform-secure token storage and exact redirect validation.",
              sink: "Mobile token storage and auth redirect paths",
              impact_if_unremediated:
                "Client-side token storage or loose auth redirects can expose sessions on the device or in logs.",
              remediation:
                "Audit storage helpers for token keys, pin AuthSession redirect URIs, and keep credentials out of EXPO_PUBLIC_ variables.",
              residual_risk:
                "OTA updates and native modules may reintroduce insecure storage paths after remediation.",
              verification_suggestion:
                "Grep AsyncStorage/MMKV for token keys and confirm SecureStore usage at login/refresh paths.",
              tags: ["expo", "react-native", "securestore", "remediation"],
            }),
          );
        }

        if (shouldEmitProfileAuthFinding("swift", profile.hasSwiftFiles, params.stack)) {
          detectorFamiliesRun.add("swift-ios.profile-auth-storage");
          findings.push(
            buildFinding({
              id: nextId(),
              title: "Review Keychain usage for session tokens",
              description:
                "Swift project detected. Confirm access tokens use Keychain (not UserDefaults) with appropriate accessibility and optional biometric access control.",
              severity: "info",
              confidence: "low",
              category: "authentication",
              stack: "swift",
              rule_family: "swift-ios.profile-auth-storage",
              root_control: "AUTH-SWIFT-KEYCHAIN-STORAGE",
              evidence: "Swift / Xcode signals present in project profile",
              source: "Swift/Xcode project signals in the reviewed tree.",
              control: "Use appropriately protected Keychain storage for session material.",
              sink: "Keychain/UserDefaults session-token paths",
              impact_if_unremediated:
                "Session tokens stored insecurely increase risk of local credential exposure.",
              remediation: "Audit Keychain helpers and entitlement keychain-access-groups; migrate secrets from UserDefaults.",
              residual_risk: "App extensions and app groups may still share secrets too broadly.",
              verification_suggestion:
                "Search for UserDefaults token storage and confirm Keychain APIs at login/logout paths.",
              tags: ["swift", "keychain", "remediation"],
            }),
          );
        }

        const detectorFamiliesAvailable = new Set(
          AUTH_PATTERNS.filter((pattern) => authPatternAppliesToStack(pattern.stack, params.stack)).map(
            (pattern) => authDetectorFamily(pattern.stack),
          ),
        );
        if (shouldEmitProfileAuthFinding("nextjs", nextProfileSignal, params.stack) && hasMiddleware) {
          detectorFamiliesAvailable.add("web-next.profile-auth-boundary");
        }
        if (shouldEmitProfileAuthFinding("expo", profile.hasExpo, params.stack)) {
          detectorFamiliesAvailable.add("expo-rn.profile-auth-storage");
        }
        if (shouldEmitProfileAuthFinding("swift", profile.hasSwiftFiles, params.stack)) {
          detectorFamiliesAvailable.add("swift-ios.profile-auth-storage");
        }

        const applied_pack_ids = authPackIdsForProfile(profile, params.stack);
        const finalizedCoverage = finalizeCoverage(coverage, filesReviewed, findings);
        const safeFindings = redactFindings(findings);

        const data = {
          ok: true as const,
          project_root: root,
          summary: `Authentication review: ${safeFindings.length} potential weakness(es) across ${filesReviewed.length} file(s)${finalizedCoverage.scan_status !== "complete" ? " (coverage is partial or truncated)" : ""}. Classify, confirm, and remediate — do not generate exploits.`,
          findings: safeFindings,
          files_reviewed: redactedSecretPaths(filesReviewed),
          truncated: finalizedCoverage.truncation.truncated,
          coverage: redactCoverageReport(finalizedCoverage),
          applied_pack_ids,
          knowledge_pack_traceability: {
            consulted_pack_ids: applied_pack_ids,
            detector_families_run: [...detectorFamiliesRun].sort(),
            detector_families_not_run: [...detectorFamiliesAvailable]
              .filter((family) => !detectorFamiliesRun.has(family))
              .sort(),
            consulted_via: "bundled detector mappings and routed pack metadata; no remote pack lookup",
          },
          notes: [
            "Defensive review only: identify → classify → remediate.",
            "Heuristic candidates need manual confirmation of data flow and authorization logic.",
            "Prioritize critical/high severity with high confidence for remediation first.",
            "applied_pack_ids follow the routed packs for the detected stacks (authn/authz content only); full checklists load via secure_mcp_get_knowledge_pack.",
          ],
        };

        const md = [
          `# Authentication review (remediation focused)`,
          "",
          data.summary,
          "",
          ...safeFindings.map(
            (f) =>
              `## [${escapeMarkdown(`${f.severity}/${f.confidence}`)}] ${escapeMarkdown(f.id)}: ${escapeMarkdown(f.title)}\n` +
              `${escapeMarkdown(f.description)}\n` +
              (f.file
                ? `- Evidence location: ${escapeMarkdown(`${f.file}${f.line ? `:${f.line}` : ""}`)}\n`
                : "") +
              `- Impact if unremediated: ${escapeMarkdown(f.impact_if_unremediated)}\n` +
              `- Remediation: ${escapeMarkdown(f.remediation)}\n`,
          ),
        ].join("\n");

        return toolSuccess(data, {
          responseFormat: params.response_format,
          markdown: md,
        });
      } catch (error) {
        return toolError(error);
      }
    },
  );
}
