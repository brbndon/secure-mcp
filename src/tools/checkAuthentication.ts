/**
 * Tool: secure_mcp_check_authentication
 * Defensive authentication / authorization review for remediation.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { z } from "zod";
import {
  findLineNumber,
  normalizeProjectRoot,
  profileProject,
  readProjectFile,
  snippetAround,
  toolError,
  toolSuccess,
  walkProject,
} from "../lib/filesystem.js";
import { redactedEvidence } from "../lib/redact.js";
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
    // Match credential suffixes after EXPO_PUBLIC_. Bare KEY is omitted so intentional
    // public client keys (API_KEY, MAPS_API_KEY, PUBLISHABLE_KEY) do not fire; also
    // exclude publishable/anon-shaped names that end in TOKEN/SECRET/etc.
    regex:
      /EXPO_PUBLIC_(?!.*(?:PUBLISHABLE|ANON))[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|CREDENTIAL|PRIVATE_KEY)\b/g,
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

PURPOSE (defensive only)
- Locate incomplete session validation, hardcoded credentials, weak TLS verification, middleware-only checks, and insecure mobile token storage.
- Classify each potential weakness (severity, confidence, category, CWE when known).
- Recommend concrete remediation steps and verification ideas.
- Never produce exploit instructions, credential-stuffing playbooks, or bypass recipes.

MANDATORY AGENT WORKFLOW (multi-phase; keep intermediate notes)
1. Inventory + architecture tools first to locate auth-related paths.
2. Run this tool for candidate weaknesses with evidence.
3. Open cited files and verify session checks, ownership checks, and secret handling (read-only).
4. For each confirmed item, complete: evidence → classification → impact_if_unremediated → remediation → residual_risk → verification_suggestion.
5. Cross-check with secure_mcp_review_secrets and secure_mcp_build_remediation_threat_model.
6. Continue until major authn/authz classes for the stack are covered with evidence; then merge via secure_mcp_produce_findings.

WHAT THIS TOOL CHECKS (heuristics)
- Hardcoded JWT/signing secrets and Authorization headers
- Disabled TLS certificate verification
- Next.js middleware-centric auth patterns needing defense in depth
- Swift UserDefaults / app-group token storage, overly broad Keychain accessibility, URLSession server-trust handlers that appear to disable validation
- Expo / React Native token storage (AsyncStorage / MMKV vs SecureStore) and credential-shaped EXPO_PUBLIC_ env
- Presence of auth helpers that still need object-level authorization review

Args:
  - project_root, stack, max_files, response_format

Returns:
  findings[] in the shared Finding schema (remediation required fields).

GUARDRAILS
- Read-only; does not execute project code.
- Frame all follow-up as helping the codebase owners fix their own application.`;

export function registerCheckAuthentication(server: McpServer): void {
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
        const profile = await profileProject(root);
        const nextId = createFindingIdFactory("AUTH");
        const findings: Finding[] = [];
        const filesReviewed: string[] = [];

        const { files } = await walkProject(root, {
          maxFiles: params.max_files ?? 400,
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

        for (const file of toScan) {
          if (file.size > 256 * 1024) continue;
          let content: string;
          try {
            content = (await readProjectFile(root, file.relativePath)).content;
          } catch {
            continue;
          }
          filesReviewed.push(file.relativePath);

          for (const pattern of AUTH_PATTERNS) {
            if (!authPatternAppliesToStack(pattern.stack, params.stack)) continue;

            pattern.regex.lastIndex = 0;
            let match: RegExpExecArray | null;
            let hits = 0;
            while ((match = pattern.regex.exec(content)) !== null && hits < 5) {
              if (pattern.filter && !pattern.filter(match[0], content)) continue;
              hits++;
              const rawEvidence = snippetAround(content, match.index);
              findings.push(
                buildFinding({
                  id: nextId(),
                  title: pattern.title,
                  description: pattern.description,
                  severity: pattern.severity,
                  confidence: pattern.confidence,
                  category: "authentication",
                  stack: pattern.stack ?? "common",
                  file: file.relativePath,
                  line: findLineNumber(content, match.index),
                  evidence:
                    pattern.stack === "swift"
                      ? redactedEvidence(rawEvidence)
                      : rawEvidence,
                  impact_if_unremediated: pattern.impact_if_unremediated,
                  remediation: pattern.remediation,
                  residual_risk:
                    "Related auth paths may need the same control; re-review after fixes.",
                  verification_suggestion:
                    "Add automated tests for unauthenticated/unauthorized access; re-run this tool after remediation.",
                  cwe: pattern.cwe,
                  tags: ["authentication", pattern.id, "remediation"],
                }),
              );
            }
          }
        }

        const nextProfileSignal =
          profile.hasNextConfig || profile.likelyStacks.includes("nextjs");
        if (shouldEmitProfileAuthFinding("nextjs", nextProfileSignal, params.stack)) {
          const hasMiddleware = files.some((f) => /middleware\.(ts|js)$/.test(f.relativePath));
          if (hasMiddleware) {
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
                evidence: "middleware file present in project tree",
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
              evidence: "Expo / React Native signals present in project profile",
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
              evidence: "Swift / Xcode signals present in project profile",
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

        const applied_pack_ids = authPackIdsForProfile(profile, params.stack);

        const data = {
          ok: true as const,
          project_root: root,
          summary: `Authentication review: ${findings.length} potential weakness(es) across ${filesReviewed.length} file(s). Classify, confirm, and remediate — do not generate exploits.`,
          findings,
          files_reviewed: filesReviewed,
          applied_pack_ids,
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
          ...findings.map(
            (f) =>
              `## [${f.severity}/${f.confidence}] ${f.id}: ${f.title}\n` +
              `${f.description}\n` +
              (f.file ? `- Evidence location: ${f.file}${f.line ? `:${f.line}` : ""}\n` : "") +
              `- Impact if unremediated: ${f.impact_if_unremediated}\n` +
              `- Remediation: ${f.remediation}\n`,
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
