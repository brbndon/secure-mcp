/**
 * Tool: secure_mcp_review_secrets
 * Defensive identification of secret exposure for rotation and remediation.
 *
 * applied_pack_ids derives from detector families that actually evaluated
 * successfully opened content. Routed packs stay in
 * knowledge_pack_traceability.consulted_pack_ids.
 */

import type { McpServer } from "@modelcontextprotocol/server";
import type { z } from "zod";
import { loadConfig, type ServerConfig } from "../config.js";
import { toolError, toolSuccess } from "../lib/envelope.js";
import { detectWithBudget, findLineNumber, snippetAround } from "../lib/filesystem.js";
import { runProjectScan } from "../lib/project-scan.js";
import {
  redactCoverageReport,
  redactFinding,
  redactFindings,
  redactedSecretPath,
  redactedSecretPaths,
} from "../lib/redact.js";
import { AWS_ACCESS_KEY_ID_SHAPE } from "../lib/secret-tokens.js";
import { renderMarkdownDocument } from "../lib/markdown.js";
import { SEVERITY_ORDER, type Finding, type StackFocus } from "../lib/types.js";
import {
  applyDispositionBaseline,
  buildFinding,
  createFindingIdFactory,
  ProjectRootInput,
} from "../knowledge/findings-schema.js";
import { SECRET_PATTERNS } from "../knowledge/common.js";
import { NEXTJS_PATTERNS } from "../knowledge/nextjs.js";
import { isSwiftSensitivePath, SWIFT_SECRETS_PATTERNS } from "../knowledge/swift.js";
import {
  recommendCategoryPackIds,
  type PackId,
} from "../knowledge/packs/registry.js";

const InputSchema = ProjectRootInput;
type Input = z.infer<typeof InputSchema>;

/**
 * Whether Next.js client-bundle secret detectors may run for this stack focus.
 * Explicit expo/common/swift must not claim or execute Next-only detectors.
 */
export function shouldRunNextjsSecretDetectors(
  stack: StackFocus | "auto" | undefined,
  detectedStacks: readonly StackFocus[] = [],
): boolean {
  return (
    stack === "nextjs" ||
    ((stack === undefined || stack === "auto") && detectedStacks.includes("nextjs"))
  );
}

export function shouldRunSwiftSecretDetectors(
  stack: StackFocus | "auto" | undefined,
  detectedStacks: readonly StackFocus[] = [],
): boolean {
  return (
    stack === "swift" ||
    ((stack === undefined || stack === "auto") && detectedStacks.includes("swift"))
  );
}

/** Pack ids claimed by secrets review for the active stack focus. */
export function secretsPackIdsForStack(
  stack: StackFocus | "auto" | undefined,
  detectedStacks: readonly StackFocus[] = [],
): PackId[] {
  const detectorStacks: StackFocus[] = ["typescript"];
  if (shouldRunNextjsSecretDetectors(stack, detectedStacks)) detectorStacks.push("nextjs");
  if (shouldRunSwiftSecretDetectors(stack, detectedStacks)) detectorStacks.push("swift");
  return recommendCategoryPackIds(detectorStacks, ["secrets"]);
}

export const SECRETS_DETECTOR_FAMILIES = [
  "secrets.secret-patterns",
  "secrets.environment-file",
  "web-next.client-bundle-secrets",
  "swift-ios.secret-config",
  "swift-ios.secret-handling",
] as const;
export type SecretsDetectorFamily = (typeof SECRETS_DETECTOR_FAMILIES)[number];

const PACK_ID_BY_SECRETS_FAMILY: Record<SecretsDetectorFamily, PackId> = {
  "secrets.secret-patterns": "secrets",
  "secrets.environment-file": "secrets",
  "web-next.client-bundle-secrets": "web-next",
  "swift-ios.secret-config": "swift-ios",
  "swift-ios.secret-handling": "swift-ios",
};

/** Packs behind families that actually evaluated opened content. */
export function appliedSecretsPackIds(evaluatedFamilies: readonly string[]): PackId[] {
  const set = new Set(evaluatedFamilies);
  const ids: PackId[] = [];
  for (const family of SECRETS_DETECTOR_FAMILIES) {
    if (!set.has(family)) continue;
    const packId = PACK_ID_BY_SECRETS_FAMILY[family];
    if (packId && !ids.includes(packId)) ids.push(packId);
  }
  return ids;
}

const FALSE_POSITIVE_HINTS =
  /example|sample|placeholder|your[_-]?key|xxx+|todo|changeme|dummy|fake|test[_-]?key|process\.env/i;

export interface SecretPatternMatchClassification {
  suppressed: boolean;
  confidence: "high" | "low";
}

/** Apply contextual false-positive hints without suppressing high-impact key material. */
export function classifySecretPatternMatch(
  patternName: string,
  match: string,
  nearbyContext: string,
): SecretPatternMatchClassification {
  const hasFalsePositiveHint =
    FALSE_POSITIVE_HINTS.test(match) || FALSE_POSITIVE_HINTS.test(nearbyContext);
  const mustRemainVisible =
    patternName === AWS_ACCESS_KEY_ID_SHAPE.name || patternName === "Private key block";
  return {
    suppressed: hasFalsePositiveHint && !mustRemainVisible,
    confidence: hasFalsePositiveHint ? "low" : "high",
  };
}

const TOOL_DESCRIPTION = `Defensive secure-code-review tool: identify potential hardcoded secrets and unsafe secret handling so the development team can rotate credentials and harden configuration.

Args: project_root, stack?, max_files?, focus_paths?, response_format.

Returns: findings[] (category secrets, remediation fields; evidence redacted), env_related_files, truncated, applied_pack_ids (packs whose detectors evaluated content), knowledge_pack_traceability.consulted_pack_ids (routed secrets packs).

Guidance: Call secure_mcp_get_audit_guidance for the full workflow and guardrails.`;

export function registerReviewSecrets(
  server: McpServer,
  config: ServerConfig = loadConfig(),
): void {
  server.registerTool(
    "secure_mcp_review_secrets",
    {
      title: "Review secrets for remediation",
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
        const nextId = createFindingIdFactory("SEC");
        const findings: Finding[] = [];
        const detectorFamiliesRun = new Set<string>();

        const scan = await runProjectScan({
          projectRoot: params.project_root,
          config,
          maxFiles: params.max_files,
          focusPaths: params.focus_paths,
          extensions: new Set([
            ".ts",
            ".tsx",
            ".js",
            ".jsx",
            ".mjs",
            ".cjs",
            ".swift",
            ".json",
            ".yml",
            ".yaml",
            ".env",
            ".plist",
            ".entitlements",
            ".toml",
            ".properties",
            ".txt",
            ".pem",
            ".key",
          ]),
          selectFile: (file) =>
            file.relativePath.includes(".min.")
              ? { skip: true, reason: "minified_file" }
              : { skip: false },
          onFile: (file, content, ctx) => {
            const detectedStacks = ctx.profile?.likelyStacks ?? [];

          if (
            /(^|\/)\.env($|\.(local|development|production|staging))/i.test(file.relativePath) &&
            !file.relativePath.endsWith(".example")
          ) {
            detectorFamiliesRun.add("secrets.environment-file");
            findings.push(
              buildFinding({
                id: nextId(),
                title: "Environment file present in tree",
                description:
                  "A .env file was found. Confirm it is gitignored and does not contain production secrets in the working tree under review.",
                severity: "medium",
                confidence: "medium",
                category: "secrets",
                rule_family: "secrets.environment-file",
                root_control: "SECRET-ENV-FILE",
                file: file.relativePath,
                evidence: redactedSecretPath(file.relativePath),
                source: "Environment/configuration file in the reviewed tree.",
                control: "Keep secrets outside source control and use managed runtime secret storage.",
                sink: redactedSecretPath(file.relativePath),
                impact_if_unremediated:
                  "Local env files that are committed or shared can leak production credentials.",
                remediation:
                  "Ensure .env* (except .env.example) is gitignored; use secret managers for production; scrub history if secrets were committed.",
                residual_risk: "Developer machines may still hold copies of rotated secrets.",
                verification_suggestion:
                  "Check .gitignore and git history for env files; confirm CI uses secret stores.",
                cwe: "CWE-200",
                tags: ["env-file", "remediation"],
              }),
            );
          }

          if (
            shouldRunSwiftSecretDetectors(params.stack, detectedStacks) &&
            /GoogleService-Info\.plist$/i.test(file.relativePath)
          ) {
            detectorFamiliesRun.add("swift-ios.secret-config");
            findings.push(
              buildFinding({
                id: nextId(),
                title: "Firebase GoogleService-Info.plist present",
                description:
                  "GoogleService-Info.plist often embeds API keys and project identifiers. Confirm keys are appropriately restricted in the Firebase/Google Cloud consoles and that no secondary secrets were added to the plist.",
                severity: "info",
                confidence: "medium",
                category: "secrets",
                stack: "swift",
                rule_family: "swift-ios.secret-config",
                root_control: "SWIFT-FIREBASE-CONFIG",
                file: file.relativePath,
                evidence: redactedSecretPath(file.relativePath),
                source: "Client-embedded Firebase configuration path.",
                control: "Restrict client-safe keys and keep server secrets out of app bundles.",
                sink: redactedSecretPath(file.relativePath),
                impact_if_unremediated:
                  "Unrestricted client keys can be abused if API restrictions and billing controls are weak.",
                remediation:
                  "Restrict API keys by app/bundle id and API surface; keep only client-safe values in the plist; never add server secrets here.",
                residual_risk:
                  "Client-embedded Firebase config remains extractable from the app bundle by design.",
                verification_suggestion:
                  "Review Google Cloud API key restrictions and Firebase App Check for this app id.",
                cwe: "CWE-200",
                tags: ["swift", "firebase", "plist", "remediation"],
              }),
            );
          }

          for (const pattern of SECRET_PATTERNS) {
            detectorFamiliesRun.add("secrets.secret-patterns");
            let hits = 0;
            for (const hit of detectWithBudget(pattern.regex, content)) {
              const full = hit.match;
              const classification = classifySecretPatternMatch(
                pattern.name,
                full,
                snippetAround(content, hit.index, 40),
              );
              if (classification.suppressed) continue;
              if (hits >= 10) break;
              hits++;
              findings.push(
                redactFinding(
                  buildFinding({
                    id: nextId(),
                    title: `Possible secret: ${pattern.name}`,
                    description: `Matched heuristic for ${pattern.name}. Verify whether this is a real credential and whether it is still active; if so, remediate and rotate.`,
                    severity: pattern.severity,
                    confidence: classification.confidence,
                    category: "secrets",
                    rule_family: "secrets.secret-patterns",
                    root_control: `SECRET-PATTERN-${pattern.name.replace(/[^A-Z0-9]+/gi, "-").toUpperCase()}`,
                    file: file.relativePath,
                    line: findLineNumber(content, hit.index),
                    evidence: full,
                    source: "Repository or configuration content matched a secret-like pattern.",
                    control: pattern.remediation,
                    sink: file.relativePath,
                    impact_if_unremediated: pattern.impact_if_unremediated,
                    remediation: pattern.remediation,
                    residual_risk:
                      "Secrets may remain in git history or secondary systems until rotated and purged.",
                    verification_suggestion:
                      "Confirm rotation in the provider console; re-scan the repository and history; ensure CI secrets are updated.",
                    cwe: "CWE-798",
                    tags: ["secrets", pattern.name, "remediation"],
                  }),
                ),
              );
            }
          }

          if (shouldRunNextjsSecretDetectors(params.stack, detectedStacks)) {
            detectorFamiliesRun.add("web-next.client-bundle-secrets");
            for (const p of NEXTJS_PATTERNS.filter(
              (x) => x.id.includes("PUBLIC") || x.id.includes("USE-CLIENT"),
            )) {
              let hits = 0;
              for (const hit of detectWithBudget(p.regex, content)) {
                if (hits >= 8) break;
                hits++;
                findings.push(
                  redactFinding(
                    buildFinding({
                      id: nextId(),
                      title: p.title,
                      description:
                        "Next.js client-bundle secret exposure pattern matched. Secrets must not be public env or client-imported.",
                      severity: p.severity,
                      confidence: "medium",
                      category: "secrets",
                      stack: "nextjs",
                      rule_family: "web-next.client-bundle-secrets",
                      root_control: p.id,
                      file: file.relativePath,
                      line: findLineNumber(content, hit.index),
                      evidence: snippetAround(content, hit.index),
                      source: "Next.js client-bundle or public configuration path.",
                      control: p.recommendation,
                      sink: file.relativePath,
                      impact_if_unremediated: p.impact_if_unremediated,
                      remediation: p.recommendation,
                      residual_risk: "Old client bundles may still contain rotated secrets until redeployed.",
                      verification_suggestion:
                        "Inspect production client bundles and env naming conventions after the fix.",
                      cwe: p.cwe,
                      tags: ["nextjs", "secrets", "remediation"],
                    }),
                  ),
                );
              }
            }
          }

          if (
            shouldRunSwiftSecretDetectors(params.stack, detectedStacks) &&
            (file.ext === ".swift" || file.ext === ".plist" || file.ext === ".entitlements")
          ) {
            detectorFamiliesRun.add("swift-ios.secret-handling");
            for (const p of SWIFT_SECRETS_PATTERNS) {
              let hits = 0;
              for (const hit of detectWithBudget(p.regex, content)) {
                if (p.filter && !p.filter(hit.match, content)) continue;
                const full = hit.match;
                const nearFp =
                  FALSE_POSITIVE_HINTS.test(full) ||
                  FALSE_POSITIVE_HINTS.test(snippetAround(content, hit.index, 40));
                if (nearFp && p.id === "SWIFT-HARDCODED-PASSWORD") continue;
                if (hits >= 8) break;
                hits++;
                findings.push(
                  redactFinding(
                    buildFinding({
                      id: nextId(),
                      title: p.title,
                      description: `Swift secret-handling heuristic ${p.id} matched — review storage and remove hardcoded or weakly protected secrets.`,
                      severity: p.severity,
                      confidence: nearFp ? "low" : p.confidence,
                      category: p.category,
                      stack: "swift",
                      rule_family: "swift-ios.secret-handling",
                      root_control: p.id,
                      file: file.relativePath,
                      line: findLineNumber(content, hit.index),
                      evidence: snippetAround(content, hit.index),
                      source: "Swift source or Apple configuration matched a secret-handling heuristic.",
                      control: p.recommendation,
                      sink: file.relativePath,
                      impact_if_unremediated: p.impact_if_unremediated,
                      remediation: p.recommendation,
                      residual_risk: "Old app installs may retain secrets until users upgrade.",
                      verification_suggestion:
                        "Audit Keychain migration paths and confirm no secrets remain in UserDefaults, pasteboard, or source.",
                      cwe: p.cwe,
                      tags: ["swift", p.category, p.id, "remediation"],
                    }),
                  ),
                );
              }
            }
          }
          },
        });
        const { root, profile, files, filesReviewed: filesScanned, finishCoverage } = scan;
        const detectedStacks = profile?.likelyStacks ?? [];
        const envish = files.filter(
          (f) =>
            f.relativePath.includes(".env") ||
            f.ext === ".pem" ||
            f.ext === ".key" ||
            f.relativePath.endsWith("credentials.json") ||
            f.relativePath.endsWith("service-account.json") ||
            isSwiftSensitivePath(f.relativePath),
        );

        findings.sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]);
        const baselined = applyDispositionBaseline(findings, params.disposition_baseline);
        const finalizedCoverage = finishCoverage(baselined);
        const safeFindings = redactFindings(baselined);

        const consulted_pack_ids = secretsPackIdsForStack(params.stack, detectedStacks);
        const applied_pack_ids = appliedSecretsPackIds([...detectorFamiliesRun]);
        const detectorFamiliesAvailable = [
          "secrets.secret-patterns",
          "secrets.environment-file",
          ...(shouldRunNextjsSecretDetectors(params.stack, detectedStacks)
            ? ["web-next.client-bundle-secrets"]
            : []),
          ...(shouldRunSwiftSecretDetectors(params.stack, detectedStacks)
            ? ["swift-ios.secret-handling", "swift-ios.secret-config"]
            : []),
        ];
        const data = {
          ok: true as const,
          project_root: root,
          summary: `Secrets review: ${safeFindings.length} potential issue(s) across ${filesScanned.length} file(s)${finalizedCoverage.scan_status !== "complete" ? " (coverage is partial or truncated)" : ""}. Rotate confirmed live secrets; remediate storage — do not misuse credentials.`,
          findings: safeFindings,
          files_reviewed: redactedSecretPaths(filesScanned),
          env_related_files: envish.map((f) => redactedSecretPath(f.relativePath)),
          truncated: finalizedCoverage.truncation.truncated,
          coverage: redactCoverageReport(finalizedCoverage),
          applied_pack_ids,
          knowledge_pack_traceability: {
            consulted_pack_ids,
            detector_families_run: [...detectorFamiliesRun].sort(),
            detector_families_not_run: detectorFamiliesAvailable
              .filter((family) => !detectorFamiliesRun.has(family))
              .sort(),
            consulted_via: "bundled detector mappings; no remote pack lookup",
          },
          notes: [
            "Defensive secret hygiene only: identify → classify → rotate/remediate.",
            "Evidence is partially redacted; open the file locally to confirm.",
            "Never use discovered credentials against systems — only help owners fix and rotate.",
            "applied_pack_ids are packs whose detectors evaluated opened content; knowledge_pack_traceability.consulted_pack_ids are the routed secrets packs for this stack.",
          ],
        };

        const md = renderMarkdownDocument({
          title: "Secrets review (remediation focused)",
          summary: data.summary,
          findings: safeFindings.slice(0, 40),
          findingOptions: { detail: "compact", headingLevel: 3 },
        });

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
