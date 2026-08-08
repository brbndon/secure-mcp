/**
 * Tool: secure_mcp_analyze_injection_risks
 * Defensive identification of injection-class weaknesses for remediation.
 *
 * Routing rules:
 * - Auto mode profiles the project and configures only the detector families
 *   for the detected stacks (core is always available; Next.js and Swift
 *   families only when those stacks are present).
 * - Forced stacks configure only their own language families, so a forced
 *   Swift scan never runs TypeScript-family detectors on a mixed inventory.
 * - Every detector family declares explicit file-extension applicability;
 *   a file is scanned only by patterns that apply to its extension.
 * - applied_pack_ids derives from detector families that actually evaluated
 *   successfully opened content; configured/consulted packs stay separate in
 *   knowledge_pack_traceability.
 */

import type { McpServer } from "@modelcontextprotocol/server";
import type { z } from "zod";
import { loadConfig, type ServerConfig } from "../config.js";
import { toolError, toolSuccess } from "../lib/envelope.js";
import {
  detectWithBudget,
  findLineNumber,
  normalizeAuthorizedProjectRoot,
  profileProject,
  readProjectFile,
  snippetAround,
  walkProject,
} from "../lib/filesystem.js";
import {
  redactCoverageReport,
  redactFinding,
  redactFindings,
  redactedSecretPaths,
} from "../lib/redact.js";
import { renderMarkdownDocument } from "../lib/markdown.js";
import { SEVERITY_ORDER, type Finding, type StackFocus } from "../lib/types.js";
import {
  buildFinding,
  createFindingIdFactory,
  ProjectRootInput,
} from "../knowledge/findings-schema.js";
import { INJECTION_PATTERNS } from "../knowledge/common.js";
import { NEXTJS_PATTERNS } from "../knowledge/nextjs.js";
import {
  SWIFT_CONFIG_PATTERNS,
  SWIFT_CRYPTO_PATTERNS,
  SWIFT_INJECTION_PATTERNS,
} from "../knowledge/swift.js";
import { uniquePackIds, type PackId } from "../knowledge/packs/registry.js";

const InputSchema = ProjectRootInput;
type Input = z.infer<typeof InputSchema>;

const TOOL_DESCRIPTION = `Defensive secure-code-review tool: identify potential injection-class weaknesses so the development team can harden the codebase.

Args: project_root, stack?, max_files?, focus_paths?, response_format.

Returns: findings[] using the shared Finding schema (evidence → classification → impact_if_unremediated → remediation → residual_risk → verification_suggestion), files_scanned_count, truncated, applied_pack_ids.

Guidance: Call secure_mcp_get_audit_guidance for the full workflow and guardrails.`;

type InjectionStackFocus = StackFocus | "auto";

/** Detector families the tool can configure, keyed by their stable id. */
export const INJECTION_DETECTOR_FAMILIES = [
  "core.injection",
  "web-next.injection",
  "swift-ios.injection",
  "swift-ios.configuration",
  "swift-ios.cryptography",
] as const;
export type InjectionDetectorFamily = (typeof INJECTION_DETECTOR_FAMILIES)[number];

const PACK_ID_BY_DETECTOR_FAMILY: Record<InjectionDetectorFamily, PackId> = {
  "core.injection": "core",
  "web-next.injection": "web-next",
  "swift-ios.injection": "swift-ios",
  "swift-ios.configuration": "swift-ios",
  "swift-ios.cryptography": "swift-ios",
};

/**
 * Which pattern stacks a forced focus may run. Swift is exclusive: its
 * detectors never run over TypeScript/JavaScript inventories, and the core
 * family (JS-flavored shapes) is not configured for Swift-only scans.
 */
const PATTERN_STACKS_BY_FOCUS: Record<StackFocus, StackFocus[]> = {
  common: ["common"],
  typescript: ["common", "typescript"],
  nextjs: ["common", "typescript", "nextjs"],
  expo: ["common", "typescript", "expo"],
  swift: ["swift"],
};

/**
 * Explicit extension applicability for detector families instead of "every
 * non-Swift file". TS/JS-shaped patterns never scan plist/xml/markdown trees
 * by default; the common core pattern (INJ-SQL-CONCAT) additionally applies to
 * Markdown so security documentation is still reviewed.
 */
export const JS_CODE_EXTENSIONS = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"];
const COMMON_CORE_EXTENSIONS = [...JS_CODE_EXTENSIONS, ".md"];

/** Exported for tests: does a pattern's family apply to this file extension? */
export function injectionPatternAppliesToFile(
  pattern: { extensions?: string[] },
  fileExt: string,
): boolean {
  return (pattern.extensions ?? JS_CODE_EXTENSIONS).includes(fileExt);
}

/** Exported for tests: Next.js detectors run only for nextjs focus or detected nextjs. */
export function shouldRunNextjsInjectionDetectors(
  stack: InjectionStackFocus,
  detectedStacks?: readonly StackFocus[],
): boolean {
  if (stack === "auto") return detectedStacks?.includes("nextjs") === true;
  return stack === "nextjs";
}

/** Exported for tests: Swift detectors run only for swift focus or detected swift. */
export function shouldRunSwiftInjectionDetectors(
  stack: InjectionStackFocus,
  detectedStacks?: readonly StackFocus[],
): boolean {
  if (stack === "auto") return detectedStacks?.includes("swift") === true;
  return stack === "swift";
}

function shouldRunCoreInjectionDetectors(stack: InjectionStackFocus): boolean {
  // The common core family is the stack-agnostic baseline: available under
  // auto and every non-Swift forced focus, never under a forced Swift scan.
  if (stack === "auto") return true;
  return stack !== "swift";
}

/** Exported for tests: detector families configured for a stack focus. */
export function injectionDetectorFamiliesForStack(
  stack: InjectionStackFocus,
  detectedStacks?: readonly StackFocus[],
): InjectionDetectorFamily[] {
  const families: InjectionDetectorFamily[] = [];
  if (shouldRunCoreInjectionDetectors(stack)) families.push("core.injection");
  if (shouldRunNextjsInjectionDetectors(stack, detectedStacks)) families.push("web-next.injection");
  if (shouldRunSwiftInjectionDetectors(stack, detectedStacks)) {
    families.push(
      "swift-ios.injection",
      "swift-ios.configuration",
      "swift-ios.cryptography",
    );
  }
  return families;
}

/** Exported for tests: packs behind the configured families (consulted). */
export function injectionPackIdsForStack(
  stack: InjectionStackFocus,
  detectedStacks?: readonly StackFocus[],
): PackId[] {
  return uniquePackIds(
    injectionDetectorFamiliesForStack(stack, detectedStacks).map(
      (family) => PACK_ID_BY_DETECTOR_FAMILY[family],
    ),
  );
}

/** Exported for tests: packs behind families that actually evaluated content. */
export function appliedInjectionPackIds(evaluatedFamilies: readonly string[]): PackId[] {
  const set = new Set(evaluatedFamilies);
  const ids: PackId[] = [];
  for (const family of INJECTION_DETECTOR_FAMILIES) {
    if (!set.has(family)) continue;
    const packId = PACK_ID_BY_DETECTOR_FAMILY[family];
    if (packId && !ids.includes(packId)) ids.push(packId);
  }
  return ids;
}

interface InjectionPattern {
  id: string;
  title: string;
  regex: RegExp;
  severity: Finding["severity"];
  cwe?: string;
  remediation: string;
  impact: string;
  stack: Finding["stack"];
  confidence?: Finding["confidence"];
  category?: string;
  extensions?: string[];
  filter?: (match: string, content: string) => boolean;
  packId: PackId;
  detectorFamily: InjectionDetectorFamily;
}

/** Decorate knowledge patterns with explicit applicability and routing ids. */
function coreInjectionPatterns(patternStacks: readonly StackFocus[]): InjectionPattern[] {
  return INJECTION_PATTERNS.filter((p) => patternStacks.includes(p.stack)).map((p) => ({
    id: p.id,
    title: p.title,
    regex: p.regex,
    severity: p.severity,
    cwe: p.cwe,
    remediation: p.recommendation,
    impact: p.impact_if_unremediated,
    stack: p.stack,
    confidence: "medium",
    category: "injection-risk",
    extensions: p.stack === "common" ? COMMON_CORE_EXTENSIONS : JS_CODE_EXTENSIONS,
    packId: "core",
    detectorFamily: "core.injection",
  }));
}

function webNextInjectionPatterns(): InjectionPattern[] {
  return NEXTJS_PATTERNS.filter(
    (p) => !p.id.includes("PUBLIC") && !p.id.includes("USE-CLIENT"),
  ).map((p) => ({
    id: p.id,
    title: p.title,
    regex: p.regex,
    severity: p.severity,
    cwe: p.cwe,
    remediation: p.recommendation,
    impact: p.impact_if_unremediated,
    stack: "nextjs",
    confidence: "medium",
    category: "injection-risk",
    extensions: JS_CODE_EXTENSIONS,
    packId: "web-next",
    detectorFamily: "web-next.injection",
  }));
}

function swiftInjectionPatterns(): InjectionPattern[] {
  return [
    ...SWIFT_INJECTION_PATTERNS,
    ...SWIFT_CONFIG_PATTERNS,
    ...SWIFT_CRYPTO_PATTERNS,
  ].map((p) => ({
    id: p.id,
    title: p.title,
    regex: p.regex,
    severity: p.severity,
    cwe: p.cwe,
    remediation: p.recommendation,
    impact: p.impact_if_unremediated,
    stack: "swift",
    confidence: p.confidence,
    category: p.category,
    extensions: p.extensions ?? [".swift"],
    filter: p.filter,
    packId: "swift-ios",
    detectorFamily:
      p.category === "configuration"
        ? "swift-ios.configuration"
        : p.category === "cryptography"
          ? "swift-ios.cryptography"
          : "swift-ios.injection",
  }));
}

function buildInjectionPatterns(
  stack: InjectionStackFocus,
  detectedStacks: readonly StackFocus[],
): InjectionPattern[] {
  const families = injectionDetectorFamiliesForStack(stack, detectedStacks);
  const patterns: InjectionPattern[] = [];
  if (families.includes("core.injection")) {
    // Under a forced focus, only the pattern stacks of that focus run (a
    // forced common scan never runs TypeScript-only core patterns). Auto
    // always keeps the full core family; extension applicability guards it.
    const coreStacks: StackFocus[] =
      stack === "auto" ? ["common", "typescript"] : PATTERN_STACKS_BY_FOCUS[stack];
    patterns.push(...coreInjectionPatterns(coreStacks));
  }
  if (families.includes("web-next.injection")) patterns.push(...webNextInjectionPatterns());
  if (
    families.includes("swift-ios.injection") ||
    families.includes("swift-ios.configuration") ||
    families.includes("swift-ios.cryptography")
  ) {
    patterns.push(...swiftInjectionPatterns());
  }
  return patterns;
}

export function registerAnalyzeInjectionRisks(
  server: McpServer,
  config: ServerConfig = loadConfig(),
): void {
  server.registerTool(
    "secure_mcp_analyze_injection_risks",
    {
      title: "Analyze injection risks for remediation",
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
        const root = await normalizeAuthorizedProjectRoot(params.project_root, config.allowedRoots);
        const nextId = createFindingIdFactory("INJ");
        const findings: Finding[] = [];
        const filesScanned: string[] = [];

        const stack = params.stack ?? "auto";
        // Auto mode routes by the stacks detected in the actual project, so a
        // Swift-only repo never configures Next.js families (and vice versa).
        const profile =
          stack === "auto"
            ? await profileProject(root, {
                focusPrefixes: params.focus_paths,
                maxFiles: params.max_files ?? config.defaultMaxFiles,
                maxDepth: config.maxDepth,
                maxFileBytes: config.maxFileBytes,
                maxTotalBytes: config.maxTotalBytes,
                allowedRoots: config.allowedRoots,
              })
            : undefined;
        const detectedStacks = (profile?.likelyStacks ?? []) as StackFocus[];
        const patterns = buildInjectionPatterns(stack, detectedStacks);
        const consultedPackIds = uniquePackIds(patterns.map((pattern) => pattern.packId));
        const detectorFamiliesAvailable = new Set(
          injectionDetectorFamiliesForStack(stack, detectedStacks),
        );
        const detectorFamiliesRun = new Set<InjectionDetectorFamily>();

        const extensions = new Set([
          ".ts",
          ".tsx",
          ".js",
          ".jsx",
          ".mjs",
          ".cjs",
          ".swift",
          ".plist",
          ".xml",
          ".entitlements",
          ".html",
          ".md",
        ]);

        const { files, coverageSession } = await walkProject(root, {
          maxFiles: params.max_files ?? config.defaultMaxFiles,
          maxDepth: config.maxDepth,
          maxFileBytes: config.maxFileBytes,
          maxTotalBytes: config.maxTotalBytes,
          allowedRoots: config.allowedRoots,
          extensions,
          focusPrefixes: params.focus_paths,
        });

        for (const file of files) {
          if (file.size > config.maxFileBytes) {
            coverageSession.recordExclusion({
              path: file.relativePath,
              kind: "file",
              reason: "max_file_bytes",
            });
            continue;
          }
          if (
            file.relativePath.endsWith(".md") &&
            !file.relativePath.toLowerCase().includes("security")
          ) {
            coverageSession.recordExclusion({
              path: file.relativePath,
              kind: "file",
              reason: "non_security_documentation",
            });
            continue;
          }

          // Explicit per-family extension applicability: a file is scanned
          // only by the patterns whose families declare its extension.
          const applicablePatterns = patterns.filter((pattern) =>
            injectionPatternAppliesToFile(pattern, file.ext),
          );
          if (applicablePatterns.length === 0) {
            coverageSession.recordExclusion({
              path: file.relativePath,
              kind: "file",
              reason: "no_applicable_injection_detectors",
            });
            continue;
          }

          let content: string;
          try {
            content = (
              await readProjectFile(
                root,
                file.relativePath,
                config.maxFileBytes,
                config.allowedRoots,
              )
            ).content;
          } catch {
            coverageSession.recordExclusion({
              path: file.relativePath,
              kind: "file",
              reason: "file_read_error",
            });
            continue;
          }
          filesScanned.push(file.relativePath);
          coverageSession.recordReviewedFile(file.relativePath);

          for (const pattern of applicablePatterns) {
            detectorFamiliesRun.add(pattern.detectorFamily);

            let hits = 0;
            for (const hit of detectWithBudget(pattern.regex, content)) {
              if (pattern.filter && !pattern.filter(hit.match, content)) {
                continue;
              }
              if (hits >= 8) break;
              hits++;
              findings.push(
                redactFinding(
                  buildFinding({
                    id: nextId(),
                    title: pattern.title,
                    description: `Potential weakness pattern ${pattern.id} observed in ${file.relativePath}. Review whether untrusted input can influence this location and apply the remediation if so.`,
                    severity: pattern.severity,
                    confidence: pattern.confidence ?? "medium",
                    category: pattern.category ?? "injection-risk",
                    stack: pattern.stack,
                    rule_family: pattern.detectorFamily,
                    root_control: pattern.id,
                    file: file.relativePath,
                    line: findLineNumber(content, hit.index),
                    evidence: snippetAround(content, hit.index),
                    source: "Request, configuration, or other untrusted input is not proven by this heuristic.",
                    control: pattern.remediation,
                    sink: `${file.relativePath}:${findLineNumber(content, hit.index)}`,
                    proof_gap: [
                      "Trace the candidate input to this sink and confirm the runtime path is reachable.",
                      "Confirm validation, encoding, parameterization, or allowlisting at the boundary.",
                    ],
                    validation: [
                      "Review the cited file and add a regression test that rejects unsafe input at the boundary.",
                    ],
                    impact_if_unremediated: pattern.impact,
                    remediation: pattern.remediation,
                    residual_risk:
                      "Even after fixing this sink, similar patterns may exist elsewhere; re-check related modules.",
                    verification_suggestion:
                      "Add tests or code-review checks that unsafe sinks do not receive unsanitized external input; re-run this tool after fixes.",
                    cwe: pattern.cwe,
                    tags: [pattern.category ?? "injection-risk", pattern.id, "remediation"],
                  }),
                ),
              );
            }
          }
        }

        findings.sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]);
        const finalizedCoverage = coverageSession.finish(findings);
        const safeFindings = redactFindings(findings);
        const appliedPackIds = appliedInjectionPackIds([...detectorFamiliesRun]);

        const data = {
          ok: true as const,
          project_root: root,
          summary: `Injection-risk review: ${safeFindings.length} potential weakness(es) in ${filesScanned.length} file(s)${finalizedCoverage.scan_status !== "complete" ? " (coverage is partial or truncated)" : ""}. Classify, confirm evidence, and remediate — do not generate exploits.`,
          findings: safeFindings,
          files_scanned_count: filesScanned.length,
          files_reviewed: redactedSecretPaths(filesScanned),
          truncated: finalizedCoverage.truncation.truncated,
          coverage: redactCoverageReport(finalizedCoverage),
          applied_pack_ids: appliedPackIds,
          knowledge_pack_traceability: {
            consulted_pack_ids: consultedPackIds,
            detector_families_run: [...detectorFamiliesRun].sort(),
            detector_families_not_run: [...detectorFamiliesAvailable]
              .filter((family) => !detectorFamiliesRun.has(family))
              .sort(),
            consulted_via: "bundled detector mappings; no remote pack lookup",
          },
          notes: [
            "Defensive review only: identify → classify → remediate.",
            "Heuristics produce candidates; verify data flow before confirming.",
            "Do not produce exploit or PoC attack code when following up.",
            "Continue analysis until stack-relevant injection categories are covered with evidence.",
          ],
        };

        const md = renderMarkdownDocument({
          title: "Injection-risk review (remediation focused)",
          summary: data.summary,
          findings: safeFindings.slice(0, 50),
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
