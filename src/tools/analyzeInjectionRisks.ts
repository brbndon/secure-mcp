/**
 * Tool: secure_mcp_analyze_injection_risks
 * Defensive identification of injection-class weaknesses for remediation.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { z } from "zod";
import { loadConfig, type ServerConfig } from "../config.js";
import {
  detectWithBudget,
  findLineNumber,
  finalizeCoverage,
  recordCoverageExclusion,
  normalizeAuthorizedProjectRoot,
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
import type { Finding, StackFocus } from "../lib/types.js";
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
import type { PackId } from "../knowledge/packs/registry.js";

const InputSchema = ProjectRootInput;
type Input = z.infer<typeof InputSchema>;

const TOOL_DESCRIPTION = `Defensive secure-code-review tool: identify potential injection-class weaknesses so the development team can harden the codebase.

Args: project_root, stack?, max_files?, focus_paths?, response_format.

Returns: findings[] using the shared Finding schema (evidence → classification → impact_if_unremediated → remediation → residual_risk → verification_suggestion), files_scanned_count, truncated, applied_pack_ids.

Guidance: Call secure_mcp_get_audit_guidance for the full workflow and guardrails.`;

function swiftPatternAppliesToFile(
  pattern: { id: string; extensions?: string[] },
  fileExt: string,
): boolean {
  const allowed = pattern.extensions ?? [".swift"];
  if (allowed.includes(fileExt)) return true;
  if (
    (pattern.id === "SWIFT-ATS-ARBITRARY" || pattern.id === "SWIFT-ATS-EXCEPTION") &&
    (fileExt === ".plist" || fileExt === ".xml")
  ) {
    return true;
  }
  return false;
}

export function shouldRunNextjsInjectionDetectors(stack: "auto" | StackFocus): boolean {
  return stack === "auto" || stack === "nextjs";
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

        const { files, coverage } = await walkProject(root, {
          maxFiles: params.max_files ?? config.defaultMaxFiles,
          maxDepth: config.maxDepth,
          maxFileBytes: config.maxFileBytes,
          maxTotalBytes: config.maxTotalBytes,
          allowedRoots: config.allowedRoots,
          extensions,
          focusPrefixes: params.focus_paths,
        });

        const patterns: {
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
          detectorFamily: string;
        }[] = [];

        if (
          stack === "auto" ||
          stack === "common" ||
          stack === "typescript" ||
          stack === "nextjs"
        ) {
          for (const p of INJECTION_PATTERNS) {
            patterns.push({
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
              packId: "core",
              detectorFamily: "core.injection",
            });
          }
        }
        if (shouldRunNextjsInjectionDetectors(stack)) {
          for (const p of NEXTJS_PATTERNS) {
            if (p.id.includes("PUBLIC") || p.id.includes("USE-CLIENT")) continue;
            patterns.push({
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
              packId: "web-next",
              detectorFamily: "web-next.injection",
            });
          }
        }
        if (stack === "auto" || stack === "swift") {
          for (const p of [
            ...SWIFT_INJECTION_PATTERNS,
            ...SWIFT_CONFIG_PATTERNS,
            ...SWIFT_CRYPTO_PATTERNS,
          ]) {
            patterns.push({
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
              extensions: p.extensions,
              filter: p.filter,
              packId: "swift-ios",
              detectorFamily:
                p.category === "configuration"
                  ? "swift-ios.configuration"
                  : p.category === "cryptography"
                    ? "swift-ios.cryptography"
                    : "swift-ios.injection",
            });
          }
        }

        const consultedPackIds = [...new Set(patterns.map((pattern) => pattern.packId))];
        const detectorFamiliesRun = new Set<string>();

        for (const file of files) {
          if (file.size > config.maxFileBytes) {
            recordCoverageExclusion(coverage, {
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
            recordCoverageExclusion(coverage, {
              path: file.relativePath,
              kind: "file",
              reason: "non_security_documentation",
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
            recordCoverageExclusion(coverage, {
              path: file.relativePath,
              kind: "file",
              reason: "file_read_error",
            });
            continue;
          }
          filesScanned.push(file.relativePath);

          for (const pattern of patterns) {
            if (pattern.stack === "swift" && !swiftPatternAppliesToFile(pattern, file.ext)) {
              continue;
            }
            if (
              (pattern.stack === "typescript" || pattern.stack === "nextjs") &&
              file.ext === ".swift"
            ) {
              continue;
            }
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

        const order = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
        findings.sort((a, b) => order[b.severity] - order[a.severity]);
        const finalizedCoverage = finalizeCoverage(coverage, filesScanned, findings);
        const safeFindings = redactFindings(findings);

        const data = {
          ok: true as const,
          project_root: root,
          summary: `Injection-risk review: ${safeFindings.length} potential weakness(es) in ${filesScanned.length} file(s)${finalizedCoverage.scan_status !== "complete" ? " (coverage is partial or truncated)" : ""}. Classify, confirm evidence, and remediate — do not generate exploits.`,
          findings: safeFindings,
          files_scanned_count: filesScanned.length,
          files_reviewed: redactedSecretPaths(filesScanned),
          truncated: finalizedCoverage.truncation.truncated,
          coverage: redactCoverageReport(finalizedCoverage),
          applied_pack_ids: consultedPackIds,
          knowledge_pack_traceability: {
            consulted_pack_ids: consultedPackIds,
            detector_families_run: [...detectorFamiliesRun],
            detector_families_not_run: consultedPackIds.length
              ? patterns
                  .map((pattern) => pattern.detectorFamily)
                  .filter((family, index, all) => all.indexOf(family) === index)
                  .filter((family) => !detectorFamiliesRun.has(family))
              : [],
            consulted_via: "bundled detector mappings; no remote pack lookup",
          },
          notes: [
            "Defensive review only: identify → classify → remediate.",
            "Heuristics produce candidates; verify data flow before confirming.",
            "Do not produce exploit or PoC attack code when following up.",
            "Continue analysis until stack-relevant injection categories are covered with evidence.",
          ],
        };

        const md = [
          `# Injection-risk review (remediation focused)`,
          data.summary,
          "",
          ...safeFindings.slice(0, 50).map(
            (f) =>
              `### ${escapeMarkdown(f.id)} [${escapeMarkdown(f.severity)}] ${escapeMarkdown(f.title)}\n` +
              `- Evidence: ${escapeMarkdown(`${f.file ?? "?"}:${f.line ?? "?"}`)}\n` +
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
