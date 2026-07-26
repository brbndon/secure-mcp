/**
 * Tool: secure_mcp_analyze_injection_risks
 * Defensive identification of injection-class weaknesses for remediation.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { z } from "zod";
import {
  findLineNumber,
  normalizeProjectRoot,
  readProjectFile,
  snippetAround,
  toolError,
  toolSuccess,
  walkProject,
} from "../lib/filesystem.js";
import type { Finding } from "../lib/types.js";
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

const InputSchema = ProjectRootInput;
type Input = z.infer<typeof InputSchema>;

const TOOL_DESCRIPTION = `Defensive secure-code-review tool: identify potential injection-class weaknesses so the development team can harden the codebase.

PURPOSE (defensive only)
- Find locations where untrusted input may influence dangerous sinks (SQL/query construction, command execution, HTML rendering, path handling, unsafe redirects).
- Classify each potential weakness with severity, confidence, category, and CWE when known.
- Recommend concrete remediation (parameterized queries, safe APIs, validation, allowlists).
- Never generate exploit code, proof-of-concept attacks, or step-by-step abuse instructions.

MANDATORY AGENT WORKFLOW (use intermediate artifacts; thorough multi-phase review is expected)
1. Inventory — Prefer calling secure_mcp_list_project_structure and secure_mcp_analyze_architecture first so review is scoped.
2. Run this tool to collect candidate weaknesses with evidence.
3. For each high/critical candidate, open the cited file and trace data flow from untrusted input to the sink (read-only).
4. Keep, downgrade confidence, or discard false positives; always fill remediation, impact_if_unremediated, residual_risk, and verification_suggestion.
5. Merge results later via secure_mcp_produce_findings into a remediation-focused report.
6. Continue until major injection categories relevant to the stack have been examined with evidence (do not stop after the first hit).

WHAT THIS TOOL CHECKS (heuristics; confirm manually)
- TypeScript/Node: eval/Function, child_process usage, SQL string concatenation, dangerouslySetInnerHTML/innerHTML, path joins with request-like data.
- Next.js: SSR HTML sinks, redirect parameters that should be allowlisted.
- Swift: Process/NSTask shell usage, WKWebView bridges / evaluateJavaScript, deep-link handlers, ATS exceptions, weak MD5/SHA1 hashes, cleartext http:// endpoints.

Args:
  - project_root (string): Codebase root to review
  - stack (auto|common|typescript|nextjs|swift): Focus filters
  - max_files (number, optional): Walk safety cap
  - response_format (json|markdown): Default json

Returns:
  findings[] using the shared Finding schema:
  evidence → classification (severity/confidence/category/cwe) → impact_if_unremediated → remediation → residual_risk → verification_suggestion

GUARDRAILS
- Read-only filesystem inspection; does not execute project code.
- Confidence may be medium/low; the agent must verify before treating a finding as confirmed.
- Frame every output as guidance for developers fixing their own code.`;

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

export function registerAnalyzeInjectionRisks(server: McpServer): void {
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
        const root = await normalizeProjectRoot(params.project_root);
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
        ]);

        const { files, truncated } = await walkProject(root, {
          maxFiles: params.max_files ?? 400,
          extensions,
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
            });
          }
        }
        if (stack === "auto" || stack === "nextjs" || stack === "typescript") {
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
            });
          }
        }

        for (const file of files) {
          if (file.size > 256 * 1024) continue;
          if (file.relativePath.endsWith(".md") && !file.relativePath.includes("security")) {
            continue;
          }

          let content: string;
          try {
            content = (await readProjectFile(root, file.relativePath)).content;
          } catch {
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

            pattern.regex.lastIndex = 0;
            let match: RegExpExecArray | null;
            let hits = 0;
            while ((match = pattern.regex.exec(content)) !== null && hits < 8) {
              if (pattern.filter && !pattern.filter(match[0], content)) {
                continue;
              }
              hits++;
              findings.push(
                buildFinding({
                  id: nextId(),
                  title: pattern.title,
                  description: `Potential weakness pattern ${pattern.id} observed in ${file.relativePath}. Review whether untrusted input can influence this location and apply the remediation if so.`,
                  severity: pattern.severity,
                  confidence: pattern.confidence ?? "medium",
                  category: pattern.category ?? "injection-risk",
                  stack: pattern.stack,
                  file: file.relativePath,
                  line: findLineNumber(content, match.index),
                  evidence: snippetAround(content, match.index),
                  impact_if_unremediated: pattern.impact,
                  remediation: pattern.remediation,
                  residual_risk:
                    "Even after fixing this sink, similar patterns may exist elsewhere; re-check related modules.",
                  verification_suggestion:
                    "Add tests or code-review checks that unsafe sinks do not receive unsanitized external input; re-run this tool after fixes.",
                  cwe: pattern.cwe,
                  tags: [pattern.category ?? "injection-risk", pattern.id, "remediation"],
                }),
              );
            }
          }
        }

        const order = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
        findings.sort((a, b) => order[b.severity] - order[a.severity]);

        const data = {
          ok: true as const,
          project_root: root,
          summary: `Injection-risk review: ${findings.length} potential weakness(es) in ${filesScanned.length} file(s)${truncated ? " (file walk truncated)" : ""}. Classify, confirm evidence, and remediate — do not generate exploits.`,
          findings,
          files_scanned_count: filesScanned.length,
          truncated,
          applied_pack_ids: ["core"] as const,
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
          ...findings.slice(0, 50).map(
            (f) =>
              `### ${f.id} [${f.severity}] ${f.title}\n` +
              `- Evidence: ${f.file}:${f.line ?? "?"}\n` +
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
