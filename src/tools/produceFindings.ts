/**
 * Tool: secure_mcp_produce_findings
 * Normalize and format a remediation-focused findings report.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { toolError, toolSuccess } from "../lib/filesystem.js";
import { SEVERITY_ORDER, type Finding, type Severity } from "../lib/types.js";
import { FindingSchema } from "../knowledge/findings-schema.js";

const InputSchema = z
  .object({
    findings: z
      .array(FindingSchema)
      .min(1)
      .max(500)
      .describe(
        "Finding objects from prior defensive review tools and agent analysis. Each must include evidence, impact_if_unremediated, remediation, residual_risk, and verification_suggestion.",
      ),
    project_root: z
      .string()
      .optional()
      .describe("Optional project root for report metadata"),
    min_severity: z
      .enum(["critical", "high", "medium", "low", "info"])
      .default("info")
      .describe("Drop findings below this severity"),
    min_confidence: z
      .enum(["high", "medium", "low"])
      .default("low")
      .describe("Drop findings below this confidence"),
    dedupe: z
      .boolean()
      .default(true)
      .describe("Merge findings with same title+file+category"),
    response_format: z.enum(["json", "markdown"]).default("json"),
    report_title: z.string().max(200).optional(),
  })
  .strict();

type Input = z.infer<typeof InputSchema>;

const CONFIDENCE_ORDER = { high: 3, medium: 2, low: 1 } as const;

function severityAtLeast(value: Severity, min: Severity): boolean {
  return SEVERITY_ORDER[value] >= SEVERITY_ORDER[min];
}

function confidenceAtLeast(
  value: Finding["confidence"],
  min: Finding["confidence"],
): boolean {
  return CONFIDENCE_ORDER[value] >= CONFIDENCE_ORDER[min];
}

function dedupeKey(f: Finding): string {
  return [f.category, f.title, f.file ?? "", f.line ?? "", f.cwe ?? ""].join("|").toLowerCase();
}

function mergeFindings(a: Finding, b: Finding): Finding {
  const severity =
    SEVERITY_ORDER[a.severity] >= SEVERITY_ORDER[b.severity] ? a.severity : b.severity;
  const confidence =
    CONFIDENCE_ORDER[a.confidence] >= CONFIDENCE_ORDER[b.confidence]
      ? a.confidence
      : b.confidence;
  const tags = [...new Set([...(a.tags ?? []), ...(b.tags ?? [])])];
  return {
    ...a,
    severity,
    confidence,
    description: a.description.length >= b.description.length ? a.description : b.description,
    evidence: a.evidence.length >= b.evidence.length ? a.evidence : b.evidence,
    impact_if_unremediated:
      a.impact_if_unremediated.length >= b.impact_if_unremediated.length
        ? a.impact_if_unremediated
        : b.impact_if_unremediated,
    remediation: a.remediation.length >= b.remediation.length ? a.remediation : b.remediation,
    residual_risk:
      a.residual_risk.length >= b.residual_risk.length ? a.residual_risk : b.residual_risk,
    verification_suggestion:
      a.verification_suggestion.length >= b.verification_suggestion.length
        ? a.verification_suggestion
        : b.verification_suggestion,
    cwe: a.cwe ?? b.cwe,
    owasp: a.owasp ?? b.owasp,
    tags: tags.length ? tags : undefined,
  };
}

function buildMarkdown(
  title: string,
  projectRoot: string | undefined,
  findings: Finding[],
  counts: Record<string, number>,
): string {
  const lines: string[] = [
    `# ${title}`,
    "",
    "> Defensive secure-code-review report. Goal: help the development team harden the codebase. Do not include exploit or attack PoC content.",
    "",
    projectRoot ? `**Project:** ${projectRoot}` : "",
    `**Total findings:** ${findings.length}`,
    "",
    "## Summary by severity (remediation priority)",
    ...Object.entries(counts).map(([k, v]) => `- **${k}**: ${v}`),
    "",
    "## Findings",
  ];

  for (const f of findings) {
    lines.push("");
    lines.push(`### ${f.id} — ${f.title}`);
    lines.push("");
    lines.push(`#### Classification`);
    lines.push(`- **Severity:** ${f.severity}`);
    lines.push(`- **Confidence:** ${f.confidence}`);
    lines.push(`- **Category:** ${f.category}`);
    if (f.cwe) lines.push(`- **CWE:** ${f.cwe}`);
    if (f.owasp) lines.push(`- **OWASP:** ${f.owasp}`);
    if (f.file) lines.push(`- **Location:** ${f.file}${f.line ? `:${f.line}` : ""}`);
    lines.push("");
    lines.push(`#### Evidence`);
    lines.push(f.description);
    lines.push("");
    lines.push(`\`${f.evidence}\``);
    lines.push("");
    lines.push(`#### Impact if unremediated`);
    lines.push(f.impact_if_unremediated);
    lines.push("");
    lines.push(`#### Remediation`);
    lines.push(f.remediation);
    lines.push("");
    lines.push(`#### Residual risk`);
    lines.push(f.residual_risk);
    lines.push("");
    lines.push(`#### Verification suggestion`);
    lines.push(f.verification_suggestion);
  }

  return lines.filter((l) => l !== undefined).join("\n");
}

const TOOL_DESCRIPTION = `Defensive secure-code-review tool: normalize, filter, deduplicate, and prioritise findings into a remediation-focused final report for the development team.

PURPOSE (defensive only)
- Combine intermediate findings from inventory, architecture, authentication, injection-risk, secrets, threat-model-for-remediation, and manual agent analysis.
- Enforce the shared Finding schema: evidence → classification → impact_if_unremediated → remediation → residual_risk → verification_suggestion.
- Produce executive summary stats for prioritising hardening work.
- Never rewrite findings into exploit guides or offensive playbooks.

WHEN TO CALL
- After multi-phase review tools and agent confirmation of high-priority items.
- Thorough audits should accumulate intermediate artifacts before this final rollup (long-running, multi-step analysis is expected and encouraged).

Args:
  - findings (Finding[], required): must include all required remediation fields
  - project_root (optional metadata)
  - min_severity / min_confidence filters
  - dedupe (boolean, default true)
  - report_title, response_format

Returns:
  Prioritised findings (renumbered F-001…), severity counts, executive_summary, optional markdown body structured for remediation.

GUARDRAILS
- Reject incomplete findings that lack remediation structure (schema validation).
- Report language must stay defensive and owner-focused.`;

export function registerProduceFindings(server: McpServer): void {
  server.registerTool(
    "secure_mcp_produce_findings",
    {
      title: "Produce remediation-focused findings report",
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
        let list: Finding[] = params.findings.map((f) => ({ ...f }));

        list = list.filter(
          (f) =>
            severityAtLeast(f.severity, params.min_severity) &&
            confidenceAtLeast(f.confidence, params.min_confidence),
        );

        if (params.dedupe) {
          const map = new Map<string, Finding>();
          for (const f of list) {
            const key = dedupeKey(f);
            const existing = map.get(key);
            map.set(key, existing ? mergeFindings(existing, f) : f);
          }
          list = [...map.values()];
        }

        list.sort((a, b) => {
          const sev = SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
          if (sev !== 0) return sev;
          return CONFIDENCE_ORDER[b.confidence] - CONFIDENCE_ORDER[a.confidence];
        });

        list = list.map((f, i) => ({
          ...f,
          tags: [...new Set([...(f.tags ?? []), `source-id:${f.id}`, "remediation-report"])],
          id: `F-${String(i + 1).padStart(3, "0")}`,
        }));

        const counts: Record<Severity, number> = {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          info: 0,
        };
        for (const f of list) counts[f.severity]++;

        const title = params.report_title ?? "Secure code review — remediation findings";
        const risk_score =
          counts.critical * 10 + counts.high * 5 + counts.medium * 2 + counts.low * 1;

        const executive_summary = {
          total: list.length,
          counts,
          risk_score,
          top_categories: topCategories(list, 5),
          remediation_priority: list
            .filter((f) => f.severity === "critical" || f.severity === "high")
            .slice(0, 10)
            .map((f) => ({
              id: f.id,
              title: f.title,
              severity: f.severity,
              remediation: f.remediation,
            })),
          framing:
            "Defensive secure-code-review for the development team. Identify weaknesses, classify them, and remediate. No exploit content.",
        };

        const data = {
          ok: true as const,
          project_root: params.project_root ?? null,
          summary: `${title}: ${list.length} finding(s); critical=${counts.critical}, high=${counts.high}, medium=${counts.medium}, low=${counts.low}, info=${counts.info}. Prioritise remediation.`,
          executive_summary,
          findings: list,
          notes: [
            "Each finding follows evidence → classify → impact → remediate → verify.",
            "Do not expand this report into exploit or PoC attack material.",
          ],
        };

        return toolSuccess(data, {
          responseFormat: params.response_format,
          markdown: buildMarkdown(title, params.project_root, list, counts),
        });
      } catch (error) {
        return toolError(
          error,
          "Ensure each finding matches the Finding schema including evidence, impact_if_unremediated, remediation, residual_risk, and verification_suggestion.",
        );
      }
    },
  );
}

function topCategories(findings: Finding[], n: number): { category: string; count: number }[] {
  const map = new Map<string, number>();
  for (const f of findings) {
    map.set(f.category, (map.get(f.category) ?? 0) + 1);
  }
  return [...map.entries()]
    .map(([category, count]) => ({ category, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, n);
}
