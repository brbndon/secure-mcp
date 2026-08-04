/**
 * Tool: secure_mcp_produce_findings
 * Normalize and format a remediation-focused findings report.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { toolError, toolSuccess } from "../lib/filesystem.js";
import { redactFindings } from "../lib/redact.js";
import { escapeMarkdown, markdownCode } from "../lib/markdown.js";
import {
  CANDIDATE_DISPOSITIONS,
  SEVERITY_ORDER,
  type CandidateDisposition,
  type Finding,
  type Severity,
} from "../lib/types.js";
import { ensureFindingTraceability, FindingSchema } from "../knowledge/findings-schema.js";

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
  return (
    f.instance_id ??
    [f.category, f.title, f.file ?? "", f.line ?? "", f.cwe ?? ""].join("|")
  ).toLowerCase();
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
    rule_family: a.rule_family ?? b.rule_family,
    root_control: a.root_control ?? b.root_control,
    instance_id: a.instance_id ?? b.instance_id,
    disposition:
      a.disposition === "reportable" || b.disposition === "reportable"
        ? "reportable"
        : a.disposition ?? b.disposition,
    disposition_reason: a.disposition_reason ?? b.disposition_reason,
    source: a.source ?? b.source,
    control: a.control ?? b.control,
    sink: a.sink ?? b.sink,
    counterevidence: [...new Set([...(a.counterevidence ?? []), ...(b.counterevidence ?? [])])],
    proof_gap: [...new Set([...(a.proof_gap ?? []), ...(b.proof_gap ?? [])])],
    validation: [...new Set([...(a.validation ?? []), ...(b.validation ?? [])])],
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
    `# ${escapeMarkdown(title)}`,
    "",
    "> Defensive secure-code-review report. Goal: help the development team harden the codebase. Do not include exploit or attack PoC content.",
    "",
    projectRoot ? `**Project:** ${escapeMarkdown(projectRoot)}` : "",
    `**Total findings:** ${findings.length}`,
    "",
    "## Summary by severity (remediation priority)",
    ...Object.entries(counts).map(([k, v]) => `- **${k}**: ${v}`),
    "",
    "## Findings",
  ];

  for (const f of findings) {
    lines.push("");
    lines.push(`### ${escapeMarkdown(f.id)} — ${escapeMarkdown(f.title)}`);
    lines.push("");
    lines.push(`#### Classification`);
    lines.push(`- **Severity:** ${f.severity}`);
    lines.push(`- **Confidence:** ${f.confidence}`);
    lines.push(`- **Category:** ${escapeMarkdown(f.category)}`);
    if (f.cwe) lines.push(`- **CWE:** ${escapeMarkdown(f.cwe)}`);
    if (f.owasp) lines.push(`- **OWASP:** ${escapeMarkdown(f.owasp)}`);
    if (f.file) {
      lines.push(
        `- **Location:** ${escapeMarkdown(`${f.file}${f.line ? `:${f.line}` : ""}`)}`,
      );
    }
    if (f.instance_id) lines.push(`- **Stable instance:** ${escapeMarkdown(f.instance_id)}`);
    if (f.rule_family) lines.push(`- **Rule family:** ${escapeMarkdown(f.rule_family)}`);
    if (f.root_control) lines.push(`- **Root control:** ${escapeMarkdown(f.root_control)}`);
    if (f.disposition) lines.push(`- **Disposition:** ${escapeMarkdown(f.disposition)}`);
    if (f.disposition_reason) {
      lines.push(`- **Disposition reason:** ${escapeMarkdown(f.disposition_reason)}`);
    }
    lines.push("");
    lines.push(`#### Evidence`);
    lines.push(escapeMarkdown(f.description));
    lines.push("");
    lines.push(markdownCode(f.evidence));
    if (f.source || f.control || f.sink) {
      lines.push("");
      lines.push(`#### Proof context`);
      if (f.source) lines.push(`- **Source:** ${escapeMarkdown(f.source)}`);
      if (f.control) lines.push(`- **Control:** ${escapeMarkdown(f.control)}`);
      if (f.sink) lines.push(`- **Sink:** ${escapeMarkdown(f.sink)}`);
    }
    if (f.counterevidence?.length) {
      lines.push("");
      lines.push(`#### Counterevidence`);
      for (const item of f.counterevidence) lines.push(`- ${escapeMarkdown(item)}`);
    }
    if (f.proof_gap?.length) {
      lines.push("");
      lines.push(`#### Proof gap`);
      for (const item of f.proof_gap) lines.push(`- ${escapeMarkdown(item)}`);
    }
    if (f.validation?.length) {
      lines.push("");
      lines.push(`#### Validation`);
      for (const item of f.validation) lines.push(`- ${escapeMarkdown(item)}`);
    }
    lines.push("");
    lines.push(`#### Impact if unremediated`);
    lines.push(escapeMarkdown(f.impact_if_unremediated));
    lines.push("");
    lines.push(`#### Remediation`);
    lines.push(escapeMarkdown(f.remediation));
    lines.push("");
    lines.push(`#### Residual risk`);
    lines.push(escapeMarkdown(f.residual_risk));
    lines.push("");
    lines.push(`#### Verification suggestion`);
    lines.push(escapeMarkdown(f.verification_suggestion));
  }

  return lines.filter((l) => l !== undefined).join("\n");
}

/** Exported for tests: markdown includes additive proof/traceability fields. */
export function findingsToMarkdown(
  title: string,
  projectRoot: string | undefined,
  findings: Finding[],
  counts: Record<string, number>,
): string {
  return buildMarkdown(title, projectRoot, findings, counts);
}

const TOOL_DESCRIPTION = `Defensive tool: normalize, filter, dedupe and prioritise a list of Finding objects into a final remediation report.\n\nArgs: findings (Finding[]), project_root?, min_severity?, min_confidence?, dedupe?, report_title?, response_format.\nReturns: findings[], executive_summary, counts.`;

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
        let list: Finding[] = params.findings.map((f) => ensureFindingTraceability({ ...f }));

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
          const confidence = CONFIDENCE_ORDER[b.confidence] - CONFIDENCE_ORDER[a.confidence];
          if (confidence !== 0) return confidence;
          return (a.instance_id ?? a.id).localeCompare(b.instance_id ?? b.id);
        });

        // Redact after identity/dedupe so stable keys use unredacted location metadata.
        list = redactFindings(list).map((f, i) => ({
          ...f,
          tags: [
            ...new Set([
              ...(f.tags ?? []),
              `source-id:${f.id}`,
              ...(f.instance_id ? [`instance-id:${f.instance_id}`] : []),
              "remediation-report",
            ]),
          ],
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
              instance_id: f.instance_id,
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
          candidate_disposition_counts: countDispositions(list),
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

function countDispositions(findings: Finding[]): Record<CandidateDisposition, number> {
  const counts = Object.fromEntries(
    CANDIDATE_DISPOSITIONS.map((disposition) => [disposition, 0]),
  ) as Record<CandidateDisposition, number>;
  for (const finding of findings) counts[finding.disposition ?? "needs_review"]++;
  return counts;
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
