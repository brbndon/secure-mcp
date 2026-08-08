/**
 * Tool: secure_mcp_produce_findings
 * Normalize and format a remediation-focused findings report.
 */

import type { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import { toolError, toolSuccess } from "../lib/filesystem.js";
import { redactFindings, redactedEvidence } from "../lib/redact.js";
import { escapeMarkdown, markdownCode } from "../lib/markdown.js";
import {
  CANDIDATE_DISPOSITIONS,
  SEVERITY_ORDER,
  type CandidateDisposition,
  type Finding,
  type Severity,
} from "../lib/types.js";
import {
  ensureFindingTraceability,
  FindingSchema,
  MAX_FINDINGS,
  MAX_FINDINGS_DECODED_BYTES,
  MAX_FINDING_CATEGORY,
  MAX_FINDING_DISPOSITION_REASON,
  MAX_FINDING_ID,
  MAX_FINDING_LABEL,
  MAX_FINDING_LIST_ITEM,
  MAX_FINDING_LIST_ITEMS,
  MAX_FINDING_NARRATIVE,
  MAX_FINDING_PATH,
  MAX_FINDING_TAG,
  MAX_FINDING_TAGS,
  MAX_FINDING_TITLE,
  MAX_PROJECT_ROOT_LENGTH,
  MAX_REPORT_TITLE,
} from "../knowledge/findings-schema.js";

const InputSchema = z
  .object({
    findings: z
      .array(FindingSchema)
      .min(1)
      .max(MAX_FINDINGS)
      .superRefine((findings, ctx) => {
        // Total decoded-request budget: enforced before hashing, deduplication,
        // redaction, or Markdown construction so processing stays bounded even
        // when every individual field is within its own cap.
        let decodedBytes = 0;
        for (const finding of findings) {
          decodedBytes += Buffer.byteLength(JSON.stringify(finding), "utf8");
          if (decodedBytes > MAX_FINDINGS_DECODED_BYTES) {
            ctx.addIssue({
              code: "custom",
              message: `findings exceed the total decoded size budget of ${MAX_FINDINGS_DECODED_BYTES} bytes`,
            });
            return;
          }
        }
      })
      .describe(
        "Finding objects from prior defensive review tools and agent analysis. Each must include evidence, impact_if_unremediated, remediation, residual_risk, and verification_suggestion.",
      ),
    project_root: z
      .string()
      .max(MAX_PROJECT_ROOT_LENGTH)
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
    report_title: z.string().max(MAX_REPORT_TITLE).optional(),
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
  const mergeList = (left: string[] | undefined, right: string[] | undefined, limit: number) =>
    [...new Set([...(left ?? []), ...(right ?? [])])].slice(0, limit);
  const tags = mergeList(a.tags, b.tags, MAX_FINDING_TAGS);
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
    counterevidence: mergeList(a.counterevidence, b.counterevidence, MAX_FINDING_LIST_ITEMS),
    proof_gap: mergeList(a.proof_gap, b.proof_gap, MAX_FINDING_LIST_ITEMS),
    validation: mergeList(a.validation, b.validation, MAX_FINDING_LIST_ITEMS),
    tags: tags.length ? tags : undefined,
  };
}

const OUTPUT_TRUNCATION_MARKER = "…[truncated]";

function boundString(value: string, limit: number): string {
  if (value.length <= limit) return value;
  if (limit <= OUTPUT_TRUNCATION_MARKER.length) return value.slice(0, limit);
  return `${value.slice(0, limit - OUTPUT_TRUNCATION_MARKER.length)}${OUTPUT_TRUNCATION_MARKER}`;
}

/** Keep post-redaction/merge fields within the same deterministic budgets as input. */
function boundFinding(finding: Finding): Finding {
  return {
    ...finding,
    id: boundString(finding.id, MAX_FINDING_ID),
    title: boundString(finding.title, MAX_FINDING_TITLE),
    description: boundString(finding.description, MAX_FINDING_NARRATIVE),
    category: boundString(finding.category, MAX_FINDING_CATEGORY),
    ...(finding.file !== undefined
      ? { file: boundString(finding.file, MAX_FINDING_PATH) }
      : {}),
    evidence: boundString(finding.evidence, MAX_FINDING_NARRATIVE),
    impact_if_unremediated: boundString(finding.impact_if_unremediated, MAX_FINDING_NARRATIVE),
    remediation: boundString(finding.remediation, MAX_FINDING_NARRATIVE),
    residual_risk: boundString(finding.residual_risk, MAX_FINDING_NARRATIVE),
    verification_suggestion: boundString(
      finding.verification_suggestion,
      MAX_FINDING_NARRATIVE,
    ),
    ...(finding.cwe !== undefined ? { cwe: boundString(finding.cwe, MAX_FINDING_LABEL) } : {}),
    ...(finding.owasp !== undefined
      ? { owasp: boundString(finding.owasp, MAX_FINDING_LABEL) }
      : {}),
    ...(finding.tags !== undefined
      ? { tags: finding.tags.slice(0, MAX_FINDING_TAGS).map((tag) => boundString(tag, MAX_FINDING_TAG)) }
      : {}),
    ...(finding.rule_family !== undefined
      ? { rule_family: boundString(finding.rule_family, MAX_FINDING_LABEL) }
      : {}),
    ...(finding.root_control !== undefined
      ? { root_control: boundString(finding.root_control, MAX_FINDING_LABEL) }
      : {}),
    ...(finding.instance_id !== undefined
      ? { instance_id: boundString(finding.instance_id, MAX_FINDING_LABEL) }
      : {}),
    ...(finding.disposition_reason !== undefined
      ? { disposition_reason: boundString(finding.disposition_reason, MAX_FINDING_DISPOSITION_REASON) }
      : {}),
    ...(finding.source !== undefined
      ? { source: boundString(finding.source, MAX_FINDING_NARRATIVE) }
      : {}),
    ...(finding.control !== undefined
      ? { control: boundString(finding.control, MAX_FINDING_NARRATIVE) }
      : {}),
    ...(finding.sink !== undefined
      ? { sink: boundString(finding.sink, MAX_FINDING_NARRATIVE) }
      : {}),
    ...(finding.counterevidence !== undefined
      ? {
          counterevidence: finding.counterevidence
            .slice(0, MAX_FINDING_LIST_ITEMS)
            .map((item) => boundString(item, MAX_FINDING_LIST_ITEM)),
        }
      : {}),
    ...(finding.proof_gap !== undefined
      ? {
          proof_gap: finding.proof_gap
            .slice(0, MAX_FINDING_LIST_ITEMS)
            .map((item) => boundString(item, MAX_FINDING_LIST_ITEM)),
        }
      : {}),
    ...(finding.validation !== undefined
      ? {
          validation: finding.validation
            .slice(0, MAX_FINDING_LIST_ITEMS)
            .map((item) => boundString(item, MAX_FINDING_LIST_ITEM)),
        }
      : {}),
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
        list = redactFindings(list).map((f, i) =>
          boundFinding({
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
          }),
        );

        const counts: Record<Severity, number> = {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          info: 0,
        };
        for (const f of list) counts[f.severity]++;

        const title = boundString(
          redactedEvidence(params.report_title ?? "Secure code review — remediation findings"),
          MAX_REPORT_TITLE,
        );
        const projectRoot = params.project_root
          ? boundString(redactedEvidence(params.project_root), MAX_PROJECT_ROOT_LENGTH)
          : undefined;
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
          project_root: projectRoot ?? null,
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
          markdown: buildMarkdown(title, projectRoot, list, counts),
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
