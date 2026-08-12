/**
 * Tool: secure_mcp_produce_findings
 * Normalize and format a remediation-focused findings report.
 */

import type { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import { toolError, toolSuccess } from "../lib/envelope.js";
import { redactFindings, redactedEvidence } from "../lib/redact.js";
import { renderFindingsReportMarkdown } from "../lib/markdown.js";
import {
  CANDIDATE_DISPOSITIONS,
  SEVERITY_ORDER,
  type CandidateDisposition,
  type Finding,
  type Severity,
} from "../lib/types.js";
import {
  boundFinding,
  boundText,
  ensureFindingTraceability,
  FindingSchema,
  mergeFindings,
  MAX_FINDINGS,
  MAX_FINDINGS_DECODED_BYTES,
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

/** Exported for tests: markdown includes additive proof/traceability fields. */
export function findingsToMarkdown(
  title: string,
  projectRoot: string | undefined,
  findings: Finding[],
  counts: Record<string, number>,
): string {
  return renderFindingsReportMarkdown({ title, projectRoot, findings, counts });
}

const TOOL_DESCRIPTION = `Defensive tool: normalize, filter, dedupe and prioritise a list of Finding objects into a final remediation report.\n\nArgs: findings (Finding[]), project_root?, min_severity?, min_confidence?, dedupe?, report_title?, response_format.\nReturns: findings[], executive_summary, counts, candidate_disposition_counts (includes fixed).\n\nDisposition: pass confirmed open findings as reportable; pass revalidated remediations as fixed with disposition_reason and evidence. Fixed findings are counted but ranked after open reportable work in remediation_priority.`;

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
          // Open work first: fixed/suppressed/not_applicable/deferred rank after open candidates.
          const openRank = (f: Finding): number => {
            switch (f.disposition) {
              case "fixed":
                return 0;
              case "suppressed":
              case "not_applicable":
              case "deferred":
                return 1;
              case "needs_review":
                return 2;
              case "reportable":
              case undefined:
              default:
                return 3;
            }
          };
          const open = openRank(b) - openRank(a);
          if (open !== 0) return open;
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

        const title = boundText(
          redactedEvidence(params.report_title ?? "Secure code review — remediation findings"),
          MAX_REPORT_TITLE,
        );
        const projectRoot = params.project_root
          ? boundText(redactedEvidence(params.project_root), MAX_PROJECT_ROOT_LENGTH)
          : undefined;
        const risk_score =
          counts.critical * 10 + counts.high * 5 + counts.medium * 2 + counts.low * 1;

        const executive_summary = {
          total: list.length,
          counts,
          risk_score,
          top_categories: topCategories(list, 5),
          remediation_priority: list
            .filter(
              (f) =>
                (f.severity === "critical" || f.severity === "high") &&
                f.disposition !== "fixed" &&
                f.disposition !== "suppressed" &&
                f.disposition !== "not_applicable",
            )
            .slice(0, 10)
            .map((f) => ({
              id: f.id,
              instance_id: f.instance_id,
              title: f.title,
              severity: f.severity,
              disposition: f.disposition,
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
            "Disposition fixed means revalidation confirmed the remediation; fixed items are counted but do not dominate remediation_priority.",
            "Do not expand this report into exploit or PoC attack material.",
          ],
        };

        return toolSuccess(data, {
          responseFormat: params.response_format,
          markdown: renderFindingsReportMarkdown({ title, projectRoot, findings: list, counts }),
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

/** Exported for tests: disposition histogram including fixed revalidation outcomes. */
export function countDispositions(findings: Finding[]): Record<CandidateDisposition, number> {
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
