/**
 * Tool: secure_mcp_produce_findings
 * Normalize and format a remediation-focused findings report.
 */

import type { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import { SERVER_VERSION } from "../config.js";
import {
  boundStructuredPayload,
  CHARACTER_LIMIT,
  toolError,
  toolSuccess,
} from "../lib/envelope.js";
import {
  redactFindings,
  redactedEvidence,
  redactValue,
  UNTRUSTED_OUTPUT_NOTICE,
} from "../lib/redact.js";
import { renderFindingsReportMarkdown } from "../lib/markdown.js";
import {
  candidateDispositionPolicy,
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
    response_format: z.enum(["json", "markdown", "sarif"]).default("json"),
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

/** Runtime-verification handoff label (defensive only; no exploit steps). */
export type ValidationStatus = "static_only" | "needs_runtime";

/** A produced finding that carries the derived validation handoff label. */
export type ExportedFinding = Finding & { validation_status: ValidationStatus };

/**
 * Derive a validation label when the caller did not set one. A finding is
 * "needs_runtime" when it is still an unconfirmed candidate or when it carries
 * an unresolved proof gap / counterevidence that only runtime or configuration
 * observation can close; a revalidated `fixed` finding is "static_only".
 */
export function deriveValidationStatus(finding: Finding): ValidationStatus {
  if (finding.disposition === "fixed") return "static_only";
  const runtimeGap =
    (finding.proof_gap?.length ?? 0) > 0 || (finding.counterevidence?.length ?? 0) > 0;
  if (runtimeGap || finding.disposition === "needs_review") return "needs_runtime";
  return "static_only";
}

function countValidationStatuses(
  findings: readonly ExportedFinding[],
): Record<ValidationStatus, number> {
  const counts: Record<ValidationStatus, number> = { static_only: 0, needs_runtime: 0 };
  for (const finding of findings) counts[finding.validation_status]++;
  return counts;
}

/** SARIF 2.1.0 subset emitted by produce_findings (defensive, remediation-focused). */
const SARIF_VERSION = "2.1.0" as const;
const SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json";
const SARIF_DRIVER_NAME = "secure-mcp";

type SarifLevel = "error" | "warning" | "note";

interface SarifLog {
  version: "2.1.0";
  $schema: string;
  runs: Array<{
    tool: {
      driver: {
        name: string;
        version: string;
        informationUri: string;
        rules: Array<{
          id: string;
          shortDescription: { text: string };
          fullDescription: { text: string };
          help: { text: string };
          defaultConfiguration: { level: SarifLevel };
          properties: { tags: string[] };
        }>;
      };
    };
    results: Array<{
      ruleId: string;
      ruleIndex: number;
      level: SarifLevel;
      message: { text: string };
      locations: Array<{
        physicalLocation: {
          artifactLocation: { uri: string };
          region?: { startLine: number };
        };
      }>;
      properties: Record<string, string | number | undefined>;
    }>;
    properties: {
      secure_mcp_report_title: string;
      secure_mcp_project_root?: string;
      /** Present when findings were dropped to fit the response budget. */
      secure_mcp_truncated?: "true";
    };
  }>;
}

function sarifLevel(severity: Severity): SarifLevel {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium") return "warning";
  return "note";
}

/** SARIF rule ids are stable strings; sanitize control identities into a safe id. */
function sarifRuleId(finding: Finding): string {
  const source = finding.root_control ?? finding.rule_family ?? finding.category ?? "finding";
  const id = source.replace(/[^A-Za-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "");
  return id || "finding";
}

/**
 * Build a valid SARIF 2.1.0 subset from already-redacted findings. Maps severity
 * to SARIF level, root_control/rule_family to stable rule ids, file/line to
 * physical locations, and remediation to rule help text. Never embeds raw
 * evidence beyond the redacted finding fields the caller already provided.
 */
export function buildSarifLog(
  findings: readonly ExportedFinding[],
  title: string,
  projectRoot?: string,
): SarifLog {
  const rulesById = new Map<string, number>();
  const rules: SarifLog["runs"][number]["tool"]["driver"]["rules"] = [];

  const results = findings.map((finding) => {
    const ruleId = sarifRuleId(finding);
    let ruleIndex = rulesById.get(ruleId);
    if (ruleIndex === undefined) {
      ruleIndex = rules.length;
      rulesById.set(ruleId, ruleIndex);
      rules.push({
        id: ruleId,
        shortDescription: { text: finding.title },
        fullDescription: { text: finding.description },
        help: { text: finding.remediation },
        defaultConfiguration: { level: sarifLevel(finding.severity) },
        properties: {
          tags: [finding.category, ...(finding.rule_family ? [finding.rule_family] : [])],
        },
      });
    }
    return {
      ruleId,
      ruleIndex,
      level: sarifLevel(finding.severity),
      message: { text: finding.title },
      locations: finding.file
        ? [
            {
              physicalLocation: {
                artifactLocation: { uri: finding.file },
                ...(finding.line !== undefined ? { region: { startLine: finding.line } } : {}),
              },
            },
          ]
        : [],
      properties: {
        category: finding.category,
        severity: finding.severity,
        confidence: finding.confidence,
        disposition: finding.disposition,
        validation_status: finding.validation_status,
        cwe: finding.cwe,
        owasp: finding.owasp,
        instance_id: finding.instance_id,
      },
    };
  });

  return {
    version: SARIF_VERSION,
    $schema: SARIF_SCHEMA_URI,
    runs: [
      {
        tool: {
          driver: {
            name: SARIF_DRIVER_NAME,
            version: SERVER_VERSION,
            informationUri: "https://github.com/brbndon/secure-mcp",
            rules,
          },
        },
        results,
        properties: {
          secure_mcp_report_title: title,
          ...(projectRoot ? { secure_mcp_project_root: projectRoot } : {}),
        },
      },
    ],
  };
}

/**
 * Fit a SARIF export under the response budget while keeping it parseable.
 *
 * The exported findings are already priority-ordered (open work first, then
 * severity/confidence), so the largest head-prefix that fits is the best
 * lossy export. Rules are derived from the retained results, so no dangling
 * ruleIndex remains — unlike generic array-halving, which cannot shrink the
 * nested results or keep the document valid. When findings were dropped, the
 * run is stamped `secure_mcp_truncated: "true"` so consumers know the export
 * is partial instead of reading a clean scan.
 */
export function buildSarifWithinBudget(
  findings: readonly ExportedFinding[],
  title: string,
  projectRoot: string | undefined,
  budget: number,
): { log: SarifLog; truncated: boolean } {
  let low = 0;
  let high = findings.length;
  let best: SarifLog | null = null;
  while (low <= high) {
    const mid = Math.floor((low + high) / 2);
    const log = buildSarifLog(findings.slice(0, mid), title, projectRoot);
    if (JSON.stringify(log).length <= budget) {
      best = log;
      low = mid + 1;
    } else {
      high = mid - 1;
    }
  }
  const log = best ?? buildSarifLog([], title, projectRoot);
  const truncated = log.runs[0].results.length < findings.length;
  if (truncated) {
    log.runs[0].properties.secure_mcp_truncated = "true";
  }
  return { log, truncated };
}

/** Exported for tests: markdown includes additive proof/traceability fields. */
export function findingsToMarkdown(
  title: string,
  projectRoot: string | undefined,
  findings: Finding[],
  counts: Record<string, number>,
): string {
  const openCounts = emptySeverityCounts();
  for (const finding of findings) {
    if (candidateDispositionPolicy(finding.disposition).openWork) {
      openCounts[finding.severity]++;
    }
  }
  return renderFindingsReportMarkdown({
    title,
    projectRoot,
    findings,
    counts,
    openCounts,
    dispositionCounts: countDispositions(findings),
  });
}

const TOOL_DESCRIPTION = `Defensive tool: normalize, filter, dedupe and prioritise a list of Finding objects into a final remediation report.\n\nArgs: findings (Finding[]), project_root?, min_severity?, min_confidence?, dedupe?, report_title?, response_format (json | markdown | sarif).\nReturns: findings[] (each with a derived validation_status: static_only | needs_runtime), executive_summary, counts, candidate_disposition_counts (includes fixed and accepted_risk), validation_counts.\n\nDisposition: reportable and deferred are confirmed open work; needs_review is an unconfirmed candidate; fixed is a revalidated remediation; accepted_risk is a conscious residual. Fixed/suppressed/accepted_risk/not_applicable are counted in the ledger but excluded from open risk and remediation_priority.\n\nValidation: a finding is needs_runtime when it is an unconfirmed candidate or carries an unresolved proof_gap/counterevidence that only runtime or configuration observation can close; static_only otherwise. needs_runtime is a handoff signal to schedule owner-authorized retest, never an exploit step.\n\nSARIF: response_format: "sarif" returns a redacted SARIF 2.1.0 subset (severity→level, rule ids, file/line locations, remediation help text) for CI annotation adjacency. If the export would exceed the response budget, the lowest-priority findings are dropped first and the run is marked secure_mcp_truncated: "true" so the document stays valid SARIF.`;

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
          const open =
            candidateDispositionPolicy(b.disposition).sortRank -
            candidateDispositionPolicy(a.disposition).sortRank;
          if (open !== 0) return open;
          const sev = SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
          if (sev !== 0) return sev;
          const confidence = CONFIDENCE_ORDER[b.confidence] - CONFIDENCE_ORDER[a.confidence];
          if (confidence !== 0) return confidence;
          return (a.instance_id ?? a.id).localeCompare(b.instance_id ?? b.id);
        });

        // Redact after identity/dedupe so stable keys use unredacted location metadata.
        const exported: ExportedFinding[] = redactFindings(list).map((f, i) => {
          const validation_status = f.validation_status ?? deriveValidationStatus(f);
          return {
            ...boundFinding({
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
            validation_status,
          } as ExportedFinding;
        });

        const counts = emptySeverityCounts();
        for (const f of exported) counts[f.severity]++;
        const openCounts = emptySeverityCounts();
        for (const finding of exported) {
          if (candidateDispositionPolicy(finding.disposition).openWork) {
            openCounts[finding.severity]++;
          }
        }
        const dispositionCounts = countDispositions(exported);

        const title = boundText(
          redactedEvidence(params.report_title ?? "Secure code review — remediation findings"),
          MAX_REPORT_TITLE,
        );
        const projectRoot = params.project_root
          ? boundText(redactedEvidence(params.project_root), MAX_PROJECT_ROOT_LENGTH)
          : undefined;
        const ledger_risk_score =
          counts.critical * 10 + counts.high * 5 + counts.medium * 2 + counts.low * 1;
        const risk_score =
          openCounts.critical * 10 +
          openCounts.high * 5 +
          openCounts.medium * 2 +
          openCounts.low;
        const openTotal = Object.values(openCounts).reduce((sum, count) => sum + count, 0);

        const executive_summary = {
          total: exported.length,
          counts,
          open_total: openTotal,
          open_counts: openCounts,
          risk_score,
          ledger_risk_score,
          top_categories: topCategories(exported, 5),
          remediation_priority: exported
            .filter(
              (f) =>
                (f.severity === "critical" || f.severity === "high") &&
                candidateDispositionPolicy(f.disposition).remediationPriority,
            )
            .slice(0, 10)
            .map((f) => ({
              id: f.id,
              instance_id: f.instance_id,
              title: f.title,
              severity: f.severity,
              disposition: f.disposition,
              validation_status: f.validation_status,
              remediation: f.remediation,
            })),
          validation_counts: countValidationStatuses(exported),
          framing:
            "Defensive secure-code-review for the development team. Identify weaknesses, classify them, and remediate. No exploit content.",
        };

        const data = {
          ok: true as const,
          project_root: projectRoot ?? null,
          summary: `${title}: ${exported.length} ledger item(s); open=${openTotal} (critical=${openCounts.critical}, high=${openCounts.high}, medium=${openCounts.medium}, low=${openCounts.low}, info=${openCounts.info}); needs_review=${dispositionCounts.needs_review}; fixed=${dispositionCounts.fixed}.${openTotal > 0 ? " Prioritise open remediation." : " No confirmed open remediation remains in this ledger."}`,
          executive_summary,
          findings: exported,
          candidate_disposition_counts: dispositionCounts,
          review_checkpoint: {
            resumable: true as const,
            next_steps: [
              "The review is resumable: re-run any category tool (secure_mcp_check_authentication, secure_mcp_analyze_injection_risks, secure_mcp_review_secrets) with the same project_root plus focus_paths to resume a partially covered area.",
              "If coverage was truncated or partial, narrow project_root or raise max_files deliberately, then re-run the affected tool before claiming coverage.",
              "For findings with validation_status needs_runtime, schedule owner-authorized runtime/configuration verification (manual QA or existing DAST) before declaring the weakness closed.",
              "After remediation, re-run secure_mcp_produce_findings with disposition fixed and the verification evidence to update the ledger.",
            ],
          },
          notes: [
            "Each finding follows evidence → classify → impact → remediate → verify.",
            "Deferred and reportable are confirmed open work; needs_review is an unconfirmed candidate; fixed/suppressed/accepted_risk/not_applicable are excluded from open risk and remediation_priority.",
            "validation_status labels handoff needs: static_only means code review alone confirms and verifies; needs_runtime means schedule owner-authorized runtime/configuration verification (manual QA or existing DAST).",
            "Do not expand this report into exploit or PoC attack material.",
          ],
        };

        if (params.response_format === "sarif") {
          // Build from already-redacted findings/title/root, then run the whole
          // document through the structural redaction policy once more so no
          // rule id, tag, or property can carry a secret into the export.
          const noticePrefix = `${UNTRUSTED_OUTPUT_NOTICE}\n\n`;
          const contentBudget = Math.max(1, CHARACTER_LIMIT - noticePrefix.length);
          const fitted = buildSarifWithinBudget(exported, title, projectRoot, contentBudget);
          const sarifLog = redactValue(fitted.log) as SarifLog;
          const bounded = boundStructuredPayload(sarifLog, contentBudget);
          let body = JSON.stringify(bounded.data, null, 2);
          if (body.length > contentBudget) body = JSON.stringify(bounded.data);
          return {
            content: [{ type: "text", text: `${noticePrefix}${body}` }],
            structuredContent: bounded.data,
          };
        }

        return toolSuccess(data, {
          responseFormat: params.response_format,
          markdown: renderFindingsReportMarkdown({
            title,
            projectRoot,
            findings: exported,
            counts,
            openCounts,
            dispositionCounts,
          }),
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

function emptySeverityCounts(): Record<Severity, number> {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
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
