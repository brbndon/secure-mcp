/**
 * Zod schemas for structured findings and tool outputs.
 *
 * FindingSchema is the stable contract for remediation-focused audit results.
 * Every finding must follow: evidence → classify → impact → remediate → verify.
 */

import { z } from "zod";
import { createHash } from "node:crypto";

export const ConfidenceSchema = z.enum(["high", "medium", "low"]);
export const SeveritySchema = z.enum(["critical", "high", "medium", "low", "info"]);
export const StackFocusSchema = z.enum(["common", "typescript", "nextjs", "swift", "expo"]);
export const CandidateDispositionSchema = z.enum([
  "reportable",
  "needs_review",
  "suppressed",
  "not_applicable",
  "deferred",
]);

/**
 * Required shape for every security finding.
 * Forces defensive secure-code-review output (not offensive guidance).
 */
export const FindingSchema = z
  .object({
    id: z
      .string()
      .min(1)
      .describe("Stable finding id within the audit session (e.g. AUTH-001, F-003)"),
    title: z
      .string()
      .min(1)
      .describe("Short name of the potential weakness to remediate"),
    description: z
      .string()
      .min(1)
      .describe(
        "Evidence-oriented description of what was observed; no exploit or attack steps",
      ),
    severity: SeveritySchema.describe(
      "Classification: remediation urgency (critical|high|medium|low|info)",
    ),
    confidence: ConfidenceSchema.describe(
      "Classification: strength of evidence for this weakness (high|medium|low)",
    ),
    category: z
      .string()
      .min(1)
      .describe(
        "Classification family, e.g. authentication, authorization, injection-risk, secrets, configuration",
      ),
    stack: StackFocusSchema.optional().describe("Optional stack focus for filtering"),
    file: z.string().optional().describe("Path relative to project root when known"),
    line: z.number().int().positive().optional().describe("1-based line when known"),
    evidence: z
      .string()
      .min(1)
      .describe(
        "Observable evidence: code snippet, config key, or path supporting the finding",
      ),
    impact_if_unremediated: z
      .string()
      .min(1)
      .describe(
        "High-level impact on confidentiality, integrity, or availability if not fixed — not exploit instructions",
      ),
    remediation: z
      .string()
      .min(1)
      .describe("Concrete steps the development team should take to harden the code"),
    residual_risk: z
      .string()
      .min(1)
      .describe("Risk that may remain after the recommended remediation"),
    verification_suggestion: z
      .string()
      .min(1)
      .describe(
        "How to verify the fix (unit/integration tests, code review checklist, config audit)",
      ),
    cwe: z.string().optional().describe('Optional CWE id, e.g. "CWE-89"'),
    owasp: z.string().optional().describe("Optional OWASP category label"),
    tags: z.array(z.string()).optional().describe("Free-form tags for filtering"),
    rule_family: z
      .string()
      .min(1)
      .optional()
      .describe("Stable detector family, independent of report ordering"),
    root_control: z
      .string()
      .min(1)
      .optional()
      .describe("Stable control/rule identity that produced the candidate"),
    instance_id: z
      .string()
      .min(1)
      .optional()
      .describe("Stable identity for the same source instance across audit runs"),
    disposition: CandidateDispositionSchema.optional().describe(
      "Candidate disposition before human/data-flow confirmation",
    ),
    disposition_reason: z.string().min(1).optional(),
    source: z.string().min(1).optional().describe("Evidence-backed input/source context"),
    control: z.string().min(1).optional().describe("Expected or observed security control"),
    sink: z.string().min(1).optional().describe("Evidence-backed sink or boundary"),
    counterevidence: z.array(z.string().min(1)).optional(),
    proof_gap: z.array(z.string().min(1)).optional(),
    validation: z.array(z.string().min(1)).optional(),
  })
  .strict();

export type FindingInput = z.infer<typeof FindingSchema>;

export const ProjectRootInput = z
  .object({
    project_root: z
      .string()
      .min(1)
      .describe(
        "Absolute path (preferred) or path relative to the MCP server process cwd of the codebase to review for defensive hardening",
      ),
    stack: z
      .enum(["auto", "common", "typescript", "nextjs", "swift", "expo"])
      .default("auto")
      .describe("Optional stack focus. Use auto to detect from project files."),
    max_files: z
      .number()
      .int()
      .min(1)
      .max(5000)
      .optional()
      .describe("Safety cap on how many files tools may inspect (default ~400)"),

    focus_paths: z
      .array(z.string().min(1))
      .max(50)
      .optional()
      .describe(
        "Optional list of relative path prefixes to restrict the walk and analysis to (scoped drill-down). Still subject to max_files. Example: [\"src/app\", \"lib/auth\"].",
      ),
    response_format: z
      .enum(["json", "markdown"])
      .default("json")
      .describe("json for structured agent processing; markdown for human-readable summaries"),
  })
  .strict();

export type ProjectRootInputType = z.infer<typeof ProjectRootInput>;

/** Helper to create sequential finding IDs. */
export function createFindingIdFactory(prefix: string): () => string {
  let n = 0;
  return () => {
    n += 1;
    return `${prefix}-${String(n).padStart(3, "0")}`;
  };
}

/**
 * Build a complete Finding with required remediation-oriented fields.
 * Tools should use this so every finding has the full defensive structure.
 */
export function buildFinding(
  partial: Omit<
    FindingInput,
    "evidence" | "impact_if_unremediated" | "remediation" | "residual_risk" | "verification_suggestion"
  > & {
    evidence: string;
    impact_if_unremediated: string;
    remediation: string;
    residual_risk?: string;
    verification_suggestion?: string;
  },
): FindingInput {
  const ruleFamily = partial.rule_family ?? partial.category;
  const rootControl =
    partial.root_control ??
    partial.tags?.find((tag) => /^[A-Z][A-Z0-9]+(?:-[A-Z0-9]+)+$/.test(tag)) ??
    `${ruleFamily}:unclassified`;
  // Canonicalize identity from detector metadata and source location. Caller-supplied
  // ids are accepted by the input schema for compatibility but never control dedupe.
  const instanceId = createFindingInstanceId({
    rule_family: ruleFamily,
    root_control: rootControl,
    file: partial.file,
    line: partial.line,
    source: partial.source,
    sink: partial.sink,
  });
  return {
    ...partial,
    rule_family: ruleFamily,
    root_control: rootControl,
    instance_id: instanceId,
    disposition: partial.disposition ?? "needs_review",
    disposition_reason:
      partial.disposition_reason ??
      "Heuristic or architecture candidate; confirm source-to-sink reachability before reporting as confirmed.",
    source: partial.source ?? "Source or input flow not established by this bounded static review.",
    control: partial.control ?? "Expected security control requires manual confirmation.",
    sink: partial.sink ?? "Sink or trust boundary not fully established by this heuristic.",
    counterevidence: partial.counterevidence ?? [
      "The detector does not prove reachability, exploitability, or runtime configuration.",
    ],
    proof_gap: partial.proof_gap ?? [
      "Trace the relevant data flow and inspect runtime/configuration context before confirmation.",
    ],
    residual_risk:
      partial.residual_risk ??
      "Some residual risk may remain until the fix is reviewed and regression-tested in the target environment.",
    verification_suggestion:
      partial.verification_suggestion ??
      "Confirm the change in code review; add or update tests that assert the secure behavior; re-run this audit category after the fix.",
    validation: partial.validation ?? [
      partial.verification_suggestion ??
        "Confirm the change in code review; add or update tests that assert the secure behavior; re-run this audit category after the fix.",
    ],
  };
}

/** Add additive traceability defaults to findings received from older callers. */
export function ensureFindingTraceability(finding: FindingInput): FindingInput {
  return buildFinding({ ...finding });
}

/**
 * Build a deterministic instance identity without exposing source content.
 * Identity is location + control only — free-form source/sink prose must not
 * change the hash across runs or after default-text edits.
 */
export function createFindingInstanceId(input: {
  rule_family: string;
  root_control: string;
  file?: string;
  line?: number;
  /** Accepted for API compatibility; ignored for hashing stability. */
  source?: string;
  /** Accepted for API compatibility; ignored for hashing stability. */
  sink?: string;
}): string {
  const seed = [input.rule_family, input.root_control, input.file ?? "", input.line ?? ""].join(
    "\u001f",
  );
  return `${input.rule_family}:${createHash("sha256").update(seed).digest("hex").slice(0, 16)}`;
}
