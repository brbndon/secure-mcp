/**
 * Zod schemas for structured findings and tool outputs.
 *
 * FindingSchema is the stable contract for remediation-focused audit results.
 * Every finding must follow: evidence → classify → impact → remediate → verify.
 */

import { z } from "zod";

export const ConfidenceSchema = z.enum(["high", "medium", "low"]);
export const SeveritySchema = z.enum(["critical", "high", "medium", "low", "info"]);
export const StackFocusSchema = z.enum(["common", "typescript", "nextjs", "swift", "expo"]);

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
  return {
    ...partial,
    residual_risk:
      partial.residual_risk ??
      "Some residual risk may remain until the fix is reviewed and regression-tested in the target environment.",
    verification_suggestion:
      partial.verification_suggestion ??
      "Confirm the change in code review; add or update tests that assert the secure behavior; re-run this audit category after the fix.",
  };
}
