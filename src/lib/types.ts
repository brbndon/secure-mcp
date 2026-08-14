/**
 * Shared types used across tools, knowledge modules, and the MCP server.
 *
 * Framing: all types support defensive secure-code-review —
 * identify weaknesses → classify → recommend remediation.
 */

import {
  CandidateDispositionSchema,
  ConfidenceSchema,
  FindingSchema,
  SeveritySchema,
  StackFocusSchema,
} from "../knowledge/findings-schema.js";
import type { z } from "zod";

/** How confident the review is in the evidence for a weakness. */
export type Confidence = z.infer<typeof ConfidenceSchema>;

/** Industry-standard severity ladder for prioritized remediation. */
export type Severity = z.infer<typeof SeveritySchema>;

/** Stack / domain a finding is associated with. */
export type StackFocus = z.infer<typeof StackFocusSchema>;

/** How a heuristic candidate should be handled before it becomes a confirmed finding. */
export type CandidateDisposition = z.infer<typeof CandidateDispositionSchema>;

export const CANDIDATE_DISPOSITIONS: readonly CandidateDisposition[] =
  CandidateDispositionSchema.options;

export interface CandidateDispositionPolicy {
  /** Confirmed work that remains unresolved and contributes to open risk. */
  openWork: boolean;
  /** Eligible for the high/critical remediation queue (including candidates awaiting proof). */
  remediationPriority: boolean;
  /** Sort rank before severity; confirmed open work outranks unconfirmed candidates. */
  sortRank: number;
}

/**
 * Exhaustive disposition semantics shared by report sorting, risk accounting,
 * and remediation-priority filtering. `deferred` is confirmed open work;
 * `needs_review` is a candidate queue; fixed/suppressed/accepted_risk/not_applicable are closed.
 */
export const CANDIDATE_DISPOSITION_POLICY = {
  reportable: { openWork: true, remediationPriority: true, sortRank: 2 },
  deferred: { openWork: true, remediationPriority: true, sortRank: 2 },
  needs_review: { openWork: false, remediationPriority: true, sortRank: 1 },
  fixed: { openWork: false, remediationPriority: false, sortRank: 0 },
  suppressed: { openWork: false, remediationPriority: false, sortRank: 0 },
  accepted_risk: { openWork: false, remediationPriority: false, sortRank: 0 },
  not_applicable: { openWork: false, remediationPriority: false, sortRank: 0 },
} as const satisfies Record<CandidateDisposition, CandidateDispositionPolicy>;

export function candidateDispositionPolicy(
  disposition: CandidateDisposition | undefined,
): CandidateDispositionPolicy {
  return CANDIDATE_DISPOSITION_POLICY[disposition ?? "needs_review"];
}

export interface CoveragePathDecision {
  path: string;
  kind: "file" | "directory" | "symlink" | "other";
  reason: string;
}

export interface CoverageCandidateDisposition {
  id: string;
  disposition: CandidateDisposition;
  reason: string;
  file?: string;
  line?: number;
  rule_family?: string;
  instance_id?: string;
}

/** Explicit scope accounting for bounded read-only reviews. */
export interface CoverageReport {
  included_paths: string[];
  excluded_paths: CoveragePathDecision[];
  ignored_paths: CoveragePathDecision[];
  caps: {
    max_files: number;
    max_depth: number;
    max_file_bytes: number;
    max_total_bytes?: number;
  };
  truncation: {
    truncated: boolean;
    reasons: string[];
    coverage_events_truncated: boolean;
  };
  files_reviewed: string[];
  candidate_dispositions: CoverageCandidateDisposition[];
  candidate_disposition_counts: Record<CandidateDisposition, number>;
  /**
   * What the review actually inspected. `inventory_only` means only path
   * metadata was collected — file contents were never opened or evaluated.
   */
  review_basis?: "content_review" | "inventory_only";
  scan_status: "complete" | "partial" | "truncated";
  not_observed_means:
    | "no_candidate_in_files_reviewed"
    | "scope_was_truncated_or_partial"
    | "inventory_only_contents_not_reviewed";
}

/**
 * Canonical security finding returned by audit tools.
 *
 * Required narrative structure (defensive only):
 * 1. evidence — what was observed in the codebase
 * 2. classification — severity, confidence, category, optional CWE/OWASP
 * 3. impact_if_unremediated — high-level risk if the team does not fix it
 * 4. remediation — concrete steps to harden the code
 * 5. residual_risk / verification_suggestion — after the fix
 *
 * Do not use this shape for exploit instructions or attack playbooks.
 * Keep field names stable — agents and sub-agents depend on them.
 */
export type Finding = z.infer<typeof FindingSchema>;

/** Severity ordering for sorting (higher = more urgent to remediate). */
export const SEVERITY_ORDER = Object.fromEntries(
  SeveritySchema.options.map((severity, index, severities) => [
    severity,
    severities.length - index,
  ]),
) as Record<Severity, number>;

/** Response format for tool outputs. */
export type ResponseFormat = "json" | "markdown";

/**
 * Standard tool success envelope.
 * Tools should return this shape (or a compatible superset) as structuredContent.
 */
export interface ToolResultBase {
  ok: true;
  project_root: string;
  summary: string;
  truncated?: boolean;
  notes?: string[];
}

export interface ToolErrorResult {
  ok: false;
  error: string;
  code?: string;
  hint?: string;
  output_trust?: "untrusted";
  output_notice?: string;
}

export type ToolResult<T extends object = object> = (ToolResultBase & T) | ToolErrorResult;

/** Detected project characteristics used by multiple tools. */
export interface ProjectProfile {
  root: string;
  hasPackageJson: boolean;
  hasNextConfig: boolean;
  hasTsConfig: boolean;
  hasPackageSwift: boolean;
  hasXcodeProject: boolean;
  hasSwiftFiles: boolean;
  hasTypeScriptFiles: boolean;
  /** Expo or React Native signals (package.json / app config). */
  hasExpo: boolean;
  /** Conservative macOS Swift/AppKit signals. */
  hasMacOS: boolean;
  likelyStacks: StackFocus[];
  topLevelEntries: string[];
  topLevelEntriesTruncated: boolean;
}
