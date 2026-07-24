/**
 * Shared types used across tools, knowledge modules, and the MCP server.
 *
 * Framing: all types support defensive secure-code-review —
 * identify weaknesses → classify → recommend remediation.
 */

/** How confident the review is in the evidence for a weakness. */
export type Confidence = "high" | "medium" | "low";

/** Industry-standard severity ladder for prioritized remediation. */
export type Severity = "critical" | "high" | "medium" | "low" | "info";

/** Stack / domain a finding is associated with. */
export type StackFocus = "common" | "typescript" | "nextjs" | "swift" | "expo";

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
export interface Finding {
  /** Stable identifier within a single audit session (e.g. "AUTH-001"). */
  id: string;
  /** Short human-readable title naming the potential weakness. */
  title: string;
  /**
   * Evidence-oriented description of what was observed and why it may be
   * a weakness (no exploit steps).
   */
  description: string;
  /** Classification: how urgent remediation is. */
  severity: Severity;
  /** Classification: how strong the supporting evidence is. */
  confidence: Confidence;
  /** Classification: weakness family (authentication, injection-risk, secrets, …). */
  category: string;
  /** Optional stack focus for filtering. */
  stack?: StackFocus;
  /** Path relative to the project root when available. */
  file?: string;
  /** 1-based line number when available. */
  line?: number;
  /** Observable evidence (snippet, config key, path) supporting the finding. */
  evidence: string;
  /**
   * High-level impact if the weakness is left unremediated.
   * Describe risk to confidentiality/integrity/availability — not how to exploit it.
   */
  impact_if_unremediated: string;
  /** Concrete remediation steps for the development team. */
  remediation: string;
  /** Residual risk remaining after the recommended remediation. */
  residual_risk: string;
  /** How maintainers can verify the fix (tests, code review checks, config audit). */
  verification_suggestion: string;
  /** Optional CWE identifier (e.g. "CWE-89"). */
  cwe?: string;
  /** Optional OWASP category label. */
  owasp?: string;
  /** Free-form tags for agent filtering. */
  tags?: string[];
}

/** Severity ordering for sorting (higher = more urgent to remediate). */
export const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

/** Response format for tool outputs. */
export type ResponseFormat = "json" | "markdown";

/** Common parameters most tools accept. */
export interface ProjectTarget {
  /** Absolute or relative path to the project root to review. */
  project_root: string;
  /** Optional stack hint to focus analysis. */
  stack?: StackFocus | "auto";
  /** Max files to inspect (safety limit). */
  max_files?: number;
  /** Response format. */
  response_format?: ResponseFormat;
}

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
}
