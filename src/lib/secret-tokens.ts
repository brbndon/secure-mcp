/**
 * Canonical standalone secret-token shapes shared by the secrets detector and
 * the output redactor.
 *
 * A token shape added here is detected AND redacted from its first day, so a
 * detector hit can never cross the MCP output seam unmasked. Labeled
 * key=value assignments and PEM blocks are handled by their own patterns in
 * lib/redact.ts and the generic entries in SECRET_PATTERNS; this module owns
 * the standalone token shapes that both sides must agree on.
 */

export interface SecretTokenShape {
  /** Detector display name used in findings. */
  name: string;
  /** Global detector regex (required by detectWithBudget). */
  regex: RegExp;
  /** Optional broader output-only regex; detector matches remain a strict subset. */
  redactionRegex?: RegExp;
  severity: "critical" | "high" | "medium";
  impact_if_unremediated: string;
  remediation: string;
}

export const AWS_ACCESS_KEY_ID_SHAPE: SecretTokenShape = {
  name: "AWS access key id",
  // Preserve the detector's provider-defined uppercase form. The redactor is
  // deliberately case-insensitive so previously masked prose stays masked.
  regex: /\bAKIA[0-9A-Z]{16}\b/g,
  redactionRegex: /\bAKIA[0-9A-Z]{16}\b/gi,
  severity: "critical",
  impact_if_unremediated:
    "Cloud credentials in source may allow unauthorized access to cloud resources.",
  remediation:
    "Rotate the key in the cloud provider console; remove from source; use a secret manager or IAM roles.",
};

export const GITHUB_TOKEN_SHAPE: SecretTokenShape = {
  name: "GitHub token",
  // Classic tokens retain the historical 20-character detector floor. Fine-
  // grained PATs are added here so both token families cross the same seam.
  regex: /\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_\-]{12,})\b/g,
  redactionRegex: /\b(?:gh[pousr]_|github_pat)[A-Za-z0-9_\-]{12,}\b/gi,
  severity: "critical",
  impact_if_unremediated:
    "Repository or org tokens can allow unauthorized code or settings changes.",
  remediation:
    "Revoke the token in GitHub settings immediately; use short-lived fine-scoped tokens.",
};

export const SLACK_TOKEN_SHAPE: SecretTokenShape = {
  name: "Slack token",
  regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
  // The output seam also masks case and underscore variants conservatively.
  redactionRegex: /\bxox[baprs]-[A-Za-z0-9_\-]{10,}\b/gi,
  severity: "high",
  impact_if_unremediated:
    "Workspace tokens may allow message or admin operations unintended for the public codebase.",
  remediation: "Revoke in Slack admin; store replacements in a secret manager.",
};

export const STRIPE_SECRET_KEY_SHAPE: SecretTokenShape = {
  name: "Stripe secret key",
  regex: /\bsk_live_[A-Za-z0-9]{16,}\b/g,
  redactionRegex: /\bsk_live_[A-Za-z0-9_\-]{12,}\b/gi,
  severity: "critical",
  impact_if_unremediated:
    "Live payment credentials can enable unauthorized financial API use.",
  remediation: "Roll the key in Stripe Dashboard; never commit sk_live_ keys.",
};

export const JWT_LIKE_TOKEN_SHAPE: SecretTokenShape = {
  name: "JWT-like token",
  regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
  severity: "medium",
  impact_if_unremediated:
    "Embedded tokens may grant session or API access if still valid.",
  remediation: "Remove embedded tokens from source; revoke/rotate; load at runtime only.",
};

export const SECRET_TOKEN_SHAPES: readonly SecretTokenShape[] = [
  AWS_ACCESS_KEY_ID_SHAPE,
  GITHUB_TOKEN_SHAPE,
  SLACK_TOKEN_SHAPE,
  STRIPE_SECRET_KEY_SHAPE,
  JWT_LIKE_TOKEN_SHAPE,
];

/** Regexes the output redactor applies for the standalone token shapes. */
export const SECRET_TOKEN_REGEXES: readonly RegExp[] = SECRET_TOKEN_SHAPES.map(
  (shape) => shape.redactionRegex ?? shape.regex,
);
