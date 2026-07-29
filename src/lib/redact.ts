import type { CoverageReport, Finding } from "./types.js";

const SECRET_BASENAME_RE =
  /^(?:\.env(?:\.[^/\\:\s]+)?|credentials?(?:\.[^/\\:\s]+)?|service-account(?:\.[^/\\:\s]+)?|GoogleService-Info\.plist|id_(?:rsa|ed25519)|[^/\\:\s]+\.(?:pem|key|p12|pfx|jks|keystore|der|cer|crt))$/i;
const SECRET_PATH_NAME_RE =
  /(?<![A-Za-z0-9_.-])(?:\.env(?:\.[^/\\:\s]+)?|credentials?(?:\.[^/\\:\s]+)?|service-account(?:\.[^/\\:\s]+)?|GoogleService-Info\.plist|id_(?:rsa|ed25519)|[^/\\:\s]+\.(?:pem|key|p12|pfx|jks|keystore|der|cer|crt))(?=[:),;\]}\s"'`]|$)/gi;
const LOCATION_SUFFIX_RE = /^(.*?)(:\d+(?::\d+)?)?$/;

/**
 * Secret-value patterns. Whole PEM blocks must run before any BEGIN-only match
 * so key material between BEGIN/END is not left in the clear.
 */
const SECRET_VALUE_PATTERNS: RegExp[] = [
  /-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----/g,
  /-----BEGIN [^-]+-----[\s\S]*$/g,
  /((?:authorization|proxy-authorization)\s*[:=]\s*)(?:Bearer|Basic)\s+[A-Za-z0-9._+\-/=]{8,}/gi,
  /((?:password|passwd|secret|token|api[_-]?key|private[_-]?key|credential|authorization)\s*[:=]\s*["'`]?)([^\s"'`,;}]+)(["'`]*)/gi,
  /\bAKIA[0-9A-Z]{16}\b/gi,
  /\b(Bearer|Basic)\s+[A-Za-z0-9._+\-/=]{8,}/gi,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
  /\b(?:sk|pk|ghp|github_pat|xox[baprs]-)[A-Za-z0-9_\-]{12,}\b/gi,
];

/** Index of the labeled password/secret capture pattern (prefix + value + suffix). */
const LABELED_SECRET_PATTERN = SECRET_VALUE_PATTERNS[3];

/** Redact a path whose name commonly identifies credential material. */
export function redactedSecretPath(relativePath: string): string {
  return relativePath
    .split("/")
    .map((part) => {
      const match = LOCATION_SUFFIX_RE.exec(part);
      const basename = match?.[1] ?? part;
      if (!SECRET_BASENAME_RE.test(basename)) return part;
      return `[redacted-secret-file]${match?.[2] ?? ""}`;
    })
    .join("/");
}

/** Map inventory paths through secret-path redaction. */
export function redactedSecretPaths(paths: readonly string[]): string[] {
  return paths.map(redactedSecretPath);
}

/** Redact secret-like values while preserving enough context for remediation. */
export function redactedEvidence(raw: string): string {
  const marker = "[REDACTED:****]";
  let output = raw;
  for (const pattern of SECRET_VALUE_PATTERNS) {
    pattern.lastIndex = 0;
    output = output.replace(pattern, (...args: unknown[]) => {
      const match = args[0];
      if (typeof match !== "string") return marker;
      // Labeled secrets keep key name + quotes; PEM/token patterns replace wholly.
      if (pattern === LABELED_SECRET_PATTERN) {
        const prefix = typeof args[1] === "string" ? args[1] : "";
        const suffix = typeof args[3] === "string" ? args[3] : "";
        return `${prefix}${marker}${suffix}`;
      }
      if (
        pattern === SECRET_VALUE_PATTERNS[2] &&
        typeof args[1] === "string"
      ) {
        return `${args[1]}${marker}`;
      }
      return marker;
    });
  }

  output = redactedSecretPath(output);
  return output.replace(SECRET_PATH_NAME_RE, "[redacted-secret-file]");
}

/**
 * Redact secret-like strings on a finding before it crosses an MCP output boundary.
 * Does not alter stable identity fields (id, instance_id, rule_family, root_control, line).
 */
export function redactFinding(finding: Finding): Finding {
  return {
    ...finding,
    title: redactedEvidence(finding.title),
    file: finding.file !== undefined ? redactedSecretPath(finding.file) : undefined,
    evidence: redactedEvidence(finding.evidence),
    description: redactedEvidence(finding.description),
    source: finding.source !== undefined ? redactedEvidence(finding.source) : undefined,
    control: finding.control !== undefined ? redactedEvidence(finding.control) : undefined,
    sink:
      finding.sink !== undefined
        ? redactedEvidence(redactedSecretPath(finding.sink))
        : undefined,
    counterevidence: finding.counterevidence?.map(redactedEvidence),
    proof_gap: finding.proof_gap?.map(redactedEvidence),
    validation: finding.validation?.map(redactedEvidence),
    impact_if_unremediated: redactedEvidence(finding.impact_if_unremediated),
    remediation: redactedEvidence(finding.remediation),
    residual_risk: redactedEvidence(finding.residual_risk),
    verification_suggestion: redactedEvidence(finding.verification_suggestion),
    disposition_reason:
      finding.disposition_reason !== undefined
        ? redactedEvidence(finding.disposition_reason)
        : undefined,
  };
}

/** Redact a list of findings at an output boundary. */
export function redactFindings(findings: readonly Finding[]): Finding[] {
  return findings.map(redactFinding);
}

/**
 * Redact secret-like path names on a coverage report before it crosses an MCP
 * output boundary. Reuses the same path policy as finding file redaction.
 */
export function redactCoverageReport(coverage: CoverageReport): CoverageReport {
  return {
    ...coverage,
    included_paths: redactedSecretPaths(coverage.included_paths),
    excluded_paths: coverage.excluded_paths.map((item) => ({
      ...item,
      path: redactedSecretPath(item.path),
    })),
    ignored_paths: coverage.ignored_paths.map((item) => ({
      ...item,
      path: redactedSecretPath(item.path),
    })),
    files_reviewed: redactedSecretPaths(coverage.files_reviewed),
    candidate_dispositions: coverage.candidate_dispositions.map((item) => ({
      ...item,
      reason: redactedEvidence(item.reason),
      ...(item.file !== undefined ? { file: redactedSecretPath(item.file) } : {}),
    })),
  };
}
