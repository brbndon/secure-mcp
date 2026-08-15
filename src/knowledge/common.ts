/**
 * Stack-agnostic secure-coding knowledge for defensive code review.
 *
 * Checklist items live in knowledge packs (`packs/core`, `packs/secrets`, …).
 * This module keeps scanning patterns used by category detectors.
 */

import {
  AWS_ACCESS_KEY_ID_SHAPE,
  GITHUB_TOKEN_SHAPE,
  JWT_LIKE_TOKEN_SHAPE,
  SLACK_TOKEN_SHAPE,
  STRIPE_SECRET_KEY_SHAPE,
} from "../lib/secret-tokens.js";

/** Patterns that often indicate secret material (heuristic; expect false positives). */
export const SECRET_PATTERNS: {
  name: string;
  regex: RegExp;
  severity: "critical" | "high" | "medium";
  impact_if_unremediated: string;
  remediation: string;
}[] = [
  AWS_ACCESS_KEY_ID_SHAPE,
  {
    name: "Generic API key assignment",
    regex:
      /\b(api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)\b\s*[:=]\s*['"][^'"]{12,}['"]/gi,
    severity: "high",
    impact_if_unremediated:
      "Hardcoded API credentials can be reused by anyone with repository access.",
    remediation: "Move secrets to environment variables or a secret manager; rotate if committed.",
  },
  JWT_LIKE_TOKEN_SHAPE,
  {
    name: "Private key block",
    regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
    severity: "critical",
    impact_if_unremediated:
      "Private keys in repositories can fully compromise associated cryptographic identities.",
    remediation: "Revoke/replace the key pair; remove from git history; store keys in a HSM or secret manager.",
  },
  // Standalone token shapes live in lib/secret-tokens.ts so the secrets
  // detector and the output redactor share one source of truth and cannot
  // drift apart (a detected token is always masked at the output seam).
  GITHUB_TOKEN_SHAPE,
  SLACK_TOKEN_SHAPE,
  STRIPE_SECRET_KEY_SHAPE,
  {
    name: "Password assignment",
    regex: /\b(password|passwd|pwd)\b\s*[:=]\s*['"][^'"]{6,}['"]/gi,
    severity: "high",
    impact_if_unremediated:
      "Hardcoded passwords may unlock accounts or services if still active.",
    remediation: "Remove hardcoded passwords; rotate; use secrets configuration.",
  },
];

/** Injection-risk heuristics for TS/JS and general text (remediation oriented). */
export const INJECTION_PATTERNS: {
  id: string;
  title: string;
  regex: RegExp;
  severity: "critical" | "high" | "medium";
  cwe: string;
  stack: "common" | "typescript";
  recommendation: string;
  impact_if_unremediated: string;
}[] = [
  {
    id: "INJ-EVAL",
    title: "Dynamic code evaluation (eval / Function)",
    regex: /\beval\s*\(|\bnew\s+Function\s*\(/g,
    severity: "critical",
    cwe: "CWE-95",
    stack: "typescript",
    recommendation:
      "Remove eval/Function. Use safe parsers or explicit allowlisted operations instead of dynamic code execution.",
    impact_if_unremediated:
      "If untrusted input reaches dynamic evaluation, application integrity and host safety are at risk.",
  },
  {
    id: "INJ-CHILD-PROCESS",
    title: "Shell or process execution API",
    regex: /\b(exec|execSync|spawn|spawnSync|execFile)\s*\(/g,
    severity: "high",
    cwe: "CWE-78",
    stack: "typescript",
    recommendation:
      "Avoid shell:true; pass fixed executables with argument arrays; never interpolate untrusted input into command strings.",
    impact_if_unremediated:
      "Untrusted influence over process execution can compromise the application host.",
  },
  {
    id: "INJ-SQL-CONCAT",
    title: "Possible SQL string concatenation",
    // Bounded spans only: at most 400 chars between the opening quote and an
    // interpolation marker (${ or + word), and at most 300 chars between a SQL
    // keyword and a quote followed by +. No unbounded greedy wildcards, so
    // repository-controlled text cannot cause superlinear regex work.
    regex:
      /(?:query|sql|execute)\s*(?:=|\()\s*[`'"][^`'"\n]{0,400}(?:\$\{|\+\s*[A-Za-z_$][A-Za-z0-9_$]*)|(?:SELECT|INSERT|UPDATE|DELETE)\s+[^;'"`\n]{0,300}['"`]\s*\+/gi,
    severity: "high",
    cwe: "CWE-89",
    stack: "common",
    recommendation: "Use parameterized queries or ORM bind parameters for all dynamic values.",
    impact_if_unremediated:
      "Unsafe query construction can lead to unauthorized data access or modification.",
  },
  {
    id: "INJ-DANGEROUS-HTML",
    title: "Raw HTML rendering sink",
    regex: /\bdangerouslySetInnerHTML\b|\.innerHTML\s*=/g,
    severity: "high",
    cwe: "CWE-79",
    stack: "typescript",
    recommendation:
      "Avoid raw HTML sinks for untrusted content; sanitize with a trusted library if HTML is required.",
    impact_if_unremediated:
      "Untrusted HTML may execute script in users' browsers and compromise sessions.",
  },
  {
    id: "INJ-PATH-JOIN-USER",
    title: "Path join with request-like segments",
    regex: /path\.(join|resolve)\s*\([^)]*(?:req\.|params\.|query\.|body\.|input)/g,
    severity: "medium",
    cwe: "CWE-22",
    stack: "typescript",
    recommendation:
      "Resolve against a fixed root directory and reject any path that escapes it before file I/O.",
    impact_if_unremediated:
      "Path confusion can expose or overwrite files outside the intended directory.",
  },
];
