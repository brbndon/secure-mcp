/**
 * Stack-agnostic secure-coding knowledge for defensive code review.
 *
 * Checklist items live in knowledge packs (`packs/core`, `packs/secrets`, …).
 * This module keeps scanning patterns and re-exports for backwards compatibility.
 */

import { corePack } from "./packs/core.js";
import type { PackItem } from "./packs/types.js";

/** @deprecated Prefer PackItem from packs/types — kept for existing imports. */
export type ChecklistItem = PackItem;

/** Cross-cutting security checklist (from core pack). */
export const COMMON_CHECKLIST: ChecklistItem[] = corePack.items;

/** Patterns that often indicate secret material (heuristic; expect false positives). */
export const SECRET_PATTERNS: {
  name: string;
  regex: RegExp;
  severity: "critical" | "high" | "medium";
  impact_if_unremediated: string;
  remediation: string;
}[] = [
  {
    name: "AWS access key id",
    regex: /\bAKIA[0-9A-Z]{16}\b/g,
    severity: "critical",
    impact_if_unremediated:
      "Cloud credentials in source may allow unauthorized access to cloud resources.",
    remediation:
      "Rotate the key in the cloud provider console; remove from source; use a secret manager or IAM roles.",
  },
  {
    name: "Generic API key assignment",
    regex:
      /\b(api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key)\b\s*[:=]\s*['"][^'"]{12,}['"]/gi,
    severity: "high",
    impact_if_unremediated:
      "Hardcoded API credentials can be reused by anyone with repository access.",
    remediation: "Move secrets to environment variables or a secret manager; rotate if committed.",
  },
  {
    name: "JWT-like token",
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
    severity: "medium",
    impact_if_unremediated:
      "Embedded tokens may grant session or API access if still valid.",
    remediation: "Remove embedded tokens from source; revoke/rotate; load at runtime only.",
  },
  {
    name: "Private key block",
    regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
    severity: "critical",
    impact_if_unremediated:
      "Private keys in repositories can fully compromise associated cryptographic identities.",
    remediation: "Revoke/replace the key pair; remove from git history; store keys in a HSM or secret manager.",
  },
  {
    name: "GitHub token",
    regex: /\bgh[pousr]_[A-Za-z0-9]{20,}\b/g,
    severity: "critical",
    impact_if_unremediated:
      "Repository or org tokens can allow unauthorized code or settings changes.",
    remediation: "Revoke the token in GitHub settings immediately; use short-lived fine-scoped tokens.",
  },
  {
    name: "Slack token",
    regex: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
    severity: "high",
    impact_if_unremediated:
      "Workspace tokens may allow message or admin operations unintended for the public codebase.",
    remediation: "Revoke in Slack admin; store replacements in a secret manager.",
  },
  {
    name: "Stripe secret key",
    regex: /\bsk_live_[A-Za-z0-9]{16,}\b/g,
    severity: "critical",
    impact_if_unremediated:
      "Live payment credentials can enable unauthorized financial API use.",
    remediation: "Roll the key in Stripe Dashboard; never commit sk_live_ keys.",
  },
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
    regex:
      /(?:query|sql|execute)\s*(?:=|\()\s*[`'"].*(?:\$\{|\+\s*\w+).*[`'"]|(?:SELECT|INSERT|UPDATE|DELETE)\s+[^;]*['"`]\s*\+/gi,
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

export function commonChecklistForCategories(categories?: string[]): ChecklistItem[] {
  if (!categories || categories.length === 0) return COMMON_CHECKLIST;
  const set = new Set(categories.map((c) => c.toLowerCase()));
  return COMMON_CHECKLIST.filter((item) => set.has(item.category.toLowerCase()));
}
