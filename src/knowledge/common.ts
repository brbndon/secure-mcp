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

/**
 * Path looks like an authorization-sensitive surface (object-level authz /
 * BOLA-IDOR): Next dynamic segments, admin/account/tenant paths, webhooks,
 * server actions, and mobile deep-link/AuthSession entry points.
 * Used to rank inventory and to share identifiers with category tools.
 */
export const AUTHZ_DYNAMIC_SEGMENT_RE = /\/\[[^\]]+\]/;
export const AUTHZ_PATH_SEGMENT_RE =
  /(^|\/)(admin|account|dashboard|settings|profile|billing|checkout|team|teams|org|organizations|users?|members|roles?|permissions?|tenants?)(\/|\.|$)/i;
export const AUTHZ_WEBHOOK_RE = /webhook|stripe-hook|svix|callback/i;
export const AUTHZ_SERVER_ACTION_RE = /(^|\/)actions?\//i;
export const AUTHZ_DEEP_LINK_RE = /authsession|deep.?link|universal.?link|onopenurl|linking/i;

/** Client-supplied object or tenant identifier in handler code. Bounded spans. */
export const OBJECT_OR_TENANT_ID_CODE_RE =
  /\b(?:params|args|input|query)\s*(?:\.|\[)\s*['"]?(?:id|userId|user_id|orgId|org_id|tenantId|tenant_id|accountId|slug)\b|\{\s*params\s*\}\s*:\s*\{[^}]{0,80}\b(?:id|userId|orgId|tenantId)\b|\bconst\s*\{\s*id\s*\}\s*=\s*params\b/i;

/**
 * High-signal owner / tenant / ownership predicate. Does not match prose like
 * `owned: true` or a bare `id` destructure. A where/filter clause only counts
 * as a predicate when an owner/tenant key is paired with a session-derived
 * reference inside the braces — `where: { id: userId }` (client-supplied id)
 * is a BOLA shape, not an ownership check.
 */
export const OWNER_OR_TENANT_PREDICATE_RE =
  /\b(?:owner(?:Id|ship)?|ownedBy|userId|orgId|organizationId|tenantId|accountId)\b[\s\S]{0,80}(?:===|==|!==|!=)|\b(?:===|==|!==|!=)[\s\S]{0,80}\b(?:owner(?:Id|ship)?|ownedBy|userId|orgId|organizationId|tenantId|accountId)\b|\b(?:where|filter)\s*:\s*\{[^}]{0,200}(?:\b(?:userId|ownerId|orgId|tenantId|accountId|user_id)\b[^}]{0,120}\b(?:session|auth|req|ctx|currentUser|principal|claims?|actor|identity|user)\b|\b(?:session|auth|req|ctx|currentUser|principal|claims?|actor|identity|user)\b[^}]{0,120}\b(?:userId|ownerId|orgId|tenantId|accountId|user_id)\b)|\b(?:assertOwner|requireOwner(?:ship)?|authorize(?:Resource|Object)?|canAccess|ownsResource|ensureOwner(?:ship)?|checkOwnership)\s*\(/i;

/** Path looks like an authorization-sensitive surface. Exported for tests. */
export function isAuthzSensitivePath(relativePath: string): boolean {
  if (!relativePath) return false;
  const lower = relativePath.toLowerCase();
  if (AUTHZ_DYNAMIC_SEGMENT_RE.test(relativePath)) return true;
  if (AUTHZ_PATH_SEGMENT_RE.test(relativePath)) return true;
  if (AUTHZ_WEBHOOK_RE.test(lower)) return true;
  if (AUTHZ_SERVER_ACTION_RE.test(lower)) return true;
  if (AUTHZ_DEEP_LINK_RE.test(lower)) return true;
  return false;
}

/** Path carries an object or tenant identifier (dynamic segment or resource noun). */
export function hasObjectOrTenantIdentifierPath(relativePath: string): boolean {
  if (AUTHZ_DYNAMIC_SEGMENT_RE.test(relativePath)) return true;
  return /(^|\/)(users?|members|orgs?|organizations|tenants?|accounts?)(\/|\.|$)/i.test(
    relativePath,
  );
}

/** Handler body compares a resource to the caller (owner / tenant / membership). */
export function hasOwnerOrTenantPredicate(content: string): boolean {
  if (!content) return false;
  // Neutralize identifier validation guards (userId == null, userId !== undefined,
  // null === ownerId, …) before predicate matching: a null/undefined check is
  // input validation, not an ownership comparison, and must not hide a real
  // missing-check gap. Remaining owner-keyword comparisons still match below.
  const stripped = content.replace(
    /\b(?:null|undefined)\s*(?:===|==|!==|!=)\s*[\w.$[\]]+|\b[\w.$[\]]+\s*(?:===|==|!==|!=)\s*(?:null|undefined)\b/g,
    " ",
  );
  OWNER_OR_TENANT_PREDICATE_RE.lastIndex = 0;
  return OWNER_OR_TENANT_PREDICATE_RE.test(stripped);
}

/** Handler body reads a client-supplied object or tenant identifier. */
export function hasObjectOrTenantIdentifierCode(content: string): boolean {
  if (!content) return false;
  OBJECT_OR_TENANT_ID_CODE_RE.lastIndex = 0;
  return OBJECT_OR_TENANT_ID_CODE_RE.test(content);
}
