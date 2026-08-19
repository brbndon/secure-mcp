/**
 * Pack: core — stack-agnostic authz, injection, secrets, crypto, logging.
 */

import type { KnowledgePack } from "./types.js";

export const corePack: KnowledgePack = {
  id: "core",
  title: "Core secure coding",
  description:
    "Stack-agnostic controls: authorization, injection-risk, secrets, crypto, logging, paths, dependencies.",
  stackTags: ["common"],
  categories: [
    "authentication",
    "authorization",
    "injection-risk",
    "secrets",
    "cryptography",
    "privacy",
    "supply-chain",
  ],
  estimatedTokens: 1200,
  items: [
    {
      id: "CMN-AUTH-SESSION",
      title: "Session and token handling",
      description:
        "Tokens and session identifiers should not appear in URLs, logs, or unprotected client storage. Prefer httpOnly secure cookies or platform secure storage.",
      category: "authentication",
      severityHint: "high",
      cwe: "CWE-522",
      tags: ["session", "tokens"],
      stacks: ["common"],
      impact_if_unremediated:
        "Session material may leak and allow account takeover if left in insecure locations.",
      remediation:
        "Store sessions in httpOnly Secure cookies or platform Keychain-equivalents; never log tokens.",
      verification_suggestion: "Search for token writes to localStorage, URLs, and logs; confirm secure storage.",
    },
    {
      id: "CMN-AUTHZ-IDOR",
      title: "Object-level authorization",
      description:
        "Every resource access should enforce ownership or role checks server-side. Do not trust client-supplied user IDs alone.",
      category: "authorization",
      severityHint: "critical",
      cwe: "CWE-639",
      tags: ["idor", "authz"],
      stacks: ["common"],
      impact_if_unremediated:
        "Users may read or modify other users' data if authorization is incomplete.",
      remediation:
        "Derive identity from the authenticated session and enforce ownership checks on every object operation.",
      verification_suggestion:
        "Review each object fetch/update — especially dynamic [id] and tenant-scoped handlers — for a session-derived owner or tenant predicate next to the identifier.",
    },
    {
      id: "CMN-INJ-COMMAND",
      title: "Unsafe command construction",
      description:
        "Avoid passing untrusted input into shell execution APIs (exec, spawn with shell:true, Process, NSTask with shell).",
      category: "injection-risk",
      severityHint: "critical",
      cwe: "CWE-78",
      tags: ["command-construction"],
      stacks: ["common"],
      impact_if_unremediated:
        "Untrusted input influencing a shell can lead to arbitrary command execution on the host.",
      remediation:
        "Prefer non-shell APIs with argument arrays; validate and allowlist any required parameters.",
      verification_suggestion: "Grep for shell/exec APIs and confirm no untrusted string interpolation.",
    },
    {
      id: "CMN-INJ-SQL",
      title: "Unsafe query construction",
      description:
        "Use parameterized queries or ORM bind parameters. Avoid string-concatenating SQL or predicates with user input.",
      category: "injection-risk",
      severityHint: "critical",
      cwe: "CWE-89",
      tags: ["query-construction"],
      stacks: ["common"],
      impact_if_unremediated:
        "Data integrity and confidentiality can be compromised through crafted query input.",
      remediation: "Use bind parameters / parameterized queries exclusively for dynamic values.",
      verification_suggestion: "Confirm all dynamic queries use bind parameters; no string-built SQL.",
    },
    {
      id: "CMN-XSS",
      title: "Untrusted HTML rendering",
      description:
        "Avoid rendering untrusted HTML. Prefer safe templating; sanitize when HTML is required.",
      category: "injection-risk",
      severityHint: "high",
      cwe: "CWE-79",
      tags: ["xss"],
      stacks: ["common"],
      impact_if_unremediated:
        "Untrusted script may run in a user's browser session if HTML sinks are misused.",
      remediation:
        "Remove raw HTML sinks or sanitize with a maintained library; prefer text-only rendering.",
      verification_suggestion: "Inventory HTML sinks and confirm sanitization or removal.",
    },
    {
      id: "CMN-SECRETS",
      title: "Hardcoded secrets",
      description:
        "API keys, private keys, passwords, and tokens must not be committed. Use env vars or a secret manager.",
      category: "secrets",
      severityHint: "critical",
      cwe: "CWE-798",
      tags: ["secrets"],
      stacks: ["common"],
      impact_if_unremediated:
        "Committed credentials can grant unintended access to production systems.",
      remediation:
        "Rotate exposed credentials; load secrets from environment or a secret manager; scrub git history if needed.",
      verification_suggestion: "Run secrets review; confirm rotated keys and no remaining literals.",
    },
    {
      id: "CMN-CRYPTO",
      title: "Cryptography misuse",
      description:
        "Use modern libraries and algorithms (AES-GCM, ChaCha20-Poly1305, bcrypt/argon2). Avoid MD5/SHA1 for security, ECB mode, and homemade crypto.",
      category: "cryptography",
      severityHint: "high",
      cwe: "CWE-327",
      tags: ["crypto"],
      stacks: ["common"],
      impact_if_unremediated:
        "Weak cryptography can undermine confidentiality or integrity of protected data.",
      remediation: "Migrate to vetted libraries and modern algorithms; avoid custom crypto protocols.",
      verification_suggestion: "List crypto call sites; confirm algorithms and libraries are current.",
    },
    {
      id: "CMN-LOGGING",
      title: "Sensitive data in logs",
      description:
        "Do not log passwords, tokens, full PANs, session cookies, or PII without redaction.",
      category: "privacy",
      severityHint: "medium",
      cwe: "CWE-532",
      tags: ["logging"],
      stacks: ["common"],
      impact_if_unremediated:
        "Log aggregation systems may become an unintended store of secrets or PII.",
      remediation: "Redact sensitive fields; use privacy-aware logging APIs; audit log samples.",
      verification_suggestion: "Sample production-like logs for tokens, passwords, and raw PII.",
    },
    {
      id: "CMN-DEPS",
      title: "Dependency hygiene",
      description:
        "Keep lockfiles committed, review new packages, and monitor for known vulnerabilities.",
      category: "supply-chain",
      severityHint: "medium",
      cwe: "CWE-1104",
      tags: ["dependencies"],
      stacks: ["common"],
      impact_if_unremediated:
        "Known vulnerable dependencies can introduce remediable weaknesses into production.",
      remediation: "Pin versions, review additions, and run SCA tooling in CI.",
      verification_suggestion: "Confirm lockfile is committed and SCA runs in CI.",
    },
    {
      id: "CMN-PATH",
      title: "Unsafe path handling",
      description:
        "Normalize and constrain file paths to an allowlisted root before reading or writing user-influenced paths.",
      category: "injection-risk",
      severityHint: "high",
      cwe: "CWE-22",
      tags: ["path-handling"],
      stacks: ["common"],
      impact_if_unremediated:
        "Path confusion can allow reading or writing files outside the intended directory.",
      remediation:
        "Resolve against a fixed root and reject paths that escape it before any file operation.",
      verification_suggestion: "Review path join sites that take request input; confirm root confinement.",
    },
  ],
};
