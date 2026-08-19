/**
 * Pack: auth-web — sessions, cookies, CSRF, common web auth hardening.
 */

import type { KnowledgePack } from "./types.js";

export const authWebPack: KnowledgePack = {
  id: "auth-web",
  title: "Web authentication hardening",
  description:
    "Browser session cookies, CSRF, OAuth callbacks, and common web authn/authz hardening checks.",
  stackTags: ["nextjs", "typescript"],
  categories: ["authentication", "authorization"],
  estimatedTokens: 1200,
  items: [
    {
      id: "AUTHWEB-COOKIE-FLAGS",
      title: "Secure session cookie flags",
      description:
        "Session cookies should be HttpOnly, Secure, and SameSite=Lax or Strict as appropriate.",
      category: "authentication",
      severityHint: "high",
      cwe: "CWE-614",
      tags: ["cookies", "session"],
      stacks: ["nextjs", "typescript"],
      impact_if_unremediated:
        "Session cookies may be readable by scripts or sent over cleartext connections.",
      remediation: "Set HttpOnly + Secure + appropriate SameSite on session cookies in production.",
      verification_suggestion: "Inspect Set-Cookie headers in a production-like response.",
    },
    {
      id: "AUTHWEB-CSRF",
      title: "CSRF on cookie-authenticated mutations",
      description:
        "Cookie-based sessions need CSRF protections for state-changing requests. Prefer SameSite cookies and framework CSRF patterns.",
      category: "authentication",
      severityHint: "medium",
      cwe: "CWE-352",
      tags: ["csrf"],
      stacks: ["nextjs", "typescript"],
      impact_if_unremediated:
        "Cross-site requests may trigger authenticated state changes without user intent.",
      remediation:
        "Use SameSite=Lax/Strict cookies, CSRF tokens where needed, and avoid overly permissive CORS with credentials.",
      verification_suggestion: "Confirm mutation endpoints require CSRF token or SameSite-safe cookies.",
    },
    {
      id: "AUTHWEB-SESSION-STORE",
      title: "Server-side session authority",
      description:
        "Do not trust client-only session blobs. Prefer server sessions or signed, short-lived tokens with revocation.",
      category: "authentication",
      severityHint: "high",
      cwe: "CWE-384",
      tags: ["session"],
      stacks: ["typescript"],
      impact_if_unremediated:
        "Sessions cannot be revoked promptly, so compromised or stale sessions stay valid.",
      remediation: "Store session state server-side or use short-lived signed tokens with rotation.",
      verification_suggestion: "Confirm logout/revocation invalidates server session or token family.",
    },
    {
      id: "AUTHWEB-OAUTH-CALLBACK",
      title: "OAuth callback and state validation",
      description:
        "Validate OAuth state/nonce, restrict redirect_uri to allowlisted URLs, and bind tokens to the initiating session.",
      category: "authentication",
      severityHint: "high",
      cwe: "CWE-601",
      tags: ["oauth"],
      stacks: ["typescript"],
      impact_if_unremediated:
        "Auth codes or tokens may be bound to the wrong session or delivered to an untrusted host.",
      remediation: "Enforce state checks and an exact redirect_uri allowlist; reject open redirects.",
      verification_suggestion: "Review auth callback handlers for state and redirect_uri validation.",
    },
    {
      id: "AUTHWEB-PASSWORD-STORAGE",
      title: "Password hashing",
      description:
        "Store passwords with modern KDFs (argon2/bcrypt/scrypt). Never store reversible password encryption for login.",
      category: "authentication",
      severityHint: "critical",
      cwe: "CWE-916",
      tags: ["passwords"],
      stacks: ["typescript"],
      impact_if_unremediated:
        "A database disclosure would expose reusable account passwords directly.",
      remediation: "Use argon2id or bcrypt with adequate cost; migrate legacy hashes on login.",
      verification_suggestion: "Confirm password write path uses a modern KDF only.",
    },
    {
      id: "AUTHWEB-RESET-TOKENS",
      title: "Password reset token hygiene",
      description:
        "Reset tokens must be single-use, short-lived, and stored hashed. Do not leak existence of accounts in responses.",
      category: "authentication",
      severityHint: "high",
      cwe: "CWE-640",
      tags: ["reset"],
      stacks: ["typescript"],
      impact_if_unremediated:
        "Long-lived or replayable reset links become an account-takeover path.",
      remediation: "Hash tokens at rest; expire quickly; use generic success messages.",
      verification_suggestion: "Review reset flow for TTL, single-use, and response wording.",
    },
    {
      id: "AUTHWEB-OBJECT-LEVEL",
      title: "Object-level checks on identifier-bearing routes",
      description:
        "A session check is not an ownership check. Handlers that take :id, org, or tenant params must compare the resource owner or tenant to the authenticated principal before read or write.",
      category: "authorization",
      severityHint: "high",
      cwe: "CWE-639",
      tags: ["idor", "authz", "object-level"],
      stacks: ["nextjs", "typescript"],
      impact_if_unremediated:
        "Any authenticated caller who can guess an identifier may read or change another user's objects.",
      remediation:
        "After authenticating, enforce an owner or tenant predicate derived from the session before the data access.",
      verification_suggestion:
        "Open each dynamic [id]/org/tenant handler and confirm an owner or tenant predicate next to the identifier use.",
    },
    {
      id: "AUTHWEB-RBAC",
      title: "Role checks on privileged routes",
      description:
        "Admin and elevated roles must be enforced server-side on every privileged route and action.",
      category: "authorization",
      severityHint: "critical",
      cwe: "CWE-285",
      tags: ["rbac"],
      stacks: ["typescript"],
      impact_if_unremediated:
        "Ordinary accounts may reach administrative data or actions.",
      remediation: "Centralize requireRole helpers; never trust client role claims alone.",
      verification_suggestion: "List admin routes and confirm requireRole (or equivalent) on each.",
    },
    {
      id: "AUTHWEB-LOGOUT",
      title: "Complete logout",
      description:
        "Logout should invalidate server session and clear auth cookies; refresh tokens must be revoked when used.",
      category: "authentication",
      severityHint: "medium",
      tags: ["logout"],
      stacks: ["typescript"],
      impact_if_unremediated:
        "Sessions remain usable after the user believes they signed out, including on shared devices.",
      remediation: "Destroy server session; clear cookies; revoke refresh tokens on logout.",
      verification_suggestion: "After logout, confirm session cookie and refresh token no longer work.",
    },
    {
      id: "AUTHWEB-MFA",
      title: "Step-up for sensitive actions",
      description:
        "High-risk actions (change email, add payment method, disable MFA) should require recent authentication or MFA.",
      category: "authentication",
      severityHint: "medium",
      tags: ["mfa", "step-up"],
      stacks: ["typescript"],
      impact_if_unremediated:
        "A single hijacked session can complete permanent account-takeover changes.",
      remediation: "Require re-auth or MFA challenge before sensitive account changes.",
      verification_suggestion: "Confirm sensitive account mutations check auth age or MFA.",
    },
    {
      id: "AUTHWEB-JWT-HYGIENE",
      title: "JWT algorithm and secret hygiene",
      description:
        "Reject alg=none; use asymmetric keys or strong secrets from env; keep short expirations and validate audience/issuer.",
      category: "authentication",
      severityHint: "high",
      cwe: "CWE-347",
      tags: ["jwt"],
      stacks: ["typescript"],
      impact_if_unremediated:
        "Weak verification lets forged or foreign-issued tokens pass as valid sessions.",
      remediation: "Pin allowed algorithms; load secrets from env; validate exp/aud/iss.",
      verification_suggestion: "Inspect JWT verify options for algorithm allowlist and claim checks.",
    },
  ],
};
