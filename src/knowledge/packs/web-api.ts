/**
 * Pack: web-api — general API route/handler hardening (framework-agnostic leanings).
 */

import type { KnowledgePack } from "./types.js";

export const webApiPack: KnowledgePack = {
  id: "web-api",
  title: "Web API hardening",
  description:
    "General API route/handler controls: authz per method, input validation, CORS, rate limits, error hygiene.",
  stackTags: ["typescript", "nextjs", "expo"],
  categories: ["authorization", "injection-risk", "configuration", "authentication"],
  estimatedTokens: 1000,
  items: [
    {
      id: "API-AUTHZ-PER-METHOD",
      title: "Authorize every HTTP method",
      description:
        "GET/POST/PUT/PATCH/DELETE handlers each need explicit authentication and authorization—sharing one check only at the router root is not enough.",
      category: "authorization",
      severityHint: "high",
      cwe: "CWE-285",
      tags: ["api", "authz"],
      stacks: ["typescript"],
      remediation: "Apply shared auth helpers in each exported method; fail closed on missing session.",
      verification_suggestion: "Open each handler method and confirm a session/role check.",
    },
    {
      id: "API-INPUT-VALIDATE",
      title: "Schema-validate request bodies and query",
      description:
        "Parse and validate JSON bodies, query strings, and path params with a schema library before business logic.",
      category: "injection-risk",
      severityHint: "high",
      cwe: "CWE-20",
      tags: ["validation"],
      stacks: ["typescript"],
      remediation: "Use Zod (or equivalent) at the handler boundary; reject unknown fields when appropriate.",
      verification_suggestion: "Confirm handlers reject malformed payloads with 400-class responses.",
    },
    {
      id: "API-CORS",
      title: "Restrict CORS with credentials",
      description:
        "Avoid Access-Control-Allow-Origin: * with credentials. Allowlist trusted origins explicitly.",
      category: "configuration",
      severityHint: "high",
      cwe: "CWE-942",
      tags: ["cors"],
      stacks: ["typescript"],
      remediation: "Configure an origin allowlist; never combine wildcard origins with cookies.",
      verification_suggestion: "Inspect CORS middleware/config for wildcard + credentials combinations.",
    },
    {
      id: "API-RATE-LIMIT",
      title: "Rate-limit sensitive endpoints",
      description:
        "Login, password reset, search, and expensive mutations need rate limits and lockout/backoff strategies.",
      category: "configuration",
      severityHint: "medium",
      cwe: "CWE-770",
      tags: ["rate-limit"],
      stacks: ["typescript"],
      remediation: "Add per-IP and per-account limits on auth and costly routes.",
      verification_suggestion: "Confirm rate-limit middleware or edge rules cover auth endpoints.",
    },
    {
      id: "API-ERROR-HYGIENE",
      title: "Generic client error responses",
      description:
        "Do not return stack traces, SQL errors, or internal paths to clients. Log detail server-side only.",
      category: "privacy",
      severityHint: "medium",
      cwe: "CWE-209",
      tags: ["errors"],
      stacks: ["typescript"],
      remediation: "Map exceptions to stable error codes; keep diagnostics in server logs with redaction.",
      verification_suggestion: "Trigger failure paths and inspect client-visible error bodies.",
    },
    {
      id: "API-IDEMPOTENCY",
      title: "Protect state-changing retries",
      description:
        "Payment and create operations should use idempotency keys or unique constraints to avoid duplicate side effects.",
      category: "configuration",
      severityHint: "medium",
      tags: ["idempotency"],
      stacks: ["typescript"],
      remediation: "Accept idempotency keys for critical POSTs; enforce uniqueness in storage.",
      verification_suggestion: "Review create/payment handlers for duplicate-submit protection.",
    },
    {
      id: "API-CONTENT-TYPE",
      title: "Enforce expected content types",
      description:
        "Reject unexpected Content-Type values for JSON APIs to reduce parser-confusion risks.",
      category: "configuration",
      severityHint: "low",
      tags: ["content-type"],
      stacks: ["typescript"],
      remediation: "Require application/json (or documented types) before parsing bodies.",
      verification_suggestion: "Send wrong Content-Type and confirm rejection.",
    },
    {
      id: "API-PAGINATION-CAPS",
      title: "Cap list query fan-out",
      description:
        "Unbounded limit/offset or graph expansions can exhaust resources. Cap page sizes server-side.",
      category: "configuration",
      severityHint: "medium",
      cwe: "CWE-770",
      tags: ["pagination"],
      stacks: ["typescript"],
      remediation: "Clamp limit parameters; set hard maxima independent of client input.",
      verification_suggestion: "Confirm list endpoints ignore or clamp oversized limit values.",
    },
    {
      id: "API-WEBHOOK-VERIFY",
      title: "Verify inbound webhooks",
      description:
        "Webhook handlers must verify signatures and timestamps before acting on payloads.",
      category: "authentication",
      severityHint: "high",
      cwe: "CWE-345",
      tags: ["webhooks"],
      stacks: ["typescript"],
      remediation: "Validate provider signatures with raw body; reject stale timestamps.",
      verification_suggestion: "Review webhook routes for signature verification before side effects.",
    },
    {
      id: "API-AUTHN-TRANSPORT",
      title: "Tokens only over HTTPS",
      description:
        "API credentials and session cookies must only be accepted on TLS; reject cleartext in production.",
      category: "authentication",
      severityHint: "high",
      cwe: "CWE-319",
      tags: ["tls"],
      stacks: ["typescript"],
      remediation: "Enforce HTTPS at the edge; set Secure cookies; fail closed without TLS in prod.",
      verification_suggestion: "Confirm production redirects HTTP→HTTPS and Secure cookie flags.",
    },
  ],
};
