/**
 * Pack: threat-model — trust boundaries and STRIDE-oriented control planning.
 */

import type { KnowledgePack } from "./types.js";

export const threatModelPack: KnowledgePack = {
  id: "threat-model",
  title: "Remediation threat model",
  description:
    "Trust-boundary and STRIDE-oriented prompts for placing controls and prioritising hardening.",
  stackTags: ["common"],
  categories: [
    "threat-model",
    "architecture",
    "authentication",
    "authorization",
    "configuration",
    "privacy",
    "secrets",
  ],
  estimatedTokens: 1300,
  items: [
    {
      id: "TM-TRUST-CLIENT-SERVER",
      title: "Client vs server trust boundary",
      description:
        "Treat all client input as untrusted. Enforce authn/authz and validation on the trusted side of each boundary.",
      category: "threat-model",
      severityHint: "high",
      tags: ["trust-boundary", "stride-spoofing"],
      stacks: ["common"],
      impact_if_unremediated:
        "Controls implemented only on the client can be skipped entirely by direct API calls.",
      remediation:
        "List entrypoints crossing the boundary; ensure shared requireAuth/validate helpers run on each.",
      verification_suggestion: "Map entrypoints and confirm server-side checks exist for each sensitive path.",
    },
    {
      id: "TM-SPOOFING-IDENTITY",
      title: "Identity spoofing controls",
      description:
        "Session and identity assertions must come from verified auth state, not client-supplied user IDs.",
      category: "authentication",
      severityHint: "critical",
      cwe: "CWE-287",
      tags: ["stride-spoofing"],
      stacks: ["common"],
      impact_if_unremediated:
        "Callers can act as other users by changing an identifier in the request.",
      remediation: "Bind actions to server session identity; reject client-asserted roles or user ids.",
      verification_suggestion: "Confirm privileged actions never take userId from the request body alone.",
    },
    {
      id: "TM-TAMPERING-INTEGRITY",
      title: "Data and request integrity",
      description:
        "Protect against tampering of tokens, signed payloads, and privileged parameters at trust boundaries.",
      category: "threat-model",
      severityHint: "high",
      cwe: "CWE-345",
      tags: ["stride-tampering"],
      stacks: ["common"],
      impact_if_unremediated:
        "Modified payloads may pass as authentic and change privileged state.",
      remediation:
        "Verify signatures/HMAC where used; re-validate server-side state before mutations.",
      verification_suggestion: "Review signed cookie/JWT and webhook verification paths.",
    },
    {
      id: "TM-REPUDIATION-AUDIT",
      title: "Auditability of sensitive actions",
      description:
        "Privileged mutations should be attributable without logging secrets or excessive PII.",
      category: "threat-model",
      severityHint: "medium",
      tags: ["stride-repudiation", "logging"],
      stacks: ["common"],
      impact_if_unremediated:
        "Incidents cannot be reconstructed or attributed after the fact.",
      remediation:
        "Log actor id, action, resource id, and outcome with redaction; retain for an agreed period.",
      verification_suggestion: "Sample audit logs for completeness and absence of secrets.",
    },
    {
      id: "TM-INFO-DISCLOSURE",
      title: "Information disclosure surfaces",
      description:
        "Error messages, client bundles, logs, and verbose APIs can leak secrets or internal detail.",
      category: "privacy",
      severityHint: "high",
      cwe: "CWE-200",
      tags: ["stride-info-disclosure"],
      stacks: ["common"],
      impact_if_unremediated:
        "Internal structure and occasionally credentials become available to ordinary callers.",
      remediation:
        "Use generic client errors; keep stack traces server-side; scrub secrets from logs and bundles.",
      verification_suggestion: "Trigger error paths and inspect client responses and log samples.",
    },
    {
      id: "TM-DOS-RESOURCE",
      title: "Resource exhaustion controls",
      description:
        "Unauthenticated or expensive endpoints need rate limits, size caps, and timeouts.",
      category: "configuration",
      severityHint: "medium",
      cwe: "CWE-770",
      tags: ["stride-dos"],
      stacks: ["common"],
      impact_if_unremediated:
        "Cheap requests can consume disproportionate capacity and degrade availability.",
      remediation: "Add rate limiting, payload size limits, and request timeouts on costly routes.",
      verification_suggestion: "Confirm limits exist on upload, search, and unauthenticated endpoints.",
    },
    {
      id: "TM-ELEVATION-PRIVILEGE",
      title: "Privilege elevation paths",
      description:
        "Admin, tenant, and role changes must be authorized and preferably dual-controlled or audited.",
      category: "authorization",
      severityHint: "critical",
      cwe: "CWE-269",
      tags: ["stride-elevation"],
      stacks: ["common"],
      impact_if_unremediated:
        "A regular account may grant itself administrative scope.",
      remediation:
        "Gate role changes behind strong authz; never trust client-supplied role fields.",
      verification_suggestion: "Review role/admin mutation endpoints for server-side authorization.",
    },
    {
      id: "TM-SECRETS-BOUNDARY",
      title: "Secrets trust boundary",
      description:
        "Secret material must stay on the trusted side of the boundary (server, Keychain, secret manager).",
      category: "secrets",
      severityHint: "critical",
      cwe: "CWE-922",
      tags: ["secrets", "trust-boundary"],
      stacks: ["common"],
      impact_if_unremediated:
        "Secrets that cross to clients or logs must be treated as disclosed and rotated.",
      remediation:
        "Inventory secret reads; ensure none ship to clients, logs, or world-readable storage.",
      verification_suggestion: "Trace each secret from load site to consumers; confirm no client leakage.",
    },
    {
      id: "TM-THIRD-PARTY",
      title: "Third-party and callback trust",
      description:
        "OAuth callbacks, webhooks, and SDKs expand the trust boundary; verify signatures and origins.",
      category: "threat-model",
      severityHint: "high",
      tags: ["callbacks", "webhooks"],
      stacks: ["common"],
      impact_if_unremediated:
        "Unverified external input can drive privileged workflows inside the application.",
      remediation:
        "Verify webhook signatures; allowlist redirect/callback URLs; pin or review SDK privileges.",
      verification_suggestion: "List external callbacks and confirm signature/origin checks.",
    },
    {
      id: "TM-CONTROL-COVERAGE",
      title: "Control coverage checklist",
      description:
        "For each trust boundary, record which controls exist (authn, authz, validate, encrypt, rate-limit, audit).",
      category: "architecture",
      severityHint: "info",
      tags: ["controls", "planning"],
      stacks: ["common"],
      impact_if_unremediated:
        "Coverage gaps stay invisible and are rediscovered only during incidents.",
      remediation:
        "Fill a per-boundary control matrix; remediate gaps before shipping sensitive features.",
      verification_suggestion: "Compare architecture surface map to the control matrix for gaps.",
    },
  ],
};
