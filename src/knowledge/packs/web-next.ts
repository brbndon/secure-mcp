/**
 * Pack: web-next — Next.js App Router, middleware, Server Actions, NEXT_PUBLIC_.
 */

import type { KnowledgePack } from "./types.js";

export const webNextPack: KnowledgePack = {
  id: "web-next",
  title: "Next.js App Router hardening",
  description:
    "Next.js-specific controls: middleware depth, Server Actions, Route Handlers, public env, SSR sinks.",
  stackTags: ["nextjs", "typescript"],
  categories: ["authentication", "authorization", "secrets", "injection-risk", "configuration"],
  estimatedTokens: 1100,
  items: [
    {
      id: "NEXT-MIDDLEWARE-AUTH",
      title: "Middleware alone is not complete authorization",
      description:
        "Next.js middleware matchers may not cover every Route Handler, Server Action, or RSC data path. Re-enforce authentication and authorization at each sensitive server entrypoint.",
      category: "authentication",
      severityHint: "high",
      cwe: "CWE-306",
      tags: ["nextjs", "middleware"],
      stacks: ["nextjs"],
      impact_if_unremediated:
        "Sensitive server entrypoints may remain reachable without adequate session or role checks.",
      remediation:
        "Call shared requireUser/requireRole helpers inside Server Actions, Route Handlers, and data loaders—not only middleware.",
      verification_suggestion: "Diff middleware matchers vs sensitive server entrypoints; confirm shared auth helpers.",
    },
    {
      id: "NEXT-SERVER-ACTIONS",
      title: "Server Actions input trust",
      description:
        "Server Actions are invocable over HTTP. Validate inputs with Zod (or similar), check authorization, and avoid trusting client-provided IDs without ownership checks.",
      category: "authorization",
      severityHint: "high",
      cwe: "CWE-20",
      tags: ["server-actions"],
      stacks: ["nextjs"],
      impact_if_unremediated:
        "Invalid or unauthorized inputs may alter data or trigger privileged operations.",
      remediation:
        "Schema-validate all Server Action arguments and enforce object-level authorization using the session.",
      verification_suggestion: "Sample Server Actions for Zod validation and ownership checks.",
    },
    {
      id: "NEXT-ROUTE-HANDLERS",
      title: "Route Handler authorization",
      description:
        "app/api/**/route.ts handlers must authenticate and authorize every method (GET/POST/…). Review cookie and CORS settings for browser-callable APIs.",
      category: "authorization",
      severityHint: "high",
      tags: ["route-handlers"],
      stacks: ["nextjs"],
      impact_if_unremediated:
        "Unauthenticated or unauthorized clients may invoke privileged HTTP handlers.",
      remediation:
        "Apply consistent authn/authz middleware helpers per method; restrict CORS to trusted origins.",
      verification_suggestion: "Open each Route Handler method and confirm auth + CORS posture.",
    },
    {
      id: "NEXT-ENV-EXPOSURE",
      title: "NEXT_PUBLIC_ secret exposure",
      description:
        "Any NEXT_PUBLIC_* env var is embedded in the client bundle. Never put secrets, private API keys, or signing keys in public env vars.",
      category: "secrets",
      severityHint: "critical",
      cwe: "CWE-200",
      tags: ["env", "client-bundle"],
      stacks: ["nextjs"],
      impact_if_unremediated:
        "Secrets shipped to browsers can be extracted by any user of the client app.",
      remediation:
        "Rename to server-only env vars; rotate any key that was ever prefixed with NEXT_PUBLIC_.",
      verification_suggestion: "Grep NEXT_PUBLIC_ for secret-like names; rotate any that were sensitive.",
    },
    {
      id: "NEXT-SSR-XSS",
      title: "SSR HTML rendering risks",
      description:
        "dangerouslySetInnerHTML, unsanitized markdown rendering, and open redirects via searchParams are common remediable weaknesses in Next.js apps.",
      category: "injection-risk",
      severityHint: "high",
      cwe: "CWE-79",
      tags: ["xss"],
      stacks: ["nextjs"],
      impact_if_unremediated:
        "Users may execute untrusted script in the application origin if HTML sinks are misused.",
      remediation: "Avoid raw HTML; sanitize when required; allowlist redirect targets.",
      verification_suggestion: "Inventory dangerouslySetInnerHTML and markdown HTML renderers.",
    },
    {
      id: "NEXT-OPEN-REDIRECT",
      title: "Unvalidated redirects",
      description:
        "Validate redirect targets (login callbackUrl, searchParams.next, headers). Allowlist relative paths or known hosts.",
      category: "injection-risk",
      severityHint: "medium",
      cwe: "CWE-601",
      tags: ["redirects"],
      stacks: ["nextjs"],
      impact_if_unremediated:
        "Users may be sent to untrusted sites after legitimate app interactions.",
      remediation: "Allowlist destinations; reject absolute external URLs unless explicitly trusted.",
      verification_suggestion: "Trace redirect() call sites fed by searchParams or headers.",
    },
    {
      id: "NEXT-HEADERS",
      title: "Security headers",
      description:
        "Configure CSP, HSTS, X-Content-Type-Options, Referrer-Policy, and frame protections via next.config or middleware.",
      category: "configuration",
      severityHint: "medium",
      tags: ["headers", "csp"],
      stacks: ["nextjs"],
      impact_if_unremediated:
        "Missing browser security headers reduce defense-in-depth against content injection and clickjacking.",
      remediation: "Set a restrictive CSP and standard security headers in production config.",
      verification_suggestion: "Inspect production response headers for CSP/HSTS/frame options.",
    },
    {
      id: "NEXT-EDGE-RUNTIME",
      title: "Edge vs Node runtime secrets",
      description:
        "Edge runtime has different crypto/network capabilities. Ensure secret-handling libraries are supported and not polyfilled insecurely.",
      category: "configuration",
      severityHint: "low",
      tags: ["edge"],
      stacks: ["nextjs"],
      impact_if_unremediated:
        "Unsupported crypto on Edge may lead to weaker fallbacks or runtime failures around secret handling.",
      remediation: "Confirm libraries support the chosen runtime; keep secret operations on Node when required.",
      verification_suggestion: "List edge routes that touch secrets; confirm supported crypto APIs.",
    },
    {
      id: "NEXT-CLIENT-SECRETS",
      title: "Secrets in client components",
      description:
        "Files with 'use client' and any imported modules ship to the browser. Keep secret material in server-only modules.",
      category: "secrets",
      severityHint: "high",
      tags: ["use-client"],
      stacks: ["nextjs"],
      impact_if_unremediated:
        "Server secrets imported into client graphs can appear in browser bundles.",
      remediation:
        "Move secret access to server components or server-only modules; audit client import graphs.",
      verification_suggestion: "Search 'use client' files for process.env and secret imports.",
    },
  ],
};
