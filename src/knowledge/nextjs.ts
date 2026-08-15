/**
 * Next.js / TypeScript App Router knowledge for defensive secure-code review.
 * Checklists live in packs; this module keeps scan patterns.
 */

/** Heuristics specific to Next.js source (remediation oriented). */
export const NEXTJS_PATTERNS: {
  id: string;
  title: string;
  regex: RegExp;
  severity: "critical" | "high" | "medium" | "low";
  cwe?: string;
  recommendation: string;
  impact_if_unremediated: string;
}[] = [
  {
    id: "NEXT-PUBLIC-SECRET",
    title: "Possible secret in NEXT_PUBLIC_ variable",
    regex:
      /NEXT_PUBLIC_(?:SECRET|API_KEY|TOKEN|PRIVATE|PASSWORD|KEY)\b\s*[:=]|process\.env\.NEXT_PUBLIC_[A-Z0-9_]*(?:SECRET|KEY|TOKEN|PASSWORD)/gi,
    severity: "critical",
    cwe: "CWE-200",
    recommendation: "Move secrets to server-only env vars without the NEXT_PUBLIC_ prefix; rotate exposed values.",
    impact_if_unremediated:
      "Client-visible secrets can be recovered from the browser bundle by any user.",
  },
  {
    id: "NEXT-DANGEROUS-HTML",
    title: "dangerouslySetInnerHTML usage",
    regex: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html:/g,
    severity: "high",
    cwe: "CWE-79",
    recommendation: "Sanitize HTML or avoid raw HTML rendering for untrusted content.",
    impact_if_unremediated:
      "Untrusted HTML may execute in the application origin and affect user sessions.",
  },
  {
    id: "NEXT-REDIRECT-PARAM",
    title: "Redirect driven by request parameter",
    regex: /redirect\s*\(\s*(?:searchParams|params|req\.|url\.|query)/g,
    severity: "medium",
    cwe: "CWE-601",
    recommendation: "Allowlist redirect destinations before calling redirect().",
    impact_if_unremediated:
      "Users may be redirected to untrusted destinations after interacting with the app.",
  },
  {
    id: "NEXT-USE-CLIENT-SECRET",
    title: "use client file referencing process.env secret-like names",
    regex: /['"]use client['"][\s\S]{0,500}process\.env\.(?!NEXT_PUBLIC_)[A-Z0-9_]+/g,
    severity: "medium",
    recommendation:
      "Verify env usage is safe in client bundles; prefer server components for any secret access.",
    impact_if_unremediated:
      "Server-only env vars referenced from client components may be inlined or mishandled.",
  },
];

export const NEXTJS_AUTH_FILE_HINTS = [
  "middleware.ts",
  "middleware.js",
  "auth.ts",
  "auth.js",
  "lib/auth.ts",
  "src/auth.ts",
  "src/lib/auth.ts",
  "app/api/auth",
  "pages/api/auth",
];
