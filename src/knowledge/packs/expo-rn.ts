/**
 * Pack: expo-rn — Expo / React Native secure storage, config secrets, deep links.
 */

import type { KnowledgePack } from "./types.js";

export const expoRnPack: KnowledgePack = {
  id: "expo-rn",
  title: "Expo / React Native hardening",
  description:
    "Expo and React Native controls: secure storage, config secrets, deep links, WebView, and client-bundle hygiene.",
  stackTags: ["expo", "react-native"],
  categories: ["secrets", "configuration", "injection-risk", "authentication", "privacy"],
  estimatedTokens: 1100,
  items: [
    {
      id: "EXPO-SECURE-STORE",
      title: "Use SecureStore for credentials",
      description:
        "Tokens and secrets belong in expo-secure-store (or platform Keychain/Keystore wrappers), not AsyncStorage or plain MMKV without encryption.",
      category: "secrets",
      severityHint: "high",
      cwe: "CWE-922",
      tags: ["secure-store", "storage"],
      stacks: ["expo"],
      remediation:
        "Migrate auth tokens to SecureStore; reserve AsyncStorage for non-sensitive preferences.",
      verification_suggestion: "Grep AsyncStorage/MMKV for token/password keys; confirm SecureStore usage.",
    },
    {
      id: "EXPO-CONFIG-SECRETS",
      title: "Secrets out of app.json / extra",
      description:
        "app.json, app.config.*, and expo.extra values can ship in the client. Never embed private API keys or signing secrets there.",
      category: "secrets",
      severityHint: "critical",
      cwe: "CWE-798",
      tags: ["config", "env"],
      stacks: ["expo"],
      remediation:
        "Keep secrets on the backend; use EAS secrets / env for build-time values that stay server-side.",
      verification_suggestion: "Inspect app.config and extra for secret-like keys; rotate if committed.",
    },
    {
      id: "EXPO-PUBLIC-ENV",
      title: "EXPO_PUBLIC_ / public env exposure",
      description:
        "EXPO_PUBLIC_* (and similar public env prefixes) are embedded in the JS bundle. Treat them as fully public.",
      category: "secrets",
      severityHint: "critical",
      cwe: "CWE-200",
      tags: ["env", "client-bundle"],
      stacks: ["expo"],
      remediation: "Rename secrets to non-public env; rotate any key that was ever public-prefixed.",
      verification_suggestion: "Grep EXPO_PUBLIC_ for secret-like names in source and .env files.",
    },
    {
      id: "EXPO-DEEP-LINKS",
      title: "Deep link and scheme validation",
      description:
        "Custom schemes and universal links can drive navigation and auth callbacks. Validate paths and parameters before privileged actions.",
      category: "injection-risk",
      severityHint: "high",
      cwe: "CWE-939",
      tags: ["deeplinks"],
      stacks: ["expo"],
      remediation:
        "Allowlist routes; validate query params; require re-auth before sensitive deep-link actions.",
      verification_suggestion: "Review Linking / expo-linking handlers for allowlists and auth gates.",
    },
    {
      id: "EXPO-AUTH-SESSION",
      title: "Auth session redirect hygiene",
      description:
        "AuthSession / OAuth redirect URIs must be exact and platform-specific. Avoid wildcard redirects and leaking tokens in URLs that get logged.",
      category: "authentication",
      severityHint: "high",
      cwe: "CWE-601",
      tags: ["oauth", "auth-session"],
      stacks: ["expo"],
      remediation:
        "Register exact redirect URIs; prefer ephemeral sessions where appropriate; never log full redirect URLs with tokens.",
      verification_suggestion: "Confirm redirect URIs match provider config; search logs for token query params.",
    },
    {
      id: "EXPO-WEBVIEW",
      title: "WebView message and navigation safety",
      description:
        "React Native WebView bridges and navigation handlers must allowlist origins and message types; do not inject secrets into JS.",
      category: "injection-risk",
      severityHint: "high",
      cwe: "CWE-749",
      tags: ["webview"],
      stacks: ["expo"],
      remediation: "Allowlist origins; validate onMessage payloads; keep secrets out of injected JS.",
      verification_suggestion: "Review WebView onMessage/onShouldStartLoadWithRequest handlers.",
    },
    {
      id: "EXPO-PERMISSIONS",
      title: "Least-privilege device permissions",
      description:
        "Request only needed permissions (camera, location, contacts). Explain purpose and avoid retaining sensitive data longer than needed.",
      category: "privacy",
      severityHint: "medium",
      tags: ["permissions", "privacy"],
      stacks: ["expo"],
      remediation: "Audit app.json plugins/permissions; remove unused; minimize retained sensitive data.",
      verification_suggestion: "Diff declared permissions against actual feature usage.",
    },
    {
      id: "EXPO-LOGGING",
      title: "No secrets in console / crash logs",
      description:
        "console.log and crash reporters can ship tokens and PII from devices. Redact before logging.",
      category: "privacy",
      severityHint: "medium",
      cwe: "CWE-532",
      tags: ["logging"],
      stacks: ["expo"],
      remediation: "Strip auth headers and tokens from logs and error reporting breadcrumbs.",
      verification_suggestion: "Search console.log near auth/network code for token interpolations.",
    },
    {
      id: "EXPO-CERT-PINNING",
      title: "TLS trust for high-value apps",
      description:
        "For high-sensitivity apps, consider certificate pinning or platform network security configs; always use HTTPS.",
      category: "configuration",
      severityHint: "low",
      cwe: "CWE-295",
      tags: ["tls"],
      stacks: ["expo"],
      remediation: "Enforce HTTPS; evaluate pinning for high-risk threat models; document trade-offs.",
      verification_suggestion: "Confirm API base URLs are https and review any pinning config.",
    },
    {
      id: "EXPO-UPDATE-CHANNEL",
      title: "OTA update integrity",
      description:
        "EAS Update / OTA channels should be authenticated and environment-separated. Do not ship secrets via update payloads.",
      category: "supply-chain",
      severityHint: "high",
      tags: ["ota", "updates"],
      stacks: ["expo"],
      remediation: "Restrict who can publish updates; separate channels per env; never embed secrets in OTA JS.",
      verification_suggestion: "Review EAS update permissions and channel configuration.",
    },
  ],
};
