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
  categories: [
    "secrets",
    "configuration",
    "injection-risk",
    "authentication",
    "privacy",
    "supply-chain",
  ],
  estimatedTokens: 1400,
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
      impact_if_unremediated:
        "Tokens in unencrypted device storage are recoverable from backups or a compromised device.",
      remediation:
        "Migrate auth tokens to SecureStore; reserve AsyncStorage for non-sensitive preferences.",
      verification_suggestion: "Grep AsyncStorage/MMKV for token/password keys; confirm SecureStore usage.",
    },
    {
      id: "EXPO-SECURE-STORE-ACCESS",
      title: "SecureStore accessibility and biometric gating",
      description:
        "SecureStore writes accept keychainAccessible and requireAuthentication options; defaults may be broader than a high-value credential warrants.",
      category: "secrets",
      severityHint: "medium",
      tags: ["secure-store", "biometrics"],
      stacks: ["expo"],
      impact_if_unremediated:
        "Credentials stay reachable in device states the product did not intend to allow.",
      remediation:
        "Set the most restrictive keychainAccessible that works (e.g. WHEN_UNLOCKED_THIS_DEVICE_ONLY); add requireAuthentication for high-value secrets.",
      verification_suggestion: "Review SecureStore.setItemAsync options at login and token-refresh paths.",
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
      impact_if_unremediated:
        "Config-embedded keys reach every installed app and must be treated as public.",
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
      impact_if_unremediated:
        "Any user can read the value from the shipped bundle, so the credential is disclosed.",
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
      impact_if_unremediated:
        "Untrusted links may drive privileged screens or actions with attacker-chosen parameters.",
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
      impact_if_unremediated:
        "Auth codes or tokens may be delivered to an unintended app or captured in logs.",
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
      impact_if_unremediated:
        "Loaded web content can reach native capabilities or read injected secrets.",
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
      impact_if_unremediated:
        "Excess permissions widen the data a bug or compromised dependency can reach.",
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
      impact_if_unremediated:
        "Third-party crash and log pipelines become an unintended store of tokens and PII.",
      remediation: "Strip auth headers and tokens from logs and error reporting breadcrumbs.",
      verification_suggestion: "Search console.log near auth/network code for token interpolations.",
    },
    {
      id: "EXPO-DEV-ARTIFACTS",
      title: "Dev-only flags out of release builds",
      description:
        "__DEV__ branches, dev-client menus, staging endpoints, and verbose network logging must not ship in production builds.",
      category: "configuration",
      severityHint: "medium",
      tags: ["release", "debug"],
      stacks: ["expo"],
      impact_if_unremediated:
        "Shipped debug paths can expose internal endpoints or bypass production safeguards.",
      remediation:
        "Gate dev tooling behind __DEV__ or build profiles; confirm EAS production profile disables dev features.",
      verification_suggestion: "Grep __DEV__ and staging URLs; review eas.json build profiles.",
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
      impact_if_unremediated:
        "On a hostile network, traffic integrity rests entirely on device trust stores.",
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
      impact_if_unremediated:
        "An over-broad publish permission can push arbitrary JS to installed apps.",
      remediation: "Restrict who can publish updates; separate channels per env; never embed secrets in OTA JS.",
      verification_suggestion: "Review EAS update permissions and channel configuration.",
    },
  ],
};
