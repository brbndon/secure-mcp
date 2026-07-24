/**
 * Pack: swift-ios — Keychain, biometrics, ATS, WebView, deep links.
 */

import type { KnowledgePack } from "./types.js";

export const swiftIosPack: KnowledgePack = {
  id: "swift-ios",
  title: "Swift / iOS hardening",
  description:
    "iOS/SwiftUI controls: Keychain, biometrics, ATS, deep links, WKWebView bridges, pasteboard.",
  stackTags: ["swift", "ios"],
  categories: ["secrets", "authentication", "injection-risk", "configuration", "privacy", "cryptography"],
  estimatedTokens: 1400,
  items: [
    {
      id: "SWIFT-KEYCHAIN",
      title: "Secrets in Keychain not UserDefaults",
      description:
        "Tokens, passwords, and refresh credentials belong in Keychain (or Secure Enclave-backed keys), not UserDefaults, plists, or plain files.",
      category: "secrets",
      severityHint: "high",
      cwe: "CWE-922",
      tags: ["keychain", "storage"],
      stacks: ["swift"],
      impact_if_unremediated:
        "Credentials in unprotected storage may be easier to extract from backups or local device access.",
      remediation:
        "Migrate tokens to Keychain with appropriate accessibility; remove secrets from UserDefaults.",
      verification_suggestion: "Search UserDefaults for token/password keys; confirm Keychain usage.",
    },
    {
      id: "SWIFT-ATS",
      title: "App Transport Security exceptions",
      description:
        "NSAllowsArbitraryLoads and broad domain exceptions in Info.plist weaken TLS. Prefer HTTPS with modern TLS only.",
      category: "configuration",
      severityHint: "high",
      cwe: "CWE-319",
      tags: ["ats", "tls"],
      stacks: ["swift"],
      impact_if_unremediated:
        "Cleartext or weakly protected network traffic may expose credentials or PII in transit.",
      remediation:
        "Disable arbitrary loads; use HTTPS endpoints; limit any ATS exceptions to documented temporary needs.",
      verification_suggestion: "Inspect Info.plist ATS keys for arbitrary loads and broad exceptions.",
    },
    {
      id: "SWIFT-KEYCHAIN-ACCESS",
      title: "Keychain accessibility flags",
      description:
        "Choose appropriate kSecAttrAccessible values. Avoid always-accessible items for high-value secrets when unlocked-only is sufficient.",
      category: "secrets",
      severityHint: "medium",
      tags: ["keychain"],
      stacks: ["swift"],
      impact_if_unremediated:
        "Overly broad Keychain accessibility increases exposure if the device is locked or partially compromised.",
      remediation:
        "Use the most restrictive accessibility that still meets product requirements; document the choice.",
      verification_suggestion: "Review SecItemAdd/Update accessibility attributes for high-value items.",
    },
    {
      id: "SWIFT-BIOMETRICS",
      title: "Biometric / LocalAuthentication gates",
      description:
        "Face ID/Touch ID should gate access to keys or sensitive actions; do not treat LAContext success alone as remote authorization.",
      category: "authentication",
      severityHint: "medium",
      tags: ["biometrics"],
      stacks: ["swift", "ios"],
      impact_if_unremediated:
        "Local biometric checks without proper key binding may be insufficient for high-value local secrets.",
      remediation:
        "Bind biometrics to Keychain access control where appropriate; still enforce server-side authorization for remote actions.",
      verification_suggestion: "Confirm biometric success is bound to Keychain ACL for sensitive secrets.",
    },
    {
      id: "SWIFT-DEEP-LINKS",
      title: "URL scheme / universal link validation",
      description:
        "Validate incoming deep-link URLs and parameters. Avoid automatic privileged actions from untrusted URLs; carefully handle WebView destinations.",
      category: "injection-risk",
      severityHint: "high",
      cwe: "CWE-939",
      tags: ["deeplinks"],
      stacks: ["swift"],
      impact_if_unremediated:
        "Unvalidated links may drive sensitive screens or actions with attacker-controlled parameters.",
      remediation:
        "Allowlist hosts/paths; validate parameters; require re-authentication before privileged deep-link actions.",
      verification_suggestion: "Review onOpenURL / continue userActivity handlers for allowlists.",
    },
    {
      id: "SWIFT-WEBVIEW",
      title: "WKWebView bridge safety",
      description:
        "JavaScript bridges (WKScriptMessageHandler) must allowlist message types and never expose raw Keychain or filesystem access to web content.",
      category: "injection-risk",
      severityHint: "high",
      cwe: "CWE-749",
      tags: ["webview"],
      stacks: ["swift"],
      impact_if_unremediated:
        "Over-privileged bridges can let web content reach native secrets or APIs.",
      remediation: "Restrict message handlers; validate payloads; never pass secrets to JavaScript.",
      verification_suggestion: "List WKScriptMessageHandler names and confirm least privilege.",
    },
    {
      id: "SWIFT-LOGGING",
      title: "os_log / print of sensitive data",
      description:
        "Avoid print/NSLog/os_log of tokens, passwords, or PII. Use privacy-aware logging APIs.",
      category: "privacy",
      severityHint: "medium",
      cwe: "CWE-532",
      tags: ["logging"],
      stacks: ["swift"],
      impact_if_unremediated:
        "Device logs may retain secrets or PII accessible to other processes or support tooling.",
      remediation: "Remove sensitive prints; use privacy-preserving os_log formats.",
      verification_suggestion: "Grep print/NSLog/os_log for token/password/PII interpolations.",
    },
    {
      id: "SWIFT-CRYPTOKIT",
      title: "CryptoKit / CommonCrypto usage",
      description:
        "Prefer CryptoKit (AES.GCM, ChaChaPoly, P256, Secure Enclave). Avoid MD5/SHA1 for security and custom crypto protocols.",
      category: "cryptography",
      severityHint: "medium",
      cwe: "CWE-327",
      tags: ["cryptokit"],
      stacks: ["swift"],
      impact_if_unremediated:
        "Weak algorithms reduce assurance for encrypted or signed application data.",
      remediation: "Migrate security-critical crypto to CryptoKit modern APIs.",
      verification_suggestion: "Inventory hash/cipher usage; flag MD5/SHA1 for security purposes.",
    },
    {
      id: "SWIFT-PASTEBOARD",
      title: "UIPasteboard secrets",
      description:
        "Do not place credentials on the general pasteboard. Use local-only pasteboard options when needed and clear promptly.",
      category: "secrets",
      severityHint: "medium",
      tags: ["pasteboard"],
      stacks: ["swift", "ios"],
      impact_if_unremediated:
        "Other apps may read general pasteboard contents containing credentials.",
      remediation: "Avoid pasteboard for secrets; clear temporary clipboard data quickly.",
      verification_suggestion: "Search UIPasteboard usage near credential flows.",
    },
    {
      id: "SWIFT-APP-TRANSPORT-HTTP",
      title: "Hardcoded cleartext URLs",
      description:
        "Prefer https:// endpoints for any traffic carrying credentials or PII. Review http:// literals in source.",
      category: "configuration",
      severityHint: "medium",
      cwe: "CWE-319",
      tags: ["tls", "http"],
      stacks: ["swift"],
      impact_if_unremediated:
        "Requests to cleartext endpoints may expose credentials or PII on the network path.",
      remediation: "Replace http:// API endpoints with https://; document any intentional exceptions.",
      verification_suggestion: "Grep http:// in networking code and configs.",
    },
    {
      id: "SWIFT-FILE-PROTECTION",
      title: "Data protection for sensitive files",
      description:
        "Sensitive caches, databases, and exports should use appropriate data-protection classes and be excluded from backups when they hold session material.",
      category: "secrets",
      severityHint: "medium",
      cwe: "CWE-311",
      tags: ["file-protection", "backup"],
      stacks: ["swift", "ios"],
      impact_if_unremediated:
        "Session or personal data may be readable from device backups or while the device is locked.",
      remediation:
        "Set NSFileProtection attributes for sensitive files; mark credential caches as excluded from backup.",
      verification_suggestion:
        "Review file writes in Documents/Caches for protection attributes and backup flags.",
    },
    {
      id: "SWIFT-EXTENSION-SHARING",
      title: "App group and extension data sharing",
      description:
        "Widgets, share extensions, and app groups share containers and Keychain items; scope what extensions can read.",
      category: "secrets",
      severityHint: "medium",
      cwe: "CWE-922",
      tags: ["app-groups", "extensions"],
      stacks: ["swift", "ios"],
      impact_if_unremediated:
        "A less-hardened extension becomes a path to credentials the main app protects.",
      remediation:
        "Share only the minimum in app-group containers; keep high-value tokens out of extension-readable Keychain groups.",
      verification_suggestion:
        "List app-group and keychain-access-group entitlements per target and confirm each is needed.",
    },
  ],
};
