/**
 * Swift / SwiftUI knowledge for defensive secure-code review and hardening.
 * Checklists live in packs; this module keeps category-scoped scan patterns.
 *
 * Patterns are split by tool category so secrets heuristics do not flood
 * injection results (and vice versa). Prefer high-signal, low-noise regexes.
 */

import { appleDesktopPack } from "./packs/apple-desktop.js";
import type { PackItem } from "./packs/types.js";
import { swiftIosPack } from "./packs/swift-ios.js";

/** @deprecated Prefer PackItem from packs/types — kept for existing imports. */
export type ChecklistItem = PackItem;

/** Combined Swift checklist (iOS + desktop entitlements item for compatibility). */
export const SWIFT_CHECKLIST: PackItem[] = [
  ...swiftIosPack.items,
  ...appleDesktopPack.items.filter((i) => i.id === "MAC-ENTITLEMENTS"),
];

export type SwiftPatternSeverity = "critical" | "high" | "medium" | "low" | "info";
export type SwiftPatternConfidence = "high" | "medium" | "low";
export type SwiftPatternCategory =
  | "authentication"
  | "injection-risk"
  | "secrets"
  | "configuration"
  | "privacy"
  | "cryptography";

export interface SwiftPattern {
  id: string;
  title: string;
  regex: RegExp;
  severity: SwiftPatternSeverity;
  confidence: SwiftPatternConfidence;
  category: SwiftPatternCategory;
  cwe?: string;
  recommendation: string;
  impact_if_unremediated: string;
  /**
   * File extensions this pattern applies to (lowercase, with dot).
   * Default: [".swift"] unless overridden by the consuming tool.
   */
  extensions?: string[];
  /** Optional post-match filter to cut obvious noise. */
  filter?: (match: string, content: string) => boolean;
}

/** Authn/authz / TLS trust sinks — consumed by check_authentication. */
export const SWIFT_AUTH_PATTERNS: SwiftPattern[] = [
  {
    id: "SWIFT-USERDEFAULTS-TOKEN",
    title: "Possible secret stored in UserDefaults",
    regex:
      /UserDefaults(?:\.standard)?\.[^(]*(?:set|string|object)[^(]*\([^)]*(?:token|password|secret|apiKey|apikey|auth)/gi,
    severity: "high",
    confidence: "medium",
    category: "authentication",
    cwe: "CWE-922",
    recommendation:
      "Store credentials in Keychain; use UserDefaults only for non-sensitive preferences.",
    impact_if_unremediated:
      "Credentials in UserDefaults are easier to extract than Keychain-protected items.",
  },
  {
    id: "SWIFT-KEYCHAIN-ALWAYS",
    title: "Overly broad Keychain accessibility",
    regex:
      /\bkSecAttrAccessibleAlways(?:ThisDeviceOnly)?\b|accessibility\s*:\s*\.always(?:ThisDeviceOnly)?\b/gi,
    severity: "high",
    confidence: "high",
    category: "authentication",
    cwe: "CWE-922",
    recommendation:
      "Prefer kSecAttrAccessibleWhenUnlockedThisDeviceOnly (or AfterFirstUnlock only when background access is required); avoid Always for session secrets.",
    impact_if_unremediated:
      "Keychain items readable while the device is locked increase exposure if the device is stolen or partially compromised.",
  },
  {
    id: "SWIFT-TRUST-DISABLE",
    title: "TLS server-trust validation appears disabled",
    // Flags .useCredential on a serverTrust / auth challenge window. The filter
    // drops windows that already call SecTrustEvaluate* (evaluate-then-accept).
    regex:
      /URLAuthenticationChallenge[\s\S]{0,220}completionHandler\s*\(\s*\.useCredential|serverTrust[\s\S]{0,160}completionHandler\s*\(\s*\.useCredential|didReceive\s+[^\n]{0,80}challenge[\s\S]{0,240}\.useCredential/gi,
    severity: "high",
    confidence: "medium",
    category: "authentication",
    cwe: "CWE-295",
    recommendation:
      "Validate the server trust with SecTrustEvaluate (or URLSession's default handling); never unconditionally accept challenges in production builds.",
    impact_if_unremediated:
      "Network peers may not be authenticated, enabling interception of credentials or session traffic.",
    filter: (match) =>
      !/SecTrustEvaluate(?:WithError)?|sec_trust_evaluate/i.test(match),
  },
  {
    id: "SWIFT-SUITE-TOKEN",
    title: "App-group UserDefaults near credential terms",
    regex:
      /UserDefaults\s*\(\s*suiteName\s*:[\s\S]{0,120}(?:token|password|secret|credential|session|auth|refresh)/gi,
    severity: "high",
    confidence: "medium",
    category: "authentication",
    cwe: "CWE-922",
    recommendation:
      "Do not store tokens in app-group UserDefaults; use a tightly scoped Keychain access group if extensions must share secrets.",
    impact_if_unremediated:
      "Any extension in the app group can read shared preferences, widening the blast radius of a less-hardened target.",
  },
];

/** Injection / bridge / deep-link sinks — consumed by analyze_injection_risks. */
export const SWIFT_INJECTION_PATTERNS: SwiftPattern[] = [
  {
    id: "SWIFT-PROCESS-SHELL",
    title: "Process shell execution",
    regex: /Process\s*\(|NSTask\s*\(|\/bin\/(sh|bash|zsh)/g,
    severity: "high",
    confidence: "medium",
    category: "injection-risk",
    cwe: "CWE-78",
    recommendation:
      "Avoid shelling out with untrusted input; prefer APIs that take argument arrays without a shell.",
    impact_if_unremediated:
      "Untrusted influence over process execution can compromise the host application environment.",
  },
  {
    id: "SWIFT-WEBVIEW-HANDLER",
    title: "WKWebView script message handler bridge",
    regex:
      /WKScriptMessageHandler|addScriptMessageHandler\s*\(|webkit\.messageHandlers/gi,
    severity: "high",
    confidence: "medium",
    category: "injection-risk",
    cwe: "CWE-749",
    recommendation:
      "Allowlist message names and payloads; never expose Keychain, filesystem, or privileged APIs to web content through the bridge.",
    impact_if_unremediated:
      "Over-privileged bridges can let web content reach native secrets or APIs.",
  },
  {
    id: "SWIFT-DEEP-LINK-HANDLER",
    title: "Deep-link / URL open handler present",
    regex:
      /\.onOpenURL\s*[\({]|func\s+application\s*\([^\)]*open\s+[^\)]*URL|openURLContexts|continue\s+userActivity|onContinueUserActivity/gi,
    severity: "medium",
    confidence: "low",
    category: "injection-risk",
    cwe: "CWE-939",
    recommendation:
      "Allowlist hosts/paths and parameters; require re-authentication before privileged deep-link actions.",
    impact_if_unremediated:
      "Unvalidated links may drive sensitive screens or actions with attacker-controlled parameters.",
  },
  {
    id: "SWIFT-EVAL-JS",
    title: "WKWebView evaluateJavaScript usage",
    regex: /\.evaluateJavaScript\s*\(/g,
    severity: "medium",
    confidence: "low",
    category: "injection-risk",
    cwe: "CWE-95",
    recommendation:
      "Never interpolate untrusted strings into evaluateJavaScript; prefer message handlers with validated payloads.",
    impact_if_unremediated:
      "Untrusted input reaching evaluateJavaScript can execute attacker-controlled script in the WebView origin.",
  },
];

/** Secret logging / pasteboard / hardcoded — consumed by review_secrets.
 * Storage/accessibility sinks (UserDefaults, Keychain Always, app-group suite)
 * live only in SWIFT_AUTH_PATTERNS so auth↔secrets do not double-report.
 */
export const SWIFT_SECRETS_PATTERNS: SwiftPattern[] = [
  {
    id: "SWIFT-HARDCODED-PASSWORD",
    title: "Hardcoded password-like assignment",
    regex: /\b(password|apiKey|api_key|secret|token)\s*=\s*"[^"]{8,}"/gi,
    severity: "high",
    confidence: "medium",
    category: "secrets",
    cwe: "CWE-798",
    recommendation:
      "Remove hardcoded secrets; load from Keychain or secure configuration at runtime.",
    impact_if_unremediated:
      "Embedded secrets in binaries or source can grant unintended access if recovered.",
  },
  {
    id: "SWIFT-PRINT-SENSITIVE",
    title: "print of sensitive-looking values",
    regex: /\bprint\s*\([^)]*(?:token|password|secret|authorization)/gi,
    severity: "medium",
    confidence: "medium",
    category: "privacy",
    cwe: "CWE-532",
    recommendation: "Remove sensitive prints; use privacy-preserving os_log.",
    impact_if_unremediated:
      "Logs may retain tokens or credentials beyond the intended session lifetime.",
  },
  {
    id: "SWIFT-PASTEBOARD-SECRET",
    title: "General pasteboard write near credential terms",
    regex:
      /(?:UIPasteboard\.general|NSPasteboard\.general)[\s\S]{0,100}(?:string|setValue|setString|writeObjects)[\s\S]{0,80}(?:token|password|secret|credential|otp|recovery)|(?:token|password|secret|credential|otp|recovery)[\s\S]{0,80}(?:UIPasteboard\.general|NSPasteboard\.general)/gi,
    severity: "medium",
    confidence: "medium",
    category: "secrets",
    cwe: "CWE-200",
    recommendation:
      "Do not place credentials on the general pasteboard; use a local-only pasteboard and clear promptly if clipboard is required.",
    impact_if_unremediated:
      "Other apps may read general pasteboard contents containing credentials.",
  },
];

/** ATS / cleartext transport — consumed by analyze_injection_risks as configuration. */
export const SWIFT_CONFIG_PATTERNS: SwiftPattern[] = [
  {
    id: "SWIFT-ATS-ARBITRARY",
    title: "ATS allows arbitrary loads",
    regex: /NSAllowsArbitraryLoads\s*=\s*true|NSAllowsArbitraryLoads<\/key>\s*<true/gi,
    severity: "high",
    confidence: "high",
    category: "configuration",
    cwe: "CWE-319",
    extensions: [".plist", ".xml", ".entitlements"],
    recommendation:
      "Disable arbitrary loads; use HTTPS endpoints and minimal domain exceptions.",
    impact_if_unremediated:
      "Cleartext network traffic may expose sensitive data in transit.",
  },
  {
    id: "SWIFT-ATS-EXCEPTION",
    title: "ATS insecure-load or local-networking exception",
    regex:
      /NSExceptionAllowsInsecureHTTPLoads\s*=\s*true|NSExceptionAllowsInsecureHTTPLoads<\/key>\s*<true|NSAllowsLocalNetworking\s*=\s*true|NSAllowsLocalNetworking<\/key>\s*<true|NSAllowsArbitraryLoadsInWebContent\s*=\s*true|NSAllowsArbitraryLoadsInWebContent<\/key>\s*<true/gi,
    severity: "medium",
    confidence: "high",
    category: "configuration",
    cwe: "CWE-319",
    extensions: [".plist", ".xml", ".entitlements"],
    recommendation:
      "Limit ATS exceptions to documented temporary needs; prefer HTTPS and remove insecure HTTP exception keys when unused.",
    impact_if_unremediated:
      "Domain or WebView exceptions can reintroduce cleartext or weakly protected traffic for sensitive flows.",
  },
  {
    id: "SWIFT-HTTP-URL",
    title: "Hardcoded http:// URL",
    regex: /https?:\/\/[^\s"'`]+/gi,
    severity: "medium",
    confidence: "medium",
    category: "configuration",
    cwe: "CWE-319",
    recommendation: "Use HTTPS for network calls carrying credentials or PII.",
    impact_if_unremediated:
      "Cleartext HTTP may allow interception of sensitive request or response data.",
    filter: (m) => {
      const lower = m.toLowerCase();
      if (!lower.startsWith("http://")) return false;
      // Skip common documentation / placeholder hosts.
      if (
        /example\.com|localhost|127\.0\.0\.1|0\.0\.0\.0|apple\.com\/documentation|swift\.org/i.test(
          m,
        )
      ) {
        return false;
      }
      return true;
    },
  },
];

/** Weak crypto in security contexts — consumed by analyze_injection_risks as cryptography. */
export const SWIFT_CRYPTO_PATTERNS: SwiftPattern[] = [
  {
    id: "SWIFT-WEAK-HASH",
    title: "Weak hash API (MD5/SHA1) in source",
    regex:
      /\bCC_MD5\s*\(|\bCC_SHA1\s*\(|Insecure\.MD5|Insecure\.SHA1|\.md5\b(?!\w)/g,
    severity: "medium",
    confidence: "low",
    category: "cryptography",
    cwe: "CWE-327",
    recommendation:
      "Use CryptoKit SHA256/SHA384 for integrity and modern AEAD (AES.GCM / ChaChaPoly) for confidentiality; do not use MD5/SHA1 for security decisions.",
    impact_if_unremediated:
      "Weak algorithms reduce assurance for integrity checks or derived security tokens.",
  },
];

/**
 * Flat union for backwards compatibility / tests (deduped by id).
 * Prefer the category-scoped arrays in new call sites.
 */
export const SWIFT_PATTERNS: SwiftPattern[] = (() => {
  const byId = new Map<string, SwiftPattern>();
  for (const p of [
    ...SWIFT_AUTH_PATTERNS,
    ...SWIFT_INJECTION_PATTERNS,
    ...SWIFT_SECRETS_PATTERNS,
    ...SWIFT_CONFIG_PATTERNS,
    ...SWIFT_CRYPTO_PATTERNS,
  ]) {
    if (!byId.has(p.id)) byId.set(p.id, p);
  }
  return [...byId.values()];
})();

/** Paths agents and tools should prioritize when reviewing Swift projects. */
export const SWIFT_SENSITIVE_FILES = [
  "Info.plist",
  ".entitlements",
  "Package.swift",
  "GoogleService-Info.plist",
];

/** True when a relative path matches a known sensitive Apple config basename/suffix. */
export function isSwiftSensitivePath(relativePath: string): boolean {
  const base = relativePath.split(/[/\\]/).pop() ?? relativePath;
  return SWIFT_SENSITIVE_FILES.some(
    (hint) => base === hint || relativePath.endsWith(hint) || base.endsWith(hint),
  );
}
