/**
 * Swift / SwiftUI knowledge for defensive secure-code review and hardening.
 * Checklists live in packs; this module re-exports and keeps scan patterns.
 */

import { appleDesktopPack } from "./packs/apple-desktop.js";
import type { PackItem } from "./packs/types.js";
import { swiftIosPack } from "./packs/swift-ios.js";

export type ChecklistItem = PackItem;

/** Combined Swift checklist (iOS + desktop entitlements item for compatibility). */
export const SWIFT_CHECKLIST: ChecklistItem[] = [
  ...swiftIosPack.items,
  ...appleDesktopPack.items.filter((i) => i.id === "MAC-ENTITLEMENTS"),
];

export const SWIFT_PATTERNS: {
  id: string;
  title: string;
  regex: RegExp;
  severity: "critical" | "high" | "medium" | "low";
  cwe?: string;
  recommendation: string;
  impact_if_unremediated: string;
}[] = [
  {
    id: "SWIFT-USERDEFAULTS-TOKEN",
    title: "Possible secret stored in UserDefaults",
    regex:
      /UserDefaults(?:\.standard)?\.[^(]*(?:set|string|object)[^(]*\([^)]*(?:token|password|secret|apiKey|apikey|auth)/gi,
    severity: "high",
    cwe: "CWE-922",
    recommendation: "Store credentials in Keychain; use UserDefaults only for non-sensitive preferences.",
    impact_if_unremediated:
      "Credentials in UserDefaults are easier to extract than Keychain-protected items.",
  },
  {
    id: "SWIFT-ATS-ARBITRARY",
    title: "ATS allows arbitrary loads",
    regex: /NSAllowsArbitraryLoads\s*=\s*true|NSAllowsArbitraryLoads<\/key>\s*<true/gi,
    severity: "high",
    cwe: "CWE-319",
    recommendation: "Disable arbitrary loads; use HTTPS endpoints and minimal domain exceptions.",
    impact_if_unremediated:
      "Cleartext network traffic may expose sensitive data in transit.",
  },
  {
    id: "SWIFT-HTTP-URL",
    title: "Hardcoded http:// URL",
    regex: /https?:\/\/[^\s"'`]+/gi,
    severity: "medium",
    cwe: "CWE-319",
    recommendation: "Use HTTPS for network calls carrying credentials or PII.",
    impact_if_unremediated:
      "Cleartext HTTP may allow interception of sensitive request or response data.",
  },
  {
    id: "SWIFT-PROCESS-SHELL",
    title: "Process shell execution",
    regex: /Process\s*\(|NSTask\s*\(|\/bin\/(sh|bash|zsh)/g,
    severity: "high",
    cwe: "CWE-78",
    recommendation: "Avoid shelling out with untrusted input; prefer APIs that take argument arrays without a shell.",
    impact_if_unremediated:
      "Untrusted influence over process execution can compromise the host application environment.",
  },
  {
    id: "SWIFT-HARDCODED-PASSWORD",
    title: "Hardcoded password-like assignment",
    regex: /\b(password|apiKey|api_key|secret|token)\s*=\s*"[^"]{8,}"/gi,
    severity: "high",
    cwe: "CWE-798",
    recommendation: "Remove hardcoded secrets; load from Keychain or secure configuration at runtime.",
    impact_if_unremediated:
      "Embedded secrets in binaries or source can grant unintended access if recovered.",
  },
  {
    id: "SWIFT-PRINT-SENSITIVE",
    title: "print of sensitive-looking values",
    regex: /\bprint\s*\([^)]*(?:token|password|secret|authorization)/gi,
    severity: "medium",
    cwe: "CWE-532",
    recommendation: "Remove sensitive prints; use privacy-preserving os_log.",
    impact_if_unremediated:
      "Logs may retain tokens or credentials beyond the intended session lifetime.",
  },
];

export const SWIFT_SENSITIVE_FILES = [
  "Info.plist",
  ".entitlements",
  "Package.swift",
  "GoogleService-Info.plist",
];
