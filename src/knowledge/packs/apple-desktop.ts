/**
 * Pack: apple-desktop — macOS-oriented storage, entitlements, logging/PII.
 */

import type { KnowledgePack } from "./types.js";

export const appleDesktopPack: KnowledgePack = {
  id: "apple-desktop",
  title: "macOS / Apple desktop hardening",
  description:
    "macOS-oriented controls: entitlements least privilege, Keychain sharing, process execution, privacy logging.",
  stackTags: ["swift", "macos"],
  categories: ["configuration", "secrets", "injection-risk", "privacy"],
  estimatedTokens: 900,
  items: [
    {
      id: "MAC-ENTITLEMENTS",
      title: "Entitlements least privilege",
      description:
        "Review .entitlements for overly broad app groups, keychain sharing, network extensions, and associated domains.",
      category: "configuration",
      severityHint: "medium",
      tags: ["entitlements"],
      stacks: ["macos", "swift"],
      impact_if_unremediated:
        "Excessive entitlements expand the privilege boundary of the app beyond what is required.",
      remediation: "Remove unused entitlements; document each retained privilege.",
      verification_suggestion: "Diff entitlements against actual features; remove unused keys.",
    },
    {
      id: "MAC-KEYCHAIN-SHARING",
      title: "Keychain sharing scope",
      description:
        "keychain-access-groups and app groups should be minimal. Shared Keychain items increase blast radius across apps.",
      category: "secrets",
      severityHint: "high",
      cwe: "CWE-922",
      tags: ["keychain", "entitlements"],
      stacks: ["macos", "swift"],
      remediation: "Limit Keychain access groups to required teammates; avoid sharing high-value secrets broadly.",
      verification_suggestion: "Inspect entitlements for keychain-access-groups membership.",
    },
    {
      id: "MAC-PROCESS-SHELL",
      title: "Process / NSTask shell execution",
      description:
        "Avoid shelling out with untrusted input via Process/NSTask. Prefer argument arrays without a shell.",
      category: "injection-risk",
      severityHint: "high",
      cwe: "CWE-78",
      tags: ["process"],
      stacks: ["macos", "swift"],
      remediation: "Use Process with executableURL + arguments; never interpolate into /bin/sh -c.",
      verification_suggestion: "Grep Process/NSTask and /bin/sh usage near user input.",
    },
    {
      id: "MAC-FILE-SANDBOX",
      title: "Sandbox and file access",
      description:
        "Prefer App Sandbox. Use security-scoped bookmarks for user-granted paths; avoid unrestricted file entitlements when possible.",
      category: "configuration",
      severityHint: "medium",
      tags: ["sandbox"],
      stacks: ["macos"],
      remediation: "Enable App Sandbox; request only needed file/network entitlements.",
      verification_suggestion: "Confirm App Sandbox entitlement and review temporary exception keys.",
    },
    {
      id: "MAC-PRIVACY-LOGGING",
      title: "Privacy-preserving desktop logs",
      description:
        "Desktop apps often log verbosely. Redact tokens, account ids, and path contents that reveal PII.",
      category: "privacy",
      severityHint: "medium",
      cwe: "CWE-532",
      tags: ["logging", "pii"],
      stacks: ["macos", "swift"],
      remediation: "Use os_log privacy modifiers; avoid printing home-directory paths with usernames casually.",
      verification_suggestion: "Sample Console logs during auth and file flows for PII/secrets.",
    },
    {
      id: "MAC-XPC-BOUNDARY",
      title: "XPC / helper privilege boundary",
      description:
        "XPC services and privileged helpers must validate client identity and never trust raw messages for authz.",
      category: "authorization",
      severityHint: "high",
      tags: ["xpc"],
      stacks: ["macos"],
      remediation: "Authenticate XPC peers; validate message schemas; keep helpers least privilege.",
      verification_suggestion: "Review XPC listeners for peer checks before privileged operations.",
    },
    {
      id: "MAC-AUTO-UPDATES",
      title: "Update channel integrity",
      description:
        "Auto-update downloads should be authenticated (code signature / notarization). Avoid unsigned payload installs.",
      category: "supply-chain",
      severityHint: "high",
      tags: ["updates"],
      stacks: ["macos"],
      remediation: "Verify signatures before applying updates; use notarized builds.",
      verification_suggestion: "Confirm updater verifies code signature before replace.",
    },
    {
      id: "MAC-PASTEBOARD-DESKTOP",
      title: "General pasteboard on desktop",
      description:
        "macOS pasteboard is broadly readable. Do not place credentials or recovery codes on the general pasteboard.",
      category: "secrets",
      severityHint: "medium",
      tags: ["pasteboard"],
      stacks: ["macos"],
      remediation: "Avoid clipboard for secrets; clear temporary clipboard data promptly.",
      verification_suggestion: "Search NSPasteboard writes near credential/recovery flows.",
    },
  ],
};
