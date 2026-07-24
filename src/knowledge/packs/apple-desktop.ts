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
  categories: [
    "configuration",
    "secrets",
    "injection-risk",
    "privacy",
    "authorization",
    "supply-chain",
  ],
  estimatedTokens: 1500,
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
      impact_if_unremediated:
        "A weakness in any group member exposes secrets belonging to all of them.",
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
      impact_if_unremediated:
        "Untrusted input reaching a shell can execute arbitrary commands with the app's privileges.",
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
      impact_if_unremediated:
        "Without the sandbox, a single bug can reach the whole user home directory.",
      remediation: "Enable App Sandbox; request only needed file/network entitlements.",
      verification_suggestion: "Confirm App Sandbox entitlement and review temporary exception keys.",
    },
    {
      id: "MAC-HARDENED-RUNTIME",
      title: "Hardened runtime exceptions",
      description:
        "Hardened runtime should be enabled with minimal exceptions; disable-library-validation and allow-unsigned-executable-memory weaken code integrity.",
      category: "configuration",
      severityHint: "high",
      tags: ["hardened-runtime", "codesign"],
      stacks: ["macos"],
      impact_if_unremediated:
        "Weakened code integrity allows unsigned or injected code to run inside the app.",
      remediation:
        "Enable hardened runtime; remove library-validation and executable-memory exceptions unless a documented dependency requires them.",
      verification_suggestion:
        "Check codesign entitlements for com.apple.security.cs.* exceptions and justify each.",
    },
    {
      id: "MAC-PRIVILEGED-HELPERS",
      title: "Privileged helpers and launch items",
      description:
        "SMAppService / launchd helpers and login items run with elevated or persistent scope; install only what is required and keep them signed.",
      category: "authorization",
      severityHint: "high",
      tags: ["launchd", "helper"],
      stacks: ["macos"],
      impact_if_unremediated:
        "A privileged helper becomes a persistent escalation path if it accepts unvalidated requests.",
      remediation:
        "Register helpers via SMAppService; verify client signing requirements; drop privileges as soon as possible.",
      verification_suggestion: "List installed launch agents/daemons and confirm each has an owner and need.",
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
      impact_if_unremediated:
        "Unified logs retain credentials and PII readable during support or diagnostics collection.",
      remediation: "Use os_log privacy modifiers; avoid printing home-directory paths with usernames casually.",
      verification_suggestion: "Sample Console logs during auth and file flows for PII/secrets.",
    },
    {
      id: "MAC-TCC-PERMISSIONS",
      title: "TCC permission least privilege",
      description:
        "Accessibility, Screen Recording, Full Disk Access, and automation permissions are broad; request only what a feature needs and explain why.",
      category: "privacy",
      severityHint: "medium",
      tags: ["tcc", "permissions"],
      stacks: ["macos"],
      impact_if_unremediated:
        "Broad TCC grants let any code in the process observe or modify unrelated user data.",
      remediation:
        "Drop unused TCC-gated features; add clear usage descriptions; isolate high-privilege work where possible.",
      verification_suggestion:
        "Diff requested TCC permissions and usage-description keys against shipped features.",
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
      impact_if_unremediated:
        "Any local process could invoke privileged operations through an unauthenticated listener.",
      remediation: "Authenticate XPC peers; validate message schemas; keep helpers least privilege.",
      verification_suggestion: "Review XPC listeners for peer checks before privileged operations.",
    },
    {
      id: "MAC-LOCAL-LISTENER",
      title: "Local IPC and loopback listeners",
      description:
        "Local HTTP/WebSocket servers and named sockets used by desktop apps must bind to loopback and authenticate callers.",
      category: "configuration",
      severityHint: "high",
      cwe: "CWE-306",
      tags: ["ipc", "listener"],
      stacks: ["macos"],
      impact_if_unremediated:
        "Other local processes — or the network, if bound broadly — can drive app functionality unauthenticated.",
      remediation:
        "Bind to 127.0.0.1, require a per-launch token, and validate request origin before privileged handlers.",
      verification_suggestion: "List listening sockets while the app runs and confirm scope plus auth.",
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
      impact_if_unremediated:
        "An unverified update payload can replace the app binary with attacker-supplied code.",
      remediation: "Verify signatures before applying updates; use notarized builds.",
      verification_suggestion: "Confirm updater verifies code signature before replace.",
    },
    {
      id: "MAC-URL-SCHEME",
      title: "URL scheme and Apple event handling",
      description:
        "Custom URL schemes and scripting/Apple event handlers are entry points from other apps; validate payloads before privileged actions.",
      category: "injection-risk",
      severityHint: "medium",
      cwe: "CWE-939",
      tags: ["urlscheme", "appleevents"],
      stacks: ["macos"],
      impact_if_unremediated:
        "Another local app can drive sensitive workflows with parameters it fully controls.",
      remediation:
        "Allowlist scheme paths and parameters; require confirmation or re-auth before destructive actions.",
      verification_suggestion: "Review URL scheme handlers and scripting commands for validation.",
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
      impact_if_unremediated:
        "Any running app can read pasteboard contents, including copied credentials.",
      remediation: "Avoid clipboard for secrets; clear temporary clipboard data promptly.",
      verification_suggestion: "Search NSPasteboard writes near credential/recovery flows.",
    },
  ],
};
