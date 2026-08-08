# Security policy

## Reporting a vulnerability in secure-mcp

Please report suspected vulnerabilities through [GitHub private vulnerability reporting](https://github.com/brbndon/secure-mcp/security/advisories/new). Do not open a public issue for a vulnerability and do not include live credentials, private source code, or weaponized proof-of-concept material.

Include the affected version or commit, the trust boundary involved, the smallest safe reproduction you can provide, the expected invariant, and the observed behavior. Reports about filesystem containment, untrusted-output handling, secret redaction, stdio integrity, or unexpected target-code execution are especially important.

The maintainers aim to acknowledge a complete report within five business days, coordinate validation and remediation privately, and credit reporters who want attribution. Please allow a reasonable remediation window before public disclosure.

## Supported versions

Security fixes are made against the latest release and the `main` branch. Older versions may be asked to reproduce on the latest release before a fix is prepared.

## Purpose and scope

`secure-mcp` is a local, defensive, read-only MCP server for helping a code owner or an explicitly authorized reviewer identify potential weaknesses and plan remediation. It performs bounded static inspection of files under a requested project root. It does not execute target-project code, make network requests, mutate target files, or test a live service.

The supported review surfaces are:

- TypeScript, JavaScript, Node.js, and common API/server code.
- Next.js, including App Router route handlers, Server Actions, middleware, client bundles, and configuration.
- Swift/SwiftUI and related iOS/macOS configuration, Keychain, URLSession, WebView, deep-link, and entitlement surfaces.
- Expo and React Native JavaScript/native-configuration surfaces, including SecureStore, AsyncStorage/MMKV, AuthSession, and `EXPO_PUBLIC_` configuration.

The server is not a general-purpose SAST engine. Findings are bounded, evidence-oriented candidates for developer confirmation.

## Assets and trust boundaries

Reviews may protect source code, credentials and signing material, user sessions, personal/business data, device-local secrets, client bundles, audit records, and service availability. Typical boundaries include:

- browser or mobile client input to server/API, middleware, Route Handler, or Server Action code;
- UI, deep links, WebView content, and native bridges to privileged app logic;
- app logic to Keychain, SecureStore, app-group storage, UserDefaults, or other local stores;
- application code to databases, third parties, and credential-bearing configuration; and
- source/CI configuration to production secret stores.

Attacker-controlled inputs are modeled as untrusted request parameters, headers, cookies, uploads, URL/deep-link values, WebView messages, client-bundle values, environment/configuration values, and identifiers supplied by a client. A detector does not assume that an input reaches a sink: source-to-sink reachability, authorization, runtime configuration, and deployment context must be validated by the code owner.

## Security invariants

The following are product invariants:

1. Every audit operation is read-only and remains under the requested project root after lexical and realpath/symlink containment checks.
2. Target code, build scripts, package scripts, plugins, and binaries are never executed.
3. Stdio stdout remains reserved for MCP JSON-RPC; diagnostics belong on stderr.
4. File count, directory depth, file size, and response size are bounded. Coverage output records ignored, excluded, reviewed, and truncated scope so “not observed” never means “not scanned.”
5. Secret-like evidence is redacted before it is returned. Review output is explicitly marked as untrusted audit data, and invisible control characters are neutralized before it crosses the MCP boundary. Review output must not be used to recover, validate, or operate credentials.
6. Findings remain remediation-focused and include evidence, control context, proof gaps, and validation guidance rather than attack instructions.

## Reportable severity

Report a candidate as `reportable` only when the evidence is sufficient for the authorized owner to act on a concrete control gap. Otherwise use `needs_review`, `suppressed`, `not_applicable`, or `deferred` with a reason. Severity is about plausible impact if the gap is left unremediated:

- **Critical:** likely compromise of authentication/signing authority, broad sensitive-data disclosure, or a secret that appears active and grants high-impact access.
- **High:** material confidentiality, integrity, authorization, or availability impact across a meaningful surface.
- **Medium:** scoped or conditional impact, defense-in-depth gaps, or weaknesses requiring additional conditions.
- **Low:** limited exposure or hardening opportunity with constrained impact.
- **Info:** an observed control or review prompt that needs confirmation and is not itself a demonstrated vulnerability.

Confidence is separate from severity. A high-severity heuristic with an unresolved proof gap remains a candidate until validated.

## Exclusions and accepted risks

Out of scope are exploit development, proof-of-concept or payload generation, bypass recipes, credential use or validation, live-target interaction, remote transport, external tracking, target-code execution, write/fix tools, and integration with a Codex Security plugin. The server does not claim that a project is secure, does not inspect runtime behavior, and does not replace dependency, infrastructure, cloud, binary, or manual authorization review.

Accepted limitations include regex false positives and false negatives, incomplete monorepo coverage, ignored/generated/vendor content, unreadable files, symlink skips, file/depth/size caps, redacted evidence, and configuration or secrets that exist outside the inspected tree. A clean result means only that no candidate was observed in the files actually reviewed within the reported scope.

## Reporting a non-security product issue

For a non-security defect, open a [GitHub issue](https://github.com/brbndon/secure-mcp/issues) with a minimal reproducible local fixture, the tool and input shape, the structured coverage report, and the observed defensive behavior. Do not include live credentials, sensitive source, exploit code, or interaction with a real target.
