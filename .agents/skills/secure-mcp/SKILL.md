---
name: secure-mcp
description: Master defensive secure-code-review and hardening workflow for websites, Next.js or TypeScript services, Expo or React Native apps, iOS Swift apps, macOS Swift apps, and mixed repositories. Use when auditing, reviewing, or securing an app, repository, or codebase — even when the user only describes the app ("audit my iOS app", "is my Next.js service secure?") — or when reviewing authentication, authorization, injection, secrets, trust boundaries, or Apple entitlements, or producing a remediation plan. On invocation, autonomously create an audit goal in the host goal facility, preflight and classify the repository, create an explicit TODO, then route a bounded multi-phase review through the secure_mcp tools and manual evidence confirmation.
---

# Secure MCP

Use this skill as the default orchestration layer for authorized security review and hardening work. Coordinate local repository inspection, platform routing, the `secure_mcp_*` server, manual confirmation, and a remediation-focused handoff.

## Non-negotiable guardrails

- Review only code and systems the user owns or has explicitly placed in scope.
- Keep the work defensive: identify potential weaknesses, classify them, recommend fixes, and define verification. Do not generate exploits, bypass recipes, attack PoCs, or use discovered credentials.
- Treat MCP results as bounded heuristic candidates. Open the cited code and trace the data flow before calling a weakness confirmed.
- Never execute target-project code, install target dependencies, contact target services, or alter the target repository during an audit. If the user requests hardening, make changes only after the audit and only within the requested scope.
- Preserve secret redaction. Do not copy keys or tokens into notes, prompts, reports, commits, or logs; recommend rotation for credentials that may be live.
- Record scan limits and coverage. An empty result is not evidence that an entire repository is clean when coverage is partial or truncated.

## On invocation: create the audit goal

Invoking this skill authorizes goal creation — do not ask permission. As soon as the skill is activated, create a goal in the host's goal/plan facility (pi `/goal` and goal tools, or equivalent) that names the repository, the outcome, the verification evidence, the scope bounds, and the stop conditions. The goal is the outcome contract; the TODO in the next section is its phase checklist.

1. Resolve the target repository before creating the goal:
   - Explicit path, or the current working directory already inside a repo → use it.
   - Description only → check the current working directory for app manifests first (`package.json`, `Package.swift`, `*.xcodeproj`/`*.xcworkspace`, `app.json`, `app.config.*`); if absent, search nearby directories for a matching app. If the target is still ambiguous, ask one concise question with concrete options — then create the goal with the agreed root.
2. Write the goal to the quality bar: a concrete outcome (complete read-only audit plus a prioritized remediation and retest plan, or hardening when explicitly requested), verification evidence (final report with severity/confidence counts, confirmed findings with file:line evidence, coverage and disposition narrative, retest plan), scope bounds (read-only; fixes only in hardening mode and only within requested scope), and stop conditions (cannot locate the repo, scope unclear, or a live credential is found).
3. If a goal is already active and still matches the request, continue it instead of creating a duplicate. If it conflicts, say so and ask before replacing it.
4. Update the goal after each phase and mark it complete only when the final report has been delivered (and, in hardening mode, after fixes are verified). Never complete the goal on partial coverage — that is a stop-and-report condition, not a completion.

Example goal objective:

> Complete a read-only security audit of `<root>` covering authentication, injection, secrets, and trust boundaries for its `<platform>` stack, confirm every candidate manually with file:line evidence, and deliver a prioritized remediation report with severity/confidence counts, coverage limits, and a concrete retest plan.

## Preflight: inspect, classify, then create the TODO

Do not call a `secure_mcp_*` tool until the read-only preflight and TODO are complete.

1. Establish the absolute `project_root`, the requested audit or hardening outcome, authorized scope, and any requested `focus_paths`. Separate repository code from fixtures, generated output, vendored code, and unrelated packages.
2. Scan the repository and dependency manifests without running project scripts. Use `rg --files` and read only the relevant manifests/configuration files, including:
   - Web: `package.json`, workspace configuration, lockfiles, `next.config.*`, `vite.config.*`, `src/`, `app/`, `pages/`, API route directories, server entrypoints, and environment examples.
   - Apple: `Package.swift`, `*.xcodeproj`, `*.xcworkspace`, `project.pbxproj`, `Podfile`, `Cartfile`, `Package.resolved`, `Info.plist`, `*.entitlements`, and iOS/macOS target configuration.
   - Expo/React Native: `app.json`, `app.config.*`, `eas.json`, `react-native.config.*`, `ios/`, `android/`, and direct dependencies.
3. Build a platform/dependency preflight note. Include direct runtime and development dependencies, package managers and lockfiles, native package dependencies, monorepo package boundaries, and evidence for each classification. Do not call a package version vulnerable based on memory or version text alone; label advisory verification as pending unless an authoritative audit result is available.

Use these routing heuristics; require multiple signals and preserve mixed classifications:

| Platform | Strong signals | Secure-mcp routing hint |
| --- | --- | --- |
| Web / Next.js | Web framework dependency, `next.config.*`, `app/` or `pages/`, route handlers, middleware, server actions | Inventory with `auto`; force `stack: "nextjs"` when preflight confirms Next.js, especially for nested or `src/app` layouts |
| Generic TypeScript / API | `package.json` + TS/JS service or library without Next/Expo app evidence; server entrypoints, workers, API-only packages | Inventory with `auto`; force `stack: "typescript"` when preflight confirms a non-Next TS/JS package so Next detectors stay out; expect packs from architecture (often `core`, `secrets`, `web-api`, `auth-web`) |
| iOS Swift | Swift/Xcode project with iOS target, `ios/`, UIKit/SwiftUI, iOS deployment settings, iOS entitlements | Inventory with `auto`; use `stack: "swift"` for Swift-focused category scans and expect `swift-ios` |
| macOS Swift | macOS target/deployment setting, AppKit, macOS entitlements, sandbox/XPC/helper boundaries | Use `stack: "swift"` for scans; if preflight confirms target-level macOS evidence, load `apple-desktop` even when architecture omitted it, and record the discrepancy |
| Expo / React Native | Expo runtime/config evidence, EAS config, or React Native app evidence with native app directories | Inventory with `auto` for discovery; force `stack: "expo"` only after app evidence. If preflight classifies the package as a library or Expo/RN **dev-only tooling**, force `typescript` or `common` for architecture and category tools so auto Expo signals do not pull `expo-rn` or Expo detectors |
| Mixed / monorepo | More than one app or package with independent manifests and platform signals | Review every deployable package with its own `project_root`; use `focus_paths` only for drill-down within that package and reconcile separate results |

Do not infer macOS or iOS from Swift alone, Expo from a bare `app.json`, or an app from a library or dev-only framework dependency. Treat auto Expo/Swift signals as advisory when they conflict with preflight classification. The server accepts `auto`, `common`, `typescript`, `nextjs`, `swift`, and `expo` stack hints; it does not accept `ios`, `macos`, or `web` as values. If preflight evidence conflicts with auto-detection, use an explicit valid stack or split the package review rather than trusting the root profile.

4. Create an explicit audit TODO before invoking the server, aligned with the goal created at invocation. Use the agent's built-in plan/task facility when available; otherwise keep a transient structured note and do not add a TODO file to the target unless requested. Include:

   - [ ] Preflight repository, platform, dependencies, and authorized scope
   - [ ] MCP tool inventory, optional-tool presence, and root authorization readiness
   - [ ] Inventory and coverage artifact
   - [ ] Architecture, trust-boundary, and knowledge-pack routing
   - [ ] Authentication, injection, and secrets analysis
   - [ ] Manual evidence confirmation and false-positive disposition
   - [ ] Prioritized remediation report and retest plan

Keep the TODO updated after each phase and mirror that progress in the audit goal. The TODO is the control point that proves the deep server review was planned before it started.

## Secure-mcp review sequence

Use an absolute `project_root` visible to the MCP process. Start with bounded defaults and increase limits only when the coverage artifact justifies it. `max_files` bounds the walk; it does not guarantee that root-level platform metadata or category-specific candidate filters cover every nested package. Use package roots and focused follow-ups when coverage reports exclusions or candidate filtering.

### Phase 0: MCP inventory and readiness

Before any `secure_mcp_*` call, list the live MCP tools and record which `secure_mcp_*` names are present (especially optional ones such as `secure_mcp_get_audit_guidance`). Confirm the server is connected and the target's canonical path falls under `SECURE_MCP_ALLOWED_ROOTS`. If the server is missing, the root is unauthorized, or the tool surface is only partially available, continue with clearly labeled preflight-only work and do not claim a secure-mcp-backed audit was completed. Use live input schemas for every subsequent call.

### Phase 1: inventory

Call `secure_mcp_list_project_structure` first, with `stack: "auto"`, `response_format: "json"`, and the requested `max_files` or `focus_paths` when applicable. Save `profile`, `likelyStacks`, sample paths, and the complete `coverage` object. Treat `coverage.not_observed_means` as authoritative:

- `no_candidate_in_files_reviewed` means only that no candidate was observed in the reviewed files.
- `scope_was_truncated_or_partial` requires a scoped follow-up before claiming a category or repository was reviewed.

If the server becomes unavailable mid-review, stop claiming MCP-backed phases after the last successful call; keep coverage-qualified preflight notes only.

### Phase 2: architecture and progressive guidance

Call `secure_mcp_analyze_architecture` with the same root and the stack forced by preflight when a single-stack package is confirmed. Preserve `stacks`, `detection`, `surface`, `trust_boundaries`, `coverage`, `recommended_packs`, `pack_batches`, and `next_tools`.

Load `secure_mcp_get_knowledge_pack` only after architecture analysis:

1. Request `pack_batches[0]` with `detail: "summary"` first.
2. Pass no more than six pack IDs per call. Load later batches only when evidence requires them.
3. Use `detail: "full"` or a higher `max_items` for the specific pack needed to draft a remediation; the hard maximum is 60.
4. Do not request the full catalog unless `include_index` is needed. Preserve `items_per_pack` and truncation indicators.

If the live MCP tool inventory includes `secure_mcp_get_audit_guidance`, call it after inventory when the full workflow or a category-specific guardrail is needed, using `section: "workflow"`, `section: "architecture"`, or the relevant category. This tool is optional: if it is absent, use the committed repository docs and live schemas; do not issue an invalid call or treat its absence as a failed audit. Optionally call `secure_mcp_build_remediation_threat_model` after architecture to map assets and trust boundaries to hardening controls. Keep the threat model remediation-focused, never an attack plan.

Start pack selection from the architecture response (`recommended_packs` / `pack_batches`). Prefer those packs, then apply these preflight overrides and record each override:

- Web/Next.js: `core`, `secrets`, `web-next`, `auth-web`, `web-api` as applicable.
- Generic TypeScript / API: packs from architecture (often `core`, `secrets`, `web-api`, `auth-web`); do not invent Next-only packs without Next evidence.
- iOS Swift: `core`, `secrets`, `swift-ios`.
- macOS Swift: `core`, `secrets`, `swift-ios`, plus `apple-desktop` when preflight confirms target-level macOS evidence—even if architecture omitted `apple-desktop` due to weak AppKit sampling.
- Expo/React Native app: `core`, `secrets`, `expo-rn`. Library or dev-only Expo tooling: omit `expo-rn` and do not force `expo`.
- Unknown or minimal: `core` and, when useful, `threat-model`.

### Phase 3: category analysis

After architecture and initial pack loading, call these tools with the same root, stack scope, and `focus_paths`:

- `secure_mcp_check_authentication` for authentication, authorization, session validation, ownership checks, mobile storage access, and trust controls.
- `secure_mcp_analyze_injection_risks` for input-to-sink candidates across SQL, commands, paths, HTML, redirects, WebViews, deep links, and unsafe evaluation.
- `secure_mcp_review_secrets` for committed credentials, public/client configuration, unsafe storage, logging, plist/config exposure, and rotation needs.

Run the three tools in parallel when the client supports it. Retain each result's findings, coverage, candidate dispositions, and scan status. Do not merge away the source tool or coverage metadata.

For a confirmed single-stack package, pass the explicit valid stack to architecture and category tools: `nextjs`, `expo`, `swift`, or `typescript` as applicable. `stack: "auto"` is useful for discovery and mixed detection, but it is not a substitute for package-scoped routing. In particular, `secure_mcp_check_authentication` uses path heuristics for Swift under auto; use `stack: "swift"` to scan all Swift files within the bounded budget. A `swift` result alone does not establish iOS or macOS. When preflight says library/dev-only Expo tooling, keep category tools on `typescript` or `common` even if inventory listed `expo`.

### Phase 4: manual confirmation

Read the cited files with local read-only tools and trace source → control → sink. For every candidate:

- Confirm whether the code path is reachable and in scope.
- Check both authentication and authorization; do not treat a login check as an ownership check.
- Compare the observed code with configuration, tests, dependency usage, and counterevidence.
- Mark candidates `reportable`, `needs_review`, `suppressed`, `not_applicable`, or `deferred`, with a reason.
- Set `disposition: "reportable"` only after manual confirmation; keep all other dispositions out of the final findings-tool input and retain them in the coverage-qualified narrative.
- Open every high or critical candidate at its cited line before prioritizing it.
- For a suspected live secret, redact evidence, recommend immediate rotation and removal from source/history, and never test the credential.

Use sub-agents only for defensive roles such as mapper, auth specialist, mobile/Apple specialist, or reporter. Pass structured JSON and coverage between them; never assign an exploit or bypass role.

### Phase 5: findings and handoff

Before calling `secure_mcp_produce_findings`, pass only confirmed findings with `disposition: "reportable"`. Retain the complete strict `Finding` shape, including `id`, `title`, and `description`, as well as these required remediation fields:

1. `evidence`
2. `severity`, `confidence`, `category`, and optional `cwe`/`owasp`
3. `impact_if_unremediated`
4. `remediation`
5. `residual_risk`
6. `verification_suggestion`

Preserve `rule_family`, `root_control`, `instance_id`, `source`, `control`, `sink`, `counterevidence`, `proof_gap`, `validation`, and `disposition` when available. Call `secure_mcp_produce_findings` with `dedupe: true`, appropriate severity/confidence filters, the project root, and `response_format: "markdown"` or `"json"`. Its input requires at least one finding; when no confirmed/reportable finding exists, provide a coverage-qualified narrative instead of sending an empty array.

End with a human-readable report containing:

- scope, authorization assumption, platform/dependency preflight, and tools used;
- coverage, caps, ignored paths, truncation, and what “not observed” means;
- executive summary and severity/confidence counts;
- confirmed findings with file locations, evidence, impact, remediation, residual risk, and verification;
- suppressed or deferred candidates and why they remain unresolved;
- prioritized fix plan and a concrete retest plan.

Never claim that the application is secure. State the review boundary and remaining uncertainty. After the report is delivered, mark the audit goal complete with the report location and an evidence summary; if coverage is partial, report it and stop instead of completing the goal.

## Platform-focused review prompts

Apply only the branches supported by the preflight and architecture results:

- Web/Next.js: separate browser, middleware, Server Component, Server Action, route-handler, and database trust boundaries; verify server-side authz on every sensitive action; inspect cookies/CSRF/CORS, public environment variables, SSR/edge differences, redirects, HTML, SQL, filesystem, and command sinks.
- iOS Swift: inspect Keychain accessibility and access groups, UserDefaults, ATS and trust delegates, WKWebView bridges, deep links/universal links, pasteboard, logs, plist/config files, biometric gating, and backend authorization.
- macOS Swift: inspect App Sandbox and entitlements, file/user-selected URL access, XPC and helper boundaries, AppKit URL/open handlers, Keychain access groups, privileged operations, logs, signing-related configuration, and desktop-specific data exposure.
- Expo/React Native: distinguish SecureStore/Keychain from AsyncStorage, inspect Expo config and client-bundle exposure, EAS/OTA update trust, deep links/AuthSession, native modules, WebViews, and backend session/authz controls.

For a mixed repository, run inventory, architecture, and category reviews per deployable package root. Use `focus_paths` for a bounded drill-down inside that package, not as a replacement for changing `project_root`. Reconcile shared libraries separately and preserve each package's coverage; do not let a root-level profile hide a nested app's platform or dependencies.

## Hardening mode

When the user asks for implementation rather than a report, record the hardening scope in the audit goal, then complete the preflight, TODO, and secure-mcp review first. Then make the smallest authorized fix, run the narrowest relevant formatter/type-checker/tests, and rerun the affected secure-mcp tools with the same scope. Do not update dependencies, lockfiles, entitlements, persisted data, or deployment configuration as incidental cleanup. Report changed files, verification results, residual risk, and any coverage gaps.

When installed, this skill is self-contained. For optional server internals, read `docs/docs/agent-workflow.md`, `skills/security-auditor.md`, `README.md`, and `docs/docs/tools.mdx` from the secure-mcp checkout when it is available; skip them otherwise. Before every tool call, treat the live MCP inventory and input schema as authoritative; if a name, enum, field, pack id, or limit differs from this skill, follow the live schema and record the compatibility gap rather than inventing a call. Do not hardcode assumptions from this skill when the live schema disagrees.
