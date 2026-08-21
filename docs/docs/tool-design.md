---
title: Tool design
description: Learn how secure-mcp names tools, shapes responses, models findings, and stays remediation-oriented as the defensive audit surface grows.
sidebar:
  label: Tool design
  order: 8
---

## Framing

All tools exist for **defensive secure code review**: identify potential weaknesses, classify them, and recommend remediation for the development team. Descriptions must not read as offensive security assistance.

## Naming

Tools use snake_case with a service prefix:

```text
secure_mcp_<action>_<resource>
```

### Current stable names

| Tool | Role |
|------|------|
| `secure_mcp_list_project_structure` | Inventory for review scoping |
| `secure_mcp_analyze_architecture` | Architecture / control placement + `recommended_packs` / `pack_batches` |
| `secure_mcp_get_knowledge_pack` | On-demand capped knowledge packs (fair multi-pack sampling) |
| `secure_mcp_check_authentication` | Authn/authz weaknesses → remediation |
| `secure_mcp_analyze_injection_risks` | Injection-class risks → remediation |
| `secure_mcp_review_secrets` | Secret hygiene → rotate & remediate |
| `secure_mcp_build_remediation_threat_model` | STRIDE fragments for hardening priority |
| `secure_mcp_produce_findings` | Final remediation report rollup |
| `secure_mcp_get_audit_guidance` | Agent workflow and guardrails on demand |
| `secure_mcp_list_authorized_roots` | Allowlisted roots and whether each exists |
| `secure_mcp_list_projects` | Depth-capped discovery of package-manifest and Xcode project roots |
| `secure_mcp_run_local_scanners` | Optional, default-off compose of local `semgrep`/`gitleaks` |

The canonical list lives in `TOOL_NAMES` (`src/tools/index.ts`). When a tool is added, extend this table in the same change.

### Renames from initial bootstrap

| Previous | Current | Reason |
|----------|---------|--------|
| `secure_mcp_scan_injections` | `secure_mcp_analyze_injection_risks` | Neutral, remediation-oriented |
| `secure_mcp_threat_model` | `secure_mcp_build_remediation_threat_model` | Explicit defensive purpose |

**Do not rename** published tool names without a migration plan.

## Compatibility and deprecation policy

Cross-agent consumers hard-code against this server's contracts. The following
surfaces are **stable**: agents and repositories may rely on them across minor
releases.

| Surface | Stable contract |
|---------|-----------------|
| Tool names | Every id in `TOOL_NAMES` (`src/tools/index.ts`) |
| Finding required fields | `evidence`, `severity`, `confidence`, `category`, `impact_if_unremediated`, `remediation`, `residual_risk`, `verification_suggestion`; optional `cwe`/`owasp` |
| Envelope keys | Success `ok: true`; errors `ok: false` with `error` and optional `hint`, plus `isError: true` |
| Enum values | Dispositions (`reportable`, `deferred`, `needs_review`, `suppressed`, `accepted_risk`, `not_applicable`, `fixed`); `coverage.not_observed_means`; `stack`; `response_format`; pack `detail` |
| Annotations | `readOnlyHint: true`, `destructiveHint: false`, `idempotentHint: true`, `openWorldHint: false` on every tool |
| Pack ids | The ids listed in `PACK_IDS` (`src/knowledge/packs/registry.ts`) |

**Additive evolution (non-breaking):** new tools, new optional input fields,
new response or traceability fields, new categories, and new packs may appear
in minor releases. Consumers must tolerate unknown fields in responses.

**Breaking changes:** input schemas are `.strict()`, so any *required* new
input field, a removed or renamed stable surface, or an enum value removal is
a breaking change. Breaking changes require a planned major/minor release with
migration notes in `CHANGELOG.md` — never an incidental edit.

## Registration pattern

Each tool file exports `registerX(server: McpServer)` and calls:

```ts
server.registerTool(name, { title, description, inputSchema, annotations }, handler);
```

- `inputSchema`: Zod object (`.strict()` preferred)
- Descriptions: long, instructional, multi-phase, defensive
- Handler returns `{ content, structuredContent }` via `toolSuccess` / `toolError`

## Shared inputs

Most tools accept:

| Field | Meaning |
|-------|---------|
| `project_root` | Target repo path (absolute preferred) |
| `stack` | `auto` \| `common` \| `typescript` \| `nextjs` \| `swift` \| `expo` |
| `max_files` | Walk safety cap |
| `response_format` | `json` (default) \| `markdown` |

`secure_mcp_produce_findings` accepts a `findings` array rather than scanning disk. An optional `disposition_baseline` (also accepted on category tools via `ProjectRootInput`) re-applies caller-held closed dispositions when `evidence_hash` is unchanged. The server does not write a baseline file; the agent persists the returned `disposition_ledger`.

`secure_mcp_get_knowledge_pack` does **not** require `project_root` (packs are server-bundled). Inputs: `pack_ids` (required, max **6**), optional `categories`, `max_items` (default **24**, hard max **60**), `detail` (`summary` default \| `full`), `include_index` (default **false** — omit `available_packs` catalog). Items are **round-robin fair-sampled** across `pack_ids` so stack packs are not starved; response includes `items_per_pack`. `truncated_by_max_items` is true only when `max_items` cut the category-filtered stream (a narrow `categories` filter alone is not truncation). Prefer architecture `pack_batches` when recommendations span multiple calls.

`secure_mcp_analyze_architecture` with `stack=auto` unions detected stacks; a concrete `stack` value exclusively focuses pack routing (does not re-OR unrelated profile flags). The response keeps legacy path-bucket `surface` fields and adds typed `surfaces`, `surfaces_truncated` (true only when the surface-kind cap dropped later stacks' kinds), `authz_graph` (object/tenant identifier and owner-predicate classification for `authz_sensitive` paths — up to 32 handler files are read, bounded by `maxFileBytes`, to observe predicates, without recording them as reviewed; coverage `evidence_basis` stays `path_inventory`), architecture-time `coverage_gaps` (including sampleable `authz_id` gaps when a handler was inventoried and no object-level check was observed), `priority_paths`, a compact derived `security_brief` (no extra walk), and `threat_highlights` — a stack-gated advisory shortlist lifted from pack titles. Highlights are not findings and must not be treated as a public `noise_tier`. Next-only highlights are never emitted for Swift-only roots.

Category tools follow the injection pack-traceability contract: `applied_pack_ids` are packs whose detectors (or emitted STRIDE fragments) actually evaluated opened content or profile signals. Routed-but-unread packs live on `knowledge_pack_traceability.consulted_pack_ids`. `secure_mcp_check_authentication` still routes consulted packs from the detected (or forced) stacks, narrowed to packs with authn/authz items — so an Expo-only project consults `core` + `expo-rn`, not `auth-web`, and applies only the families that ran. Its Expo/React Native heuristics cover token writes to AsyncStorage/MMKV, credential-shaped `EXPO_PUBLIC_` names, and SecureStore access-control review. Its Swift heuristics cover UserDefaults/app-group token storage, overly broad Keychain accessibility (`kSecAttrAccessibleAlways`), and URLSession server-trust handlers that appear to disable validation. Swift injection/config heuristics (WebView bridges, deep-link handlers, ATS exceptions, weak hashes) live in `analyze_injection_risks`; pasteboard/logging/hardcoded secret patterns live in `review_secrets`.

## Finding schema (required structure)

Every finding must support:

1. **evidence**
2. **classification** — severity, confidence, category, optional CWE/OWASP
3. **impact_if_unremediated** — high-level only
4. **remediation** — concrete fix steps
5. **residual_risk**
6. **verification_suggestion**

The additive traceability fields are `rule_family`, `root_control`, `instance_id`, `source`, `control`, `sink`, `counterevidence`, `proof_gap`, `validation`, and `disposition`. `instance_id` is deterministic for the same detector/control/source location and is independent of session/report numbering.

A standalone machine-readable contract is generated from the Zod source of
truth: `schemas/finding.schema.json` (JSON Schema draft 2020-12, producer/input
semantics). Non-TypeScript consumers can validate findings against it directly.
Regenerate with `pnpm gen:schemas` after any Finding schema change;
`scripts/finding-schema-artifact.test.ts` fails on drift.

See `src/knowledge/findings-schema.ts` and `src/lib/types.ts`.

## Output shape

Success payloads include at least:

```json
{
  "ok": true,
  "project_root": "/path",
  "summary": "one-line human summary",
  "...tool-specific fields"
}
```

Category tools include `findings: Finding[]`.

Read-only inventory and category tools also return `coverage`. It records included paths, excluded/ignored paths with reasons, file/depth/size caps, truncation causes, files actually reviewed, and all candidate dispositions (`reportable`, `needs_review`, `suppressed`, `accepted_risk`, `not_applicable`, `deferred`, `fixed`). `not_observed_means` explicitly distinguishes an empty result within reviewed files from an incomplete scan. In final reports, `reportable` and `deferred` are confirmed open work, `needs_review` is an unconfirmed candidate, and `fixed`/`suppressed`/`accepted_risk`/`not_applicable` remain ledger states excluded from open risk and remediation priority.

Inventory and architecture responses expose a bounded top-level entry preview; `topLevelEntriesTruncated` / `top_level_truncated` indicates when the preview was shortened while stack signals were still collected from the full root directory stream.

Errors use `isError: true` and `{ "ok": false, "error": "...", "hint": "..." }`.

## Annotations (all tools)

| Annotation | Value |
|------------|-------|
| `readOnlyHint` | true |
| `destructiveHint` | false |
| `idempotentHint` | true |
| `openWorldHint` | false |

## False positives

Heuristics over-flag by design. Response:

1. Always set `confidence`
2. Include `notes` teaching verification
3. Prefer candidates with remediation over silent misses

## Adding a new tool

1. Implement `registerMyTool` in `src/tools/myTool.ts`
2. Defensive, multi-phase description; Zod `.strict()` inputs
3. Emit full Finding schema when producing findings
4. Register in `src/tools/index.ts` and `TOOL_NAMES`
5. Extend smoke test + README + this doc
