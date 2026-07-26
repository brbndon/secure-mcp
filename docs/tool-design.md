# Tool design

## Framing

All tools exist for **defensive secure code review**: identify potential weaknesses, classify them, and recommend remediation for the development team. Descriptions must not read as offensive security assistance.

## Naming

Tools use snake_case with a service prefix:

```text
secure_mcp_<action>_<resource>
```

### Current stable names (v1)

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

### Renames from initial bootstrap

| Previous | Current | Reason |
|----------|---------|--------|
| `secure_mcp_scan_injections` | `secure_mcp_analyze_injection_risks` | Neutral, remediation-oriented |
| `secure_mcp_threat_model` | `secure_mcp_build_remediation_threat_model` | Explicit defensive purpose |

**Do not rename** published tool names without a migration plan.

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

`secure_mcp_produce_findings` accepts a `findings` array rather than scanning disk.

`secure_mcp_get_knowledge_pack` does **not** require `project_root` (packs are server-bundled). Inputs: `pack_ids` (required, max **6**), optional `categories`, `max_items` (default **24**, hard max **60**), `detail` (`summary` default \| `full`), `include_index` (default **false** — omit `available_packs` catalog). Items are **round-robin fair-sampled** across `pack_ids` so stack packs are not starved; response includes `items_per_pack`. `truncated_by_max_items` is true only when `max_items` cut the category-filtered stream (a narrow `categories` filter alone is not truncation). Prefer architecture `pack_batches` when recommendations span multiple calls.

`secure_mcp_analyze_architecture` with `stack=auto` unions detected stacks; a concrete `stack` value exclusively focuses pack routing (does not re-OR unrelated profile flags).

`secure_mcp_check_authentication` derives `applied_pack_ids` from the routed packs for the detected (or forced) stacks, narrowed to packs with authn/authz items — so an Expo-only project reports `core` + `expo-rn`, not `auth-web`. Its Expo/React Native heuristics cover token writes to AsyncStorage/MMKV, credential-shaped `EXPO_PUBLIC_` names, and SecureStore access-control review. Its Swift heuristics cover UserDefaults/app-group token storage, overly broad Keychain accessibility (`kSecAttrAccessibleAlways`), and URLSession server-trust handlers that appear to disable validation. Swift injection/config heuristics (WebView bridges, deep-link handlers, ATS exceptions, weak hashes) live in `analyze_injection_risks`; pasteboard/logging/hardcoded secret patterns live in `review_secrets`.

## Finding schema (required structure)

Every finding must support:

1. **evidence**
2. **classification** — severity, confidence, category, optional CWE/OWASP
3. **impact_if_unremediated** — high-level only
4. **remediation** — concrete fix steps
5. **residual_risk**
6. **verification_suggestion**

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

Errors use `isError: true` and `{ "ok": false, "error": "...", "hint": "..." }`.

## Annotations (all v1 tools)

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
3. Prefer candidates with remediation over silent misses for v1

## Adding a new tool

1. Implement `registerMyTool` in `src/tools/myTool.ts`
2. Defensive, multi-phase description; Zod `.strict()` inputs
3. Emit full Finding schema when producing findings
4. Register in `src/tools/index.ts` and `TOOL_NAMES`
5. Extend smoke test + README + this doc
