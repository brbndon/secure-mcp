# Tier 2 skill delta

**Apply at integration time** (after Tier 1's slim base is in place) by the integration
agent. These are exact additive lines for `.agents/skills/secure-mcp/SKILL.md`. Tier 2 does
**not** edit SKILL.md directly.

## 1. New tools (Phase 0 / readiness)

In **Phase 0: MCP inventory and readiness**, after the existing "list the live MCP tools"
sentence, add:

> When the target root is unknown, call `secure_mcp_list_authorized_roots` (optionally with
> `include_metadata: true`) to see which absolute roots the server may inspect, and
> `secure_mcp_list_projects` on an allowlisted parent to discover nested package manifests
> before choosing a `project_root`. Both are read-only and fail closed on the allowlist.

## 2. Routing table — unknown / unsupported stacks

Add a row to the preflight routing table (after the "Mixed / monorepo" row):

| Unknown / other (Python, Go, Java, Android/Kotlin, Ruby, PHP, Rust, .NET) | No known app-stack signals; language manifests only (`pyproject.toml`/`requirements.txt`, `go.mod`, `build.gradle`, `Cargo.toml`, etc.) | Inventory with `auto`. Architecture returns `unsupported_signals` and a limited-review note; expect `core`, `secrets`, `threat-model` only. Report a **limited generic review**, never full stack coverage. |

And update the "Unknown or minimal" bullet under pack-selection overrides from
`core` and, when useful, `threat-model` to:

> - Unknown or minimal: `core`, `secrets`, `threat-model` — no stack pack without evidence.

## 3. Architecture retained fields (Phase 2)

Add `unsupported_signals` to the list of retained architecture fields:

> - `unsupported_signals` (recognizable-but-uncovered stacks; when non-empty the review is a limited generic review)

## 4. Authz prioritization (Phase 3)

In **Phase 3: category analysis**, in the reconciliation sub-step, add a bullet:

> - Before trusting an empty authorization result, sample zero-hit **authorization-sensitive** surfaces (`authz_sensitive` on typed surfaces; dynamic `[id]` routes, admin/account/tenant paths, webhooks, server actions, deep links) — object-level authorization (BOLA/IDOR) matters more than a generic auth check.

## 5. Optional local scanners

Add a short line after the Phase 3 category tools paragraph:

> `secure_mcp_run_local_scanners` composes locally-installed `semgrep`/`gitleaks` (optional, default off — requires `enable: true` AND server env `SECURE_MCP_LOCAL_SCANNERS=1`; offline-first, no ruleset download unless `allow_remote_rules: true`). Results are `needs_review` candidates — still confirm each in source manually.

---

**Notes for the integration agent:**

- Tool names are already registered in `src/tools/index.ts` and listed in
  `scripts/test-constants.ts` `REQUIRED_TOOLS`. `server.json` (Tier 3) has not been updated for
  the three new tools; add registry tool metadata there if the registry schema requires it.
- New Tier 2 test files run under `pnpm exec tsx --test`:
  `src/tools/analyzeArchitecture.test.ts`, `src/tools/listProjects.test.ts`,
  `src/tools/runLocalScanners.test.ts`. Wire them into the `package.json` `test` script during
  integration (package.json is "nobody" during parallel work).
- `recommendPackPlan` now returns `core + secrets + threat-model` for unknown/minimal stacks
  (was `core + threat-model`). This is intentional honesty and is covered by
  `registry.test.ts` and `analyzeArchitecture.test.ts`.
