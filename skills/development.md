# Skill: Developing secure-mcp

Guidance for coding agents that modify this repository.

## Product constraints

- Local **stdio** MCP only, strict protocol revision `2026-07-28` (`legacy: "reject"`)
- TypeScript + official MCP SDK v2 (`@modelcontextprotocol/server`, `@modelcontextprotocol/client`)
- Open source under Apache-2.0
- **Defensive secure-code-review framing only** — identify weaknesses, classify, remediate
- Keep comments for non-obvious security or MCP decisions, not basic syntax
- **Progressive knowledge packs** — thin always-on skill; stack checklists load on demand via `secure_mcp_get_knowledge_pack`

## Language & safety rules (user-facing surfaces)

Anything an agent or hosted model reads (tool names/descriptions, skills, docs, knowledge copy, finding schema) must:

- Prefer: “identify potential weaknesses”, “classify by CWE/severity/confidence”, “recommend remediation”, “harden the codebase”
- Avoid: exploit generation, PoC attack code, “weaponize”, offensive bypass framing
- Findings: evidence → classify → impact_if_unremediated → remediation → residual_risk → verification_suggestion

## Setup

```bash
pnpm install
pnpm build
pnpm smoke
```

Install the master skill and MCP client wiring for pi / Cursor / Codex:

```bash
./scripts/install-agents.sh install    # idempotent; re-run any time
./scripts/install-agents.sh check     # verify symlinks, configs, server startup
./scripts/install-agents.sh uninstall
```

Windows uses the equivalent `scripts/install-agents.ps1`. The installer never
overwrites conflicting non-owned entries or skills.

## Code map

| Path | Responsibility |
|------|----------------|
| `src/index.ts` | Entry, configuration, stdio |
| `src/server.ts` | Server factory |
| `src/tools/` | One tool per file + `index.ts` registration |
| `src/knowledge/packs/` | Named packs + registry / stack routing |
| `src/knowledge/common.ts` etc. | Scan patterns used by category detectors |
| `scripts/install-agents.sh` / `install-agents.ps1` | Idempotent install/check/uninstall of the master skill links + MCP client configs (pi, Cursor, Codex) |
| `agents/codex.toml` | OpenAI Codex agent manifest copied to `~/.codex/agents/secure-mcp.toml` by the install script |
| `src/lib/filesystem.ts` | Safe FS walk/read/helpers + stack profiling |
| `src/lib/types.ts` | Shared TS types |
| `skills/security-auditor.md` | Thin agent orchestrator (~2k tokens) |

## Knowledge packs

| Pack id | Audience |
|---------|----------|
| `core` | All stacks |
| `threat-model` | Trust boundaries / STRIDE planning |
| `web-next` | Next.js App Router |
| `web-api` | General API handlers |
| `auth-web` | Cookies, CSRF, web auth |
| `swift-ios` | iOS / SwiftUI |
| `apple-desktop` | macOS entitlements / desktop |
| `expo-rn` | Expo / React Native |
| `secrets` | Rotation, env, client-bundle |

Aim ~10–13 checklist items per pack (a full five-pack recommendation must fit `ABSOLUTE_MAX_ITEMS`), and give every item `impact_if_unremediated`, `remediation`, and `verification_suggestion` — they are required `PackItem` fields. Keep `pack.categories` in sync with the categories its items use, and only claim a `stackTags` stack the router actually routes to that pack. Do not auto-load markdown refs from tools. See `src/knowledge/ATTRIBUTION.md` for inspiration notes (not for tool payloads).

## Rules of the road

1. **Stable API:** do not rename tools or break `Finding` fields without explicit approval.
2. **Small PR-sized changes:** prefer additive tools/patterns over refactors.
3. **No stdout logging** in the server (stderr only).
4. **No executing target code.**
5. **Path safety:** always go through `normalizeProjectRoot` / `resolveSafePath`.
6. **Build must pass:** `pnpm build` after meaningful edits.
7. **Update docs** when behavior or tools change (README, docs/*, skills/*).
8. **Keep defensive framing** in every new description string.
9. **Context discipline:** architecture returns `recommended_packs` + `pack_batches` (≤6 ids/call); full checklists only via `get_knowledge_pack` (no `available_packs` unless `include_index`). Multi-pack item selection is **round-robin** (`filterPackItems`); defaults `DEFAULT_MAX_ITEMS=24`, `ABSOLUTE_MAX_ITEMS=60`.

## Adding a tool

1. Implement `registerMyTool` in `src/tools/myTool.ts`.
2. Use Zod `.strict()` input schema with `.describe()` on fields.
3. Write a long, agent-oriented **defensive** `description` (purpose, multi-phase workflow, args, returns, guardrails).
4. Set annotations (`readOnlyHint: true` for reviewers).
5. Return `toolSuccess` / `toolError` helpers; use `buildFinding` for full schema.
6. Register in `src/tools/index.ts` and `TOOL_NAMES`.
7. Add a smoke-test invocation if practical.
8. Document in README + `docs/docs/tool-design.md`.

## Adding / editing a pack

1. Add or edit `src/knowledge/packs/<id>.ts` with `KnowledgePack` shape.
2. Register in `packs/registry.ts` (`PACK_BY_ID` + `PACK_IDS`).
3. Update `recommendPackPlan` / `recommendPackIds` if stack routing changes; keep `pack_batches` ≤ `MAX_PACKS_PER_REQUEST` (6).
4. Keep item count and copy lean; prefer checkable remediation over essays. Multi-pack loads fair-sample via `filterPackItems` — do not reintroduce sequential drain that starves stack packs.
5. Re-export from `common.ts` / `nextjs.ts` / `swift.ts` if scanners still need checklist aliases.
6. When changing sampling or caps, extend `registry.test.ts` multi-pack coverage asserts and smoke.

## Testing

- `pnpm verify` — typecheck + unit tests + build + smoke
- `pnpm test` — unit tests, registry metadata checks, and strict v2 protocol tests
- `pnpm test:installer` — temp-home integration tests for the Bash/PowerShell installers
- `pnpm test:package` — nonpublishing npm tarball E2E against a temporary consumer
- `pnpm smoke` — client connect + tool calls against `fixtures/` (Next, Expo, non-Expo `app.json`)
- Manual: MCP Inspector with `SECURE_MCP_ALLOWED_ROOTS` set to a test fixture or repository

## Style

- Strict TypeScript, no `any`
- ESM (`"type": "module"`, `.js` extensions in relative imports)
- Prefer explicit types on exported functions
- Comments explain non-obvious security or MCP decisions, not basic syntax
