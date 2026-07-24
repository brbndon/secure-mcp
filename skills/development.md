# Skill: Developing secure-mcp

Guidance for coding agents that modify this repository.

## Product constraints

- Local **stdio** MCP only (v1)
- TypeScript + official `@modelcontextprotocol/sdk`
- Private / closed-source (`private: true`, `UNLICENSED`)
- **Defensive secure-code-review framing only** — identify weaknesses, classify, remediate
- Keep code clear and commented—the owner is learning and multiple agents collaborate
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
export SECURE_MCP_LICENSE_KEY=smcp_dev_local_testing_key_v1
pnpm smoke
```

## Code map

| Path | Responsibility |
|------|----------------|
| `src/index.ts` | Entry, license, stdio |
| `src/server.ts` | Server factory |
| `src/tools/` | One tool per file + `index.ts` registration |
| `src/knowledge/packs/` | Named packs + registry / stack routing |
| `src/knowledge/common.ts` etc. | Scan patterns + re-exports of pack checklists |
| `src/lib/filesystem.ts` | Safe FS walk/read/helpers + stack profiling |
| `src/lib/license.ts` | License resolution/validation |
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

Aim ~15–25 checklist items per pack. Do not auto-load markdown refs from tools. See `src/knowledge/ATTRIBUTION.md` for inspiration notes (not for tool payloads).

## Rules of the road

1. **Stable API:** do not rename tools or break `Finding` fields without explicit approval.
2. **Small PR-sized changes:** prefer additive tools/patterns over refactors.
3. **No stdout logging** in the server (stderr only).
4. **No executing target code.**
5. **Path safety:** always go through `normalizeProjectRoot` / `resolveSafePath`.
6. **Build must pass:** `pnpm build` after meaningful edits.
7. **Update docs** when behavior or tools change (README, docs/*, skills/*).
8. **Keep defensive framing** in every new description string.
9. **Context discipline:** architecture returns `recommended_packs` + `pack_batches` (≤6 ids/call); full checklists only via `get_knowledge_pack` (no `available_packs` unless `include_index`).

## Adding a tool

1. Implement `registerMyTool` in `src/tools/myTool.ts`.
2. Use Zod `.strict()` input schema with `.describe()` on fields.
3. Write a long, agent-oriented **defensive** `description` (purpose, multi-phase workflow, args, returns, guardrails).
4. Set annotations (`readOnlyHint: true` for reviewers).
5. Return `toolSuccess` / `toolError` helpers; use `buildFinding` for full schema.
6. Register in `src/tools/index.ts` and `TOOL_NAMES`.
7. Add a smoke-test invocation if practical.
8. Document in README + `docs/tool-design.md`.

## Adding / editing a pack

1. Add or edit `src/knowledge/packs/<id>.ts` with `KnowledgePack` shape.
2. Register in `packs/registry.ts` (`PACK_BY_ID` + `PACK_IDS`).
3. Update `recommendPackPlan` / `recommendPackIds` if stack routing changes; keep `pack_batches` ≤ `MAX_PACKS_PER_REQUEST` (6).
4. Keep item count and copy lean; prefer checkable remediation over essays.
5. Re-export from `common.ts` / `nextjs.ts` / `swift.ts` if scanners still need checklist aliases.

## Testing

- `pnpm build` — TypeScript compile
- `pnpm smoke` — client connect + tool calls against `fixtures/tiny-app` (+ pack / expo checks)
- Manual: MCP Inspector with license env set

## Style

- Strict TypeScript, no `any`
- ESM (`"type": "module"`, `.js` extensions in relative imports)
- Prefer explicit types on exported functions
- Comments explain non-obvious security or MCP decisions, not basic syntax
