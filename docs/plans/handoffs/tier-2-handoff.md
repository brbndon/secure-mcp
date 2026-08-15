## Handoff — Tier 2 complete

### Commits
- c09056a feat(packs): unsupported-stack honesty
- 71fe0e0 feat(tools): list authorized roots and shallow projects
- 1696671 feat(architecture): prioritize authz-sensitive surfaces
- 5ddb612 feat(tools): optional local scanner compose (default off)
- 53fe1a3 docs(handoff): tier2 skill delta and tool docs

### Verification run
- pnpm typecheck: PASS
- pnpm test: PASS (278 tests)
- pnpm build: PASS
- pnpm smoke: PASS (12 tools, all checks)
- Targeted: `pnpm exec tsx --test` on `analyzeArchitecture.test.ts` (9),
  `listProjects.test.ts` (6), `runLocalScanners.test.ts` (9) — all PASS.

### Stack isolation proof (required)
- Pure Expo (`fixtures/tiny-expo`, smoke): `recommended_packs` includes `expo-rn`, not `web-next`/`swift-ios`; no Next-only surfaces. Command: `pnpm smoke`.
- Pure Next (`fixtures/tiny-app`, smoke + `analyzeArchitecture.test.ts`): `recommended_packs` includes `web-next`, not `expo-rn`; `unsupported_signals` is `[]`.
- Plain Python (temp fixture, `analyzeArchitecture.test.ts`): `stacks=["common"]`, `recommended_packs` = `core,secrets,threat-model`, `unsupported_signals` includes `python`, notes say "limited generic review".

### Skill / docs SSOT
- SKILL.md and `skills/security-auditor.md` NOT touched.
- Skill deltas written to `docs/plans/handoffs/tier-2-skill-delta.md` (routing row, new-tool lines, authz + scanner bullets, unsupported-stack note).
- README + `docs/docs/tools.mdx`: additive tool rows only.

### Shared-file touches (announce)
- `src/tools/index.ts`: registered 3 new tools + added to `TOOL_NAMES`.
- `scripts/test-constants.ts`: added 3 names to `REQUIRED_TOOLS` (smoke asserts exact tool count).
- `src/knowledge/packs/registry.ts` + `registry.test.ts`: unknown/minimal stack degrade now `core + secrets + threat-model` (was `core + threat-model`).

### Residual risks / follow-ups for next tier
- New test files are not yet in the `package.json` `test` script (package.json is "nobody" during parallel work) — wire them in at integration.
- `server.json` (Tier 3) does not yet list the 3 new tools.
- Real `web-python` pack deferred (see below); `SECURE_MCP_LOCAL_SCANNERS` env not yet in `server.json`/`.env.example`.

### Explicitly out of scope (deferred)
- **New language pack (B1a/B1b/B1c)**: deferred. The `StackFocus` enum lives in `findings-schema.ts` (Tier 1 exclusive) and has no `python`/`go` value, so a real pack could not be routed "only when signals fire" without cross-tier edits. Unsupported-stack honesty (B1 always-on) is shipped instead.
- Git-root discovery in `list_projects` (marker-file/manifest discovery only).
