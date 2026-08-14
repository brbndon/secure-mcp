## Handoff — Tier 3 complete

### Commits
- `8cf750a` feat(findings): static_only vs needs_runtime validation labels
- `176fae8` feat(findings): optional SARIF export
- `3739cb1` feat(workflow): resumable audit checkpoints
- `566b37c` test(eval): fixture recall/precision smoke harness
- `77d5cba` docs: llms.txt agents snippet and registry metadata

### Verification run (paste outcomes)
- pnpm typecheck: PASS (tsc --noEmit + tsconfig.scripts.json)
- pnpm test: PASS (288 tests)
- pnpm build: PASS (clean + tsc)
- extra: `pnpm exec tsx --test scripts/eval-audit.test.ts` PASS (25 tests)
- extra: `pnpm exec tsx --test scripts/registry-metadata.test.ts` PASS

### Stack isolation proof (required)
- `fixtures/tiny-expo`, `stack=auto`: packs=core,secrets,expo-rn; surface kinds
  Expo-only; no `web-next`/`swift-ios`/`auth-web`; asserts in
  `scripts/eval-audit.test.ts` (forbidden families/packs).
- `fixtures/tiny-app`, `stack=auto`: packs include `web-next`; no `expo-rn`;
  asserts in `scripts/eval-audit.test.ts`.
- `fixtures/rn-lib-no-expo`: zero findings, no `expo-rn`/`swift-ios` packs;
  asserts `expect_zero_findings` + forbidden packs.
- Command/test names that assert the above: `scripts/eval-audit.test.ts`
  (`recalls expected candidate rule families`, `does not recommend forbidden
  packs`, `produces zero candidate findings`).

### Skill / docs SSOT
- Files touched under skill/docs: `public/llms.txt` (additive), `server.json`
  (description only), `examples/agents-md-snippet.md` (new), `docs/plans/eval-harness.md`
  (new), `docs/plans/handoffs/tier-3-skill-delta.md` (new).
- `.agents/skills/secure-mcp/SKILL.md` NOT edited; `skills/security-auditor.md`
  NOT edited; `docs/docs/agent-workflow.md` NOT edited; `get_audit_guidance` NOT
  edited. Skill text lives in `docs/plans/handoffs/tier-3-skill-delta.md`.

### Cross-tier file touch (must reconcile at integration)
- `src/knowledge/findings-schema.ts`: added the optional `validation_status`
  field + its `FINDING_FIELD_METADATA` entry. This is Tier 1's file, but the
  plan assigns validation labels to Tier 3 (C4). The change is additive and
  does not touch the disposition contract; merge Tier 1 first, then Tier 3.

### Residual risks / follow-ups for next tier
- SARIF is a "valid 2.1.0 subset"; not validated against a SARIF JSON-Schema
  validator (no new dev deps allowed). A CI consumer should validate once before
  treating it as a hard contract.
- Eval recall floors are smoke thresholds on committed fixtures, not a public
  benchmark; do not publish recall/precision numbers until run on real repos.
- MCP Tasks / long-running job primitives were NOT used (YAGNI); checkpointing
  is host-side via `review_checkpoint` + focus_paths re-runs.

### Explicitly out of scope (deferred)
- MCP Tasks long-running audit jobs (no SDK primitive used in-repo).
- Offensive/runtime exploit validation — validation handoff is label-only.
- Per-stack `references/*.md` under the skill dir (proposal noted in skill-delta).
