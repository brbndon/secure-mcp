# Handoff — Tier 1 complete

## Commits

- `541cb95` docs(skill): single-source orchestration and de-dupe companion docs
- `ebcb790` test(packs): lock stack-isolation, surface honesty, and redaction guarantees
- `e3d8d97` test(findings): lock disposition contract across schema and policy
- `e79fd38` test(smoke): golden audit sequence on fixtures

## Verification run

- pnpm typecheck: PASS
- pnpm test: PASS (296 tests)
- pnpm build: PASS
- pnpm smoke: PASS (all checks, incl. raw-Stripe-key redaction on the stdio path)

## Stack isolation proof

| Case | packs | surface kinds |
| --- | --- | --- |
| Expo app (`iso-expo`, `iso-expo surfaces`) | `core`,`secrets`,`expo-rn`; no `web-next`/`auth-web`/`web-api`/`swift-ios` | `deep_link`,`webview`,`secure_storage`,`app_entry`; **no** `server_action`/`middleware`/`page_entry`/`http_route` |
| Next app (`iso-next`) | `core`,`secrets`,`web-next`,`auth-web`,`web-api`; no `expo-rn`/`swift-ios`/`apple-desktop` | no `deep_link`/`webview`/`secure_storage` (server.test.ts + tools iso tests) |
| Swift (`iso-swift`) | `core`,`secrets`,`swift-ios` (+`apple-desktop` only with macOS); no `web-next`/`expo-rn` | **no** `server_action`/`middleware`/`page_entry` |
| RN lib, no Expo (`iso-rn-lib`) | no `expo-rn`; `typescript` honesty | n/a |
| Mixed Next+Expo (`mixed monorepo`) | union `core`,`secrets`,`web-next`,`auth-web`,`web-api`,`expo-rn` priority-ordered; `pack_batches` ≤6; `security_brief` complete; `surfaces_truncated` reported |

Asserting tests: `src/knowledge/packs/stack-isolation.test.ts`,
`src/tools/stack-isolation.test.ts` (registered in the `test` script).

## Skill / docs SSOT

Files touched: `.agents/skills/secure-mcp/SKILL.md` (194 lines, under budget),
`skills/security-auditor.md` (≤40-line pointer),
`docs/docs/agent-workflow.md` (human summary + one sequence diagram),
`src/tools/getAuditGuidance.ts` (`all` section now points at the skill).

Confirmed no duplicated full playbook in: security-auditor.md (no `Phase 1/2`
list, enforced by the `skill-pointer` test) | agent-workflow.md (summary only)
| get_audit_guidance (short slices; no skill paste).

## Shared-file touches (for the orchestrator)

- `package.json` — `test` script only: registered the two new `stack-isolation`
  test files. No dependency or lockfile change.
- `README.md` — additive "First scan" fixture-demo paragraph only.
- `scripts/smoke-test.ts` — added one redaction assertion; nothing else.

## Residual risks / follow-ups for next tier

- `surfaces_truncated` cap (SURFACE_KIND_CAP=40) is defensive headroom; the
  current kind set cannot reach it with a single forced stack, so truncation is
  only asserted as "reported (boolean)" in the mixed test, not triggered.
  Tier 2 pack/surface expansion may make it reachable — keep the field wired.
- The isolation tests import the public registry API by design; if Tier 2
  changes `registry.ts` routing semantics it must keep these green.
- No production-code changes were required for A1–A4: routing, surface honesty,
  disposition policy, and redaction were already correct; this tier pinned them
  with durable tests and tightened docs.

## Explicitly out of scope (deferred)

- New language packs (Python/Go/Android) — Tier 2.
- Multi-repo discovery / authorized-roots tools — Tier 2.
- SARIF / export, eval harness, runtime labels — Tier 3.
- No protocol legacy fallback, no new dependencies, no push/PR/release.
