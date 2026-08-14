# Agent tier sessions — multi-stack secure-mcp product plan

**Status:** ready for sequential agent execution  
**Date:** 2026-08-14  
**Branch context:** implement on current feature branch unless instructed otherwise; do not push or open PRs unless asked  
**Outcome:** three sequential agent sessions (Tier 1 → Tier 2 → Tier 3). A human or orchestrator verifies each tier before the next session starts.

---

## 0. How to use this document

| Who | What to do |
| --- | --- |
| Orchestrator | Start **only one** tier agent at a time. Run the **Verification gate** for that tier. Pass only if every checkbox is green. Then start the next tier agent with the handoff block. |
| Tier agent | Read **§1–§4** (shared rules), then **only your tier section**. Ignore later tiers. Implement, verify, commit phased units, hand off. |
| Verifier loop | Use **§5 Verification protocol** after every agent turn that claims completion. Do not advance tiers on green unit tests alone when stack isolation or skill SSOT failed. |

**Zero-context rule:** each tier section is self-contained for an agent with no chat history. Paths are repo-relative from the secure-mcp root.

---

## 1. Product north star (do not renegotiate mid-tier)

secure-mcp is a **local, read-only, defensive** MCP + skill for coding agents. It helps agents audit **one authorized repository root at a time**, load **only stack-relevant** knowledge, produce **candidate findings** that the agent confirms, and emit a **remediation report**.

### 1.1 Multi-app contract (“works for RN *and* Next”)

| Guarantee | Meaning |
| --- | --- |
| **Stack-honest** | A pure Expo/RN app never receives Next-only surfaces, packs, or detector narratives. A pure Next app never receives Expo/Swift-only surfaces or packs. Mixed monorepos get the **union of detected packages**, not every pack in the catalog. |
| **Context-thin** | Default pack load is `pack_batches[0]` + `detail=summary` + fair-sampled `max_items`. Agents never load the full catalog by default. Architecture returns a compact `security_brief` so the host agent can steer without re-reading the tree. |
| **Package-scoped** | One `project_root` = one deployable package review. Monorepos: change `project_root` per package; use `focus_paths` only for drill-down inside that package. |
| **Coverage-honest** | Empty findings + truncated coverage ≠ “secure.” Unsupported stacks must say so (`coverage_gaps` / notes), not pretend full AppSec. |
| **Secret-safe** | Tool output is redacted and marked untrusted. Agents must not re-paste raw secrets into notes or reports. |
| **Defensive only** | No exploits, PoCs, or credential testing. |

### 1.2 “Any app” honesty boundary

| Stack | Expected quality after Tier 1 | After Tier 2 |
| --- | --- | --- |
| Next.js / TS web | First-class (packs + surfaces + detectors) | Same + authz path prioritization |
| Expo / React Native | First-class (same bar as Next for mobile surfaces) | Same |
| Swift iOS / macOS | First-class within Apple packs | Same |
| Pure RN without Expo | First-class via Expo/RN pack + honest profile (not Next) | Same |
| Unknown / other (Python, Go, Android-only, etc.) | **Honest degrade:** `core` + `secrets` + `threat-model` + explicit unsupported/gap notes — no fake stack confidence | Optional real packs **or** still-honest gaps + optional scanner compose |

Do **not** expand language packs in Tier 1. Tier 1 makes **existing** first-class stacks flawless and non-bloating. Tier 2 expands breadth.

---

## 2. Single source of truth (skill / docs / server)

**Problem:** the model currently can receive the same workflow from `.agents/skills/secure-mcp/SKILL.md`, `skills/security-auditor.md`, `docs/docs/agent-workflow.md`, `secure_mcp_get_audit_guidance`, and README — causing token bloat and drift.

### 2.1 Ownership matrix (every tier must respect this)

| Content | Owner (edit here) | Consumers may only **link**, not copy long prose |
| --- | --- | --- |
| Tool schemas, pack ids, caps, routing algorithms, detectors, redaction, envelopes | `src/**` | Skill: “follow live MCP schema”; docs: short tables generated from behavior |
| **When/how** the host agent orchestrates a review (phases, preflight, dispositions, stop conditions) | `.agents/skills/secure-mcp/SKILL.md` | `skills/security-auditor.md` becomes a **pointer** (≤40 lines) to the skill; do not dual-maintain phase lists |
| Human site narrative | `docs/docs/*` | Short; deep sequences say “see skill in checkout” or one sequence diagram, not a third full playbook |
| On-demand server workflow slices | `secure_mcp_get_audit_guidance` | Thin extracts of **guardrails** (category dos/don’ts), not a paste of SKILL.md |
| Install / client config | `README.md`, `docs/docs/clients.mdx`, installers | Skill mentions allowlist only |

### 2.2 Skill size budget

| Artifact | Soft max | Rule |
| --- | --- | --- |
| `.agents/skills/secure-mcp/SKILL.md` | ~200 lines (currently ~210 — hold or shrink) | Orchestration + routing table + disposition enum + phase checklist. **No** pack item text, **no** detector recipes, **no** full client config matrices. |
| Stack-specific detail | Prefer **server packs** + architecture `threat_highlights` / surfaces | If a thin `references/*.md` is added under the skill dir later, load only when preflight selects that stack (progressive disclosure). Tier 1 may add at most **one** `references/stack-routing.md` if it keeps SKILL.md under budget. |
| `skills/security-auditor.md` | ≤40 lines after Tier 1 | Mandate + link to skill path + tool name table only |

### 2.3 When a tier changes behavior

1. Change `src/**` first.  
2. Update tests.  
3. Update **skill only** for agent behavior deltas (new tool, new disposition, new routing rule).  
4. Update hosted docs only if public API or install UX changed.  
5. Never paste the same multi-phase workflow into three files.

---

## 3. Shared implementation rules (all tiers)

### 3.1 Repo facts

- Package: `@brdndon/secure-mcp`, bin `secure-mcp`
- Server entry: `src/index.ts` → `src/server.ts`
- Tools: `src/tools/*`
- Packs: `src/knowledge/packs/*` (ids: `core`, `threat-model`, `web-next`, `web-api`, `auth-web`, `swift-ios`, `apple-desktop`, `expo-rn`, `secrets`)
- Routing: `src/knowledge/packs/registry.ts` (`recommendPackPlan`, `MAX_PACKS_PER_REQUEST = 6`)
- Architecture surfaces: `src/tools/analyzeArchitecture.ts`
- Skill (master): `.agents/skills/secure-mcp/SKILL.md`
- Fixtures: `fixtures/tiny-app` (Next), `fixtures/tiny-expo`, `fixtures/tiny-swift`, `fixtures/rn-lib-no-expo`
- Stacks accepted by tools: `auto` \| `common` \| `typescript` \| `nextjs` \| `swift` \| `expo`
- Protocol: MCP revision `2026-07-28` only (stdio). Do not silently add legacy protocol support without an explicit product decision in the tier notes.
- Workflow: YAGNI; smallest cohesive change; no new deps/lockfile changes unless the tier explicitly authorizes them; no push/PR/release unless user asks; stage explicit paths only.

### 3.2 Commands (default verification set)

```bash
pnpm typecheck
pnpm test
pnpm build
# When installers / skill install paths change:
pnpm exec tsx --test scripts/installer-integration.test.ts
# When docs/site claims change (if project defines it):
pnpm smoke   # or documented smoke/verify if present
```

Prefer targeted tests first (`pnpm exec tsx --test path/to/file.test.ts`), then full suite before tier handoff.

### 3.3 Commit style

Phased local commits after each verified unit:

```text
type(scope): short description

- user-visible behavior or key implementation detail
- verification: <commands and outcome>
```

### 3.4 Already landed (do not re-implement; extend only)

Treat these as **done** unless tests prove broken:

- Typed `surfaces`, `coverage_gaps`, `priority_paths`, `security_brief`
- Stack-gated surface honesty (no Next-only kinds on pure Swift)
- Progressive packs + `pack_batches` + fair sampling
- `applied_pack_ids` vs `consulted_pack_ids`
- Finding dispositions including `accepted_risk`, `fixed`, etc.
- Redaction + `output_trust: untrusted` envelopes
- Fail-closed `SECURE_MCP_ALLOWED_ROOTS`
- Installers (Bash + PowerShell) + skill install for pi/Cursor/Codex
- Fixtures for Next, Expo, Swift, RN-lib-no-Expo

Tier agents **productize, harden, test, and document** these — they do not rewrite them from scratch.

---

## 4. Inter-session handoff template

At the end of every tier, the agent appends (or writes) a handoff using this shape. Orchestrator pastes it into the next session prompt.

```markdown
## Handoff — Tier N complete

### Commits
- <sha> <subject>
- ...

### Verification run (paste outcomes)
- pnpm typecheck: PASS|FAIL
- pnpm test: PASS|FAIL (N tests)
- pnpm build: PASS|FAIL
- extra: ...

### Stack isolation proof (required)
- Fixture/path A (Expo/RN): packs=…; surface kinds=…; no Next-only kinds
- Fixture/path B (Next): packs=…; surface kinds=…; no Expo-only kinds
- Command or test names that assert the above: …

### Skill / docs SSOT
- Files touched under skill/docs:
- Confirmed no duplicated full playbook in: security-auditor.md | agent-workflow.md | get_audit_guidance

### Residual risks / follow-ups for next tier
- …

### Explicitly out of scope (deferred)
- …
```

---

## 5. Verification protocol (orchestrator / loop)

After each tier claims done:

1. **Clean tree for tier scope** — only expected files; no unrelated drive-bys.  
2. **Run default verification set** (§3.2). Fail = tier incomplete.  
3. **Stack isolation matrix** (automated tests preferred):

   | Case | Expect |
   | --- | --- |
   | `fixtures/tiny-expo` or RN app fixture, `stack=auto` or `expo` | `recommended_packs` ⊆ {`core`,`secrets`,`expo-rn`} (+ threat-model only if routing says so). No `web-next`. Surfaces ⊆ mobile/web-generic kinds allowed for RN; **no** `server_action`. |
   | `fixtures/tiny-app` Next | packs include `web-next` path; **no** `expo-rn` unless Expo also detected. |
   | `fixtures/tiny-swift` | no Next page/middleware/server_action surfaces. |
   | `fixtures/rn-lib-no-expo` | does **not** force full Expo app pack the way an app does (library/dev-tool honesty). |

4. **Skill bloat check** — SKILL.md line count ≤ budget; no pack checklist prose; security-auditor not a second playbook.  
5. **Smoke tool sequence** (manual or scripted) on one fixture:

   ```text
   list_project_structure → analyze_architecture → get_knowledge_pack(pack_batches[0], summary)
   → check_authentication + analyze_injection_risks + review_secrets
   → produce_findings (if confirmed candidates) or coverage-qualified narrative
   ```

6. Only then open Tier N+1.

---

# TIER 1 — Agent session A  
## “Flawless first-class stacks + thin agent context + installable demo”

**Goal:** React Native / Expo and Next.js (and existing Swift) audits feel **native**, **non-bloating**, and **skill-correct**. Productize surface-graph + disposition + secret-safe story. Ship a deterministic demo path.

**Out of scope for this session:** new language packs (Python/Go/Android), scanner CLI compose, multi-repo portfolio tool, SARIF, MCP Tasks, public eval harness, protocol legacy fallback.

### A.0 Session start checklist

- [ ] Read this entire Tier 1 section + §1–§3  
- [ ] `git status` / recent commits — do not clobber WIP outside your units  
- [ ] Skim `src/knowledge/packs/registry.ts`, `src/tools/analyzeArchitecture.ts`, skill file  
- [ ] Run existing tests once to establish baseline  

### A.1 Work units (implement in order; commit after each verified unit)

#### Unit A1 — Stack isolation hard guarantees (server)

**Why:** “Works for RN and Next” is a **routing + surface honesty** property, not a marketing line.

**Implement:**

1. Add/extend tests that lock pack plans:
   - Pure Next fixture → never recommends `expo-rn` / `swift-ios` / `apple-desktop` without signals  
   - Pure Expo app → never recommends `web-next`  
   - Pure Swift → never emits Next-only surface kinds  
   - Forced `stack: "expo"` exclusive focus (document and test registry behavior already claimed in skill)  
2. If any detector or architecture path leaks cross-stack noise, fix with stack gates (pattern already used for surfaces).  
3. Ensure category tools’ `applied_pack_ids` stay stack-true; consulted packs may be broader only when intentional and tested.

**Files (likely):**  
`src/knowledge/packs/registry.ts`, `registry.test.ts`, `src/tools/analyzeArchitecture.ts`, `src/server.test.ts`, category tool tests, fixtures if needed.

**Acceptance:**

- [ ] New or updated tests fail if Next packs appear on pure Expo  
- [ ] New or updated tests fail if Expo packs appear on pure Next  
- [ ] `pnpm exec tsx --test` on touched tests PASS  

**Commit:** `test(packs): lock stack-isolation for next vs expo vs swift` (+ any `fix` commits if code changes)

---

#### Unit A2 — Surface-graph product completeness (no bloat)

**Why:** Agents should steer from architecture alone for most of the audit.

**Implement:**

1. Audit architecture JSON for token waste: caps already exist — verify `surfaces`, `coverage_gaps`, `priority_paths`, `security_brief` stay within caps under mixed monorepo fixtures.  
2. Ensure `security_brief` is always present and sufficient for skill Phase 2 (stacks, high_value_surfaces, coverage_gap_count, recommended_packs, priority_paths, notes).  
3. Add one **mixed** fixture or temp monorepo test (Next app + expo package paths) proving:
   - union packs ordered by priority  
   - `pack_batches` chunking  
   - `surfaces_truncated` reported if cap hit (no silent drop)  
4. RN-specific surface kinds (`deep_link`, `webview`, `secure_storage`, `app_entry`) must appear when Expo/RN signals exist; must **not** appear on pure Next without evidence.

**Acceptance:**

- [ ] Tests cover mixed monorepo truncation honesty  
- [ ] RN surface kinds tested on Expo fixture  
- [ ] Architecture response remains under existing caps  

**Commit:** `feat(architecture): harden surface-graph caps and RN/Next honesty`

---

#### Unit A3 — Disposition / proof contract (agent-operable)

**Why:** False positives kill trust; candidates must not equal findings.

**Implement:**

1. Confirm server finding schema + `produce_findings` behavior for dispositions (`reportable`, `needs_review`, `suppressed`, `accepted_risk`, `not_applicable`, `deferred`, `fixed`) matches skill language. Fix schema/docs/skill **one-way** if drift.  
2. Category tools: candidates should carry disposition-friendly fields already present (`counterevidence`, `proof_gap`, etc.) — add only missing **stable** fields, not essays.  
3. Ensure `produce_findings` prioritization treats open vs closed dispositions correctly (skill already specifies).  
4. Add tests: closed dispositions excluded from open risk / remediation priority when that is the contract.

**Acceptance:**

- [ ] Schema and skill disposition enums match exactly  
- [ ] Tests for open vs closed rollup  
- [ ] No second disposition taxonomy invented in docs  

**Commit:** `fix(findings): align disposition contract across schema skill and produce_findings`

---

#### Unit A4 — Secret-safe output as product story (not just code)

**Why:** Viral/trust differentiator vs “dump .env into the model.”

**Implement:**

1. Inventory redaction seams (`src/lib/redact.ts`, envelope) — ensure all tool success/error paths go through them (no bypass).  
2. Add/extend tests that a known secret fixture path never appears raw in tool JSON text.  
3. Skill: **one short bullet** under guardrails pointing at redaction + rotation; do not paste redaction algorithm.  
4. Optional: architecture/inventory note when secret-like paths were redacted (if not already).

**Acceptance:**

- [ ] Redaction tests cover tool envelope path  
- [ ] Skill mentions secret-safe output without implementation prose  

**Commit:** `test(redact): prove secret-safe tool envelopes` (+ skill touch if needed)

---

#### Unit A5 — Skill SSOT slim + companion de-dupe

**Why:** Host agents must understand MCP without triple-loading playbooks.

**Implement:**

1. Rewrite/trim `.agents/skills/secure-mcp/SKILL.md` to stay ≤ ~200 lines:
   - Keep: guardrails, goal/TODO, preflight routing table, phase sequence, disposition list, progressive pack rules, package-scoped monorepo rule, hardening mode, “live schema wins”
   - Remove/shorten: long client config, duplicated pack tables that only repeat registry, repeated finding field lists if `produce_findings` schema is live  
2. Collapse `skills/security-auditor.md` to a pointer skill (mandate + tool map + “full workflow: `.agents/skills/secure-mcp/SKILL.md`”).  
3. Trim `docs/docs/agent-workflow.md` to a **human** summary + link to skill path; one sequence diagram max; no third full disposition essay.  
4. Ensure `get_audit_guidance` (if content lives in `src/tools/getAuditGuidance.ts`) returns **short** section slices, not the full skill.  
5. Installer still installs the master skill path; verify installer tests.

**Acceptance:**

- [ ] SKILL.md under budget  
- [ ] No full phase playbook duplicated in security-auditor or agent-workflow  
- [ ] Installer still links/copies correct skill  
- [ ] RN and Next routing still described **once** (skill table)  

**Commit:** `docs(skill): single-source orchestration and de-dupe companion docs`

---

#### Unit A6 — Zero-to-first-finding demo path

**Why:** New users and agent sessions need a reliable golden path.

**Implement:**

1. Document a **fixture demo** in README or `examples/` (short): allowlist `fixtures/tiny-app` or `tiny-expo`, run tool sequence, expect at least one redacted candidate class (secrets or auth) **or** explicit coverage narrative.  
2. Prefer automated smoke: extend `scripts/smoke-test.ts` or add `scripts/demo-audit-sequence.test.ts` that drives server tools against a fixture with allowlisted temp root.  
3. Do **not** require network. Do **not** add deps.  
4. Skill Phase 0 stays: live tool inventory before calls.

**Acceptance:**

- [ ] Automated smoke/demo test PASS in CI-like local run  
- [ ] README “First scan” points at fixture demo without contradicting clone-first install  

**Commit:** `test(smoke): golden audit sequence on fixtures`

---

### A.7 Tier 1 exit criteria (all required)

- [ ] Units A1–A6 done and committed  
- [ ] `pnpm typecheck` · `pnpm test` · `pnpm build` PASS  
- [ ] Stack isolation matrix green (Expo vs Next vs Swift)  
- [ ] Skill SSOT matrix green  
- [ ] Handoff block filled (§4)  
- [ ] No Python/Go/Android pack expansion snuck in  

### A.8 Tier 1 agent system prompt (paste to new session)

```text
You are implementing Tier 1 only from docs/plans/2026-08-14-agent-tier-sessions.md
in the secure-mcp repo. Read §1–§3 and the entire Tier 1 section. Do not implement
Tier 2 or 3. Follow CODE_WORKFLOW / AGENTS conventions: inspect → implement → verify →
phased local commits. Preserve unrelated WIP. No push/PR/deps.

Priorities: (1) stack isolation so Expo/RN and Next never cross-bloat packs/surfaces,
(2) surface-graph + disposition + redaction product completeness, (3) skill SSOT slim
with no duplicated playbooks, (4) golden fixture smoke sequence.

Exit only when Tier 1 exit criteria are met and the handoff block is written.
```

---

# TIER 2 — Agent session B  
## “Breadth without bloat + multi-repo + optional deterministic compose”

**Prerequisites:** Tier 1 handoff green. Re-read Tier 1 residual risks.

**Goal:** Support more real-world repos **without** dumping irrelevant packs into agent context; multi-repo ergonomics; optional local scanners folded into the same finding contract.

**Out of scope:** MCP Tasks protocol features, full public benchmark marketing site, runtime exploit validation, SaaS backends.

### B.0 Session start checklist

- [ ] Read Tier 1 handoff + this Tier 2 section + §1–§3  
- [ ] Confirm stack isolation tests still pass (do not regress Tier 1)  
- [ ] List current pack ids and registry priority  

### B.1 Work units

#### Unit B1 — Unsupported-stack honesty + optional first expansion

**Policy (product decision locked for this plan):**

1. **Always:** unknown stacks emit explicit `coverage_gaps` / architecture `notes` / profile fields so agents say “limited generic review,” not “full audit.”  
2. **Then pick ONE expansion track** (implement one per unit commit; YAGNI — only if tests + pack quality bar met):

| Track | Pack id | Signals | When to choose |
| --- | --- | --- | --- |
| B1a Python web | `web-python` (name TBD) | `pyproject.toml` / `requirements.txt` + FastAPI/Django/Flask | High demand |
| B1b Go services | `web-go` | `go.mod` + net/http/chi/echo | High demand |
| B1c Android/Kotlin | `android-kotlin` | `android/` + Gradle/Kotlin | Only if Apple/mobile story needs parity |

**Quality bar for any new pack:**

- ≥8 checkable items with full remediation fields (same as existing packs)  
- Registry routing only when signals fire  
- Surfaces: only kinds that apply (no fake `server_action`)  
- Skill: **one row** in routing table, not a new essay  
- Fixture under `fixtures/` + registry/architecture tests  

If timeboxed: ship **B1 honesty only** (gaps + notes + skill row “unknown → core/secrets/threat-model”) and defer real packs to a follow-up commit still inside Tier 2.

**Acceptance:**

- [ ] Unknown empty repo / plain Python without pack still honest  
- [ ] If pack added: pure Next still never loads it  

**Commit:** `feat(packs): unsupported-stack honesty` and/or `feat(packs): add <stack> pack`

---

#### Unit B2 — Cross-repo allowlist ergonomics

**Why:** Users audit many client repos; today allowlist is env-only and each call needs absolute `project_root`.

**Implement:**

1. Add tool e.g. `secure_mcp_list_authorized_roots` (name finalizable): returns canonical allowlisted roots, whether each exists, optional shallow name/`package.json` name when readable **within** root — no full tree walk by default.  
2. Optional: `secure_mcp_list_projects` under a single allowlisted parent (depth-capped) discovering git roots / package manifests — hard caps, ignore rules, redaction.  
3. Fail closed: never escape allowlist.  
4. Skill: Phase 0 may call list roots when `project_root` unknown — **3–5 lines only**.

**Acceptance:**

- [ ] Tests for allowlist confinement  
- [ ] Caps on discovery  
- [ ] Skill not bloated  

**Commit:** `feat(tools): list authorized roots and shallow projects`

---

#### Unit B3 — Authz / tenancy path prioritization (Next + API focus)

**Why:** Practitioners say BOLA/IDOR matter more than classic SAST hits.

**Implement:**

1. Extend architecture surfaces or `priority_paths` scoring so authz-sensitive paths rank higher: server actions, route handlers with dynamic `[id]`, webhooks, admin paths, Expo AuthSession/deep links.  
2. Threat highlights / security_brief notes: “verify authorization on every sensitive action,” not generic XSS first.  
3. Skill Phase 3: one bullet — sample zero-hit **authz** surfaces before trusting empty auth findings.  
4. Tests on `fixtures/tiny-app` dynamic routes if present; extend fixture minimally if not.

**Acceptance:**

- [ ] priority_paths prefer authz-sensitive samples in Next fixture  
- [ ] No offensive content  

**Commit:** `feat(architecture): prioritize authz-sensitive surfaces`

---

#### Unit B4 — Optional deterministic scanner compose (local only)

**Why:** Become the agent **orchestrator** without reimplementing Semgrep.

**Implement (YAGNI options — pick minimal):**

1. New tool `secure_mcp_run_local_scanners` **or** extend secrets/injection with optional adapters:
   - If binary present on PATH (`semgrep`, `gitleaks`, etc.) **and** config flag/env enables it, run with timeout, cwd=`project_root`, allowlisted root only  
   - Parse subset of findings → map into secure-mcp candidate finding shape  
   - If binary missing: structured skip, not error  
2. **Default off** (env `SECURE_MCP_LOCAL_SCANNERS=0|1` or explicit tool arg `enable: false` default).  
3. Never download rulesets mid-run without explicit user opt-in (no surprise network). Prefer offline/custom config path under project if present.  
4. Skill: one line — optional, default off, still require manual confirmation.

**Authorization for deps:** do **not** add Semgrep as an npm dependency. Shell out only.

**Acceptance:**

- [ ] Default path unchanged when scanners disabled  
- [ ] Timeout + allowlist tests (mock spawn)  
- [ ] Findings schema compatible  

**Commit:** `feat(tools): optional local scanner compose (default off)`

---

#### Unit B5 — Skill / docs delta for Tier 2 only

- Update skill routing table for new packs/tools (minimal).  
- README feature table one-liners.  
- No third playbook.

**Commit:** `docs(skill): tier2 tools and pack routing`

---

### B.2 Tier 2 exit criteria

- [ ] B1 honesty shipped; optional pack only if quality bar met  
- [ ] B2 multi-repo tools usable and fail-closed  
- [ ] B3 authz prioritization tested  
- [ ] B4 default-off scanner compose or explicit deferral noted in handoff  
- [ ] Full verification set PASS; Tier 1 isolation tests still PASS  
- [ ] Handoff block filled  

### B.3 Tier 2 agent system prompt

```text
You are implementing Tier 2 only from docs/plans/2026-08-14-agent-tier-sessions.md.
Read the Tier 1 handoff residuals, §1–§3, and Tier 2. Do not implement Tier 3.
Do not regress stack isolation. Prefer honesty over shallow new languages.
No new npm dependencies. No push/PR. Phased commits + verification + handoff.
```

---

# TIER 3 — Agent session C  
## “Credibility, CI adjacency, long-running reviews”

**Prerequisites:** Tier 1 + Tier 2 green.

**Goal:** Make secure-mcp trustworthy for teams and shareable for growth: eval fixtures, export, long-job ergonomics, runtime handoff **labels** (not offensive runtime).

### C.1 Work units

#### Unit C1 — Public fixture eval harness (local)

**Implement:**

1. Expand fixtures with labeled **expected candidate families** (not full CVE theater): e.g. known secret pattern, missing authz on a route, insecure storage on RN.  
2. Script `scripts/eval-audit.mjs` or tsx test suite:
   - Runs inventory → architecture → category tools  
   - Asserts expected families surface as candidates (recall floor)  
   - Asserts known clean paths do not spam critical FPs (precision smoke)  
3. Document how to interpret scores in `docs/plans/` or `examples/` — not a vanity badge in README until numbers are real.

**Acceptance:**

- [ ] Eval runs offline  
- [ ] Failures are actionable  

**Commit:** `test(eval): fixture recall/precision smoke harness`

---

#### Unit C2 — Export for agent/CI adjacency (SARIF or compact JSON)

**Implement:**

1. `produce_findings` optional `response_format: "sarif"` **or** separate export field — map severity, rule id, locations, help text from remediation.  
2. Keep markdown/json defaults.  
3. Skill: one line when user asks for CI annotations.

**Acceptance:**

- [ ] Valid SARIF 2.1.0 subset or documented compact export  
- [ ] Redaction still applied  

**Commit:** `feat(findings): optional SARIF export`

---

#### Unit C3 — Long review ergonomics (without full MCP Tasks if unavailable)

**Implement (choose based on SDK support in repo):**

1. If MCP Tasks / long-running primitives exist in current SDK and are already used elsewhere — wire a single long “audit job” carefully.  
2. Else (YAGNI):  
   - Document **host-side** checkpointing (skill already multi-phase)  
   - Add tool output `review_checkpoint` hints (next_tools, remaining coverage_gaps) already partly present — tighten consistency  
   - Ensure category tools are independently resumable with `focus_paths`  

Do **not** invent a custom job store on disk unless necessary.

**Commit:** `feat(workflow): resumable audit checkpoints` or `docs: long-review host checklist`

---

#### Unit C4 — Runtime verification handoff (defensive labels only)

**Implement:**

1. Disposition or finding field `validation: "static_only" | "needs_runtime"` (if not present) with `proof_gap` text.  
2. Skill: when `needs_runtime`, tell agent to recommend **owner-authorized** retest (manual QA, existing DAST in their stack) — never generate exploit steps.  
3. Architecture notes for pure static limits on BOLA.

**Commit:** `feat(findings): static_only vs needs_runtime validation labels`

---

#### Unit C5 — Distribution polish (still no unauthorized release)

**Implement as docs/config only unless user later asks to publish:**

1. `server.json` / registry metadata accuracy for new tools  
2. `public/llms.txt` short update (stack isolation + progressive packs + secret-safe)  
3. Example `AGENTS.md` **snippet** in `examples/agents-md-snippet.md` for consumer repos (copy-paste). Do not force AGENTS.md into every consumer.  
4. Optional thin stack skills **only if** Tier 1 budget failed without them: `.agents/skills/secure-mcp-expo/SKILL.md` etc. that only say “force stack expo; load skill master for phases.” Prefer **not** fragmenting unless master skill is still too large.

**Commit:** `docs: llms.txt agents snippet and registry metadata`

---

### C.2 Tier 3 exit criteria

- [ ] Eval harness exists and PASS  
- [ ] Export path exists and redacts  
- [ ] Runtime handoff is label-only / defensive  
- [ ] Full verification PASS; Tier 1 isolation still PASS  
- [ ] Handoff complete; note any deferred protocol Tasks work  

### C.3 Tier 3 agent system prompt

```text
You are implementing Tier 3 only from docs/plans/2026-08-14-agent-tier-sessions.md.
Read prior handoffs. Focus on eval harness, export, resumability, runtime labels,
and distribution docs. No offensive capabilities. No npm deps. No push/PR unless asked.
```

---

## 6. Cross-tier regression suite (must remain green forever)

Add these as durable tests during Tier 1; later tiers must not delete them.

| Test id | Assertion |
| --- | --- |
| `iso-next` | Pure Next: no `expo-rn` pack; no Expo-only surface kinds without signals |
| `iso-expo` | Pure Expo app: no `web-next` pack; no `server_action` |
| `iso-swift` | Pure Swift: no Next page/middleware/server_action |
| `iso-rn-lib` | RN library / no Expo app: does not behave like full Expo app |
| `prog-packs` | Default knowledge load path uses batches + summary; catalog omitted unless `include_index` |
| `redact-envelope` | Known secret fixture never appears raw in tool output text |
| `skill-pointer` | (doc test or checklist) security-auditor does not re-list full phases |

---

## 7. Mapping from research tiers → sessions

| Research item | Session unit |
| --- | --- |
| Surface-graph audit | A2 |
| Secret-safe read path story | A4 |
| Disposition + proof contract | A3 |
| Zero-to-first-finding install/demo | A6 |
| Skills / AGENTS.md progressive disclosure | A5, C5 |
| Stack-first multi-app (RN + Next) | A1 (hard gate), all tiers regression |
| Pack expansion / honest unsupported | B1 |
| Cross-repo portfolio | B2 |
| Authz prioritization | B3 |
| Scanner compose | B4 |
| Eval harness | C1 |
| SARIF / CI export | C2 |
| Long review / Tasks | C3 |
| Runtime handoff | C4 |

---

## 8. Orchestrator mini-runbook

```text
1. Open session with Tier 1 system prompt (§A.8)
2. Wait for agent handoff
3. Run §5 verification protocol
4. If fail → same tier bugfix session (do not start Tier 2)
5. If pass → Tier 2 prompt (§B.3) + paste handoff
6. Verify §5 + isolation suite
7. Tier 3 prompt (§C.3) + paste handoffs
8. Final: full pnpm typecheck/test/build + fixture demos for Next and Expo
```

### Final product demo script (after all tiers)

```bash
export SECURE_MCP_ALLOWED_ROOTS="$(pwd)/fixtures"
# Client configured to secure-mcp; then ask agent:
# "Audit fixtures/tiny-expo defensively using secure-mcp only."
# Expect: expo packs only, RN surfaces, summary packs, redacted secrets, dispositions.
# Then: "Audit fixtures/tiny-app"
# Expect: web-next path, no expo-rn, authz-priority paths, same skill phases.
```

---

## 9. Explicit non-goals (all sessions)

- Becoming a cloud AppSec SaaS  
- Replacing Semgrep/Snyk rule volume  
- Offensive scanning or exploit generation  
- Silent legacy MCP protocol support without a dedicated product decision  
- Duplicating the full skill into `get_audit_guidance`, README, and agent-workflow  
- Adding dependencies or lockfile changes without user approval  
- Push, npm publish, or GitHub Release unless the user asks  

---

## 10. Success definition (program complete)

secure-mcp is **program-complete** for this plan when:

1. An agent can audit a **random Expo/RN app** and a **Next.js app** back-to-back with correct packs/surfaces and no cross-stack bloat.  
2. The **skill is the only** full orchestration document; companions are pointers.  
3. Findings are **candidates with dispositions**, secret-safe, coverage-honest.  
4. Multi-repo allowlist discovery works fail-closed.  
5. Unknown stacks are honest; optional expanded packs/scanners do not break defaults.  
6. Eval smoke and optional SARIF exist for credibility.  

That is the bar for “usable across the apps people actually bring to agents” without claiming infinite language depth.
