# Tier 3 skill delta (apply to `.agents/skills/secure-mcp/SKILL.md` at integration)

These are the exact skill deltas for Tier 3 ("Credibility, CI adjacency,
long-running reviews"). Tier 3 does **not** edit SKILL.md during parallel work;
the integration agent applies these lines after Tier 1's slim skill base lands.

## 1. Phase 4 — validation handoff label (add one bullet to the disposition list)

Under the "Mark candidates with a disposition" list, append a sibling bullet:

- Set `validation_status` on every confirmed finding: `"static_only"` when code
  review alone confirms the weakness and verifies the fix, or `"needs_runtime"`
  when owner-authorized runtime/configuration verification (manual QA or an
  existing DAST) is still required before the weakness can be declared closed.

## 2. Phase 5 — export + resumability (extend the produce_findings paragraph)

Replace the sentence "Call `secure_mcp_produce_findings` with ... and
`response_format: "markdown"` or `"json"`." with:

> Call `secure_mcp_produce_findings` with `dedupe: true`, appropriate
> severity/confidence filters, the project root, and `response_format:
> "markdown"`, `"json"`, or `"sarif"`. Use `"sarif"` when the user asks for CI
> annotations; the export is a redacted SARIF 2.1.0 subset and carries the same
> secret redaction as every other output boundary.

Add one resumability line to the same paragraph:

> The review is resumable: if a category scan was truncated or partial, re-run
> the affected `secure_mcp_*` tool with the same `project_root` plus
> `focus_paths` before claiming coverage; the report's `review_checkpoint`
> field lists concrete resume steps. Do not invent a server-side job store.

## 3. Guardrails — one defensive line (append to the "Non-negotiable guardrails")

- When a finding is labeled `needs_runtime`, recommend owner-authorized retest
  (manual QA or an existing DAST) and record it as open work; never author or
  run exploit or bypass steps to "prove" a runtime finding.

## 4. No new tools / no fragmented skills

- Tier 3 adds no new `secure_mcp_*` tools (it extends `secure_mcp_produce_findings`
  with `response_format: "sarif"` and the `validation_status` label). No skill
  routing table change is required.
- Tier 3 does not create fragmented per-stack skills under `.agents/skills/`.
  If finer stack guidance is ever needed, prefer thin `references/*.md` loaded
  only when preflight selects that stack (proposal only; not implemented here).
