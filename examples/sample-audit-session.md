# Sample defensive audit session

Illustrative transcript of an agent using secure-mcp for **remediation-focused** review of a Next.js app at `/Users/me/code/acme-web`.

## Mandate reminder

Identify potential weaknesses → classify → recommend remediation. **No exploit or PoC attack code.**

## Phase 1 — Inventory

**Tool:** `secure_mcp_list_project_structure`

```json
{
  "project_root": "/Users/me/code/acme-web",
  "stack": "auto",
  "response_format": "json"
}
```

**Artifact:** stacks `common, typescript, nextjs`; paths under `app/`, `lib/auth.ts`, `middleware.ts`.

## Phase 2 — Architecture, packs & remediation threat model

**Tools:** `secure_mcp_analyze_architecture`, `secure_mcp_get_knowledge_pack`, optional `secure_mcp_build_remediation_threat_model`

Architecture returns `recommended_packs` and `pack_batches` (e.g. one batch in priority order: `core`, `secrets`, `web-next`, `auth-web`, `web-api`) — not a large checklist dump. Load batch 0 first (max 6 pack ids per call). Default summary fair-samples items across packs so Next/auth/api guidance is not starved by core/secrets.

```json
{
  "pack_ids": ["core", "secrets", "web-next", "auth-web", "web-api"],
  "detail": "summary"
}
```

Response includes `items_per_pack` (coverage per id). Raise `max_items` (up to 60) or load one pack with `detail=full` when drafting remediations.

Threat model (optional):

```json
{
  "project_root": "/Users/me/code/acme-web",
  "focus_area": "billing Server Actions hardening",
  "assets": ["payment methods", "customer PII", "session cookie"]
}
```

**Artifact:** trust boundaries (browser ↔ Server Actions ↔ DB); pack checklist seeds; recommended controls for middleware defense-in-depth and input validation.

## Phase 3 — Category analysis

- `secure_mcp_check_authentication`
- `secure_mcp_analyze_injection_risks`
- `secure_mcp_review_secrets`

Example secrets finding (schema abridged):

```json
{
  "id": "SEC-002",
  "title": "Possible secret: Generic API key assignment",
  "severity": "high",
  "confidence": "medium",
  "category": "secrets",
  "file": "lib/legacy.ts",
  "line": 14,
  "evidence": "apiKey: 'sk_***'",
  "impact_if_unremediated": "Hardcoded API credentials may grant unauthorized API use if still active.",
  "remediation": "Rotate the key; load from a secret manager; remove from source and history.",
  "residual_risk": "Key may remain in git history until purged.",
  "verification_suggestion": "Confirm rotation in the provider console; re-run secrets review."
}
```

## Phase 4 — Confirmation

Agent opens `app/actions/billing.ts`, confirms missing ownership check, authors:

```json
{
  "id": "AGENT-001",
  "title": "Missing ownership check on billing portal action",
  "description": "updateBillingMethod accepts customerId from the client without comparing to session.user.id.",
  "severity": "critical",
  "confidence": "high",
  "category": "authorization",
  "file": "app/actions/billing.ts",
  "line": 42,
  "evidence": "customerId from input used in DB update without session ownership check",
  "impact_if_unremediated": "Authenticated users may modify another customer's billing methods.",
  "remediation": "Derive customerId from the authenticated session; reject mismatches server-side.",
  "residual_risk": "Similar handlers may need the same pattern.",
  "verification_suggestion": "Add a negative test with a cross-user customerId; re-review billing actions.",
  "cwe": "CWE-639"
}
```

## Phase 5 — Produce remediation report

**Tool:** `secure_mcp_produce_findings`

```json
{
  "project_root": "/Users/me/code/acme-web",
  "report_title": "Acme Web — secure code review (remediation)",
  "min_severity": "low",
  "min_confidence": "medium",
  "dedupe": true,
  "response_format": "markdown",
  "findings": ["/* merged arrays from tools + agent */"]
}
```

## Phase 6 — Human report

1. Executive summary (risk score, counts)
2. Critical/high findings with **remediation** and verification
3. Medium backlog
4. Methodology limits (static heuristics + partial manual review)
5. Retest plan after fixes

No exploit content in any section.
