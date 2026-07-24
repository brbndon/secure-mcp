# Agent workflow

How a coding agent should use `secure-mcp` for **defensive, remediation-focused** secure code review.

## Mandate

**Defensive security audit only — remediation focused.**

Goal: help the development team **identify potential weaknesses**, **classify** them (CWE / severity / confidence), and **recommend concrete remediation** and verification steps.

### Forbidden

- Exploit generation or proof-of-concept attack code
- Offensive “bypass” / weaponization guidance
- Using discovered secrets against systems

Prefer long, multi-phase analysis with intermediate artifacts when thoroughness requires it (including extended sessions).

## Preconditions

1. MCP server is connected and licensed.
2. Absolute path to the target repository (`project_root`) is known.
3. You will **not** treat heuristic hits as confirmed without reading code.
4. You are authorized to review the target (owned or explicitly in-scope code).

## Mandatory multi-phase sequence

```text
Phase 1  list_project_structure          → inventory artifact (no packs yet)
Phase 2  analyze_architecture            → stacks + recommended_packs + pack_batches
         get_knowledge_pack              → pack_batches[0] first (summary); more batches only if needed
         build_remediation_threat_model  → trust boundaries + controls (optional)
Phase 3  check_authentication
         analyze_injection_risks
         review_secrets                  → category candidate artifacts
Phase 4  Manual / sub-agent data-flow    → confirmed findings
Phase 5  produce_findings                → remediation report
Phase 6  Human-facing narrative          → executive summary + fix plan
```

**Progressive load rule:** do not call `secure_mcp_get_knowledge_pack` until after Phase 1 stack detection. Prefer `pack_batches` from architecture (max 6 pack ids per call). Start with `pack_batches[0]` and `detail=summary`; use `full` only when drafting remediations. Do not set `include_index` unless you need the pack catalog.

Tools remain independently useful if the user only asks about one category (e.g. secrets only)—still stay defensive and remediation-oriented.

## Intermediate artifacts

After each phase, retain structured notes the final report can cite:

| Artifact | Contents |
|----------|----------|
| Inventory | stacks, file counts, sample paths |
| Architecture | surfaces, trust boundaries, `recommended_packs`, `pack_batches`, small `checklist_seed` |
| Knowledge packs | checklist items for detected stacks only |
| Threat model (remediation) | STRIDE items + recommended controls |
| Category findings | raw tool findings with confidence |
| Confirmed set | evidence-verified findings with full schema |
| Final report | `produce_findings` output + narrative |

## Parallelism

Auth, injection-risk, and secrets tools are independent. When the client supports parallel tool calls, run them together after architecture analysis.

## Sub-agents (defensive roles)

| Sub-agent role | Inputs | Focus |
|----------------|--------|--------|
| Mapper | structure + architecture | Control placement notes |
| Auth specialist | auth findings + auth files | Session checks, ownership (IDOR remediation) |
| Mobile specialist | swift findings | Keychain, ATS, WebView least privilege |
| Reporter | all findings | produce_findings + remediation narrative |

Pass **structured JSON** between sub-agents—not only prose. Never assign an “exploit writer” role.

## Confidence handling

| Confidence | Agent behavior |
|------------|----------------|
| high | Prioritise remediation; still open the file to confirm |
| medium | Verify data flow before treating as confirmed |
| low | Checklist / investigate further if severity is high |

## Severity handling

For **critical** secrets that appear live, recommend **immediate rotation** and removal from source/history—not offensive use.

## Required finding structure

Every finding passed to `secure_mcp_produce_findings` must include:

1. **evidence**
2. **classification** (`severity`, `confidence`, `category`, optional `cwe`)
3. **impact_if_unremediated** (high-level CIA impact — no exploit steps)
4. **remediation**
5. **residual_risk**
6. **verification_suggestion**

## False positive hygiene

Before final report:

1. Open each high/critical finding’s file at the cited line.
2. Drop pure test fixtures if out of scope (or mark as info).
3. Merge duplicates via `secure_mcp_produce_findings` with `dedupe: true`.
4. Keep residual low-confidence items in an appendix if useful.

## Example parameters

**Medium monorepo:**

```json
{ "project_root": "/abs/path", "max_files": 800, "stack": "auto" }
```

**Swift-focused hardening pass:**

```json
{ "project_root": "/abs/path", "stack": "swift", "max_files": 400 }
```

**Final remediation report:**

```json
{
  "project_root": "/abs/path",
  "min_severity": "low",
  "min_confidence": "medium",
  "dedupe": true,
  "report_title": "Secure code review — Acme iOS remediation",
  "findings": [/* merged with full schema */],
  "response_format": "markdown"
}
```

## What not to do

- Do not pass relative paths unless you know the MCP process cwd.
- Do not re-scan entire monorepos at max_files=5000 by default—scope first.
- Do not execute untrusted project scripts as part of the review unless the user explicitly asks and understands the risk (this MCP will not execute target code).
- Do not generate exploits or PoC attack code under any circumstance when using this MCP.
