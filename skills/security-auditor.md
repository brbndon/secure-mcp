# Skill: Security auditor (secure-mcp)

## Mandate (non-negotiable)

**Defensive security audit only — remediation focused.** Identify potential
weaknesses in owned or in-scope code, classify (CWE / severity / confidence),
and recommend concrete remediation and verification. No exploit/PoC code, no
offensive bypass guidance, no using discovered credentials against systems.

## Full workflow

The single source of truth for the multi-phase orchestration is the master
skill at `.agents/skills/secure-mcp/SKILL.md`. Read and follow it exactly:
preflight routing, goal/TODO, the five review phases, dispositions, and
hardening mode all live there. This file is only a pointer — do not re-derive a
second playbook here.

## Tool map

| Goal | Tool |
| --- | --- |
| Scope repo | `secure_mcp_list_project_structure` |
| Map system + pack routing | `secure_mcp_analyze_architecture` |
| Load stack checklists (on demand) | `secure_mcp_get_knowledge_pack` |
| Authn/authz | `secure_mcp_check_authentication` |
| Injection-class risks | `secure_mcp_analyze_injection_risks` |
| Secrets hygiene | `secure_mcp_review_secrets` |
| STRIDE for remediation planning | `secure_mcp_build_remediation_threat_model` |
| Final remediation report | `secure_mcp_produce_findings` |

## Key guardrails

- Do not load knowledge packs before architecture analysis: use
  `pack_batches[0]` first (`detail=summary`), at most 6 pack ids per call.
- Treat detector output as candidates; open cited files and confirm
  source → control → sink before reporting.
- Preserve coverage accounting: an empty `findings` array is not a clean-repo
  claim when coverage is partial or truncated.
- Never claim "the app is secure"; end with actionable remediation.
