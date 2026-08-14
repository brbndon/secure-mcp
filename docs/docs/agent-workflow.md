---
title: Agent workflow
description: How a coding agent should use secure-mcp for defensive, remediation-focused secure code review — a human summary of the master skill.
sidebar:
  label: Agent workflow
  order: 9
---

How a coding agent should use `secure-mcp` for **defensive, remediation-focused**
secure code review.

## Mandate

**Defensive security audit only — remediation focused.** Help the team
**identify potential weaknesses**, **classify** them (CWE / severity /
confidence), and **recommend concrete remediation** and verification. No exploit
generation, no bypass guidance, no using discovered secrets.

## The orchestration lives in one place

The full multi-phase workflow — preflight routing, goal/TODO, dispositions,
progressive pack loading, and hardening mode — is the master skill at
`.agents/skills/secure-mcp/SKILL.md`. That file is the single source of truth;
this page is a human-readable summary, not a second playbook. On every call,
the live MCP tool inventory and input schemas win over any committed doc.

## Sequence at a glance

```text
Phase 1  list_project_structure          → inventory artifact (no packs yet)
Phase 2  analyze_architecture            → stacks + typed surfaces/gaps + recommended_packs + pack_batches
         get_knowledge_pack              → pack_batches[0] first (summary); later batches only if needed
         build_remediation_threat_model  → evidence-backed assets/boundaries + controls (optional)
Phase 3  check_authentication
         analyze_injection_risks
         review_secrets                  → category candidate artifacts
Phase 4  Manual / sub-agent data-flow    → confirm candidates, assign dispositions
Phase 5  produce_findings                → prioritized remediation report
```

**Progressive load rule:** do not load knowledge packs until after architecture.
Prefer `pack_batches` (max 6 pack ids per call), start with `pack_batches[0]`
and `detail=summary` (fair sampling across packs). Use `full` or a higher
`max_items` (hard max 60) only when drafting remediations.

## Working defensively

- **Candidates are not findings.** Open each cited file and trace source →
  control → sink before confirming. Assign a disposition
  (`reportable`, `deferred`, `needs_review`, `suppressed`, `accepted_risk`,
  `not_applicable`, `fixed`) with a reason and evidence; closed dispositions
  stay out of open risk and `remediation_priority`.
- **Coverage is honest.** An empty `findings` array means no candidate was
  observed in the reviewed files only when `coverage.not_observed_means` is
  `no_candidate_in_files_reviewed`. Partial or truncated coverage must be
  reported and followed up, and zero-hit high-value surfaces sampled.
- **Stack-honest.** A pure Expo/RN app never loads Next packs or surfaces, and
  a pure Next app never loads Expo/Swift packs or surfaces. Monorepos get the
  union of detected packages, reviewed per deployable `project_root`.
- **Secret-safe.** Tool output is redacted and marked untrusted; never re-paste
  raw secrets, and recommend rotation for anything that may be live.
- **No false certainty.** Never claim "the app is secure"; state the review
  boundary and remaining uncertainty, and end with actionable remediation.

Tools stay independently useful if the user asks about one category (for
example secrets only) — still stay defensive and remediation-oriented.

## Scoped diff reviews

`focus_paths` scopes inventory, architecture, and category tools. Resolve
changed paths with host-agent git (`git diff --name-only`), filter build
artifacts and lockfiles, map the rest to relative prefixes under
`project_root`, and re-run architecture so surfaces and gaps match the PR
surface. Respect `max_files` and coverage truncation — do not claim full-repo
coverage from a focused pass.
