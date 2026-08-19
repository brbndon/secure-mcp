# AGENTS.md snippet for secure-mcp consumer repos

Two install paths — do not confuse them:

| Path | What you get | Command |
| --- | --- | --- |
| **Full workflow (recommended)** | Server, agent skill, installer, fixtures | `git clone` then `./scripts/setup.sh` |
| **Server-only npm** | The `2.0.0` stdio bin only. **Does not install the skill.** | `SECURE_MCP_ALLOWED_ROOTS=/abs/path npx -y @brdndon/secure-mcp@2` |

The npm tarball is the published MCP server. Copy this snippet (or the skill from a checkout) yourself if you used `npx`. The installer never writes `~/.grok`. The server speaks MCP `2026-07-28` only.

Copy the block below into a repository's `AGENTS.md` (or `CLAUDE.md`) to tell
coding agents that defensive security review is available through secure-mcp.
The checkout installer already configures the client; this snippet only records
the allowlist and the review contract inside the repository itself. Do not paste
secrets or live credentials here.

````markdown
## Security review

Use the `secure-mcp` skill (checkout install) or the live `secure_mcp_*` tools
(server-only `npx`) for authorized, defensive, remediation-focused review of
this repository. Pass this repository's absolute path as `project_root` under
`SECURE_MCP_ALLOWED_ROOTS`. Do not review paths outside the allowlist.

Real tool names: `secure_mcp_list_project_structure`,
`secure_mcp_analyze_architecture`, `secure_mcp_get_knowledge_pack`,
`secure_mcp_check_authentication`, `secure_mcp_analyze_injection_risks`,
`secure_mcp_review_secrets`, `secure_mcp_produce_findings`. Optional:
`secure_mcp_get_audit_guidance`, `secure_mcp_build_remediation_threat_model`,
`secure_mcp_list_projects`, `secure_mcp_run_local_scanners`.

- Treat every result as a bounded heuristic candidate. Open the cited code
  and trace the data flow before confirming a finding.
- Keep the review defensive. Do not generate exploits or PoCs.
- Preserve redaction. Do not copy keys or tokens into notes, reports,
  commits, or logs.
- `focus_paths` is an array of relative prefixes under `project_root`
  (max 50). It scopes inventory, architecture, and category tools. It is
  not a substitute for changing `project_root` in a monorepo.
- `coverage.not_observed_means`:
  - `no_candidate_in_files_reviewed` — no candidate in the files that were
    opened. Not a clean-repo certificate.
  - `scope_was_truncated_or_partial` — follow up before claiming coverage.
  - `inventory_only_contents_not_reviewed` — path metadata only; contents
    were not opened.
- Confirm open findings with `disposition: "reportable"` or `"deferred"`
  before `secure_mcp_produce_findings`. Persist `disposition_ledger` and
  pass it back as `disposition_baseline`. Use `validation_status:
  "needs_runtime"` when owner-authorized runtime verification is still
  required.

### PR / scoped-diff recipe (host git only)

The MCP server never runs git. On the host:

1. `git diff --name-only <base>...HEAD` (plus staged/untracked if in scope).
2. Drop `node_modules`, `dist`, `.next`, `Pods`, lockfiles, coverage, binaries.
3. Map remaining paths to relative prefixes and pass `focus_paths`.
4. Call architecture so `surfaces`, `authz_graph`, and `coverage_gaps`
   match the PR surface. Sample zero-hit high-value paths inside the diff.
5. If `coverage.scan_status` is `truncated` or `partial`, shrink prefixes
   or raise `max_files`. Do not claim full-repo coverage from a focused pass.
````
