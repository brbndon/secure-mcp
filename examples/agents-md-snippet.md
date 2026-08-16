# AGENTS.md snippet for secure-mcp consumer repos

Copy the block below into a repository's `AGENTS.md` (or `CLAUDE.md`) to tell
coding agents that defensive security review is available through secure-mcp.
The installer already configures the client; this snippet only records the
allowlist and the review contract inside the repository itself. Do not paste
secrets or live credentials here.

````markdown
## Security review

Use the `secure-mcp` skill for authorized, defensive, remediation-focused
secure code review of this repository. The secure-mcp MCP server is configured
with `SECURE_MCP_ALLOWED_ROOTS` covering this repository — often a parent
such as your `Code` directory. Pass this repository's absolute path as
`project_root`. Do not review paths outside the allowlist.

- Treat every `secure_mcp_*` result as a bounded heuristic candidate, not a
  confirmed vulnerability. Open the cited code and trace the data flow before
  confirming a finding.
- Keep the review defensive: identify weaknesses, classify them, recommend
  fixes, and define verification. Do not generate exploits or PoCs.
- Preserve redaction: do not copy keys or tokens into notes, reports, commits,
  or logs; recommend rotation for credentials that may be live.
- Record coverage limits. An empty findings list is not a certificate that the
  repository is clean when coverage was partial or truncated.
- Confirm open findings with `disposition: "reportable"` or `"deferred"` before
  passing them to `secure_mcp_produce_findings`; use `validation_status:
  "needs_runtime"` to hand off findings that require owner-authorized runtime
  verification.
````
