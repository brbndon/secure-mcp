# Changelog

Notable changes to secure-mcp are documented here. The project follows [Semantic Versioning](https://semver.org/).

## 2.0.0 — 2026-08-14

### Changed

- Became a strict MCP v2 project: protocol revision `2026-07-28` only, served via `serveStdio` with `legacy: "reject"`. Legacy 2025-era `initialize` openings are rejected with the SDK's unsupported-protocol-version error; there is no SDK v1 dependency or compatibility fallback.
- Set the package, server-reported version, changelog, registry metadata, and future tag identity to `2.0.0`.
- Made clone + build + `install-agents` the primary onboarding path. The README, docs site, help page, and `llms.txt` now lead with the checkout, skill, installer, fixtures, and source.
- Documented npm as a server-only fallback that targets `@brdndon/secure-mcp@2` explicitly and intentionally excludes the skill, installer, fixtures, and source.
- Hardened `scripts/install-agents.sh` with an ownership marker, refusal to overwrite conflicting non-owned entries or skills, and verified temp-home install/check/uninstall behavior.
- Added `scripts/install-agents.ps1`, a Windows installer with equivalent ownership and safety behavior, plus cross-platform installer integration coverage.
- Added a nonpublishing npm tarball E2E test that installs the packed artifact in a temporary consumer directory, checks the `secure-mcp` bin, and connects with the MCP v2 client pinned to `2026-07-28`.
- Added a documented client compatibility and configuration matrix for Codex, Cursor, Claude Desktop, Claude Code, VS Code / GitHub Copilot, pi, and generic stdio clients. The server does not claim compatibility with clients that have not adopted `2026-07-28`.
- Added MCP Registry metadata (`server.json` with `io.github.brbndon/secure-mcp`, matching `mcpName` in `package.json`) and deterministic consistency validation in the test and release gates.
- Added a manual-only, OIDC trusted-publishing release workflow that refuses non-`main`, non-canonical-repository runs and verifies identity, tag, and changelog before publishing.
- Expanded CI to Linux, macOS, and Windows, including Bash and PowerShell installer tests, protocol tests, package E2E, and documentation checks.
- Updated the security policy so 2.x is supported and 1.x is historical and unsupported.

### Fixed

- Removed claims that legacy SDK v1 clients continue to work and stale `1.0.0` server identity outside the historical changelog.
- Replaced shell-only cleanup in package scripts with cross-platform Node cleanup.
- Accepted explicit `null` values in pre-existing client JSON configs (`.pi/agent/mcp.json`, `.cursor/mcp.json`) during PowerShell install, check, and uninstall; the mandatory-parameter binding previously rejected null fields and aborted every action. Single-element arrays and nested entries are preserved byte-for-byte through the round-trip.
- Surfaced malformed `semgrep`/`gitleaks` output as a scanner `error` status with an explanatory note instead of a false `completed` with zero findings, so a misbehaving local scanner can never read as a clean scan.
- Documented the default-off `SECURE_MCP_LOCAL_SCANNERS` environment gate in `.env.example` alongside the required allowlist variable.

## 1.0.0 — 2026-08-09

Initial public release of `@brdndon/secure-mcp`.

### Added

- Local stdio MCP server for defensive, remediation-focused secure code review.
- Tools for project inventory, architecture analysis, knowledge packs, authentication, injection risks, secrets review, threat-model fragments, and findings reports.
- Knowledge packs for core, secrets, auth-web, web-next, web-api, swift-ios, apple-desktop, expo-rn, and threat-model workflows.
- Filesystem allowlist (`SECURE_MCP_ALLOWED_ROOTS`), read caps, coverage contracts, and secret redaction before MCP responses.
- Public package metadata, Apache-2.0 license, CI, Dependabot, contributor guidance, issue/PR templates, and release checklist.
- Documentation site and sample audit session for agent-oriented workflows.

### Changed

- Re-licensed the project under Apache-2.0 and removed the proprietary runtime license gate.
- Made explicit filesystem-root authorization mandatory for process-level repository reads.
