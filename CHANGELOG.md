# Changelog

Notable changes to secure-mcp are documented here. The project follows [Semantic Versioning](https://semver.org/).

## Unreleased

### Changed

- Migrated to MCP spec `2026-07-28` (stateless protocol core) via SDK v2: `@modelcontextprotocol/server` and `@modelcontextprotocol/client` replace the monolithic `@modelcontextprotocol/sdk`, and Zod moved to v4. No handshake or session state; each request is self-contained. Legacy clients (pre-2026-07-28) remain supported through the SDK's backward-compatible fallback.
- Documented npm-first install (`npx` / global bin) alongside the clone development path.
- Routed vulnerability reports to private GitHub Security Advisories instead of public issues.
- Added Contributor Covenant code of conduct and clarified support vs security channels.

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
