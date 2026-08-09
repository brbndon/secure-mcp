# Changelog

Notable changes to secure-mcp are documented here. The project follows [Semantic Versioning](https://semver.org/).

## Unreleased

### Changed

- Migrated to MCP spec `2026-07-28` (stateless protocol core) via SDK v2: `@modelcontextprotocol/server` and `@modelcontextprotocol/client` replace the monolithic `@modelcontextprotocol/sdk`, and Zod moved to v4. No handshake or session state; each request is self-contained. Legacy clients (pre-2026-07-28) remain supported through the SDK's backward-compatible fallback.
- Re-licensed the project under Apache-2.0 and removed the proprietary runtime license gate.
- Made explicit filesystem-root authorization mandatory for process-level repository reads.
- Added public package metadata, release-artifact checks, contributor guidance, issue templates, and CI coverage; support and reporting route through GitHub Issues.
