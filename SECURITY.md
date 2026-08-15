# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 2.x | ✅ |
| 1.x | ❌ historical, unsupported |

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Report suspected vulnerabilities privately through
[GitHub Security Advisories](https://github.com/brbndon/secure-mcp/security/advisories/new).

Include:

- secure-mcp version or commit SHA
- environment (Node.js version, OS, MCP client)
- minimal reproduction or proof of concept using fake data only
- impact assessment if you have one

You should receive an acknowledgment within 7 days. Please avoid public
disclosure until the report has been triaged and a fix or advisory is available.

If you cannot use Security Advisories, open a normal issue **without**
sensitive details and ask for a private channel, or contact the maintainer
listed on the [GitHub profile for @brbndon](https://github.com/brbndon).

## Scope

The server runs locally over stdio and performs read-only analysis of
repositories you explicitly authorize. Reports may target the server (`src/`),
the knowledge packs (`src/knowledge/`), the installer scripts (`scripts/`), or
the documentation site (`pages/`, `docs/`). The threat model assumes a trusted
local user; issues triggered by malicious repository content are in scope.

Out of scope:

- Findings produced when reviewing third-party code (product output, not
  product defects), unless they reveal a server, pack, or docs defect
- Requests for exploit development or live-target attacks
