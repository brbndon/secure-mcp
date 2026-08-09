# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 1.x | ✅ |

## Reporting a vulnerability

Please report suspected vulnerabilities by opening a
[GitHub issue](https://github.com/brbndon/secure-mcp/issues) with the `security`
label. Include the version and environment you observed the issue in, a minimal
reproduction or proof of concept, and your impact assessment if you have one.

You should receive an acknowledgment within 7 days. We ask that you avoid
public disclosure until the report has been triaged and addressed.

## Scope

The server runs locally over stdio and performs read-only analysis of
repositories you explicitly authorize. Reports may target the server (`src/`),
the knowledge packs (`src/knowledge/`), the installer scripts (`scripts/`), or
the documentation site (`pages/`, `docs/`). The threat model assumes a trusted
local user; issues triggered by malicious repository content are in scope.
