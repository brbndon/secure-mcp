# Contributing to secure-mcp

Thanks for helping improve defensive, agent-first code review. Contributions of bug fixes, detection improvements, knowledge packs, documentation, fixtures, and tests are welcome.

## Before you start

- Use [GitHub Issues](https://github.com/brbndon/secure-mcp/issues) for reproducible bugs and focused feature proposals.
- Report product vulnerabilities privately via [GitHub Security Advisories](https://github.com/brbndon/secure-mcp/security/advisories/new) ([SECURITY.md](SECURITY.md))—not public issues.
- Do not post live credentials, private source, or sensitive audit output in public issues.
- Keep all work defensive and remediation-focused. Exploit generation, live-target interaction, credential use, and offensive bypass guidance are out of scope.
- Follow the [Code of Conduct](CODE_OF_CONDUCT.md).
- For larger changes, open an issue first so tool contracts and trust-boundary implications can be discussed before implementation.

## Development setup

Requirements are Node.js 20 or newer and pnpm 10.

```bash
git clone https://github.com/brbndon/secure-mcp.git
cd secure-mcp
pnpm install --frozen-lockfile
pnpm verify
```

The smoke test scopes the server to bundled fixtures. For manual client testing, explicitly configure the repositories the server may read:

```bash
export SECURE_MCP_ALLOWED_ROOTS=/absolute/path/to/test/repositories
pnpm dev
```

## Trust model

Changes must preserve these invariants:

1. Tools are read-only and never execute target-project code, scripts, plugins, or binaries.
2. Every filesystem operation stays within both the requested `project_root` and the process allowlist after canonical path and symlink checks.
3. Stdout is reserved for MCP JSON-RPC; diagnostics go to stderr.
4. Reads and responses remain bounded, and coverage states what was excluded or truncated.
5. Secret-like and untrusted evidence is redacted or neutralized before return.
6. Findings distinguish evidence from assumptions and always lead to remediation and verification.

Review [the architecture notes](docs/docs/architecture.md) and [the development guide](skills/development.md) before changing filesystem, redaction, finding-schema, or tool-boundary code.

## Making changes

- Keep tool names and existing finding fields backward compatible unless a breaking change is explicitly planned.
- Use strict TypeScript and ESM-relative imports with `.js` extensions.
- Add or update focused tests for behavior changes and false-positive guards.
- Update the smallest relevant documentation when setup, configuration, tools, or output contracts change.
- Do not commit real credentials. Fixtures must contain unmistakably fake values that cannot authenticate anywhere.
- Avoid unrelated refactors in the same pull request.

## Verification

Run the full server suite:

```bash
pnpm verify
```

For documentation changes, also run:

```bash
pnpm docs:build
pnpm docs:check
pnpm docs:validate
```

Before proposing a package or release change, run the complete release gate:

```bash
pnpm release:check
```

## Pull requests

A pull request should explain what changed, why it changed, security or compatibility impact, and how it was verified. Keep commits reviewable and respond to review feedback with follow-up commits when practical.

By contributing, you agree that your contribution is licensed under the [Apache License 2.0](LICENSE).
