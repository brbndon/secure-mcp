# secure-mcp

[![CI](https://github.com/brbndon/secure-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/brbndon/secure-mcp/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Local **Model Context Protocol (MCP)** server that helps coding agents run defensive, remediation-focused secure code review of source repositories.

- Focus (v1): TypeScript / Next.js, Swift / SwiftUI, and Expo / React Native
- Transport: stdio only, running as a local subprocess of the agent client
- License: [Apache-2.0](LICENSE)
- Framing: identify potential weaknesses, classify them by CWE, severity, and confidence, then recommend concrete remediation. This is not an offensive toolkit.

## Why this exists

Rule-based scanners are useful, but agents still need:

- Portable, agent-first tools that work across Codex, Claude, Cursor, pi, and similar clients
- Structured findings with required remediation fields for multi-phase workflows
- Stack awareness beyond generic SAST, especially for modern Swift and Next.js App Router patterns
- Remediation-oriented threat modeling, not only regex hits

`secure-mcp` is an open-source implementation of that workflow.

## Features

| Tool | Purpose |
| --- | --- |
| `secure_mcp_list_project_structure` | Inventory for review scoping |
| `secure_mcp_analyze_architecture` | Stacks, trust boundaries, `recommended_packs`, and `pack_batches` |
| `secure_mcp_get_knowledge_pack` | On-demand stack checklists (maximum six packs per call) |
| `secure_mcp_get_audit_guidance` | Detailed agent workflow and guardrails on demand |
| `secure_mcp_check_authentication` | Authentication and authorization weaknesses to remediate |
| `secure_mcp_analyze_injection_risks` | Injection-class risks to remediate |
| `secure_mcp_review_secrets` | Secret hygiene, rotation, and remediation |
| `secure_mcp_build_remediation_threat_model` | STRIDE fragments for hardening priorities |
| `secure_mcp_produce_findings` | Deduplicated, prioritized remediation report |

All tools are read-only, never execute project code, and respect ignore patterns and size caps. Bounded audit tools return structured `coverage` with reviewed and excluded paths, ignore reasons, caps, truncation, and candidate dispositions. An empty finding list is not a claim that the entire tree was scanned.

`focus_paths` accepts relative path prefixes for scoped drill-down on repository, architecture, and category tools. Omit it for a whole-repository review.

### Finding structure

Every finding follows the same shape:

1. `evidence`
2. `classification` (severity, confidence, category, optional CWE)
3. `impact_if_unremediated`
4. `remediation`
5. `residual_risk` and `verification_suggestion`

Findings can also include stable traceability fields such as `rule_family`, `root_control`, `instance_id`, `source`, `control`, `sink`, `counterevidence`, `proof_gap`, `validation`, and candidate `disposition`.

## Requirements

- Node.js 20 or newer
- pnpm 10 (preferred) or npm
- One or more local paths that the server is authorized to inspect

## Quick start

```bash
git clone https://github.com/brbndon/secure-mcp.git
cd secure-mcp
pnpm install --frozen-lockfile
pnpm build

# Required for filesystem tools. Use `:` between roots on macOS/Linux and `;` on Windows.
export SECURE_MCP_ALLOWED_ROOTS=/absolute/path/to/repositories
pnpm start
```

Development uses `tsx` and does not require a build first:

```bash
export SECURE_MCP_ALLOWED_ROOTS=/absolute/path/to/repositories
pnpm dev
```

The smoke test scopes itself to the bundled fixtures:

```bash
pnpm smoke
```

## Filesystem authorization

`SECURE_MCP_ALLOWED_ROOTS` is required for tools that read a repository. It is an OS-path-delimited list of canonical roots under which `project_root` values may resolve. Missing or stale entries fail closed; symlink and path-traversal escapes are rejected.

Keep the allowlist as narrow as practical. For example, authorize one checkout instead of your entire home directory:

```bash
export SECURE_MCP_ALLOWED_ROOTS=/Users/alice/Code/example-app
```

## Connect from common MCP clients

Build the project, then point your client at `dist/index.js`. The paths below must be absolute.

### Claude Desktop / Claude Code

```json
{
  "mcpServers": {
    "secure-mcp": {
      "command": "node",
      "args": ["/absolute/path/to/secure-mcp/dist/index.js"],
      "env": {
        "SECURE_MCP_ALLOWED_ROOTS": "/absolute/path/to/repositories"
      }
    }
  }
}
```

### pi

```json
{
  "mcpServers": {
    "secure-mcp": {
      "command": "node",
      "args": ["/absolute/path/to/secure-mcp/dist/index.js"],
      "env": {
        "SECURE_MCP_ALLOWED_ROOTS": "/absolute/path/to/repositories"
      },
      "lifecycle": "lazy",
      "directTools": true,
      "toolPrefix": "none"
    }
  }
}
```

`directTools: true` and `toolPrefix: "none"` expose the canonical `secure_mcp_*` tool names used by the master skill.

Cursor and other stdio clients use the same `command`, `args`, and `env` shape. The `project_root` passed to a tool must be visible to the machine running the MCP server; absolute paths are safest.

## Install the skill for coding agents

The repository ships a master skill at `.agents/skills/secure-mcp/SKILL.md`. It preflights a repository, routes a bounded multi-phase review through the `secure_mcp_*` tools, and completes only after a remediation report is delivered.

```bash
export SECURE_MCP_ALLOWED_ROOTS=/absolute/path/to/repositories
./scripts/install-agents.sh install
./scripts/install-agents.sh check
./scripts/install-agents.sh uninstall
```

The installer requires that explicit allowlist and writes it into each client configuration.

| Harness | Skill location | MCP server config |
| --- | --- | --- |
| pi | `~/.agents/skills/secure-mcp` → checkout | `~/.pi/agent/mcp.json` |
| Cursor | `~/.cursor/skills/secure-mcp` → checkout | `~/.cursor/mcp.json` |
| OpenAI Codex | `~/.codex/agents/secure-mcp.toml` | `~/.codex/config.toml` |

Restart agent sessions after installation so clients reload their skills and MCP configuration.

## Suggested agent workflow

1. `secure_mcp_list_project_structure`: inventory the repository and coverage.
2. `secure_mcp_analyze_architecture`: identify stacks, trust boundaries, and `pack_batches`.
3. `secure_mcp_get_knowledge_pack`: load the first batch at summary detail.
4. Run authentication, injection-risk, secrets, and threat-model tools as applicable.
5. Confirm candidate data flows in source; do not generate exploit content.
6. `secure_mcp_produce_findings`: deliver the remediation-focused report.

Long reviews intentionally carry small intermediate artifacts between phases. See the [agent workflow](docs/docs/agent-workflow.md) and [security auditor skill](skills/security-auditor.md).

## Project layout

```text
src/
  index.ts          # stdio entrypoint
  server.ts         # McpServer factory
  config.ts         # environment-driven limits and root allowlist
  tools/            # one file per MCP tool
  knowledge/
    packs/          # progressive knowledge packs and registry
    common.ts       # scan patterns and re-exports
  lib/              # filesystem safety, redaction, markdown, and types
.agents/skills/     # installable secure-mcp agent skill
docs/docs/          # architecture, workflow, and usage documentation
examples/           # sample remediation-focused session
scripts/            # installer, smoke test, and site capture utilities
fixtures/           # intentionally vulnerable and stack-detection test apps
```

## Configuration

| Variable | Default | Meaning |
| --- | --- | --- |
| `SECURE_MCP_ALLOWED_ROOTS` | none (filesystem access denied) | OS-path-delimited canonical roots the tools may inspect |
| `SECURE_MCP_MAX_FILES` | `400` | Default walk cap |
| `SECURE_MCP_MAX_FILE_BYTES` | `262144` | Per-file read cap |
| `SECURE_MCP_MAX_DEPTH` | `12` | Directory depth cap |
| `SECURE_MCP_MAX_TOTAL_BYTES` | `67108864` | Aggregate file-size cap per walk |

The server clamps configurable values to fixed hard limits.

## Documentation

- [Architecture](docs/docs/architecture.md)
- [Tool design](docs/docs/tool-design.md)
- [Agent workflow](docs/docs/agent-workflow.md)
- [Security auditor skill](skills/security-auditor.md)
- [Development guide](skills/development.md)
- [Sample audit session](examples/sample-audit-session.md)
- [Contributing guide](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)
- [Release process](RELEASING.md)

The Blume-powered documentation site can be verified locally with:

```bash
pnpm docs:build
pnpm docs:check
pnpm docs:validate
```

## Security notes

- Filesystem tools only read authorized `project_root` paths; path traversal and symlink escapes are blocked.
- The server does not execute target code or make network requests.
- Logs go to stderr only; stdout is reserved for MCP JSON-RPC.
- Secret-like evidence is redacted before it crosses the MCP boundary, but audit output should still be handled carefully.
- Coverage distinguishes “no candidate in files reviewed” from a partial or truncated scan.
- Use the project only for authorized defensive review of codebases you own or are engaged to harden.

For bugs, questions, and feature requests, use [GitHub Issues](https://github.com/brbndon/secure-mcp/issues). Prefer a private contact for anything that would leak secrets or sensitive audit output if posted publicly.

## Contributing

Contributions are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. Keep changes read-only and remediation-focused.

## License

Licensed under the [Apache License 2.0](LICENSE).
