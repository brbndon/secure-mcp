# secure-mcp

Local **Model Context Protocol (MCP)** server that helps coding agents run defensive, remediation-focused secure code review of source repositories.

- Focus (v1): TypeScript / Next.js and Swift / SwiftUI
- Transport: stdio only, runs as a local subprocess of the agent client
- License: private / closed-source (`UNLICENSED`)
- Framing: identify potential weaknesses, classify them (CWE / severity / confidence), and recommend concrete remediation. Not an offensive toolkit.

## Why this exists

Rule-based scanners are useful, but agents still need:

- Portable, agent-first tools that work across Codex, Claude, Cursor, Grok, and similar clients
- Structured findings (severity + confidence + required remediation fields) for multi-phase workflows
- Stack awareness beyond generic SAST, especially modern Swift and Next.js App Router patterns
- Remediation-oriented threat modeling, not only regex hits

`secure-mcp` is the private implementation of that.

## Features (v1)

| Tool | Purpose |
|------|---------|
| `secure_mcp_list_project_structure` | Inventory for review scoping |
| `secure_mcp_analyze_architecture` | Stacks, trust boundaries, `recommended_packs` / `pack_batches` |
| `secure_mcp_get_knowledge_pack` | On-demand stack checklists (max 6 packs/call) |
| `secure_mcp_get_audit_guidance` | Detailed agent workflow/guardrails on demand (avoids description bloat) |
| `secure_mcp_check_authentication` | Authn/authz weaknesses → remediation |
| `secure_mcp_analyze_injection_risks` | Injection-class risks → remediation |
| `secure_mcp_review_secrets` | Secret hygiene → rotate & remediate |
| `secure_mcp_build_remediation_threat_model` | STRIDE fragments for hardening priority |
| `secure_mcp_produce_findings` | Dedupe, prioritise, remediation report |

All tools are read-only, never execute project code, and respect ignore patterns / size caps. Bounded audit tools return structured `coverage` with included/reviewed/excluded paths, ignore reasons, caps, truncation, and candidate dispositions; an empty finding list is not a claim that the whole tree was scanned.

Shared optional argument: `focus_paths` accepts relative path prefixes for scoped drill-down on `secure_mcp_list_project_structure`, `secure_mcp_analyze_architecture`, and the category/remediation tools; omit it for a whole-repository review.

### Finding structure

Every finding follows the same shape:

1. `evidence`
2. `classification` (severity, confidence, category, optional CWE)
3. `impact_if_unremediated` (high-level only)
4. `remediation`
5. `residual_risk` / `verification_suggestion`

Findings can also include additive traceability when available: stable `rule_family`, `root_control`, and `instance_id`, plus `source`, `control`, `sink`, `counterevidence`, `proof_gap`, `validation`, and a candidate `disposition`.

## Requirements

- Node.js **20+**
- pnpm (preferred) or npm
- A valid license key (see below)

## Quick start

```bash
# Install
pnpm install

# Build
pnpm build

# Run (stdio MCP server)
export SECURE_MCP_DEV_MODE=1
export SECURE_MCP_LICENSE_KEY=smcp_dev_local_testing_key_v1
pnpm start
```

Development (tsx, no build step):

```bash
export SECURE_MCP_DEV_MODE=1
export SECURE_MCP_LICENSE_KEY=smcp_dev_local_testing_key_v1
pnpm dev
```

Smoke test (spawns the server, lists tools, runs a few calls against a fixture):

```bash
export SECURE_MCP_DEV_MODE=1
export SECURE_MCP_LICENSE_KEY=smcp_dev_local_testing_key_v1
pnpm smoke
```

## License key

The server refuses to start without a valid key (except in DEV_MODE with the documented dev key, which emits a warning).

| Source | Variable |
|--------|----------|
| Environment | `SECURE_MCP_LICENSE_KEY` |
| File (single line) | `SECURE_MCP_LICENSE_FILE` |

Production keys use the signed format `smcp_<payload>.<base64url-signature>`. The payload and signature are verified locally with the operator-configured public key.

Development / CI key (for local and agent testing only):

```text
smcp_dev_local_testing_key_v1
```

**To use dev key:** set both `SECURE_MCP_DEV_MODE=1` and `SECURE_MCP_LICENSE_KEY=smcp_dev_local_testing_key_v1`.
The server emits a clear warning on stderr. Never use the dev key in production or with real data.

Production keys are signed opaque tokens in the form `smcp_<payload>.<base64url-signature>` and are verified locally with `SECURE_MCP_LICENSE_PUBLIC_KEY`; the server fails closed when that public key is missing. No network call is required. The documented development key remains available only with `SECURE_MCP_DEV_MODE=1`.

## Connect from common MCP clients

Use the built entrypoint after `pnpm build`. Always set the license env var in the client config.

### Claude Desktop / Claude Code

```json
{
  "mcpServers": {
    "secure-mcp": {
      "command": "node",
      "args": ["/absolute/path/to/secure-mcp/dist/index.js"],
      "env": {
        "SECURE_MCP_DEV_MODE": "1",
        "SECURE_MCP_LICENSE_KEY": "smcp_dev_local_testing_key_v1"
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
        "SECURE_MCP_DEV_MODE": "1",
        "SECURE_MCP_LICENSE_KEY": "smcp_dev_local_testing_key_v1"
      },
      "lifecycle": "lazy",
      "directTools": true,
      "toolPrefix": "none"
    }
  }
}
```

`directTools: true` + `toolPrefix: "none"` exposes the tools under their canonical `secure_mcp_*` names (matching the master skill).

### Cursor

Add a similar server entry in Cursor MCP settings (`command` + `args` + `env`), including both license env vars. See `scripts/install-agents.sh` for the canonical config.

### Codex / other stdio clients

Point the client at:

```bash
node /absolute/path/to/secure-mcp/dist/index.js
```

with `SECURE_MCP_LICENSE_KEY` in the process environment; when using the documented dev key, also set `SECURE_MCP_DEV_MODE=1`.

> **Important:** `project_root` arguments must be paths visible to the machine running the MCP server (usually your laptop). Prefer absolute paths.

## Install the skill for coding agents

The repository ships a master skill (`.agents/skills/secure-mcp/SKILL.md`) that makes any coding agent run the full defensive audit autonomously: on invocation it creates an audit goal, preflights the repository, routes the bounded multi-phase review through the `secure_mcp_*` tools, and completes the goal only after the remediation report is delivered. Install the skill and the MCP server wiring for every harness with:

```bash
./scripts/install-agents.sh install    # symlink the skill + configure pi, Claude Code, Cursor, Codex
./scripts/install-agents.sh check     # verify symlinks, configs, and server startup
./scripts/install-agents.sh uninstall # remove exactly what install added
```

| Harness | Skill location | MCP server config |
| --- | --- | --- |
| pi | `~/.agents/skills/secure-mcp` → repo | `~/.pi/agent/mcp.json` |
| Claude Code | `~/.claude/skills/secure-mcp` → repo | `~/.claude/settings.json` |
| Cursor | `~/.cursor/skills/secure-mcp` → repo | `~/.cursor/mcp.json` |
| OpenAI Codex | `~/.codex/agents/secure-mcp.toml` (agent manifest) | `~/.codex/config.toml` |

Notes:

- Skill locations are symlinks to the checkout, so edits to the skill propagate to every harness.
- Every client config must set both `SECURE_MCP_LICENSE_KEY` and `SECURE_MCP_DEV_MODE=1` when using the dev key. Omitting `DEV_MODE` makes the server exit at startup (the license gate is strict).
- Restart agent sessions after installing. Skills and MCP servers load at session start.

## Suggested agent workflow (defensive, multi-phase)

1. `secure_mcp_list_project_structure`: inventory (no knowledge packs yet)  
2. `secure_mcp_analyze_architecture`: stacks, trust boundaries, `recommended_packs`, `pack_batches`  
3. `secure_mcp_get_knowledge_pack`: load `pack_batches[0]` first (`detail=summary`; max 6 pack ids per call; items fair-sampled across packs, default max 24)  
4. Category tools: authentication, injection-risks, secrets, threat-model (support focus_paths)
5. Confirm data flows in code; no exploit generation  
6. `secure_mcp_produce_findings`: remediation-focused report  

Long multi-phase reviews with intermediate artifacts are expected for thorough hardening work.

See [docs/agent-workflow.md](docs/agent-workflow.md) and [skills/security-auditor.md](skills/security-auditor.md).

## Project layout

```text
src/
  index.ts          # stdio entry + license gate
  server.ts         # McpServer factory
  config.ts
  tools/            # one file per tool
  knowledge/
    packs/          # named progressive knowledge packs + registry
    common.ts       # scan patterns + re-exports
  lib/              # filesystem helpers, license, types
skills/             # thin auditor orchestrator + development guidance
docs/               # architecture and design notes
examples/           # sample remediation-focused session
scripts/smoke-test.ts
fixtures/tiny-app/  # intentional issues for smoke tests
fixtures/tiny-expo/ # minimal Expo signals for pack routing
fixtures/rn-lib-no-expo/ # react-native dep + non-Expo app.json (detection guard)
```

## Configuration (optional env)

| Variable | Default | Meaning |
|----------|---------|---------|
| `SECURE_MCP_DEV_MODE` | (none) | Set to `1` to allow the documented dev key for local/agent/CI testing only |
| `SECURE_MCP_LICENSE_KEY` | (none) | License key |
| `SECURE_MCP_LICENSE_FILE` | (none) | Path to key file |
| `SECURE_MCP_MAX_FILES` | `400` | Default walk cap |
| `SECURE_MCP_MAX_FILE_BYTES` | `262144` | Per-file read cap |
| `SECURE_MCP_MAX_DEPTH` | `12` | Directory depth cap |
| `SECURE_MCP_MAX_TOTAL_BYTES` | `67108864` | Aggregate file-size cap per walk |
| `SECURE_MCP_ALLOWED_ROOTS` | (required outside dev mode) | OS-path-delimited canonical roots the tools may inspect |
| `SECURE_MCP_LICENSE_PUBLIC_KEY` | (required for production keys) | PEM public key used to verify signed license tokens |

## Documentation

- [Architecture](docs/architecture.md)
- [Tool design](docs/tool-design.md)
- [Agent workflow](docs/agent-workflow.md)
- [Security auditor skill](skills/security-auditor.md)
- [Development skill](skills/development.md)
- [Sample audit session](examples/sample-audit-session.md)
- [Security policy](SECURITY.md)

### Docs website

The repository includes a Blume-powered docs site and a GitHub Actions workflow that builds and checks it:

```bash
pnpm docs:dev
pnpm docs:build
pnpm docs:preview
```

Local docs verification uses `.blume-verify/dist` so it stays separate from the MCP server's compiled `dist/` output. The workflow at `.github/workflows/deploy-docs.yml` runs the same build, type-check, and link validation steps on pushes to `main`; deployment is a separate step handled by a future Cloudflare Pages or Workers configuration.

## Security notes

- Tools only read paths under the requested `project_root` (path traversal and symlink escapes are blocked); production mode additionally requires `SECURE_MCP_ALLOWED_ROOTS`.
- The server does **not** execute target project code.
- Logs go to stderr only (stdout is MCP JSON-RPC).
- Secret findings redact evidence where practical; still handle outputs carefully.
- Secret-like evidence paths and snippets are redacted before return; source file locations remain available for authorized local remediation.
- `not_observed_means` in coverage distinguishes "no candidate in files reviewed" from a partial or truncated scan.
- This product is for authorized defensive review of codebases you own or are engaged to harden.

## Extending

Read [skills/development.md](skills/development.md). Keep tool names and the `Finding` schema stable once clients depend on them. Keep all user-facing language remediation-oriented.

## License

Proprietary: `UNLICENSED`. All rights reserved.
