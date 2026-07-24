# secure-mcp

Local **Model Context Protocol (MCP)** server that helps coding agents perform **defensive, remediation-focused secure code review** of source repositories.

**Focus (v1):** TypeScript / Next.js and Swift / SwiftUI  
**Transport:** stdio only (runs as a local subprocess of the agent client)  
**License:** private / closed-source (`UNLICENSED`)  
**Framing:** identify potential weaknesses → classify (CWE / severity / confidence) → recommend concrete remediation. **Not** an offensive toolkit.

## Why this exists

Rule-based scanners are useful, but agents still need:

- Portable, agent-first tools that work across Codex, Claude, Cursor, Grok, and similar clients
- Structured findings (severity + confidence + **required remediation fields**) for multi-phase workflows
- Stack awareness beyond generic SAST—especially modern Swift and Next.js App Router patterns
- Remediation-oriented threat modeling, not only regex hits

`secure-mcp` is the private implementation of that product surface.

## Features (v1)

| Tool | Purpose |
|------|---------|
| `secure_mcp_list_project_structure` | Inventory for review scoping |
| `secure_mcp_analyze_architecture` | Stacks, trust boundaries, `recommended_packs` / `pack_batches` |
| `secure_mcp_get_knowledge_pack` | On-demand stack checklists (max 6 packs/call) |
| `secure_mcp_check_authentication` | Authn/authz weaknesses → remediation |
| `secure_mcp_analyze_injection_risks` | Injection-class risks → remediation |
| `secure_mcp_review_secrets` | Secret hygiene → rotate & remediate |
| `secure_mcp_build_remediation_threat_model` | STRIDE fragments for hardening priority |
| `secure_mcp_produce_findings` | Dedupe, prioritise, remediation report |

All tools are **read-only**, never execute project code, and respect ignore patterns / size caps.

### Finding structure

Every finding is structured as:

1. **evidence**
2. **classification** (severity, confidence, category, optional CWE)
3. **impact_if_unremediated** (high-level only)
4. **remediation**
5. **residual_risk** / **verification_suggestion**

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
export SECURE_MCP_LICENSE_KEY=smcp_dev_local_testing_key_v1
pnpm start
```

Development (tsx, no build step):

```bash
export SECURE_MCP_LICENSE_KEY=smcp_dev_local_testing_key_v1
pnpm dev
```

Smoke test (spawns the server, lists tools, runs a few calls against a fixture):

```bash
export SECURE_MCP_LICENSE_KEY=smcp_dev_local_testing_key_v1
pnpm smoke
```

## License key

The server **refuses to start** without a valid key.

| Source | Variable |
|--------|----------|
| Environment | `SECURE_MCP_LICENSE_KEY` |
| File (single line) | `SECURE_MCP_LICENSE_FILE` |

**Format:** `smcp_<token>` where token is ≥16 characters of `[A-Za-z0-9_-]`.

**Development key (documented for local/CI only):**

```text
smcp_dev_local_testing_key_v1
```

v1 performs **local format validation only** (no network). A remote validator can be added later without changing tool names.

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
        "SECURE_MCP_LICENSE_KEY": "smcp_dev_local_testing_key_v1"
      }
    }
  }
}
```

### Cursor

Add a similar server entry in Cursor MCP settings (`command` + `args` + `env`).

### Codex / other stdio clients

Point the client at:

```bash
node /absolute/path/to/secure-mcp/dist/index.js
```

with `SECURE_MCP_LICENSE_KEY` in the process environment.

> **Important:** `project_root` arguments must be paths **visible to the machine running the MCP server** (usually your laptop). Prefer absolute paths.

## Suggested agent workflow (defensive, multi-phase)

1. `secure_mcp_list_project_structure` — inventory (no knowledge packs yet)  
2. `secure_mcp_analyze_architecture` — stacks, trust boundaries, `recommended_packs`, `pack_batches`  
3. `secure_mcp_get_knowledge_pack` — load `pack_batches[0]` first (`detail=summary`; max 6 pack ids per call; items fair-sampled across packs, default max 24)  
4. Category tools: authentication, injection-risks, secrets (+ optional threat model)  
5. Confirm data flows in code; no exploit generation  
6. `secure_mcp_produce_findings` — remediation-focused report  

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
| `SECURE_MCP_LICENSE_KEY` | — | License key |
| `SECURE_MCP_LICENSE_FILE` | — | Path to key file |
| `SECURE_MCP_MAX_FILES` | `400` | Default walk cap |
| `SECURE_MCP_MAX_FILE_BYTES` | `262144` | Per-file read cap |
| `SECURE_MCP_MAX_DEPTH` | `12` | Directory depth cap |

## Documentation

- [Architecture](docs/architecture.md)
- [Tool design](docs/tool-design.md)
- [Agent workflow](docs/agent-workflow.md)
- [Security auditor skill](skills/security-auditor.md)
- [Development skill](skills/development.md)
- [Sample audit session](examples/sample-audit-session.md)

## Security notes

- Tools only **read** paths under the requested `project_root` (path traversal blocked).
- The server does **not** execute target project code.
- Logs go to **stderr** only (stdout is MCP JSON-RPC).
- Secret findings redact evidence where practical; still handle outputs carefully.
- This product is for **authorized defensive review** of codebases you own or are engaged to harden.

## Extending

Read [skills/development.md](skills/development.md). Keep tool names and the `Finding` schema stable once clients depend on them. Keep all user-facing language remediation-oriented.

## License

Proprietary — `UNLICENSED`. All rights reserved.
