# Agent Instructions

## Package Manager
- Use **pnpm** 10 with `pnpm install --frozen-lockfile`.

## Commands
| Task | Command |
|------|---------|
| Typecheck | `pnpm typecheck` |
| Unit + protocol tests | `pnpm exec tsx --test path/to/file.test.ts` |
| Full server suite | `pnpm verify` |
| Docs | `pnpm docs:build` then `pnpm docs:check` then `pnpm docs:validate` |
| Release gate | `pnpm release:check` |

## External References
| Need | File |
|------|------|
| Setup and PR rules | `CONTRIBUTING.md` |
| Contributor code map | `skills/development.md` |
| Architecture | `docs/docs/architecture.md` |
| Tool contracts | `docs/docs/tool-design.md` |
| Agent workflow (human summary) | `docs/docs/agent-workflow.md` |
| Installed audit skill | `.agents/skills/secure-mcp/SKILL.md` |
| Security policy | `SECURITY.md` |
| Release process | `RELEASING.md` |

## Key Conventions
- Tools are read-only and must never execute target-project code.
- Filesystem access goes through `normalizeProjectRoot` / `resolveSafePath` and the process allowlist.
- Stdout is reserved for MCP JSON-RPC; diagnostics go to stderr.
- Keep tool names and `Finding` fields backward compatible unless a break is planned.
- Use ESM-relative imports with `.js` extensions.
- Do not add, remove, or upgrade dependencies unless explicitly requested.
