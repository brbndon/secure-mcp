---
title: Architecture
description: Understand secure-mcp's stdio process boundary, filesystem safety policy, progressive knowledge packs, and the layers that keep audits read-only.
sidebar:
  label: Architecture
  order: 6
---

## Overview

`secure-mcp` is a **local, stdio MCP server** written in TypeScript. Coding agents spawn it as a subprocess and call tools to perform **defensive, remediation-focused secure code review** of a target repository on disk.

```text
┌─────────────────────┐     stdio (JSON-RPC)     ┌──────────────────────┐
│  Coding agent       │ ◄──────────────────────► │  secure-mcp process  │
│  (Codex/Claude/…)   │                          │  src/index.ts        │
└─────────────────────┘                          │    ├ license gate    │
                                                 │    ├ McpServer       │
                                                 │    └ tools/*         │
                                                 └──────────┬───────────┘
                                                            │ read-only FS
                                                            ▼
                                                 ┌──────────────────────┐
                                                 │  target project_root │
                                                 └──────────────────────┘
```

## Design principles

1. **Defensive only:** identify weaknesses → classify → remediate. No exploit/PoC generation.
2. **Agent-first:** precise tool descriptions, structured JSON, severity + confidence.
3. **Stateless tools:** no server-side session store; the agent holds intermediate artifacts.
4. **Safe by default:** path confinement, ignore lists, size/depth caps, no code execution.
5. **Stable contracts:** tool names and `Finding` shape should not change casually.
6. **Light abstractions:** small modules agents can extend without a framework maze.

## Layers

| Layer | Path | Role |
|-------|------|------|
| Entry | `src/index.ts` | License check, stdio transport |
| Server | `src/server.ts` | `McpServer` + tool registration |
| Tools | `src/tools/*.ts` | MCP tool handlers (defensive descriptions) |
| Knowledge | `src/knowledge/packs/` + `*.ts` | Progressive packs, patterns, findings schema |
| Lib | `src/lib/*` | FS safety, license, shared types |
| Config | `src/config.ts` | Env-driven limits |

## Transport

v1 supports **stdio only** (`StdioServerTransport` from `@modelcontextprotocol/sdk`).

- Do **not** log to stdout (corrupts the protocol).
- Use `console.error` for startup and failure messages.

## License gate

On startup, `requireValidLicense()` resolves:

1. `SECURE_MCP_LICENSE_KEY`, or
2. first non-comment line of `SECURE_MCP_LICENSE_FILE`

Validation is local format checking (`smcp_<token>`). The documented development key is accepted only when `SECURE_MCP_DEV_MODE=1` is set; startup emits a warning in that mode. Invalid/missing keys exit with code `1`, and production keys should be used without DEV_MODE.

## Filesystem policy

`src/lib/filesystem.ts` centralizes:

- Absolute root normalization
- Path traversal rejection (`resolveSafePath`)
- Default ignores (`node_modules`, `.git`, `dist`, `.next`, `Pods`, …)
- Caps: max files, max depth, max bytes per file
- Response truncation (`CHARACTER_LIMIT`)

## Findings contract

Defined in `src/lib/types.ts` and `src/knowledge/findings-schema.ts`:

Required remediation structure:

- `evidence`
- `severity` / `confidence` / `category` (+ optional `cwe`)
- `impact_if_unremediated`
- `remediation`
- `residual_risk`
- `verification_suggestion`

Category tools emit findings; `secure_mcp_produce_findings` normalises them for reports.

## Progressive knowledge packs

Agents should **not** load every stack checklist into context. Architecture returns `recommended_packs` and `pack_batches` (chunks of ≤6 ids for `secure_mcp_get_knowledge_pack`). Load `pack_batches[0]` first with `detail=summary`; load later batches only if needed. Multi-pack responses fair-sample checklist items (round-robin; default max 24, hard max 60) so core/secrets priority order does not zero out stack packs. Pack responses omit the global catalog unless `include_index=true`.

| Pack id | Content |
|---------|---------|
| `core` | Authz, injection, secrets, crypto, logging, paths, deps |
| `threat-model` | Trust boundaries / STRIDE-oriented control planning |
| `web-next` | Next.js App Router, middleware, Server Actions, `NEXT_PUBLIC_` |
| `web-api` | General API route/handler hardening |
| `auth-web` | Cookies, CSRF, web session hardening |
| `swift-ios` | Keychain, biometrics, ATS, WebView, deep links |
| `apple-desktop` | macOS entitlements, sandbox, XPC, desktop logging |
| `expo-rn` | SecureStore, Expo config secrets, deep links, OTA |
| `secrets` | Rotation, env hygiene, client-bundle exposure |

Every pack item carries the full remediation narrative (`impact_if_unremediated`, `remediation`, `verification_suggestion`) so agents can lift items into findings without inventing copy. Packs hold ~10–13 items each: substantial, but small enough that a complete five-pack recommendation still fits the 60-item budget in one call. `truncated_by_max_items` compares the returned items against the **category-filtered** stream, so narrow `categories` filters are not reported as truncation.

Stack detection is deliberately conservative (`looksLikeExpoOrReactNativeApp` in `src/lib/filesystem.ts`): Expo/React Native routing needs an Expo dependency, an `expo` block in `app.json`/`app.config.*`, `eas.json`, or a `react-native` dependency plus app evidence (metro/RN config or `android/` + `ios/`). A bare `app.json` or a stray `react-native` dependency in a web/library package does not route to `expo-rn`. Profiling is root-scoped: Expo apps under `apps/` or `packages/` in a monorepo are invisible until `project_root` points at that package (or you force `stack: "expo"`).

Registry + routing + fair sampling: `src/knowledge/packs/registry.ts` (`recommendPackPlan`, `filterPackItems`).  
Scan heuristics remain in `common.ts` / `nextjs.ts` / `swift.ts` (used server-side by category tools without dumping full packs).

Heuristics are intentionally imperfect. Confidence fields tell agents to verify before confirming.

## Out of scope (v1)

- HTTP / remote MCP transport
- Database or persistent audit history
- Heavy DRM / online license enforcement
- Full multi-language SAST
- GUI dashboard
- Executing or building the target project
- Offensive exploit development

## Extension points

1. Add a tool under `src/tools/` and register it in `src/tools/index.ts` with defensive descriptions.
2. Add or extend packs under `src/knowledge/packs/` and register them in `registry.ts`.
3. Optional remote license validation inside `src/lib/license.ts` without changing tools.
