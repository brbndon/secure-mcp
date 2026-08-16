#!/usr/bin/env bash
#
# setup.sh — one-command bootstrap for a fresh clone (macOS / Linux).
# Builds the server, prompts for the filesystem allowlist when unset, then
# installs the skill and MCP server wiring for the configured harness (pi,
# Cursor, OpenAI Codex) and verifies the result.
#
# Usage:
#   ./scripts/setup.sh                                   # interactive roots prompt
#   SECURE_MCP_ALLOWED_ROOTS=/abs/path ./scripts/setup.sh  # non-interactive
#
# Idempotent: re-run any time to refresh skill links and client configs.
# Uninstall remains:  ./scripts/install-agents.sh uninstall
# Windows users:      .\scripts\setup.ps1
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

log() { printf '\033[1;36m[setup]\033[0m %s\n' "$*"; }
die() { printf '\033[1;31m[setup]\033[0m error: %s\n' "$*" >&2; exit 1; }

require() { command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"; }
require node
require pnpm
require python3

log "installing dependencies (pnpm install --frozen-lockfile)"
(cd "$ROOT" && pnpm install --frozen-lockfile)

log "building the server (pnpm build)"
(cd "$ROOT" && pnpm build)

if [[ ! "${SECURE_MCP_ALLOWED_ROOTS:-}" =~ [^[:space:]] ]]; then
  printf '%s\n' \
    "secure-mcp needs an explicit allowlist of existing absolute directories." \
    "Prefer the parent that contains the repositories you review" \
    "(for example /Users/you/Code), not your home directory and not a single" \
    "app unless that is the only tree you will audit. Separate multiple" \
    "paths with ':' on macOS/Linux. Add another root later with:" \
    "  ./scripts/install-agents.sh add-root /absolute/path"
  read -r -p "[setup] allowlisted roots: " SECURE_MCP_ALLOWED_ROOTS \
    || die "an allowlist is required (SECURE_MCP_ALLOWED_ROOTS)"
  if [ -z "$SECURE_MCP_ALLOWED_ROOTS" ]; then
    die "an allowlist is required (SECURE_MCP_ALLOWED_ROOTS)"
  fi
  export SECURE_MCP_ALLOWED_ROOTS
fi

log "wiring the skill and MCP server for pi, Cursor, and Codex"
"$ROOT/scripts/install-agents.sh" install
"$ROOT/scripts/install-agents.sh" check

log "done. Restart your agent sessions to pick up the new skill and MCP server."
