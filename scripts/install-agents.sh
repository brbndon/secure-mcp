#!/usr/bin/env bash
#
# install-agents.sh — install, verify, or remove the secure-mcp skill and MCP
# server wiring for the user's coding agents (pi, Claude Code, Cursor, OpenAI Codex).
#
# Usage:
#   ./scripts/install-agents.sh install    # symlink the skill + configure every harness (default)
#   ./scripts/install-agents.sh check      # verify symlinks, configs, and server startup
#   ./scripts/install-agents.sh uninstall  # remove exactly what install added
#
# Idempotent: install may be re-run safely. check exits non-zero on any failure.
# Uses python3 (macOS/Linux) for JSON edits; edits only the secure-mcp keys it owns.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SKILL_SRC="$ROOT/.agents/skills/secure-mcp"
SERVER_ENTRY="$ROOT/dist/index.js"
DEV_KEY="smcp_dev_local_testing_key_v1"

SKILL_LINKS=(
  "$HOME/.agents/skills/secure-mcp"
  "$HOME/.claude/skills/secure-mcp"
  "$HOME/.cursor/skills/secure-mcp"
)
JSON_CONFIGS=(
  "$HOME/.pi/agent/mcp.json"
  "$HOME/.claude/settings.json"
  "$HOME/.cursor/mcp.json"
)
CODEX_CONFIG="$HOME/.codex/config.toml"
CODEX_AGENT_SRC="$ROOT/agents/codex.toml"
CODEX_AGENT_DST="$HOME/.codex/agents/secure-mcp.toml"

log()  { printf '\033[1;36m[install-agents]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[install-agents]\033[0m warning: %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[install-agents]\033[0m error: %s\n' "$*" >&2; exit 1; }

# --- JSON helpers -----------------------------------------------------------

# json_set <file> — set mcpServers["secure-mcp"] to the standard entry (create file if needed).
json_set() {
  local file="$1"
  mkdir -p "$(dirname "$file")"
  SECURE_MCP_ENTRY="$SERVER_ENTRY" SECURE_MCP_DEV_KEY="$DEV_KEY" python3 - "$file" <<'PY'
import json, os, sys

path = sys.argv[1]
entry = {
    "command": "node",
    "args": [os.environ["SECURE_MCP_ENTRY"]],
    "env": {
        "SECURE_MCP_LICENSE_KEY": os.environ["SECURE_MCP_DEV_KEY"],
        "SECURE_MCP_DEV_MODE": "1",
    },
}
try:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
except FileNotFoundError:
    data = {}
except json.JSONDecodeError as exc:
    sys.exit(f"cannot parse {path}: {exc}")
data.setdefault("mcpServers", {})["secure-mcp"] = entry
with open(path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
PY
}

# json_remove <file> — remove mcpServers["secure-mcp"]; drop an emptied mcpServers object.
json_remove() {
  local file="$1"
  [ -f "$file" ] || return 0
  python3 - "$file" <<'PY'
import json, os, sys

path = sys.argv[1]
try:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
except json.JSONDecodeError as exc:
    sys.exit(f"cannot parse {path}: {exc}")
servers = data.get("mcpServers")
if isinstance(servers, dict):
    servers.pop("secure-mcp", None)
    if not servers:
        data.pop("mcpServers", None)
with open(path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
PY
}

json_has_entry() {
  local file="$1"
  [ -f "$file" ] || return 1
  python3 - "$file" <<'PY'
import json, sys
try:
    data = json.load(open(sys.argv[1], encoding="utf-8"))
except (FileNotFoundError, json.JSONDecodeError):
    sys.exit(1)
entry = (data.get("mcpServers") or {}).get("secure-mcp")
sys.exit(0 if isinstance(entry, dict) else 1)
PY
}

# --- Codex TOML helpers -----------------------------------------------------

codex_section_present() {
  grep -q '^\[mcp_servers\.secure-mcp\]' "$CODEX_CONFIG" 2>/dev/null
}

codex_section_append() {
  if codex_section_present; then
    log "codex: $CODEX_CONFIG already has [mcp_servers.secure-mcp]"
    return 0
  fi
  cat >> "$CODEX_CONFIG" <<EOF

[mcp_servers.secure-mcp]
command = "node"
args = ["$SERVER_ENTRY"]

[mcp_servers.secure-mcp.env]
SECURE_MCP_LICENSE_KEY = "$DEV_KEY"
SECURE_MCP_DEV_MODE = "1"
EOF
  log "codex: appended [mcp_servers.secure-mcp] to $CODEX_CONFIG"
}

codex_section_remove() {
  [ -f "$CODEX_CONFIG" ] || return 0
  if ! codex_section_present; then
    log "codex: no secure-mcp section in $CODEX_CONFIG"
    return 0
  fi
  local tmp
  tmp="$(mktemp)"
  # Drop from the section header (and its sub-tables) through the line before
  # the next top-level section, preserving everything else.
  awk '
    /^\[mcp_servers\.secure-mcp(\]|\.)/ { skip = 1; next }
    /^\[/ { skip = 0 }
    !skip
  ' "$CODEX_CONFIG" > "$tmp"
  mv "$tmp" "$CODEX_CONFIG"
  log "codex: removed [mcp_servers.secure-mcp] from $CODEX_CONFIG"
}

# --- Skill symlinks ---------------------------------------------------------

link_skill() {
  local target="$1"
  mkdir -p "$(dirname "$target")"
  if [ -L "$target" ]; then
    local cur
    cur="$(readlink "$target")"
    if [ "$cur" = "$SKILL_SRC" ]; then
      log "skill: $target already linked"
      return 0
    fi
    warn "replacing existing symlink at $target (was -> $cur)"
    rm "$target"
  elif [ -e "$target" ]; then
    die "refusing to replace non-symlink at $target; move it aside and re-run"
  fi
  ln -s "$SKILL_SRC" "$target"
  log "skill: linked $target -> $SKILL_SRC"
}

unlink_skill() {
  local target="$1"
  if [ -L "$target" ]; then
    local cur
    cur="$(readlink "$target")"
    if [ "$cur" = "$SKILL_SRC" ]; then
      rm "$target"
      log "skill: removed $target"
    else
      warn "not removing $target (points to $cur, not $SKILL_SRC)"
    fi
  fi
}

# --- Server probe -----------------------------------------------------------

probe_server() {
  local out
  out="$(SECURE_MCP_LICENSE_KEY="$DEV_KEY" SECURE_MCP_DEV_MODE=1 node "$SERVER_ENTRY" </dev/null 2>&1)" || {
    warn "server probe failed with exit $?"
    printf '%s\n' "$out" | sed 's/^/    /' >&2
    return 1
  }
  printf '%s\n' "$out" | grep -q "License OK" || { warn "server probe: license not OK"; return 1; }
  printf '%s\n' "$out" | grep -q "running on stdio" || { warn "server probe: did not reach stdio"; return 1; }
  log "server: $SERVER_ENTRY starts and passes the license gate"
}

# --- Modes ------------------------------------------------------------------

cmd_install() {
  [ -f "$SERVER_ENTRY" ] || die "build the server first (pnpm build) — $SERVER_ENTRY missing"
  log "installing secure-mcp for coding agents (skill source: $SKILL_SRC)"
  for target in "${SKILL_LINKS[@]}"; do link_skill "$target"; done
  for cfg in "${JSON_CONFIGS[@]}"; do json_set "$cfg"; log "json: configured secure-mcp in $cfg"; done
  codex_section_append
  mkdir -p "$(dirname "$CODEX_AGENT_DST")"
  cp "$CODEX_AGENT_SRC" "$CODEX_AGENT_DST"
  log "codex: installed agent manifest $CODEX_AGENT_DST"
  log "done. Restart your agent sessions (pi, Claude Code, Cursor, Codex) to pick up changes."
}

cmd_uninstall() {
  log "uninstalling secure-mcp agent wiring"
  for target in "${SKILL_LINKS[@]}"; do unlink_skill "$target"; done
  for cfg in "${JSON_CONFIGS[@]}"; do json_remove "$cfg"; log "json: removed secure-mcp from $cfg"; done
  codex_section_remove
  if [ -f "$CODEX_AGENT_DST" ]; then rm -f "$CODEX_AGENT_DST"; log "codex: removed $CODEX_AGENT_DST"; fi
  log "done. The repo skill and server are untouched."
}

cmd_check() {
  local failures=0
  log "checking skill symlinks"
  for target in "${SKILL_LINKS[@]}"; do
    if [ -L "$target" ] && [ "$(readlink "$target")" = "$SKILL_SRC" ]; then
      log "  ok: $target"
    else
      warn "missing or wrong symlink at $target"
      failures=$((failures + 1))
    fi
  done

  log "checking client configs"
  for cfg in "${JSON_CONFIGS[@]}"; do
    if json_has_entry "$cfg"; then
      log "  ok: $cfg has secure-mcp entry"
    else
      warn "missing secure-mcp entry in $cfg"
      failures=$((failures + 1))
    fi
  done

  if codex_section_present && grep -q '^SECURE_MCP_DEV_MODE = "1"' "$CODEX_CONFIG"; then
    log "  ok: $CODEX_CONFIG has secure-mcp section"
  else
    warn "missing secure-mcp section in $CODEX_CONFIG"
    failures=$((failures + 1))
  fi

  if [ -f "$CODEX_AGENT_DST" ] && cmp -s "$CODEX_AGENT_SRC" "$CODEX_AGENT_DST"; then
    log "  ok: $CODEX_AGENT_DST matches repo manifest"
  else
    warn "missing or stale Codex agent manifest at $CODEX_AGENT_DST"
    failures=$((failures + 1))
  fi

  if [ -f "$SERVER_ENTRY" ]; then
    probe_server || failures=$((failures + 1))
    if find "$ROOT/src" -name "*.ts" -newer "$SERVER_ENTRY" -print -quit | grep -q .; then
      warn "dist/index.js is older than some src files — run pnpm build"
    fi
  else
    warn "server entry $SERVER_ENTRY missing — run pnpm build"
    failures=$((failures + 1))
  fi

  if [ "$failures" -eq 0 ]; then
    log "all checks passed."
  else
    die "$failures check(s) failed"
  fi
}

case "${1:-install}" in
  install)   cmd_install ;;
  uninstall) cmd_uninstall ;;
  check)     cmd_check ;;
  *) die "usage: $0 [install|uninstall|check]" ;;
esac
