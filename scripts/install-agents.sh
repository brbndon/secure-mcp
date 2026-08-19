#!/usr/bin/env bash
#
# install-agents.sh — install, verify, or remove the secure-mcp skill and MCP
# server wiring for the user's coding agents (pi, Cursor, OpenAI Codex).
#
# secure-mcp 2.x speaks MCP revision 2026-07-28 only. Clients must support the
# modern `server/discover` opening; legacy 2025-era handshakes are rejected.
#
# Usage:
#   SECURE_MCP_ALLOWED_ROOTS=/path/to/repos ./scripts/install-agents.sh install
#   ./scripts/install-agents.sh check      # verify symlinks, configs, and server startup
#   ./scripts/install-agents.sh add-root /absolute/path   # append a root to an existing install
#   ./scripts/install-agents.sh uninstall  # remove exactly what install added
#
# Windows is unsupported; use Linux or macOS.
#
# Idempotent: install may be re-run safely. check exits non-zero on any failure.
# The installer owns only the secure-mcp keys it writes; conflicting non-owned
# entries and skills are never overwritten. Test harnesses may redirect all
# user-level writes with SECURE_MCP_INSTALL_HOME.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SKILL_SRC="$ROOT/.agents/skills/secure-mcp"
SERVER_ENTRY="$ROOT/dist/index.js"
CONFIGURED_ROOTS="${SECURE_MCP_ALLOWED_ROOTS:-}"
# Test harnesses may redirect all user-level writes without repurposing HOME.
INSTALL_HOME="${SECURE_MCP_INSTALL_HOME:-$HOME}"
INSTALL_VERSION="2.0.0"
INSTALL_REPO="https://github.com/brbndon/secure-mcp"
MARKER_KEY="secureMcpInstall"

SKILL_LINKS=(
  "$INSTALL_HOME/.agents/skills/secure-mcp"
  "$INSTALL_HOME/.cursor/skills/secure-mcp"
)
JSON_CONFIGS=(
  "$INSTALL_HOME/.pi/agent/mcp.json"
  "$INSTALL_HOME/.cursor/mcp.json"
)
CODEX_CONFIG="$INSTALL_HOME/.codex/config.toml"
CODEX_AGENT_SRC="$ROOT/agents/codex.toml"
CODEX_AGENT_DST="$INSTALL_HOME/.codex/agents/secure-mcp.toml"

log()  { printf '\033[1;36m[install-agents]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[install-agents]\033[0m warning: %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[install-agents]\033[0m error: %s\n' "$*" >&2; exit 1; }

validate_roots_string() {
  SECURE_MCP_ROOTS="$1" python3 - <<'PY'
import os, sys

roots = [root.strip() for root in os.environ["SECURE_MCP_ROOTS"].split(os.pathsep) if root.strip()]
if not roots:
    sys.exit("SECURE_MCP_ALLOWED_ROOTS must contain at least one path")
if any(not os.path.isabs(root) for root in roots):
    sys.exit("every SECURE_MCP_ALLOWED_ROOTS entry must be absolute")
if any(not os.path.isdir(root) for root in roots):
    sys.exit("every SECURE_MCP_ALLOWED_ROOTS entry must be an existing directory")
PY
}

validate_configured_roots() {
  validate_roots_string "$CONFIGURED_ROOTS"
}

# --- JSON helpers -----------------------------------------------------------

json_entry() {
  SECURE_MCP_ENTRY="$SERVER_ENTRY" SECURE_MCP_ROOTS="$CONFIGURED_ROOTS" python3 - <<'PY'
import json, os

print(json.dumps({
    "command": "node",
    "args": [os.environ["SECURE_MCP_ENTRY"]],
    "env": {"SECURE_MCP_ALLOWED_ROOTS": os.environ["SECURE_MCP_ROOTS"]},
}))
PY
}

# json_set <file> — set mcpServers["secure-mcp"] and the ownership marker,
# refusing to overwrite a conflicting non-owned entry.
json_set() {
  local file="$1"
  mkdir -p "$(dirname "$file")"
  SECURE_MCP_ENTRY="$SERVER_ENTRY" SECURE_MCP_ROOTS="$CONFIGURED_ROOTS" \
  SECURE_MCP_INSTALL_REPO="$INSTALL_REPO" SECURE_MCP_INSTALL_VERSION="$INSTALL_VERSION" \
  SECURE_MCP_MARKER_KEY="$MARKER_KEY" python3 - "$file" <<'PY'
import json, os, sys

path = sys.argv[1]
marker_key = os.environ["SECURE_MCP_MARKER_KEY"]
entry = {
    "command": "node",
    "args": [os.environ["SECURE_MCP_ENTRY"]],
    "env": {"SECURE_MCP_ALLOWED_ROOTS": os.environ["SECURE_MCP_ROOTS"]},
}
marker = {
    "owner": os.environ["SECURE_MCP_INSTALL_REPO"],
    "version": os.environ["SECURE_MCP_INSTALL_VERSION"],
}

def owned(data):
    return data.get(marker_key) == marker

def points_to_checkout(existing):
    env = existing.get("env") if isinstance(existing, dict) else None
    roots = env.get("SECURE_MCP_ALLOWED_ROOTS") if isinstance(env, dict) else None
    return (
        existing.get("command") == "node"
        and existing.get("args") == entry["args"]
        and isinstance(roots, str)
        and roots.strip() != ""
    )

try:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
except FileNotFoundError:
    data = {}
except json.JSONDecodeError as exc:
    sys.exit(f"cannot parse {path}: {exc}")
if not isinstance(data, dict):
    sys.exit(f"cannot update {path}: top-level JSON value must be an object")
servers = data.get("mcpServers")
if servers is not None and not isinstance(servers, dict):
    sys.exit(f"cannot update {path}: mcpServers must be an object")
servers = data.get("mcpServers")
existing = servers.get("secure-mcp") if isinstance(servers, dict) else None
if existing is not None and not owned(data) and not points_to_checkout(existing):
    sys.exit(f"refusing to overwrite non-owned secure-mcp entry in {path}; move it aside and re-run")
data.setdefault("mcpServers", {})["secure-mcp"] = entry
data[marker_key] = marker
with open(path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
PY
}

# json_roots_ok <file> — true when the entry's allowlist is non-empty, absolute, and exists.
json_roots_ok() {
  local file="$1"
  [ -f "$file" ] || return 1
  python3 - "$file" <<'PY'
import json, os, sys

try:
    data = json.load(open(sys.argv[1], encoding="utf-8"))
except (FileNotFoundError, json.JSONDecodeError):
    sys.exit(1)
entry = (data.get("mcpServers") or {}).get("secure-mcp")
env = entry.get("env") if isinstance(entry, dict) else None
raw = env.get("SECURE_MCP_ALLOWED_ROOTS") if isinstance(env, dict) else None
if not isinstance(raw, str) or not raw.strip():
    sys.exit(1)
roots = [r.strip() for r in raw.split(os.pathsep) if r.strip()]
if not roots:
    sys.exit(1)
if any(not os.path.isabs(r) for r in roots):
    sys.exit(1)
if any(not os.path.isdir(r) for r in roots):
    sys.exit(1)
PY
}

# json_remove <file> — remove mcpServers["secure-mcp"] and the marker, but only
# when the entry is owned by secure-mcp (or matches the entry this installer
# generated); never remove an unrelated entry.
json_remove() {
  local file="$1"
  [ -f "$file" ] || return 0
  SECURE_MCP_ENTRY="$SERVER_ENTRY" SECURE_MCP_ROOTS="$CONFIGURED_ROOTS" \
  SECURE_MCP_INSTALL_REPO="$INSTALL_REPO" SECURE_MCP_MARKER_KEY="$MARKER_KEY" \
  python3 - "$file" <<'PY'
import json, os, sys

path = sys.argv[1]
marker_key = os.environ["SECURE_MCP_MARKER_KEY"]
entry = {
    "command": "node",
    "args": [os.environ["SECURE_MCP_ENTRY"]],
    "env": {"SECURE_MCP_ALLOWED_ROOTS": os.environ["SECURE_MCP_ROOTS"]},
}
expected_owner = os.environ["SECURE_MCP_INSTALL_REPO"]

def points_to_checkout(existing):
    env = existing.get("env") if isinstance(existing, dict) else None
    roots = env.get("SECURE_MCP_ALLOWED_ROOTS") if isinstance(env, dict) else None
    return (
        existing.get("command") == "node"
        and existing.get("args") == entry["args"]
        and isinstance(roots, str)
        and roots.strip() != ""
    )

try:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
except json.JSONDecodeError as exc:
    sys.exit(f"cannot parse {path}: {exc}")
if not isinstance(data, dict):
    sys.exit(f"cannot update {path}: top-level JSON value must be an object")
servers = data.get("mcpServers")
existing = servers.get("secure-mcp") if isinstance(servers, dict) else None
marker = data.get(marker_key)
owned = isinstance(marker, dict) and marker.get("owner") == expected_owner
if existing is not None and not owned and not points_to_checkout(existing):
    sys.exit(f"refusing to remove non-owned secure-mcp entry in {path}")
if isinstance(servers, dict):
    servers.pop("secure-mcp", None)
    if not servers:
        data.pop("mcpServers", None)
if owned:
    data.pop(marker_key, None)
with open(path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2)
    f.write("\n")
PY
}

# json_read_roots <file> — print the entry's allowlist, but only when the
# entry is owned by this installer (marker) or points at this checkout
# (installer-equivalent). Never read a conflicting non-owned entry.
json_read_roots() {
  local file="$1"
  [ -f "$file" ] || return 1
  SECURE_MCP_ENTRY="$SERVER_ENTRY" SECURE_MCP_INSTALL_REPO="$INSTALL_REPO" \
  SECURE_MCP_INSTALL_VERSION="$INSTALL_VERSION" SECURE_MCP_MARKER_KEY="$MARKER_KEY" \
  python3 - "$file" <<'PY'
import json, os, sys

path = sys.argv[1]
marker_key = os.environ["SECURE_MCP_MARKER_KEY"]

def owned(data):
    return data.get(marker_key) == {
        "owner": os.environ["SECURE_MCP_INSTALL_REPO"],
        "version": os.environ["SECURE_MCP_INSTALL_VERSION"],
    }

def points_to_checkout(existing):
    env = existing.get("env") if isinstance(existing, dict) else None
    roots = env.get("SECURE_MCP_ALLOWED_ROOTS") if isinstance(env, dict) else None
    return (
        existing.get("command") == "node"
        and existing.get("args") == [os.environ["SECURE_MCP_ENTRY"]]
        and isinstance(roots, str)
        and roots.strip() != ""
    )

try:
    data = json.load(open(path, encoding="utf-8"))
except (FileNotFoundError, json.JSONDecodeError):
    sys.exit(1)
if not isinstance(data, dict):
    sys.exit(1)
entry = (data.get("mcpServers") or {}).get("secure-mcp")
if not isinstance(entry, dict) or not (owned(data) or points_to_checkout(entry)):
    sys.exit(1)
env = entry.get("env")
raw = env.get("SECURE_MCP_ALLOWED_ROOTS") if isinstance(env, dict) else None
if isinstance(raw, str) and raw.strip():
    print(raw)
    sys.exit(0)
sys.exit(1)
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
env = entry.get("env") if isinstance(entry, dict) else None
roots = env.get("SECURE_MCP_ALLOWED_ROOTS") if isinstance(env, dict) else None
sys.exit(0 if isinstance(roots, str) and roots.strip() else 1)
PY
}

# json_set_preflight <file> — read-only mirror of the json_set refusal checks,
# so add-root can fail before mutating any client.
json_set_preflight() {
  local file="$1"
  [ -f "$file" ] || return 0
  SECURE_MCP_ENTRY="$SERVER_ENTRY" SECURE_MCP_INSTALL_REPO="$INSTALL_REPO" \
  SECURE_MCP_INSTALL_VERSION="$INSTALL_VERSION" SECURE_MCP_MARKER_KEY="$MARKER_KEY" \
  python3 - "$file" <<'PY'
import json, os, sys

path = sys.argv[1]
marker_key = os.environ["SECURE_MCP_MARKER_KEY"]
marker = {
    "owner": os.environ["SECURE_MCP_INSTALL_REPO"],
    "version": os.environ["SECURE_MCP_INSTALL_VERSION"],
}

def owned(data):
    return data.get(marker_key) == marker

def points_to_checkout(existing):
    env = existing.get("env") if isinstance(existing, dict) else None
    roots = env.get("SECURE_MCP_ALLOWED_ROOTS") if isinstance(env, dict) else None
    return (
        existing.get("command") == "node"
        and existing.get("args") == [os.environ["SECURE_MCP_ENTRY"]]
        and isinstance(roots, str)
        and roots.strip() != ""
    )

try:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
except json.JSONDecodeError as exc:
    sys.exit(f"cannot parse {path}: {exc}")
if not isinstance(data, dict):
    sys.exit(f"cannot update {path}: top-level JSON value must be an object")
servers = data.get("mcpServers")
if servers is not None and not isinstance(servers, dict):
    sys.exit(f"cannot update {path}: mcpServers must be an object")
existing = servers.get("secure-mcp") if isinstance(servers, dict) else None
if existing is not None and not owned(data) and not points_to_checkout(existing):
    sys.exit(f"refusing to overwrite non-owned secure-mcp entry in {path}; move it aside and re-run")
PY
}

# json_remove_preflight <file> — read-only mirror of the json_remove refusal
# check, for the legacy Claude cleanup the install path performs last.
json_remove_preflight() {
  local file="$1"
  [ -f "$file" ] || return 0
  SECURE_MCP_ENTRY="$SERVER_ENTRY" SECURE_MCP_INSTALL_REPO="$INSTALL_REPO" \
  SECURE_MCP_MARKER_KEY="$MARKER_KEY" python3 - "$file" <<'PY'
import json, os, sys

path = sys.argv[1]
marker_key = os.environ["SECURE_MCP_MARKER_KEY"]
expected_owner = os.environ["SECURE_MCP_INSTALL_REPO"]

def points_to_checkout(existing):
    env = existing.get("env") if isinstance(existing, dict) else None
    roots = env.get("SECURE_MCP_ALLOWED_ROOTS") if isinstance(env, dict) else None
    return (
        existing.get("command") == "node"
        and existing.get("args") == [os.environ["SECURE_MCP_ENTRY"]]
        and isinstance(roots, str)
        and roots.strip() != ""
    )

try:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
except json.JSONDecodeError as exc:
    sys.exit(f"cannot parse {path}: {exc}")
if not isinstance(data, dict):
    sys.exit(f"cannot update {path}: top-level JSON value must be an object")
servers = data.get("mcpServers")
existing = servers.get("secure-mcp") if isinstance(servers, dict) else None
marker = data.get(marker_key)
owned = isinstance(marker, dict) and marker.get("owner") == expected_owner
if existing is not None and not owned and not points_to_checkout(existing):
    sys.exit(f"refusing to remove non-owned secure-mcp entry in {path}")
PY
}

# --- Codex TOML helpers -----------------------------------------------------

codex_section_present() {
  # Canonical sub-table header or dotted-key definition ("mcp_servers.secure-mcp.env = {…}").
  grep -qE '^\[mcp_servers\.secure-mcp(\]|\.)|^mcp_servers\.secure-mcp(\.| ?=)' "$CODEX_CONFIG" 2>/dev/null
}

codex_has_marker() {
  grep -qE "^# secure-mcp install owner: $INSTALL_REPO" "$CODEX_CONFIG" 2>/dev/null
}

codex_read_roots() {
  [ -f "$CODEX_CONFIG" ] || return 1
  if ! codex_has_marker && ! codex_entry_points_to_checkout; then
    return 1
  fi
  python3 - "$CODEX_CONFIG" <<'PY'
import json, re, sys

text = open(sys.argv[1], encoding="utf-8").read()

# Read only the installer-written [mcp_servers.secure-mcp.env] sub-table; a
# SECURE_MCP_ALLOWED_ROOTS assignment in any other table is not this install's
# allowlist. TOML is never executed, only this sub-table is text-matched.
def section(name):
    match = re.search(r"^\s*\[\s*" + re.escape(name) + r"\s*\](.*?)(?=^\s*\[|\Z)", text, re.M | re.S)
    return match.group(1) if match else None

env = section("mcp_servers.secure-mcp.env")
if env is None:
    sys.exit(1)
match = re.search(r'^\s*SECURE_MCP_ALLOWED_ROOTS\s*=\s*("(?:\\.|[^"\\])*")', env, re.M)
if not match:
    sys.exit(1)
roots = json.loads(match.group(1))
if not roots.strip():
    sys.exit(1)
print(roots)
PY
}

codex_has_authorized_entry() {
  [ -f "$CODEX_CONFIG" ] || return 1
  awk '
    /^\[/ { in_block = 0 }
    /^\[mcp_servers\.secure-mcp(\]|\.)/ { in_block = 1; next }
    in_block && /SECURE_MCP_ALLOWED_ROOTS = ".+"/ { found = 1 }
    END { exit(found ? 0 : 1) }
  ' "$CODEX_CONFIG"
}

codex_entry_matches() {
  [ -f "$CODEX_CONFIG" ] || return 1
  SECURE_MCP_ENTRY="$SERVER_ENTRY" SECURE_MCP_ROOTS="$CONFIGURED_ROOTS" python3 - "$CODEX_CONFIG" <<'PY'
import json, os, re, sys

text = open(sys.argv[1], encoding="utf-8").read()

def section(name):
    match = re.search(r"^\s*\[\s*" + re.escape(name) + r"\s*\](.*?)(?=^\s*\[|\Z)", text, re.M | re.S)
    return match.group(1) if match else None

server = section("mcp_servers.secure-mcp")
env = section("mcp_servers.secure-mcp.env")
if server is None or env is None:
    sys.exit(1)
entry = json.dumps(os.environ["SECURE_MCP_ENTRY"])
roots = json.dumps(os.environ["SECURE_MCP_ROOTS"])
ok = (
    re.search(r'^\s*command\s*=\s*"node"', server, re.M) is not None
    and re.search(r"^\s*args\s*=\s*\[" + re.escape(entry) + r"\]", server, re.M) is not None
    and re.search(r"^\s*SECURE_MCP_ALLOWED_ROOTS\s*=\s*" + re.escape(roots), env, re.M) is not None
)
sys.exit(0 if ok else 1)
PY
}

codex_entry_points_to_checkout() {
  [ -f "$CODEX_CONFIG" ] || return 1
  SECURE_MCP_ENTRY="$SERVER_ENTRY" python3 - "$CODEX_CONFIG" <<'PY'
import json, os, re, sys

text = open(sys.argv[1], encoding="utf-8").read()

def section(name):
    match = re.search(r"^\s*\[\s*" + re.escape(name) + r"\s*\](.*?)(?=^\s*\[|\Z)", text, re.M | re.S)
    return match.group(1) if match else None

server = section("mcp_servers.secure-mcp")
env = section("mcp_servers.secure-mcp.env")
if server is None or env is None:
    sys.exit(1)
entry = json.dumps(os.environ["SECURE_MCP_ENTRY"])
ok = (
    re.search(r'^\s*command\s*=\s*"node"', server, re.M) is not None
    and re.search(r"^\s*args\s*=\s*\[" + re.escape(entry) + r"\]", server, re.M) is not None
    and re.search(r'^\s*SECURE_MCP_ALLOWED_ROOTS\s*=\s*".+"', env, re.M) is not None
)
sys.exit(0 if ok else 1)
PY
}

codex_section_strip() {
  local tmp mode
  mode="$(stat -c %a "$CODEX_CONFIG" 2>/dev/null || stat -f %Lp "$CODEX_CONFIG" 2>/dev/null || printf '600')"
  tmp="$(mktemp)"
  # Drop from the section header (and its sub-tables) through the line before
  # the next top-level section, plus any dotted-key definition of the same
  # table and the installer marker comment; preserve everything else and the
  # original file mode.
  awk '
    /^# secure-mcp install owner:/ { next }
    /^\[mcp_servers\.secure-mcp(\]|\.)/ { skip = 1; next }
    /^mcp_servers\.secure-mcp(\.| ?=)/ { next }
    /^\[/ { skip = 0 }
    !skip
  ' "$CODEX_CONFIG" > "$tmp"
  chmod "$mode" "$tmp"
  mv "$tmp" "$CODEX_CONFIG"
}

codex_section_append() {
  mkdir -p "$(dirname "$CODEX_CONFIG")"
  if codex_section_present; then
    if ! codex_has_marker && ! codex_entry_points_to_checkout; then
      die "refusing to overwrite non-owned [mcp_servers.secure-mcp] in $CODEX_CONFIG; move it aside and re-run"
    fi
    codex_section_strip
    log "codex: updating [mcp_servers.secure-mcp] in $CODEX_CONFIG"
  fi
  SECURE_MCP_ENTRY="$SERVER_ENTRY" SECURE_MCP_ROOTS="$CONFIGURED_ROOTS" \
  SECURE_MCP_INSTALL_REPO="$INSTALL_REPO" SECURE_MCP_INSTALL_VERSION="$INSTALL_VERSION" \
  python3 - "$CODEX_CONFIG" <<'PY'
import json, os, sys

path = sys.argv[1]
try:
    with open(path, encoding="utf-8") as f:
        content = f.read()
except FileNotFoundError:
    content = ""
with open(path, "a", encoding="utf-8") as f:
    # Avoid stacking blank lines across install/uninstall cycles.
    if content and not content.endswith("\n"):
        f.write("\n")
    elif content and content.endswith("\n\n"):
        f.truncate(len(content.rstrip("\n")) + 1)
    f.write(f"# secure-mcp install owner: {os.environ['SECURE_MCP_INSTALL_REPO']} (v{os.environ['SECURE_MCP_INSTALL_VERSION']})\n")
    f.write("[mcp_servers.secure-mcp]\n")
    f.write('command = "node"\n')
    f.write(f'args = [{json.dumps(os.environ["SECURE_MCP_ENTRY"])}]\n')
    f.write("\n[mcp_servers.secure-mcp.env]\n")
    f.write(f'SECURE_MCP_ALLOWED_ROOTS = {json.dumps(os.environ["SECURE_MCP_ROOTS"])}\n')
PY
  log "codex: configured [mcp_servers.secure-mcp] in $CODEX_CONFIG"
}

codex_section_remove() {
  [ -f "$CODEX_CONFIG" ] || return 0
  if ! codex_section_present; then
    log "codex: no secure-mcp section in $CODEX_CONFIG"
    return 0
  fi
  if ! codex_has_marker && ! codex_entry_points_to_checkout; then
    warn "codex: refusing to remove non-owned [mcp_servers.secure-mcp] in $CODEX_CONFIG"
    return 0
  fi
  codex_section_strip
  log "codex: removed [mcp_servers.secure-mcp] from $CODEX_CONFIG"
}

codex_agent_install() {
  mkdir -p "$(dirname "$CODEX_AGENT_DST")"
  if [ -f "$CODEX_AGENT_DST" ] && ! cmp -s "$CODEX_AGENT_SRC" "$CODEX_AGENT_DST"; then
    die "refusing to overwrite non-owned Codex agent manifest $CODEX_AGENT_DST; move it aside and re-run"
  fi
  cp "$CODEX_AGENT_SRC" "$CODEX_AGENT_DST"
  log "codex: installed agent manifest $CODEX_AGENT_DST"
}

codex_agent_remove() {
  if [ -f "$CODEX_AGENT_DST" ]; then
    if cmp -s "$CODEX_AGENT_SRC" "$CODEX_AGENT_DST"; then
      rm -f "$CODEX_AGENT_DST"
      log "codex: removed $CODEX_AGENT_DST"
    else
      warn "codex: refusing to remove non-owned agent manifest $CODEX_AGENT_DST"
    fi
  fi
}

# --- Legacy Claude Code cleanup ----------------------------------------------

# Older versions of this installer also wired Claude Code. Clean up those
# artifacts when present so upgrading leaves no stale wiring behind.
LEGACY_CLAUDE_LINK="$INSTALL_HOME/.claude/skills/secure-mcp"
LEGACY_CLAUDE_CONFIG="$INSTALL_HOME/.claude/settings.json"

cleanup_legacy_claude() {
  if [ -L "$LEGACY_CLAUDE_LINK" ] && [ "$(readlink "$LEGACY_CLAUDE_LINK")" = "$SKILL_SRC" ]; then
    rm "$LEGACY_CLAUDE_LINK"
    log "claude: removed legacy skill link $LEGACY_CLAUDE_LINK"
  elif [ -e "$LEGACY_CLAUDE_LINK" ]; then
    warn "legacy Claude skill path $LEGACY_CLAUDE_LINK exists but is not a link to $SKILL_SRC; leaving it alone"
  fi
  if json_has_entry "$LEGACY_CLAUDE_CONFIG"; then
    json_remove "$LEGACY_CLAUDE_CONFIG"
    log "claude: removed legacy secure-mcp entry from $LEGACY_CLAUDE_CONFIG"
  fi
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
    die "refusing to replace non-owned symlink at $target (points to $cur); move it aside and re-run"
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
  out="$(SECURE_MCP_ALLOWED_ROOTS="$ROOT" node "$SERVER_ENTRY" </dev/null 2>&1)" || {
    warn "server probe failed with exit $?"
    printf '%s\n' "$out" | sed 's/^/    /' >&2
    return 1
  }
  printf '%s\n' "$out" | grep -q "running on stdio" || { warn "server probe: did not reach stdio"; return 1; }
  log "server: $SERVER_ENTRY starts with an explicit filesystem allowlist"
}

# --- Modes ------------------------------------------------------------------

# read_installed_roots — print the union of every owned client's allowlist,
# in first-seen order with exact duplicates skipped. add-root merges this
# union with the requested roots, so a root installed in only one client is
# preserved instead of being dropped for the first client's allowlist.
read_installed_roots() {
  local cfg merged="" one found=0
  for cfg in "${JSON_CONFIGS[@]}"; do
    if one="$(json_read_roots "$cfg")"; then
      merged="$(merge_roots_string "$merged" "$one")"
      found=1
    fi
  done
  if one="$(codex_read_roots)"; then
    merged="$(merge_roots_string "$merged" "$one")"
    found=1
  fi
  [ "$found" -eq 1 ] || return 1
  printf '%s\n' "$merged"
}

merge_roots_string() {
  EXISTING_ROOTS="$1" EXTRA_ROOTS="$2" python3 - <<'PY'
import os

seen: list[str] = []
for raw in (os.environ.get("EXISTING_ROOTS", ""), os.environ.get("EXTRA_ROOTS", "")):
    for part in raw.split(os.pathsep):
        root = part.strip()
        if root and root not in seen:
            seen.append(root)
print(os.pathsep.join(seen))
PY
}

# preflight_install_targets — before add-root mutates anything, verify every
# target the install rewrite would write, using the same ownership and
# points-to-this-checkout predicates as the writers. A refused add-root must
# leave every client's allowlist unchanged.
preflight_install_targets() {
  local target cfg
  for target in "${SKILL_LINKS[@]}"; do
    if [ -L "$target" ] && [ "$(readlink "$target")" = "$SKILL_SRC" ]; then
      continue
    fi
    if [ -e "$target" ] || [ -L "$target" ]; then
      die "refusing to replace non-owned path at $target; move it aside and re-run"
    fi
  done
  for cfg in "${JSON_CONFIGS[@]}"; do
    json_set_preflight "$cfg" || die "add-root aborted: it would refuse to update $cfg; move it aside and re-run"
  done
  if codex_section_present && ! codex_has_marker && ! codex_entry_points_to_checkout; then
    die "refusing to overwrite non-owned [mcp_servers.secure-mcp] in $CODEX_CONFIG; move it aside and re-run"
  fi
  if [ -f "$CODEX_AGENT_DST" ] && ! cmp -s "$CODEX_AGENT_SRC" "$CODEX_AGENT_DST"; then
    die "refusing to overwrite non-owned Codex agent manifest $CODEX_AGENT_DST; move it aside and re-run"
  fi
  if json_has_entry "$LEGACY_CLAUDE_CONFIG"; then
    json_remove_preflight "$LEGACY_CLAUDE_CONFIG" ||
      die "add-root aborted: it would refuse to remove the legacy Claude entry in $LEGACY_CLAUDE_CONFIG; move it aside and re-run"
  fi
}

cmd_add_root() {
  [ "$#" -ge 1 ] || die "usage: $0 add-root /absolute/path [...]"
  local existing extra path
  existing="$(read_installed_roots)" || die "no existing install found; run install first"
  for path in "$@"; do
    validate_roots_string "$path" || die "invalid root: $path"
  done
  preflight_install_targets
  extra="$(python3 - "$@" <<'PY'
import os, sys
print(os.pathsep.join(sys.argv[1:]))
PY
)"
  CONFIGURED_ROOTS="$(merge_roots_string "$existing" "$extra")"
  log "allowlist is now: $CONFIGURED_ROOTS"
  cmd_install
}

cmd_install() {
  [ -n "$CONFIGURED_ROOTS" ] || die "set SECURE_MCP_ALLOWED_ROOTS to the repositories this server may inspect"
  validate_configured_roots || die "invalid SECURE_MCP_ALLOWED_ROOTS"
  [ -f "$SERVER_ENTRY" ] || die "build the server first (pnpm build) — $SERVER_ENTRY missing"
  log "installing secure-mcp v$INSTALL_VERSION for coding agents (skill source: $SKILL_SRC)"
  for target in "${SKILL_LINKS[@]}"; do link_skill "$target"; done
  for cfg in "${JSON_CONFIGS[@]}"; do json_set "$cfg"; log "json: configured secure-mcp in $cfg"; done
  codex_section_append
  codex_agent_install
  cleanup_legacy_claude
  log "done. Restart your agent sessions (pi, Cursor, Codex) to pick up changes."
}

cmd_uninstall() {
  log "uninstalling secure-mcp agent wiring"
  for target in "${SKILL_LINKS[@]}"; do unlink_skill "$target"; done
  for cfg in "${JSON_CONFIGS[@]}"; do json_remove "$cfg"; log "json: removed secure-mcp from $cfg"; done
  codex_section_remove
  codex_agent_remove
  cleanup_legacy_claude
  log "done. The repo skill and server are untouched."
}

cmd_check() {
  local failures=0
  if [ -L "$LEGACY_CLAUDE_LINK" ] && [ "$(readlink "$LEGACY_CLAUDE_LINK")" = "$SKILL_SRC" ]; then
    warn "legacy Claude Code skill link still present at $LEGACY_CLAUDE_LINK (re-run install or uninstall to clean up)"
  fi
  if json_has_entry "$LEGACY_CLAUDE_CONFIG"; then
    warn "legacy Claude Code config entry still present in $LEGACY_CLAUDE_CONFIG (re-run install or uninstall to clean up)"
  fi
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
      if json_roots_ok "$cfg"; then
        log "  ok: $cfg has secure-mcp entry with an allowed-root scope"
      else
        warn "$cfg allowlist is empty, relative, or points at a missing directory"
        failures=$((failures + 1))
      fi
    else
      warn "missing secure-mcp entry in $cfg"
      failures=$((failures + 1))
    fi
  done

  if codex_section_present && codex_has_authorized_entry; then
    log "  ok: $CODEX_CONFIG has secure-mcp section with an allowed-root scope"
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
  add-root)  shift; cmd_add_root "$@" ;;
  *) die "usage: $0 [install|uninstall|check|add-root]" ;;
esac
