<#
setup.ps1 - unsupported Windows bootstrap retained for historical reference.
Windows is not supported by secure-mcp; use scripts/setup.sh on Linux/macOS.
Builds the server, prompts for the filesystem allowlist when unset, then
installs the skill and MCP server wiring for the configured harness (pi,
Cursor, OpenAI Codex) and verifies the result.

Usage:
  .\scripts\setup.ps1                                  # interactive roots prompt
  $env:SECURE_MCP_ALLOWED_ROOTS = "C:\abs\path"; .\scripts\setup.ps1

Idempotent: re-run any time to refresh skill links and client configs.
Uninstall remains:  .\scripts\install-agents.ps1 uninstall
macOS / Linux:      ./scripts/setup.sh
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

function Write-Log { Write-Host "[setup] $($args -join ' ')" -ForegroundColor Cyan }
function Assert-Command {
  param([Parameter(Mandatory)][string]$Name)
  if ($null -eq (Get-Command $Name -ErrorAction SilentlyContinue)) {
    throw "missing required tool: $Name"
  }
}

Assert-Command node
Assert-Command pnpm

Write-Log "installing dependencies (pnpm install --frozen-lockfile)"
Push-Location $Root
try {
  & pnpm install --frozen-lockfile
  if ($LASTEXITCODE -ne 0) { throw "pnpm install failed (exit $LASTEXITCODE)" }
  Write-Log "building the server (pnpm build)"
  & pnpm build
  if ($LASTEXITCODE -ne 0) { throw "pnpm build failed (exit $LASTEXITCODE)" }
} finally {
  Pop-Location
}

if ([string]::IsNullOrWhiteSpace($env:SECURE_MCP_ALLOWED_ROOTS)) {
  Write-Host "secure-mcp needs an explicit allowlist of existing absolute directories."
  Write-Host "Prefer the parent that contains the repositories you review"
  Write-Host "(for example C:\Users\you\Code), not your home directory and not a"
  Write-Host "single app unless that is the only tree you will audit. Separate"
  Write-Host "multiple paths with ';' on Windows. Add another root later with:"
  Write-Host "  .\scripts\install-agents.ps1 -Action add-root C:\absolute\path"
  $roots = Read-Host "[setup] allowlisted roots"
  if ([string]::IsNullOrWhiteSpace($roots)) {
    throw "an allowlist is required (SECURE_MCP_ALLOWED_ROOTS)"
  }
  $env:SECURE_MCP_ALLOWED_ROOTS = $roots.Trim()
}

Write-Log "wiring the skill and MCP server for pi, Cursor, and Codex"
& (Join-Path $Root "scripts/install-agents.ps1") -Action install
& (Join-Path $Root "scripts/install-agents.ps1") -Action check

Write-Log "done. Restart your agent sessions to pick up the new skill and MCP server."
