<#
install-agents.ps1 - install, verify, or remove the secure-mcp skill and MCP
server wiring for the user's coding agents (pi, Cursor, OpenAI Codex).

secure-mcp 2.x speaks MCP revision 2026-07-28 only. Clients must support the
modern `server/discover` opening; legacy 2025-era handshakes are rejected.

Usage:
  $env:SECURE_MCP_ALLOWED_ROOTS = "C:\path\to\repos"
  .\scripts\install-agents.ps1 install
  .\scripts\install-agents.ps1 check
  .\scripts\install-agents.ps1 uninstall

Idempotent and ownership-safe: the installer modifies only the secure-mcp keys
it owns and refuses to overwrite conflicting non-owned entries or skills. Test
harnesses may redirect all user-level writes with SECURE_MCP_INSTALL_HOME.
#>
[CmdletBinding()]
param(
  [ValidateSet("install", "check", "uninstall")]
  [string]$Action = "install"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$Root = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$SkillSrc = Join-Path $Root ".agents\skills\secure-mcp"
$ServerEntry = Join-Path $Root "dist\index.js"
$InstallHome = if ($env:SECURE_MCP_INSTALL_HOME) { $env:SECURE_MCP_INSTALL_HOME } else { $HOME }
$Roots = if ($env:SECURE_MCP_ALLOWED_ROOTS) { $env:SECURE_MCP_ALLOWED_ROOTS } else { "" }
$InstallVersion = "2.0.0"
$InstallRepo = "https://github.com/brbndon/secure-mcp"
$MarkerKey = "secureMcpInstall"

$SkillLinks = @(
  (Join-Path $InstallHome ".agents\skills\secure-mcp"),
  (Join-Path $InstallHome ".cursor\skills\secure-mcp")
)
$JsonConfigs = @(
  (Join-Path $InstallHome ".pi\agent\mcp.json"),
  (Join-Path $InstallHome ".cursor\mcp.json")
)
$CodexConfig = Join-Path $InstallHome ".codex\config.toml"
$CodexAgentSrc = Join-Path $Root "agents\codex.toml"
$CodexAgentDst = Join-Path $InstallHome ".codex\agents\secure-mcp.toml"
$LegacyClaudeLink = Join-Path $InstallHome ".claude\skills\secure-mcp"
$LegacyClaudeConfig = Join-Path $InstallHome ".claude\settings.json"

function Write-Log {
  Write-Host "[install-agents] $($args -join ' ')" -ForegroundColor Cyan
}

function Write-Warn {
  Write-Host "[install-agents] warning: $($args -join ' ')" -ForegroundColor Yellow
}

function Assert-ConfiguredRoots {
  if ([string]::IsNullOrWhiteSpace($Roots)) {
    throw "set SECURE_MCP_ALLOWED_ROOTS to the repositories this server may inspect"
  }
  $parts = @(
    $Roots -split [IO.Path]::PathSeparator |
      ForEach-Object { $_.Trim() } |
      Where-Object { $_ }
  )
  if ($parts.Count -eq 0) {
    throw "SECURE_MCP_ALLOWED_ROOTS must contain at least one path"
  }
  foreach ($part in $parts) {
    if (-not [IO.Path]::IsPathRooted($part)) {
      throw "every SECURE_MCP_ALLOWED_ROOTS entry must be absolute"
    }
    if (-not (Test-Path -LiteralPath $part -PathType Container)) {
      throw "every SECURE_MCP_ALLOWED_ROOTS entry must be an existing directory"
    }
  }
}

function ConvertTo-Hashtable {
  param([Parameter(Mandatory)][object]$InputObject)
  if ($null -eq $InputObject) { return $null }
  if ($InputObject -is [System.Collections.IDictionary]) {
    $table = @{}
    foreach ($key in $InputObject.Keys) {
      $table[$key] = ConvertTo-Hashtable $InputObject[$key]
    }
    return $table
  }
  if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
    $items = @()
    foreach ($item in $InputObject) { $items += ConvertTo-Hashtable $item }
    return $items
  }
  return $InputObject
}

function Read-JsonFile {
  param([Parameter(Mandatory)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { return @{} }
  try {
    $raw = Get-Content -LiteralPath $Path -Raw -Encoding UTF8
    $parsed = ConvertFrom-Json $raw
    if ($null -eq $parsed) { return @{} }
    return ConvertTo-Hashtable $parsed
  } catch {
    throw "cannot parse $Path : $($_.Exception.Message)"
  }
}

function Write-JsonFile {
  param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][hashtable]$Data)
  $directory = Split-Path -Parent $Path
  if (-not (Test-Path -LiteralPath $directory)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
  $json = $Data | ConvertTo-Json -Depth 100
  Set-Content -LiteralPath $Path -Value $json -Encoding UTF8
}

function Get-ExpectedEntry {
  return @{
    command = "node"
    args = @($ServerEntry)
    env = @{ SECURE_MCP_ALLOWED_ROOTS = $Roots }
  }
}

function Test-ValueEquals {
  param([object]$Expected, [object]$Actual)
  if ($null -eq $Expected -and $null -eq $Actual) { return $true }
  if ($null -eq $Expected -or $null -eq $Actual) { return $false }
  if ($Expected -is [System.Collections.IDictionary] -and $Actual -is [System.Collections.IDictionary]) {
    if ($Expected.Count -ne $Actual.Count) { return $false }
    foreach ($key in $Expected.Keys) {
      if (-not $Actual.ContainsKey($key)) { return $false }
      if (-not (Test-ValueEquals $Expected[$key] $Actual[$key])) { return $false }
    }
    return $true
  }
  if ($Expected -is [System.Collections.IEnumerable] -and $Expected -isnot [string] -and
      $Actual -is [System.Collections.IEnumerable] -and $Actual -isnot [string]) {
    $expectedArray = @($Expected)
    $actualArray = @($Actual)
    if ($expectedArray.Count -ne $actualArray.Count) { return $false }
    for ($i = 0; $i -lt $expectedArray.Count; $i++) {
      if (-not (Test-ValueEquals $expectedArray[$i] $actualArray[$i])) { return $false }
    }
    return $true
  }
  return [string]$Expected -eq [string]$Actual
}

function Test-EntryOwned {
  param([Parameter(Mandatory)][hashtable]$Data)
  if (-not $Data.ContainsKey($MarkerKey)) { return $false }
  $marker = $Data[$MarkerKey]
  return $marker -is [hashtable] -and $marker["owner"] -eq $InstallRepo
}

function Test-EntryPointsToCheckout {
  param([Parameter(Mandatory)][hashtable]$Entry)
  if (-not $Entry.ContainsKey("command") -or $Entry["command"] -ne "node") { return $false }
  $argsValue = if ($Entry.ContainsKey("args")) { $Entry["args"] } else { $null }
  if ($null -eq $argsValue -or @($argsValue).Count -ne 1 -or @($argsValue)[0] -ne $ServerEntry) { return $false }
  $envMap = if ($Entry.ContainsKey("env")) { $Entry["env"] } else { $null }
  $raw = if ($envMap -is [hashtable] -and $envMap.ContainsKey("SECURE_MCP_ALLOWED_ROOTS")) { [string]$envMap["SECURE_MCP_ALLOWED_ROOTS"] } else { "" }
  return -not [string]::IsNullOrWhiteSpace($raw)
}

function Set-SecureMcpJson {
  param([Parameter(Mandatory)][string]$Path)
  $data = Read-JsonFile $Path
  if (-not $data.ContainsKey("mcpServers")) { $data["mcpServers"] = @{} }
  $servers = $data["mcpServers"]
  if ($servers -isnot [hashtable]) { throw "cannot update $Path : mcpServers must be an object" }
  $entry = Get-ExpectedEntry
  if ($servers.ContainsKey("secure-mcp")) {
    $existing = $servers["secure-mcp"]
    $owned = Test-EntryOwned $data
    $pointsToCheckout = ($existing -is [hashtable]) -and (Test-EntryPointsToCheckout $existing)
    if (-not $owned -and -not $pointsToCheckout) {
      throw "refusing to overwrite non-owned secure-mcp entry in $Path; move it aside and re-run"
    }
  }
  $servers["secure-mcp"] = $entry
  $data[$MarkerKey] = @{ owner = $InstallRepo; version = $InstallVersion }
  Write-JsonFile $Path $data
  Write-Log "json: configured secure-mcp in $Path"
}

function Remove-SecureMcpJson {
  param([Parameter(Mandatory)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { return }
  $data = Read-JsonFile $Path
  $servers = if ($data.ContainsKey("mcpServers")) { $data["mcpServers"] } else { @{} }
  $existing = if ($servers -is [hashtable] -and $servers.ContainsKey("secure-mcp")) { $servers["secure-mcp"] } else { $null }
  if ($null -ne $existing) {
    $owned = Test-EntryOwned $data
    $pointsToCheckout = ($existing -is [hashtable]) -and (Test-EntryPointsToCheckout $existing)
    if (-not $owned -and -not $pointsToCheckout) {
      throw "refusing to remove non-owned secure-mcp entry in $Path"
    }
  }
  if ($servers -is [hashtable]) {
    $servers.Remove("secure-mcp")
    if ($servers.Count -eq 0) { $data.Remove("mcpServers") }
  }
  if (Test-EntryOwned $data) { $data.Remove($MarkerKey) }
  Write-JsonFile $Path $data
  Write-Log "json: removed secure-mcp from $Path"
}

function Test-JsonHasEntry {
  param([Parameter(Mandatory)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { return $false }
  $data = Read-JsonFile $Path
  $servers = if ($data.ContainsKey("mcpServers")) { $data["mcpServers"] } else { @{} }
  $entry = if ($servers -is [hashtable] -and $servers.ContainsKey("secure-mcp")) { $servers["secure-mcp"] } else { $null }
  if ($null -eq $entry) { return $false }
  $envMap = if ($entry -is [hashtable] -and $entry.ContainsKey("env")) { $entry["env"] } else { $null }
  $raw = if ($envMap -is [hashtable] -and $envMap.ContainsKey("SECURE_MCP_ALLOWED_ROOTS")) { [string]$envMap["SECURE_MCP_ALLOWED_ROOTS"] } else { "" }
  return -not [string]::IsNullOrWhiteSpace($raw)
}

function Test-JsonRootsOk {
  param([Parameter(Mandatory)][string]$Path)
  if (-not (Test-Path -LiteralPath $Path)) { return $false }
  $data = Read-JsonFile $Path
  $servers = if ($data.ContainsKey("mcpServers")) { $data["mcpServers"] } else { @{} }
  $entry = if ($servers -is [hashtable] -and $servers.ContainsKey("secure-mcp")) { $servers["secure-mcp"] } else { $null }
  $envMap = if ($entry -is [hashtable] -and $entry.ContainsKey("env")) { $entry["env"] } else { $null }
  $raw = if ($envMap -is [hashtable] -and $envMap.ContainsKey("SECURE_MCP_ALLOWED_ROOTS")) { [string]$envMap["SECURE_MCP_ALLOWED_ROOTS"] } else { "" }
  if ([string]::IsNullOrWhiteSpace($raw)) { return $false }
  $parts = @(
    $raw -split [IO.Path]::PathSeparator |
      ForEach-Object { $_.Trim() } |
      Where-Object { $_ }
  )
  if ($parts.Count -eq 0) { return $false }
  foreach ($part in $parts) {
    if (-not [IO.Path]::IsPathRooted($part)) { return $false }
    if (-not (Test-Path -LiteralPath $part -PathType Container)) { return $false }
  }
  return $true
}

function Get-CodexSection {
  param([Parameter(Mandatory)][string]$Text, [Parameter(Mandatory)][string]$Name)
  $pattern = "(?m)^\s*\[\s*" + [regex]::Escape($Name) + "\s*\]\s*(.*?)(?=^\s*\[|\z)"
  $match = [regex]::Match($Text, $pattern, [System.Text.RegularExpressions.RegexOptions]::Singleline)
  if (-not $match.Success) { return $null }
  return $match.Groups[1].Value
}

function Test-CodexSectionPresent {
  if (-not (Test-Path -LiteralPath $CodexConfig)) { return $false }
  $text = Get-Content -LiteralPath $CodexConfig -Raw -Encoding UTF8
  return $null -ne (Get-CodexSection $text "mcp_servers.secure-mcp")
}

function Test-CodexMarker {
  if (-not (Test-Path -LiteralPath $CodexConfig)) { return $false }
  $text = Get-Content -LiteralPath $CodexConfig -Raw -Encoding UTF8
  return $text -match [regex]::Escape("# secure-mcp install owner: $InstallRepo")
}

function Test-CodexEntryMatches {
  if (-not (Test-Path -LiteralPath $CodexConfig)) { return $false }
  $text = Get-Content -LiteralPath $CodexConfig -Raw -Encoding UTF8
  $server = Get-CodexSection $text "mcp_servers.secure-mcp"
  $envSection = Get-CodexSection $text "mcp_servers.secure-mcp.env"
  if ($null -eq $server -or $null -eq $envSection) { return $false }
  $entry = [regex]::Escape(('"' + $ServerEntry.Replace("\", "\\") + '"'))
  $roots = [regex]::Escape(('"' + $Roots.Replace("\", "\\") + '"'))
  return ($server -match "(?m)^\s*command\s*=\s*`"node`"") -and
    ($server -match "(?m)^\s*args\s*=\s*\[$entry\]") -and
    ($envSection -match "(?m)^\s*SECURE_MCP_ALLOWED_ROOTS\s*=\s*$roots")
}

function Test-CodexEntryPointsToCheckout {
  if (-not (Test-Path -LiteralPath $CodexConfig)) { return $false }
  $text = Get-Content -LiteralPath $CodexConfig -Raw -Encoding UTF8
  $server = Get-CodexSection $text "mcp_servers.secure-mcp"
  $envSection = Get-CodexSection $text "mcp_servers.secure-mcp.env"
  if ($null -eq $server -or $null -eq $envSection) { return $false }
  $entry = [regex]::Escape(('"' + $ServerEntry.Replace("\", "\\") + '"'))
  return ($server -match "(?m)^\s*command\s*=\s*`"node`"") -and
    ($server -match "(?m)^\s*args\s*=\s*\[$entry\]") -and
    ($envSection -match '(?m)^\s*SECURE_MCP_ALLOWED_ROOTS\s*=\s*".+"')
}

function Test-CodexAuthorizedEntry {
  if (-not (Test-Path -LiteralPath $CodexConfig)) { return $false }
  $text = Get-Content -LiteralPath $CodexConfig -Raw -Encoding UTF8
  $envSection = Get-CodexSection $text "mcp_servers.secure-mcp.env"
  return $null -ne $envSection -and $envSection -match '(?m)^\s*SECURE_MCP_ALLOWED_ROOTS\s*=\s*".+"'
}

function Remove-CodexSection {
  $text = Get-Content -LiteralPath $CodexConfig -Raw -Encoding UTF8
  $lines = @()
  $skip = $false
  foreach ($line in (Get-Content -LiteralPath $CodexConfig -Encoding UTF8)) {
    if ($line -match "^\s*# secure-mcp install owner:") { continue }
    if ($line -match "^\s*\[mcp_servers\.secure-mcp(\]|\.)") {
      $skip = $true
      continue
    }
    if ($line -match "^\s*mcp_servers\.secure-mcp(\.| ?=)") { continue }
    if ($line -match "^\s*\[") { $skip = $false }
    if (-not $skip) { $lines += $line }
  }
  $joined = ($lines -join "`n").TrimEnd() + "`n"
  Set-Content -LiteralPath $CodexConfig -Value $joined -Encoding UTF8 -NoNewline
}

function Add-CodexSection {
  $directory = Split-Path -Parent $CodexConfig
  if (-not (Test-Path -LiteralPath $directory)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
  if (Test-CodexSectionPresent) {
    if (-not (Test-CodexMarker) -and -not (Test-CodexEntryPointsToCheckout)) {
      throw "refusing to overwrite non-owned [mcp_servers.secure-mcp] in $CodexConfig; move it aside and re-run"
    }
    Remove-CodexSection
    Write-Log "codex: updating [mcp_servers.secure-mcp] in $CodexConfig"
  }
  $existing = if (Test-Path -LiteralPath $CodexConfig) { Get-Content -LiteralPath $CodexConfig -Raw -Encoding UTF8 } else { "" }
  if ($existing -and -not $existing.EndsWith("`n")) { $existing += "`n" }
  $section = @(
    "# secure-mcp install owner: $InstallRepo (v$InstallVersion)",
    "[mcp_servers.secure-mcp]",
    'command = "node"',
    "args = [`"$($ServerEntry.Replace('\','\\'))`"]",
    "",
    "[mcp_servers.secure-mcp.env]",
    "SECURE_MCP_ALLOWED_ROOTS = `"$($Roots.Replace('\','\\'))`"",
    ""
  ) -join "`n"
  Add-Content -LiteralPath $CodexConfig -Value $section -Encoding UTF8 -NoNewline
  Write-Log "codex: configured [mcp_servers.secure-mcp] in $CodexConfig"
}

function Remove-CodexSectionSafe {
  if (-not (Test-Path -LiteralPath $CodexConfig)) { return }
  if (-not (Test-CodexSectionPresent)) {
    Write-Log "codex: no secure-mcp section in $CodexConfig"
    return
  }
  if (-not (Test-CodexMarker) -and -not (Test-CodexEntryPointsToCheckout)) {
    Write-Warn "codex: refusing to remove non-owned [mcp_servers.secure-mcp] in $CodexConfig"
    return
  }
  Remove-CodexSection
  Write-Log "codex: removed [mcp_servers.secure-mcp] from $CodexConfig"
}

function Test-FileEquals {
  param([Parameter(Mandatory)][string]$First, [Parameter(Mandatory)][string]$Second)
  return (Get-FileHash -LiteralPath $First).Hash -eq (Get-FileHash -LiteralPath $Second).Hash
}

function Install-CodexAgent {
  $directory = Split-Path -Parent $CodexAgentDst
  if (-not (Test-Path -LiteralPath $directory)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
  if ((Test-Path -LiteralPath $CodexAgentDst) -and -not (Test-FileEquals $CodexAgentSrc $CodexAgentDst)) {
    throw "refusing to overwrite non-owned Codex agent manifest $CodexAgentDst; move it aside and re-run"
  }
  Copy-Item -LiteralPath $CodexAgentSrc -Destination $CodexAgentDst -Force
  Write-Log "codex: installed agent manifest $CodexAgentDst"
}

function Remove-CodexAgent {
  if (Test-Path -LiteralPath $CodexAgentDst) {
    if (Test-FileEquals $CodexAgentSrc $CodexAgentDst) {
      Remove-Item -LiteralPath $CodexAgentDst -Force
      Write-Log "codex: removed $CodexAgentDst"
    } else {
      Write-Warn "codex: refusing to remove non-owned agent manifest $CodexAgentDst"
    }
  }
}

function Set-SkillLink {
  param([Parameter(Mandatory)][string]$Target)
  $directory = Split-Path -Parent $Target
  if (-not (Test-Path -LiteralPath $directory)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
  if (Test-Path -LiteralPath $Target) {
    $item = Get-Item -LiteralPath $Target -Force
    if ($item.LinkType -eq "SymbolicLink" -or $item.LinkType -eq "Junction") {
      $current = [IO.Path]::GetFullPath(($item.Target | Select-Object -First 1))
      $expected = [IO.Path]::GetFullPath($SkillSrc)
      if ($current -eq $expected) {
        Write-Log "skill: $Target already linked"
        return
      }
      throw "refusing to replace non-owned link at $Target (points to $current); move it aside and re-run"
    }
    throw "refusing to replace non-symlink at $Target; move it aside and re-run"
  }
  New-Item -ItemType Junction -Path $Target -Target $SkillSrc | Out-Null
  Write-Log "skill: linked $Target -> $SkillSrc"
}

function Remove-SkillLink {
  param([Parameter(Mandatory)][string]$Target)
  if (-not (Test-Path -LiteralPath $Target)) { return }
  $item = Get-Item -LiteralPath $Target -Force
  if ($item.LinkType -eq "SymbolicLink" -or $item.LinkType -eq "Junction") {
    $current = [IO.Path]::GetFullPath(($item.Target | Select-Object -First 1))
    $expected = [IO.Path]::GetFullPath($SkillSrc)
    if ($current -eq $expected) {
      Remove-Item -LiteralPath $Target -Force
      Write-Log "skill: removed $Target"
    } else {
      Write-Warn "not removing $Target (points to $current, not $SkillSrc)"
    }
  }
}

function Test-ServerProbe {
  if (-not (Test-Path -LiteralPath $ServerEntry)) {
    throw "build the server first (pnpm build) - $ServerEntry missing"
  }
  $psi = [System.Diagnostics.ProcessStartInfo]::new()
  $psi.FileName = "node"
  $psi.ArgumentList.Add($ServerEntry)
  $psi.WorkingDirectory = $Root
  $psi.RedirectStandardInput = $true
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  $psi.UseShellExecute = $false
  $psi.Environment["SECURE_MCP_ALLOWED_ROOTS"] = $Root
  $process = [System.Diagnostics.Process]::Start($psi)
  $process.StandardInput.Close()
  $output = $process.StandardError.ReadToEnd() + $process.StandardOutput.ReadToEnd()
  if (-not $process.WaitForExit(5000)) {
    $process.Kill()
    throw "server probe timed out"
  }
  if (-not $output.Contains("running on stdio")) {
    throw "server probe did not reach stdio: $output"
  }
  Write-Log "server: $ServerEntry starts with an explicit filesystem allowlist"
}

function Cleanup-LegacyClaude {
  if (Test-Path -LiteralPath $LegacyClaudeLink) {
    $item = Get-Item -LiteralPath $LegacyClaudeLink -Force
    if ($item.LinkType -eq "SymbolicLink" -or $item.LinkType -eq "Junction") {
      $current = [IO.Path]::GetFullPath(($item.Target | Select-Object -First 1))
      if ($current -eq [IO.Path]::GetFullPath($SkillSrc)) {
        Remove-Item -LiteralPath $LegacyClaudeLink -Force
        Write-Log "claude: removed legacy skill link $LegacyClaudeLink"
      } else {
        Write-Warn "legacy Claude skill path $LegacyClaudeLink exists but is not a link to $SkillSrc; leaving it alone"
      }
    }
  }
  if (Test-Path -LiteralPath $LegacyClaudeConfig) {
    if (Test-JsonHasEntry $LegacyClaudeConfig) {
      Remove-SecureMcpJson $LegacyClaudeConfig
      Write-Log "claude: removed legacy secure-mcp entry from $LegacyClaudeConfig"
    }
  }
}

function Invoke-Install {
  Assert-ConfiguredRoots
  if (-not (Test-Path -LiteralPath $ServerEntry)) {
    throw "build the server first (pnpm build) - $ServerEntry missing"
  }
  Write-Log "installing secure-mcp v$InstallVersion for coding agents (skill source: $SkillSrc)"
  foreach ($target in $SkillLinks) { Set-SkillLink $target }
  foreach ($config in $JsonConfigs) { Set-SecureMcpJson $config }
  Add-CodexSection
  Install-CodexAgent
  Cleanup-LegacyClaude
  Write-Log "done. Restart your agent sessions (pi, Cursor, Codex) to pick up changes."
}

function Invoke-Uninstall {
  Write-Log "uninstalling secure-mcp agent wiring"
  foreach ($target in $SkillLinks) { Remove-SkillLink $target }
  foreach ($config in $JsonConfigs) { Remove-SecureMcpJson $config }
  Remove-CodexSectionSafe
  Remove-CodexAgent
  Cleanup-LegacyClaude
  Write-Log "done. The repo skill and server are untouched."
}

function Invoke-Check {
  $failures = 0
  Write-Log "checking skill links"
  foreach ($target in $SkillLinks) {
    if (Test-Path -LiteralPath $target) {
      $item = Get-Item -LiteralPath $target -Force
      if ($item.LinkType -eq "SymbolicLink" -or $item.LinkType -eq "Junction") {
        $current = [IO.Path]::GetFullPath(($item.Target | Select-Object -First 1))
        if ($current -eq [IO.Path]::GetFullPath($SkillSrc)) {
          Write-Log "  ok: $target"
        } else {
          Write-Warn "wrong link at $target"
          $failures++
        }
      } else {
        Write-Warn "not a link at $target"
        $failures++
      }
    } else {
      Write-Warn "missing link at $target"
      $failures++
    }
  }

  Write-Log "checking client configs"
  foreach ($config in $JsonConfigs) {
    if (Test-JsonHasEntry $config) {
      if (Test-JsonRootsOk $config) {
        Write-Log "  ok: $config has secure-mcp entry with an allowed-root scope"
      } else {
        Write-Warn "$config allowlist is empty, relative, or points at a missing directory"
        $failures++
      }
    } else {
      Write-Warn "missing secure-mcp entry in $config"
      $failures++
    }
  }

  if ((Test-CodexSectionPresent) -and (Test-CodexAuthorizedEntry)) {
    Write-Log "  ok: $CodexConfig has secure-mcp section with an allowed-root scope"
  } else {
    Write-Warn "missing secure-mcp section in $CodexConfig"
    $failures++
  }

  if ((Test-Path -LiteralPath $CodexAgentDst) -and (Test-FileEquals $CodexAgentSrc $CodexAgentDst)) {
    Write-Log "  ok: $CodexAgentDst matches repo manifest"
  } else {
    Write-Warn "missing or stale Codex agent manifest at $CodexAgentDst"
    $failures++
  }

  try {
    Test-ServerProbe
  } catch {
    Write-Warn $_.Exception.Message
    $failures++
  }

  if ($failures -eq 0) {
    Write-Log "all checks passed."
  } else {
    throw "$failures check(s) failed"
  }
}

switch ($Action) {
  "install" { Invoke-Install }
  "uninstall" { Invoke-Uninstall }
  "check" { Invoke-Check }
}
