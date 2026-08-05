<#
.SYNOPSIS
  Install the snmp-switch-monitoring skill for Claude Code on Windows.

.EXAMPLE
  .\install.ps1
  Installs for the current user into $HOME\.claude\skills

.EXAMPLE
  .\install.ps1 -Project
  Installs into .\.claude\skills for the current folder only

Only ever writes inside the chosen skills directory. Never elevates.
#>
[CmdletBinding()]
param(
    [switch]$Project,
    [string]$Dir,
    [switch]$NoTest
)

$ErrorActionPreference = 'Stop'
$SkillName = 'snmp-switch-monitoring'
$SourceDir = Split-Path -Parent $MyInvocation.MyCommand.Path

if ($Dir)          { $TargetRoot = $Dir }
elseif ($Project)  { $TargetRoot = Join-Path $PWD '.claude\skills' }
elseif ($env:CLAUDE_SKILLS_DIR) { $TargetRoot = $env:CLAUDE_SKILLS_DIR }
else               { $TargetRoot = Join-Path $HOME '.claude\skills' }

$Target = Join-Path $TargetRoot $SkillName

if (-not (Test-Path (Join-Path $SourceDir 'SKILL.md'))) {
    throw "Run this from the skill directory (SKILL.md not found next to install.ps1)."
}

# --- find a usable Python -------------------------------------------------

$Python = $null
foreach ($candidate in @('python', 'python3', 'py')) {
    $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
    if (-not $cmd) { continue }
    try {
        & $candidate -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 9) else 1)' 2>$null
        if ($LASTEXITCODE -eq 0) { $Python = $candidate; break }
    } catch { }
}

if (-not $Python) {
    throw "Need Python 3.9 or newer on PATH. Install it from https://python.org (tick 'Add Python to PATH' in the installer), then re-run this script."
}

Write-Host "Python:  $(& $Python --version 2>&1)"
Write-Host "Source:  $SourceDir"
Write-Host "Target:  $Target"
Write-Host ""

# --- install --------------------------------------------------------------

if (Test-Path $Target) {
    # Back up *outside* the skills directory. A backup left alongside the skill
    # still contains a SKILL.md, so an agent scanning the directory would
    # discover it as a second, duplicate skill with the same name.
    $backupRoot = Join-Path (Split-Path -Parent $TargetRoot) 'skill-backups'
    $backup = Join-Path $backupRoot "$SkillName-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    New-Item -ItemType Directory -Path $backupRoot -Force | Out-Null
    Write-Host "An existing install is present. Moving it to:"
    Write-Host "  $backup"
    Move-Item $Target $backup
}

New-Item -ItemType Directory -Path $Target -Force | Out-Null
foreach ($item in @('SKILL.md', 'README.md', 'scripts', 'references', 'tests', 'install.sh', 'install.ps1')) {
    $path = Join-Path $SourceDir $item
    if (Test-Path $path) { Copy-Item $path -Destination $Target -Recurse -Force }
}
Get-ChildItem -Path $Target -Filter '__pycache__' -Recurse -Directory -ErrorAction SilentlyContinue |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

$count = (Get-ChildItem -Path $Target -Recurse -File).Count
Write-Host "Installed $count files."

# --- verify ---------------------------------------------------------------

if (-not $NoTest) {
    Write-Host ""
    Write-Host "Running the test suite to confirm it works on this machine..."
    Push-Location $Target
    try {
        $output = & $Python tests\test_netmon.py 2>&1
        if ($LASTEXITCODE -ne 0) {
            $output | Select-Object -Last 20 | ForEach-Object { "  $_" } | Write-Host
            throw "The skill was copied but its self-test did not pass; do not rely on it until this is resolved."
        }
        $output | Select-Object -Last 3 | ForEach-Object { "  $_" } | Write-Host
    } finally {
        Pop-Location
    }
}

# --- done -----------------------------------------------------------------

Write-Host @"

Done. Claude Code will pick the skill up on its next start.

Try it with no hardware (two terminals):
  cd "$Target"
  $Python scripts\mock_switch.py --port 11161 --flap 8 --errors 12 --saturate 3
  $Python scripts\netmon.py check 127.0.0.1:11161

Or point it at a real switch:
  $Python scripts\netmon.py check <switch-ip> -c <community-string>

In Claude Code, just ask in plain English:
  "check the switch at 192.168.1.254, the community string is public"

To uninstall:  Remove-Item -Recurse "$Target"
"@
