# =============================================================================
#  windows-install.ps1 — install Cipherjet on Windows (no admin needed).
#
#  Copies the tools to %LOCALAPPDATA%\Cipherjet\bin and adds that to your PATH.
#  Right-click this file -> "Run with PowerShell", or run:  ./windows-install.ps1
# =============================================================================
$ErrorActionPreference = "Stop"
$dst = Join-Path $env:LOCALAPPDATA "Cipherjet\bin"
New-Item -ItemType Directory -Force -Path $dst | Out-Null

$src = Join-Path $PSScriptRoot "bin"
if (-not (Test-Path $src)) { $src = $PSScriptRoot }   # exes alongside the script
Copy-Item (Join-Path $src "cipherjet*.exe") $dst -Force

# Add to the user's PATH if not already present.
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$dst*") {
    [Environment]::SetEnvironmentVariable("Path", "$userPath;$dst", "User")
    Write-Host "Added $dst to your PATH."
}
Write-Host "Cipherjet installed to $dst."
Write-Host "Open a NEW terminal, then run:  cipherjet-send --help"
