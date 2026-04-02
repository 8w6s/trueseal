<#
.SYNOPSIS
Secure standalone binary installer for TrueSeal.
Bypasses pip completely to prevent source code and site-packages modification.

.DESCRIPTION
Invokes standalone executable download directly from GitHub releases and registers to PATH.
Usage: irm https://trueseal.dev/install.ps1 | iex
#>

$ErrorActionPreference = "Stop"

Write-Host "[TrueSeal] Initializing secure installation for Windows..."

$InstallDir = "$env:LOCALAPPDATA\trueseal\bin"
if (!(Test-Path -Path $InstallDir)) {
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
}

$Architecture = "amd64"
if ($env:PROCESSOR_ARCHITECTURE -match "ARM") {
    $Architecture = "arm64"
}

$BinaryName = "trueseal-windows-$Architecture.exe"
# Replace URL with actual releases
$DownloadUrl = "https://github.com/your-org/trueseal/releases/latest/download/$BinaryName"
$TargetPath = "$InstallDir\trueseal.exe"

Write-Host "[TrueSeal] Downloading native binary from $DownloadUrl"
# Invoke-WebRequest -Uri $DownloadUrl -OutFile $TargetPath
# Placeholder for local testing:
Set-Content -Path $TargetPath -Value "MZ..." | Out-Null

$CurrentPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($CurrentPath -notmatch [regex]::Escape($InstallDir)) {
    Write-Host "[TrueSeal] Adding $InstallDir to User PATH..."
    [Environment]::SetEnvironmentVariable("Path", "$CurrentPath;$InstallDir", "User")
}

Write-Host "[TrueSeal] Installation complete."
Write-Host "Please restart your terminal to apply PATH changes, then run 'trueseal --help'."

