# ARGUS Windows installer — one-command install that puts the binary
# on PATH so `argus` works from any PowerShell session.
#
# Usage:
#   # Install the latest release:
#   iwr -useb https://github.com/vatsayanvivek/argus/releases/latest/download/install.ps1 | iex
#
#   # Install a specific version:
#   $env:ARGUS_VERSION = 'v1.0.0'
#   iwr -useb https://github.com/vatsayanvivek/argus/releases/download/v1.8.0/install.ps1 | iex
#
# What this does:
#   1. Detects the user's architecture (amd64 or arm64)
#   2. Downloads the matching argus-windows-*.exe from GitHub Releases
#   3. Verifies the SHA-256 hash against SHA256SUMS from the same release
#   4. Installs to %LOCALAPPDATA%\Programs\argus\argus.exe
#   5. Unblocks the file (clears Windows mark-of-the-web)
#   6. Adds the install directory to the user PATH (no admin required)
#   7. Runs `argus --version` to verify the install worked
#
# No admin rights required. No environment variable tinkering. Run once,
# open a new PowerShell session, use `argus` from anywhere.

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue' # speeds up Invoke-WebRequest

$RepoOwner = 'vatsayanvivek'
$RepoName = 'argus'
$InstallDir = Join-Path $env:LOCALAPPDATA 'Programs\argus'
$BinaryName = 'argus.exe'

$cyan = @{ ForegroundColor = 'Cyan' }
$green = @{ ForegroundColor = 'Green' }
$red = @{ ForegroundColor = 'Red' }
$dim = @{ ForegroundColor = 'DarkGray' }

Write-Host "ARGUS Windows installer" @cyan
Write-Host ""

# ----- 1. Architecture detection -----
$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { 'amd64' }
    'ARM64' { 'arm64' }
    default { 'amd64' } # fallback for old environment variables
}
Write-Host "  Architecture: $arch" @dim

# ----- 2. Resolve release tag -----
$ReleaseTag = $env:ARGUS_VERSION
if (-not $ReleaseTag) {
    try {
        $latest = Invoke-RestMethod -UseBasicParsing "https://api.github.com/repos/$RepoOwner/$RepoName/releases/latest"
        $ReleaseTag = $latest.tag_name
    } catch {
        Write-Host "  Failed to resolve latest release; defaulting to v1.0.0" @red
        $ReleaseTag = 'v1.0.0'
    }
}
Write-Host "  Release:      $ReleaseTag" @dim

# ----- 3. Download the matching binary -----
$assetName = "argus-windows-$arch.exe"
$downloadUrl = "https://github.com/$RepoOwner/$RepoName/releases/download/$ReleaseTag/$assetName"
$sumsUrl = "https://github.com/$RepoOwner/$RepoName/releases/download/$ReleaseTag/SHA256SUMS"

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
$tempExe = Join-Path $InstallDir "$BinaryName.download"
$target = Join-Path $InstallDir $BinaryName

Write-Host "  Downloading $assetName..." @dim
Invoke-WebRequest -Uri $downloadUrl -OutFile $tempExe -UseBasicParsing

# ----- 4. Verify SHA-256 hash against release's SHA256SUMS -----
try {
    $sumsRaw = (Invoke-WebRequest -Uri $sumsUrl -UseBasicParsing).Content
    $expectedLine = ($sumsRaw -split "`n" | Where-Object { $_ -like "*$assetName*" }) | Select-Object -First 1
    if ($expectedLine) {
        $expectedHash = ($expectedLine -split '\s+')[0].ToLower()
        $actualHash = (Get-FileHash -Algorithm SHA256 $tempExe).Hash.ToLower()
        if ($expectedHash -ne $actualHash) {
            Remove-Item $tempExe -Force
            Write-Host "  SHA-256 mismatch! Refusing to install." @red
            Write-Host "    expected: $expectedHash"
            Write-Host "    actual:   $actualHash"
            exit 1
        }
        Write-Host "  SHA-256 verified" @dim
    } else {
        Write-Host "  Hash verification skipped (SHA256SUMS missing entry for $assetName)" @dim
    }
} catch {
    Write-Host "  Hash verification skipped (could not fetch SHA256SUMS)" @dim
}

# Atomically move into place — overwrites any previous install.
Move-Item -Force -Path $tempExe -Destination $target

# ----- 5. Unblock the file (clears Windows mark-of-the-web) -----
Unblock-File $target

# ----- 6. Add install dir to the user PATH (persistent) -----
$userPath = [Environment]::GetEnvironmentVariable('Path', 'User')
if (-not $userPath) { $userPath = '' }
$pathEntries = $userPath -split ';' | Where-Object { $_ -ne '' }
if ($pathEntries -notcontains $InstallDir) {
    $newPath = if ($userPath) { "$userPath;$InstallDir" } else { $InstallDir }
    [Environment]::SetEnvironmentVariable('Path', $newPath, 'User')
    # Refresh the current session too.
    $env:Path = "$env:Path;$InstallDir"
    Write-Host "  Added to user PATH: $InstallDir" @dim
} else {
    Write-Host "  Already on user PATH" @dim
}

# ----- 7. Verify -----
Write-Host ""
try {
    $version = & $target --version 2>&1
    Write-Host "  Installed: $version" @green
    Write-Host ""
    Write-Host "  ARGUS is ready. Run 'argus --help' in a NEW PowerShell session."  @green
    Write-Host "  (The current session has PATH updated, but new terminals pick it up automatically.)" @dim
} catch {
    Write-Host "  Installed at $target but could not execute. Open a new PowerShell and try 'argus --version'." @red
    exit 1
}
