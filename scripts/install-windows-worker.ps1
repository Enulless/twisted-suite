# Windows worker bootstrap.
#
# Run from PowerShell on the Windows side. Creates a venv at
# %USERPROFILE%\.twisted\venv, installs the editable twisted-suite package
# from the WSL repo via the \\wsl$ UNC path, fetches the bearer token,
# and launches the worker.
#
# Usage:
#   .\install-windows-worker.ps1                                      # defaults
#   .\install-windows-worker.ps1 -Distro Ubuntu -EngineUrl http://127.0.0.1:8000

param(
    [string] $Distro     = "Ubuntu",
    [string] $WslUser    = $env:USERNAME,
    [string] $RepoPath   = $null,
    [string] $EngineUrl  = "http://127.0.0.1:8000",
    [switch] $RunWorker  = $true
)

$ErrorActionPreference = "Stop"

function Resolve-Repo {
    param([string]$Distro, [string]$WslUser, [string]$RepoPath)
    if ($RepoPath) { return $RepoPath }
    $candidates = @(
        "\\wsl$\$Distro\home\$WslUser\twisted_suite",
        "\\wsl.localhost\$Distro\home\$WslUser\twisted_suite"
    )
    foreach ($p in $candidates) {
        if (Test-Path $p) { return $p }
    }
    throw "Could not locate twisted_suite under WSL distro '$Distro' for user '$WslUser'. Pass -RepoPath explicitly."
}

function Resolve-TokenFile {
    param([string]$Distro, [string]$WslUser)
    $candidates = @(
        "\\wsl$\$Distro\home\$WslUser\.twisted\worker.token",
        "\\wsl.localhost\$Distro\home\$WslUser\.twisted\worker.token"
    )
    foreach ($p in $candidates) {
        if (Test-Path $p) { return $p }
    }
    throw "Worker token file not found. Run 'twisted token show' on the WSL side first."
}

$repo  = Resolve-Repo -Distro $Distro -WslUser $WslUser -RepoPath $RepoPath
$token = (Get-Content (Resolve-TokenFile -Distro $Distro -WslUser $WslUser) -Raw).Trim()

Write-Host "Repo:    $repo"
Write-Host "Engine:  $EngineUrl"
Write-Host "Token:   $($token.Substring(0,8))…"

# Create venv
$venv = Join-Path $env:USERPROFILE ".twisted\venv"
if (-not (Test-Path $venv)) {
    Write-Host "Creating venv at $venv ..."
    python -m venv $venv
}
$pyExe   = Join-Path $venv "Scripts\python.exe"
$pipExe  = Join-Path $venv "Scripts\pip.exe"
$twisted = Join-Path $venv "Scripts\twisted.exe"

# Install editable package from WSL repo
Write-Host "Installing twisted-suite from $repo ..."
& $pipExe install --quiet --upgrade pip
& $pipExe install --quiet -e $repo

# Persist token + engine URL for the user
[Environment]::SetEnvironmentVariable("TWISTED_TOKEN",      $token,      "User")
[Environment]::SetEnvironmentVariable("TWISTED_ENGINE_URL", $EngineUrl,  "User")
$env:TWISTED_TOKEN      = $token
$env:TWISTED_ENGINE_URL = $EngineUrl

if ($RunWorker) {
    Write-Host "Starting Windows worker..."
    & $twisted worker windows
} else {
    Write-Host "Setup complete. Start the worker with:"
    Write-Host "  & $twisted worker windows"
}
