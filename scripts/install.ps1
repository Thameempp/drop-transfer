# scripts/install.ps1
# Builds drop and installs it into a directory on your PATH on Windows.
# Automatically downloads and installs Go if missing — no manual steps needed.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\install.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\install.ps1 -BinDir "C:\custom\bin"
param(
    [string]$BinDir  = $env:BINDIR,
    [string]$Version = $env:VERSION
)

Set-StrictMode -Off
$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

function Write-Step([string]$msg) {
    Write-Host "==> $msg"
}

function Write-Ok([string]$msg) {
    Write-Host "    ok  $msg"
}

# Returns $true when $dir is already present in the CURRENT session PATH.
function Test-InPath([string]$dir) {
    if (-not $dir) { return $false }
    $want = $dir.TrimEnd('\').ToLowerInvariant()
    foreach ($p in ($env:PATH -split ';')) {
        if ($p.Trim().TrimEnd('\').ToLowerInvariant() -eq $want) { return $true }
    }
    return $false
}

# Append $dir to both the current session PATH and to the permanent User PATH.
function Add-ToPath([string]$dir) {
    if (-not (Test-InPath $dir)) {
        $env:PATH = "$env:PATH;$dir"
    }
    $reg = [Environment]::GetEnvironmentVariable("Path", "User")
    $regWant = $dir.TrimEnd('\').ToLowerInvariant()
    $alreadyReg = ($reg -split ';') | Where-Object {
        $_.Trim().TrimEnd('\').ToLowerInvariant() -eq $regWant
    }
    if (-not $alreadyReg) {
        $newReg = if ($reg) { "$reg;$dir" } else { $dir }
        [Environment]::SetEnvironmentVariable("Path", $newReg, "User")
    }
}

# Download $url to $dest using WebClient (faster than Invoke-WebRequest, no
# hanging progress bar).  Shows a simple dots heartbeat so users know it's running.
function Download-File([string]$url, [string]$dest) {
    $wc   = New-Object System.Net.WebClient
    $task = $wc.DownloadFileTaskAsync($url, $dest)

    # Heartbeat — print a dot every 2 s so users know it's running
    Write-Host -NoNewline "    downloading"
    while (-not $task.IsCompleted) {
        Start-Sleep -Milliseconds 2000
        Write-Host -NoNewline "."
    }
    Write-Host " done"

    $wc.Dispose()

    if ($task.IsFaulted) {
        throw $task.Exception.InnerException
    }
}

# ---------------------------------------------------------------------------
# Ensure Go is available
# ---------------------------------------------------------------------------

function Ensure-Go {
    Write-Step "Checking for Go..."

    # Already on PATH?
    if (Get-Command go -ErrorAction SilentlyContinue) {
        Write-Ok "found $(go version)"
        return
    }

    # Check well-known locations that might exist but aren't on PATH yet
    $knownLocations = @(
        "$env:ProgramFiles\Go\bin",
        "$env:LOCALAPPDATA\Programs\go\bin",
        "$env:USERPROFILE\sdk\go\bin",
        "$env:USERPROFILE\go\bin"
    )
    # ProgramFiles(x86) can be $null on 64-bit-only systems
    $pf86 = [System.Environment]::GetEnvironmentVariable("ProgramFiles(x86)")
    if ($pf86) { $knownLocations += "$pf86\Go\bin" }

    foreach ($loc in $knownLocations) {
        if ($loc -and (Test-Path "$loc\go.exe")) {
            $env:PATH = "$loc;$env:PATH"
            Write-Ok "found existing Go at $loc"
            return
        }
    }

    # --- Need to install Go ---
    Write-Host "    Go not found. Downloading the official portable Go archive from go.dev..."

    $arch = "amd64"
    if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64" -or
        $env:PROCESSOR_ARCHITEW6432 -eq "ARM64") {
        $arch = "arm64"
    } elseif (-not [System.Environment]::Is64BitOperatingSystem) {
        $arch = "386"
    }

    # Query latest stable release
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    Write-Host -NoNewline "    fetching release list from go.dev..."
    $releases = Invoke-RestMethod -Uri "https://go.dev/dl/?mode=json" -UseBasicParsing
    Write-Host " done"

    $fileObj = $null
    foreach ($release in $releases) {
        if (-not $release.stable) { continue }
        foreach ($f in $release.files) {
            if ($f.os -eq "windows" -and $f.arch -eq $arch -and $f.kind -eq "archive") {
                $fileObj = $f
                break
            }
        }
        if ($fileObj) { break }
    }

    # Hard fallback if API changes
    $filename = if ($fileObj) { $fileObj.filename } else { "go1.27.1.windows-$arch.zip" }
    $dlUrl    = "https://go.dev/dl/$filename"

    $zipPath = Join-Path $env:TEMP ("go-$([System.Guid]::NewGuid().ToString('N')).zip")

    try {
        # go.dev/dl zips always extract to a subfolder called "go" inside the
        # chosen destination parent.  We put the parent at Programs\ and end up
        # with Programs\go\bin\go.exe — which we expose as $destFolder.
        $destParent = Join-Path $env:LOCALAPPDATA "Programs"
        $destFolder = Join-Path $destParent "go"        # = …\Programs\go

        Write-Host "    target: $destFolder"
        Write-Host "    url:    $dlUrl"

        Download-File $dlUrl $zipPath

        Write-Step "Extracting Go..."

        # Remove stale install if present
        if (Test-Path $destFolder) {
            Remove-Item -Path $destFolder -Recurse -Force -ErrorAction SilentlyContinue
        }
        if (-not (Test-Path $destParent)) {
            New-Item -ItemType Directory -Path $destParent -Force | Out-Null
        }

        $oldPP = $ProgressPreference
        $ProgressPreference = "SilentlyContinue"
        Expand-Archive -Path $zipPath -DestinationPath $destParent -Force
        $ProgressPreference = $oldPP

        $goBin = Join-Path $destFolder "bin"
        if (-not (Test-Path (Join-Path $goBin "go.exe"))) {
            throw "Expected go.exe at $goBin\go.exe after extraction — please report this."
        }

        $env:PATH    = "$goBin;$env:PATH"
        $env:GOROOT  = $destFolder
        Add-ToPath $goBin

        Write-Ok "Go installed at $destFolder"
        Write-Ok "$(go version)"
    } finally {
        if (Test-Path $zipPath) {
            Remove-Item $zipPath -Force -ErrorAction SilentlyContinue
        }
    }
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

Ensure-Go

# Git is optional (only needed for `drop diff` / `drop git`)
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Host "NOTE: Git not found. File/text transfer works fine; 'drop diff'/'drop git' require Git."
}

# Determine version string
if (-not $Version) {
    if (Get-Command git -ErrorAction SilentlyContinue) {
        try {
            $g = (& git describe --tags --always --dirty 2>&1) | Out-String
            if ($LASTEXITCODE -eq 0 -and $g -and ($g -notmatch "fatal|error")) {
                $Version = $g.Trim()
            }
        } catch { }
    }
    if (-not $Version) { $Version = "0.1.0-dev" }
}

Write-Step "Building drop $Version..."

$ldflags = "-X github.com/thameem/drop/internal/cli.Version=$Version"

# ---------------------------------------------------------------------------
# Choose install directory
# ---------------------------------------------------------------------------
$targetDir  = $BinDir
$addedToPath = $false

if (-not $targetDir) {
    $candidates = @()
    if ($env:GOPATH) { $candidates += Join-Path $env:GOPATH "bin" }
    $candidates += Join-Path $env:USERPROFILE "go\bin"
    $candidates += Join-Path $env:USERPROFILE ".local\bin"
    $candidates += Join-Path $env:USERPROFILE "bin"

    foreach ($cand in $candidates) {
        if ((Test-Path $cand) -and (Test-InPath $cand)) {
            $targetDir = $cand
            break
        }
    }
}

if (-not $targetDir) {
    $targetDir = Join-Path $env:LOCALAPPDATA "Programs\drop"
    if (-not (Test-Path $targetDir)) {
        New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
    }
    Add-ToPath $targetDir
    $addedToPath = $true
}

if (-not (Test-Path $targetDir)) {
    New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
}

# ---------------------------------------------------------------------------
# Build and install
# ---------------------------------------------------------------------------
$guid      = [System.Guid]::NewGuid().ToString("N")
$tempFile  = Join-Path $targetDir ".drop-install-$guid.exe"
$finalFile = Join-Path $targetDir "drop.exe"

try {
    & go build -ldflags "$ldflags" -o "$tempFile" ./cmd/drop
    if ($LASTEXITCODE -ne 0) {
        throw "go build exited with code $LASTEXITCODE"
    }
    Move-Item -Path $tempFile -Destination $finalFile -Force
} finally {
    if (Test-Path $tempFile) {
        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
    }
}

Write-Ok "installed: $finalFile"

if ($addedToPath) {
    Write-Host ""
    Write-Host "  Added $targetDir to your User PATH."
    Write-Host "  Open a NEW terminal window, then run:  drop --version"
} else {
    # Verify immediately — drop is already on PATH in this session
    try {
        Write-Ok "$(& $finalFile --version)"
    } catch { }
}
