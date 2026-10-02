# scripts/install.ps1
# Builds drop and installs it into a directory on your PATH on Windows.
# Automatically detects and installs requirements (Go) if missing.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File scripts\install.ps1
#   powershell -ExecutionPolicy Bypass -File scripts\install.ps1 -BinDir "C:\custom\bin"
param(
    [string]$BinDir = $env:BINDIR,
    [string]$Version = $env:VERSION
)

$ErrorActionPreference = "Stop"

function Ensure-Go {
    # 1. Check if go is already reachable in PATH
    if (Get-Command go -ErrorAction SilentlyContinue) {
        return
    }

    # 2. Check standard install locations in case PATH has not refreshed
    $knownLocations = @(
        "$env:ProgramFiles\Go\bin",
        "$env:LOCALAPPDATA\Programs\go\bin",
        "$env:USERPROFILE\go-sdk\go\bin"
    )
    foreach ($loc in $knownLocations) {
        if (Test-Path "$loc\go.exe") {
            $env:PATH = "$loc;$env:PATH"
            return
        }
    }

    Write-Host "Go is required to build drop, but is not currently installed."
    Write-Host "Attempting automatic installation..."

    # 3. Try winget if available
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget) {
        try {
            Write-Host "Installing Go via winget..."
            Start-Process -FilePath "winget" -ArgumentList "install --id GoLang.Go -e --accept-source-agreements --accept-package-agreements --silent" -NoNewWindow -Wait

            # Refresh PATH from registry
            $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
            $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
            $env:PATH = "$machinePath;$userPath;$env:PATH"

            if (Test-Path "$env:ProgramFiles\Go\bin\go.exe") {
                $env:PATH = "$env:ProgramFiles\Go\bin;$env:PATH"
                return
            }
            if (Get-Command go -ErrorAction SilentlyContinue) {
                return
            }
        } catch {
            Write-Warning "winget installation unsuccessful. Falling back to direct download..."
        }
    }

    # 4. Direct download official portable Go zip (requires no administrator rights)
    $arch = if ([System.Environment]::Is64BitOperatingSystem) {
        if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
    } else {
        "386"
    }

    $destFolder = Join-Path $env:LOCALAPPDATA "Programs\go"
    $zipPath = Join-Path $env:TEMP ("go-install-" + [System.Guid]::NewGuid().ToString("N") + ".zip")

    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Write-Host "Querying latest Go release metadata from https://go.dev/dl/?mode=json..."
        $json = Invoke-RestMethod -Uri "https://go.dev/dl/?mode=json" -UseBasicParsing
        $fileObj = $null
        foreach ($release in $json) {
            if ($release.stable) {
                foreach ($f in $release.files) {
                    if ($f.os -eq "windows" -and $f.arch -eq $arch -and $f.kind -eq "archive") {
                        $fileObj = $f
                        break
                    }
                }
            }
            if ($fileObj) { break }
        }

        if (-not $fileObj) {
            throw "Could not find a Windows archive at https://go.dev/dl/?mode=json"
        }

        $dlUrl = "https://go.dev/dl/$($fileObj.filename)"
        Write-Host "Downloading $dlUrl..."
        Invoke-WebRequest -Uri $dlUrl -OutFile $zipPath -UseBasicParsing

        Write-Host "Extracting Go to $destFolder..."
        $parentFolder = Split-Path $destFolder -Parent
        if (-not (Test-Path $parentFolder)) {
            New-Item -ItemType Directory -Path $parentFolder -Force | Out-Null
        }
        if (Test-Path $destFolder) {
            Remove-Item -Path $destFolder -Recurse -Force -ErrorAction SilentlyContinue
        }

        Expand-Archive -Path $zipPath -DestinationPath $parentFolder -Force

        $goBin = Join-Path $destFolder "bin"
        if (-not (Test-Path (Join-Path $goBin "go.exe"))) {
            throw "Extracted Go binary not found at $goBin\go.exe"
        }

        # Persistently save Go to User PATH
        $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
        if ($userPath -notlike "*$goBin*") {
            $newUserPath = if ($userPath) { "$userPath;$goBin" } else { $goBin }
            [Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")
        }
        $env:PATH = "$goBin;$env:PATH"
        Write-Host "Successfully installed Go into $destFolder"
    } finally {
        if (Test-Path $zipPath) {
            Remove-Item -Path $zipPath -Force -ErrorAction SilentlyContinue
        }
    }
}

# Ensure requirements
Ensure-Go

# Check Git (optional for basic drop, needed for drop diff/git)
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Host "NOTE: Git is not installed. File transfer and text drop will work normally, but 'drop diff' and 'drop git' require Git."
}

# Determine version
if (-not $Version) {
    if (Get-Command git -ErrorAction SilentlyContinue) {
        $gitVer = git describe --tags --always --dirty 2>$null
        if ($LASTEXITCODE -eq 0 -and $gitVer) {
            $Version = $gitVer.Trim()
        }
    }
    if (-not $Version) {
        $Version = "0.1.0-dev"
    }
}

$ldflags = "-X github.com/thameem/drop/internal/cli.Version=$Version"

function Test-OnPath([string]$dirPath) {
    if (-not $dirPath -or -not (Test-Path $dirPath)) {
        return $false
    }
    $normalized = (Resolve-Path -Path $dirPath).Path.TrimEnd('\').ToLowerInvariant()
    $envPaths = ($env:PATH -split ';') | Where-Object { $_.Trim() -ne "" }
    foreach ($p in $envPaths) {
        if (Test-Path $p) {
            $res = (Resolve-Path -Path $p).Path.TrimEnd('\').ToLowerInvariant()
            if ($res -eq $normalized) {
                return $true
            }
        }
    }
    return $false
}

# Select target directory
$targetDir = $BinDir
$addedToPath = $false

if (-not $targetDir) {
    # Check common user bin directories already on PATH
    $candidates = @()
    if ($env:GOPATH) {
        $candidates += (Join-Path $env:GOPATH "bin")
    }
    $candidates += (Join-Path $env:USERPROFILE "go\bin")
    $candidates += (Join-Path $env:USERPROFILE ".local\bin")
    $candidates += (Join-Path $env:USERPROFILE "bin")

    foreach ($cand in $candidates) {
        if ((Test-Path $cand) -and (Test-OnPath $cand)) {
            $targetDir = $cand
            break
        }
    }
}

# Fallback: create a dedicated directory and add it to PATH
if (-not $targetDir) {
    $targetDir = Join-Path $env:LOCALAPPDATA "Programs\drop"
    if (-not (Test-Path $targetDir)) {
        New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
    }
    if (-not (Test-OnPath $targetDir)) {
        $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
        $newUserPath = if ($userPath) { "$userPath;$targetDir" } else { $targetDir }
        [Environment]::SetEnvironmentVariable("Path", $newUserPath, "User")
        $env:PATH = "$env:PATH;$targetDir"
        $addedToPath = $true
    }
}

if (-not (Test-Path $targetDir)) {
    New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
}

$guid = [System.Guid]::NewGuid().ToString("N")
$tempFile = Join-Path $targetDir (".drop-install-$guid.exe")
$finalFile = Join-Path $targetDir "drop.exe"

try {
    go build -ldflags $ldflags -o $tempFile ./cmd/drop
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Build failed."
        exit 1
    }
    Move-Item -Path $tempFile -Destination $finalFile -Force
} finally {
    if (Test-Path $tempFile) {
        Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "installed: $finalFile"

if ($addedToPath) {
    Write-Host "added $targetDir to User PATH"
    Write-Host "NOTE: open a NEW terminal window before using 'drop'."
}

# Shadow check and version verification
$found = Get-Command drop.exe -ErrorAction SilentlyContinue
if ($found -and ((Resolve-Path $found.Source).Path.ToLowerInvariant() -ne (Resolve-Path $finalFile).Path.ToLowerInvariant())) {
    Write-Warning "another 'drop' comes first on your PATH and will shadow this one:"
    Write-Warning "         $($found.Source)"
    Write-Warning "         remove it or place $targetDir earlier in your PATH."
} else {
    try {
        $ver = & $finalFile --version
        Write-Host "check: $ver"
    } catch {
        # ignore execution policy or subshell errors
    }
}
