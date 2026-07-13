param(
    [string]$PythonVersion = "3.11.0",
    [string]$InnoSetupUrl = "https://jrsoftware.org/download.php/is.exe",
    [string]$InnoSetupPath = "$env:TEMP\innosetup\is.exe",
    [string]$ISCCPath = "$env:TEMP\innosetup\ISCC.exe"
)

$ErrorActionPreference = "Stop"
$BuildDir = $PSScriptRoot

Write-Host "============================================"
Write-Host " Threat Intelligence Agent — Builder"
Write-Host "============================================"

# -------------------------------------------------------
# Step 1: Set up embedded Python
# -------------------------------------------------------
Write-Host "[1/3] Setting up embedded Python..."
& "$BuildDir\setup_embedded_python.ps1" -PythonVersion $PythonVersion
if (-not (Test-Path "$BuildDir\embed\python\python.exe")) {
    Write-Error "Embedded Python not found after setup"
    exit 1
}

# -------------------------------------------------------
# Step 2: Locate or download Inno Setup
# -------------------------------------------------------
Write-Host "[2/3] Locating Inno Setup..."
if (-not (Test-Path $ISCCPath)) {
    Write-Host "  -> Not found at $ISCCPath, downloading..."
    $InnoDir = [System.IO.Path]::GetDirectoryName($InnoSetupPath)
    if (-not (Test-Path $InnoDir)) { New-Item -ItemType Directory -Path $InnoDir -Force | Out-Null }
    try {
        Invoke-WebRequest -Uri $InnoSetupUrl -OutFile $InnoSetupPath -UseBasicParsing -ErrorAction Stop
        Write-Host "  -> Downloaded to $InnoSetupPath"
    } catch {
        Write-Error "Failed to download Inno Setup: $_`nPlease install Inno Setup manually from https://jrsoftware.org/isdl.php"
        exit 1
    }
    Write-Host "  -> Installing Inno Setup (silent)..."
    $ExtractDir = [System.IO.Path]::GetDirectoryName($ISCCPath)
    Start-Process -FilePath $InnoSetupPath -ArgumentList "/VERYSILENT /DIR=$ExtractDir /SUPPRESSMSGBOXES" -Wait -NoNewWindow
    # ISCC.exe might be directly in ExtractDir or in a subfolder
    $possiblePaths = @(
        $ISCCPath,
        "$ExtractDir\ISCC.exe",
        "$ExtractDir\Inno Setup 6\ISCC.exe",
        "$ExtractDir\Inno Setup 5\ISCC.exe"
    )
    $found = $false
    foreach ($p in $possiblePaths) {
        if (Test-Path $p) { $ISCCPath = $p; $found = $true; break }
    }
    if (-not $found) {
        Write-Error "ISCC.exe not found. Searched:`n$($possiblePaths -join "`n")"
        exit 1
    }
    Write-Host "  -> Found ISCC at $ISCCPath"
} else {
    Write-Host "  -> Found at $ISCCPath"
}

# -------------------------------------------------------
# Step 3: Compile the installer
# -------------------------------------------------------
Write-Host "[3/3] Compiling installer..."
$IssFile = "$BuildDir\installer.iss"
if (-not (Test-Path $IssFile)) {
    Write-Error "Inno Setup script not found at $IssFile"
    exit 1
}

$OutputDir = "$BuildDir\output"
if (Test-Path $OutputDir) {
    Remove-Item -Path "$OutputDir\*" -Recurse -Force -ErrorAction SilentlyContinue
}

$result = Start-Process -FilePath $ISCCPath -ArgumentList "`"$IssFile`"" -Wait -NoNewWindow -PassThru
if ($result.ExitCode -ne 0) {
    Write-Error "ISCC compilation failed with exit code $($result.ExitCode)"
    exit $result.ExitCode
}

# -------------------------------------------------------
# Done
# -------------------------------------------------------
$InstallerFile = Get-ChildItem -Path $OutputDir -Filter "ThreatIntelAgentSetup-*.exe" | Select-Object -First 1
if ($InstallerFile) {
    Write-Host ""
    Write-Host "============================================"
    Write-Host " Build complete!"
    Write-Host "   Output: $($InstallerFile.FullName)"
    $installerSize = [math]::Round((Get-Item $InstallerFile.FullName).Length / 1MB, 0)
    Write-Host "   Size: $installerSize MB"
    Write-Host "============================================"
} else {
    Write-Error "Installer not found in output directory"
    exit 1
}
