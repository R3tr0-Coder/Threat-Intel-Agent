param(
    [string]$PythonVersion = "3.11.0",
    [string]$Arch = "amd64",
    [string]$OutputDir = "$PSScriptRoot\embed"
)

$ErrorActionPreference = "Stop"
$PythonDir = "$OutputDir\python"
$ZipPath = "$OutputDir\python-${PythonVersion}-embed-${Arch}.zip"
$PythonUrl = "https://www.python.org/ftp/python/${PythonVersion}/python-${PythonVersion}-embed-${Arch}.zip"
$GetPipUrl = "https://bootstrap.pypa.io/get-pip.py"

if (Test-Path "$PythonDir\python.exe") {
    Write-Host "[SKIP] Python already extracted at $PythonDir"
} else {
    Write-Host "[1/5] Downloading Python $PythonVersion embeddable ($Arch)..."
    if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }
    if (-not (Test-Path $ZipPath)) {
        Invoke-WebRequest -Uri $PythonUrl -OutFile $ZipPath -UseBasicParsing
    }
    Write-Host "[2/5] Extracting..."
    Expand-Archive -Path $ZipPath -DestinationPath $PythonDir -Force
}

# Always configure ._pth to exclude user site-packages
Write-Host "[3/5] Configuring ._pth for portable use..."
$PthFile = Get-ChildItem -Path $PythonDir -Filter "python*._pth" | Select-Object -First 1
if ($PthFile) {
    $content = @(
        "python311.zip",
        ".",
        "Lib\site-packages",
        ""
    )
    Set-Content -Path $PthFile.FullName -Value ($content -join "`r`n")
}

$PythonExe = "$PythonDir\python.exe"
if (-not (Test-Path $PythonExe)) {
    Write-Error "python.exe not found after extraction at $PythonExe"
    exit 1
}

Write-Host "[4/5] Installing pip..."
$GetPipPath = "$OutputDir\get-pip.py"
if (-not (Test-Path $GetPipPath)) {
    Invoke-WebRequest -Uri $GetPipUrl -OutFile $GetPipPath -UseBasicParsing
}
& $PythonExe $GetPipPath --no-warn-script-location 2>&1

Write-Host "[5/5] Installing dependencies from requirements.txt..."
$ReqFile = Join-Path $PSScriptRoot "..\requirements.txt"
if (Test-Path $ReqFile) {
    & $PythonExe -m pip install -r $ReqFile --no-warn-script-location 2>&1
} else {
    Write-Warning "requirements.txt not found at $ReqFile"
}

Write-Host "[6/6] Cleaning up..."
& $PythonExe -m pip cache purge --quiet 2>&1 | Out-Null
Get-ChildItem -Path "$PythonDir\Lib\site-packages" -Recurse -Directory -Filter "__pycache__" | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

$size = [math]::Round((Get-ChildItem -Recurse $PythonDir | Measure-Object -Property Length -Sum).Sum / 1MB, 0)
Write-Host "[DONE] Embedded Python ready at $PythonDir"
Write-Host "Size: $size MB"
