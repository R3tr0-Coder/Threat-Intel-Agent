# Building the Windows Installer

## Prerequisites

- Windows 10/11 (x64)
- PowerShell 5.1+

## Quick Build

Run this from PowerShell:

```powershell
.\build\build_installer.ps1
```

The script will:
1. Download Python 3.11 embeddable + install pip + all Python dependencies
2. Download Inno Setup (if not already cached) and extract the compiler
3. Compile `installer.iss` into a standalone `.exe`

## Output

The installer will be at:

```
build\output\ThreatIntelAgentSetup-1.0.0.exe
```

## What Gets Bundled

| Component | Location in install |
|---|---|
| App source code | `src\` |
| Embedded Python 3.11 | `python\` |
| All pip dependencies | `python\Lib\site-packages\` |
| `.env` template | `.env` (blank API keys — user adds their own) |
| Launcher script | `launch_app.bat` |
| README | `README.md` |

## Manual Build (if the script fails)

1. Install [Inno Setup](https://jrsoftware.org/isdl.php) (default options)
2. Run `.\build\setup_embedded_python.ps1` to prepare the portable Python
3. Open `build\installer.iss` in Inno Setup Compiler and press F9 (Compile)
4. Or use CLI: `iscc.exe build\installer.iss`
