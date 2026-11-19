<#
RAVEN Recon — installer for Windows 10/11 (per user, no administrator rights needed).

  powershell -ExecutionPolicy Bypass -File .\install.ps1              install / update
  powershell -ExecutionPolicy Bypass -File .\install.ps1 -Uninstall   remove shortcuts + commands (data kept)

After installing (open a NEW terminal so PATH is refreshed):
  raven-recon        desktop app (its own window)          — also in the Start Menu
  raven-recon-web    local web UI in your browser
  raven-sec          AI assistant in the terminal (Claude, with the key saved in Settings)

Data folder: %LOCALAPPDATA%\RAVEN-Recon
Note: the AI agent's command sandbox (bubblewrap) is Linux-only; on Windows the agent can
still search, read, send approved in-scope requests and write files, but not run commands.
#>
param([switch]$Uninstall)
$ErrorActionPreference = "Stop"

$Root      = Split-Path -Parent $MyInvocation.MyCommand.Path
$Home_     = Join-Path $env:LOCALAPPDATA "RAVEN-Recon"
$Bin       = Join-Path $Home_ "bin"
$StartMenu = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs"
$Shortcut  = Join-Path $StartMenu "RAVEN Recon.lnk"

function Remove-FromUserPath([string]$dir) {
    $p = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($p) {
        $parts = $p.Split(";") | Where-Object { $_ -and ($_ -ne $dir) }
        [Environment]::SetEnvironmentVariable("Path", ($parts -join ";"), "User")
    }
}

if ($Uninstall) {
    Remove-Item -Force -ErrorAction SilentlyContinue $Shortcut
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue $Bin
    Remove-FromUserPath $Bin
    Write-Host "Removed the Start Menu entry and commands. Your data is kept in $Home_"
    exit 0
}

# 1) Python 3.11+
$py = $null; $pyArgs = @()
if (Get-Command py -ErrorAction SilentlyContinue) { $py = "py"; $pyArgs = @("-3") }
elseif (Get-Command python -ErrorAction SilentlyContinue) { $py = "python" }
if (-not $py) {
    Write-Host "Python 3.11+ was not found. Install it, then run this script again:"
    Write-Host "    winget install -e --id Python.Python.3.12"
    exit 1
}
& $py @pyArgs -c "import sys; assert sys.version_info >= (3, 11), 'Python 3.11 or newer is required'"
if ($LASTEXITCODE -ne 0) { exit 1 }

# 2) Python environment + dependencies
Write-Host "==> Creating the Python environment (.venv)"
$Venv = Join-Path $Root ".venv"
if (-not (Test-Path (Join-Path $Venv "Scripts\python.exe"))) { & $py @pyArgs -m venv $Venv }
$VPy  = Join-Path $Venv "Scripts\python.exe"
$VPyw = Join-Path $Venv "Scripts\pythonw.exe"
& $VPy -m pip install --upgrade pip | Out-Null
& $VPy -m pip install -r (Join-Path $Root "requirements-windows.txt")
if ($LASTEXITCODE -ne 0) { Write-Host "pip install failed"; exit 1 }

# 3) Launchers (data always in %LOCALAPPDATA%\RAVEN-Recon, never inside the code folder)
New-Item -ItemType Directory -Force -Path $Bin, $Home_ | Out-Null
$Launcher = Join-Path $Bin "raven-recon.pyw"
@"
import os, runpy, sys
os.environ.setdefault("RAVEN_DATA_DIR", r"$Home_")
sys.path.insert(0, r"$Root")
os.chdir(r"$Root")
sys.argv[0] = r"$Root\launch.py"
runpy.run_path(r"$Root\launch.py", run_name="__main__")
"@ | Set-Content -Encoding UTF8 $Launcher

"@echo off`r`nstart `"`" `"$VPyw`" `"$Launcher`" %*" | Set-Content -Encoding ASCII (Join-Path $Bin "raven-recon.cmd")
"@echo off`r`n`"$VPy`" `"$Launcher`" --browser %*" | Set-Content -Encoding ASCII (Join-Path $Bin "raven-recon-web.cmd")
"@echo off`r`nset RAVEN_DATA_DIR=$Home_`r`nset PYTHONPATH=$Root`r`n`"$VPy`" -m raven.sec_ai.cli %*" | Set-Content -Encoding ASCII (Join-Path $Bin "raven-sec.cmd")

# 4) Start Menu shortcut
$ws  = New-Object -ComObject WScript.Shell
$lnk = $ws.CreateShortcut($Shortcut)
$lnk.TargetPath       = $VPyw
$lnk.Arguments        = "`"$Launcher`""
$lnk.WorkingDirectory = $Root
$lnk.IconLocation     = (Join-Path $Root "raven.ico")
$lnk.Description      = "RAVEN Recon — authorised security testing"
$lnk.Save()

# 5) User PATH
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if (-not ($userPath -split ";" | Where-Object { $_ -eq $Bin })) {
    [Environment]::SetEnvironmentVariable("Path", (($userPath, $Bin) -join ";").Trim(";"), "User")
}

Write-Host ""
Write-Host "RAVEN Recon is installed. Open a NEW terminal, then:"
Write-Host "  raven-recon        desktop app (also: Start Menu -> RAVEN Recon)"
Write-Host "  raven-recon-web    local web UI in your browser"
Write-Host "  raven-sec          AI assistant in the terminal"
Write-Host ""
Write-Host "Data folder: $Home_"
Write-Host "Use it only on targets you are authorised to test - see RESPONSIBLE_USE.md."
