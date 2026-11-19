@echo off
title Build RAVEN.exe
cd /d "%~dp0"
echo Building RAVEN.exe (native window, no console)...
rem ONE canonical build definition: RAVEN.spec (tracked in git, alongside raven.ico
rem and build\version_info.txt). RAVEN-V7.spec and RAVEN-V5.spec are DEPRECATED and
rem kept on disk for reference only — do not invoke them.
rem Do not add a separate PyInstaller CLI-flags invocation here — if the build needs
rem to change, edit RAVEN.spec so there is exactly one place that defines the build.
rem (RAVEN.spec regenerates build\version_info.txt if --clean wiped the work path.)
python -m PyInstaller RAVEN.spec --noconfirm --clean
echo.
echo Done. The app is at dist\RAVEN.exe
pause
