@echo off
rem RAVEN Recon - start from source (run install.ps1 once first).
title RAVEN Recon
cd /d "%~dp0"
if not defined RAVEN_DATA_DIR set "RAVEN_DATA_DIR=%LOCALAPPDATA%\RAVEN-Recon"
if exist ".venv\Scripts\python.exe" ( ".venv\Scripts\python.exe" launch.py %* ) else ( python launch.py %* )
