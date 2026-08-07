@echo off
:: ============================================================
:: uninstall.bat - Eyxa EDR Agent Uninstaller Launcher
:: Double-click this file. It will auto-request Admin (UAC).
:: ============================================================

:: --- Self-elevate via UAC if not already Admin ---
fltmc >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting Administrator privileges...
    powershell -Command "Start-Process -FilePath 'cmd.exe' -ArgumentList '/c \"%~f0\"' -Verb RunAs"
    exit /b
)

:: --- Launch the PowerShell uninstaller ---
powershell -ExecutionPolicy Bypass -NoProfile -File "%~dp0uninstall.ps1"
