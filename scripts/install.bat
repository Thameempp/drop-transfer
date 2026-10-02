@echo off
setlocal
cd /d "%~dp0.."
powershell -NoProfile -ExecutionPolicy Bypass -File "scripts\install.ps1" %*
if %ERRORLEVEL% neq 0 (
    echo.
    echo Installation failed. See errors above.
    pause
    exit /b %ERRORLEVEL%
)
