@echo off
setlocal enabledelayedexpansion

cd /d "%~dp0"

powershell -NoProfile -ExecutionPolicy Bypass -File "scripts\install.ps1" %*
set _ERR=!ERRORLEVEL!

if !_ERR! neq 0 (
    echo.
    echo Installation failed with exit code !_ERR!. See errors above.
    endlocal
    pause
    exit /b !_ERR!
)

echo.
echo Installation successful. Open a new terminal and run: drop --version
endlocal
pause
