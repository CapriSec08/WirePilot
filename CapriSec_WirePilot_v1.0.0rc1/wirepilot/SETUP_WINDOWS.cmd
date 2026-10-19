@echo off
setlocal
cd /d "%~dp0"
echo WirePilot setup for Claude Desktop
echo No administrator access or API key required.
echo.
py -3 -c "import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)" >nul 2>&1
if not errorlevel 1 (
    py -3 "%~dp0scripts\setup_windows.py" %*
    goto finish
)
python -c "import sys; sys.exit(0 if sys.version_info >= (3,11) else 1)" >nul 2>&1
if not errorlevel 1 (
    python "%~dp0scripts\setup_windows.py" %*
    goto finish
)
echo Python 3.11 or newer was not found.
echo Install Python from https://www.python.org/downloads/windows/
echo Enable the Python launcher or Add Python to PATH, then run this again.
pause
exit /b 1
:finish
if errorlevel 1 (
    echo.
    echo Setup did not complete. Read the error above, fix it, and run again.
    pause
    exit /b 1
)
echo.
pause
