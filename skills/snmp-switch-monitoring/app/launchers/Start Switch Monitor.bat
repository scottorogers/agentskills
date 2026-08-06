@echo off
rem Windows: double-click this file to start Switch Monitor.
cd /d "%~dp0"

rem Each candidate must actually RUN and be new enough -- merely existing on
rem PATH is not enough. Windows ships a stub python.exe in WindowsApps that
rem only opens the Microsoft Store; `where python` finds it and it is useless.
rem Running a version probe and checking the exit code filters that out, and
rem rejects a genuine but too-old Python at the same time.
rem The probe deliberately avoids the characters cmd treats as redirection.

set "PROBE=import sys; sys.exit(min(sys.version_info[:2], (3,9)) != (3,9))"

py -3 -c "%PROBE%" >nul 2>nul
if not errorlevel 1 (
    py -3 netmon-app.py %*
    goto finished
)

python -c "%PROBE%" >nul 2>nul
if not errorlevel 1 (
    python netmon-app.py %*
    goto finished
)

python3 -c "%PROBE%" >nul 2>nul
if not errorlevel 1 (
    python3 netmon-app.py %*
    goto finished
)

echo.
echo   Switch Monitor needs Python 3.9 or newer, and could not find it.
echo.
echo   Install it from https://www.python.org/downloads/
echo   IMPORTANT: tick "Add Python to PATH" in the installer.
echo.
echo   If the Microsoft Store opened instead, that is a placeholder, not
echo   Python. Install from the link above.
echo.
pause
exit /b 1

:finished
rem A double-clicked window closes the instant the program ends, so hold it
rem open on failure -- otherwise the error is invisible.
if errorlevel 1 pause
