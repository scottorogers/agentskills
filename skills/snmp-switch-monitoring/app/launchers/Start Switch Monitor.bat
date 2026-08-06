@echo off
rem Windows: double-click this file to start Switch Monitor.
cd /d "%~dp0"

rem Try the py launcher first, then plain python.
where py >nul 2>nul
if %ERRORLEVEL%==0 (
    py -3 netmon-app.py %*
    goto :eof
)

where python >nul 2>nul
if %ERRORLEVEL%==0 (
    python netmon-app.py %*
    goto :eof
)

echo.
echo Python 3.9 or newer is required, and was not found.
echo.
echo Install it from https://www.python.org/downloads/
echo IMPORTANT: tick "Add Python to PATH" in the installer.
echo.
pause
