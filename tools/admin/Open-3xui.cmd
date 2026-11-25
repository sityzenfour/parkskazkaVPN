@echo off
title ParkSkazka - 3x-ui administration
cd /d "%~dp0"
echo Enter the Linux SSH account configured on the server when prompted for SshUser.
echo Keep the SSH tunnel window open while using the panel.
echo.
if not exist "%~dp0Open-3xui.ps1" (
    echo Open-3xui.ps1 is missing. Put both files in the same folder.
    pause
    exit /b 1
)
"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -ExecutionPolicy Bypass -File "%~dp0Open-3xui.ps1" %*
set "panelExitCode=%errorlevel%"
echo.
if not "%panelExitCode%"=="0" echo Panel launcher failed. Copy the error text above for diagnosis.
pause
exit /b %panelExitCode%
