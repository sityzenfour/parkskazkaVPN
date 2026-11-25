@echo off
title ParkSkazka Profiles 2026-11-25.5
cd /d "%~dp0"
powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File "%~dp0New-EmployeeProfile.ps1" %*
set "profileExitCode=%errorlevel%"
pause
exit /b %profileExitCode%
