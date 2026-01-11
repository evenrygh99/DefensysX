REM @even rygh
@echo off
echo ========================================
echo   Stopping SOC Platform
echo ========================================
echo.

echo Stopping all Python processes...
for %%P in (python.exe pythonw.exe python3.13.exe) do (
	taskkill /F /IM %%P >nul 2>&1
)

timeout /t 1 /nobreak >nul

echo.
echo ========================================
echo   SOC Platform Stopped
echo ========================================
echo.
