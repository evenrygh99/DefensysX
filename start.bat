REM @even rygh
@echo off
echo ========================================
echo   Starting SOC Platform
echo ========================================
echo.

REM Clear Python cache to ensure latest code is loaded
if exist __pycache__ rmdir /s /q __pycache__ >nul 2>&1
del /s /q *.pyc >nul 2>&1

REM Prefer local virtualenv Python if available
set "PYTHON_EXE=python"
if exist ".venv\Scripts\python.exe" set "PYTHON_EXE=.venv\Scripts\python.exe"

echo [1/2] Starting Backend API on port 8000...
start "" /B "%PYTHON_EXE%" -B main.py

timeout /t 3 /nobreak >nul

echo [2/2] Starting Frontend Server on port 8080...
start "" /B "%PYTHON_EXE%" serve_frontend.py

timeout /t 2 /nobreak >nul

echo.
echo ========================================
echo   SOC Platform Started!
echo ========================================
echo.
echo   Backend:  http://localhost:8000
echo   Frontend: http://localhost:8080/index.html
echo.
echo   Press any key to open frontend in browser...
pause >nul

start http://localhost:8080/index.html

echo.
echo   To stop services: run stop.bat
echo.
