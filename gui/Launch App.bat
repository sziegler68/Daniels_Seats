@echo off
title LIN Bus Analyzer - Launcher
echo ============================================
echo   LIN Bus Analyzer - Lexus IS350 Seat ECU
echo ============================================
echo.

REM Navigate to the gui folder (where this .bat file lives)
cd /d "%~dp0"

echo Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo.
    echo ERROR: Python is not installed or not in your PATH.
    echo Please install Python from https://www.python.org/downloads/
    echo Make sure to check "Add Python to PATH" during installation.
    echo.
    pause
    exit /b 1
)

echo Python found! Checking dependencies...
echo.

REM Install dependencies if needed (silent if already installed)
pip install -r requirements.txt --quiet 2>nul

echo.
echo Starting LIN Bus Analyzer...
echo (Close this window to stop the app)
echo.

python app.py

echo.
echo App closed.
pause
