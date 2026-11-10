@echo off
rem Secure Code Analyzer - Windows launcher. Double-click this file.
cd /d "%~dp0"

where python >nul 2>nul
if errorlevel 1 (
    echo Python was not found. Install Python 3.10 or newer from https://www.python.org/downloads/
    echo and tick "Add python.exe to PATH" during the installation.
    pause
    exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
    echo Creating the virtual environment ^(first run only^)...
    python -m venv .venv
    if errorlevel 1 ( pause & exit /b 1 )
)

echo Installing the requirements ^(first run takes a few minutes^)...
".venv\Scripts\python.exe" -m pip install --quiet --upgrade pip
".venv\Scripts\python.exe" -m pip install --quiet -r requirements.txt
if errorlevel 1 (
    echo The installation failed. Check your internet connection and try again.
    pause
    exit /b 1
)

".venv\Scripts\python.exe" -m sca ui
pause
