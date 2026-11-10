@echo off
REM ==============================================================================
REM Cyber Digital Twin - Windows One-Click Quickstart Launcher
REM ==============================================================================
title Cyber Digital Twin - Launchpad
color 0b

echo ======================================================================
echo    AI-POWERED CYBER DIGITAL TWIN FOR LINUX
echo    One-Click Quickstart Launcher (Windows)
echo ======================================================================
echo.

REM 1. Verify Python Installation
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH!
    echo Please install Python 3.10+ from https://python.org
    pause
    exit /b 1
)

REM 2. Create .env if not exists
if not exist ".env" (
    echo [*] Creating default local .env configuration...
    copy .env.example .env >nul
)

REM 3. Check / Install dependencies
echo [*] Checking Python dependencies...
python -m pip install -r requirements.txt --quiet

REM 4. Run system status check
echo [*] Inspecting platform readiness...
python manage.py status

REM 5. Launch FastAPI backend
echo.
echo ======================================================================
echo  Starting Cyber Digital Twin Backend API Server...
echo  - Interactive Swagger API Docs:  http://localhost:8000/docs
echo  - Web Dashboard UI:              http://localhost:8000/static/index.html
echo  - Press CTRL+C to stop the server
echo ======================================================================
echo.

REM Automatically open browser after 3 seconds
start "" http://localhost:8000/docs

python manage.py run --port 8000
pause
