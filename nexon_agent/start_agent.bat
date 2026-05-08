@echo off
setlocal

REM ── Nexon Technologies Endpoint Agent ───────────────────────────────────────
REM Activate venv and start monitoring agent

cd /d "%~dp0"

if not exist "venv\Scripts\activate.bat" (
    echo [ERROR] Virtual environment not found.
    echo         Run setup.bat first.
    pause
    exit /b 1
)

call venv\Scripts\activate.bat

echo Starting Nexon Endpoint Agent...
python agent.py

if errorlevel 1 (
    echo.
    echo [ERROR] Agent crashed. Check the output above.
    pause
)
