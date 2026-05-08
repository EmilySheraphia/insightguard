@echo off
setlocal

echo.
echo  ================================================
echo   Nexon Technologies - Endpoint Agent Setup
echo  ================================================
echo.

REM Check Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Install Python 3.10+ from https://python.org
    echo         Make sure to tick "Add to PATH" during install.
    pause
    exit /b 1
)

echo [OK] Python found:
python --version

echo.
echo [STEP 1] Creating virtual environment...
python -m venv venv
if errorlevel 1 (
    echo [ERROR] Failed to create virtual environment.
    pause
    exit /b 1
)
echo [OK] Virtual environment created.

echo.
echo [STEP 2] Activating virtual environment...
call venv\Scripts\activate.bat

echo.
echo [STEP 3] Upgrading pip...
python -m pip install --upgrade pip --quiet

echo.
echo [STEP 4] Installing dependencies...
pip install -r requirements.txt
if errorlevel 1 (
    echo [WARN] Some packages failed. pywin32 requires Windows — OK on Windows machines.
)

echo.
echo [STEP 5] Post-install pywin32 setup (Windows)...
python venv\Scripts\pywin32_postinstall.py -install >nul 2>&1
echo [OK] pywin32 configured (or not needed).

echo.
echo  ================================================
echo   Setup Complete!
echo  ================================================
echo.
echo  NEXT STEPS:
echo  1. Edit config.json:
echo     - Set "server_url" to your InsightGuard server IP
echo       e.g. "http://192.168.1.10:5000"
echo     - Set "user_id" to the employee ID (e.g. "EMP042")
echo     - Set "name", "department", "role" for this employee
echo     - Set "device_id" to identify this laptop
echo.
echo  2. Make sure InsightGuard is running on the other machine.
echo     It must be reachable from this laptop on the network.
echo.
echo  3. Run start_agent.bat to launch the agent.
echo.
pause
