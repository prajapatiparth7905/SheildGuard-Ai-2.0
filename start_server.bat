@echo off
title ShieldGuard AI 2.0 - Spam, Scam & Phishing Threat Intelligence Platform
color 0B
echo ==============================================================================
echo       🛡️ SHIELDGUARD AI 2.0 - CYBER THREAT DEFENSE PLATFORM
echo          Academic Final Year Project Demonstration
echo ==============================================================================
echo.
echo [1/3] Checking Python installation...
python --version
if %errorlevel% neq 0 (
    echo [!] Python is not installed or not in PATH! Please install Python 3.9+.
    pause
    exit /b 1
)

echo.
echo [2/3] Verifying dependencies...
pip install -r requirements.txt --quiet

echo.
echo [3/3] Launching FastAPI Backend Server at http://127.0.0.1:8000 ...
echo [i] Interactive Swagger API Docs: http://127.0.0.1:8000/docs
echo.
python run.py
pause
