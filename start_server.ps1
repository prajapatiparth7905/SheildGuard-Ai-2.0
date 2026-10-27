# PowerShell Launcher for ShieldGuard AI 2.0
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "      🛡️ SHIELDGUARD AI 2.0 - CYBER THREAT DEFENSE PLATFORM" -ForegroundColor Cyan
Write-Host "         Academic Final Year Project Demonstration" -ForegroundColor Cyan
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "[1/3] Checking Python installation..." -ForegroundColor Yellow
python --version

Write-Host "[2/3] Checking Python dependencies..." -ForegroundColor Yellow
pip install -r requirements.txt --quiet

Write-Host "[3/3] Launching FastAPI Backend Server at http://127.0.0.1:8000 ..." -ForegroundColor Green
Write-Host "[i] Interactive Swagger API Docs at http://127.0.0.1:8000/docs" -ForegroundColor Green
Write-Host ""

python run.py
