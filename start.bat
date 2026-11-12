@echo off
REM CYBER ATTACK DETECTION SYSTEM launcher (Windows). Right-click -> "Run as administrator" if you want LIVE capture of your network.
cd /d "%~dp0backend"
if not exist .venv\Scripts\python.exe (
  echo Creating virtual environment and installing packages (first run only)...
  python -m venv .venv
  call .venv\Scripts\python.exe -m pip install -r requirements.txt
)
start "" http://localhost:8000
.venv\Scripts\python.exe -m uvicorn app.main:app --port 8000
