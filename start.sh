#!/usr/bin/env bash
# CYBER ATTACK DETECTION SYSTEM launcher (Linux/macOS). Use `sudo ./start.sh` for LIVE capture of your network.
set -e
cd "$(dirname "$0")/backend"
if [ ! -d .venv ]; then
  echo "Creating virtual environment and installing packages (first run only)..."
  python3 -m venv .venv
  .venv/bin/pip install -r requirements.txt
fi
(sleep 2; xdg-open http://localhost:8000 2>/dev/null || open http://localhost:8000 2>/dev/null || true) &
exec .venv/bin/python -m uvicorn app.main:app --port 8000
