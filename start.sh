#!/usr/bin/env bash
# ==============================================================================
# Cyber Digital Twin - Linux/macOS One-Click Quickstart Launcher
# ==============================================================================

set -euo pipefail

echo "======================================================================"
echo "   AI-POWERED CYBER DIGITAL TWIN FOR LINUX"
echo "   One-Click Quickstart Launcher (Linux / macOS)"
echo "======================================================================"
echo ""

# 1. Verify Python
if ! command -v python3 &> /dev/null; then
    echo "[ERROR] Python 3 is not installed or not in PATH."
    exit 1
fi

# 2. Environment config
if [ ! -f ".env" ]; then
    echo "[*] Creating default local .env configuration..."
    cp .env.example .env
fi

# 3. Virtual environment (optional / recommended)
if [ ! -d "venv" ]; then
    echo "[*] Creating local virtualenv 'venv'..."
    python3 -m venv venv
fi

source venv/bin/activate || source venv/Scripts/activate || true

# 4. Dependencies
echo "[*] Ensuring dependencies are installed..."
pip install -r requirements.txt --quiet

# 5. System Status Check
echo "[*] Verifying platform subsystems..."
python manage.py status

# 6. Launch platform
echo ""
echo "======================================================================"
echo " Starting Cyber Digital Twin Backend API Server..."
echo " - Web Dashboard UI:              http://localhost:8000/"
echo " - Interactive Swagger API Docs:  http://localhost:8000/docs"
echo " - Press CTRL+C to stop the server"
echo "======================================================================"
echo ""

python manage.py run --host 0.0.0.0 --port 8000
