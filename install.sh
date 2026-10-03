#!/usr/bin/env bash
set -e

echo "============================================================"
echo "          KRYPT CLI Installer (macOS & Linux)"
echo "   OSINT • RECON • DISCOVER • ASSESS"
echo "   Created by Gaddam Manyu (@manoharmanyu)"
echo "============================================================"

# 1. Detect Python
PYTHON_CMD=""
if command -v python3.11 >/dev/null 2>&1; then
    PYTHON_CMD="python3.11"
elif command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_CMD="python"
else
    echo "[ERROR] Python 3 is required but was not found on your PATH."
    exit 1
fi

PY_VERSION=$($PYTHON_CMD -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "[+] Detected Python: $($PYTHON_CMD --version) at $(which $PYTHON_CMD)"

# 2. Create virtual environment
if [ ! -d ".venv" ]; then
    echo "[+] Creating virtual environment (.venv)..."
    $PYTHON_CMD -m venv .venv
fi

# 3. Activate venv
echo "[+] Activating virtual environment..."
source .venv/bin/activate

# 4. Upgrade pip and install dependencies
echo "[+] Installing core dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

# 5. Install krypt-cli in editable mode
echo "[+] Installing krypt-cli in editable mode..."
pip install --no-build-isolation -e .

echo "============================================================"
echo "[+] Running KRYPT System Diagnostics (krypt doctor)..."
echo "============================================================"
krypt doctor

echo "============================================================"
echo "[+] Installation Successful!"
echo ""
echo "To get started:"
echo "  1. source .venv/bin/activate"
echo "  2. krypt --help"
echo "  3. krypt lab start"
echo "  4. krypt target add http://127.0.0.1:8888"
echo "  5. krypt scan http://127.0.0.1:8888 --all"
echo "============================================================"
