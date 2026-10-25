#!/usr/bin/env bash
# ==============================================================================
# KRYPT CLI — Upstream Integrations Setup Script
# Clones and installs theHarvester, Photon, TorBot, and ARES into isolated venvs.
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

VENDOR_DIR="${ROOT_DIR}/integrations/vendor"
VENVS_DIR="${ROOT_DIR}/integrations/venvs"

mkdir -p "${VENDOR_DIR}"
mkdir -p "${VENVS_DIR}"

echo "=================================================="
echo "KRYPT CLI: Setting up Upstream Tool Integrations"
echo "=================================================="

# 1. theHarvester
HARVESTER_DIR="${VENDOR_DIR}/theHarvester"
HARVESTER_COMMIT="6790b147f52309e4eee22ed941db1d285ab2ec23"
if [ ! -d "${HARVESTER_DIR}" ]; then
    echo "[+] Cloning theHarvester (master)..."
    git clone https://github.com/laramies/theHarvester.git "${HARVESTER_DIR}"
    git -C "${HARVESTER_DIR}" checkout "${HARVESTER_COMMIT}"
fi
if [ ! -d "${VENVS_DIR}/theHarvester" ]; then
    echo "[+] Setting up theHarvester virtual environment (Python 3.14+ required)..."
    PY314="$(which python3.14 || echo "${HOME}/.local/bin/python3.14")"
    if [ ! -x "${PY314}" ]; then
        echo "[-] Python 3.14 not found. Please install Python 3.14 for theHarvester."
    else
        "${PY314}" -m venv "${VENVS_DIR}/theHarvester"
        "${VENVS_DIR}/theHarvester/bin/pip" install --upgrade pip
        "${VENVS_DIR}/theHarvester/bin/pip" install -e "${HARVESTER_DIR}"
    fi
fi

# 2. Photon
PHOTON_DIR="${VENDOR_DIR}/Photon"
PHOTON_COMMIT="c8d2566841d69a268b244609921143d84b72b0c6"
if [ ! -d "${PHOTON_DIR}" ]; then
    echo "[+] Cloning Photon (master)..."
    git clone https://github.com/s0md3v/Photon.git "${PHOTON_DIR}"
    git -C "${PHOTON_DIR}" checkout "${PHOTON_COMMIT}"
fi
if [ ! -d "${VENVS_DIR}/photon" ]; then
    echo "[+] Setting up Photon virtual environment (Python 3.11)..."
    python3.11 -m venv "${VENVS_DIR}/photon"
    "${VENVS_DIR}/photon/bin/pip" install --upgrade pip
    "${VENVS_DIR}/photon/bin/pip" install -r "${PHOTON_DIR}/requirements.txt"
fi

# 3. TorBot
TORBOT_DIR="${VENDOR_DIR}/TorBot"
TORBOT_COMMIT="1cc500ff2bae6c2cce3a3accd3e55a9c69f51034"
if [ ! -d "${TORBOT_DIR}" ]; then
    echo "[+] Cloning TorBot (dev)..."
    git clone -b dev https://github.com/DedSecInside/TorBot.git "${TORBOT_DIR}"
    git -C "${TORBOT_DIR}" checkout "${TORBOT_COMMIT}"
fi
if [ ! -d "${VENVS_DIR}/torbot" ]; then
    echo "[+] Setting up TorBot virtual environment (Python 3.12)..."
    python3.12 -m venv "${VENVS_DIR}/torbot"
    "${VENVS_DIR}/torbot/bin/pip" install --upgrade pip
    "${VENVS_DIR}/torbot/bin/pip" install -e "${TORBOT_DIR}"
fi

# 4. ARES
ARES_DIR="${VENDOR_DIR}/ARES"
ARES_COMMIT="3e1a9dd5137cc778b19a0aae6cd4218853f4f603"
if [ ! -d "${ARES_DIR}" ]; then
    echo "[+] Cloning ARES (main)..."
    git clone https://github.com/Mafifrizi/ARES.git "${ARES_DIR}"
    git -C "${ARES_DIR}" checkout "${ARES_COMMIT}"
fi
if [ ! -d "${VENVS_DIR}/ares" ]; then
    echo "[+] Setting up ARES virtual environment (Python 3.11)..."
    python3.11 -m venv "${VENVS_DIR}/ares"
    "${VENVS_DIR}/ares/bin/pip" install --upgrade pip
    "${VENVS_DIR}/ares/bin/pip" install -e "${ARES_DIR}"
fi

echo "=================================================="
echo "[✓] Upstream Tool Integrations Setup Completed!"
echo "Run: krypt tools doctor"
echo "=================================================="
