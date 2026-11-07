#!/usr/bin/env bash
# CTF Crypto Toolkit launcher for Linux / macOS (first run creates ./venv)
cd "$(dirname "$0")" || exit 1

PY=$(command -v python3 || command -v python)
if [ -z "$PY" ]; then
    echo "[x] Python 3 not found. Install it first (e.g. sudo apt install python3 python3-venv)."
    exit 1
fi

if [ ! -x venv/bin/python ]; then
    echo "[*] First run: creating virtual environment..."
    if ! "$PY" -m venv venv; then
        echo "[x] Could not create venv. On Debian/Ubuntu run: sudo apt install python3-venv"
        rm -rf venv
        exit 1
    fi
    venv/bin/python -m pip install --upgrade pip --quiet
    [ -f requirements.txt ] && venv/bin/python -m pip install -r requirements.txt --quiet
    echo "[+] Setup complete."
fi

exec venv/bin/python ctf_toolkit.py "$@"
