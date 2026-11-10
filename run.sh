#!/usr/bin/env bash
# Secure Code Analyzer - Linux / macOS launcher:  ./run.sh
set -e
cd "$(dirname "$0")"

PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "Python 3.10 or newer is required."
    exit 1
fi

if [ ! -x ".venv/bin/python" ]; then
    echo "Creating the virtual environment (first run only)..."
    "$PYTHON" -m venv .venv
fi

echo "Installing the requirements (first run takes a few minutes)..."
.venv/bin/python -m pip install --quiet --upgrade pip
.venv/bin/python -m pip install --quiet -r requirements.txt

exec .venv/bin/python -m sca ui
