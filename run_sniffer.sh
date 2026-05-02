#!/bin/bash
# run_sniffer.sh — Always uses the correct venv Python with sudo

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PYTHON="$SCRIPT_DIR/venv/bin/python3"
SNIFFER="$SCRIPT_DIR/sniffer.py"

if [ ! -f "$PYTHON" ]; then
    echo "❌ Virtual environment not found. Run: python3 -m venv venv && pip install -r requirements.txt"
    exit 1
fi

echo "🛡️  Starting sniffer with correct Python: $PYTHON"
sudo "$PYTHON" "$SNIFFER"
