#!/bin/bash
# Wrapper script to run the malware detector with virtual environment

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Activate virtual environment
if [ -d "venv" ]; then
    source venv/bin/activate
else
    echo "[ERROR] Virtual environment not found. Please run: python3 -m venv venv"
    exit 1
fi

# Run the main script
python3 main.py "$@"

