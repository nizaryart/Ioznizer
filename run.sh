#!/usr/bin/env bash
# Run the analyser inside the project virtual environment.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ ! -d venv ]; then
    echo "[ERROR] Project is not set up yet."
    echo
    echo "  Run ./setup.sh once to create the environment and install"
    echo "  dependencies, then try this command again."
    exit 1
fi

if [ ! -f .env ] && [ -f .env.example ]; then
    echo "[WARNING] No .env found; copying .env.example - add your API key to it."
    cp .env.example .env && chmod 600 .env
fi

# Surface a missing key here rather than after extraction has already run.
# The placeholder from .env.example also starts with sk-, so it must be
# excluded explicitly or it passes as a real key.
if ! grep -qE '^OPENROUTER_API_KEY=sk-' .env 2>/dev/null \
   || grep -q 'your-key-here' .env 2>/dev/null; then
    echo "[WARNING] No OpenRouter API key set in .env"
    echo "          Get one free at https://openrouter.ai/keys"
    echo "          Extraction and decompilation still run; AI analysis is skipped."
    echo
fi

source venv/bin/activate
exec python3 main.py "$@"
