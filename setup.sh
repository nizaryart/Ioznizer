#!/usr/bin/env bash
#
# One-command setup for Ioznizer.
#
#   ./setup.sh                 install Python deps, check system tools
#   ./setup.sh --with-ghidra   also download and verify Ghidra locally
#   ./setup.sh --check         report what is present, change nothing
#
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Pinned release. The checksum is published by the NSA on the release page and
# is verified before the archive is extracted; a mismatch aborts the install.
GHIDRA_VERSION="12.1.2"
GHIDRA_ZIP="ghidra_${GHIDRA_VERSION}_PUBLIC_20260605.zip"
GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/${GHIDRA_ZIP}"
GHIDRA_SHA256="b62e81a0390618466c019c60d8c2f796ced2509c4c1aea4a37644a77272cf99d"
GHIDRA_DIR="$SCRIPT_DIR/ghidra/ghidra_${GHIDRA_VERSION}_PUBLIC"

WITH_GHIDRA=0
CHECK_ONLY=0
for arg in "$@"; do
    case "$arg" in
        --with-ghidra) WITH_GHIDRA=1 ;;
        --check)       CHECK_ONLY=1 ;;
        -h|--help)     sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Unknown option: $arg (try --help)"; exit 1 ;;
    esac
done

ok()   { printf '  \033[32m✓\033[0m %s\n' "$1"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$1"; }
bad()  { printf '  \033[31m✗\033[0m %s\n' "$1"; }
head_() { printf '\n\033[1m%s\033[0m\n' "$1"; }

MISSING_REQUIRED=0

# --------------------------------------------------------------------------
head_ "System tools"

if command -v python3 >/dev/null 2>&1; then
    PYV=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
    if python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3,9) else 1)'; then
        ok "python3 $PYV"
    else
        bad "python3 $PYV (3.9+ required)"; MISSING_REQUIRED=1
    fi
else
    bad "python3 not found"; MISSING_REQUIRED=1
fi

BINUTILS_MISSING=()
for tool in readelf objdump strings; do
    if command -v "$tool" >/dev/null 2>&1; then
        ok "$tool"
    else
        bad "$tool"; BINUTILS_MISSING+=("$tool")
    fi
done

if [ ${#BINUTILS_MISSING[@]} -gt 0 ]; then
    MISSING_REQUIRED=1
    if   command -v apt-get >/dev/null 2>&1; then warn "install with: sudo apt-get install binutils"
    elif command -v dnf     >/dev/null 2>&1; then warn "install with: sudo dnf install binutils"
    elif command -v pacman  >/dev/null 2>&1; then warn "install with: sudo pacman -S binutils"
    elif command -v brew    >/dev/null 2>&1; then warn "install with: brew install binutils"
    else warn "install your distribution's binutils package"
    fi
fi

if command -v bwrap >/dev/null 2>&1; then
    ok "bwrap (decompiler will run sandboxed)"
else
    warn "bwrap not found - decompilation runs unsandboxed (apt install bubblewrap)"
fi

# --------------------------------------------------------------------------
head_ "Decompiler"

DECOMPILER_FOUND=0
GHIDRA_FOUND_AT=""

# GHIDRA_HOME may only be recorded in .env rather than exported in this shell.
ENV_GHIDRA=""
if [ -f .env ]; then
    ENV_GHIDRA=$(grep -E '^GHIDRA_HOME=' .env 2>/dev/null | tail -1 | cut -d= -f2-)
fi

# Installations are commonly version-suffixed (ghidra_12.1.2_PUBLIC), so the
# well-known locations have to be globbed rather than matched literally.
for candidate in \
    "${GHIDRA_HOME:-}/support/analyzeHeadless" \
    "${ENV_GHIDRA:-}/support/analyzeHeadless" \
    "$GHIDRA_DIR/support/analyzeHeadless" \
    /opt/ghidra*/support/analyzeHeadless \
    "$HOME"/ghidra*/support/analyzeHeadless \
    /usr/share/ghidra/support/analyzeHeadless
do
    if [ -n "$candidate" ] && [ -f "$candidate" ]; then
        GHIDRA_FOUND_AT="$(dirname "$(dirname "$candidate")")"
        break
    fi
done

if [ -z "$GHIDRA_FOUND_AT" ] && command -v analyzeHeadless >/dev/null 2>&1; then
    GHIDRA_FOUND_AT="$(dirname "$(dirname "$(command -v analyzeHeadless)")")"
fi

if [ -n "$GHIDRA_FOUND_AT" ]; then
    ok "Ghidra at $GHIDRA_FOUND_AT"
    DECOMPILER_FOUND=1
elif command -v r2 >/dev/null 2>&1 || command -v radare2 >/dev/null 2>&1; then
    warn "Ghidra not found; radare2 will be used (lower quality decompilation)"
    DECOMPILER_FOUND=1
else
    bad "no decompiler found"
    warn "run ./setup.sh --with-ghidra, or: sudo apt install radare2"
fi

if command -v java >/dev/null 2>&1; then
    # Greedy matching on the version line silently yields an empty string;
    # split on the quoted version instead.
    JV=$(java -version 2>&1 | awk -F'"' '/version/{split($2,a,"."); print a[1]; exit}')
    if [ "${JV:-0}" -eq 21 ] 2>/dev/null; then
        ok "java $JV"
    elif [ "${JV:-0}" -gt 21 ] 2>/dev/null; then
        ok "java $JV"
        warn "Ghidra targets JDK 21; if it refuses to start, pin it with:"
        warn "  echo 'JAVA_HOME_OVERRIDE=/usr/lib/jvm/java-21-openjdk-amd64' >> \\"
        warn "    \"\$GHIDRA_HOME/support/launch.properties\""
    else
        warn "java $JV found, Ghidra needs 21+ (sudo apt install openjdk-21-jdk)"
    fi
elif [ -n "$GHIDRA_FOUND_AT" ]; then
    warn "java not found - Ghidra needs JDK 21 (sudo apt install openjdk-21-jdk)"
fi

# --------------------------------------------------------------------------
if [ "$CHECK_ONLY" -eq 1 ]; then
    head_ "Python environment"
    [ -d venv ] && ok "venv present" || warn "venv not created (run ./setup.sh)"
    [ -f .env ] && ok ".env present" || warn ".env not created (run ./setup.sh)"
    echo
    exit $MISSING_REQUIRED
fi

# --------------------------------------------------------------------------
head_ "Python environment"

if [ ! -d venv ]; then
    echo "  creating virtual environment..."
    python3 -m venv venv || { bad "could not create venv"; exit 1; }
fi
ok "venv"

echo "  installing dependencies..."
if ./venv/bin/pip install -q --upgrade pip >/dev/null 2>&1 && \
   ./venv/bin/pip install -q -r requirements.txt; then
    ok "dependencies installed"
else
    bad "dependency installation failed - check your network connection"
    exit 1
fi

# --------------------------------------------------------------------------
if [ "$WITH_GHIDRA" -eq 1 ] && [ -z "$GHIDRA_FOUND_AT" ]; then
    head_ "Ghidra"
    echo "  This downloads roughly 1 GB from github.com/NationalSecurityAgency."
    read -r -p "  Continue? [y/N] " reply
    if [[ "$reply" =~ ^[Yy]$ ]]; then
        mkdir -p ghidra && cd ghidra
        echo "  downloading ${GHIDRA_ZIP}..."
        if curl -fL --progress-bar -o "$GHIDRA_ZIP" "$GHIDRA_URL"; then
            echo "  verifying checksum..."
            actual=$(sha256sum "$GHIDRA_ZIP" | cut -d' ' -f1)
            if [ "$actual" = "$GHIDRA_SHA256" ]; then
                ok "checksum verified"
                unzip -q "$GHIDRA_ZIP" && rm -f "$GHIDRA_ZIP"
                GHIDRA_FOUND_AT="$GHIDRA_DIR"
                ok "installed to $GHIDRA_DIR"
            else
                bad "checksum mismatch - refusing to extract"
                warn "expected: $GHIDRA_SHA256"
                warn "actual:   $actual"
                rm -f "$GHIDRA_ZIP"
            fi
        else
            bad "download failed"
        fi
        cd "$SCRIPT_DIR"
    else
        warn "skipped"
    fi
fi

# --------------------------------------------------------------------------
head_ "Configuration"

if [ ! -f .env ]; then
    cp .env.example .env
    chmod 600 .env
    ok ".env created from .env.example"
else
    ok ".env already exists (left unchanged)"
fi

if [ -n "$GHIDRA_FOUND_AT" ] && ! grep -q '^GHIDRA_HOME=' .env 2>/dev/null; then
    echo "GHIDRA_HOME=$GHIDRA_FOUND_AT" >> .env
    ok "GHIDRA_HOME recorded in .env"
fi

# --------------------------------------------------------------------------
# API key. Prompted only when one is not already configured, and only when a
# terminal is attached so that scripted installs are unaffected.
if grep -q 'your-key-here' .env 2>/dev/null && [ -t 0 ]; then
    head_ "OpenRouter API key"
    echo "  Needed for the AI analysis stage. Free keys: https://openrouter.ai/keys"
    echo "  Input is hidden. Press Enter to skip - extraction and decompilation"
    echo "  work without it, only the AI stage is disabled."
    echo
    read -r -s -p "  Paste your key: " USER_KEY
    echo

    if [ -z "$USER_KEY" ]; then
        warn "skipped - add OPENROUTER_API_KEY to .env when you have one"
    elif [[ ! "$USER_KEY" =~ ^sk-or-v1-[A-Za-z0-9]{16,}$ ]]; then
        bad "that does not look like an OpenRouter key (expected sk-or-v1-...)"
        warn "nothing written; edit .env by hand to set it"
    else
        if command -v curl >/dev/null 2>&1; then
            echo "  verifying..."
            code=$(curl -s -o /dev/null -w '%{http_code}' \
                   https://openrouter.ai/api/v1/key \
                   -H "Authorization: Bearer $USER_KEY" 2>/dev/null)
            case "$code" in
                200) ok "key accepted by OpenRouter" ;;
                401) bad "OpenRouter rejected this key (401)"
                     warn "saving anyway - check it at https://openrouter.ai/keys" ;;
                *)   warn "could not verify (HTTP ${code:-none}); saving anyway" ;;
            esac
        fi

        # Key charset is [A-Za-z0-9-], so a | delimiter is safe here.
        sed -i "s|^OPENROUTER_API_KEY=.*|OPENROUTER_API_KEY=$USER_KEY|" .env
        chmod 600 .env
        ok "key saved to .env (not tracked by git)"
    fi

    CURRENT_MODEL=$(grep -E '^OPENROUTER_MODEL=' .env | tail -1 | cut -d= -f2-)
    echo
    echo "  Model: ${CURRENT_MODEL:-<unset>}"
    echo "  Press Enter to keep it, or paste another OpenRouter model slug."
    read -r -p "  Model: " USER_MODEL
    if [ -n "$USER_MODEL" ]; then
        sed -i "s|^OPENROUTER_MODEL=.*|OPENROUTER_MODEL=$USER_MODEL|" .env
        ok "model set to $USER_MODEL"
    fi
fi

# --------------------------------------------------------------------------
head_ "Next steps"

if grep -q 'your-key-here' .env 2>/dev/null; then
    echo "  1. Add your OpenRouter API key to .env"
    echo "     Get one free at https://openrouter.ai/keys"
    echo
    echo "  2. Run an analysis:"
else
    echo "  Run an analysis:"
fi
echo "       ./run.sh samples/time              # benign control sample"
echo "       ./run.sh samples/your_sample.elf   # your own binary"
echo

[ "$DECOMPILER_FOUND" -eq 1 ] || warn "without a decompiler, analysis falls back to disassembly only"
exit 0
