#!/bin/bash
# AI-BugBounty-Hunter — Linux System Install Script
# Installs tool system-wide so you can run:
#   bugbounty example.com
#   bugbot
# from ANYWHERE on your system.
# Usage: sudo bash install_linux.sh

set -e
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'

TOOL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_MODE="user"  # "user" (no sudo) or "system" (with sudo)

echo -e "${CYAN}"
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║   AI-BugBounty-Hunter — Linux Installer      ║"
echo "  ╚══════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Check Python ─────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}[✗] Python3 not found. Install it first.${NC}"
    exit 1
fi
PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo -e "${GREEN}[+] Python ${PY_VER} found${NC}"

# ── Create virtual environment ─────────────────────────────────────
if [ ! -d "$TOOL_DIR/.venv" ]; then
    echo -e "${YELLOW}[*] Creating virtual environment...${NC}"
    python3 -m venv "$TOOL_DIR/.venv"
fi
source "$TOOL_DIR/.venv/bin/activate"
echo -e "${GREEN}[+] Virtual environment ready${NC}"

# ── Install Python dependencies ────────────────────────────────────
echo -e "${YELLOW}[*] Installing dependencies...${NC}"
pip install -q --upgrade pip
pip install -q -r "$TOOL_DIR/requirements.txt"
echo -e "${GREEN}[+] Dependencies installed${NC}"

# ── Create wrapper scripts in /usr/local/bin ───────────────────────
VENV_PYTHON="$TOOL_DIR/.venv/bin/python3"

create_wrapper() {
    local CMD=$1
    local SCRIPT=$2
    local TARGET

    # Try /usr/local/bin (system) or ~/.local/bin (user)
    if [ -w "/usr/local/bin" ] || [ "$(id -u)" = "0" ]; then
        TARGET="/usr/local/bin/$CMD"
    else
        mkdir -p "$HOME/.local/bin"
        TARGET="$HOME/.local/bin/$CMD"
        INSTALL_MODE="user"
    fi

    cat > "$TARGET" << EOF
#!/bin/bash
# AI-BugBounty-Hunter wrapper: $CMD
export PYTHONUTF8=1
export PYTHONIOENCODING=utf-8
source "$TOOL_DIR/.venv/bin/activate" 2>/dev/null || true
exec "$VENV_PYTHON" "$TOOL_DIR/$SCRIPT" "\$@"
EOF
    chmod +x "$TARGET"
    echo -e "${GREEN}[+] Installed: $TARGET${NC}"
}

echo -e "${YELLOW}[*] Installing system commands...${NC}"
create_wrapper "bugbounty" "cli.py"
create_wrapper "bugbot"    "telegram_bot.py"
create_wrapper "bugmain"   "main.py"

# ── Create systemd service for the bot ────────────────────────────
if command -v systemctl &>/dev/null && [ "$(id -u)" = "0" ]; then
    SERVICE_FILE="/etc/systemd/system/bugbounty-bot.service"
    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=AI-BugBounty-Hunter Telegram Bot
After=network.target

[Service]
Type=simple
User=$(logname 2>/dev/null || echo $SUDO_USER || echo $USER)
WorkingDirectory=$TOOL_DIR
Environment=PYTHONUTF8=1
Environment=PYTHONIOENCODING=utf-8
EnvironmentFile=-$TOOL_DIR/.env
ExecStart=$VENV_PYTHON $TOOL_DIR/telegram_bot.py
Restart=on-failure
RestartSec=5
StandardOutput=append:$TOOL_DIR/logs/bot.log
StandardError=append:$TOOL_DIR/logs/bot.log

[Install]
WantedBy=multi-user.target
EOF
    systemctl daemon-reload
    echo -e "${GREEN}[+] Systemd service created: bugbounty-bot.service${NC}"
    echo -e "${YELLOW}    Enable with: systemctl enable --now bugbounty-bot${NC}"
fi

# ── Create .env template ───────────────────────────────────────────
if [ ! -f "$TOOL_DIR/.env" ]; then
    cat > "$TOOL_DIR/.env" << 'EOF'
# AI-BugBounty-Hunter Environment Config
TELEGRAM_BOT_TOKEN=
TELEGRAM_ALLOWED_USERS=
AI_API_KEY=
PYTHONUTF8=1
PYTHONIOENCODING=utf-8
EOF
    echo -e "${GREEN}[+] Created .env template${NC}"
fi

# ── PATH reminder ──────────────────────────────────────────────────
if [ "$INSTALL_MODE" = "user" ]; then
    echo ""
    echo -e "${YELLOW}[!] Commands installed to ~/.local/bin${NC}"
    if ! echo "$PATH" | grep -q "$HOME/.local/bin"; then
        echo -e "${YELLOW}    Add to your shell config:${NC}"
        echo -e "    ${CYAN}echo 'export PATH=\"\$HOME/.local/bin:\$PATH\"' >> ~/.bashrc && source ~/.bashrc${NC}"
    fi
fi

# ── Done ──────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}"
echo "  ╔══════════════════════════════════════════════════════╗"
echo "  ║   Installation Complete!                             ║"
echo "  ╚══════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo "  COMMANDS NOW AVAILABLE ANYWHERE:"
echo ""
echo -e "  ${CYAN}bugbounty example.com${NC}             # Full AI scan"
echo -e "  ${CYAN}bugbounty example.com --quick${NC}     # Passive recon"
echo -e "  ${CYAN}bugbounty example.com --help${NC}      # All options"
echo ""
echo -e "  ${CYAN}bugbot${NC}                            # Start Telegram bot"
echo -e "  ${CYAN}export TELEGRAM_BOT_TOKEN=your-token${NC}"
echo -e "  ${CYAN}bugbot${NC}"
echo ""
echo "  SET API KEY:"
echo -e "  ${CYAN}export AI_API_KEY=your-openai-key${NC}"
echo ""
if command -v systemctl &>/dev/null && [ "$(id -u)" = "0" ]; then
    echo "  RUN BOT AS SERVICE (24/7):"
    echo -e "  ${CYAN}nano $TOOL_DIR/.env               # Add TELEGRAM_BOT_TOKEN=${NC}"
    echo -e "  ${CYAN}systemctl enable --now bugbounty-bot${NC}"
    echo -e "  ${CYAN}systemctl status bugbounty-bot${NC}"
    echo ""
fi
