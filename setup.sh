#!/bin/bash
# AI-BugBounty-Hunter — One-Click Setup Script (Linux/macOS)
# Usage: bash setup.sh

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}"
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║   AI-BugBounty-Hunter — Setup v1.0           ║"
echo "  ║   AI-Powered Bug Bounty Automation            ║"
echo "  ╚══════════════════════════════════════════════╝"
echo -e "${NC}"

# ── Python Check ────────────────────────────────────────────────
PYTHON_VERSION=$(python3 --version 2>&1 | awk '{print $2}')
PYTHON_MAJOR=$(echo $PYTHON_VERSION | cut -d. -f1)
PYTHON_MINOR=$(echo $PYTHON_VERSION | cut -d. -f2)

echo -e "${YELLOW}[*] Python version: $PYTHON_VERSION${NC}"

if [ "$PYTHON_MAJOR" -lt 3 ] || ([ "$PYTHON_MAJOR" -eq 3 ] && [ "$PYTHON_MINOR" -lt 9 ]); then
    echo -e "${RED}[✗] Python 3.9+ is required. Please upgrade Python.${NC}"
    exit 1
fi
echo -e "${GREEN}[✓] Python version OK${NC}"

# ── Create virtual environment ───────────────────────────────────
if [ ! -d ".venv" ]; then
    echo -e "${YELLOW}[*] Creating virtual environment...${NC}"
    python3 -m venv .venv
    echo -e "${GREEN}[✓] Virtual environment created (.venv)${NC}"
fi

# Activate venv
source .venv/bin/activate 2>/dev/null || true

# ── Install Python dependencies ──────────────────────────────────
echo -e "${YELLOW}[*] Installing Python dependencies...${NC}"
python3 -m pip install --upgrade pip -q
python3 -m pip install -r requirements.txt -q
echo -e "${GREEN}[✓] Python dependencies installed${NC}"

# ── Check external tools ─────────────────────────────────────────
echo ""
echo -e "${YELLOW}[*] Checking external security tools (optional)...${NC}"
echo "    These tools enhance capabilities but are not required."

TOOLS_STATUS=()
for tool in subfinder httpx nuclei katana ffuf nmap; do
    if command -v $tool &> /dev/null; then
        echo -e "  ${GREEN}[✓] $tool found: $(command -v $tool)${NC}"
    else
        echo -e "  ${YELLOW}[!] $tool not found — some features will be limited${NC}"
    fi
done

# ── Create directories ───────────────────────────────────────────
echo ""
echo -e "${YELLOW}[*] Creating directory structure...${NC}"
mkdir -p reports/output reports/templates logs findings_db wordlists
echo -e "${GREEN}[✓] Directories created${NC}"

# ── Config check ─────────────────────────────────────────────────
if [ ! -f "config.json" ]; then
    echo -e "${YELLOW}[!] config.json not found — using defaults${NC}"
else
    echo -e "${GREEN}[✓] config.json found${NC}"
fi

# ── Ollama check ─────────────────────────────────────────────────
echo ""
echo -e "${YELLOW}[*] Checking Ollama (free local AI)...${NC}"
if command -v ollama &> /dev/null; then
    echo -e "${GREEN}[✓] Ollama is installed${NC}"
    if ollama list 2>/dev/null | grep -q "llama"; then
        echo -e "${GREEN}[✓] Llama model available${NC}"
    else
        echo -e "${YELLOW}[!] No llama model found. Run: ollama pull llama3${NC}"
    fi
else
    echo -e "${YELLOW}[!] Ollama not found. To use free local AI:${NC}"
    echo -e "    ${CYAN}curl -fsSL https://ollama.com/install.sh | sh${NC}"
    echo -e "    ${CYAN}ollama pull llama3${NC}"
fi

# ── Done ─────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}"
echo "  ╔══════════════════════════════════════════════╗"
echo "  ║   ✓ Setup Complete!                          ║"
echo "  ╚══════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "Quick Start:"
echo -e "  ${CYAN}python3 cli.py example.com${NC}                          # Full pipeline"
echo -e "  ${CYAN}python3 cli.py example.com --quick${NC}                   # Passive recon only"
echo -e "  ${CYAN}python3 cli.py example.com --recon-only${NC}              # Recon only"
echo -e "  ${CYAN}python3 cli.py example.com --ai-provider openai${NC}      # Use OpenAI"
echo -e "  ${CYAN}python3 cli.py example.com --report --platform bugcrowd${NC}"
echo ""
echo -e "Set AI API key:"
echo -e "  ${CYAN}export AI_API_KEY=your-key-here${NC}"
echo ""
echo -e "Docs & Help:"
echo -e "  ${CYAN}python3 cli.py --help${NC}"
echo ""
