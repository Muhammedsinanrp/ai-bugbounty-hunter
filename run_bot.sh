#!/bin/bash
# AI-BugBounty-Hunter — Telegram Bot Launcher (Linux/macOS)
echo ""
echo "  ================================================"
echo "  |   AI-BugBounty-Hunter Telegram Bot           |"
echo "  ================================================"
echo ""

# Activate virtual environment if it exists
if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
fi

# Check for token
if [ -z "$TELEGRAM_BOT_TOKEN" ] && [ ! -f "bot_config.json" ]; then
    echo "  [!] No bot token found!"
    echo ""
    echo "  Option 1: Set environment variable"
    echo "    export TELEGRAM_BOT_TOKEN=1234567890:ABCdef..."
    echo ""
    echo "  Option 2: Edit bot_config.json"
    echo "    { \"telegram_token\": \"1234567890:ABCdef...\" }"
    echo ""
    exit 1
fi

echo "  [*] Starting bot..."
python3 telegram_bot.py
