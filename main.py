#!/usr/bin/env python3
"""
AI-BugBounty-Hunter — Unified Entry Point
Detects how it was invoked and routes to the correct interface:
  - As CLI:       python main.py <domain> [options]
  - As Bot:       python main.py --bot
  - As API:       python main.py --api
  - Installed:    bugbounty <domain>  |  bugbot
"""
import sys
import os

# ── Cross-platform encoding fix ───────────────────────────────────────────────
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
os.environ.setdefault("PYTHONUTF8", "1")
os.environ.setdefault("PYTHONIOENCODING", "utf-8")

# ── Add project root to path ──────────────────────────────────────────────────
from pathlib import Path
ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT))


def main_cli():
    """Entry point for the 'bugbounty' command (CLI)."""
    # Route all args to cli.py
    import asyncio
    from cli import main
    asyncio.run(main())


def main_bot():
    """Entry point for the 'bugbot' command (Telegram bot)."""
    import json

    TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
    ALLOWED_STR = os.getenv("TELEGRAM_ALLOWED_USERS", "")

    if not TOKEN:
        cfg_path = ROOT / "bot_config.json"
        if cfg_path.exists():
            with open(cfg_path, encoding="utf-8") as f:
                bot_cfg = json.load(f)
            TOKEN = bot_cfg.get("telegram_token", "")
            allowed_list = bot_cfg.get("allowed_user_ids", [])
            if allowed_list:
                ALLOWED_STR = ",".join(str(x) for x in allowed_list)

    if not TOKEN and len(sys.argv) > 1:
        TOKEN = sys.argv[1]

    if not TOKEN:
        print("\n  ERROR: No bot token found.")
        print("  Options:")
        print("    export TELEGRAM_BOT_TOKEN=your-token   (Linux/macOS)")
        print("    set TELEGRAM_BOT_TOKEN=your-token      (Windows)")
        print("    Edit bot_config.json")
        print("    bugbot YOUR_TOKEN\n")
        sys.exit(1)

    allowed_ids = []
    if ALLOWED_STR:
        try:
            allowed_ids = [int(x.strip()) for x in ALLOWED_STR.split(",") if x.strip()]
        except ValueError:
            pass

    from telegram_bot import run_bot
    run_bot(TOKEN, allowed_ids)


def main():
    """Smart router — detect mode from arguments."""
    args = sys.argv[1:]

    # ── Bot mode ──────────────────────────────────────────────────
    if "--bot" in args or "-b" in args:
        sys.argv = [sys.argv[0]] + [a for a in args if a not in ("--bot", "-b")]
        main_bot()
        return

    # ── Version ───────────────────────────────────────────────────
    if "--version" in args or "-v" in args[:1]:
        print("AI-BugBounty-Hunter v1.0.0")
        return

    # ── No args → show help ───────────────────────────────────────
    if not args:
        _print_main_help()
        return

    # ── Default: CLI mode ─────────────────────────────────────────
    main_cli()


def _print_main_help():
    print("""
  ╔══════════════════════════════════════════════════════╗
  ║       AI-BugBounty-Hunter v1.0                       ║
  ║   AI-Powered Bug Bounty Automation Platform          ║
  ╚══════════════════════════════════════════════════════╝

  USAGE:
    bugbounty <domain> [options]     CLI scan
    bugbounty --bot                  Start Telegram bot
    python main.py <domain>          Same as above

  QUICK EXAMPLES:
    bugbounty example.com                        Full pipeline
    bugbounty example.com --quick                Passive recon only
    bugbounty example.com --recon-only           Recon, no scan
    bugbounty example.com --ai-provider openai   Use OpenAI
    bugbounty example.com --stealth              Stealth mode
    bugbounty example.com --report               Generate report
    bugbounty --bot                              Start Telegram bot

  RUN BOT:
    export TELEGRAM_BOT_TOKEN=your-token
    bugbot                                       (if installed)
    python telegram_bot.py                       (direct)
    bash run_bot.sh                              (Linux script)
    run_bot.bat                                  (Windows script)

  INSTALL (system-wide):
    pip install -e .
    # Then use anywhere:
    bugbounty example.com
    bugbot

  CONFIG:
    Edit config.json to set AI provider, API keys, and scan settings.
    See README.md for full documentation.
""")


if __name__ == "__main__":
    main()
