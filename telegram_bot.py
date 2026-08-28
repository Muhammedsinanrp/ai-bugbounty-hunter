#!/usr/bin/env python3
"""
AI-BugBounty-Hunter — Telegram Bot Integration
Full-control Telegram bot: start scans, live progress, findings alerts, report delivery.

Commands:
  /start       — Welcome + help
  /scan <domain> — Start full pipeline scan
  /quick <domain> — Quick passive recon only
  /recon <domain> — Recon only (no scanning)
  /status      — Show current scan status
  /findings    — List latest findings from DB
  /report      — Send latest report file
  /cancel      — Cancel running scan
  /config      — Show current config
  /setprovider <openai|anthropic|groq|ollama> — Switch AI provider
  /setkey <api_key> — Set AI API key
  /help        — Show all commands
"""
import asyncio
import json
import os
import sys
import traceback

# Fix Windows console encoding (must be before any output)
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
    os.environ["PYTHONIOENCODING"] = "utf-8"
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any

# Telegram
from telegram import (
    Update, InlineKeyboardButton, InlineKeyboardMarkup,
    BotCommand, Document
)
from telegram.ext import (
    Application, CommandHandler, CallbackQueryHandler,
    ContextTypes, MessageHandler, filters
)
from telegram.constants import ParseMode

# Project modules
sys.path.insert(0, str(Path(__file__).parent))
from core.config import Config
from core.agent import AIAgent
from core.database import FindingsDB
from core.logger import Logger


# ── Globals ──────────────────────────────────────────────────────────────────
logger = Logger("TelegramBot")
config = Config()
db = FindingsDB()
active_scan: Optional[asyncio.Task] = None
scan_status: Dict[str, Any] = {"phase": "idle", "percentage": 0, "target": ""}

SEVERITY_EMOJI = {
    "critical": "🔴", "high": "🟠", "medium": "🟡",
    "low": "🔵", "info": "⚪"
}

# Authorized user IDs (set in config or TELEGRAM_ALLOWED_USERS env var)
ALLOWED_USERS: list = []


# ── Authorization ─────────────────────────────────────────────────────────────
def is_authorized(user_id: int) -> bool:
    """Check if user is allowed to use the bot."""
    if not ALLOWED_USERS:
        return True  # Open to all if no restrictions set
    return user_id in ALLOWED_USERS


def auth_required(func):
    """Decorator to enforce authorization."""
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
        user_id = update.effective_user.id
        if not is_authorized(user_id):
            await update.message.reply_text(
                "⛔ *Access Denied*\n\nYou are not authorized to use this bot.",
                parse_mode=ParseMode.MARKDOWN,
            )
            logger.warning(f"Unauthorized access attempt from user {user_id}")
            return
        return await func(update, context)
    return wrapper


# ── /start ────────────────────────────────────────────────────────────────────
@auth_required
async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user = update.effective_user
    text = (
        f"👋 *Welcome, {user.first_name}!*\n\n"
        "🎯 *AI\\-BugBounty\\-Hunter Bot* — Your AI\\-powered bug bounty assistant\\.\n\n"
        "I can:\n"
        "• 🔍 Run full vulnerability scans\n"
        "• 📡 Do passive recon \\(safe, no active scanning\\)\n"
        "• 🤖 Use AI to analyze \\& validate findings\n"
        "• 📝 Generate submission\\-ready reports\n"
        "• 📤 Send you reports as files\n\n"
        "Use /help to see all available commands\\."
    )
    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton("📖 Help", callback_data="help"),
         InlineKeyboardButton("⚙️ Config", callback_data="config")],
        [InlineKeyboardButton("📊 Findings", callback_data="findings"),
         InlineKeyboardButton("📄 Report", callback_data="report")],
    ])
    await update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN_V2,
                                    reply_markup=keyboard)


# ── /help ─────────────────────────────────────────────────────────────────────
@auth_required
async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (
        "🛠 *Available Commands*\n\n"
        "*Scanning:*\n"
        "`/scan example.com` — Full AI pipeline scan\n"
        "`/quick example.com` — Quick passive recon only\n"
        "`/recon example.com` — Recon only (no active scanning)\n"
        "`/cancel` — Cancel the running scan\n\n"
        "*Results:*\n"
        "`/status` — Current scan status & progress\n"
        "`/findings` — View latest findings\n"
        "`/findings critical` — Filter by severity\n"
        "`/report` — Receive the latest report file\n\n"
        "*Configuration:*\n"
        "`/config` — Show current settings\n"
        "`/setprovider openai` — Switch AI provider\n"
        "`/setkey sk-your-key` — Set AI API key\n"
        "`/setmodel gpt-4o` — Set AI model\n\n"
        "*Info:*\n"
        "`/start` — Welcome screen\n"
        "`/help` — This help message\n\n"
        "⚠️ *Only scan targets you have permission to test!*"
    )
    await update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN)


# ── /scan ─────────────────────────────────────────────────────────────────────
@auth_required
async def cmd_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global active_scan, scan_status

    if not context.args:
        await update.message.reply_text(
            "❌ Please provide a target domain.\n\nUsage: `/scan example.com`",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    if active_scan and not active_scan.done():
        await update.message.reply_text(
            f"⏳ A scan is already running for `{scan_status['target']}`.\n"
            "Use /status to check progress or /cancel to stop it.",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    target = context.args[0].strip().lower().replace("https://", "").replace("http://", "")
    scan_status = {"phase": "starting", "percentage": 0, "target": target}

    msg = await update.message.reply_text(
        f"🚀 *Starting full scan for:* `{target}`\n\n"
        f"🤖 AI Provider: `{config.ai_provider}`\n"
        f"📋 Platform: `{config.get('reports', 'platform', default='hackerone')}`\n\n"
        "This may take several minutes\\. I'll send updates as we go\\.",
        parse_mode=ParseMode.MARKDOWN_V2,
    )

    async def progress_callback(phase: str, percentage: int):
        scan_status["phase"] = phase
        scan_status["percentage"] = percentage

    async def run_scan():
        try:
            agent = AIAgent(config)

            def on_progress(phase: str, percentage: int):
                scan_status["phase"] = phase
                scan_status["percentage"] = percentage

            agent.register_progress_callback(on_progress)

            # Send phase update messages
            phase_msgs = {
                "recon": "🔭 *Phase 1/5: Reconnaissance*\nDiscovering subdomains...",
                "enumeration": "📡 *Phase 2/5: Surface Enumeration*\nProbing live hosts & crawling URLs...",
                "scanning": "🛡️ *Phase 3/5: Vulnerability Scanning*\nRunning XSS, SQLi, SSRF, LFI & more...",
                "ai_analysis": "🤖 *Phase 4/5: AI Analysis*\nValidating findings & scoring severity...",
                "reporting": "📝 *Phase 5/5: Report Generation*\nCreating submission-ready reports...",
            }

            async def phase_notifier():
                last_phase = ""
                while not active_scan.done():
                    current = scan_status.get("phase", "")
                    if current != last_phase and current in phase_msgs:
                        await update.message.reply_text(
                            phase_msgs[current],
                            parse_mode=ParseMode.MARKDOWN,
                        )
                        last_phase = current
                    await asyncio.sleep(3)

            notifier = asyncio.create_task(phase_notifier())
            summary = await agent.run_full_pipeline(target)
            notifier.cancel()

            # ── Send Summary ──────────────────────────────────────────────
            total = summary.get("findings_total", 0)
            crit = summary.get("critical_findings", 0)
            high = summary.get("high_findings", 0)
            med = summary.get("medium_findings", 0)
            low = summary.get("low_findings", 0)
            dur = summary.get("duration_seconds", 0)

            result_text = (
                f"✅ *Scan Complete!*\n\n"
                f"🎯 Target: `{target}`\n"
                f"⏱ Duration: `{dur:.1f}s`\n\n"
                f"📊 *Recon Stats:*\n"
                f"• Subdomains: `{summary.get('subdomains_found', 0)}`\n"
                f"• Live Hosts: `{summary.get('live_hosts', 0)}`\n"
                f"• URLs Crawled: `{summary.get('urls_crawled', 0)}`\n"
                f"• Parameters: `{summary.get('parameters_discovered', 0)}`\n\n"
                f"🔎 *Findings: {total}*\n"
            )
            if crit:
                result_text += f"  🔴 Critical: `{crit}`\n"
            if high:
                result_text += f"  🟠 High:     `{high}`\n"
            if med:
                result_text += f"  🟡 Medium:   `{med}`\n"
            if low:
                result_text += f"  🔵 Low:      `{low}`\n"
            if not total:
                result_text += "  ✅ No vulnerabilities found\n"

            result_text += "\nUse /findings to view details or /report to receive the file."

            keyboard = InlineKeyboardMarkup([
                [InlineKeyboardButton("📊 View Findings", callback_data="findings"),
                 InlineKeyboardButton("📄 Get Report", callback_data="report")],
            ])
            await update.message.reply_text(
                result_text, parse_mode=ParseMode.MARKDOWN, reply_markup=keyboard
            )

            # ── Alert critical/high findings ──────────────────────────────
            if crit or high:
                findings = db.get_all_findings(target)
                urgent = [
                    f for f in findings
                    if f.get("severity") in ("critical", "high")
                ][:5]

                for f in urgent:
                    emoji = SEVERITY_EMOJI.get(f.get("severity", "low"), "⚪")
                    alert = (
                        f"🚨 *{f.get('severity', '').upper()} FINDING*\n\n"
                        f"{emoji} *Type:* {f.get('type', 'Unknown')}\n"
                        f"🌐 *URL:* `{f.get('url', 'N/A')[:80]}`\n"
                        f"🔢 *CVSS:* `{f.get('cvss', 'N/A')}`\n"
                        f"📋 *Description:* {str(f.get('description', 'N/A'))[:200]}"
                    )
                    await update.message.reply_text(alert, parse_mode=ParseMode.MARKDOWN)

            # ── Auto-send report file if findings exist ───────────────────
            if total > 0:
                report_path = summary.get("report_path", "")
                if report_path:
                    await _send_report_files(update, report_path)

        except asyncio.CancelledError:
            await update.message.reply_text("⚠️ Scan was cancelled.")
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            await update.message.reply_text(
                f"❌ *Scan failed:* `{str(e)[:500]}`",
                parse_mode=ParseMode.MARKDOWN,
            )
        finally:
            scan_status["phase"] = "idle"
            scan_status["percentage"] = 0

    active_scan = asyncio.create_task(run_scan())


# ── /quick ────────────────────────────────────────────────────────────────────
@auth_required
async def cmd_quick(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global active_scan, scan_status

    if not context.args:
        await update.message.reply_text(
            "❌ Usage: `/quick example.com`",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    if active_scan and not active_scan.done():
        await update.message.reply_text(
            f"⏳ Scan already running for `{scan_status['target']}`.",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    target = context.args[0].strip().lower().replace("https://", "").replace("http://", "")
    scan_status = {"phase": "recon", "percentage": 5, "target": target}

    await update.message.reply_text(
        f"⚡ *Quick passive recon for:* `{target}`\n\nNo active scanning — safe for all targets.",
        parse_mode=ParseMode.MARKDOWN,
    )

    async def run_quick():
        try:
            from recon.subdomain import SubdomainEnumerator
            from recon.port_scanner import PortScanner
            from recon.tech_detect import TechDetector

            enum = SubdomainEnumerator(config)
            subdomains = await enum.discover(target)

            scan_status["phase"] = "enumeration"
            scanner = PortScanner(config)
            live = await scanner.scan(subdomains)

            scan_status["phase"] = "tech_detect"
            tech = TechDetector(config)
            tech_stack = await tech.fingerprint(live)

            total_techs = sum(len(v) for v in tech_stack.values())
            tech_preview = []
            for host, techs in list(tech_stack.items())[:3]:
                tech_preview.append(f"• `{host}`: {', '.join(techs[:4])}")

            text = (
                f"✅ *Quick Recon Complete!*\n\n"
                f"🎯 Target: `{target}`\n"
                f"🔍 Subdomains: `{len(subdomains)}`\n"
                f"🌐 Live Hosts: `{len(live)}`\n"
                f"⚙️ Technologies: `{total_techs}`\n\n"
            )

            if subdomains:
                top_subs = subdomains[:10]
                text += "*Top Subdomains:*\n"
                text += "\n".join(f"• `{s}`" for s in top_subs)
                if len(subdomains) > 10:
                    text += f"\n_...and {len(subdomains)-10} more_"
                text += "\n\n"

            if tech_preview:
                text += "*Tech Stack:*\n"
                text += "\n".join(tech_preview)

            text += "\n\nRun `/scan " + target + "` for full vulnerability scanning."
            await update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN)

        except asyncio.CancelledError:
            await update.message.reply_text("⚠️ Recon cancelled.")
        except Exception as e:
            await update.message.reply_text(f"❌ Recon failed: `{e}`", parse_mode=ParseMode.MARKDOWN)
        finally:
            scan_status["phase"] = "idle"

    active_scan = asyncio.create_task(run_quick())


# ── /status ───────────────────────────────────────────────────────────────────
@auth_required
async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global active_scan, scan_status

    if active_scan and not active_scan.done():
        phase = scan_status.get("phase", "unknown")
        pct = scan_status.get("percentage", 0)
        target = scan_status.get("target", "unknown")

        # Progress bar
        filled = "█" * (pct // 5)
        empty = "░" * (20 - pct // 5)
        bar = f"`[{filled}{empty}] {pct}%`"

        phase_names = {
            "recon": "🔭 Reconnaissance",
            "enumeration": "📡 Surface Enumeration",
            "scanning": "🛡️ Vulnerability Scanning",
            "ai_analysis": "🤖 AI Analysis",
            "reporting": "📝 Report Generation",
        }

        text = (
            f"⏳ *Scan In Progress*\n\n"
            f"🎯 Target: `{target}`\n"
            f"📍 Phase: {phase_names.get(phase, phase.title())}\n"
            f"📊 Progress: {bar}\n\n"
            "Use /cancel to stop the scan."
        )
    else:
        stats = db.get_stats()
        total = stats.get("total", 0)
        by_sev = stats.get("by_severity", {})

        text = (
            "💤 *No scan running*\n\n"
            f"📦 *Total findings in DB:* `{total}`\n"
        )
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = by_sev.get(sev, 0)
            if count:
                text += f"  {SEVERITY_EMOJI.get(sev, '⚪')} {sev.title()}: `{count}`\n"

        text += "\nStart a scan with `/scan example.com`"

    await update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN)


# ── /cancel ───────────────────────────────────────────────────────────────────
@auth_required
async def cmd_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    global active_scan

    if active_scan and not active_scan.done():
        active_scan.cancel()
        scan_status["phase"] = "idle"
        await update.message.reply_text("🛑 *Scan cancelled.*", parse_mode=ParseMode.MARKDOWN)
    else:
        await update.message.reply_text("ℹ️ No scan is currently running.")


# ── /findings ─────────────────────────────────────────────────────────────────
@auth_required
async def cmd_findings(update: Update, context: ContextTypes.DEFAULT_TYPE):
    severity_filter = None
    target_filter = None

    for arg in (context.args or []):
        if arg.lower() in ("critical", "high", "medium", "low", "info"):
            severity_filter = arg.lower()
        else:
            target_filter = arg

    findings = db.get_all_findings(
        target=target_filter,
        severity=severity_filter,
    )

    if not findings:
        msg = "📭 *No findings"
        if severity_filter:
            msg += f" with severity `{severity_filter}`"
        if target_filter:
            msg += f" for `{target_filter}`"
        msg += " in the database.*\n\nRun `/scan example.com` to start scanning."
        await update.message.reply_text(msg, parse_mode=ParseMode.MARKDOWN)
        return

    # Group by severity
    by_sev: Dict[str, list] = {}
    for f in findings[:30]:
        sev = f.get("severity", "info")
        by_sev.setdefault(sev, []).append(f)

    text = f"📊 *Findings ({len(findings)} total)*"
    if severity_filter:
        text += f" — filtered: `{severity_filter}`"
    if target_filter:
        text += f" — target: `{target_filter}`"
    text += "\n\n"

    for sev in ["critical", "high", "medium", "low", "info"]:
        items = by_sev.get(sev, [])
        if not items:
            continue
        emoji = SEVERITY_EMOJI.get(sev, "⚪")
        text += f"{emoji} *{sev.upper()}* ({len(items)})\n"
        for f in items[:3]:
            url = f.get("url", "N/A")[:60]
            vtype = f.get("type", "Unknown")[:30]
            text += f"  • {vtype} — `{url}`\n"
        if len(items) > 3:
            text += f"  _...+{len(items)-3} more_\n"
        text += "\n"

    await update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN)


# ── /report ───────────────────────────────────────────────────────────────────
@auth_required
async def cmd_report(update: Update, context: ContextTypes.DEFAULT_TYPE):
    target = context.args[0] if context.args else None
    report_dir = Path("reports/output")

    if not report_dir.exists():
        await update.message.reply_text("📭 No reports generated yet. Run `/scan example.com` first.")
        return

    # Find the most recent report directory
    subdirs = sorted(
        [d for d in report_dir.iterdir() if d.is_dir()],
        key=lambda d: d.stat().st_mtime,
        reverse=True,
    )

    if target:
        safe_target = target.replace(".", "_").replace("/", "_")
        subdirs = [d for d in subdirs if safe_target in d.name] or subdirs

    if not subdirs:
        await update.message.reply_text("📭 No report directories found.")
        return

    report_path = str(subdirs[0])
    await update.message.reply_text(
        f"📄 Sending latest report from: `{subdirs[0].name}`",
        parse_mode=ParseMode.MARKDOWN,
    )
    await _send_report_files(update, report_path)


async def _send_report_files(update: Update, report_dir: str):
    """Send all .md report files from a directory."""
    path = Path(report_dir)
    if not path.exists():
        await update.message.reply_text("📭 Report directory not found.")
        return

    md_files = sorted(path.glob("*.md"), key=lambda f: f.stat().st_size, reverse=True)

    if not md_files:
        await update.message.reply_text("📭 No report files found.")
        return

    await update.message.reply_text(f"📤 Sending `{len(md_files)}` report file(s)...",
                                    parse_mode=ParseMode.MARKDOWN)

    for fpath in md_files:
        try:
            with open(fpath, "rb") as f:
                await update.message.reply_document(
                    document=f,
                    filename=fpath.name,
                    caption=f"📄 `{fpath.name}`",
                    parse_mode=ParseMode.MARKDOWN,
                )
        except Exception as e:
            await update.message.reply_text(f"⚠️ Could not send `{fpath.name}`: {e}",
                                            parse_mode=ParseMode.MARKDOWN)


# ── /config ───────────────────────────────────────────────────────────────────
@auth_required
async def cmd_config(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (
        "⚙️ *Current Configuration*\n\n"
        f"🤖 *AI Provider:* `{config.get('ai', 'provider', default='ollama')}`\n"
        f"📦 *AI Model:* `{config.get('ai', 'model', default='N/A')}`\n"
        f"🌡️ *Temperature:* `{config.get('ai', 'temperature', default=0.1)}`\n"
        f"🔑 *API Key:* `{'Set ✓' if config.get('ai', 'api_key') else 'Not set ✗'}`\n\n"
        f"🛡️ *Validation Gate:* `{'On' if config.get('ai_engine', 'validation_gate_enabled', default=True) else 'Off'}`\n"
        f"📋 *Report Platform:* `{config.get('reports', 'platform', default='hackerone')}`\n"
        f"⚡ *Rate Limit:* `{config.get('target', 'rate_limit', default=10)} req/s`\n"
        f"🔒 *Stealth Mode:* `{'On' if config.get('stealth', 'enabled', default=False) else 'Off'}`\n\n"
        "*Active Scanners:*\n"
    )

    for scanner in ["xss", "sqli", "ssti", "ssrf", "lfi", "open_redirect", "idor", "api"]:
        enabled = config.get("scanners", scanner, default={}).get("enabled", True)
        icon = "✅" if enabled else "❌"
        text += f"  {icon} {scanner.upper()}\n"

    keyboard = InlineKeyboardMarkup([
        [InlineKeyboardButton("OpenAI", callback_data="provider_openai"),
         InlineKeyboardButton("Anthropic", callback_data="provider_anthropic"),
         InlineKeyboardButton("Groq", callback_data="provider_groq"),
         InlineKeyboardButton("Ollama", callback_data="provider_ollama")],
        [InlineKeyboardButton("HackerOne", callback_data="platform_hackerone"),
         InlineKeyboardButton("Bugcrowd", callback_data="platform_bugcrowd"),
         InlineKeyboardButton("Intigriti", callback_data="platform_intigriti")],
    ])
    await update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN, reply_markup=keyboard)


# ── /setprovider ──────────────────────────────────────────────────────────────
@auth_required
async def cmd_set_provider(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "Usage: `/setprovider openai|anthropic|groq|ollama`",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    provider = context.args[0].lower()
    valid = ["openai", "anthropic", "groq", "ollama"]
    if provider not in valid:
        await update.message.reply_text(
            f"❌ Invalid provider. Choose: `{', '.join(valid)}`",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    config.data["ai"]["provider"] = provider
    config.save()
    await update.message.reply_text(
        f"✅ AI provider set to: `{provider}`",
        parse_mode=ParseMode.MARKDOWN,
    )


# ── /setkey ───────────────────────────────────────────────────────────────────
@auth_required
async def cmd_set_key(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "Usage: `/setkey your-api-key-here`\n⚠️ Your key will be stored in config.json",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    key = context.args[0]
    config.data["ai"]["api_key"] = key
    config.save()

    # Delete the message to avoid key exposure in chat
    try:
        await update.message.delete()
    except Exception:
        pass

    await update.effective_chat.send_message(
        "✅ *API key saved successfully!*\n_(Your message with the key was deleted for security)_",
        parse_mode=ParseMode.MARKDOWN,
    )


# ── /setmodel ─────────────────────────────────────────────────────────────────
@auth_required
async def cmd_set_model(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text(
            "Usage: `/setmodel gpt-4o`\n\n"
            "Examples:\n"
            "• OpenAI: `gpt-4o`, `gpt-4o-mini`\n"
            "• Anthropic: `claude-3-5-sonnet-20241022`\n"
            "• Groq: `llama-3.1-70b-versatile`\n"
            "• Ollama: `llama3`, `mistral`, `phi3`",
            parse_mode=ParseMode.MARKDOWN,
        )
        return

    model = context.args[0]
    config.data["ai"]["model"] = model
    config.save()
    await update.message.reply_text(
        f"✅ AI model set to: `{model}`",
        parse_mode=ParseMode.MARKDOWN,
    )


# ── Inline Button Callbacks ───────────────────────────────────────────────────
async def callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data

    if data == "help":
        await cmd_help.__wrapped__(update, context) if hasattr(cmd_help, '__wrapped__') else None
        await query.message.reply_text(
            "Use /help to see all commands.", parse_mode=ParseMode.MARKDOWN
        )
    elif data == "config":
        await query.message.reply_text(
            "Use /config to view settings.", parse_mode=ParseMode.MARKDOWN
        )
    elif data == "findings":
        await query.message.reply_text(
            "Use /findings to view latest findings.", parse_mode=ParseMode.MARKDOWN
        )
    elif data == "report":
        await query.message.reply_text(
            "Use /report to receive the latest report.", parse_mode=ParseMode.MARKDOWN
        )
    elif data.startswith("provider_"):
        provider = data.replace("provider_", "")
        config.data["ai"]["provider"] = provider
        config.save()
        await query.message.reply_text(f"✅ AI provider switched to: `{provider}`",
                                       parse_mode=ParseMode.MARKDOWN)
    elif data.startswith("platform_"):
        platform = data.replace("platform_", "")
        config.data["reports"]["platform"] = platform
        config.save()
        await query.message.reply_text(f"✅ Report platform set to: `{platform}`",
                                       parse_mode=ParseMode.MARKDOWN)


# ── Unknown command handler ───────────────────────────────────────────────────
async def cmd_unknown(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "❓ Unknown command. Use /help to see all available commands."
    )


# ── Error Handler ─────────────────────────────────────────────────────────────
async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE):
    logger.error(f"Telegram error: {context.error}")
    if isinstance(update, Update) and update.message:
        await update.message.reply_text(
            f"⚠️ An error occurred: `{str(context.error)[:200]}`",
            parse_mode=ParseMode.MARKDOWN,
        )


# ── Main Bot Runner ───────────────────────────────────────────────────────────
def run_bot(token: str, allowed_user_ids: list = None):
    """Start the Telegram bot."""
    global ALLOWED_USERS
    if allowed_user_ids:
        ALLOWED_USERS = allowed_user_ids

    logger.info("Starting AI-BugBounty-Hunter Telegram Bot...")

    app = Application.builder().token(token).build()

    # Register commands
    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("help", cmd_help))
    app.add_handler(CommandHandler("scan", cmd_scan))
    app.add_handler(CommandHandler("quick", cmd_quick))
    app.add_handler(CommandHandler("recon", cmd_quick))  # Alias
    app.add_handler(CommandHandler("status", cmd_status))
    app.add_handler(CommandHandler("cancel", cmd_cancel))
    app.add_handler(CommandHandler("findings", cmd_findings))
    app.add_handler(CommandHandler("report", cmd_report))
    app.add_handler(CommandHandler("config", cmd_config))
    app.add_handler(CommandHandler("setprovider", cmd_set_provider))
    app.add_handler(CommandHandler("setkey", cmd_set_key))
    app.add_handler(CommandHandler("setmodel", cmd_set_model))
    app.add_handler(CallbackQueryHandler(callback_handler))
    app.add_handler(MessageHandler(filters.COMMAND, cmd_unknown))
    app.add_error_handler(error_handler)

    # Set bot command list (shows in Telegram menu)
    commands = [
        BotCommand("start", "Welcome screen"),
        BotCommand("scan", "Full AI scan: /scan example.com"),
        BotCommand("quick", "Quick passive recon: /quick example.com"),
        BotCommand("status", "Current scan status"),
        BotCommand("findings", "View latest findings"),
        BotCommand("report", "Get report file"),
        BotCommand("cancel", "Cancel running scan"),
        BotCommand("config", "View/change settings"),
        BotCommand("setprovider", "Set AI provider"),
        BotCommand("setkey", "Set API key"),
        BotCommand("setmodel", "Set AI model"),
        BotCommand("help", "Show all commands"),
    ]

    async def post_init(application: Application):
        await application.bot.set_my_commands(commands)

    app.post_init = post_init

    logger.info("Bot is running. Press Ctrl+C to stop.")
    app.run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)


if __name__ == "__main__":
    # Load token from environment or config
    TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
    ALLOWED_IDS_STR = os.getenv("TELEGRAM_ALLOWED_USERS", "")

    if not TOKEN:
        # Try loading from bot_config.json
        bot_cfg_path = Path("bot_config.json")
        if bot_cfg_path.exists():
            with open(bot_cfg_path) as f:
                bot_cfg = json.load(f)
            TOKEN = bot_cfg.get("telegram_token", "")
            ALLOWED_IDS_STR = str(bot_cfg.get("allowed_user_ids", ""))

    if not TOKEN:
        print("\n  ❌ No Telegram bot token found!")
        print("  Set it with one of these methods:")
        print("  1. Environment variable:  set TELEGRAM_BOT_TOKEN=your-token")
        print("  2. bot_config.json:       {\"telegram_token\": \"your-token\"}")
        print("  3. Argument:              python telegram_bot.py YOUR_TOKEN\n")
        if len(sys.argv) > 1:
            TOKEN = sys.argv[1]
        else:
            sys.exit(1)

    allowed_ids = []
    if ALLOWED_IDS_STR:
        try:
            allowed_ids = [int(x.strip()) for x in ALLOWED_IDS_STR.split(",") if x.strip()]
        except ValueError:
            pass

    run_bot(TOKEN, allowed_ids)
