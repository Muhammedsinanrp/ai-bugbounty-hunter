#!/usr/bin/env python3
"""
AI-BugBounty-Hunter — Telegram Bot (Multi-User, Cross-Platform)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Supports unlimited simultaneous users — each user has their own:
  - Independent scan session
  - Live progress tracking
  - Findings history
  - Configuration (AI provider, model, platform)

Works on: Windows, Linux, macOS
"""

# ── Cross-platform encoding fix (MUST be first) ──────────────────────────────
import sys, os
if sys.platform == "win32":
    import io
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")
os.environ.setdefault("PYTHONUTF8", "1")
os.environ.setdefault("PYTHONIOENCODING", "utf-8")

# ── Stdlib ───────────────────────────────────────────────────────────────────
import asyncio
import json
import logging
import traceback
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any
from dataclasses import dataclass, field

# ── Telegram ──────────────────────────────────────────────────────────────────
from telegram import (
    Update, InlineKeyboardButton, InlineKeyboardMarkup, BotCommand
)
from telegram.ext import (
    Application, CommandHandler, CallbackQueryHandler,
    ContextTypes, MessageHandler, filters
)
from telegram.constants import ParseMode

# ── Project ───────────────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))
from core.config import Config
from core.database import FindingsDB

# ── Logging (plain, cross-platform) ──────────────────────────────────────────
logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
    level=logging.INFO,
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("logs/bot.log", encoding="utf-8"),
    ]
)
log = logging.getLogger("BugBot")

# Create logs dir
Path("logs").mkdir(exist_ok=True)
Path("reports/output").mkdir(parents=True, exist_ok=True)
Path("findings_db").mkdir(exist_ok=True)

# ─────────────────────────────────────────────────────────────────────────────
# Per-user session state
# ─────────────────────────────────────────────────────────────────────────────
@dataclass
class UserSession:
    user_id: int
    username: str = ""
    # Scan state
    active_task: Optional[asyncio.Task] = None
    scan_phase: str = "idle"
    scan_pct: int = 0
    scan_target: str = ""
    # Per-user config overrides
    ai_provider: str = "ollama"
    ai_model: str = "llama3"
    report_platform: str = "hackerone"
    api_key: str = ""
    # Stats
    total_scans: int = 0
    last_scan: str = ""

    def is_scanning(self) -> bool:
        return self.active_task is not None and not self.active_task.done()

    def get_config(self) -> Config:
        """Build a config object for this user."""
        cfg = Config()
        cfg.data["ai"]["provider"] = self.ai_provider
        cfg.data["ai"]["model"] = self.ai_model
        cfg.data["reports"]["platform"] = self.report_platform
        if self.api_key:
            cfg.data["ai"]["api_key"] = self.api_key
        return cfg


# Global session store: user_id → UserSession
SESSIONS: Dict[int, UserSession] = {}

# Load base config
BASE_CONFIG = Config()
db = FindingsDB()

# Authorized users (empty = allow all)
ALLOWED_USERS: list = []

SEV_EMOJI = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────
def get_session(user: Any) -> UserSession:
    """Get or create a session for a user."""
    uid = user.id
    if uid not in SESSIONS:
        SESSIONS[uid] = UserSession(
            user_id=uid,
            username=user.username or user.first_name or str(uid),
            ai_provider=BASE_CONFIG.get("ai", "provider", default="ollama"),
            ai_model=BASE_CONFIG.get("ai", "model", default="llama3"),
            report_platform=BASE_CONFIG.get("reports", "platform", default="hackerone"),
        )
    return SESSIONS[uid]


def is_authorized(user_id: int) -> bool:
    return not ALLOWED_USERS or user_id in ALLOWED_USERS


def progress_bar(pct: int) -> str:
    filled = "█" * (pct // 5)
    empty = "░" * (20 - pct // 5)
    return f"`[{filled}{empty}] {pct}%`"


def escape_md(text: str) -> str:
    """Escape special MarkdownV2 chars."""
    for ch in r"_*[]()~`>#+-=|{}.!":
        text = text.replace(ch, f"\\{ch}")
    return text


async def safe_reply(update: Update, text: str, **kwargs):
    """Reply with Markdown, fallback to plain text on error."""
    try:
        await update.message.reply_text(text, parse_mode=ParseMode.MARKDOWN, **kwargs)
    except Exception:
        try:
            plain = text.replace("*", "").replace("`", "").replace("_", "")
            await update.message.reply_text(plain, **kwargs)
        except Exception as e:
            log.error(f"Failed to send message: {e}")


# ─────────────────────────────────────────────────────────────────────────────
# Authorization decorator
# ─────────────────────────────────────────────────────────────────────────────
def auth(func):
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not update.effective_user:
            return
        uid = update.effective_user.id
        if not is_authorized(uid):
            await safe_reply(update, "⛔ *Access Denied.* You are not authorized to use this bot.")
            log.warning(f"Unauthorized: user {uid}")
            return
        return await func(update, context)
    wrapper.__name__ = func.__name__
    return wrapper


# ─────────────────────────────────────────────────────────────────────────────
# /start
# ─────────────────────────────────────────────────────────────────────────────
@auth
async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    s = get_session(update.effective_user)
    text = (
        f"👋 *Welcome, {update.effective_user.first_name}!*\n\n"
        "🎯 *AI-BugBounty-Hunter Bot*\n"
        "AI-powered bug bounty automation platform.\n\n"
        "*What I can do:*\n"
        "• 🔍 Full vulnerability pipeline scans\n"
        "• ⚡ Quick passive recon (no active traffic)\n"
        "• 🤖 AI-driven finding analysis & validation\n"
        "• 📄 Generate platform-ready reports\n"
        "• 📤 Send reports as files directly to you\n\n"
        f"*Your session:* `{s.username}` | Provider: `{s.ai_provider}`\n\n"
        "Use /help to see all commands."
    )
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("📖 Help", callback_data="help"),
         InlineKeyboardButton("⚙️ My Config", callback_data="myconfig")],
        [InlineKeyboardButton("📊 My Findings", callback_data="myfindings"),
         InlineKeyboardButton("📄 Get Report", callback_data="myreport")],
    ])
    await safe_reply(update, text, reply_markup=kb)


# ─────────────────────────────────────────────────────────────────────────────
# /help
# ─────────────────────────────────────────────────────────────────────────────
@auth
async def cmd_help(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = (
        "🛠 *Commands*\n\n"
        "*Scanning:*\n"
        "`/scan <domain>` — Full AI pipeline scan\n"
        "`/quick <domain>` — Passive recon (safe)\n"
        "`/status` — Your current scan progress\n"
        "`/cancel` — Cancel your running scan\n\n"
        "*Results:*\n"
        "`/findings` — Your latest findings\n"
        "`/findings critical` — Filter by severity\n"
        "`/findings <domain>` — Filter by target\n"
        "`/report` — Get latest report as file\n"
        "`/report <domain>` — Report for specific target\n\n"
        "*Your Config:*\n"
        "`/myconfig` — View your settings\n"
        "`/setprovider <openai|anthropic|groq|ollama>`\n"
        "`/setmodel <model-name>`\n"
        "`/setkey <api-key>` — Set your API key\n"
        "`/setplatform <hackerone|bugcrowd|intigriti|immunefi>`\n\n"
        "*Info:*\n"
        "`/mystats` — Your scan statistics\n"
        "`/start` — Welcome screen\n"
        "`/help` — This message\n\n"
        "⚠️ *Only scan targets you have permission to test!*"
    )
    await safe_reply(update, text)


# ─────────────────────────────────────────────────────────────────────────────
# /scan — Full pipeline
# ─────────────────────────────────────────────────────────────────────────────
@auth
async def cmd_scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
    s = get_session(update.effective_user)

    if not context.args:
        await safe_reply(update, "❌ Usage: `/scan example.com`")
        return

    if s.is_scanning():
        await safe_reply(
            update,
            f"⏳ *You already have a scan running* for `{s.scan_target}`.\n"
            "Use /status to check progress or /cancel to stop it."
        )
        return

    target = context.args[0].strip().lower().replace("https://", "").replace("http://", "").rstrip("/")
    s.scan_target = target
    s.scan_phase = "starting"
    s.scan_pct = 0
    s.total_scans += 1
    s.last_scan = datetime.utcnow().isoformat()

    await safe_reply(
        update,
        f"🚀 *Starting full scan for:* `{target}`\n\n"
        f"🤖 AI Provider: `{s.ai_provider}` | Model: `{s.ai_model}`\n"
        f"📋 Platform: `{s.report_platform}`\n\n"
        "_This may take several minutes. I'll update you at each phase._"
    )

    async def run_scan():
        try:
            from recon.subdomain import SubdomainEnumerator
            from recon.port_scanner import PortScanner
            from recon.tech_detect import TechDetector
            from recon.url_crawler import URLCrawler
            from recon.osint import OSINTEnricher
            from scanners.xss_scanner import XSSScanner
            from scanners.sqli_scanner import SQLIScanner
            from scanners.ssrf_scanner import SSRFScanner
            from scanners.ssti_scanner import SSTIScanner
            from scanners.lfi_scanner import LFIScanner
            from scanners.open_redirect import OpenRedirectScanner
            from scanners.idor_scanner import IDORScanner
            from scanners.api_tester import APITester
            from ai_engine.analyzer import AIAnalyzer
            from ai_engine.validator import AIValidator
            from ai_engine.report_gen import AIReportGenerator
            from core.database import FindingsDB

            cfg = s.get_config()
            cfg.set_target(target)
            scan_db = FindingsDB()
            all_findings = []
            t_start = datetime.utcnow()

            async def notify(text: str):
                await safe_reply(update, text)

            # ══════════════════════════════════════════════════
            # PHASE 1: RECONNAISSANCE
            # ══════════════════════════════════════════════════
            s.scan_phase = "recon"
            await notify(
                "🔭 *Phase 1/5 — Reconnaissance*\n\n"
                f"🎯 Target: `{target}`\n"
                "Querying CRT.sh, Wayback Machine, SecurityTrails...\n"
                "Predicting subdomains with AI patterns..."
            )

            enum = SubdomainEnumerator(cfg)
            subdomains = await enum.discover(target)

            # Show discovered subdomains
            sub_preview = "\n".join(f"  • `{s_}`" for s_ in subdomains[:15])
            if len(subdomains) > 15:
                sub_preview += f"\n  _...+{len(subdomains)-15} more_"

            await notify(
                f"✅ *Recon done!*\n\n"
                f"🔍 Found `{len(subdomains)}` subdomains:\n"
                f"{sub_preview if subdomains else '  _None found — using root domain_'}"
            )

            # ══════════════════════════════════════════════════
            # PHASE 2: SURFACE ENUMERATION
            # ══════════════════════════════════════════════════
            s.scan_phase = "enumeration"
            await notify(
                "📡 *Phase 2/5 — Surface Enumeration*\n\n"
                f"Probing `{len(subdomains) or 1}` hosts for HTTP/HTTPS...\n"
                "Detecting technology stacks...\n"
                "Crawling URLs and extracting parameters..."
            )

            # Live host probe
            port_scanner = PortScanner(cfg)
            live_hosts = await port_scanner.scan(subdomains or [target])

            # Tech detection
            tech_detector = TechDetector(cfg)
            tech_stack = await tech_detector.fingerprint(live_hosts)

            # Build tech summary
            tech_lines = []
            for host, techs in list(tech_stack.items())[:6]:
                short = host.replace("https://","").replace("http://","")[:35]
                tech_lines.append(f"  • `{short}`: {', '.join(techs[:5])}")

            # URL crawling
            crawler = URLCrawler(cfg)
            crawl_results = await crawler.crawl(live_hosts)
            all_urls = crawl_results.get("urls", [])
            all_params = crawl_results.get("parameters", [])

            await notify(
                f"✅ *Enumeration done!*\n\n"
                f"🌐 Live hosts: `{len(live_hosts)}`\n"
                f"🔗 URLs found: `{len(all_urls)}`\n"
                f"🔢 Parameters: `{len(all_params)}`\n\n"
                f"*Tech Stack:*\n"
                f"{chr(10).join(tech_lines) if tech_lines else '  _Not detected_'}"
            )

            # OSINT enrichment (quick, non-blocking)
            try:
                osint = OSINTEnricher(cfg)
                osint_data = await osint.enrich(target)
                if osint_data:
                    ip = osint_data.get("ip", "?")
                    org = osint_data.get("org", "?")
                    country = osint_data.get("country", "?")
                    await notify(
                        f"🌍 *OSINT Intel*\n\n"
                        f"🖥 IP: `{ip}`\n"
                        f"🏢 Org: `{org}`\n"
                        f"📍 Country: `{country}`"
                    )
            except Exception:
                pass

            # ══════════════════════════════════════════════════
            # PHASE 3: VULNERABILITY SCANNING
            # ══════════════════════════════════════════════════
            s.scan_phase = "scanning"

            # Prepare target URLs for scanning
            scan_targets = []
            for url in all_urls[:200]:
                for param in all_params[:20]:
                    scan_targets.append({"url": url, "param": param})
            if not scan_targets:
                # Fallback: use live hosts directly
                for host in live_hosts[:5]:
                    scan_targets.append({"url": host, "param": "q"})

            await notify(
                f"🛡 *Phase 3/5 — Vulnerability Scanning*\n\n"
                f"📋 Targets: `{len(scan_targets)}` URL+param combos\n\n"
                "Running these checks:\n"
                "  🔸 XSS (Reflected, Stored, DOM)\n"
                "  🔸 SQL Injection (Error, Time, Boolean)\n"
                "  🔸 SSTI (Jinja2, Twig, Freemarker)\n"
                "  🔸 SSRF (Cloud metadata endpoints)\n"
                "  🔸 LFI / Path Traversal\n"
                "  🔸 Open Redirect\n"
                "  🔸 IDOR (Insecure Direct Object Reference)\n"
                "  🔸 API Security (CORS, Secrets, GraphQL)\n"
            )

            SCANNERS = [
                ("XSS",           XSSScanner,           "🔸 XSS"),
                ("SQLi",          SQLIScanner,          "🔸 SQL Injection"),
                ("SSTI",          SSTIScanner,          "🔸 SSTI"),
                ("SSRF",          SSRFScanner,          "🔸 SSRF"),
                ("LFI",           LFIScanner,           "🔸 LFI"),
                ("OpenRedirect",  OpenRedirectScanner,  "🔸 Open Redirect"),
                ("IDOR",          IDORScanner,          "🔸 IDOR"),
                ("API",           APITester,            "🔸 API Security"),
            ]

            scan_log = []
            for scanner_name, ScannerClass, label in SCANNERS:
                s.scan_pct = 30 + (len(scan_log) * 8)
                try:
                    scanner = ScannerClass(cfg)
                    findings = await scanner.scan(scan_targets)
                    count = len(findings)
                    all_findings.extend(findings)

                    for f in findings:
                        scan_db.add_finding(f)

                    status = f"✅ {count} found" if count else "✅ Clean"
                    scan_log.append(f"  {label}: `{status}`")

                    # Instant alert for high/critical finds
                    for f in findings:
                        sev = f.get("severity", "low")
                        if sev in ("critical", "high"):
                            emoji = SEV_EMOJI.get(sev, "⚪")
                            await notify(
                                f"🚨 *LIVE FINDING: {sev.upper()}*\n\n"
                                f"{emoji} *Type:* {f.get('type', scanner_name)}\n"
                                f"🌐 *URL:* `{str(f.get('url',''))[:70]}`\n"
                                f"🔑 *Parameter:* `{f.get('param', 'N/A')}`\n"
                                f"💉 *Payload:* `{str(f.get('payload',''))[:80]}`\n"
                                f"📋 *Details:* {str(f.get('description',''))[:150]}"
                            )
                except Exception as e:
                    scan_log.append(f"  {label}: `⚠ Error ({str(e)[:30]})`")
                    log.error(f"Scanner {scanner_name} error: {e}")

            await notify(
                f"✅ *Scanning done!*\n\n"
                f"*Results per scanner:*\n"
                + "\n".join(scan_log) +
                f"\n\n🔎 Raw findings: `{len(all_findings)}`"
            )

            # ══════════════════════════════════════════════════
            # PHASE 4: AI ANALYSIS & VALIDATION
            # ══════════════════════════════════════════════════
            s.scan_phase = "ai_analysis"
            s.scan_pct = 80

            if all_findings:
                await notify(
                    f"🤖 *Phase 4/5 — AI Analysis & Validation*\n\n"
                    f"Analysing `{len(all_findings)}` raw findings...\n\n"
                    "AI will:\n"
                    "  1️⃣ Score severity (CVSS)\n"
                    "  2️⃣ Generate proof-of-concept steps\n"
                    "  3️⃣ Assess business impact\n"
                    "  4️⃣ Run 7-question validation gate\n"
                    "  5️⃣ Eliminate false positives\n"
                    "  6️⃣ Prioritize by exploitability"
                )

                try:
                    analyzer = AIAnalyzer(cfg)
                    analyzed = await analyzer.analyze(all_findings)
                except Exception as e:
                    log.error(f"Analyzer error: {e}")
                    analyzed = all_findings

                try:
                    validator = AIValidator(cfg)
                    validated = await validator.validate(analyzed)
                except Exception as e:
                    log.error(f"Validator error: {e}")
                    validated = analyzed

                # Count by severity
                sev_counts = {}
                for f in validated:
                    sev = f.get("severity", "info")
                    sev_counts[sev] = sev_counts.get(sev, 0) + 1

                validation_msg = (
                    f"✅ *AI Validation done!*\n\n"
                    f"📥 Raw findings: `{len(all_findings)}`\n"
                    f"✅ Validated (real): `{len(validated)}`\n"
                    f"❌ Rejected (false pos): `{len(all_findings) - len(validated)}`\n\n"
                    f"*Severity breakdown:*\n"
                )
                for sev in ["critical", "high", "medium", "low", "info"]:
                    count = sev_counts.get(sev, 0)
                    if count:
                        validation_msg += f"  {SEV_EMOJI.get(sev)} {sev.title()}: `{count}`\n"

                await notify(validation_msg)
                all_findings = validated
            else:
                await notify(
                    "🤖 *Phase 4/5 — AI Analysis*\n\n"
                    "No raw findings to analyze.\n"
                    "Target appears clean or scan scope was limited."
                )

            # ══════════════════════════════════════════════════
            # PHASE 5: REPORT GENERATION
            # ══════════════════════════════════════════════════
            s.scan_phase = "reporting"
            s.scan_pct = 95
            report_path = ""

            if all_findings:
                await notify(
                    f"📝 *Phase 5/5 — Report Generation*\n\n"
                    f"Building `{s.report_platform}` submission-ready report...\n"
                    f"Generating PoC steps, remediation advice, CVSS scores..."
                )
                try:
                    reporter = AIReportGenerator(cfg)
                    report_data = await reporter.generate(
                        target=target,
                        findings=all_findings,
                        subdomains=subdomains,
                        live_hosts=live_hosts,
                        tech_stack=tech_stack,
                        summary={
                            "total_findings": len(all_findings),
                            "subdomains_found": len(subdomains),
                            "live_hosts": len(live_hosts),
                            "urls_crawled": len(all_urls),
                        },
                    )
                    report_path = report_data.get("path", "")
                except Exception as e:
                    log.error(f"Report generation error: {e}")

            # ══════════════════════════════════════════════════
            # FINAL SUMMARY
            # ══════════════════════════════════════════════════
            dur = (datetime.utcnow() - t_start).total_seconds()
            sev_counts = {}
            for f in all_findings:
                sev = f.get("severity", "info")
                sev_counts[sev] = sev_counts.get(sev, 0) + 1

            summary_msg = (
                f"🎯 *SCAN COMPLETE — {target}*\n"
                f"{'━'*35}\n\n"
                f"⏱ *Duration:* `{dur:.1f}s`\n\n"
                f"📡 *Reconnaissance:*\n"
                f"  • Subdomains: `{len(subdomains)}`\n"
                f"  • Live hosts: `{len(live_hosts)}`\n"
                f"  • URLs crawled: `{len(all_urls)}`\n"
                f"  • Parameters: `{len(all_params)}`\n\n"
                f"🔎 *Findings: `{len(all_findings)}`*\n"
            )
            if not all_findings:
                summary_msg += "  ✅ No confirmed vulnerabilities\n"
            for sev in ["critical", "high", "medium", "low", "info"]:
                count = sev_counts.get(sev, 0)
                if count:
                    summary_msg += f"  {SEV_EMOJI.get(sev)} {sev.title()}: `{count}`\n"

            summary_msg += f"\n📋 *Platform:* `{s.report_platform}`\n"
            if report_path:
                summary_msg += "📄 *Report:* Ready — sending now...\n"

            summary_msg += "\nUse /findings or /report anytime to review."

            kb = InlineKeyboardMarkup([
                [InlineKeyboardButton("📊 View Findings", callback_data="myfindings"),
                 InlineKeyboardButton("📄 Get Report",    callback_data="myreport")],
            ])
            await safe_reply(update, summary_msg, reply_markup=kb)

            # Send report file
            if report_path:
                await _send_reports(update, report_path)

        except asyncio.CancelledError:
            await safe_reply(update, "🛑 *Scan cancelled.*")
        except Exception as e:
            log.error(f"Scan error for user {s.user_id}: {e}\n{traceback.format_exc()}")
            await safe_reply(update, f"❌ *Scan failed:* `{str(e)[:300]}`")
        finally:
            s.scan_phase = "idle"
            s.scan_pct = 0
            s.active_task = None

    s.active_task = asyncio.create_task(run_scan())


# ─────────────────────────────────────────────────────────────────────────────
# /quick — Passive recon only
# ─────────────────────────────────────────────────────────────────────────────
@auth
async def cmd_quick(update: Update, context: ContextTypes.DEFAULT_TYPE):
    s = get_session(update.effective_user)

    if not context.args:
        await safe_reply(update, "❌ Usage: `/quick example.com`")
        return

    if s.is_scanning():
        await safe_reply(update, f"⏳ Scan running for `{s.scan_target}`. Use /cancel first.")
        return

    target = context.args[0].strip().lower().replace("https://", "").replace("http://", "").rstrip("/")
    s.scan_target = target
    s.scan_phase = "recon"
    s.total_scans += 1
    s.last_scan = datetime.utcnow().isoformat()

    await safe_reply(
        update,
        f"⚡ *Quick passive recon for:* `{target}`\n\n"
        "_No active scanning — safe for all targets._"
    )

    async def run_quick():
        try:
            from recon.subdomain import SubdomainEnumerator
            from recon.port_scanner import PortScanner
            from recon.tech_detect import TechDetector

            cfg = s.get_config()

            s.scan_phase = "recon"
            enum = SubdomainEnumerator(cfg)
            subdomains = await enum.discover(target)

            s.scan_phase = "enumeration"
            scanner = PortScanner(cfg)
            live = await scanner.scan(subdomains)

            s.scan_phase = "tech"
            tech = TechDetector(cfg)
            tech_stack = await tech.fingerprint(live)
            total_techs = sum(len(v) for v in tech_stack.values())

            msg = (
                f"✅ *Quick Recon Complete!*\n\n"
                f"🎯 Target: `{target}`\n"
                f"🔍 Subdomains: `{len(subdomains)}`\n"
                f"🌐 Live Hosts: `{len(live)}`\n"
                f"⚙️ Technologies: `{total_techs}`\n"
            )
            if subdomains:
                top = subdomains[:10]
                msg += "\n*Top Subdomains:*\n" + "\n".join(f"• `{s_}`" for s_ in top)
                if len(subdomains) > 10:
                    msg += f"\n_...and {len(subdomains)-10} more_"

            if tech_stack:
                msg += "\n\n*Tech Stack:*\n"
                for host, techs in list(tech_stack.items())[:4]:
                    short_host = host.replace("https://","").replace("http://","")[:30]
                    msg += f"• `{short_host}`: {', '.join(techs[:4])}\n"

            msg += f"\n\n_Run_ `/scan {target}` _for full vulnerability scanning._"
            await safe_reply(update, msg)

        except asyncio.CancelledError:
            await safe_reply(update, "🛑 Recon cancelled.")
        except Exception as e:
            log.error(f"Quick recon error: {e}")
            await safe_reply(update, f"❌ Recon failed: `{str(e)[:200]}`")
        finally:
            s.scan_phase = "idle"
            s.active_task = None

    s.active_task = asyncio.create_task(run_quick())


# ─────────────────────────────────────────────────────────────────────────────
# /status
# ─────────────────────────────────────────────────────────────────────────────
@auth
async def cmd_status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    s = get_session(update.effective_user)

    if s.is_scanning():
        phase_names = {
            "recon":       "🔭 Reconnaissance",
            "enumeration": "📡 Surface Enumeration",
            "scanning":    "🛡 Vulnerability Scanning",
            "ai_analysis": "🤖 AI Analysis",
            "reporting":   "📝 Report Generation",
            "tech":        "⚙️ Tech Detection",
        }
        phase_label = phase_names.get(s.scan_phase, s.scan_phase.title())
        bar = progress_bar(s.scan_pct)

        text = (
            f"⏳ *Scan In Progress*\n\n"
            f"👤 User: `{s.username}`\n"
            f"🎯 Target: `{s.scan_target}`\n"
            f"📍 Phase: {phase_label}\n"
            f"📊 Progress: {bar}\n\n"
            "_Use /cancel to stop._"
        )
    else:
        stats = db.get_stats()
        total = stats.get("total", 0)
        by_sev = stats.get("by_severity", {})

        text = (
            f"💤 *No scan running*\n\n"
            f"👤 User: `{s.username}`\n"
            f"🔢 Total scans done: `{s.total_scans}`\n"
            f"📦 Total findings in DB: `{total}`\n"
        )
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = by_sev.get(sev, 0)
            if count:
                text += f"  {SEV_EMOJI.get(sev)} {sev.title()}: `{count}`\n"
        text += "\nStart a scan: `/scan example.com`"

    await safe_reply(update, text)


# ─────────────────────────────────────────────────────────────────────────────
# /cancel
# ─────────────────────────────────────────────────────────────────────────────
@auth
async def cmd_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    s = get_session(update.effective_user)
    if s.is_scanning():
        s.active_task.cancel()
        s.scan_phase = "idle"
        await safe_reply(update, "🛑 *Scan cancelled.*")
    else:
        await safe_reply(update, "ℹ️ No scan is currently running for you.")


# ─────────────────────────────────────────────────────────────────────────────
# /findings
# ─────────────────────────────────────────────────────────────────────────────
@auth
async def cmd_findings(update: Update, context: ContextTypes.DEFAULT_TYPE):
    severity_filter = None
    target_filter = None

    for arg in (context.args or []):
        if arg.lower() in ("critical", "high", "medium", "low", "info"):
            severity_filter = arg.lower()
        else:
            target_filter = arg

    findings = db.get_all_findings(target=target_filter, severity=severity_filter)

    if not findings:
        msg = "📭 *No findings"
        if severity_filter: msg += f" with severity `{severity_filter}`"
        if target_filter:   msg += f" for `{target_filter}`"
        msg += "*\n\nRun `/scan example.com` to start."
        await safe_reply(update, msg)
        return

    # Group by severity
    by_sev: Dict[str, list] = {}
    for f in findings[:50]:
        sev = f.get("severity", "info")
        by_sev.setdefault(sev, []).append(f)

    msg = f"📊 *Findings ({len(findings)} total)*"
    if severity_filter: msg += f" — `{severity_filter}`"
    if target_filter:   msg += f" — `{target_filter}`"
    msg += "\n\n"

    for sev in ["critical", "high", "medium", "low", "info"]:
        items = by_sev.get(sev, [])
        if not items:
            continue
        emoji = SEV_EMOJI.get(sev, "⚪")
        msg += f"{emoji} *{sev.upper()}* ({len(items)})\n"
        for f in items[:3]:
            url   = str(f.get("url", "N/A"))[:55]
            vtype = str(f.get("type", "Unknown"))[:28]
            msg += f"  • {vtype} — `{url}`\n"
        if len(items) > 3:
            msg += f"  _+{len(items)-3} more_\n"
        msg += "\n"

    await safe_reply(update, msg)


# ─────────────────────────────────────────────────────────────────────────────
# /report
# ─────────────────────────────────────────────────────────────────────────────
@auth
async def cmd_report(update: Update, context: ContextTypes.DEFAULT_TYPE):
    target = context.args[0] if context.args else None
    report_base = Path("reports/output")

    if not report_base.exists():
        await safe_reply(update, "📭 No reports yet. Run `/scan example.com` first.")
        return

    subdirs = sorted(
        [d for d in report_base.iterdir() if d.is_dir()],
        key=lambda d: d.stat().st_mtime,
        reverse=True,
    )

    if target:
        safe_t = target.replace(".", "_").replace("/", "_")
        filtered = [d for d in subdirs if safe_t in d.name]
        subdirs = filtered or subdirs

    if not subdirs:
        await safe_reply(update, "📭 No report directories found.")
        return

    await safe_reply(update, f"📤 Sending report for: `{subdirs[0].name}`")
    await _send_reports(update, str(subdirs[0]))


async def _send_reports(update: Update, report_dir: str):
    """Send all markdown report files from a directory."""
    path = Path(report_dir)
    if not path.exists():
        await safe_reply(update, "📭 Report directory not found.")
        return

    md_files = sorted(path.glob("*.md"), key=lambda f: f.stat().st_size, reverse=True)
    if not md_files:
        await safe_reply(update, "📭 No report files found.")
        return

    await safe_reply(update, f"📄 Sending `{len(md_files)}` report file(s)...")
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
            log.error(f"Failed to send report {fpath.name}: {e}")
            await safe_reply(update, f"⚠️ Could not send `{fpath.name}`")


# ─────────────────────────────────────────────────────────────────────────────
# /myconfig
# ─────────────────────────────────────────────────────────────────────────────
@auth
async def cmd_myconfig(update: Update, context: ContextTypes.DEFAULT_TYPE):
    s = get_session(update.effective_user)
    text = (
        f"⚙️ *Your Configuration*\n\n"
        f"👤 User: `{s.username}`\n"
        f"🤖 AI Provider: `{s.ai_provider}`\n"
        f"📦 AI Model: `{s.ai_model}`\n"
        f"🔑 API Key: `{'Set ✓' if s.api_key else 'Not set'}`\n"
        f"📋 Report Platform: `{s.report_platform}`\n\n"
        "*Switch AI Provider:*"
    )
    kb = InlineKeyboardMarkup([
        [InlineKeyboardButton("🟢 Ollama (Free)", callback_data="prov_ollama"),
         InlineKeyboardButton("🔵 OpenAI",        callback_data="prov_openai")],
        [InlineKeyboardButton("🟣 Anthropic",     callback_data="prov_anthropic"),
         InlineKeyboardButton("⚡ Groq",          callback_data="prov_groq")],
        [InlineKeyboardButton("H1 HackerOne",     callback_data="plat_hackerone"),
         InlineKeyboardButton("BC Bugcrowd",      callback_data="plat_bugcrowd"),
         InlineKeyboardButton("IT Intigriti",     callback_data="plat_intigriti")],
    ])
    await safe_reply(update, text, reply_markup=kb)


# ─────────────────────────────────────────────────────────────────────────────
# /mystats
# ─────────────────────────────────────────────────────────────────────────────
@auth
async def cmd_mystats(update: Update, context: ContextTypes.DEFAULT_TYPE):
    s = get_session(update.effective_user)
    all_sessions = list(SESSIONS.values())
    active_count = sum(1 for sess in all_sessions if sess.is_scanning())

    text = (
        f"📈 *Your Stats*\n\n"
        f"👤 Username: `{s.username}`\n"
        f"🔢 Total scans: `{s.total_scans}`\n"
        f"⏰ Last scan: `{s.last_scan or 'Never'}`\n"
        f"🤖 AI Provider: `{s.ai_provider}`\n"
        f"📋 Platform: `{s.report_platform}`\n\n"
        f"🌐 *Bot-wide stats:*\n"
        f"• Active users: `{len(all_sessions)}`\n"
        f"• Scans running: `{active_count}`\n"
        f"• Total DB findings: `{db.get_stats().get('total', 0)}`"
    )
    await safe_reply(update, text)


# ─────────────────────────────────────────────────────────────────────────────
# Config commands
# ─────────────────────────────────────────────────────────────────────────────
@auth
async def cmd_set_provider(update: Update, context: ContextTypes.DEFAULT_TYPE):
    s = get_session(update.effective_user)
    valid = ["openai", "anthropic", "groq", "ollama"]
    if not context.args or context.args[0].lower() not in valid:
        await safe_reply(update, f"Usage: `/setprovider {{'|'.join(valid)}}`")
        return
    s.ai_provider = context.args[0].lower()
    await safe_reply(update, f"✅ AI provider set to: `{s.ai_provider}`")


@auth
async def cmd_set_model(update: Update, context: ContextTypes.DEFAULT_TYPE):
    s = get_session(update.effective_user)
    if not context.args:
        await safe_reply(update,
            "Usage: `/setmodel <model>`\n\n"
            "Examples:\n"
            "• `gpt-4o` (OpenAI)\n"
            "• `claude-3-5-sonnet-20241022` (Anthropic)\n"
            "• `llama-3.1-70b-versatile` (Groq)\n"
            "• `llama3` (Ollama)"
        )
        return
    s.ai_model = context.args[0]
    await safe_reply(update, f"✅ AI model set to: `{s.ai_model}`")


@auth
async def cmd_set_key(update: Update, context: ContextTypes.DEFAULT_TYPE):
    s = get_session(update.effective_user)
    if not context.args:
        await safe_reply(update, "Usage: `/setkey your-api-key`")
        return
    s.api_key = context.args[0]
    try:
        await update.message.delete()
    except Exception:
        pass
    await update.effective_chat.send_message(
        "✅ *API key saved!* _(Your message was deleted for security)_",
        parse_mode=ParseMode.MARKDOWN,
    )


@auth
async def cmd_set_platform(update: Update, context: ContextTypes.DEFAULT_TYPE):
    s = get_session(update.effective_user)
    valid = ["hackerone", "bugcrowd", "intigriti", "immunefi"]
    if not context.args or context.args[0].lower() not in valid:
        await safe_reply(update, f"Usage: `/setplatform {'|'.join(valid)}`")
        return
    s.report_platform = context.args[0].lower()
    await safe_reply(update, f"✅ Report platform set to: `{s.report_platform}`")


# ─────────────────────────────────────────────────────────────────────────────
# Inline button callbacks
# ─────────────────────────────────────────────────────────────────────────────
async def callback_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    query = update.callback_query
    await query.answer()
    data = query.data
    s = get_session(update.effective_user)

    if data == "help":
        await query.message.reply_text("Use /help to see all commands.")
    elif data == "myconfig":
        await query.message.reply_text("Use /myconfig to view your settings.")
    elif data == "myfindings":
        await query.message.reply_text("Use /findings to view your latest findings.")
    elif data == "myreport":
        await query.message.reply_text("Use /report to receive your latest report file.")
    elif data.startswith("prov_"):
        s.ai_provider = data.replace("prov_", "")
        await query.message.reply_text(
            f"✅ AI provider switched to: `{s.ai_provider}`",
            parse_mode=ParseMode.MARKDOWN
        )
    elif data.startswith("plat_"):
        s.report_platform = data.replace("plat_", "")
        await query.message.reply_text(
            f"✅ Report platform set to: `{s.report_platform}`",
            parse_mode=ParseMode.MARKDOWN
        )


# ─────────────────────────────────────────────────────────────────────────────
# Unknown command
# ─────────────────────────────────────────────────────────────────────────────
async def cmd_unknown(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await safe_reply(update, "❓ Unknown command. Use /help to see all commands.")


# ─────────────────────────────────────────────────────────────────────────────
# Error handler
# ─────────────────────────────────────────────────────────────────────────────
async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE):
    log.error(f"Bot error: {context.error}")


# ─────────────────────────────────────────────────────────────────────────────
# Main runner
# ─────────────────────────────────────────────────────────────────────────────
def run_bot(token: str, allowed_user_ids: list = None):
    global ALLOWED_USERS
    if allowed_user_ids:
        ALLOWED_USERS = allowed_user_ids

    log.info("Starting AI-BugBounty-Hunter Telegram Bot (Multi-User Mode)...")
    log.info(f"Authorization: {'Restricted to ' + str(len(ALLOWED_USERS)) + ' users' if ALLOWED_USERS else 'Open to all'}")

    app = Application.builder().token(token).build()

    # Handlers
    app.add_handler(CommandHandler("start",       cmd_start))
    app.add_handler(CommandHandler("help",        cmd_help))
    app.add_handler(CommandHandler("scan",        cmd_scan))
    app.add_handler(CommandHandler("quick",       cmd_quick))
    app.add_handler(CommandHandler("recon",       cmd_quick))
    app.add_handler(CommandHandler("status",      cmd_status))
    app.add_handler(CommandHandler("cancel",      cmd_cancel))
    app.add_handler(CommandHandler("findings",    cmd_findings))
    app.add_handler(CommandHandler("report",      cmd_report))
    app.add_handler(CommandHandler("myconfig",    cmd_myconfig))
    app.add_handler(CommandHandler("mystats",     cmd_mystats))
    app.add_handler(CommandHandler("setprovider", cmd_set_provider))
    app.add_handler(CommandHandler("setmodel",    cmd_set_model))
    app.add_handler(CommandHandler("setkey",      cmd_set_key))
    app.add_handler(CommandHandler("setplatform", cmd_set_platform))
    app.add_handler(CallbackQueryHandler(callback_handler))
    app.add_handler(MessageHandler(filters.COMMAND, cmd_unknown))
    app.add_error_handler(error_handler)

    # Bot command menu
    async def post_init(application: Application):
        await application.bot.set_my_commands([
            BotCommand("start",       "Welcome screen"),
            BotCommand("scan",        "Full AI scan: /scan example.com"),
            BotCommand("quick",       "Passive recon: /quick example.com"),
            BotCommand("status",      "Your scan progress"),
            BotCommand("findings",    "View findings"),
            BotCommand("report",      "Get report file"),
            BotCommand("cancel",      "Cancel your scan"),
            BotCommand("myconfig",    "Your settings"),
            BotCommand("mystats",     "Your scan stats"),
            BotCommand("setprovider", "Set AI provider"),
            BotCommand("setmodel",    "Set AI model"),
            BotCommand("setkey",      "Set API key"),
            BotCommand("setplatform", "Set report platform"),
            BotCommand("help",        "All commands"),
        ])
        log.info("Bot command menu registered.")

    app.post_init = post_init

    log.info("Bot running. Press Ctrl+C to stop.")
    app.run_polling(
        allowed_updates=Update.ALL_TYPES,
        drop_pending_updates=True,
    )


# ─────────────────────────────────────────────────────────────────────────────
# Entry point
# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "")
    ALLOWED_IDS_STR = os.getenv("TELEGRAM_ALLOWED_USERS", "")

    if not TOKEN:
        cfg_path = Path("bot_config.json")
        if cfg_path.exists():
            with open(cfg_path, encoding="utf-8") as f:
                bot_cfg = json.load(f)
            TOKEN = bot_cfg.get("telegram_token", "")
            allowed_list = bot_cfg.get("allowed_user_ids", [])
            if allowed_list:
                ALLOWED_IDS_STR = ",".join(str(x) for x in allowed_list)

    if not TOKEN:
        if len(sys.argv) > 1:
            TOKEN = sys.argv[1]
        else:
            print("\n  ERROR: No Telegram bot token found!")
            print("  1. Set env:  TELEGRAM_BOT_TOKEN=your-token")
            print("  2. Edit bot_config.json: {\"telegram_token\": \"your-token\"}")
            print("  3. Pass directly: python telegram_bot.py YOUR_TOKEN\n")
            sys.exit(1)

    allowed_ids = []
    if ALLOWED_IDS_STR:
        try:
            allowed_ids = [int(x.strip()) for x in ALLOWED_IDS_STR.split(",") if x.strip()]
        except ValueError:
            pass

    run_bot(TOKEN, allowed_ids)
