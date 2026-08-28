#!/usr/bin/env python3
"""
AI-BugBounty-Hunter — Command Line Interface
The main entry point for the tool.
"""
import asyncio
import argparse
import sys
import json
from pathlib import Path
from datetime import datetime

from core.config import Config
from core.agent import AIAgent
from core.logger import Logger


def banner():
    print(r"""
    ╔══════════════════════════════════════════════════════╗
    ║   █████╗ ██╗    ██████╗ ██╗   ██╗ ██████╗           ║
    ║  ██╔══██╗██║    ██╔══██╗██║   ██║██╔════╝           ║
    ║  ███████║██║    ██████╔╝██║   ██║██║  ███╗          ║
    ║  ██╔══██║██║    ██╔══██╗██║   ██║██║   ██║          ║
    ║  ██║  ██║██║    ██████╔╝╚██████╔╝╚██████╔╝          ║
    ║  ╚═╝  ╚═╝╚═╝    ╚═════╝  ╚═════╝  ╚═════╝           ║
    ║                                                        ║
    ║         AI Bug Bounty Hunter  v1.0                     ║
    ║     AI-Powered Vulnerability Discovery Platform         ║
    ╚══════════════════════════════════════════════════════╝
    """)


def parse_args():
    parser = argparse.ArgumentParser(
        description="AI-BugBounty-Hunter — AI-Powered Bug Bounty Automation Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py example.com                                # Full pipeline (Ollama)
  python cli.py example.com --ai-provider openai          # Use OpenAI
  python cli.py example.com --quick                       # Passive recon only
  python cli.py example.com --recon-only                  # Recon only
  python cli.py example.com --stealth                     # Stealth mode
  python cli.py example.com --report --platform bugcrowd # Generate report
  python cli.py example.com --validate                    # Validate findings
        """,
    )

    parser.add_argument("target", nargs="?", help="Target domain (e.g., example.com)")

    # AI Configuration
    ai_group = parser.add_argument_group("AI Configuration")
    ai_group.add_argument("--config", "-c", default="config.json",
                          help="Path to configuration file (default: config.json)")
    ai_group.add_argument("--ai-provider", choices=["openai", "anthropic", "groq", "ollama"],
                          help="AI provider to use")
    ai_group.add_argument("--ai-model", help="AI model name (e.g., gpt-4o, claude-3-5-sonnet)")
    ai_group.add_argument("--api-key", help="AI API key (or set AI_API_KEY env var)")

    # Output
    out_group = parser.add_argument_group("Output")
    out_group.add_argument("--output", "-o", default="reports/output",
                           help="Output directory for reports")
    out_group.add_argument("--format", choices=["markdown", "json", "html"],
                           default="markdown", help="Report format")
    out_group.add_argument("--platform", choices=["hackerone", "bugcrowd", "intigriti", "immunefi"],
                           help="Bug bounty platform for report format")
    out_group.add_argument("--verbose", "-v", action="count", default=0,
                           help="Verbosity level (-v, -vv, -vvv)")

    # Scope
    scope_group = parser.add_argument_group("Scope")
    scope_group.add_argument("--scope", nargs="+", help="Additional in-scope URLs/domains")
    scope_group.add_argument("--exclude", nargs="+", help="Exclude patterns from scanning")

    # Modes
    mode_group = parser.add_argument_group("Modes")
    mode_group.add_argument("--recon-only", action="store_true",
                            help="Run reconnaissance only, skip scanning")
    mode_group.add_argument("--scan-only", action="store_true",
                            help="Skip recon, only run scanners on provided scope URLs")
    mode_group.add_argument("--quick", action="store_true",
                            help="Quick mode: passive recon only, no active scanning")
    mode_group.add_argument("--stealth", action="store_true",
                            help="Stealth mode: random delays, proxy rotation")
    mode_group.add_argument("--validate", action="store_true",
                            help="Only run validation gate on existing findings in DB")
    mode_group.add_argument("--report", action="store_true",
                            help="Only generate report from existing findings in DB")

    # Integration
    int_group = parser.add_argument_group("Integration")
    int_group.add_argument("--webhook", help="Slack/Discord webhook URL for notifications")
    int_group.add_argument("--findings-file",
                           help="Load findings from JSON file instead of scanning")

    return parser.parse_args()


async def send_webhook_notification(webhook_url: str, message: str):
    """Send notification to Slack/Discord webhook."""
    try:
        import aiohttp
        payload = {"text": message, "content": message}  # Works for both Slack and Discord
        async with aiohttp.ClientSession() as session:
            await session.post(webhook_url, json=payload, timeout=aiohttp.ClientTimeout(total=10))
    except Exception:
        pass


async def main():
    args = parse_args()
    banner()

    # Initialize configuration
    config = Config(args.config)

    # Apply CLI overrides
    if args.ai_provider:
        config.data["ai"]["provider"] = args.ai_provider
    if args.ai_model:
        config.data["ai"]["model"] = args.ai_model
    if args.api_key:
        config.data["ai"]["api_key"] = args.api_key
    if args.output:
        config.data["reports"]["output_dir"] = args.output
    if args.format:
        config.data["reports"]["format"] = args.format
    if args.platform:
        config.data["reports"]["platform"] = args.platform
    if args.stealth:
        config.data["stealth"]["enabled"] = True
    if args.exclude:
        config.data["target"]["exclude"] = args.exclude
    if args.scope:
        config.data["target"]["scope"] = args.scope

    logger = Logger("CLI", verbose=args.verbose)

    # Validate arguments
    if not args.target and not args.report and not args.validate:
        print("\n  ⚠  Error: No target specified.")
        print("  Usage: python cli.py example.com [options]")
        print("         python cli.py --help for full options\n")
        sys.exit(1)

    # Load existing findings if provided
    existing_findings = []
    if args.findings_file:
        try:
            with open(args.findings_file) as f:
                existing_findings = json.load(f)
            logger.info(f"Loaded {len(existing_findings)} findings from {args.findings_file}")
        except Exception as e:
            logger.error(f"Failed to load findings file: {e}")
            sys.exit(1)

    # Create the AI Agent
    agent = AIAgent(config)

    # Setup progress callback
    def on_progress(phase: str, percentage: int):
        if percentage >= 0:
            bars = "█" * (percentage // 5)
            spaces = "░" * (20 - percentage // 5)
            print(f"\r  [{bars}{spaces}] {percentage:3d}% — {phase.upper():<15}", end="", flush=True)
        else:
            print(f"\r  [✗] Failed — {phase}")

    agent.register_progress_callback(on_progress)

    try:
        # ── Report-only mode ─────────────────────────────────────────
        if args.report:
            logger.info("📄 Report generation mode...")
            from ai_engine.report_gen import AIReportGenerator
            generator = AIReportGenerator(config)

            findings = existing_findings or agent.db.get_all_findings(args.target)
            if not findings:
                logger.error("No findings in database for this target. Run a scan first.")
                sys.exit(1)

            report = await generator.generate(
                target=args.target or "unknown",
                findings=findings,
                subdomains=[],
                live_hosts=[],
                tech_stack={},
                summary={"total_findings": len(findings)},
            )
            logger.success(f"Report generated: {report.get('path', 'N/A')}")

        # ── Validation-only mode ──────────────────────────────────────
        elif args.validate:
            logger.info("🔍 Validation gate mode...")
            from ai_engine.validator import AIValidator
            validator = AIValidator(config)

            findings = existing_findings or agent.db.get_all_findings(args.target)
            if not findings:
                logger.error("No findings in database. Run a scan first.")
                sys.exit(1)

            validated = await validator.validate(findings)
            logger.success(f"Validation complete. {len(validated)}/{len(findings)} findings accepted.")

        # ── Recon-only mode ───────────────────────────────────────────
        elif args.recon_only:
            logger.info(f"🔭 Reconnaissance mode for: {args.target}")
            config.set_target(args.target)

            from recon.subdomain import SubdomainEnumerator
            from recon.port_scanner import PortScanner
            from recon.tech_detect import TechDetector

            enum = SubdomainEnumerator(config)
            subdomains = await enum.discover(args.target)
            logger.success(f"Found {len(subdomains)} subdomains")

            if subdomains:
                scanner = PortScanner(config)
                live = await scanner.scan(subdomains)
                logger.success(f"Found {len(live)} live hosts")

                if live:
                    tech = TechDetector(config)
                    tech_stack = await tech.fingerprint(live)
                    total_techs = sum(len(v) for v in tech_stack.values())
                    logger.info(f"Technologies detected: {total_techs}")

                    output = {
                        "target": args.target,
                        "timestamp": datetime.utcnow().isoformat(),
                        "subdomains": subdomains,
                        "live_hosts": live,
                        "tech_stack": tech_stack,
                    }

                    out_path = Path(args.output) / f"{args.target}_recon.json"
                    out_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(out_path, "w") as f:
                        json.dump(output, f, indent=2)
                    logger.success(f"Recon data saved: {out_path}")

        # ── Quick passive mode ────────────────────────────────────────
        elif args.quick:
            logger.info(f"⚡ Quick passive mode for: {args.target}")
            config.data["recon"]["use_passive_only"] = True
            config.data["target"]["max_pages"] = 100
            summary = await agent.run_full_pipeline(args.target)
            print("\n\n" + json.dumps(summary, indent=2, default=str))

        # ── Full pipeline ─────────────────────────────────────────────
        else:
            logger.info(f"🚀 Starting full bug bounty pipeline for: {args.target}")
            logger.info(f"   AI Provider: {config.ai_provider}")
            logger.info(f"   AI Model:    {config.get('ai', 'model', default='default')}")
            logger.info(f"   Report Fmt:  {config.get('reports', 'platform', default='hackerone')}")

            summary = await agent.run_full_pipeline(args.target)

            print("\n\n")
            print("╔" + "═" * 58 + "╗")
            print("║" + "  📋 PIPELINE SUMMARY".center(58) + "║")
            print("╠" + "═" * 58 + "╣")
            print(f"║  Target:          {summary.get('target', 'N/A'):<38}║")
            print(f"║  Duration:        {summary.get('duration_seconds', 0):.1f}s{'':<35}║")
            print(f"║  Subdomains:      {summary.get('subdomains_found', 0):<38}║")
            print(f"║  Live Hosts:      {summary.get('live_hosts', 0):<38}║")
            print(f"║  URLs Crawled:    {summary.get('urls_crawled', 0):<38}║")
            print(f"║  Params Found:    {summary.get('parameters_discovered', 0):<38}║")
            print("╠" + "═" * 58 + "╣")
            print(f"║  Total Findings:  {summary.get('findings_total', 0):<38}║")
            if summary.get("critical_findings", 0):
                print(f"║  🔴 Critical:     {summary['critical_findings']:<38}║")
            if summary.get("high_findings", 0):
                print(f"║  🟠 High:         {summary['high_findings']:<38}║")
            if summary.get("medium_findings", 0):
                print(f"║  🟡 Medium:       {summary['medium_findings']:<38}║")
            if summary.get("low_findings", 0):
                print(f"║  🔵 Low:          {summary['low_findings']:<38}║")
            print("╠" + "═" * 58 + "╣")
            report_path = summary.get("report_path", "")
            if report_path:
                print(f"║  📄 Report:       {report_path[:38]:<38}║")
            print("╚" + "═" * 58 + "╝")

            # Save summary JSON
            summary_path = Path(args.output) / f"{args.target}_summary.json"
            summary_path.parent.mkdir(parents=True, exist_ok=True)
            with open(summary_path, "w") as f:
                json.dump(summary, f, indent=2, default=str)
            print(f"\n  💾 Summary saved: {summary_path}")

            # Webhook notification
            if args.webhook and summary:
                msg = (
                    f"🎯 *AI-BugBounty-Hunter* scan complete for `{args.target}`\n"
                    f"• Findings: {summary.get('findings_total', 0)} "
                    f"(Critical: {summary.get('critical_findings', 0)}, "
                    f"High: {summary.get('high_findings', 0)})\n"
                    f"• Duration: {summary.get('duration_seconds', 0):.1f}s"
                )
                await send_webhook_notification(args.webhook, msg)

    except KeyboardInterrupt:
        print("\n\n  ⚠  Interrupted by user. Partial results may be saved.")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        if args.verbose > 1:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
