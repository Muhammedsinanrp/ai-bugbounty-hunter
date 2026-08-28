#!/usr/bin/env python3
"""
AI-BugBounty-Hunter — AI Orchestration Agent
The core brain that coordinates all modules, makes intelligent decisions,
and drives the full pipeline from recon to report.
"""
import asyncio
import json
import time
import uuid
from typing import List, Dict, Any, Optional, Callable
from pathlib import Path
from datetime import datetime

from core.config import Config
from core.database import FindingsDB
from core.logger import Logger


class AIAgent:
    """
    The master orchestrator. Coordinates recon → scanning → validation → reporting.
    Uses AI to make intelligent decisions at every stage.
    """

    def __init__(self, config: Config):
        self.config = config
        self.logger = Logger("AIAgent")
        self.db = FindingsDB()
        self.running = False
        self.progress_callback: Optional[Callable] = None
        self._results_cache: Dict[str, Any] = {}
        self._scan_id = str(uuid.uuid4())

        # Pipeline state
        self.target = config.target_domain
        self.subdomains: List[str] = []
        self.live_hosts: List[str] = []
        self.urls: List[str] = []
        self.parameters: List[Dict] = []
        self.tech_stack: Dict[str, List[str]] = {}
        self.findings: List[Dict] = []

    async def run_full_pipeline(self, domain: str) -> Dict[str, Any]:
        """Execute the complete bug bounty pipeline from start to finish."""
        self.target = domain
        self.config.set_target(domain)
        self.running = True
        start_time = time.time()
        self._scan_id = str(uuid.uuid4())

        self.logger.info(f"🎯 Starting full pipeline for: {domain}")
        self.db.save_scan(self._scan_id, domain)
        self._update_progress("initializing", 0)

        try:
            # Phase 1: Reconnaissance
            self._update_progress("recon", 5)
            await self._phase_recon()

            # Phase 2: Surface Enumeration
            self._update_progress("enumeration", 20)
            await self._phase_enumeration()

            # Phase 3: Smart Scanning
            self._update_progress("scanning", 40)
            await self._phase_scanning()

            # Phase 4: AI Analysis & Validation
            self._update_progress("ai_analysis", 70)
            await self._phase_ai_analysis()

            # Phase 5: Report Generation
            self._update_progress("reporting", 90)
            report = await self._phase_reporting()

            elapsed = time.time() - start_time
            self._update_progress("complete", 100)

            summary = {
                "target": domain,
                "scan_id": self._scan_id,
                "duration_seconds": elapsed,
                "subdomains_found": len(self.subdomains),
                "live_hosts": len(self.live_hosts),
                "urls_crawled": len(self.urls),
                "parameters_discovered": len(self.parameters),
                "tech_stack": self.tech_stack,
                "findings_total": len(self.findings),
                "critical_findings": sum(1 for f in self.findings if f.get("severity") == "critical"),
                "high_findings": sum(1 for f in self.findings if f.get("severity") == "high"),
                "medium_findings": sum(1 for f in self.findings if f.get("severity") == "medium"),
                "low_findings": sum(1 for f in self.findings if f.get("severity") == "low"),
                "info_findings": sum(1 for f in self.findings if f.get("severity") == "info"),
                "report_path": report.get("path", ""),
                "top_findings": self.findings[:5] if self.findings else [],
            }

            self.db.complete_scan(self._scan_id, len(self.findings), summary)

            self.logger.success(f"✅ Pipeline complete in {elapsed:.1f}s")
            self.logger.info(
                f"   Subdomains: {len(self.subdomains)} | Live: {len(self.live_hosts)} | URLs: {len(self.urls)}"
            )
            self.logger.info(
                f"   Findings: {len(self.findings)} "
                f"(C:{summary['critical_findings']} H:{summary['high_findings']} M:{summary['medium_findings']})"
            )

            return summary

        except Exception as e:
            self.logger.error(f"Pipeline failed: {e}")
            self._update_progress("failed", -1)
            return {"error": str(e), "target": domain}

        finally:
            self.running = False

    async def _phase_recon(self):
        """Phase 1: Intelligence gathering with AI-assisted discovery."""
        from recon.subdomain import SubdomainEnumerator
        from recon.osint import OSINTEnricher

        self.logger.banner("Phase 1: Reconnaissance")

        enum = SubdomainEnumerator(self.config)
        self.subdomains = await enum.discover(self.target)
        self.logger.info(f"  → Found {len(self.subdomains)} subdomains")

        osint = OSINTEnricher(self.config)
        osint_data = await osint.enrich(self.target, self.subdomains)
        self._results_cache["osint"] = osint_data

    async def _phase_enumeration(self):
        """Phase 2: Live host detection, tech fingerprinting, URL crawling."""
        from recon.port_scanner import PortScanner
        from recon.tech_detect import TechDetector
        from recon.url_crawler import URLCrawler

        self.logger.banner("Phase 2: Surface Enumeration")

        scanner = PortScanner(self.config)
        self.live_hosts = await scanner.scan(self.subdomains)
        self.logger.info(f"  → {len(self.live_hosts)} live hosts")

        tech = TechDetector(self.config)
        self.tech_stack = await tech.fingerprint(self.live_hosts)
        self.logger.info(f"  → Technologies detected: {sum(len(v) for v in self.tech_stack.values())}")

        crawler = URLCrawler(self.config)
        self.urls = await crawler.crawl(self.live_hosts)
        self.parameters = crawler.extracted_parameters
        self.logger.info(f"  → {len(self.urls)} URLs crawled, {len(self.parameters)} params found")

    async def _phase_scanning(self):
        """Phase 3: Intelligent vulnerability scanning."""
        from scanners.xss_scanner import XSSScanner
        from scanners.sqli_scanner import SQLIScanner
        from scanners.ssti_scanner import SSTIScanner
        from scanners.ssrf_scanner import SSRFScanner
        from scanners.lfi_scanner import LFIScanner
        from scanners.open_redirect import OpenRedirectScanner
        from scanners.idor_scanner import IDORScanner
        from scanners.api_tester import APITester
        from scanners.web3_scanner import Web3Scanner

        self.logger.banner("Phase 3: Smart Vulnerability Scanning")

        scan_config = self.config.get("scanners") or {}
        targets = self.urls[:self.config.get("target", "max_pages", default=500)]

        scan_tasks = []

        if scan_config.get("xss", {}).get("enabled"):
            scan_tasks.append(XSSScanner(self.config).scan(targets, self.parameters))
        if scan_config.get("sqli", {}).get("enabled"):
            scan_tasks.append(SQLIScanner(self.config).scan(targets, self.parameters))
        if scan_config.get("ssti", {}).get("enabled"):
            scan_tasks.append(SSTIScanner(self.config).scan(targets, self.parameters))
        if scan_config.get("ssrf", {}).get("enabled"):
            scan_tasks.append(SSRFScanner(self.config).scan(targets, self.parameters))
        if scan_config.get("lfi", {}).get("enabled"):
            scan_tasks.append(LFIScanner(self.config).scan(targets, self.parameters))
        if scan_config.get("open_redirect", {}).get("enabled"):
            scan_tasks.append(OpenRedirectScanner(self.config).scan(targets, self.parameters))
        if scan_config.get("idor", {}).get("enabled"):
            scan_tasks.append(IDORScanner(self.config).scan(targets, self.parameters, self.tech_stack))
        if scan_config.get("api", {}).get("enabled"):
            scan_tasks.append(APITester(self.config).scan(self.urls, self.parameters))
        if scan_config.get("web3", {}).get("enabled"):
            scan_tasks.append(Web3Scanner(self.config).scan(self.target))

        if not scan_tasks:
            self.logger.warning("No scanners enabled. Check your config.")
            return

        results = await asyncio.gather(*scan_tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                self.logger.error(f"Scanner failed: {result}")
                continue
            if result and isinstance(result, list):
                self.findings.extend(result)

        self.logger.info(f"  → Raw findings before validation: {len(self.findings)}")

    async def _phase_ai_analysis(self):
        """Phase 4: AI-powered analysis, validation gate, and prioritization."""
        from ai_engine.analyzer import AIAnalyzer
        from ai_engine.validator import AIValidator
        from ai_engine.prioritizer import AIPrioritizer

        self.logger.banner("Phase 4: AI Analysis & Validation Gate")

        analyzer = AIAnalyzer(self.config)
        self.findings = await analyzer.analyze(
            self.findings, self.tech_stack, self._results_cache.get("osint", {})
        )

        if self.config.get("ai_engine", "validation_gate_enabled", default=True):
            validator = AIValidator(self.config)
            self.findings = await validator.validate(self.findings)
            self.logger.info(f"  → After validation gate: {len(self.findings)} findings")

        if self.config.get("ai_engine", "auto_prioritize", default=True):
            prioritizer = AIPrioritizer(self.config)
            self.findings = await prioritizer.prioritize(self.findings)

        for finding in self.findings:
            self.db.save_finding(finding)

    async def _phase_reporting(self) -> Dict[str, Any]:
        """Phase 5: Generate submission-ready reports."""
        from ai_engine.report_gen import AIReportGenerator

        self.logger.banner("Phase 5: Report Generation")

        generator = AIReportGenerator(self.config)
        report = await generator.generate(
            target=self.target,
            findings=self.findings,
            subdomains=self.subdomains,
            live_hosts=self.live_hosts,
            tech_stack=self.tech_stack,
            summary=self._build_summary(),
        )

        self.logger.success(f"  → Report saved: {report.get('path', 'N/A')}")
        return report

    def _build_summary(self) -> Dict:
        return {
            "target": self.target,
            "timestamp": datetime.utcnow().isoformat(),
            "total_subdomains": len(self.subdomains),
            "total_live_hosts": len(self.live_hosts),
            "total_urls": len(self.urls),
            "total_parameters": len(self.parameters),
            "total_findings": len(self.findings),
            "severity_breakdown": {
                "critical": sum(1 for f in self.findings if f.get("severity") == "critical"),
                "high": sum(1 for f in self.findings if f.get("severity") == "high"),
                "medium": sum(1 for f in self.findings if f.get("severity") == "medium"),
                "low": sum(1 for f in self.findings if f.get("severity") == "low"),
                "info": sum(1 for f in self.findings if f.get("severity") == "info"),
            },
            "vulnerability_types": self._get_vuln_type_counts(),
        }

    def _get_vuln_type_counts(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for f in self.findings:
            vtype = f.get("type", "Unknown")
            counts[vtype] = counts.get(vtype, 0) + 1
        return counts

    def _update_progress(self, phase: str, percentage: int):
        if self.progress_callback:
            self.progress_callback(phase, percentage)

    def register_progress_callback(self, callback: Callable):
        self.progress_callback = callback
