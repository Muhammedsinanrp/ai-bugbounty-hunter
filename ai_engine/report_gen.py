#!/usr/bin/env python3
"""
AI-BugBounty-Hunter — AI Report Generator
Generates submission-ready bug bounty reports for multiple platforms.
"""
import json
import os
from datetime import datetime
from typing import List, Dict, Any, Optional
from pathlib import Path

from core.config import Config
from core.logger import Logger
from ai_engine.llm_client import LLMClient


class AIReportGenerator:
    """
    Generates professional, submission-ready reports.
    Supports HackerOne, Bugcrowd, Intigriti, and Immunefi formats.
    """

    PLATFORM_TEMPLATES: Dict[str, Dict] = {
        "hackerone": {
            "fields": [
                "Summary", "Description", "Impact", "Steps to Reproduce",
                "Suggested Fix", "Impact Score (CVSS)", "Proof of Concept",
                "Supporting Material",
            ],
            "max_title_length": 255,
        },
        "bugcrowd": {
            "fields": [
                "Title", "Vulnerability Type", "Severity", "Description",
                "Steps to Reproduce", "Impact", "Proof of Concept",
                "Suggested Remediation",
            ],
            "max_title_length": 200,
        },
        "intigriti": {
            "fields": [
                "Title", "Description", "Impact", "Proof of Concept",
                "Resolution", "CVSS Score",
            ],
            "max_title_length": 150,
        },
        "immunefi": {
            "fields": [
                "Title", "Description", "Impact", "Proof of Concept",
                "Risk Classification", "Submission Details",
            ],
            "max_title_length": 200,
        },
    }

    REPORT_PROMPT = """You are a professional bug bounty report writer.
Generate a submission-ready report for the following finding on {platform}.

Target: {target}
Vulnerability Type: {vtype}
Severity: {severity}
CVSS: {cvss}
Description: {description}
Steps: {steps}
Impact: {impact}
POC: {poc}
Remediation: {remediation}
Attack Scenario: {scenario}

Write a professional report using the {platform} format with these fields: {fields}

The report must be:
- Clear and concise
- Include exact reproduction steps
- Show business impact concretely
- Include a working PoC
- Professional tone

Return the report in the exact format expected by {platform}.
Make the title compelling but factual."""

    def __init__(self, config: Config):
        self.config = config
        self.logger = Logger("ReportGen")
        self.llm = LLMClient(config)
        self.platform = config.get("reports", "platform", default="hackerone")
        self.report_dir = Path("reports/output")
        self.report_dir.mkdir(parents=True, exist_ok=True)

    async def generate(
        self,
        target: str,
        findings: List[Dict],
        subdomains: List[str],
        live_hosts: List[str],
        tech_stack: Dict,
        summary: Dict,
    ) -> Dict[str, Any]:
        """Generate the complete report."""
        if not findings:
            self.logger.info("No findings to report.")
            return {"path": "", "platform": self.platform, "findings_count": 0}

        template = self.PLATFORM_TEMPLATES.get(
            self.platform, self.PLATFORM_TEMPLATES["hackerone"]
        )
        fields_text = ", ".join(template["fields"])

        timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace(".", "_").replace("/", "_")
        report_dir = self.report_dir / safe_target
        report_dir.mkdir(parents=True, exist_ok=True)

        generated_reports = []

        for i, finding in enumerate(findings):
            if finding.get("status") == "false_positive":
                continue

            try:
                report_content = await self._generate_finding_report(
                    finding, template, fields_text
                )
                if report_content:
                    vtype_safe = finding.get("type", "vuln").replace(" ", "_")
                    fname = f"{i+1:02d}_{vtype_safe}_{finding.get('severity', 'medium')}.md"
                    fpath = report_dir / fname
                    with open(fpath, "w", encoding="utf-8") as f:
                        f.write(report_content)
                    generated_reports.append({
                        "file": str(fpath),
                        "title": finding.get("description", f"Finding {i+1}")[:100],
                        "severity": finding.get("severity", "low"),
                        "type": finding.get("type", "Unknown"),
                    })
                    self.logger.info(f"  Report: {fpath.name}")
            except Exception as e:
                self.logger.error(f"Failed to generate report for finding {i}: {e}")

        summary_path = await self._generate_executive_summary(
            target, summary, tech_stack, generated_reports, report_dir
        )
        combined_path = await self._generate_combined_report(
            target, findings, subdomains, live_hosts, tech_stack, summary, report_dir
        )

        return {
            "path": str(report_dir),
            "platform": self.platform,
            "target": target,
            "findings_count": len(generated_reports),
            "individual_reports": generated_reports,
            "summary_path": str(summary_path) if summary_path else "",
            "combined_path": str(combined_path) if combined_path else "",
            "timestamp": timestamp,
        }

    async def _generate_finding_report(
        self, finding: Dict, template: Dict, fields_text: str
    ) -> Optional[str]:
        """Generate a single finding report using AI."""
        ai = finding.get("ai_analysis", {})
        repro = finding.get("reproduction_steps", ai.get("reproduction_steps", ["N/A"]))
        if isinstance(repro, list):
            repro = "\n".join(repro)

        prompt = self.REPORT_PROMPT.format(
            platform=self.platform.title(),
            target=self.config.target_domain,
            vtype=finding.get("type", "Unknown"),
            severity=finding.get("severity", "medium"),
            cvss=finding.get("cvss", ai.get("cvss_score", 0)),
            description=finding.get("description", ai.get("description", "No description")),
            steps=repro,
            impact=finding.get("impact", ai.get("impact", "N/A")),
            poc=str(finding.get("poc", ai.get("poc", "N/A"))),
            remediation=finding.get("remediation", ai.get("remediation", "N/A")),
            scenario=finding.get("attack_scenario", ai.get("attack_scenario", "N/A")),
            fields=fields_text,
        )

        try:
            response = await self.llm.query(prompt, temperature=0.2)
            return response
        except Exception as e:
            self.logger.debug(f"Report generation failed: {e}")
            return None

    async def _generate_executive_summary(
        self,
        target: str,
        summary: Dict,
        tech_stack: Dict,
        reports: List[Dict],
        report_dir: Path,
    ) -> Optional[Path]:
        """Generate an executive summary of all findings."""
        lines = [
            f"# AI Bug Bounty Report — {target}",
            f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}",
            f"**Platform:** {self.platform.title()}",
            "",
            "## Executive Summary",
            "",
            f"- **Target:** {target}",
            f"- **Subdomains Discovered:** {summary.get('total_subdomains', 0)}",
            f"- **Live Hosts:** {summary.get('total_live_hosts', 0)}",
            f"- **URLs Crawled:** {summary.get('total_urls', 0)}",
            f"- **Parameters Found:** {summary.get('total_parameters', 0)}",
            f"- **Total Validated Findings:** {summary.get('total_findings', 0)}",
            "",
            "### Severity Breakdown",
        ]

        sev = summary.get("severity_breakdown", {})
        badges = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪"}
        for level in ["critical", "high", "medium", "low", "info"]:
            count = sev.get(level, 0)
            if count > 0:
                lines.append(f"- {badges[level]} **{level.title()}:** {count}")

        if tech_stack:
            lines.extend(["", "### Technology Stack Detected"])
            for tech, details in tech_stack.items():
                lines.append(f"- **{tech}:** {', '.join(list(details)[:5])}")

        lines.extend([
            "", "## Findings Summary", "",
            "| # | Type | Severity | Title |",
            "|---|------|----------|-------|",
        ])
        for i, r in enumerate(reports, 1):
            lines.append(f"| {i} | {r['type']} | {r['severity']} | {r['title']} |")

        lines.extend(["", "---", "*Report generated by AI-BugBounty-Hunter v1.0*"])

        content = "\n".join(lines)
        path = report_dir / "executive_summary.md"
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path

    async def _generate_combined_report(
        self,
        target: str,
        findings: List[Dict],
        subdomains: List[str],
        live_hosts: List[str],
        tech_stack: Dict,
        summary: Dict,
        report_dir: Path,
    ) -> Optional[Path]:
        """Generate a combined platform-specific report."""
        path = report_dir / f"combined_report_{self.platform}.md"
        vuln_summary = summary.get("vulnerability_types", {})
        top_vulns = dict(
            sorted(vuln_summary.items(), key=lambda x: x[1], reverse=True)[:10]
        )

        lines = [
            "# Bug Bounty Submission Report",
            f"**Target:** {target}",
            f"**Report Date:** {datetime.utcnow().strftime('%Y-%m-%d')}",
            f"**Platform:** {self.platform.title()}",
            "", "---", "", "## Vulnerability Summary", "",
            f"A total of **{len(findings)}** vulnerabilities were identified during testing:",
            "",
        ]

        sev = summary.get("severity_breakdown", {})
        for level in ["critical", "high", "medium", "low", "info"]:
            count = sev.get(level, 0)
            if count > 0:
                lines.append(f"- **{level.title()}:** {count}")

        if top_vulns:
            lines.extend(["", "### Vulnerability Types"])
            for vtype, count in top_vulns.items():
                lines.append(f"- **{vtype}:** {count}")

        lines.extend(["", "---", "", "## Detailed Findings", ""])

        for i, finding in enumerate(findings, 1):
            ai = finding.get("ai_analysis", {})
            vuln_type = finding.get("type", "Unknown")
            severity = finding.get("severity", "low").upper()
            desc = finding.get("description", ai.get("description", "No description"))
            url = finding.get("url", "N/A")
            param = finding.get("parameter", "N/A")
            poc = finding.get("poc", ai.get("poc", "N/A"))
            impact = finding.get("impact", ai.get("impact", "N/A"))
            remediation = finding.get("remediation", ai.get("remediation", "N/A"))
            repro_steps = finding.get(
                "reproduction_steps", ai.get("reproduction_steps", [])
            )

            lines.extend([
                f"### Finding #{i}: {vuln_type}", "",
                f"**Severity:** {severity}",
                f"**CVSS:** {finding.get('cvss', 'N/A')}",
                f"**URL:** `{url}`",
                f"**Parameter:** `{param}`",
                "", "**Description:**", desc,
                "", "**Impact:**", impact,
                "", "**Steps to Reproduce:**",
            ])

            if isinstance(repro_steps, list):
                for step_num, step in enumerate(repro_steps, 1):
                    lines.append(f"{step_num}. {step}")
            else:
                lines.append(f"- {repro_steps}")

            lines.extend([
                "", "**Proof of Concept:**",
                "```", str(poc), "```",
                "", "**Remediation:**", remediation,
                "", "---", "",
            ])

        lines.append("_Report generated by AI-BugBounty-Hunter v1.0_")

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return path
