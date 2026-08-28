#!/usr/bin/env python3
"""
AI-BugBounty-Hunter — AI Finding Prioritizer
Ranks validated findings by real-world impact, exploitability, and business risk.
"""
import asyncio
import json
from typing import List, Dict, Any, Optional
from core.config import Config
from core.logger import Logger
from ai_engine.llm_client import LLMClient


# Severity ordering for fallback sort
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


class AIPrioritizer:
    """
    AI-powered finding prioritizer. Ranks findings by:
    - Real-world exploitability
    - Business impact
    - Chaining potential with other findings
    - Target-specific risk context
    """

    PRIORITIZE_PROMPT = """You are a senior bug bounty hunter prioritizing findings for submission.
Given these {count} validated findings, assign each a priority score 1-100 
(100 = submit immediately, 1 = lowest priority).

Consider:
- Exploitability (can it be exploited in the wild right now?)
- Business impact (data breach, account takeover, financial loss)
- Chaining potential with other findings
- Uniqueness (rare vulnerability types score higher)
- CVSS score

Findings:
{findings_json}

Return a JSON array of objects: [{{"index": 0, "priority": 95, "reason": "..."}}]
Only return JSON, no explanation."""

    def __init__(self, config: Config):
        self.config = config
        self.logger = Logger("AIPrioritizer")
        self.llm = LLMClient(config)

    async def prioritize(self, findings: List[Dict]) -> List[Dict]:
        """Prioritize findings. Returns sorted list (highest priority first)."""
        if not findings:
            return []

        if len(findings) == 1:
            findings[0]["priority"] = 80
            return findings

        self.logger.info(f"AI prioritizing {len(findings)} findings...")

        # Summarize findings for the prompt
        summaries = [
            {
                "index": i,
                "type": f.get("type", "Unknown"),
                "severity": f.get("severity", "info"),
                "cvss": f.get("cvss", 0),
                "url": f.get("url", ""),
                "description": str(f.get("description", ""))[:200],
                "impact": str(f.get("impact", ""))[:150],
            }
            for i, f in enumerate(findings)
        ]

        try:
            prompt = self.PRIORITIZE_PROMPT.format(
                count=len(findings),
                findings_json=json.dumps(summaries, indent=2)[:4000],
            )
            response = await self.llm.query(prompt, temperature=0.2)
            json_str = self.llm.extract_json(response)

            if json_str:
                priority_data = json.loads(json_str)
                if isinstance(priority_data, list):
                    for item in priority_data:
                        idx = item.get("index", -1)
                        if 0 <= idx < len(findings):
                            findings[idx]["priority"] = item.get("priority", 50)
                            findings[idx]["priority_reason"] = item.get("reason", "")

        except Exception as e:
            self.logger.debug(f"AI prioritization failed, using fallback: {e}")
            self._fallback_prioritize(findings)

        # Sort: highest priority first, then by CVSS, then severity
        findings.sort(
            key=lambda f: (
                -(f.get("priority", 50)),
                -(f.get("cvss", 0)),
                SEVERITY_ORDER.get(f.get("severity", "info"), 99),
            )
        )

        self.logger.info("Findings prioritized and sorted.")
        return findings

    def _fallback_prioritize(self, findings: List[Dict]):
        """Fallback: score based on severity + CVSS."""
        severity_scores = {"critical": 90, "high": 70, "medium": 45, "low": 20, "info": 5}
        for f in findings:
            sev_score = severity_scores.get(f.get("severity", "info"), 10)
            cvss_bonus = f.get("cvss", 0) * 2
            f["priority"] = min(100, int(sev_score + cvss_bonus))
            f["priority_reason"] = "Fallback score based on severity and CVSS"
