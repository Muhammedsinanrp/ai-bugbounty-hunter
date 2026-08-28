#!/usr/bin/env python3
"""
AI-BugBounty-Hunter — AI Finding Analyzer
Uses LLM to analyze raw findings, determine true impact, and contextualize.
"""
import asyncio
import json
from typing import List, Dict, Any, Optional
from core.config import Config
from core.logger import Logger
from ai_engine.llm_client import LLMClient


class AIAnalyzer:
    """
    AI-powered analysis engine. Takes raw scanner output and uses LLM to:
    - Determine real-world exploitability
    - Assess business impact
    - Remove obvious false positives
    - Add attack scenarios and proof-of-concept context
    - Assign accurate CVSS scores
    """

    PROMPT_TEMPLATE = """You are an expert bug bounty hunter and security analyst. Analyze the following potential vulnerability finding.

Target Context:
- Domain: {target}
- Technology Stack: {tech_stack}
- OSINT Context: {osint_data}

Raw Finding:
- Type: {finding_type}
- URL: {url}
- Parameter: {param}
- Payload: {payload}
- Evidence: {evidence}
- Raw Confidence: {raw_confidence}

Analyze this finding and return a JSON object with:
1. "is_valid": true/false (is this actually exploitable?)
2. "severity": "critical"/"high"/"medium"/"low"/"info"
3. "cvss_score": a float 0-10 (CVSS 3.1 base score)
4. "vulnerability_type": the precise OWASP/CWE category
5. "description": a short description of the vulnerability
6. "reproduction_steps": array of step-by-step strings
7. "impact": what an attacker could achieve
8. "remediation": how to fix it
9. "confidence": float 0.0-1.0
10. "attack_scenario": a realistic attack chain using this finding
11. "poc": a minimal proof-of-concept (curl command or code snippet)

Return ONLY valid JSON, no markdown formatting."""

    def __init__(self, config: Config):
        self.config = config
        self.logger = Logger("AIAnalyzer")
        self.llm = LLMClient(config)
        self._semaphore = asyncio.Semaphore(5)  # Limit concurrent AI calls

    async def analyze(
        self, findings: List[Dict], tech_stack: Dict, osint_data: Dict
    ) -> List[Dict]:
        """Analyze all findings with AI. Returns enriched findings."""
        if not findings:
            return []

        self.logger.info(f"Analyzing {len(findings)} findings with AI...")
        tech_str = json.dumps(tech_stack, indent=2)[:2000]
        osint_str = json.dumps(osint_data, indent=2)[:1000] if osint_data else "None"

        tasks = [
            self._analyze_single(finding, tech_str, osint_str) for finding in findings
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        enriched = []
        for original, result in zip(findings, results):
            if isinstance(result, Exception):
                self.logger.error(f"AI analysis failed: {result}")
                enriched.append(original)
            elif result:
                original["ai_analysis"] = result
                if result.get("is_valid") is False:
                    original["status"] = "false_positive"
                else:
                    original["status"] = "validated"
                    original["severity"] = result.get("severity", original.get("severity", "low"))
                    original["cvss"] = result.get("cvss_score", 0)
                    original["description"] = result.get("description", original.get("description", ""))
                    original["remediation"] = result.get("remediation", "")
                    original["impact"] = result.get("impact", "")
                    original["reproduction_steps"] = result.get("reproduction_steps", [])
                    original["poc"] = result.get("poc", "")
                    original["attack_scenario"] = result.get("attack_scenario", "")
                enriched.append(original)
            else:
                enriched.append(original)

        valid = [f for f in enriched if f.get("status") != "false_positive"]
        self.logger.info(
            f"AI analysis complete. {len(valid)}/{len(enriched)} findings survived."
        )
        return valid

    async def _analyze_single(
        self, finding: Dict, tech_str: str, osint_str: str
    ) -> Optional[Dict]:
        """Analyze a single finding using the LLM."""
        async with self._semaphore:
            prompt = self.PROMPT_TEMPLATE.format(
                target=self.config.target_domain,
                tech_stack=tech_str,
                osint_data=osint_str,
                finding_type=finding.get("type", "Unknown"),
                url=finding.get("url", ""),
                param=finding.get("parameter", ""),
                payload=str(finding.get("payload", ""))[:500],
                evidence=str(finding.get("evidence", ""))[:1000],
                raw_confidence=finding.get("confidence", 0.5),
            )

            try:
                response = await self.llm.query(prompt, temperature=0.1)
                json_str = self.llm.extract_json(response)
                if json_str:
                    return json.loads(json_str)
                return None
            except Exception as e:
                self.logger.debug(f"AI single analysis error: {e}")
                return None
