#!/usr/bin/env python3
"""
AI-BugBounty-Hunter — AI Validation Gate
The critical quality filter. Inspired by BugHunter's 7-question gate
but enhanced with deep AI reasoning to eliminate false positives before submission.
"""
import asyncio
import json
from typing import List, Dict, Any, Optional
from core.config import Config
from core.logger import Logger
from ai_engine.llm_client import LLMClient


class AIValidator:
    """
    The Validation Gate — the most critical quality control step.
    Each finding must pass a rigorous AI-driven assessment before being reported.
    """

    VALIDATION_QUESTIONS = [
        "Is the vulnerability genuinely exploitable, or is it a false positive from scanner noise?",
        "Can the impact be demonstrated with a clear proof-of-concept, not just a theoretical scenario?",
        "Is there a realistic attack chain that begins with this vulnerability, given the target's architecture and defenses?",
        "Does this finding represent a real security boundary bypass, or is it self-XSS/cross-tenant noise that only affects the attacker?",
        "Is this finding novel/unexpected for this target, or is it a known/expected behavior the platform accepts?",
        "What is the business impact if exploited — data exposure, account takeover, RCE, or informational?",
        "Would a human triager accept this finding, or would they close it as 'informative' or 'out of scope'?",
    ]

    VALIDATION_PROMPT = """You are a strict bug bounty triager working for a major platform (HackerOne, Bugcrowd).
Your reputation depends on only accepting high-quality, validated findings.
You MUST be skeptical — most scanner output is noise.

Finding to validate:
- Target: {target}
- Type: {vulnerability_type}
- URL: {url}
- Parameter: {parameter}
- Severity (raw): {severity}
- Description: {description}
- Evidence: {evidence}
- POC: {poc}
- Tech Stack: {tech_stack}
- CVSS Score: {cvss}

Answer these {num_questions} validation questions with "yes" or "no" AND a brief justification:

{questions}

After answering all questions, decide:
- "accepted": The finding is valid, exploitable, and in-scope.
- "rejected_false_positive": The scanner generated a false positive.
- "rejected_out_of_scope": Valid issue but out of scope for bug bounty.
- "rejected_low_impact": Technically valid but impact too low to report.
- "rejected_duplicate": Likely a known/duplicate finding.

Return your analysis as a JSON object:
{{
    "questions": [{{"question": "...", "answer": "yes/no", "justification": "..."}}],
    "decision": "accepted/rejected_...",
    "final_severity": "critical/high/medium/low/info",
    "final_cvss": 0.0,
    "triage_notes": "...",
    "requires_human_review": true/false
}}

Return ONLY valid JSON."""

    def __init__(self, config: Config):
        self.config = config
        self.logger = Logger("AIValidator")
        self.llm = LLMClient(config)
        self._semaphore = asyncio.Semaphore(3)

    async def validate(self, findings: List[Dict]) -> List[Dict]:
        """Run each finding through the validation gate. Returns only accepted findings."""
        if not findings:
            return []

        num_questions = self.config.get("ai_engine", "validation_questions", default=7)
        self.logger.info(
            f"Running {num_questions}-question validation gate on {len(findings)} findings..."
        )

        tasks = [self._validate_finding(f, num_questions) for f in findings]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        accepted = []
        rejected: Dict[str, int] = {
            "false_positive": 0, "out_of_scope": 0, "low_impact": 0, "duplicate": 0, "error": 0
        }

        for original, result in zip(findings, results):
            if isinstance(result, Exception):
                self.logger.error(f"Validation failed for finding: {result}")
                rejected["error"] += 1
                continue

            if result and result.get("decision") == "accepted":
                original["validation"] = result
                original["validated"] = True
                original["severity"] = result.get("final_severity", original.get("severity", "low"))
                original["cvss"] = result.get("final_cvss", original.get("cvss", 0))
                original["triage_notes"] = result.get("triage_notes", "")
                original["requires_human_review"] = result.get("requires_human_review", False)
                accepted.append(original)
            else:
                reason = (result.get("decision", "unknown") if result else "no_response")
                if "false_positive" in reason:
                    rejected["false_positive"] += 1
                elif "out_of_scope" in reason:
                    rejected["out_of_scope"] += 1
                elif "low_impact" in reason:
                    rejected["low_impact"] += 1
                elif "duplicate" in reason:
                    rejected["duplicate"] += 1
                else:
                    rejected["error"] += 1

        self.logger.info("Validation gate complete:")
        self.logger.info(f"  ✓ Accepted: {len(accepted)}")
        for reason, count in rejected.items():
            if count > 0:
                self.logger.info(f"  ✗ Rejected ({reason}): {count}")

        return accepted

    async def _validate_finding(self, finding: Dict, num_questions: int) -> Optional[Dict]:
        """Validate a single finding through the AI gate."""
        async with self._semaphore:
            questions_text = "\n".join(
                f"{i+1}. {q}" for i, q in enumerate(self.VALIDATION_QUESTIONS[:num_questions])
            )
            prompt = self.VALIDATION_PROMPT.format(
                target=self.config.target_domain,
                vulnerability_type=finding.get("type", "Unknown"),
                url=finding.get("url", "N/A"),
                parameter=finding.get("parameter", "N/A"),
                severity=finding.get("severity", "low"),
                description=finding.get(
                    "description",
                    finding.get("ai_analysis", {}).get("description", "No description"),
                ),
                evidence=str(finding.get("evidence", ""))[:2000],
                poc=str(finding.get("poc", finding.get("ai_analysis", {}).get("poc", "")))[:1000],
                tech_stack=json.dumps(finding.get("tech_context", {}), indent=2)[:1000],
                cvss=finding.get("cvss", finding.get("ai_analysis", {}).get("cvss_score", 0)),
                num_questions=num_questions,
                questions=questions_text,
            )

            try:
                response = await self.llm.query(prompt, temperature=0.1)
                json_str = self.llm.extract_json(response)
                if json_str:
                    return json.loads(json_str)
                return None
            except Exception as e:
                self.logger.debug(f"Validation error: {e}")
                return None
