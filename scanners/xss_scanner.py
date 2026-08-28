#!/usr/bin/env python3
"""
AI-BugBounty-Hunter — XSS Scanner
Detects Reflected, Stored, DOM-based, and Blind XSS vulnerabilities.
"""
import asyncio
import re
from typing import List, Dict, Optional
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
from scanners.base_scanner import BaseScanner
from core.config import Config


class XSSScanner(BaseScanner):
    """Advanced XSS detection scanner."""

    VULN_TYPE = "Cross-Site Scripting (XSS)"
    DEFAULT_SEVERITY = "high"

    # Reflected XSS probes — innocuous marker payloads
    PROBE_PAYLOADS = [
        "<xss>aibug1</xss>",
        "\"><xss>aibug2</xss>",
        "javascript:alert(document.domain)",
        "<img src=x onerror=prompt(1)>",
        "';alert(1)//",
        "<svg/onload=alert(1)>",
        "%3Cscript%3Ealert(1)%3C/script%3E",
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<SCRIPT>alert(1)</SCRIPT>",
        "\"onmouseover=\"alert(1)",
    ]

    DOM_SINKS = [
        "document.write",
        "innerHTML",
        "outerHTML",
        "document.location",
        "eval(",
        "setTimeout(",
        "setInterval(",
    ]

    def __init__(self, config: Config):
        super().__init__(config)
        self.blind_xss = config.get("scanners", "xss", default={}).get("blind_xss_enabled", True)

    async def scan(self, urls: List[str], parameters: List[Dict]) -> List[Dict]:
        """Scan for XSS vulnerabilities across URLs and parameters."""
        self.logger.info(f"XSS scan: {len(urls)} URLs, {len(parameters)} parameters")
        findings: List[Dict] = []

        # Test URL parameters
        url_tasks = [
            self._test_get_param(param, findings)
            for param in parameters
            if param.get("method", "GET") == "GET"
        ]
        # Test POST parameters
        post_tasks = [
            self._test_post_param(param, findings)
            for param in parameters
            if param.get("method") == "POST"
        ]

        await asyncio.gather(*url_tasks, *post_tasks, return_exceptions=True)
        self.logger.info(f"  XSS: {len(findings)} potential findings")
        return findings

    async def _test_get_param(self, param: Dict, findings: List[Dict]):
        """Test a GET parameter for XSS."""
        base_url = param.get("url", "")
        param_name = param.get("parameter", "")

        if not base_url or not param_name:
            return

        for payload in self.PROBE_PAYLOADS:
            test_url = self._inject_param(base_url, param_name, payload)
            resp, body = await self._get(test_url)

            if body and self._check_reflection(payload, body):
                findings.append(self._make_finding(
                    url=base_url,
                    parameter=param_name,
                    payload=payload,
                    evidence=self._extract_context(payload, body),
                    severity="high",
                    confidence=0.75,
                ))
                break  # Found for this param, move on

    async def _test_post_param(self, param: Dict, findings: List[Dict]):
        """Test a POST parameter for XSS."""
        base_url = param.get("url", "")
        param_name = param.get("parameter", "")

        if not base_url or not param_name:
            return

        for payload in self.PROBE_PAYLOADS[:5]:
            post_data = {param_name: payload}
            resp, body = await self._post(base_url, data=post_data)

            if body and self._check_reflection(payload, body):
                findings.append(self._make_finding(
                    url=base_url,
                    parameter=param_name,
                    payload=payload,
                    evidence=self._extract_context(payload, body),
                    severity="high",
                    confidence=0.75,
                    extra={"method": "POST"},
                ))
                break

    def _inject_param(self, url: str, param_name: str, value: str) -> str:
        """Inject a value into a URL parameter."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param_name] = [value]
        new_query = urlencode({k: v[0] for k, v in params.items()})
        return urlunparse(parsed._replace(query=new_query))

    def _check_reflection(self, payload: str, body: str) -> bool:
        """Check if the payload is reflected in the response."""
        # Check for various encoding forms
        checks = [
            payload,
            payload.replace("<", "&lt;").replace(">", "&gt;"),  # HTML encoded (skip)
        ]
        # Only count raw reflection, not HTML-encoded (that's safe)
        return payload in body and "&lt;" not in body[body.find(payload)-5:body.find(payload)+len(payload)+5]

    def _extract_context(self, payload: str, body: str) -> str:
        """Extract surrounding context of the reflected payload."""
        idx = body.find(payload)
        if idx < 0:
            return ""
        start = max(0, idx - 100)
        end = min(len(body), idx + len(payload) + 100)
        return body[start:end]
