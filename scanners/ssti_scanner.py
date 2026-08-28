#!/usr/bin/env python3
"""
AI-BugBounty-Hunter — SSTI Scanner
Detects Server-Side Template Injection across multiple template engines.
"""
import asyncio
import re
from typing import List, Dict
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
from scanners.base_scanner import BaseScanner
from core.config import Config


class SSTIScanner(BaseScanner):
    """Server-Side Template Injection (SSTI) scanner."""

    VULN_TYPE = "Server-Side Template Injection (SSTI)"
    DEFAULT_SEVERITY = "critical"

    # Math expressions that if evaluated server-side produce a known result
    PROBES = [
        ("{{7*7}}", "49"),           # Jinja2, Twig
        ("${7*7}", "49"),            # Freemarker, Velocity
        ("#{7*7}", "49"),            # Ruby ERB
        ("<%= 7*7 %>", "49"),        # Ruby ERB, JSP
        ("{{7*'7'}}", "7777777"),    # Jinja2 (string mult)
        ("${7*7}", "49"),            # Spring EL, Thymeleaf
        ("[[${7*7}]]", "49"),        # Thymeleaf
        ("*{7*7}", "49"),            # Thymeleaf
    ]

    def __init__(self, config: Config):
        super().__init__(config)

    async def scan(self, urls: List[str], parameters: List[Dict]) -> List[Dict]:
        """Scan for SSTI vulnerabilities."""
        self.logger.info(f"SSTI scan: {len(parameters)} parameters")
        findings: List[Dict] = []

        tasks = [self._test_param(param, findings) for param in parameters]
        await asyncio.gather(*tasks, return_exceptions=True)
        self.logger.info(f"  SSTI: {len(findings)} potential findings")
        return findings

    async def _test_param(self, param: Dict, findings: List[Dict]):
        """Test a single parameter for SSTI."""
        base_url = param.get("url", "")
        param_name = param.get("parameter", "")
        method = param.get("method", "GET")

        if not base_url or not param_name:
            return

        for payload, expected in self.PROBES:
            resp, body = await self._send(base_url, param_name, payload, method)
            if body and expected in body:
                findings.append(self._make_finding(
                    url=base_url,
                    parameter=param_name,
                    payload=payload,
                    evidence=f"Template expression {payload!r} evaluated to '{expected}'",
                    severity="critical",
                    confidence=0.95,
                    extra={"method": method, "expected_result": expected},
                ))
                return  # Found, stop testing this param

    async def _send(self, url: str, param_name: str, payload: str, method: str):
        """Send request with payload."""
        if method == "POST":
            return await self._post(url, data={param_name: payload})
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param_name] = [payload]
        new_query = urlencode({k: v[0] for k, v in params.items()})
        return await self._get(urlunparse(parsed._replace(query=new_query)))
