#!/usr/bin/env python3
"""
AI-BugBounty-Hunter — Open Redirect Scanner
Detects open redirect vulnerabilities.
"""
import asyncio
import re
from typing import List, Dict
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
from scanners.base_scanner import BaseScanner
from core.config import Config


class OpenRedirectScanner(BaseScanner):
    """Open Redirect vulnerability scanner."""

    VULN_TYPE = "Open Redirect"
    DEFAULT_SEVERITY = "medium"

    REDIRECT_PAYLOADS = [
        "https://evil.com",
        "//evil.com",
        "/\\evil.com",
        "https:evil.com",
        "//evil.com/%2F%2E%2E",
        "%2F%2Fevil.com",
        "https://evil.com?",
        "javascript:alert(1)",
        "data:text/html,<script>alert(1)</script>",
        "/%09/evil.com",
        "//evil%00.com",
    ]

    REDIRECT_PARAMS = {
        "redirect", "url", "next", "return", "return_url", "returnUrl",
        "return_to", "goto", "go", "link", "to", "target", "ref",
        "referrer", "continue", "destination", "redir", "redirect_uri",
        "redirect_url", "successUrl", "failureUrl", "callback",
    }

    def __init__(self, config: Config):
        super().__init__(config)

    async def scan(self, urls: List[str], parameters: List[Dict]) -> List[Dict]:
        """Scan for open redirect vulnerabilities."""
        self.logger.info(f"Open Redirect scan: {len(parameters)} parameters")
        findings: List[Dict] = []

        interesting = [
            p for p in parameters
            if p.get("parameter", "").lower() in self.REDIRECT_PARAMS
        ]
        self.logger.info(f"  → {len(interesting)} redirect-like parameters to test")

        tasks = [self._test_param(param, findings) for param in interesting]
        await asyncio.gather(*tasks, return_exceptions=True)
        self.logger.info(f"  Open Redirect: {len(findings)} potential findings")
        return findings

    async def _test_param(self, param: Dict, findings: List[Dict]):
        """Test a parameter for open redirect."""
        base_url = param.get("url", "")
        param_name = param.get("parameter", "")
        method = param.get("method", "GET")

        for payload in self.REDIRECT_PAYLOADS:
            resp, body = await self._send(base_url, param_name, payload, method)
            if not resp:
                continue

            # Check final URL after redirects
            final_url = str(resp.url) if hasattr(resp, "url") else ""
            location = resp.headers.get("Location", "") if hasattr(resp, "headers") else ""

            if (
                "evil.com" in final_url
                or "evil.com" in location
                or (payload.startswith("//") and payload[2:] in final_url)
            ):
                findings.append(self._make_finding(
                    url=base_url,
                    parameter=param_name,
                    payload=payload,
                    evidence=f"Redirected to: {final_url or location}",
                    severity="medium",
                    confidence=0.85,
                    extra={"method": method, "redirect_destination": final_url},
                ))
                return

    async def _send(self, url: str, param_name: str, payload: str, method: str):
        if method == "POST":
            return await self._post(url, data={param_name: payload})
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param_name] = [payload]
        new_query = urlencode({k: v[0] for k, v in params.items()})
        return await self._get(urlunparse(parsed._replace(query=new_query)))
