#!/usr/bin/env python3
"""
AI-BugBounty-Hunter — SSRF Scanner
Detects Server-Side Request Forgery vulnerabilities.
"""
import asyncio
import os
from typing import List, Dict
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
from scanners.base_scanner import BaseScanner
from core.config import Config


class SSRFScanner(BaseScanner):
    """SSRF vulnerability scanner."""

    VULN_TYPE = "Server-Side Request Forgery (SSRF)"
    DEFAULT_SEVERITY = "high"

    # SSRF probe URLs (safe ones — no real interaction needed, just check for reflection)
    METADATA_URLS = [
        "http://169.254.169.254/latest/meta-data/",       # AWS IMDSv1
        "http://metadata.google.internal/computeMetadata/v1/",  # GCP
        "http://169.254.169.254/metadata/instance",        # Azure
        "http://localhost:80/",
        "http://127.0.0.1/",
        "http://[::1]/",
        "http://0.0.0.0/",
    ]

    # OOB callback domain (canary token or Burp Collaborator equivalent)
    CALLBACK_DOMAIN = os.getenv("SSRF_CALLBACK_DOMAIN", "")

    INTERESTING_PARAMS = {
        "url", "uri", "path", "file", "src", "source", "dest", "destination",
        "redirect", "location", "image", "img", "link", "ref", "proxy",
        "server", "host", "endpoint", "api", "callback", "webhook",
        "fetch", "load", "import", "include", "page",
    }

    def __init__(self, config: Config):
        super().__init__(config)

    async def scan(self, urls: List[str], parameters: List[Dict]) -> List[Dict]:
        """Scan for SSRF vulnerabilities."""
        self.logger.info(f"SSRF scan: {len(parameters)} parameters")
        findings: List[Dict] = []

        # Focus on interesting parameter names
        interesting = [
            p for p in parameters
            if p.get("parameter", "").lower() in self.INTERESTING_PARAMS
        ]
        self.logger.info(f"  → {len(interesting)} URL-like parameters to test")

        tasks = [self._test_param(param, findings) for param in interesting]
        await asyncio.gather(*tasks, return_exceptions=True)
        self.logger.info(f"  SSRF: {len(findings)} potential findings")
        return findings

    async def _test_param(self, param: Dict, findings: List[Dict]):
        """Test a parameter for SSRF."""
        base_url = param.get("url", "")
        param_name = param.get("parameter", "")
        method = param.get("method", "GET")

        for ssrf_url in self.METADATA_URLS[:4]:
            resp, body = await self._send(base_url, param_name, ssrf_url, method)
            if body and self._check_ssrf_response(body):
                findings.append(self._make_finding(
                    url=base_url,
                    parameter=param_name,
                    payload=ssrf_url,
                    evidence=body[:500],
                    severity="high",
                    confidence=0.7,
                    extra={"method": method, "ssrf_target": ssrf_url},
                ))
                return

    def _check_ssrf_response(self, body: str) -> bool:
        """Check if the response contains indicators of SSRF success."""
        indicators = [
            "ami-id",              # AWS metadata
            "instance-id",         # AWS/GCP metadata
            "computeMetadata",     # GCP metadata
            "MSI_ENDPOINT",        # Azure MSI
            "<title>",             # Fetched a real page
            "127.0.0.1",
            "root:",               # /etc/passwd via file SSRF
        ]
        body_lower = body.lower()
        return any(i.lower() in body_lower for i in indicators)

    async def _send(self, url: str, param_name: str, payload: str, method: str):
        """Send request with SSRF payload."""
        if method == "POST":
            return await self._post(url, data={param_name: payload})
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param_name] = [payload]
        new_query = urlencode({k: v[0] for k, v in params.items()})
        return await self._get(urlunparse(parsed._replace(query=new_query)))
