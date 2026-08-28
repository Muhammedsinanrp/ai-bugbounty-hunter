#!/usr/bin/env python3
"""
AI-BugBounty-Hunter — Base Scanner Class
Common interface and utilities for all vulnerability scanners.
"""
import asyncio
import aiohttp
import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime
from core.config import Config
from core.logger import Logger


class BaseScanner:
    """Base class for all vulnerability scanners."""

    VULN_TYPE = "Unknown"
    DEFAULT_SEVERITY = "medium"

    DEFAULT_HEADERS = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }

    def __init__(self, config: Config):
        self.config = config
        self.logger = Logger(self.__class__.__name__)
        self.timeout = config.get("target", "timeout", default=10)
        self.rate_limit = config.get("target", "rate_limit", default=10)
        self._sem = asyncio.Semaphore(
            config.get("target", "concurrent_requests", default=20)
        )
        self.findings: List[Dict] = []

    def _make_finding(self, url: str, parameter: str, payload: str,
                       evidence: str, severity: Optional[str] = None,
                       confidence: float = 0.7, extra: Optional[Dict] = None) -> Dict:
        """Create a standardized finding dict."""
        finding = {
            "id": str(uuid.uuid4()),
            "type": self.VULN_TYPE,
            "url": url,
            "parameter": parameter,
            "payload": payload,
            "evidence": evidence[:5000],
            "severity": severity or self.DEFAULT_SEVERITY,
            "confidence": confidence,
            "timestamp": datetime.utcnow().isoformat(),
            "status": "new",
        }
        if extra:
            finding.update(extra)
        return finding

    async def _get(self, url: str, params: Optional[Dict] = None,
                   headers: Optional[Dict] = None) -> Optional[aiohttp.ClientResponse]:
        """Perform a GET request with rate limiting."""
        async with self._sem:
            try:
                connector = aiohttp.TCPConnector(ssl=False)
                merged_headers = {**self.DEFAULT_HEADERS, **(headers or {})}
                async with aiohttp.ClientSession(
                    connector=connector, headers=merged_headers
                ) as session:
                    async with session.get(
                        url, params=params,
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        allow_redirects=True,
                    ) as resp:
                        body = await resp.text(errors="replace")
                        return resp, body
            except Exception:
                return None, None

    async def _post(self, url: str, data: Optional[Dict] = None,
                    json_data: Optional[Dict] = None,
                    headers: Optional[Dict] = None):
        """Perform a POST request with rate limiting."""
        async with self._sem:
            try:
                connector = aiohttp.TCPConnector(ssl=False)
                merged_headers = {**self.DEFAULT_HEADERS, **(headers or {})}
                async with aiohttp.ClientSession(
                    connector=connector, headers=merged_headers
                ) as session:
                    async with session.post(
                        url, data=data, json=json_data,
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        allow_redirects=True,
                    ) as resp:
                        body = await resp.text(errors="replace")
                        return resp, body
            except Exception:
                return None, None
