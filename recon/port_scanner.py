#!/usr/bin/env python3
"""
AI-BugBounty-Hunter — Port Scanner & Live Host Detector
Discovers live web hosts from subdomain list with HTTP/HTTPS probing.
"""
import asyncio
import aiohttp
from typing import List, Set, Optional
from core.config import Config
from core.logger import Logger


class PortScanner:
    """
    HTTP/HTTPS probe-based live host detection.
    Tests common web ports and returns URLs of responding hosts.
    """

    WEB_PORTS = [80, 443, 8080, 8443, 8000, 8888, 3000, 4000, 5000, 9000]

    DEFAULT_HEADERS = {
        "User-Agent": "Mozilla/5.0 (compatible; BugBountyScanner/1.0)"
    }

    def __init__(self, config: Config):
        self.config = config
        self.logger = Logger("PortScanner")
        self.timeout = config.get("target", "timeout", default=10)
        self._sem = asyncio.Semaphore(50)

    async def scan(self, subdomains: List[str]) -> List[str]:
        """Probe subdomains for live web services. Returns list of live host URLs."""
        self.logger.info(f"Probing {len(subdomains)} subdomains for live hosts...")
        live: Set[str] = set()

        tasks = [self._probe_host(sub, live) for sub in subdomains]
        await asyncio.gather(*tasks, return_exceptions=True)

        result = sorted(live)
        self.logger.info(f"Found {len(result)} live hosts")
        return result

    async def _probe_host(self, subdomain: str, live: Set[str]):
        """Probe a single subdomain on common ports."""
        # Try HTTPS first, then HTTP
        schemes = ["https", "http"]
        ports_to_try = [443, 80, 8443, 8080]

        async with self._sem:
            for scheme in schemes:
                default_port = 443 if scheme == "https" else 80
                url = f"{scheme}://{subdomain}"
                if await self._check_url(url):
                    live.add(url)
                    return  # Found, don't need more ports

            # Try non-standard ports
            for port in [8080, 8443, 8000, 3000, 5000]:
                for scheme in ["http", "https"]:
                    url = f"{scheme}://{subdomain}:{port}"
                    if await self._check_url(url):
                        live.add(url)
                        return

    async def _check_url(self, url: str) -> bool:
        """Check if a URL responds."""
        try:
            connector = aiohttp.TCPConnector(ssl=False)
            async with aiohttp.ClientSession(
                connector=connector,
                headers=self.DEFAULT_HEADERS,
            ) as session:
                async with session.get(
                    url,
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                    allow_redirects=True,
                    max_redirects=3,
                ) as resp:
                    return resp.status < 500
        except Exception:
            return False
