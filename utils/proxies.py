#!/usr/bin/env python3
"""
AI-BugBounty-Hunter — Proxy Rotation Manager
Manages proxy pools for stealth scanning.
"""
import asyncio
import random
import aiohttp
from typing import List, Optional
from pathlib import Path
from core.config import Config
from core.logger import Logger


class ProxyManager:
    """
    Manages a pool of HTTP/SOCKS proxies with:
    - Automatic rotation
    - Health checking
    - Dead proxy removal
    - Per-domain proxy assignment
    """

    def __init__(self, config: Config):
        self.config = config
        self.logger = Logger("ProxyManager")
        self.proxies: List[str] = []
        self.dead_proxies: set = set()
        self._index = 0
        self._lock = asyncio.Lock()

        if config.get("stealth", "proxy_rotation", default=False):
            proxy_file = config.get("stealth", "proxy_file", default="proxies.txt")
            self._load(proxy_file)

    def _load(self, proxy_file: str):
        """Load proxies from file."""
        path = Path(proxy_file)
        if not path.exists():
            self.logger.warning(f"Proxy file not found: {proxy_file}")
            return

        with open(path) as f:
            self.proxies = [
                line.strip() for line in f
                if line.strip() and not line.startswith("#")
            ]
        self.logger.info(f"Loaded {len(self.proxies)} proxies from {proxy_file}")

    def get_proxy(self) -> Optional[str]:
        """Get the next available proxy."""
        if not self.proxies:
            return None

        active = [p for p in self.proxies if p not in self.dead_proxies]
        if not active:
            self.logger.warning("All proxies are dead. Resetting dead list.")
            self.dead_proxies.clear()
            active = self.proxies

        return random.choice(active)

    def mark_dead(self, proxy: str):
        """Mark a proxy as dead."""
        self.dead_proxies.add(proxy)
        self.logger.debug(f"Proxy marked dead: {proxy}")

    async def check_proxy(self, proxy: str, test_url: str = "https://httpbin.org/ip") -> bool:
        """Test if a proxy is working."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    test_url,
                    proxy=proxy,
                    timeout=aiohttp.ClientTimeout(total=10),
                ) as resp:
                    return resp.status == 200
        except Exception:
            return False

    async def validate_all(self):
        """Validate all proxies and remove dead ones."""
        self.logger.info(f"Validating {len(self.proxies)} proxies...")
        tasks = [self.check_proxy(p) for p in self.proxies]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        valid = [p for p, ok in zip(self.proxies, results) if ok is True]
        self.logger.info(f"Valid proxies: {len(valid)}/{len(self.proxies)}")
        self.proxies = valid
