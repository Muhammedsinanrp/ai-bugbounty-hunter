#!/usr/bin/env python3
"""
AI-BugBounty-Hunter — Advanced HTTP Client
Wrapper around aiohttp with retry logic, proxy support, and user-agent rotation.
"""
import asyncio
import random
import aiohttp
from typing import Optional, Dict, Any, List, Tuple
from core.config import Config
from core.logger import Logger


USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
]


class HTTPClient:
    """
    Advanced async HTTP client with:
    - Automatic retry on transient errors
    - User-Agent rotation
    - Proxy rotation support
    - Rate limiting
    - Response caching (optional)
    """

    def __init__(self, config: Config):
        self.config = config
        self.logger = Logger("HTTPClient")
        self.timeout = config.get("target", "timeout", default=10)
        self.rotate_ua = config.get("stealth", "rotate_user_agents", default=True)
        self.random_delays = config.get("stealth", "random_delays", default=False)
        self.proxies = []
        self._proxy_index = 0

    def _get_headers(self) -> Dict[str, str]:
        ua = random.choice(USER_AGENTS) if self.rotate_ua else USER_AGENTS[0]
        return {
            "User-Agent": ua,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
        }

    def _get_proxy(self) -> Optional[str]:
        if self.proxies:
            proxy = self.proxies[self._proxy_index % len(self.proxies)]
            self._proxy_index += 1
            return proxy
        return None

    async def get(
        self,
        url: str,
        params: Optional[Dict] = None,
        headers: Optional[Dict] = None,
        retries: int = 3,
    ) -> Tuple[Optional[int], Optional[str], Optional[Dict]]:
        """Perform a GET request. Returns (status_code, body, response_headers)."""
        if self.random_delays:
            await asyncio.sleep(random.uniform(0.1, 0.5))

        merged_headers = {**self._get_headers(), **(headers or {})}
        proxy = self._get_proxy()

        for attempt in range(retries):
            try:
                connector = aiohttp.TCPConnector(ssl=False)
                async with aiohttp.ClientSession(
                    connector=connector, headers=merged_headers
                ) as session:
                    async with session.get(
                        url,
                        params=params,
                        proxy=proxy,
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        allow_redirects=True,
                    ) as resp:
                        body = await resp.text(errors="replace")
                        return resp.status, body, dict(resp.headers)
            except aiohttp.ClientError as e:
                if attempt == retries - 1:
                    self.logger.debug(f"GET failed after {retries} retries: {url}: {e}")
                    return None, None, None
                await asyncio.sleep(2 ** attempt)
            except Exception as e:
                self.logger.debug(f"GET error: {url}: {e}")
                return None, None, None

        return None, None, None

    async def post(
        self,
        url: str,
        data: Optional[Dict] = None,
        json_data: Optional[Any] = None,
        headers: Optional[Dict] = None,
        retries: int = 2,
    ) -> Tuple[Optional[int], Optional[str], Optional[Dict]]:
        """Perform a POST request."""
        if self.random_delays:
            await asyncio.sleep(random.uniform(0.1, 0.5))

        merged_headers = {**self._get_headers(), **(headers or {})}
        proxy = self._get_proxy()

        for attempt in range(retries):
            try:
                connector = aiohttp.TCPConnector(ssl=False)
                async with aiohttp.ClientSession(
                    connector=connector, headers=merged_headers
                ) as session:
                    async with session.post(
                        url,
                        data=data,
                        json=json_data,
                        proxy=proxy,
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                    ) as resp:
                        body = await resp.text(errors="replace")
                        return resp.status, body, dict(resp.headers)
            except Exception as e:
                if attempt == retries - 1:
                    return None, None, None
                await asyncio.sleep(2 ** attempt)

        return None, None, None

    def load_proxies(self, proxy_file: str):
        """Load proxies from file."""
        try:
            with open(proxy_file) as f:
                self.proxies = [
                    line.strip() for line in f
                    if line.strip() and not line.startswith("#")
                ]
            self.logger.info(f"Loaded {len(self.proxies)} proxies")
        except FileNotFoundError:
            self.logger.warning(f"Proxy file not found: {proxy_file}")
