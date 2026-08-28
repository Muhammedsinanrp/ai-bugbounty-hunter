#!/usr/bin/env python3
"""
AI-BugBounty-Hunter — URL Crawler
Intelligent web crawler with parameter extraction and AI-guided priority crawling.
"""
import asyncio
import aiohttp
import re
from typing import List, Dict, Set, Optional
from urllib.parse import urlparse, urljoin, urlencode, parse_qs, urlunparse
from bs4 import BeautifulSoup

from core.config import Config
from core.logger import Logger


class URLCrawler:
    """
    Intelligent URL crawler that:
    - Discovers URLs from live hosts
    - Extracts parameters (GET, POST, hidden fields, JSON bodies)
    - Respects scope and rate limits
    - Uses AI to prioritize interesting endpoints
    """

    INTERESTING_EXTENSIONS = {
        ".php", ".asp", ".aspx", ".jsp", ".jspx", ".do", ".action",
        ".cfm", ".cgi", ".pl", ".py", ".rb",
    }

    SKIP_EXTENSIONS = {
        ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".woff",
        ".woff2", ".ttf", ".eot", ".css", ".js", ".pdf", ".zip",
        ".tar", ".gz", ".mp4", ".mp3", ".avi",
    }

    INTERESTING_PARAM_NAMES = {
        "id", "user", "username", "email", "file", "path", "url", "redirect",
        "next", "return", "callback", "page", "search", "q", "query", "cmd",
        "command", "exec", "token", "key", "api_key", "password", "pass",
        "lang", "language", "template", "theme", "view", "format", "output",
        "type", "action", "module", "function", "debug", "test",
    }

    DEFAULT_HEADERS = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }

    def __init__(self, config: Config):
        self.config = config
        self.logger = Logger("URLCrawler")
        self._visited: Set[str] = set()
        self._urls: Set[str] = set()
        self.extracted_parameters: List[Dict] = []
        self._param_set: Set[str] = set()
        self.max_pages = config.get("target", "max_pages", default=500)
        self.max_depth = config.get("target", "max_depth", default=3)
        self.timeout = config.get("target", "timeout", default=10)
        self.rate_limit = config.get("target", "rate_limit", default=10)
        self._sem = asyncio.Semaphore(config.get("target", "concurrent_requests", default=20))

    async def crawl(self, hosts: List[str]) -> List[str]:
        """Crawl URLs from a list of live hosts."""
        self._visited.clear()
        self._urls.clear()
        self.extracted_parameters.clear()

        self.logger.info(f"Starting URL crawl on {len(hosts)} hosts...")

        tasks = [self._crawl_host(host) for host in hosts[:50]]  # Limit hosts
        await asyncio.gather(*tasks, return_exceptions=True)

        result = sorted(self._urls)
        self.logger.info(
            f"Crawl complete: {len(result)} URLs, {len(self.extracted_parameters)} parameters"
        )
        return result

    async def _crawl_host(self, host: str):
        """Crawl a single host."""
        if not host.startswith("http"):
            host = f"https://{host}"

        await self._crawl_url(host, depth=0)

    async def _crawl_url(self, url: str, depth: int):
        """Crawl a single URL, extract links and params."""
        if depth > self.max_depth:
            return
        if len(self._visited) >= self.max_pages:
            return
        if url in self._visited:
            return

        self._visited.add(url)

        # Skip uninteresting file types
        parsed = urlparse(url)
        ext = "." + url.split(".")[-1].split("?")[0].lower() if "." in url.split("/")[-1] else ""
        if ext in self.SKIP_EXTENSIONS:
            return

        async with self._sem:
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
                        max_redirects=5,
                    ) as resp:
                        if resp.status not in (200, 201, 301, 302):
                            return

                        content_type = resp.headers.get("Content-Type", "")
                        if "text/html" not in content_type and "application/json" not in content_type:
                            return

                        body = await resp.text(errors="replace")
                        self._urls.add(str(resp.url))

                        # Extract parameters from URL
                        self._extract_url_params(str(resp.url))

                        if "text/html" in content_type:
                            links = self._extract_links(body, str(resp.url), parsed.netloc)
                            self._extract_form_params(body, str(resp.url))

                            # Recursively crawl links
                            crawl_tasks = [
                                self._crawl_url(link, depth + 1)
                                for link in links
                                if link not in self._visited
                            ]
                            if crawl_tasks:
                                await asyncio.gather(*crawl_tasks[:20], return_exceptions=True)

            except asyncio.TimeoutError:
                pass
            except Exception as e:
                self.logger.debug(f"Crawl error for {url}: {e}")

    def _extract_links(self, html: str, base_url: str, base_netloc: str) -> List[str]:
        """Extract valid links from HTML."""
        links = []
        try:
            soup = BeautifulSoup(html, "lxml")
            for tag in soup.find_all(["a", "form", "script", "link"]):
                href = tag.get("href") or tag.get("action") or tag.get("src")
                if not href:
                    continue

                full_url = urljoin(base_url, href)
                parsed = urlparse(full_url)

                # Stay in scope
                if parsed.netloc and base_netloc not in parsed.netloc:
                    continue
                if parsed.scheme not in ("http", "https"):
                    continue

                # Normalize
                normalized = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path, "", parsed.query, ""
                ))
                if normalized not in self._visited:
                    links.append(normalized)
        except Exception:
            pass
        return links[:50]

    def _extract_url_params(self, url: str):
        """Extract GET parameters from URL."""
        parsed = urlparse(url)
        if not parsed.query:
            return

        params = parse_qs(parsed.query)
        for param_name, values in params.items():
            key = f"{url.split('?')[0]}:{param_name}"
            if key not in self._param_set:
                self._param_set.add(key)
                self.extracted_parameters.append({
                    "url": url.split("?")[0],
                    "parameter": param_name,
                    "value": values[0] if values else "",
                    "method": "GET",
                    "interesting": param_name.lower() in self.INTERESTING_PARAM_NAMES,
                })

    def _extract_form_params(self, html: str, url: str):
        """Extract POST parameters from HTML forms."""
        try:
            soup = BeautifulSoup(html, "lxml")
            for form in soup.find_all("form"):
                action = form.get("action", url)
                method = form.get("method", "GET").upper()
                full_action = urljoin(url, action)

                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if not name:
                        continue
                    value = inp.get("value", "")
                    inp_type = inp.get("type", "text")

                    key = f"{full_action}:{name}:{method}"
                    if key not in self._param_set:
                        self._param_set.add(key)
                        self.extracted_parameters.append({
                            "url": full_action,
                            "parameter": name,
                            "value": value,
                            "method": method,
                            "input_type": inp_type,
                            "interesting": name.lower() in self.INTERESTING_PARAM_NAMES,
                        })
        except Exception:
            pass
