#!/usr/bin/env python3
"""
AI-BugBounty-Hunter — AI Subdomain Enumerator
Combines multiple techniques with AI-enhanced discovery:
- Passive: Certificate Transparency, DNS, search engines
- AI-driven: pattern-based prediction of subdomains
- Active: DNS brute-force with smart wordlists
"""
import asyncio
import json
import os
import aiohttp
import dns.resolver
from typing import List, Dict, Set, Optional
from urllib.parse import urlparse

from core.config import Config
from core.logger import Logger
from ai_engine.llm_client import LLMClient


class SubdomainEnumerator:
    """
    Multi-source subdomain enumeration with AI-enhanced discovery.
    Uses passive sources first, then AI-guided active brute-force.
    """

    COMMON_SUBDOMAINS = [
        "www", "mail", "remote", "blog", "webmail", "server", "ns1", "ns2",
        "smtp", "secure", "vpn", "admin", "cpanel", "whm", "autodiscover",
        "test", "dev", "staging", "api", "app", "beta", "demo", "stage",
        "alpha", "internal", "corp", "portal", "docs", "help", "support",
        "status", "cdn", "static", "media", "assets", "uploads", "files",
        "download", "shop", "store", "payment", "checkout", "login",
        "auth", "oauth", "sso", "identity", "accounts", "profile",
        "dashboard", "console", "manager", "backup", "monitor",
        "jenkins", "gitlab", "jira", "confluence", "wiki", "grafana",
        "prometheus", "kibana", "elastic", "mongo", "redis", "mysql",
        "db", "database", "prod", "production", "qa", "develop",
        "feature", "hotfix", "release", "ci", "cd", "deploy",
        "mx", "ftp", "ssh", "git", "svn", "bugs", "issues",
        "dev2", "staging2", "api2", "v2", "v1", "old", "new",
        "partner", "partners", "b2b", "enterprise", "cloud",
        "mobile", "m", "wap", "gateway", "proxy", "lb",
    ]

    def __init__(self, config: Config):
        self.config = config
        self.logger = Logger("SubdomainEnum")
        self.llm = LLMClient(config)
        self._found: Set[str] = set()
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = 5
        self.resolver.lifetime = 5

    async def discover(self, domain: str) -> List[str]:
        """Discover subdomains using multiple techniques."""
        self._found = set()
        self.logger.info(f"Enumerating subdomains for: {domain}")

        # Phase 1: Passive discovery
        await self._passive_discovery(domain)
        self.logger.info(f"  → After passive: {len(self._found)} subdomains")

        # Phase 2: AI-predicted subdomains
        if len(self._found) > 3:
            await self._ai_predicted(domain)
            self.logger.info(f"  → After AI prediction: {len(self._found)} subdomains")

        # Phase 3: Active brute-force (configurable)
        if not self.config.get("recon", "use_passive_only", default=False):
            await self._active_bruteforce(domain)

        result = sorted(self._found)
        self.logger.info(f"Total subdomains discovered: {len(result)}")
        return result

    async def _passive_discovery(self, domain: str):
        """Passive subdomain discovery using multiple sources."""
        tasks = [
            self._crt_discovery(domain),
            self._query_wayback(domain),
            self._query_securitytrails(domain),
        ]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _crt_discovery(self, domain: str):
        """Query Certificate Transparency logs via crt.sh."""
        try:
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            headers = {"User-Agent": "Mozilla/5.0 (compatible; BugBountyHunter/1.0)"}
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url, headers=headers, timeout=aiohttp.ClientTimeout(total=20)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        for entry in data:
                            name = entry.get("name_value", "")
                            for sub in name.split("\n"):
                                sub = sub.strip().lower().lstrip("*.")
                                full = f"{sub}" if "." in sub else f"{sub}.{domain}"
                                if full.endswith(f".{domain}") and full != domain:
                                    self._found.add(full)
        except Exception as e:
            self.logger.debug(f"CRT.sh query failed: {e}")

    async def _query_wayback(self, domain: str):
        """Query Wayback Machine for historical subdomains."""
        try:
            url = (
                f"http://web.archive.org/cdx/search/cdx"
                f"?url=*.{domain}/*&output=json&fl=original&limit=5000&collapse=urlkey"
            )
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=30)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        for row in data[1:]:  # Skip header
                            original_url = row[0] if isinstance(row, list) else row
                            parsed = urlparse(original_url)
                            hostname = parsed.hostname
                            if hostname and hostname.endswith(f".{domain}") and hostname != domain:
                                self._found.add(hostname.lower())
        except Exception as e:
            self.logger.debug(f"Wayback query failed: {e}")

    async def _query_securitytrails(self, domain: str):
        """Query SecurityTrails API (requires API key)."""
        api_key = os.getenv("SECURITYTRAILS_API_KEY", "")
        if not api_key:
            return
        try:
            headers = {"APIKEY": api_key}
            url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
            async with aiohttp.ClientSession(headers=headers) as session:
                async with session.get(
                    url, timeout=aiohttp.ClientTimeout(total=15)
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for sub in data.get("subdomains", []):
                            full = f"{sub}.{domain}".lower()
                            self._found.add(full)
        except Exception as e:
            self.logger.debug(f"SecurityTrails query failed: {e}")

    async def _ai_predicted(self, domain: str):
        """Use AI to predict additional subdomains based on discovered patterns."""
        if len(self._found) < 5:
            return

        discovered = list(self._found)[:50]
        prompt = (
            f"Given these discovered subdomains of {domain}:\n"
            + "\n".join(discovered[:30])
            + f"\n\nBased on patterns, naming conventions, and common infrastructure, "
            f"predict 20 additional subdomains that likely exist but haven't been discovered yet.\n"
            f"Focus on:\n"
            f"1. Infrastructure naming patterns (e.g., if 'us-api' exists, 'eu-api' probably does too)\n"
            f"2. Common internal tools (jenkins, grafana, jira, etc.)\n"
            f"3. Development/staging environments\n"
            f"4. Alternative service endpoints\n"
            f"5. Geographic/data center patterns\n\n"
            f"Return ONLY a JSON array of full subdomain strings.\n"
            f'Example: ["sub1.{domain}", "sub2.{domain}"]'
        )

        try:
            response = await self.llm.query(prompt, temperature=0.5)
            json_str = self.llm.extract_json(response)
            if json_str:
                predicted = json.loads(json_str)
                for sub in predicted[:20]:
                    if isinstance(sub, str) and sub.endswith(f".{domain}"):
                        self._found.add(sub.lower())
        except Exception as e:
            self.logger.debug(f"AI prediction failed: {e}")

    async def _active_bruteforce(self, domain: str):
        """Active DNS brute-force with smart wordlist."""
        wordlist = list(self.COMMON_SUBDOMAINS)

        if len(self._found) > 5:
            try:
                ai_words = await self._generate_wordlist(domain)
                wordlist.extend(ai_words)
            except Exception:
                pass

        wordlist = list(set(wordlist))
        sem = asyncio.Semaphore(50)
        loop = asyncio.get_event_loop()

        async def check_sub(sub: str) -> Optional[str]:
            async with sem:
                full = f"{sub}.{domain}"
                if full in self._found:
                    return None
                try:
                    answers = await loop.run_in_executor(
                        None, lambda: self.resolver.resolve(full, "A")
                    )
                    if answers:
                        return full
                except Exception:
                    pass
                return None

        chunks = [wordlist[i:i+100] for i in range(0, len(wordlist), 100)]
        for chunk in chunks:
            tasks = [check_sub(sub) for sub in chunk]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, str):
                    self._found.add(result)

    async def _generate_wordlist(self, domain: str) -> List[str]:
        """Use AI to generate a targeted wordlist."""
        discovered = list(self._found)[:20]
        prompt = (
            f"Based on these discovered subdomains of {domain}:\n"
            + "\n".join(discovered)
            + "\n\nGenerate 30 likely subdomain prefix names for this organization.\n"
            "Return a JSON array of single-word subdomain names (just the prefix, not full domain).\n"
            'Example: ["grafana", "jenkins", "eu-api"]'
        )

        try:
            response = await self.llm.query(prompt, temperature=0.6)
            json_str = self.llm.extract_json(response)
            if json_str:
                words = json.loads(json_str)
                if isinstance(words, list):
                    return [w.strip().lower() for w in words if isinstance(w, str)]
        except Exception:
            pass
        return []
