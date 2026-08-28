#!/usr/bin/env python3
"""
AI-BugBounty-Hunter — OSINT Enricher
Gathers open-source intelligence about the target domain.
"""
import asyncio
import aiohttp
import json
from typing import List, Dict, Any, Optional
from core.config import Config
from core.logger import Logger


class OSINTEnricher:
    """
    OSINT enrichment engine. Gathers:
    - WHOIS-like data (via public APIs)
    - DNS records (MX, TXT, NS, A, CNAME)
    - SSL certificate info
    - IP geolocation
    - ASN information
    - Email/data breach exposure (via HaveIBeenPwned-style APIs)
    """

    def __init__(self, config: Config):
        self.config = config
        self.logger = Logger("OSINTEnricher")
        self.timeout = config.get("target", "timeout", default=10)

    async def enrich(self, domain: str, subdomains: List[str]) -> Dict[str, Any]:
        """Enrich target with OSINT data."""
        self.logger.info(f"OSINT enrichment for: {domain}")
        osint_data: Dict[str, Any] = {"domain": domain, "subdomains_count": len(subdomains)}

        tasks = [
            self._get_dns_records(domain, osint_data),
            self._get_ip_info(domain, osint_data),
            self._get_ssl_info(domain, osint_data),
            self._get_whois_data(domain, osint_data),
        ]

        await asyncio.gather(*tasks, return_exceptions=True)

        self.logger.info(f"  → OSINT gathered {len(osint_data)} data points")
        return osint_data

    async def _get_dns_records(self, domain: str, data: Dict):
        """Fetch DNS records using public DNS API."""
        try:
            record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
            dns_data: Dict[str, Any] = {}

            async with aiohttp.ClientSession() as session:
                for rtype in record_types:
                    try:
                        url = f"https://dns.google/resolve?name={domain}&type={rtype}"
                        async with session.get(
                            url,
                            timeout=aiohttp.ClientTimeout(total=self.timeout),
                        ) as resp:
                            if resp.status == 200:
                                result = await resp.json()
                                answers = result.get("Answer", [])
                                if answers:
                                    dns_data[rtype] = [a.get("data", "") for a in answers]
                    except Exception:
                        pass

            if dns_data:
                data["dns_records"] = dns_data

        except Exception as e:
            self.logger.debug(f"DNS lookup failed: {e}")

    async def _get_ip_info(self, domain: str, data: Dict):
        """Get IP geolocation and ASN info."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://ipinfo.io/{domain}/json",
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as resp:
                    if resp.status == 200:
                        ip_data = await resp.json()
                        data["ip_info"] = {
                            "ip": ip_data.get("ip"),
                            "org": ip_data.get("org"),
                            "country": ip_data.get("country"),
                            "city": ip_data.get("city"),
                            "hostname": ip_data.get("hostname"),
                        }
        except Exception as e:
            self.logger.debug(f"IP info failed: {e}")

    async def _get_ssl_info(self, domain: str, data: Dict):
        """Get SSL certificate information."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://api.ssllabs.com/api/v3/analyze?host={domain}&fromCache=on&maxAge=12",
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status == 200:
                        ssl_data = await resp.json()
                        endpoints = ssl_data.get("endpoints", [{}])
                        if endpoints:
                            ep = endpoints[0]
                            data["ssl_info"] = {
                                "grade": ep.get("grade"),
                                "ip": ep.get("ipAddress"),
                                "server_name": ssl_data.get("host"),
                            }
        except Exception as e:
            self.logger.debug(f"SSL info failed (expected on rate-limit): {e}")

    async def _get_whois_data(self, domain: str, data: Dict):
        """Get basic WHOIS data via public API."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"https://rdap.org/domain/{domain}",
                    timeout=aiohttp.ClientTimeout(total=self.timeout),
                ) as resp:
                    if resp.status == 200:
                        rdap_data = await resp.json()
                        data["whois"] = {
                            "registrar": next(
                                (e.get("fn", "") for e in rdap_data.get("entities", [])
                                 if "registrar" in e.get("roles", [])), ""
                            ),
                            "created": next(
                                (e.get("eventDate") for e in rdap_data.get("events", [])
                                 if e.get("eventAction") == "registration"), ""
                            ),
                            "expiry": next(
                                (e.get("eventDate") for e in rdap_data.get("events", [])
                                 if e.get("eventAction") == "expiration"), ""
                            ),
                            "nameservers": [
                                ns.get("ldhName", "") for ns in rdap_data.get("nameservers", [])
                            ],
                        }
        except Exception as e:
            self.logger.debug(f"WHOIS failed: {e}")
