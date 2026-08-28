#!/usr/bin/env python3
"""
AI-BugBounty-Hunter — Technology Stack Detector
Fingerprints web technologies using HTTP headers, HTML meta tags, and response analysis.
"""
import asyncio
import re
import aiohttp
from typing import Dict, List, Set, Optional
from core.config import Config
from core.logger import Logger


class TechDetector:
    """
    Technology fingerprinting engine. Detects:
    - Web frameworks (React, Angular, Vue, Django, Laravel, etc.)
    - CMS (WordPress, Drupal, Joomla, etc.)
    - Web servers (Nginx, Apache, IIS, etc.)
    - CDNs (Cloudflare, Akamai, Fastly, etc.)
    - Security headers (WAF detection)
    - Cloud providers
    """

    SIGNATURES: Dict[str, Dict] = {
        # Web Servers
        "Nginx": {"headers": {"server": r"nginx"}, "priority": "server"},
        "Apache": {"headers": {"server": r"apache"}, "priority": "server"},
        "IIS": {"headers": {"server": r"microsoft-iis"}, "priority": "server"},
        "Caddy": {"headers": {"server": r"caddy"}, "priority": "server"},
        "LiteSpeed": {"headers": {"server": r"litespeed"}, "priority": "server"},
        # CMS
        "WordPress": {
            "html": r'wp-content|wp-includes|wordpress',
            "headers": {"x-powered-by": r"wordpress"},
        },
        "Drupal": {"html": r'drupal|sites/default/files'},
        "Joomla": {"html": r'joomla|\/components\/com_'},
        "Magento": {"html": r'magento|mage-'},
        "Shopify": {"headers": {"x-shopify-stage": r"."}, "html": r'shopify'},
        # Frameworks
        "Django": {
            "headers": {"x-frame-options": r"SAMEORIGIN"},
            "html": r'csrfmiddlewaretoken',
        },
        "Laravel": {"headers": {"set-cookie": r"laravel_session"}},
        "Rails": {"headers": {"x-powered-by": r"Phusion Passenger", "x-runtime": r"[\d.]+"}},
        "ASP.NET": {"headers": {"x-powered-by": r"ASP\.NET", "x-aspnet-version": r"."}},
        "Express.js": {"headers": {"x-powered-by": r"Express"}},
        "Spring": {"html": r'Spring Framework|org\.springframework'},
        "Struts": {"html": r'Apache Struts|struts'},
        # Frontend
        "React": {"html": r'__REACT_DEVTOOLS|react\.development\.js|react\.production\.min'},
        "Angular": {"html": r'ng-version|angular\.js|angular\.min\.js'},
        "Vue.js": {"html": r'__vue__|vue\.js|vue\.min\.js'},
        "jQuery": {"html": r'jquery[\.-][\d.]+\.min\.js|jQuery v[\d.]+'},
        # CDN / WAF
        "Cloudflare": {
            "headers": {"server": r"cloudflare", "cf-ray": r"."},
        },
        "Akamai": {"headers": {"x-check-cacheable": r".", "x-akamai": r"."}},
        "Fastly": {"headers": {"x-served-by": r"cache", "fastly-stats": r"."}},
        "AWS CloudFront": {"headers": {"x-amz-cf-id": r".", "via": r"CloudFront"}},
        # Databases (via error messages, etc.)
        "MySQL": {"html": r"MySQL|You have an error in your SQL syntax"},
        "PostgreSQL": {"html": r"PostgreSQL|ERROR:.*syntax error at or near"},
        "MongoDB": {"html": r"MongoDB|MongoError|mongo"},
        # Cloud
        "AWS": {"html": r"amazonaws\.com|s3\.amazonaws"},
        "Azure": {"html": r"azure\.com|azurewebsites\.net", "headers": {"x-ms-version": r"."}},
        "GCP": {"html": r"googleapis\.com|storage\.cloud\.google"},
    }

    DEFAULT_HEADERS = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"
    }

    def __init__(self, config: Config):
        self.config = config
        self.logger = Logger("TechDetector")
        self.timeout = config.get("target", "timeout", default=10)
        self._sem = asyncio.Semaphore(20)

    async def fingerprint(self, hosts: List[str]) -> Dict[str, List[str]]:
        """Fingerprint technology stack of all live hosts."""
        self.logger.info(f"Fingerprinting {len(hosts)} hosts...")
        results: Dict[str, List[str]] = {}

        tasks = [self._fingerprint_host(host, results) for host in hosts]
        await asyncio.gather(*tasks, return_exceptions=True)

        total_techs = sum(len(v) for v in results.values())
        self.logger.info(f"Detected {total_techs} technologies across {len(results)} hosts")
        return results

    async def _fingerprint_host(self, host: str, results: Dict[str, List[str]]):
        """Fingerprint a single host."""
        async with self._sem:
            try:
                connector = aiohttp.TCPConnector(ssl=False)
                async with aiohttp.ClientSession(
                    connector=connector,
                    headers=self.DEFAULT_HEADERS,
                ) as session:
                    async with session.get(
                        host,
                        timeout=aiohttp.ClientTimeout(total=self.timeout),
                        allow_redirects=True,
                    ) as resp:
                        body = await resp.text(errors="replace")
                        headers_dict = {k.lower(): v for k, v in resp.headers.items()}

                        detected = self._match_signatures(body[:50000], headers_dict)
                        if detected:
                            results[host] = detected

            except Exception as e:
                self.logger.debug(f"Tech detect failed for {host}: {e}")

    def _match_signatures(self, body: str, headers: Dict[str, str]) -> List[str]:
        """Match technology signatures against response body and headers."""
        detected = []
        body_lower = body.lower()

        for tech, sig in self.SIGNATURES.items():
            matched = False

            # Check HTML pattern
            if "html" in sig:
                pattern = sig["html"]
                if re.search(pattern, body, re.IGNORECASE):
                    matched = True

            # Check headers
            if not matched and "headers" in sig:
                for header_name, pattern in sig["headers"].items():
                    header_val = headers.get(header_name, "")
                    if header_val and re.search(pattern, header_val, re.IGNORECASE):
                        matched = True
                        break

            if matched:
                detected.append(tech)

        return detected
