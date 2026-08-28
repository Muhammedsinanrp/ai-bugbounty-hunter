#!/usr/bin/env python3
"""
AI-BugBounty-Hunter — API Security Tester
Tests REST API endpoints and GraphQL for common vulnerabilities.
"""
import asyncio
import json
import re
from typing import List, Dict, Optional
from urllib.parse import urljoin, urlparse
from scanners.base_scanner import BaseScanner
from core.config import Config


class APITester(BaseScanner):
    """API security testing scanner."""

    VULN_TYPE = "API Security Misconfiguration"
    DEFAULT_SEVERITY = "medium"

    # Common API endpoint patterns
    API_PATTERNS = [
        "/api/", "/api/v1/", "/api/v2/", "/api/v3/",
        "/rest/", "/graphql", "/gql",
        "/v1/", "/v2/", "/v3/",
        "/_api/", "/internal/api/",
    ]

    GRAPHQL_QUERIES = [
        '{"query": "{__schema{types{name}}}"}',  # Introspection
        '{"query": "{__typename}"}',
    ]

    # API keys and secrets patterns in responses
    SECRET_PATTERNS = [
        r'"api_key"\s*:\s*"[a-zA-Z0-9]{20,}"',
        r'"secret"\s*:\s*"[a-zA-Z0-9]{20,}"',
        r'"token"\s*:\s*"[a-zA-Z0-9._-]{30,}"',
        r'"password"\s*:\s*"[^"]{6,}"',
        r'AWS_ACCESS_KEY_ID\s*=\s*[A-Z0-9]{20}',
        r'aws_secret_access_key\s*=\s*[a-zA-Z0-9/+]{40}',
        r'"private_key"\s*:',
    ]

    HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

    def __init__(self, config: Config):
        super().__init__(config)
        self.graphql_enabled = config.get("scanners", "api", default={}).get(
            "graphql_enabled", True
        )

    async def scan(self, urls: List[str], parameters: List[Dict]) -> List[Dict]:
        """Scan API endpoints for vulnerabilities."""
        self.logger.info(f"API scan: {len(urls)} URLs")
        findings: List[Dict] = []

        # Find API endpoints
        api_urls = [u for u in urls if any(p in u for p in self.API_PATTERNS)]
        self.logger.info(f"  → {len(api_urls)} API endpoints found")

        tasks = []

        # Test for exposed secrets
        tasks.extend([self._test_secrets(url, findings) for url in api_urls[:30]])

        # Test HTTP method enumeration
        tasks.extend([self._test_method_enum(url, findings) for url in api_urls[:20]])

        # Test CORS misconfiguration
        tasks.extend([self._test_cors(url, findings) for url in api_urls[:20]])

        # Test GraphQL
        if self.graphql_enabled:
            graphql_urls = [u for u in urls if "graphql" in u.lower() or "gql" in u.lower()]
            tasks.extend([self._test_graphql(url, findings) for url in graphql_urls[:10]])

        await asyncio.gather(*tasks, return_exceptions=True)
        self.logger.info(f"  API: {len(findings)} potential findings")
        return findings

    async def _test_secrets(self, url: str, findings: List[Dict]):
        """Test for exposed secrets in API responses."""
        resp, body = await self._get(url)
        if not body:
            return

        for pattern in self.SECRET_PATTERNS:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                findings.append(self._make_finding(
                    url=url,
                    parameter="response_body",
                    payload="GET request",
                    evidence=match.group(0)[:200],
                    severity="critical",
                    confidence=0.85,
                    extra={"vuln_type": "Exposed Secret/Credential"},
                ))
                return

    async def _test_method_enum(self, url: str, findings: List[Dict]):
        """Test which HTTP methods are allowed."""
        try:
            connector = __import__("aiohttp").TCPConnector(ssl=False)
            async with __import__("aiohttp").ClientSession(
                connector=connector, headers=self.DEFAULT_HEADERS
            ) as session:
                async with session.options(
                    url, timeout=__import__("aiohttp").ClientTimeout(total=self.timeout)
                ) as resp:
                    allow = resp.headers.get("Allow", "")
                    if allow and ("PUT" in allow or "DELETE" in allow):
                        findings.append(self._make_finding(
                            url=url,
                            parameter="HTTP Methods",
                            payload="OPTIONS",
                            evidence=f"Allowed methods: {allow}",
                            severity="low",
                            confidence=0.6,
                            extra={"allowed_methods": allow},
                        ))
        except Exception:
            pass

    async def _test_cors(self, url: str, findings: List[Dict]):
        """Test for CORS misconfiguration."""
        headers = {**self.DEFAULT_HEADERS, "Origin": "https://evil.com"}
        resp, body = await self._get(url, headers=headers)
        if not resp:
            return

        acao = ""
        acac = ""
        try:
            acao = resp.headers.get("Access-Control-Allow-Origin", "")
            acac = resp.headers.get("Access-Control-Allow-Credentials", "")
        except Exception:
            pass

        if acao == "https://evil.com" or (acao == "*" and acac.lower() == "true"):
            findings.append(self._make_finding(
                url=url,
                parameter="CORS Headers",
                payload="Origin: https://evil.com",
                evidence=f"ACAO: {acao} | ACAC: {acac}",
                severity="high",
                confidence=0.9,
                extra={"vuln_type": "CORS Misconfiguration"},
            ))

    async def _test_graphql(self, url: str, findings: List[Dict]):
        """Test GraphQL endpoint for introspection exposure."""
        for query in self.GRAPHQL_QUERIES:
            try:
                resp, body = await self._post(
                    url,
                    json_data=json.loads(query),
                    headers={**self.DEFAULT_HEADERS, "Content-Type": "application/json"},
                )
                if body and "__schema" in body and '"types"' in body:
                    findings.append(self._make_finding(
                        url=url,
                        parameter="GraphQL",
                        payload=query,
                        evidence="GraphQL introspection is enabled — schema exposed",
                        severity="medium",
                        confidence=0.9,
                        extra={"vuln_type": "GraphQL Introspection Enabled"},
                    ))
                    return
            except Exception:
                pass
