#!/usr/bin/env python3
"""
AI-BugBounty-Hunter — IDOR Scanner
Detects Insecure Direct Object Reference and access control issues.
"""
import asyncio
import re
from typing import List, Dict
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
from scanners.base_scanner import BaseScanner
from core.config import Config


class IDORScanner(BaseScanner):
    """IDOR / Access Control vulnerability scanner."""

    VULN_TYPE = "Insecure Direct Object Reference (IDOR)"
    DEFAULT_SEVERITY = "high"

    NUMERIC_ID_PARAMS = {
        "id", "user_id", "uid", "account", "account_id", "customer_id",
        "order_id", "invoice_id", "doc_id", "document_id", "file_id",
        "msg_id", "message_id", "ticket_id", "report_id", "record_id",
        "profile_id", "post_id", "comment_id", "product_id",
    }

    def __init__(self, config: Config):
        super().__init__(config)

    async def scan(self, urls: List[str], parameters: List[Dict],
                   tech_stack: Dict = None) -> List[Dict]:
        """Scan for IDOR vulnerabilities."""
        self.logger.info(f"IDOR scan: {len(parameters)} parameters")
        findings: List[Dict] = []

        # Find numeric ID parameters
        id_params = [
            p for p in parameters
            if (
                p.get("parameter", "").lower() in self.NUMERIC_ID_PARAMS
                or re.match(r"^\d+$", str(p.get("value", "")))
            )
        ]
        self.logger.info(f"  → {len(id_params)} ID-like parameters to test")

        tasks = [self._test_idor(param, findings) for param in id_params]
        await asyncio.gather(*tasks, return_exceptions=True)

        # Also test URL path-based IDs
        path_tasks = [self._test_path_idor(url, findings) for url in urls[:100]]
        await asyncio.gather(*path_tasks, return_exceptions=True)

        self.logger.info(f"  IDOR: {len(findings)} potential findings")
        return findings

    async def _test_idor(self, param: Dict, findings: List[Dict]):
        """Test a numeric parameter for IDOR."""
        base_url = param.get("url", "")
        param_name = param.get("parameter", "")
        original_value = str(param.get("value", "1"))
        method = param.get("method", "GET")

        # Try to get baseline response
        _, original_body = await self._send(base_url, param_name, original_value, method)
        if not original_body:
            return

        # Try adjacent IDs
        try:
            numeric_val = int(original_value)
        except ValueError:
            return

        test_ids = [
            str(numeric_val - 1),
            str(numeric_val + 1),
            "1",
            "0",
            "-1",
            "9999999",
        ]

        for test_id in test_ids:
            if test_id == original_value:
                continue

            _, test_body = await self._send(base_url, param_name, test_id, method)

            if not test_body:
                continue

            # Check if we got a meaningful response (not 404/error)
            if len(test_body) > 200 and test_body != original_body:
                # Look for PII-like data in response
                has_pii = self._detect_pii(test_body)
                if has_pii:
                    findings.append(self._make_finding(
                        url=base_url,
                        parameter=param_name,
                        payload=test_id,
                        evidence=f"Got {len(test_body)} byte response for ID={test_id} (original={original_value}). PII indicators found.",
                        severity="high",
                        confidence=0.65,
                        extra={"method": method, "original_id": original_value, "tested_id": test_id},
                    ))
                    return

    async def _test_path_idor(self, url: str, findings: List[Dict]):
        """Test URL path segments for numeric IDs."""
        parsed = urlparse(url)
        path_parts = parsed.path.split("/")

        for i, part in enumerate(path_parts):
            if not re.match(r"^\d{1,10}$", part):
                continue

            # This path segment looks like an ID
            numeric_id = int(part)
            test_id = str(numeric_id + 1)

            new_parts = path_parts.copy()
            new_parts[i] = test_id
            new_path = "/".join(new_parts)
            test_url = urlunparse(parsed._replace(path=new_path))

            _, original_body = await self._get(url)
            _, test_body = await self._get(test_url)

            if original_body and test_body and len(test_body) > 200:
                if self._detect_pii(test_body):
                    findings.append(self._make_finding(
                        url=url,
                        parameter=f"path_segment_{i}",
                        payload=test_id,
                        evidence=f"Path-based IDOR: {url} → {test_url}",
                        severity="high",
                        confidence=0.6,
                    ))
                    return

    def _detect_pii(self, body: str) -> bool:
        """Detect potential PII in response body."""
        patterns = [
            r'"email"\s*:\s*"[^"]+@[^"]+\.[^"]+"',
            r'"name"\s*:\s*"[A-Za-z ]{2,50}"',
            r'"phone"\s*:\s*"[\d\+\-\(\) ]{7,20}"',
            r'"ssn"\s*:\s*"\d{3}-\d{2}-\d{4}"',
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            r'"address"\s*:',
            r'"credit_card"\s*:',
        ]
        for pattern in patterns:
            if re.search(pattern, body, re.IGNORECASE):
                return True
        return False

    async def _send(self, url: str, param_name: str, value: str, method: str):
        if method == "POST":
            return await self._post(url, data={param_name: value})
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        params[param_name] = [value]
        new_query = urlencode({k: v[0] for k, v in params.items()})
        return await self._get(urlunparse(parsed._replace(query=new_query)))
