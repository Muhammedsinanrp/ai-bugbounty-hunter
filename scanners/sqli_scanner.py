#!/usr/bin/env python3
"""
AI-BugBounty-Hunter — SQL Injection Scanner
Detects Error-based, Boolean-based, and Time-based SQL injection.
"""
import asyncio
import re
import time
from typing import List, Dict, Optional
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse
from scanners.base_scanner import BaseScanner
from core.config import Config


class SQLIScanner(BaseScanner):
    """SQL Injection detection scanner."""

    VULN_TYPE = "SQL Injection"
    DEFAULT_SEVERITY = "critical"

    # Error patterns for different databases
    ERROR_PATTERNS = [
        # MySQL
        r"you have an error in your sql syntax",
        r"warning: mysql_",
        r"unclosed quotation mark",
        r"quoted string not properly terminated",
        # PostgreSQL
        r"pg_query\(\):",
        r"pg_exec\(\):",
        r"ERROR:.*syntax error at or near",
        # SQLite
        r"sqlite_",
        r"sqlite3_",
        r"SQLite/JDBCDriver",
        # MSSQL
        r"microsoft sql server",
        r"sql server.*driver",
        r"ole db provider",
        # Oracle
        r"ORA-\d{5}",
        r"Oracle error",
        r"oracle.*driver",
        # Generic
        r"sql syntax.*error",
        r"invalid sql statement",
        r"sql command not properly ended",
    ]

    ERROR_PAYLOADS = ["'", "\"", "'--", "\"--", "';--", "1'1", "' OR 1=1--"]

    TIME_PAYLOADS = [
        "' AND SLEEP(5)--",
        "'; WAITFOR DELAY '0:0:5'--",
        "' OR SLEEP(5)--",
        "1; SELECT SLEEP(5)--",
        "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    ]

    BOOLEAN_PAYLOADS = [
        ("' OR '1'='1", "' OR '1'='2"),
        ("' OR 1=1--", "' OR 1=2--"),
        ("admin'--", "admin'#"),
    ]

    def __init__(self, config: Config):
        super().__init__(config)
        self.time_based = config.get("scanners", "sqli", default={}).get("time_based", True)
        self.error_based = config.get("scanners", "sqli", default={}).get("error_based", True)
        self.boolean_based = config.get("scanners", "sqli", default={}).get("boolean_based", True)

    async def scan(self, urls: List[str], parameters: List[Dict]) -> List[Dict]:
        """Scan for SQL injection across parameters."""
        self.logger.info(f"SQLi scan: {len(parameters)} parameters")
        findings: List[Dict] = []

        tasks = []
        for param in parameters:
            if self.error_based:
                tasks.append(self._test_error_based(param, findings))
            if self.time_based:
                tasks.append(self._test_time_based(param, findings))
            if self.boolean_based:
                tasks.append(self._test_boolean_based(param, findings))

        await asyncio.gather(*tasks, return_exceptions=True)
        self.logger.info(f"  SQLi: {len(findings)} potential findings")
        return findings

    async def _test_error_based(self, param: Dict, findings: List[Dict]):
        """Test for error-based SQL injection."""
        base_url = param.get("url", "")
        param_name = param.get("parameter", "")
        method = param.get("method", "GET")

        for payload in self.ERROR_PAYLOADS:
            resp, body = await self._send_request(base_url, param_name, payload, method)
            if not body:
                continue

            for pattern in self.ERROR_PATTERNS:
                if re.search(pattern, body, re.IGNORECASE):
                    findings.append(self._make_finding(
                        url=base_url,
                        parameter=param_name,
                        payload=payload,
                        evidence=self._extract_error(body),
                        severity="critical",
                        confidence=0.9,
                        extra={"technique": "error_based", "method": method},
                    ))
                    return

    async def _test_time_based(self, param: Dict, findings: List[Dict]):
        """Test for time-based blind SQL injection."""
        base_url = param.get("url", "")
        param_name = param.get("parameter", "")
        method = param.get("method", "GET")

        # First get baseline response time
        start = time.monotonic()
        await self._send_request(base_url, param_name, "normal_value", method)
        baseline = time.monotonic() - start

        for payload in self.TIME_PAYLOADS[:3]:
            start = time.monotonic()
            await self._send_request(base_url, param_name, payload, method)
            elapsed = time.monotonic() - start

            if elapsed > baseline + 4:  # 4+ second delay = suspicious
                findings.append(self._make_finding(
                    url=base_url,
                    parameter=param_name,
                    payload=payload,
                    evidence=f"Response delayed {elapsed:.1f}s (baseline: {baseline:.1f}s)",
                    severity="critical",
                    confidence=0.8,
                    extra={"technique": "time_based", "method": method},
                ))
                return

    async def _test_boolean_based(self, param: Dict, findings: List[Dict]):
        """Test for boolean-based SQL injection."""
        base_url = param.get("url", "")
        param_name = param.get("parameter", "")
        method = param.get("method", "GET")

        for true_payload, false_payload in self.BOOLEAN_PAYLOADS:
            _, true_body = await self._send_request(base_url, param_name, true_payload, method)
            _, false_body = await self._send_request(base_url, param_name, false_payload, method)

            if true_body and false_body and len(true_body) != len(false_body):
                # Significant content difference suggests boolean injection
                diff = abs(len(true_body) - len(false_body))
                if diff > 50:
                    findings.append(self._make_finding(
                        url=base_url,
                        parameter=param_name,
                        payload=true_payload,
                        evidence=f"Response length difference: {diff} bytes between true/false payloads",
                        severity="high",
                        confidence=0.65,
                        extra={"technique": "boolean_based", "method": method},
                    ))
                    return

    async def _send_request(self, url: str, param_name: str, payload: str, method: str):
        """Send request with injected payload."""
        if method == "POST":
            return await self._post(url, data={param_name: payload})
        else:
            parsed = urlparse(url)
            params = parse_qs(parsed.query)
            params[param_name] = [payload]
            new_query = urlencode({k: v[0] for k, v in params.items()})
            test_url = urlunparse(parsed._replace(query=new_query))
            return await self._get(test_url)

    def _extract_error(self, body: str) -> str:
        """Extract error message context from response body."""
        for pattern in self.ERROR_PATTERNS:
            match = re.search(pattern, body, re.IGNORECASE)
            if match:
                idx = match.start()
                return body[max(0, idx-50):min(len(body), idx+300)]
        return body[:500]
