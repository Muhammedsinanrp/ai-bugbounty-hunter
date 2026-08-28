#!/usr/bin/env python3
"""
AI-BugBounty-Hunter — Findings Database
SQLite-backed persistent storage for all vulnerability findings.
Supports querying, deduplication, and export.
"""
import json
import sqlite3
import hashlib
import uuid
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional


class FindingsDB:
    """
    Persistent SQLite database for storing, querying, and deduplicating findings.
    Thread-safe with connection-per-call pattern for asyncio compatibility.
    """

    DB_PATH = "findings_db/findings.db"

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = db_path or self.DB_PATH
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        """Initialize database schema."""
        with self._get_conn() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    type TEXT NOT NULL,
                    url TEXT,
                    parameter TEXT,
                    severity TEXT DEFAULT 'info',
                    cvss REAL DEFAULT 0.0,
                    status TEXT DEFAULT 'new',
                    validated INTEGER DEFAULT 0,
                    description TEXT,
                    impact TEXT,
                    remediation TEXT,
                    poc TEXT,
                    attack_scenario TEXT,
                    reproduction_steps TEXT,
                    payload TEXT,
                    evidence TEXT,
                    triage_notes TEXT,
                    requires_human_review INTEGER DEFAULT 0,
                    ai_analysis TEXT,
                    validation TEXT,
                    confidence REAL DEFAULT 0.5,
                    hash TEXT UNIQUE,
                    timestamp TEXT,
                    raw_data TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    started_at TEXT,
                    completed_at TEXT,
                    status TEXT DEFAULT 'running',
                    summary TEXT,
                    findings_count INTEGER DEFAULT 0
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_target ON findings(target)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_severity ON findings(severity)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_type ON findings(type)")
            conn.commit()

    def _make_hash(self, finding: Dict) -> str:
        """Create a deduplication hash from key fields."""
        key = f"{finding.get('type', '')}{finding.get('url', '')}{finding.get('parameter', '')}{finding.get('payload', '')}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def save_finding(self, finding: Dict) -> Optional[str]:
        """Save a finding to the database. Returns ID or None if duplicate."""
        finding_hash = self._make_hash(finding)

        # Check for duplicate
        with self._get_conn() as conn:
            existing = conn.execute(
                "SELECT id FROM findings WHERE hash = ?", (finding_hash,)
            ).fetchone()
            if existing:
                return None  # Duplicate

        finding_id = finding.get("id") or str(uuid.uuid4())
        timestamp = finding.get("timestamp") or datetime.utcnow().isoformat()

        repro_steps = finding.get("reproduction_steps", [])
        if isinstance(repro_steps, list):
            repro_steps = json.dumps(repro_steps)

        try:
            with self._get_conn() as conn:
                conn.execute("""
                    INSERT OR IGNORE INTO findings (
                        id, target, type, url, parameter, severity, cvss,
                        status, validated, description, impact, remediation,
                        poc, attack_scenario, reproduction_steps, payload,
                        evidence, triage_notes, requires_human_review,
                        ai_analysis, validation, confidence, hash, timestamp, raw_data
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    finding_id,
                    finding.get("target", finding.get("url", "").split("/")[2] if finding.get("url") else "unknown"),
                    finding.get("type", "Unknown"),
                    finding.get("url", ""),
                    finding.get("parameter", ""),
                    finding.get("severity", "info"),
                    float(finding.get("cvss", 0)),
                    finding.get("status", "new"),
                    1 if finding.get("validated") else 0,
                    finding.get("description", ""),
                    finding.get("impact", ""),
                    finding.get("remediation", ""),
                    finding.get("poc", ""),
                    finding.get("attack_scenario", ""),
                    repro_steps,
                    finding.get("payload", ""),
                    str(finding.get("evidence", ""))[:5000],
                    finding.get("triage_notes", ""),
                    1 if finding.get("requires_human_review") else 0,
                    json.dumps(finding.get("ai_analysis", {})),
                    json.dumps(finding.get("validation", {})),
                    float(finding.get("confidence", 0.5)),
                    finding_hash,
                    timestamp,
                    json.dumps({k: v for k, v in finding.items() if k not in (
                        "ai_analysis", "validation", "reproduction_steps"
                    )})
                ))
                conn.commit()
            return finding_id
        except Exception as e:
            return None

    def get_all_findings(self, target: Optional[str] = None,
                         severity: Optional[str] = None,
                         status: Optional[str] = None) -> List[Dict]:
        """Retrieve findings with optional filters."""
        query = "SELECT * FROM findings WHERE 1=1"
        params = []

        if target:
            query += " AND target LIKE ?"
            params.append(f"%{target}%")
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if status:
            query += " AND status = ?"
            params.append(status)

        query += " ORDER BY cvss DESC, timestamp DESC"

        with self._get_conn() as conn:
            rows = conn.execute(query, params).fetchall()

        results = []
        for row in rows:
            d = dict(row)
            # Deserialize JSON fields
            for field in ("ai_analysis", "validation"):
                if d.get(field):
                    try:
                        d[field] = json.loads(d[field])
                    except Exception:
                        pass
            if d.get("reproduction_steps"):
                try:
                    d["reproduction_steps"] = json.loads(d["reproduction_steps"])
                except Exception:
                    pass
            results.append(d)

        return results

    def get_finding_by_id(self, finding_id: str) -> Optional[Dict]:
        """Retrieve a single finding by ID."""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM findings WHERE id = ?", (finding_id,)
            ).fetchone()
        if row:
            return dict(row)
        return None

    def update_finding_status(self, finding_id: str, status: str):
        """Update the status of a finding."""
        with self._get_conn() as conn:
            conn.execute(
                "UPDATE findings SET status = ? WHERE id = ?",
                (status, finding_id)
            )
            conn.commit()

    def get_stats(self, target: Optional[str] = None) -> Dict:
        """Get finding statistics."""
        query_base = "SELECT severity, COUNT(*) as count FROM findings"
        params = []
        if target:
            query_base += " WHERE target LIKE ?"
            params.append(f"%{target}%")
        query_base += " GROUP BY severity"

        with self._get_conn() as conn:
            rows = conn.execute(query_base, params).fetchall()
            total = conn.execute(
                "SELECT COUNT(*) FROM findings" + (" WHERE target LIKE ?" if target else ""),
                params if target else []
            ).fetchone()[0]

        stats = {"total": total, "by_severity": {}}
        for row in rows:
            stats["by_severity"][row["severity"]] = row["count"]

        return stats

    def export_json(self, target: Optional[str] = None, output_path: str = "findings_export.json") -> str:
        """Export findings to JSON file."""
        findings = self.get_all_findings(target)
        with open(output_path, "w") as f:
            json.dump(findings, f, indent=2, default=str)
        return output_path

    def clear_target(self, target: str):
        """Remove all findings for a target."""
        with self._get_conn() as conn:
            conn.execute("DELETE FROM findings WHERE target LIKE ?", (f"%{target}%",))
            conn.commit()

    def save_scan(self, scan_id: str, target: str, status: str = "running",
                  summary: Optional[Dict] = None, findings_count: int = 0):
        """Record a scan session."""
        with self._get_conn() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO scans (id, target, started_at, status, summary, findings_count)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                scan_id, target, datetime.utcnow().isoformat(), status,
                json.dumps(summary or {}), findings_count
            ))
            conn.commit()

    def complete_scan(self, scan_id: str, findings_count: int, summary: Optional[Dict] = None):
        """Mark a scan as complete."""
        with self._get_conn() as conn:
            conn.execute("""
                UPDATE scans SET status = 'complete', completed_at = ?,
                findings_count = ?, summary = ?
                WHERE id = ?
            """, (
                datetime.utcnow().isoformat(),
                findings_count,
                json.dumps(summary or {}),
                scan_id,
            ))
            conn.commit()
