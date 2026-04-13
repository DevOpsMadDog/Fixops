"""Data Loss Prevention engine — detect PII, PCI, and sensitive data patterns."""
import re
import json
import uuid
import time
import sqlite3
import structlog
from pathlib import Path
from typing import Optional

_logger = structlog.get_logger()

# Detection patterns
DLP_PATTERNS = {
    "credit_card": {
        "pattern": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b",
        "severity": "critical", "category": "pci"
    },
    "ssn": {
        "pattern": r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",
        "severity": "critical", "category": "pii"
    },
    "email_address": {
        "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
        "severity": "medium", "category": "pii"
    },
    "phone_number": {
        "pattern": r"\b(?:\+?1[-.]?)?\(?(?:[0-9]{3})\)?[-.]?(?:[0-9]{3})[-.]?(?:[0-9]{4})\b",
        "severity": "medium", "category": "pii"
    },
    "aws_access_key": {
        "pattern": r"\b(AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b",
        "severity": "critical", "category": "credentials"
    },
    "private_key": {
        "pattern": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
        "severity": "critical", "category": "credentials"
    },
    "ip_address": {
        "pattern": r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
        "severity": "low", "category": "network"
    },
    "passport_number": {
        "pattern": r"\b[A-Z]{1,2}[0-9]{6,9}\b",
        "severity": "high", "category": "pii"
    },
}

_SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _redact_sample(match: str) -> str:
    """Return a redacted sample: first 3 chars + *** + last 2 chars."""
    if len(match) <= 5:
        return "*" * len(match)
    return match[:3] + "***" + match[-2:]


def _compute_risk_level(findings: list) -> str:
    """Compute overall risk level from list of finding dicts."""
    if not findings:
        return "low"
    highest = max(_SEVERITY_ORDER.get(f["severity"], 0) for f in findings)
    return {0: "low", 1: "medium", 2: "high", 3: "critical"}[highest]


class DLPEngine:
    def __init__(self, db_path: str = "data/dlp.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.row_factory = sqlite3.Row
        return conn

    def _init_tables(self):
        conn = self._get_connection()
        try:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS scan_results (
                    scan_id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    context TEXT,
                    total_findings INTEGER NOT NULL,
                    findings_json TEXT NOT NULL,
                    categories_found TEXT NOT NULL,
                    risk_level TEXT NOT NULL,
                    created_at REAL NOT NULL
                );

                CREATE TABLE IF NOT EXISTS custom_patterns (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    pattern TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    category TEXT NOT NULL,
                    org_id TEXT NOT NULL,
                    created_at REAL NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_scan_results_org_id ON scan_results(org_id);
                CREATE INDEX IF NOT EXISTS idx_scan_results_risk_level ON scan_results(risk_level);
                CREATE INDEX IF NOT EXISTS idx_custom_patterns_org_id ON custom_patterns(org_id);
            """)
            conn.commit()
        finally:
            conn.close()

    def _get_patterns_for_org(self, org_id: str) -> dict:
        """Return merged built-in + org-specific patterns."""
        patterns = dict(DLP_PATTERNS)
        conn = self._get_connection()
        try:
            rows = conn.execute(
                "SELECT name, pattern, severity, category FROM custom_patterns WHERE org_id = ?",
                (org_id,)
            ).fetchall()
            for row in rows:
                patterns[row["name"]] = {
                    "pattern": row["pattern"],
                    "severity": row["severity"],
                    "category": row["category"],
                }
        finally:
            conn.close()
        return patterns

    def scan_text(self, text: str, context: str = "", org_id: str = "default") -> dict:
        """Scan text for sensitive data patterns.

        Returns:
            {scan_id, total_findings, findings, categories_found, risk_level}

        NOTE: Never stores actual matched values — only counts and redacted samples.
        """
        patterns = self._get_patterns_for_org(org_id)
        findings = []

        for pattern_name, meta in patterns.items():
            try:
                matches = re.findall(meta["pattern"], text)
            except re.error as exc:
                _logger.warning("dlp.bad_pattern", pattern=pattern_name, error=str(exc))
                continue

            # Flatten tuple matches (e.g. groups from alternation)
            flat_matches = []
            for m in matches:
                if isinstance(m, tuple):
                    flat_matches.append("".join(m))
                else:
                    flat_matches.append(m)

            if not flat_matches:
                continue

            findings.append({
                "pattern_name": pattern_name,
                "severity": meta["severity"],
                "category": meta["category"],
                "match_count": len(flat_matches),
                "redacted_sample": _redact_sample(flat_matches[0]),
            })

        categories_found = sorted({f["category"] for f in findings})
        risk_level = _compute_risk_level(findings)
        scan_id = str(uuid.uuid4())
        now = time.time()

        conn = self._get_connection()
        try:
            conn.execute(
                """INSERT INTO scan_results
                   (scan_id, org_id, context, total_findings, findings_json,
                    categories_found, risk_level, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id, org_id, context, len(findings),
                    json.dumps(findings), json.dumps(categories_found),
                    risk_level, now,
                )
            )
            conn.commit()
        finally:
            conn.close()

        _logger.info("dlp.scan_complete", scan_id=scan_id, findings=len(findings),
                     risk_level=risk_level, org_id=org_id)
        return {
            "scan_id": scan_id,
            "total_findings": len(findings),
            "findings": findings,
            "categories_found": categories_found,
            "risk_level": risk_level,
        }

    def scan_file(self, file_path: str, org_id: str = "default") -> dict:
        """Read a file and scan its contents. Returns same shape as scan_text."""
        path = Path(file_path)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            _logger.error("dlp.file_read_error", path=file_path, error=str(exc))
            raise ValueError(f"Cannot read file: {file_path}") from exc

        return self.scan_text(text, context=f"file:{file_path}", org_id=org_id)

    def redact_text(self, text: str, org_id: str = "default") -> str:
        """Replace all detected sensitive data with [REDACTED-TYPE] placeholders."""
        patterns = self._get_patterns_for_org(org_id)
        result = text
        for pattern_name, meta in patterns.items():
            try:
                result = re.sub(
                    meta["pattern"],
                    f"[REDACTED-{pattern_name.upper()}]",
                    result,
                )
            except re.error as exc:
                _logger.warning("dlp.bad_pattern_redact", pattern=pattern_name, error=str(exc))
        return result

    def get_scan_result(self, scan_id: str) -> Optional[dict]:
        """Retrieve a stored scan result by ID."""
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM scan_results WHERE scan_id = ?", (scan_id,)
            ).fetchone()
        finally:
            conn.close()

        if row is None:
            return None
        return {
            "scan_id": row["scan_id"],
            "org_id": row["org_id"],
            "context": row["context"],
            "total_findings": row["total_findings"],
            "findings": json.loads(row["findings_json"]),
            "categories_found": json.loads(row["categories_found"]),
            "risk_level": row["risk_level"],
            "created_at": row["created_at"],
        }

    def list_scan_results(self, org_id: str = "default", risk_level: str = None,
                          limit: int = 50) -> list:
        """List scan results for an org, optionally filtered by risk_level."""
        conn = self._get_connection()
        try:
            if risk_level:
                rows = conn.execute(
                    """SELECT * FROM scan_results
                       WHERE org_id = ? AND risk_level = ?
                       ORDER BY created_at DESC LIMIT ?""",
                    (org_id, risk_level, limit)
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT * FROM scan_results
                       WHERE org_id = ?
                       ORDER BY created_at DESC LIMIT ?""",
                    (org_id, limit)
                ).fetchall()
        finally:
            conn.close()

        return [
            {
                "scan_id": r["scan_id"],
                "org_id": r["org_id"],
                "context": r["context"],
                "total_findings": r["total_findings"],
                "categories_found": json.loads(r["categories_found"]),
                "risk_level": r["risk_level"],
                "created_at": r["created_at"],
            }
            for r in rows
        ]

    def get_stats(self, org_id: str = "default") -> dict:
        """Return {total_scans, total_findings, by_category, by_severity, critical_scans}."""
        conn = self._get_connection()
        try:
            total_scans = conn.execute(
                "SELECT COUNT(*) FROM scan_results WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            total_findings = conn.execute(
                "SELECT COALESCE(SUM(total_findings), 0) FROM scan_results WHERE org_id = ?",
                (org_id,)
            ).fetchone()[0]

            critical_scans = conn.execute(
                "SELECT COUNT(*) FROM scan_results WHERE org_id = ? AND risk_level = 'critical'",
                (org_id,)
            ).fetchone()[0]

            rows = conn.execute(
                "SELECT findings_json FROM scan_results WHERE org_id = ?", (org_id,)
            ).fetchall()
        finally:
            conn.close()

        by_category: dict = {}
        by_severity: dict = {}
        for row in rows:
            findings = json.loads(row["findings_json"])
            for f in findings:
                cat = f.get("category", "unknown")
                sev = f.get("severity", "unknown")
                count = f.get("match_count", 1)
                by_category[cat] = by_category.get(cat, 0) + count
                by_severity[sev] = by_severity.get(sev, 0) + count

        return {
            "total_scans": total_scans,
            "total_findings": total_findings,
            "by_category": by_category,
            "by_severity": by_severity,
            "critical_scans": critical_scans,
        }

    def add_custom_pattern(self, name: str, pattern: str, severity: str,
                           category: str, org_id: str = "default") -> dict:
        """Add a custom detection pattern for an org."""
        # Validate regex compiles
        try:
            re.compile(pattern)
        except re.error as exc:
            raise ValueError(f"Invalid regex pattern: {exc}") from exc

        record_id = str(uuid.uuid4())
        now = time.time()

        conn = self._get_connection()
        try:
            conn.execute(
                """INSERT INTO custom_patterns
                   (id, name, pattern, severity, category, org_id, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (record_id, name, pattern, severity, category, org_id, now)
            )
            conn.commit()
        finally:
            conn.close()

        _logger.info("dlp.custom_pattern_added", name=name, org_id=org_id)
        return {
            "id": record_id,
            "name": name,
            "pattern": pattern,
            "severity": severity,
            "category": category,
            "org_id": org_id,
            "created_at": now,
        }
