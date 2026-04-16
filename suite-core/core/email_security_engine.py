"""Email Security Engine — ALDECI.

DMARC/SPF/DKIM analysis backend: domain configuration tracking, email threat
detection, DMARC aggregate report ingestion, and compliance scoring.

Compliance: NIST SP 800-177r1, CIS Controls v8 9.5, M3AAWG Best Practices
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "email_security.db"
)

# Compliance scoring weights
_DMARC_POLICY_SCORES: Dict[str, int] = {
    "reject": 40,
    "quarantine": 25,
    "none": 10,
    "missing": 0,
}

_RECORD_STATUS_SCORES: Dict[str, int] = {
    "pass": 30,
    "fail": 5,
    "missing": 0,
}

_VALID_THREAT_TYPES = frozenset({"phishing", "spoofing", "bec", "spam", "malware"})
_VALID_THREAT_STATUSES = frozenset({"detected", "blocked", "quarantined", "released"})
_VALID_DMARC_POLICIES = frozenset({"none", "quarantine", "reject", "missing"})
_VALID_RECORD_STATUSES = frozenset({"pass", "fail", "missing"})


class EmailSecurityEngine:
    """SQLite WAL-backed DMARC/SPF/DKIM analysis and email threat tracking engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS domain_configs (
                    domain_id         TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    domain            TEXT NOT NULL,
                    spf_record        TEXT,
                    spf_status        TEXT NOT NULL DEFAULT 'missing',
                    dkim_selector     TEXT,
                    dkim_status       TEXT NOT NULL DEFAULT 'missing',
                    dmarc_policy      TEXT NOT NULL DEFAULT 'missing',
                    compliance_score  INTEGER NOT NULL DEFAULT 0,
                    issues            TEXT NOT NULL DEFAULT '[]',
                    created_at        DATETIME NOT NULL,
                    updated_at        DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_domain_org
                    ON domain_configs (org_id);
                CREATE INDEX IF NOT EXISTS idx_domain_name
                    ON domain_configs (org_id, domain);

                CREATE TABLE IF NOT EXISTS email_threats (
                    threat_id         TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    domain_id         TEXT,
                    threat_type       TEXT NOT NULL,
                    source_ip         TEXT NOT NULL DEFAULT '',
                    sender            TEXT NOT NULL DEFAULT '',
                    subject_preview   TEXT NOT NULL DEFAULT '',
                    similarity_score  REAL NOT NULL DEFAULT 0.0,
                    status            TEXT NOT NULL DEFAULT 'detected',
                    created_at        DATETIME NOT NULL,
                    updated_at        DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_threat_org
                    ON email_threats (org_id);
                CREATE INDEX IF NOT EXISTS idx_threat_type
                    ON email_threats (org_id, threat_type);
                CREATE INDEX IF NOT EXISTS idx_threat_status
                    ON email_threats (org_id, status);

                CREATE TABLE IF NOT EXISTS dmarc_reports (
                    report_id         TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    domain_id         TEXT,
                    date              TEXT NOT NULL,
                    pass_count        INTEGER NOT NULL DEFAULT 0,
                    fail_count        INTEGER NOT NULL DEFAULT 0,
                    quarantine_count  INTEGER NOT NULL DEFAULT 0,
                    reject_count      INTEGER NOT NULL DEFAULT 0,
                    source_ips        TEXT NOT NULL DEFAULT '[]',
                    created_at        DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_dmarc_org
                    ON dmarc_reports (org_id);
                CREATE INDEX IF NOT EXISTS idx_dmarc_domain
                    ON dmarc_reports (org_id, domain_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        for field in ("issues", "source_ips"):
            if field in d:
                d[field] = json.loads(d[field] or "[]")
        return d

    @staticmethod
    def _compute_compliance_score(
        spf_status: str,
        dkim_status: str,
        dmarc_policy: str,
    ) -> int:
        """Compute 0-100 compliance score from SPF/DKIM/DMARC values.

        Scoring breakdown:
          SPF status:   pass=30, fail=5, missing=0
          DKIM status:  pass=30, fail=5, missing=0
          DMARC policy: reject=40, quarantine=25, none=10, missing=0
        """
        score = (
            _RECORD_STATUS_SCORES.get(spf_status, 0)
            + _RECORD_STATUS_SCORES.get(dkim_status, 0)
            + _DMARC_POLICY_SCORES.get(dmarc_policy, 0)
        )
        return min(100, max(0, score))

    @staticmethod
    def _detect_issues(
        spf_status: str,
        dkim_status: str,
        dmarc_policy: str,
    ) -> List[str]:
        """Return list of human-readable security issues for a domain."""
        issues: List[str] = []
        if spf_status == "missing":
            issues.append("SPF record not found — domain vulnerable to spoofing")
        elif spf_status == "fail":
            issues.append("SPF record present but validation failed")

        if dkim_status == "missing":
            issues.append("DKIM selector not configured — email authentication incomplete")
        elif dkim_status == "fail":
            issues.append("DKIM signature validation failed")

        if dmarc_policy == "missing":
            issues.append("DMARC policy not configured — no enforcement action defined")
        elif dmarc_policy == "none":
            issues.append("DMARC policy is 'none' — monitoring only, no enforcement")
        return issues

    # ------------------------------------------------------------------
    # Domain CRUD
    # ------------------------------------------------------------------

    def add_domain(
        self,
        org_id: str,
        domain: str,
        spf_record: Optional[str] = None,
        dkim_selector: Optional[str] = None,
        dmarc_policy: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Add a domain to email security inventory. Returns the created domain dict."""
        domain_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        # Derive statuses from provided values
        spf_status = "pass" if spf_record else "missing"
        dkim_status = "pass" if dkim_selector else "missing"

        # Normalise DMARC policy
        policy = (dmarc_policy or "missing").lower()
        if policy not in _VALID_DMARC_POLICIES:
            policy = "missing"

        compliance_score = self._compute_compliance_score(spf_status, dkim_status, policy)
        issues = self._detect_issues(spf_status, dkim_status, policy)

        row = {
            "domain_id": domain_id,
            "org_id": org_id,
            "domain": domain,
            "spf_record": spf_record or "",
            "spf_status": spf_status,
            "dkim_selector": dkim_selector or "",
            "dkim_status": dkim_status,
            "dmarc_policy": policy,
            "compliance_score": compliance_score,
            "issues": json.dumps(issues),
            "created_at": now,
            "updated_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO domain_configs
                        (domain_id, org_id, domain, spf_record, spf_status,
                         dkim_selector, dkim_status, dmarc_policy,
                         compliance_score, issues, created_at, updated_at)
                    VALUES
                        (:domain_id, :org_id, :domain, :spf_record, :spf_status,
                         :dkim_selector, :dkim_status, :dmarc_policy,
                         :compliance_score, :issues, :created_at, :updated_at)
                    """,
                    row,
                )

        result = dict(row)
        result["issues"] = issues
        return result

    def list_domains(self, org_id: str) -> List[Dict[str, Any]]:
        """List all domains for an org, ordered by compliance score ascending."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM domain_configs WHERE org_id=? ORDER BY compliance_score ASC",
                (org_id,),
            ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def get_domain(self, org_id: str, domain_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single domain config scoped to org."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM domain_configs WHERE domain_id=? AND org_id=?",
                (domain_id, org_id),
            ).fetchone()
        return self._row_to_dict(row) if row else None

    def analyze_domain(self, org_id: str, domain_id: str) -> Dict[str, Any]:
        """Recompute compliance score and issues for a domain. Returns updated dict."""
        domain = self.get_domain(org_id, domain_id)
        if domain is None:
            raise ValueError(f"Domain {domain_id} not found for org {org_id}")

        spf_status = domain.get("spf_status", "missing")
        dkim_status = domain.get("dkim_status", "missing")
        dmarc_policy = domain.get("dmarc_policy", "missing")

        compliance_score = self._compute_compliance_score(spf_status, dkim_status, dmarc_policy)
        issues = self._detect_issues(spf_status, dkim_status, dmarc_policy)
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    UPDATE domain_configs
                    SET compliance_score=?, issues=?, updated_at=?
                    WHERE domain_id=? AND org_id=?
                    """,
                    (compliance_score, json.dumps(issues), now, domain_id, org_id),
                )

        domain["compliance_score"] = compliance_score
        domain["issues"] = issues
        domain["updated_at"] = now
        return domain

    def update_domain_policy(
        self, org_id: str, domain_id: str, data: Dict[str, Any]
    ) -> bool:
        """Update domain SPF/DKIM/DMARC fields and recompute compliance score.

        Returns True if a row was updated.
        """
        allowed = {"spf_record", "spf_status", "dkim_selector", "dkim_status", "dmarc_policy"}
        fields = {k: v for k, v in data.items() if k in allowed}
        if not fields:
            return False

        # Normalise dmarc_policy
        if "dmarc_policy" in fields:
            policy = str(fields["dmarc_policy"]).lower()
            fields["dmarc_policy"] = policy if policy in _VALID_DMARC_POLICIES else "missing"

        # Normalise statuses
        for status_field in ("spf_status", "dkim_status"):
            if status_field in fields:
                val = str(fields[status_field]).lower()
                fields[status_field] = val if val in _VALID_RECORD_STATUSES else "missing"

        # Infer status from record presence if record field supplied
        if "spf_record" in fields and "spf_status" not in fields:
            fields["spf_status"] = "pass" if fields["spf_record"] else "missing"
        if "dkim_selector" in fields and "dkim_status" not in fields:
            fields["dkim_status"] = "pass" if fields["dkim_selector"] else "missing"

        # Recompute compliance score with latest values
        existing = self.get_domain(org_id, domain_id)
        if existing is None:
            return False

        spf_status = fields.get("spf_status", existing.get("spf_status", "missing"))
        dkim_status = fields.get("dkim_status", existing.get("dkim_status", "missing"))
        dmarc_policy = fields.get("dmarc_policy", existing.get("dmarc_policy", "missing"))

        fields["compliance_score"] = self._compute_compliance_score(spf_status, dkim_status, dmarc_policy)
        fields["issues"] = json.dumps(self._detect_issues(spf_status, dkim_status, dmarc_policy))
        fields["updated_at"] = datetime.now(timezone.utc).isoformat()

        set_clause = ", ".join(f"{k}=?" for k in fields)
        values = list(fields.values()) + [domain_id, org_id]

        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    f"UPDATE domain_configs SET {set_clause} WHERE domain_id=? AND org_id=?",  # nosec B608
                    values,
                )
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Email Threats
    # ------------------------------------------------------------------

    def create_threat(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create an email threat record. Returns the created threat dict."""
        threat_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        threat_type = str(data.get("threat_type", "phishing")).lower()
        if threat_type not in _VALID_THREAT_TYPES:
            threat_type = "phishing"

        status = str(data.get("status", "detected")).lower()
        if status not in _VALID_THREAT_STATUSES:
            status = "detected"

        similarity_score = float(data.get("similarity_score", 0.0))
        similarity_score = max(0.0, min(1.0, similarity_score))

        row = {
            "threat_id": threat_id,
            "org_id": org_id,
            "domain_id": data.get("domain_id") or "",
            "threat_type": threat_type,
            "source_ip": data.get("source_ip") or "",
            "sender": data.get("sender") or "",
            "subject_preview": data.get("subject_preview") or "",
            "similarity_score": similarity_score,
            "status": status,
            "created_at": now,
            "updated_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO email_threats
                        (threat_id, org_id, domain_id, threat_type, source_ip,
                         sender, subject_preview, similarity_score, status,
                         created_at, updated_at)
                    VALUES
                        (:threat_id, :org_id, :domain_id, :threat_type, :source_ip,
                         :sender, :subject_preview, :similarity_score, :status,
                         :created_at, :updated_at)
                    """,
                    row,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "email_security", "org_id": org_id, "source_engine": "email_security"})
            except Exception:
                pass

        return dict(row)

    def list_threats(
        self,
        org_id: str,
        threat_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List email threats for an org, with optional type/status filter."""
        query = "SELECT * FROM email_threats WHERE org_id=?"
        params: list = [org_id]

        if threat_type:
            query += " AND threat_type=?"
            params.append(threat_type.lower())
        if status:
            query += " AND status=?"
            params.append(status.lower())

        query += " ORDER BY created_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def update_threat_status(
        self, org_id: str, threat_id: str, status: str
    ) -> bool:
        """Update a threat's status. Returns True if updated."""
        normalized = status.lower()
        if normalized not in _VALID_THREAT_STATUSES:
            return False

        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    "UPDATE email_threats SET status=?, updated_at=? WHERE threat_id=? AND org_id=?",
                    (normalized, now, threat_id, org_id),
                )
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # DMARC Reports
    # ------------------------------------------------------------------

    def add_dmarc_report(
        self, org_id: str, domain_id: str, report: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Ingest a DMARC aggregate report. Returns the created report dict."""
        report_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        source_ips = report.get("source_ips", [])
        if not isinstance(source_ips, list):
            source_ips = []

        row = {
            "report_id": report_id,
            "org_id": org_id,
            "domain_id": domain_id,
            "date": report.get("date") or now[:10],
            "pass_count": int(report.get("pass_count", 0)),
            "fail_count": int(report.get("fail_count", 0)),
            "quarantine_count": int(report.get("quarantine_count", 0)),
            "reject_count": int(report.get("reject_count", 0)),
            "source_ips": json.dumps(source_ips),
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO dmarc_reports
                        (report_id, org_id, domain_id, date, pass_count,
                         fail_count, quarantine_count, reject_count,
                         source_ips, created_at)
                    VALUES
                        (:report_id, :org_id, :domain_id, :date, :pass_count,
                         :fail_count, :quarantine_count, :reject_count,
                         :source_ips, :created_at)
                    """,
                    row,
                )

        result = dict(row)
        result["source_ips"] = source_ips
        return result

    def list_dmarc_reports(
        self, org_id: str, domain_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List DMARC reports for an org, optionally filtered by domain."""
        if domain_id:
            query = (
                "SELECT * FROM dmarc_reports WHERE org_id=? AND domain_id=? ORDER BY date DESC"
            )
            params = [org_id, domain_id]
        else:
            query = "SELECT * FROM dmarc_reports WHERE org_id=? ORDER BY date DESC"
            params = [org_id]

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_email_stats(self, org_id: str) -> Dict[str, Any]:
        """Return email security summary statistics for an org."""
        with self._conn() as conn:
            total_domains = conn.execute(
                "SELECT COUNT(*) FROM domain_configs WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            compliant_domains = conn.execute(
                "SELECT COUNT(*) FROM domain_configs WHERE org_id=? AND compliance_score >= 80",
                (org_id,),
            ).fetchone()[0]

            avg_score_row = conn.execute(
                "SELECT AVG(compliance_score) FROM domain_configs WHERE org_id=?", (org_id,)
            ).fetchone()
            avg_compliance_score = round(avg_score_row[0] or 0.0, 1)

            threats_detected = conn.execute(
                "SELECT COUNT(*) FROM email_threats WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            threats_blocked = conn.execute(
                "SELECT COUNT(*) FROM email_threats WHERE org_id=? AND status IN ('blocked', 'quarantined')",
                (org_id,),
            ).fetchone()[0]

            phishing_count = conn.execute(
                "SELECT COUNT(*) FROM email_threats WHERE org_id=? AND threat_type='phishing'",
                (org_id,),
            ).fetchone()[0]

        return {
            "total_domains": total_domains,
            "compliant_domains": compliant_domains,
            "threats_detected": threats_detected,
            "threats_blocked": threats_blocked,
            "phishing_count": phishing_count,
            "avg_compliance_score": avg_compliance_score,
        }
