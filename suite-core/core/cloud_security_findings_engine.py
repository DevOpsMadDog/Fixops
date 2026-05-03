"""Cloud Security Findings Engine — ALDECI. SQLite WAL + RLock + org_id isolation.

Multi-cloud security findings aggregator:
  - Ingest findings from AWS / Azure / GCP / Alibaba / OCI / IBM
  - Dedup: same (org_id, provider, account_id, resource_id, finding_title) + open → skip
  - Resolve, suppress, and track remediation lifecycle
  - Summary stats, top affected resources

Compliance: CSPM, CIS Benchmarks, NIST 800-53
"""
from __future__ import annotations

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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "cloud_security_findings.db"
)

VALID_PROVIDERS = frozenset({"aws", "azure", "gcp", "alibaba", "oci", "ibm"})
VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "informational"})
VALID_FINDING_TYPES = frozenset({
    "misconfiguration", "vulnerability", "compliance", "threat", "exposure",
})
VALID_STATUSES = frozenset({"open", "resolved", "suppressed", "in_progress"})
VALID_REMEDIATION_STATUSES = frozenset({"assigned", "in_progress", "completed", "cancelled"})


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class CloudSecurityFindingsEngine:
    """SQLite WAL-backed multi-cloud security findings aggregator.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/cloud_security_findings.db
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
                CREATE TABLE IF NOT EXISTS cloud_findings (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    provider        TEXT NOT NULL DEFAULT 'aws',
                    account_id      TEXT NOT NULL DEFAULT '',
                    region          TEXT NOT NULL DEFAULT '',
                    resource_type   TEXT NOT NULL DEFAULT '',
                    resource_id     TEXT NOT NULL DEFAULT '',
                    finding_title   TEXT NOT NULL DEFAULT '',
                    finding_type    TEXT NOT NULL DEFAULT 'misconfiguration',
                    severity        TEXT NOT NULL DEFAULT 'medium',
                    status          TEXT NOT NULL DEFAULT 'open',
                    cvss_score      REAL NOT NULL DEFAULT 0.0,
                    remediation     TEXT NOT NULL DEFAULT '',
                    detected_at     TEXT NOT NULL,
                    resolved_at     TEXT,
                    created_at      TEXT NOT NULL
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_cf_dedup
                    ON cloud_findings (org_id, provider, account_id, resource_id, finding_title)
                    WHERE status = 'open';

                CREATE INDEX IF NOT EXISTS idx_cf_org_status
                    ON cloud_findings (org_id, status);

                CREATE INDEX IF NOT EXISTS idx_cf_org_severity
                    ON cloud_findings (org_id, severity);

                CREATE TABLE IF NOT EXISTS finding_suppressions (
                    id              TEXT PRIMARY KEY,
                    finding_id      TEXT NOT NULL,
                    org_id          TEXT NOT NULL,
                    suppressed_by   TEXT NOT NULL DEFAULT '',
                    reason          TEXT NOT NULL DEFAULT '',
                    expires_at      TEXT NOT NULL DEFAULT '',
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_fs_finding
                    ON finding_suppressions (finding_id);

                CREATE TABLE IF NOT EXISTS remediation_tracking (
                    id              TEXT PRIMARY KEY,
                    finding_id      TEXT NOT NULL,
                    org_id          TEXT NOT NULL,
                    assignee        TEXT NOT NULL DEFAULT '',
                    due_date        TEXT NOT NULL DEFAULT '',
                    notes           TEXT NOT NULL DEFAULT '',
                    status          TEXT NOT NULL DEFAULT 'assigned',
                    updated_at      TEXT NOT NULL,
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_rt_finding
                    ON remediation_tracking (finding_id);

                CREATE INDEX IF NOT EXISTS idx_rt_org_status
                    ON remediation_tracking (org_id, status);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def ingest_finding(
        self,
        org_id: str,
        provider: str,
        account_id: str,
        region: str,
        resource_type: str,
        resource_id: str,
        finding_title: str,
        finding_type: str,
        severity: str,
        cvss_score: float = 0.0,
        remediation: str = "",
    ) -> Dict[str, Any]:
        """Ingest a cloud security finding. Deduplicates open findings by
        (org_id, provider, account_id, resource_id, finding_title)."""
        if provider not in VALID_PROVIDERS:
            raise ValueError(f"provider must be one of {sorted(VALID_PROVIDERS)}")
        if severity not in VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(VALID_SEVERITIES)}")
        if finding_type not in VALID_FINDING_TYPES:
            raise ValueError(f"finding_type must be one of {sorted(VALID_FINDING_TYPES)}")

        cvss_score = max(0.0, min(float(cvss_score), 10.0))

        with self._lock:
            with self._conn() as conn:
                # Dedup check: same key AND status=open
                existing = conn.execute(
                    """SELECT * FROM cloud_findings
                       WHERE org_id=? AND provider=? AND account_id=?
                         AND resource_id=? AND finding_title=? AND status='open'""",
                    (org_id, provider, account_id, resource_id, finding_title),
                ).fetchone()
                if existing:
                    return self._row(existing)

                now = _now_iso()
                record: Dict[str, Any] = {
                    "id": str(uuid.uuid4()),
                    "org_id": org_id,
                    "provider": provider,
                    "account_id": account_id,
                    "region": region,
                    "resource_type": resource_type,
                    "resource_id": resource_id,
                    "finding_title": finding_title,
                    "finding_type": finding_type,
                    "severity": severity,
                    "status": "open",
                    "cvss_score": cvss_score,
                    "remediation": remediation,
                    "detected_at": now,
                    "resolved_at": None,
                    "created_at": now,
                }
                conn.execute(
                    """INSERT INTO cloud_findings
                       (id, org_id, provider, account_id, region, resource_type,
                        resource_id, finding_title, finding_type, severity, status,
                        cvss_score, remediation, detected_at, resolved_at, created_at)
                       VALUES (:id, :org_id, :provider, :account_id, :region, :resource_type,
                               :resource_id, :finding_title, :finding_type, :severity, :status,
                               :cvss_score, :remediation, :detected_at, :resolved_at, :created_at)""",
                    record,
                )
        _logger.info("finding ingested id=%s org=%s provider=%s severity=%s",
                     record["id"], org_id, provider, severity)
        return record

    def resolve_finding(self, finding_id: str, org_id: str) -> Dict[str, Any]:
        """Mark a finding as resolved."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM cloud_findings WHERE id=? AND org_id=?",
                    (finding_id, org_id),
                ).fetchone()
                if not row:
                    raise KeyError(f"finding {finding_id!r} not found")
                conn.execute(
                    "UPDATE cloud_findings SET status='resolved', resolved_at=? WHERE id=? AND org_id=?",
                    (now, finding_id, org_id),
                )
                updated = conn.execute(
                    "SELECT * FROM cloud_findings WHERE id=?", (finding_id,)
                ).fetchone()
        return self._row(updated)

    def suppress_finding(
        self,
        finding_id: str,
        org_id: str,
        suppressed_by: str,
        reason: str,
        expires_at: str = "",
    ) -> Dict[str, Any]:
        """Suppress a finding and record suppression details."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM cloud_findings WHERE id=? AND org_id=?",
                    (finding_id, org_id),
                ).fetchone()
                if not row:
                    raise KeyError(f"finding {finding_id!r} not found")
                conn.execute(
                    "UPDATE cloud_findings SET status='suppressed' WHERE id=? AND org_id=?",
                    (finding_id, org_id),
                )
                sup_id = str(uuid.uuid4())
                conn.execute(
                    """INSERT INTO finding_suppressions
                       (id, finding_id, org_id, suppressed_by, reason, expires_at, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (sup_id, finding_id, org_id, suppressed_by, reason, expires_at, now),
                )
                updated = conn.execute(
                    "SELECT * FROM cloud_findings WHERE id=?", (finding_id,)
                ).fetchone()
        return self._row(updated)

    def assign_remediation(
        self,
        finding_id: str,
        org_id: str,
        assignee: str,
        due_date: str,
        notes: str = "",
    ) -> Dict[str, Any]:
        """Create a remediation tracking record for a finding."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT id FROM cloud_findings WHERE id=? AND org_id=?",
                    (finding_id, org_id),
                ).fetchone()
                if not row:
                    raise KeyError(f"finding {finding_id!r} not found")
                record: Dict[str, Any] = {
                    "id": str(uuid.uuid4()),
                    "finding_id": finding_id,
                    "org_id": org_id,
                    "assignee": assignee,
                    "due_date": due_date,
                    "notes": notes,
                    "status": "assigned",
                    "updated_at": now,
                    "created_at": now,
                }
                conn.execute(
                    """INSERT INTO remediation_tracking
                       (id, finding_id, org_id, assignee, due_date, notes,
                        status, updated_at, created_at)
                       VALUES (:id, :finding_id, :org_id, :assignee, :due_date, :notes,
                               :status, :updated_at, :created_at)""",
                    record,
                )
        return record

    def update_remediation(
        self,
        remediation_id: str,
        org_id: str,
        status: str,
        notes: str = "",
    ) -> Dict[str, Any]:
        """Update status and notes on a remediation tracking record."""
        if status not in VALID_REMEDIATION_STATUSES:
            raise ValueError(f"status must be one of {sorted(VALID_REMEDIATION_STATUSES)}")
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM remediation_tracking WHERE id=? AND org_id=?",
                    (remediation_id, org_id),
                ).fetchone()
                if not row:
                    raise KeyError(f"remediation {remediation_id!r} not found")
                conn.execute(
                    "UPDATE remediation_tracking SET status=?, notes=?, updated_at=? WHERE id=? AND org_id=?",
                    (status, notes, now, remediation_id, org_id),
                )
                updated = conn.execute(
                    "SELECT * FROM remediation_tracking WHERE id=?", (remediation_id,)
                ).fetchone()
        return self._row(updated)

    def get_findings(
        self,
        org_id: str,
        provider: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return findings with optional filters."""
        query = "SELECT * FROM cloud_findings WHERE org_id=?"
        params: List[Any] = [org_id]
        if provider:
            query += " AND provider=?"
            params.append(provider)
        if severity:
            query += " AND severity=?"
            params.append(severity)
        if status:
            query += " AND status=?"
            params.append(status)
        query += " ORDER BY detected_at DESC"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def get_finding_summary(self, org_id: str) -> Dict[str, Any]:
        """Summary: total, by_provider, by_severity, by_status, critical_open,
        overdue_remediations."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                total = conn.execute(
                    "SELECT COUNT(*) AS c FROM cloud_findings WHERE org_id=?", (org_id,)
                ).fetchone()["c"]

                by_provider_rows = conn.execute(
                    "SELECT provider, COUNT(*) AS c FROM cloud_findings WHERE org_id=? GROUP BY provider",
                    (org_id,),
                ).fetchall()
                by_severity_rows = conn.execute(
                    "SELECT severity, COUNT(*) AS c FROM cloud_findings WHERE org_id=? GROUP BY severity",
                    (org_id,),
                ).fetchall()
                by_status_rows = conn.execute(
                    "SELECT status, COUNT(*) AS c FROM cloud_findings WHERE org_id=? GROUP BY status",
                    (org_id,),
                ).fetchall()

                critical_open = conn.execute(
                    "SELECT COUNT(*) AS c FROM cloud_findings WHERE org_id=? AND severity='critical' AND status='open'",
                    (org_id,),
                ).fetchone()["c"]

                # overdue: due_date < now AND remediation status != completed
                overdue = conn.execute(
                    """SELECT COUNT(*) AS c FROM remediation_tracking
                       WHERE org_id=? AND due_date != '' AND due_date < ?
                         AND status != 'completed'""",
                    (org_id, now),
                ).fetchone()["c"]

        return {
            "total": total,
            "by_provider": {r["provider"]: r["c"] for r in by_provider_rows},
            "by_severity": {r["severity"]: r["c"] for r in by_severity_rows},
            "by_status": {r["status"]: r["c"] for r in by_status_rows},
            "critical_open": critical_open,
            "overdue_remediations": overdue,
        }

    def get_top_affected_resources(
        self, org_id: str, limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Top resources by open finding count."""
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    """SELECT resource_id, resource_type, provider,
                              COUNT(*) AS finding_count
                       FROM cloud_findings
                       WHERE org_id=?
                       GROUP BY resource_id
                       ORDER BY finding_count DESC
                       LIMIT ?""",
                    (org_id, limit),
                ).fetchall()
        return [self._row(r) for r in rows]

    def export_findings_csv(
        self,
        org_id: str,
        provider: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> str:
        """Return findings as a CSV string with headers.

        Columns: id, org_id, provider, account_id, region, resource_type,
                 resource_id, finding_title, finding_type, severity, status,
                 cvss_score, remediation, detected_at, resolved_at
        """
        import csv
        import io

        findings = self.get_findings(
            org_id=org_id, provider=provider, severity=severity, status=status
        )

        fieldnames = [
            "id", "org_id", "provider", "account_id", "region", "resource_type",
            "resource_id", "finding_title", "finding_type", "severity", "status",
            "cvss_score", "remediation", "detected_at", "resolved_at",
        ]

        buf = io.StringIO()
        writer = csv.DictWriter(
            buf, fieldnames=fieldnames, extrasaction="ignore", lineterminator="\n"
        )
        writer.writeheader()
        for finding in findings:
            writer.writerow(finding)

        return buf.getvalue()

    def bulk_ingest(
        self, org_id: str, findings_list: List[Dict[str, Any]]
    ) -> Dict[str, int]:
        """Bulk ingest findings. Returns {ingested, skipped_duplicates}."""
        ingested = 0
        skipped_duplicates = 0
        for f in findings_list:
            existing_id = None
            # Capture the state before ingest to detect dedup
            provider = f.get("provider", "aws")
            account_id = f.get("account_id", "")
            resource_id = f.get("resource_id", "")
            finding_title = f.get("finding_title", "")

            with self._lock:
                with self._conn() as conn:
                    existing = conn.execute(
                        """SELECT id FROM cloud_findings
                           WHERE org_id=? AND provider=? AND account_id=?
                             AND resource_id=? AND finding_title=? AND status='open'""",
                        (org_id, provider, account_id, resource_id, finding_title),
                    ).fetchone()
                    existing_id = existing["id"] if existing else None

            if existing_id:
                skipped_duplicates += 1
                continue

            try:
                self.ingest_finding(
                    org_id=org_id,
                    provider=provider,
                    account_id=account_id,
                    region=f.get("region", ""),
                    resource_type=f.get("resource_type", ""),
                    resource_id=resource_id,
                    finding_title=finding_title,
                    finding_type=f.get("finding_type", "misconfiguration"),
                    severity=f.get("severity", "medium"),
                    cvss_score=float(f.get("cvss_score", 0.0)),
                    remediation=f.get("remediation", ""),
                )
                ingested += 1
            except (ValueError, KeyError) as exc:
                _logger.warning("bulk_ingest skip: %s", exc)
                skipped_duplicates += 1

        return {"ingested": ingested, "skipped_duplicates": skipped_duplicates}
