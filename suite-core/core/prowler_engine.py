"""Prowler CSPM Engine — ALDECI. SQLite WAL + RLock + org_id isolation.

Agentless cloud security scanning via Prowler (AWS/Azure/GCP):
  - Scan lifecycle: pending → running → completed / failed
  - Finding persistence with dedup (same org+check+resource+status=open → skip)
  - CIS Benchmark compliance mapping (CIS AWS 1.5, Azure 2.0, GCP 1.3)
  - Summary stats, provider breakdown, compliance scores

Compliance: CSPM, CIS Benchmarks, NIST 800-53, PCI-DSS, HIPAA, SOC2
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "prowler_cspm.db"
)

VALID_PROVIDERS = frozenset({"aws", "azure", "gcp"})
VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "informational"})
VALID_SCAN_STATUSES = frozenset({"pending", "running", "completed", "failed"})
VALID_FINDING_STATUSES = frozenset({"open", "resolved", "suppressed"})

CIS_BENCHMARKS = {
    "aws": "CIS Amazon Web Services Foundations Benchmark v1.5.0",
    "azure": "CIS Microsoft Azure Foundations Benchmark v2.0.0",
    "gcp": "CIS Google Cloud Platform Foundation Benchmark v1.3.0",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ProwlerEngine:
    """SQLite WAL-backed Prowler CSPM scan engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/prowler_cspm.db
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
                CREATE TABLE IF NOT EXISTS prowler_scans (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    provider        TEXT NOT NULL DEFAULT 'aws',
                    account_id      TEXT NOT NULL DEFAULT '',
                    regions         TEXT NOT NULL DEFAULT '',
                    status          TEXT NOT NULL DEFAULT 'pending',
                    checks_total    INTEGER NOT NULL DEFAULT 0,
                    checks_passed   INTEGER NOT NULL DEFAULT 0,
                    checks_failed   INTEGER NOT NULL DEFAULT 0,
                    findings_count  INTEGER NOT NULL DEFAULT 0,
                    critical_count  INTEGER NOT NULL DEFAULT 0,
                    high_count      INTEGER NOT NULL DEFAULT 0,
                    medium_count    INTEGER NOT NULL DEFAULT 0,
                    low_count       INTEGER NOT NULL DEFAULT 0,
                    started_at      TEXT,
                    completed_at    TEXT,
                    error_message   TEXT NOT NULL DEFAULT '',
                    prowler_version TEXT NOT NULL DEFAULT '',
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ps_org_status
                    ON prowler_scans (org_id, status);

                CREATE INDEX IF NOT EXISTS idx_ps_org_provider
                    ON prowler_scans (org_id, provider);

                CREATE TABLE IF NOT EXISTS prowler_findings (
                    id              TEXT PRIMARY KEY,
                    scan_id         TEXT NOT NULL,
                    org_id          TEXT NOT NULL,
                    provider        TEXT NOT NULL DEFAULT 'aws',
                    account_id      TEXT NOT NULL DEFAULT '',
                    region          TEXT NOT NULL DEFAULT '',
                    service         TEXT NOT NULL DEFAULT '',
                    check_id        TEXT NOT NULL DEFAULT '',
                    check_title     TEXT NOT NULL DEFAULT '',
                    status          TEXT NOT NULL DEFAULT 'open',
                    severity        TEXT NOT NULL DEFAULT 'medium',
                    resource_type   TEXT NOT NULL DEFAULT '',
                    resource_id     TEXT NOT NULL DEFAULT '',
                    resource_arn    TEXT NOT NULL DEFAULT '',
                    status_extended TEXT NOT NULL DEFAULT '',
                    risk            TEXT NOT NULL DEFAULT '',
                    remediation     TEXT NOT NULL DEFAULT '',
                    remediation_url TEXT NOT NULL DEFAULT '',
                    cis_benchmark   TEXT NOT NULL DEFAULT '',
                    cis_section     TEXT NOT NULL DEFAULT '',
                    compliance_frameworks TEXT NOT NULL DEFAULT '[]',
                    raw_json        TEXT NOT NULL DEFAULT '{}',
                    detected_at     TEXT NOT NULL,
                    resolved_at     TEXT,
                    created_at      TEXT NOT NULL
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_pf_dedup
                    ON prowler_findings (org_id, check_id, resource_id)
                    WHERE status = 'open';

                CREATE INDEX IF NOT EXISTS idx_pf_scan
                    ON prowler_findings (scan_id);

                CREATE INDEX IF NOT EXISTS idx_pf_org_status
                    ON prowler_findings (org_id, status);

                CREATE INDEX IF NOT EXISTS idx_pf_org_severity
                    ON prowler_findings (org_id, severity);

                CREATE INDEX IF NOT EXISTS idx_pf_org_service
                    ON prowler_findings (org_id, service);

                CREATE TABLE IF NOT EXISTS prowler_compliance (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    scan_id         TEXT NOT NULL,
                    provider        TEXT NOT NULL DEFAULT 'aws',
                    framework       TEXT NOT NULL DEFAULT '',
                    section         TEXT NOT NULL DEFAULT '',
                    description     TEXT NOT NULL DEFAULT '',
                    total_checks    INTEGER NOT NULL DEFAULT 0,
                    passed_checks   INTEGER NOT NULL DEFAULT 0,
                    failed_checks   INTEGER NOT NULL DEFAULT 0,
                    compliance_pct  REAL NOT NULL DEFAULT 0.0,
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_pc_org_scan
                    ON prowler_compliance (org_id, scan_id);

                CREATE INDEX IF NOT EXISTS idx_pc_org_framework
                    ON prowler_compliance (org_id, framework);
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
    # TrustGraph event emission
    # ------------------------------------------------------------------

    def _emit(self, event_type: str, data: Dict[str, Any]) -> None:
        try:
            bus_fn = _get_tg_bus
            if bus_fn is not None:
                bus = bus_fn()
                if bus is not None:
                    bus.emit(event_type, data)
        except Exception:
            pass  # non-critical — TrustGraph wiring is best-effort

    # ------------------------------------------------------------------
    # Scans
    # ------------------------------------------------------------------

    def create_scan(
        self,
        org_id: str,
        provider: str,
        account_id: str = "",
        regions: str = "",
    ) -> Dict[str, Any]:
        """Create a new Prowler scan record."""
        if provider not in VALID_PROVIDERS:
            raise ValueError(f"provider must be one of {sorted(VALID_PROVIDERS)}")

        now = _now_iso()
        scan_id = str(uuid.uuid4())
        record: Dict[str, Any] = {
            "id": scan_id,
            "org_id": org_id,
            "provider": provider,
            "account_id": account_id,
            "regions": regions,
            "status": "pending",
            "checks_total": 0,
            "checks_passed": 0,
            "checks_failed": 0,
            "findings_count": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "started_at": None,
            "completed_at": None,
            "error_message": "",
            "prowler_version": "",
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO prowler_scans
                       (id, org_id, provider, account_id, regions, status,
                        checks_total, checks_passed, checks_failed, findings_count,
                        critical_count, high_count, medium_count, low_count,
                        started_at, completed_at, error_message, prowler_version, created_at)
                       VALUES (:id, :org_id, :provider, :account_id, :regions, :status,
                               :checks_total, :checks_passed, :checks_failed, :findings_count,
                               :critical_count, :high_count, :medium_count, :low_count,
                               :started_at, :completed_at, :error_message, :prowler_version, :created_at)""",
                    record,
                )
        _logger.info("prowler scan created id=%s org=%s provider=%s", scan_id, org_id, provider)
        self._emit("PROWLER_SCAN_CREATED", {"scan_id": scan_id, "org_id": org_id, "provider": provider})
        return record

    def start_scan(self, scan_id: str, org_id: str) -> Dict[str, Any]:
        """Mark scan as running."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM prowler_scans WHERE id=? AND org_id=?",
                    (scan_id, org_id),
                ).fetchone()
                if not row:
                    raise KeyError(f"scan {scan_id!r} not found")
                conn.execute(
                    "UPDATE prowler_scans SET status='running', started_at=? WHERE id=? AND org_id=?",
                    (now, scan_id, org_id),
                )
                updated = conn.execute(
                    "SELECT * FROM prowler_scans WHERE id=?", (scan_id,)
                ).fetchone()
        return self._row(updated)

    def complete_scan(
        self,
        scan_id: str,
        org_id: str,
        checks_total: int = 0,
        checks_passed: int = 0,
        checks_failed: int = 0,
        prowler_version: str = "",
    ) -> Dict[str, Any]:
        """Mark scan as completed and update check counts."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM prowler_scans WHERE id=? AND org_id=?",
                    (scan_id, org_id),
                ).fetchone()
                if not row:
                    raise KeyError(f"scan {scan_id!r} not found")

                # Count findings by severity
                severity_counts = {}
                for sev in ("critical", "high", "medium", "low"):
                    count = conn.execute(
                        "SELECT COUNT(*) FROM prowler_findings WHERE scan_id=? AND org_id=? AND severity=?",
                        (scan_id, org_id, sev),
                    ).fetchone()[0]
                    severity_counts[sev] = count

                findings_count = conn.execute(
                    "SELECT COUNT(*) FROM prowler_findings WHERE scan_id=? AND org_id=?",
                    (scan_id, org_id),
                ).fetchone()[0]

                conn.execute(
                    """UPDATE prowler_scans SET status='completed', completed_at=?,
                       checks_total=?, checks_passed=?, checks_failed=?,
                       findings_count=?, critical_count=?, high_count=?,
                       medium_count=?, low_count=?, prowler_version=?
                       WHERE id=? AND org_id=?""",
                    (
                        now, checks_total, checks_passed, checks_failed,
                        findings_count,
                        severity_counts.get("critical", 0),
                        severity_counts.get("high", 0),
                        severity_counts.get("medium", 0),
                        severity_counts.get("low", 0),
                        prowler_version,
                        scan_id, org_id,
                    ),
                )
                updated = conn.execute(
                    "SELECT * FROM prowler_scans WHERE id=?", (scan_id,)
                ).fetchone()
        result = self._row(updated)
        self._emit("PROWLER_SCAN_COMPLETED", {
            "scan_id": scan_id, "org_id": org_id,
            "findings_count": findings_count,
            "critical_count": severity_counts.get("critical", 0),
        })
        _logger.info("prowler scan completed id=%s findings=%d", scan_id, findings_count)
        return result

    def fail_scan(self, scan_id: str, org_id: str, error_message: str = "") -> Dict[str, Any]:
        """Mark scan as failed."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM prowler_scans WHERE id=? AND org_id=?",
                    (scan_id, org_id),
                ).fetchone()
                if not row:
                    raise KeyError(f"scan {scan_id!r} not found")
                conn.execute(
                    "UPDATE prowler_scans SET status='failed', completed_at=?, error_message=? WHERE id=? AND org_id=?",
                    (now, error_message, scan_id, org_id),
                )
                updated = conn.execute(
                    "SELECT * FROM prowler_scans WHERE id=?", (scan_id,)
                ).fetchone()
        return self._row(updated)

    def get_scan(self, scan_id: str, org_id: str) -> Dict[str, Any]:
        """Get a single scan by ID."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM prowler_scans WHERE id=? AND org_id=?",
                    (scan_id, org_id),
                ).fetchone()
                if not row:
                    raise KeyError(f"scan {scan_id!r} not found")
        return self._row(row)

    def list_scans(
        self,
        org_id: str,
        provider: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """List scans with optional filters."""
        clauses = ["org_id=?"]
        params: list = [org_id]
        if provider:
            clauses.append("provider=?")
            params.append(provider)
        if status:
            clauses.append("status=?")
            params.append(status)
        params.append(limit)
        where = " AND ".join(clauses)
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    f"SELECT * FROM prowler_scans WHERE {where} ORDER BY created_at DESC LIMIT ?",
                    params,
                ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def ingest_finding(
        self,
        scan_id: str,
        org_id: str,
        provider: str,
        account_id: str,
        region: str,
        service: str,
        check_id: str,
        check_title: str,
        severity: str,
        resource_type: str = "",
        resource_id: str = "",
        resource_arn: str = "",
        status_extended: str = "",
        risk: str = "",
        remediation: str = "",
        remediation_url: str = "",
        cis_section: str = "",
        compliance_frameworks: str = "[]",
        raw_json: str = "{}",
    ) -> Dict[str, Any]:
        """Ingest a Prowler finding. Deduplicates open findings by
        (org_id, check_id, resource_id)."""
        if severity not in VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(VALID_SEVERITIES)}")

        cis_benchmark = CIS_BENCHMARKS.get(provider, "")

        now = _now_iso()
        finding_id = str(uuid.uuid4())

        with self._lock:
            with self._conn() as conn:
                # Dedup check
                existing = conn.execute(
                    """SELECT * FROM prowler_findings
                       WHERE org_id=? AND check_id=? AND resource_id=? AND status='open'""",
                    (org_id, check_id, resource_id),
                ).fetchone()
                if existing:
                    result = self._row(existing)
                    result["_dedup"] = True
                    return result

                record: Dict[str, Any] = {
                    "id": finding_id,
                    "scan_id": scan_id,
                    "org_id": org_id,
                    "provider": provider,
                    "account_id": account_id,
                    "region": region,
                    "service": service,
                    "check_id": check_id,
                    "check_title": check_title,
                    "status": "open",
                    "severity": severity,
                    "resource_type": resource_type,
                    "resource_id": resource_id,
                    "resource_arn": resource_arn,
                    "status_extended": status_extended,
                    "risk": risk,
                    "remediation": remediation,
                    "remediation_url": remediation_url,
                    "cis_benchmark": cis_benchmark,
                    "cis_section": cis_section,
                    "compliance_frameworks": compliance_frameworks,
                    "raw_json": raw_json,
                    "detected_at": now,
                    "resolved_at": None,
                    "created_at": now,
                }
                conn.execute(
                    """INSERT INTO prowler_findings
                       (id, scan_id, org_id, provider, account_id, region, service,
                        check_id, check_title, status, severity, resource_type,
                        resource_id, resource_arn, status_extended, risk,
                        remediation, remediation_url, cis_benchmark, cis_section,
                        compliance_frameworks, raw_json, detected_at, resolved_at, created_at)
                       VALUES (:id, :scan_id, :org_id, :provider, :account_id, :region, :service,
                               :check_id, :check_title, :status, :severity, :resource_type,
                               :resource_id, :resource_arn, :status_extended, :risk,
                               :remediation, :remediation_url, :cis_benchmark, :cis_section,
                               :compliance_frameworks, :raw_json, :detected_at, :resolved_at, :created_at)""",
                    record,
                )
        self._emit("FINDING_CREATED", {
            "source": "prowler", "finding_id": finding_id, "org_id": org_id,
            "severity": severity, "check_id": check_id,
        })
        return record

    def resolve_finding(self, finding_id: str, org_id: str) -> Dict[str, Any]:
        """Mark a finding as resolved."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM prowler_findings WHERE id=? AND org_id=?",
                    (finding_id, org_id),
                ).fetchone()
                if not row:
                    raise KeyError(f"finding {finding_id!r} not found")
                conn.execute(
                    "UPDATE prowler_findings SET status='resolved', resolved_at=? WHERE id=? AND org_id=?",
                    (now, finding_id, org_id),
                )
                updated = conn.execute(
                    "SELECT * FROM prowler_findings WHERE id=?", (finding_id,)
                ).fetchone()
        return self._row(updated)

    def suppress_finding(self, finding_id: str, org_id: str) -> Dict[str, Any]:
        """Suppress a finding."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM prowler_findings WHERE id=? AND org_id=?",
                    (finding_id, org_id),
                ).fetchone()
                if not row:
                    raise KeyError(f"finding {finding_id!r} not found")
                conn.execute(
                    "UPDATE prowler_findings SET status='suppressed' WHERE id=? AND org_id=?",
                    (finding_id, org_id),
                )
                updated = conn.execute(
                    "SELECT * FROM prowler_findings WHERE id=?", (finding_id,)
                ).fetchone()
        return self._row(updated)

    def get_findings(
        self,
        org_id: str,
        scan_id: Optional[str] = None,
        provider: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        service: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """List findings with optional filters."""
        clauses = ["org_id=?"]
        params: list = [org_id]
        if scan_id:
            clauses.append("scan_id=?")
            params.append(scan_id)
        if provider:
            clauses.append("provider=?")
            params.append(provider)
        if severity:
            clauses.append("severity=?")
            params.append(severity)
        if status:
            clauses.append("status=?")
            params.append(status)
        if service:
            clauses.append("service=?")
            params.append(service)
        params.append(limit)
        where = " AND ".join(clauses)
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    f"SELECT * FROM prowler_findings WHERE {where} ORDER BY created_at DESC LIMIT ?",
                    params,
                ).fetchall()
        return [self._row(r) for r in rows]

    def get_finding(self, finding_id: str, org_id: str) -> Dict[str, Any]:
        """Get a single finding by ID."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM prowler_findings WHERE id=? AND org_id=?",
                    (finding_id, org_id),
                ).fetchone()
                if not row:
                    raise KeyError(f"finding {finding_id!r} not found")
        return self._row(row)

    # ------------------------------------------------------------------
    # Compliance
    # ------------------------------------------------------------------

    def ingest_compliance(
        self,
        scan_id: str,
        org_id: str,
        provider: str,
        framework: str,
        section: str,
        description: str = "",
        total_checks: int = 0,
        passed_checks: int = 0,
        failed_checks: int = 0,
    ) -> Dict[str, Any]:
        """Ingest a CIS compliance section result."""
        compliance_pct = (passed_checks / max(1, total_checks)) * 100.0

        now = _now_iso()
        comp_id = str(uuid.uuid4())
        record: Dict[str, Any] = {
            "id": comp_id,
            "org_id": org_id,
            "scan_id": scan_id,
            "provider": provider,
            "framework": framework,
            "section": section,
            "description": description,
            "total_checks": total_checks,
            "passed_checks": passed_checks,
            "failed_checks": failed_checks,
            "compliance_pct": round(compliance_pct, 2),
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO prowler_compliance
                       (id, org_id, scan_id, provider, framework, section, description,
                        total_checks, passed_checks, failed_checks, compliance_pct, created_at)
                       VALUES (:id, :org_id, :scan_id, :provider, :framework, :section, :description,
                               :total_checks, :passed_checks, :failed_checks, :compliance_pct, :created_at)""",
                    record,
                )
        return record

    def get_compliance(
        self,
        org_id: str,
        scan_id: Optional[str] = None,
        framework: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Get compliance results with optional filters."""
        clauses = ["org_id=?"]
        params: list = [org_id]
        if scan_id:
            clauses.append("scan_id=?")
            params.append(scan_id)
        if framework:
            clauses.append("framework=?")
            params.append(framework)
        where = " AND ".join(clauses)
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    f"SELECT * FROM prowler_compliance WHERE {where} ORDER BY section ASC",
                    params,
                ).fetchall()
        return [self._row(r) for r in rows]

    def get_compliance_summary(self, org_id: str, scan_id: Optional[str] = None) -> Dict[str, Any]:
        """Get aggregated compliance summary per framework."""
        clauses = ["org_id=?"]
        params: list = [org_id]
        if scan_id:
            clauses.append("scan_id=?")
            params.append(scan_id)
        where = " AND ".join(clauses)
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    f"""SELECT framework,
                               SUM(total_checks) as total_checks,
                               SUM(passed_checks) as passed_checks,
                               SUM(failed_checks) as failed_checks
                        FROM prowler_compliance WHERE {where}
                        GROUP BY framework""",
                    params,
                ).fetchall()
        result = {}
        for r in rows:
            d = dict(r)
            total = d["total_checks"] or 1
            d["compliance_pct"] = round((d["passed_checks"] / max(1, total)) * 100.0, 2)
            result[d["framework"]] = d
        return result

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_summary(self, org_id: str) -> Dict[str, Any]:
        """Get overall Prowler scan summary for an org."""
        with self._lock:
            with self._conn() as conn:
                total_scans = conn.execute(
                    "SELECT COUNT(*) FROM prowler_scans WHERE org_id=?", (org_id,)
                ).fetchone()[0]
                completed_scans = conn.execute(
                    "SELECT COUNT(*) FROM prowler_scans WHERE org_id=? AND status='completed'",
                    (org_id,),
                ).fetchone()[0]
                total_findings = conn.execute(
                    "SELECT COUNT(*) FROM prowler_findings WHERE org_id=?", (org_id,)
                ).fetchone()[0]
                open_findings = conn.execute(
                    "SELECT COUNT(*) FROM prowler_findings WHERE org_id=? AND status='open'",
                    (org_id,),
                ).fetchone()[0]

                by_severity = {}
                for sev in ("critical", "high", "medium", "low", "informational"):
                    count = conn.execute(
                        "SELECT COUNT(*) FROM prowler_findings WHERE org_id=? AND severity=? AND status='open'",
                        (org_id, sev),
                    ).fetchone()[0]
                    by_severity[sev] = count

                by_provider = {}
                for prov in ("aws", "azure", "gcp"):
                    count = conn.execute(
                        "SELECT COUNT(*) FROM prowler_findings WHERE org_id=? AND provider=? AND status='open'",
                        (org_id, prov),
                    ).fetchone()[0]
                    by_provider[prov] = count

                top_services = conn.execute(
                    """SELECT service, COUNT(*) as cnt
                       FROM prowler_findings WHERE org_id=? AND status='open'
                       GROUP BY service ORDER BY cnt DESC LIMIT 10""",
                    (org_id,),
                ).fetchall()

        return {
            "total_scans": total_scans,
            "completed_scans": completed_scans,
            "total_findings": total_findings,
            "open_findings": open_findings,
            "by_severity": by_severity,
            "by_provider": by_provider,
            "top_services": [{"service": r["service"], "count": r["cnt"]} for r in top_services],
        }

    def bulk_ingest_findings(
        self,
        scan_id: str,
        org_id: str,
        findings_list: List[Dict[str, Any]],
    ) -> Dict[str, int]:
        """Bulk ingest findings from a Prowler scan. Returns ingested/skipped counts."""
        ingested = 0
        skipped = 0
        for f in findings_list:
            try:
                result = self.ingest_finding(
                    scan_id=scan_id,
                    org_id=org_id,
                    provider=f.get("provider", "aws"),
                    account_id=f.get("account_id", ""),
                    region=f.get("region", ""),
                    service=f.get("service", ""),
                    check_id=f.get("check_id", ""),
                    check_title=f.get("check_title", ""),
                    severity=f.get("severity", "medium"),
                    resource_type=f.get("resource_type", ""),
                    resource_id=f.get("resource_id", ""),
                    resource_arn=f.get("resource_arn", ""),
                    status_extended=f.get("status_extended", ""),
                    risk=f.get("risk", ""),
                    remediation=f.get("remediation", ""),
                    remediation_url=f.get("remediation_url", ""),
                    cis_section=f.get("cis_section", ""),
                    compliance_frameworks=f.get("compliance_frameworks", "[]"),
                    raw_json=f.get("raw_json", "{}"),
                )
                if result.get("_dedup"):
                    skipped += 1
                else:
                    ingested += 1
            except (ValueError, KeyError):
                skipped += 1
        return {"ingested": ingested, "skipped_duplicates": skipped}
