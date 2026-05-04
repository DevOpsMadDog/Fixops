"""Prowler CSPM Scan Engine — async-queue model with SQLite persistence.

Complementary to the existing ProwlerEngine in prowler_engine.py:
- ProwlerEngine = full lifecycle scan/finding/compliance store (CIS-focused)
- ProwlerScanEngine = async-queued multi-framework scans + durable SQLite per scan_id

Endpoints exposed by prowler_router (prefix /api/v1/prowler):
  GET  /                          — capability summary
  GET  /providers                 — provider catalog with check counts
  GET  /compliance/frameworks     — supported compliance frameworks catalog
  POST /scan/queue                — queue a multi-framework scan
  GET  /scan/{scan_id}            — fetch a queued scan record

Storage: SQLite at data/security/prowler_scans.db
Schema:
    prowler_scans (
        scan_id PK, provider, region, compliance_frameworks_json, status,
        severity_counts_json, compliance_counts_json, findings_json,
        started_at, completed_at
    )

Falls back to record-only mode (status=unavailable) when the prowler binary
is absent so tests / dev installs can exercise the queue + SQLite roundtrip.
"""
from __future__ import annotations

import json
import logging
import shutil
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except ImportError:
    _get_tg_bus = None  # type: ignore

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DEFAULT_DB_DIR = _REPO_ROOT / "data" / "security"
_DEFAULT_DB_PATH = _DEFAULT_DB_DIR / "prowler_scans.db"

VALID_PROVIDERS = ("aws", "azure", "gcp", "kubernetes")
VALID_COMPLIANCE = (
    "cis",
    "pci-dss",
    "hipaa",
    "gdpr",
    "iso27001",
    "soc2",
    "nist-800-53",
    "fedramp",
    "aws-well-architected",
)
VALID_SEVERITIES = ("low", "medium", "high", "critical")
VALID_STATUSES = ("queued", "running", "completed", "failed", "unavailable")

COMPLIANCE_DESCRIPTIONS: Dict[str, str] = {
    "cis": "CIS Benchmarks — Center for Internet Security configuration baselines",
    "pci-dss": "PCI DSS — Payment Card Industry Data Security Standard",
    "hipaa": "HIPAA — Health Insurance Portability and Accountability Act",
    "gdpr": "GDPR — EU General Data Protection Regulation",
    "iso27001": "ISO/IEC 27001 — Information security management systems",
    "soc2": "SOC 2 — Trust Service Criteria for service organizations",
    "nist-800-53": "NIST SP 800-53 — Security and Privacy Controls",
    "fedramp": "FedRAMP — Federal Risk and Authorization Management Program",
    "aws-well-architected": "AWS Well-Architected Framework — security pillar",
}

# Approximate Prowler check counts per provider (public Prowler v3 numbers)
PROVIDER_CHECK_COUNTS: Dict[str, int] = {
    "aws": 327,
    "azure": 142,
    "gcp": 77,
    "kubernetes": 83,
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class ProwlerScanEngine:
    """Async-queue Prowler CSPM scan engine with SQLite persistence."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(_DEFAULT_DB_PATH)
        self._db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # DB
    # ------------------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS prowler_scans (
                    scan_id                     TEXT PRIMARY KEY,
                    provider                    TEXT NOT NULL,
                    region                      TEXT NOT NULL DEFAULT '',
                    compliance_frameworks_json  TEXT NOT NULL DEFAULT '[]',
                    services_json               TEXT NOT NULL DEFAULT '[]',
                    status                      TEXT NOT NULL DEFAULT 'queued',
                    severity_counts_json        TEXT NOT NULL DEFAULT '{}',
                    compliance_counts_json      TEXT NOT NULL DEFAULT '{}',
                    findings_json               TEXT NOT NULL DEFAULT '[]',
                    started_at                  TEXT,
                    completed_at                TEXT
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_prowler_scans_provider "
                "ON prowler_scans (provider)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_prowler_scans_status "
                "ON prowler_scans (status)"
            )

    # ------------------------------------------------------------------
    # Capability + catalog
    # ------------------------------------------------------------------

    def binary_present(self) -> bool:
        return shutil.which("prowler") is not None

    def scan_count(self) -> int:
        with self._lock, self._conn() as conn:
            row = conn.execute("SELECT COUNT(*) FROM prowler_scans").fetchone()
            return int(row[0])

    def capability_summary(self) -> Dict[str, Any]:
        count = self.scan_count()
        binary = self.binary_present()
        if not binary:
            status = "unavailable"
        elif count == 0:
            status = "empty"
        else:
            status = "ok"
        return {
            "service": "Prowler",
            "providers": list(VALID_PROVIDERS),
            "compliance_frameworks": list(VALID_COMPLIANCE),
            "severity_levels": list(VALID_SEVERITIES),
            "binary_present": binary,
            "scan_count": count,
            "status": status,
        }

    def providers_catalog(self) -> List[Dict[str, Any]]:
        return [
            {
                "provider": p,
                "check_count": PROVIDER_CHECK_COUNTS.get(p, 0),
                "compliance_frameworks": list(VALID_COMPLIANCE),
            }
            for p in VALID_PROVIDERS
        ]

    def compliance_catalog(self) -> List[Dict[str, Any]]:
        return [
            {"framework": fw, "description": COMPLIANCE_DESCRIPTIONS[fw]}
            for fw in VALID_COMPLIANCE
        ]

    # ------------------------------------------------------------------
    # Queue + fetch
    # ------------------------------------------------------------------

    def queue_scan(
        self,
        provider: str,
        region: str = "",
        compliance_frameworks: Optional[List[str]] = None,
        services: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        if provider not in VALID_PROVIDERS:
            raise ValueError(
                f"provider must be one of {list(VALID_PROVIDERS)}; got {provider!r}"
            )
        frameworks = list(compliance_frameworks or [])
        bad_fw = [f for f in frameworks if f not in VALID_COMPLIANCE]
        if bad_fw:
            raise ValueError(
                f"unknown compliance_frameworks: {bad_fw}; "
                f"allowed: {list(VALID_COMPLIANCE)}"
            )
        services = list(services or [])

        scan_id = f"prowler-{uuid.uuid4().hex[:12]}"
        now = _now_iso()
        # If the binary isn't present, we still record the request but mark it
        # unavailable so the caller knows real scanning won't happen.
        status = "queued" if self.binary_present() else "unavailable"

        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO prowler_scans (
                    scan_id, provider, region, compliance_frameworks_json,
                    services_json, status, severity_counts_json,
                    compliance_counts_json, findings_json, started_at, completed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_id,
                    provider,
                    region,
                    json.dumps(frameworks),
                    json.dumps(services),
                    status,
                    json.dumps({sev: 0 for sev in VALID_SEVERITIES}),
                    json.dumps({fw: {"passed": 0, "failed": 0} for fw in frameworks}),
                    json.dumps([]),
                    now,
                    None,
                ),
            )

        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit(
                        "scan.completed",
                        {
                            "entity_id": scan_id,
                            "type": "prowler_cspm_scan",
                            "severity": "unknown",
                            "source_engine": "prowler_scan",
                            "provider": provider,
                            "region": region,
                            "frameworks": frameworks,
                            "status": status,
                        },
                    )
            except Exception:
                pass
        return {
            "scan_id": scan_id,
            "provider": provider,
            "region": region,
            "queued_at": now,
            "status": status,
        }

    def get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        with self._lock, self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM prowler_scans WHERE scan_id=?", (scan_id,)
            ).fetchone()
        if row is None:
            return None
        d = dict(row)
        return {
            "scan_id": d["scan_id"],
            "provider": d["provider"],
            "region": d["region"],
            "status": d["status"],
            "compliance_frameworks": json.loads(d["compliance_frameworks_json"] or "[]"),
            "services": json.loads(d["services_json"] or "[]"),
            "severity_counts": json.loads(d["severity_counts_json"] or "{}"),
            "compliance_counts": {
                "by_framework": json.loads(d["compliance_counts_json"] or "{}")
            },
            "findings": json.loads(d["findings_json"] or "[]"),
            "started_at": d["started_at"],
            "completed_at": d["completed_at"],
        }

    def update_scan(
        self,
        scan_id: str,
        status: Optional[str] = None,
        severity_counts: Optional[Dict[str, int]] = None,
        compliance_counts: Optional[Dict[str, Dict[str, int]]] = None,
        findings: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        existing = self.get_scan(scan_id)
        if existing is None:
            raise KeyError(f"scan_id {scan_id!r} not found")
        if status and status not in VALID_STATUSES:
            raise ValueError(
                f"status must be one of {list(VALID_STATUSES)}; got {status!r}"
            )

        new_status = status or existing["status"]
        new_severity = severity_counts if severity_counts is not None else existing["severity_counts"]
        new_compliance = compliance_counts if compliance_counts is not None else existing["compliance_counts"]["by_framework"]
        new_findings = findings if findings is not None else existing["findings"]

        completed_at = existing["completed_at"]
        if new_status in ("completed", "failed") and completed_at is None:
            completed_at = _now_iso()

        with self._lock, self._conn() as conn:
            conn.execute(
                """
                UPDATE prowler_scans
                SET status=?, severity_counts_json=?, compliance_counts_json=?,
                    findings_json=?, completed_at=?
                WHERE scan_id=?
                """,
                (
                    new_status,
                    json.dumps(new_severity),
                    json.dumps(new_compliance),
                    json.dumps(new_findings),
                    completed_at,
                    scan_id,
                ),
            )
        return self.get_scan(scan_id)  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_singleton: Optional[ProwlerScanEngine] = None
_singleton_lock = threading.Lock()


def get_prowler_scan_engine(db_path: Optional[str] = None) -> ProwlerScanEngine:
    """Return the global ProwlerScanEngine singleton.

    When *db_path* is provided, returns a fresh non-singleton instance
    (used by tests for per-tmp_path isolation).
    """
    global _singleton
    if db_path is not None:
        return ProwlerScanEngine(db_path=db_path)
    with _singleton_lock:
        if _singleton is None:
            _singleton = ProwlerScanEngine()
        return _singleton
