"""
Automated Evidence Collection for ALDECI compliance workflows.

Pulls REAL evidence from ALDECI's own systems: audit logs, scan results,
config snapshots, access matrices, encryption status, backup records, and
incident reports.  Evidence is SQLite-backed, hash-verified, and mapped to
SOC2 / PCI-DSS / HIPAA controls.
"""
from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class EvidenceSource(str, Enum):
    API_LOGS = "api_logs"
    AUDIT_TRAIL = "audit_trail"
    SCAN_RESULTS = "scan_results"
    CONFIG_SNAPSHOTS = "config_snapshots"
    ACCESS_REVIEWS = "access_reviews"
    ENCRYPTION_STATUS = "encryption_status"
    BACKUP_RECORDS = "backup_records"
    INCIDENT_REPORTS = "incident_reports"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class AutoEvidence(BaseModel):
    """A single automatically-collected compliance evidence artifact."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    source: EvidenceSource
    control_id: str
    framework: str
    content_hash: str
    collected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    verified: bool = False
    org_id: str
    # Human-readable summary of what was collected
    summary: str = ""
    # Raw payload stored as JSON string
    raw_content: str = "{}"


class EvidenceCoverage(BaseModel):
    """Coverage report: which controls have fresh evidence."""

    org_id: str
    framework: str
    total_controls: int
    covered_controls: int
    coverage_pct: float
    fresh_controls: List[str]
    stale_controls: List[str]
    missing_controls: List[str]
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ---------------------------------------------------------------------------
# Framework → control → source mapping
# ---------------------------------------------------------------------------

# Maps (framework, control_id) → list of EvidenceSource
FRAMEWORK_CONTROL_MAP: Dict[str, Dict[str, List[EvidenceSource]]] = {
    "SOC2": {
        "CC6.1": [EvidenceSource.ACCESS_REVIEWS, EvidenceSource.AUDIT_TRAIL],
        "CC6.2": [EvidenceSource.ACCESS_REVIEWS, EvidenceSource.AUDIT_TRAIL],
        "CC6.3": [EvidenceSource.ACCESS_REVIEWS, EvidenceSource.CONFIG_SNAPSHOTS],
        "CC7.1": [EvidenceSource.CONFIG_SNAPSHOTS, EvidenceSource.SCAN_RESULTS],
        "CC7.2": [EvidenceSource.SCAN_RESULTS, EvidenceSource.AUDIT_TRAIL],
        "CC7.3": [EvidenceSource.INCIDENT_REPORTS, EvidenceSource.AUDIT_TRAIL],
        "CC8.1": [EvidenceSource.AUDIT_TRAIL, EvidenceSource.CONFIG_SNAPSHOTS],
        "A1.2": [EvidenceSource.BACKUP_RECORDS, EvidenceSource.CONFIG_SNAPSHOTS],
        "CC9.1": [EvidenceSource.ENCRYPTION_STATUS, EvidenceSource.CONFIG_SNAPSHOTS],
        "PI1.1": [EvidenceSource.API_LOGS, EvidenceSource.AUDIT_TRAIL],
    },
    "PCI": {
        "1.1": [EvidenceSource.CONFIG_SNAPSHOTS, EvidenceSource.SCAN_RESULTS],
        "2.1": [EvidenceSource.CONFIG_SNAPSHOTS, EvidenceSource.SCAN_RESULTS],
        "3.4": [EvidenceSource.ENCRYPTION_STATUS, EvidenceSource.CONFIG_SNAPSHOTS],
        "6.3": [EvidenceSource.SCAN_RESULTS, EvidenceSource.AUDIT_TRAIL],
        "7.1": [EvidenceSource.ACCESS_REVIEWS, EvidenceSource.AUDIT_TRAIL],
        "8.1": [EvidenceSource.ACCESS_REVIEWS, EvidenceSource.AUDIT_TRAIL],
        "10.1": [EvidenceSource.API_LOGS, EvidenceSource.AUDIT_TRAIL],
        "10.5": [EvidenceSource.AUDIT_TRAIL, EvidenceSource.CONFIG_SNAPSHOTS],
        "12.10": [EvidenceSource.INCIDENT_REPORTS, EvidenceSource.AUDIT_TRAIL],
        "9.5": [EvidenceSource.BACKUP_RECORDS, EvidenceSource.ENCRYPTION_STATUS],
    },
    "HIPAA": {
        "164.308(a)(1)": [EvidenceSource.INCIDENT_REPORTS, EvidenceSource.AUDIT_TRAIL],
        "164.308(a)(3)": [EvidenceSource.ACCESS_REVIEWS, EvidenceSource.AUDIT_TRAIL],
        "164.308(a)(5)": [EvidenceSource.AUDIT_TRAIL, EvidenceSource.CONFIG_SNAPSHOTS],
        "164.312(a)(1)": [EvidenceSource.ACCESS_REVIEWS, EvidenceSource.CONFIG_SNAPSHOTS],
        "164.312(b)": [EvidenceSource.API_LOGS, EvidenceSource.AUDIT_TRAIL],
        "164.312(c)(1)": [EvidenceSource.ENCRYPTION_STATUS, EvidenceSource.SCAN_RESULTS],
        "164.312(e)(1)": [EvidenceSource.ENCRYPTION_STATUS, EvidenceSource.CONFIG_SNAPSHOTS],
        "164.310(d)(1)": [EvidenceSource.BACKUP_RECORDS, EvidenceSource.AUDIT_TRAIL],
        "164.308(a)(7)": [EvidenceSource.BACKUP_RECORDS, EvidenceSource.INCIDENT_REPORTS],
        "164.314(a)(1)": [EvidenceSource.CONFIG_SNAPSHOTS, EvidenceSource.AUDIT_TRAIL],
    },
}

# Default TTL per source (days)
SOURCE_TTL_DAYS: Dict[EvidenceSource, int] = {
    EvidenceSource.API_LOGS: 1,
    EvidenceSource.AUDIT_TRAIL: 1,
    EvidenceSource.SCAN_RESULTS: 7,
    EvidenceSource.CONFIG_SNAPSHOTS: 7,
    EvidenceSource.ACCESS_REVIEWS: 30,
    EvidenceSource.ENCRYPTION_STATUS: 7,
    EvidenceSource.BACKUP_RECORDS: 1,
    EvidenceSource.INCIDENT_REPORTS: 90,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sha256(data: Any) -> str:
    raw = json.dumps(data, sort_keys=True, default=str).encode()
    return hashlib.sha256(raw).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# AutoEvidenceCollector
# ---------------------------------------------------------------------------


class AutoEvidenceCollector:
    """
    SQLite-backed automated evidence collector.

    Connects to ALDECI's existing audit_db, access_matrix, scan results,
    and app_config to pull real system state as compliance evidence.
    """

    def __init__(self, db_path: str = "data/auto_evidence.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()

    # ------------------------------------------------------------------
    # DB helpers
    # ------------------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_tables(self) -> None:
        conn = self._conn()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS auto_evidence (
                    id TEXT PRIMARY KEY,
                    source TEXT NOT NULL,
                    control_id TEXT NOT NULL,
                    framework TEXT NOT NULL,
                    content_hash TEXT NOT NULL,
                    collected_at TEXT NOT NULL,
                    expires_at TEXT,
                    verified INTEGER NOT NULL DEFAULT 0,
                    org_id TEXT NOT NULL,
                    summary TEXT NOT NULL DEFAULT '',
                    raw_content TEXT NOT NULL DEFAULT '{}'
                );

                CREATE INDEX IF NOT EXISTS idx_ae_org_framework
                    ON auto_evidence(org_id, framework);
                CREATE INDEX IF NOT EXISTS idx_ae_control
                    ON auto_evidence(org_id, framework, control_id);
                CREATE INDEX IF NOT EXISTS idx_ae_expires
                    ON auto_evidence(expires_at);
                """
            )
            conn.commit()
        finally:
            conn.close()

    def _save(self, ev: AutoEvidence) -> AutoEvidence:
        conn = self._conn()
        try:
            conn.execute(
                """
                INSERT OR REPLACE INTO auto_evidence
                    (id, source, control_id, framework, content_hash,
                     collected_at, expires_at, verified, org_id, summary, raw_content)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ev.id,
                    ev.source.value,
                    ev.control_id,
                    ev.framework,
                    ev.content_hash,
                    ev.collected_at.isoformat(),
                    ev.expires_at.isoformat() if ev.expires_at else None,
                    int(ev.verified),
                    ev.org_id,
                    ev.summary,
                    ev.raw_content,
                ),
            )
            conn.commit()
            return ev
        finally:
            conn.close()

    def _row_to_model(self, row: sqlite3.Row) -> AutoEvidence:
        return AutoEvidence(
            id=row["id"],
            source=EvidenceSource(row["source"]),
            control_id=row["control_id"],
            framework=row["framework"],
            content_hash=row["content_hash"],
            collected_at=datetime.fromisoformat(row["collected_at"]),
            expires_at=datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None,
            verified=bool(row["verified"]),
            org_id=row["org_id"],
            summary=row["summary"],
            raw_content=row["raw_content"],
        )

    def _get_by_id(self, evidence_id: str) -> Optional[AutoEvidence]:
        conn = self._conn()
        try:
            row = conn.execute(
                "SELECT * FROM auto_evidence WHERE id = ?", (evidence_id,)
            ).fetchone()
            return self._row_to_model(row) if row else None
        finally:
            conn.close()

    def _make_evidence(
        self,
        org_id: str,
        control_id: str,
        framework: str,
        source: EvidenceSource,
        payload: Any,
        summary: str,
    ) -> AutoEvidence:
        content_hash = _sha256(payload)
        ttl = SOURCE_TTL_DAYS.get(source, 7)
        expires_at = _now() + timedelta(days=ttl)
        ev = AutoEvidence(
            source=source,
            control_id=control_id,
            framework=framework,
            content_hash=content_hash,
            expires_at=expires_at,
            verified=False,
            org_id=org_id,
            summary=summary,
            raw_content=json.dumps(payload, default=str),
        )
        return self._save(ev)

    # ------------------------------------------------------------------
    # Source-specific collectors
    # ------------------------------------------------------------------

    def collect_from_audit_logs(
        self, org_id: str, control_id: str, framework: str = "SOC2", limit: int = 100
    ) -> AutoEvidence:
        """Pull recent audit log entries as evidence."""
        payload: Dict[str, Any] = {
            "collected_at": _now().isoformat(),
            "org_id": org_id,
            "control_id": control_id,
            "source": "audit_db",
            "entries": [],
        }
        try:
            audit_db_path = Path("data/audit.db")
            if audit_db_path.exists():
                conn = sqlite3.connect(str(audit_db_path))
                conn.row_factory = sqlite3.Row
                try:
                    rows = conn.execute(
                        "SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?",
                        (limit,),
                    ).fetchall()
                    payload["entries"] = [dict(r) for r in rows]
                    payload["entry_count"] = len(rows)
                finally:
                    conn.close()
            else:
                payload["entries"] = []
                payload["entry_count"] = 0
                payload["note"] = "audit.db not found — no historical logs yet"
        except Exception as exc:
            _logger.warning("audit_log collection error: %s", exc)
            payload["error"] = str(exc)

        summary = (
            f"Audit trail: {payload.get('entry_count', 0)} log entries "
            f"for org={org_id}, control={control_id}"
        )
        return self._make_evidence(
            org_id, control_id, framework, EvidenceSource.AUDIT_TRAIL, payload, summary
        )

    def collect_from_scan_results(
        self, org_id: str, control_id: str, framework: str = "SOC2"
    ) -> AutoEvidence:
        """Pull scan findings from ALDECI's findings store as evidence."""
        payload: Dict[str, Any] = {
            "collected_at": _now().isoformat(),
            "org_id": org_id,
            "control_id": control_id,
            "source": "scan_results",
            "findings": [],
        }
        try:
            findings_path = Path("data/findings.db")
            if findings_path.exists():
                conn = sqlite3.connect(str(findings_path))
                conn.row_factory = sqlite3.Row
                try:
                    # Try common findings table shapes
                    tables = [
                        r[0]
                        for r in conn.execute(
                            "SELECT name FROM sqlite_master WHERE type='table'"
                        ).fetchall()
                    ]
                    if "findings" in tables:
                        rows = conn.execute(
                            "SELECT * FROM findings ORDER BY rowid DESC LIMIT 200"
                        ).fetchall()
                        payload["findings"] = [dict(r) for r in rows]
                    payload["finding_count"] = len(payload["findings"])
                finally:
                    conn.close()
            else:
                payload["finding_count"] = 0
                payload["note"] = "findings.db not found"
        except Exception as exc:
            _logger.warning("scan_results collection error: %s", exc)
            payload["error"] = str(exc)

        summary = (
            f"Scan results: {payload.get('finding_count', 0)} findings "
            f"for org={org_id}, control={control_id}"
        )
        return self._make_evidence(
            org_id, control_id, framework, EvidenceSource.SCAN_RESULTS, payload, summary
        )

    def collect_from_config(
        self, org_id: str, control_id: str, framework: str = "SOC2"
    ) -> AutoEvidence:
        """Snapshot current ALDECI application config as evidence."""
        import os

        config_keys = [
            "FIXOPS_MODE",
            "FIXOPS_DISABLE_TELEMETRY",
            "FIXOPS_DISABLE_RATE_LIMIT",
            "FIXOPS_USE_COUNCIL",
        ]
        config_snapshot: Dict[str, Any] = {
            "collected_at": _now().isoformat(),
            "org_id": org_id,
            "control_id": control_id,
            "env_config": {k: os.environ.get(k, "<not-set>") for k in config_keys},
        }

        # Also snapshot app_config.db if it exists
        try:
            cfg_path = Path("data/app_config.db")
            if cfg_path.exists():
                conn = sqlite3.connect(str(cfg_path))
                conn.row_factory = sqlite3.Row
                try:
                    tables = [
                        r[0]
                        for r in conn.execute(
                            "SELECT name FROM sqlite_master WHERE type='table'"
                        ).fetchall()
                    ]
                    config_snapshot["db_tables"] = tables
                finally:
                    conn.close()
        except Exception as exc:
            _logger.warning("config snapshot error: %s", exc)
            config_snapshot["db_error"] = str(exc)

        summary = f"Config snapshot for org={org_id}, control={control_id}"
        return self._make_evidence(
            org_id,
            control_id,
            framework,
            EvidenceSource.CONFIG_SNAPSHOTS,
            config_snapshot,
            summary,
        )

    def collect_from_access_matrix(
        self, org_id: str, control_id: str, framework: str = "SOC2"
    ) -> AutoEvidence:
        """Pull access control state from ALDECI's access matrix."""
        payload: Dict[str, Any] = {
            "collected_at": _now().isoformat(),
            "org_id": org_id,
            "control_id": control_id,
            "source": "access_matrix",
            "rules": [],
        }
        try:
            matrix_path = Path("data/access_matrix.db")
            if matrix_path.exists():
                conn = sqlite3.connect(str(matrix_path))
                conn.row_factory = sqlite3.Row
                try:
                    tables = [
                        r[0]
                        for r in conn.execute(
                            "SELECT name FROM sqlite_master WHERE type='table'"
                        ).fetchall()
                    ]
                    if "access_rules" in tables:
                        rows = conn.execute("SELECT * FROM access_rules LIMIT 500").fetchall()
                        payload["rules"] = [dict(r) for r in rows]
                    payload["rule_count"] = len(payload["rules"])
                finally:
                    conn.close()
            else:
                payload["rule_count"] = 0
                payload["note"] = "access_matrix.db not found"
        except Exception as exc:
            _logger.warning("access_matrix collection error: %s", exc)
            payload["error"] = str(exc)

        summary = (
            f"Access review: {payload.get('rule_count', 0)} rules "
            f"for org={org_id}, control={control_id}"
        )
        return self._make_evidence(
            org_id, control_id, framework, EvidenceSource.ACCESS_REVIEWS, payload, summary
        )

    def collect_from_encryption_status(
        self, org_id: str, framework: str = "SOC2"
    ) -> AutoEvidence:
        """Pull FIPS encryption status as evidence."""
        import hashlib as _hl
        import ssl

        control_id = "CC9.1"  # default; caller can override via returned evidence

        ssl_info = ssl.OPENSSL_VERSION
        fips_mode = getattr(ssl, "FIPS_mode", None)
        fips_enabled = fips_mode() if callable(fips_mode) else False

        # Check what hash algorithms are available
        available_algos = sorted(_hl.algorithms_available)

        payload: Dict[str, Any] = {
            "collected_at": _now().isoformat(),
            "org_id": org_id,
            "ssl_version": ssl_info,
            "fips_mode_enabled": fips_enabled,
            "available_hash_algorithms": available_algos,
            "sha256_available": "sha256" in available_algos,
            "sha512_available": "sha512" in available_algos,
            "tls_default_context": str(ssl.create_default_context().protocol),
        }

        summary = (
            f"Encryption status: OpenSSL={ssl_info}, FIPS={fips_enabled}, org={org_id}"
        )
        return self._make_evidence(
            org_id, control_id, framework, EvidenceSource.ENCRYPTION_STATUS, payload, summary
        )

    def collect_from_backup_records(
        self, org_id: str, framework: str = "SOC2"
    ) -> AutoEvidence:
        """Pull backup history from ALDECI's backup store."""
        control_id = "A1.2"

        payload: Dict[str, Any] = {
            "collected_at": _now().isoformat(),
            "org_id": org_id,
            "source": "backup_db",
            "backups": [],
        }
        try:
            backup_path = Path("data/backup.db")
            if backup_path.exists():
                conn = sqlite3.connect(str(backup_path))
                conn.row_factory = sqlite3.Row
                try:
                    tables = [
                        r[0]
                        for r in conn.execute(
                            "SELECT name FROM sqlite_master WHERE type='table'"
                        ).fetchall()
                    ]
                    payload["tables_found"] = tables
                    for tbl in ("backups", "backup_records", "backup_history"):
                        if tbl in tables:
                            rows = conn.execute(
                                f"SELECT * FROM {tbl} ORDER BY rowid DESC LIMIT 100"  # nosec B608
                            ).fetchall()
                            payload["backups"] = [dict(r) for r in rows]
                            break
                finally:
                    conn.close()
            else:
                payload["note"] = "backup.db not found"

            # Also check data/ directory for .bak / .backup files
            data_dir = Path("data")
            if data_dir.exists():
                backup_files = list(data_dir.glob("*.bak")) + list(data_dir.glob("*.backup"))
                payload["backup_files"] = [
                    {
                        "name": f.name,
                        "size_bytes": f.stat().st_size,
                        "modified": datetime.fromtimestamp(
                            f.stat().st_mtime, tz=timezone.utc
                        ).isoformat(),
                    }
                    for f in backup_files
                ]
        except Exception as exc:
            _logger.warning("backup_records collection error: %s", exc)
            payload["error"] = str(exc)

        summary = f"Backup records: {len(payload.get('backups', []))} entries, org={org_id}"
        return self._make_evidence(
            org_id, control_id, framework, EvidenceSource.BACKUP_RECORDS, payload, summary
        )

    def collect_from_incidents(
        self, org_id: str, control_id: str, framework: str = "SOC2"
    ) -> AutoEvidence:
        """Pull incident reports from ALDECI's incident / finding stores."""
        payload: Dict[str, Any] = {
            "collected_at": _now().isoformat(),
            "org_id": org_id,
            "control_id": control_id,
            "source": "incidents",
            "incidents": [],
        }
        try:
            # Check multiple possible incident sources
            for candidate in ("data/incidents.db", "data/findings.db"):
                p = Path(candidate)
                if not p.exists():
                    continue
                conn = sqlite3.connect(str(p))
                conn.row_factory = sqlite3.Row
                try:
                    tables = [
                        r[0]
                        for r in conn.execute(
                            "SELECT name FROM sqlite_master WHERE type='table'"
                        ).fetchall()
                    ]
                    for tbl in ("incidents", "incident_reports", "findings"):
                        if tbl in tables:
                            rows = conn.execute(
                                f"SELECT * FROM {tbl} ORDER BY rowid DESC LIMIT 100"  # nosec B608
                            ).fetchall()
                            payload["incidents"] = [dict(r) for r in rows]
                            payload["source_table"] = f"{candidate}:{tbl}"
                            break
                finally:
                    conn.close()
                if payload["incidents"]:
                    break

            payload["incident_count"] = len(payload["incidents"])
        except Exception as exc:
            _logger.warning("incident_reports collection error: %s", exc)
            payload["error"] = str(exc)

        summary = (
            f"Incident reports: {payload.get('incident_count', 0)} records "
            f"for org={org_id}, control={control_id}"
        )
        return self._make_evidence(
            org_id, control_id, framework, EvidenceSource.INCIDENT_REPORTS, payload, summary
        )

    # ------------------------------------------------------------------
    # Bulk collection
    # ------------------------------------------------------------------

    def auto_collect_all(
        self, org_id: str, framework: str = "SOC2"
    ) -> List[AutoEvidence]:
        """
        Collect evidence for ALL controls in the given framework.

        Uses FRAMEWORK_CONTROL_MAP to determine which sources to pull for
        each control, then calls the appropriate collector methods.
        """
        framework_upper = framework.upper()
        control_map = FRAMEWORK_CONTROL_MAP.get(framework_upper, {})

        if not control_map:
            _logger.warning("Unknown framework %s — no controls mapped", framework)
            return []

        results: List[AutoEvidence] = []

        # Collect once-per-org sources that aren't control-specific
        encryption_done = False
        backup_done = False

        for control_id, sources in control_map.items():
            for source in sources:
                try:
                    ev: Optional[AutoEvidence] = None
                    if source == EvidenceSource.AUDIT_TRAIL:
                        ev = self.collect_from_audit_logs(org_id, control_id, framework_upper)
                    elif source == EvidenceSource.SCAN_RESULTS:
                        ev = self.collect_from_scan_results(org_id, control_id, framework_upper)
                    elif source == EvidenceSource.CONFIG_SNAPSHOTS:
                        ev = self.collect_from_config(org_id, control_id, framework_upper)
                    elif source == EvidenceSource.ACCESS_REVIEWS:
                        ev = self.collect_from_access_matrix(
                            org_id, control_id, framework_upper
                        )
                    elif source == EvidenceSource.ENCRYPTION_STATUS and not encryption_done:
                        ev = self.collect_from_encryption_status(org_id, framework_upper)
                        encryption_done = True
                    elif source == EvidenceSource.BACKUP_RECORDS and not backup_done:
                        ev = self.collect_from_backup_records(org_id, framework_upper)
                        backup_done = True
                    elif source == EvidenceSource.INCIDENT_REPORTS:
                        ev = self.collect_from_incidents(org_id, control_id, framework_upper)
                    elif source == EvidenceSource.API_LOGS:
                        ev = self.collect_from_audit_logs(
                            org_id, control_id, framework_upper
                        )  # API logs are in audit trail
                    if ev:
                        results.append(ev)
                except Exception as exc:
                    _logger.error(
                        "auto_collect_all error source=%s control=%s: %s",
                        source,
                        control_id,
                        exc,
                    )

        return results

    # ------------------------------------------------------------------
    # Verification
    # ------------------------------------------------------------------

    def verify_evidence(self, evidence_id: str) -> Tuple[bool, str]:
        """
        Hash-verify stored evidence.

        Re-hashes the raw_content and compares against stored content_hash.
        Returns (is_valid, message).
        """
        ev = self._get_by_id(evidence_id)
        if not ev:
            return False, f"Evidence {evidence_id} not found"

        try:
            payload = json.loads(ev.raw_content)
        except json.JSONDecodeError:
            return False, "raw_content is not valid JSON"

        computed = _sha256(payload)
        is_valid = computed == ev.content_hash

        # Persist verified flag
        if is_valid:
            conn = self._conn()
            try:
                conn.execute(
                    "UPDATE auto_evidence SET verified = 1 WHERE id = ?", (evidence_id,)
                )
                conn.commit()
            finally:
                conn.close()

        msg = "Hash verified OK" if is_valid else f"Hash mismatch: {computed} != {ev.content_hash}"
        return is_valid, msg

    # ------------------------------------------------------------------
    # Coverage report
    # ------------------------------------------------------------------

    def get_evidence_coverage(
        self, org_id: str, framework: str = "SOC2"
    ) -> EvidenceCoverage:
        """
        Return which controls have fresh (non-expired) evidence.
        """
        framework_upper = framework.upper()
        control_map = FRAMEWORK_CONTROL_MAP.get(framework_upper, {})
        all_controls = list(control_map.keys())
        now = _now()

        conn = self._conn()
        try:
            rows = conn.execute(
                """
                SELECT control_id, expires_at
                FROM auto_evidence
                WHERE org_id = ? AND framework = ?
                ORDER BY collected_at DESC
                """,
                (org_id, framework_upper),
            ).fetchall()
        finally:
            conn.close()

        # Build set of controls with at least one fresh record
        fresh: set[str] = set()
        stale: set[str] = set()
        for row in rows:
            cid = row["control_id"]
            exp = row["expires_at"]
            if exp is None:
                fresh.add(cid)
            else:
                exp_dt = datetime.fromisoformat(exp)
                if exp_dt > now:
                    fresh.add(cid)
                else:
                    stale.add(cid)

        # Controls in the framework that were never collected
        collected_any = fresh | stale
        missing = set(all_controls) - collected_any
        # Controls that are stale but not fresh
        stale_only = stale - fresh

        covered = len(fresh)
        total = len(all_controls) if all_controls else 1
        pct = round(covered / total * 100, 1)

        return EvidenceCoverage(
            org_id=org_id,
            framework=framework_upper,
            total_controls=len(all_controls),
            covered_controls=covered,
            coverage_pct=pct,
            fresh_controls=sorted(fresh),
            stale_controls=sorted(stale_only),
            missing_controls=sorted(missing),
        )

    # ------------------------------------------------------------------
    # List / get helpers (used by the router)
    # ------------------------------------------------------------------

    def list_evidence(
        self,
        org_id: str,
        framework: Optional[str] = None,
        control_id: Optional[str] = None,
        source: Optional[EvidenceSource] = None,
        limit: int = 100,
    ) -> List[AutoEvidence]:
        conditions = ["org_id = ?"]
        params: List[Any] = [org_id]
        if framework:
            conditions.append("framework = ?")
            params.append(framework.upper())
        if control_id:
            conditions.append("control_id = ?")
            params.append(control_id)
        if source:
            conditions.append("source = ?")
            params.append(source.value)
        where = " AND ".join(conditions)
        params.append(limit)
        conn = self._conn()
        try:
            rows = conn.execute(
                f"SELECT * FROM auto_evidence WHERE {where} ORDER BY collected_at DESC LIMIT ?",  # nosec B608
                params,
            ).fetchall()
            return [self._row_to_model(r) for r in rows]
        finally:
            conn.close()

    def get_evidence(self, evidence_id: str) -> Optional[AutoEvidence]:
        return self._get_by_id(evidence_id)


# ---------------------------------------------------------------------------
# Module-level singleton factory
# ---------------------------------------------------------------------------

_collector: Optional[AutoEvidenceCollector] = None


def get_collector() -> AutoEvidenceCollector:
    global _collector
    if _collector is None:
        _collector = AutoEvidenceCollector()
    return _collector
