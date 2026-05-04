"""Vulnerability Scanner Management Engine — ALDECI.

Manages scanner inventory, scan schedules, results, and findings
across multiple vulnerability scanners (Nessus, Qualys, OpenVAS,
Trivy, Grype, Nuclei, Nikto).

Multi-tenant via org_id. SQLite WAL for durability.
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

try:
    from core.feed_correlator import enrich_finding as _enrich_finding
except Exception:  # noqa: BLE001
    _enrich_finding = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "vuln_scanner.db"
)

_SCANNER_TYPES = {"nessus", "qualys", "openvas", "trivy", "grype", "nuclei", "nikto"}
_LICENSE_TYPES = {"commercial", "community", "oss"}
_SCANNER_STATUSES = {"active", "inactive", "maintenance"}
_TARGET_TYPES = {"ip_range", "asset_group", "cidr", "hostname"}
_FREQUENCIES = {"daily", "weekly", "monthly", "on_demand"}
_SCAN_STATUSES = {"running", "completed", "failed"}
_FINDING_STATUSES = {"open", "in_progress", "patched", "accepted", "false_positive"}
_SEVERITIES = {"critical", "high", "medium", "low", "info"}


class VulnScannerEngine:
    """SQLite WAL-backed vulnerability scanner management engine.

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
                CREATE TABLE IF NOT EXISTS scanner_configs (
                    scanner_id      TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    name            TEXT NOT NULL,
                    scanner_type    TEXT NOT NULL,
                    version         TEXT NOT NULL DEFAULT '',
                    license_type    TEXT NOT NULL DEFAULT 'oss',
                    status          TEXT NOT NULL DEFAULT 'active',
                    last_sync       TEXT,
                    scan_count      INTEGER NOT NULL DEFAULT 0,
                    created_at      TEXT NOT NULL,
                    updated_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_sc_org
                    ON scanner_configs (org_id, status);

                CREATE TABLE IF NOT EXISTS scan_schedules (
                    schedule_id     TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    scanner_id      TEXT NOT NULL,
                    name            TEXT NOT NULL,
                    target_type     TEXT NOT NULL DEFAULT 'hostname',
                    targets         TEXT NOT NULL DEFAULT '[]',
                    frequency       TEXT NOT NULL DEFAULT 'on_demand',
                    cron_expression TEXT NOT NULL DEFAULT '',
                    enabled         INTEGER NOT NULL DEFAULT 1,
                    last_run        TEXT,
                    next_run        TEXT,
                    status          TEXT NOT NULL DEFAULT 'active',
                    created_at      TEXT NOT NULL,
                    updated_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ss_org
                    ON scan_schedules (org_id, enabled);

                CREATE TABLE IF NOT EXISTS scan_results (
                    result_id       TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    schedule_id     TEXT,
                    scanner_id      TEXT NOT NULL,
                    scan_start      TEXT NOT NULL,
                    scan_end        TEXT,
                    assets_scanned  INTEGER NOT NULL DEFAULT 0,
                    total_findings  INTEGER NOT NULL DEFAULT 0,
                    critical_count  INTEGER NOT NULL DEFAULT 0,
                    high_count      INTEGER NOT NULL DEFAULT 0,
                    medium_count    INTEGER NOT NULL DEFAULT 0,
                    low_count       INTEGER NOT NULL DEFAULT 0,
                    status          TEXT NOT NULL DEFAULT 'running',
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_sr_org
                    ON scan_results (org_id, status);

                CREATE TABLE IF NOT EXISTS vuln_findings (
                    finding_id      TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    result_id       TEXT NOT NULL,
                    asset_ip        TEXT NOT NULL DEFAULT '',
                    asset_hostname  TEXT NOT NULL DEFAULT '',
                    vuln_name       TEXT NOT NULL,
                    cve_id          TEXT NOT NULL DEFAULT '',
                    cvss_score      REAL NOT NULL DEFAULT 0.0,
                    severity        TEXT NOT NULL DEFAULT 'medium',
                    plugin_id       TEXT NOT NULL DEFAULT '',
                    description     TEXT NOT NULL DEFAULT '',
                    solution        TEXT NOT NULL DEFAULT '',
                    status          TEXT NOT NULL DEFAULT 'open',
                    created_at      TEXT NOT NULL,
                    updated_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_vf_org
                    ON vuln_findings (org_id, severity, status);

                CREATE INDEX IF NOT EXISTS idx_vf_result
                    ON vuln_findings (result_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # Scanners
    # ------------------------------------------------------------------

    def add_scanner(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new scanner. Returns the created scanner record."""
        scanner_id = str(uuid.uuid4())
        now = self._now()
        scanner_type = data.get("scanner_type", "nessus")
        if scanner_type not in _SCANNER_TYPES:
            scanner_type = "nessus"
        license_type = data.get("license_type", "oss")
        if license_type not in _LICENSE_TYPES:
            license_type = "oss"
        status = data.get("status", "active")
        if status not in _SCANNER_STATUSES:
            status = "active"

        record = {
            "scanner_id": scanner_id,
            "org_id": org_id,
            "name": data.get("name", ""),
            "scanner_type": scanner_type,
            "version": data.get("version", ""),
            "license_type": license_type,
            "status": status,
            "last_sync": data.get("last_sync"),
            "scan_count": int(data.get("scan_count", 0)),
            "created_at": now,
            "updated_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO scanner_configs
                        (scanner_id, org_id, name, scanner_type, version, license_type,
                         status, last_sync, scan_count, created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        record["scanner_id"], record["org_id"], record["name"],
                        record["scanner_type"], record["version"], record["license_type"],
                        record["status"], record["last_sync"], record["scan_count"],
                        record["created_at"], record["updated_at"],
                    ),
                )
        _logger.info("Added scanner %s (org=%s, type=%s)", scanner_id, org_id, scanner_type)
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("FINDING_CREATED", {"entity_type": "vuln_scanner", "org_id": org_id, "source_engine": "vuln_scanner"})
            except Exception:
                pass

        return record

    def list_scanners(self, org_id: str) -> List[Dict[str, Any]]:
        """List all scanners for an org."""
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM scanner_configs WHERE org_id=? ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Schedules
    # ------------------------------------------------------------------

    def create_schedule(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a scan schedule. Returns the created schedule record."""
        schedule_id = str(uuid.uuid4())
        now = self._now()
        target_type = data.get("target_type", "hostname")
        if target_type not in _TARGET_TYPES:
            target_type = "hostname"
        frequency = data.get("frequency", "on_demand")
        if frequency not in _FREQUENCIES:
            frequency = "on_demand"

        targets = data.get("targets", [])
        if isinstance(targets, list):
            targets_json = json.dumps(targets)
        else:
            targets_json = str(targets)

        record = {
            "schedule_id": schedule_id,
            "org_id": org_id,
            "scanner_id": data.get("scanner_id", ""),
            "name": data.get("name", ""),
            "target_type": target_type,
            "targets": targets_json,
            "frequency": frequency,
            "cron_expression": data.get("cron_expression", ""),
            "enabled": 1 if data.get("enabled", True) else 0,
            "last_run": data.get("last_run"),
            "next_run": data.get("next_run"),
            "status": data.get("status", "active"),
            "created_at": now,
            "updated_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO scan_schedules
                        (schedule_id, org_id, scanner_id, name, target_type, targets,
                         frequency, cron_expression, enabled, last_run, next_run,
                         status, created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        record["schedule_id"], record["org_id"], record["scanner_id"],
                        record["name"], record["target_type"], record["targets"],
                        record["frequency"], record["cron_expression"], record["enabled"],
                        record["last_run"], record["next_run"], record["status"],
                        record["created_at"], record["updated_at"],
                    ),
                )
        out = dict(record)
        out["targets"] = json.loads(targets_json)
        out["enabled"] = bool(out["enabled"])
        return out

    def list_schedules(
        self, org_id: str, enabled: Optional[bool] = None
    ) -> List[Dict[str, Any]]:
        """List scan schedules for an org, optionally filtered by enabled flag."""
        if enabled is None:
            query = "SELECT * FROM scan_schedules WHERE org_id=? ORDER BY created_at DESC"
            params: list = [org_id]
        else:
            query = "SELECT * FROM scan_schedules WHERE org_id=? AND enabled=? ORDER BY created_at DESC"
            params = [org_id, 1 if enabled else 0]

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()

        result = []
        for r in rows:
            d = self._row(r)
            d["targets"] = json.loads(d.get("targets") or "[]")
            d["enabled"] = bool(d["enabled"])
            result.append(d)
        return result

    # ------------------------------------------------------------------
    # Scan Results
    # ------------------------------------------------------------------

    def create_scan_result(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a scan result. Returns the created result record."""
        result_id = str(uuid.uuid4())
        now = self._now()
        scan_status = data.get("status", "running")
        if scan_status not in _SCAN_STATUSES:
            scan_status = "running"

        record = {
            "result_id": result_id,
            "org_id": org_id,
            "schedule_id": data.get("schedule_id"),
            "scanner_id": data.get("scanner_id", ""),
            "scan_start": data.get("scan_start", now),
            "scan_end": data.get("scan_end"),
            "assets_scanned": int(data.get("assets_scanned", 0)),
            "total_findings": int(data.get("total_findings", 0)),
            "critical_count": int(data.get("critical_count", 0)),
            "high_count": int(data.get("high_count", 0)),
            "medium_count": int(data.get("medium_count", 0)),
            "low_count": int(data.get("low_count", 0)),
            "status": scan_status,
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO scan_results
                        (result_id, org_id, schedule_id, scanner_id, scan_start, scan_end,
                         assets_scanned, total_findings, critical_count, high_count,
                         medium_count, low_count, status, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        record["result_id"], record["org_id"], record["schedule_id"],
                        record["scanner_id"], record["scan_start"], record["scan_end"],
                        record["assets_scanned"], record["total_findings"],
                        record["critical_count"], record["high_count"],
                        record["medium_count"], record["low_count"],
                        record["status"], record["created_at"],
                    ),
                )
        return record

    def list_scan_results(
        self, org_id: str, schedule_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List scan results for an org, optionally filtered by schedule."""
        if schedule_id:
            query = (
                "SELECT * FROM scan_results WHERE org_id=? AND schedule_id=? "
                "ORDER BY created_at DESC"
            )
            params: list = [org_id, schedule_id]
        else:
            query = "SELECT * FROM scan_results WHERE org_id=? ORDER BY created_at DESC"
            params = [org_id]

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def create_finding(
        self, org_id: str, result_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Record a vulnerability finding. Returns the created finding record."""
        finding_id = str(uuid.uuid4())
        now = self._now()
        severity = data.get("severity", "medium")
        if severity not in _SEVERITIES:
            severity = "medium"
        finding_status = data.get("status", "open")
        if finding_status not in _FINDING_STATUSES:
            finding_status = "open"

        record = {
            "finding_id": finding_id,
            "org_id": org_id,
            "result_id": result_id,
            "asset_ip": data.get("asset_ip", ""),
            "asset_hostname": data.get("asset_hostname", ""),
            "vuln_name": data.get("vuln_name", ""),
            "cve_id": data.get("cve_id", ""),
            "cvss_score": float(data.get("cvss_score", 0.0)),
            "severity": severity,
            "plugin_id": data.get("plugin_id", ""),
            "description": data.get("description", ""),
            "solution": data.get("solution", ""),
            "status": finding_status,
            "created_at": now,
            "updated_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO vuln_findings
                        (finding_id, org_id, result_id, asset_ip, asset_hostname,
                         vuln_name, cve_id, cvss_score, severity, plugin_id,
                         description, solution, status, created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        record["finding_id"], record["org_id"], record["result_id"],
                        record["asset_ip"], record["asset_hostname"], record["vuln_name"],
                        record["cve_id"], record["cvss_score"], record["severity"],
                        record["plugin_id"], record["description"], record["solution"],
                        record["status"], record["created_at"], record["updated_at"],
                    ),
                )
        # Enrich with unified ALDECI feed-correlation score (non-blocking)
        if _enrich_finding is not None:
            _enrich_finding(record)
        return record

    def list_findings(
        self,
        org_id: str,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List vulnerability findings for an org with optional filters."""
        params: list = [org_id]
        clauses = ["org_id=?"]
        if severity:
            clauses.append("severity=?")
            params.append(severity)
        if status:
            clauses.append("status=?")
            params.append(status)
        where = " AND ".join(clauses)
        query = f"SELECT * FROM vuln_findings WHERE {where} ORDER BY cvss_score DESC, created_at DESC"  # nosec B608

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def update_finding_status(
        self, org_id: str, finding_id: str, status: str
    ) -> bool:
        """Update a finding's remediation status. Returns True if updated."""
        if status not in _FINDING_STATUSES:
            return False
        now = self._now()
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    "UPDATE vuln_findings SET status=?, updated_at=? WHERE finding_id=? AND org_id=?",
                    (status, now, finding_id, org_id),
                )
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_scanner_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated scanner statistics for an org."""
        with self._conn() as conn:
            total_scanners = conn.execute(
                "SELECT COUNT(*) FROM scanner_configs WHERE org_id=?", (org_id,)
            ).fetchone()[0]
            active_scanners = conn.execute(
                "SELECT COUNT(*) FROM scanner_configs WHERE org_id=? AND status='active'",
                (org_id,),
            ).fetchone()[0]
            total_schedules = conn.execute(
                "SELECT COUNT(*) FROM scan_schedules WHERE org_id=?", (org_id,)
            ).fetchone()[0]
            findings_open = conn.execute(
                "SELECT COUNT(*) FROM vuln_findings WHERE org_id=? AND status='open'",
                (org_id,),
            ).fetchone()[0]

            # by severity (open only)
            sev_rows = conn.execute(
                """
                SELECT severity, COUNT(*) as cnt
                FROM vuln_findings
                WHERE org_id=? AND status='open'
                GROUP BY severity
                """,
                (org_id,),
            ).fetchall()
            by_severity = {r["severity"]: r["cnt"] for r in sev_rows}

            # assets covered (distinct IPs)
            assets_row = conn.execute(
                "SELECT COUNT(DISTINCT asset_ip) FROM vuln_findings WHERE org_id=? AND asset_ip != ''",
                (org_id,),
            ).fetchone()
            assets_covered = assets_row[0] if assets_row else 0

            # last scan date
            last_scan_row = conn.execute(
                "SELECT MAX(scan_start) FROM scan_results WHERE org_id=?", (org_id,)
            ).fetchone()
            last_scan_date = last_scan_row[0] if last_scan_row else None

        return {
            "total_scanners": total_scanners,
            "active": active_scanners,
            "total_schedules": total_schedules,
            "findings_open": findings_open,
            "by_severity": by_severity,
            "assets_covered": assets_covered,
            "last_scan_date": last_scan_date,
        }
