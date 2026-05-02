"""
⚠️  SIMULATED DATA — NOT FOR PRODUCTION OR DEMO USE  ⚠️

This engine generates randomized example findings for development/testing.
DO NOT use the output in customer-facing screens or pitches.

Real implementation tracking:
- DevSecOps pipeline metrics: requires CI integration via
  /api/v1/connectors/{github,gitlab,jenkins,bitbucket}/configure
- Cloud drift detection: requires CSPM connector via
  /api/v1/connectors/cspm-{aws,azure,gcp}/configure

Until real integrations are wired, these endpoints return a structured
warning header so callers can detect simulation mode.

Cloud Drift Detection Engine — ALDECI.

Detects configuration drift in cloud infrastructure by comparing IaC-defined
baselines (Terraform / CloudFormation / manual) against actual resource state.

Compliance: NIST SP 800-53 CM-2/CM-6, CIS Benchmark, SOC 2 CC7.1
"""

from __future__ import annotations

import json
import logging
import random
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
_logger.warning(
    "⚠️  %s loaded in SIMULATION mode — output is randomized; do not present in demos. "
    "Configure real connectors via /api/v1/connectors/",
    __name__,
)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "cloud_drift.db"
)

_VALID_RESOURCE_TYPES = {"ec2", "s3", "rds", "lambda", "sg", "vpc"}
_VALID_DRIFT_TYPES = {
    "config_changed", "resource_deleted", "new_resource",
    "tag_missing", "permission_widened",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_ENVIRONMENTS = {"prod", "staging", "dev"}
_VALID_SOURCES = {"terraform", "cloudformation", "manual"}
_VALID_DRIFT_STATUSES = {"open", "acknowledged", "remediated"}
_VALID_REMEDIATION_METHODS = {"manual", "automated"}


class CloudDriftDetectionEngine:
    """SQLite WAL-backed Cloud Drift Detection engine.

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
                CREATE TABLE IF NOT EXISTS drift_baselines (
                    baseline_id      TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    resource_id      TEXT NOT NULL,
                    resource_type    TEXT NOT NULL DEFAULT 'ec2',
                    resource_name    TEXT NOT NULL DEFAULT '',
                    expected_config  TEXT NOT NULL DEFAULT '{}',
                    source           TEXT NOT NULL DEFAULT 'terraform',
                    environment      TEXT NOT NULL DEFAULT 'prod',
                    created_at       TEXT NOT NULL,
                    updated_at       TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_drift_baseline_org
                    ON drift_baselines (org_id, environment);

                CREATE TABLE IF NOT EXISTS drift_events (
                    drift_id         TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    resource_id      TEXT NOT NULL,
                    drift_type       TEXT NOT NULL DEFAULT 'config_changed',
                    severity         TEXT NOT NULL DEFAULT 'medium',
                    expected_value   TEXT NOT NULL DEFAULT '',
                    actual_value     TEXT NOT NULL DEFAULT '',
                    detected_at      TEXT NOT NULL,
                    status           TEXT NOT NULL DEFAULT 'open',
                    acknowledged_by  TEXT,
                    acknowledged_at  TEXT,
                    ack_notes        TEXT,
                    remediated_by    TEXT,
                    remediated_at    TEXT,
                    remediation_method TEXT,
                    created_at       TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_drift_events_org
                    ON drift_events (org_id, status, severity);

                CREATE TABLE IF NOT EXISTS drift_scans (
                    scan_id          TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    environment      TEXT,
                    scanned          INTEGER NOT NULL DEFAULT 0,
                    drifts_found     INTEGER NOT NULL DEFAULT 0,
                    resolved_drifts  INTEGER NOT NULL DEFAULT 0,
                    scanned_at       TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_drift_scans_org
                    ON drift_scans (org_id, scanned_at);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # Baselines
    # ------------------------------------------------------------------

    def register_baseline(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new IaC baseline for a cloud resource."""
        baseline_id = str(uuid.uuid4())
        now = self._now()
        resource_type = data.get("resource_type", "ec2")
        if resource_type not in _VALID_RESOURCE_TYPES:
            resource_type = "ec2"
        source = data.get("source", "terraform")
        if source not in _VALID_SOURCES:
            source = "terraform"
        environment = data.get("environment", "prod")
        if environment not in _VALID_ENVIRONMENTS:
            environment = "prod"

        row = {
            "baseline_id": baseline_id,
            "org_id": org_id,
            "resource_id": data.get("resource_id", ""),
            "resource_type": resource_type,
            "resource_name": data.get("resource_name", ""),
            "expected_config": json.dumps(data.get("expected_config", {})),
            "source": source,
            "environment": environment,
            "created_at": now,
            "updated_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO drift_baselines VALUES
                       (:baseline_id,:org_id,:resource_id,:resource_type,:resource_name,
                        :expected_config,:source,:environment,:created_at,:updated_at)""",
                    row,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ASSET_DISCOVERED", {"entity_type": "cloud_drift", "org_id": org_id, "source_engine": "cloud_drift"})
            except Exception:
                pass

        return {**row, "expected_config": data.get("expected_config", {})}

    def list_baselines(
        self,
        org_id: str,
        environment: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List baselines, optionally filtered by environment."""
        clauses = ["org_id = ?"]
        params: List[Any] = [org_id]
        if environment:
            clauses.append("environment = ?")
            params.append(environment)
        sql = f"SELECT * FROM drift_baselines WHERE {' AND '.join(clauses)} ORDER BY created_at DESC"  # nosec B608
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(sql, params).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["expected_config"] = json.loads(d.get("expected_config", "{}"))
            result.append(d)
        return result

    # ------------------------------------------------------------------
    # Drift Events
    # ------------------------------------------------------------------

    def record_drift(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a detected drift event."""
        drift_id = str(uuid.uuid4())
        now = self._now()
        drift_type = data.get("drift_type", "config_changed")
        if drift_type not in _VALID_DRIFT_TYPES:
            drift_type = "config_changed"
        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            severity = "medium"

        row = {
            "drift_id": drift_id,
            "org_id": org_id,
            "resource_id": data.get("resource_id", ""),
            "drift_type": drift_type,
            "severity": severity,
            "expected_value": str(data.get("expected_value", "")),
            "actual_value": str(data.get("actual_value", "")),
            "detected_at": data.get("detected_at", now),
            "status": "open",
            "acknowledged_by": None,
            "acknowledged_at": None,
            "ack_notes": None,
            "remediated_by": None,
            "remediated_at": None,
            "remediation_method": None,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO drift_events VALUES
                       (:drift_id,:org_id,:resource_id,:drift_type,:severity,
                        :expected_value,:actual_value,:detected_at,:status,
                        :acknowledged_by,:acknowledged_at,:ack_notes,
                        :remediated_by,:remediated_at,:remediation_method,:created_at)""",
                    row,
                )
        return row

    def list_drifts(
        self,
        org_id: str,
        severity: Optional[str] = None,
        drift_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List drift events with optional filters."""
        clauses = ["org_id = ?"]
        params: List[Any] = [org_id]
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if drift_type:
            clauses.append("drift_type = ?")
            params.append(drift_type)
        if status:
            clauses.append("status = ?")
            params.append(status)
        sql = f"SELECT * FROM drift_events WHERE {' AND '.join(clauses)} ORDER BY detected_at DESC"  # nosec B608
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(sql, params).fetchall()
        return [dict(r) for r in rows]

    def acknowledge_drift(
        self,
        org_id: str,
        drift_id: str,
        acknowledged_by: str,
        notes: str = "",
    ) -> Dict[str, Any]:
        """Acknowledge a drift event."""
        now = self._now()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM drift_events WHERE drift_id = ? AND org_id = ?",
                    (drift_id, org_id),
                ).fetchone()
                if not row:
                    return {"error": "drift_id not found"}
                conn.execute(
                    """UPDATE drift_events
                       SET status = 'acknowledged',
                           acknowledged_by = ?,
                           acknowledged_at = ?,
                           ack_notes = ?
                       WHERE drift_id = ? AND org_id = ?""",
                    (acknowledged_by, now, notes, drift_id, org_id),
                )
                updated = conn.execute(
                    "SELECT * FROM drift_events WHERE drift_id = ?", (drift_id,)
                ).fetchone()
        return dict(updated)

    def remediate_drift(
        self,
        org_id: str,
        drift_id: str,
        remediated_by: str,
        method: str = "manual",
    ) -> Dict[str, Any]:
        """Mark a drift event as remediated."""
        if method not in _VALID_REMEDIATION_METHODS:
            method = "manual"
        now = self._now()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM drift_events WHERE drift_id = ? AND org_id = ?",
                    (drift_id, org_id),
                ).fetchone()
                if not row:
                    return {"error": "drift_id not found"}
                conn.execute(
                    """UPDATE drift_events
                       SET status = 'remediated',
                           remediated_by = ?,
                           remediated_at = ?,
                           remediation_method = ?
                       WHERE drift_id = ? AND org_id = ?""",
                    (remediated_by, now, method, drift_id, org_id),
                )
                updated = conn.execute(
                    "SELECT * FROM drift_events WHERE drift_id = ?", (drift_id,)
                ).fetchone()
        return dict(updated)

    # ------------------------------------------------------------------
    # Drift Scan
    # ------------------------------------------------------------------

    def run_drift_scan(
        self,
        org_id: str,
        environment: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Simulate a drift scan across all baselines.

        In production this would call cloud provider APIs. Here we simulate
        by randomly detecting minor drifts on a fraction of baselines and
        resolving previously open drifts that now match baseline.
        """
        baselines = self.list_baselines(org_id, environment=environment)
        scanned = len(baselines)
        new_drifts: List[Dict[str, Any]] = []

        # Simulate: ~20% of baselines have drift
        drift_severity_pool = ["low", "medium", "high", "critical"]
        drift_type_pool = list(_VALID_DRIFT_TYPES)

        for baseline in baselines:
            if random.random() < 0.2:
                severity = random.choice(drift_severity_pool)
                drift_type = random.choice(drift_type_pool)
                drift = self.record_drift(
                    org_id,
                    {
                        "resource_id": baseline["resource_id"],
                        "drift_type": drift_type,
                        "severity": severity,
                        "expected_value": json.dumps(baseline.get("expected_config", {})),
                        "actual_value": json.dumps({"drift": True, "field": "config"}),
                        "detected_at": self._now(),
                    },
                )
                new_drifts.append(drift)

        # Simulate resolution: randomly resolve 10% of open drifts
        open_drifts = self.list_drifts(org_id, status="open")
        resolved_count = 0
        for drift in open_drifts:
            if random.random() < 0.1:
                self.remediate_drift(org_id, drift["drift_id"], "scan-auto", "automated")
                resolved_count += 1

        # Record scan
        scan_id = str(uuid.uuid4())
        now = self._now()
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO drift_scans VALUES
                       (:scan_id,:org_id,:environment,:scanned,:drifts_found,
                        :resolved_drifts,:scanned_at)""",
                    {
                        "scan_id": scan_id,
                        "org_id": org_id,
                        "environment": environment,
                        "scanned": scanned,
                        "drifts_found": len(new_drifts),
                        "resolved_drifts": resolved_count,
                        "scanned_at": now,
                    },
                )

        return {
            "scan_id": scan_id,
            "scanned": scanned,
            "drifts_found": len(new_drifts),
            "new_drifts": new_drifts,
            "resolved_drifts": resolved_count,
        }

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_drift_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated drift statistics for an org."""
        with self._lock:
            with self._conn() as conn:
                total_baselines = conn.execute(
                    "SELECT COUNT(*) FROM drift_baselines WHERE org_id = ?", (org_id,)
                ).fetchone()[0]

                drifts_open = conn.execute(
                    "SELECT COUNT(*) FROM drift_events WHERE org_id = ? AND status = 'open'",
                    (org_id,),
                ).fetchone()[0]

                by_severity_rows = conn.execute(
                    """SELECT severity, COUNT(*) as cnt
                       FROM drift_events WHERE org_id = ? AND status = 'open'
                       GROUP BY severity""",
                    (org_id,),
                ).fetchall()

                by_type_rows = conn.execute(
                    """SELECT drift_type, COUNT(*) as cnt
                       FROM drift_events WHERE org_id = ? AND status = 'open'
                       GROUP BY drift_type""",
                    (org_id,),
                ).fetchall()

                remediated_count = conn.execute(
                    "SELECT COUNT(*) FROM drift_events WHERE org_id = ? AND status = 'remediated'",
                    (org_id,),
                ).fetchone()[0]

                conn.execute(
                    "SELECT COUNT(*) FROM drift_events WHERE org_id = ?", (org_id,)
                ).fetchone()[0]

                scans_last_7d = conn.execute(
                    """SELECT COUNT(*) FROM drift_scans
                       WHERE org_id = ?
                         AND scanned_at >= datetime('now', '-7 days')""",
                    (org_id,),
                ).fetchone()[0]

        drift_rate_pct = round(
            (drifts_open / total_baselines * 100) if total_baselines else 0.0, 1
        )

        return {
            "total_baselines": total_baselines,
            "drifts_open": drifts_open,
            "by_severity": {r["severity"]: r["cnt"] for r in by_severity_rows},
            "by_drift_type": {r["drift_type"]: r["cnt"] for r in by_type_rows},
            "remediated_count": remediated_count,
            "drift_rate_pct": drift_rate_pct,
            "scans_last_7d": scans_last_7d,
        }
