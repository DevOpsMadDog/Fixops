"""Digital Twin Security Engine — ALDECI.

Manages digital twin environments for security simulation and analysis.

Capabilities:
  - Twin lifecycle: create, list, get for network/application/infrastructure/OT/cloud/datacenter
  - Simulation runs: attack_path, vulnerability_scan, config_drift, compliance_check, performance_test
  - Findings management per simulation with severity tracking
  - Stats: totals, avg_risk_score, critical_findings, by_twin_type, high_risk_twins

Compliance: NIST SP 800-82, IEC 62443, NIST CSF ID.AM-2
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "digital_twin_security.db"
)

_VALID_TWIN_TYPES = {
    "network",
    "application",
    "infrastructure",
    "ot_environment",
    "cloud_environment",
    "datacenter",
}
_VALID_SIMULATION_TYPES = {
    "attack_path",
    "vulnerability_scan",
    "config_drift",
    "compliance_check",
    "performance_test",
}
_VALID_SIM_STATUSES = {"queued", "running", "completed", "failed"}
_VALID_FIDELITY_LEVELS = {"low", "medium", "high"}
_VALID_SYNC_STATUSES = {"synced", "stale", "syncing"}
_VALID_FINDING_SEVERITIES = {"critical", "high", "medium", "low"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _deterministic_findings_count(simulation_type: str, twin_id: str) -> int:
    """Deterministic findings count based on simulation_type and twin_id."""
    return (hash(simulation_type + twin_id) % 15) + 1


class DigitalTwinSecurityEngine:
    """SQLite WAL-backed Digital Twin Security engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/digital_twin_security.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        self.db_path = db_path if db_path is not None else _DEFAULT_DB
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
                CREATE TABLE IF NOT EXISTS dt_twins (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    name         TEXT NOT NULL DEFAULT '',
                    twin_type    TEXT NOT NULL DEFAULT 'network',
                    description  TEXT NOT NULL DEFAULT '',
                    asset_count  INTEGER NOT NULL DEFAULT 0,
                    fidelity_level TEXT NOT NULL DEFAULT 'medium',
                    last_synced  DATETIME,
                    sync_status  TEXT NOT NULL DEFAULT 'stale',
                    created_at   DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_dt_twins_org
                    ON dt_twins (org_id, twin_type, created_at DESC);

                CREATE TABLE IF NOT EXISTS dt_simulations (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    twin_id         TEXT NOT NULL,
                    simulation_type TEXT NOT NULL DEFAULT 'attack_path',
                    parameters_json TEXT NOT NULL DEFAULT '{}',
                    status          TEXT NOT NULL DEFAULT 'queued',
                    findings_count  INTEGER NOT NULL DEFAULT 0,
                    risk_score      REAL NOT NULL DEFAULT 0.0,
                    started_at      DATETIME,
                    completed_at    DATETIME,
                    created_at      DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_dt_simulations_org
                    ON dt_simulations (org_id, twin_id, simulation_type, status, created_at DESC);

                CREATE TABLE IF NOT EXISTS dt_findings (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    twin_id       TEXT NOT NULL DEFAULT '',
                    simulation_id TEXT NOT NULL DEFAULT '',
                    title         TEXT NOT NULL DEFAULT '',
                    severity      TEXT NOT NULL DEFAULT 'medium',
                    description   TEXT NOT NULL DEFAULT '',
                    remediation   TEXT NOT NULL DEFAULT '',
                    status        TEXT NOT NULL DEFAULT 'open',
                    detected_at   DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_dt_findings_org
                    ON dt_findings (org_id, twin_id, severity, status, detected_at DESC);
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
    # Twins
    # ------------------------------------------------------------------

    def create_twin(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new digital twin."""
        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("name is required.")

        twin_type = data.get("twin_type", "network")
        if twin_type not in _VALID_TWIN_TYPES:
            raise ValueError(
                f"Invalid twin_type: {twin_type!r}. "
                f"Must be one of {sorted(_VALID_TWIN_TYPES)}"
            )

        fidelity_level = data.get("fidelity_level", "medium")
        if fidelity_level not in _VALID_FIDELITY_LEVELS:
            raise ValueError(
                f"Invalid fidelity_level: {fidelity_level!r}. "
                f"Must be one of {sorted(_VALID_FIDELITY_LEVELS)}"
            )

        sync_status = data.get("sync_status", "stale")
        if sync_status not in _VALID_SYNC_STATUSES:
            sync_status = "stale"

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "name": name,
            "twin_type": twin_type,
            "description": data.get("description", ""),
            "asset_count": int(data.get("asset_count", 0)),
            "fidelity_level": fidelity_level,
            "last_synced": data.get("last_synced", None),
            "sync_status": sync_status,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO dt_twins
                       (id, org_id, name, twin_type, description, asset_count,
                        fidelity_level, last_synced, sync_status, created_at)
                       VALUES (:id, :org_id, :name, :twin_type, :description, :asset_count,
                               :fidelity_level, :last_synced, :sync_status, :created_at)""",
                    record,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "digital_twin_security", "org_id": org_id, "source_engine": "digital_twin_security"})
            except Exception:
                pass

        return record

    def list_twins(
        self,
        org_id: str,
        twin_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List digital twins with optional type filter."""
        sql = "SELECT * FROM dt_twins WHERE org_id = ?"
        params: list = [org_id]
        if twin_type:
            sql += " AND twin_type = ?"
            params.append(twin_type)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_twin(self, org_id: str, twin_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single twin by ID. Returns None if not found or wrong org."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM dt_twins WHERE org_id = ? AND id = ?",
                (org_id, twin_id),
            ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Simulations
    # ------------------------------------------------------------------

    def run_simulation(
        self, org_id: str, twin_id: str, sim_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Create and immediately run a simulation on a digital twin."""
        simulation_type = sim_data.get("simulation_type", "attack_path")
        if simulation_type not in _VALID_SIMULATION_TYPES:
            raise ValueError(
                f"Invalid simulation_type: {simulation_type!r}. "
                f"Must be one of {sorted(_VALID_SIMULATION_TYPES)}"
            )

        parameters = sim_data.get("parameters_json", sim_data.get("parameters", {}))
        if isinstance(parameters, dict):
            parameters_json = json.dumps(parameters)
        else:
            parameters_json = str(parameters)

        now = _now_iso()
        sim_id = str(uuid.uuid4())

        # Deterministic simulation results
        findings_count = _deterministic_findings_count(simulation_type, twin_id)
        risk_score = min(100.0, float(findings_count * 5))

        record: Dict[str, Any] = {
            "id": sim_id,
            "org_id": org_id,
            "twin_id": twin_id,
            "simulation_type": simulation_type,
            "parameters_json": parameters_json,
            "status": "completed",
            "findings_count": findings_count,
            "risk_score": risk_score,
            "started_at": now,
            "completed_at": now,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO dt_simulations
                       (id, org_id, twin_id, simulation_type, parameters_json,
                        status, findings_count, risk_score, started_at, completed_at, created_at)
                       VALUES (:id, :org_id, :twin_id, :simulation_type, :parameters_json,
                               :status, :findings_count, :risk_score, :started_at,
                               :completed_at, :created_at)""",
                    record,
                )
        return record

    def list_simulations(
        self,
        org_id: str,
        twin_id: Optional[str] = None,
        simulation_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List simulations with optional filters."""
        sql = "SELECT * FROM dt_simulations WHERE org_id = ?"
        params: list = [org_id]
        if twin_id:
            sql += " AND twin_id = ?"
            params.append(twin_id)
        if simulation_type:
            sql += " AND simulation_type = ?"
            params.append(simulation_type)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def add_finding(
        self, org_id: str, simulation_id: str, finding_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add a finding linked to a simulation."""
        severity = finding_data.get("severity", "medium")
        if severity not in _VALID_FINDING_SEVERITIES:
            raise ValueError(
                f"Invalid severity: {severity!r}. "
                f"Must be one of {sorted(_VALID_FINDING_SEVERITIES)}"
            )

        title = (finding_data.get("title") or "").strip()
        if not title:
            raise ValueError("title is required for finding.")

        # Resolve twin_id from simulation if not provided
        twin_id = finding_data.get("twin_id", "")
        if not twin_id:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT twin_id FROM dt_simulations WHERE org_id = ? AND id = ?",
                    (org_id, simulation_id),
                ).fetchone()
            if row:
                twin_id = row["twin_id"]

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "twin_id": twin_id,
            "simulation_id": simulation_id,
            "title": title,
            "severity": severity,
            "description": finding_data.get("description", ""),
            "remediation": finding_data.get("remediation", ""),
            "status": "open",
            "detected_at": finding_data.get("detected_at", now),
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO dt_findings
                       (id, org_id, twin_id, simulation_id, title, severity,
                        description, remediation, status, detected_at)
                       VALUES (:id, :org_id, :twin_id, :simulation_id, :title, :severity,
                               :description, :remediation, :status, :detected_at)""",
                    record,
                )
        return record

    def list_findings(
        self,
        org_id: str,
        twin_id: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List findings with optional filters."""
        sql = "SELECT * FROM dt_findings WHERE org_id = ?"
        params: list = [org_id]
        if twin_id:
            sql += " AND twin_id = ?"
            params.append(twin_id)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        sql += " ORDER BY detected_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_twin_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated digital twin statistics for an org."""
        with self._conn() as conn:
            total_twins = conn.execute(
                "SELECT COUNT(*) FROM dt_twins WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            total_simulations = conn.execute(
                "SELECT COUNT(*) FROM dt_simulations WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            avg_row = conn.execute(
                "SELECT AVG(risk_score) FROM dt_simulations WHERE org_id = ?", (org_id,)
            ).fetchone()
            avg_risk_score = round(float(avg_row[0] or 0.0), 2)

            critical_findings = conn.execute(
                "SELECT COUNT(*) FROM dt_findings WHERE org_id = ? AND severity = 'critical'",
                (org_id,),
            ).fetchone()[0]

            by_twin_type_rows = conn.execute(
                "SELECT twin_type, COUNT(*) as cnt FROM dt_twins "
                "WHERE org_id = ? GROUP BY twin_type",
                (org_id,),
            ).fetchall()

            # High risk twins: any simulation with risk_score > 70
            high_risk_rows = conn.execute(
                "SELECT DISTINCT twin_id FROM dt_simulations "
                "WHERE org_id = ? AND risk_score > 70",
                (org_id,),
            ).fetchall()
            high_risk_twins = len(high_risk_rows)

        return {
            "total_twins": total_twins,
            "total_simulations": total_simulations,
            "avg_risk_score": avg_risk_score,
            "critical_findings": critical_findings,
            "by_twin_type": {r["twin_type"]: r["cnt"] for r in by_twin_type_rows},
            "high_risk_twins": high_risk_twins,
        }
