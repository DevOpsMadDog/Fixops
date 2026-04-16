"""Threat Simulation Engine — ALDECI.

Full threat simulation lifecycle with scenario management and detection tracking.

Capabilities:
  - Scenario registry: create, list, get with org isolation
  - Simulation lifecycle: start → running → completed
  - Detection recording per simulation technique
  - Stats: avg detection rate and dwell time for completed simulations

Compliance: MITRE ATT&CK, NIST SP 800-53 CA-8 (Penetration Testing)
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

_DEFAULT_DB_DIR = str(
    Path(__file__).resolve().parents[2] / ".fixops_data"
)

_VALID_SCENARIO_TYPES = {
    "ransomware", "apt", "insider_threat", "supply_chain",
    "ddos", "data_exfiltration", "lateral_movement",
}
_VALID_DIFFICULTIES = {"easy", "medium", "hard", "expert"}
_VALID_SIM_STATUSES = {"running", "completed", "aborted"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ThreatSimulationEngine:
    """SQLite WAL-backed Threat Simulation engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/threat_simulation.db (shared, org-scoped by column)
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(Path(_DEFAULT_DB_DIR) / "threat_simulation.db")
        self._db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS scenarios (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    name              TEXT NOT NULL,
                    scenario_type     TEXT NOT NULL,
                    difficulty        TEXT NOT NULL DEFAULT 'medium',
                    description       TEXT NOT NULL DEFAULT '',
                    mitre_techniques  TEXT NOT NULL DEFAULT '[]',
                    status            TEXT NOT NULL DEFAULT 'draft',
                    created_at        TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_scenarios_org
                    ON scenarios (org_id, scenario_type, created_at DESC);

                CREATE TABLE IF NOT EXISTS simulations (
                    id                        TEXT PRIMARY KEY,
                    org_id                    TEXT NOT NULL,
                    scenario_id               TEXT NOT NULL,
                    initiated_by              TEXT NOT NULL,
                    target_systems            TEXT NOT NULL DEFAULT '[]',
                    status                    TEXT NOT NULL DEFAULT 'running',
                    total_techniques_executed INTEGER NOT NULL DEFAULT 0,
                    techniques_detected       INTEGER NOT NULL DEFAULT 0,
                    detection_rate            REAL NOT NULL DEFAULT 0.0,
                    dwell_time_seconds        INTEGER,
                    detections                TEXT NOT NULL DEFAULT '[]',
                    started_at                TEXT NOT NULL,
                    completed_at              TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_simulations_org
                    ON simulations (org_id, status, started_at DESC);

                CREATE INDEX IF NOT EXISTS idx_simulations_scenario
                    ON simulations (org_id, scenario_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    @staticmethod
    def _deserialize_sim(row: Dict[str, Any]) -> Dict[str, Any]:
        """Parse JSON fields in a simulation row."""
        for field in ("target_systems", "detections"):
            if isinstance(row.get(field), str):
                try:
                    row[field] = json.loads(row[field])
                except (json.JSONDecodeError, TypeError):
                    row[field] = []
        return row

    @staticmethod
    def _deserialize_scenario(row: Dict[str, Any]) -> Dict[str, Any]:
        """Parse JSON fields in a scenario row."""
        if isinstance(row.get("mitre_techniques"), str):
            try:
                row["mitre_techniques"] = json.loads(row["mitre_techniques"])
            except (json.JSONDecodeError, TypeError):
                row["mitre_techniques"] = []
        return row

    # ------------------------------------------------------------------
    # Scenarios
    # ------------------------------------------------------------------

    def create_scenario(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new threat simulation scenario."""
        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("name is required.")

        scenario_type = data.get("scenario_type", "")
        if scenario_type not in _VALID_SCENARIO_TYPES:
            raise ValueError(
                f"Invalid scenario_type: {scenario_type!r}. "
                f"Must be one of {sorted(_VALID_SCENARIO_TYPES)}"
            )

        difficulty = data.get("difficulty", "medium")
        if difficulty not in _VALID_DIFFICULTIES:
            raise ValueError(
                f"Invalid difficulty: {difficulty!r}. "
                f"Must be one of {sorted(_VALID_DIFFICULTIES)}"
            )

        mitre = data.get("mitre_techniques", [])
        if not isinstance(mitre, list):
            mitre = []

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "name": name,
            "scenario_type": scenario_type,
            "difficulty": difficulty,
            "description": data.get("description", ""),
            "mitre_techniques": json.dumps(mitre),
            "status": "draft",
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO scenarios
                       (id, org_id, name, scenario_type, difficulty, description,
                        mitre_techniques, status, created_at)
                       VALUES (:id, :org_id, :name, :scenario_type, :difficulty,
                               :description, :mitre_techniques, :status, :created_at)""",
                    record,
                )
        result = dict(record)
        result["mitre_techniques"] = mitre
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("THREAT_DETECTED", {"entity_type": "threat_simulation", "org_id": org_id, "source_engine": "threat_simulation"})
            except Exception:
                pass

        return result

    def list_scenarios(
        self,
        org_id: str,
        scenario_type: Optional[str] = None,
        difficulty: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List scenarios with optional filters."""
        sql = "SELECT * FROM scenarios WHERE org_id = ?"
        params: list = [org_id]
        if scenario_type:
            sql += " AND scenario_type = ?"
            params.append(scenario_type)
        if difficulty:
            sql += " AND difficulty = ?"
            params.append(difficulty)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._deserialize_scenario(self._row(r)) for r in rows]

    def get_scenario(self, org_id: str, scenario_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single scenario by ID. Returns None if not found."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM scenarios WHERE org_id = ? AND id = ?",
                (org_id, scenario_id),
            ).fetchone()
        if not row:
            return None
        return self._deserialize_scenario(self._row(row))

    # ------------------------------------------------------------------
    # Simulations
    # ------------------------------------------------------------------

    def start_simulation(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Start a new simulation run from a scenario."""
        scenario_id = (data.get("scenario_id") or "").strip()
        if not scenario_id:
            raise ValueError("scenario_id is required.")

        initiated_by = (data.get("initiated_by") or "").strip()
        if not initiated_by:
            raise ValueError("initiated_by is required.")

        target_systems = data.get("target_systems", [])
        if not isinstance(target_systems, list):
            target_systems = []

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "scenario_id": scenario_id,
            "initiated_by": initiated_by,
            "target_systems": json.dumps(target_systems),
            "status": "running",
            "total_techniques_executed": 0,
            "techniques_detected": 0,
            "detection_rate": 0.0,
            "dwell_time_seconds": None,
            "detections": json.dumps([]),
            "started_at": now,
            "completed_at": None,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO simulations
                       (id, org_id, scenario_id, initiated_by, target_systems, status,
                        total_techniques_executed, techniques_detected, detection_rate,
                        dwell_time_seconds, detections, started_at, completed_at)
                       VALUES (:id, :org_id, :scenario_id, :initiated_by, :target_systems,
                               :status, :total_techniques_executed, :techniques_detected,
                               :detection_rate, :dwell_time_seconds, :detections,
                               :started_at, :completed_at)""",
                    record,
                )
        result = dict(record)
        result["target_systems"] = target_systems
        result["detections"] = []
        return result

    def record_detection(
        self, org_id: str, sim_id: str, data: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Record a technique detection within a running simulation."""
        technique = (data.get("technique") or "").strip()
        if not technique:
            raise ValueError("technique is required.")
        detected_by = (data.get("detected_by") or "").strip()
        if not detected_by:
            raise ValueError("detected_by is required.")

        detection_time_seconds = data.get("detection_time_seconds", 0)
        true_positive = bool(data.get("true_positive", True))

        detection_entry = {
            "id": str(uuid.uuid4()),
            "technique": technique,
            "detected_by": detected_by,
            "detection_time_seconds": detection_time_seconds,
            "true_positive": true_positive,
            "recorded_at": _now_iso(),
        }

        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM simulations WHERE org_id = ? AND id = ?",
                    (org_id, sim_id),
                ).fetchone()
                if not row:
                    return None

                existing = json.loads(row["detections"] or "[]")
                existing.append(detection_entry)

                conn.execute(
                    "UPDATE simulations SET detections = ? WHERE org_id = ? AND id = ?",
                    (json.dumps(existing), org_id, sim_id),
                )
                updated = conn.execute(
                    "SELECT * FROM simulations WHERE org_id = ? AND id = ?",
                    (org_id, sim_id),
                ).fetchone()
        return self._deserialize_sim(self._row(updated)) if updated else None

    def complete_simulation(
        self, org_id: str, sim_id: str, data: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Mark a simulation as completed and compute detection metrics."""
        total_techniques_executed = int(data.get("total_techniques_executed", 0))
        techniques_detected = int(data.get("techniques_detected", 0))
        dwell_time_seconds = data.get("dwell_time_seconds")

        if total_techniques_executed > 0:
            detection_rate = round(
                techniques_detected / total_techniques_executed * 100, 2
            )
        else:
            detection_rate = 0.0

        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT id FROM simulations WHERE org_id = ? AND id = ?",
                    (org_id, sim_id),
                ).fetchone()
                if not row:
                    return None

                conn.execute(
                    """UPDATE simulations
                       SET status = 'completed',
                           completed_at = ?,
                           total_techniques_executed = ?,
                           techniques_detected = ?,
                           detection_rate = ?,
                           dwell_time_seconds = ?
                       WHERE org_id = ? AND id = ?""",
                    (
                        now,
                        total_techniques_executed,
                        techniques_detected,
                        detection_rate,
                        dwell_time_seconds,
                        org_id,
                        sim_id,
                    ),
                )
                updated = conn.execute(
                    "SELECT * FROM simulations WHERE org_id = ? AND id = ?",
                    (org_id, sim_id),
                ).fetchone()
        return self._deserialize_sim(self._row(updated)) if updated else None

    def list_simulations(
        self,
        org_id: str,
        status: Optional[str] = None,
        scenario_id: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List simulations with optional filters."""
        sql = "SELECT * FROM simulations WHERE org_id = ?"
        params: list = [org_id]
        if status:
            sql += " AND status = ?"
            params.append(status)
        if scenario_id:
            sql += " AND scenario_id = ?"
            params.append(scenario_id)
        sql += " ORDER BY started_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._deserialize_sim(self._row(r)) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_simulation_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated simulation statistics for an org."""
        with self._conn() as conn:
            total_scenarios = conn.execute(
                "SELECT COUNT(*) FROM scenarios WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            type_rows = conn.execute(
                "SELECT scenario_type, COUNT(*) as cnt FROM scenarios "
                "WHERE org_id = ? GROUP BY scenario_type",
                (org_id,),
            ).fetchall()
            by_type = {r["scenario_type"]: r["cnt"] for r in type_rows}

            total_simulations = conn.execute(
                "SELECT COUNT(*) FROM simulations WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            completed_simulations = conn.execute(
                "SELECT COUNT(*) FROM simulations WHERE org_id = ? AND status = 'completed'",
                (org_id,),
            ).fetchone()[0]

            # Avg detection rate for completed simulations only
            dr_row = conn.execute(
                "SELECT AVG(detection_rate) FROM simulations "
                "WHERE org_id = ? AND status = 'completed'",
                (org_id,),
            ).fetchone()[0]
            avg_detection_rate = round(dr_row, 2) if dr_row is not None else 0.0

            # Avg dwell time for completed simulations with non-null dwell
            dw_row = conn.execute(
                "SELECT AVG(dwell_time_seconds) FROM simulations "
                "WHERE org_id = ? AND status = 'completed' AND dwell_time_seconds IS NOT NULL",
                (org_id,),
            ).fetchone()[0]
            avg_dwell_time_seconds = round(dw_row, 2) if dw_row is not None else 0.0

        return {
            "total_scenarios": total_scenarios,
            "by_type": by_type,
            "total_simulations": total_simulations,
            "completed_simulations": completed_simulations,
            "avg_detection_rate": avg_detection_rate,
            "avg_dwell_time_seconds": avg_dwell_time_seconds,
        }
