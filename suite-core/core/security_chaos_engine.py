"""Security Chaos Engine — ALDECI.

Manages security chaos engineering — resilience tests for security controls.

Capabilities:
  - Chaos experiment lifecycle: create, start, complete, cancel
  - Observation recording per experiment
  - Remediation tracking with priority/status lifecycle
  - Stats: resilience scores, critical findings, type/status breakdowns

Compliance: NIST SP 800-53 CA-8 (penetration testing), ISO 27001 A.8.8
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

_DEFAULT_DB_DIR = str(
    Path(__file__).resolve().parents[2] / ".fixops_data"
)

_VALID_EXPERIMENT_TYPES = {
    "firewall_bypass",
    "auth_disruption",
    "mfa_failure",
    "cert_expiry",
    "key_rotation",
    "siem_outage",
    "dlp_bypass",
    "iam_misconfiguration",
}

_VALID_STATUSES = {"planned", "running", "completed", "failed", "cancelled"}

_VALID_OBSERVATION_TYPES = {
    "control_bypassed",
    "control_held",
    "service_degraded",
    "alert_triggered",
    "no_alert",
    "recovery_time",
}

_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}

_VALID_PRIORITIES = {"critical", "high", "medium", "low"}

_VALID_REMEDIATION_STATUSES = {"open", "in_progress", "completed"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class SecurityChaosEngine:
    """SQLite WAL-backed Security Chaos Engineering engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/security_chaos.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(Path(_DEFAULT_DB_DIR) / "security_chaos.db")
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
                CREATE TABLE IF NOT EXISTS chaos_experiments (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    experiment_name  TEXT NOT NULL,
                    experiment_type  TEXT NOT NULL,
                    target_system    TEXT NOT NULL,
                    status           TEXT NOT NULL DEFAULT 'planned',
                    hypothesis       TEXT NOT NULL DEFAULT '',
                    expected_outcome TEXT NOT NULL DEFAULT '',
                    actual_outcome   TEXT NOT NULL DEFAULT '',
                    resilience_score INTEGER NOT NULL DEFAULT 0,
                    scheduled_at     TEXT,
                    started_at       TEXT,
                    completed_at     TEXT,
                    created_at       TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_chaos_exp_org
                    ON chaos_experiments (org_id, experiment_type, status, created_at DESC);

                CREATE TABLE IF NOT EXISTS chaos_observations (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    experiment_id    TEXT NOT NULL,
                    observation_type TEXT NOT NULL,
                    severity         TEXT NOT NULL DEFAULT 'info',
                    description      TEXT NOT NULL DEFAULT '',
                    observed_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_chaos_obs_exp
                    ON chaos_observations (org_id, experiment_id, observed_at ASC);

                CREATE TABLE IF NOT EXISTS chaos_remediations (
                    id                 TEXT PRIMARY KEY,
                    org_id             TEXT NOT NULL,
                    experiment_id      TEXT NOT NULL,
                    finding            TEXT NOT NULL,
                    remediation_action TEXT NOT NULL,
                    priority           TEXT NOT NULL DEFAULT 'medium',
                    status             TEXT NOT NULL DEFAULT 'open',
                    created_at         TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_chaos_rem_exp
                    ON chaos_remediations (org_id, experiment_id, created_at DESC);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Experiments
    # ------------------------------------------------------------------

    def create_experiment(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new chaos experiment."""
        experiment_name = (data.get("experiment_name") or "").strip()
        if not experiment_name:
            raise ValueError("experiment_name is required.")

        experiment_type = data.get("experiment_type", "")
        if experiment_type not in _VALID_EXPERIMENT_TYPES:
            raise ValueError(
                f"Invalid experiment_type: {experiment_type!r}. "
                f"Must be one of {sorted(_VALID_EXPERIMENT_TYPES)}"
            )

        target_system = (data.get("target_system") or "").strip()
        if not target_system:
            raise ValueError("target_system is required.")

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "experiment_name": experiment_name,
            "experiment_type": experiment_type,
            "target_system": target_system,
            "status": "planned",
            "hypothesis": data.get("hypothesis", ""),
            "expected_outcome": data.get("expected_outcome", ""),
            "actual_outcome": "",
            "resilience_score": 0,
            "scheduled_at": data.get("scheduled_at"),
            "started_at": None,
            "completed_at": None,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO chaos_experiments
                       (id, org_id, experiment_name, experiment_type, target_system,
                        status, hypothesis, expected_outcome, actual_outcome,
                        resilience_score, scheduled_at, started_at, completed_at, created_at)
                       VALUES (:id, :org_id, :experiment_name, :experiment_type, :target_system,
                               :status, :hypothesis, :expected_outcome, :actual_outcome,
                               :resilience_score, :scheduled_at, :started_at, :completed_at, :created_at)""",
                    record,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "security_chaos", "org_id": org_id, "source_engine": "security_chaos"})
            except Exception:
                pass

        return record

    def list_experiments(
        self,
        org_id: str,
        experiment_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List chaos experiments with optional filters."""
        query = "SELECT * FROM chaos_experiments WHERE org_id = ?"
        params: List[Any] = [org_id]
        if experiment_type:
            query += " AND experiment_type = ?"
            params.append(experiment_type)
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def get_experiment(self, org_id: str, experiment_id: str) -> Optional[Dict[str, Any]]:
        """Get a single experiment by ID, scoped to org."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM chaos_experiments WHERE id = ? AND org_id = ?",
                (experiment_id, org_id),
            ).fetchone()
        return self._row(row) if row else None

    def start_experiment(self, org_id: str, experiment_id: str) -> Dict[str, Any]:
        """Set experiment status to running."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM chaos_experiments WHERE id = ? AND org_id = ?",
                    (experiment_id, org_id),
                ).fetchone()
                if not row:
                    raise KeyError(f"Experiment {experiment_id!r} not found.")
                current_status = row["status"]
                if current_status not in ("planned", "cancelled"):
                    raise ValueError(
                        f"Cannot start experiment in status {current_status!r}. "
                        "Must be planned or cancelled."
                    )
                now = _now_iso()
                conn.execute(
                    "UPDATE chaos_experiments SET status='running', started_at=? WHERE id=? AND org_id=?",
                    (now, experiment_id, org_id),
                )
                updated = conn.execute(
                    "SELECT * FROM chaos_experiments WHERE id=? AND org_id=?",
                    (experiment_id, org_id),
                ).fetchone()
        return self._row(updated)

    def complete_experiment(
        self, org_id: str, experiment_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Mark experiment completed with actual outcome and resilience score."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM chaos_experiments WHERE id = ? AND org_id = ?",
                    (experiment_id, org_id),
                ).fetchone()
                if not row:
                    raise KeyError(f"Experiment {experiment_id!r} not found.")
                now = _now_iso()
                actual_outcome = data.get("actual_outcome", "")
                resilience_score = int(data.get("resilience_score", 0))
                conn.execute(
                    """UPDATE chaos_experiments
                       SET status='completed', completed_at=?, actual_outcome=?, resilience_score=?
                       WHERE id=? AND org_id=?""",
                    (now, actual_outcome, resilience_score, experiment_id, org_id),
                )
                updated = conn.execute(
                    "SELECT * FROM chaos_experiments WHERE id=? AND org_id=?",
                    (experiment_id, org_id),
                ).fetchone()
        return self._row(updated)

    # ------------------------------------------------------------------
    # Observations
    # ------------------------------------------------------------------

    def add_observation(
        self, org_id: str, experiment_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add an observation to a chaos experiment."""
        # Validate experiment exists in org
        exp = self.get_experiment(org_id, experiment_id)
        if not exp:
            raise KeyError(f"Experiment {experiment_id!r} not found.")

        observation_type = data.get("observation_type", "")
        if observation_type not in _VALID_OBSERVATION_TYPES:
            raise ValueError(
                f"Invalid observation_type: {observation_type!r}. "
                f"Must be one of {sorted(_VALID_OBSERVATION_TYPES)}"
            )

        severity = data.get("severity", "info")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity: {severity!r}. "
                f"Must be one of {sorted(_VALID_SEVERITIES)}"
            )

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "experiment_id": experiment_id,
            "observation_type": observation_type,
            "severity": severity,
            "description": data.get("description", ""),
            "observed_at": data.get("observed_at", now),
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO chaos_observations
                       (id, org_id, experiment_id, observation_type, severity, description, observed_at)
                       VALUES (:id, :org_id, :experiment_id, :observation_type, :severity, :description, :observed_at)""",
                    record,
                )
        return record

    def list_observations(
        self, org_id: str, experiment_id: str
    ) -> List[Dict[str, Any]]:
        """List observations for an experiment ordered by observed_at ASC."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM chaos_observations
                   WHERE org_id=? AND experiment_id=?
                   ORDER BY observed_at ASC""",
                (org_id, experiment_id),
            ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Remediations
    # ------------------------------------------------------------------

    def add_remediation(
        self, org_id: str, experiment_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add a remediation item for a chaos experiment finding."""
        exp = self.get_experiment(org_id, experiment_id)
        if not exp:
            raise KeyError(f"Experiment {experiment_id!r} not found.")

        finding = (data.get("finding") or "").strip()
        if not finding:
            raise ValueError("finding is required.")

        remediation_action = (data.get("remediation_action") or "").strip()
        if not remediation_action:
            raise ValueError("remediation_action is required.")

        priority = data.get("priority", "medium")
        if priority not in _VALID_PRIORITIES:
            raise ValueError(
                f"Invalid priority: {priority!r}. "
                f"Must be one of {sorted(_VALID_PRIORITIES)}"
            )

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "experiment_id": experiment_id,
            "finding": finding,
            "remediation_action": remediation_action,
            "priority": priority,
            "status": "open",
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO chaos_remediations
                       (id, org_id, experiment_id, finding, remediation_action, priority, status, created_at)
                       VALUES (:id, :org_id, :experiment_id, :finding, :remediation_action, :priority, :status, :created_at)""",
                    record,
                )
        return record

    def update_remediation_status(
        self, org_id: str, remediation_id: str, new_status: str
    ) -> Dict[str, Any]:
        """Update the status of a remediation item."""
        if new_status not in _VALID_REMEDIATION_STATUSES:
            raise ValueError(
                f"Invalid status: {new_status!r}. "
                f"Must be one of {sorted(_VALID_REMEDIATION_STATUSES)}"
            )
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM chaos_remediations WHERE id=? AND org_id=?",
                    (remediation_id, org_id),
                ).fetchone()
                if not row:
                    raise KeyError(f"Remediation {remediation_id!r} not found.")
                conn.execute(
                    "UPDATE chaos_remediations SET status=? WHERE id=? AND org_id=?",
                    (new_status, remediation_id, org_id),
                )
                updated = conn.execute(
                    "SELECT * FROM chaos_remediations WHERE id=? AND org_id=?",
                    (remediation_id, org_id),
                ).fetchone()
        return self._row(updated)

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_chaos_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated chaos engineering statistics."""
        with self._conn() as conn:
            total = conn.execute(
                "SELECT COUNT(*) FROM chaos_experiments WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            by_type_rows = conn.execute(
                """SELECT experiment_type, COUNT(*) as cnt
                   FROM chaos_experiments WHERE org_id=?
                   GROUP BY experiment_type""",
                (org_id,),
            ).fetchall()
            by_type = {r["experiment_type"]: r["cnt"] for r in by_type_rows}

            by_status_rows = conn.execute(
                """SELECT status, COUNT(*) as cnt
                   FROM chaos_experiments WHERE org_id=?
                   GROUP BY status""",
                (org_id,),
            ).fetchall()
            by_status = {r["status"]: r["cnt"] for r in by_status_rows}

            avg_row = conn.execute(
                """SELECT AVG(resilience_score) as avg_score
                   FROM chaos_experiments WHERE org_id=? AND status='completed'""",
                (org_id,),
            ).fetchone()
            avg_resilience_score = float(avg_row["avg_score"] or 0.0)

            critical_findings = conn.execute(
                """SELECT COUNT(*) FROM chaos_remediations
                   WHERE org_id=? AND priority='critical' AND status != 'completed'""",
                (org_id,),
            ).fetchone()[0]

            total_observations = conn.execute(
                "SELECT COUNT(*) FROM chaos_observations WHERE org_id=?", (org_id,)
            ).fetchone()[0]

        return {
            "total_experiments": total,
            "by_type": by_type,
            "by_status": by_status,
            "avg_resilience_score": avg_resilience_score,
            "critical_findings": critical_findings,
            "total_observations": total_observations,
        }
