"""Container Runtime Security Engine — ALDECI.

Monitors container runtime security — running containers, security events,
and policy violations.

Capabilities:
  - Container instance registry with security scoring and org isolation
  - Runtime event tracking with automatic security score impact
  - Policy management (audit/enforce/disabled) with namespace scoping
  - Stats: totals, running count, avg security score, event breakdown

Compliance: CIS Docker Benchmark, NIST SP 800-190, SOC2 CC6.8
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

_DEFAULT_DB_PATH = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "container_runtime_security.db"
)

_VALID_RUNTIME_STATUSES = {"running", "stopped", "paused", "crashed"}
_VALID_EVENT_TYPES = {
    "exec_command", "network_connection", "file_write", "privilege_escalation",
    "unexpected_process", "port_scan", "crypto_mining",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_EVENT_STATUSES = {"detected", "investigated", "mitigated", "false_positive"}
_VALID_POLICY_TYPES = {
    "block_privileged", "restrict_exec", "network_isolation",
    "readonly_filesystem", "resource_limits",
}
_VALID_ENFORCEMENTS = {"audit", "enforce", "disabled"}

_SEVERITY_WEIGHTS = {"critical": 20, "high": 15, "medium": 10, "low": 5}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ContainerRuntimeSecurityEngine:
    """SQLite WAL-backed Container Runtime Security engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/container_runtime_security.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = _DEFAULT_DB_PATH
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
                CREATE TABLE IF NOT EXISTS container_instances (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    container_id   TEXT NOT NULL,
                    image_name     TEXT NOT NULL,
                    image_tag      TEXT NOT NULL DEFAULT 'latest',
                    pod_name       TEXT NOT NULL DEFAULT '',
                    namespace      TEXT NOT NULL DEFAULT 'default',
                    cluster        TEXT NOT NULL DEFAULT '',
                    runtime_status TEXT NOT NULL DEFAULT 'running',
                    privileged     INTEGER NOT NULL DEFAULT 0,
                    host_network   INTEGER NOT NULL DEFAULT 0,
                    security_score INTEGER NOT NULL DEFAULT 100,
                    last_seen      TEXT NOT NULL,
                    created_at     TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ci_org
                    ON container_instances (org_id, namespace, runtime_status, created_at DESC);

                CREATE TABLE IF NOT EXISTS runtime_events (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    container_id    TEXT NOT NULL,
                    event_type      TEXT NOT NULL,
                    severity        TEXT NOT NULL,
                    process_name    TEXT NOT NULL DEFAULT '',
                    command_preview TEXT NOT NULL DEFAULT '',
                    status          TEXT NOT NULL DEFAULT 'detected',
                    detected_at     TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_re_org
                    ON runtime_events (org_id, event_type, severity, status, detected_at DESC);

                CREATE TABLE IF NOT EXISTS runtime_policies (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    policy_name TEXT NOT NULL,
                    policy_type TEXT NOT NULL,
                    enforcement TEXT NOT NULL DEFAULT 'audit',
                    scope       TEXT NOT NULL DEFAULT '[]',
                    created_at  TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_rp_org
                    ON runtime_policies (org_id, enforcement, created_at DESC);
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
    # Container Instances
    # ------------------------------------------------------------------

    def register_container(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a container instance."""
        container_id = (data.get("container_id") or "").strip()
        if not container_id:
            raise ValueError("container_id is required.")
        image_name = (data.get("image_name") or "").strip()
        if not image_name:
            raise ValueError("image_name is required.")

        runtime_status = data.get("runtime_status", "running")
        if runtime_status not in _VALID_RUNTIME_STATUSES:
            raise ValueError(
                f"Invalid runtime_status: {runtime_status}. "
                f"Must be one of {_VALID_RUNTIME_STATUSES}"
            )

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "container_id": container_id,
            "image_name": image_name,
            "image_tag": data.get("image_tag", "latest"),
            "pod_name": data.get("pod_name", ""),
            "namespace": data.get("namespace", "default"),
            "cluster": data.get("cluster", ""),
            "runtime_status": runtime_status,
            "privileged": int(bool(data.get("privileged", False))),
            "host_network": int(bool(data.get("host_network", False))),
            "security_score": int(data.get("security_score", 100)),
            "last_seen": now,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO container_instances
                       (id, org_id, container_id, image_name, image_tag, pod_name,
                        namespace, cluster, runtime_status, privileged, host_network,
                        security_score, last_seen, created_at)
                       VALUES (:id, :org_id, :container_id, :image_name, :image_tag,
                               :pod_name, :namespace, :cluster, :runtime_status,
                               :privileged, :host_network, :security_score,
                               :last_seen, :created_at)""",
                    record,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ASSET_DISCOVERED", {"entity_type": "container_runtime_security", "org_id": org_id, "source_engine": "container_runtime_security"})
            except Exception:
                pass

        return record

    def list_containers(
        self,
        org_id: str,
        namespace: Optional[str] = None,
        runtime_status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List container instances with optional filters."""
        sql = "SELECT * FROM container_instances WHERE org_id = ?"
        params: List[Any] = [org_id]
        if namespace is not None:
            sql += " AND namespace = ?"
            params.append(namespace)
        if runtime_status is not None:
            sql += " AND runtime_status = ?"
            params.append(runtime_status)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_container(self, org_id: str, container_id: str) -> Optional[Dict[str, Any]]:
        """Get a container by its container_id field (not UUID). Returns None if not found or wrong org."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM container_instances WHERE org_id = ? AND container_id = ?",
                (org_id, container_id),
            ).fetchone()
        return self._row(row) if row else None

    def update_container_status(
        self, org_id: str, container_id: str, new_status: str
    ) -> Dict[str, Any]:
        """Update runtime_status and last_seen for a container."""
        if new_status not in _VALID_RUNTIME_STATUSES:
            raise ValueError(
                f"Invalid status: {new_status}. Must be one of {_VALID_RUNTIME_STATUSES}"
            )
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    """UPDATE container_instances
                       SET runtime_status = ?, last_seen = ?
                       WHERE org_id = ? AND container_id = ?""",
                    (new_status, now, org_id, container_id),
                )
                if cur.rowcount == 0:
                    raise KeyError(f"Container '{container_id}' not found in org '{org_id}'.")
                row = conn.execute(
                    "SELECT * FROM container_instances WHERE org_id = ? AND container_id = ?",
                    (org_id, container_id),
                ).fetchone()
        return self._row(row)

    # ------------------------------------------------------------------
    # Runtime Events
    # ------------------------------------------------------------------

    def record_runtime_event(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a runtime security event and decrement container security_score."""
        container_id = (data.get("container_id") or "").strip()
        if not container_id:
            raise ValueError("container_id is required.")

        # Verify container exists in org
        existing = self.get_container(org_id, container_id)
        if existing is None:
            raise ValueError(
                f"Container '{container_id}' not found in org '{org_id}'."
            )

        event_type = data.get("event_type", "")
        if event_type not in _VALID_EVENT_TYPES:
            raise ValueError(
                f"Invalid event_type: {event_type}. Must be one of {_VALID_EVENT_TYPES}"
            )

        severity = data.get("severity", "")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"Invalid severity: {severity}. Must be one of {_VALID_SEVERITIES}"
            )

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "container_id": container_id,
            "event_type": event_type,
            "severity": severity,
            "process_name": data.get("process_name", ""),
            "command_preview": data.get("command_preview", ""),
            "status": "detected",
            "detected_at": now,
        }

        weight = _SEVERITY_WEIGHTS.get(severity, 0)
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO runtime_events
                       (id, org_id, container_id, event_type, severity,
                        process_name, command_preview, status, detected_at)
                       VALUES (:id, :org_id, :container_id, :event_type, :severity,
                               :process_name, :command_preview, :status, :detected_at)""",
                    record,
                )
                # Decrement security_score, clamp at 0
                conn.execute(
                    """UPDATE container_instances
                       SET security_score = MAX(0, security_score - ?)
                       WHERE org_id = ? AND container_id = ?""",
                    (weight, org_id, container_id),
                )
        return record

    def list_events(
        self,
        org_id: str,
        event_type: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List runtime events with optional filters."""
        sql = "SELECT * FROM runtime_events WHERE org_id = ?"
        params: List[Any] = [org_id]
        if event_type is not None:
            sql += " AND event_type = ?"
            params.append(event_type)
        if severity is not None:
            sql += " AND severity = ?"
            params.append(severity)
        if status is not None:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY detected_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def update_event_status(
        self, org_id: str, event_id: str, new_status: str
    ) -> Dict[str, Any]:
        """Update the status of a runtime event."""
        if new_status not in _VALID_EVENT_STATUSES:
            raise ValueError(
                f"Invalid status: {new_status}. Must be one of {_VALID_EVENT_STATUSES}"
            )
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    "UPDATE runtime_events SET status = ? WHERE id = ? AND org_id = ?",
                    (new_status, event_id, org_id),
                )
                if cur.rowcount == 0:
                    raise KeyError(f"Event '{event_id}' not found in org '{org_id}'.")
                row = conn.execute(
                    "SELECT * FROM runtime_events WHERE id = ?", (event_id,)
                ).fetchone()
        return self._row(row)

    # ------------------------------------------------------------------
    # Runtime Policies
    # ------------------------------------------------------------------

    def create_policy(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a runtime security policy."""
        policy_name = (data.get("policy_name") or "").strip()
        if not policy_name:
            raise ValueError("policy_name is required.")

        policy_type = data.get("policy_type", "")
        if policy_type not in _VALID_POLICY_TYPES:
            raise ValueError(
                f"Invalid policy_type: {policy_type}. Must be one of {_VALID_POLICY_TYPES}"
            )

        enforcement = data.get("enforcement", "audit")
        if enforcement not in _VALID_ENFORCEMENTS:
            raise ValueError(
                f"Invalid enforcement: {enforcement}. Must be one of {_VALID_ENFORCEMENTS}"
            )

        scope = data.get("scope", [])
        if isinstance(scope, list):
            scope_json = json.dumps(scope)
        else:
            scope_json = str(scope)

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "policy_name": policy_name,
            "policy_type": policy_type,
            "enforcement": enforcement,
            "scope": scope_json,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO runtime_policies
                       (id, org_id, policy_name, policy_type, enforcement, scope, created_at)
                       VALUES (:id, :org_id, :policy_name, :policy_type, :enforcement,
                               :scope, :created_at)""",
                    record,
                )
        return record

    def list_policies(
        self, org_id: str, enforcement: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List policies with optional enforcement filter."""
        sql = "SELECT * FROM runtime_policies WHERE org_id = ?"
        params: List[Any] = [org_id]
        if enforcement is not None:
            sql += " AND enforcement = ?"
            params.append(enforcement)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_runtime_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate runtime security stats for an org."""
        with self._conn() as conn:
            total_containers = conn.execute(
                "SELECT COUNT(*) FROM container_instances WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            running_containers = conn.execute(
                "SELECT COUNT(*) FROM container_instances WHERE org_id = ? AND runtime_status = 'running'",
                (org_id,),
            ).fetchone()[0]
            avg_score_row = conn.execute(
                "SELECT AVG(security_score) FROM container_instances WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            avg_security_score = float(avg_score_row) if avg_score_row is not None else 0.0

            total_events = conn.execute(
                "SELECT COUNT(*) FROM runtime_events WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            active_events = conn.execute(
                "SELECT COUNT(*) FROM runtime_events WHERE org_id = ? AND status = 'detected'",
                (org_id,),
            ).fetchone()[0]
            critical_events = conn.execute(
                "SELECT COUNT(*) FROM runtime_events WHERE org_id = ? AND severity = 'critical'",
                (org_id,),
            ).fetchone()[0]

            by_event_type_rows = conn.execute(
                """SELECT event_type, COUNT(*) as cnt
                   FROM runtime_events WHERE org_id = ?
                   GROUP BY event_type""",
                (org_id,),
            ).fetchall()

        by_event_type = {r["event_type"]: r["cnt"] for r in by_event_type_rows}

        return {
            "total_containers": total_containers,
            "running_containers": running_containers,
            "total_events": total_events,
            "active_events": active_events,
            "critical_events": critical_events,
            "avg_security_score": round(avg_security_score, 2),
            "by_event_type": by_event_type,
        }
