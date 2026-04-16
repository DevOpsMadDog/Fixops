"""Container Security Posture Engine — ALDECI.

Tracks Kubernetes/container cluster security posture, findings, and remediation
across runtimes with a live posture score that degrades on findings and recovers
on resolution.

Capabilities:
  - Cluster registry: docker, containerd, cri-o, podman
  - Finding types: image_vuln, misconfiguration, secret_exposure,
                   privilege_escalation, network_policy, runtime_anomaly
  - Posture score: starts at 100, decremented per finding severity, restored on resolve
  - Stats: avg score, open/critical findings, clusters at risk (<70)

Compliance: CIS Kubernetes Benchmark, NIST SP 800-190 (Container Security)
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "container_security_posture.db"
)

_VALID_RUNTIMES = {"docker", "containerd", "cri-o", "podman"}

_VALID_FINDING_TYPES = {
    "image_vuln",
    "misconfiguration",
    "secret_exposure",
    "privilege_escalation",
    "network_policy",
    "runtime_anomaly",
}

_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}

_VALID_IMAGE_STATUSES = {"compliant", "non_compliant", "scanning", "unknown"}

# Score deltas per severity (negative = deduct, restore adds them back)
_SEVERITY_DELTA = {
    "critical": -8,
    "high": -4,
    "medium": -2,
    "low": -1,
    "info": 0,
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class ContainerSecurityPostureEngine:
    """SQLite WAL-backed Container Security Posture engine."""

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS csp_clusters (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    name             TEXT NOT NULL DEFAULT '',
                    runtime          TEXT NOT NULL DEFAULT 'docker',
                    version          TEXT NOT NULL DEFAULT '',
                    node_count       INTEGER NOT NULL DEFAULT 0,
                    namespace_count  INTEGER NOT NULL DEFAULT 0,
                    posture_score    REAL NOT NULL DEFAULT 100.0,
                    last_scanned     DATETIME,
                    status           TEXT NOT NULL DEFAULT 'active',
                    created_at       DATETIME
                );

                CREATE TABLE IF NOT EXISTS csp_findings (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    cluster_id      TEXT NOT NULL,
                    namespace       TEXT NOT NULL DEFAULT '',
                    pod_name        TEXT NOT NULL DEFAULT '',
                    container_name  TEXT NOT NULL DEFAULT '',
                    finding_type    TEXT NOT NULL DEFAULT 'misconfiguration',
                    severity        TEXT NOT NULL DEFAULT 'medium',
                    title           TEXT NOT NULL DEFAULT '',
                    description     TEXT NOT NULL DEFAULT '',
                    remediation     TEXT NOT NULL DEFAULT '',
                    status          TEXT NOT NULL DEFAULT 'open',
                    detected_at     DATETIME,
                    resolved_at     DATETIME
                );
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    def _clamp_score(self, score: float) -> float:
        return max(0.0, min(100.0, score))

    # ------------------------------------------------------------------
    # Clusters
    # ------------------------------------------------------------------

    def register_cluster(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new cluster."""
        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("name is required")

        runtime = data.get("runtime", "docker")
        if runtime not in _VALID_RUNTIMES:
            raise ValueError(
                f"runtime must be one of {sorted(_VALID_RUNTIMES)}, got {runtime!r}"
            )

        cluster_id = str(uuid.uuid4())
        now = _now_iso()

        row_data = {
            "id": cluster_id,
            "org_id": org_id,
            "name": name,
            "runtime": runtime,
            "version": data.get("version", ""),
            "node_count": int(data.get("node_count", 0)),
            "namespace_count": int(data.get("namespace_count", 0)),
            "posture_score": 100.0,
            "last_scanned": data.get("last_scanned"),
            "status": "active",
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO csp_clusters
                        (id, org_id, name, runtime, version, node_count,
                         namespace_count, posture_score, last_scanned, status, created_at)
                    VALUES
                        (:id, :org_id, :name, :runtime, :version, :node_count,
                         :namespace_count, :posture_score, :last_scanned, :status, :created_at)
                    """,
                    row_data,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ASSET_DISCOVERED", {"entity_type": "container_security_posture", "org_id": org_id, "source_engine": "container_security_posture"})
            except Exception:
                pass

        return row_data

    def list_clusters(
        self,
        org_id: str,
        runtime: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List clusters with optional runtime filter."""
        query = "SELECT * FROM csp_clusters WHERE org_id = ?"
        params: List[Any] = [org_id]
        if runtime:
            query += " AND runtime = ?"
            params.append(runtime)
        query += " ORDER BY created_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def get_cluster(self, org_id: str, cluster_id: str) -> Optional[Dict[str, Any]]:
        """Return a single cluster or None."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM csp_clusters WHERE id = ? AND org_id = ?",
                (cluster_id, org_id),
            ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def record_finding(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a security finding and decrement cluster posture score."""
        cluster_id = (data.get("cluster_id") or "").strip()
        if not cluster_id:
            raise ValueError("cluster_id is required")

        finding_type = data.get("finding_type", "misconfiguration")
        if finding_type not in _VALID_FINDING_TYPES:
            raise ValueError(
                f"finding_type must be one of {sorted(_VALID_FINDING_TYPES)}, got {finding_type!r}"
            )

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"severity must be one of {sorted(_VALID_SEVERITIES)}, got {severity!r}"
            )

        finding_id = str(uuid.uuid4())
        now = _now_iso()

        row_data = {
            "id": finding_id,
            "org_id": org_id,
            "cluster_id": cluster_id,
            "namespace": data.get("namespace", ""),
            "pod_name": data.get("pod_name", ""),
            "container_name": data.get("container_name", ""),
            "finding_type": finding_type,
            "severity": severity,
            "title": data.get("title", ""),
            "description": data.get("description", ""),
            "remediation": data.get("remediation", ""),
            "status": "open",
            "detected_at": data.get("detected_at", now),
            "resolved_at": None,
        }

        delta = _SEVERITY_DELTA.get(severity, 0)

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO csp_findings
                        (id, org_id, cluster_id, namespace, pod_name, container_name,
                         finding_type, severity, title, description, remediation,
                         status, detected_at, resolved_at)
                    VALUES
                        (:id, :org_id, :cluster_id, :namespace, :pod_name, :container_name,
                         :finding_type, :severity, :title, :description, :remediation,
                         :status, :detected_at, :resolved_at)
                    """,
                    row_data,
                )
                if delta != 0:
                    # Read current score, apply delta, clamp, write back
                    cur = conn.execute(
                        "SELECT posture_score FROM csp_clusters WHERE id = ? AND org_id = ?",
                        (cluster_id, org_id),
                    ).fetchone()
                    if cur:
                        new_score = self._clamp_score(cur["posture_score"] + delta)
                        conn.execute(
                            "UPDATE csp_clusters SET posture_score = ?, last_scanned = ? WHERE id = ? AND org_id = ?",
                            (new_score, now, cluster_id, org_id),
                        )
        return row_data

    def list_findings(
        self,
        org_id: str,
        cluster_id: Optional[str] = None,
        finding_type: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List findings with optional filters."""
        query = "SELECT * FROM csp_findings WHERE org_id = ?"
        params: List[Any] = [org_id]
        if cluster_id:
            query += " AND cluster_id = ?"
            params.append(cluster_id)
        if finding_type:
            query += " AND finding_type = ?"
            params.append(finding_type)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY detected_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def resolve_finding(
        self,
        org_id: str,
        finding_id: str,
        resolution: str,
    ) -> Dict[str, Any]:
        """Resolve a finding and restore posture score."""
        now = _now_iso()

        with self._lock:
            with self._conn() as conn:
                finding = conn.execute(
                    "SELECT * FROM csp_findings WHERE id = ? AND org_id = ?",
                    (finding_id, org_id),
                ).fetchone()
                if not finding:
                    raise KeyError(f"Finding {finding_id!r} not found for org {org_id!r}")

                finding_dict = self._row(finding)
                severity = finding_dict["severity"]
                cluster_id = finding_dict["cluster_id"]

                conn.execute(
                    "UPDATE csp_findings SET status = 'resolved', resolved_at = ? WHERE id = ? AND org_id = ?",
                    (now, finding_id, org_id),
                )

                # Restore score: add back the absolute value of the delta
                delta = _SEVERITY_DELTA.get(severity, 0)
                restore = abs(delta)
                if restore > 0:
                    cur = conn.execute(
                        "SELECT posture_score FROM csp_clusters WHERE id = ? AND org_id = ?",
                        (cluster_id, org_id),
                    ).fetchone()
                    if cur:
                        new_score = self._clamp_score(cur["posture_score"] + restore)
                        conn.execute(
                            "UPDATE csp_clusters SET posture_score = ? WHERE id = ? AND org_id = ?",
                            (new_score, cluster_id, org_id),
                        )

                updated = conn.execute(
                    "SELECT * FROM csp_findings WHERE id = ? AND org_id = ?",
                    (finding_id, org_id),
                ).fetchone()

        result = self._row(updated)
        result["resolution"] = resolution
        return result

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_posture_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated container posture statistics."""
        with self._conn() as conn:
            total_clusters = conn.execute(
                "SELECT COUNT(*) FROM csp_clusters WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            avg_row = conn.execute(
                "SELECT AVG(posture_score) FROM csp_clusters WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            avg_posture_score = round(avg_row or 0.0, 2)

            total_findings = conn.execute(
                "SELECT COUNT(*) FROM csp_findings WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            open_findings = conn.execute(
                "SELECT COUNT(*) FROM csp_findings WHERE org_id = ? AND status = 'open'",
                (org_id,),
            ).fetchone()[0]

            critical_findings = conn.execute(
                "SELECT COUNT(*) FROM csp_findings WHERE org_id = ? AND severity = 'critical' AND status = 'open'",
                (org_id,),
            ).fetchone()[0]

            type_rows = conn.execute(
                """
                SELECT finding_type, COUNT(*) as cnt
                FROM csp_findings WHERE org_id = ?
                GROUP BY finding_type
                """,
                (org_id,),
            ).fetchall()
            by_finding_type = {r["finding_type"]: r["cnt"] for r in type_rows}

            risk_clusters = conn.execute(
                "SELECT COUNT(*) FROM csp_clusters WHERE org_id = ? AND posture_score < 70",
                (org_id,),
            ).fetchone()[0]

        return {
            "total_clusters": total_clusters,
            "avg_posture_score": avg_posture_score,
            "total_findings": total_findings,
            "open_findings": open_findings,
            "critical_findings": critical_findings,
            "by_finding_type": by_finding_type,
            "clusters_at_risk": risk_clusters,
        }
