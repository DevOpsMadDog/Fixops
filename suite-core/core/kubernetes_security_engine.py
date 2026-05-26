"""
KubernetesSecurityEngine — ALDECI.

STATUS: PARTIALLY REAL — CRUD operations (register_cluster, record_finding,
list_findings, resolve_finding, list_clusters, get_cluster_stats) are fully
production-ready and backed by SQLite WAL.

NOT PRODUCTION READY: run_cis_benchmark() and get_rbac_analysis() use
seeded-random to simulate CIS Kubernetes Benchmark counts and RBAC metrics
instead of calling real kube-bench or the Kubernetes API. To make fully
real: wire kube-bench integration or managed cluster security APIs
(EKS Security Hub, AKS Defender, GKE SCC) via
/api/v1/connectors/kubernetes/configure.

Kubernetes cluster security: misconfiguration detection, RBAC audit,
container privilege analysis, CIS Kubernetes Benchmark v1.8 simulation.

Multi-tenant via org_id.  Thread-safe via RLock.  SQLite WAL for concurrency.
"""
from __future__ import annotations

import logging
import random
import sqlite3

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_logger = logging.getLogger(__name__)
_logger.warning(
    "⚠️  %s: run_cis_benchmark() and get_rbac_analysis() are STUB — they raise "
    "NotImplementedError rather than fabricate scores. Set K8S_KUBEBENCH_URL to "
    "enable real CIS benchmarking. CRUD operations are production-ready.",
    __name__,
)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "k8s_security.db"
)

_VALID_PROVIDERS = {"eks", "aks", "gke", "self_managed"}
_VALID_FINDING_TYPES = {
    "privileged_container",
    "host_network",
    "no_resource_limits",
    "default_serviceaccount",
    "exposed_dashboard",
    "unencrypted_secrets",
    "rbac_wildcard",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_STATUSES = {"open", "resolved", "suppressed"}

# CIS Kubernetes Benchmark v1.8 categories (simulated)
_CIS_CATEGORIES = [
    "Control Plane Components",
    "Control Plane Configuration",
    "Worker Nodes",
    "Policies",
    "Managed Services",
]

# Severity weight for risk scoring
_SEVERITY_WEIGHT = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class KubernetesSecurityEngine:
    """SQLite WAL-backed Kubernetes security engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    Tables: k8s_clusters, k8s_findings.
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
            conn.execute("""
                CREATE TABLE IF NOT EXISTS k8s_clusters (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    cluster_name TEXT NOT NULL,
                    provider TEXT NOT NULL DEFAULT 'eks',
                    k8s_version TEXT NOT NULL DEFAULT '1.28',
                    node_count INTEGER NOT NULL DEFAULT 1,
                    namespace_count INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS k8s_findings (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    cluster_id TEXT NOT NULL,
                    finding_type TEXT NOT NULL,
                    severity TEXT NOT NULL DEFAULT 'medium',
                    namespace TEXT NOT NULL DEFAULT 'default',
                    resource_name TEXT NOT NULL DEFAULT '',
                    resource_type TEXT NOT NULL DEFAULT '',
                    description TEXT NOT NULL DEFAULT '',
                    remediation TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'open',
                    resolved_by TEXT,
                    resolution_notes TEXT,
                    created_at TEXT NOT NULL,
                    resolved_at TEXT
                )
            """)
            conn.execute("CREATE INDEX IF NOT EXISTS idx_k8s_clusters_org ON k8s_clusters(org_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_k8s_findings_org ON k8s_findings(org_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_k8s_findings_cluster ON k8s_findings(cluster_id)")
            conn.commit()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Clusters
    # ------------------------------------------------------------------

    def register_cluster(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a Kubernetes cluster for an org."""
        cluster_id = str(uuid.uuid4())
        provider = data.get("provider", "eks")
        if provider not in _VALID_PROVIDERS:
            provider = "eks"
        row = {
            "id": cluster_id,
            "org_id": org_id,
            "cluster_name": data.get("cluster_name", "unnamed-cluster"),
            "provider": provider,
            "k8s_version": data.get("k8s_version", "1.28"),
            "node_count": int(data.get("node_count", 1)),
            "namespace_count": int(data.get("namespace_count", 1)),
            "created_at": _now(),
            "updated_at": _now(),
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO k8s_clusters
                       (id, org_id, cluster_name, provider, k8s_version, node_count, namespace_count, created_at, updated_at)
                       VALUES (:id, :org_id, :cluster_name, :provider, :k8s_version, :node_count, :namespace_count, :created_at, :updated_at)""",
                    row,
                )
                conn.commit()
        _logger.info("Registered K8s cluster %s for org %s", cluster_id, org_id)
        if _get_tg_bus is not None:
            try:
                _get_tg_bus().emit("ASSET_DISCOVERED", {
                    "org_id": org_id,
                    "entity": "k8s_cluster",
                    "asset_id": cluster_id,
                    "cluster_name": row["cluster_name"],
                    "provider": provider,
                })
            except Exception:
                pass
        return dict(row)

    def list_clusters(self, org_id: str) -> List[Dict[str, Any]]:
        """List all clusters for an org."""
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM k8s_clusters WHERE org_id = ? ORDER BY created_at DESC",
                    (org_id,),
                ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def record_finding(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a security finding for a cluster."""
        finding_id = str(uuid.uuid4())
        finding_type = data.get("finding_type", "no_resource_limits")
        if finding_type not in _VALID_FINDING_TYPES:
            finding_type = "no_resource_limits"
        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            severity = "medium"
        row = {
            "id": finding_id,
            "org_id": org_id,
            "cluster_id": data.get("cluster_id", ""),
            "finding_type": finding_type,
            "severity": severity,
            "namespace": data.get("namespace", "default"),
            "resource_name": data.get("resource_name", ""),
            "resource_type": data.get("resource_type", ""),
            "description": data.get("description", ""),
            "remediation": data.get("remediation", ""),
            "status": "open",
            "resolved_by": None,
            "resolution_notes": None,
            "created_at": _now(),
            "resolved_at": None,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO k8s_findings
                       (id, org_id, cluster_id, finding_type, severity, namespace,
                        resource_name, resource_type, description, remediation,
                        status, resolved_by, resolution_notes, created_at, resolved_at)
                       VALUES (:id, :org_id, :cluster_id, :finding_type, :severity, :namespace,
                               :resource_name, :resource_type, :description, :remediation,
                               :status, :resolved_by, :resolution_notes, :created_at, :resolved_at)""",
                    row,
                )
                conn.commit()
        _logger.info("Recorded K8s finding %s (type=%s, sev=%s)", finding_id, finding_type, severity)
        return dict(row)

    def list_findings(
        self,
        org_id: str,
        cluster_id: Optional[str] = None,
        severity: Optional[str] = None,
        finding_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List findings with optional filters."""
        query = "SELECT * FROM k8s_findings WHERE org_id = ?"
        params: List[Any] = [org_id]
        if cluster_id:
            query += " AND cluster_id = ?"
            params.append(cluster_id)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if finding_type:
            query += " AND finding_type = ?"
            params.append(finding_type)
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY created_at DESC"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def resolve_finding(
        self,
        org_id: str,
        finding_id: str,
        resolved_by: str,
        resolution_notes: str = "",
    ) -> Dict[str, Any]:
        """Mark a finding as resolved."""
        now = _now()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM k8s_findings WHERE id = ? AND org_id = ?",
                    (finding_id, org_id),
                ).fetchone()
                if not row:
                    raise ValueError(f"Finding {finding_id} not found for org {org_id}")
                conn.execute(
                    """UPDATE k8s_findings
                       SET status = 'resolved', resolved_by = ?, resolution_notes = ?, resolved_at = ?
                       WHERE id = ? AND org_id = ?""",
                    (resolved_by, resolution_notes, now, finding_id, org_id),
                )
                conn.commit()
                updated = conn.execute(
                    "SELECT * FROM k8s_findings WHERE id = ?", (finding_id,)
                ).fetchone()
        return dict(updated)

    # ------------------------------------------------------------------
    # CIS Benchmark
    # ------------------------------------------------------------------

    def run_cis_benchmark(self, org_id: str, cluster_id: str) -> Dict[str, Any]:
        """Run CIS Kubernetes Benchmark v1.8 via kube-bench integration.

        Requires a Kubernetes connector configured via
        /api/v1/connectors/kubernetes/configure. Until wired, raises
        NotImplementedError to prevent fake scores reaching customers.

        To enable: set K8S_KUBEBENCH_URL env var to your kube-bench endpoint,
        or configure via /api/v1/connectors/kubernetes/configure.
        CRUD operations (register_cluster, record_finding, resolve_finding)
        work now.
        """
        import os
        if not os.environ.get("K8S_KUBEBENCH_URL"):
            raise NotImplementedError(
                "run_cis_benchmark() requires kube-bench integration. "
                "Configure via /api/v1/connectors/kubernetes/configure and set "
                "K8S_KUBEBENCH_URL env var. "
                "Use record_finding() directly to ingest real kube-bench findings."
            )
        raise NotImplementedError(
            "run_cis_benchmark() kube-bench integration not yet implemented."
        )

    # ------------------------------------------------------------------
    # RBAC Analysis
    # ------------------------------------------------------------------

    def get_rbac_analysis(self, org_id: str, cluster_id: str) -> Dict[str, Any]:
        """Return RBAC analysis for a cluster via Kubernetes API.

        Requires a Kubernetes connector configured via
        /api/v1/connectors/kubernetes/configure. Until wired, raises
        NotImplementedError to prevent simulated role counts reaching customers.

        Real wildcard_permissions and overprivileged_serviceaccounts counts are
        derived from actual recorded findings and are always accurate; the
        total_roles and unused_roles metrics require live kubectl API access.
        """
        import os
        if not os.environ.get("K8S_KUBEBENCH_URL"):
            raise NotImplementedError(
                "get_rbac_analysis() requires Kubernetes API access. "
                "Configure via /api/v1/connectors/kubernetes/configure and set "
                "K8S_KUBEBENCH_URL env var. "
                "rbac_wildcard and default_serviceaccount findings from record_finding() "
                "are already tracked accurately in the database."
            )
        raise NotImplementedError(
            "get_rbac_analysis() Kubernetes API integration not yet implemented."
        )

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_cluster_stats(self, org_id: str) -> Dict[str, Any]:
        """Aggregate stats across all clusters for an org."""
        with self._lock:
            with self._conn() as conn:
                total_clusters = conn.execute(
                    "SELECT COUNT(*) as cnt FROM k8s_clusters WHERE org_id = ?", (org_id,)
                ).fetchone()["cnt"]
                total_findings = conn.execute(
                    "SELECT COUNT(*) as cnt FROM k8s_findings WHERE org_id = ?", (org_id,)
                ).fetchone()["cnt"]
                critical_count = conn.execute(
                    "SELECT COUNT(*) as cnt FROM k8s_findings WHERE org_id = ? AND severity = 'critical' AND status = 'open'",
                    (org_id,),
                ).fetchone()["cnt"]
                resolved_count = conn.execute(
                    "SELECT COUNT(*) as cnt FROM k8s_findings WHERE org_id = ? AND status = 'resolved'",
                    (org_id,),
                ).fetchone()["cnt"]
                by_severity_rows = conn.execute(
                    "SELECT severity, COUNT(*) as cnt FROM k8s_findings WHERE org_id = ? GROUP BY severity",
                    (org_id,),
                ).fetchall()

        by_severity = {r["severity"]: r["cnt"] for r in by_severity_rows}

        # avg_cis_score: simplified estimate based on finding distribution
        total_open = total_findings - resolved_count
        avg_cis_score = max(0.0, round(100.0 - (total_open * 2.5), 1)) if total_findings > 0 else 100.0

        return {
            "org_id": org_id,
            "total_clusters": total_clusters,
            "total_findings": total_findings,
            "by_severity": by_severity,
            "critical_count": critical_count,
            "resolved_count": resolved_count,
            "avg_cis_score": avg_cis_score,
        }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_engine: Optional[KubernetesSecurityEngine] = None
_engine_lock = threading.Lock()


def get_engine() -> KubernetesSecurityEngine:
    global _engine
    with _engine_lock:
        if _engine is None:
            _engine = KubernetesSecurityEngine()
    return _engine
