"""
⚠️  SIMULATED DATA — NOT FOR PRODUCTION OR DEMO USE  ⚠️

This engine generates synthetic CIS Kubernetes Benchmark counts for development/testing.
DO NOT use the output in customer-facing screens or pitches.

Real implementation tracking:
- CIS benchmark counts (lines 307-368) are derived from cluster_id seed — not
  from real kubectl/kube-bench output or live cluster API calls.
- RBAC analysis (get_rbac_analysis) uses seeded random for role/binding counts.
- Real implementation requires: kube-bench integration, kubectl API access,
  or managed cluster security APIs (EKS Security Hub, AKS Defender, GKE Security Command Center).
  Configure via /api/v1/connectors/kubernetes/configure

Until real integrations are wired, these endpoints return a structured
warning header so callers can detect simulation mode.

KubernetesSecurityEngine — ALDECI.

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
    "⚠️  %s loaded in SIMULATION mode — CIS counts are seeded-random; do not present in demos. "
    "Configure real connectors via /api/v1/connectors/kubernetes/configure",
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
        """Simulate CIS Kubernetes Benchmark v1.8 for a cluster.

        Uses actual open findings to influence the score.
        """
        with self._lock:
            with self._conn() as conn:
                cluster = conn.execute(
                    "SELECT * FROM k8s_clusters WHERE id = ? AND org_id = ?",
                    (cluster_id, org_id),
                ).fetchone()
                if not cluster:
                    raise ValueError(f"Cluster {cluster_id} not found for org {org_id}")
                open_findings = conn.execute(
                    "SELECT severity FROM k8s_findings WHERE cluster_id = ? AND org_id = ? AND status = 'open'",
                    (cluster_id, org_id),
                ).fetchall()

        # Weight penalty from open findings
        penalty = sum(_SEVERITY_WEIGHT.get(r["severity"], 0) for r in open_findings)

        # Build per-category results deterministically from cluster_id seed
        rng = random.Random(cluster_id)
        categories = []
        total_passed = 0
        total_failed = 0
        for cat_name in _CIS_CATEGORIES:
            total_checks = rng.randint(8, 20)
            # More failures for clusters with more open findings
            base_fail = max(0, rng.randint(0, 4) + (penalty // 5))
            failed = min(base_fail, total_checks)
            passed = total_checks - failed
            categories.append({"name": cat_name, "passed": passed, "failed": failed})
            total_passed += passed
            total_failed += failed

        total = total_passed + total_failed
        score_pct = round((total_passed / total * 100) if total > 0 else 0.0, 1)

        return {
            "cluster_id": cluster_id,
            "benchmark": "CIS Kubernetes Benchmark v1.8",
            "passed": total_passed,
            "failed": total_failed,
            "score_pct": score_pct,
            "categories": categories,
            "run_at": _now(),
        }

    # ------------------------------------------------------------------
    # RBAC Analysis
    # ------------------------------------------------------------------

    def get_rbac_analysis(self, org_id: str, cluster_id: str) -> Dict[str, Any]:
        """Return RBAC analysis for a cluster.

        Derives metrics from actual rbac_wildcard findings plus cluster size.
        """
        with self._lock:
            with self._conn() as conn:
                cluster = conn.execute(
                    "SELECT * FROM k8s_clusters WHERE id = ? AND org_id = ?",
                    (cluster_id, org_id),
                ).fetchone()
                if not cluster:
                    raise ValueError(f"Cluster {cluster_id} not found for org {org_id}")
                wildcard_findings = conn.execute(
                    "SELECT COUNT(*) as cnt FROM k8s_findings "
                    "WHERE cluster_id = ? AND org_id = ? AND finding_type = 'rbac_wildcard' AND status = 'open'",
                    (cluster_id, org_id),
                ).fetchone()
                default_sa_findings = conn.execute(
                    "SELECT COUNT(*) as cnt FROM k8s_findings "
                    "WHERE cluster_id = ? AND org_id = ? AND finding_type = 'default_serviceaccount' AND status = 'open'",
                    (cluster_id, org_id),
                ).fetchone()

        node_count = cluster["node_count"]
        namespace_count = cluster["namespace_count"]
        wildcard_count = wildcard_findings["cnt"]
        default_sa_count = default_sa_findings["cnt"]

        # Simulate realistic RBAC metrics based on cluster size
        rng = random.Random(cluster_id + "_rbac")
        total_roles = namespace_count * rng.randint(3, 8) + rng.randint(5, 15)
        cluster_admin_bindings = rng.randint(1, max(1, node_count // 5 + 1))
        unused_roles = rng.randint(0, max(0, total_roles // 4))

        return {
            "cluster_id": cluster_id,
            "total_roles": total_roles,
            "cluster_admin_bindings": cluster_admin_bindings,
            "wildcard_permissions": wildcard_count,
            "unused_roles": unused_roles,
            "overprivileged_serviceaccounts": default_sa_count,
            "analyzed_at": _now(),
        }

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
