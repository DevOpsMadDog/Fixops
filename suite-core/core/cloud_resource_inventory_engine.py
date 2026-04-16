"""Cloud Resource Inventory Engine — ALDECI.

Tracks cloud resources across all major providers with security scoring,
compliance status, and security finding management.

Compliance: NIST SP 800-53 CM-8, CIS Benchmark, SOC 2 CC6.1
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "cloud_resource_inventory.db"
)

_VALID_PROVIDERS = {"aws", "azure", "gcp", "alibaba", "oracle", "ibm", "digitalocean"}
_VALID_RESOURCE_TYPES = {
    "compute", "storage", "database", "network", "iam",
    "container", "serverless", "cdn", "dns", "load_balancer",
}
_VALID_COMPLIANCE_STATUSES = {"compliant", "non_compliant", "unknown", "exempt"}
_VALID_RESOURCE_STATES = {"running", "stopped", "terminated", "unknown", "pending"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}

# Security score decrements per severity
_SCORE_DECREMENT = {"critical": 10, "high": 5, "medium": 2, "low": 1}
# Severities that force compliance_status → non_compliant
_NON_COMPLIANT_SEVERITIES = {"critical", "high"}


class CloudResourceInventoryEngine:
    """SQLite WAL-backed Cloud Resource Inventory engine.

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
                CREATE TABLE IF NOT EXISTS cri_resources (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    resource_id       TEXT NOT NULL DEFAULT '',
                    resource_name     TEXT NOT NULL DEFAULT '',
                    provider          TEXT NOT NULL DEFAULT 'aws',
                    resource_type     TEXT NOT NULL DEFAULT 'compute',
                    region            TEXT NOT NULL DEFAULT '',
                    account_id        TEXT NOT NULL DEFAULT '',
                    tags_json         TEXT NOT NULL DEFAULT '{}',
                    resource_state    TEXT NOT NULL DEFAULT 'running',
                    compliance_status TEXT NOT NULL DEFAULT 'unknown',
                    security_score    REAL NOT NULL DEFAULT 100.0,
                    last_seen         DATETIME,
                    created_at        DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_cri_resources_org
                    ON cri_resources (org_id, provider, resource_type);

                CREATE TABLE IF NOT EXISTS cri_findings (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    cloud_resource_id TEXT NOT NULL,
                    severity          TEXT NOT NULL DEFAULT 'medium',
                    title             TEXT NOT NULL DEFAULT '',
                    compliance_check  TEXT NOT NULL DEFAULT '',
                    remediation       TEXT NOT NULL DEFAULT '',
                    status            TEXT NOT NULL DEFAULT 'open',
                    found_at          DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_cri_findings_org
                    ON cri_findings (org_id, cloud_resource_id, severity, status);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # Resources
    # ------------------------------------------------------------------

    def register_resource(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new cloud resource in the inventory."""
        resource_id_val = data.get("resource_id", "")
        if not resource_id_val:
            raise ValueError("resource_id is required")

        provider = data.get("provider", "aws")
        if provider not in _VALID_PROVIDERS:
            raise ValueError(f"provider must be one of {sorted(_VALID_PROVIDERS)}")

        resource_type = data.get("resource_type", "compute")
        if resource_type not in _VALID_RESOURCE_TYPES:
            raise ValueError(f"resource_type must be one of {sorted(_VALID_RESOURCE_TYPES)}")

        now = self._now()
        row = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "resource_id": resource_id_val,
            "resource_name": data.get("resource_name", ""),
            "provider": provider,
            "resource_type": resource_type,
            "region": data.get("region", ""),
            "account_id": data.get("account_id", ""),
            "tags_json": json.dumps(data.get("tags", {})),
            "resource_state": data.get("resource_state", "running"),
            "compliance_status": "unknown",
            "security_score": 100.0,
            "last_seen": now,
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO cri_resources VALUES
                       (:id,:org_id,:resource_id,:resource_name,:provider,:resource_type,
                        :region,:account_id,:tags_json,:resource_state,:compliance_status,
                        :security_score,:last_seen,:created_at)""",
                    row,
                )
        result = dict(row)
        result["tags"] = data.get("tags", {})
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ASSET_DISCOVERED", {"entity_type": "cloud_resource_inventory", "org_id": org_id, "source_engine": "cloud_resource_inventory"})
            except Exception:
                pass

        return result

    def list_resources(
        self,
        org_id: str,
        provider: Optional[str] = None,
        resource_type: Optional[str] = None,
        compliance_status: Optional[str] = None,
        resource_state: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List resources with optional filters, org-isolated."""
        clauses = ["org_id = ?"]
        params: List[Any] = [org_id]
        if provider:
            clauses.append("provider = ?")
            params.append(provider)
        if resource_type:
            clauses.append("resource_type = ?")
            params.append(resource_type)
        if compliance_status:
            clauses.append("compliance_status = ?")
            params.append(compliance_status)
        if resource_state:
            clauses.append("resource_state = ?")
            params.append(resource_state)

        sql = (
            f"SELECT * FROM cri_resources WHERE {' AND '.join(clauses)}"  # nosec B608
            " ORDER BY created_at DESC"
        )
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def get_resource(self, org_id: str, resource_id_param: str) -> Optional[Dict[str, Any]]:
        """Fetch a resource by internal id, org-isolated."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM cri_resources WHERE id = ? AND org_id = ?",
                    (resource_id_param, org_id),
                ).fetchone()
        return self._row(row) if row else None

    def update_resource_state(
        self,
        org_id: str,
        resource_id_param: str,
        state: str,
        compliance_status: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update resource_state and optionally compliance_status."""
        if state not in _VALID_RESOURCE_STATES:
            raise ValueError(f"state must be one of {sorted(_VALID_RESOURCE_STATES)}")
        if compliance_status and compliance_status not in _VALID_COMPLIANCE_STATUSES:
            raise ValueError(
                f"compliance_status must be one of {sorted(_VALID_COMPLIANCE_STATUSES)}"
            )

        now = self._now()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM cri_resources WHERE id = ? AND org_id = ?",
                    (resource_id_param, org_id),
                ).fetchone()
                if not row:
                    raise KeyError("resource not found")

                if compliance_status:
                    conn.execute(
                        """UPDATE cri_resources
                           SET resource_state = ?, compliance_status = ?, last_seen = ?
                           WHERE id = ? AND org_id = ?""",
                        (state, compliance_status, now, resource_id_param, org_id),
                    )
                else:
                    conn.execute(
                        """UPDATE cri_resources
                           SET resource_state = ?, last_seen = ?
                           WHERE id = ? AND org_id = ?""",
                        (state, now, resource_id_param, org_id),
                    )
                updated = conn.execute(
                    "SELECT * FROM cri_resources WHERE id = ?", (resource_id_param,)
                ).fetchone()
        return self._row(updated)

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def record_security_finding(
        self, org_id: str, resource_id_param: str, finding_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Record a security finding against a resource and update its score."""
        severity = finding_data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(_VALID_SEVERITIES)}")

        now = self._now()
        finding_id = str(uuid.uuid4())
        row = {
            "id": finding_id,
            "org_id": org_id,
            "cloud_resource_id": resource_id_param,
            "severity": severity,
            "title": finding_data.get("title", ""),
            "compliance_check": finding_data.get("compliance_check", ""),
            "remediation": finding_data.get("remediation", ""),
            "status": "open",
            "found_at": now,
        }

        decrement = _SCORE_DECREMENT[severity]

        with self._lock:
            with self._conn() as conn:
                # Verify resource belongs to org
                res = conn.execute(
                    "SELECT id, security_score FROM cri_resources WHERE id = ? AND org_id = ?",
                    (resource_id_param, org_id),
                ).fetchone()
                if not res:
                    raise KeyError("resource not found")

                conn.execute(
                    """INSERT INTO cri_findings VALUES
                       (:id,:org_id,:cloud_resource_id,:severity,:title,
                        :compliance_check,:remediation,:status,:found_at)""",
                    row,
                )

                # Decrement score (floor 0)
                new_score = max(0.0, float(res["security_score"]) - decrement)
                if severity in _NON_COMPLIANT_SEVERITIES:
                    conn.execute(
                        """UPDATE cri_resources
                           SET security_score = ?, compliance_status = 'non_compliant', last_seen = ?
                           WHERE id = ? AND org_id = ?""",
                        (new_score, now, resource_id_param, org_id),
                    )
                else:
                    conn.execute(
                        """UPDATE cri_resources
                           SET security_score = ?, last_seen = ?
                           WHERE id = ? AND org_id = ?""",
                        (new_score, now, resource_id_param, org_id),
                    )
        return dict(row)

    def list_findings(
        self,
        org_id: str,
        cloud_resource_id: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List findings with optional filters."""
        clauses = ["org_id = ?"]
        params: List[Any] = [org_id]
        if cloud_resource_id:
            clauses.append("cloud_resource_id = ?")
            params.append(cloud_resource_id)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if status:
            clauses.append("status = ?")
            params.append(status)

        sql = (
            f"SELECT * FROM cri_findings WHERE {' AND '.join(clauses)}"  # nosec B608
            " ORDER BY found_at DESC"
        )
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_inventory_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated inventory statistics for an org."""
        with self._lock:
            with self._conn() as conn:
                total_resources = conn.execute(
                    "SELECT COUNT(*) FROM cri_resources WHERE org_id = ?", (org_id,)
                ).fetchone()[0]

                running_resources = conn.execute(
                    "SELECT COUNT(*) FROM cri_resources WHERE org_id = ? AND resource_state = 'running'",
                    (org_id,),
                ).fetchone()[0]

                non_compliant_resources = conn.execute(
                    "SELECT COUNT(*) FROM cri_resources WHERE org_id = ? AND compliance_status = 'non_compliant'",
                    (org_id,),
                ).fetchone()[0]

                total_findings = conn.execute(
                    "SELECT COUNT(*) FROM cri_findings WHERE org_id = ?", (org_id,)
                ).fetchone()[0]

                by_provider_rows = conn.execute(
                    """SELECT provider, COUNT(*) as cnt
                       FROM cri_resources WHERE org_id = ?
                       GROUP BY provider""",
                    (org_id,),
                ).fetchall()

                by_type_rows = conn.execute(
                    """SELECT resource_type, COUNT(*) as cnt
                       FROM cri_resources WHERE org_id = ?
                       GROUP BY resource_type""",
                    (org_id,),
                ).fetchall()

                avg_score_row = conn.execute(
                    "SELECT AVG(security_score) FROM cri_resources WHERE org_id = ?", (org_id,)
                ).fetchone()
                avg_security_score = round(float(avg_score_row[0] or 100.0), 2)

                critical_resources = conn.execute(
                    "SELECT COUNT(*) FROM cri_resources WHERE org_id = ? AND security_score < 60",
                    (org_id,),
                ).fetchone()[0]

        return {
            "total_resources": total_resources,
            "running_resources": running_resources,
            "non_compliant_resources": non_compliant_resources,
            "total_findings": total_findings,
            "by_provider": {r["provider"]: r["cnt"] for r in by_provider_rows},
            "by_resource_type": {r["resource_type"]: r["cnt"] for r in by_type_rows},
            "avg_security_score": avg_security_score,
            "critical_resources": critical_resources,
        }
