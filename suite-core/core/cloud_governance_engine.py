"""Cloud Governance Engine — ALDECI.

Tracks governance policies across cloud providers, records violations,
and supports remediation workflows for multi-cloud environments.

Compliance: NIST CSF ID.GV, ISO/IEC 27001 A.5, SOC 2 CC2.1
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "cloud_governance.db"
)

_VALID_POLICY_TYPES = {"access", "cost", "security", "compliance", "resource", "tagging"}
_VALID_CLOUD_PROVIDERS = {"aws", "azure", "gcp", "multi_cloud", "on_premise"}
_VALID_ENFORCEMENTS = {"advisory", "warning", "blocking"}
_VALID_SEVERITIES = {"low", "medium", "high", "critical"}
_VALID_VIOLATION_STATUSES = {"open", "remediated", "acknowledged"}


class CloudGovernanceEngine:
    """SQLite WAL-backed Cloud Governance Engine.

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
                CREATE TABLE IF NOT EXISTS governance_policies (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    name            TEXT NOT NULL,
                    policy_type     TEXT NOT NULL,
                    cloud_provider  TEXT NOT NULL DEFAULT 'multi_cloud',
                    enforcement     TEXT NOT NULL DEFAULT 'advisory',
                    description     TEXT NOT NULL DEFAULT '',
                    violation_count INTEGER NOT NULL DEFAULT 0,
                    status          TEXT NOT NULL DEFAULT 'active',
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_gov_pol_org
                    ON governance_policies (org_id, status);

                CREATE TABLE IF NOT EXISTS governance_violations (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    policy_id        TEXT NOT NULL,
                    resource_id      TEXT NOT NULL,
                    resource_type    TEXT NOT NULL,
                    violation_details TEXT NOT NULL DEFAULT '',
                    severity         TEXT NOT NULL DEFAULT 'medium',
                    status           TEXT NOT NULL DEFAULT 'open',
                    remediated_by    TEXT,
                    action_taken     TEXT,
                    detected_at      TEXT NOT NULL,
                    remediated_at    TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_gov_viol_org
                    ON governance_violations (org_id, status, detected_at);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Policies
    # ------------------------------------------------------------------

    def create_governance_policy(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a governance policy. Validates name, policy_type, cloud_provider, enforcement."""
        name = data.get("name", "").strip()
        if not name:
            raise ValueError("name is required")

        policy_type = data.get("policy_type", "")
        if policy_type not in _VALID_POLICY_TYPES:
            raise ValueError(
                f"Invalid policy_type {policy_type!r}. Valid: {sorted(_VALID_POLICY_TYPES)}"
            )

        cloud_provider = data.get("cloud_provider", "multi_cloud")
        if cloud_provider not in _VALID_CLOUD_PROVIDERS:
            cloud_provider = "multi_cloud"

        enforcement = data.get("enforcement", "advisory")
        if enforcement not in _VALID_ENFORCEMENTS:
            enforcement = "advisory"

        policy_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO governance_policies
                        (id, org_id, name, policy_type, cloud_provider, enforcement,
                         description, violation_count, status, created_at)
                    VALUES (?,?,?,?,?,?,?,0,?,?)
                    """,
                    (
                        policy_id, org_id, name, policy_type, cloud_provider,
                        enforcement, data.get("description", ""), "active", now,
                    ),
                )

        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ASSET_DISCOVERED", {"entity_type": "cloud_governance", "org_id": org_id, "source_engine": "cloud_governance"})
            except Exception:
                pass

        return {
            "id": policy_id,
            "org_id": org_id,
            "name": name,
            "policy_type": policy_type,
            "cloud_provider": cloud_provider,
            "enforcement": enforcement,
            "description": data.get("description", ""),
            "violation_count": 0,
            "status": "active",
            "created_at": now,
        }

    def list_governance_policies(
        self,
        org_id: str,
        policy_type: Optional[str] = None,
        cloud_provider: Optional[str] = None,
        enforcement: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List governance policies for an org with optional filters."""
        query = "SELECT * FROM governance_policies WHERE org_id=?"
        params: List[Any] = [org_id]

        if policy_type:
            query += " AND policy_type=?"
            params.append(policy_type)
        if cloud_provider:
            query += " AND cloud_provider=?"
            params.append(cloud_provider)
        if enforcement:
            query += " AND enforcement=?"
            params.append(enforcement)

        query += " ORDER BY created_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_governance_policy(self, org_id: str, policy_id: str) -> Optional[Dict[str, Any]]:
        """Return a single governance policy or None if not found."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM governance_policies WHERE org_id=? AND id=?",
                (org_id, policy_id),
            ).fetchone()
        return dict(row) if row else None

    # ------------------------------------------------------------------
    # Violations
    # ------------------------------------------------------------------

    def record_violation(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a policy violation and increment the policy's violation_count."""
        policy_id = data.get("policy_id", "").strip()
        if not policy_id:
            raise ValueError("policy_id is required")

        resource_id = data.get("resource_id", "").strip()
        if not resource_id:
            raise ValueError("resource_id is required")

        resource_type = data.get("resource_type", "").strip()
        if not resource_type:
            raise ValueError("resource_type is required")

        violation_details = data.get("violation_details", "")

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            severity = "medium"

        violation_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO governance_violations
                        (id, org_id, policy_id, resource_id, resource_type,
                         violation_details, severity, status, detected_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        violation_id, org_id, policy_id, resource_id, resource_type,
                        violation_details, severity, "open", now,
                    ),
                )
                conn.execute(
                    """
                    UPDATE governance_policies
                       SET violation_count = violation_count + 1
                     WHERE org_id=? AND id=?
                    """,
                    (org_id, policy_id),
                )

        return {
            "id": violation_id,
            "org_id": org_id,
            "policy_id": policy_id,
            "resource_id": resource_id,
            "resource_type": resource_type,
            "violation_details": violation_details,
            "severity": severity,
            "status": "open",
            "remediated_by": None,
            "action_taken": None,
            "detected_at": now,
            "remediated_at": None,
        }

    def list_violations(
        self,
        org_id: str,
        policy_id: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List violations for an org with optional filters. Returns up to 100 ordered by detected_at DESC."""
        query = "SELECT * FROM governance_violations WHERE org_id=?"
        params: List[Any] = [org_id]

        if policy_id:
            query += " AND policy_id=?"
            params.append(policy_id)
        if severity:
            query += " AND severity=?"
            params.append(severity)
        if status:
            query += " AND status=?"
            params.append(status)

        query += " ORDER BY detected_at DESC LIMIT 100"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def remediate_violation(
        self,
        org_id: str,
        violation_id: str,
        remediated_by: str,
        action_taken: str,
    ) -> Optional[Dict[str, Any]]:
        """Mark a violation as remediated."""
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._conn() as conn:
                cursor = conn.execute(
                    """
                    UPDATE governance_violations
                       SET status='remediated', remediated_by=?, action_taken=?, remediated_at=?
                     WHERE org_id=? AND id=?
                    """,
                    (remediated_by, action_taken, now, org_id, violation_id),
                )
                if cursor.rowcount == 0:
                    return None
                row = conn.execute(
                    "SELECT * FROM governance_violations WHERE org_id=? AND id=?",
                    (org_id, violation_id),
                ).fetchone()
        return dict(row) if row else None

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_governance_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated governance statistics for an org."""
        with self._conn() as conn:
            # Policy stats
            pol_rows = conn.execute(
                "SELECT policy_type, enforcement, COUNT(*) as cnt "
                "FROM governance_policies WHERE org_id=? GROUP BY policy_type, enforcement",
                (org_id,),
            ).fetchall()

            total_policies = conn.execute(
                "SELECT COUNT(*) FROM governance_policies WHERE org_id=?",
                (org_id,),
            ).fetchone()[0]

            # Violation stats
            viol_rows = conn.execute(
                "SELECT status, severity, COUNT(*) as cnt "
                "FROM governance_violations WHERE org_id=? GROUP BY status, severity",
                (org_id,),
            ).fetchall()

            total_violations = conn.execute(
                "SELECT COUNT(*) FROM governance_violations WHERE org_id=?",
                (org_id,),
            ).fetchone()[0]

        by_type: Dict[str, int] = {}
        by_enforcement: Dict[str, int] = {}
        for row in pol_rows:
            pt = row["policy_type"]
            en = row["enforcement"]
            cnt = row["cnt"]
            by_type[pt] = by_type.get(pt, 0) + cnt
            by_enforcement[en] = by_enforcement.get(en, 0) + cnt

        open_violations = 0
        critical_violations = 0
        remediated_violations = 0
        for row in viol_rows:
            cnt = row["cnt"]
            if row["status"] == "open":
                open_violations += cnt
            if row["severity"] == "critical" and row["status"] == "open":
                critical_violations += cnt
            if row["status"] == "remediated":
                remediated_violations += cnt

        raw_score = 100 - (open_violations / (total_violations or 1) * 100)
        compliance_score = round(max(0.0, min(100.0, raw_score)), 2)

        return {
            "total_policies": total_policies,
            "by_type": by_type,
            "by_enforcement": by_enforcement,
            "total_violations": total_violations,
            "open_violations": open_violations,
            "critical_violations": critical_violations,
            "remediated_violations": remediated_violations,
            "compliance_score": compliance_score,
        }


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_instances: Dict[str, CloudGovernanceEngine] = {}
_instances_lock = threading.Lock()


def _db_path_for_org(org_id: str) -> str:
    base = Path(__file__).resolve().parents[2] / ".fixops_data"
    return str(base / f"cloud_governance_{org_id}.db")


def get_engine(org_id: str) -> CloudGovernanceEngine:
    with _instances_lock:
        if org_id not in _instances:
            _instances[org_id] = CloudGovernanceEngine(db_path=_db_path_for_org(org_id))
        return _instances[org_id]
