"""Data Governance Engine — ALDECI.

Manage data assets, governance policies, policy violations, and data flows
for enterprise data governance, privacy compliance, and regulatory adherence.

Compliance: GDPR, CCPA, HIPAA, PCI-DSS, ISO 27001.
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "data_governance.db"
)

_ASSET_TYPES = {"database", "file_share", "cloud_storage", "api_endpoint", "data_stream"}
_CLASSIFICATIONS = {"public", "internal", "confidential", "restricted", "secret"}
_DATA_CATEGORIES = {"PII", "PHI", "PCI", "financial", "IP"}
_POLICY_TYPES = {"retention", "access", "encryption", "transfer", "deletion"}
_POLICY_STATUSES = {"active", "inactive", "draft"}
_ENFORCEMENT_MODES = {"manual", "automated", "advisory"}
_SEVERITIES = {"critical", "high", "medium", "low"}
_FLOW_TYPES = {"internal", "external", "cross_border"}


class DataGovernanceEngine:
    """SQLite WAL-backed Data Governance engine.

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
                CREATE TABLE IF NOT EXISTS data_assets (
                    asset_id            TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    name                TEXT NOT NULL,
                    description         TEXT NOT NULL DEFAULT '',
                    asset_type          TEXT NOT NULL DEFAULT 'database',
                    classification      TEXT NOT NULL DEFAULT 'internal',
                    owner               TEXT NOT NULL DEFAULT '',
                    data_categories     TEXT NOT NULL DEFAULT '[]',
                    retention_days      INTEGER NOT NULL DEFAULT 365,
                    location            TEXT NOT NULL DEFAULT '',
                    encrypted           INTEGER NOT NULL DEFAULT 0,
                    last_audited        DATETIME,
                    created_at          DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_asset_org
                    ON data_assets (org_id, classification);

                CREATE TABLE IF NOT EXISTS governance_policies (
                    policy_id               TEXT PRIMARY KEY,
                    org_id                  TEXT NOT NULL,
                    name                    TEXT NOT NULL,
                    description             TEXT NOT NULL DEFAULT '',
                    policy_type             TEXT NOT NULL DEFAULT 'retention',
                    applies_to_classification TEXT NOT NULL DEFAULT '',
                    requirement             TEXT NOT NULL DEFAULT '',
                    enforcement             TEXT NOT NULL DEFAULT 'advisory',
                    status                  TEXT NOT NULL DEFAULT 'draft',
                    created_at              DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_policy_org
                    ON governance_policies (org_id, status);

                CREATE TABLE IF NOT EXISTS policy_violations (
                    violation_id    TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    asset_id        TEXT NOT NULL DEFAULT '',
                    policy_id       TEXT NOT NULL DEFAULT '',
                    violation_type  TEXT NOT NULL DEFAULT '',
                    description     TEXT NOT NULL DEFAULT '',
                    severity        TEXT NOT NULL DEFAULT 'medium',
                    detected_at     DATETIME NOT NULL,
                    resolved_at     DATETIME,
                    resolved_by     TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_violation_org
                    ON policy_violations (org_id, resolved_at);

                CREATE TABLE IF NOT EXISTS data_flows (
                    flow_id             TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    source_asset_id     TEXT NOT NULL DEFAULT '',
                    destination         TEXT NOT NULL DEFAULT '',
                    flow_type           TEXT NOT NULL DEFAULT 'internal',
                    data_categories     TEXT NOT NULL DEFAULT '[]',
                    encrypted           INTEGER NOT NULL DEFAULT 0,
                    approved            INTEGER NOT NULL DEFAULT 0,
                    created_at          DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_flow_org
                    ON data_flows (org_id, flow_type);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _parse_json_list(value: Any) -> list:
        if isinstance(value, list):
            return value
        try:
            result = json.loads(value or "[]")
            return result if isinstance(result, list) else []
        except (json.JSONDecodeError, TypeError):
            return []

    # ------------------------------------------------------------------
    # Data Assets
    # ------------------------------------------------------------------

    def register_asset(self, org_id: str, data: dict) -> dict:
        """Register a new data asset for an org."""
        asset_id = str(uuid.uuid4())
        now = self._now()

        asset_type = data.get("asset_type", "database")
        if asset_type not in _ASSET_TYPES:
            asset_type = "database"

        classification = data.get("classification", "internal")
        if classification not in _CLASSIFICATIONS:
            classification = "internal"

        data_categories = data.get("data_categories", [])
        if not isinstance(data_categories, list):
            data_categories = []
        data_categories = [c for c in data_categories if c in _DATA_CATEGORIES]

        record = {
            "asset_id": asset_id,
            "org_id": org_id,
            "name": str(data.get("name", "")),
            "description": str(data.get("description", "")),
            "asset_type": asset_type,
            "classification": classification,
            "owner": str(data.get("owner", "")),
            "data_categories": data_categories,
            "retention_days": int(data.get("retention_days", 365)),
            "location": str(data.get("location", "")),
            "encrypted": int(bool(data.get("encrypted", False))),
            "last_audited": data.get("last_audited"),
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO data_assets
                        (asset_id, org_id, name, description, asset_type, classification,
                         owner, data_categories, retention_days, location, encrypted,
                         last_audited, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        record["asset_id"], record["org_id"], record["name"],
                        record["description"], record["asset_type"], record["classification"],
                        record["owner"], json.dumps(record["data_categories"]),
                        record["retention_days"], record["location"], record["encrypted"],
                        record["last_audited"], record["created_at"],
                    ),
                )
        _logger.info("Registered data asset %s for org %s", asset_id, org_id)
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("CONTROL_ASSESSED", {"entity_type": "data_governance", "org_id": org_id, "source_engine": "data_governance"})
            except Exception:
                pass

        return record

    def list_assets(
        self,
        org_id: str,
        classification: Optional[str] = None,
        asset_type: Optional[str] = None,
    ) -> List[dict]:
        """List data assets for an org with optional filters."""
        query = "SELECT * FROM data_assets WHERE org_id=?"
        params: list = [org_id]

        if classification:
            query += " AND classification=?"
            params.append(classification)

        if asset_type:
            query += " AND asset_type=?"
            params.append(asset_type)

        query += " ORDER BY created_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()

        results = []
        for r in rows:
            d = self._row_to_dict(r)
            d["data_categories"] = self._parse_json_list(d.get("data_categories"))
            results.append(d)
        return results

    def get_asset(self, org_id: str, asset_id: str) -> Optional[dict]:
        """Fetch a single data asset by ID, scoped to org."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM data_assets WHERE asset_id=? AND org_id=?",
                (asset_id, org_id),
            ).fetchone()
        if not row:
            return None
        d = self._row_to_dict(row)
        d["data_categories"] = self._parse_json_list(d.get("data_categories"))
        return d

    def update_asset_classification(
        self, org_id: str, asset_id: str, classification: str
    ) -> bool:
        """Update an asset's classification level. Returns True if updated."""
        if classification not in _CLASSIFICATIONS:
            return False
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    "UPDATE data_assets SET classification=? WHERE asset_id=? AND org_id=?",
                    (classification, asset_id, org_id),
                )
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Governance Policies
    # ------------------------------------------------------------------

    def create_policy(self, org_id: str, data: dict) -> dict:
        """Create a new governance policy."""
        policy_id = str(uuid.uuid4())
        now = self._now()

        policy_type = data.get("policy_type", "retention")
        if policy_type not in _POLICY_TYPES:
            policy_type = "retention"

        enforcement = data.get("enforcement", "advisory")
        if enforcement not in _ENFORCEMENT_MODES:
            enforcement = "advisory"

        status = data.get("status", "draft")
        if status not in _POLICY_STATUSES:
            status = "draft"

        record = {
            "policy_id": policy_id,
            "org_id": org_id,
            "name": str(data.get("name", "")),
            "description": str(data.get("description", "")),
            "policy_type": policy_type,
            "applies_to_classification": str(data.get("applies_to_classification", "")),
            "requirement": str(data.get("requirement", "")),
            "enforcement": enforcement,
            "status": status,
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO governance_policies
                        (policy_id, org_id, name, description, policy_type,
                         applies_to_classification, requirement, enforcement, status, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        record["policy_id"], record["org_id"], record["name"],
                        record["description"], record["policy_type"],
                        record["applies_to_classification"], record["requirement"],
                        record["enforcement"], record["status"], record["created_at"],
                    ),
                )
        _logger.info("Created governance policy %s for org %s", policy_id, org_id)
        return record

    def list_policies(
        self,
        org_id: str,
        policy_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[dict]:
        """List governance policies for an org with optional filters."""
        query = "SELECT * FROM governance_policies WHERE org_id=?"
        params: list = [org_id]

        if policy_type:
            query += " AND policy_type=?"
            params.append(policy_type)

        if status:
            query += " AND status=?"
            params.append(status)

        query += " ORDER BY created_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Policy Violations
    # ------------------------------------------------------------------

    def log_violation(self, org_id: str, data: dict) -> dict:
        """Log a policy violation for an org."""
        violation_id = str(uuid.uuid4())
        now = self._now()

        severity = data.get("severity", "medium")
        if severity not in _SEVERITIES:
            severity = "medium"

        record = {
            "violation_id": violation_id,
            "org_id": org_id,
            "asset_id": str(data.get("asset_id", "")),
            "policy_id": str(data.get("policy_id", "")),
            "violation_type": str(data.get("violation_type", "")),
            "description": str(data.get("description", "")),
            "severity": severity,
            "detected_at": data.get("detected_at", now),
            "resolved_at": None,
            "resolved_by": "",
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO policy_violations
                        (violation_id, org_id, asset_id, policy_id, violation_type,
                         description, severity, detected_at, resolved_at, resolved_by)
                    VALUES (?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        record["violation_id"], record["org_id"], record["asset_id"],
                        record["policy_id"], record["violation_type"], record["description"],
                        record["severity"], record["detected_at"], record["resolved_at"],
                        record["resolved_by"],
                    ),
                )
        _logger.info("Logged policy violation %s for org %s", violation_id, org_id)
        return record

    def list_violations(
        self,
        org_id: str,
        resolved: bool = False,
        severity: Optional[str] = None,
    ) -> List[dict]:
        """List policy violations for an org."""
        if resolved:
            query = "SELECT * FROM policy_violations WHERE org_id=? AND resolved_at IS NOT NULL"
        else:
            query = "SELECT * FROM policy_violations WHERE org_id=? AND resolved_at IS NULL"
        params: list = [org_id]

        if severity:
            query += " AND severity=?"
            params.append(severity)

        query += " ORDER BY detected_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def resolve_violation(
        self, org_id: str, violation_id: str, resolved_by: str
    ) -> bool:
        """Mark a violation as resolved. Returns True if updated."""
        now = self._now()
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    """
                    UPDATE policy_violations
                    SET resolved_at=?, resolved_by=?
                    WHERE violation_id=? AND org_id=? AND resolved_at IS NULL
                    """,
                    (now, resolved_by, violation_id, org_id),
                )
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Data Flows
    # ------------------------------------------------------------------

    def add_data_flow(self, org_id: str, data: dict) -> dict:
        """Register a data flow between source and destination."""
        flow_id = str(uuid.uuid4())
        now = self._now()

        flow_type = data.get("flow_type", "internal")
        if flow_type not in _FLOW_TYPES:
            flow_type = "internal"

        data_categories = data.get("data_categories", [])
        if not isinstance(data_categories, list):
            data_categories = []

        record = {
            "flow_id": flow_id,
            "org_id": org_id,
            "source_asset_id": str(data.get("source_asset_id", "")),
            "destination": str(data.get("destination", "")),
            "flow_type": flow_type,
            "data_categories": data_categories,
            "encrypted": int(bool(data.get("encrypted", False))),
            "approved": int(bool(data.get("approved", False))),
            "created_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO data_flows
                        (flow_id, org_id, source_asset_id, destination, flow_type,
                         data_categories, encrypted, approved, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        record["flow_id"], record["org_id"], record["source_asset_id"],
                        record["destination"], record["flow_type"],
                        json.dumps(record["data_categories"]),
                        record["encrypted"], record["approved"], record["created_at"],
                    ),
                )
        _logger.info("Registered data flow %s for org %s", flow_id, org_id)
        return record

    def list_data_flows(
        self, org_id: str, flow_type: Optional[str] = None
    ) -> List[dict]:
        """List data flows for an org with optional flow_type filter."""
        query = "SELECT * FROM data_flows WHERE org_id=?"
        params: list = [org_id]

        if flow_type:
            query += " AND flow_type=?"
            params.append(flow_type)

        query += " ORDER BY created_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()

        results = []
        for r in rows:
            d = self._row_to_dict(r)
            d["data_categories"] = self._parse_json_list(d.get("data_categories"))
            results.append(d)
        return results

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_governance_stats(self, org_id: str) -> dict:
        """Return aggregate governance statistics for an org."""
        with self._conn() as conn:
            total_assets = conn.execute(
                "SELECT COUNT(*) FROM data_assets WHERE org_id=?",
                (org_id,),
            ).fetchone()[0]

            # Assets by classification
            by_classification: Dict[str, int] = {}
            for row in conn.execute(
                "SELECT classification, COUNT(*) as cnt FROM data_assets WHERE org_id=? GROUP BY classification",
                (org_id,),
            ).fetchall():
                by_classification[row[0]] = row[1]

            total_policies = conn.execute(
                "SELECT COUNT(*) FROM governance_policies WHERE org_id=?",
                (org_id,),
            ).fetchone()[0]

            active_policies = conn.execute(
                "SELECT COUNT(*) FROM governance_policies WHERE org_id=? AND status='active'",
                (org_id,),
            ).fetchone()[0]

            open_violations = conn.execute(
                "SELECT COUNT(*) FROM policy_violations WHERE org_id=? AND resolved_at IS NULL",
                (org_id,),
            ).fetchone()[0]

            critical_violations = conn.execute(
                "SELECT COUNT(*) FROM policy_violations WHERE org_id=? AND severity='critical' AND resolved_at IS NULL",
                (org_id,),
            ).fetchone()[0]

            cross_border_flows = conn.execute(
                "SELECT COUNT(*) FROM data_flows WHERE org_id=? AND flow_type='cross_border'",
                (org_id,),
            ).fetchone()[0]

            unencrypted_restricted = conn.execute(
                """
                SELECT COUNT(*) FROM data_assets
                WHERE org_id=? AND encrypted=0
                  AND classification IN ('restricted', 'secret')
                """,
                (org_id,),
            ).fetchone()[0]

        return {
            "total_assets": total_assets,
            "by_classification": by_classification,
            "total_policies": total_policies,
            "active_policies": active_policies,
            "open_violations": open_violations,
            "critical_violations": critical_violations,
            "cross_border_flows": cross_border_flows,
            "unencrypted_restricted": unencrypted_restricted,
        }
