"""Supply Chain Monitoring Engine — ALDECI.

Tracks suppliers, risk assessments, and supply chain events.
Multi-tenant via org_id.  SQLite WAL + threading.RLock for concurrency safety.
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "supply_chain_monitoring.db"
)

_VALID_SUPPLIER_TYPES = {"software", "hardware", "services", "cloud", "logistics", "manufacturing"}
_VALID_RISK_TIERS = {"critical", "high", "medium", "low"}
_VALID_EVENT_TYPES = {
    "breach", "disruption", "compliance_violation", "performance_issue",
    "contract_breach", "bankruptcy",
}
_VALID_SEVERITIES = {"low", "medium", "high", "critical"}


class SupplyChainMonitoringEngine:
    """SQLite WAL-backed Supply Chain Monitoring engine.

    Thread-safe via RLock.  Multi-tenant via org_id.
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
                CREATE TABLE IF NOT EXISTS scm_suppliers (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    name          TEXT NOT NULL DEFAULT '',
                    supplier_type TEXT NOT NULL DEFAULT 'services',
                    risk_tier     TEXT NOT NULL DEFAULT 'medium',
                    risk_score    REAL NOT NULL DEFAULT 50.0,
                    risk_level    TEXT NOT NULL DEFAULT 'medium',
                    contact_email TEXT NOT NULL DEFAULT '',
                    website       TEXT NOT NULL DEFAULT '',
                    assessed_at   DATETIME,
                    status        TEXT NOT NULL DEFAULT 'active',
                    created_at    DATETIME
                );
                CREATE INDEX IF NOT EXISTS idx_scms_org
                    ON scm_suppliers (org_id);

                CREATE TABLE IF NOT EXISTS scm_events (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    supplier_id TEXT NOT NULL,
                    event_type  TEXT NOT NULL DEFAULT '',
                    severity    TEXT NOT NULL DEFAULT 'medium',
                    description TEXT NOT NULL DEFAULT '',
                    status      TEXT NOT NULL DEFAULT 'open',
                    event_at    DATETIME,
                    resolved_at DATETIME,
                    resolution  TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_scme_org
                    ON scm_events (org_id, event_at DESC);
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
    # Suppliers
    # ------------------------------------------------------------------

    def register_supplier(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new supplier. Validates name, supplier_type, and risk_tier."""
        name = data.get("name", "").strip()
        if not name:
            raise ValueError("name is required")

        supplier_type = data.get("supplier_type", "")
        if supplier_type not in _VALID_SUPPLIER_TYPES:
            raise ValueError(
                f"supplier_type must be one of {sorted(_VALID_SUPPLIER_TYPES)}, got {supplier_type!r}"
            )

        risk_tier = data.get("risk_tier", "medium")
        if risk_tier not in _VALID_RISK_TIERS:
            raise ValueError(
                f"risk_tier must be one of {sorted(_VALID_RISK_TIERS)}, got {risk_tier!r}"
            )

        supplier_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO scm_suppliers
                        (id, org_id, name, supplier_type, risk_tier, risk_score, risk_level,
                         contact_email, website, assessed_at, status, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        supplier_id, org_id, name, supplier_type, risk_tier,
                        50.0, "medium",
                        data.get("contact_email", ""),
                        data.get("website", ""),
                        None,
                        "active",
                        now,
                    ),
                )

        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "supply_chain_monitoring", "org_id": org_id, "source_engine": "supply_chain_monitoring"})
            except Exception:
                pass

        return {
            "id": supplier_id,
            "org_id": org_id,
            "name": name,
            "supplier_type": supplier_type,
            "risk_tier": risk_tier,
            "risk_score": 50.0,
            "risk_level": "medium",
            "contact_email": data.get("contact_email", ""),
            "website": data.get("website", ""),
            "assessed_at": None,
            "status": "active",
            "created_at": now,
        }

    def list_suppliers(
        self,
        org_id: str,
        supplier_type: Optional[str] = None,
        risk_tier: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List suppliers for an org with optional type/tier filters."""
        query = "SELECT * FROM scm_suppliers WHERE org_id=?"
        params: list = [org_id]
        if supplier_type:
            query += " AND supplier_type=?"
            params.append(supplier_type)
        if risk_tier:
            query += " AND risk_tier=?"
            params.append(risk_tier)
        query += " ORDER BY name"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def get_supplier(self, org_id: str, supplier_id: str) -> Optional[Dict[str, Any]]:
        """Return a single supplier or None if not found."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM scm_suppliers WHERE org_id=? AND id=?",
                (org_id, supplier_id),
            ).fetchone()
        return self._row(row) if row else None

    def assess_supplier_risk(
        self, org_id: str, supplier_id: str, assessment_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Run a risk assessment against a supplier.

        risk_score = 100
                     - (security_certifications * 20)
                     + (incident_history * 30)
                     - (financial_stability * 10)
                     - (compliance_status * 10)
                     - (business_continuity * 10)
        Clamped 0-100.  risk_level: <=30=low, 31-60=medium, 61-80=high, >80=critical.
        """
        security_certifications = bool(assessment_data.get("security_certifications", False))
        incident_history = bool(assessment_data.get("incident_history", False))
        financial_stability = bool(assessment_data.get("financial_stability", False))
        compliance_status = bool(assessment_data.get("compliance_status", False))
        business_continuity = bool(assessment_data.get("business_continuity", False))

        risk_score = (
            100
            - (int(security_certifications) * 20)
            + (int(incident_history) * 30)
            - (int(financial_stability) * 10)
            - (int(compliance_status) * 10)
            - (int(business_continuity) * 10)
        )
        risk_score = max(0, min(100, risk_score))

        if risk_score <= 30:
            risk_level = "low"
        elif risk_score <= 60:
            risk_level = "medium"
        elif risk_score <= 80:
            risk_level = "high"
        else:
            risk_level = "critical"

        assessed_at = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    UPDATE scm_suppliers
                       SET risk_score=?, risk_level=?, assessed_at=?
                     WHERE org_id=? AND id=?
                    """,
                    (risk_score, risk_level, assessed_at, org_id, supplier_id),
                )

        return {
            "supplier_id": supplier_id,
            "org_id": org_id,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "assessed_at": assessed_at,
            "factors": {
                "security_certifications": security_certifications,
                "incident_history": incident_history,
                "financial_stability": financial_stability,
                "compliance_status": compliance_status,
                "business_continuity": business_continuity,
            },
        }

    # ------------------------------------------------------------------
    # Events
    # ------------------------------------------------------------------

    def record_supply_chain_event(
        self, org_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Record a supply chain event (breach, disruption, etc.)."""
        supplier_id = data.get("supplier_id", "")
        if not supplier_id:
            raise ValueError("supplier_id is required")

        event_type = data.get("event_type", "")
        if event_type not in _VALID_EVENT_TYPES:
            raise ValueError(
                f"event_type must be one of {sorted(_VALID_EVENT_TYPES)}, got {event_type!r}"
            )

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(
                f"severity must be one of {sorted(_VALID_SEVERITIES)}, got {severity!r}"
            )

        event_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO scm_events
                        (id, org_id, supplier_id, event_type, severity,
                         description, status, event_at, resolved_at, resolution)
                    VALUES (?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        event_id, org_id, supplier_id, event_type, severity,
                        data.get("description", ""),
                        "open",
                        now,
                        None,
                        "",
                    ),
                )

        return {
            "id": event_id,
            "org_id": org_id,
            "supplier_id": supplier_id,
            "event_type": event_type,
            "severity": severity,
            "description": data.get("description", ""),
            "status": "open",
            "event_at": now,
            "resolved_at": None,
            "resolution": "",
        }

    def list_events(
        self,
        org_id: str,
        supplier_id: Optional[str] = None,
        event_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List supply chain events with optional filters."""
        query = "SELECT * FROM scm_events WHERE org_id=?"
        params: list = [org_id]
        if supplier_id:
            query += " AND supplier_id=?"
            params.append(supplier_id)
        if event_type:
            query += " AND event_type=?"
            params.append(event_type)
        if status:
            query += " AND status=?"
            params.append(status)
        query += " ORDER BY event_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def resolve_event(
        self, org_id: str, event_id: str, resolution: str
    ) -> Dict[str, Any]:
        """Resolve a supply chain event."""
        resolved_at = datetime.now(timezone.utc).isoformat()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    UPDATE scm_events
                       SET status='resolved', resolved_at=?, resolution=?
                     WHERE org_id=? AND id=?
                    """,
                    (resolved_at, resolution, org_id, event_id),
                )

        return {
            "event_id": event_id,
            "org_id": org_id,
            "status": "resolved",
            "resolved_at": resolved_at,
            "resolution": resolution,
        }

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_supply_chain_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate supply chain stats for an org."""
        with self._conn() as conn:
            total_suppliers = conn.execute(
                "SELECT COUNT(*) FROM scm_suppliers WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            avg_risk_score = conn.execute(
                "SELECT COALESCE(AVG(risk_score), 0) FROM scm_suppliers WHERE org_id=?",
                (org_id,),
            ).fetchone()[0]

            high_risk_suppliers = conn.execute(
                "SELECT COUNT(*) FROM scm_suppliers WHERE org_id=? AND risk_score > 60",
                (org_id,),
            ).fetchone()[0]

            open_events = conn.execute(
                "SELECT COUNT(*) FROM scm_events WHERE org_id=? AND status='open'",
                (org_id,),
            ).fetchone()[0]

            critical_events = conn.execute(
                "SELECT COUNT(*) FROM scm_events WHERE org_id=? AND severity='critical'",
                (org_id,),
            ).fetchone()[0]

            # by_tier
            tier_rows = conn.execute(
                "SELECT risk_tier, COUNT(*) AS cnt FROM scm_suppliers WHERE org_id=? GROUP BY risk_tier",
                (org_id,),
            ).fetchall()
            by_tier = {r["risk_tier"]: r["cnt"] for r in tier_rows}

            # by_event_type
            et_rows = conn.execute(
                "SELECT event_type, COUNT(*) AS cnt FROM scm_events WHERE org_id=? GROUP BY event_type",
                (org_id,),
            ).fetchall()
            by_event_type = {r["event_type"]: r["cnt"] for r in et_rows}

        return {
            "org_id": org_id,
            "total_suppliers": total_suppliers,
            "by_tier": by_tier,
            "avg_risk_score": round(float(avg_risk_score), 2),
            "high_risk_suppliers": high_risk_suppliers,
            "open_events": open_events,
            "critical_events": critical_events,
            "by_event_type": by_event_type,
        }
