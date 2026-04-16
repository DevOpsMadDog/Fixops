"""Supply Chain Risk Engine — ALDECI.

Tracks third-party suppliers, software components, SBOM data, and supply-chain risks.

Capabilities:
  - Supplier registry with risk tiering (critical / high / medium / low)
  - Component inventory with PURL, license, EOL and CVE tracking
  - Supply-chain risk register (single_source, eol, geo_political, breach_history, etc.)
  - SBOM import (parse component list, detect EOL, count CVEs)

Compliance: NIST SP 800-161r1 (C-SCRM), EO 14028, CISA SBOM guidance
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "supply_chain_risk.db"
)

_VALID_CATEGORIES = {"software", "hardware", "service", "cloud"}
_VALID_RISK_TIERS = {"critical", "high", "medium", "low"}
_VALID_COMPONENT_TYPES = {"library", "container", "firmware", "service"}
_VALID_RISK_TYPES = {
    "single_source",
    "eol",
    "geo_political",
    "breach_history",
    "no_audit",
    "license_violation",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_VALID_RISK_STATUSES = {"open", "mitigated", "accepted"}


class SupplyChainRiskEngine:
    """SQLite WAL-backed Supply Chain Risk engine.

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
                CREATE TABLE IF NOT EXISTS suppliers (
                    supplier_id       TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    name              TEXT NOT NULL,
                    category          TEXT NOT NULL DEFAULT 'software',
                    country           TEXT NOT NULL DEFAULT '',
                    risk_tier         TEXT NOT NULL DEFAULT 'medium',
                    compliance_score  REAL NOT NULL DEFAULT 0.0,
                    last_assessed     DATETIME,
                    contacts          TEXT NOT NULL DEFAULT '[]',
                    created_at        DATETIME NOT NULL,
                    updated_at        DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_sc_sup_org
                    ON suppliers (org_id, risk_tier);

                CREATE TABLE IF NOT EXISTS supply_components (
                    component_id    TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    supplier_id     TEXT NOT NULL,
                    name            TEXT NOT NULL,
                    version         TEXT NOT NULL DEFAULT '',
                    component_type  TEXT NOT NULL DEFAULT 'library',
                    license         TEXT NOT NULL DEFAULT '',
                    cve_count       INTEGER NOT NULL DEFAULT 0,
                    is_eol          INTEGER NOT NULL DEFAULT 0,
                    purl            TEXT NOT NULL DEFAULT '',
                    created_at      DATETIME NOT NULL,
                    updated_at      DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_sc_comp_org
                    ON supply_components (org_id, supplier_id);

                CREATE INDEX IF NOT EXISTS idx_sc_comp_eol
                    ON supply_components (org_id, is_eol);

                CREATE TABLE IF NOT EXISTS supply_risks (
                    risk_id       TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    supplier_id   TEXT NOT NULL DEFAULT '',
                    risk_type     TEXT NOT NULL,
                    severity      TEXT NOT NULL DEFAULT 'medium',
                    description   TEXT NOT NULL DEFAULT '',
                    status        TEXT NOT NULL DEFAULT 'open',
                    created_at    DATETIME NOT NULL,
                    updated_at    DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_sc_risk_org
                    ON supply_risks (org_id, status);

                CREATE TABLE IF NOT EXISTS sbom_entries (
                    entry_id      TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    name          TEXT NOT NULL,
                    version       TEXT NOT NULL DEFAULT '',
                    purl          TEXT NOT NULL DEFAULT '',
                    license       TEXT NOT NULL DEFAULT '',
                    cve_count     INTEGER NOT NULL DEFAULT 0,
                    is_eol        INTEGER NOT NULL DEFAULT 0,
                    import_batch  TEXT NOT NULL DEFAULT '',
                    created_at    DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_sbom_org
                    ON sbom_entries (org_id, import_batch);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        if "is_eol" in d:
            d["is_eol"] = bool(d["is_eol"])
        if "contacts" in d:
            d["contacts"] = json.loads(d.get("contacts") or "[]")
        return d

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # Suppliers
    # ------------------------------------------------------------------

    def add_supplier(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new supplier."""
        supplier_id = str(uuid.uuid4())
        now = self._now()

        category = data.get("category", "software")
        if category not in _VALID_CATEGORIES:
            category = "software"

        risk_tier = data.get("risk_tier", "medium")
        if risk_tier not in _VALID_RISK_TIERS:
            risk_tier = "medium"

        contacts = data.get("contacts", [])
        if isinstance(contacts, str):
            try:
                contacts = json.loads(contacts)
            except Exception:
                contacts = []

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO suppliers
                        (supplier_id, org_id, name, category, country, risk_tier,
                         compliance_score, last_assessed, contacts, created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        supplier_id,
                        org_id,
                        data.get("name", ""),
                        category,
                        data.get("country", ""),
                        risk_tier,
                        float(data.get("compliance_score", 0.0)),
                        data.get("last_assessed"),
                        json.dumps(contacts),
                        now,
                        now,
                    ),
                )
                row = conn.execute(
                    "SELECT * FROM suppliers WHERE supplier_id=?",
                    (supplier_id,),
                ).fetchone()
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("RISK_ASSESSED", {"entity_type": "supply_chain_risk", "org_id": org_id, "source_engine": "supply_chain_risk"})
            except Exception:
                pass

        return self._row(row)

    def list_suppliers(
        self,
        org_id: str,
        risk_tier: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List suppliers, optionally filtered by risk tier."""
        query = "SELECT * FROM suppliers WHERE org_id=?"
        params: list = [org_id]
        if risk_tier:
            query += " AND risk_tier=?"
            params.append(risk_tier)
        query += " ORDER BY name ASC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Components
    # ------------------------------------------------------------------

    def add_component(
        self,
        org_id: str,
        supplier_id: str,
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Add a software/hardware component for a supplier."""
        component_id = str(uuid.uuid4())
        now = self._now()

        component_type = data.get("component_type", "library")
        if component_type not in _VALID_COMPONENT_TYPES:
            component_type = "library"

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO supply_components
                        (component_id, org_id, supplier_id, name, version,
                         component_type, license, cve_count, is_eol, purl,
                         created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        component_id,
                        org_id,
                        supplier_id,
                        data.get("name", ""),
                        data.get("version", ""),
                        component_type,
                        data.get("license", ""),
                        int(data.get("cve_count", 0)),
                        1 if data.get("is_eol") else 0,
                        data.get("purl", ""),
                        now,
                        now,
                    ),
                )
                row = conn.execute(
                    "SELECT * FROM supply_components WHERE component_id=?",
                    (component_id,),
                ).fetchone()
        return self._row(row)

    def list_components(
        self,
        org_id: str,
        supplier_id: Optional[str] = None,
        is_eol: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        """List components, optionally filtered by supplier and/or EOL status."""
        query = "SELECT * FROM supply_components WHERE org_id=?"
        params: list = [org_id]
        if supplier_id is not None:
            query += " AND supplier_id=?"
            params.append(supplier_id)
        if is_eol is not None:
            query += " AND is_eol=?"
            params.append(1 if is_eol else 0)
        query += " ORDER BY name ASC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Risks
    # ------------------------------------------------------------------

    def add_risk(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a supply-chain risk."""
        risk_id = str(uuid.uuid4())
        now = self._now()

        risk_type = data.get("risk_type", "single_source")
        if risk_type not in _VALID_RISK_TYPES:
            risk_type = "single_source"

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            severity = "medium"

        status = data.get("status", "open")
        if status not in _VALID_RISK_STATUSES:
            status = "open"

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO supply_risks
                        (risk_id, org_id, supplier_id, risk_type, severity,
                         description, status, created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        risk_id,
                        org_id,
                        data.get("supplier_id", ""),
                        risk_type,
                        severity,
                        data.get("description", ""),
                        status,
                        now,
                        now,
                    ),
                )
                row = conn.execute(
                    "SELECT * FROM supply_risks WHERE risk_id=?",
                    (risk_id,),
                ).fetchone()
        return self._row(row)

    def list_risks(
        self,
        org_id: str,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List supply-chain risks, optionally filtered by status."""
        query = "SELECT * FROM supply_risks WHERE org_id=?"
        params: list = [org_id]
        if status:
            query += " AND status=?"
            params.append(status)
        query += " ORDER BY created_at DESC"

        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # SBOM Import
    # ------------------------------------------------------------------

    def import_sbom(self, org_id: str, sbom_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse an SBOM dict and store entries.

        Expected format::

            {
                "components": [
                    {
                        "name": "log4j-core",
                        "version": "2.14.1",
                        "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
                        "license": "Apache-2.0",
                        "cve_count": 3,
                        "is_eol": false
                    },
                    ...
                ]
            }

        Returns summary statistics.
        """
        components = sbom_data.get("components", [])
        now = self._now()
        batch_id = str(uuid.uuid4())

        imported = 0
        eol_detected = 0
        total_cves = 0

        with self._lock:
            with self._conn() as conn:
                for comp in components:
                    if not isinstance(comp, dict):
                        continue
                    entry_id = str(uuid.uuid4())
                    is_eol = bool(comp.get("is_eol", False))
                    cve_count = int(comp.get("cve_count", 0))

                    conn.execute(
                        """
                        INSERT INTO sbom_entries
                            (entry_id, org_id, name, version, purl, license,
                             cve_count, is_eol, import_batch, created_at)
                        VALUES (?,?,?,?,?,?,?,?,?,?)
                        """,
                        (
                            entry_id,
                            org_id,
                            comp.get("name", ""),
                            comp.get("version", ""),
                            comp.get("purl", ""),
                            comp.get("license", ""),
                            cve_count,
                            1 if is_eol else 0,
                            batch_id,
                            now,
                        ),
                    )
                    imported += 1
                    if is_eol:
                        eol_detected += 1
                    total_cves += cve_count

        return {
            "imported": imported,
            "eol_detected": eol_detected,
            "cve_count": total_cves,
            "batch_id": batch_id,
        }

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_supply_chain_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated supply-chain statistics for an org."""
        with self._conn() as conn:
            sup_row = conn.execute(
                "SELECT COUNT(*) AS total, "
                "SUM(CASE WHEN risk_tier='critical' THEN 1 ELSE 0 END) AS critical, "
                "AVG(compliance_score) AS avg_score "
                "FROM suppliers WHERE org_id=?",
                (org_id,),
            ).fetchone()

            comp_row = conn.execute(
                "SELECT COUNT(*) AS total, "
                "SUM(CASE WHEN is_eol=1 THEN 1 ELSE 0 END) AS eol "
                "FROM supply_components WHERE org_id=?",
                (org_id,),
            ).fetchone()

            risk_row = conn.execute(
                "SELECT COUNT(*) AS cnt FROM supply_risks WHERE org_id=? AND status='open'",
                (org_id,),
            ).fetchone()

        return {
            "total_suppliers": sup_row["total"] or 0,
            "critical_tier": sup_row["critical"] or 0,
            "total_components": comp_row["total"] or 0,
            "eol_components": comp_row["eol"] or 0,
            "open_risks": risk_row["cnt"] or 0,
            "avg_compliance_score": round(sup_row["avg_score"] or 0.0, 1),
        }
