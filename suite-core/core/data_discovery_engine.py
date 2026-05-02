"""Data Discovery Engine — ALDECI. SQLite WAL + RLock + org_id isolation.

Manages data store discovery and classification:
  - Datastore registration with type/risk_level validation
  - Discovery records with sensitivity tracking
  - Scan job lifecycle management
  - Aggregated stats across datastores and discovery types

Compliance: GDPR Art.30, CCPA, NIST SP 800-53 RA-2
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "data_discovery_engine.db"
)

_VALID_DATASTORE_TYPES = {"database", "s3", "filesystem", "api", "data_lake", "message_queue", "cache"}
_VALID_DATA_TYPES = {"pii", "phi", "financial", "credentials", "ip", "confidential", "public"}
_VALID_RISK_LEVELS = {"critical", "high", "medium", "low", "none"}
_VALID_SCAN_STATUSES = {"pending", "running", "completed", "failed"}

# severity ordering for risk escalation
_RISK_SEVERITY: Dict[str, int] = {
    "none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4,
}

# data types that bump sensitive_record_count
_SENSITIVE_DATA_TYPES = {"pii", "phi", "credentials"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class DataDiscoveryEngine:
    """SQLite WAL-backed Data Discovery engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/data_discovery_engine.db
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
                CREATE TABLE IF NOT EXISTS data_datastores (
                    id                      TEXT PRIMARY KEY,
                    org_id                  TEXT NOT NULL,
                    name                    TEXT NOT NULL DEFAULT '',
                    datastore_type          TEXT NOT NULL DEFAULT 'database',
                    location                TEXT NOT NULL DEFAULT '',
                    owner_team              TEXT NOT NULL DEFAULT '',
                    data_types_found        TEXT NOT NULL DEFAULT '',
                    risk_level              TEXT NOT NULL DEFAULT 'none',
                    last_scanned            TEXT NOT NULL DEFAULT '',
                    record_count            INTEGER NOT NULL DEFAULT 0,
                    sensitive_record_count  INTEGER NOT NULL DEFAULT 0,
                    created_at              TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_dd_datastores_org
                    ON data_datastores (org_id, datastore_type, risk_level);

                CREATE TABLE IF NOT EXISTS data_discoveries (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    datastore_id    TEXT NOT NULL,
                    data_type       TEXT NOT NULL DEFAULT 'public',
                    record_count    INTEGER NOT NULL DEFAULT 0,
                    sample_path     TEXT NOT NULL DEFAULT '',
                    confidence      INTEGER NOT NULL DEFAULT 80,
                    risk_level      TEXT NOT NULL DEFAULT 'low',
                    detected_at     TEXT NOT NULL,
                    is_classified   INTEGER NOT NULL DEFAULT 0
                );

                CREATE INDEX IF NOT EXISTS idx_dd_discoveries_org
                    ON data_discoveries (org_id, datastore_id, data_type, risk_level);

                CREATE TABLE IF NOT EXISTS discovery_scans (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    datastore_id    TEXT NOT NULL,
                    scan_status     TEXT NOT NULL DEFAULT 'pending',
                    started_at      TEXT NOT NULL DEFAULT '',
                    completed_at    TEXT NOT NULL DEFAULT '',
                    records_scanned INTEGER NOT NULL DEFAULT 0,
                    findings_count  INTEGER NOT NULL DEFAULT 0,
                    scanner_version TEXT NOT NULL DEFAULT '',
                    error_message   TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_dd_scans_org
                    ON discovery_scans (org_id, datastore_id, scan_status);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    @staticmethod
    def _parse_datastore(record: Dict[str, Any]) -> Dict[str, Any]:
        """Split data_types_found CSV back into a list."""
        raw = record.get("data_types_found", "")
        record["data_types_found"] = [t for t in raw.split(",") if t] if raw else []
        return record

    # ------------------------------------------------------------------
    # Datastores
    # ------------------------------------------------------------------

    def register_datastore(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new datastore."""
        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("name is required.")

        datastore_type = data.get("datastore_type", "database")
        if datastore_type not in _VALID_DATASTORE_TYPES:
            raise ValueError(
                f"Invalid datastore_type '{datastore_type}'. "
                f"Must be one of {sorted(_VALID_DATASTORE_TYPES)}"
            )

        risk_level = data.get("risk_level", "none")
        if risk_level not in _VALID_RISK_LEVELS:
            raise ValueError(
                f"Invalid risk_level '{risk_level}'. "
                f"Must be one of {sorted(_VALID_RISK_LEVELS)}"
            )

        # data_types_found stored as comma-joined string
        dtf_input = data.get("data_types_found", [])
        if isinstance(dtf_input, list):
            dtf_str = ",".join(str(t) for t in dtf_input)
        else:
            dtf_str = str(dtf_input)

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "name": name,
            "datastore_type": datastore_type,
            "location": data.get("location", ""),
            "owner_team": data.get("owner_team", ""),
            "data_types_found": dtf_str,
            "risk_level": risk_level,
            "last_scanned": "",
            "record_count": int(data.get("record_count", 0)),
            "sensitive_record_count": 0,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO data_datastores
                       (id, org_id, name, datastore_type, location, owner_team,
                        data_types_found, risk_level, last_scanned,
                        record_count, sensitive_record_count, created_at)
                       VALUES (:id, :org_id, :name, :datastore_type, :location,
                               :owner_team, :data_types_found, :risk_level,
                               :last_scanned, :record_count, :sensitive_record_count,
                               :created_at)""",
                    record,
                )
        # Return with list form
        record["data_types_found"] = [t for t in dtf_str.split(",") if t] if dtf_str else []
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "data_discovery", "org_id": org_id, "source_engine": "data_discovery"})
            except Exception:
                pass

        return record

    def list_datastores(
        self,
        org_id: str,
        datastore_type: Optional[str] = None,
        risk_level: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List datastores with optional filters."""
        sql = "SELECT * FROM data_datastores WHERE org_id = ?"
        params: List[Any] = [org_id]
        if datastore_type:
            sql += " AND datastore_type = ?"
            params.append(datastore_type)
        if risk_level:
            sql += " AND risk_level = ?"
            params.append(risk_level)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._parse_datastore(self._row(r)) for r in rows]

    def get_datastore(self, org_id: str, datastore_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single datastore by ID. data_types_found returned as list."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM data_datastores WHERE org_id = ? AND id = ?",
                (org_id, datastore_id),
            ).fetchone()
        if not row:
            return None
        return self._parse_datastore(self._row(row))

    # ------------------------------------------------------------------
    # Discoveries
    # ------------------------------------------------------------------

    def record_discovery(
        self,
        org_id: str,
        datastore_id: str,
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Record a data discovery finding for a datastore."""
        data_type = data.get("data_type", "")
        if data_type not in _VALID_DATA_TYPES:
            raise ValueError(
                f"Invalid data_type '{data_type}'. "
                f"Must be one of {sorted(_VALID_DATA_TYPES)}"
            )

        risk_level = data.get("risk_level", "low")
        if risk_level not in _VALID_RISK_LEVELS:
            raise ValueError(
                f"Invalid risk_level '{risk_level}'. "
                f"Must be one of {sorted(_VALID_RISK_LEVELS)}"
            )

        confidence = int(data.get("confidence", 80))
        confidence = max(0, min(100, confidence))
        is_classified = bool(data.get("is_classified", False))
        record_count = int(data.get("record_count", 0))

        now = _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "datastore_id": datastore_id,
            "data_type": data_type,
            "record_count": record_count,
            "sample_path": data.get("sample_path", ""),
            "confidence": confidence,
            "risk_level": risk_level,
            "detected_at": now,
            "is_classified": 1 if is_classified else 0,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO data_discoveries
                       (id, org_id, datastore_id, data_type, record_count,
                        sample_path, confidence, risk_level, detected_at, is_classified)
                       VALUES (:id, :org_id, :datastore_id, :data_type, :record_count,
                               :sample_path, :confidence, :risk_level, :detected_at,
                               :is_classified)""",
                    record,
                )

                # Update datastore: last_scanned
                conn.execute(
                    "UPDATE data_datastores SET last_scanned = ? WHERE org_id = ? AND id = ?",
                    (now, org_id, datastore_id),
                )

                # Increment sensitive_record_count if sensitive data type
                if data_type in _SENSITIVE_DATA_TYPES:
                    conn.execute(
                        """UPDATE data_datastores
                           SET sensitive_record_count = sensitive_record_count + ?
                           WHERE org_id = ? AND id = ?""",
                        (record_count, org_id, datastore_id),
                    )

                # Escalate datastore risk_level if new finding is higher severity
                ds_row = conn.execute(
                    "SELECT risk_level FROM data_datastores WHERE org_id = ? AND id = ?",
                    (org_id, datastore_id),
                ).fetchone()
                if ds_row:
                    current_sev = _RISK_SEVERITY.get(ds_row["risk_level"], 0)
                    new_sev = _RISK_SEVERITY.get(risk_level, 0)
                    if new_sev > current_sev:
                        conn.execute(
                            "UPDATE data_datastores SET risk_level = ? WHERE org_id = ? AND id = ?",
                            (risk_level, org_id, datastore_id),
                        )

        record["is_classified"] = is_classified
        return record

    def list_discoveries(
        self,
        org_id: str,
        datastore_id: Optional[str] = None,
        data_type: Optional[str] = None,
        risk_level: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List discoveries with optional filters."""
        sql = "SELECT * FROM data_discoveries WHERE org_id = ?"
        params: List[Any] = [org_id]
        if datastore_id:
            sql += " AND datastore_id = ?"
            params.append(datastore_id)
        if data_type:
            sql += " AND data_type = ?"
            params.append(data_type)
        if risk_level:
            sql += " AND risk_level = ?"
            params.append(risk_level)
        sql += " ORDER BY detected_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        result = []
        for r in rows:
            d = self._row(r)
            d["is_classified"] = bool(d["is_classified"])
            result.append(d)
        return result

    # ------------------------------------------------------------------
    # Scan Jobs
    # ------------------------------------------------------------------

    def create_scan_job(
        self,
        org_id: str,
        datastore_id: str,
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Create a new scan job for a datastore."""
        _now_iso()
        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "datastore_id": datastore_id,
            "scan_status": "pending",
            "started_at": data.get("started_at", ""),
            "completed_at": "",
            "records_scanned": int(data.get("records_scanned", 0)),
            "findings_count": int(data.get("findings_count", 0)),
            "scanner_version": data.get("scanner_version", ""),
            "error_message": "",
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO discovery_scans
                       (id, org_id, datastore_id, scan_status, started_at,
                        completed_at, records_scanned, findings_count,
                        scanner_version, error_message)
                       VALUES (:id, :org_id, :datastore_id, :scan_status, :started_at,
                               :completed_at, :records_scanned, :findings_count,
                               :scanner_version, :error_message)""",
                    record,
                )
        return record

    def list_scan_jobs(
        self,
        org_id: str,
        datastore_id: Optional[str] = None,
        scan_status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List scan jobs with optional filters."""
        sql = "SELECT * FROM discovery_scans WHERE org_id = ?"
        params: List[Any] = [org_id]
        if datastore_id:
            sql += " AND datastore_id = ?"
            params.append(datastore_id)
        if scan_status:
            sql += " AND scan_status = ?"
            params.append(scan_status)
        sql += " ORDER BY id DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_discovery_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated discovery statistics for an org."""
        with self._conn() as conn:
            total_datastores = conn.execute(
                "SELECT COUNT(*) FROM data_datastores WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            high_risk_datastores = conn.execute(
                """SELECT COUNT(*) FROM data_datastores
                   WHERE org_id = ? AND risk_level IN ('critical', 'high')""",
                (org_id,),
            ).fetchone()[0]

            total_discoveries = conn.execute(
                "SELECT COUNT(*) FROM data_discoveries WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            # datastores that have at least one pii discovery
            pii_datastores = conn.execute(
                """SELECT COUNT(DISTINCT datastore_id) FROM data_discoveries
                   WHERE org_id = ? AND data_type = 'pii'""",
                (org_id,),
            ).fetchone()[0]

            total_sensitive_records = conn.execute(
                """SELECT COALESCE(SUM(sensitive_record_count), 0)
                   FROM data_datastores WHERE org_id = ?""",
                (org_id,),
            ).fetchone()[0]

            type_rows = conn.execute(
                """SELECT datastore_type, COUNT(*) as cnt
                   FROM data_datastores WHERE org_id = ?
                   GROUP BY datastore_type""",
                (org_id,),
            ).fetchall()
            by_datastore_type = {r["datastore_type"]: r["cnt"] for r in type_rows}

            dt_rows = conn.execute(
                """SELECT data_type, COUNT(*) as cnt
                   FROM data_discoveries WHERE org_id = ?
                   GROUP BY data_type""",
                (org_id,),
            ).fetchall()
            by_data_type = {r["data_type"]: r["cnt"] for r in dt_rows}

        return {
            "total_datastores": total_datastores,
            "high_risk_datastores": high_risk_datastores,
            "total_discoveries": total_discoveries,
            "pii_datastores": pii_datastores,
            "total_sensitive_records": total_sensitive_records,
            "by_datastore_type": by_datastore_type,
            "by_data_type": by_data_type,
        }

    # ------------------------------------------------------------------
    # GAP-065 — Architecture-aware graph: link datastore to layer
    # ------------------------------------------------------------------

    def link_to_layer(
        self,
        org_id: str,
        datastore_ref: str,
        layer: str = "data",
    ) -> Dict[str, Any]:
        """Associate a datastore node with its architecture layer.

        Delegates the write to SecurityDependencyMappingEngine's
        layer_classifications table — no schema change on this engine.

        Fails gracefully if the dependency mapping engine is unavailable.
        """
        if not datastore_ref:
            raise ValueError("datastore_ref is required")
        try:
            from core.security_dependency_mapping_engine import (
                SecurityDependencyMappingEngine,
            )
        except ImportError:
            _logger.warning(
                "data_discovery.link_to_layer.dep_map_missing org=%s datastore=%s",
                org_id, datastore_ref,
            )
            return {
                "node_ref": datastore_ref,
                "layer": layer,
                "confidence": 0.0,
                "signals": ["dep_map_unavailable"],
                "linked": False,
            }

        dep = SecurityDependencyMappingEngine()
        record = dep.upsert_layer(
            org_id=org_id,
            node_ref=datastore_ref,
            layer=layer,
            confidence=0.95,
            signals=["data_discovery_link"],
        )
        record["linked"] = True
        _logger.info(
            "data_discovery.linked org=%s datastore=%s layer=%s",
            org_id, datastore_ref, layer,
        )
        return record
