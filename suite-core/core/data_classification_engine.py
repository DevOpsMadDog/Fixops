"""Data Classification Engine — ALDECI.

Classifies data assets by sensitivity level, detects PII, tracks violations,
and enforces data governance policies across the organization.

Capabilities:
  - Data asset registry (databases, file shares, APIs, cloud storage, etc.)
  - Automated PII detection heuristics based on asset type
  - Classification rule management (regex/keyword/ml_model patterns)
  - Violation tracking lifecycle (open → investigating → resolved)
  - Stats aggregation per org with coverage metrics

Compliance: GDPR, CCPA, HIPAA, PCI-DSS, NIST SP 800-53 (RA-2), ISO/IEC 27001 (A.8.2)
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

_VALID_ASSET_TYPES = {
    "database", "file_share", "api_endpoint", "cloud_storage",
    "email_archive", "code_repo", "backup",
}
_VALID_CLASSIFICATION_LEVELS = {"public", "internal", "confidential", "restricted", "secret"}
_VALID_CLASSIFICATION_METHODS = {"manual", "auto", "ml"}
_VALID_PII_TYPES = {"email", "phone", "ssn", "credit_card", "dob", "name", "address", "passport"}
_VALID_DATA_RESIDENCY = {"us", "eu", "apac", "global"}
_VALID_PATTERN_TYPES = {"regex", "keyword", "ml_model"}
_VALID_SCAN_TYPES = {"manual", "scheduled", "triggered"}
_VALID_VIOLATION_TYPES = {
    "misclassified", "unclassified", "pii_exposed", "retention_breach", "cross_border",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_VIOLATION_STATUSES = {"open", "investigating", "resolved"}

# ---------------------------------------------------------------------------
# PII heuristics: asset_type → likely PII types
# ---------------------------------------------------------------------------
_ASSET_PII_HEURISTICS: Dict[str, List[str]] = {
    "database": ["email", "phone", "ssn", "credit_card", "dob", "name", "address"],
    "file_share": ["name", "email", "phone", "address"],
    "api_endpoint": ["email", "name", "phone"],
    "cloud_storage": ["name", "email", "address", "dob"],
    "email_archive": ["email", "name", "phone", "address"],
    "code_repo": ["email"],
    "backup": ["email", "phone", "ssn", "credit_card", "dob", "name", "address", "passport"],
}

_ASSET_SENSITIVITY_DEFAULTS: Dict[str, int] = {
    "database": 70,
    "file_share": 45,
    "api_endpoint": 50,
    "cloud_storage": 55,
    "email_archive": 60,
    "code_repo": 35,
    "backup": 75,
}

_ASSET_AUTO_CLASSIFICATION: Dict[str, str] = {
    "database": "confidential",
    "file_share": "internal",
    "api_endpoint": "internal",
    "cloud_storage": "confidential",
    "email_archive": "confidential",
    "code_repo": "internal",
    "backup": "restricted",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class DataClassificationEngine:
    """SQLite WAL-backed Data Classification engine.

    Thread-safe via RLock. Multi-tenant via org_id. Each org gets its own DB file.
    """

    def __init__(self, data_dir: str = ".fixops_data") -> None:
        self._data_dir = Path(data_dir)
        self._locks: Dict[str, threading.RLock] = {}
        self._locks_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _db_path(self, org_id: str) -> str:
        return str(self._data_dir / f"{org_id}_data_classification.db")

    def _get_lock(self, org_id: str) -> threading.RLock:
        with self._locks_lock:
            if org_id not in self._locks:
                self._locks[org_id] = threading.RLock()
            return self._locks[org_id]

    def _conn(self, org_id: str) -> sqlite3.Connection:
        db_path = self._db_path(org_id)
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self, org_id: str) -> None:
        with self._conn(org_id) as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS data_assets (
                    id                      TEXT PRIMARY KEY,
                    org_id                  TEXT NOT NULL,
                    name                    TEXT NOT NULL,
                    asset_type              TEXT NOT NULL DEFAULT 'database',
                    location                TEXT NOT NULL DEFAULT '',
                    owner_team              TEXT NOT NULL DEFAULT '',
                    classification_level    TEXT NOT NULL DEFAULT 'internal',
                    auto_classification_level TEXT NOT NULL DEFAULT '',
                    classification_method   TEXT NOT NULL DEFAULT 'manual',
                    pii_detected            INTEGER NOT NULL DEFAULT 0,
                    pii_types               TEXT NOT NULL DEFAULT '[]',
                    sensitivity_score       REAL NOT NULL DEFAULT 0.0,
                    last_scanned_at         DATETIME,
                    record_count            INTEGER NOT NULL DEFAULT 0,
                    data_residency          TEXT NOT NULL DEFAULT 'us',
                    created_at              DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_da_org_level
                    ON data_assets (org_id, classification_level);

                CREATE INDEX IF NOT EXISTS idx_da_org_pii
                    ON data_assets (org_id, pii_detected);

                CREATE TABLE IF NOT EXISTS classification_rules (
                    id                   TEXT PRIMARY KEY,
                    org_id               TEXT NOT NULL,
                    rule_name            TEXT NOT NULL,
                    pattern_type         TEXT NOT NULL DEFAULT 'keyword',
                    pattern_value        TEXT NOT NULL DEFAULT '',
                    classification_level TEXT NOT NULL DEFAULT 'confidential',
                    confidence_threshold REAL NOT NULL DEFAULT 0.8,
                    enabled              INTEGER NOT NULL DEFAULT 1,
                    match_count          INTEGER NOT NULL DEFAULT 0,
                    created_at           DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_cr_org
                    ON classification_rules (org_id, enabled);

                CREATE TABLE IF NOT EXISTS scan_results (
                    id                       TEXT PRIMARY KEY,
                    org_id                   TEXT NOT NULL,
                    asset_id                 TEXT NOT NULL,
                    scan_type                TEXT NOT NULL DEFAULT 'manual',
                    scanned_at               DATETIME NOT NULL,
                    findings_count           INTEGER NOT NULL DEFAULT 0,
                    pii_matches              TEXT NOT NULL DEFAULT '{}',
                    classification_suggested TEXT NOT NULL DEFAULT '',
                    operator                 TEXT NOT NULL DEFAULT 'system'
                );

                CREATE INDEX IF NOT EXISTS idx_sr_org_asset
                    ON scan_results (org_id, asset_id, scanned_at DESC);

                CREATE TABLE IF NOT EXISTS violations (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    asset_id       TEXT NOT NULL,
                    violation_type TEXT NOT NULL DEFAULT 'unclassified',
                    severity       TEXT NOT NULL DEFAULT 'medium',
                    detected_at    DATETIME NOT NULL,
                    resolved_at    DATETIME,
                    status         TEXT NOT NULL DEFAULT 'open'
                );

                CREATE INDEX IF NOT EXISTS idx_viol_org_status
                    ON violations (org_id, status, detected_at DESC);

                CREATE INDEX IF NOT EXISTS idx_viol_org_severity
                    ON violations (org_id, severity);
                """
            )

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        # Deserialize JSON fields
        for field in ("pii_types", "pii_matches"):
            if field in d and isinstance(d[field], str):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, TypeError):
                    pass
        # Convert SQLite int booleans
        if "pii_detected" in d:
            d["pii_detected"] = bool(d["pii_detected"])
        if "enabled" in d:
            d["enabled"] = bool(d["enabled"])
        return d

    def _ensure_db(self, org_id: str) -> None:
        self._init_db(org_id)

    # ------------------------------------------------------------------
    # Data Assets
    # ------------------------------------------------------------------

    def register_asset(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new data asset. Returns the created record."""
        self._ensure_db(org_id)

        name = (data.get("name") or "").strip()
        if not name:
            raise ValueError("name is required.")

        asset_type = data.get("asset_type", "database")
        if asset_type not in _VALID_ASSET_TYPES:
            raise ValueError(f"Invalid asset_type: {asset_type}. Must be one of {_VALID_ASSET_TYPES}")

        classification_level = data.get("classification_level", "internal")
        if classification_level not in _VALID_CLASSIFICATION_LEVELS:
            raise ValueError(f"Invalid classification_level: {classification_level}")

        data_residency = data.get("data_residency", "us")
        if data_residency not in _VALID_DATA_RESIDENCY:
            raise ValueError(f"Invalid data_residency: {data_residency}")

        pii_types = data.get("pii_types", [])
        auto_class = _ASSET_AUTO_CLASSIFICATION.get(asset_type, "internal")
        sensitivity = float(data.get("sensitivity_score", _ASSET_SENSITIVITY_DEFAULTS.get(asset_type, 50)))

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "name": name,
            "asset_type": asset_type,
            "location": data.get("location", ""),
            "owner_team": data.get("owner_team", ""),
            "classification_level": classification_level,
            "auto_classification_level": auto_class,
            "classification_method": data.get("classification_method", "manual"),
            "pii_detected": bool(data.get("pii_detected", False)),
            "pii_types": pii_types,
            "sensitivity_score": sensitivity,
            "last_scanned_at": data.get("last_scanned_at"),
            "record_count": int(data.get("record_count", 0)),
            "data_residency": data_residency,
            "created_at": now,
        }

        lock = self._get_lock(org_id)
        with lock:
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO data_assets
                       (id, org_id, name, asset_type, location, owner_team,
                        classification_level, auto_classification_level, classification_method,
                        pii_detected, pii_types, sensitivity_score, last_scanned_at,
                        record_count, data_residency, created_at)
                       VALUES (:id, :org_id, :name, :asset_type, :location, :owner_team,
                               :classification_level, :auto_classification_level,
                               :classification_method, :pii_detected, :pii_types,
                               :sensitivity_score, :last_scanned_at, :record_count,
                               :data_residency, :created_at)""",
                    {**record, "pii_types": json.dumps(record["pii_types"]),
                     "pii_detected": 1 if record["pii_detected"] else 0},
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "data_classification", "org_id": org_id, "source_engine": "data_classification"})
            except Exception:
                pass

        return record

    def list_assets(
        self,
        org_id: str,
        classification_level: Optional[str] = None,
        pii_detected: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        """List data assets, optionally filtered by classification level and/or PII detection."""
        self._ensure_db(org_id)
        sql = "SELECT * FROM data_assets WHERE org_id = ?"
        params: list = [org_id]
        if classification_level:
            sql += " AND classification_level = ?"
            params.append(classification_level)
        if pii_detected is not None:
            sql += " AND pii_detected = ?"
            params.append(1 if pii_detected else 0)
        sql += " ORDER BY created_at DESC"
        with self._conn(org_id) as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    def get_asset(self, org_id: str, asset_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single data asset by ID."""
        self._ensure_db(org_id)
        with self._conn(org_id) as conn:
            row = conn.execute(
                "SELECT * FROM data_assets WHERE org_id = ? AND id = ?",
                (org_id, asset_id),
            ).fetchone()
        return self._row(row) if row else None

    def classify_asset(
        self,
        org_id: str,
        asset_id: str,
        level: str,
        method: str = "manual",
    ) -> Dict[str, Any]:
        """Update the classification level of a data asset."""
        self._ensure_db(org_id)
        if level not in _VALID_CLASSIFICATION_LEVELS:
            raise ValueError(f"Invalid classification level: {level}")
        if method not in _VALID_CLASSIFICATION_METHODS:
            raise ValueError(f"Invalid classification method: {method}")

        lock = self._get_lock(org_id)
        with lock:
            with self._conn(org_id) as conn:
                cur = conn.execute(
                    """UPDATE data_assets
                       SET classification_level = ?, classification_method = ?
                       WHERE org_id = ? AND id = ?""",
                    (level, method, org_id, asset_id),
                )
                if cur.rowcount == 0:
                    raise ValueError(f"Asset not found: {asset_id}")
                row = conn.execute(
                    "SELECT * FROM data_assets WHERE org_id = ? AND id = ?",
                    (org_id, asset_id),
                ).fetchone()
        return self._row(row)

    def scan_asset(
        self,
        org_id: str,
        asset_id: str,
        operator: str = "system",
    ) -> Dict[str, Any]:
        """Simulate a PII scan on the asset using asset-type heuristics.

        Returns the scan_results record and updates the asset's pii_detected / last_scanned_at.
        """
        self._ensure_db(org_id)
        asset = self.get_asset(org_id, asset_id)
        if not asset:
            raise ValueError(f"Asset not found: {asset_id}")

        asset_type = asset.get("asset_type", "database")
        detected_pii = _ASSET_PII_HEURISTICS.get(asset_type, [])
        pii_matches = {pii: True for pii in detected_pii}
        findings_count = len(detected_pii)
        pii_detected = findings_count > 0

        # Suggest classification based on PII presence
        if "ssn" in detected_pii or "credit_card" in detected_pii or "passport" in detected_pii:
            suggested = "restricted"
        elif "dob" in detected_pii or "email" in detected_pii:
            suggested = "confidential"
        elif pii_detected:
            suggested = "internal"
        else:
            suggested = "public"

        now = _now_iso()
        scan_record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "asset_id": asset_id,
            "scan_type": "manual",
            "scanned_at": now,
            "findings_count": findings_count,
            "pii_matches": pii_matches,
            "classification_suggested": suggested,
            "operator": operator,
        }

        lock = self._get_lock(org_id)
        with lock:
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO scan_results
                       (id, org_id, asset_id, scan_type, scanned_at, findings_count,
                        pii_matches, classification_suggested, operator)
                       VALUES (:id, :org_id, :asset_id, :scan_type, :scanned_at,
                               :findings_count, :pii_matches, :classification_suggested,
                               :operator)""",
                    {**scan_record, "pii_matches": json.dumps(scan_record["pii_matches"])},
                )
                conn.execute(
                    """UPDATE data_assets
                       SET pii_detected = ?, pii_types = ?, last_scanned_at = ?
                       WHERE org_id = ? AND id = ?""",
                    (
                        1 if pii_detected else 0,
                        json.dumps(detected_pii),
                        now,
                        org_id,
                        asset_id,
                    ),
                )
        return scan_record

    # ------------------------------------------------------------------
    # Classification Rules
    # ------------------------------------------------------------------

    def add_rule(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a new classification rule."""
        self._ensure_db(org_id)

        rule_name = (data.get("rule_name") or "").strip()
        if not rule_name:
            raise ValueError("rule_name is required.")

        pattern_type = data.get("pattern_type", "keyword")
        if pattern_type not in _VALID_PATTERN_TYPES:
            raise ValueError(f"Invalid pattern_type: {pattern_type}")

        classification_level = data.get("classification_level", "confidential")
        if classification_level not in _VALID_CLASSIFICATION_LEVELS:
            raise ValueError(f"Invalid classification_level: {classification_level}")

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "rule_name": rule_name,
            "pattern_type": pattern_type,
            "pattern_value": data.get("pattern_value", ""),
            "classification_level": classification_level,
            "confidence_threshold": float(data.get("confidence_threshold", 0.8)),
            "enabled": bool(data.get("enabled", True)),
            "match_count": 0,
            "created_at": now,
        }

        lock = self._get_lock(org_id)
        with lock:
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO classification_rules
                       (id, org_id, rule_name, pattern_type, pattern_value,
                        classification_level, confidence_threshold, enabled, match_count, created_at)
                       VALUES (:id, :org_id, :rule_name, :pattern_type, :pattern_value,
                               :classification_level, :confidence_threshold, :enabled,
                               :match_count, :created_at)""",
                    {**record, "enabled": 1 if record["enabled"] else 0},
                )
        return record

    def list_rules(self, org_id: str) -> List[Dict[str, Any]]:
        """List all classification rules for the org."""
        self._ensure_db(org_id)
        with self._conn(org_id) as conn:
            return [
                self._row(r)
                for r in conn.execute(
                    "SELECT * FROM classification_rules WHERE org_id = ? ORDER BY created_at DESC",
                    (org_id,),
                ).fetchall()
            ]

    # ------------------------------------------------------------------
    # Violations
    # ------------------------------------------------------------------

    def log_violation(self, org_id: str, asset_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Log a data classification violation."""
        self._ensure_db(org_id)

        violation_type = data.get("violation_type", "unclassified")
        if violation_type not in _VALID_VIOLATION_TYPES:
            raise ValueError(f"Invalid violation_type: {violation_type}")

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {severity}")

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "asset_id": asset_id,
            "violation_type": violation_type,
            "severity": severity,
            "detected_at": now,
            "resolved_at": None,
            "status": "open",
        }

        lock = self._get_lock(org_id)
        with lock:
            with self._conn(org_id) as conn:
                conn.execute(
                    """INSERT INTO violations
                       (id, org_id, asset_id, violation_type, severity,
                        detected_at, resolved_at, status)
                       VALUES (:id, :org_id, :asset_id, :violation_type, :severity,
                               :detected_at, :resolved_at, :status)""",
                    record,
                )
        return record

    def list_violations(
        self,
        org_id: str,
        status: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List violations with optional status and/or severity filters."""
        self._ensure_db(org_id)
        sql = "SELECT * FROM violations WHERE org_id = ?"
        params: list = [org_id]
        if status:
            sql += " AND status = ?"
            params.append(status)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        sql += " ORDER BY detected_at DESC"
        with self._conn(org_id) as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    def resolve_violation(self, org_id: str, violation_id: str) -> bool:
        """Mark a violation as resolved. Returns True if found."""
        self._ensure_db(org_id)
        now = _now_iso()
        lock = self._get_lock(org_id)
        with lock:
            with self._conn(org_id) as conn:
                cur = conn.execute(
                    """UPDATE violations SET status = 'resolved', resolved_at = ?
                       WHERE org_id = ? AND id = ?""",
                    (now, org_id, violation_id),
                )
                return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated data classification stats for the org."""
        self._ensure_db(org_id)
        with self._conn(org_id) as conn:
            total_assets = conn.execute(
                "SELECT COUNT(*) FROM data_assets WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            classified_assets = conn.execute(
                """SELECT COUNT(*) FROM data_assets
                   WHERE org_id = ? AND classification_level != 'internal'""",
                (org_id,),
            ).fetchone()[0]

            pii_exposed = conn.execute(
                "SELECT COUNT(*) FROM data_assets WHERE org_id = ? AND pii_detected = 1",
                (org_id,),
            ).fetchone()[0]

            # By classification level
            level_rows = conn.execute(
                """SELECT classification_level, COUNT(*) as cnt
                   FROM data_assets WHERE org_id = ?
                   GROUP BY classification_level""",
                (org_id,),
            ).fetchall()
            by_classification = {r["classification_level"]: r["cnt"] for r in level_rows}

            # Open violations by severity
            viol_rows = conn.execute(
                """SELECT severity, COUNT(*) as cnt
                   FROM violations WHERE org_id = ? AND status = 'open'
                   GROUP BY severity""",
                (org_id,),
            ).fetchall()
            open_violations_by_severity = {r["severity"]: r["cnt"] for r in viol_rows}

        coverage_pct = round((classified_assets / total_assets * 100) if total_assets > 0 else 0.0, 2)

        return {
            "total_assets": total_assets,
            "by_classification": by_classification,
            "pii_exposed_count": pii_exposed,
            "open_violations_by_severity": open_violations_by_severity,
            "coverage_pct": coverage_pct,
        }
