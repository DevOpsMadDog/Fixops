"""Digital Identity Engine — ALDECI.

Tracks digital identity verification, credentials, and identity proofing.

Capabilities:
  - Identity profiles with NIST 800-63 assurance levels (IAL/AAL)
  - Verification event history (initiation, document check, biometric, approval, rejection, suspension)
  - Identity attribute management with per-attribute verification
  - Stats: totals, by status, by level, verified/suspended counts

Compliance: NIST SP 800-63, eIDAS, ISO/IEC 29115
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

_DEFAULT_DB_DIR = str(
    Path(__file__).resolve().parents[2] / ".fixops_data"
)

_VALID_IDENTITY_LEVELS = {"ial1", "ial2", "ial3"}
_VALID_VERIFICATION_STATUSES = {"unverified", "pending", "verified", "suspended"}
_VALID_VERIFICATION_METHODS = {
    "self_asserted",
    "document",
    "biometric",
    "in_person",
}
_VALID_ASSURANCE_LEVELS = {"aal1", "aal2", "aal3"}
_VALID_EVENT_TYPES = {
    "initiation",
    "document_check",
    "biometric_check",
    "approval",
    "rejection",
    "suspension",
}
_VALID_OUTCOMES = {"success", "failure", "pending"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class DigitalIdentityEngine:
    """SQLite WAL-backed Digital Identity engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/digital_identity.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(Path(_DEFAULT_DB_DIR) / "digital_identity.db")
        self._db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS identity_profiles (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    user_id             TEXT NOT NULL,
                    identity_level      TEXT NOT NULL DEFAULT 'ial1',
                    verification_status TEXT NOT NULL DEFAULT 'unverified',
                    verification_method TEXT NOT NULL DEFAULT 'self_asserted',
                    assurance_level     TEXT NOT NULL DEFAULT 'aal1',
                    attributes          TEXT NOT NULL DEFAULT '{}',
                    created_at          TEXT NOT NULL,
                    verified_at         TEXT,
                    UNIQUE (org_id, user_id)
                );

                CREATE INDEX IF NOT EXISTS idx_profiles_org
                    ON identity_profiles (org_id, verification_status, identity_level, created_at DESC);

                CREATE TABLE IF NOT EXISTS verification_events (
                    id           TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL,
                    user_id      TEXT NOT NULL,
                    event_type   TEXT NOT NULL,
                    outcome      TEXT NOT NULL DEFAULT 'pending',
                    evidence_type TEXT NOT NULL DEFAULT '',
                    notes        TEXT NOT NULL DEFAULT '',
                    created_at   TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_events_org
                    ON verification_events (org_id, user_id, created_at DESC);

                CREATE TABLE IF NOT EXISTS identity_attributes (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    user_id         TEXT NOT NULL,
                    attribute_name  TEXT NOT NULL,
                    attribute_value TEXT NOT NULL,
                    verified        INTEGER NOT NULL DEFAULT 0,
                    source          TEXT NOT NULL DEFAULT '',
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_attributes_org
                    ON identity_attributes (org_id, user_id, created_at DESC);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        # Parse JSON fields
        for field in ("attributes",):
            if field in d and isinstance(d[field], str):
                try:
                    d[field] = json.loads(d[field])
                except (json.JSONDecodeError, TypeError):
                    d[field] = {}
        # Coerce verified integer to bool for attributes
        if "verified" in d:
            d["verified"] = bool(d["verified"])
        return d

    # ------------------------------------------------------------------
    # Profiles
    # ------------------------------------------------------------------

    def create_profile(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new identity profile."""
        user_id = (data.get("user_id") or "").strip()
        if not user_id:
            raise ValueError("user_id is required.")

        identity_level = data.get("identity_level", "ial1")
        if identity_level not in _VALID_IDENTITY_LEVELS:
            raise ValueError(
                f"Invalid identity_level: {identity_level}. "
                f"Must be one of {sorted(_VALID_IDENTITY_LEVELS)}"
            )

        assurance_level = data.get("assurance_level", "aal1")
        if assurance_level not in _VALID_ASSURANCE_LEVELS:
            raise ValueError(
                f"Invalid assurance_level: {assurance_level}. "
                f"Must be one of {sorted(_VALID_ASSURANCE_LEVELS)}"
            )

        attributes = data.get("attributes", {})
        if not isinstance(attributes, dict):
            attributes = {}

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "user_id": user_id,
            "identity_level": identity_level,
            "verification_status": "unverified",
            "verification_method": data.get("verification_method", "self_asserted"),
            "assurance_level": assurance_level,
            "attributes": json.dumps(attributes),
            "created_at": now,
            "verified_at": None,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO identity_profiles
                       (id, org_id, user_id, identity_level, verification_status,
                        verification_method, assurance_level, attributes, created_at, verified_at)
                       VALUES (:id, :org_id, :user_id, :identity_level, :verification_status,
                               :verification_method, :assurance_level, :attributes, :created_at, :verified_at)""",
                    record,
                )
        record["attributes"] = attributes
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("IDENTITY_UPDATED", {"entity_type": "digital_identity", "org_id": org_id, "source_engine": "digital_identity"})
            except Exception:
                pass

        return record

    def get_profile(self, org_id: str, user_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve identity profile by user_id."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM identity_profiles WHERE org_id = ? AND user_id = ?",
                (org_id, user_id),
            ).fetchone()
        return self._row(row) if row else None

    def list_profiles(
        self,
        org_id: str,
        verification_status: Optional[str] = None,
        identity_level: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List identity profiles with optional filters."""
        sql = "SELECT * FROM identity_profiles WHERE org_id = ?"
        params: list = [org_id]
        if verification_status:
            sql += " AND verification_status = ?"
            params.append(verification_status)
        if identity_level:
            sql += " AND identity_level = ?"
            params.append(identity_level)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row(r) for r in rows]

    def verify_identity(
        self, org_id: str, user_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Verify an identity profile."""
        verification_method = data.get("verification_method", "document")
        if verification_method not in _VALID_VERIFICATION_METHODS:
            raise ValueError(
                f"Invalid verification_method: {verification_method}. "
                f"Must be one of {sorted(_VALID_VERIFICATION_METHODS)}"
            )

        identity_level = data.get("identity_level", "ial2")
        if identity_level not in _VALID_IDENTITY_LEVELS:
            raise ValueError(
                f"Invalid identity_level: {identity_level}. "
                f"Must be one of {sorted(_VALID_IDENTITY_LEVELS)}"
            )

        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    """UPDATE identity_profiles
                       SET verification_status = 'verified',
                           verification_method = ?,
                           identity_level = ?,
                           verified_at = ?
                       WHERE org_id = ? AND user_id = ?""",
                    (verification_method, identity_level, now, org_id, user_id),
                )
                if cur.rowcount == 0:
                    raise KeyError(
                        f"Profile for user {user_id} not found in org {org_id}"
                    )
                row = conn.execute(
                    "SELECT * FROM identity_profiles WHERE org_id = ? AND user_id = ?",
                    (org_id, user_id),
                ).fetchone()
        # Log verification event
        self._log_event(org_id, user_id, "approval", "success", notes="Identity verified")
        return self._row(row)

    def suspend_identity(
        self, org_id: str, user_id: str, reason: str
    ) -> Dict[str, Any]:
        """Suspend an identity profile."""
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    """UPDATE identity_profiles
                       SET verification_status = 'suspended'
                       WHERE org_id = ? AND user_id = ?""",
                    (org_id, user_id),
                )
                if cur.rowcount == 0:
                    raise KeyError(
                        f"Profile for user {user_id} not found in org {org_id}"
                    )
                row = conn.execute(
                    "SELECT * FROM identity_profiles WHERE org_id = ? AND user_id = ?",
                    (org_id, user_id),
                ).fetchone()
        # Log suspension event
        self._log_event(
            org_id, user_id, "suspension", "success", notes=reason
        )
        return self._row(row)

    # ------------------------------------------------------------------
    # Verification Events
    # ------------------------------------------------------------------

    def _log_event(
        self,
        org_id: str,
        user_id: str,
        event_type: str,
        outcome: str,
        evidence_type: str = "",
        notes: str = "",
    ) -> Dict[str, Any]:
        """Internal helper to log a verification event."""
        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "user_id": user_id,
            "event_type": event_type,
            "outcome": outcome,
            "evidence_type": evidence_type,
            "notes": notes,
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO verification_events
                       (id, org_id, user_id, event_type, outcome, evidence_type, notes, created_at)
                       VALUES (:id, :org_id, :user_id, :event_type, :outcome, :evidence_type, :notes, :created_at)""",
                    record,
                )
        return record

    def record_verification_event(
        self, org_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Record a verification event."""
        user_id = (data.get("user_id") or "").strip()
        if not user_id:
            raise ValueError("user_id is required.")

        event_type = data.get("event_type", "initiation")
        if event_type not in _VALID_EVENT_TYPES:
            raise ValueError(
                f"Invalid event_type: {event_type}. "
                f"Must be one of {sorted(_VALID_EVENT_TYPES)}"
            )

        outcome = data.get("outcome", "pending")
        if outcome not in _VALID_OUTCOMES:
            raise ValueError(
                f"Invalid outcome: {outcome}. "
                f"Must be one of {sorted(_VALID_OUTCOMES)}"
            )

        return self._log_event(
            org_id,
            user_id,
            event_type,
            outcome,
            evidence_type=data.get("evidence_type", ""),
            notes=data.get("notes", ""),
        )

    def get_verification_history(
        self, org_id: str, user_id: str, limit: int = 50
    ) -> List[Dict[str, Any]]:
        """Get verification event history for a user."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM verification_events
                   WHERE org_id = ? AND user_id = ?
                   ORDER BY created_at DESC
                   LIMIT ?""",
                (org_id, user_id, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Attributes
    # ------------------------------------------------------------------

    def add_attribute(
        self, org_id: str, user_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add an identity attribute."""
        attribute_name = (data.get("attribute_name") or "").strip()
        if not attribute_name:
            raise ValueError("attribute_name is required.")

        attribute_value = data.get("attribute_value")
        if attribute_value is None or str(attribute_value).strip() == "":
            raise ValueError("attribute_value is required.")

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "user_id": user_id,
            "attribute_name": attribute_name,
            "attribute_value": str(attribute_value),
            "verified": 1 if data.get("verified", False) else 0,
            "source": data.get("source", ""),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO identity_attributes
                       (id, org_id, user_id, attribute_name, attribute_value, verified, source, created_at)
                       VALUES (:id, :org_id, :user_id, :attribute_name, :attribute_value, :verified, :source, :created_at)""",
                    record,
                )
        record["verified"] = bool(record["verified"])
        return record

    def list_attributes(self, org_id: str, user_id: str) -> List[Dict[str, Any]]:
        """List identity attributes for a user."""
        with self._conn() as conn:
            rows = conn.execute(
                """SELECT * FROM identity_attributes
                   WHERE org_id = ? AND user_id = ?
                   ORDER BY created_at DESC""",
                (org_id, user_id),
            ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_identity_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated identity statistics."""
        with self._conn() as conn:
            total_profiles = conn.execute(
                "SELECT COUNT(*) FROM identity_profiles WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            verified_count = conn.execute(
                "SELECT COUNT(*) FROM identity_profiles WHERE org_id = ? AND verification_status = 'verified'",
                (org_id,),
            ).fetchone()[0]

            suspended_count = conn.execute(
                "SELECT COUNT(*) FROM identity_profiles WHERE org_id = ? AND verification_status = 'suspended'",
                (org_id,),
            ).fetchone()[0]

            by_status_rows = conn.execute(
                """SELECT verification_status, COUNT(*) as cnt
                   FROM identity_profiles WHERE org_id = ?
                   GROUP BY verification_status""",
                (org_id,),
            ).fetchall()

            by_level_rows = conn.execute(
                """SELECT identity_level, COUNT(*) as cnt
                   FROM identity_profiles WHERE org_id = ?
                   GROUP BY identity_level""",
                (org_id,),
            ).fetchall()

            total_events = conn.execute(
                "SELECT COUNT(*) FROM verification_events WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

        return {
            "total_profiles": total_profiles,
            "verified_count": verified_count,
            "suspended_count": suspended_count,
            "by_status": {r["verification_status"]: r["cnt"] for r in by_status_rows},
            "by_level": {r["identity_level"]: r["cnt"] for r in by_level_rows},
            "total_events": total_events,
        }
