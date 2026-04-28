"""Data Privacy Engine — Privacy asset management and DSR handling for ALDECI.

Manages data asset inventory and data subject request (DSR) workflows.

Features:
- Data asset registration with category and classification tagging
- Privacy request lifecycle (access/deletion/rectification/portability/objection)
- Request status tracking with completion timestamps
- Overdue detection (pending/in_progress older than 30 days)
- Privacy stats: assets by category/classification, requests by type

Compliance: GDPR Art. 30, CCPA, PIPEDA, ISO 27701
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(Path(__file__).resolve().parents[2] / ".fixops_data" / "data_privacy.db")

_VALID_DATA_CATEGORIES = {
    "pii", "phi", "financial", "intellectual_property", "public", "internal", "confidential"
}
_VALID_CLASSIFICATIONS = {"public", "internal", "confidential", "restricted"}
_VALID_REQUEST_TYPES = {"access", "deletion", "rectification", "portability", "objection"}
_VALID_REQUEST_STATUSES = {"pending", "in_progress", "completed", "rejected"}


# ============================================================================
# PYDANTIC MODELS
# ============================================================================


class DataAssetCreate(BaseModel):
    name: str
    data_category: str
    classification: str = "internal"
    description: Optional[str] = None
    location: Optional[str] = None
    data_owner: Optional[str] = None
    retention_days: Optional[int] = None


class PrivacyRequestCreate(BaseModel):
    request_type: str
    subject_email: str
    notes: Optional[str] = None


class RequestStatusUpdate(BaseModel):
    status: str
    notes: str = ""


# ============================================================================
# DATA PRIVACY ENGINE
# ============================================================================


class DataPrivacyEngine:
    """Data privacy engine — asset inventory and DSR lifecycle management."""

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db_path = db_path
        self._lock = threading.RLock()
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ------------------------------------------------------------------
    # DB INIT
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS privacy_assets (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    name            TEXT NOT NULL,
                    data_category   TEXT NOT NULL,
                    classification  TEXT NOT NULL DEFAULT 'internal',
                    description     TEXT,
                    location        TEXT,
                    data_owner      TEXT,
                    retention_days  INTEGER,
                    status          TEXT NOT NULL DEFAULT 'active',
                    created_at      TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS privacy_requests (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    request_type    TEXT NOT NULL,
                    subject_email   TEXT NOT NULL,
                    status          TEXT NOT NULL DEFAULT 'pending',
                    notes           TEXT,
                    submitted_at    TEXT NOT NULL,
                    completed_at    TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_privacy_assets_org ON privacy_assets(org_id);
                CREATE INDEX IF NOT EXISTS idx_privacy_requests_org ON privacy_requests(org_id);
            """)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # DATA ASSETS
    # ------------------------------------------------------------------

    def register_data_asset(self, org_id: str, data: DataAssetCreate) -> Dict[str, Any]:
        """Register a new data asset. Validates name, data_category, and classification."""
        if not data.name:
            raise ValueError("name is required")
        if data.data_category not in _VALID_DATA_CATEGORIES:
            raise ValueError(
                f"Invalid data_category '{data.data_category}'. Must be one of {sorted(_VALID_DATA_CATEGORIES)}"
            )
        if data.classification not in _VALID_CLASSIFICATIONS:
            raise ValueError(
                f"Invalid classification '{data.classification}'. Must be one of {sorted(_VALID_CLASSIFICATIONS)}"
            )

        asset_id = str(uuid.uuid4())
        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO privacy_assets
                   (id, org_id, name, data_category, classification, description,
                    location, data_owner, retention_days, status, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    asset_id, org_id, data.name, data.data_category, data.classification,
                    data.description, data.location, data.data_owner,
                    data.retention_days, "active", now,
                ),
            )
        _logger.info("privacy.asset_registered org=%s asset_id=%s", org_id, asset_id)
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("CONTROL_ASSESSED", {"entity_type": "data_privacy", "org_id": org_id, "source_engine": "data_privacy"})
            except Exception:
                pass

        return self.get_data_asset(org_id, asset_id)

    def list_data_assets(
        self,
        org_id: str,
        data_category: Optional[str] = None,
        classification: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List data assets for org, optionally filtered by data_category or classification."""
        query = "SELECT * FROM privacy_assets WHERE org_id=?"
        params: List[Any] = [org_id]
        if data_category:
            query += " AND data_category=?"
            params.append(data_category)
        if classification:
            query += " AND classification=?"
            params.append(classification)
        query += " ORDER BY created_at DESC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_data_asset(self, org_id: str, asset_id: str) -> Dict[str, Any]:
        """Fetch a single data asset, scoped to org_id."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM privacy_assets WHERE org_id=? AND id=?",
                (org_id, asset_id),
            ).fetchone()
        if not row:
            raise ValueError(f"Asset {asset_id} not found for org {org_id}")
        return dict(row)

    # ------------------------------------------------------------------
    # PRIVACY REQUESTS
    # ------------------------------------------------------------------

    def record_privacy_request(self, org_id: str, data: PrivacyRequestCreate) -> Dict[str, Any]:
        """Record a new data subject request. Validates request_type and subject_email."""
        if data.request_type not in _VALID_REQUEST_TYPES:
            raise ValueError(
                f"Invalid request_type '{data.request_type}'. Must be one of {sorted(_VALID_REQUEST_TYPES)}"
            )
        if not data.subject_email:
            raise ValueError("subject_email is required")

        request_id = str(uuid.uuid4())
        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO privacy_requests
                   (id, org_id, request_type, subject_email, status, notes, submitted_at, completed_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    request_id, org_id, data.request_type, data.subject_email,
                    "pending", data.notes, now, None,
                ),
            )
        _logger.info("privacy.request_recorded org=%s request_id=%s type=%s", org_id, request_id, data.request_type)
        return self._get_request(org_id, request_id)

    def list_privacy_requests(
        self,
        org_id: str,
        request_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List privacy requests for org, optionally filtered by request_type or status."""
        query = "SELECT * FROM privacy_requests WHERE org_id=?"
        params: List[Any] = [org_id]
        if request_type:
            query += " AND request_type=?"
            params.append(request_type)
        if status:
            query += " AND status=?"
            params.append(status)
        query += " ORDER BY submitted_at DESC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def update_request_status(
        self,
        org_id: str,
        request_id: str,
        status: str,
        notes: str = "",
    ) -> Dict[str, Any]:
        """Update a privacy request status. Sets completed_at when status=completed."""
        if status not in _VALID_REQUEST_STATUSES:
            raise ValueError(
                f"Invalid status '{status}'. Must be one of {sorted(_VALID_REQUEST_STATUSES)}"
            )

        # Verify request belongs to org
        self._get_request(org_id, request_id)

        now = self._now()
        completed_at = now if status == "completed" else None

        with self._lock, self._connect() as conn:
            conn.execute(
                """UPDATE privacy_requests
                   SET status=?, notes=?, completed_at=?
                   WHERE org_id=? AND id=?""",
                (status, notes, completed_at, org_id, request_id),
            )

        _logger.info("privacy.request_updated org=%s request_id=%s status=%s", org_id, request_id, status)
        return self._get_request(org_id, request_id)

    def _get_request(self, org_id: str, request_id: str) -> Dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM privacy_requests WHERE org_id=? AND id=?",
                (org_id, request_id),
            ).fetchone()
        if not row:
            raise ValueError(f"Request {request_id} not found for org {org_id}")
        return dict(row)

    # ------------------------------------------------------------------
    # STATS
    # ------------------------------------------------------------------

    def get_privacy_stats(self, org_id: str) -> Dict[str, Any]:
        """Return privacy overview stats: assets by category/classification, requests by type/status."""
        overdue_cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()

        with self._connect() as conn:
            total_assets = conn.execute(
                "SELECT COUNT(*) FROM privacy_assets WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            category_rows = conn.execute(
                "SELECT data_category, COUNT(*) as cnt FROM privacy_assets WHERE org_id=? GROUP BY data_category",
                (org_id,),
            ).fetchall()
            by_category = {r["data_category"]: r["cnt"] for r in category_rows}

            classification_rows = conn.execute(
                "SELECT classification, COUNT(*) as cnt FROM privacy_assets WHERE org_id=? GROUP BY classification",
                (org_id,),
            ).fetchall()
            by_classification = {r["classification"]: r["cnt"] for r in classification_rows}

            total_requests = conn.execute(
                "SELECT COUNT(*) FROM privacy_requests WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            type_rows = conn.execute(
                "SELECT request_type, COUNT(*) as cnt FROM privacy_requests WHERE org_id=? GROUP BY request_type",
                (org_id,),
            ).fetchall()
            by_request_type = {r["request_type"]: r["cnt"] for r in type_rows}

            pending_requests = conn.execute(
                "SELECT COUNT(*) FROM privacy_requests WHERE org_id=? AND status='pending'",
                (org_id,),
            ).fetchone()[0]

            overdue_requests = conn.execute(
                """SELECT COUNT(*) FROM privacy_requests
                   WHERE org_id=? AND status IN ('pending','in_progress')
                   AND submitted_at < ?""",
                (org_id, overdue_cutoff),
            ).fetchone()[0]

        return {
            "total_assets": total_assets,
            "by_category": by_category,
            "by_classification": by_classification,
            "total_requests": total_requests,
            "by_request_type": by_request_type,
            "pending_requests": pending_requests,
            "overdue_requests": overdue_requests,
        }
