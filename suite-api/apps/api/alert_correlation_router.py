"""Alert Correlation Rules Router — ALDECI (Multica #3756, 2026-05-31).

Provides CRUD management for alert correlation rules: time-window grouping,
suppression windows, and escalation rules that operate on top of the existing
smart_dedup.py cross-scanner deduplication layer.

Prefix: /api/v1/alert-mgmt
Auth:   api_key_auth dependency (read:scans scope at registration)
Storage: SQLite at data/alert_correlation_rules.db (thread-safe RLock pattern)

Routes:
  GET    /api/v1/alert-mgmt/                     router info + rule counts
  GET    /api/v1/alert-mgmt/rules                list rules (filter by org_id)
  POST   /api/v1/alert-mgmt/rules                create a new correlation rule
  GET    /api/v1/alert-mgmt/rules/{rule_id}      fetch single rule by id
  PUT    /api/v1/alert-mgmt/rules/{rule_id}      partial update a rule
  DELETE /api/v1/alert-mgmt/rules/{rule_id}      hard-delete a rule

NO MOCKS rule: all data is read from / written to the live SQLite database.
When a rule_id is not found the endpoint returns HTTP 404. No fabricated rows.

Schema
------
  correlation_rules (id, org_id, name, match_field, match_value, window_secs,
                     suppress_secs, action, enabled, created_at, updated_at)

  Indexes:
    idx_corr_org_enabled ON correlation_rules(org_id, enabled)
"""

from __future__ import annotations

import logging
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from apps.api.dependencies import get_org_id
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SQLite DB path — override via env var for tests
# ---------------------------------------------------------------------------

_DEFAULT_DB_PATH = Path("data/alert_correlation_rules.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS correlation_rules (
  id            TEXT PRIMARY KEY,
  org_id        TEXT NOT NULL,
  name          TEXT NOT NULL,
  match_field   TEXT NOT NULL,
  match_value   TEXT,
  window_secs   INTEGER NOT NULL DEFAULT 300,
  suppress_secs INTEGER NOT NULL DEFAULT 0,
  action        TEXT NOT NULL DEFAULT 'group',
  enabled       INTEGER NOT NULL DEFAULT 1,
  created_at    TEXT NOT NULL,
  updated_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_corr_org_enabled ON correlation_rules(org_id, enabled);
"""

_VALID_ACTIONS = {"group", "suppress", "escalate"}


# ---------------------------------------------------------------------------
# Thread-safe DB manager (singleton per db_path)
# ---------------------------------------------------------------------------

class _AlertCorrelationDB:
    """Thread-safe SQLite wrapper for alert correlation rules."""

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = Path(db_path)
        self._lock = threading.RLock()
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_schema(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.executescript(_SCHEMA)
                conn.commit()
            finally:
                conn.close()

    def count_rules(self, org_id: Optional[str] = None) -> Dict[str, int]:
        """Return {'total': N, 'enabled': M} optionally scoped to org_id."""
        with self._lock:
            conn = self._connect()
            try:
                if org_id:
                    total = conn.execute(
                        "SELECT COUNT(*) FROM correlation_rules WHERE org_id=?", (org_id,)
                    ).fetchone()[0]
                    enabled = conn.execute(
                        "SELECT COUNT(*) FROM correlation_rules WHERE org_id=? AND enabled=1",
                        (org_id,),
                    ).fetchone()[0]
                else:
                    total = conn.execute("SELECT COUNT(*) FROM correlation_rules").fetchone()[0]
                    enabled = conn.execute(
                        "SELECT COUNT(*) FROM correlation_rules WHERE enabled=1"
                    ).fetchone()[0]
                return {"total": total, "enabled": enabled}
            finally:
                conn.close()

    def list_rules(self, org_id: str) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT * FROM correlation_rules WHERE org_id=? ORDER BY created_at DESC",
                    (org_id,),
                ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def get_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT * FROM correlation_rules WHERE id=?", (rule_id,)
                ).fetchone()
                return dict(row) if row else None
            finally:
                conn.close()

    def create_rule(self, data: Dict[str, Any]) -> Dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        rule_id = str(uuid.uuid4())
        row = {
            "id": rule_id,
            "org_id": data["org_id"],
            "name": data["name"],
            "match_field": data["match_field"],
            "match_value": data.get("match_value"),
            "window_secs": data.get("window_secs", 300),
            "suppress_secs": data.get("suppress_secs", 0),
            "action": data.get("action", "group"),
            "enabled": 1,
            "created_at": now,
            "updated_at": now,
        }
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """INSERT INTO correlation_rules
                       (id, org_id, name, match_field, match_value, window_secs,
                        suppress_secs, action, enabled, created_at, updated_at)
                       VALUES (:id, :org_id, :name, :match_field, :match_value,
                               :window_secs, :suppress_secs, :action, :enabled,
                               :created_at, :updated_at)""",
                    row,
                )
                conn.commit()
            finally:
                conn.close()
        _logger.info(
            "alert_correlation_rule_created id=%s org_id=%s name=%r action=%s",
            rule_id, row["org_id"], row["name"], row["action"],
        )
        return row

    def update_rule(self, rule_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        allowed = {"name", "match_value", "window_secs", "suppress_secs", "action", "enabled"}
        filtered = {k: v for k, v in updates.items() if k in allowed and v is not None}
        if not filtered:
            return self.get_rule(rule_id)
        now = datetime.now(timezone.utc).isoformat()
        filtered["updated_at"] = now
        set_clause = ", ".join(f"{k}=:{k}" for k in filtered)
        filtered["_rule_id"] = rule_id
        with self._lock:
            conn = self._connect()
            try:
                result = conn.execute(
                    f"UPDATE correlation_rules SET {set_clause} WHERE id=:_rule_id",  # noqa: S608
                    filtered,
                )
                conn.commit()
                if result.rowcount == 0:
                    return None
            finally:
                conn.close()
        _logger.info("alert_correlation_rule_updated id=%s fields=%s", rule_id, list(filtered.keys()))
        return self.get_rule(rule_id)

    def delete_rule(self, rule_id: str) -> bool:
        with self._lock:
            conn = self._connect()
            try:
                result = conn.execute(
                    "DELETE FROM correlation_rules WHERE id=?", (rule_id,)
                )
                conn.commit()
                deleted = result.rowcount > 0
            finally:
                conn.close()
        if deleted:
            _logger.info("alert_correlation_rule_deleted id=%s", rule_id)
        return deleted


# Module-level DB instance — path resolved at import time (tests override via env)
_db: Optional[_AlertCorrelationDB] = None
_db_lock = threading.Lock()


def _get_db() -> _AlertCorrelationDB:
    global _db
    with _db_lock:
        if _db is None:
            db_path = os.environ.get(
                "ALERT_CORRELATION_DB_PATH", str(_DEFAULT_DB_PATH)
            )
            _db = _AlertCorrelationDB(db_path)
    return _db


# ---------------------------------------------------------------------------
# FastAPI router
# ---------------------------------------------------------------------------

router = APIRouter(
    prefix="/api/v1/alert-mgmt",
    tags=["Alert Correlation"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class RouterInfoResponse(BaseModel):
    service: str = "Alert Correlation Rules"
    prefix: str = "/api/v1/alert-mgmt"
    endpoints: List[str]
    rule_count: int
    enabled_count: int
    status: str  # ok | empty


class CorrelationRuleResponse(BaseModel):
    id: str
    org_id: str
    name: str
    match_field: str
    match_value: Optional[str] = None
    window_secs: int
    suppress_secs: int
    action: str
    enabled: int
    created_at: str
    updated_at: str


class RuleListResponse(BaseModel):
    rules: List[CorrelationRuleResponse]
    count: int


class CreateRuleRequest(BaseModel):
    org_id: str = Field(default="default", min_length=1, max_length=256)
    name: str = Field(..., min_length=1, max_length=256)
    match_field: str = Field(..., min_length=1, max_length=128,
                             description="Field to match on, e.g. 'cve_id', 'source_tool', 'asset_id'")
    match_value: Optional[str] = Field(None, max_length=512,
                                       description="Exact match value; null = any")
    window_secs: int = Field(default=300, ge=1, le=86400,
                             description="Coalesce alerts within this window (seconds)")
    suppress_secs: int = Field(default=0, ge=0, le=604800,
                               description="Suppress follow-up alerts for N seconds (0 = no suppression)")
    action: str = Field(default="group", description="'group' | 'suppress' | 'escalate'")


class UpdateRuleRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=256)
    match_value: Optional[str] = Field(None, max_length=512)
    window_secs: Optional[int] = Field(None, ge=1, le=86400)
    suppress_secs: Optional[int] = Field(None, ge=0, le=604800)
    action: Optional[str] = None
    enabled: Optional[int] = Field(None, ge=0, le=1)


# ---------------------------------------------------------------------------
# GET / — router info
# ---------------------------------------------------------------------------


@router.get("/", response_model=RouterInfoResponse)
async def router_info() -> RouterInfoResponse:
    """Return info about the alert correlation rules surface.

    Always returns 200 — no credentials required; data is local SQLite.
    """
    db = _get_db()
    counts = db.count_rules()
    status = "ok" if counts["total"] > 0 else "empty"
    _logger.info(
        "alert_correlation_info rule_count=%d enabled=%d",
        counts["total"], counts["enabled"],
    )
    return RouterInfoResponse(
        endpoints=[
            "GET    /rules?org_id=",
            "POST   /rules",
            "GET    /rules/{rule_id}",
            "PUT    /rules/{rule_id}",
            "DELETE /rules/{rule_id}",
        ],
        rule_count=counts["total"],
        enabled_count=counts["enabled"],
        status=status,
    )


# ---------------------------------------------------------------------------
# GET /rules — list rules for org
# ---------------------------------------------------------------------------


@router.get("/rules", response_model=RuleListResponse)
async def list_rules(
    org_id: str = Depends(get_org_id),
) -> RuleListResponse:
    """List all correlation rules for the given org_id."""
    db = _get_db()
    rows = db.list_rules(org_id)
    _logger.info("alert_correlation_list_rules org_id=%s count=%d", org_id, len(rows))
    return RuleListResponse(
        rules=[CorrelationRuleResponse(**r) for r in rows],
        count=len(rows),
    )


# ---------------------------------------------------------------------------
# POST /rules — create a rule
# ---------------------------------------------------------------------------


@router.post("/rules", response_model=CorrelationRuleResponse, status_code=201)
async def create_rule(body: CreateRuleRequest) -> CorrelationRuleResponse:
    """Create a new alert correlation rule.

    Returns the created row with its generated ``id``.
    HTTP 422 if ``action`` is not one of 'group', 'suppress', 'escalate'.
    """
    if body.action not in _VALID_ACTIONS:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "invalid_action",
                "allowed": sorted(_VALID_ACTIONS),
                "received": body.action,
            },
        )
    db = _get_db()
    created = db.create_rule(body.model_dump())
    return CorrelationRuleResponse(**created)


# ---------------------------------------------------------------------------
# GET /rules/{rule_id} — fetch single rule
# ---------------------------------------------------------------------------


@router.get("/rules/{rule_id}", response_model=CorrelationRuleResponse)
async def get_rule(rule_id: str) -> CorrelationRuleResponse:
    """Fetch a single correlation rule by its UUID.

    Returns HTTP 404 when the rule_id does not exist.
    """
    db = _get_db()
    row = db.get_rule(rule_id)
    if row is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "rule_not_found", "rule_id": rule_id},
        )
    return CorrelationRuleResponse(**row)


# ---------------------------------------------------------------------------
# PUT /rules/{rule_id} — partial update
# ---------------------------------------------------------------------------


@router.put("/rules/{rule_id}", response_model=CorrelationRuleResponse)
async def update_rule(rule_id: str, body: UpdateRuleRequest) -> CorrelationRuleResponse:
    """Partially update a correlation rule.

    Only supplied (non-null) fields are written. Returns the updated row.
    HTTP 404 when rule_id does not exist.
    HTTP 422 when action value is invalid.
    """
    if body.action is not None and body.action not in _VALID_ACTIONS:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "invalid_action",
                "allowed": sorted(_VALID_ACTIONS),
                "received": body.action,
            },
        )
    db = _get_db()
    updated = db.update_rule(rule_id, body.model_dump(exclude_none=True))
    if updated is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "rule_not_found", "rule_id": rule_id},
        )
    return CorrelationRuleResponse(**updated)


# ---------------------------------------------------------------------------
# DELETE /rules/{rule_id} — hard delete
# ---------------------------------------------------------------------------


@router.delete("/rules/{rule_id}", status_code=204)
async def delete_rule(rule_id: str) -> None:
    """Hard-delete a correlation rule.

    Returns HTTP 204 on success, HTTP 404 when rule_id does not exist.
    Deletion is permanent — use enabled=0 via PUT if you want soft-disable.
    """
    db = _get_db()
    deleted = db.delete_rule(rule_id)
    if not deleted:
        raise HTTPException(
            status_code=404,
            detail={"error": "rule_not_found", "rule_id": rule_id},
        )


__all__ = ["router"]
