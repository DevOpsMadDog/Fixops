"""RaaS Intelligence Router — ALDECI (Multica #3760, 2026-05-31).

RaaS-specific threat intelligence: extortion negotiation tracking, dark-web
leak-site monitoring, and affiliate group attribution. Complements the existing
ransomware_protection_router.py (detection/containment/playbooks) with
adversary-facing intel stored in a dedicated SQLite domain DB.

Prefix: /api/v1/raas-intel
Auth:   api_key_auth dependency (read:scans scope at registration)
Storage: SQLite at data/raas_intel.db (thread-safe RLock pattern)

Routes:
  GET    /api/v1/raas-intel/                         router info + summary counts
  GET    /api/v1/raas-intel/raas-groups              list groups (filter org_id, status)
  POST   /api/v1/raas-intel/raas-groups              create a group record
  PUT    /api/v1/raas-intel/raas-groups/{id}         partial update a group record
  GET    /api/v1/raas-intel/extortion-intel          list negotiations (filter org_id, status)
  POST   /api/v1/raas-intel/extortion-intel          create a negotiation record
  GET    /api/v1/raas-intel/leak-posts               list leak-site posts (filter org_id, days)
  POST   /api/v1/raas-intel/leak-posts               create a leak-site post record

NO MOCKS rule: all data is read from / written to the live SQLite database.
When a record id is not found PUT returns HTTP 404. No fabricated rows.

Schema
------
  raas_groups           (id, org_id, name, aliases, tactics, active_since,
                         last_seen, status, created_at)
  leak_site_posts       (id, org_id, group_id, victim_org, leak_url,
                         posted_at, data_size_gb, status, created_at)
  extortion_negotiations (id, org_id, group_id, ransom_demand_usd, paid,
                          paid_usd, status, notes, started_at, updated_at)

  Indexes:
    idx_raas_org_status    ON raas_groups(org_id, status)
    idx_leak_org_posted    ON leak_site_posts(org_id, posted_at DESC)
    idx_extortion_org_stat ON extortion_negotiations(org_id, status)
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SQLite DB path — override via env var for tests
# ---------------------------------------------------------------------------

_DEFAULT_DB_PATH = Path("data/raas_intel.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS raas_groups (
  id           TEXT PRIMARY KEY,
  org_id       TEXT NOT NULL,
  name         TEXT NOT NULL,
  aliases      TEXT,
  tactics      TEXT,
  active_since TEXT,
  last_seen    TEXT,
  status       TEXT NOT NULL DEFAULT 'active',
  created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_raas_org_status ON raas_groups(org_id, status);

CREATE TABLE IF NOT EXISTS leak_site_posts (
  id           TEXT PRIMARY KEY,
  org_id       TEXT NOT NULL,
  group_id     TEXT,
  victim_org   TEXT NOT NULL,
  leak_url     TEXT,
  posted_at    TEXT NOT NULL,
  data_size_gb REAL,
  status       TEXT NOT NULL DEFAULT 'posted',
  created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_leak_org_posted ON leak_site_posts(org_id, posted_at DESC);

CREATE TABLE IF NOT EXISTS extortion_negotiations (
  id                TEXT PRIMARY KEY,
  org_id            TEXT NOT NULL,
  group_id          TEXT,
  ransom_demand_usd REAL,
  paid              INTEGER NOT NULL DEFAULT 0,
  paid_usd          REAL,
  status            TEXT NOT NULL DEFAULT 'open',
  notes             TEXT,
  started_at        TEXT NOT NULL,
  updated_at        TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_extortion_org_status ON extortion_negotiations(org_id, status);
"""

_VALID_GROUP_STATUSES = {"active", "defunct", "sanctioned"}
_VALID_LEAK_STATUSES = {"posted", "partial", "full", "removed"}
_VALID_EXTORTION_STATUSES = {"open", "paid", "expired", "negotiating"}


# ---------------------------------------------------------------------------
# Thread-safe DB manager
# ---------------------------------------------------------------------------


class _RaasIntelDB:
    """Thread-safe SQLite wrapper for RaaS intelligence tables."""

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

    # ------------------------------------------------------------------
    # Summary / info counts
    # ------------------------------------------------------------------

    def summary_counts(self) -> Dict[str, Any]:
        """Return group count, leak posts last 30d, open negotiations."""
        cutoff = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        with self._lock:
            conn = self._connect()
            try:
                group_count = conn.execute(
                    "SELECT COUNT(*) FROM raas_groups"
                ).fetchone()[0]
                leak_30d = conn.execute(
                    "SELECT COUNT(*) FROM leak_site_posts WHERE posted_at >= ?",
                    (cutoff,),
                ).fetchone()[0]
                open_negot = conn.execute(
                    "SELECT COUNT(*) FROM extortion_negotiations WHERE status='open'"
                ).fetchone()[0]
                return {
                    "group_count": group_count,
                    "leak_posts_last_30d": leak_30d,
                    "open_negotiations": open_negot,
                }
            finally:
                conn.close()

    # ------------------------------------------------------------------
    # RaaS groups
    # ------------------------------------------------------------------

    def list_groups(self, org_id: str, status: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                if status:
                    rows = conn.execute(
                        "SELECT * FROM raas_groups WHERE org_id=? AND status=? ORDER BY created_at DESC",
                        (org_id, status),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM raas_groups WHERE org_id=? ORDER BY created_at DESC",
                        (org_id,),
                    ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def create_group(self, data: Dict[str, Any]) -> Dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        row = {
            "id": str(uuid.uuid4()),
            "org_id": data.get("org_id", "default"),
            "name": data["name"],
            "aliases": json.dumps(data.get("aliases") or []),
            "tactics": json.dumps(data.get("tactics") or []),
            "active_since": data.get("active_since"),
            "last_seen": data.get("last_seen"),
            "status": data.get("status") or "active",
            "created_at": now,
        }
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """INSERT INTO raas_groups
                       (id, org_id, name, aliases, tactics, active_since,
                        last_seen, status, created_at)
                       VALUES (:id, :org_id, :name, :aliases, :tactics,
                               :active_since, :last_seen, :status, :created_at)""",
                    row,
                )
                conn.commit()
            finally:
                conn.close()
        _logger.info(
            "raas_group_created id=%s org_id=%s name=%r status=%s",
            row["id"], row["org_id"], row["name"], row["status"],
        )
        return row

    def update_group(self, group_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        allowed = {"name", "aliases", "tactics", "active_since", "last_seen", "status"}
        filtered: Dict[str, Any] = {}
        for k, v in updates.items():
            if k not in allowed or v is None:
                continue
            # Serialize lists to JSON for storage
            if k in ("aliases", "tactics") and isinstance(v, list):
                filtered[k] = json.dumps(v)
            else:
                filtered[k] = v
        if not filtered:
            return self._get_group(group_id)
        set_clause = ", ".join(f"{k}=:{k}" for k in filtered)
        filtered["_group_id"] = group_id
        with self._lock:
            conn = self._connect()
            try:
                result = conn.execute(
                    f"UPDATE raas_groups SET {set_clause} WHERE id=:_group_id",  # noqa: S608
                    filtered,
                )
                conn.commit()
                if result.rowcount == 0:
                    return None
            finally:
                conn.close()
        _logger.info("raas_group_updated id=%s fields=%s", group_id, list(filtered.keys()))
        return self._get_group(group_id)

    def _get_group(self, group_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT * FROM raas_groups WHERE id=?", (group_id,)
                ).fetchone()
                return dict(row) if row else None
            finally:
                conn.close()

    # ------------------------------------------------------------------
    # Extortion negotiations
    # ------------------------------------------------------------------

    def list_negotiations(self, org_id: str, status: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                if status:
                    rows = conn.execute(
                        """SELECT * FROM extortion_negotiations
                           WHERE org_id=? AND status=? ORDER BY started_at DESC""",
                        (org_id, status),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM extortion_negotiations WHERE org_id=? ORDER BY started_at DESC",
                        (org_id,),
                    ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def create_negotiation(self, data: Dict[str, Any]) -> Dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        row = {
            "id": str(uuid.uuid4()),
            "org_id": data.get("org_id", "default"),
            "group_id": data.get("group_id"),
            "ransom_demand_usd": data.get("ransom_demand_usd"),
            "paid": 0,
            "paid_usd": data.get("paid_usd"),
            "status": data.get("status") or "open",
            "notes": data.get("notes"),
            "started_at": now,
            "updated_at": now,
        }
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """INSERT INTO extortion_negotiations
                       (id, org_id, group_id, ransom_demand_usd, paid, paid_usd,
                        status, notes, started_at, updated_at)
                       VALUES (:id, :org_id, :group_id, :ransom_demand_usd, :paid, :paid_usd,
                               :status, :notes, :started_at, :updated_at)""",
                    row,
                )
                conn.commit()
            finally:
                conn.close()
        _logger.info(
            "extortion_negotiation_created id=%s org_id=%s status=%s",
            row["id"], row["org_id"], row["status"],
        )
        return row

    # ------------------------------------------------------------------
    # Leak site posts
    # ------------------------------------------------------------------

    def list_leak_posts(self, org_id: str, days: int = 30) -> List[Dict[str, Any]]:
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    """SELECT * FROM leak_site_posts
                       WHERE org_id=? AND posted_at >= ?
                       ORDER BY posted_at DESC""",
                    (org_id, cutoff),
                ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def create_leak_post(self, data: Dict[str, Any]) -> Dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        row = {
            "id": str(uuid.uuid4()),
            "org_id": data.get("org_id", "default"),
            "group_id": data.get("group_id"),
            "victim_org": data["victim_org"],
            "leak_url": data.get("leak_url"),
            "posted_at": now,
            "data_size_gb": data.get("data_size_gb"),
            "status": data.get("status") or "posted",
            "created_at": now,
        }
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """INSERT INTO leak_site_posts
                       (id, org_id, group_id, victim_org, leak_url,
                        posted_at, data_size_gb, status, created_at)
                       VALUES (:id, :org_id, :group_id, :victim_org, :leak_url,
                               :posted_at, :data_size_gb, :status, :created_at)""",
                    row,
                )
                conn.commit()
            finally:
                conn.close()
        _logger.info(
            "leak_post_created id=%s org_id=%s victim_org=%r status=%s",
            row["id"], row["org_id"], row["victim_org"], row["status"],
        )
        return row


# Module-level DB instance — lazily initialized
_db: Optional[_RaasIntelDB] = None
_db_lock = threading.Lock()


def _get_db() -> _RaasIntelDB:
    global _db
    with _db_lock:
        if _db is None:
            db_path = os.environ.get("RAAS_INTEL_DB_PATH", str(_DEFAULT_DB_PATH))
            _db = _RaasIntelDB(db_path)
    return _db


# ---------------------------------------------------------------------------
# FastAPI router
# ---------------------------------------------------------------------------

router = APIRouter(
    prefix="/api/v1/raas-intel",
    tags=["RaaS Intelligence"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class RouterInfoResponse(BaseModel):
    service: str = "RaaS Intelligence"
    prefix: str = "/api/v1/raas-intel"
    endpoints: List[str]
    group_count: int
    leak_posts_last_30d: int
    open_negotiations: int
    status: str  # ok | empty


class RaasGroupResponse(BaseModel):
    id: str
    org_id: str
    name: str
    aliases: Optional[str] = None   # JSON string
    tactics: Optional[str] = None   # JSON string
    active_since: Optional[str] = None
    last_seen: Optional[str] = None
    status: str
    created_at: str


class GroupListResponse(BaseModel):
    groups: List[RaasGroupResponse]
    count: int


class CreateGroupRequest(BaseModel):
    org_id: str = Field(default="default", min_length=1, max_length=256)
    name: str = Field(..., min_length=1, max_length=256)
    aliases: Optional[List[str]] = Field(None, description="Known aliases / alternative names")
    tactics: Optional[List[str]] = Field(None, description="ATT&CK technique IDs e.g. ['T1486','T1489']")
    active_since: Optional[str] = Field(None, max_length=32, description="ISO date or year string")
    status: Optional[str] = Field(None, description="active | defunct | sanctioned")


class UpdateGroupRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=256)
    aliases: Optional[List[str]] = None
    tactics: Optional[List[str]] = None
    active_since: Optional[str] = Field(None, max_length=32)
    last_seen: Optional[str] = Field(None, max_length=32)
    status: Optional[str] = None


class ExtortionNegotiationResponse(BaseModel):
    id: str
    org_id: str
    group_id: Optional[str] = None
    ransom_demand_usd: Optional[float] = None
    paid: int
    paid_usd: Optional[float] = None
    status: str
    notes: Optional[str] = None
    started_at: str
    updated_at: str


class NegotiationListResponse(BaseModel):
    negotiations: List[ExtortionNegotiationResponse]
    count: int


class CreateNegotiationRequest(BaseModel):
    org_id: str = Field(default="default", min_length=1, max_length=256)
    group_id: Optional[str] = Field(None, max_length=36, description="FK to raas_groups.id (loose)")
    ransom_demand_usd: Optional[float] = Field(None, ge=0)
    status: Optional[str] = Field(None, description="open | paid | expired | negotiating")
    notes: Optional[str] = Field(None, max_length=4096)


class LeakPostResponse(BaseModel):
    id: str
    org_id: str
    group_id: Optional[str] = None
    victim_org: str
    leak_url: Optional[str] = None
    posted_at: str
    data_size_gb: Optional[float] = None
    status: str
    created_at: str


class LeakPostListResponse(BaseModel):
    posts: List[LeakPostResponse]
    count: int


class CreateLeakPostRequest(BaseModel):
    org_id: str = Field(default="default", min_length=1, max_length=256)
    group_id: Optional[str] = Field(None, max_length=36, description="FK to raas_groups.id (loose)")
    victim_org: str = Field(..., min_length=1, max_length=512)
    leak_url: Optional[str] = Field(None, max_length=2048)
    data_size_gb: Optional[float] = Field(None, ge=0)
    status: Optional[str] = Field(None, description="posted | partial | full | removed")


# ---------------------------------------------------------------------------
# GET / — router info
# ---------------------------------------------------------------------------


@router.get("/", response_model=RouterInfoResponse)
async def router_info() -> RouterInfoResponse:
    """Return RaaS intelligence service info and aggregate counts.

    Always returns 200. Data comes from live SQLite; no fabricated numbers.
    """
    db = _get_db()
    counts = db.summary_counts()
    total = counts["group_count"] + counts["leak_posts_last_30d"] + counts["open_negotiations"]
    status = "ok" if total > 0 else "empty"
    _logger.info(
        "raas_intel_info groups=%d leaks_30d=%d open_negot=%d",
        counts["group_count"], counts["leak_posts_last_30d"], counts["open_negotiations"],
    )
    return RouterInfoResponse(
        endpoints=[
            "GET    /raas-groups?org_id=&status=",
            "POST   /raas-groups",
            "PUT    /raas-groups/{id}",
            "GET    /extortion-intel?org_id=&status=open",
            "POST   /extortion-intel",
            "GET    /leak-posts?org_id=&days=30",
            "POST   /leak-posts",
        ],
        group_count=counts["group_count"],
        leak_posts_last_30d=counts["leak_posts_last_30d"],
        open_negotiations=counts["open_negotiations"],
        status=status,
    )


# ---------------------------------------------------------------------------
# GET /raas-groups — list groups
# ---------------------------------------------------------------------------


@router.get("/raas-groups", response_model=GroupListResponse)
async def list_groups(
    org_id: str = Query(default="default", min_length=1, max_length=256),
    status: Optional[str] = Query(None, description="Filter by status: active | defunct | sanctioned"),
) -> GroupListResponse:
    """List RaaS affiliate groups, optionally filtered by status."""
    if status is not None and status not in _VALID_GROUP_STATUSES:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "invalid_status",
                "allowed": sorted(_VALID_GROUP_STATUSES),
                "received": status,
            },
        )
    db = _get_db()
    rows = db.list_groups(org_id, status)
    _logger.info("raas_groups_listed org_id=%s status=%s count=%d", org_id, status, len(rows))
    return GroupListResponse(groups=[RaasGroupResponse(**r) for r in rows], count=len(rows))


# ---------------------------------------------------------------------------
# POST /raas-groups — create group
# ---------------------------------------------------------------------------


@router.post("/raas-groups", response_model=RaasGroupResponse, status_code=201)
async def create_group(body: CreateGroupRequest) -> RaasGroupResponse:
    """Create a new RaaS affiliate group record.

    HTTP 422 when status is not one of 'active', 'defunct', 'sanctioned'.
    """
    if body.status is not None and body.status not in _VALID_GROUP_STATUSES:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "invalid_status",
                "allowed": sorted(_VALID_GROUP_STATUSES),
                "received": body.status,
            },
        )
    db = _get_db()
    created = db.create_group(body.model_dump())
    return RaasGroupResponse(**created)


# ---------------------------------------------------------------------------
# PUT /raas-groups/{id} — partial update group
# ---------------------------------------------------------------------------


@router.put("/raas-groups/{group_id}", response_model=RaasGroupResponse)
async def update_group(group_id: str, body: UpdateGroupRequest) -> RaasGroupResponse:
    """Partially update a RaaS group record. Only non-null fields are written.

    HTTP 404 when group_id does not exist.
    HTTP 422 when status value is invalid.
    """
    if body.status is not None and body.status not in _VALID_GROUP_STATUSES:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "invalid_status",
                "allowed": sorted(_VALID_GROUP_STATUSES),
                "received": body.status,
            },
        )
    db = _get_db()
    updated = db.update_group(group_id, body.model_dump(exclude_none=True))
    if updated is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "group_not_found", "group_id": group_id},
        )
    return RaasGroupResponse(**updated)


# ---------------------------------------------------------------------------
# GET /extortion-intel — list negotiations
# ---------------------------------------------------------------------------


@router.get("/extortion-intel", response_model=NegotiationListResponse)
async def list_negotiations(
    org_id: str = Query(default="default", min_length=1, max_length=256),
    status: Optional[str] = Query(None, description="Filter by status: open | paid | expired | negotiating"),
) -> NegotiationListResponse:
    """List extortion negotiations, optionally filtered by status."""
    if status is not None and status not in _VALID_EXTORTION_STATUSES:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "invalid_status",
                "allowed": sorted(_VALID_EXTORTION_STATUSES),
                "received": status,
            },
        )
    db = _get_db()
    rows = db.list_negotiations(org_id, status)
    _logger.info(
        "extortion_negotiations_listed org_id=%s status=%s count=%d",
        org_id, status, len(rows),
    )
    return NegotiationListResponse(
        negotiations=[ExtortionNegotiationResponse(**r) for r in rows],
        count=len(rows),
    )


# ---------------------------------------------------------------------------
# POST /extortion-intel — create negotiation
# ---------------------------------------------------------------------------


@router.post("/extortion-intel", response_model=ExtortionNegotiationResponse, status_code=201)
async def create_negotiation(body: CreateNegotiationRequest) -> ExtortionNegotiationResponse:
    """Create a new extortion negotiation record.

    HTTP 422 when status is not a valid negotiation status value.
    """
    if body.status is not None and body.status not in _VALID_EXTORTION_STATUSES:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "invalid_status",
                "allowed": sorted(_VALID_EXTORTION_STATUSES),
                "received": body.status,
            },
        )
    db = _get_db()
    created = db.create_negotiation(body.model_dump())
    return ExtortionNegotiationResponse(**created)


# ---------------------------------------------------------------------------
# GET /leak-posts — list leak site posts
# ---------------------------------------------------------------------------


@router.get("/leak-posts", response_model=LeakPostListResponse)
async def list_leak_posts(
    org_id: str = Query(default="default", min_length=1, max_length=256),
    days: int = Query(default=30, ge=1, le=3650, description="Look-back window in days (max 10y)"),
) -> LeakPostListResponse:
    """List dark-web leak-site posts within the specified time window."""
    db = _get_db()
    rows = db.list_leak_posts(org_id, days)
    _logger.info("leak_posts_listed org_id=%s days=%d count=%d", org_id, days, len(rows))
    return LeakPostListResponse(posts=[LeakPostResponse(**r) for r in rows], count=len(rows))


# ---------------------------------------------------------------------------
# POST /leak-posts — create leak post
# ---------------------------------------------------------------------------


@router.post("/leak-posts", response_model=LeakPostResponse, status_code=201)
async def create_leak_post(body: CreateLeakPostRequest) -> LeakPostResponse:
    """Create a new dark-web leak-site post record.

    HTTP 422 when status is not one of 'posted', 'partial', 'full', 'removed'.
    """
    if body.status is not None and body.status not in _VALID_LEAK_STATUSES:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "invalid_status",
                "allowed": sorted(_VALID_LEAK_STATUSES),
                "received": body.status,
            },
        )
    db = _get_db()
    created = db.create_leak_post(body.model_dump())
    return LeakPostResponse(**created)


__all__ = ["router"]
