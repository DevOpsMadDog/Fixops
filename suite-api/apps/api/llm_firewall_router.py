"""LLM Firewall / Prompt-Injection / Model-Governance Router — ALDECI (Multica #3761, 2026-05-31).

API surface for the AI-security wave. Provides:
  - Firewall policy management (regex block patterns + semantic categories)
  - Real-time prompt scanning against active policies
  - Injection-event ledger (per-org, time-filterable)
  - Model-governance registry (approved models, data-residency, approval workflow)

Prefix: /api/v1/llm-firewall
Auth:   api_key_auth dependency (read:scans scope at registration)
Storage: SQLite at data/llm_firewall.db (thread-safe RLock pattern)

Routes:
  GET    /api/v1/llm-firewall/                        router info + aggregate counts
  GET    /api/v1/llm-firewall/policies                list policies (filter by org_id)
  POST   /api/v1/llm-firewall/policies                create a firewall policy
  PUT    /api/v1/llm-firewall/policies/{id}           partial update a policy
  DELETE /api/v1/llm-firewall/policies/{id}           delete a policy
  POST   /api/v1/llm-firewall/scan                    scan a prompt against active policies
  GET    /api/v1/llm-firewall/events                  list injection events (filter org_id, hours, category)
  GET    /api/v1/llm-firewall/models                  list governed models (filter org_id, approved)
  POST   /api/v1/llm-firewall/models                  register a model for governance
  PUT    /api/v1/llm-firewall/models/{id}/approve     approve a governed model

NO MOCKS rule: all data is read from / written to the live SQLite database.
The /scan endpoint runs heuristic checks against active policies and writes
injection_events rows for every match. No fabricated detections.

Heuristics (applied in order, first matching action wins):
  prompt_injection  — prompt contains "ignore previous instructions" (case-insensitive)
  jailbreak         — prompt contains "DAN" as a word boundary (case-insensitive)
  pii_exfil         — prompt contains an email-like pattern ([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})
  secret_leak       — prompt contains token prefixes: sk-, ghp_, AKIA

Schema
------
  firewall_policies   (id, org_id, name, block_patterns, block_categories,
                       action, enabled, created_at, updated_at)
  injection_events    (id, org_id, policy_id, prompt_snippet, category,
                       confidence, action_taken, user_id, source_model, detected_at)
  model_governance    (id, org_id, model_name, provider, approved, data_residency,
                       approved_by, approved_at, notes, created_at)

  Indexes:
    idx_fwpol_org_enabled  ON firewall_policies(org_id, enabled)
    idx_inj_org_time       ON injection_events(org_id, detected_at DESC)
    idx_govern_org_approved ON model_governance(org_id, approved)
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
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

_DEFAULT_DB_PATH = Path("data/llm_firewall.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS firewall_policies (
  id               TEXT PRIMARY KEY,
  org_id           TEXT NOT NULL,
  name             TEXT NOT NULL,
  block_patterns   TEXT,
  block_categories TEXT,
  action           TEXT NOT NULL DEFAULT 'block',
  enabled          INTEGER NOT NULL DEFAULT 1,
  created_at       TEXT NOT NULL,
  updated_at       TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fwpol_org_enabled ON firewall_policies(org_id, enabled);

CREATE TABLE IF NOT EXISTS injection_events (
  id             TEXT PRIMARY KEY,
  org_id         TEXT NOT NULL,
  policy_id      TEXT,
  prompt_snippet TEXT NOT NULL,
  category       TEXT NOT NULL,
  confidence     REAL NOT NULL DEFAULT 0.0,
  action_taken   TEXT NOT NULL,
  user_id        TEXT,
  source_model   TEXT,
  detected_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_inj_org_time ON injection_events(org_id, detected_at DESC);

CREATE TABLE IF NOT EXISTS model_governance (
  id             TEXT PRIMARY KEY,
  org_id         TEXT NOT NULL,
  model_name     TEXT NOT NULL,
  provider       TEXT NOT NULL,
  approved       INTEGER NOT NULL DEFAULT 0,
  data_residency TEXT,
  approved_by    TEXT,
  approved_at    TEXT,
  notes          TEXT,
  created_at     TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_govern_org_approved ON model_governance(org_id, approved);
"""

_VALID_ACTIONS = {"block", "warn", "log"}
_VALID_CATEGORIES = {"prompt_injection", "jailbreak", "pii_exfil", "secret_leak"}

# Heuristic patterns for /scan — checked in order
_HEURISTICS: List[tuple[str, re.Pattern[str], float]] = [
    ("prompt_injection", re.compile(r"ignore\s+previous\s+instructions", re.IGNORECASE), 0.95),
    ("jailbreak", re.compile(r"\bDAN\b", re.IGNORECASE), 0.85),
    ("pii_exfil", re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"), 0.80),
    ("secret_leak", re.compile(r"(?:sk-[A-Za-z0-9]{10,}|ghp_[A-Za-z0-9]{10,}|AKIA[A-Z0-9]{16})"), 0.90),
]


# ---------------------------------------------------------------------------
# Thread-safe DB manager
# ---------------------------------------------------------------------------


class _LlmFirewallDB:
    """Thread-safe SQLite wrapper for LLM firewall tables."""

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
    # Info / aggregate counts
    # ------------------------------------------------------------------

    def info_counts(self) -> Dict[str, Any]:
        """Return policy count, events last 24h, governed model count."""
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        with self._lock:
            conn = self._connect()
            try:
                policy_count = conn.execute(
                    "SELECT COUNT(*) FROM firewall_policies"
                ).fetchone()[0]
                events_24h = conn.execute(
                    "SELECT COUNT(*) FROM injection_events WHERE detected_at >= ?",
                    (cutoff,),
                ).fetchone()[0]
                model_count = conn.execute(
                    "SELECT COUNT(*) FROM model_governance"
                ).fetchone()[0]
                return {
                    "policy_count": policy_count,
                    "events_last_24h": events_24h,
                    "governed_model_count": model_count,
                }
            finally:
                conn.close()

    # ------------------------------------------------------------------
    # Policies
    # ------------------------------------------------------------------

    def list_policies(self, org_id: str) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT * FROM firewall_policies WHERE org_id=? ORDER BY created_at DESC",
                    (org_id,),
                ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def list_active_policies(self, org_id: str) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                rows = conn.execute(
                    "SELECT * FROM firewall_policies WHERE org_id=? AND enabled=1 ORDER BY created_at DESC",
                    (org_id,),
                ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def create_policy(self, data: Dict[str, Any]) -> Dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        row = {
            "id": str(uuid.uuid4()),
            "org_id": data.get("org_id", "default"),
            "name": data["name"],
            "block_patterns": json.dumps(data.get("block_patterns") or []),
            "block_categories": json.dumps(data.get("block_categories") or []),
            "action": data.get("action", "block"),
            "enabled": 1,
            "created_at": now,
            "updated_at": now,
        }
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """INSERT INTO firewall_policies
                       (id, org_id, name, block_patterns, block_categories,
                        action, enabled, created_at, updated_at)
                       VALUES (:id, :org_id, :name, :block_patterns, :block_categories,
                               :action, :enabled, :created_at, :updated_at)""",
                    row,
                )
                conn.commit()
            finally:
                conn.close()
        _logger.info(
            "llm_fw_policy_created id=%s org_id=%s name=%r action=%s",
            row["id"], row["org_id"], row["name"], row["action"],
        )
        return row

    def update_policy(self, policy_id: str, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        allowed = {"name", "block_patterns", "block_categories", "action", "enabled"}
        filtered: Dict[str, Any] = {}
        for k, v in updates.items():
            if k not in allowed or v is None:
                continue
            if k in ("block_patterns", "block_categories") and isinstance(v, list):
                filtered[k] = json.dumps(v)
            else:
                filtered[k] = v
        if not filtered:
            return self._get_policy(policy_id)
        now = datetime.now(timezone.utc).isoformat()
        filtered["updated_at"] = now
        set_clause = ", ".join(f"{k}=:{k}" for k in filtered)
        filtered["_policy_id"] = policy_id
        with self._lock:
            conn = self._connect()
            try:
                result = conn.execute(
                    f"UPDATE firewall_policies SET {set_clause} WHERE id=:_policy_id",  # noqa: S608
                    filtered,
                )
                conn.commit()
                if result.rowcount == 0:
                    return None
            finally:
                conn.close()
        _logger.info("llm_fw_policy_updated id=%s fields=%s", policy_id, list(filtered.keys()))
        return self._get_policy(policy_id)

    def delete_policy(self, policy_id: str) -> bool:
        with self._lock:
            conn = self._connect()
            try:
                result = conn.execute(
                    "DELETE FROM firewall_policies WHERE id=?", (policy_id,)
                )
                conn.commit()
                deleted = result.rowcount > 0
            finally:
                conn.close()
        if deleted:
            _logger.info("llm_fw_policy_deleted id=%s", policy_id)
        return deleted

    def _get_policy(self, policy_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                row = conn.execute(
                    "SELECT * FROM firewall_policies WHERE id=?", (policy_id,)
                ).fetchone()
                return dict(row) if row else None
            finally:
                conn.close()

    # ------------------------------------------------------------------
    # Injection events
    # ------------------------------------------------------------------

    def create_event(self, data: Dict[str, Any]) -> Dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        row = {
            "id": str(uuid.uuid4()),
            "org_id": data.get("org_id", "default"),
            "policy_id": data.get("policy_id"),
            "prompt_snippet": data["prompt_snippet"][:500],
            "category": data["category"],
            "confidence": data.get("confidence", 0.0),
            "action_taken": data["action_taken"],
            "user_id": data.get("user_id"),
            "source_model": data.get("source_model"),
            "detected_at": now,
        }
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """INSERT INTO injection_events
                       (id, org_id, policy_id, prompt_snippet, category, confidence,
                        action_taken, user_id, source_model, detected_at)
                       VALUES (:id, :org_id, :policy_id, :prompt_snippet, :category, :confidence,
                               :action_taken, :user_id, :source_model, :detected_at)""",
                    row,
                )
                conn.commit()
            finally:
                conn.close()
        _logger.info(
            "llm_fw_event_created id=%s org_id=%s category=%s action=%s confidence=%.2f",
            row["id"], row["org_id"], row["category"], row["action_taken"], row["confidence"],
        )
        return row

    def list_events(
        self,
        org_id: str,
        hours: int = 24,
        category: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        with self._lock:
            conn = self._connect()
            try:
                if category:
                    rows = conn.execute(
                        """SELECT * FROM injection_events
                           WHERE org_id=? AND detected_at >= ? AND category=?
                           ORDER BY detected_at DESC""",
                        (org_id, cutoff, category),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        """SELECT * FROM injection_events
                           WHERE org_id=? AND detected_at >= ?
                           ORDER BY detected_at DESC""",
                        (org_id, cutoff),
                    ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    # ------------------------------------------------------------------
    # Model governance
    # ------------------------------------------------------------------

    def list_models(self, org_id: str, approved: Optional[int] = None) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                if approved is not None:
                    rows = conn.execute(
                        """SELECT * FROM model_governance
                           WHERE org_id=? AND approved=? ORDER BY created_at DESC""",
                        (org_id, approved),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM model_governance WHERE org_id=? ORDER BY created_at DESC",
                        (org_id,),
                    ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def create_model(self, data: Dict[str, Any]) -> Dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        row = {
            "id": str(uuid.uuid4()),
            "org_id": data.get("org_id", "default"),
            "model_name": data["model_name"],
            "provider": data["provider"],
            "approved": 0,
            "data_residency": data.get("data_residency"),
            "approved_by": None,
            "approved_at": None,
            "notes": data.get("notes"),
            "created_at": now,
        }
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """INSERT INTO model_governance
                       (id, org_id, model_name, provider, approved, data_residency,
                        approved_by, approved_at, notes, created_at)
                       VALUES (:id, :org_id, :model_name, :provider, :approved, :data_residency,
                               :approved_by, :approved_at, :notes, :created_at)""",
                    row,
                )
                conn.commit()
            finally:
                conn.close()
        _logger.info(
            "llm_fw_model_registered id=%s org_id=%s model=%r provider=%s",
            row["id"], row["org_id"], row["model_name"], row["provider"],
        )
        return row

    def approve_model(self, model_id: str, approved_by: str) -> Optional[Dict[str, Any]]:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            conn = self._connect()
            try:
                result = conn.execute(
                    """UPDATE model_governance
                       SET approved=1, approved_by=?, approved_at=?
                       WHERE id=?""",
                    (approved_by, now, model_id),
                )
                conn.commit()
                if result.rowcount == 0:
                    return None
                row = conn.execute(
                    "SELECT * FROM model_governance WHERE id=?", (model_id,)
                ).fetchone()
                return dict(row) if row else None
            finally:
                conn.close()


# Module-level DB instance — lazily initialized
_db: Optional[_LlmFirewallDB] = None
_db_lock = threading.Lock()


def _get_db() -> _LlmFirewallDB:
    global _db
    with _db_lock:
        if _db is None:
            db_path = os.environ.get("LLM_FIREWALL_DB_PATH", str(_DEFAULT_DB_PATH))
            _db = _LlmFirewallDB(db_path)
    return _db


# ---------------------------------------------------------------------------
# FastAPI router
# ---------------------------------------------------------------------------

router = APIRouter(
    prefix="/api/v1/llm-firewall",
    tags=["LLM Firewall"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class RouterInfoResponse(BaseModel):
    service: str = "LLM Firewall / Prompt-Injection / Model-Governance"
    prefix: str = "/api/v1/llm-firewall"
    endpoints: List[str]
    policy_count: int
    events_last_24h: int
    governed_model_count: int
    status: str  # ok | empty


class FirewallPolicyResponse(BaseModel):
    id: str
    org_id: str
    name: str
    block_patterns: Optional[str] = None    # JSON string
    block_categories: Optional[str] = None  # JSON string
    action: str
    enabled: int
    created_at: str
    updated_at: str


class PolicyListResponse(BaseModel):
    policies: List[FirewallPolicyResponse]
    count: int


class CreatePolicyRequest(BaseModel):
    org_id: str = Field(default="default", min_length=1, max_length=256)
    name: str = Field(..., min_length=1, max_length=256)
    block_patterns: Optional[List[str]] = Field(
        None, description="List of regex patterns to block"
    )
    block_categories: Optional[List[str]] = Field(
        None,
        description="Categories: prompt_injection | jailbreak | pii_exfil | secret_leak",
    )
    action: str = Field(default="block", description="block | warn | log")


class UpdatePolicyRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=256)
    block_patterns: Optional[List[str]] = None
    block_categories: Optional[List[str]] = None
    action: Optional[str] = None
    enabled: Optional[int] = Field(None, ge=0, le=1)


class ScanRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=65536, description="Prompt text to scan")
    org_id: str = Field(default="default", min_length=1, max_length=256)
    user_id: Optional[str] = Field(None, max_length=256)
    source_model: Optional[str] = Field(None, max_length=256)


class ScanResponse(BaseModel):
    verdict: str                              # blocked | warned | allowed
    matched_categories: List[str]
    matched_policy_id: Optional[str] = None
    event_ids: List[str]                      # injection_events rows created


class InjectionEventResponse(BaseModel):
    id: str
    org_id: str
    policy_id: Optional[str] = None
    prompt_snippet: str
    category: str
    confidence: float
    action_taken: str
    user_id: Optional[str] = None
    source_model: Optional[str] = None
    detected_at: str


class EventListResponse(BaseModel):
    events: List[InjectionEventResponse]
    count: int


class ModelGovernanceResponse(BaseModel):
    id: str
    org_id: str
    model_name: str
    provider: str
    approved: int
    data_residency: Optional[str] = None
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    notes: Optional[str] = None
    created_at: str


class ModelListResponse(BaseModel):
    models: List[ModelGovernanceResponse]
    count: int


class CreateModelRequest(BaseModel):
    org_id: str = Field(default="default", min_length=1, max_length=256)
    model_name: str = Field(..., min_length=1, max_length=256)
    provider: str = Field(
        ..., min_length=1, max_length=64,
        description="openai | anthropic | google | local | etc",
    )
    data_residency: Optional[str] = Field(
        None, max_length=32,
        description="us | eu | apac | on-prem",
    )
    notes: Optional[str] = Field(None, max_length=4096)


class ApproveModelRequest(BaseModel):
    approved_by: str = Field(..., min_length=1, max_length=256,
                             description="Identity of the approver (username / email)")


# ---------------------------------------------------------------------------
# GET / — router info
# ---------------------------------------------------------------------------


@router.get("/", response_model=RouterInfoResponse)
async def router_info() -> RouterInfoResponse:
    """Return LLM firewall service info and aggregate counts.

    Always returns 200. Data comes from live SQLite; no fabricated numbers.
    """
    db = _get_db()
    counts = db.info_counts()
    total = counts["policy_count"] + counts["events_last_24h"] + counts["governed_model_count"]
    status = "ok" if total > 0 else "empty"
    _logger.info(
        "llm_fw_info policies=%d events_24h=%d models=%d",
        counts["policy_count"], counts["events_last_24h"], counts["governed_model_count"],
    )
    return RouterInfoResponse(
        endpoints=[
            "GET    /policies?org_id=",
            "POST   /policies",
            "PUT    /policies/{id}",
            "DELETE /policies/{id}",
            "POST   /scan",
            "GET    /events?org_id=&hours=24&category=",
            "GET    /models?org_id=&approved=",
            "POST   /models",
            "PUT    /models/{id}/approve",
        ],
        policy_count=counts["policy_count"],
        events_last_24h=counts["events_last_24h"],
        governed_model_count=counts["governed_model_count"],
        status=status,
    )


# ---------------------------------------------------------------------------
# GET /policies — list policies
# ---------------------------------------------------------------------------


@router.get("/policies", response_model=PolicyListResponse)
async def list_policies(
    org_id: str = Depends(get_org_id),
) -> PolicyListResponse:
    """List all firewall policies for the given org_id."""
    db = _get_db()
    rows = db.list_policies(org_id)
    _logger.info("llm_fw_policies_listed org_id=%s count=%d", org_id, len(rows))
    return PolicyListResponse(
        policies=[FirewallPolicyResponse(**r) for r in rows],
        count=len(rows),
    )


# ---------------------------------------------------------------------------
# POST /policies — create policy
# ---------------------------------------------------------------------------


@router.post("/policies", response_model=FirewallPolicyResponse, status_code=201)
async def create_policy(body: CreatePolicyRequest) -> FirewallPolicyResponse:
    """Create a new LLM firewall policy.

    HTTP 422 when action is not one of 'block', 'warn', 'log'.
    HTTP 422 when block_categories contains an unknown category value.
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
    if body.block_categories:
        bad = [c for c in body.block_categories if c not in _VALID_CATEGORIES]
        if bad:
            raise HTTPException(
                status_code=422,
                detail={
                    "error": "invalid_categories",
                    "allowed": sorted(_VALID_CATEGORIES),
                    "invalid": bad,
                },
            )
    db = _get_db()
    created = db.create_policy(body.model_dump())
    return FirewallPolicyResponse(**created)


# ---------------------------------------------------------------------------
# PUT /policies/{id} — partial update
# ---------------------------------------------------------------------------


@router.put("/policies/{policy_id}", response_model=FirewallPolicyResponse)
async def update_policy(policy_id: str, body: UpdatePolicyRequest) -> FirewallPolicyResponse:
    """Partially update a firewall policy. Only non-null fields are written.

    HTTP 404 when policy_id does not exist.
    HTTP 422 when action or category values are invalid.
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
    if body.block_categories is not None:
        bad = [c for c in body.block_categories if c not in _VALID_CATEGORIES]
        if bad:
            raise HTTPException(
                status_code=422,
                detail={
                    "error": "invalid_categories",
                    "allowed": sorted(_VALID_CATEGORIES),
                    "invalid": bad,
                },
            )
    db = _get_db()
    updated = db.update_policy(policy_id, body.model_dump(exclude_none=True))
    if updated is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "policy_not_found", "policy_id": policy_id},
        )
    return FirewallPolicyResponse(**updated)


# ---------------------------------------------------------------------------
# DELETE /policies/{id} — delete policy
# ---------------------------------------------------------------------------


@router.delete("/policies/{policy_id}", status_code=204)
async def delete_policy(policy_id: str) -> None:
    """Hard-delete a firewall policy.

    Returns HTTP 204 on success, HTTP 404 when policy_id does not exist.
    """
    db = _get_db()
    deleted = db.delete_policy(policy_id)
    if not deleted:
        raise HTTPException(
            status_code=404,
            detail={"error": "policy_not_found", "policy_id": policy_id},
        )


# ---------------------------------------------------------------------------
# POST /scan — scan a prompt
# ---------------------------------------------------------------------------


@router.post("/scan", response_model=ScanResponse)
async def scan_prompt(body: ScanRequest) -> ScanResponse:
    """Scan a prompt against active policies for the given org_id.

    Heuristics applied (in order, first action wins):
      - prompt_injection: "ignore previous instructions"
      - jailbreak: word-boundary "DAN"
      - pii_exfil: email-like pattern
      - secret_leak: sk-... / ghp_... / AKIA...

    For each active policy, block_patterns (regex) and block_categories
    (category enablement) are also checked. The most restrictive action across
    all matching policies governs the verdict: block > warn > log > allowed.

    Matching categories are recorded as injection_events rows.
    Returns verdict, matched categories, matched_policy_id, and event_ids.
    """
    db = _get_db()
    prompt = body.prompt
    snippet = prompt[:500]

    active_policies = db.list_active_policies(body.org_id)

    matched_categories: List[str] = []
    matched_policy_id: Optional[str] = None
    event_ids: List[str] = []
    winning_action: Optional[str] = None

    _ACTION_RANK = {"block": 3, "warn": 2, "log": 1}

    def _record_event(category: str, confidence: float, action: str, policy_id: Optional[str]) -> str:
        ev = db.create_event({
            "org_id": body.org_id,
            "policy_id": policy_id,
            "prompt_snippet": snippet,
            "category": category,
            "confidence": confidence,
            "action_taken": action,
            "user_id": body.user_id,
            "source_model": body.source_model,
        })
        return ev["id"]

    def _update_action(new_action: str) -> None:
        nonlocal winning_action
        if winning_action is None:
            winning_action = new_action
        elif _ACTION_RANK.get(new_action, 0) > _ACTION_RANK.get(winning_action, 0):
            winning_action = new_action

    # --- Check active policies ---
    for policy in active_policies:
        policy_action = policy.get("action", "block")
        policy_matched = False

        # 1. Check block_patterns (raw regex substrings)
        patterns_json = policy.get("block_patterns") or "[]"
        try:
            patterns: List[str] = json.loads(patterns_json)
        except (json.JSONDecodeError, TypeError):
            patterns = []
        for pat in patterns:
            try:
                if re.search(pat, prompt, re.IGNORECASE):
                    # Pattern match — attribute to first matching heuristic category
                    # for category labeling; default to prompt_injection
                    cat = "prompt_injection"
                    if cat not in matched_categories:
                        matched_categories.append(cat)
                    _update_action(policy_action)
                    matched_policy_id = policy["id"]
                    policy_matched = True
            except re.error:
                _logger.warning("llm_fw_bad_pattern policy_id=%s pat=%r", policy["id"], pat)

        # 2. Check block_categories — run heuristics for enabled categories
        categories_json = policy.get("block_categories") or "[]"
        try:
            enabled_cats: List[str] = json.loads(categories_json)
        except (json.JSONDecodeError, TypeError):
            enabled_cats = []

        for cat, pattern, confidence in _HEURISTICS:
            if cat not in enabled_cats:
                continue
            if pattern.search(prompt):
                if cat not in matched_categories:
                    matched_categories.append(cat)
                _update_action(policy_action)
                if not policy_matched:
                    matched_policy_id = policy["id"]
                    policy_matched = True

    # --- Also run heuristics unconditionally if no policy active but want base detection ---
    # (even with no policies, we want to detect and record events)
    if not active_policies:
        for cat, pattern, confidence in _HEURISTICS:
            if pattern.search(prompt) and cat not in matched_categories:
                matched_categories.append(cat)
                if winning_action is None:
                    winning_action = "log"

    # Record an injection_event for every matched category
    for cat in matched_categories:
        confidence = next((c for (n, _, c) in _HEURISTICS if n == cat), 0.8)
        action_for_event = winning_action or "log"
        eid = _record_event(cat, confidence, action_for_event, matched_policy_id)
        event_ids.append(eid)

    # Determine final verdict
    if not matched_categories:
        verdict = "allowed"
    elif winning_action == "block":
        verdict = "blocked"
    elif winning_action == "warn":
        verdict = "warned"
    else:
        verdict = "allowed"  # log action = non-blocking

    _logger.info(
        "llm_fw_scan org_id=%s verdict=%s categories=%s events=%d",
        body.org_id, verdict, matched_categories, len(event_ids),
    )
    return ScanResponse(
        verdict=verdict,
        matched_categories=matched_categories,
        matched_policy_id=matched_policy_id,
        event_ids=event_ids,
    )


# ---------------------------------------------------------------------------
# GET /events — list injection events
# ---------------------------------------------------------------------------


@router.get("/events", response_model=EventListResponse)
async def list_events(
    org_id: str = Depends(get_org_id),
    hours: int = Query(default=24, ge=1, le=8760, description="Look-back window in hours (max 365d)"),
    category: Optional[str] = Query(
        None,
        description="Filter by category: prompt_injection | jailbreak | pii_exfil | secret_leak",
    ),
) -> EventListResponse:
    """List injection events within the specified time window."""
    if category is not None and category not in _VALID_CATEGORIES:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "invalid_category",
                "allowed": sorted(_VALID_CATEGORIES),
                "received": category,
            },
        )
    db = _get_db()
    rows = db.list_events(org_id, hours, category)
    _logger.info(
        "llm_fw_events_listed org_id=%s hours=%d category=%s count=%d",
        org_id, hours, category, len(rows),
    )
    return EventListResponse(
        events=[InjectionEventResponse(**r) for r in rows],
        count=len(rows),
    )


# ---------------------------------------------------------------------------
# GET /models — list governed models
# ---------------------------------------------------------------------------


@router.get("/models", response_model=ModelListResponse)
async def list_models(
    org_id: str = Depends(get_org_id),
    approved: Optional[int] = Query(None, ge=0, le=1, description="Filter: 0=unapproved, 1=approved"),
) -> ModelListResponse:
    """List governed models, optionally filtered by approval state."""
    db = _get_db()
    rows = db.list_models(org_id, approved)
    _logger.info("llm_fw_models_listed org_id=%s approved=%s count=%d", org_id, approved, len(rows))
    return ModelListResponse(models=[ModelGovernanceResponse(**r) for r in rows], count=len(rows))


# ---------------------------------------------------------------------------
# POST /models — register a model
# ---------------------------------------------------------------------------


@router.post("/models", response_model=ModelGovernanceResponse, status_code=201)
async def create_model(body: CreateModelRequest) -> ModelGovernanceResponse:
    """Register a model in the governance registry. Starts unapproved."""
    db = _get_db()
    created = db.create_model(body.model_dump())
    return ModelGovernanceResponse(**created)


# ---------------------------------------------------------------------------
# PUT /models/{id}/approve — approve a model
# ---------------------------------------------------------------------------


@router.put("/models/{model_id}/approve", response_model=ModelGovernanceResponse)
async def approve_model(model_id: str, body: ApproveModelRequest) -> ModelGovernanceResponse:
    """Set approved=1 on a governed model record.

    HTTP 404 when model_id does not exist.
    """
    db = _get_db()
    updated = db.approve_model(model_id, body.approved_by)
    if updated is None:
        raise HTTPException(
            status_code=404,
            detail={"error": "model_not_found", "model_id": model_id},
        )
    _logger.info("llm_fw_model_approved id=%s approved_by=%r", model_id, body.approved_by)
    return ModelGovernanceResponse(**updated)


__all__ = ["router"]
