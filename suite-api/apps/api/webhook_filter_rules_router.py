"""Webhook Filter Rules — per-org event filtering rules for webhook delivery.

Endpoints:
  GET    /api/v1/webhook-filter-rules            — list rules for org
  POST   /api/v1/webhook-filter-rules            — create a filter rule
  GET    /api/v1/webhook-filter-rules/{rule_id}  — get a single rule
  PUT    /api/v1/webhook-filter-rules/{rule_id}  — update a rule
  DELETE /api/v1/webhook-filter-rules/{rule_id}  — delete a rule
  POST   /api/v1/webhook-filter-rules/evaluate   — test a payload against active rules

Rules let operators suppress or allow specific event types, severities, or
source prefixes before webhook delivery, reducing noise for downstream consumers.

Storage: SQLite WAL at data/webhook_filter_rules.db
Compliance: SOC2 CC6.1, NIST SP 800-53 SI-12
"""
from __future__ import annotations

import logging
import os
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional

from apps.api.dependencies import get_org_id
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

ALLOWED_EVENT_TYPES = frozenset({
    "finding.created",
    "finding.critical",
    "finding.resolved",
    "sla.breach",
    "pipeline.completed",
    "autofix.applied",
    "compliance.violation",
    "attack_path.discovered",
})

ALLOWED_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})

_MAX_RULES_PER_ORG = 200
_RULE_ID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")

# ---------------------------------------------------------------------------
# DB
# ---------------------------------------------------------------------------

_DB_PATH = os.path.normpath(os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "..", "..", "data", "webhook_filter_rules.db",
))
_db_lock = threading.Lock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS filter_rules (
    id          TEXT PRIMARY KEY,
    org_id      TEXT NOT NULL,
    name        TEXT NOT NULL,
    action      TEXT NOT NULL DEFAULT 'allow',
    event_type  TEXT,
    severity    TEXT,
    source_prefix TEXT,
    enabled     INTEGER NOT NULL DEFAULT 1,
    priority    INTEGER NOT NULL DEFAULT 100,
    created_at  TEXT NOT NULL,
    updated_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_fr_org     ON filter_rules(org_id);
CREATE INDEX IF NOT EXISTS idx_fr_enabled ON filter_rules(enabled);
CREATE INDEX IF NOT EXISTS idx_fr_prio    ON filter_rules(priority);
"""


def _get_db(path: str = _DB_PATH) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    conn = sqlite3.connect(path, timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_SCHEMA)
    return conn


# Overridable for tests
_DB_PATH_OVERRIDE: Optional[str] = None


def _db() -> sqlite3.Connection:
    return _get_db(_DB_PATH_OVERRIDE or _DB_PATH)


def _row(r: sqlite3.Row) -> Dict[str, Any]:
    d = dict(r)
    d["enabled"] = bool(d.get("enabled", 1))
    return d


def _validate_rule_id(rule_id: str) -> str:
    s = rule_id.strip().lower()
    if not _RULE_ID_RE.match(s):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "Invalid rule ID format")
    return s


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class CreateFilterRuleRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=128)
    action: Literal["allow", "deny"] = Field(default="allow")
    event_type: Optional[str] = Field(default=None)
    severity: Optional[str] = Field(default=None)
    source_prefix: Optional[str] = Field(default=None, max_length=128)
    enabled: bool = Field(default=True)
    priority: int = Field(default=100, ge=1, le=1000)

    @field_validator("event_type")
    @classmethod
    def _check_event_type(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in ALLOWED_EVENT_TYPES:
            raise ValueError(
                f"Invalid event_type '{v}'. Allowed: {sorted(ALLOWED_EVENT_TYPES)}"
            )
        return v

    @field_validator("severity")
    @classmethod
    def _check_severity(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v.lower() not in ALLOWED_SEVERITIES:
            raise ValueError(
                f"Invalid severity '{v}'. Allowed: {sorted(ALLOWED_SEVERITIES)}"
            )
        return v.lower() if v else v


class UpdateFilterRuleRequest(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=128)
    action: Optional[Literal["allow", "deny"]] = None
    event_type: Optional[str] = None
    severity: Optional[str] = None
    source_prefix: Optional[str] = Field(default=None, max_length=128)
    enabled: Optional[bool] = None
    priority: Optional[int] = Field(default=None, ge=1, le=1000)

    @field_validator("event_type")
    @classmethod
    def _check_event_type(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v not in ALLOWED_EVENT_TYPES:
            raise ValueError(f"Invalid event_type '{v}'")
        return v

    @field_validator("severity")
    @classmethod
    def _check_severity(cls, v: Optional[str]) -> Optional[str]:
        if v is not None and v.lower() not in ALLOWED_SEVERITIES:
            raise ValueError(f"Invalid severity '{v}'")
        return v.lower() if v else v


class EvaluateRequest(BaseModel):
    event_type: str = Field(..., description="The event type to evaluate")
    severity: Optional[str] = Field(default=None)
    source: Optional[str] = Field(default=None)


# ---------------------------------------------------------------------------
# Filter evaluation logic
# ---------------------------------------------------------------------------


def evaluate_event(
    rules: List[Dict[str, Any]],
    event_type: str,
    severity: Optional[str],
    source: Optional[str],
) -> Dict[str, Any]:
    """Evaluate an event against a sorted list of active rules.

    Rules are evaluated in ascending priority order.  The first matching rule
    wins.  If no rule matches the default action is 'allow'.

    A rule matches when ALL non-None criteria match the event:
      - event_type: exact match
      - severity: exact match (case-insensitive)
      - source_prefix: source starts with prefix
    """
    matched_rule: Optional[Dict[str, Any]] = None
    for rule in sorted(rules, key=lambda r: r.get("priority", 100)):
        if not rule.get("enabled", True):
            continue
        # Check each criterion — None means "match anything"
        if rule.get("event_type") and rule["event_type"] != event_type:
            continue
        if rule.get("severity") and rule["severity"] != (severity or "").lower():
            continue
        if rule.get("source_prefix") and not (source or "").startswith(rule["source_prefix"]):
            continue
        matched_rule = rule
        break

    action = matched_rule["action"] if matched_rule else "allow"
    return {
        "action": action,
        "allowed": action == "allow",
        "matched_rule_id": matched_rule["id"] if matched_rule else None,
        "matched_rule_name": matched_rule["name"] if matched_rule else None,
    }


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(
    prefix="/api/v1/webhook-filter-rules",
    tags=["webhook-filter-rules"],
)


@router.get("/", summary="List webhook filter rules for the org")
async def list_rules(org_id: str = Depends(get_org_id)) -> List[Dict[str, Any]]:
    """Return all filter rules for the authenticated org, ordered by priority."""
    try:
        with _db_lock:
            conn = _db()
            try:
                rows = conn.execute(
                    "SELECT * FROM filter_rules WHERE org_id=? ORDER BY priority ASC, created_at ASC",
                    (org_id,),
                ).fetchall()
            finally:
                conn.close()
    except (sqlite3.Error, OSError) as exc:
        logger.error("list_rules db error: %s", exc)
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Database error")
    return [_row(r) for r in rows]


@router.post("/", status_code=status.HTTP_201_CREATED, summary="Create a webhook filter rule")
async def create_rule(
    req: CreateFilterRuleRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Create a new filter rule. At least one of event_type, severity, or
    source_prefix must be specified so the rule is not a no-op wildcard."""
    if req.event_type is None and req.severity is None and req.source_prefix is None:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "At least one of event_type, severity, or source_prefix must be specified",
        )

    try:
        with _db_lock:
            conn = _db()
            try:
                count = conn.execute(
                    "SELECT COUNT(*) FROM filter_rules WHERE org_id=?", (org_id,)
                ).fetchone()[0]
            finally:
                conn.close()
    except (sqlite3.Error, OSError):
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Database error")

    if count >= _MAX_RULES_PER_ORG:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            f"Maximum {_MAX_RULES_PER_ORG} filter rules per organization",
        )

    rule_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    try:
        with _db_lock:
            conn = _db()
            try:
                conn.execute(
                    """INSERT INTO filter_rules
                       (id, org_id, name, action, event_type, severity,
                        source_prefix, enabled, priority, created_at, updated_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        rule_id, org_id, req.name, req.action,
                        req.event_type, req.severity, req.source_prefix,
                        int(req.enabled), req.priority, now, now,
                    ),
                )
                conn.commit()
            finally:
                conn.close()
    except sqlite3.IntegrityError:
        raise HTTPException(status.HTTP_409_CONFLICT, "Rule already exists")
    except (sqlite3.Error, OSError):
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Database error")

    return {
        "id": rule_id, "org_id": org_id, "name": req.name,
        "action": req.action, "event_type": req.event_type,
        "severity": req.severity, "source_prefix": req.source_prefix,
        "enabled": req.enabled, "priority": req.priority,
        "created_at": now, "updated_at": now,
    }


@router.get("/{rule_id}", summary="Get a specific webhook filter rule")
async def get_rule(rule_id: str, org_id: str = Depends(get_org_id)) -> Dict[str, Any]:
    rule_id = _validate_rule_id(rule_id)
    try:
        with _db_lock:
            conn = _db()
            try:
                row = conn.execute(
                    "SELECT * FROM filter_rules WHERE id=? AND org_id=?", (rule_id, org_id)
                ).fetchone()
            finally:
                conn.close()
    except (sqlite3.Error, OSError):
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Database error")
    if not row:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Filter rule not found")
    return _row(row)


@router.put("/{rule_id}", summary="Update a webhook filter rule")
async def update_rule(
    rule_id: str,
    req: UpdateFilterRuleRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    rule_id = _validate_rule_id(rule_id)
    updates: List[str] = []
    params: List[Any] = []
    if req.name is not None:
        updates.append("name=?"); params.append(req.name)
    if req.action is not None:
        updates.append("action=?"); params.append(req.action)
    if req.event_type is not None:
        updates.append("event_type=?"); params.append(req.event_type)
    if req.severity is not None:
        updates.append("severity=?"); params.append(req.severity)
    if req.source_prefix is not None:
        updates.append("source_prefix=?"); params.append(req.source_prefix)
    if req.enabled is not None:
        updates.append("enabled=?"); params.append(int(req.enabled))
    if req.priority is not None:
        updates.append("priority=?"); params.append(req.priority)
    if not updates:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "No fields to update")

    now = datetime.now(timezone.utc).isoformat()
    updates.append("updated_at=?"); params.append(now)
    params.extend([rule_id, org_id])
    sql = f"UPDATE filter_rules SET {', '.join(updates)} WHERE id=? AND org_id=?"  # nosec B608

    try:
        with _db_lock:
            conn = _db()
            try:
                cur = conn.execute(sql, params)
                if cur.rowcount == 0:
                    raise HTTPException(status.HTTP_404_NOT_FOUND, "Filter rule not found")
                conn.commit()
                row = conn.execute("SELECT * FROM filter_rules WHERE id=?", (rule_id,)).fetchone()
            finally:
                conn.close()
    except HTTPException:
        raise
    except (sqlite3.Error, OSError):
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Database error")
    return _row(row)


@router.delete("/{rule_id}", summary="Delete a webhook filter rule")
async def delete_rule(rule_id: str, org_id: str = Depends(get_org_id)) -> Dict[str, Any]:
    rule_id = _validate_rule_id(rule_id)
    try:
        with _db_lock:
            conn = _db()
            try:
                cur = conn.execute(
                    "DELETE FROM filter_rules WHERE id=? AND org_id=?", (rule_id, org_id)
                )
                if cur.rowcount == 0:
                    raise HTTPException(status.HTTP_404_NOT_FOUND, "Filter rule not found")
                conn.commit()
            finally:
                conn.close()
    except HTTPException:
        raise
    except (sqlite3.Error, OSError):
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Database error")
    return {"id": rule_id, "status": "deleted"}


@router.post("/evaluate", summary="Evaluate an event against active filter rules")
async def evaluate_rule(
    req: EvaluateRequest,
    org_id: str = Depends(get_org_id),
) -> Dict[str, Any]:
    """Test whether a given event would be allowed or denied by the org's active rules."""
    try:
        with _db_lock:
            conn = _db()
            try:
                rows = conn.execute(
                    "SELECT * FROM filter_rules WHERE org_id=? AND enabled=1 ORDER BY priority ASC",
                    (org_id,),
                ).fetchall()
            finally:
                conn.close()
    except (sqlite3.Error, OSError):
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, "Database error")

    rules = [_row(r) for r in rows]
    result = evaluate_event(rules, req.event_type, req.severity, req.source)
    return {
        "event_type": req.event_type,
        "severity": req.severity,
        "source": req.source,
        "org_id": org_id,
        "rules_evaluated": len(rules),
        **result,
    }
