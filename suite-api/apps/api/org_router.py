"""Org Management Router — ALDECI multi-tenancy.

Prefix: /api/v1/orgs
Auth: api_key_auth dependency

Routes:
  GET    /api/v1/orgs                       list_orgs
  POST   /api/v1/orgs                       create_org
  GET    /api/v1/orgs/{org_id}/summary      get_org_summary
  GET    /api/v1/orgs/{org_id}/users        list_org_users
  POST   /api/v1/orgs/{org_id}/users        invite_org_user
  PUT    /api/v1/orgs/{org_id}/users/{uid}  update_org_user_role
  DELETE /api/v1/orgs/{org_id}/users/{uid}  remove_org_user
"""

from __future__ import annotations

import logging
import re
import uuid
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, EmailStr, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/orgs",
    tags=["Organizations"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.org_engine import OrgEngine
        _engine = OrgEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

def _slugify(name: str) -> str:
    """Convert a display name to a URL-safe slug."""
    slug = name.lower().strip()
    slug = re.sub(r"[^\w\s-]", "", slug)
    slug = re.sub(r"[\s_]+", "-", slug)
    slug = re.sub(r"-+", "-", slug).strip("-")
    return slug or str(uuid.uuid4())[:8]


class CreateOrgRequest(BaseModel):
    name: str = Field(..., description="Human-readable display name")
    industry: Optional[str] = Field(default="", description="Industry vertical")
    slug: Optional[str] = Field(default=None, description="URL slug — auto-derived from name if absent")
    # Legacy field kept for backwards-compat with direct API callers
    org_id: Optional[str] = Field(default=None, description="Explicit org_id; falls back to slug")
    description: Optional[str] = Field(default="", description="Optional description")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("", dependencies=[Depends(api_key_auth)])
def list_orgs(
    include_discovered: bool = Query(
        default=True,
        description="Include org_ids discovered from engine databases",
    ),
) -> List[Dict[str, Any]]:
    """List all known organisations.

    Returns registered orgs plus any org_ids discovered by scanning engine
    SQLite databases (when ``include_discovered=true``).
    """
    return _get_engine().list_orgs(include_discovered=include_discovered)


@router.post("", dependencies=[Depends(api_key_auth)], status_code=201)
def create_org(req: CreateOrgRequest) -> Dict[str, Any]:
    """Create a new organisation in the registry.

    Accepts onboarding wizard payload ``{name, industry}`` — slug is
    auto-derived from name when not supplied.  Also accepts legacy callers
    that pass ``org_id`` explicitly.
    """
    slug = req.slug or req.org_id or _slugify(req.name)
    description = req.description or req.industry or ""
    try:
        result = _get_engine().create_org(
            org_id=slug,
            name=req.name,
            description=description,
        )
        # Normalise response to match what the onboarding wizard expects.
        result.setdefault("slug", result.get("org_id", slug))
        return result
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc


@router.get("/{org_id}/summary", dependencies=[Depends(api_key_auth)])
def get_org_summary(org_id: str) -> Dict[str, Any]:
    """Return a dashboard summary for a specific org.

    Shows how many engine databases contain data for this org_id and the
    total row count across all tables.
    """
    try:
        return _get_engine().get_org_summary(org_id)
    except Exception as exc:
        _logger.exception("Error fetching org summary for %s", org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.delete("/{org_id}", dependencies=[Depends(api_key_auth)], status_code=200)
def delete_org(org_id: str) -> Dict[str, Any]:
    """GDPR right-to-be-forgotten — soft-delete an organisation.

    Sets ``deleted_at`` and ``status=DELETED`` on the registry row.
    Data is NOT removed immediately; the ops purge job (scripts/purge_deleted_orgs.py)
    performs the hard purge after 30 days.

    The built-in 'default' org cannot be deleted.
    Returns 404 when org_id is unknown, 400 for the protected default org.
    """
    if not org_id or not org_id.strip():
        raise HTTPException(status_code=400, detail="org_id is required")
    try:
        result = _get_engine().soft_delete_org(org_id)
    except ValueError as exc:
        msg = str(exc)
        if "not found" in msg:
            raise HTTPException(status_code=404, detail=msg) from exc
        raise HTTPException(status_code=400, detail=msg) from exc
    except Exception as exc:
        _logger.exception("Error soft-deleting org %s", org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return result


@router.get("/{org_id}", dependencies=[Depends(api_key_auth)])
def get_org(org_id: str) -> Dict[str, Any]:
    """Return the registry record for a specific org by slug.

    Bug C fix (playbook 2026-04-27): the playbook references this endpoint but
    we previously only exposed /summary. SEs running smoke tests on a single
    org need a quick existence-check that doesn't traverse every engine DB.

    Falls back to a synthesized record from get_org_summary() when the org is
    only "discovered" (i.e. has rows in engine DBs but no registry row yet).
    Raises 404 only when the slug is unknown to both registry + discovery.

    NOTE: This route is registered AFTER /{org_id}/summary so the more
    specific path wins on FastAPI's first-match-by-registration order.
    """
    if not org_id or not org_id.strip():
        raise HTTPException(status_code=400, detail="org_id is required")

    engine = _get_engine()

    # 1) Registry hit — preferred path.
    for entry in engine.list_orgs(include_discovered=False):
        if entry.get("org_id") == org_id or entry.get("id") == org_id:
            return entry

    # 2) Fall back to discovery — catches orgs whose data was created via
    #    pipeline ingestion before the registry row was written.
    try:
        summary = engine.get_org_summary(org_id)
    except Exception as exc:  # noqa: BLE001 — engine may raise broad
        _logger.exception("Error fetching org for %s", org_id)
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    if not summary or summary.get("total_rows", 0) == 0:
        raise HTTPException(status_code=404, detail=f"org '{org_id}' not found")

    return {
        "org_id": org_id,
        "name": summary.get("name") or org_id,
        "description": summary.get("description") or "",
        "discovered": True,
        "summary": summary,
    }


# ---------------------------------------------------------------------------
# Org-scoped user management
# GET/POST/PUT/DELETE /api/v1/orgs/{org_id}/users[/{uid}]
# ---------------------------------------------------------------------------

_user_db = None


def _get_user_db():
    global _user_db
    if _user_db is None:
        from core.user_db import UserDB
        _user_db = UserDB()
    return _user_db


class InviteUserRequest(BaseModel):
    email: EmailStr
    role: str = Field(default="viewer", description="Role: admin|security_analyst|developer|viewer")
    first_name: str = Field(default="Invited")
    last_name: str = Field(default="User")


class UpdateRoleRequest(BaseModel):
    role: str = Field(..., description="New role: admin|security_analyst|developer|viewer")


_VALID_ROLES = {"admin", "security_analyst", "developer", "viewer"}


def _user_to_dict(u: Any) -> Dict[str, Any]:
    d = u.to_dict() if hasattr(u, "to_dict") else dict(u)
    return {
        "id": d.get("id", ""),
        "email": d.get("email", ""),
        "first_name": d.get("first_name", ""),
        "last_name": d.get("last_name", ""),
        "role": d.get("role", "viewer"),
        "status": d.get("status", "active"),
        "last_login": d.get("last_login_at") or d.get("last_login") or None,
        "created_at": d.get("created_at", ""),
    }


@router.get("/{org_id}/users", dependencies=[Depends(api_key_auth)])
def list_org_users(org_id: str) -> Dict[str, Any]:
    """List all users for an org (org_id used as namespace tag; returns all users in shared UserDB)."""
    udb = _get_user_db()
    users = udb.list_users(limit=500, offset=0)
    items = [_user_to_dict(u) for u in users]
    return {"org_id": org_id, "items": items, "total": len(items)}


@router.post("/{org_id}/users", dependencies=[Depends(api_key_auth)], status_code=201)
def invite_org_user(org_id: str, req: InviteUserRequest) -> Dict[str, Any]:
    """Invite (create) a user into an org. Generates a random temporary password."""
    if req.role not in _VALID_ROLES:
        raise HTTPException(status_code=422, detail=f"Invalid role '{req.role}'. Must be one of {sorted(_VALID_ROLES)}")
    udb = _get_user_db()
    if udb.get_user_by_email(req.email):
        raise HTTPException(status_code=409, detail="A user with that email already exists")
    from core.user_models import User, UserRole, UserStatus
    import secrets as _secrets
    tmp_password = _secrets.token_urlsafe(16)
    role_enum = UserRole(req.role)
    user = User(
        id="",
        email=req.email,
        password_hash=udb.hash_password(tmp_password),
        first_name=req.first_name,
        last_name=req.last_name,
        role=role_enum,
        status=UserStatus.ACTIVE,
        department=None,
    )
    created = udb.create_user(user)
    result = _user_to_dict(created)
    result["org_id"] = org_id
    result["temp_password_hint"] = "Check email — temporary password issued"
    return result


@router.put("/{org_id}/users/{uid}", dependencies=[Depends(api_key_auth)])
def update_org_user_role(org_id: str, uid: str, req: UpdateRoleRequest) -> Dict[str, Any]:
    """Update a user's role within an org."""
    if req.role not in _VALID_ROLES:
        raise HTTPException(status_code=422, detail=f"Invalid role '{req.role}'")
    udb = _get_user_db()
    user = udb.get_user(uid)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    from core.user_models import UserRole
    user.role = UserRole(req.role)
    updated = udb.update_user(user)
    result = _user_to_dict(updated)
    result["org_id"] = org_id
    return result


@router.delete("/{org_id}/users/{uid}", dependencies=[Depends(api_key_auth)], status_code=200)
def remove_org_user(org_id: str, uid: str) -> Dict[str, Any]:
    """Remove a user from an org (deletes user record)."""
    udb = _get_user_db()
    user = udb.get_user(uid)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    udb.delete_user(uid)
    return {"org_id": org_id, "deleted_user_id": uid, "status": "removed"}
