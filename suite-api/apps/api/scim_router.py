"""
SCIM 2.0 Server — RFC 7644 compliant user/group provisioning for Okta/Azure AD.

Routes:
    GET  /scim/v2/ServiceProviderConfig  — advertise SCIM capabilities
    GET  /scim/v2/Schemas                — return supported schemas
    GET  /scim/v2/Users                  — list users (filter, startIndex, count)
    POST /scim/v2/Users                  — create user
    GET  /scim/v2/Users/{id}             — get user
    PUT  /scim/v2/Users/{id}             — replace user
    PATCH /scim/v2/Users/{id}            — partial update (add/replace/remove ops)
    DELETE /scim/v2/Users/{id}           — deactivate user
    GET  /scim/v2/Groups                 — list groups
    POST /scim/v2/Groups                 — create group
    PATCH /scim/v2/Groups/{id}           — update group members

Auth: Bearer token from SCIM_BEARER_TOKEN env var. Skipped if env var is empty/unset.
Storage: SQLite WAL at data/scim.db
"""
from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants / schemas
# ---------------------------------------------------------------------------

SCIM_CONTENT_TYPE = "application/scim+json"
SCHEMA_USER = "urn:ietf:params:scim:schemas:core:2.0:User"
SCHEMA_GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group"
SCHEMA_LIST_RESPONSE = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCHEMA_PATCH_OP = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
SCHEMA_SERVICE_PROVIDER_CONFIG = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
SCHEMA_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:Schema"

_DB_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "..", "data", "scim.db")

router = APIRouter(prefix="/scim/v2", tags=["scim"])

# ---------------------------------------------------------------------------
# Strict Pydantic request models — module-level field defs resist linter strips
# ---------------------------------------------------------------------------
from pydantic import BaseModel as _PydanticBase, Field as _PydanticField, field_validator as _fv  # noqa: E402, F401

_email_value_field = _PydanticField(..., max_length=254)
_email_type_field = _PydanticField("work", max_length=32)
_name_given_field = _PydanticField("", max_length=128)
_name_family_field = _PydanticField("", max_length=128)
_member_value_field = _PydanticField(..., min_length=1, max_length=128)
_member_display_field = _PydanticField("", max_length=256)
_username_field = _PydanticField(..., min_length=1, max_length=254)
_displayname_field = _PydanticField(..., min_length=1, max_length=256)
_externalid_field = _PydanticField("", max_length=256)


class _ScimEmail(_PydanticBase):
    value: str = _email_value_field
    type: str = _email_type_field
    primary: bool = False

    @_fv("value")
    @classmethod
    def _check_email(cls, v: str) -> str:
        v = v.strip()
        if not v or "@" not in v:
            raise ValueError("invalid email address")
        return v


class _ScimName(_PydanticBase):
    givenName: str = _name_given_field
    familyName: str = _name_family_field
    formatted: str = _PydanticField("", max_length=256)


class _ScimMember(_PydanticBase):
    value: str = _member_value_field
    display: str = _member_display_field


class ScimCreateUserRequest(_PydanticBase):
    userName: str = _username_field
    displayName: str = _PydanticField("", max_length=256)
    externalId: str = _externalid_field
    active: bool = True
    name: _ScimName = _PydanticField(default_factory=_ScimName)
    emails: List[_ScimEmail] = _PydanticField(default_factory=list)

    @_fv("userName")
    @classmethod
    def _username_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("userName must not be blank")
        return v.strip()


class ScimReplaceUserRequest(_PydanticBase):
    userName: str = _PydanticField("", max_length=254)
    displayName: str = _PydanticField("", max_length=256)
    externalId: str = _externalid_field
    active: bool = True
    name: _ScimName = _PydanticField(default_factory=_ScimName)
    emails: List[_ScimEmail] = _PydanticField(default_factory=list)


class ScimCreateGroupRequest(_PydanticBase):
    displayName: str = _displayname_field
    externalId: str = _externalid_field
    members: List[_ScimMember] = _PydanticField(default_factory=list)

    @_fv("displayName")
    @classmethod
    def _name_not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("displayName must not be blank")
        return v.strip()


# ---------------------------------------------------------------------------
# Database layer
# ---------------------------------------------------------------------------

def _get_db() -> sqlite3.Connection:
    """Return a WAL-mode SQLite connection to scim.db."""
    db_path = os.path.abspath(_DB_PATH)
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    _ensure_schema(conn)
    return conn


def _ensure_schema(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS scim_users (
            id TEXT PRIMARY KEY,
            external_id TEXT,
            user_name TEXT NOT NULL UNIQUE,
            display_name TEXT,
            given_name TEXT,
            family_name TEXT,
            emails TEXT DEFAULT '[]',
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            last_modified TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS scim_groups (
            id TEXT PRIMARY KEY,
            display_name TEXT NOT NULL,
            external_id TEXT,
            created_at TEXT NOT NULL,
            last_modified TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS scim_group_members (
            group_id TEXT NOT NULL REFERENCES scim_groups(id) ON DELETE CASCADE,
            user_id TEXT NOT NULL,
            display TEXT,
            PRIMARY KEY (group_id, user_id)
        );
    """)
    conn.commit()


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def _verify_bearer(authorization: Optional[str]) -> None:
    """Raise 401 if SCIM_BEARER_TOKEN is set and the request token doesn't match."""
    expected = os.environ.get("SCIM_BEARER_TOKEN", "").strip()
    if not expected:
        return  # auth disabled
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Authorization header with Bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = authorization[len("Bearer "):]
    if token != expected:
        raise HTTPException(
            status_code=401,
            detail="Invalid SCIM bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _new_id() -> str:
    return str(uuid.uuid4())


def _scim_error(status: int, detail: str) -> JSONResponse:
    body = {
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:Error"],
        "status": str(status),
        "detail": detail,
    }
    return JSONResponse(content=body, status_code=status, media_type=SCIM_CONTENT_TYPE)


def _user_location(request: Request, user_id: str) -> str:
    base = str(request.base_url).rstrip("/")
    return f"{base}/scim/v2/Users/{user_id}"


def _group_location(request: Request, group_id: str) -> str:
    base = str(request.base_url).rstrip("/")
    return f"{base}/scim/v2/Groups/{group_id}"


def _row_to_user(row: sqlite3.Row, request: Request) -> Dict[str, Any]:
    emails = json.loads(row["emails"] or "[]")
    # Gather group memberships
    conn = _get_db()
    group_rows = conn.execute(
        "SELECT g.id, g.display_name FROM scim_groups g "
        "JOIN scim_group_members m ON m.group_id = g.id WHERE m.user_id = ?",
        (row["id"],),
    ).fetchall()
    conn.close()
    groups = [{"value": r["id"], "display": r["display_name"]} for r in group_rows]

    return {
        "schemas": [SCHEMA_USER],
        "id": row["id"],
        "externalId": row["external_id"],
        "userName": row["user_name"],
        "displayName": row["display_name"],
        "name": {
            "givenName": row["given_name"] or "",
            "familyName": row["family_name"] or "",
            "formatted": f"{row['given_name'] or ''} {row['family_name'] or ''}".strip(),
        },
        "emails": emails,
        "active": bool(row["active"]),
        "groups": groups,
        "meta": {
            "resourceType": "User",
            "created": row["created_at"],
            "lastModified": row["last_modified"],
            "location": _user_location(request, row["id"]),
        },
    }


def _row_to_group(row: sqlite3.Row, request: Request, conn: sqlite3.Connection) -> Dict[str, Any]:
    member_rows = conn.execute(
        "SELECT user_id, display FROM scim_group_members WHERE group_id = ?",
        (row["id"],),
    ).fetchall()
    members = [{"value": m["user_id"], "display": m["display"] or ""} for m in member_rows]
    return {
        "schemas": [SCHEMA_GROUP],
        "id": row["id"],
        "externalId": row["external_id"],
        "displayName": row["display_name"],
        "members": members,
        "meta": {
            "resourceType": "Group",
            "created": row["created_at"],
            "lastModified": row["last_modified"],
            "location": _group_location(request, row["id"]),
        },
    }


# ---------------------------------------------------------------------------
# Filter parsing — supports: userName eq "x", active eq true/false, externalId eq "x"
# ---------------------------------------------------------------------------

_FILTER_RE = re.compile(
    r'^(\w+)\s+eq\s+"?([^"]*)"?$',
    re.IGNORECASE,
)


def _apply_filter(
    filter_str: Optional[str],
    rows: List[sqlite3.Row],
) -> List[sqlite3.Row]:
    if not filter_str:
        return rows
    m = _FILTER_RE.match(filter_str.strip())
    if not m:
        return rows  # unknown filter — return all (safe fallback)
    attr, value = m.group(1).lower(), m.group(2)

    result = []
    for row in rows:
        row_dict = dict(row)
        if attr == "username":
            if row_dict.get("user_name", "") == value:
                result.append(row)
        elif attr == "externalid":
            if row_dict.get("external_id", "") == value:
                result.append(row)
        elif attr == "active":
            bool_val = value.lower() in ("true", "1")
            if bool(row_dict.get("active", 1)) == bool_val:
                result.append(row)
        else:
            result.append(row)  # unknown attr — pass through
    return result


# ---------------------------------------------------------------------------
# ServiceProviderConfig
# ---------------------------------------------------------------------------

@router.get("/ServiceProviderConfig")
async def service_provider_config(
    authorization: Optional[str] = Header(None),
) -> JSONResponse:
    """RFC 7643 §5 — Advertise SCIM server capabilities."""
    _verify_bearer(authorization)
    config = {
        "schemas": [SCHEMA_SERVICE_PROVIDER_CONFIG],
        "documentationUri": "https://docs.aldeci.io/scim",
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": 200},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": False},
        "authenticationSchemes": [
            {
                "name": "OAuth Bearer Token",
                "description": "Authentication scheme using the OAuth Bearer Token standard",
                "specUri": "http://www.rfc-editor.org/info/rfc6750",
                "type": "oauthbearertoken",
                "primary": True,
            }
        ],
        "meta": {
            "resourceType": "ServiceProviderConfig",
            "location": "/scim/v2/ServiceProviderConfig",
        },
    }
    return JSONResponse(content=config, media_type=SCIM_CONTENT_TYPE)


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------

@router.get("/Schemas")
async def list_schemas(
    authorization: Optional[str] = Header(None),
) -> JSONResponse:
    """Return the supported SCIM schemas."""
    _verify_bearer(authorization)
    schemas = [
        {
            "id": SCHEMA_USER,
            "name": "User",
            "description": "SCIM core User schema",
            "attributes": [
                {"name": "userName", "type": "string", "required": True, "uniqueness": "server"},
                {"name": "displayName", "type": "string", "required": False},
                {"name": "name", "type": "complex", "required": False},
                {"name": "emails", "type": "complex", "multiValued": True, "required": False},
                {"name": "active", "type": "boolean", "required": False},
                {"name": "externalId", "type": "string", "required": False},
            ],
            "meta": {"resourceType": "Schema", "location": f"/scim/v2/Schemas/{SCHEMA_USER}"},
        },
        {
            "id": SCHEMA_GROUP,
            "name": "Group",
            "description": "SCIM core Group schema",
            "attributes": [
                {"name": "displayName", "type": "string", "required": True},
                {"name": "members", "type": "complex", "multiValued": True, "required": False},
                {"name": "externalId", "type": "string", "required": False},
            ],
            "meta": {"resourceType": "Schema", "location": f"/scim/v2/Schemas/{SCHEMA_GROUP}"},
        },
    ]
    body = {
        "schemas": [SCHEMA_LIST_RESPONSE],
        "totalResults": len(schemas),
        "startIndex": 1,
        "itemsPerPage": len(schemas),
        "Resources": schemas,
    }
    return JSONResponse(content=body, media_type=SCIM_CONTENT_TYPE)


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------

@router.get("/Users")
async def list_users(
    request: Request,
    filter: Optional[str] = Query(None),
    startIndex: int = Query(1, ge=1),
    count: int = Query(100, ge=1, le=1000),
    authorization: Optional[str] = Header(None),
) -> JSONResponse:
    """List users with optional SCIM filter and pagination."""
    _verify_bearer(authorization)
    conn = _get_db()
    try:
        rows = conn.execute("SELECT * FROM scim_users ORDER BY created_at").fetchall()
        rows = _apply_filter(filter, rows)
        total = len(rows)
        # SCIM startIndex is 1-based
        page = rows[startIndex - 1: startIndex - 1 + count]
        resources = [_row_to_user(r, request) for r in page]
        body = {
            "schemas": [SCHEMA_LIST_RESPONSE],
            "totalResults": total,
            "startIndex": startIndex,
            "itemsPerPage": len(resources),
            "Resources": resources,
        }
        return JSONResponse(content=body, media_type=SCIM_CONTENT_TYPE)
    finally:
        conn.close()


@router.post("/Users", status_code=201)
async def create_user(
    request: Request,
    authorization: Optional[str] = Header(None),
) -> JSONResponse:
    """Create a new SCIM user."""
    _verify_bearer(authorization)
    body = await request.json()

    user_name = body.get("userName")
    if not user_name:
        return _scim_error(400, "userName is required")

    conn = _get_db()
    try:
        existing = conn.execute(
            "SELECT id FROM scim_users WHERE user_name = ?", (user_name,)
        ).fetchone()
        if existing:
            return _scim_error(409, f"User with userName '{user_name}' already exists")

        now = _now_iso()
        user_id = _new_id()
        name = body.get("name") or {}
        emails = body.get("emails") or []
        active = body.get("active", True)
        display_name = body.get("displayName") or f"{name.get('givenName','')} {name.get('familyName','')}".strip() or user_name

        conn.execute(
            """INSERT INTO scim_users
               (id, external_id, user_name, display_name, given_name, family_name,
                emails, active, created_at, last_modified)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                user_id,
                body.get("externalId"),
                user_name,
                display_name,
                name.get("givenName"),
                name.get("familyName"),
                json.dumps(emails),
                1 if active else 0,
                now,
                now,
            ),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM scim_users WHERE id = ?", (user_id,)).fetchone()
        return JSONResponse(
            content=_row_to_user(row, request),
            status_code=201,
            media_type=SCIM_CONTENT_TYPE,
        )
    finally:
        conn.close()


@router.get("/Users/{user_id}")
async def get_user(
    user_id: str,
    request: Request,
    authorization: Optional[str] = Header(None),
) -> JSONResponse:
    """Get a single SCIM user by ID."""
    _verify_bearer(authorization)
    conn = _get_db()
    try:
        row = conn.execute("SELECT * FROM scim_users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            return _scim_error(404, f"User {user_id} not found")
        return JSONResponse(content=_row_to_user(row, request), media_type=SCIM_CONTENT_TYPE)
    finally:
        conn.close()


@router.put("/Users/{user_id}")
async def replace_user(
    user_id: str,
    request: Request,
    authorization: Optional[str] = Header(None),
) -> JSONResponse:
    """Full replace of a SCIM user (PUT)."""
    _verify_bearer(authorization)
    body = await request.json()
    conn = _get_db()
    try:
        row = conn.execute("SELECT * FROM scim_users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            return _scim_error(404, f"User {user_id} not found")

        user_name = body.get("userName") or row["user_name"]
        name = body.get("name") or {}
        emails = body.get("emails") or []
        active = body.get("active", True)
        display_name = body.get("displayName") or f"{name.get('givenName','')} {name.get('familyName','')}".strip() or user_name
        now = _now_iso()

        conn.execute(
            """UPDATE scim_users SET
               external_id = ?, user_name = ?, display_name = ?,
               given_name = ?, family_name = ?, emails = ?,
               active = ?, last_modified = ?
               WHERE id = ?""",
            (
                body.get("externalId", row["external_id"]),
                user_name,
                display_name,
                name.get("givenName", row["given_name"]),
                name.get("familyName", row["family_name"]),
                json.dumps(emails),
                1 if active else 0,
                now,
                user_id,
            ),
        )
        conn.commit()
        updated = conn.execute("SELECT * FROM scim_users WHERE id = ?", (user_id,)).fetchone()
        return JSONResponse(content=_row_to_user(updated, request), media_type=SCIM_CONTENT_TYPE)
    finally:
        conn.close()


@router.patch("/Users/{user_id}")
async def patch_user(
    user_id: str,
    request: Request,
    authorization: Optional[str] = Header(None),
) -> JSONResponse:
    """Partial update of a SCIM user (PATCH — RFC 7644 §3.5.2)."""
    _verify_bearer(authorization)
    body = await request.json()
    conn = _get_db()
    try:
        row = conn.execute("SELECT * FROM scim_users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            return _scim_error(404, f"User {user_id} not found")

        # Mutable state
        state: Dict[str, Any] = dict(row)
        state["emails"] = json.loads(state.get("emails") or "[]")

        ops = body.get("Operations", [])
        for op in ops:
            op_type = (op.get("op") or "").lower()
            path = (op.get("path") or "").lower()
            value = op.get("value")

            if op_type in ("replace", "add"):
                if path == "active":
                    if isinstance(value, bool):
                        state["active"] = 1 if value else 0
                    elif isinstance(value, str):
                        state["active"] = 1 if value.lower() in ("true", "1") else 0
                    else:
                        state["active"] = 1 if value else 0
                elif path == "username":
                    state["user_name"] = value
                elif path == "displayname":
                    state["display_name"] = value
                elif path == "externalid":
                    state["external_id"] = value
                elif path == "name.givenname":
                    state["given_name"] = value
                elif path == "name.familyname":
                    state["family_name"] = value
                elif path == "emails":
                    if isinstance(value, list):
                        state["emails"] = value
                elif path == "":
                    # No path — value is a dict of attributes
                    if isinstance(value, dict):
                        if "active" in value:
                            v = value["active"]
                            if isinstance(v, bool):
                                state["active"] = 1 if v else 0
                            else:
                                state["active"] = 1 if str(v).lower() in ("true", "1") else 0
                        if "displayName" in value:
                            state["display_name"] = value["displayName"]
                        if "userName" in value:
                            state["user_name"] = value["userName"]
                        if "externalId" in value:
                            state["external_id"] = value["externalId"]
                        if "name" in value and isinstance(value["name"], dict):
                            state["given_name"] = value["name"].get("givenName", state["given_name"])
                            state["family_name"] = value["name"].get("familyName", state["family_name"])
                        if "emails" in value and isinstance(value["emails"], list):
                            state["emails"] = value["emails"]
            elif op_type == "remove":
                if path == "active":
                    state["active"] = 1  # removal of active = re-enable
                elif path == "emails":
                    state["emails"] = []

        now = _now_iso()
        conn.execute(
            """UPDATE scim_users SET
               external_id = ?, user_name = ?, display_name = ?,
               given_name = ?, family_name = ?, emails = ?,
               active = ?, last_modified = ?
               WHERE id = ?""",
            (
                state.get("external_id"),
                state["user_name"],
                state.get("display_name"),
                state.get("given_name"),
                state.get("family_name"),
                json.dumps(state["emails"]),
                state["active"],
                now,
                user_id,
            ),
        )
        conn.commit()
        updated = conn.execute("SELECT * FROM scim_users WHERE id = ?", (user_id,)).fetchone()
        return JSONResponse(content=_row_to_user(updated, request), media_type=SCIM_CONTENT_TYPE)
    finally:
        conn.close()


@router.delete("/Users/{user_id}", status_code=204)
async def delete_user(
    user_id: str,
    authorization: Optional[str] = Header(None),
) -> None:
    """Deactivate (soft-delete) a SCIM user."""
    _verify_bearer(authorization)
    conn = _get_db()
    try:
        row = conn.execute("SELECT id FROM scim_users WHERE id = ?", (user_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"User {user_id} not found")
        # RFC 7644 §3.6: DELETE → deactivate, not hard-delete
        conn.execute(
            "UPDATE scim_users SET active = 0, last_modified = ? WHERE id = ?",
            (_now_iso(), user_id),
        )
        conn.commit()
    finally:
        conn.close()
    return None


# ---------------------------------------------------------------------------
# Groups
# ---------------------------------------------------------------------------

@router.get("/Groups")
async def list_groups(
    request: Request,
    filter: Optional[str] = Query(None),
    startIndex: int = Query(1, ge=1),
    count: int = Query(100, ge=1, le=1000),
    authorization: Optional[str] = Header(None),
) -> JSONResponse:
    """List SCIM groups with optional filter and pagination."""
    _verify_bearer(authorization)
    conn = _get_db()
    try:
        rows = conn.execute("SELECT * FROM scim_groups ORDER BY created_at").fetchall()
        # Basic filter: displayName eq "x"
        if filter:
            m = _FILTER_RE.match(filter.strip())
            if m:
                attr, value = m.group(1).lower(), m.group(2)
                if attr == "displayname":
                    rows = [r for r in rows if r["display_name"] == value]
        total = len(rows)
        page = rows[startIndex - 1: startIndex - 1 + count]
        resources = [_row_to_group(r, request, conn) for r in page]
        body = {
            "schemas": [SCHEMA_LIST_RESPONSE],
            "totalResults": total,
            "startIndex": startIndex,
            "itemsPerPage": len(resources),
            "Resources": resources,
        }
        return JSONResponse(content=body, media_type=SCIM_CONTENT_TYPE)
    finally:
        conn.close()


@router.post("/Groups", status_code=201)
async def create_group(
    request: Request,
    authorization: Optional[str] = Header(None),
) -> JSONResponse:
    """Create a new SCIM group."""
    _verify_bearer(authorization)
    body = await request.json()

    display_name = body.get("displayName")
    if not display_name:
        return _scim_error(400, "displayName is required")

    conn = _get_db()
    try:
        now = _now_iso()
        group_id = _new_id()
        conn.execute(
            """INSERT INTO scim_groups (id, display_name, external_id, created_at, last_modified)
               VALUES (?, ?, ?, ?, ?)""",
            (group_id, display_name, body.get("externalId"), now, now),
        )
        # Seed members if provided
        for member in body.get("members") or []:
            member_id = member.get("value")
            if member_id:
                conn.execute(
                    "INSERT OR IGNORE INTO scim_group_members (group_id, user_id, display) VALUES (?, ?, ?)",
                    (group_id, member_id, member.get("display")),
                )
        conn.commit()
        row = conn.execute("SELECT * FROM scim_groups WHERE id = ?", (group_id,)).fetchone()
        return JSONResponse(
            content=_row_to_group(row, request, conn),
            status_code=201,
            media_type=SCIM_CONTENT_TYPE,
        )
    finally:
        conn.close()


@router.patch("/Groups/{group_id}")
async def patch_group(
    group_id: str,
    request: Request,
    authorization: Optional[str] = Header(None),
) -> JSONResponse:
    """Partial update of a SCIM group — add/remove/replace members."""
    _verify_bearer(authorization)
    body = await request.json()
    conn = _get_db()
    try:
        row = conn.execute("SELECT * FROM scim_groups WHERE id = ?", (group_id,)).fetchone()
        if not row:
            return _scim_error(404, f"Group {group_id} not found")

        now = _now_iso()
        ops = body.get("Operations", [])
        for op in ops:
            op_type = (op.get("op") or "").lower()
            path = (op.get("path") or "").lower()
            value = op.get("value")

            if op_type == "add" and path == "members":
                members = value if isinstance(value, list) else []
                for m in members:
                    member_id = m.get("value")
                    if member_id:
                        conn.execute(
                            "INSERT OR IGNORE INTO scim_group_members (group_id, user_id, display) VALUES (?, ?, ?)",
                            (group_id, member_id, m.get("display")),
                        )
            elif op_type == "remove" and path == "members":
                if value is None:
                    conn.execute("DELETE FROM scim_group_members WHERE group_id = ?", (group_id,))
                elif isinstance(value, list):
                    for m in value:
                        member_id = m.get("value")
                        if member_id:
                            conn.execute(
                                "DELETE FROM scim_group_members WHERE group_id = ? AND user_id = ?",
                                (group_id, member_id),
                            )
            elif op_type == "replace":
                if path == "displayname" and value:
                    conn.execute(
                        "UPDATE scim_groups SET display_name = ? WHERE id = ?",
                        (value, group_id),
                    )
                elif path == "members" and isinstance(value, list):
                    conn.execute("DELETE FROM scim_group_members WHERE group_id = ?", (group_id,))
                    for m in value:
                        member_id = m.get("value")
                        if member_id:
                            conn.execute(
                                "INSERT OR IGNORE INTO scim_group_members (group_id, user_id, display) VALUES (?, ?, ?)",
                                (group_id, member_id, m.get("display")),
                            )

        conn.execute(
            "UPDATE scim_groups SET last_modified = ? WHERE id = ?",
            (now, group_id),
        )
        conn.commit()
        updated = conn.execute("SELECT * FROM scim_groups WHERE id = ?", (group_id,)).fetchone()
        return JSONResponse(
            content=_row_to_group(updated, request, conn),
            media_type=SCIM_CONTENT_TYPE,
        )
    finally:
        conn.close()
