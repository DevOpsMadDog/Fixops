"""HIBP (Have I Been Pwned) Router — ALDECI.

Endpoints for breach catalog import/query and k-anonymity password checks.

Prefix: /api/v1/hibp
Auth:   api_key_auth dependency

Routes:
  POST /api/v1/hibp/check-password   check_password   — k-anonymity range proxy
  POST /api/v1/hibp/check-email      check_email      — paid tier (graceful no-key)
  POST /api/v1/hibp/import-breaches  import_breaches  — pull HIBP breach catalog
  GET  /api/v1/hibp/breaches         list_breaches    — query stored catalog
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/hibp",
    tags=["HIBP"],
)


# ---------------------------------------------------------------------------
# Lazy importer accessor
# ---------------------------------------------------------------------------

def _get_importer(db_path: Optional[str] = None):
    """Return a HibpImporter instance (lazy import to avoid startup errors)."""
    from feeds.hibp.importer import _DEFAULT_DB, HibpImporter  # noqa: PLC0415
    return HibpImporter(db_path=db_path or _DEFAULT_DB)


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class PasswordCheckRequest(BaseModel):
    password_sha1_first5: str = Field(
        ...,
        min_length=5,
        max_length=5,
        description="First 5 hex characters of the SHA-1 hash of the password (k-anonymity safe).",
        examples=["5BAA6"],
    )


class EmailCheckRequest(BaseModel):
    email: str = Field(
        ...,
        description="Email address to check. Requires HIBP_API_KEY env var.",
    )


class ImportBreachesRequest(BaseModel):
    force_update: bool = Field(
        default=False,
        description="When True, update existing breach records instead of skipping them.",
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/check-password", dependencies=[Depends(api_key_auth)])
def check_password(body: PasswordCheckRequest) -> Dict[str, Any]:
    """K-anonymity password range proxy.

    Sends only the 5-char SHA-1 prefix to HIBP — the full hash never leaves
    this service.  Returns matching suffixes and their exposure counts.

    Privacy: the full password hash is never stored or logged.
    """
    prefix = body.password_sha1_first5.upper()
    try:
        imp = _get_importer()
        return imp.check_password_range(prefix)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("HIBP password range check failed for prefix (hidden)")
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.post("/check-email", dependencies=[Depends(api_key_auth)])
def check_email(body: EmailCheckRequest) -> Dict[str, Any]:
    """Check whether an email has appeared in any known data breach.

    Requires HIBP_API_KEY environment variable.  When the key is absent
    the endpoint returns immediately with status="needs_credentials" — no
    error is raised.

    Privacy: the full email address is never logged.
    """
    try:
        imp = _get_importer()
        return imp.check_email(body.email)
    except Exception as exc:
        logger.exception("HIBP email check failed")
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.post("/import-breaches", dependencies=[Depends(api_key_auth)])
def import_breaches(body: ImportBreachesRequest = ImportBreachesRequest()) -> Dict[str, Any]:
    """Pull the HIBP breach catalog (~700 entries, free endpoint) and upsert into DB.

    Returns import summary with year-bucket distribution and biggest breach.
    """
    try:
        imp = _get_importer()
        return imp.import_breaches(idempotent=not body.force_update)
    except Exception as exc:
        logger.exception("HIBP breach import failed")
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@router.get("/breaches", dependencies=[Depends(api_key_auth)])
def list_breaches(
    domain: Optional[str] = Query(default=None, description="Filter by exact domain (e.g. adobe.com)"),
    since: Optional[str] = Query(default=None, description="ISO date (YYYY-MM-DD) — breaches on or after"),
    data_class: Optional[str] = Query(default=None, description="Filter by data class substring (e.g. Passwords)"),
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
) -> Dict[str, Any]:
    """List stored HIBP breach catalog with optional filters."""
    try:
        imp = _get_importer()
        return imp.list_breaches(
            domain=domain,
            since=since,
            data_class=data_class,
            limit=limit,
            offset=offset,
        )
    except Exception as exc:
        logger.exception("HIBP breach list failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
