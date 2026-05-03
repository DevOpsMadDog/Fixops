"""Secrets Management API Router — ALDECI.

Endpoints under /api/v1/secrets-management:

  Secrets:
    POST   /secrets              — store secret metadata
    GET    /secrets              — list secrets (filter: secret_type)
    GET    /secrets/{id}         — get secret metadata
    POST   /secrets/{id}/rotate  — record rotation
    POST   /secrets/{id}/revoke  — revoke secret
    GET    /expiring             — secrets expiring within N days
    GET    /stats                — secrets stats

  Audit:
    POST   /secrets/{id}/access  — record access event
    GET    /secrets/{id}/access  — get access log

Auth: api_key_auth from apps.api.auth_deps
"""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/secrets-management", tags=["secrets-management"])

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.secrets_management_engine import SecretsManagementEngine
        _engine = SecretsManagementEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class StoreSecretIn(BaseModel):
    name: str = Field(..., description="Human-readable secret name")
    secret_type: str = Field("api_key", description="api_key|password|certificate|token|ssh_key|database")
    path: str = Field("", description="Vault path or location reference")
    tags: List[str] = Field(default_factory=list, description="Arbitrary tags")
    rotation_days: int = Field(90, ge=1, description="Rotation interval in days")


class RevokeSecretIn(BaseModel):
    reason: str = Field(..., description="Reason for revocation")


class RecordAccessIn(BaseModel):
    accessor: str = Field(..., description="Identity/service that accessed the secret")
    action: str = Field(..., description="Action performed (read|write|delete|rotate)")


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/secrets", summary="Store secret metadata")
def store_secret(
    req: StoreSecretIn,
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Store secret metadata. The actual secret value is never persisted."""
    try:
        return _get_engine().store_secret(org_id, req.model_dump())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to store secret: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/secrets", summary="List secrets metadata")
def list_secrets(
    org_id: str = Query("default", description="Organisation ID"),
    secret_type: Optional[str] = Query(None, description="Filter by secret type"),
) -> List[Dict[str, Any]]:
    """List secret metadata for org. Secret values are never returned."""
    return _get_engine().list_secrets(org_id, secret_type=secret_type)


@router.get("/secrets/{secret_id}", summary="Get secret metadata")
def get_secret_metadata(
    secret_id: str,
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Return metadata for a single secret (no value exposed)."""
    result = _get_engine().get_secret_metadata(org_id, secret_id)
    if not result:
        raise HTTPException(status_code=404, detail=f"Secret {secret_id} not found.")
    return result


@router.post("/secrets/{secret_id}/rotate", summary="Record secret rotation")
def rotate_secret(
    secret_id: str,
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Record a rotation event — updates last_rotated timestamp."""
    try:
        return _get_engine().rotate_secret(org_id, secret_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to rotate secret: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/secrets/{secret_id}/revoke", summary="Revoke a secret")
def revoke_secret(
    secret_id: str,
    req: RevokeSecretIn,
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Permanently revoke a secret with a stated reason."""
    try:
        return _get_engine().revoke_secret(org_id, secret_id, req.reason)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Failed to revoke secret: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/expiring", summary="List expiring secrets")
def get_expiring_secrets(
    org_id: str = Query("default", description="Organisation ID"),
    days_ahead: int = Query(30, ge=0, description="Warning window in days"),
) -> List[Dict[str, Any]]:
    """Return active secrets at or past their rotation window."""
    return _get_engine().get_expiring_secrets(org_id, days_ahead=days_ahead)


@router.get("/stats", summary="Secrets statistics")
def get_secrets_stats(
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Return aggregated secrets stats: total, by_type, overdue, revoked."""
    return _get_engine().get_secrets_stats(org_id)


@router.post("/secrets/{secret_id}/access", summary="Record access event")
def record_access(
    secret_id: str,
    req: RecordAccessIn,
    org_id: str = Query("default", description="Organisation ID"),
) -> Dict[str, Any]:
    """Record an audit access event for a secret."""
    return _get_engine().record_access(org_id, secret_id, req.accessor, req.action)


@router.get("/secrets/{secret_id}/access", summary="Get access log")
def get_access_log(
    secret_id: str,
    org_id: str = Query("default", description="Organisation ID"),
    limit: int = Query(50, ge=1, le=500, description="Max records to return"),
) -> List[Dict[str, Any]]:
    """Return recent access audit log for a secret."""
    return _get_engine().get_access_log(org_id, secret_id, limit=limit)


@router.get("/audit", summary="Org-wide vault audit log")
def get_vault_audit_log(
    org_id: str = Query("default", description="Organisation ID"),
    accessor: Optional[str] = Query(None, description="Filter by accessor identity"),
    action: Optional[str] = Query(None, description="Filter by action (read|write|delete|rotate)"),
    limit: int = Query(100, ge=1, le=1000, description="Max records to return"),
) -> List[Dict[str, Any]]:
    """Return org-wide access audit log across all secrets.

    Supports filtering by accessor identity and/or action type.
    Ordered by accessed_at DESC. Max 1000 records.
    Compliance: NIST SP 800-57, CIS Control 3.11 — non-repudiation trail.
    """
    return _get_engine().get_vault_audit_log(
        org_id, accessor=accessor, action=action, limit=limit
    )
