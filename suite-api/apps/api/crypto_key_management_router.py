"""Crypto Key Management Router — ALDECI.

Full lifecycle management of cryptographic keys: creation, rotation,
revocation, expiry tracking, and usage audit trail.

Prefix: /api/v1/crypto-keys
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/crypto-keys/                        create_key
  GET    /api/v1/crypto-keys/                        list_keys
  GET    /api/v1/crypto-keys/{key_id}                get_key
  POST   /api/v1/crypto-keys/{key_id}/rotate         rotate_key
  POST   /api/v1/crypto-keys/{key_id}/revoke         revoke_key
  GET    /api/v1/crypto-keys/expiring                 get_expiring_keys
  POST   /api/v1/crypto-keys/{key_id}/usage          record_key_usage
  GET    /api/v1/crypto-keys/stats                    get_key_stats
"""

from __future__ import annotations

import logging
from typing import List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/crypto-keys",
    tags=["Crypto Key Management"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.crypto_key_management_engine import CryptoKeyManagementEngine
        _engine = CryptoKeyManagementEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class CreateKeyRequest(BaseModel):
    name: str = Field(default="", description="Human-readable key name")
    key_type: str = Field(
        default="aes256",
        description="Key algorithm: aes256 | rsa2048 | rsa4096 | ecdsa256 | ed25519",
    )
    purpose: str = Field(
        default="encryption",
        description="Key purpose: encryption | signing | authentication",
    )
    expiry_days: int = Field(default=365, description="Days until the key expires")
    tags: List[str] = Field(default_factory=list, description="Arbitrary classification tags")


class RevokeKeyRequest(BaseModel):
    reason: str = Field(..., description="Reason for revocation")


class RecordUsageRequest(BaseModel):
    usage_type: str = Field(..., description="Type of usage event (e.g. encrypt, decrypt, sign)")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/", dependencies=[Depends(api_key_auth)], status_code=201)
def create_key(
    body: CreateKeyRequest,
    org_id: str = Query(default="default"),
):
    """Create a new cryptographic key for the org."""
    try:
        return _get_engine().create_key(org_id, body.model_dump())
    except Exception as exc:
        _logger.exception("Error creating key")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.get("/expiring", dependencies=[Depends(api_key_auth)])
def get_expiring_keys(
    org_id: str = Query(default="default"),
    days_ahead: int = Query(default=30, ge=1, le=365),
):
    """Return active keys expiring within the next N days."""
    return _get_engine().get_expiring_keys(org_id, days_ahead=days_ahead)


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_key_stats(org_id: str = Query(default="default")):
    """Return aggregated key statistics for the org."""
    return _get_engine().get_key_stats(org_id)


@router.get("/", dependencies=[Depends(api_key_auth)])
def list_keys(
    org_id: str = Query(default="default"),
    key_type: Optional[str] = Query(default=None),
    purpose: Optional[str] = Query(default=None),
):
    """List keys for an org, optionally filtered by key_type and/or purpose."""
    return _get_engine().list_keys(org_id, key_type=key_type, purpose=purpose)


@router.get("/{key_id}", dependencies=[Depends(api_key_auth)])
def get_key(
    key_id: str,
    org_id: str = Query(default="default"),
):
    """Fetch a single key by ID (org-scoped)."""
    key = _get_engine().get_key(org_id, key_id)
    if not key:
        raise HTTPException(status_code=404, detail="Key not found")
    return key


@router.post("/{key_id}/rotate", dependencies=[Depends(api_key_auth)], status_code=201)
def rotate_key(
    key_id: str,
    org_id: str = Query(default="default"),
):
    """Rotate a key: mark old as 'rotating', create new version."""
    try:
        return _get_engine().rotate_key(org_id, key_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error rotating key")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/{key_id}/revoke", dependencies=[Depends(api_key_auth)], status_code=200)
def revoke_key(
    key_id: str,
    body: RevokeKeyRequest,
    org_id: str = Query(default="default"),
):
    """Revoke a key with a stated reason."""
    try:
        return _get_engine().revoke_key(org_id, key_id, body.reason)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        _logger.exception("Error revoking key")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


@router.post("/{key_id}/usage", dependencies=[Depends(api_key_auth)], status_code=201)
def record_key_usage(
    key_id: str,
    body: RecordUsageRequest,
    org_id: str = Query(default="default"),
):
    """Record a key usage event for the audit trail."""
    try:
        return _get_engine().record_key_usage(org_id, key_id, body.usage_type)
    except Exception as exc:
        _logger.exception("Error recording key usage")
        raise HTTPException(status_code=500, detail=str(exc)) from exc
