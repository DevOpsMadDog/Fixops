"""Secrets Manager API router — vault and secret inventory, rotation tracking."""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

# Auth dep — same pattern used across all ALDECI routers
from apps.api.auth_deps import api_key_auth as _verify_api_key
from core.secrets_manager_engine import SecretsManagerEngine
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

router = APIRouter(prefix="/api/v1/secrets-manager", tags=["secrets-manager"])

_DB_PATH = os.environ.get(
    "SECRETS_MANAGER_DB",
    os.path.join(os.path.dirname(__file__), "..", "..", "..", ".fixops_data", "secrets_manager.db"),
)

_engine: Optional[SecretsManagerEngine] = None


def _get_engine() -> SecretsManagerEngine:
    global _engine
    if _engine is None:
        _engine = SecretsManagerEngine(db_path=_DB_PATH)
    return _engine


def _org(request_data: Optional[str] = None) -> str:
    return request_data or "default"


# ------------------------------------------------------------------
# Pydantic models
# ------------------------------------------------------------------

class VaultCreate(BaseModel):
    name: str = Field(..., description="Human-readable vault name")
    vault_type: str = Field("local", description="hashicorp|aws_secrets|azure_kv|gcp_sm|local")
    status: str = Field("active", description="active|locked")
    org_id: str = Field("default")


class SecretCreate(BaseModel):
    name: str = Field(..., description="Secret name / identifier")
    secret_type: str = Field("api_key", description="api_key|db_password|tls_cert|oauth_token|ssh_key|service_account")
    owner: str = Field("", description="Owner team or user")
    environment: str = Field("prod", description="prod|staging|dev")
    rotation_days: int = Field(90, ge=1, description="Days between required rotations")
    expires_at: Optional[float] = Field(None, description="Unix timestamp of expiry (computed if omitted)")
    last_rotated: Optional[float] = Field(None, description="Unix timestamp of last rotation")
    org_id: str = Field("default")


class RotationScheduleCreate(BaseModel):
    rotation_days: int = Field(90, ge=1)
    org_id: str = Field("default")


class RotationRecord(BaseModel):
    rotation_type: str = Field("manual", description="manual|automated|emergency")
    performed_by: str = Field("", description="User or system that performed rotation")
    org_id: str = Field("default")


class OrgQuery(BaseModel):
    org_id: str = "default"


# ------------------------------------------------------------------
# Vault endpoints
# ------------------------------------------------------------------

@router.get("/vaults", dependencies=[Depends(_verify_api_key)])
def list_vaults(org_id: str = Query("default")) -> List[Dict[str, Any]]:
    """List all secret vaults for an org."""
    return _get_engine().list_vaults(org_id)


@router.post("/vaults", dependencies=[Depends(_verify_api_key)])
def create_vault(body: VaultCreate) -> Dict[str, Any]:
    """Create a new secret vault."""
    try:
        return _get_engine().create_vault(body.org_id, body.model_dump(exclude={"org_id"}))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# ------------------------------------------------------------------
# Secret endpoints
# ------------------------------------------------------------------

@router.get("/secrets", dependencies=[Depends(_verify_api_key)])
def list_secrets(
    org_id: str = Query("default"),
    vault_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    """List secrets, optionally filtered by vault_id or status."""
    return _get_engine().list_secrets(org_id, vault_id=vault_id, status=status)


@router.post("/secrets", dependencies=[Depends(_verify_api_key)])
def add_secret(vault_id: str, body: SecretCreate) -> Dict[str, Any]:
    """Add a secret to a vault."""
    try:
        return _get_engine().add_secret(
            body.org_id,
            vault_id,
            body.model_dump(exclude={"org_id"}),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/secrets/expiring", dependencies=[Depends(_verify_api_key)])
def get_expiring_secrets(
    org_id: str = Query("default"),
    days_ahead: int = Query(30, ge=1),
) -> List[Dict[str, Any]]:
    """Return secrets expiring within the next N days."""
    return _get_engine().get_expiring_secrets(org_id, days_ahead=days_ahead)


@router.post("/secrets/{secret_id}/rotate", dependencies=[Depends(_verify_api_key)])
def record_rotation(secret_id: str, body: RotationRecord) -> Dict[str, Any]:
    """Record that a secret was rotated."""
    try:
        return _get_engine().record_rotation(
            body.org_id, secret_id, body.rotation_type, body.performed_by
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/secrets/{secret_id}/schedule", dependencies=[Depends(_verify_api_key)])
def schedule_rotation(secret_id: str, body: RotationScheduleCreate) -> Dict[str, Any]:
    """Set or update the rotation schedule for a secret."""
    try:
        return _get_engine().schedule_rotation(body.org_id, secret_id, body.rotation_days)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/secrets/{secret_id}/history", dependencies=[Depends(_verify_api_key)])
def get_rotation_history(
    secret_id: str,
    org_id: str = Query("default"),
) -> List[Dict[str, Any]]:
    """Get rotation history for a secret."""
    try:
        return _get_engine().get_rotation_history(org_id, secret_id)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


# ------------------------------------------------------------------
# Stats
# ------------------------------------------------------------------

@router.get("/stats", dependencies=[Depends(_verify_api_key)])
def get_stats(org_id: str = Query("default")) -> Dict[str, Any]:
    """Return aggregated secrets stats for an org."""
    return _get_engine().get_secrets_stats(org_id)
