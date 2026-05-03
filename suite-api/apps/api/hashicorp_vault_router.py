"""HashiCorp Vault Router — ALDECI.

Wraps ``core.hashicorp_vault_engine.HashiCorpVaultEngine`` with REST endpoints
mirroring the HashiCorp Vault HTTP API.

Prefix: /api/v1/hashicorp-vault
Auth:   api_key_auth dependency (mount layer adds scope checks — read:scans)

NOTE: ALDECI ships its own ``evidence_vault_router`` for tenant evidence
storage. This router is a separate integration with the *external* HashiCorp
Vault product and intentionally uses a distinct prefix to avoid collision.

Routes:
  GET  /api/v1/hashicorp-vault/                      capability summary
  GET  /api/v1/hashicorp-vault/v1/sys/health         vault health
  GET  /api/v1/hashicorp-vault/v1/sys/seal-status    seal status
  GET  /api/v1/hashicorp-vault/v1/secret/data/{path} KV v2 read
  POST /api/v1/hashicorp-vault/v1/secret/data/{path} KV v2 write
  GET  /api/v1/hashicorp-vault/v1/sys/policies/acl   ACL policy list
  GET  /api/v1/hashicorp-vault/v1/sys/policies/acl/{name} ACL policy read
  GET  /api/v1/hashicorp-vault/v1/sys/auth           enabled auth methods
  GET  /api/v1/hashicorp-vault/v1/sys/mounts         enabled secret engines

NO MOCKS rule: when ``VAULT_ADDR`` or ``VAULT_TOKEN`` is unset the capability
summary returns ``status="unavailable"`` and every live call returns HTTP 503.
We never fabricate Vault data.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, HTTPException, Path, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/hashicorp-vault",
    tags=["HashiCorp Vault"],
    dependencies=[Depends(api_key_auth)],
)


def _engine():
    from core.hashicorp_vault_engine import get_hashicorp_vault_engine

    return get_hashicorp_vault_engine()


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class CapabilityResponse(BaseModel):
    service: str
    endpoints: List[str]
    vault_addr_present: bool
    vault_token_present: bool
    status: str  # ok | empty | unavailable


class WriteSecretRequest(BaseModel):
    data: Dict[str, Any] = Field(..., description="Secret payload (key/value object)")
    options: Optional[Dict[str, Any]] = Field(
        default=None, description='Optional KV v2 options (e.g. {"cas":0})'
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _serve(callable_):
    """Translate engine errors to HTTP responses.

    HashiCorpVaultUnavailableError -> 503
    ValueError                     -> 422
    """
    from core.hashicorp_vault_engine import HashiCorpVaultUnavailableError

    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except HashiCorpVaultUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/", response_model=CapabilityResponse)
async def capability_summary() -> CapabilityResponse:
    """Service capability summary — safe to call without Vault env."""
    eng = _engine()
    addr = eng.vault_addr_present()
    token = eng.vault_token_present()
    if not (addr and token):
        status = "unavailable"
    else:
        status = "empty"  # no in-process cache; live calls populate
    return CapabilityResponse(
        service="HashiCorp Vault",
        endpoints=[
            "/v1/sys/health",
            "/v1/secret/data/{path}",
            "/v1/sys/policies/acl",
            "/v1/sys/auth",
            "/v1/sys/mounts",
        ],
        vault_addr_present=addr,
        vault_token_present=token,
        status=status,
    )


@router.get("/v1/sys/health")
async def health(
    standbyok: bool = Query(True),
    perfstandbyok: bool = Query(True),
    sealedcode: int = Query(503, ge=100, le=599),
    uninitcode: int = Query(501, ge=100, le=599),
) -> Dict[str, Any]:
    """``GET /v1/sys/health`` — proxied directly. Vault encodes state in HTTP code."""
    eng = _engine()
    return _serve(
        lambda: eng.health(
            standbyok=standbyok,
            perfstandbyok=perfstandbyok,
            sealedcode=sealedcode,
            uninitcode=uninitcode,
        )
    )


@router.get("/v1/sys/seal-status")
async def seal_status() -> Dict[str, Any]:
    """``GET /v1/sys/seal-status``"""
    eng = _engine()
    return _serve(eng.seal_status)


@router.get("/v1/secret/data/{path:path}")
async def read_secret(
    path: str = Path(..., description="KV v2 secret path (supports nested segments)"),
) -> Dict[str, Any]:
    """``GET /v1/secret/data/{path}`` — KV v2 read."""
    eng = _engine()
    return _serve(lambda: eng.read_secret(path=path))


@router.post("/v1/secret/data/{path:path}")
async def write_secret(
    path: str = Path(..., description="KV v2 secret path (supports nested segments)"),
    body: WriteSecretRequest = Body(...),
) -> Dict[str, Any]:
    """``POST /v1/secret/data/{path}`` — KV v2 create/update."""
    eng = _engine()
    cas: Optional[int] = None
    if body.options and "cas" in body.options:
        try:
            cas = int(body.options["cas"])
        except (TypeError, ValueError) as exc:
            raise HTTPException(status_code=422, detail="options.cas must be int") from exc
    return _serve(lambda: eng.write_secret(path=path, data=body.data, cas=cas))


@router.get("/v1/sys/policies/acl")
async def list_acl_policies(
    list: bool = Query(True, description="Vault requires list=true to enumerate"),  # noqa: A002
) -> Dict[str, Any]:
    """``GET /v1/sys/policies/acl?list=true``"""
    eng = _engine()
    return _serve(eng.list_acl_policies)


@router.get("/v1/sys/policies/acl/{name}")
async def read_acl_policy(
    name: str = Path(..., description="ACL policy name"),
) -> Dict[str, Any]:
    """``GET /v1/sys/policies/acl/{name}``"""
    eng = _engine()
    return _serve(lambda: eng.read_acl_policy(name=name))


@router.get("/v1/sys/auth")
async def list_auth_methods() -> Dict[str, Dict[str, Any]]:
    """``GET /v1/sys/auth`` — returns mount-path → method spec."""
    eng = _engine()
    return _serve(eng.list_auth_methods)


@router.get("/v1/sys/mounts")
async def list_mounts() -> Dict[str, Dict[str, Any]]:
    """``GET /v1/sys/mounts`` — returns mount-path → secret-engine spec."""
    eng = _engine()
    return _serve(eng.list_mounts)
