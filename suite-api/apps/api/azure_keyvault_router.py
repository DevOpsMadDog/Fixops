"""Azure Key Vault Router — ALDECI.

Prefix: ``/api/v1/azure-keyvault``
Scope:  ``read:scans`` (mounted via platform_app)

Routes:
  GET  /                                              capability summary
  GET  /vaults                                        list vaults (ARM)
  GET  /vaults/{name}/secrets                         list secrets (data plane)
  GET  /vaults/{name}/secrets/{secret_name}           get secret value
  GET  /vaults/{name}/secrets/{secret_name}/versions  list secret versions
  GET  /vaults/{name}/keys                            list keys
  GET  /vaults/{name}/keys/{key_name}                 get key (public material)
  GET  /vaults/{name}/certificates                    list certificates
  GET  /vaults/{name}/certificates/{cert_name}        get certificate (full)

NO MOCKS — engine raises ``RuntimeError`` when env unset → mapped to HTTP 503.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

import httpx
from fastapi import APIRouter, HTTPException, Path, Query

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/azure-keyvault", tags=["Azure Key Vault"])


def _engine():
    from core.azure_keyvault_engine import get_azure_keyvault_engine
    return get_azure_keyvault_engine()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _handle_engine_call(callable_):
    """Invoke an engine call and translate errors to HTTPException."""
    try:
        return callable_()
    except RuntimeError as exc:
        # NO MOCKS — env not set / token fetch failed.
        raise HTTPException(
            status_code=503, detail=f"azure key vault unavailable: {exc}"
        ) from exc
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code if exc.response is not None else 502
        raise HTTPException(
            status_code=status, detail=f"azure key vault error: {exc}"
        ) from exc
    except (httpx.HTTPError, OSError) as exc:
        raise HTTPException(
            status_code=502, detail=f"azure key vault transport error: {exc}"
        ) from exc


def _require_configured(eng) -> None:
    if not eng.configured:
        raise HTTPException(
            status_code=503,
            detail=(
                "azure key vault unavailable: AZURE_TENANT_ID, "
                "AZURE_CLIENT_ID, AZURE_CLIENT_SECRET must be set"
            ),
        )


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


@router.get("/")
def capability_summary() -> Dict[str, Any]:
    """Return capability/health summary for the Azure Key Vault integration."""
    eng = _engine()
    return eng.capability_summary()


# ---------------------------------------------------------------------------
# ARM — vaults
# ---------------------------------------------------------------------------


@router.get("/vaults")
def list_vaults(
    subscriptionId: str = Query(..., min_length=1, max_length=128),
    resourceGroupName: str = Query(..., min_length=1, max_length=128),
    top: Optional[int] = Query(default=None, ge=1, le=1000),
) -> Dict[str, Any]:
    """List Key Vaults in a resource group via Azure ARM."""
    eng = _engine()
    _require_configured(eng)
    return _handle_engine_call(
        lambda: eng.list_vaults(
            subscription_id=subscriptionId,
            resource_group_name=resourceGroupName,
            top=top,
        )
    )


# ---------------------------------------------------------------------------
# Data plane — secrets
# ---------------------------------------------------------------------------


@router.get("/vaults/{name}/secrets")
def list_secrets(
    name: str = Path(..., min_length=3, max_length=24),
    maxresults: Optional[int] = Query(default=None, ge=1, le=25),
) -> Dict[str, Any]:
    """List secret identifiers in a Key Vault (data plane)."""
    eng = _engine()
    _require_configured(eng)
    return _handle_engine_call(
        lambda: eng.list_secrets(vault_name=name, maxresults=maxresults)
    )


@router.get("/vaults/{name}/secrets/{secret_name}/versions")
def list_secret_versions(
    name: str = Path(..., min_length=3, max_length=24),
    secret_name: str = Path(..., min_length=1, max_length=127),
    maxresults: Optional[int] = Query(default=None, ge=1, le=25),
) -> Dict[str, Any]:
    """List historical versions of a secret."""
    eng = _engine()
    _require_configured(eng)
    return _handle_engine_call(
        lambda: eng.list_secret_versions(
            vault_name=name, secret_name=secret_name, maxresults=maxresults
        )
    )


@router.get("/vaults/{name}/secrets/{secret_name}")
def get_secret(
    name: str = Path(..., min_length=3, max_length=24),
    secret_name: str = Path(..., min_length=1, max_length=127),
) -> Dict[str, Any]:
    """Get the current version of a secret (value + attributes)."""
    eng = _engine()
    _require_configured(eng)
    return _handle_engine_call(
        lambda: eng.get_secret(vault_name=name, secret_name=secret_name)
    )


# ---------------------------------------------------------------------------
# Data plane — keys
# ---------------------------------------------------------------------------


@router.get("/vaults/{name}/keys")
def list_keys(
    name: str = Path(..., min_length=3, max_length=24),
    maxresults: Optional[int] = Query(default=None, ge=1, le=25),
) -> Dict[str, Any]:
    """List key identifiers in a Key Vault."""
    eng = _engine()
    _require_configured(eng)
    return _handle_engine_call(
        lambda: eng.list_keys(vault_name=name, maxresults=maxresults)
    )


@router.get("/vaults/{name}/keys/{key_name}")
def get_key(
    name: str = Path(..., min_length=3, max_length=24),
    key_name: str = Path(..., min_length=1, max_length=127),
) -> Dict[str, Any]:
    """Get a key's public material + attributes (private material never returned)."""
    eng = _engine()
    _require_configured(eng)
    return _handle_engine_call(
        lambda: eng.get_key(vault_name=name, key_name=key_name)
    )


# ---------------------------------------------------------------------------
# Data plane — certificates
# ---------------------------------------------------------------------------


@router.get("/vaults/{name}/certificates")
def list_certificates(
    name: str = Path(..., min_length=3, max_length=24),
    maxresults: Optional[int] = Query(default=None, ge=1, le=25),
) -> Dict[str, Any]:
    """List certificate identifiers in a Key Vault."""
    eng = _engine()
    _require_configured(eng)
    return _handle_engine_call(
        lambda: eng.list_certificates(vault_name=name, maxresults=maxresults)
    )


@router.get("/vaults/{name}/certificates/{cert_name}")
def get_certificate(
    name: str = Path(..., min_length=3, max_length=24),
    cert_name: str = Path(..., min_length=1, max_length=127),
) -> Dict[str, Any]:
    """Get a certificate including DER-encoded body, policy, and attributes."""
    eng = _engine()
    _require_configured(eng)
    return _handle_engine_call(
        lambda: eng.get_certificate(vault_name=name, cert_name=cert_name)
    )


__all__ = ["router"]
