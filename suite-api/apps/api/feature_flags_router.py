"""Feature Flags API router.

Exposes the flags registry and LocalOverlayProvider evaluation surface
via a single REST endpoint:

  GET  /api/v1/feature-flags           – list all registered flags with live values
  GET  /api/v1/feature-flags/{key}     – evaluate one flag (all types)
  POST /api/v1/feature-flags/{key}/override  – set a runtime in-memory override
  DELETE /api/v1/feature-flags/{key}/override – remove runtime override
  GET  /api/v1/feature-flags/rollout/{key}   – evaluate percentage rollout for a context

Auth: ``Depends(api_key_auth)`` on all endpoints.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from core.flags.base import EvaluationContext
from core.flags.local_provider import LocalOverlayProvider
from core.flags.registry import FlagType, get_registry
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi import Path as PathParam
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/feature-flags",
    tags=["feature-flags"],
    dependencies=[Depends(api_key_auth)],
)

# ---------------------------------------------------------------------------
# In-memory runtime overrides (survives request lifetime, not persisted)
# ---------------------------------------------------------------------------
_runtime_overrides: Dict[str, Any] = {}

# Singleton provider backed by runtime overrides
def _get_provider() -> LocalOverlayProvider:
    return LocalOverlayProvider({"feature_flags": _runtime_overrides})


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class FlagSummary(BaseModel):
    key: str
    type: str
    default: Any
    description: str
    owner: str
    tags: List[str]
    expiry: Optional[str] = None
    overridden: bool = False
    runtime_value: Optional[Any] = None


class FlagEvalResponse(BaseModel):
    key: str
    type: str
    value: Any
    default: Any
    overridden: bool


class OverrideRequest(BaseModel):
    value: Any = Field(..., description="Runtime override value (any JSON type)")


class RolloutRequest(BaseModel):
    tenant_id: Optional[str] = None
    user_email: Optional[str] = None
    plan: Optional[str] = None
    environment: Optional[str] = None
    custom: Dict[str, Any] = Field(default_factory=dict)


class RolloutResponse(BaseModel):
    key: str
    value: Any
    context: Dict[str, Any]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.get("", response_model=List[FlagSummary], summary="List all feature flags")
def list_flags(
    tag: Optional[str] = Query(None, description="Filter by tag"),
) -> List[FlagSummary]:
    """Return all registered flags with metadata and current runtime override status."""
    registry = get_registry()
    flags = registry.list_by_tag(tag) if tag else registry.list_all()

    result: List[FlagSummary] = []
    for meta in flags:
        overridden = meta.key in _runtime_overrides
        result.append(
            FlagSummary(
                key=meta.key,
                type=meta.flag_type.value,
                default=meta.default,
                description=meta.description,
                owner=meta.owner,
                tags=meta.tags,
                expiry=meta.expiry,
                overridden=overridden,
                runtime_value=_runtime_overrides.get(meta.key) if overridden else None,
            )
        )
    return result


@router.get("/{key:path}", response_model=FlagEvalResponse, summary="Evaluate a feature flag")
def get_flag(
    key: str = PathParam(..., description="Flag key, e.g. fixops.ops.kill_switch"),
    tenant_id: Optional[str] = Query(None),
    user_email: Optional[str] = Query(None),
    plan: Optional[str] = Query(None),
    environment: Optional[str] = Query(None),
) -> FlagEvalResponse:
    """Evaluate a single flag against optional targeting context.

    Uses runtime overrides first; falls back to registry default.
    """
    registry = get_registry()
    meta = registry.get(key)
    if meta is None:
        raise HTTPException(status_code=404, detail=f"Flag '{key}' not found in registry")

    ctx = EvaluationContext(
        tenant_id=tenant_id,
        user_email=user_email,
        plan=plan,
        environment=environment,
    )
    provider = _get_provider()
    overridden = key in _runtime_overrides

    if meta.flag_type == FlagType.BOOL:
        value = provider.bool(key, meta.default, ctx) if overridden else meta.default
    elif meta.flag_type == FlagType.STRING:
        value = provider.string(key, meta.default, ctx) if overridden else meta.default
    elif meta.flag_type == FlagType.NUMBER:
        value = provider.number(key, meta.default, ctx) if overridden else meta.default
    elif meta.flag_type == FlagType.JSON:
        value = provider.json(key, meta.default, ctx) if overridden else meta.default
    elif meta.flag_type == FlagType.VARIANT:
        value = provider.variant(key, meta.default, ctx) if overridden else meta.default
    else:
        value = meta.default

    return FlagEvalResponse(
        key=key,
        type=meta.flag_type.value,
        value=value,
        default=meta.default,
        overridden=overridden,
    )


@router.post("/{key:path}/override", response_model=FlagEvalResponse, summary="Set runtime override")
def set_override(
    key: str = PathParam(..., description="Flag key"),
    body: OverrideRequest = ...,
) -> FlagEvalResponse:
    """Set an in-memory runtime override for a flag (not persisted across restarts)."""
    registry = get_registry()
    meta = registry.get(key)
    if meta is None:
        raise HTTPException(status_code=404, detail=f"Flag '{key}' not found in registry")

    _runtime_overrides[key] = body.value
    _logger.info("Feature flag override set: %s = %r", key, body.value)

    return FlagEvalResponse(
        key=key,
        type=meta.flag_type.value,
        value=body.value,
        default=meta.default,
        overridden=True,
    )


@router.delete("/{key:path}/override", status_code=204, summary="Remove runtime override")
def delete_override(
    key: str = PathParam(..., description="Flag key"),
) -> None:
    """Remove an in-memory runtime override, reverting to registry default."""
    registry = get_registry()
    meta = registry.get(key)
    if meta is None:
        raise HTTPException(status_code=404, detail=f"Flag '{key}' not found in registry")

    if key not in _runtime_overrides:
        raise HTTPException(status_code=404, detail=f"No runtime override for flag '{key}'")

    del _runtime_overrides[key]
    _logger.info("Feature flag override removed: %s", key)


@router.post("/rollout/{key:path}", response_model=RolloutResponse, summary="Evaluate rollout for context")
def evaluate_rollout(
    key: str = PathParam(..., description="Flag key"),
    body: RolloutRequest = ...,
) -> RolloutResponse:
    """Evaluate a percentage-based rollout or variant flag for a specific context.

    Useful for client-side hydration — pass tenant_id / user_email to get
    consistent bucketing without exposing the hashing logic to the client.
    """
    registry = get_registry()
    meta = registry.get(key)
    if meta is None:
        raise HTTPException(status_code=404, detail=f"Flag '{key}' not found in registry")

    ctx = EvaluationContext(
        tenant_id=body.tenant_id,
        user_email=body.user_email,
        plan=body.plan,
        environment=body.environment,
        custom=body.custom,
    )
    provider = _get_provider()
    overridden = key in _runtime_overrides

    if meta.flag_type == FlagType.VARIANT:
        value = provider.variant(key, meta.default, ctx)
    elif meta.flag_type == FlagType.BOOL:
        value = provider.bool(key, meta.default if not overridden else _runtime_overrides[key], ctx)
    elif meta.flag_type == FlagType.NUMBER:
        value = provider.number(key, meta.default if not overridden else _runtime_overrides[key], ctx)
    else:
        value = provider.string(key, str(meta.default) if not overridden else str(_runtime_overrides[key]), ctx)

    return RolloutResponse(key=key, value=value, context=ctx.to_dict())


__all__ = ["router"]
