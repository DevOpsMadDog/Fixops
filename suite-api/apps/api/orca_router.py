"""Orca Security Router — ALDECI.

Prefix: /api/v1/orca
Scope:  read:scans (mounted via platform_app)

Routes:
  GET   /                                capability summary
  GET   /api/alerts                      list alerts (paginated, filtered)
  GET   /api/asset                       list assets (filter by type)
  GET   /api/asset/{asset_unique_id}     single asset
  GET   /api/policies                    list policies (built_in + custom)
  POST  /api/sonar/query                 execute Orca Sonar DSL query
  GET   /api/clouds                      list cloud accounts
  GET   /api/users                       list Orca console users

Returns 503 on lookup endpoints when ORCA_API_TOKEN unset. NO MOCKS —
engine raises RuntimeError → mapped to 503.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import httpx
from fastapi import APIRouter, HTTPException, Path, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/orca", tags=["Orca Security"])


def _engine():
    from core.orca_engine import get_orca_engine
    return get_orca_engine()


# ---------------------------------------------------------------------------
# Pydantic request models
# ---------------------------------------------------------------------------


class SonarQueryRequest(BaseModel):
    query: str = Field(
        ...,
        min_length=1,
        max_length=64 * 1024,
        description="Orca Sonar DSL query (e.g. Asset.Type:Instance with vulnerability.exploitable.kev=true)",
    )
    limit: Optional[int] = Field(default=None, ge=1, le=10000)
    next_page_token: Optional[str] = Field(default=None, max_length=4096)
    additional_attributes: Optional[List[str]] = Field(default=None, max_length=128)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _handle_engine_call(callable_):
    """Invoke engine call and translate errors to HTTPException."""
    try:
        return callable_()
    except RuntimeError as exc:
        # NO MOCKS — when env not set
        raise HTTPException(status_code=503, detail=f"orca unavailable: {exc}") from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f"orca bad request: {exc}") from exc
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code if exc.response is not None else 502
        raise HTTPException(status_code=status, detail=f"orca error: {exc}") from exc
    except (httpx.HTTPError, OSError) as exc:
        raise HTTPException(status_code=502, detail=f"orca transport error: {exc}") from exc


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


@router.get("/")
def capability_summary() -> Dict[str, Any]:
    """Return capability/health summary for the Orca Security integration."""
    eng = _engine()
    return eng.capability_summary()


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------


@router.get("/api/alerts")
def list_alerts(
    next_page_token: Optional[str] = Query(default=None, max_length=4096),
    limit: Optional[int] = Query(default=None, ge=1, le=10000),
    start_at_time: Optional[str] = Query(default=None, max_length=64),
    end_at_time: Optional[str] = Query(default=None, max_length=64),
    status: Optional[str] = Query(default=None, max_length=64,
                                  description="open|closed|in_progress|snoozed|dismissed"),
    priority: Optional[str] = Query(default=None, max_length=64,
                                    description="critical|high|medium|low"),
    type: Optional[str] = Query(default=None, max_length=128, alias="type"),  # noqa: A002
    cloud_account: Optional[str] = Query(default=None, max_length=256),
) -> Dict[str, Any]:
    """List Orca alerts. Filterable by time/status/priority/type/cloud_account."""
    return _handle_engine_call(
        lambda: _engine().list_alerts(
            next_page_token=next_page_token,
            limit=limit,
            start_at_time=start_at_time,
            end_at_time=end_at_time,
            status=status,
            priority=priority,
            type_=type,
            cloud_account=cloud_account,
        )
    )


# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------


@router.get("/api/asset")
def list_assets(
    type: Optional[str] = Query(default=None, max_length=128, alias="type"),  # noqa: A002
    limit: Optional[int] = Query(default=None, ge=1, le=10000),
    next_page_token: Optional[str] = Query(default=None, max_length=4096),
) -> Dict[str, Any]:
    """List Orca assets (instances, buckets, databases, container_images, ...)."""
    return _handle_engine_call(
        lambda: _engine().list_assets(
            type_=type,
            limit=limit,
            next_page_token=next_page_token,
        )
    )


@router.get("/api/asset/{asset_unique_id:path}")
def get_asset(
    asset_unique_id: str = Path(..., min_length=1, max_length=512),
) -> Dict[str, Any]:
    """Return a single Orca asset by unique id."""
    return _handle_engine_call(lambda: _engine().get_asset(asset_unique_id))


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------


@router.get("/api/policies")
def list_policies() -> Dict[str, Any]:
    """List Orca policies (built_in + custom)."""
    return _handle_engine_call(lambda: _engine().list_policies())


# ---------------------------------------------------------------------------
# Sonar
# ---------------------------------------------------------------------------


@router.post("/api/sonar/query")
def sonar_query(req: SonarQueryRequest) -> Dict[str, Any]:
    """Execute an Orca Sonar DSL query."""
    return _handle_engine_call(
        lambda: _engine().sonar_query(
            query=req.query,
            limit=req.limit,
            next_page_token=req.next_page_token,
            additional_attributes=req.additional_attributes,
        )
    )


# ---------------------------------------------------------------------------
# Clouds
# ---------------------------------------------------------------------------


@router.get("/api/clouds")
def list_clouds() -> Dict[str, Any]:
    """List Orca-monitored cloud accounts."""
    return _handle_engine_call(lambda: _engine().list_clouds())


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------


@router.get("/api/users")
def list_users() -> Dict[str, Any]:
    """List Orca console users."""
    return _handle_engine_call(lambda: _engine().list_users())
