"""Lacework CSPM Router — ALDECI.

Prefix: /api/v1/lacework
Scope:  read:scans (mounted via platform_app)

Routes:
  GET   /                                                   capability summary
  POST  /api/v2/access/tokens                               request access token
  GET   /api/v2/Alerts                                      list alerts (paginated)
  GET   /api/v2/Alerts/{alert_id}                           single alert
  GET   /api/v2/Compliance/Reports/AwsLatest                aws compliance latest
  POST  /api/v2/Vulnerabilities/Hosts/search                search host vulns
  POST  /api/v2/Vulnerabilities/Containers/search           search container vulns
  GET   /api/v2/Inventory                                   list inventory

Returns 503 on lookup endpoints when LACEWORK_ACCOUNT/LACEWORK_KEY_ID/
LACEWORK_SECRET unset. NO MOCKS — engine raises RuntimeError → mapped to 503.
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

import httpx
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/lacework", tags=["Lacework CSPM"])


def _engine():
    from core.lacework_engine import get_lacework_engine
    return get_lacework_engine()


# ---------------------------------------------------------------------------
# Pydantic request models
# ---------------------------------------------------------------------------


class AccessTokenRequest(BaseModel):
    keyId: str = Field(..., min_length=1, max_length=512, description="Lacework API key id")  # noqa: N815
    expiryTime: Optional[int] = Field(default=None, ge=60, le=86400, description="Token TTL seconds")  # noqa: N815


class TimeFilter(BaseModel):
    startTime: Optional[str] = Field(default=None, max_length=64)  # noqa: N815
    endTime: Optional[str] = Field(default=None, max_length=64)  # noqa: N815


class VulnFilter(BaseModel):
    field: str = Field(..., min_length=1, max_length=128)
    expression: str = Field(..., min_length=1, max_length=32)
    value: Optional[Any] = Field(default=None)
    values: Optional[List[Any]] = Field(default=None)


class VulnSearchRequest(BaseModel):
    filters: Optional[List[VulnFilter]] = Field(default=None)
    returns: Optional[List[str]] = Field(default=None)
    timeFilter: Optional[TimeFilter] = Field(default=None)  # noqa: N815


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _handle_engine_call(callable_):
    """Invoke an engine call and translate errors to HTTPException."""
    try:
        return callable_()
    except RuntimeError as exc:
        # NO MOCKS — when env not set
        raise HTTPException(status_code=503, detail=f"lacework unavailable: {exc}") from exc
    except httpx.HTTPStatusError as exc:
        status = exc.response.status_code if exc.response is not None else 502
        raise HTTPException(status_code=status, detail=f"lacework error: {exc}") from exc
    except (httpx.HTTPError, OSError) as exc:
        raise HTTPException(status_code=502, detail=f"lacework transport error: {exc}") from exc


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


@router.get("/")
def capability_summary() -> Dict[str, Any]:
    """Return capability/health summary for the Lacework integration."""
    eng = _engine()
    return eng.capability_summary()


# ---------------------------------------------------------------------------
# Access tokens
# ---------------------------------------------------------------------------


@router.post("/api/v2/access/tokens")
def access_tokens(req: AccessTokenRequest) -> Dict[str, Any]:
    """POST /api/v2/access/tokens — exchange keyId+secret for bearer token."""
    eng = _engine()
    return _handle_engine_call(
        lambda: eng.request_access_token(
            key_id=req.keyId,
            expiry_time=req.expiryTime,
        )
    )


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------


@router.get("/api/v2/Alerts")
def list_alerts(
    startTime: Optional[str] = Query(default=None, max_length=64),  # noqa: N803
    endTime: Optional[str] = Query(default=None, max_length=64),  # noqa: N803
    status: Optional[str] = Query(default=None, max_length=32, description="Open|Closed|Suppressed"),
    pageSize: Optional[int] = Query(default=None, ge=1, le=5000),  # noqa: N803
    token: Optional[str] = Query(default=None, max_length=4096, description="Pagination token"),
) -> Dict[str, Any]:
    """List Lacework alerts."""
    eng = _engine()
    return _handle_engine_call(
        lambda: eng.list_alerts(
            start_time=startTime,
            end_time=endTime,
            status=status,
            page_size=pageSize,
            token=token,
        )
    )


@router.get("/api/v2/Alerts/{alert_id}")
def get_alert(alert_id: str) -> Dict[str, Any]:
    """Return a single Lacework alert by id."""
    eng = _engine()
    return _handle_engine_call(lambda: eng.get_alert(alert_id))


# ---------------------------------------------------------------------------
# Compliance
# ---------------------------------------------------------------------------


@router.get("/api/v2/Compliance/Reports/AwsLatest")
def aws_compliance_latest(
    accountId: str = Query(..., min_length=1, max_length=64),  # noqa: N803
    format: str = Query(default="json", pattern="^(json|html|pdf)$"),  # noqa: A002
) -> Dict[str, Any]:
    """Latest AWS compliance report for a given account id."""
    eng = _engine()
    return _handle_engine_call(
        lambda: eng.aws_compliance_latest(account_id=accountId, report_format=format)
    )


# ---------------------------------------------------------------------------
# Vulnerabilities
# ---------------------------------------------------------------------------


@router.post("/api/v2/Vulnerabilities/Hosts/search")
def search_host_vulnerabilities(req: VulnSearchRequest) -> Dict[str, Any]:
    """Search host vulnerabilities (Lacework /Hosts/search)."""
    eng = _engine()
    body = req.model_dump(exclude_none=True)
    return _handle_engine_call(lambda: eng.search_host_vulnerabilities(body))


@router.post("/api/v2/Vulnerabilities/Containers/search")
def search_container_vulnerabilities(req: VulnSearchRequest) -> Dict[str, Any]:
    """Search container vulnerabilities (Lacework /Containers/search)."""
    eng = _engine()
    body = req.model_dump(exclude_none=True)
    return _handle_engine_call(lambda: eng.search_container_vulnerabilities(body))


# ---------------------------------------------------------------------------
# Inventory
# ---------------------------------------------------------------------------


@router.get("/api/v2/Inventory")
def list_inventory(
    type: Optional[str] = Query(  # noqa: A002
        default=None,
        description="AwsResources|AzureResources|GcpResources",
        max_length=64,
    ),
    csp: Optional[str] = Query(default=None, max_length=16, description="AWS|AZURE|GCP"),
    pageSize: Optional[int] = Query(default=None, ge=1, le=5000),  # noqa: N803
    token: Optional[str] = Query(default=None, max_length=4096),
    filters: Optional[str] = Query(
        default=None,
        max_length=8192,
        description="JSON-encoded list of filter expressions",
    ),
    returns: Optional[str] = Query(
        default=None,
        max_length=8192,
        description="JSON-encoded list of return field names",
    ),
) -> Dict[str, Any]:
    """List Lacework cloud-resource inventory."""
    eng = _engine()

    parsed_filters: Optional[List[Dict[str, Any]]] = None
    if filters:
        try:
            decoded = json.loads(filters)
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=400, detail=f"invalid filters json: {exc}") from exc
        if not isinstance(decoded, list):
            raise HTTPException(status_code=400, detail="filters must be a JSON list")
        parsed_filters = decoded

    parsed_returns: Optional[List[str]] = None
    if returns:
        try:
            decoded_r = json.loads(returns)
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=400, detail=f"invalid returns json: {exc}") from exc
        if not isinstance(decoded_r, list):
            raise HTTPException(status_code=400, detail="returns must be a JSON list")
        parsed_returns = [str(v) for v in decoded_r]

    return _handle_engine_call(
        lambda: eng.list_inventory(
            inv_type=type,
            csp=csp,
            page_size=pageSize,
            token=token,
            filters=parsed_filters,
            returns=parsed_returns,
        )
    )
