"""ALDECI Container Security Connector Router — REAL OSS scan endpoints.

Backed by ``connectors.container_security_connector.ContainerSecurityConnector``
which wraps Trivy + Grype + Dockle + (optional) kube-bench.

Endpoints:
    GET  /api/v1/connectors/container-security/health     — liveness
    GET  /api/v1/connectors/container-security/status     — alias of health
    GET  /api/v1/connectors/container-security/tools      — which OSS tools are installed
    GET  /api/v1/connectors/container-security/tenants    — discoverable tenant repos
    POST /api/v1/connectors/container-security/scan       — scan one tenant or all
    GET  /api/v1/connectors/container-security/history    — recent scans for org

Security:
    Mounted by app.py with ``Depends(_verify_api_key)``; org isolation via
    ``get_org_id``. Tenant id is path-traversal-checked inside the connector.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.dependencies import get_org_id
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field, field_validator

try:
    from connectors.container_security_connector import (
        ContainerSecurityConnector,
        get_container_security_connector,
        get_scan_history,
    )
    _CONNECTOR_AVAILABLE = True
    _IMPORT_ERROR: Optional[str] = None
except Exception as exc:  # pragma: no cover — import-time only
    _CONNECTOR_AVAILABLE = False
    _IMPORT_ERROR = str(exc)
    ContainerSecurityConnector = None  # type: ignore
    get_container_security_connector = None  # type: ignore
    get_scan_history = None  # type: ignore


logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/connectors/container-security",
    tags=["Container Security Connector"],
)


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------

class ScanRequest(BaseModel):
    tenant: Optional[str] = Field(
        None,
        description="Tenant id (directory name under tenants_root). Omit to scan all.",
        max_length=128,
    )
    tenants_root: Optional[str] = Field(
        None,
        description="Override default tenants root (defaults to /tmp/aspm-repos).",
        max_length=2048,
    )
    image_prefix: Optional[str] = Field(
        None,
        description="Image tag prefix, default 'fixops-test'.",
        max_length=128,
    )
    run_kubebench: bool = Field(
        False,
        description="Also run kube-bench against the currently-active cluster.",
    )

    @field_validator("tenant")
    @classmethod
    def _no_traversal(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        v = v.strip()
        if "/" in v or "\\" in v or ".." in v or "\x00" in v:
            raise ValueError("tenant must be a plain identifier (no slashes or '..')")
        return v


class ScanResponse(BaseModel):
    org_id: str
    requested: str
    tools_present: Dict[str, bool]
    results: List[Dict[str, Any]]


class ToolStatusResponse(BaseModel):
    tools: Dict[str, bool]
    note: str


# ---------------------------------------------------------------------------
# Health / status (BOTH for the demo readiness gate)
# ---------------------------------------------------------------------------

def _health_payload() -> Dict[str, Any]:
    return {
        "router": "container-security-connector",
        "ok": _CONNECTOR_AVAILABLE,
        "import_error": _IMPORT_ERROR,
    }


@router.get("/health")
def health() -> Dict[str, Any]:
    return _health_payload()


@router.get("/status")
def status() -> Dict[str, Any]:
    return _health_payload()


# ---------------------------------------------------------------------------
# Tooling introspection
# ---------------------------------------------------------------------------

@router.get("/tools", response_model=ToolStatusResponse)
def tools() -> ToolStatusResponse:
    if not _CONNECTOR_AVAILABLE:
        raise HTTPException(status_code=503,
                            detail=f"connector unavailable: {_IMPORT_ERROR}")
    conn = get_container_security_connector()
    return ToolStatusResponse(
        tools=conn.tool_status(),
        note="Required: docker, trivy, grype, dockle. Optional: kube-bench.",
    )


@router.get("/tenants")
def tenants(tenants_root: Optional[str] = None) -> Dict[str, Any]:
    if not _CONNECTOR_AVAILABLE:
        raise HTTPException(status_code=503,
                            detail=f"connector unavailable: {_IMPORT_ERROR}")
    conn = get_container_security_connector(tenants_root=tenants_root)
    return {
        "tenants_root": str(conn.tenants_root),
        "tenants": conn.list_tenants(),
    }


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

@router.post("/scan", response_model=ScanResponse)
def scan(
    payload: ScanRequest,
    org_id: str = Depends(get_org_id),
) -> ScanResponse:
    if not _CONNECTOR_AVAILABLE:
        raise HTTPException(status_code=503,
                            detail=f"connector unavailable: {_IMPORT_ERROR}")
    conn = get_container_security_connector(
        tenants_root=payload.tenants_root,
        image_prefix=payload.image_prefix,
        run_kubebench=payload.run_kubebench,
    )

    if payload.tenant:
        try:
            result = conn.scan_tenant(payload.tenant, org_id=org_id)
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        results = [result.to_dict()]
        requested = payload.tenant
    else:
        scan_results = conn.scan_all(org_id=org_id)
        results = [r.to_dict() for r in scan_results]
        requested = "all"

    return ScanResponse(
        org_id=org_id,
        requested=requested,
        tools_present=conn.tool_status(),
        results=results,
    )


# ---------------------------------------------------------------------------
# History
# ---------------------------------------------------------------------------

@router.get("/history")
def history(
    org_id: str = Depends(get_org_id),
    limit: int = 50,
) -> Dict[str, Any]:
    if not _CONNECTOR_AVAILABLE:
        raise HTTPException(status_code=503,
                            detail=f"connector unavailable: {_IMPORT_ERROR}")
    return {
        "org_id": org_id,
        "limit": limit,
        "entries": get_scan_history(org_id=org_id, limit=limit),
    }
