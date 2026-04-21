"""ServiceNow Integration Router — ALDECI.

Provides REST endpoints for managing ServiceNow connections,
CMDB synchronization, incident push, and change request creation.

Endpoints:
    POST   /api/v1/servicenow/connect              — Configure a ServiceNow connection
    GET    /api/v1/servicenow/connections            — List connections
    GET    /api/v1/servicenow/status/{connection_id} — Connection health check
    DELETE /api/v1/servicenow/connections/{id}        — Remove a connection
    POST   /api/v1/servicenow/sync/cmdb             — Trigger CMDB CI sync
    GET    /api/v1/servicenow/sync/cmdb/assets       — List synced CMDB assets
    GET    /api/v1/servicenow/sync/cmdb/stats        — CMDB sync statistics
    POST   /api/v1/servicenow/sync/incidents         — Push ALDECI alerts to ServiceNow
    GET    /api/v1/servicenow/sync/incidents/mappings — List incident mappings
    POST   /api/v1/servicenow/sync/changes           — Create change request
    GET    /api/v1/servicenow/sync/changes            — List change requests
    GET    /api/v1/servicenow/mappings               — Get field mapping config
    PUT    /api/v1/servicenow/mappings               — Update field mappings
    GET    /api/v1/servicenow/sync/jobs              — List sync jobs
    GET    /api/v1/servicenow/sync/stats/{conn_id}   — Sync statistics

Security:
    - All endpoints require API key authentication
    - Multi-tenant via org_id from request
    - Credentials are SHA-256 hashed before storage
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(
    prefix="/api/v1/servicenow",
    tags=["servicenow"],
)

# ---------------------------------------------------------------------------
# Engine singleton
# ---------------------------------------------------------------------------

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from servicenow.servicenow_engine import ServiceNowSyncEngine
        _engine = ServiceNowSyncEngine()
    return _engine


def _get_org_id(request: Request) -> str:
    """Extract org_id from request state (set by auth middleware)."""
    org_id = getattr(request.state, "org_id", None)
    if not org_id:
        org_id = request.headers.get("X-Org-Id", "default")
    return org_id


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------

class ConnectRequest(BaseModel):
    instance_url: str = Field(..., description="ServiceNow instance URL (e.g., https://dev12345.service-now.com)")
    client_id: str = Field(default="", description="OAuth2 client ID")
    client_secret: str = Field(default="", description="OAuth2 client secret")
    username: str = Field(default="", description="Basic auth username (fallback)")
    password: str = Field(default="", description="Basic auth password (fallback)")
    auth_method: str = Field(default="oauth2", description="Auth method: oauth2 or basic")


class CMDBSyncRequest(BaseModel):
    connection_id: str = Field(..., description="Connection ID to sync from")
    ci_classes: List[str] = Field(
        default=["cmdb_ci_server"],
        description="CI class names to pull",
    )
    query: str = Field(default="operational_status=1", description="ServiceNow encoded query filter")
    limit: int = Field(default=100, ge=1, le=1000, description="Max CIs per class")


class IncidentPushRequest(BaseModel):
    connection_id: str = Field(..., description="Connection ID")
    alerts: List[Dict[str, Any]] = Field(..., description="List of ALDECI alerts to push")
    assignment_group: str = Field(default="", description="Default assignment group sys_id")


class ChangeRequestCreate(BaseModel):
    connection_id: str = Field(..., description="Connection ID")
    short_description: str = Field(..., description="Change request title")
    description: str = Field(default="", description="Detailed description")
    change_type: str = Field(default="standard", description="standard | normal | emergency")
    justification: str = Field(default="", description="Business justification")
    risk_level: str = Field(default="medium", description="Risk level")
    aldeci_remediation_id: Optional[str] = Field(default=None, description="Linked remediation ID")


class FieldMappingUpdate(BaseModel):
    connection_id: str
    sync_type: str = Field(default="cmdb")
    mappings: List[Dict[str, str]] = Field(
        ...,
        description="List of {aldeci_field, snow_field, transform}",
    )


# ---------------------------------------------------------------------------
# Connection endpoints
# ---------------------------------------------------------------------------

@router.post("/connect")
async def create_connection(body: ConnectRequest, request: Request):
    """Configure a new ServiceNow instance connection."""
    org_id = _get_org_id(request)
    engine = _get_engine()

    if not body.instance_url.startswith("https://"):
        if not body.instance_url.startswith("http://"):
            raise HTTPException(400, "instance_url must start with https://")

    result = engine.create_connection(
        org_id,
        body.instance_url,
        client_id=body.client_id,
        client_secret=body.client_secret,
        username=body.username,
        auth_method=body.auth_method,
    )
    return result


@router.get("/connections")
async def list_connections(request: Request):
    """List all ServiceNow connections for the organization."""
    org_id = _get_org_id(request)
    return _get_engine().list_connections(org_id)


@router.get("/status/{connection_id}")
async def connection_status(connection_id: str, request: Request):
    """Check ServiceNow connection health.

    Attempts to authenticate and make a test API call.
    Updates connection status in the database.
    """
    org_id = _get_org_id(request)
    engine = _get_engine()
    conn = engine.get_connection(org_id, connection_id)
    if not conn:
        raise HTTPException(404, "Connection not found")

    # Try to instantiate connector and health check
    from servicenow.servicenow_connector import ServiceNowConnector

    try:
        connector = ServiceNowConnector(
            instance_url=conn["instance_url"],
            auth_method=conn["auth_method"],
        )
        result = connector.health_check()
        healthy = result.success
    except Exception as exc:
        _logger.warning("Health check failed for %s: %s", connection_id, exc)
        healthy = False

    status = "active" if healthy else "error"
    engine.update_connection_status(org_id, connection_id, status, health_ok=healthy)

    return {
        "connection_id": connection_id,
        "instance_url": conn["instance_url"],
        "status": status,
        "healthy": healthy,
    }


@router.delete("/connections/{connection_id}")
async def delete_connection(connection_id: str, request: Request):
    """Delete a ServiceNow connection and all associated sync data."""
    org_id = _get_org_id(request)
    deleted = _get_engine().delete_connection(org_id, connection_id)
    if not deleted:
        raise HTTPException(404, "Connection not found")
    return {"deleted": True, "connection_id": connection_id}


# ---------------------------------------------------------------------------
# CMDB sync endpoints
# ---------------------------------------------------------------------------

@router.post("/sync/cmdb")
async def sync_cmdb(body: CMDBSyncRequest, request: Request):
    """Trigger a CMDB CI sync from ServiceNow.

    Pulls Configuration Items for each specified CI class and
    upserts them as ALDECI assets in the sync state database.
    """
    org_id = _get_org_id(request)
    engine = _get_engine()

    conn = engine.get_connection(org_id, body.connection_id)
    if not conn:
        raise HTTPException(404, "Connection not found")

    # Create sync job
    job = engine.create_sync_job(org_id, body.connection_id, "cmdb", "pull")
    engine.update_sync_job(org_id, job["job_id"], status="running")

    # Attempt CMDB pull via connector
    from servicenow.servicenow_connector import ServiceNowConnector

    connector = ServiceNowConnector(
        instance_url=conn["instance_url"],
        auth_method=conn["auth_method"],
    )

    total_synced = 0
    total_failed = 0
    results_by_class: Dict[str, Any] = {}

    for ci_class in body.ci_classes:
        result = connector.pull_cmdb_cis(ci_class, limit=body.limit, query=body.query)
        if not result.success:
            total_failed += 1
            results_by_class[ci_class] = {"status": "failed", "error": result.details.get("reason")}
            continue

        cis = result.data if isinstance(result.data, list) else []
        class_synced = 0
        for ci in cis:
            try:
                engine.upsert_cmdb_asset(
                    org_id,
                    body.connection_id,
                    ci.get("sys_id", ""),
                    snow_ci_class=ci_class,
                    name=ci.get("name", ""),
                    ip_address=ci.get("ip_address"),
                    os=ci.get("os"),
                    environment=ci.get("environment"),
                    category=ci.get("category"),
                    attributes={
                        k: v for k, v in ci.items()
                        if k not in ("sys_id", "name", "ip_address", "os", "environment", "category")
                    },
                )
                class_synced += 1
            except Exception as exc:
                _logger.warning("Failed to upsert CI %s: %s", ci.get("sys_id"), exc)
                total_failed += 1

        total_synced += class_synced
        results_by_class[ci_class] = {"synced": class_synced}

    # Finalize job
    final_status = "completed" if total_failed == 0 else ("completed" if total_synced > 0 else "failed")
    engine.update_sync_job(
        org_id,
        job["job_id"],
        status=final_status,
        items_total=total_synced + total_failed,
        items_synced=total_synced,
        items_failed=total_failed,
    )

    return {
        "job_id": job["job_id"],
        "status": final_status,
        "items_synced": total_synced,
        "items_failed": total_failed,
        "by_class": results_by_class,
    }


@router.get("/sync/cmdb/assets")
async def list_cmdb_assets(
    request: Request,
    connection_id: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
):
    """List synced CMDB assets."""
    org_id = _get_org_id(request)
    return _get_engine().list_cmdb_assets(org_id, connection_id=connection_id, limit=limit)


@router.get("/sync/cmdb/stats")
async def cmdb_stats(connection_id: str, request: Request):
    """Get CMDB sync statistics for a connection."""
    org_id = _get_org_id(request)
    return _get_engine().get_cmdb_stats(org_id, connection_id)


# ---------------------------------------------------------------------------
# Incident sync endpoints
# ---------------------------------------------------------------------------

@router.post("/sync/incidents")
async def push_incidents(body: IncidentPushRequest, request: Request):
    """Push ALDECI alerts as ServiceNow incidents.

    Transforms each alert using severity-to-urgency mapping and
    creates incidents via the ServiceNow Table API. Records the
    sys_id mapping for bidirectional tracking.
    """
    org_id = _get_org_id(request)
    engine = _get_engine()

    conn = engine.get_connection(org_id, body.connection_id)
    if not conn:
        raise HTTPException(404, "Connection not found")

    # Create sync job
    job = engine.create_sync_job(org_id, body.connection_id, "incident", "push")
    engine.update_sync_job(org_id, job["job_id"], status="running")

    from servicenow.servicenow_connector import ServiceNowConnector

    connector = ServiceNowConnector(
        instance_url=conn["instance_url"],
        auth_method=conn["auth_method"],
    )

    created = 0
    failed = 0
    mappings = []

    for alert in body.alerts:
        payload = ServiceNowConnector.alert_to_incident_payload(alert)
        if body.assignment_group:
            payload["assignment_group"] = body.assignment_group

        result = connector.create_incident(**payload)
        if result.success and isinstance(result.data, dict):
            mapping = engine.create_incident_mapping(
                org_id,
                body.connection_id,
                alert.get("alert_id", alert.get("id", "")),
                snow_sys_id=result.data.get("sys_id", ""),
                snow_number=result.data.get("number", ""),
            )
            mappings.append(mapping)
            created += 1
        else:
            failed += 1

    final_status = "completed" if failed == 0 else ("completed" if created > 0 else "failed")
    engine.update_sync_job(
        org_id,
        job["job_id"],
        status=final_status,
        items_total=len(body.alerts),
        items_synced=created,
        items_failed=failed,
    )

    return {
        "job_id": job["job_id"],
        "status": final_status,
        "incidents_created": created,
        "incidents_failed": failed,
        "mappings": mappings,
    }


@router.get("/sync/incidents/mappings")
async def list_incident_mappings(
    request: Request,
    connection_id: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
):
    """List incident mappings (ALDECI alert <-> ServiceNow incident)."""
    org_id = _get_org_id(request)
    return _get_engine().list_incident_mappings(org_id, connection_id=connection_id, limit=limit)


# ---------------------------------------------------------------------------
# Change request endpoints
# ---------------------------------------------------------------------------

@router.post("/sync/changes")
async def create_change_request(body: ChangeRequestCreate, request: Request):
    """Create a ServiceNow change request for a remediation action."""
    org_id = _get_org_id(request)
    engine = _get_engine()

    conn = engine.get_connection(org_id, body.connection_id)
    if not conn:
        raise HTTPException(404, "Connection not found")

    from servicenow.servicenow_connector import ServiceNowConnector

    connector = ServiceNowConnector(
        instance_url=conn["instance_url"],
        auth_method=conn["auth_method"],
    )

    result = connector.create_change_request(
        body.short_description,
        description=body.description,
        change_type=body.change_type,
        risk=body.risk_level,
        justification=body.justification,
    )

    snow_sys_id = ""
    snow_number = ""
    if result.success and isinstance(result.data, dict):
        snow_sys_id = result.data.get("sys_id", "")
        snow_number = result.data.get("number", "")

    change = engine.create_change_request(
        org_id,
        body.connection_id,
        body.short_description,
        change_type=body.change_type,
        justification=body.justification,
        risk_level=body.risk_level,
        aldeci_remediation_id=body.aldeci_remediation_id,
        snow_sys_id=snow_sys_id,
        snow_number=snow_number,
    )

    return {
        "change": change,
        "servicenow_response": result.to_dict() if result.success else {"status": "failed"},
    }


@router.get("/sync/changes")
async def list_change_requests(
    request: Request,
    connection_id: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
):
    """List change requests."""
    org_id = _get_org_id(request)
    return _get_engine().list_change_requests(org_id, connection_id=connection_id, limit=limit)


# ---------------------------------------------------------------------------
# Field mapping endpoints
# ---------------------------------------------------------------------------

@router.get("/mappings")
async def get_field_mappings(
    request: Request,
    connection_id: Optional[str] = Query(None),
    sync_type: Optional[str] = Query(None),
):
    """Get field mapping configuration.

    Returns custom mappings if configured, otherwise returns defaults.
    """
    org_id = _get_org_id(request)
    engine = _get_engine()

    custom = engine.list_field_mappings(
        org_id, connection_id=connection_id, sync_type=sync_type
    )
    if custom:
        return {"source": "custom", "mappings": custom}

    # Return defaults
    defaults = []
    for st in (["cmdb", "incident"] if not sync_type else [sync_type]):
        for m in engine.get_default_field_mappings(st):
            m["sync_type"] = st
            defaults.append(m)

    return {"source": "default", "mappings": defaults}


@router.put("/mappings")
async def update_field_mappings(body: FieldMappingUpdate, request: Request):
    """Update field mappings for a connection."""
    org_id = _get_org_id(request)
    engine = _get_engine()

    results = []
    for m in body.mappings:
        result = engine.set_field_mapping(
            org_id,
            body.connection_id,
            body.sync_type,
            m["aldeci_field"],
            m["snow_field"],
            transform=m.get("transform", "direct"),
        )
        results.append(result)

    return {"updated": len(results), "mappings": results}


# ---------------------------------------------------------------------------
# Sync job & stats endpoints
# ---------------------------------------------------------------------------

@router.get("/sync/jobs")
async def list_sync_jobs(
    request: Request,
    connection_id: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
):
    """List sync jobs for auditing."""
    org_id = _get_org_id(request)
    return _get_engine().list_sync_jobs(org_id, connection_id=connection_id, limit=limit)


@router.get("/sync/stats/{connection_id}")
async def sync_stats(connection_id: str, request: Request):
    """Get overall sync statistics for a connection."""
    org_id = _get_org_id(request)
    return _get_engine().get_sync_stats(org_id, connection_id)
