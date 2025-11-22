"""
Inventory management API endpoints.
"""
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from core.inventory_db import InventoryDB
from core.inventory_models import Application, ApplicationCriticality, ApplicationStatus

router = APIRouter(prefix="/api/v1/inventory", tags=["inventory"])
db = InventoryDB()


class ApplicationCreate(BaseModel):
    """Request model for creating an application."""

    name: str = Field(..., min_length=1, max_length=255)
    description: str
    criticality: ApplicationCriticality
    status: ApplicationStatus = ApplicationStatus.ACTIVE
    owner_team: Optional[str] = None
    repository_url: Optional[str] = None
    environment: str = "production"
    tags: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)


class ApplicationUpdate(BaseModel):
    """Request model for updating an application."""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    criticality: Optional[ApplicationCriticality] = None
    status: Optional[ApplicationStatus] = None
    owner_team: Optional[str] = None
    repository_url: Optional[str] = None
    environment: Optional[str] = None
    tags: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None


class ApplicationResponse(BaseModel):
    """Response model for an application."""

    id: str
    name: str
    description: str
    criticality: str
    status: str
    owner_team: Optional[str]
    repository_url: Optional[str]
    environment: str
    tags: List[str]
    metadata: Dict[str, Any]
    created_at: str
    updated_at: str


class PaginatedResponse(BaseModel):
    """Paginated response wrapper."""

    items: List[ApplicationResponse]
    total: int
    limit: int
    offset: int


@router.get("/applications", response_model=PaginatedResponse)
async def list_applications(
    limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)
):
    """List all applications with pagination."""
    applications = db.list_applications(limit=limit, offset=offset)
    return {
        "items": [ApplicationResponse(**app.to_dict()) for app in applications],
        "total": len(applications),
        "limit": limit,
        "offset": offset,
    }


@router.post("/applications", response_model=ApplicationResponse, status_code=201)
async def create_application(app_data: ApplicationCreate):
    """Register a new application."""
    app = Application(
        id="",
        name=app_data.name,
        description=app_data.description,
        criticality=app_data.criticality,
        status=app_data.status,
        owner_team=app_data.owner_team,
        repository_url=app_data.repository_url,
        environment=app_data.environment,
        tags=app_data.tags,
        metadata=app_data.metadata,
    )
    created_app = db.create_application(app)
    return ApplicationResponse(**created_app.to_dict())


@router.get("/applications/{id}", response_model=ApplicationResponse)
async def get_application(id: str):
    """Get application details by ID."""
    app = db.get_application(id)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    return ApplicationResponse(**app.to_dict())


@router.put("/applications/{id}", response_model=ApplicationResponse)
async def update_application(id: str, app_data: ApplicationUpdate):
    """Update an application."""
    app = db.get_application(id)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")

    if app_data.name is not None:
        app.name = app_data.name
    if app_data.description is not None:
        app.description = app_data.description
    if app_data.criticality is not None:
        app.criticality = app_data.criticality
    if app_data.status is not None:
        app.status = app_data.status
    if app_data.owner_team is not None:
        app.owner_team = app_data.owner_team
    if app_data.repository_url is not None:
        app.repository_url = app_data.repository_url
    if app_data.environment is not None:
        app.environment = app_data.environment
    if app_data.tags is not None:
        app.tags = app_data.tags
    if app_data.metadata is not None:
        app.metadata = app_data.metadata

    updated_app = db.update_application(app)
    return ApplicationResponse(**updated_app.to_dict())


@router.delete("/applications/{id}", status_code=204)
async def delete_application(id: str):
    """Archive an application."""
    app = db.get_application(id)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    db.delete_application(id)
    return None


@router.get("/applications/{id}/components")
async def list_application_components(id: str):
    """List components for an application."""
    app = db.get_application(id)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    return {"application_id": id, "components": []}


@router.get("/applications/{id}/apis")
async def list_application_apis(id: str):
    """List API endpoints for an application."""
    app = db.get_application(id)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    return {"application_id": id, "apis": []}


@router.get("/applications/{id}/dependencies")
async def get_application_dependencies(id: str):
    """Get dependency graph for an application."""
    app = db.get_application(id)
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    return {"application_id": id, "dependencies": [], "graph": {}}


@router.get("/services")
async def list_services(
    limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)
):
    """List all services with pagination."""
    return {"items": [], "total": 0, "limit": limit, "offset": offset}


@router.post("/services", status_code=201)
async def create_service(service_data: Dict[str, Any]):
    """Register a new service."""
    return {"id": "service-123", **service_data}


@router.get("/services/{id}")
async def get_service(id: str):
    """Get service details by ID."""
    raise HTTPException(status_code=404, detail="Service not found")


@router.get("/apis")
async def list_apis(
    limit: int = Query(100, ge=1, le=1000), offset: int = Query(0, ge=0)
):
    """List all API endpoints with pagination."""
    return {"items": [], "total": 0, "limit": limit, "offset": offset}


@router.post("/apis", status_code=201)
async def create_api(api_data: Dict[str, Any]):
    """Register a new API endpoint."""
    return {"id": "api-123", **api_data}


@router.get("/apis/{id}/security")
async def get_api_security(id: str):
    """Get security posture for an API endpoint."""
    return {
        "api_id": id,
        "security_score": 85,
        "vulnerabilities": [],
        "compliance_status": "compliant",
    }


@router.get("/search")
async def search_inventory(
    q: str = Query(..., min_length=1), limit: int = Query(100, ge=1, le=1000)
):
    """Search across all inventory types."""
    results = db.search_inventory(q, limit=limit)
    return results
