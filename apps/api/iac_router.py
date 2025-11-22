"""
IaC scanning API endpoints.
"""
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from core.iac_db import IaCDB
from core.iac_models import IaCFinding, IaCFindingStatus, IaCProvider

router = APIRouter(prefix="/api/v1/iac", tags=["iac"])
db = IaCDB()


class IaCFindingCreate(BaseModel):
    """Request model for creating IaC finding."""

    provider: IaCProvider
    severity: str
    title: str
    description: str
    file_path: str
    line_number: int
    resource_type: str
    resource_name: str
    rule_id: str
    remediation: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class IaCFindingResponse(BaseModel):
    """Response model for IaC finding."""

    id: str
    provider: str
    status: str
    severity: str
    title: str
    description: str
    file_path: str
    line_number: int
    resource_type: str
    resource_name: str
    rule_id: str
    remediation: Optional[str]
    metadata: Dict[str, Any]
    detected_at: str
    resolved_at: Optional[str]


class PaginatedIaCFindingResponse(BaseModel):
    """Paginated IaC finding response."""

    items: List[IaCFindingResponse]
    total: int
    limit: int
    offset: int


@router.get("", response_model=PaginatedIaCFindingResponse)
async def list_iac_findings(
    provider: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """List all IaC findings with optional filtering."""
    findings = db.list_findings(provider=provider, limit=limit, offset=offset)
    return {
        "items": [IaCFindingResponse(**f.to_dict()) for f in findings],
        "total": len(findings),
        "limit": limit,
        "offset": offset,
    }


@router.post("", response_model=IaCFindingResponse, status_code=201)
async def create_iac_finding(finding_data: IaCFindingCreate):
    """Create a new IaC finding."""
    finding = IaCFinding(
        id="",
        provider=finding_data.provider,
        status=IaCFindingStatus.OPEN,
        severity=finding_data.severity,
        title=finding_data.title,
        description=finding_data.description,
        file_path=finding_data.file_path,
        line_number=finding_data.line_number,
        resource_type=finding_data.resource_type,
        resource_name=finding_data.resource_name,
        rule_id=finding_data.rule_id,
        remediation=finding_data.remediation,
        metadata=finding_data.metadata,
    )
    created_finding = db.create_finding(finding)
    return IaCFindingResponse(**created_finding.to_dict())


@router.get("/{id}", response_model=IaCFindingResponse)
async def get_iac_finding(id: str):
    """Get IaC finding by ID."""
    finding = db.get_finding(id)
    if not finding:
        raise HTTPException(status_code=404, detail="IaC finding not found")
    return IaCFindingResponse(**finding.to_dict())


@router.post("/{id}/resolve", response_model=IaCFindingResponse)
async def resolve_iac_finding(id: str):
    """Mark IaC finding as resolved."""
    finding = db.get_finding(id)
    if not finding:
        raise HTTPException(status_code=404, detail="IaC finding not found")

    finding.status = IaCFindingStatus.RESOLVED
    finding.resolved_at = datetime.utcnow()
    updated_finding = db.update_finding(finding)
    return IaCFindingResponse(**updated_finding.to_dict())


@router.post("/scan")
async def scan_iac(provider: IaCProvider, file_path: str):
    """Trigger IaC scan for a file or directory."""
    return {
        "provider": provider.value,
        "file_path": file_path,
        "status": "scanning",
        "message": "IaC scan initiated",
    }
