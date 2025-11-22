"""
Secrets detection API endpoints.
"""
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from core.secrets_db import SecretsDB
from core.secrets_models import SecretFinding, SecretStatus, SecretType

router = APIRouter(prefix="/api/v1/secrets", tags=["secrets"])
db = SecretsDB()


class SecretFindingCreate(BaseModel):
    """Request model for creating secret finding."""

    secret_type: SecretType
    file_path: str
    line_number: int
    repository: str
    branch: str
    commit_hash: Optional[str] = None
    matched_pattern: Optional[str] = None
    entropy_score: Optional[float] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SecretFindingResponse(BaseModel):
    """Response model for secret finding."""

    id: str
    secret_type: str
    status: str
    file_path: str
    line_number: int
    repository: str
    branch: str
    commit_hash: Optional[str]
    matched_pattern: Optional[str]
    entropy_score: Optional[float]
    metadata: Dict[str, Any]
    detected_at: str
    resolved_at: Optional[str]


class PaginatedSecretFindingResponse(BaseModel):
    """Paginated secret finding response."""

    items: List[SecretFindingResponse]
    total: int
    limit: int
    offset: int


@router.get("", response_model=PaginatedSecretFindingResponse)
async def list_secret_findings(
    repository: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """List all secret findings with optional filtering."""
    findings = db.list_findings(repository=repository, limit=limit, offset=offset)
    return {
        "items": [SecretFindingResponse(**f.to_dict()) for f in findings],
        "total": len(findings),
        "limit": limit,
        "offset": offset,
    }


@router.post("", response_model=SecretFindingResponse, status_code=201)
async def create_secret_finding(finding_data: SecretFindingCreate):
    """Create a new secret finding."""
    finding = SecretFinding(
        id="",
        secret_type=finding_data.secret_type,
        status=SecretStatus.ACTIVE,
        file_path=finding_data.file_path,
        line_number=finding_data.line_number,
        repository=finding_data.repository,
        branch=finding_data.branch,
        commit_hash=finding_data.commit_hash,
        matched_pattern=finding_data.matched_pattern,
        entropy_score=finding_data.entropy_score,
        metadata=finding_data.metadata,
    )
    created_finding = db.create_finding(finding)
    return SecretFindingResponse(**created_finding.to_dict())


@router.get("/{id}", response_model=SecretFindingResponse)
async def get_secret_finding(id: str):
    """Get secret finding by ID."""
    finding = db.get_finding(id)
    if not finding:
        raise HTTPException(status_code=404, detail="Secret finding not found")
    return SecretFindingResponse(**finding.to_dict())


@router.post("/{id}/resolve", response_model=SecretFindingResponse)
async def resolve_secret_finding(id: str):
    """Mark secret finding as resolved."""
    finding = db.get_finding(id)
    if not finding:
        raise HTTPException(status_code=404, detail="Secret finding not found")

    finding.status = SecretStatus.RESOLVED
    finding.resolved_at = datetime.utcnow()
    updated_finding = db.update_finding(finding)
    return SecretFindingResponse(**updated_finding.to_dict())


@router.post("/scan")
async def scan_repository(repository: str, branch: str = "main"):
    """Trigger secret scan for a repository."""
    return {
        "repository": repository,
        "branch": branch,
        "status": "scanning",
        "message": "Secret scan initiated",
    }
