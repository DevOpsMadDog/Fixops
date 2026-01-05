"""
IaC scanning API endpoints.

Provides enterprise-grade IaC security scanning with checkov and tfsec integration.
"""

import logging
import os
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

from core.iac_db import IaCDB
from core.iac_models import IaCFinding, IaCFindingStatus, IaCProvider
from core.iac_scanner import ScannerType, get_iac_scanner

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/iac", tags=["iac"])
db = IaCDB()

# Server-side configured base path for scanning - NOT user-controllable
SCAN_BASE_PATH = os.getenv("FIXOPS_SCAN_BASE_PATH", "/var/fixops/scans")


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


class IaCScanRequest(BaseModel):
    """Request model for IaC scan."""

    file_path: str = Field(
        ...,
        description="Relative path to file or directory to scan (under configured base path)",
    )
    provider: Optional[IaCProvider] = Field(
        None, description="IaC provider type (auto-detected if not specified)"
    )
    scanner: Optional[str] = Field(
        None,
        description="Scanner to use: 'checkov' or 'tfsec' (auto-selected if not specified)",
    )


class IaCScanResponse(BaseModel):
    """Response model for IaC scan."""

    scan_id: str
    status: str
    scanner: str
    provider: str
    target_path: str
    findings_count: int
    findings: List[IaCFindingResponse]
    started_at: Optional[str]
    completed_at: Optional[str]
    duration_seconds: Optional[float]
    error_message: Optional[str]
    metadata: Dict[str, Any]


class ScannerStatusResponse(BaseModel):
    """Response model for scanner status."""

    checkov_available: bool
    tfsec_available: bool
    available_scanners: List[str]


@router.get("/scanners/status", response_model=ScannerStatusResponse)
async def get_scanner_status():
    """Get status of available IaC scanners."""
    scanner = get_iac_scanner()
    available = scanner.get_available_scanners()
    return {
        "checkov_available": scanner._is_checkov_available(),
        "tfsec_available": scanner._is_tfsec_available(),
        "available_scanners": [s.value for s in available],
    }


def _validate_scan_path(file_path: str) -> str:
    """
    Validate and resolve the scan path securely.

    Security measures:
    1. Reject null bytes in path
    2. Normalize path to prevent traversal via os.path.normpath
    3. Reject absolute paths from user input
    4. Reject path traversal attempts
    5. Resolve path under server-controlled base directory using os.path.realpath
    6. Verify resolved path stays within base directory using os.path.commonpath
    """
    # Reject null bytes in path
    if "\x00" in file_path:
        raise HTTPException(
            status_code=400,
            detail="Invalid path: contains null bytes.",
        )

    # Normalize the path to collapse .. and . components
    normalized = os.path.normpath(file_path)

    # Reject absolute paths - user must provide relative paths only
    if os.path.isabs(normalized):
        raise HTTPException(
            status_code=400,
            detail="Absolute paths are not allowed. Provide a relative path.",
        )

    # Reject obvious path traversal attempts
    if normalized.startswith("..") or "/../" in normalized or normalized == "..":
        raise HTTPException(
            status_code=400,
            detail="Path traversal is not allowed.",
        )

    # Get server-controlled base path using realpath (CodeQL-recognized sanitizer)
    base = os.path.realpath(SCAN_BASE_PATH)

    # Join with base path and resolve using realpath
    candidate = os.path.realpath(os.path.join(base, normalized))

    # Verify the resolved path stays within the base directory using commonpath
    # This is the containment check that CodeQL recognizes
    if os.path.commonpath([base, candidate]) != base:
        raise HTTPException(
            status_code=400,
            detail="Path traversal detected: path escapes base directory.",
        )

    return candidate


@router.post("/scan", response_model=IaCScanResponse)
async def scan_iac(request: IaCScanRequest):
    """
    Trigger IaC security scan for a file or directory.

    Uses checkov or tfsec to scan Infrastructure-as-Code files for security
    misconfigurations. Supports Terraform, CloudFormation, Kubernetes, Ansible,
    and Helm.

    The scanner is auto-selected based on availability and provider:
    - tfsec is preferred for Terraform files
    - checkov is used for all other providers

    Findings are automatically persisted to the database.

    Security: Only relative paths under the configured FIXOPS_SCAN_BASE_PATH
    are allowed. Absolute paths and path traversal attempts are rejected.
    """
    # Validate and resolve the path securely using server-side base path
    validated_path = _validate_scan_path(request.file_path)

    scanner = get_iac_scanner()

    scanner_type = None
    if request.scanner:
        try:
            scanner_type = ScannerType(request.scanner.lower())
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid scanner: {request.scanner}. Use 'checkov' or 'tfsec'.",
            )

    try:
        # Pass the validated path directly - no user-controlled base_path
        result = await scanner.scan(
            target_path=validated_path,
            provider=request.provider,
            scanner=scanner_type,
        )
    except Exception as e:
        logger.exception(f"IaC scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

    for finding in result.findings:
        try:
            db.create_finding(finding)
        except Exception as e:
            logger.warning(f"Failed to persist finding: {e}")

    return IaCScanResponse(
        scan_id=result.scan_id,
        status=result.status.value,
        scanner=result.scanner.value,
        provider=result.provider.value,
        target_path=result.target_path,
        findings_count=len(result.findings),
        findings=[IaCFindingResponse(**f.to_dict()) for f in result.findings],
        started_at=result.started_at.isoformat() if result.started_at else None,
        completed_at=result.completed_at.isoformat() if result.completed_at else None,
        duration_seconds=result.duration_seconds,
        error_message=result.error_message,
        metadata=result.metadata,
    )


class IaCScanContentRequest(BaseModel):
    """Request model for scanning IaC content."""

    content: str = Field(..., description="IaC file content to scan")
    filename: str = Field(..., description="Filename (used for provider detection)")
    provider: Optional[IaCProvider] = Field(
        None, description="IaC provider type (auto-detected if not specified)"
    )
    scanner: Optional[str] = Field(
        None,
        description="Scanner to use: 'checkov' or 'tfsec' (auto-selected if not specified)",
    )


@router.post("/scan/content", response_model=IaCScanResponse)
async def scan_iac_content(request: IaCScanContentRequest):
    """
    Scan IaC content provided as a string.

    Useful for scanning code snippets or content from CI/CD pipelines
    without requiring file system access.
    """
    scanner = get_iac_scanner()

    scanner_type = None
    if request.scanner:
        try:
            scanner_type = ScannerType(request.scanner.lower())
        except ValueError:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid scanner: {request.scanner}. Use 'checkov' or 'tfsec'.",
            )

    try:
        result = await scanner.scan_content(
            content=request.content,
            filename=request.filename,
            provider=request.provider,
            scanner=scanner_type,
        )
    except Exception as e:
        logger.exception(f"IaC content scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")

    for finding in result.findings:
        try:
            db.create_finding(finding)
        except Exception as e:
            logger.warning(f"Failed to persist finding: {e}")

    return IaCScanResponse(
        scan_id=result.scan_id,
        status=result.status.value,
        scanner=result.scanner.value,
        provider=result.provider.value,
        target_path=result.target_path,
        findings_count=len(result.findings),
        findings=[IaCFindingResponse(**f.to_dict()) for f in result.findings],
        started_at=result.started_at.isoformat() if result.started_at else None,
        completed_at=result.completed_at.isoformat() if result.completed_at else None,
        duration_seconds=result.duration_seconds,
        error_message=result.error_message,
        metadata=result.metadata,
    )
