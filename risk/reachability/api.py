"""Enterprise API endpoints for reachability analysis."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from pydantic import BaseModel, Field

from risk.reachability.analyzer import ReachabilityAnalyzer
from risk.reachability.git_integration import GitRepository
from risk.reachability.job_queue import JobQueue, ReachabilityJob
from risk.reachability.storage import ReachabilityStorage

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/reachability", tags=["reachability"])


# Request/Response Models
class GitRepositoryRequest(BaseModel):
    """Git repository configuration."""

    url: str = Field(..., description="Repository URL")
    branch: str = Field(default="main", description="Branch to analyze")
    commit: Optional[str] = Field(None, description="Specific commit to analyze")
    auth_token: Optional[str] = Field(None, description="Authentication token")
    auth_username: Optional[str] = Field(
        None, description="Username for authentication"
    )
    auth_password: Optional[str] = Field(
        None, description="Password for authentication"
    )


class VulnerabilityRequest(BaseModel):
    """Vulnerability details for analysis."""

    cve_id: str = Field(..., description="CVE identifier")
    component_name: str = Field(..., description="Component name")
    component_version: str = Field(..., description="Component version")
    cwe_ids: List[str] = Field(default_factory=list, description="CWE identifiers")
    description: Optional[str] = Field(None, description="Vulnerability description")
    severity: str = Field(default="medium", description="Severity level")


class ReachabilityAnalysisRequest(BaseModel):
    """Request for reachability analysis."""

    repository: GitRepositoryRequest = Field(
        ..., description="Repository configuration"
    )
    vulnerability: VulnerabilityRequest = Field(
        ..., description="Vulnerability details"
    )
    force_refresh: bool = Field(default=False, description="Force repository refresh")
    async_analysis: bool = Field(
        default=True, description="Run analysis asynchronously"
    )


class ReachabilityAnalysisResponse(BaseModel):
    """Response from reachability analysis."""

    job_id: Optional[str] = Field(None, description="Job ID for async analysis")
    status: str = Field(..., description="Analysis status")
    result: Optional[Dict[str, Any]] = Field(None, description="Analysis result")
    message: Optional[str] = Field(None, description="Status message")
    created_at: str = Field(..., description="Analysis creation timestamp")


class JobStatusResponse(BaseModel):
    """Job status response."""

    job_id: str
    status: str
    progress: float = Field(0.0, ge=0.0, le=100.0)
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    created_at: str
    started_at: Optional[str] = None
    completed_at: Optional[str] = None
    estimated_completion: Optional[str] = None


class BulkAnalysisRequest(BaseModel):
    """Request for bulk analysis."""

    repository: GitRepositoryRequest
    vulnerabilities: List[VulnerabilityRequest]
    async_analysis: bool = Field(default=True)


class BulkAnalysisResponse(BaseModel):
    """Response from bulk analysis."""

    job_ids: List[str]
    total_vulnerabilities: int
    created_at: str


# Dependency Injection
def get_analyzer() -> ReachabilityAnalyzer:
    """Get reachability analyzer instance."""
    from core.configuration import load_overlay

    overlay = load_overlay()
    config = overlay.raw_config.get("reachability_analysis", {})
    return ReachabilityAnalyzer(config=config)


def get_storage() -> ReachabilityStorage:
    """Get storage instance."""
    from core.configuration import load_overlay

    overlay = load_overlay()
    reachability_config = overlay.raw_config.get("reachability_analysis", {})
    config = (
        reachability_config.get("storage", {})
        if isinstance(reachability_config, dict)
        else {}
    )
    return ReachabilityStorage(config=config)


def get_job_queue() -> JobQueue:
    """Get job queue instance."""
    from core.configuration import load_overlay

    overlay = load_overlay()
    reachability_config = overlay.raw_config.get("reachability_analysis", {})
    config = (
        reachability_config.get("job_queue", {})
        if isinstance(reachability_config, dict)
        else {}
    )
    return JobQueue(config=config)


# API Endpoints
@router.post("/analyze", response_model=ReachabilityAnalysisResponse)
async def analyze_reachability(
    request: ReachabilityAnalysisRequest,
    background_tasks: BackgroundTasks,
    analyzer: ReachabilityAnalyzer = Depends(get_analyzer),
    storage: ReachabilityStorage = Depends(get_storage),
    job_queue: JobQueue = Depends(get_job_queue),
):
    """Analyze vulnerability reachability in a Git repository.

    This endpoint performs comprehensive reachability analysis combining
    design-time and runtime analysis to determine if a vulnerability is
    actually exploitable in the codebase.
    """
    try:
        # Check cache first
        cached_result = storage.get_cached_result(
            cve_id=request.vulnerability.cve_id,
            component_name=request.vulnerability.component_name,
            component_version=request.vulnerability.component_version,
            repo_url=request.repository.url,
            repo_commit=request.repository.commit,
        )

        if cached_result and not request.force_refresh:
            logger.info(f"Returning cached result for {request.vulnerability.cve_id}")
            return ReachabilityAnalysisResponse(
                job_id=None,
                status="completed",
                result=cached_result.to_dict(),
                message="Result retrieved from cache",
                created_at=datetime.now(timezone.utc).isoformat(),
            )

        # Prepare repository
        git_repo = GitRepository(
            url=request.repository.url,
            branch=request.repository.branch,
            commit=request.repository.commit,
            auth_token=request.repository.auth_token,
            auth_username=request.repository.auth_username,
            auth_password=request.repository.auth_password,
        )

        # Prepare vulnerability details
        vuln_details = {
            "cwe_ids": request.vulnerability.cwe_ids,
            "description": request.vulnerability.description,
            "severity": request.vulnerability.severity,
        }

        if request.async_analysis:
            # Queue async job
            job = ReachabilityJob(
                repository=git_repo,
                cve_id=request.vulnerability.cve_id,
                component_name=request.vulnerability.component_name,
                component_version=request.vulnerability.component_version,
                vulnerability_details=vuln_details,
                force_refresh=request.force_refresh,
            )

            job_id = job_queue.enqueue(job)

            logger.info(f"Queued reachability analysis job: {job_id}")

            return ReachabilityAnalysisResponse(
                job_id=job_id,
                status="queued",
                result=None,
                message=f"Analysis queued with job ID: {job_id}",
                created_at=datetime.now(timezone.utc).isoformat(),
            )
        else:
            # Synchronous analysis
            logger.info(
                f"Starting synchronous analysis for {request.vulnerability.cve_id}"
            )

            result = analyzer.analyze_vulnerability_from_repo(
                repository=git_repo,
                cve_id=request.vulnerability.cve_id,
                component_name=request.vulnerability.component_name,
                component_version=request.vulnerability.component_version,
                vulnerability_details=vuln_details,
                force_refresh=request.force_refresh,
            )

            # Cache result
            storage.save_result(result, git_repo.url, git_repo.commit)

            return ReachabilityAnalysisResponse(
                job_id=None,
                status="completed",
                result=result.to_dict(),
                message="Analysis completed successfully",
                created_at=datetime.now(timezone.utc).isoformat(),
            )

    except ValueError as e:
        logger.exception("Invalid request parameters")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid request parameters: {str(e)}",
        )
    except RuntimeError as e:
        # Handle git clone failures gracefully - this is an operational issue, not a server bug
        error_msg = str(e)
        if "Git clone failed" in error_msg or "clone" in error_msg.lower():
            # Log full error server-side but sanitize for client response
            logger.warning(f"Repository access failed: {error_msg}")
            # Sanitize error message to prevent information disclosure
            # Remove potential sensitive info like paths, credentials, hostnames
            sanitized_msg = "Repository clone operation failed"
            if "not found" in error_msg.lower():
                sanitized_msg = "Repository or branch not found"
            elif (
                "authentication" in error_msg.lower()
                or "permission" in error_msg.lower()
            ):
                sanitized_msg = "Authentication or permission error"
            elif "timeout" in error_msg.lower():
                sanitized_msg = "Connection timeout"
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail={
                    "error": "repository_unreachable",
                    "message": "Unable to access the specified repository. Please verify the URL, branch, and credentials.",
                    "details": sanitized_msg,
                    "remediation": [
                        "Verify the repository URL is correct and accessible",
                        "Check if authentication credentials are required",
                        "Ensure the specified branch exists",
                        "For private repositories, provide auth_token or auth_username/auth_password",
                    ],
                },
            )
        logger.exception("Reachability analysis failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Analysis failed",
        )
    except Exception:
        logger.exception("Reachability analysis failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Analysis failed",
        )


@router.post("/analyze/bulk", response_model=BulkAnalysisResponse)
async def analyze_bulk(
    request: BulkAnalysisRequest,
    analyzer: ReachabilityAnalyzer = Depends(get_analyzer),
    job_queue: JobQueue = Depends(get_job_queue),
):
    """Analyze multiple vulnerabilities in bulk.

    This endpoint queues multiple reachability analyses for efficient
    batch processing.
    """
    try:
        git_repo = GitRepository(
            url=request.repository.url,
            branch=request.repository.branch,
            commit=request.repository.commit,
            auth_token=request.repository.auth_token,
            auth_username=request.repository.auth_username,
            auth_password=request.repository.auth_password,
        )

        job_ids = []

        for vuln in request.vulnerabilities:
            vuln_details = {
                "cwe_ids": vuln.cwe_ids,
                "description": vuln.description,
                "severity": vuln.severity,
            }

            job = ReachabilityJob(
                repository=git_repo,
                cve_id=vuln.cve_id,
                component_name=vuln.component_name,
                component_version=vuln.component_version,
                vulnerability_details=vuln_details,
            )

            job_id = job_queue.enqueue(job)
            job_ids.append(job_id)

        logger.info(f"Queued {len(job_ids)} bulk analysis jobs")

        return BulkAnalysisResponse(
            job_ids=job_ids,
            total_vulnerabilities=len(request.vulnerabilities),
            created_at=datetime.now(timezone.utc).isoformat(),
        )

    except Exception:
        logger.exception("Bulk analysis failed")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Bulk analysis failed",
        )


@router.get("/job/{job_id}", response_model=JobStatusResponse)
async def get_job_status(
    job_id: str,
    job_queue: JobQueue = Depends(get_job_queue),
):
    """Get status of an analysis job."""
    try:
        job_status = job_queue.get_status(job_id)

        if not job_status:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Job {job_id} not found",
            )

        return JobStatusResponse(**job_status)

    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to get job status")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get job status",
        )


@router.get("/results/{cve_id}")
async def get_result(
    cve_id: str,
    component_name: str,
    component_version: str,
    repo_url: str,
    repo_commit: Optional[str] = None,
    storage: ReachabilityStorage = Depends(get_storage),
):
    """Get cached analysis result."""
    try:
        result = storage.get_cached_result(
            cve_id=cve_id,
            component_name=component_name,
            component_version=component_version,
            repo_url=repo_url,
            repo_commit=repo_commit,
        )

        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Result not found",
            )

        return result.to_dict()

    except HTTPException:
        raise
    except Exception:
        logger.exception("Failed to get result")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get result",
        )


@router.delete("/results/{cve_id}")
async def delete_result(
    cve_id: str,
    component_name: str,
    component_version: str,
    repo_url: str,
    repo_commit: Optional[str] = None,
    storage: ReachabilityStorage = Depends(get_storage),
):
    """Delete cached analysis result."""
    try:
        storage.delete_result(
            cve_id=cve_id,
            component_name=component_name,
            component_version=component_version,
            repo_url=repo_url,
            repo_commit=repo_commit,
        )

        return {"message": "Result deleted successfully"}

    except Exception:
        logger.exception("Failed to delete result")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete result",
        )


@router.get("/health")
async def health_check(
    analyzer: ReachabilityAnalyzer = Depends(get_analyzer),
    storage: ReachabilityStorage = Depends(get_storage),
    job_queue: JobQueue = Depends(get_job_queue),
):
    """Health check endpoint."""
    try:
        # Check components
        health_status = {
            "status": "healthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "components": {
                "analyzer": "ok",
                "storage": storage.health_check(),
                "job_queue": job_queue.health_check(),
            },
        }

        return health_status

    except Exception:
        logger.exception("Health check failed")
        return {
            "status": "unhealthy",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": "Health check failed",
        }


@router.get("/metrics")
async def get_metrics(
    storage: ReachabilityStorage = Depends(get_storage),
    job_queue: JobQueue = Depends(get_job_queue),
):
    """Get analysis metrics."""
    try:
        metrics = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "storage": storage.get_metrics(),
            "job_queue": job_queue.get_metrics(),
        }

        return metrics

    except Exception:
        logger.exception("Failed to get metrics")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to get metrics",
        )
