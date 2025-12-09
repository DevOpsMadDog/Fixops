"""Enhanced API router for advanced Pentagi pen testing integration."""
import logging
from typing import Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from pydantic import BaseModel, Field

from core.pentagi_db import PentagiDB
from core.pentagi_models import (
    ExploitabilityLevel,
    PenTestConfig,
    PenTestPriority,
    PenTestRequest,
    PenTestResult,
    PenTestStatus,
)
from integrations.pentagi_service import AdvancedPentagiService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/pentagi", tags=["pentagi"])
db = PentagiDB()

# Global service instance (should be initialized from config)
_pentagi_service: Optional[AdvancedPentagiService] = None


def get_pentagi_service() -> Optional[AdvancedPentagiService]:
    """Get or create Pentagi service instance."""
    global _pentagi_service
    if _pentagi_service is None:
        # Get config from database
        configs = db.list_configs(limit=1)
        if configs and configs[0].enabled:
            config = configs[0]
            try:
                _pentagi_service = AdvancedPentagiService(
                    pentagi_url=config.pentagi_url,
                    api_key=config.api_key,
                    db=db,
                )
            except Exception as e:
                logger.error(f"Failed to initialize Pentagi service: {e}")
                return None
        else:
            return None
    return _pentagi_service


class CreatePenTestRequestModel(BaseModel):
    """Model for creating pen test request."""

    finding_id: str
    target_url: str
    vulnerability_type: str
    test_case: str
    priority: str = "medium"
    auto_verify: bool = True


class VerifyVulnerabilityModel(BaseModel):
    """Model for vulnerability verification."""

    finding_id: str
    target_url: str
    vulnerability_type: str
    evidence: str


class ContinuousMonitoringModel(BaseModel):
    """Model for continuous monitoring setup."""

    targets: List[str]
    interval_minutes: int = 60


class ComprehensiveScanModel(BaseModel):
    """Model for comprehensive scan."""

    target: str
    scan_types: Optional[List[str]] = None


class UpdatePenTestRequestModel(BaseModel):
    """Model for updating pen test request."""

    status: Optional[str] = None
    pentagi_job_id: Optional[str] = None


class CreatePenTestResultModel(BaseModel):
    """Model for creating pen test result."""

    request_id: str
    finding_id: str
    exploitability: str
    exploit_successful: bool
    evidence: str
    steps_taken: List[str] = Field(default_factory=list)
    artifacts: List[str] = Field(default_factory=list)
    confidence_score: float = 0.0
    execution_time_seconds: float = 0.0


class CreatePenTestConfigModel(BaseModel):
    """Model for creating Pentagi configuration."""

    name: str
    pentagi_url: str
    api_key: Optional[str] = None
    enabled: bool = True
    max_concurrent_tests: int = 5
    timeout_seconds: int = 300
    auto_trigger: bool = False
    target_environments: List[str] = Field(default_factory=list)


class UpdatePenTestConfigModel(BaseModel):
    """Model for updating Pentagi configuration."""

    pentagi_url: Optional[str] = None
    api_key: Optional[str] = None
    enabled: Optional[bool] = None
    max_concurrent_tests: Optional[int] = None
    timeout_seconds: Optional[int] = None
    auto_trigger: Optional[bool] = None
    target_environments: Optional[List[str]] = None


# Existing endpoints (kept for backward compatibility)
@router.get("/requests")
def list_pen_test_requests(
    finding_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """List pen test requests."""
    status_enum = PenTestStatus(status) if status else None
    requests = db.list_requests(
        finding_id=finding_id, status=status_enum, limit=limit, offset=offset
    )
    return {"items": [r.to_dict() for r in requests], "total": len(requests)}


@router.post("/requests", status_code=201)
async def create_pen_test_request(
    data: CreatePenTestRequestModel,
    background_tasks: BackgroundTasks,
):
    """Create a new pen test request with automated testing."""
    try:
        service = get_pentagi_service()
        if not service:
            # Fallback to basic request creation if service not available
            request = PenTestRequest(
                id="",
                finding_id=data.finding_id,
                target_url=data.target_url,
                vulnerability_type=data.vulnerability_type,
                test_case=data.test_case,
                priority=PenTestPriority(data.priority),
            )
            created = db.create_request(request)
            return created.to_dict()

        priority = PenTestPriority(data.priority)

        request = await service.trigger_pen_test_from_finding(
            finding_id=data.finding_id,
            target_url=data.target_url,
            vulnerability_type=data.vulnerability_type,
            test_case=data.test_case,
            priority=priority,
            auto_verify=data.auto_verify,
        )

        return request.to_dict()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to create pen test: {str(e)}"
        )


@router.get("/requests/{request_id}")
def get_pen_test_request(request_id: str):
    """Get a pen test request by ID."""
    request = db.get_request(request_id)
    if not request:
        raise HTTPException(status_code=404, detail="Pen test request not found")
    return request.to_dict()


@router.put("/requests/{request_id}")
def update_pen_test_request(request_id: str, data: UpdatePenTestRequestModel):
    """Update a pen test request."""
    request = db.get_request(request_id)
    if not request:
        raise HTTPException(status_code=404, detail="Pen test request not found")

    if data.status:
        request.status = PenTestStatus(data.status)
    if data.pentagi_job_id:
        request.pentagi_job_id = data.pentagi_job_id

    updated = db.update_request(request)
    return updated.to_dict()


@router.post("/requests/{request_id}/start")
def start_pen_test(request_id: str):
    """Start a pen test."""
    request = db.get_request(request_id)
    if not request:
        raise HTTPException(status_code=404, detail="Pen test request not found")

    request.status = PenTestStatus.RUNNING
    from datetime import datetime

    request.started_at = datetime.utcnow()
    updated = db.update_request(request)

    return {"status": "started", "request": updated.to_dict()}


@router.post("/requests/{request_id}/cancel")
def cancel_pen_test(request_id: str):
    """Cancel a pen test."""
    request = db.get_request(request_id)
    if not request:
        raise HTTPException(status_code=404, detail="Pen test request not found")

    request.status = PenTestStatus.CANCELLED
    from datetime import datetime

    request.completed_at = datetime.utcnow()
    updated = db.update_request(request)

    return {"status": "cancelled", "request": updated.to_dict()}


@router.get("/results")
def list_pen_test_results(
    finding_id: Optional[str] = Query(None),
    exploitability: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """List pen test results."""
    exploitability_enum = (
        ExploitabilityLevel(exploitability) if exploitability else None
    )
    results = db.list_results(
        finding_id=finding_id,
        exploitability=exploitability_enum,
        limit=limit,
        offset=offset,
    )
    return {"items": [r.to_dict() for r in results], "total": len(results)}


@router.post("/results", status_code=201)
def create_pen_test_result(data: CreatePenTestResultModel):
    """Create a new pen test result."""
    result = PenTestResult(
        id="",
        request_id=data.request_id,
        finding_id=data.finding_id,
        exploitability=ExploitabilityLevel(data.exploitability),
        exploit_successful=data.exploit_successful,
        evidence=data.evidence,
        steps_taken=data.steps_taken,
        artifacts=data.artifacts,
        confidence_score=data.confidence_score,
        execution_time_seconds=data.execution_time_seconds,
    )
    created = db.create_result(result)

    request = db.get_request(data.request_id)
    if request:
        request.status = PenTestStatus.COMPLETED
        from datetime import datetime

        request.completed_at = datetime.utcnow()
        db.update_request(request)

    return created.to_dict()


@router.get("/results/by-request/{request_id}")
def get_pen_test_result_by_request(request_id: str):
    """Get pen test result by request ID."""
    result = db.get_result_by_request(request_id)
    if not result:
        raise HTTPException(status_code=404, detail="Pen test result not found")
    return result.to_dict()


@router.get("/configs")
def list_pen_test_configs(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """List Pentagi configurations."""
    configs = db.list_configs(limit=limit, offset=offset)
    return {"items": [c.to_dict() for c in configs], "total": len(configs)}


@router.post("/configs", status_code=201)
def create_pen_test_config(data: CreatePenTestConfigModel):
    """Create a new Pentagi configuration."""
    config = PenTestConfig(
        id="",
        name=data.name,
        pentagi_url=data.pentagi_url,
        api_key=data.api_key,
        enabled=data.enabled,
        max_concurrent_tests=data.max_concurrent_tests,
        timeout_seconds=data.timeout_seconds,
        auto_trigger=data.auto_trigger,
        target_environments=data.target_environments,
    )
    created = db.create_config(config)

    # Reset service to use new config
    global _pentagi_service
    _pentagi_service = None

    return created.to_dict()


@router.get("/configs/{config_id}")
def get_pen_test_config(config_id: str):
    """Get Pentagi configuration by ID."""
    config = db.get_config(config_id)
    if not config:
        raise HTTPException(status_code=404, detail="Pentagi configuration not found")
    return config.to_dict()


@router.put("/configs/{config_id}")
def update_pen_test_config(config_id: str, data: UpdatePenTestConfigModel):
    """Update Pentagi configuration."""
    config = db.get_config(config_id)
    if not config:
        raise HTTPException(status_code=404, detail="Pentagi configuration not found")

    if data.pentagi_url is not None:
        config.pentagi_url = data.pentagi_url
    if data.api_key is not None:
        config.api_key = data.api_key
    if data.enabled is not None:
        config.enabled = data.enabled
    if data.max_concurrent_tests is not None:
        config.max_concurrent_tests = data.max_concurrent_tests
    if data.timeout_seconds is not None:
        config.timeout_seconds = data.timeout_seconds
    if data.auto_trigger is not None:
        config.auto_trigger = data.auto_trigger
    if data.target_environments is not None:
        config.target_environments = data.target_environments

    updated = db.update_config(config)

    # Reset service to use updated config
    global _pentagi_service
    _pentagi_service = None

    return updated.to_dict()


@router.delete("/configs/{config_id}")
def delete_pen_test_config(config_id: str):
    """Delete Pentagi configuration."""
    deleted = db.delete_config(config_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Pentagi configuration not found")
    return {"status": "deleted"}


# Enhanced endpoints for advanced features
@router.post("/verify", status_code=201)
async def verify_vulnerability(data: VerifyVulnerabilityModel):
    """
    Verify a vulnerability by attempting exploitation.

    Similar to Akido Security's automated verification.
    """
    try:
        service = get_pentagi_service()
        if not service:
            raise HTTPException(
                status_code=503,
                detail="Pentagi service not configured. Please create a configuration first.",
            )
        result = await service.verify_vulnerability_from_finding(
            finding_id=data.finding_id,
            target_url=data.target_url,
            vulnerability_type=data.vulnerability_type,
            evidence=data.evidence,
        )
        return result
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to verify vulnerability: {str(e)}"
        )


@router.post("/monitoring", status_code=201)
async def setup_continuous_monitoring(data: ContinuousMonitoringModel):
    """
    Set up continuous security monitoring.

    Similar to Prism Security's continuous scanning.
    """
    try:
        service = get_pentagi_service()
        if not service:
            raise HTTPException(
                status_code=503,
                detail="Pentagi service not configured. Please create a configuration first.",
            )
        job_ids = await service.setup_continuous_monitoring(
            targets=data.targets,
            interval_minutes=data.interval_minutes,
        )
        return {"status": "monitoring_setup", "jobs": job_ids}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to setup monitoring: {str(e)}"
        )


@router.post("/scan/comprehensive", status_code=201)
async def run_comprehensive_scan(data: ComprehensiveScanModel):
    """
    Run comprehensive multi-vector security scan.

    Performs multiple types of security tests in parallel.
    """
    try:
        service = get_pentagi_service()
        if not service:
            raise HTTPException(
                status_code=503,
                detail="Pentagi service not configured. Please create a configuration first.",
            )

        from integrations.pentagi_client import PentagiTestType

        scan_types = None
        if data.scan_types:
            scan_types = [PentagiTestType(st) for st in data.scan_types]

        requests = await service.run_comprehensive_scan(
            target=data.target,
            scan_types=scan_types,
        )
        return {
            "status": "scan_started",
            "requests": [r.to_dict() for r in requests],
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500, detail=f"Failed to start comprehensive scan: {str(e)}"
        )


@router.get("/findings/{finding_id}/exploitability")
def get_finding_exploitability(finding_id: str):
    """Get exploitability assessment for a finding."""
    try:
        service = get_pentagi_service()
        if service:
            exploitability = service.get_exploitability_for_finding(finding_id)
            if exploitability:
                return {
                    "finding_id": finding_id,
                    "exploitability": exploitability.value,
                }

        # Check database directly if service not available
        requests = db.list_requests(finding_id=finding_id, limit=1)
        if requests:
            result = db.get_result_by_request(requests[0].id)
            if result:
                return {
                    "finding_id": finding_id,
                    "exploitability": result.exploitability.value,
                }

        return {
            "finding_id": finding_id,
            "exploitability": "not_tested",
            "message": "No pen test results available for this finding",
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get exploitability: {str(e)}",
        )


@router.get("/stats")
def get_pen_test_stats():
    """Get statistics about pen tests."""
    all_requests = db.list_requests(limit=10000)
    all_results = db.list_results(limit=10000)

    stats = {
        "total_requests": len(all_requests),
        "total_results": len(all_results),
        "by_status": {},
        "by_exploitability": {},
        "by_priority": {},
    }

    for request in all_requests:
        status = request.status.value
        stats["by_status"][status] = stats["by_status"].get(status, 0) + 1
        priority = request.priority.value
        stats["by_priority"][priority] = stats["by_priority"].get(priority, 0) + 1

    for result in all_results:
        exploitability = result.exploitability.value
        stats["by_exploitability"][exploitability] = (
            stats["by_exploitability"].get(exploitability, 0) + 1
        )

    return stats
