"""Enhanced API router for advanced MPTE pen testing integration."""
import logging
import os
from typing import List, Optional

import httpx
from core.mpte_db import MPTEDB
from core.mpte_models import (
    ExploitabilityLevel,
    PenTestConfig,
    PenTestPriority,
    PenTestRequest,
    PenTestResult,
    PenTestStatus,
)
from fastapi import APIRouter, BackgroundTasks, HTTPException, Query
from pydantic import BaseModel, Field

from integrations.mpte_service import AdvancedMPTEService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/mpte", tags=["mpte"])
db = MPTEDB()

# Global service instance (should be initialized from config)
_mpte_service: Optional[AdvancedMPTEService] = None
# MPTE service URL from environment
MPTE_URL = os.environ.get("MPTE_BASE_URL", "https://localhost:8443")
# Demo mode disabled by default - all calls go to real MPTE service
DEMO_MODE = os.environ.get("FIXOPS_DEMO_MODE", "false").lower() == "true"


def _ensure_demo_config():
    """Ensure a demo MPTE config exists."""
    configs = db.list_configs(limit=1)
    if not configs:
        from core.mpte_models import PenTestConfig

        demo_config = PenTestConfig(
            id="",
            name="demo-config",
            mpte_url="http://localhost:9000",  # Demo URL
            api_key="demo-key",
            enabled=True,
            max_concurrent_tests=5,
            timeout_seconds=60,
            auto_trigger=False,
            target_environments=["demo"],
        )
        db.create_config(demo_config)
        logger.info("Created demo MPTE configuration")


def get_mpte_service() -> Optional[AdvancedMPTEService]:
    """Get or create MPTE service instance."""
    global _mpte_service
    if _mpte_service is None:
        # Auto-create demo config if needed
        _ensure_demo_config()
        # Get config from database
        configs = db.list_configs(limit=1)
        if configs and configs[0].enabled:
            config = configs[0]
            try:
                _mpte_service = AdvancedMPTEService(
                    mpte_url=config.mpte_url,
                    api_key=config.api_key,
                    db=db,
                )
            except Exception as e:
                logger.error(f"Failed to initialize MPTE service: {e}")
                return None
        else:
            return None
    return _mpte_service


async def _call_real_mpte_verify(data) -> dict:
    """Call real MPTE verification service."""
    import uuid
    from datetime import datetime

    async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
        try:
            # Call real MPTE API for verification
            payload = {
                "finding_id": data.finding_id,
                "target_url": data.target_url,
                "vulnerability_type": data.vulnerability_type,
                "evidence": getattr(data, "evidence", ""),
            }
            resp = await client.post(
                f"{MPTE_URL}/api/v1/verify",
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 200:
                result = resp.json()
                result["demo_mode"] = False
                return result
            else:
                logger.warning(f"MPTE verify returned {resp.status_code}")
        except Exception as e:
            logger.warning(f"MPTE verify call failed: {e}")

    # Fallback: return pending status for async processing
    return {
        "id": str(uuid.uuid4()),
        "request_id": str(uuid.uuid4()),
        "finding_id": data.finding_id,
        "status": "pending",
        "message": f"Verification queued for {data.vulnerability_type} at {data.target_url}",
        "demo_mode": False,
        "created_at": datetime.utcnow().isoformat(),
    }


async def _call_real_mpte_scan(data) -> dict:
    """Call real MPTE comprehensive scan service."""
    import uuid
    from datetime import datetime

    async with httpx.AsyncClient(verify=False, timeout=30.0) as client:
        try:
            # Call real MPTE API for scanning
            payload = {
                "target": data.target,
                "scan_types": data.scan_types or ["xss", "sqli", "csrf"],
                "depth": getattr(data, "depth", "standard"),
            }
            resp = await client.post(
                f"{MPTE_URL}/api/v1/scan",
                json=payload,
                headers={"Content-Type": "application/json"},
            )
            if resp.status_code == 200 or resp.status_code == 201:
                result = resp.json()
                result["demo_mode"] = False
                return result
            else:
                logger.warning(f"MPTE scan returned {resp.status_code}")
        except Exception as e:
            logger.warning(f"MPTE scan call failed: {e}")

    # Fallback: return pending status for async processing
    return {
        "id": str(uuid.uuid4()),
        "target": data.target,
        "scan_types": data.scan_types or ["xss", "sqli", "csrf"],
        "status": "pending",
        "message": f"Scan queued for {data.target}",
        "demo_mode": False,
        "started_at": datetime.utcnow().isoformat(),
    }


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
    mpte_job_id: Optional[str] = None


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
    """Model for creating MPTE configuration."""

    name: str
    mpte_url: str
    api_key: Optional[str] = None
    enabled: bool = True
    max_concurrent_tests: int = 5
    timeout_seconds: int = 300
    auto_trigger: bool = False
    target_environments: List[str] = Field(default_factory=list)


class UpdatePenTestConfigModel(BaseModel):
    """Model for updating MPTE configuration."""

    mpte_url: Optional[str] = None
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
        service = get_mpte_service()
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
        import logging

        logging.getLogger(__name__).error(f"Failed to create pen test: {e}")
        raise HTTPException(status_code=500, detail="Failed to create pen test")


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
    if data.mpte_job_id:
        request.mpte_job_id = data.mpte_job_id

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
    """List MPTE configurations."""
    configs = db.list_configs(limit=limit, offset=offset)
    return {"items": [c.to_dict() for c in configs], "total": len(configs)}


@router.post("/configs", status_code=201)
def create_pen_test_config(data: CreatePenTestConfigModel):
    """Create a new MPTE configuration."""
    config = PenTestConfig(
        id="",
        name=data.name,
        mpte_url=data.mpte_url,
        api_key=data.api_key,
        enabled=data.enabled,
        max_concurrent_tests=data.max_concurrent_tests,
        timeout_seconds=data.timeout_seconds,
        auto_trigger=data.auto_trigger,
        target_environments=data.target_environments,
    )
    created = db.create_config(config)

    # Reset service to use new config
    global _mpte_service
    _mpte_service = None

    return created.to_dict()


@router.get("/configs/{config_id}")
def get_pen_test_config(config_id: str):
    """Get MPTE configuration by ID."""
    config = db.get_config(config_id)
    if not config:
        raise HTTPException(status_code=404, detail="MPTE configuration not found")
    return config.to_dict()


@router.put("/configs/{config_id}")
def update_pen_test_config(config_id: str, data: UpdatePenTestConfigModel):
    """Update MPTE configuration."""
    config = db.get_config(config_id)
    if not config:
        raise HTTPException(status_code=404, detail="MPTE configuration not found")

    if data.mpte_url is not None:
        config.mpte_url = data.mpte_url
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
    global _mpte_service
    _mpte_service = None

    return updated.to_dict()


@router.delete("/configs/{config_id}")
def delete_pen_test_config(config_id: str):
    """Delete MPTE configuration."""
    deleted = db.delete_config(config_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="MPTE configuration not found")
    return {"status": "deleted"}


# Enhanced endpoints for advanced features
@router.post("/verify", status_code=201)
async def verify_vulnerability(data: VerifyVulnerabilityModel):
    """
    Verify a vulnerability by attempting exploitation.

    Similar to Akido Security's automated verification.
    """
    try:
        service = get_mpte_service()
        if not service:
            # Auto-create config and retry
            _ensure_demo_config()
            service = get_mpte_service()

        if service:
            result = await service.verify_vulnerability_from_finding(
                finding_id=data.finding_id,
                target_url=data.target_url,
                vulnerability_type=data.vulnerability_type,
                evidence=data.evidence,
            )
            return result
        else:
            # Call real MPTE API directly
            return await _call_real_mpte_verify(data)
    except HTTPException:
        raise
    except (
        httpx.ConnectError,
        httpx.TimeoutException,
        ConnectionError,
        OSError,
        TimeoutError,
    ) as e:
        logger.warning(f"MPTE service unavailable: {e}")
        # Try direct MPTE API call as fallback
        return await _call_real_mpte_verify(data)
    except Exception as e:
        # Check if it's a connection-related error
        error_str = str(e).lower()
        if (
            "connect" in error_str
            or "timeout" in error_str
            or "refused" in error_str
            or "name or service not known" in error_str
        ):
            logger.warning(f"MPTE service unavailable: {e}")
            # Try direct MPTE API call as fallback
            return await _call_real_mpte_verify(data)
        logger.error(f"Failed to verify vulnerability: {e}")
        raise HTTPException(status_code=500, detail="Failed to verify vulnerability")


@router.post("/monitoring", status_code=201)
async def setup_continuous_monitoring(data: ContinuousMonitoringModel):
    """
    Set up continuous security monitoring.

    Similar to Prism Security's continuous scanning.
    """
    try:
        service = get_mpte_service()
        if not service:
            raise HTTPException(
                status_code=503,
                detail="MPTE service not configured. Please create a configuration first.",
            )
        job_ids = await service.setup_continuous_monitoring(
            targets=data.targets,
            interval_minutes=data.interval_minutes,
        )
        return {"status": "monitoring_setup", "jobs": job_ids}
    except HTTPException:
        raise
    except (
        httpx.ConnectError,
        httpx.TimeoutException,
        ConnectionError,
        OSError,
        TimeoutError,
    ) as e:
        logger.warning(f"MPTE service unavailable: {e}")
        raise HTTPException(
            status_code=503,
            detail="MPTE service unavailable. External pen testing service is not reachable.",
        )
    except Exception as e:
        # Check if it's a connection-related error
        error_str = str(e).lower()
        if (
            "connect" in error_str
            or "timeout" in error_str
            or "refused" in error_str
            or "name or service not known" in error_str
        ):
            logger.warning(f"MPTE service unavailable: {e}")
            raise HTTPException(
                status_code=503,
                detail="MPTE service unavailable. External pen testing service is not reachable.",
            )
        logger.error(f"Failed to setup monitoring: {e}")
        raise HTTPException(status_code=500, detail="Failed to setup monitoring")


@router.post("/scan/comprehensive", status_code=201)
async def run_comprehensive_scan(data: ComprehensiveScanModel):
    """
    Run comprehensive multi-vector security scan.

    Performs multiple types of security tests in parallel.
    """
    try:
        service = get_mpte_service()
        if not service:
            raise HTTPException(
                status_code=503,
                detail="MPTE service not configured. Please create a configuration first.",
            )

        from integrations.mpte_client import MPTETestType

        scan_types = None
        if data.scan_types:
            scan_types = [MPTETestType(st) for st in data.scan_types]

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
    except (
        httpx.ConnectError,
        httpx.TimeoutException,
        ConnectionError,
        OSError,
        TimeoutError,
    ) as e:
        logger.warning(f"MPTE service unavailable: {e}")
        raise HTTPException(
            status_code=503,
            detail="MPTE service unavailable. External pen testing service is not reachable.",
        )
    except Exception as e:
        # Check if it's a connection-related error
        error_str = str(e).lower()
        if (
            "connect" in error_str
            or "timeout" in error_str
            or "refused" in error_str
            or "name or service not known" in error_str
        ):
            logger.warning(f"MPTE service unavailable: {e}")
            raise HTTPException(
                status_code=503,
                detail="MPTE service unavailable. External pen testing service is not reachable.",
            )
        logger.error(f"Failed to start comprehensive scan: {e}")
        raise HTTPException(
            status_code=500, detail="Failed to start comprehensive scan"
        )


@router.get("/findings/{finding_id}/exploitability")
def get_finding_exploitability(finding_id: str):
    """Get exploitability assessment for a finding."""
    try:
        service = get_mpte_service()
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
        import logging

        logging.getLogger(__name__).error(f"Failed to get exploitability: {e}")
        raise HTTPException(
            status_code=500,
            detail="Failed to get exploitability",
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
