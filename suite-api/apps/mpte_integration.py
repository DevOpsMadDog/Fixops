"""MPTE integration API for FixOps."""

import logging
from typing import Dict, List, Optional

from core.continuous_validation import ContinuousValidationEngine, ValidationTrigger
from core.exploit_generator import IntelligentExploitGenerator, PayloadComplexity
from core.llm_providers import LLMProviderManager
from core.mpte_advanced import AdvancedMPTEClient, MultiAIOrchestrator
from core.mpte_db import MPTEDB
from core.mpte_models import (
    ExploitabilityLevel,
    PenTestConfig,
    PenTestPriority,
    PenTestRequest,
    PenTestStatus,
)
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/mpte", tags=["MPTE Integration"])


# Request/Response Models
class PenTestRequestModel(BaseModel):
    """Request model for creating a pentest."""

    finding_id: str
    target_url: str
    vulnerability_type: str
    test_case: str
    priority: str = "medium"
    metadata: Optional[Dict] = None


class PenTestConsensusRequest(BaseModel):
    """Request model for consensus-based pentesting."""

    vulnerability: Dict
    context: Dict
    use_consensus: bool = True


class ExploitGenerationRequest(BaseModel):
    """Request model for exploit generation."""

    vulnerability: Dict
    context: Dict
    complexity: str = "moderate"


class ExploitChainRequest(BaseModel):
    """Request model for exploit chain generation."""

    vulnerabilities: List[Dict]
    context: Dict


class ValidationTriggerRequest(BaseModel):
    """Request model for triggering validation."""

    trigger: str
    target: str
    vulnerabilities: List[Dict]
    priority: Optional[str] = None
    metadata: Optional[Dict] = None


class RemediationValidationRequest(BaseModel):
    """Request model for remediation validation."""

    finding_id: str
    context: Dict


# Dependency injection
async def get_mpte_client() -> AdvancedMPTEClient:
    """Get MPTE client instance."""
    db = MPTEDB()
    configs = db.list_configs(limit=1)

    if not configs:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="MPTE not configured",
        )

    config = configs[0]
    if not config.enabled:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="MPTE is disabled",
        )

    llm_manager = LLMProviderManager()
    client = AdvancedMPTEClient(config, llm_manager, db)

    return client


async def get_exploit_generator() -> IntelligentExploitGenerator:
    """Get exploit generator instance."""
    llm_manager = LLMProviderManager()
    return IntelligentExploitGenerator(llm_manager)


async def get_validation_engine() -> ContinuousValidationEngine:
    """Get validation engine instance."""
    client = await get_mpte_client()
    orchestrator = MultiAIOrchestrator(LLMProviderManager())
    engine = ContinuousValidationEngine(client, orchestrator)
    return engine


# Configuration Endpoints
@router.post("/config", status_code=status.HTTP_201_CREATED)
async def create_config(
    name: str,
    mpte_url: str,
    api_key: Optional[str] = None,
    enabled: bool = True,
    max_concurrent_tests: int = 5,
    timeout_seconds: int = 300,
) -> Dict:
    """Create a new MPTE configuration."""
    db = MPTEDB()

    config = PenTestConfig(
        id="",
        name=name,
        mpte_url=mpte_url,
        api_key=api_key,
        enabled=enabled,
        max_concurrent_tests=max_concurrent_tests,
        timeout_seconds=timeout_seconds,
    )

    created_config = db.create_config(config)
    return created_config.to_dict()


@router.get("/config")
async def list_configs() -> List[Dict]:
    """List all MPTE configurations."""
    db = MPTEDB()
    configs = db.list_configs()
    return [c.to_dict() for c in configs]


@router.get("/config/{config_id}")
async def get_config(config_id: str) -> Dict:
    """Get a specific MPTE configuration."""
    db = MPTEDB()
    config = db.get_config(config_id)

    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Configuration not found"
        )

    return config.to_dict()


@router.put("/config/{config_id}")
async def update_config(config_id: str, enabled: Optional[bool] = None) -> Dict:
    """Update a MPTE configuration."""
    db = MPTEDB()
    config = db.get_config(config_id)

    if not config:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Configuration not found"
        )

    if enabled is not None:
        config.enabled = enabled

    updated_config = db.update_config(config)
    return updated_config.to_dict()


# Pentest Execution Endpoints
@router.post("/pentest", status_code=status.HTTP_202_ACCEPTED)
async def execute_pentest(
    request: PenTestRequestModel,
    background_tasks: BackgroundTasks,
    client: AdvancedMPTEClient = Depends(get_mpte_client),
) -> Dict:
    """Execute a penetration test."""
    priority_map = {
        "critical": PenTestPriority.CRITICAL,
        "high": PenTestPriority.HIGH,
        "medium": PenTestPriority.MEDIUM,
        "low": PenTestPriority.LOW,
    }

    pen_request = PenTestRequest(
        id="",
        finding_id=request.finding_id,
        target_url=request.target_url,
        vulnerability_type=request.vulnerability_type,
        test_case=request.test_case,
        priority=priority_map.get(request.priority.lower(), PenTestPriority.MEDIUM),
        metadata=request.metadata or {},
    )

    # Execute in background
    background_tasks.add_task(client.execute_pentest, pen_request)

    return {
        "status": "accepted",
        "message": "Pentest execution started",
        "finding_id": request.finding_id,
    }


@router.post("/pentest/consensus", status_code=status.HTTP_202_ACCEPTED)
async def execute_pentest_with_consensus(
    request: PenTestConsensusRequest,
    background_tasks: BackgroundTasks,
    client: AdvancedMPTEClient = Depends(get_mpte_client),
) -> Dict:
    """Execute pentest with multi-AI consensus."""
    if request.use_consensus:
        # Execute with full consensus
        background_tasks.add_task(
            client.execute_pentest_with_consensus,
            request.vulnerability,
            request.context,
        )
    else:
        # Execute standard pentest
        pen_request = PenTestRequest(
            id="",
            finding_id=request.vulnerability.get("id", "unknown"),
            target_url=request.context.get("target_url", ""),
            vulnerability_type=request.vulnerability.get("type", "unknown"),
            test_case=request.vulnerability.get("description", ""),
            priority=PenTestPriority.MEDIUM,
        )
        background_tasks.add_task(client.execute_pentest, pen_request)

    return {
        "status": "accepted",
        "message": "Consensus-based pentest started",
        "vulnerability_id": request.vulnerability.get("id"),
        "consensus_enabled": request.use_consensus,
    }


@router.get("/pentest/{request_id}")
async def get_pentest_status(request_id: str) -> Dict:
    """Get status of a pentest request."""
    db = MPTEDB()
    request = db.get_request(request_id)

    if not request:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Pentest request not found"
        )

    response = request.to_dict()

    # Add result if completed
    if request.status == PenTestStatus.COMPLETED:
        result = db.get_result_by_request(request_id)
        if result:
            response["result"] = result.to_dict()

    return response


@router.get("/pentest/finding/{finding_id}")
async def get_pentests_by_finding(finding_id: str) -> List[Dict]:
    """Get all pentests for a finding."""
    db = MPTEDB()
    requests = db.list_requests(finding_id=finding_id)
    return [r.to_dict() for r in requests]


# Exploit Generation Endpoints
@router.post("/exploit/generate")
async def generate_exploit(
    request: ExploitGenerationRequest,
    generator: IntelligentExploitGenerator = Depends(get_exploit_generator),
) -> Dict:
    """Generate a custom exploit payload."""
    complexity_map = {
        "simple": PayloadComplexity.SIMPLE,
        "moderate": PayloadComplexity.MODERATE,
        "advanced": PayloadComplexity.ADVANCED,
        "apt_level": PayloadComplexity.APT_LEVEL,
    }

    complexity = complexity_map.get(
        request.complexity.lower(), PayloadComplexity.MODERATE
    )

    exploit = await generator.generate_exploit(
        request.vulnerability, request.context, complexity
    )

    return exploit.to_dict()


@router.post("/exploit/chain")
async def generate_exploit_chain(
    request: ExploitChainRequest,
    generator: IntelligentExploitGenerator = Depends(get_exploit_generator),
) -> Dict:
    """Generate a multi-stage exploit chain."""
    chain = await generator.generate_exploit_chain(
        request.vulnerabilities, request.context
    )

    return chain.to_dict()


@router.post("/exploit/{payload_id}/optimize")
async def optimize_exploit(
    payload_id: str,
    target_constraints: Dict,
    generator: IntelligentExploitGenerator = Depends(get_exploit_generator),
) -> Dict:
    """Optimize an exploit payload."""
    # Get the payload from generator's cache
    if payload_id not in generator.generated_exploits:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Exploit payload not found"
        )

    payload = generator.generated_exploits[payload_id]
    optimized = await generator.optimize_payload(payload, target_constraints)

    return optimized.to_dict()


# Continuous Validation Endpoints
@router.post("/validation/trigger", status_code=status.HTTP_202_ACCEPTED)
async def trigger_validation(
    request: ValidationTriggerRequest,
    engine: ContinuousValidationEngine = Depends(get_validation_engine),
) -> Dict:
    """Trigger a continuous validation job."""
    trigger_map = {
        "code_commit": ValidationTrigger.CODE_COMMIT,
        "deployment": ValidationTrigger.DEPLOYMENT,
        "scheduled": ValidationTrigger.SCHEDULED,
        "manual": ValidationTrigger.MANUAL,
        "vulnerability_discovered": ValidationTrigger.VULNERABILITY_DISCOVERED,
        "security_incident": ValidationTrigger.SECURITY_INCIDENT,
        "configuration_change": ValidationTrigger.CONFIGURATION_CHANGE,
    }

    priority_map = {
        "critical": PenTestPriority.CRITICAL,
        "high": PenTestPriority.HIGH,
        "medium": PenTestPriority.MEDIUM,
        "low": PenTestPriority.LOW,
    }

    trigger = trigger_map.get(request.trigger.lower(), ValidationTrigger.MANUAL)
    priority = priority_map.get(request.priority.lower()) if request.priority else None

    job = await engine.trigger_validation(
        trigger,
        request.target,
        request.vulnerabilities,
        priority,
        request.metadata,
    )

    return job.to_dict()


@router.get("/validation/job/{job_id}")
async def get_validation_job(
    job_id: str, engine: ContinuousValidationEngine = Depends(get_validation_engine)
) -> Dict:
    """Get status of a validation job."""
    if job_id in engine.active_jobs:
        return engine.active_jobs[job_id].to_dict()

    # Check completed jobs
    for job in engine.completed_jobs:
        if job.id == job_id:
            return job.to_dict()

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND, detail="Validation job not found"
    )


@router.get("/validation/posture")
async def get_security_posture(
    engine: ContinuousValidationEngine = Depends(get_validation_engine),
) -> Dict:
    """Get current security posture."""
    if not engine.posture_history:
        return {"status": "no_data", "message": "No posture data available yet"}

    current_posture = engine.posture_history[-1]
    return current_posture.to_dict()


@router.get("/validation/posture/history")
async def get_posture_history(
    limit: int = 30,
    engine: ContinuousValidationEngine = Depends(get_validation_engine),
) -> List[Dict]:
    """Get security posture history."""
    history = engine.posture_history[-limit:]
    return [p.to_dict() for p in history]


@router.get("/validation/statistics")
async def get_validation_statistics(
    engine: ContinuousValidationEngine = Depends(get_validation_engine),
) -> Dict:
    """Get continuous validation statistics."""
    return engine.get_statistics()


# Remediation Validation Endpoints
@router.post("/remediation/validate")
async def validate_remediation(
    request: RemediationValidationRequest,
    background_tasks: BackgroundTasks,
    client: AdvancedMPTEClient = Depends(get_mpte_client),
) -> Dict:
    """Validate that a remediation fixed the vulnerability."""
    # Execute validation in background
    background_tasks.add_task(
        client.validate_remediation, request.finding_id, request.context
    )

    return {
        "status": "accepted",
        "message": "Remediation validation started",
        "finding_id": request.finding_id,
    }


# Statistics and Reporting Endpoints
@router.get("/statistics")
async def get_statistics(
    client: AdvancedMPTEClient = Depends(get_mpte_client),
) -> Dict:
    """Get overall MPTE integration statistics."""
    return client.get_statistics()


@router.get("/results/exploitable")
async def get_exploitable_findings() -> List[Dict]:
    """Get all confirmed exploitable findings."""
    db = MPTEDB()
    results = db.list_results(
        exploitability=ExploitabilityLevel.CONFIRMED_EXPLOITABLE, limit=100
    )
    return [r.to_dict() for r in results]


@router.get("/results/false-positives")
async def get_false_positives() -> List[Dict]:
    """Get all confirmed false positives."""
    db = MPTEDB()
    results = db.list_results(
        exploitability=ExploitabilityLevel.UNEXPLOITABLE, limit=100
    )
    return [r.to_dict() for r in results]


@router.get("/health")
async def health_check() -> Dict:
    """Health check endpoint."""
    try:
        db = MPTEDB()
        configs = db.list_configs(limit=1)

        if not configs:
            return {"status": "degraded", "message": "No MPTE configuration found"}

        config = configs[0]
        if not config.enabled:
            return {"status": "disabled", "message": "MPTE is disabled"}

        return {"status": "healthy", "message": "MPTE integration is operational"}

    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return {"status": "unhealthy", "error": "Health check failed"}
