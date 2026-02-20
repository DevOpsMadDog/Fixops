"""
FixOps Decision & Verification API Endpoints
Provides decision engine operations and metrics
"""

import time
from typing import Any, Dict, List, Optional

import structlog
from config.enterprise.settings import get_settings
from core.db.enterprise.session import DatabaseManager
from core.enterprise.security import get_current_user
from core.services.enterprise.decision_engine import DecisionContext, decision_engine
from core.services.enterprise.metrics import FixOpsMetrics
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel

logger = structlog.get_logger()
router = APIRouter(prefix="/decisions", tags=["decision-engine"])


class DecisionRequest(BaseModel):
    service_name: str = "unknown-service"
    environment: str = "production"
    business_context: Dict[str, Any] = {}
    security_findings: List[Dict[str, Any]] = []
    sbom_data: Optional[Dict[str, Any]] = None
    threat_model: Optional[Dict[str, Any]] = None


class DecisionResponse(BaseModel):
    decision: str
    confidence_score: float
    evidence_id: str
    reasoning: str
    processing_time_us: float
    consensus_details: Dict[str, Any]
    validation_results: Dict[str, Any]


@router.post("/make-decision", response_model=DecisionResponse)
async def make_security_decision(request: DecisionRequest):
    """
    Make a security decision based on context and intelligence
    Core FixOps Decision & Verification Engine endpoint
    """
    try:
        context = DecisionContext(
            service_name=request.service_name,
            environment=request.environment,
            business_context=request.business_context,
            security_findings=request.security_findings,
            sbom_data=request.sbom_data,
            threat_model=request.threat_model,
        )

        result = await decision_engine.make_decision(context)

        response = DecisionResponse(
            decision=result.decision.value,
            confidence_score=result.confidence_score,
            evidence_id=result.evidence_id,
            reasoning=result.reasoning,
            processing_time_us=result.processing_time_us,
            consensus_details=result.consensus_details,
            validation_results=result.validation_results,
        )

        FixOpsMetrics.record_decision(
            verdict=result.decision.value,
            confidence=result.confidence_score,
            duration_seconds=result.processing_time_us / 1_000_000,
        )

        return response

    except Exception as e:
        logger.error(f"Decision making failed: {str(e)}")
        FixOpsMetrics.record_decision_error(reason="exception")
        raise HTTPException(status_code=500, detail=f"Decision engine error: {str(e)}")


@router.get("/metrics")
async def get_decision_metrics():
    """Get decision engine performance metrics and status"""
    try:
        metrics = await decision_engine.get_decision_metrics()
        return {"status": "success", "data": metrics}

    except Exception as e:
        logger.error(f"Failed to get decision metrics: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/recent")
async def get_recent_decisions(limit: int = Query(default=10, ge=1, le=50)):
    """Get recent pipeline decisions with full context"""
    try:
        decisions = await decision_engine.get_recent_decisions(limit)
        return {"status": "success", "data": decisions}

    except Exception as e:
        logger.error(f"Failed to get recent decisions: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/ssdlc-stages")
async def get_ssdlc_stage_data(current_user: Dict = Depends(get_current_user)):
    """Get SSDLC stage data ingestion status"""
    try:
        stage_data = await decision_engine.get_ssdlc_stage_data()
        return {"status": "success", "data": stage_data}

    except Exception as e:
        logger.error(f"Failed to get SSDLC stage data: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/core-components")
async def get_core_components_status(current_user: Dict = Depends(get_current_user)):
    """Get Decision & Verification Core components status with real data"""
    try:
        settings = get_settings()

        if settings.DEMO_MODE:
            # Demo mode — clearly labeled, no fabricated metrics
            components = {
                "demo_data": True,
                "vector_db": {
                    "status": "demo_active",
                    "demo_data": True,
                    "type": "Demo Vector Store",
                    "security_patterns": None,
                    "threat_models": None,
                    "context_match_rate": None,
                },
                "llm_rag": {
                    "status": "demo_active",
                    "demo_data": True,
                    "model": "not configured (demo mode)",
                    "enrichment_rate": None,
                    "business_impact_correlation": None,
                    "threat_intel_enrichment": None,
                },
                "consensus_checker": {
                    "status": "demo_active",
                    "demo_data": True,
                    "current_rate": None,
                    "threshold": 0.85,
                    "threshold_met": None,
                },
                "golden_regression": {
                    "status": "demo_active",
                    "demo_data": True,
                    "total_cases": 0,
                    "validation_accuracy": None,
                    "last_validation": None,
                },
                "policy_engine": {
                    "status": "demo_active",
                    "demo_data": True,
                    "type": "Demo OPA Engine",
                    "active_policies": 0,
                    "enforcement_rate": None,
                    "compliance_score": None,
                },
                "sbom_injection": {
                    "status": "demo_active",
                    "demo_data": True,
                    "criticality_assessment": "enabled",
                    "metadata_sources": [],
                },
            }
        else:
            # Production mode - get real component status
            components = {}

            # Real Vector DB status
            if hasattr(decision_engine, "real_vector_db_stats"):
                vector_stats = decision_engine.real_vector_db_stats
                components["vector_db"] = {
                    "status": "production_active"
                    if vector_stats.get("connection_status") == "connected"
                    else "error",
                    "type": vector_stats.get("type", "ChromaDB"),
                    "patterns_loaded": vector_stats.get("patterns_loaded", False),
                    "search_functional": vector_stats.get(
                        "test_search_successful", False
                    ),
                }
            else:
                components["vector_db"] = {
                    "status": "not_initialized",
                    "type": "ChromaDB",
                }

            # Real LLM integration status
            components["llm_rag"] = {
                "status": "production_active"
                if decision_engine.chatgpt_client
                else "not_configured",
                "model": "ChatGPT"
                if decision_engine.chatgpt_client
                else "not_available",
                "integration_type": "OpenAI ChatGPT",
            }

            # Real consensus checker status
            components["consensus_checker"] = {
                "status": "production_active",
                "algorithm": "weighted_consensus",
                "threshold": 0.85,
                "components_integrated": [
                    "vector_db",
                    "policy_engine",
                    "golden_regression",
                ],
            }

            # Real golden regression using database
            async with DatabaseManager.get_session_context() as session:
                from sqlalchemy import text

                # Count real policy decisions for validation
                result = await session.execute(
                    text("SELECT COUNT(*) FROM policy_decision_logs")
                )
                decision_count = result.scalar() or 0

                components["golden_regression"] = {
                    "status": "production_active",
                    "real_cases": decision_count,
                    "data_source": "policy_decision_logs",
                    "validation_method": "historical_decisions",
                }

            # Real policy engine status
            from core.services.enterprise.real_opa_engine import get_opa_engine

            opa_engine = await get_opa_engine()
            opa_healthy = await opa_engine.health_check()

            components["policy_engine"] = {
                "status": "production_active" if opa_healthy else "opa_unavailable",
                "type": "Production OPA Engine"
                if not settings.DEMO_MODE
                else "Demo OPA Engine",
                "opa_server_healthy": opa_healthy,
                "policies_loaded": ["vulnerability", "sbom"],
            }

            # Real SBOM injection status
            components["sbom_injection"] = {
                "status": "production_active",
                "library": "lib4sbom",
                "criticality_assessment": "enabled",
                "metadata_sources": ["Real CycloneDX SBOM", "Real Component Analysis"],
            }

        # Add system-wide metrics
        components["system_info"] = {
            "mode": "demo" if settings.DEMO_MODE else "production",
            "processing_layer_available": decision_engine.processing_layer is not None,
            "oss_integrations_available": decision_engine.oss_integrations is not None,
        }

        return {"status": "success", "data": components}

    except Exception as e:
        logger.error(f"Failed to get core components status: {str(e)}")
        # Return error status but don't fail completely
        return {
            "status": "error",
            "error": "Failed to get core components status",
            "data": {"system_info": {"mode": "error"}},
        }


@router.get("/evidence/{evidence_id}")
async def get_evidence_record(
    evidence_id: str, current_user: Dict = Depends(get_current_user)
):
    """Get immutable evidence record from Evidence Lake"""
    start_time = time.perf_counter()
    source = "none"

    try:
        settings = get_settings()

        # Try Evidence Lake first (production mode)
        if not settings.DEMO_MODE:
            from core.services.enterprise.evidence_lake import EvidenceLake

            evidence = await EvidenceLake.retrieve_evidence(evidence_id)

            if evidence:
                source = "lake"
                FixOpsMetrics.record_evidence_request(
                    source=source,
                    status="hit",
                    duration_seconds=time.perf_counter() - start_time,
                )
                return {
                    "status": "success",
                    "data": evidence,
                    "source": "evidence_lake",
                }

        # Fallback to cache (demo mode or if not found in Evidence Lake)
        from core.services.enterprise.cache_service import CacheService

        cache = CacheService.get_instance()

        cached_evidence = await cache.get(f"evidence:{evidence_id}")
        if cached_evidence:
            source = "cache"
            if isinstance(cached_evidence, str):
                import json

                cached_evidence = json.loads(cached_evidence)
            FixOpsMetrics.record_evidence_request(
                source=source,
                status="hit",
                duration_seconds=time.perf_counter() - start_time,
            )
            return {"status": "success", "data": cached_evidence, "source": "cache"}

        # Not found in either location
        FixOpsMetrics.record_evidence_request(
            source=source,
            status="miss",
            duration_seconds=time.perf_counter() - start_time,
        )
        raise HTTPException(status_code=404, detail="Evidence record not found")

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get evidence record: {str(e)}")
        FixOpsMetrics.record_evidence_request(
            source=source or "unknown",
            status="error",
            duration_seconds=time.perf_counter() - start_time,
        )
        raise HTTPException(status_code=500, detail=str(e))
