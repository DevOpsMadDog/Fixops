"""
System Mode Management API
Handles switching between demo and production modes
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import structlog

from src.config.settings import get_settings
from src.services.real_opa_engine import get_opa_engine

logger = structlog.get_logger()
router = APIRouter(prefix="/system-mode", tags=["system-management"])

class ModeToggleRequest(BaseModel):
    target_mode: str  # "demo" or "production"
    force: bool = False

class ModeToggleResponse(BaseModel):
    current_mode: str
    previous_mode: str
    requirements_met: bool
    missing_requirements: list[str]
    restart_required: bool

@router.get("/current")
async def get_current_mode():
    """Get current system mode and readiness status"""
    try:
        settings = get_settings()
        
        # Check production readiness
        missing_requirements = []
        
        if not settings.primary_llm_api_key:
            missing_requirements.append("OPENAI_API_KEY")
        
        opa_ready = False
        if getattr(settings, "OPA_SERVER_URL", None):
            try:
                engine = await get_opa_engine()
                opa_ready = await engine.health_check()
            except Exception as exc:  # pragma: no cover - defensive logging
                logger.warning("OPA health check failed", error=str(exc))

        if not opa_ready:
            missing_requirements.append("OPA_SERVER")
        
        if not (settings.JIRA_URL and settings.JIRA_USERNAME and settings.JIRA_API_TOKEN):
            missing_requirements.append("JIRA_CREDENTIALS")
            
        if not (settings.CONFLUENCE_URL and settings.CONFLUENCE_USERNAME and settings.CONFLUENCE_API_TOKEN):
            missing_requirements.append("CONFLUENCE_CREDENTIALS")
        
        return {
            "status": "success",
            "data": {
                "current_mode": "demo" if settings.DEMO_MODE else "production",
                "demo_mode_enabled": settings.DEMO_MODE,
                "production_ready": len(missing_requirements) == 0,
                "missing_requirements": missing_requirements,
                "can_switch_to_production": len(missing_requirements) == 0,
                "components_status": {
                    "decision_engine": "operational",
                    "vector_database": "demo" if settings.DEMO_MODE else ("operational" if settings.PGVECTOR_ENABLED else "needs_config"),
                    "llm_consensus": "demo" if settings.DEMO_MODE else ("operational" if settings.primary_llm_api_key else "needs_keys"),
                    "policy_engine": "demo"
                    if settings.DEMO_MODE
                    else ("operational" if opa_ready else "needs_server"),
                    "evidence_lake": "operational"
                }
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to get current mode: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/toggle", response_model=ModeToggleResponse)
async def toggle_system_mode(request: ModeToggleRequest):
    """
    Toggle between demo and production modes
    Note: In container environment, this requires restart
    """
    try:
        settings = get_settings()
        current_mode = "demo" if settings.DEMO_MODE else "production"
        
        if request.target_mode == current_mode:
            raise HTTPException(
                status_code=400, 
                detail=f"System already in {current_mode} mode"
            )
        
        # Check production readiness if switching to production
        missing_requirements = []
        if request.target_mode == "production":
            if not settings.primary_llm_api_key:
                missing_requirements.append("OPENAI_API_KEY")
            # Add other production checks here
            
            if missing_requirements and not request.force:
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": "production_requirements_not_met",
                        "missing_requirements": missing_requirements,
                        "message": "Use force=true to switch anyway"
                    }
                )
        
        # In container environment, mode switching requires environment variable change
        # This would typically be handled by the deployment system
        response = ModeToggleResponse(
            current_mode=current_mode,
            previous_mode=current_mode,
            requirements_met=len(missing_requirements) == 0,
            missing_requirements=missing_requirements,
            restart_required=True
        )
        
        logger.info(f"Mode toggle requested: {current_mode} -> {request.target_mode}")
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Mode toggle failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/production-requirements")
async def get_production_requirements():
    """Get detailed production setup requirements"""
    return {
        "status": "success",
        "requirements": {
            "critical": {
                "OPENAI_API_KEY": {
                    "description": "OpenAI API key for ChatGPT-backed consensus and explanations",
                    "setup": "Create an API key in the OpenAI console and set OPENAI_API_KEY",
                    "component": "ChatGPT Decision Engine",
                    "impact": "No AI-powered decision analysis without this key"
                },
                "OPA_SERVER": {
                    "description": "Open Policy Agent server for security policies",
                    "setup": "docker run -p 8181:8181 openpolicyagent/opa:latest run --server",
                    "component": "Policy Engine",
                    "impact": "Falls back to basic policy logic without OPA"
                }
            },
            "optional": {
                "JIRA_CREDENTIALS": {
                    "description": "Jira integration for business context enrichment",
                    "setup": "Set JIRA_URL, JIRA_USERNAME, JIRA_API_TOKEN",
                    "component": "Business Context Engine",
                    "impact": "Limited business impact assessment"
                },
                "CONFLUENCE_CREDENTIALS": {
                    "description": "Confluence integration for threat model retrieval",
                    "setup": "Set CONFLUENCE_URL, CONFLUENCE_USERNAME, CONFLUENCE_API_TOKEN",
                    "component": "Threat Model Integration",
                    "impact": "No automated threat model lookup"
                },
                "PGVECTOR_DSN": {
                    "description": "PostgreSQL with pgvector for similarity search",
                    "setup": "postgresql+psycopg://user:pass@host:5432/db",
                    "component": "Vector Database",
                    "impact": "Uses fallback similarity search"
                }
            },
            "setup_guide": {
                "step_1": "Set DEMO_MODE=false in environment variables",
                "step_2": "Configure OPENAI_API_KEY for ChatGPT functionality",
                "step_3": "Start OPA server: docker run -p 8181:8181 openpolicyagent/opa:latest run --server",
                "step_4": "Optional: Configure Jira/Confluence for business context",
                "step_5": "Optional: Setup PostgreSQL with pgvector extension",
                "step_6": "Restart FixOps services to apply configuration"
            }
        }
    }