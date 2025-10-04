"""System Mode Management API for demo vs production orchestration."""

from __future__ import annotations

import os
from typing import List

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field, field_validator
import structlog

from src.config.settings import RuntimeMode, Settings, get_settings, reload_settings
from src.services.decision_engine import refresh_decision_engine_settings

logger = structlog.get_logger()
router = APIRouter(prefix="/system-mode", tags=["system-management"])


def _component_status(
    settings: Settings,
    missing: List[str],
    requirement: str,
    *,
    demo_value: str,
    production_value: str,
    missing_value: str,
) -> str:
    """Return a consistent component status string for the dashboard."""

    if settings.runtime_mode is RuntimeMode.DEMO:
        return demo_value
    if requirement in missing:
        return missing_value
    return production_value


class ModeToggleRequest(BaseModel):
    """Payload for switching between runtime modes."""

    target_mode: str = Field(description="demo or production")
    force: bool = Field(default=False, description="Override readiness checks")

    @field_validator("target_mode")
    @classmethod
    def normalise_target_mode(cls, value: str) -> str:
        try:
            return RuntimeMode(value.strip().lower()).value
        except ValueError as exc:  # pragma: no cover - validation error path
            raise ValueError(f"Unsupported mode '{value}'") from exc


class ModeToggleResponse(BaseModel):
    """Shape of the mode toggle API response."""

    current_mode: str
    previous_mode: str
    requirements_met: bool
    missing_requirements: List[str]
    restart_required: bool


@router.get("/current")
async def get_current_mode():
    """Get current system mode and readiness status"""
    try:
        settings = get_settings()
        missing_requirements = settings.missing_production_requirements()

        return {
            "status": "success",
            "data": {
                "current_mode": settings.runtime_mode.value,
                "demo_mode_enabled": settings.DEMO_MODE,
                "production_ready": not missing_requirements,
                "missing_requirements": missing_requirements,
                "can_switch_to_production": not missing_requirements,
                "components_status": {
                    "decision_engine": "operational",
                    "vector_database": _component_status(
                        settings,
                        missing_requirements,
                        "PGVECTOR_DSN",
                        demo_value="demo",
                        production_value="operational",
                        missing_value="needs_config",
                    ),
                    "llm_consensus": _component_status(
                        settings,
                        missing_requirements,
                        "EMERGENT_LLM_KEY",
                        demo_value="demo",
                        production_value="operational",
                        missing_value="needs_keys",
                    ),
                    "policy_engine": _component_status(
                        settings,
                        missing_requirements,
                        "OPA_SERVER",
                        demo_value="demo",
                        production_value="operational",
                        missing_value="needs_server",
                    ),
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
        current_mode = settings.runtime_mode.value
        previous_mode = current_mode
        target_mode = request.target_mode

        if target_mode == current_mode:
            raise HTTPException(
                status_code=400,
                detail=f"System already in {current_mode} mode"
            )

        # Check production readiness if switching to production
        missing_requirements: List[str] = []
        if target_mode == RuntimeMode.PRODUCTION.value:
            missing_requirements = settings.missing_production_requirements()

            if missing_requirements and not request.force:
                raise HTTPException(
                    status_code=400,
                    detail={
                        "error": "production_requirements_not_met",
                        "missing_requirements": missing_requirements,
                        "message": "Use force=true to switch anyway"
                    }
                )

        new_demo_mode = target_mode == RuntimeMode.DEMO.value

        # Apply mode change for the current process
        os.environ["DEMO_MODE"] = "true" if new_demo_mode else "false"
        reloaded = reload_settings()
        await refresh_decision_engine_settings(force=True)

        updated_settings = reloaded
        current_mode = updated_settings.runtime_mode.value

        response = ModeToggleResponse(
            current_mode=current_mode,
            previous_mode=previous_mode,
            requirements_met=not missing_requirements,
            missing_requirements=missing_requirements,
            restart_required=(target_mode == RuntimeMode.PRODUCTION.value and bool(missing_requirements))
        )

        logger.info(
            "Mode toggle processed",
            previous_mode=response.previous_mode,
            current_mode=response.current_mode,
            requirements_met=response.requirements_met,
        )

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
                "EMERGENT_LLM_KEY": {
                    "description": "API key for multi-LLM consensus (GPT-5, Claude, Gemini)",
                    "setup": "Get from Emergent platform → Profile → Universal Key",
                    "component": "Multi-LLM Consensus Engine",
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
                "step_2": "Configure EMERGENT_LLM_KEY for AI functionality",
                "step_3": "Start OPA server: docker run -p 8181:8181 openpolicyagent/opa:latest run --server",
                "step_4": "Optional: Configure Jira/Confluence for business context",
                "step_5": "Optional: Setup PostgreSQL with pgvector extension",
                "step_6": "Restart FixOps services to apply configuration"
            }
        }
    }