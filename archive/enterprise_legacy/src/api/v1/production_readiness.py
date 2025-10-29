"""
Production Readiness API
Shows what's required to enable production mode functionality
"""

from typing import Any, Dict, List

import structlog
from fastapi import APIRouter, HTTPException
from src.config.settings import get_settings
from src.services.real_opa_engine import get_opa_engine

logger = structlog.get_logger()
router = APIRouter(prefix="/production-readiness", tags=["production-status"])


@router.get("/status")
async def get_production_readiness():
    """
    Get detailed status of what's required for production mode
    Returns specific missing credentials/configurations
    """
    try:
        settings = get_settings()

        # Check production requirements
        readiness_status = {
            "demo_mode": settings.DEMO_MODE,
            "overall_production_ready": False,
            "missing_requirements": [],
            "component_status": {},
        }

        # Vector Database Readiness
        vector_db_ready = bool(settings.PGVECTOR_ENABLED and settings.PGVECTOR_DSN)
        readiness_status["component_status"]["vector_database"] = {
            "status": "READY" if vector_db_ready else "NEEDS_CONFIG",
            "required": "PGVECTOR_DSN" if not vector_db_ready else None,
            "description": "PostgreSQL with pgvector extension"
            if not vector_db_ready
            else "ChromaDB vector store active",
        }
        if not vector_db_ready:
            readiness_status["missing_requirements"].append("PGVECTOR_DSN")

        # Business Context Integration Readiness
        jira_ready = bool(
            settings.JIRA_URL and settings.JIRA_USERNAME and settings.JIRA_API_TOKEN
        )
        confluence_ready = bool(
            settings.CONFLUENCE_URL
            and settings.CONFLUENCE_USERNAME
            and settings.CONFLUENCE_API_TOKEN
        )

        readiness_status["component_status"]["business_context"] = {
            "status": "READY"
            if (jira_ready and confluence_ready)
            else "NEEDS_CREDENTIALS",
            "required": "JIRA_CREDENTIALS"
            if not jira_ready
            else "CONFLUENCE_CREDENTIALS"
            if not confluence_ready
            else None,
            "description": "Jira + Confluence API tokens"
            if not (jira_ready and confluence_ready)
            else "Business context enrichment active",
        }
        if not jira_ready:
            readiness_status["missing_requirements"].append("JIRA_CREDENTIALS")
        if not confluence_ready:
            readiness_status["missing_requirements"].append("CONFLUENCE_CREDENTIALS")

        # LLM Integration Readiness
        llm_ready = bool(settings.primary_llm_api_key)
        readiness_status["component_status"]["llm_consensus"] = {
            "status": "READY" if llm_ready else "NEEDS_KEYS",
            "required": "OPENAI_API_KEY" if not llm_ready else None,
            "description": "OpenAI API key for ChatGPT"
            if not llm_ready
            else "ChatGPT consensus active",
        }
        if not llm_ready:
            readiness_status["missing_requirements"].append("OPENAI_API_KEY")

        opa_ready = False
        if getattr(settings, "OPA_SERVER_URL", None):
            try:
                engine = await get_opa_engine()
                opa_ready = await engine.health_check()
            except Exception as exc:  # pragma: no cover - defensive logging
                logger.warning("OPA health check failed", error=str(exc))

        if not opa_ready:
            readiness_status["component_status"]["policy_engine"] = {
                "status": "NEEDS_SERVER",
                "required": "OPA_SERVER",
                "description": getattr(settings, "OPA_SERVER_URL", "OPA server"),
            }
            readiness_status["missing_requirements"].append("OPA_SERVER")
        else:
            readiness_status["component_status"]["policy_engine"] = {
                "status": "READY",
                "required": None,
                "description": "OPA policy enforcement active",
            }

        # Threat Intelligence Readiness
        threat_intel_ready = bool(settings.THREAT_INTEL_API_KEY)
        readiness_status["component_status"]["threat_intelligence"] = {
            "status": "READY" if threat_intel_ready else "NEEDS_API_KEY",
            "required": "THREAT_INTEL_API_KEY" if not threat_intel_ready else None,
            "description": "Threat intelligence API key"
            if not threat_intel_ready
            else "Real-time threat feeds active",
        }
        if not threat_intel_ready:
            readiness_status["missing_requirements"].append("THREAT_INTEL_API_KEY")

        # Evidence Lake Readiness
        evidence_lake_ready = True  # SQLite database always available
        readiness_status["component_status"]["evidence_lake"] = {
            "status": "READY",
            "required": None,
            "description": "SQLite database active",
        }

        # Overall readiness
        readiness_status["overall_production_ready"] = (
            len(readiness_status["missing_requirements"]) == 0
        )
        readiness_status["production_score"] = max(
            0, 100 - (len(readiness_status["missing_requirements"]) * 20)
        )

        # Quick setup guide
        readiness_status["quick_setup"] = {
            "priority_1": "Set DEMO_MODE=false in environment",
            "priority_2": "Configure OPENAI_API_KEY for ChatGPT consensus",
            "priority_3": "Setup OPA server for policy evaluation",
            "priority_4": "Configure Jira/Confluence for business context",
            "priority_5": "Setup pgvector for vector database",
        }

        return {"status": "success", "data": readiness_status}

    except Exception as e:
        logger.error(f"Production readiness check failed: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/requirements")
async def get_production_requirements():
    """Get detailed production requirements with setup instructions"""
    return {
        "status": "success",
        "requirements": {
            "OPENAI_API_KEY": {
                "component": "ChatGPT Consensus",
                "description": "OpenAI API key powering ChatGPT-based analysis",
                "setup": "Create an API key in the OpenAI console",
                "priority": "HIGH",
            },
            "OPA_SERVER": {
                "component": "Policy Engine",
                "description": "Open Policy Agent server for security policies",
                "setup": "docker run -p 8181:8181 openpolicyagent/opa:latest run --server",
                "priority": "HIGH",
            },
            "JIRA_CREDENTIALS": {
                "component": "Business Context",
                "description": "Jira integration for business impact assessment",
                "setup": "Set JIRA_URL, JIRA_USERNAME, JIRA_API_TOKEN",
                "priority": "MEDIUM",
            },
            "CONFLUENCE_CREDENTIALS": {
                "component": "Threat Models",
                "description": "Confluence integration for threat model retrieval",
                "setup": "Set CONFLUENCE_URL, CONFLUENCE_USERNAME, CONFLUENCE_API_TOKEN",
                "priority": "MEDIUM",
            },
            "PGVECTOR_DSN": {
                "component": "Vector Database",
                "description": "PostgreSQL with pgvector for similarity search",
                "setup": "postgresql+psycopg://user:pass@host:5432/db",
                "priority": "MEDIUM",
            },
            "THREAT_INTEL_API_KEY": {
                "component": "Threat Intelligence",
                "description": "External threat intelligence feeds",
                "setup": "Commercial threat intel provider API key",
                "priority": "LOW",
            },
        },
    }
