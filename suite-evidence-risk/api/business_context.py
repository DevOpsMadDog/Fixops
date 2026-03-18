"""
Business Context Integration API
Connects to Jira, Confluence, and other business systems
"""

from typing import Any, Dict, List

import structlog
from core.enterprise.security import get_current_user
from fastapi import APIRouter, Depends, HTTPException

logger = structlog.get_logger()
router = APIRouter(prefix="/business-context", tags=["business-integration"])


@router.get("/jira-context/{ticket_id}")
async def get_jira_context(
    ticket_id: str, current_user: Dict = Depends(get_current_user)
):
    """Get business context from Jira ticket.

    Requires Jira integration to be configured in Settings → Integrations.
    """
    try:
        from core.connectors import AutomationConnectors
        connectors = AutomationConnectors()
        if hasattr(connectors, "jira") and connectors.jira and getattr(connectors.jira, "configured", False):
            result = connectors.jira.get_issue(ticket_id)
            return {"status": "success", "data": result}
        return {
            "status": "not_configured",
            "message": "Jira integration not configured. Go to Settings → Integrations → Jira to connect.",
            "data": {"ticket_id": ticket_id},
        }
    except ImportError:
        return {
            "status": "not_configured",
            "message": "Jira connector module not available",
            "data": {"ticket_id": ticket_id},
        }
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        logger.error(f"Failed to get Jira context: {str(e)}")
        raise HTTPException(status_code=500, detail=type(e).__name__)


@router.get("/confluence-context/{page_id}")
async def get_confluence_context(
    page_id: str, current_user: Dict = Depends(get_current_user)
):
    """Get threat model and requirements from Confluence.

    Requires Confluence integration to be configured in Settings → Integrations.
    """
    try:
        from core.connectors import AutomationConnectors
        connectors = AutomationConnectors()
        if hasattr(connectors, "confluence") and connectors.confluence and getattr(connectors.confluence, "configured", False):
            result = connectors.confluence.get_page(page_id)
            return {"status": "success", "data": result}
        return {
            "status": "not_configured",
            "message": "Confluence integration not configured. Go to Settings → Integrations → Confluence to connect.",
            "data": {"page_id": page_id},
        }
    except ImportError:
        return {
            "status": "not_configured",
            "message": "Confluence connector module not available",
            "data": {"page_id": page_id},
        }
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        logger.error(f"Failed to get Confluence context: {str(e)}")
        raise HTTPException(status_code=500, detail=type(e).__name__)


@router.post("/enrich-context")
async def enrich_business_context(
    request: Dict[str, Any], current_user: Dict = Depends(get_current_user)
):
    """Enrich security findings with business context"""
    try:
        service_name = request.get("service_name")
        environment = request.get("environment")

        # Business context enrichment logic
        enriched_context = {
            "service_name": service_name,
            "environment": environment,
            "business_impact": _assess_business_impact(service_name),
            "data_sensitivity": _assess_data_sensitivity(service_name),
            "compliance_requirements": _get_compliance_requirements(service_name),
            "stakeholder_impact": _assess_stakeholder_impact(service_name, environment),
        }

        return {"status": "success", "data": enriched_context}

    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        logger.error(f"Failed to enrich business context: {str(e)}")
        raise HTTPException(status_code=500, detail=type(e).__name__)


def _assess_business_impact(service_name: str) -> str:
    """Assess business impact based on service name"""
    if "payment" in service_name.lower():
        return "critical"
    elif "auth" in service_name.lower() or "user" in service_name.lower():
        return "high"
    elif "api" in service_name.lower() or "gateway" in service_name.lower():
        return "medium"
    else:
        return "low"


def _assess_data_sensitivity(service_name: str) -> str:
    """Assess data sensitivity level"""
    if "payment" in service_name.lower():
        return "pii + financial"
    elif "user" in service_name.lower() or "auth" in service_name.lower():
        return "pii"
    else:
        return "internal"


def _get_compliance_requirements(service_name: str) -> List[str]:
    """Get applicable compliance requirements"""
    requirements = ["NIST SSDF", "SOC2"]

    if "payment" in service_name.lower():
        requirements.extend(["PCI DSS", "GDPR"])
    elif "user" in service_name.lower():
        requirements.append("GDPR")

    return requirements


def _assess_stakeholder_impact(service_name: str, environment: str) -> List[str]:
    """Assess which stakeholders are impacted"""
    stakeholders = ["engineering"]

    if environment == "production":
        stakeholders.extend(["product", "compliance"])

    if "payment" in service_name.lower():
        stakeholders.extend(["finance", "legal"])
    elif "user" in service_name.lower():
        stakeholders.append("customer-support")

    return stakeholders
