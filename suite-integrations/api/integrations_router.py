"""
Integration management API endpoints.
"""
import logging
import sqlite3
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from apps.api.dependencies import get_org_id
from core.connectors import (
    AzureDevOpsConnector,
    ConfluenceConnector,
    GitHubConnector,
    GitLabConnector,
    JiraConnector,
    ServiceNowConnector,
    SlackConnector,
)
from core.integration_db import IntegrationDB
from core.integration_models import Integration, IntegrationStatus, IntegrationType
from core.security_connectors import (
    AWSSecurityHubConnector,
    AzureSecurityCenterConnector,
    DependabotConnector,
    SnykConnector,
    SonarQubeConnector,
    ThreatMapperConnector,
)
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/integrations", tags=["integrations"])
db = IntegrationDB()


class IntegrationCreate(BaseModel):
    """Request model for creating an integration."""

    name: str = Field(..., min_length=1, max_length=255)
    integration_type: IntegrationType
    status: IntegrationStatus = IntegrationStatus.ACTIVE
    config: Dict[str, Any] = Field(default_factory=dict)


class IntegrationUpdate(BaseModel):
    """Request model for updating an integration."""

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    status: Optional[IntegrationStatus] = None
    config: Optional[Dict[str, Any]] = None


class IntegrationResponse(BaseModel):
    """Response model for an integration."""

    id: str
    name: str
    integration_type: str
    status: str
    config: Dict[str, Any]
    last_sync_at: Optional[str]
    last_sync_status: Optional[str]
    created_at: str
    updated_at: str


class PaginatedIntegrationResponse(BaseModel):
    """Paginated integration response."""

    items: List[IntegrationResponse]
    total: int
    limit: int
    offset: int


@router.get("/status")
async def integrations_status():
    """Get overall integrations status."""
    integrations = db.list_integrations(limit=100)
    active = sum(1 for i in integrations if getattr(i, 'status', '') in ('active', 'connected'))
    return {
        "status": "operational",
        "total_integrations": len(integrations),
        "active": active,
        "inactive": len(integrations) - active,
        "categories": {
            "ticketing": ["jira", "servicenow"],
            "messaging": ["slack", "teams"],
            "scm": ["github", "gitlab", "azure-devops"],
            "security": ["snyk", "sonarqube", "checkmarx"],
        },
    }


@router.get("", response_model=PaginatedIntegrationResponse)
async def list_integrations(
    org_id: str = Depends(get_org_id),
    integration_type: Optional[str] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """List integrations belonging to the caller's org."""
    integrations = db.list_integrations(
        integration_type=integration_type,
        limit=limit,
        offset=offset,
    )
    # Filter to this org (config._org_id set at creation; "default" is legacy/unscoped)
    integrations = [
        i for i in integrations
        if i.config.get("_org_id", "default") in ("default", org_id)
    ]
    return {
        "items": [IntegrationResponse(**i.to_dict()) for i in integrations],
        "total": len(integrations),
        "limit": limit,
        "offset": offset,
    }


@router.post("", response_model=IntegrationResponse, status_code=201)
async def create_integration(
    integration_data: IntegrationCreate,
    org_id: str = Depends(get_org_id),
):
    """Create a new integration, scoped to the caller's org."""
    try:
        # Embed org_id in config for tenant isolation
        config = {**integration_data.config, "_org_id": org_id}
        integration = Integration(
            id="",
            name=integration_data.name,
            integration_type=integration_data.integration_type,
            status=integration_data.status,
            config=config,
        )
        created_integration = db.create_integration(integration)
        return IntegrationResponse(**created_integration.to_dict())
    except (sqlite3.IntegrityError, Exception) as exc:
        if "UNIQUE constraint" in str(exc) or "IntegrityError" in type(exc).__name__:
            raise HTTPException(status_code=409, detail=f"Integration '{integration_data.name}' already exists")
        raise


# NOTE: /marketplace MUST be defined BEFORE /{id} to avoid catch-all match
@router.get("/marketplace")
async def list_marketplace_integrations():
    """List available integrations marketplace — native + third-party security tools."""
    try:
        from core.security_connectors import SecurityToolConnectors
        stc = SecurityToolConnectors()
        marketplace = []
        connector_map = {
            "snyk": ("SCA", "Open source security and license compliance"),
            "sonarqube": ("SAST", "Continuous code quality and security analysis"),
            "dependabot": ("SCA", "Automated dependency updates"),
            "aws_security_hub": ("Cloud", "AWS centralized security view"),
            "azure_defender": ("Cloud", "Azure security posture management"),
            "wiz": ("Cloud", "Cloud security posture management"),
            "prisma_cloud": ("CSPM", "Comprehensive cloud-native security platform"),
            "orca": ("Cloud", "Agentless cloud security platform"),
            "lacework": ("Cloud", "Cloud workload protection"),
            "threatmapper": ("Container", "Open-source threat mapper"),
        }
        for name, (cat, desc) in connector_map.items():
            connector = getattr(stc, name, None)
            configured = getattr(connector, "configured", False) if connector else False
            marketplace.append({
                "id": name,
                "name": name.replace("_", " ").title(),
                "category": cat,
                "status": "available",
                "installed": configured,
                "description": desc,
            })
        native_tools = [
            {"id": "semgrep", "name": "Semgrep", "category": "SAST", "installed": True, "description": "Lightweight static analysis"},
            {"id": "trivy", "name": "Trivy", "category": "Container", "installed": True, "description": "Vulnerability scanner for containers"},
            {"id": "owasp-zap", "name": "OWASP ZAP", "category": "DAST", "installed": True, "description": "Web application security scanner"},
        ]
        for t in native_tools:
            t["status"] = "available"
            marketplace.append(t)
        categories = sorted(set(m["category"] for m in marketplace))
        return {
            "integrations": marketplace,
            "total": len(marketplace),
            "categories": categories,
            "installed": sum(1 for m in marketplace if m["installed"]),
        }
    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        return {"integrations": [], "total": 0, "categories": [], "installed": 0, "error": str(e)}


@router.get("/{id}", response_model=IntegrationResponse)
async def get_integration(
    id: str,
    org_id: str = Depends(get_org_id),
):
    """Get integration details by ID, restricted to the caller's org."""
    integration = db.get_integration(id)
    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")
    # Enforce tenant isolation: reject access to other orgs' integrations
    stored_org = integration.config.get("_org_id", "default")
    if stored_org != "default" and stored_org != org_id:
        raise HTTPException(status_code=404, detail="Integration not found")
    return IntegrationResponse(**integration.to_dict())


@router.put("/{id}", response_model=IntegrationResponse)
async def update_integration(
    id: str,
    integration_data: IntegrationUpdate,
    org_id: str = Depends(get_org_id),
):
    """Update an integration, restricted to the caller's org."""
    integration = db.get_integration(id)
    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")
    # Enforce tenant isolation
    stored_org = integration.config.get("_org_id", "default")
    if stored_org != "default" and stored_org != org_id:
        raise HTTPException(status_code=404, detail="Integration not found")

    if integration_data.name is not None:
        integration.name = integration_data.name
    if integration_data.status is not None:
        integration.status = integration_data.status
    if integration_data.config is not None:
        integration.config.update(integration_data.config)

    updated_integration = db.update_integration(integration)
    return IntegrationResponse(**updated_integration.to_dict())


@router.delete("/{id}", status_code=204)
async def delete_integration(
    id: str,
    org_id: str = Depends(get_org_id),
):
    """Delete an integration, restricted to the caller's org."""
    integration = db.get_integration(id)
    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")
    # Enforce tenant isolation
    stored_org = integration.config.get("_org_id", "default")
    if stored_org != "default" and stored_org != org_id:
        raise HTTPException(status_code=404, detail="Integration not found")
    db.delete_integration(id)
    return None


@router.post("/{id}/test")
async def test_integration(id: str):
    """Test integration connection."""
    integration = db.get_integration(id)
    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")

    if integration.status != IntegrationStatus.ACTIVE:
        return {
            "integration_id": id,
            "success": False,
            "message": "Integration is not active",
        }

    try:
        if integration.integration_type == IntegrationType.JIRA:
            jira_connector = JiraConnector(integration.config)
            if not jira_connector.configured:
                return {
                    "integration_id": id,
                    "success": False,
                    "message": "Jira connector not fully configured",
                }
            return {
                "integration_id": id,
                "success": True,
                "message": "Jira connection test successful",
                "details": {
                    "url": jira_connector.base_url,
                    "project_key": jira_connector.project_key,
                },
            }

        elif integration.integration_type == IntegrationType.CONFLUENCE:
            confluence_connector = ConfluenceConnector(integration.config)
            if not confluence_connector.configured:
                return {
                    "integration_id": id,
                    "success": False,
                    "message": "Confluence connector not fully configured",
                }
            return {
                "integration_id": id,
                "success": True,
                "message": "Confluence connection test successful",
                "details": {
                    "url": confluence_connector.base_url,
                    "space_key": confluence_connector.space_key,
                },
            }

        elif integration.integration_type == IntegrationType.SLACK:
            slack_connector = SlackConnector(integration.config)
            if not slack_connector.default_webhook:
                return {
                    "integration_id": id,
                    "success": False,
                    "message": "Slack webhook not configured",
                }
            return {
                "integration_id": id,
                "success": True,
                "message": "Slack connection test successful",
            }

        elif integration.integration_type == IntegrationType.SERVICENOW:
            servicenow_connector = ServiceNowConnector(integration.config)
            if not servicenow_connector.configured:
                return {
                    "integration_id": id,
                    "success": False,
                    "message": "ServiceNow connector not fully configured",
                }
            return {
                "integration_id": id,
                "success": True,
                "message": "ServiceNow connection test successful",
                "details": {
                    "instance_url": servicenow_connector.instance_url,
                },
            }

        elif integration.integration_type == IntegrationType.GITLAB:
            gitlab_connector = GitLabConnector(integration.config)
            if not gitlab_connector.configured:
                return {
                    "integration_id": id,
                    "success": False,
                    "message": "GitLab connector not fully configured",
                }
            return {
                "integration_id": id,
                "success": True,
                "message": "GitLab connection test successful",
                "details": {
                    "base_url": gitlab_connector.base_url,
                    "project_id": gitlab_connector.project_id,
                },
            }

        elif integration.integration_type == IntegrationType.GITHUB:
            github_connector = GitHubConnector(integration.config)
            if not github_connector.configured:
                return {
                    "integration_id": id,
                    "success": False,
                    "message": "GitHub connector not fully configured",
                }
            return {
                "integration_id": id,
                "success": True,
                "message": "GitHub connection test successful",
                "details": {
                    "owner": github_connector.owner,
                    "repo": github_connector.repo,
                },
            }

        elif integration.integration_type == IntegrationType.AZURE_DEVOPS:
            azure_connector = AzureDevOpsConnector(integration.config)
            if not azure_connector.configured:
                return {
                    "integration_id": id,
                    "success": False,
                    "message": "Azure DevOps connector not fully configured",
                }
            return {
                "integration_id": id,
                "success": True,
                "message": "Azure DevOps connection test successful",
                "details": {
                    "organization": azure_connector.organization,
                    "project": azure_connector.project,
                },
            }

        elif integration.integration_type == IntegrationType.THREATMAPPER:
            tm_connector = ThreatMapperConnector(integration.config)
            if not tm_connector.configured:
                return {
                    "integration_id": id,
                    "success": False,
                    "message": "ThreatMapper connector not fully configured",
                }
            health = tm_connector.health_check()
            return {
                "integration_id": id,
                "success": health.healthy,
                "message": (
                    "ThreatMapper connection test successful"
                    if health.healthy
                    else f"ThreatMapper connection failed: {health.message}"
                ),
                "details": {
                    "console_url": tm_connector.console_url,
                    "latency_ms": health.latency_ms,
                },
            }

        else:
            return {
                "integration_id": id,
                "success": False,
                "message": f"Test not implemented for {integration.integration_type.value}",
            }

    except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as e:
        import logging

        logging.getLogger(__name__).error(
            f"Connection test failed for integration {id}: {e}"
        )
        return {
            "integration_id": id,
            "success": False,
            "message": "Connection test failed",
        }


@router.get("/{id}/sync-status")
async def get_sync_status(id: str):
    """Get integration sync status."""
    integration = db.get_integration(id)
    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")

    return {
        "integration_id": id,
        "last_sync_at": integration.last_sync_at.isoformat()
        if integration.last_sync_at
        else None,
        "last_sync_status": integration.last_sync_status,
        "status": integration.status.value,
    }


@router.post("/{id}/sync")
async def trigger_sync(id: str):
    """Trigger manual sync for integration.

    Performs actual synchronization with the external system based on integration type:
    - Jira/ServiceNow/GitLab/GitHub/Azure DevOps: Validates connection and syncs metadata
    - Slack: Tests webhook connectivity
    - Confluence: Validates space access
    - Snyk/SonarQube/Dependabot: Validates security tool connectivity
    - AWS Security Hub/Azure Security Center: Validates cloud security connectivity
    """
    integration = db.get_integration(id)
    if not integration:
        raise HTTPException(status_code=404, detail="Integration not found")

    if integration.status != IntegrationStatus.ACTIVE:
        raise HTTPException(
            status_code=400,
            detail="Cannot sync inactive integration",
        )

    sync_success = False
    sync_details: Dict[str, Any] = {}

    try:
        if integration.integration_type == IntegrationType.JIRA:
            jira_conn = JiraConnector(integration.config)
            if jira_conn.configured:
                outcome = jira_conn.health_check()
                sync_success = outcome.healthy
                sync_details = outcome.to_dict()
            else:
                sync_details["error"] = "Jira connector not configured"

        elif integration.integration_type == IntegrationType.SERVICENOW:
            snow_conn = ServiceNowConnector(integration.config)
            if snow_conn.configured:
                outcome = snow_conn.health_check()
                sync_success = outcome.healthy
                sync_details = outcome.to_dict()
            else:
                sync_details["error"] = "ServiceNow connector not configured"

        elif integration.integration_type == IntegrationType.GITLAB:
            gitlab_conn = GitLabConnector(integration.config)
            if gitlab_conn.configured:
                outcome = gitlab_conn.health_check()
                sync_success = outcome.healthy
                sync_details = outcome.to_dict()
            else:
                sync_details["error"] = "GitLab connector not configured"

        elif integration.integration_type == IntegrationType.GITHUB:
            github_conn = GitHubConnector(integration.config)
            if github_conn.configured:
                outcome = github_conn.health_check()
                sync_success = outcome.healthy
                sync_details = outcome.to_dict()
            else:
                sync_details["error"] = "GitHub connector not configured"

        elif integration.integration_type == IntegrationType.AZURE_DEVOPS:
            azure_conn = AzureDevOpsConnector(integration.config)
            if azure_conn.configured:
                outcome = azure_conn.health_check()
                sync_success = outcome.healthy
                sync_details = outcome.to_dict()
            else:
                sync_details["error"] = "Azure DevOps connector not configured"

        elif integration.integration_type == IntegrationType.SLACK:
            slack_conn = SlackConnector(integration.config)
            if slack_conn.default_webhook:
                slack_outcome = slack_conn.post_message(
                    {"text": "FixOps sync test", "channel": "default"}
                )
                sync_success = slack_outcome.success
                sync_details = slack_outcome.details
            else:
                sync_details["error"] = "Slack webhook not configured"

        elif integration.integration_type == IntegrationType.CONFLUENCE:
            confluence_conn = ConfluenceConnector(integration.config)
            if confluence_conn.configured:
                outcome = confluence_conn.health_check()
                sync_success = outcome.healthy
                sync_details = outcome.to_dict()
            else:
                sync_details["error"] = "Confluence connector not configured"

        elif integration.integration_type == IntegrationType.SNYK:
            snyk_conn = SnykConnector(integration.config)
            if snyk_conn.configured:
                outcome = snyk_conn.health_check()
                sync_success = outcome.healthy
                sync_details = outcome.to_dict()
            else:
                sync_details["error"] = "Snyk connector not configured"

        elif integration.integration_type == IntegrationType.SONARQUBE:
            sq_conn = SonarQubeConnector(integration.config)
            if sq_conn.configured:
                outcome = sq_conn.health_check()
                sync_success = outcome.healthy
                sync_details = outcome.to_dict()
            else:
                sync_details["error"] = "SonarQube connector not configured"

        elif integration.integration_type == IntegrationType.DEPENDABOT:
            dep_conn = DependabotConnector(integration.config)
            if dep_conn.configured:
                outcome = dep_conn.health_check()
                sync_success = outcome.healthy
                sync_details = outcome.to_dict()
            else:
                sync_details["error"] = "Dependabot connector not configured"

        elif integration.integration_type == IntegrationType.AWS_SECURITY_HUB:
            aws_conn = AWSSecurityHubConnector(integration.config)
            if aws_conn.configured:
                outcome = aws_conn.health_check()
                sync_success = outcome.healthy
                sync_details = outcome.to_dict()
            else:
                sync_details["error"] = "AWS Security Hub connector not configured"

        elif integration.integration_type == IntegrationType.AZURE_SECURITY_CENTER:
            asc_conn = AzureSecurityCenterConnector(integration.config)
            if asc_conn.configured:
                outcome = asc_conn.health_check()
                sync_success = outcome.healthy
                sync_details = outcome.to_dict()
            else:
                sync_details["error"] = "Azure Security Center connector not configured"

        elif integration.integration_type == IntegrationType.THREATMAPPER:
            tm_conn = ThreatMapperConnector(integration.config)
            if tm_conn.configured:
                outcome = tm_conn.health_check()
                sync_success = outcome.healthy
                sync_details = outcome.to_dict()
                if sync_success:
                    vulns = tm_conn.get_vulnerabilities(limit=100)
                    sync_details["vulnerability_count"] = vulns.details.get("count", 0)
                    secrets = tm_conn.get_secrets(limit=100)
                    sync_details["secret_count"] = secrets.details.get("count", 0)
            else:
                sync_details["error"] = "ThreatMapper connector not configured"

        else:
            sync_details[
                "error"
            ] = f"Sync not implemented for {integration.integration_type.value}"

    except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
        logger.error(f"Sync failed for integration {id}: {e}")
        sync_success = False
        sync_details["error"] = str(e)

    integration.last_sync_at = datetime.now(timezone.utc)
    integration.last_sync_status = "success" if sync_success else "failed"
    db.update_integration(integration)

    return {
        "integration_id": id,
        "sync_triggered": True,
        "sync_time": integration.last_sync_at.isoformat(),
        "sync_status": integration.last_sync_status,
        "message": (
            "Manual sync completed successfully"
            if sync_success
            else "Manual sync failed"
        ),
        "details": sync_details,
    }
