"""FixOps Enterprise Integration Framework

Provides integrations with SIEM, ticketing systems, SCM, CI/CD, and container registries.
Gartner Magic Quadrant #1 ready.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional

import aiohttp

logger = logging.getLogger(__name__)


class IntegrationType(Enum):
    """Integration types."""
    
    SIEM = "siem"
    TICKETING = "ticketing"
    SCM = "scm"
    CICD = "cicd"
    CONTAINER_REGISTRY = "container_registry"
    WEBHOOK = "webhook"


@dataclass
class IntegrationConfig:
    """Integration configuration."""
    
    type: IntegrationType
    name: str
    enabled: bool
    config: Dict[str, Any]
    credentials: Dict[str, str]


class SIEMIntegration:
    """SIEM integration base class."""
    
    async def send_alert(
        self, severity: str, message: str, metadata: Dict[str, Any]
    ) -> bool:
        """Send alert to SIEM."""
        raise NotImplementedError


class SplunkIntegration(SIEMIntegration):
    """Splunk integration."""
    
    def __init__(self, config: IntegrationConfig):
        """Initialize Splunk integration."""
        self.config = config
        self.url = config.config.get("url")
        self.token = config.credentials.get("token")
        self.index = config.config.get("index", "fixops")
    
    async def send_alert(
        self, severity: str, message: str, metadata: Dict[str, Any]
    ) -> bool:
        """Send alert to Splunk."""
        try:
            async with aiohttp.ClientSession() as session:
                payload = {
                    "time": datetime.now(timezone.utc).timestamp(),
                    "host": "fixops",
                    "source": "fixops-api",
                    "sourcetype": "fixops:security",
                    "event": {
                        "severity": severity,
                        "message": message,
                        **metadata,
                    },
                }
                
                async with session.post(
                    f"{self.url}/services/collector/event",
                    headers={"Authorization": f"Splunk {self.token}"},
                    json=payload,
                ) as response:
                    return response.status == 200
        except Exception as e:
            logger.error(f"Splunk integration error: {e}")
            return False


class QRadarIntegration(SIEMIntegration):
    """IBM QRadar integration."""
    
    def __init__(self, config: IntegrationConfig):
        """Initialize QRadar integration."""
        self.config = config
        self.url = config.config.get("url")
        self.token = config.credentials.get("token")
    
    async def send_alert(
        self, severity: str, message: str, metadata: Dict[str, Any]
    ) -> bool:
        """Send alert to QRadar."""
        try:
            async with aiohttp.ClientSession() as session:
                payload = {
                    "qid": metadata.get("qid", "FIXOPS-001"),
                    "category": metadata.get("category", "Security"),
                    "severity": severity,
                    "message": message,
                    **metadata,
                }
                
                async with session.post(
                    f"{self.url}/api/data/integration/events",
                    headers={"SEC": self.token},
                    json=payload,
                ) as response:
                    return response.status == 200
        except Exception as e:
            logger.error(f"QRadar integration error: {e}")
            return False


class TicketingIntegration:
    """Ticketing system integration base class."""
    
    async def create_ticket(
        self, title: str, description: str, priority: str, metadata: Dict[str, Any]
    ) -> Optional[str]:
        """Create ticket in ticketing system."""
        raise NotImplementedError
    
    async def update_ticket(
        self, ticket_id: str, status: str, comment: str
    ) -> bool:
        """Update ticket status."""
        raise NotImplementedError


class JiraIntegration(TicketingIntegration):
    """Jira integration."""
    
    def __init__(self, config: IntegrationConfig):
        """Initialize Jira integration."""
        self.config = config
        self.url = config.config.get("url")
        self.email = config.credentials.get("email")
        self.api_token = config.credentials.get("api_token")
        self.project_key = config.config.get("project_key")
    
    async def create_ticket(
        self, title: str, description: str, priority: str, metadata: Dict[str, Any]
    ) -> Optional[str]:
        """Create Jira ticket."""
        try:
            auth = aiohttp.BasicAuth(self.email, self.api_token)
            
            async with aiohttp.ClientSession(auth=auth) as session:
                payload = {
                    "fields": {
                        "project": {"key": self.project_key},
                        "summary": title,
                        "description": description,
                        "issuetype": {"name": "Bug"},
                        "priority": {"name": priority},
                        **metadata.get("custom_fields", {}),
                    }
                }
                
                async with session.post(
                    f"{self.url}/rest/api/3/issue", json=payload
                ) as response:
                    if response.status == 201:
                        result = await response.json()
                        return result.get("key")
                    return None
        except Exception as e:
            logger.error(f"Jira integration error: {e}")
            return None
    
    async def update_ticket(
        self, ticket_id: str, status: str, comment: str
    ) -> bool:
        """Update Jira ticket."""
        try:
            auth = aiohttp.BasicAuth(self.email, self.api_token)
            
            async with aiohttp.ClientSession(auth=auth) as session:
                # Transition to status
                transitions = await session.get(
                    f"{self.url}/rest/api/3/issue/{ticket_id}/transitions",
                    auth=auth,
                )
                transitions_data = await transitions.json()
                
                transition_id = None
                for t in transitions_data.get("transitions", []):
                    if t["to"]["name"].lower() == status.lower():
                        transition_id = t["id"]
                        break
                
                if transition_id:
                    await session.post(
                        f"{self.url}/rest/api/3/issue/{ticket_id}/transitions",
                        json={"transition": {"id": transition_id}},
                        auth=auth,
                    )
                
                # Add comment
                if comment:
                    await session.post(
                        f"{self.url}/rest/api/3/issue/{ticket_id}/comment",
                        json={"body": comment},
                        auth=auth,
                    )
                
                return True
        except Exception as e:
            logger.error(f"Jira update error: {e}")
            return False


class ServiceNowIntegration(TicketingIntegration):
    """ServiceNow integration."""
    
    def __init__(self, config: IntegrationConfig):
        """Initialize ServiceNow integration."""
        self.config = config
        self.url = config.config.get("url")
        self.username = config.credentials.get("username")
        self.password = config.credentials.get("password")
        self.table = config.config.get("table", "incident")
    
    async def create_ticket(
        self, title: str, description: str, priority: str, metadata: Dict[str, Any]
    ) -> Optional[str]:
        """Create ServiceNow ticket."""
        try:
            auth = aiohttp.BasicAuth(self.username, self.password)
            
            async with aiohttp.ClientSession(auth=auth) as session:
                payload = {
                    "short_description": title,
                    "description": description,
                    "priority": priority,
                    "category": "Security",
                    **metadata,
                }
                
                async with session.post(
                    f"{self.url}/api/now/table/{self.table}", json=payload, auth=auth
                ) as response:
                    if response.status == 201:
                        result = await response.json()
                        return result.get("result", {}).get("sys_id")
                    return None
        except Exception as e:
            logger.error(f"ServiceNow integration error: {e}")
            return None
    
    async def update_ticket(
        self, ticket_id: str, status: str, comment: str
    ) -> bool:
        """Update ServiceNow ticket."""
        try:
            auth = aiohttp.BasicAuth(self.username, self.password)
            
            async with aiohttp.ClientSession(auth=auth) as session:
                payload = {"state": status}
                if comment:
                    payload["comments"] = comment
                
                async with session.patch(
                    f"{self.url}/api/now/table/{self.table}/{ticket_id}",
                    json=payload,
                    auth=auth,
                ) as response:
                    return response.status == 200
        except Exception as e:
            logger.error(f"ServiceNow update error: {e}")
            return False


class SCMIntegration:
    """Source control management integration base class."""
    
    async def create_pull_request(
        self, repo: str, title: str, description: str, branch: str, base: str
    ) -> Optional[str]:
        """Create pull request."""
        raise NotImplementedError
    
    async def get_repository_info(self, repo: str) -> Dict[str, Any]:
        """Get repository information."""
        raise NotImplementedError


class GitHubIntegration(SCMIntegration):
    """GitHub integration."""
    
    def __init__(self, config: IntegrationConfig):
        """Initialize GitHub integration."""
        self.config = config
        self.token = config.credentials.get("token")
        self.base_url = config.config.get("base_url", "https://api.github.com")
    
    async def create_pull_request(
        self, repo: str, title: str, description: str, branch: str, base: str = "main"
    ) -> Optional[str]:
        """Create GitHub pull request."""
        try:
            headers = {
                "Authorization": f"token {self.token}",
                "Accept": "application/vnd.github.v3+json",
            }
            
            async with aiohttp.ClientSession() as session:
                payload = {
                    "title": title,
                    "body": description,
                    "head": branch,
                    "base": base,
                }
                
                async with session.post(
                    f"{self.base_url}/repos/{repo}/pulls",
                    headers=headers,
                    json=payload,
                ) as response:
                    if response.status == 201:
                        result = await response.json()
                        return result.get("html_url")
                    return None
        except Exception as e:
            logger.error(f"GitHub integration error: {e}")
            return None
    
    async def get_repository_info(self, repo: str) -> Dict[str, Any]:
        """Get GitHub repository information."""
        try:
            headers = {
                "Authorization": f"token {self.token}",
                "Accept": "application/vnd.github.v3+json",
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.base_url}/repos/{repo}", headers=headers
                ) as response:
                    if response.status == 200:
                        return await response.json()
                    return {}
        except Exception as e:
            logger.error(f"GitHub repo info error: {e}")
            return {}


class IntegrationManager:
    """Manages all integrations."""
    
    def __init__(self):
        """Initialize integration manager."""
        self.integrations: Dict[str, Any] = {}
    
    def register_integration(
        self, name: str, config: IntegrationConfig, integration: Any
    ) -> None:
        """Register an integration."""
        self.integrations[name] = {
            "config": config,
            "instance": integration,
        }
        logger.info(f"Registered integration: {name} ({config.type.value})")
    
    async def send_alert_to_siem(
        self, severity: str, message: str, metadata: Dict[str, Any]
    ) -> List[bool]:
        """Send alert to all enabled SIEM integrations."""
        results = []
        
        for name, integration_data in self.integrations.items():
            config = integration_data["config"]
            if config.type == IntegrationType.SIEM and config.enabled:
                instance = integration_data["instance"]
                if isinstance(instance, SIEMIntegration):
                    result = await instance.send_alert(severity, message, metadata)
                    results.append(result)
        
        return results
    
    async def create_ticket_in_ticketing(
        self, title: str, description: str, priority: str, metadata: Dict[str, Any]
    ) -> List[Optional[str]]:
        """Create ticket in all enabled ticketing systems."""
        results = []
        
        for name, integration_data in self.integrations.items():
            config = integration_data["config"]
            if config.type == IntegrationType.TICKETING and config.enabled:
                instance = integration_data["instance"]
                if isinstance(instance, TicketingIntegration):
                    result = await instance.create_ticket(
                        title, description, priority, metadata
                    )
                    results.append(result)
        
        return results
