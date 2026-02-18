"""
Database models for FixOps integration management.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional


class IntegrationType(str, Enum):
    """Integration types."""

    JIRA = "jira"
    CONFLUENCE = "confluence"
    SLACK = "slack"
    GITHUB = "github"
    GITLAB = "gitlab"
    PAGERDUTY = "pagerduty"
    SERVICENOW = "servicenow"
    AZURE_DEVOPS = "azure_devops"


class IntegrationStatus(str, Enum):
    """Integration status."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"


@dataclass
class Integration:
    """Integration configuration record."""

    id: str
    name: str
    integration_type: IntegrationType
    status: IntegrationStatus
    config: Dict[str, Any] = field(default_factory=dict)
    last_sync_at: Optional[datetime] = None
    last_sync_status: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self, include_secrets: bool = False) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        config = dict(self.config)
        if not include_secrets:
            for key in ["token", "api_key", "password", "secret", "webhook_url"]:
                if key in config:
                    config[key] = "***REDACTED***"

        return {
            "id": self.id,
            "name": self.name,
            "integration_type": self.integration_type.value,
            "status": self.status.value,
            "config": config,
            "last_sync_at": self.last_sync_at.isoformat()
            if self.last_sync_at
            else None,
            "last_sync_status": self.last_sync_status,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
