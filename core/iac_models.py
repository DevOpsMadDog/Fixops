"""
Database models for FixOps IaC scanning.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class IaCProvider(str, Enum):
    """IaC provider types."""

    TERRAFORM = "terraform"
    CLOUDFORMATION = "cloudformation"
    KUBERNETES = "kubernetes"
    ANSIBLE = "ansible"
    HELM = "helm"


class IaCFindingStatus(str, Enum):
    """IaC finding status."""

    OPEN = "open"
    RESOLVED = "resolved"
    SUPPRESSED = "suppressed"


@dataclass
class IaCFinding:
    """IaC security finding."""

    id: str
    provider: IaCProvider
    status: IaCFindingStatus
    severity: str
    title: str
    description: str
    file_path: str
    line_number: int
    resource_type: str
    resource_name: str
    rule_id: str
    remediation: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    detected_at: datetime = field(default_factory=datetime.utcnow)
    resolved_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "id": self.id,
            "provider": self.provider.value,
            "status": self.status.value,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "resource_type": self.resource_type,
            "resource_name": self.resource_name,
            "rule_id": self.rule_id,
            "remediation": self.remediation,
            "metadata": self.metadata,
            "detected_at": self.detected_at.isoformat(),
            "resolved_at": self.resolved_at.isoformat() if self.resolved_at else None,
        }


@dataclass
class IaCScanConfig:
    """Configuration for IaC scanning."""

    id: str
    name: str
    provider: IaCProvider
    enabled: bool
    rules: List[str] = field(default_factory=list)
    exclusions: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "id": self.id,
            "name": self.name,
            "provider": self.provider.value,
            "enabled": self.enabled,
            "rules": self.rules,
            "exclusions": self.exclusions,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
