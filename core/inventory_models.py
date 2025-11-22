"""
Database models for FixOps inventory, users, policies, and workflows.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class ApplicationCriticality(str, Enum):
    """Application criticality levels."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ApplicationStatus(str, Enum):
    """Application lifecycle status."""

    ACTIVE = "active"
    DEPRECATED = "deprecated"
    ARCHIVED = "archived"


@dataclass
class Application:
    """Application inventory record."""

    id: str
    name: str
    description: str
    criticality: ApplicationCriticality
    status: ApplicationStatus
    owner_team: Optional[str] = None
    repository_url: Optional[str] = None
    environment: str = "production"
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "criticality": self.criticality.value,
            "status": self.status.value,
            "owner_team": self.owner_team,
            "repository_url": self.repository_url,
            "environment": self.environment,
            "tags": self.tags,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass
class Service:
    """Microservice inventory record."""

    id: str
    name: str
    application_id: str
    description: str
    version: str
    status: str = "active"
    endpoint_url: Optional[str] = None
    repository_url: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "id": self.id,
            "name": self.name,
            "application_id": self.application_id,
            "description": self.description,
            "version": self.version,
            "status": self.status,
            "endpoint_url": self.endpoint_url,
            "repository_url": self.repository_url,
            "tags": self.tags,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass
class APIEndpoint:
    """API endpoint inventory record."""

    id: str
    service_id: str
    path: str
    method: str
    description: str
    is_public: bool = False
    requires_auth: bool = True
    rate_limit: Optional[int] = None
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "id": self.id,
            "service_id": self.service_id,
            "path": self.path,
            "method": self.method,
            "description": self.description,
            "is_public": self.is_public,
            "requires_auth": self.requires_auth,
            "rate_limit": self.rate_limit,
            "tags": self.tags,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass
class Component:
    """Software component (library, package) inventory record."""

    id: str
    application_id: str
    name: str
    version: str
    type: str
    license: Optional[str] = None
    source_url: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "id": self.id,
            "application_id": self.application_id,
            "name": self.name,
            "version": self.version,
            "type": self.type,
            "license": self.license,
            "source_url": self.source_url,
            "metadata": self.metadata,
            "created_at": self.created_at.isoformat(),
        }
