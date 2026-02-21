"""
Database models for FixOps policy management.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional


class PolicyStatus(str, Enum):
    """Policy status."""

    ACTIVE = "active"
    DRAFT = "draft"
    ARCHIVED = "archived"


@dataclass
class Policy:
    """Security policy record."""

    id: str
    name: str
    description: str
    policy_type: str
    status: PolicyStatus
    rules: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_by: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "policy_type": self.policy_type,
            "status": self.status.value,
            "rules": self.rules,
            "metadata": self.metadata,
            "created_by": self.created_by,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
