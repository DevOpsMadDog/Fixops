"""
Database models for FixOps users, teams, and RBAC.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional


class UserRole(str, Enum):
    """User roles for RBAC."""

    ADMIN = "admin"
    SECURITY_ANALYST = "security_analyst"
    DEVELOPER = "developer"
    VIEWER = "viewer"


class UserStatus(str, Enum):
    """User account status."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"


@dataclass
class User:
    """User account record."""

    id: str
    email: str
    password_hash: str
    first_name: str
    last_name: str
    role: UserRole
    status: UserStatus = UserStatus.ACTIVE
    department: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    last_login_at: Optional[datetime] = None

    def to_dict(self, include_password: bool = False) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        result = {
            "id": self.id,
            "email": self.email,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "role": self.role.value,
            "status": self.status.value,
            "department": self.department,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "last_login_at": self.last_login_at.isoformat()
            if self.last_login_at
            else None,
        }
        if include_password:
            result["password_hash"] = self.password_hash
        return result


@dataclass
class Team:
    """Team record for organizing users."""

    id: str
    name: str
    description: str
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass
class TeamMember:
    """Team membership record."""

    team_id: str
    user_id: str
    role: str = "member"
    added_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "team_id": self.team_id,
            "user_id": self.user_id,
            "role": self.role,
            "added_at": self.added_at.isoformat(),
        }
