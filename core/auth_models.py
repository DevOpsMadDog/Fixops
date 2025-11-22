"""
Database models for FixOps authentication and SSO/SAML.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional


class AuthProvider(str, Enum):
    """Authentication provider types."""

    LOCAL = "local"
    SAML = "saml"
    OAUTH2 = "oauth2"
    LDAP = "ldap"


class SSOStatus(str, Enum):
    """SSO configuration status."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    PENDING = "pending"


@dataclass
class SSOConfig:
    """SSO configuration record."""

    id: str
    name: str
    provider: AuthProvider
    status: SSOStatus
    metadata: Dict[str, Any] = field(default_factory=dict)
    entity_id: Optional[str] = None
    sso_url: Optional[str] = None
    certificate: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "id": self.id,
            "name": self.name,
            "provider": self.provider.value,
            "status": self.status.value,
            "metadata": self.metadata,
            "entity_id": self.entity_id,
            "sso_url": self.sso_url,
            "certificate": self.certificate,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass
class SAMLAssertion:
    """SAML assertion record."""

    id: str
    user_id: str
    assertion_data: Dict[str, Any]
    issued_at: datetime = field(default_factory=datetime.utcnow)
    expires_at: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            "id": self.id,
            "user_id": self.user_id,
            "assertion_data": self.assertion_data,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }
