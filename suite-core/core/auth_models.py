"""
Database models for FixOps authentication, SSO/SAML, users, roles, and API keys.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

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


class UserRole(str, Enum):
    """Built-in user roles."""
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"
    SERVICE = "service"


class APIKeyScope(str, Enum):
    """Granular permission scopes for API keys."""
    READ_SBOM = "read:sbom"
    WRITE_SBOM = "write:sbom"
    READ_FINDINGS = "read:findings"
    WRITE_FINDINGS = "write:findings"
    READ_GRAPH = "read:graph"
    WRITE_GRAPH = "write:graph"
    READ_FEEDS = "read:feeds"
    READ_EVIDENCE = "read:evidence"
    WRITE_EVIDENCE = "write:evidence"
    READ_INTEGRATIONS = "read:integrations"
    WRITE_INTEGRATIONS = "write:integrations"
    ATTACK_EXECUTE = "attack:execute"
    ADMIN_ALL = "admin:all"


# Role → default scopes mapping
ROLE_SCOPES: Dict[UserRole, List[str]] = {
    UserRole.ADMIN: [s.value for s in APIKeyScope],
    UserRole.ANALYST: [
        APIKeyScope.READ_SBOM.value, APIKeyScope.WRITE_SBOM.value,
        APIKeyScope.READ_FINDINGS.value, APIKeyScope.WRITE_FINDINGS.value,
        APIKeyScope.READ_GRAPH.value, APIKeyScope.READ_FEEDS.value,
        APIKeyScope.READ_EVIDENCE.value, APIKeyScope.WRITE_EVIDENCE.value,
        APIKeyScope.READ_INTEGRATIONS.value, APIKeyScope.ATTACK_EXECUTE.value,
    ],
    UserRole.VIEWER: [
        APIKeyScope.READ_SBOM.value, APIKeyScope.READ_FINDINGS.value,
        APIKeyScope.READ_GRAPH.value, APIKeyScope.READ_FEEDS.value,
        APIKeyScope.READ_EVIDENCE.value, APIKeyScope.READ_INTEGRATIONS.value,
    ],
    UserRole.SERVICE: [s.value for s in APIKeyScope],
}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

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
        return {
            "id": self.id, "name": self.name,
            "provider": self.provider.value, "status": self.status.value,
            "metadata": self.metadata, "entity_id": self.entity_id,
            "sso_url": self.sso_url, "certificate": self.certificate,
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
        return {
            "id": self.id, "user_id": self.user_id,
            "assertion_data": self.assertion_data,
            "issued_at": self.issued_at.isoformat(),
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
        }


@dataclass
class User:
    """Platform user."""
    id: str
    email: str
    name: str
    role: UserRole
    password_hash: str = ""
    is_active: bool = True
    org_id: str = "default"
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "email": self.email, "name": self.name,
            "role": self.role.value, "is_active": self.is_active,
            "org_id": self.org_id,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


@dataclass
class APIKey:
    """Scoped API key."""
    id: str
    key_prefix: str          # First 8 chars for identification
    key_hash: str            # bcrypt hash of full key
    user_id: str
    name: str
    scopes: List[str] = field(default_factory=list)
    is_active: bool = True
    expires_at: Optional[datetime] = None
    last_used_at: Optional[datetime] = None
    created_at: datetime = field(default_factory=datetime.utcnow)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id, "key_prefix": self.key_prefix, "name": self.name,
            "user_id": self.user_id, "scopes": self.scopes,
            "is_active": self.is_active,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "last_used_at": self.last_used_at.isoformat() if self.last_used_at else None,
            "created_at": self.created_at.isoformat(),
        }
