"""
Enterprise user model with security, compliance, and RBAC
"""

from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional

from core.models.enterprise.base import (
    AuditMixin,
    BaseModel,
    EncryptedFieldMixin,
    SoftDeleteMixin,
)
from sqlalchemy import JSON, Boolean, DateTime
from sqlalchemy import Enum as SQLEnum
from sqlalchemy import Integer, String, Text
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Mapped, mapped_column


class UserStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    LOCKED = "locked"
    PENDING_VERIFICATION = "pending_verification"


class UserRole(str, Enum):
    ADMIN = "admin"
    SECURITY_ANALYST = "security_analyst"
    OPERATOR = "operator"
    VIEWER = "viewer"
    COMPLIANCE_OFFICER = "compliance_officer"


class User(BaseModel, AuditMixin, SoftDeleteMixin, EncryptedFieldMixin):
    """Enterprise user model with comprehensive security features"""

    __tablename__ = "users"

    # Basic user information
    email: Mapped[str] = mapped_column(
        String(255), unique=True, nullable=False, index=True
    )

    username: Mapped[Optional[str]] = mapped_column(
        String(100), unique=True, nullable=True, index=True
    )

    first_name: Mapped[str] = mapped_column(String(100), nullable=False)

    last_name: Mapped[str] = mapped_column(String(100), nullable=False)

    # Authentication
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)

    # Status and roles
    status: Mapped[UserStatus] = mapped_column(
        SQLEnum(UserStatus), default=UserStatus.PENDING_VERIFICATION, nullable=False
    )

    roles: Mapped[List[str]] = mapped_column(
        ARRAY(String(50)), default=[UserRole.VIEWER.value], nullable=False
    )
    tenant_roles: Mapped[Dict[str, List[str]]] = mapped_column(
        JSON,
        default=dict,
        nullable=False,
    )

    # Security settings
    email_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    mfa_secret: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True  # Encrypted TOTP secret
    )

    # Account security
    failed_login_attempts: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False
    )

    last_login_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    last_login_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)

    password_changed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    account_locked_until: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Profile information
    phone: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)

    department: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    job_title: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Notification preferences
    notification_email: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )

    notification_sms: Mapped[bool] = mapped_column(
        Boolean, default=False, nullable=False
    )

    notification_slack: Mapped[bool] = mapped_column(
        Boolean, default=True, nullable=False
    )

    # Compliance and audit
    last_password_reminder: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    terms_accepted_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    privacy_policy_accepted_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    @property
    def full_name(self) -> str:
        """Get user's full name"""
        return f"{self.first_name} {self.last_name}".strip()

    @property
    def is_admin(self) -> bool:
        """Check if user has admin role"""
        return UserRole.ADMIN.value in self.roles

    @property
    def is_locked(self) -> bool:
        """Check if account is currently locked"""
        if self.status == UserStatus.LOCKED:
            return True

        if self.account_locked_until:
            return datetime.utcnow() < self.account_locked_until

        return False

    def has_role(self, role: UserRole) -> bool:
        """Check if user has specific role"""
        return role.value in self.roles

    def get_tenant_roles(self) -> Dict[str, List[str]]:
        """Return tenant role assignments keyed by tenant identifier."""

        if isinstance(self.tenant_roles, dict):
            return {
                str(tenant): [str(role).lower() for role in (roles or [])]
                for tenant, roles in self.tenant_roles.items()
            }
        return {}

    def grant_tenant_role(self, tenant_id: str, role: str) -> None:
        mapping = self.get_tenant_roles()
        roles = set(mapping.get(tenant_id, []))
        roles.add(role.lower())
        mapping[tenant_id] = sorted(roles)
        self.tenant_roles = mapping

    def revoke_tenant_role(self, tenant_id: str, role: str) -> None:
        mapping = self.get_tenant_roles()
        roles = set(mapping.get(tenant_id, []))
        if role.lower() in roles:
            roles.remove(role.lower())
            mapping[tenant_id] = sorted(roles)
            self.tenant_roles = mapping

    def add_role(self, role: UserRole) -> None:
        """Add role to user"""
        if role.value not in self.roles:
            self.roles = self.roles + [role.value]

    def remove_role(self, role: UserRole) -> None:
        """Remove role from user"""
        if role.value in self.roles:
            self.roles = [r for r in self.roles if r != role.value]

    def set_mfa_secret(self, secret: str) -> None:
        """Set encrypted MFA secret"""
        self.set_encrypted_field("mfa_secret", secret)
        self.mfa_enabled = True

    def get_mfa_secret(self) -> Optional[str]:
        """Get decrypted MFA secret"""
        return self.get_encrypted_field("mfa_secret")

    def increment_failed_logins(self) -> None:
        """Increment failed login counter and lock account if needed"""
        self.failed_login_attempts += 1

        # Lock account after 5 failed attempts
        if self.failed_login_attempts >= 5:
            self.status = UserStatus.LOCKED
            self.account_locked_until = datetime.utcnow() + timedelta(minutes=30)

    def reset_failed_logins(self) -> None:
        """Reset failed login counter on successful login"""
        self.failed_login_attempts = 0
        self.account_locked_until = None
        if self.status == UserStatus.LOCKED:
            self.status = UserStatus.ACTIVE

    def record_login(self, ip_address: str) -> None:
        """Record successful login"""
        self.last_login_at = datetime.utcnow()
        self.last_login_ip = ip_address
        self.reset_failed_logins()

    def to_dict(self, include_sensitive: bool = False) -> dict:
        """Convert to dict with optional sensitive data exclusion"""
        result = super().to_dict()

        if not include_sensitive:
            # Remove sensitive fields from API responses
            sensitive_fields = [
                "password_hash",
                "mfa_secret",
                "failed_login_attempts",
                "last_login_ip",
                "created_from_ip",
                "modified_from_ip",
            ]
            for field in sensitive_fields:
                result.pop(field, None)

        return result


class UserSession(BaseModel):
    """User session tracking for security monitoring"""

    __tablename__ = "user_sessions"

    user_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    session_token: Mapped[str] = mapped_column(
        String(255), unique=True, nullable=False, index=True
    )

    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)

    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    last_activity_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )

    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    @property
    def is_expired(self) -> bool:
        """Check if session is expired"""
        return datetime.utcnow() > self.expires_at

    @property
    def is_valid(self) -> bool:
        """Check if session is valid"""
        return not self.is_revoked and not self.is_expired


class UserAuditLog(BaseModel):
    """Comprehensive audit logging for compliance"""

    __tablename__ = "user_audit_logs"

    user_id: Mapped[Optional[str]] = mapped_column(
        String(36), nullable=True, index=True
    )

    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)

    resource: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    resource_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)

    details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    ip_address: Mapped[str] = mapped_column(String(45), nullable=False)

    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    success: Mapped[bool] = mapped_column(Boolean, nullable=False)

    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
