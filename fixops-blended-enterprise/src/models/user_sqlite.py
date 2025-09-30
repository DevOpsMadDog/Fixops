"""
SQLite-compatible user model with security, compliance, and RBAC
"""

import json
from datetime import datetime, timedelta
from typing import List, Optional
from enum import Enum

from sqlalchemy import Column, String, Boolean, DateTime, Text, Integer
from sqlalchemy.orm import Mapped, mapped_column

from src.models.base_sqlite import BaseModel, AuditMixin, SoftDeleteMixin, EncryptedFieldMixin


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
    """Enterprise user model with comprehensive security features (SQLite compatible)"""
    
    __tablename__ = "users"
    
    # Basic user information
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True
    )
    
    username: Mapped[Optional[str]] = mapped_column(
        String(100),
        unique=True,
        nullable=True,
        index=True
    )
    
    first_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False
    )
    
    last_name: Mapped[str] = mapped_column(
        String(100),
        nullable=False
    )
    
    # Authentication
    password_hash: Mapped[str] = mapped_column(
        Text,
        nullable=False
    )
    
    # Status and roles (JSON as text for SQLite)
    status: Mapped[str] = mapped_column(
        String(50),
        default=UserStatus.PENDING_VERIFICATION.value,
        nullable=False
    )
    
    roles: Mapped[str] = mapped_column(
        Text,  # JSON string in SQLite
        default=json.dumps([UserRole.VIEWER.value]),
        nullable=False
    )
    
    # Security settings
    email_verified: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False
    )
    
    mfa_enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False
    )
    
    mfa_secret: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True  # Encrypted TOTP secret
    )
    
    # Account security
    failed_login_attempts: Mapped[int] = mapped_column(
        Integer,
        default=0,
        nullable=False
    )
    
    last_login_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True
    )
    
    last_login_ip: Mapped[Optional[str]] = mapped_column(
        String(45),
        nullable=True
    )
    
    password_changed_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True
    )
    
    account_locked_until: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True
    )
    
    # Profile information
    phone: Mapped[Optional[str]] = mapped_column(
        String(20),
        nullable=True
    )
    
    department: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True
    )
    
    job_title: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True
    )
    
    # Notification preferences
    notification_email: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False
    )
    
    notification_sms: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False
    )
    
    notification_slack: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False
    )
    
    # Compliance and audit
    last_password_reminder: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True
    )
    
    terms_accepted_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True
    )
    
    privacy_policy_accepted_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True
    )
    
    @property
    def full_name(self) -> str:
        """Get user's full name"""
        return f"{self.first_name} {self.last_name}".strip()
    
    @property
    def is_admin(self) -> bool:
        """Check if user has admin role"""
        return UserRole.ADMIN.value in self.get_roles()
    
    @property
    def is_locked(self) -> bool:
        """Check if account is currently locked"""
        if self.status == UserStatus.LOCKED.value:
            return True
        
        if self.account_locked_until:
            return datetime.utcnow() < self.account_locked_until
        
        return False
    
    def get_roles(self) -> List[str]:
        """Get user roles as list"""
        try:
            return json.loads(self.roles) if self.roles else [UserRole.VIEWER.value]
        except json.JSONDecodeError:
            return [UserRole.VIEWER.value]
    
    def set_roles(self, roles: List[str]) -> None:
        """Set user roles from list"""
        self.roles = json.dumps(roles)
    
    def has_role(self, role: UserRole) -> bool:
        """Check if user has specific role"""
        return role.value in self.get_roles()
    
    def add_role(self, role: UserRole) -> None:
        """Add role to user"""
        current_roles = self.get_roles()
        if role.value not in current_roles:
            current_roles.append(role.value)
            self.set_roles(current_roles)
    
    def remove_role(self, role: UserRole) -> None:
        """Remove role from user"""
        current_roles = self.get_roles()
        if role.value in current_roles:
            current_roles.remove(role.value)
            self.set_roles(current_roles)
    
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
            self.status = UserStatus.LOCKED.value
            self.account_locked_until = datetime.utcnow() + timedelta(minutes=30)
    
    def reset_failed_logins(self) -> None:
        """Reset failed login counter on successful login"""
        self.failed_login_attempts = 0
        self.account_locked_until = None
        if self.status == UserStatus.LOCKED.value:
            self.status = UserStatus.ACTIVE.value
    
    def record_login(self, ip_address: str) -> None:
        """Record successful login"""
        self.last_login_at = datetime.utcnow()
        self.last_login_ip = ip_address
        self.reset_failed_logins()
    
    def to_dict(self, include_sensitive: bool = False) -> dict:
        """Convert to dict with optional sensitive data exclusion"""
        result = {}
        
        # Manually serialize only the required fields to avoid SQLAlchemy metadata issues
        result['id'] = self.id
        result['email'] = self.email
        result['username'] = self.username
        result['first_name'] = self.first_name
        result['last_name'] = self.last_name
        result['status'] = self.status
        result['roles'] = self.get_roles()
        result['email_verified'] = self.email_verified
        result['mfa_enabled'] = self.mfa_enabled
        result['phone'] = self.phone
        result['department'] = self.department
        result['job_title'] = self.job_title
        result['notification_email'] = self.notification_email
        result['notification_sms'] = self.notification_sms
        result['notification_slack'] = self.notification_slack
        result['is_active'] = self.is_active
        result['created_at'] = self.created_at.isoformat() if self.created_at else None
        result['updated_at'] = self.updated_at.isoformat() if self.updated_at else None
        
        if include_sensitive:
            result['failed_login_attempts'] = self.failed_login_attempts
            result['last_login_at'] = self.last_login_at.isoformat() if self.last_login_at else None
            result['last_login_ip'] = self.last_login_ip
            result['password_changed_at'] = self.password_changed_at.isoformat() if self.password_changed_at else None
        
        return result


class UserSession(BaseModel):
    """User session tracking for security monitoring (SQLite compatible)"""
    
    __tablename__ = "user_sessions"
    
    user_id: Mapped[str] = mapped_column(
        String(36),
        nullable=False,
        index=True
    )
    
    session_token: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True
    )
    
    ip_address: Mapped[str] = mapped_column(
        String(45),
        nullable=False
    )
    
    user_agent: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True
    )
    
    expires_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False
    )
    
    last_activity_at: Mapped[datetime] = mapped_column(
        DateTime,
        nullable=False
    )
    
    is_revoked: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False
    )
    
    @property
    def is_expired(self) -> bool:
        """Check if session is expired"""
        return datetime.utcnow() > self.expires_at
    
    @property
    def is_valid(self) -> bool:
        """Check if session is valid"""
        return not self.is_revoked and not self.is_expired


class UserAuditLog(BaseModel):
    """Comprehensive audit logging for compliance (SQLite compatible)"""
    
    __tablename__ = "user_audit_logs"
    
    user_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        nullable=True,
        index=True
    )
    
    action: Mapped[str] = mapped_column(
        String(100),
        nullable=False,
        index=True
    )
    
    resource: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True
    )
    
    resource_id: Mapped[Optional[str]] = mapped_column(
        String(36),
        nullable=True
    )
    
    details: Mapped[Optional[str]] = mapped_column(
        Text,  # JSON as text
        nullable=True
    )
    
    ip_address: Mapped[str] = mapped_column(
        String(45),
        nullable=False
    )
    
    user_agent: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True
    )
    
    success: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False
    )
    
    error_message: Mapped[Optional[str]] = mapped_column(
        Text,
        nullable=True
    )
    
    def get_details(self) -> dict:
        """Get details as dictionary"""
        try:
            return json.loads(self.details) if self.details else {}
        except json.JSONDecodeError:
            return {}
    
    def set_details(self, details: dict) -> None:
        """Set details from dictionary"""
        self.details = json.dumps(details)