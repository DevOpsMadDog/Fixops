"""
User-related Pydantic schemas for API request/response validation
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, EmailStr, Field, validator
from enum import Enum


class UserRole(str, Enum):
    ADMIN = "admin"
    SECURITY_ANALYST = "security_analyst"
    OPERATOR = "operator"
    VIEWER = "viewer"
    COMPLIANCE_OFFICER = "compliance_officer"


class UserStatus(str, Enum):
    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    LOCKED = "locked"
    PENDING_VERIFICATION = "pending_verification"


# Authentication Schemas
class LoginRequest(BaseModel):
    """Login request with optional MFA code"""
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., min_length=8, description="User password")
    mfa_code: Optional[str] = Field(None, regex=r"^\d{6}$", description="6-digit MFA code")


class LoginResponse(BaseModel):
    """Login response with JWT tokens and user info"""
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field(default="bearer", description="Token type")
    expires_in: int = Field(..., description="Token expiration in seconds")
    user: Dict[str, Any] = Field(..., description="User information")


class RefreshTokenRequest(BaseModel):
    """Refresh token request"""
    refresh_token: str = Field(..., description="JWT refresh token")


class MFASetupResponse(BaseModel):
    """MFA setup response with QR code and backup codes"""
    qr_uri: str = Field(..., description="QR code URI for authenticator app")
    secret: str = Field(..., description="TOTP secret key for manual entry")
    backup_codes: List[str] = Field(..., description="Backup recovery codes")


# User Management Schemas
class UserBase(BaseModel):
    """Base user schema with common fields"""
    email: EmailStr = Field(..., description="User email address")
    first_name: str = Field(..., min_length=1, max_length=100, description="First name")
    last_name: str = Field(..., min_length=1, max_length=100, description="Last name")
    username: Optional[str] = Field(None, min_length=3, max_length=50, description="Username")
    phone: Optional[str] = Field(None, regex=r"^\+?[1-9]\d{1,14}$", description="Phone number")
    department: Optional[str] = Field(None, max_length=100, description="Department")
    job_title: Optional[str] = Field(None, max_length=100, description="Job title")


class UserCreate(UserBase):
    """User creation schema"""
    password: str = Field(..., min_length=12, description="User password")
    roles: List[UserRole] = Field(default=[UserRole.VIEWER], description="User roles")
    
    @validator('password')
    def validate_password(cls, v):
        """Validate password strength"""
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in v):
            raise ValueError('Password must contain at least one special character')
        return v


class UserUpdate(BaseModel):
    """User update schema"""
    first_name: Optional[str] = Field(None, min_length=1, max_length=100)
    last_name: Optional[str] = Field(None, min_length=1, max_length=100)
    username: Optional[str] = Field(None, min_length=3, max_length=50)
    phone: Optional[str] = Field(None, regex=r"^\+?[1-9]\d{1,14}$")
    department: Optional[str] = Field(None, max_length=100)
    job_title: Optional[str] = Field(None, max_length=100)
    roles: Optional[List[UserRole]] = None
    status: Optional[UserStatus] = None
    
    # Notification preferences
    notification_email: Optional[bool] = None
    notification_sms: Optional[bool] = None
    notification_slack: Optional[bool] = None


class UserResponse(UserBase):
    """User response schema (excludes sensitive data)"""
    id: str = Field(..., description="User ID")
    status: UserStatus = Field(..., description="User status")
    roles: List[UserRole] = Field(..., description="User roles")
    email_verified: bool = Field(..., description="Email verification status")
    mfa_enabled: bool = Field(..., description="MFA enablement status")
    last_login_at: Optional[datetime] = Field(None, description="Last login timestamp")
    created_at: datetime = Field(..., description="Account creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    
    # Notification preferences
    notification_email: bool = Field(..., description="Email notifications enabled")
    notification_sms: bool = Field(..., description="SMS notifications enabled")
    notification_slack: bool = Field(..., description="Slack notifications enabled")
    
    class Config:
        from_attributes = True


class UserListResponse(BaseModel):
    """Paginated user list response"""
    users: List[UserResponse] = Field(..., description="List of users")
    total: int = Field(..., description="Total number of users")
    page: int = Field(..., description="Current page number")
    size: int = Field(..., description="Number of users per page")
    pages: int = Field(..., description="Total number of pages")


# Session Management Schemas
class UserSession(BaseModel):
    """User session information"""
    id: str = Field(..., description="Session ID")
    ip_address: str = Field(..., description="IP address")
    user_agent: Optional[str] = Field(None, description="User agent string")
    created_at: datetime = Field(..., description="Session creation timestamp")
    last_activity_at: datetime = Field(..., description="Last activity timestamp")
    expires_at: datetime = Field(..., description="Session expiration timestamp")
    is_current: bool = Field(False, description="Is this the current session")


# Password Management Schemas
class ChangePasswordRequest(BaseModel):
    """Password change request"""
    current_password: str = Field(..., description="Current password")
    new_password: str = Field(..., min_length=12, description="New password")
    
    @validator('new_password')
    def validate_new_password(cls, v):
        """Validate new password strength"""
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in v):
            raise ValueError('Password must contain at least one special character')
        return v


class ResetPasswordRequest(BaseModel):
    """Password reset request"""
    email: EmailStr = Field(..., description="User email address")


class ResetPasswordConfirm(BaseModel):
    """Password reset confirmation"""
    token: str = Field(..., description="Password reset token")
    new_password: str = Field(..., min_length=12, description="New password")
    
    @validator('new_password')
    def validate_new_password(cls, v):
        """Validate new password strength"""
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        if not any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?' for c in v):
            raise ValueError('Password must contain at least one special character')
        return v


# Audit and Compliance Schemas
class UserAuditLogEntry(BaseModel):
    """User audit log entry"""
    id: str = Field(..., description="Log entry ID")
    action: str = Field(..., description="Action performed")
    resource: Optional[str] = Field(None, description="Resource affected")
    details: Dict[str, Any] = Field(default_factory=dict, description="Additional details")
    ip_address: str = Field(..., description="IP address")
    success: bool = Field(..., description="Action success status")
    created_at: datetime = Field(..., description="Timestamp")


class SecurityEventRequest(BaseModel):
    """Security event reporting"""
    event_type: str = Field(..., description="Type of security event")
    severity: str = Field(..., description="Event severity")
    description: str = Field(..., description="Event description")
    metadata: Optional[Dict[str, Any]] = Field(None, description="Additional metadata")


# Preferences and Profile Schemas
class UserPreferences(BaseModel):
    """User preferences"""
    timezone: str = Field(default="UTC", description="User timezone")
    language: str = Field(default="en", description="Preferred language")
    theme: str = Field(default="light", description="UI theme preference")
    date_format: str = Field(default="YYYY-MM-DD", description="Date format preference")
    time_format: str = Field(default="24h", description="Time format preference")
    
    # Dashboard preferences
    default_dashboard: str = Field(default="overview", description="Default dashboard view")
    dashboard_refresh_interval: int = Field(default=30, description="Dashboard refresh interval in seconds")
    
    # Notification preferences
    notification_digest: str = Field(default="daily", description="Notification digest frequency")
    notification_quiet_hours_start: Optional[str] = Field(None, description="Quiet hours start time")
    notification_quiet_hours_end: Optional[str] = Field(None, description="Quiet hours end time")


class ProfileUpdateRequest(BaseModel):
    """Profile update request"""
    first_name: Optional[str] = Field(None, min_length=1, max_length=100)
    last_name: Optional[str] = Field(None, min_length=1, max_length=100)
    phone: Optional[str] = Field(None, regex=r"^\+?[1-9]\d{1,14}$")
    department: Optional[str] = Field(None, max_length=100)
    job_title: Optional[str] = Field(None, max_length=100)
    preferences: Optional[UserPreferences] = None


# Role and Permission Schemas
class RolePermission(BaseModel):
    """Role permission definition"""
    permission: str = Field(..., description="Permission name")
    resource: Optional[str] = Field(None, description="Resource type")
    action: str = Field(..., description="Action allowed")
    conditions: Optional[Dict[str, Any]] = Field(None, description="Permission conditions")


class RoleDefinition(BaseModel):
    """Role definition with permissions"""
    role: UserRole = Field(..., description="Role name")
    display_name: str = Field(..., description="Human-readable role name")
    description: str = Field(..., description="Role description")
    permissions: List[RolePermission] = Field(..., description="Role permissions")
    is_system_role: bool = Field(default=False, description="System-defined role")