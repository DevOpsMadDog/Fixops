"""
User and team management API endpoints with secure authentication.

This module provides production-ready user management with:
- Secure JWT authentication with required secret
- Password hashing with bcrypt
- Role-based access control
- Session management
- Audit logging
"""
import logging
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import jwt
from apps.api.dependencies import get_org_id
from core.persistent_store import get_persistent_store
from core.user_db import UserDB
from core.user_models import User, UserRole, UserStatus
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, EmailStr, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/users", tags=["users"])
public_router = APIRouter(prefix="/api/v1/users", tags=["users-public"])
db = UserDB()


def _get_jwt_secret() -> str:
    """Get JWT secret from environment, raising error if not configured.

    SECURITY: Never use a default secret in production.
    The JWT secret must be:
    - At least 32 characters long
    - Randomly generated
    - Stored securely (environment variable or secrets manager)
    """
    secret = os.environ.get("FIXOPS_JWT_SECRET")
    if not secret:
        raise RuntimeError(
            "FIXOPS_JWT_SECRET environment variable is required. "
            'Generate a secure secret with: python -c "import secrets; print(secrets.token_urlsafe(32))"'
        )
    if len(secret) < 32:
        raise RuntimeError(
            "FIXOPS_JWT_SECRET must be at least 32 characters long for security"
        )
    return secret


JWT_ALGORITHM = "HS256"
JWT_ACCESS_TOKEN_EXPIRE_HOURS = int(os.environ.get("FIXOPS_JWT_EXPIRE_HOURS", "2"))
JWT_REFRESH_TOKEN_EXPIRE_DAYS = int(os.environ.get("FIXOPS_JWT_REFRESH_DAYS", "7"))

# Rate limiting for login attempts — persisted so restarts don't reset lockouts
_login_attempts = get_persistent_store("login_attempts")
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 900  # 15 minutes (AUTH-VULN-08/11)

# AUTH-VULN-06: In-memory short-lived token blocklist for logout revocation
# Maps jti -> expiry timestamp. Pruned on each check to avoid unbounded growth.
_revoked_jtis: Dict[str, float] = {}

# Roles that only admins may assign (AUTHZ-VULN-04)
_PRIVILEGED_ROLES: frozenset = frozenset({"admin", "super_admin"})


def _is_token_revoked(jti: str) -> bool:
    """Return True if the JWT jti is in the revocation blocklist."""
    now = time.time()
    # Prune expired entries
    expired = [k for k, exp in _revoked_jtis.items() if now > exp]
    for k in expired:
        _revoked_jtis.pop(k, None)
    return jti in _revoked_jtis


def _revoke_token(jti: str, exp: float) -> None:
    """Add a jti to the blocklist until its natural expiry."""
    _revoked_jtis[jti] = exp

# Role → JWT scopes mapping (must align with _require_scope in app.py)
_ROLE_SCOPES: Dict[str, List[str]] = {
    "admin": [
        "admin:all",
        "read:findings", "write:findings",
        "read:sbom", "write:sbom",
        "read:users", "write:users",
        "read:policies", "write:policies",
    ],
    "security_analyst": [
        "read:findings", "write:findings",
        "read:sbom",
        "read:users",
        "read:policies", "write:policies",
    ],
    "developer": [
        "read:findings",
        "read:sbom",
    ],
    "viewer": [
        "read:findings",
        "read:sbom",
    ],
}


class LoginRequest(BaseModel):
    """Login request."""

    email: EmailStr
    password: str


class LoginResponse(BaseModel):
    """Login response with JWT token."""

    access_token: str
    token_type: str = "bearer"
    user: Dict[str, Any]


class UserCreate(BaseModel):
    """Request model for creating a user."""

    email: EmailStr = Field(..., description="User email")
    password: str = Field(..., min_length=8, description="User password")
    first_name: str = Field(..., min_length=1, max_length=100)
    last_name: str = Field(..., min_length=1, max_length=100)
    role: UserRole = Field(default=UserRole.VIEWER)
    department: Optional[str] = None


class UserUpdate(BaseModel):
    """Request model for updating a user."""

    first_name: Optional[str] = Field(None, min_length=1, max_length=100)
    last_name: Optional[str] = Field(None, min_length=1, max_length=100)
    role: Optional[UserRole] = None
    status: Optional[UserStatus] = None
    department: Optional[str] = None


class UserResponse(BaseModel):
    """Response model for a user."""

    id: str
    email: str
    first_name: str
    last_name: str
    role: str
    status: str
    department: Optional[str]
    created_at: str
    updated_at: str
    last_login_at: Optional[str]


class PaginatedUserResponse(BaseModel):
    """Paginated user response."""

    items: List[UserResponse]
    total: int
    limit: int
    offset: int


def _check_rate_limit(email: str) -> None:
    """Check if login attempts are rate limited.

    Raises HTTPException if too many failed attempts.
    """
    now = time.time()
    attempts = _login_attempts.get(email, [])

    # Remove old attempts outside the lockout window
    attempts = [t for t in attempts if now - t < LOGIN_LOCKOUT_SECONDS]
    _login_attempts[email] = attempts

    if len(attempts) >= MAX_LOGIN_ATTEMPTS:
        remaining = int(LOGIN_LOCKOUT_SECONDS - (now - attempts[0]))
        raise HTTPException(
            status_code=429,
            detail=f"Too many login attempts. Try again in {remaining} seconds.",
        )


def _record_failed_attempt(email: str) -> None:
    """Record a failed login attempt."""
    attempts = _login_attempts.get(email, [])
    attempts.append(time.time())
    _login_attempts[email] = attempts  # write-through to SQLite


def _clear_failed_attempts(email: str) -> None:
    """Clear failed login attempts after successful login."""
    _login_attempts.pop(email, None)


@public_router.post("/login", response_model=LoginResponse)
async def login(credentials: LoginRequest, request: Request):
    """Authenticate user and return JWT token.

    Features:
    - Rate limiting to prevent brute force attacks
    - Secure JWT token generation
    - Audit logging
    """
    # Check rate limiting
    _check_rate_limit(credentials.email)

    user = db.get_user_by_email(credentials.email)
    if not user or not db.verify_password(credentials.password, user.password_hash):
        _record_failed_attempt(credentials.email)
        logger.warning(
            f"Failed login attempt for email: {credentials.email} "
            f"from IP: {request.client.host if request.client else 'unknown'}"
        )
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if user.status != UserStatus.ACTIVE:
        logger.warning(f"Login attempt for inactive account: {credentials.email}")
        raise HTTPException(status_code=403, detail="Account is not active")

    # Clear failed attempts on successful login
    _clear_failed_attempts(credentials.email)

    user.last_login_at = datetime.now(timezone.utc)
    db.update_user(user)

    # Generate JWT token with secure secret
    jwt_secret = _get_jwt_secret()
    token_id = secrets.token_urlsafe(16)

    # Map role → scopes so the middleware can enforce granular access
    role_scopes = _ROLE_SCOPES.get(user.role.value, ["read:findings"])

    token = jwt.encode(
        {
            "user_id": user.id,
            "email": user.email,
            "role": user.role.value,
            "scopes": role_scopes,
            "jti": token_id,  # JWT ID for token revocation
            "iat": datetime.now(timezone.utc),
            "exp": datetime.now(timezone.utc)
            + timedelta(hours=JWT_ACCESS_TOKEN_EXPIRE_HOURS),
        },
        jwt_secret,
        algorithm=JWT_ALGORITHM,
    )

    logger.info(
        f"Successful login for user: {user.id} "
        f"from IP: {request.client.host if request.client else 'unknown'}"
    )

    return {
        "access_token": token,
        "user": user.to_dict(),
    }


@public_router.post("/logout")
async def logout(request: Request):
    """Logout — revoke the current JWT by adding its jti to the server-side blocklist.

    AUTH-VULN-06: Server-side session revocation on logout.
    """
    auth_header: str = request.headers.get("Authorization", "")
    if not auth_header.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="No Bearer token provided")
    token = auth_header[7:].strip()
    jwt_secret = os.environ.get("FIXOPS_JWT_SECRET", "")
    if not jwt_secret:
        # Dev mode: nothing to revoke
        return {"status": "logged_out"}
    try:
        claims = jwt.decode(
            token,
            jwt_secret,
            algorithms=[JWT_ALGORITHM],
            options={"require": ["exp", "iat"]},
        )
        jti = claims.get("jti")
        exp = claims.get("exp", time.time())
        if jti:
            _revoke_token(jti, float(exp))
        logger.info("User %s logged out, token jti=%s revoked", claims.get("user_id", "unknown"), jti)
    except jwt.ExpiredSignatureError:
        pass  # Already expired — no need to blocklist
    except jwt.InvalidTokenError:
        pass  # Invalid token — ignore
    return {"status": "logged_out"}


@router.get("", response_model=PaginatedUserResponse)
async def list_users(
    org_id: str = Depends(get_org_id),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
):
    """List all users with pagination."""
    users = db.list_users(limit=limit, offset=offset)
    return {
        "items": [UserResponse(**u.to_dict()) for u in users],
        "total": len(users),
        "limit": limit,
        "offset": offset,
    }


@router.post("", response_model=UserResponse, status_code=201)
async def create_user(user_data: UserCreate, request: Request):
    """Create a new user.

    AUTHZ-VULN-04: Only admin/super_admin callers may assign privileged roles.
    Non-admin callers are restricted to non-privileged roles (viewer, developer,
    security_analyst). Assigning admin/super_admin requires admin:all scope.
    """
    # Determine caller's role from request state (set by api_key_auth dependency)
    caller_role: str = getattr(request.state, "user_role", "viewer")
    caller_scopes: list = getattr(request.state, "user_scopes", [])
    is_admin_caller = caller_role in ("admin", "super_admin") or "admin:all" in caller_scopes

    requested_role_value = user_data.role.value if hasattr(user_data.role, "value") else str(user_data.role)
    if requested_role_value in _PRIVILEGED_ROLES and not is_admin_caller:
        raise HTTPException(
            status_code=403,
            detail=f"Insufficient permissions: assigning role '{requested_role_value}' requires admin privileges",
        )

    if db.get_user_by_email(user_data.email):
        raise HTTPException(status_code=409, detail="Email already exists")

    user = User(
        id="",
        email=user_data.email,
        password_hash=db.hash_password(user_data.password),
        first_name=user_data.first_name,
        last_name=user_data.last_name,
        role=user_data.role,
        status=UserStatus.ACTIVE,
        department=user_data.department,
    )
    created_user = db.create_user(user)
    return UserResponse(**created_user.to_dict())


@router.get("/{id}", response_model=UserResponse)
async def get_user(id: str):
    """Get user details by ID."""
    user = db.get_user(id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return UserResponse(**user.to_dict())


@router.put("/{id}", response_model=UserResponse)
async def update_user(id: str, user_data: UserUpdate, request: Request):
    """Update a user.

    AUTHZ-VULN-04: Only admin callers may promote users to privileged roles.
    """
    user = db.get_user(id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user_data.role is not None:
        caller_role: str = getattr(request.state, "user_role", "viewer")
        caller_scopes: list = getattr(request.state, "user_scopes", [])
        is_admin_caller = caller_role in ("admin", "super_admin") or "admin:all" in caller_scopes
        requested_role_value = user_data.role.value if hasattr(user_data.role, "value") else str(user_data.role)
        if requested_role_value in _PRIVILEGED_ROLES and not is_admin_caller:
            raise HTTPException(
                status_code=403,
                detail=f"Insufficient permissions: promoting to role '{requested_role_value}' requires admin privileges",
            )
        user.role = user_data.role

    if user_data.first_name is not None:
        user.first_name = user_data.first_name
    if user_data.last_name is not None:
        user.last_name = user_data.last_name
    if user_data.status is not None:
        user.status = user_data.status
    if user_data.department is not None:
        user.department = user_data.department

    updated_user = db.update_user(user)
    return UserResponse(**updated_user.to_dict())


@router.delete("/{id}", status_code=204)
async def delete_user(id: str):
    """Delete a user."""
    user = db.get_user(id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    db.delete_user(id)
    return None
