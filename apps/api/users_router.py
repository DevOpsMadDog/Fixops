"""
User and team management API endpoints.
"""
import os
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import jwt
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, EmailStr, Field

from apps.api.dependencies import get_org_id
from core.user_db import UserDB
from core.user_models import User, UserRole, UserStatus

router = APIRouter(prefix="/api/v1/users", tags=["users"])
db = UserDB()

JWT_SECRET = os.getenv("FIXOPS_JWT_SECRET", "demo-secret-key")
JWT_ALGORITHM = "HS256"


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


@router.post("/login", response_model=LoginResponse)
async def login(credentials: LoginRequest):
    """Authenticate user and return JWT token."""
    user = db.get_user_by_email(credentials.email)
    if not user or not db.verify_password(credentials.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    if user.status != UserStatus.ACTIVE:
        raise HTTPException(status_code=403, detail="Account is not active")

    user.last_login_at = datetime.utcnow()
    db.update_user(user)

    token = jwt.encode(
        {
            "user_id": user.id,
            "email": user.email,
            "role": user.role.value,
            "exp": datetime.utcnow() + timedelta(hours=2),
        },
        JWT_SECRET,
        algorithm=JWT_ALGORITHM,
    )

    return {
        "access_token": token,
        "user": user.to_dict(),
    }


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
async def create_user(user_data: UserCreate):
    """Create a new user."""
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
async def update_user(id: str, user_data: UserUpdate):
    """Update a user."""
    user = db.get_user(id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user_data.first_name is not None:
        user.first_name = user_data.first_name
    if user_data.last_name is not None:
        user.last_name = user_data.last_name
    if user_data.role is not None:
        user.role = user_data.role
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
