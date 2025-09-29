"""
Enterprise authentication endpoints with 299μs hot path optimization
"""

import time
from datetime import datetime, timedelta
from typing import Dict, Any

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import HTTPBearer
import structlog

from src.core.security import (
    PasswordManager, 
    JWTManager, 
    MFAManager,
    get_current_user
)
from src.services.auth_service import AuthService
from src.services.cache_service import CacheService
from src.schemas.user import LoginRequest, LoginResponse, RefreshTokenRequest, MFASetupResponse
from src.utils.logger import log_security_event

logger = structlog.get_logger()
router = APIRouter()
security = HTTPBearer()


@router.post("/login", response_model=LoginResponse, tags=["hot-path"])
async def login(
    login_data: LoginRequest,
    request: Request,
    auth_service: AuthService = Depends(lambda: AuthService())
) -> LoginResponse:
    """
    User authentication - Hot Path Optimized (Target: 299μs)
    Enterprise-grade login with MFA, rate limiting, and audit logging
    """
    start_time = time.perf_counter()
    client_ip = request.client.host
    
    try:
        # Performance-optimized authentication
        auth_result = await auth_service.authenticate_user(
            email=login_data.email,
            password=login_data.password,
            mfa_code=login_data.mfa_code,
            client_ip=client_ip,
            user_agent=request.headers.get("user-agent")
        )
        
        # Log successful authentication
        await log_security_event(
            action="login_success",
            user_id=auth_result["user"]["id"],
            ip_address=client_ip,
            details={"method": "password_mfa" if login_data.mfa_code else "password"}
        )
        
        # Record hot path performance
        latency_us = (time.perf_counter() - start_time) * 1_000_000
        logger.info(
            "Authentication completed",
            user_id=auth_result["user"]["id"],
            latency_us=latency_us,
            method="password_mfa" if login_data.mfa_code else "password"
        )
        
        return LoginResponse(**auth_result)
        
    except HTTPException:
        # Log failed authentication
        await log_security_event(
            action="login_failed",
            user_id=None,
            ip_address=client_ip,
            details={"email": login_data.email, "reason": "invalid_credentials"}
        )
        raise
        
    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        await log_security_event(
            action="login_error",
            user_id=None,
            ip_address=client_ip,
            details={"email": login_data.email, "error": str(e)}
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication service unavailable"
        )


@router.post("/refresh", response_model=LoginResponse, tags=["hot-path"])
async def refresh_token(
    refresh_data: RefreshTokenRequest,
    auth_service: AuthService = Depends(lambda: AuthService())
) -> LoginResponse:
    """
    Token refresh - Hot Path Optimized (Target: 299μs)
    """
    start_time = time.perf_counter()
    
    try:
        # Validate refresh token
        payload = JWTManager.verify_token(refresh_data.refresh_token)
        
        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )
        
        user_id = int(payload["sub"])
        
        # Generate new tokens (optimized path)
        new_tokens = await auth_service.refresh_tokens(user_id)
        
        # Record hot path performance
        latency_us = (time.perf_counter() - start_time) * 1_000_000
        logger.info(
            "Token refresh completed",
            user_id=user_id,
            latency_us=latency_us
        )
        
        return LoginResponse(**new_tokens)
        
    except Exception as e:
        logger.error(f"Token refresh error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid refresh token"
        )


@router.post("/logout")
async def logout(
    current_user: Dict = Depends(get_current_user),
    auth_service: AuthService = Depends(lambda: AuthService())
) -> Dict[str, str]:
    """
    User logout with token invalidation
    """
    user_id = int(current_user["sub"])
    
    # Invalidate all user sessions
    await auth_service.logout_user(user_id)
    
    await log_security_event(
        action="logout",
        user_id=user_id,
        details={"method": "explicit"}
    )
    
    return {"message": "Successfully logged out"}


@router.post("/setup-mfa", response_model=MFASetupResponse)
async def setup_mfa(
    current_user: Dict = Depends(get_current_user),
    auth_service: AuthService = Depends(lambda: AuthService())
) -> MFASetupResponse:
    """
    Setup Multi-Factor Authentication (TOTP)
    """
    user_id = int(current_user["sub"])
    
    mfa_setup = await auth_service.setup_mfa(user_id)
    
    await log_security_event(
        action="mfa_setup",
        user_id=user_id,
        details={"method": "totp"}
    )
    
    return MFASetupResponse(**mfa_setup)


@router.post("/verify-mfa")
async def verify_mfa(
    mfa_code: str,
    current_user: Dict = Depends(get_current_user),
    auth_service: AuthService = Depends(lambda: AuthService())
) -> Dict[str, bool]:
    """
    Verify MFA code
    """
    user_id = int(current_user["sub"])
    
    is_valid = await auth_service.verify_mfa(user_id, mfa_code)
    
    await log_security_event(
        action="mfa_verification",
        user_id=user_id,
        details={"success": is_valid}
    )
    
    return {"valid": is_valid}


@router.get("/me")
async def get_current_user_info(
    current_user: Dict = Depends(get_current_user),
    auth_service: AuthService = Depends(lambda: AuthService())
) -> Dict[str, Any]:
    """
    Get current user information
    """
    user_id = int(current_user["sub"])
    
    user_info = await auth_service.get_user_info(user_id)
    
    return user_info


@router.post("/change-password")
async def change_password(
    old_password: str,
    new_password: str,
    current_user: Dict = Depends(get_current_user),
    auth_service: AuthService = Depends(lambda: AuthService())
) -> Dict[str, str]:
    """
    Change user password
    """
    user_id = int(current_user["sub"])
    
    success = await auth_service.change_password(user_id, old_password, new_password)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid current password"
        )
    
    await log_security_event(
        action="password_change",
        user_id=user_id,
        details={"method": "user_initiated"}
    )
    
    return {"message": "Password changed successfully"}


@router.get("/sessions")
async def get_user_sessions(
    current_user: Dict = Depends(get_current_user),
    auth_service: AuthService = Depends(lambda: AuthService())
) -> Dict[str, Any]:
    """
    Get active user sessions
    """
    user_id = int(current_user["sub"])
    
    sessions = await auth_service.get_user_sessions(user_id)
    
    return {"sessions": sessions}


@router.delete("/sessions/{session_id}")
async def revoke_session(
    session_id: str,
    current_user: Dict = Depends(get_current_user),
    auth_service: AuthService = Depends(lambda: AuthService())
) -> Dict[str, str]:
    """
    Revoke specific user session
    """
    user_id = int(current_user["sub"])
    
    success = await auth_service.revoke_session(user_id, session_id)
    
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found"
        )
    
    await log_security_event(
        action="session_revoked",
        user_id=user_id,
        details={"session_id": session_id}
    )
    
    return {"message": "Session revoked successfully"}