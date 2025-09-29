"""
Enterprise authentication service with performance optimization and security
"""

import asyncio
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, List, Optional

import structlog
from sqlalchemy import select, update, and_
from sqlalchemy.ext.asyncio import AsyncSession

from src.config.settings import get_settings
from src.core.security import PasswordManager, JWTManager, MFAManager, SecurityManager
from src.db.session import DatabaseManager
from src.models.user import User, UserSession, UserAuditLog, UserStatus
from src.services.cache_service import CacheService
from src.utils.crypto import generate_secure_token

logger = structlog.get_logger()
settings = get_settings()


class AuthService:
    """
    Enterprise authentication service with hot path optimization
    Target: 299μs for authentication operations
    """
    
    def __init__(self):
        self.cache = CacheService.get_instance()
        self.password_manager = PasswordManager()
        self.jwt_manager = JWTManager()
        self.mfa_manager = MFAManager()
    
    async def authenticate_user(
        self,
        email: str,
        password: str,
        mfa_code: Optional[str] = None,
        client_ip: str = "unknown",
        user_agent: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Authenticate user with performance optimization
        Hot Path: Database query + password verification + token generation
        """
        start_time = time.perf_counter()
        
        # Step 1: Get user from cache or database (Target: 50μs from cache, 150μs from DB)
        user = await self._get_user_optimized(email)
        
        if not user:
            # Simulate timing to prevent enumeration attacks
            await asyncio.sleep(0.1)
            raise HTTPException(
                status_code=401,
                detail="Invalid credentials"
            )
        
        # Step 2: Check user status and account locks (Target: 10μs)
        if user.is_locked or user.status != UserStatus.ACTIVE:
            raise HTTPException(
                status_code=401,
                detail="Account is locked or inactive"
            )
        
        # Step 3: Verify password (Target: 80μs with optimized bcrypt)
        password_valid = self.password_manager.verify_password(password, user.password_hash)
        
        if not password_valid:
            await self._handle_failed_login(user, client_ip)
            raise HTTPException(
                status_code=401,
                detail="Invalid credentials"
            )
        
        # Step 4: MFA verification if enabled (Target: 30μs)
        if user.mfa_enabled:
            if not mfa_code:
                raise HTTPException(
                    status_code=401,
                    detail="MFA code required"
                )
            
            mfa_secret = user.get_mfa_secret()
            if not mfa_secret or not self.mfa_manager.verify_totp(mfa_secret, mfa_code):
                await self._handle_failed_login(user, client_ip)
                raise HTTPException(
                    status_code=401,
                    detail="Invalid MFA code"
                )
        
        # Step 5: Generate tokens (Target: 50μs)
        access_token = self.jwt_manager.create_access_token({
            "sub": str(user.id),
            "email": user.email,
            "roles": user.roles
        })
        
        refresh_token = self.jwt_manager.create_refresh_token(user.id)
        
        # Step 6: Update user login info (Background task, doesn't block response)
        asyncio.create_task(self._update_login_info(user, client_ip, user_agent))
        
        # Step 7: Cache user info for future requests (Background task)
        asyncio.create_task(self._cache_user_info(user))
        
        # Record performance
        total_time_us = (time.perf_counter() - start_time) * 1_000_000
        
        if total_time_us > settings.HOT_PATH_TARGET_LATENCY_US:
            logger.warning(
                "Authentication latency exceeded target",
                target_us=settings.HOT_PATH_TARGET_LATENCY_US,
                actual_us=total_time_us,
                user_id=user.id
            )
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "user": user.to_dict()
        }
    
    async def _get_user_optimized(self, email: str) -> Optional[User]:
        """
        Get user with cache-first strategy for hot path performance
        Cache hit: ~5μs, Database query: ~150μs
        """
        # Try cache first
        cache_key = f"user:email:{email}"
        cached_user_data = await self.cache.get(cache_key)
        
        if cached_user_data:
            # Reconstruct user object from cache
            user = User()
            for key, value in cached_user_data.items():
                if hasattr(user, key):
                    setattr(user, key, value)
            return user
        
        # Cache miss - query database
        async with DatabaseManager.get_session_context() as session:
            result = await session.execute(
                select(User).where(
                    and_(
                        User.email == email,
                        User.is_active == True
                    )
                )
            )
            user = result.scalar_one_or_none()
            
            if user:
                # Cache for future requests (TTL: 5 minutes)
                await self.cache.set(cache_key, user.to_dict(include_sensitive=True), ttl=300)
            
            return user
    
    async def _handle_failed_login(self, user: User, client_ip: str) -> None:
        """Handle failed login attempt with rate limiting"""
        # Update failed attempts counter (background task)
        asyncio.create_task(self._increment_failed_attempts(user.id))
        
        # Log security event
        await self._log_security_event(
            action="login_failed",
            user_id=user.id,
            ip_address=client_ip,
            details={"reason": "invalid_credentials"}
        )
    
    async def _increment_failed_attempts(self, user_id: str) -> None:
        """Increment failed login attempts and lock account if necessary"""
        async with DatabaseManager.get_session_context() as session:
            # Get current failed attempts
            result = await session.execute(
                select(User.failed_login_attempts).where(User.id == user_id)
            )
            current_attempts = result.scalar_one_or_none() or 0
            
            new_attempts = current_attempts + 1
            lock_account = new_attempts >= 5
            
            # Update user record
            update_data = {"failed_login_attempts": new_attempts}
            if lock_account:
                update_data.update({
                    "status": UserStatus.LOCKED,
                    "account_locked_until": datetime.utcnow() + timedelta(minutes=30)
                })
            
            await session.execute(
                update(User).where(User.id == user_id).values(**update_data)
            )
            
            # Invalidate cache
            cache_key = f"user:id:{user_id}"
            await self.cache.delete(cache_key)
    
    async def _update_login_info(self, user: User, client_ip: str, user_agent: Optional[str]) -> None:
        """Update user login information (background task)"""
        async with DatabaseManager.get_session_context() as session:
            # Update user login info
            await session.execute(
                update(User).where(User.id == user.id).values(
                    last_login_at=datetime.utcnow(),
                    last_login_ip=client_ip,
                    failed_login_attempts=0,
                    account_locked_until=None
                )
            )
            
            # Create session record
            session_token = generate_secure_token(32)
            user_session = UserSession(
                user_id=user.id,
                session_token=session_token,
                ip_address=client_ip,
                user_agent=user_agent,
                expires_at=datetime.utcnow() + timedelta(days=7),
                last_activity_at=datetime.utcnow()
            )
            session.add(user_session)
    
    async def _cache_user_info(self, user: User) -> None:
        """Cache user information for hot path access"""
        cache_key = f"user:id:{user.id}"
        await self.cache.set(
            cache_key,
            user.to_dict(include_sensitive=True),
            ttl=300  # 5 minutes
        )
    
    async def refresh_tokens(self, user_id: int) -> Dict[str, Any]:
        """
        Refresh JWT tokens - Hot Path Optimized
        """
        # Get user info from cache
        user_data = await self.cache.get(f"user:id:{user_id}")
        
        if not user_data:
            raise HTTPException(status_code=401, detail="User not found")
        
        # Generate new tokens
        access_token = self.jwt_manager.create_access_token({
            "sub": str(user_id),
            "email": user_data["email"],
            "roles": user_data["roles"]
        })
        
        refresh_token = self.jwt_manager.create_refresh_token(user_id)
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "user": user_data
        }
    
    async def logout_user(self, user_id: int) -> None:
        """Logout user by invalidating all sessions"""
        async with DatabaseManager.get_session_context() as session:
            # Revoke all user sessions
            await session.execute(
                update(UserSession)
                .where(UserSession.user_id == str(user_id))
                .values(is_revoked=True)
            )
        
        # Clear cache
        await self.cache.delete(f"user:id:{user_id}")
    
    async def setup_mfa(self, user_id: int) -> Dict[str, Any]:
        """Setup MFA for user"""
        # Get user
        async with DatabaseManager.get_session_context() as session:
            result = await session.execute(
                select(User).where(User.id == str(user_id))
            )
            user = result.scalar_one_or_none()
            
            if not user:
                raise HTTPException(status_code=404, detail="User not found")
            
            # Generate MFA setup
            mfa_setup = self.mfa_manager.setup_totp(user_id, user.email)
            
            # Store encrypted secret
            user.set_mfa_secret(mfa_setup["secret"])
            
            return {
                "qr_uri": mfa_setup["qr_uri"],
                "backup_codes": mfa_setup["backup_codes"],
                "secret": mfa_setup["secret"]  # For manual entry
            }
    
    async def verify_mfa(self, user_id: int, mfa_code: str) -> bool:
        """Verify MFA code"""
        # Get user from cache or database
        user_data = await self.cache.get(f"user:id:{user_id}")
        
        if not user_data or not user_data.get("mfa_enabled"):
            return False
        
        # Get MFA secret (requires database access for decryption)
        async with DatabaseManager.get_session_context() as session:
            result = await session.execute(
                select(User.mfa_secret).where(User.id == str(user_id))
            )
            encrypted_secret = result.scalar_one_or_none()
            
            if not encrypted_secret:
                return False
            
            # Decrypt and verify
            secret = SecurityManager.decrypt_sensitive_data(encrypted_secret)
            return self.mfa_manager.verify_totp(secret, mfa_code)
    
    async def get_user_info(self, user_id: int) -> Dict[str, Any]:
        """Get user information"""
        user_data = await self.cache.get(f"user:id:{user_id}")
        
        if user_data:
            return user_data
        
        # Get from database if not in cache
        async with DatabaseManager.get_session_context() as session:
            result = await session.execute(
                select(User).where(User.id == str(user_id))
            )
            user = result.scalar_one_or_none()
            
            if not user:
                raise HTTPException(status_code=404, detail="User not found")
            
            user_info = user.to_dict()
            
            # Cache for future requests
            await self.cache.set(f"user:id:{user_id}", user_info, ttl=300)
            
            return user_info
    
    async def change_password(self, user_id: int, old_password: str, new_password: str) -> bool:
        """Change user password"""
        async with DatabaseManager.get_session_context() as session:
            result = await session.execute(
                select(User).where(User.id == str(user_id))
            )
            user = result.scalar_one_or_none()
            
            if not user:
                return False
            
            # Verify old password
            if not self.password_manager.verify_password(old_password, user.password_hash):
                return False
            
            # Update password
            new_password_hash = self.password_manager.hash_password(new_password)
            await session.execute(
                update(User)
                .where(User.id == str(user_id))
                .values(
                    password_hash=new_password_hash,
                    password_changed_at=datetime.utcnow()
                )
            )
            
            # Clear cache
            await self.cache.delete(f"user:id:{user_id}")
            
            return True
    
    async def get_user_sessions(self, user_id: int) -> List[Dict[str, Any]]:
        """Get active user sessions"""
        async with DatabaseManager.get_session_context() as session:
            result = await session.execute(
                select(UserSession)
                .where(
                    and_(
                        UserSession.user_id == str(user_id),
                        UserSession.is_revoked == False,
                        UserSession.expires_at > datetime.utcnow()
                    )
                )
            )
            sessions = result.scalars().all()
            
            return [session.to_dict() for session in sessions]
    
    async def revoke_session(self, user_id: int, session_id: str) -> bool:
        """Revoke specific user session"""
        async with DatabaseManager.get_session_context() as session:
            result = await session.execute(
                update(UserSession)
                .where(
                    and_(
                        UserSession.id == session_id,
                        UserSession.user_id == str(user_id)
                    )
                )
                .values(is_revoked=True)
            )
            
            return result.rowcount > 0
    
    async def _log_security_event(
        self,
        action: str,
        user_id: Optional[str] = None,
        ip_address: str = "unknown",
        details: Optional[Dict[str, Any]] = None
    ) -> None:
        """Log security events for audit compliance"""
        async with DatabaseManager.get_session_context() as session:
            audit_log = UserAuditLog(
                user_id=user_id,
                action=action,
                ip_address=ip_address,
                details=details or {},
                success=True  # Adjust based on context
            )
            session.add(audit_log)