"""
Enterprise-grade security components with zero-trust architecture
"""

import asyncio
import hashlib
import secrets
import time
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any

import bcrypt
import jwt
from cryptography.fernet import Fernet
from fastapi import HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
import pyotp
import structlog

from src.config.settings import get_settings
from src.services.cache_service import CacheService
from src.models.user import User
from src.utils.crypto import generate_secure_token

logger = structlog.get_logger()
settings = get_settings()

# Password hashing with enterprise-grade security
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12  # High security rounds
)

# JWT Security
security = HTTPBearer()


class SecurityManager:
    """Enterprise security manager with zero-trust principles"""
    
    _encryption_key: Optional[bytes] = None
    _fernet: Optional[Fernet] = None
    
    @classmethod
    def initialize(cls):
        """Initialize security components"""
        cls._encryption_key = cls._get_encryption_key()
        cls._fernet = Fernet(cls._encryption_key)
        logger.info("Security manager initialized with enterprise encryption")
    
    @classmethod
    def _get_encryption_key(cls) -> bytes:
        """Get or generate encryption key for sensitive data"""
        # In production, this should come from a secure key management service
        key = settings.SECRET_KEY.encode()
        return hashlib.sha256(key).digest()[:32]  # 32 bytes for Fernet
    
    @classmethod
    def encrypt_sensitive_data(cls, data: str) -> str:
        """Encrypt sensitive data (PII, credentials, etc.)"""
        if not cls._fernet:
            raise RuntimeError("Security manager not initialized")
        
        encrypted_data = cls._fernet.encrypt(data.encode())
        return encrypted_data.decode()
    
    @classmethod
    def decrypt_sensitive_data(cls, encrypted_data: str) -> str:
        """Decrypt sensitive data"""
        if not cls._fernet:
            raise RuntimeError("Security manager not initialized")
        
        decrypted_data = cls._fernet.decrypt(encrypted_data.encode())
        return decrypted_data.decode()


class PasswordManager:
    """Enterprise password management with advanced security"""
    
    @staticmethod
    def hash_password(password: str) -> str:
        """Hash password with bcrypt (enterprise-grade)"""
        return pwd_context.hash(password)
    
    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """Verify password against hash"""
        return pwd_context.verify(plain_password, hashed_password)
    
    @staticmethod
    def generate_secure_password(length: int = 16) -> str:
        """Generate cryptographically secure password"""
        return generate_secure_token(length)


class MFAManager:
    """Multi-Factor Authentication management"""
    
    @staticmethod
    def setup_totp(user_id: int, user_email: str) -> Dict[str, Any]:
        """Setup Time-based One-Time Password (TOTP) for user"""
        secret = pyotp.random_base32()
        
        # Generate QR code data
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=user_email,
            issuer_name="FixOps Enterprise"
        )
        
        # Generate backup codes
        backup_codes = [generate_secure_token(8) for _ in range(10)]
        
        return {
            "secret": secret,
            "qr_uri": totp_uri,
            "backup_codes": backup_codes
        }
    
    @staticmethod
    def verify_totp(secret: str, code: str, valid_window: int = 1) -> bool:
        """Verify TOTP code"""
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=valid_window)
    
    @staticmethod
    async def verify_backup_code(user_id: int, code: str) -> bool:
        """Verify backup code (one-time use)"""
        cache = CacheService.get_instance()
        
        # Check if code exists and hasn't been used
        cache_key = f"backup_codes:{user_id}"
        used_codes = await cache.get(cache_key) or []
        
        if code in used_codes:
            return False
        
        # Mark code as used
        used_codes.append(code)
        await cache.set(cache_key, used_codes, ttl=86400 * 365)  # 1 year
        
        return True


class JWTManager:
    """JWT token management with enterprise security"""
    
    @staticmethod
    def create_access_token(data: Dict[str, Any]) -> str:
        """Create JWT access token with security claims"""
        to_encode = data.copy()
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES
        )
        
        # Add security claims
        to_encode.update({
            "exp": expire,
            "iat": datetime.now(timezone.utc),
            "iss": "fixops-enterprise",
            "aud": "fixops-api",
            "jti": generate_secure_token(16)  # JWT ID for tracking
        })
        
        return jwt.encode(
            to_encode,
            settings.SECRET_KEY,
            algorithm=settings.JWT_ALGORITHM
        )
    
    @staticmethod
    def create_refresh_token(user_id: int) -> str:
        """Create refresh token for token renewal"""
        to_encode = {
            "sub": str(user_id),
            "type": "refresh",
            "exp": datetime.now(timezone.utc) + timedelta(
                days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS
            ),
            "iat": datetime.now(timezone.utc),
            "jti": generate_secure_token(16)
        }
        
        return jwt.encode(
            to_encode,
            settings.SECRET_KEY,
            algorithm=settings.JWT_ALGORITHM
        )
    
    @staticmethod
    def verify_token(token: str) -> Dict[str, Any]:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(
                token,
                settings.SECRET_KEY,
                algorithms=[settings.JWT_ALGORITHM],
                audience="fixops-api",
                issuer="fixops-enterprise"
            )
            return payload
        except jwt.ExpiredSignatureError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token has expired"
            )
        except jwt.JWTError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )


class RBACManager:
    """Role-Based Access Control management"""
    
    # Enterprise permission matrix
    PERMISSIONS = {
        "admin": [
            "user.create", "user.read", "user.update", "user.delete",
            "incident.create", "incident.read", "incident.update", "incident.delete",
            "analytics.read", "analytics.export",
            "system.configure", "system.monitor",
            "audit.read", "compliance.manage"
        ],
        "security_analyst": [
            "incident.create", "incident.read", "incident.update",
            "analytics.read", "audit.read",
            "system.monitor"
        ],
        "operator": [
            "incident.create", "incident.read", "incident.update",
            "analytics.read"
        ],
        "viewer": [
            "incident.read", "analytics.read"
        ],
        "compliance_officer": [
            "incident.read", "analytics.read", "analytics.export",
            "audit.read", "compliance.manage"
        ]
    }
    
    @classmethod
    async def check_permission(cls, user_id: int, permission: str) -> bool:
        """Check if user has specific permission"""
        cache = CacheService.get_instance()
        
        # Try cache first for performance
        cache_key = f"user_permissions:{user_id}"
        user_permissions = await cache.get(cache_key)
        
        if user_permissions is None:
            # Load from database (implement based on your user model)
            user_roles = await cls._get_user_roles(user_id)
            user_permissions = []
            
            for role in user_roles:
                user_permissions.extend(cls.PERMISSIONS.get(role, []))
            
            # Cache for performance
            await cache.set(cache_key, list(set(user_permissions)), ttl=300)
        
        return permission in user_permissions
    
    @classmethod
    async def _get_user_roles(cls, user_id: int) -> List[str]:
        """Get user roles from database"""
        # This would be implemented with your actual database logic
        # For now, return a default role
        return ["operator"]  # Replace with actual database query


# FastAPI Dependencies
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict[str, Any]:
    """Get current authenticated user from JWT token"""
    start_time = time.perf_counter()
    
    try:
        # Verify token
        payload = JWTManager.verify_token(credentials.credentials)
        
        # Check token type
        if payload.get("type") == "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Cannot use refresh token for authentication"
            )
        
        # Performance logging for hot path
        latency_us = (time.perf_counter() - start_time) * 1_000_000
        if latency_us > 100:  # Log if auth takes > 100μs
            logger.warning(f"Auth latency high: {latency_us:.2f}μs")
        
        return payload
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials"
        )


def require_permission(permission: str):
    """Dependency to require specific permission"""
    async def permission_checker(current_user: Dict = Depends(get_current_user)) -> bool:
        user_id = int(current_user["sub"])
        
        has_permission = await RBACManager.check_permission(user_id, permission)
        if not has_permission:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions: {permission} required"
            )
        return True
    
    return Depends(permission_checker)
    return permission_checker


# Admin-only dependency
require_admin = require_permission("system.configure")

# Common permission dependencies
require_incident_read = require_permission("incident.read")
require_incident_write = require_permission("incident.create")
require_analytics_read = require_permission("analytics.read")