"""
User management API endpoints
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Dict, List, Any, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import structlog

from src.db.session import get_db
from src.core.security import get_current_user, require_permission
from src.models.user_sqlite import User
from src.utils.logger import log_security_event

logger = structlog.get_logger()
router = APIRouter()

@router.get("/")
async def list_users(
    db: AsyncSession = Depends(get_db),
    current_user: Dict = Depends(get_current_user),
    _: bool = Depends(require_permission("user.read")),
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000)
) -> Dict[str, Any]:
    """List all users"""
    
    try:
        result = await db.execute(
            select(User).offset(skip).limit(limit)
        )
        users = result.scalars().all()
        
        return {
            "users": [user.to_dict() for user in users],
            "total": len(users)
        }
        
    except Exception as e:
        logger.error(f"Failed to list users: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to list users")

@router.get("/{user_id}")  
async def get_user(
    user_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: Dict = Depends(get_current_user),
    _: bool = Depends(require_permission("user.read"))
) -> Dict[str, Any]:
    """Get user by ID"""
    
    try:
        result = await db.execute(
            select(User).where(User.id == user_id)
        )
        user = result.scalar_one_or_none()
        
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
            
        return user.to_dict()
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get user {user_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to get user")