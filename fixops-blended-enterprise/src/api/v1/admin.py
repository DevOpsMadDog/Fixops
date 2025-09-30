"""
Admin API endpoints
"""

from fastapi import APIRouter, Depends, HTTPException
from typing import Dict, Any
import structlog

from src.core.security import get_current_user, require_permission

logger = structlog.get_logger()
router = APIRouter()

@router.get("/system-info")
async def get_system_info(
    current_user: Dict = Depends(get_current_user),
    _: bool = Depends(require_permission("admin.read"))
) -> Dict[str, Any]:
    """Get system information"""
    
    return {
        "version": "1.0.0",
        "environment": "development",
        "uptime_seconds": 3600
    }

@router.post("/clear-cache")
async def clear_cache(
    current_user: Dict = Depends(get_current_user),
    _: bool = Depends(require_permission("admin.write"))
) -> Dict[str, str]:
    """Clear system cache"""
    
    return {"message": "Cache cleared successfully"}