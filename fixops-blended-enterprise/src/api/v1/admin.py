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
    _: bool = Depends(require_permission("admin.cache"))
):
    """Clear application cache"""
    from src.services.cache_service import CacheService
    cache = CacheService.get_instance()
    await cache.clear()
    return {"message": "Cache cleared successfully"}

@router.post("/set-mode")
async def set_operation_mode(
    request: Dict[str, Any],
    current_user: Dict = Depends(get_current_user),
    _: bool = Depends(require_permission("admin.config"))
):
    """Toggle between demo mode and production mode"""
    try:
        demo_mode = request.get("demo_mode", True)
        
        # Update settings (in real implementation, this would update config file)
        from src.config.settings import get_settings
        settings = get_settings()
        settings.DEMO_MODE = demo_mode
        
        # Reinitialize decision engine with new mode
        from src.services.decision_engine import decision_engine
        await decision_engine.initialize()
        
        mode_name = "DEMO" if demo_mode else "PRODUCTION"
        logger.info(f"Operation mode changed to {mode_name} by {current_user.get('username', 'unknown')}")
        
        return {
            "status": "success",
            "message": f"Mode changed to {mode_name}",
            "demo_mode": demo_mode,
            "effective_immediately": True
        }
        
    except Exception as e:
        logger.error(f"Failed to set operation mode: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))