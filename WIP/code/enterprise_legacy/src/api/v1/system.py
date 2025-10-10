"""
System status and diagnostics endpoints
"""
from fastapi import APIRouter, HTTPException
from datetime import datetime, timezone
import structlog

from src.config.settings import get_settings

router = APIRouter(prefix="/system", tags=["system-status"])
logger = structlog.get_logger()
settings = get_settings()

@router.get("/status")
async def system_status():
    try:
        now = datetime.now(timezone.utc).isoformat()
        return {
            "status": "ok",
            "timestamp": now,
            "app": settings.APP_NAME,
            "version": settings.APP_VERSION,
            "environment": settings.ENVIRONMENT,
            "features": {
                "multi_llm": settings.ENABLE_MULTI_LLM,
                "epss": settings.ENABLED_EPSS,
                "kev": settings.ENABLED_KEV,
                "vex": settings.ENABLED_VEX,
                "rss_sidecar": settings.ENABLED_RSS_SIDECAR,
            }
        }
    except Exception as e:
        logger.error(f"system_status failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
