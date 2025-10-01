"""
Jira/Confluence integration stubs (config-first, no keys required yet)
"""
from fastapi import APIRouter, HTTPException
import structlog
from src.config.settings import get_settings

router = APIRouter(prefix="/integrations", tags=["integrations-stub"])
logger = structlog.get_logger()
settings = get_settings()

@router.get("/jira/status")
async def jira_status():
    try:
        return {
            "status": "success",
            "data": {
                "configured": bool(settings.JIRA_URL),
                "url": settings.JIRA_URL,
                "username_present": bool(settings.JIRA_USERNAME),
                "token_present": bool(settings.JIRA_API_TOKEN),
            }
        }
    except Exception as e:
        logger.error(f"jira_status failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/confluence/status")
async def confluence_status():
    try:
        return {
            "status": "success",
            "data": {
                "configured": bool(settings.CONFLUENCE_URL),
                "url": settings.CONFLUENCE_URL,
                "username_present": bool(settings.CONFLUENCE_USERNAME),
                "token_present": bool(settings.CONFLUENCE_API_TOKEN),
            }
        }
    except Exception as e:
        logger.error(f"confluence_status failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
