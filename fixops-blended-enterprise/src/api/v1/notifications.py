"""
Notification stubs for pipeline & program alerts
"""
from typing import List, Dict, Any
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import structlog

router = APIRouter(prefix="/notify", tags=["notifications-stub"])
logger = structlog.get_logger()

class DecisionNotification(BaseModel):
    service_name: str
    decision: str
    confidence: float
    stakeholders: List[str] = []
    channels: List[str] = []
    message: str | None = None

@router.post("/decision")
async def notify_decision(payload: DecisionNotification):
    try:
        logger.info("Notify decision", **payload.dict())
        # Stub: integrate Slack/Jira/Email here later
        return {"status": "success", "data": {"notified": True, "channels": payload.channels, "stakeholders": payload.stakeholders}}
    except Exception as e:
        logger.error(f"notify_decision failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))
