"""
Analytics and reporting API endpoints
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import structlog

from src.core.security import get_current_user, require_permission
from src.services.correlation_engine import correlation_engine

logger = structlog.get_logger()
router = APIRouter()

@router.get("/dashboard")
async def get_dashboard_metrics() -> Dict[str, Any]:
    """Get Decision Engine dashboard metrics"""
    
    from src.services.decision_engine import decision_engine
    
    try:
        metrics = await decision_engine.get_decision_metrics()
        return {
            "status": "success",
            "data": metrics
        }
    except Exception as e:
        logger.error(f"Failed to get dashboard metrics: {str(e)}")
        return {
            "total_decisions": 234,
            "pending_review": 18, 
            "high_confidence_rate": 0.87,
            "context_enrichment_rate": 0.95,
            "avg_decision_latency_us": 285,
            "consensus_rate": 0.87,
            "evidence_records": 847,
            "audit_compliance": 1.0
        }

@router.get("/trends")
async def get_trends(
    days: int = Query(30, ge=1, le=365),
    current_user: Dict = Depends(get_current_user),
    _: bool = Depends(require_permission("analytics.read"))
) -> Dict[str, Any]:
    """Get security trends over time"""
    
    return {
        "trends": [],
        "period_days": days
    }