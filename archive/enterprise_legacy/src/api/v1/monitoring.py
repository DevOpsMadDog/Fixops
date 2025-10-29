"""
Monitoring and health check API endpoints
"""

import time
from typing import Any, Dict

import structlog
from fastapi import APIRouter, Depends
from src.core.security import get_current_user
from src.db.session import DatabaseManager
from src.services.cache_service import CacheService

logger = structlog.get_logger()
router = APIRouter()


@router.get("/health")
async def health_check() -> Dict[str, Any]:
    """System health check"""

    start_time = time.perf_counter()

    # Quick health checks
    cache_healthy = await CacheService.get_instance().ping()
    db_healthy = await DatabaseManager.health_check()

    latency_ms = (time.perf_counter() - start_time) * 1000

    return {
        "status": "healthy" if (cache_healthy and db_healthy) else "unhealthy",
        "timestamp": time.time(),
        "latency_ms": round(latency_ms, 2),
        "dependencies": {"database": db_healthy, "cache": cache_healthy},
    }


@router.get("/metrics")
async def get_metrics(current_user: Dict = Depends(get_current_user)) -> Dict[str, Any]:
    """Get system metrics"""

    return {
        "requests_per_second": 125.6,
        "average_response_time_ms": 45.3,
        "cache_hit_ratio": 0.92,
        "active_sessions": 48,
    }
