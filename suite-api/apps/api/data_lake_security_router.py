"""Data Lake Security Router — ALDECI.

Security posture, access pattern monitoring, and exfiltration risk for
data lakes (S3, GCS, Blob, HDFS, Snowflake, Redshift).

Prefix: /api/v1/data-lake-security
Auth: api_key_auth dependency

Routes:
  POST   /api/v1/data-lake-security/stores                       register_data_store
  GET    /api/v1/data-lake-security/stores                       list_data_stores
  POST   /api/v1/data-lake-security/stores/{store_id}/assess     run_security_assessment
  POST   /api/v1/data-lake-security/stores/{store_id}/access     record_access_pattern
  GET    /api/v1/data-lake-security/stores/{store_id}/access     get_access_patterns
  GET    /api/v1/data-lake-security/stores/{store_id}/exfil-risk detect_data_exfiltration_risk
  GET    /api/v1/data-lake-security/stats                        get_data_lake_stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/data-lake-security",
    tags=["Data Lake Security"],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.data_lake_security_engine import DataLakeSecurityEngine
        _engine = DataLakeSecurityEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------

class DataStoreCreate(BaseModel):
    org_id: str = Field("default")
    name: str
    store_type: str = Field("s3")
    classification: str = Field("internal")
    encryption_at_rest: bool = Field(True)
    access_logging: bool = Field(True)


class AccessPatternCreate(BaseModel):
    org_id: str = Field("default")
    user_or_role: str = Field("")
    access_type: str = Field("read")
    bytes_accessed: int = Field(0)
    is_anomalous: bool = Field(False)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@router.post("/stores", summary="Register data store", dependencies=[Depends(api_key_auth)], status_code=201)
def register_data_store(req: DataStoreCreate) -> Dict[str, Any]:
    """Register a data store with classification and security configuration."""
    try:
        return _get_engine().register_data_store(req.org_id, req.model_dump())
    except Exception as exc:
        _logger.exception("Error registering data store")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/stores", summary="List data stores", dependencies=[Depends(api_key_auth)])
def list_data_stores(
    org_id: str = Query("default"),
    classification: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    """List data stores with optional classification filter."""
    return _get_engine().list_data_stores(org_id, classification=classification)


@router.post(
    "/stores/{store_id}/assess",
    summary="Run security assessment",
    dependencies=[Depends(api_key_auth)],
)
def run_security_assessment(
    store_id: str,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Run a security assessment on a data store. Returns findings and score."""
    try:
        return _get_engine().run_security_assessment(org_id, store_id)
    except Exception as exc:
        _logger.exception("Error running security assessment")
        raise HTTPException(status_code=500, detail=str(exc))


@router.post(
    "/stores/{store_id}/access",
    summary="Record access pattern",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def record_access_pattern(
    store_id: str,
    req: AccessPatternCreate,
) -> Dict[str, Any]:
    """Record an access event for a data store."""
    try:
        return _get_engine().record_access_pattern(req.org_id, store_id, req.model_dump())
    except Exception as exc:
        _logger.exception("Error recording access pattern")
        raise HTTPException(status_code=500, detail=str(exc))


@router.get(
    "/stores/{store_id}/access",
    summary="Get access patterns",
    dependencies=[Depends(api_key_auth)],
)
def get_access_patterns(
    store_id: str,
    org_id: str = Query("default"),
    limit: int = Query(50, ge=1, le=500),
) -> List[Dict[str, Any]]:
    """Return recent access patterns for a data store."""
    return _get_engine().get_access_patterns(org_id, store_id, limit=limit)


@router.get(
    "/stores/{store_id}/exfil-risk",
    summary="Detect data exfiltration risk",
    dependencies=[Depends(api_key_auth)],
)
def detect_data_exfiltration_risk(
    store_id: str,
    org_id: str = Query("default"),
) -> Dict[str, Any]:
    """Compute data exfiltration risk score and indicators."""
    return _get_engine().detect_data_exfiltration_risk(org_id, store_id)


@router.get("/stats", summary="Data lake security stats", dependencies=[Depends(api_key_auth)])
def get_data_lake_stats(org_id: str = Query("default")) -> Dict[str, Any]:
    """Return aggregate data lake security statistics for the org."""
    return _get_engine().get_data_lake_stats(org_id)
