"""Composite Alert Router — ALDECI (GAP-052).

Groups anomaly signals (ml_anomalies rows) into composite alert groups
and ingests them into the security_event_correlation pipeline.

Prefix: /api/v1/composite-alerts
Auth:   api_key_auth dependency

Routes:
  POST  /api/v1/composite-alerts/group          group_signals_manual
  POST  /api/v1/composite-alerts/auto-group     auto_group_by_time_window
  GET   /api/v1/composite-alerts/groups         list_groups
  GET   /api/v1/composite-alerts/groups/{id}    get_group
  GET   /api/v1/composite-alerts/stats          stats
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

try:
    from apps.api.auth_deps import api_key_auth as _api_key_auth
    _AUTH_DEP = [Depends(_api_key_auth)]
except ImportError:
    logging.getLogger(__name__).warning(
        "composite_alert_router: auth_deps not available, relying on mount-level auth"
    )
    _AUTH_DEP = []

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/composite-alerts",
    tags=["Composite Alerts"],
    dependencies=_AUTH_DEP,
)

_ml_engine = None
_corr_engine = None


def _get_ml_engine():
    global _ml_engine
    if _ml_engine is None:
        from core.anomaly_ml_engine import AnomalyMLEngine
        _ml_engine = AnomalyMLEngine()
    return _ml_engine


def _get_corr_engine():
    global _corr_engine
    if _corr_engine is None:
        from core.security_event_correlation_engine import (
            SecurityEventCorrelationEngine,
        )
        _corr_engine = SecurityEventCorrelationEngine()
    return _corr_engine


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------


class GroupRequest(BaseModel):
    org_id: str = Field(..., min_length=1, max_length=128)
    signal_ids: List[str] = Field(..., min_length=1)
    group_name: Optional[str] = Field(None, max_length=256)
    ingest_into_correlation: bool = True


class AutoGroupRequest(BaseModel):
    org_id: str = Field(..., min_length=1, max_length=128)
    window_seconds: int = Field(300, ge=10, le=86_400)
    ingest_into_correlation: bool = True


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/group")
def group_signals_manual(payload: GroupRequest) -> Dict[str, Any]:
    """Manually group a list of anomaly signal ids into a composite group."""
    try:
        group = _get_ml_engine().group_signals_into_composite(
            org_id=payload.org_id,
            signal_ids=payload.signal_ids,
            group_name=payload.group_name,
        )
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        _logger.exception("composite_alerts.group failed")
        raise HTTPException(status_code=500, detail=f"group failed: {exc}")

    ingestion: Optional[Dict[str, Any]] = None
    if payload.ingest_into_correlation:
        try:
            ingestion = _get_corr_engine().ingest_composite_group(
                group_id=group["id"], org_id=payload.org_id
            )
        except Exception as exc:
            _logger.warning("composite ingest skipped: %s", exc)
            ingestion = {"error": str(exc)}

    return {"group": group, "ingestion": ingestion}


@router.post("/auto-group")
def auto_group(payload: AutoGroupRequest) -> Dict[str, Any]:
    """Cluster recent anomaly signals by entity+time-bucket and create a
    composite group for any cluster with ≥3 signals."""
    try:
        groups = _get_ml_engine().auto_group_by_time_window(
            org_id=payload.org_id,
            window_seconds=payload.window_seconds,
        )
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        _logger.exception("composite_alerts.auto_group failed")
        raise HTTPException(status_code=500, detail=f"auto_group failed: {exc}")

    ingestions: List[Dict[str, Any]] = []
    if payload.ingest_into_correlation and groups:
        corr = _get_corr_engine()
        for group in groups:
            try:
                ingestions.append(
                    corr.ingest_composite_group(
                        group_id=group["id"], org_id=payload.org_id
                    )
                )
            except Exception as exc:
                _logger.warning("composite ingest skipped: %s", exc)
                ingestions.append({"error": str(exc), "group_id": group.get("id")})

    return {"groups": groups, "group_count": len(groups), "ingestions": ingestions}


@router.get("/groups")
def list_groups(
    org_id: str = Query(..., min_length=1),
    limit: int = Query(50, ge=1, le=500),
) -> Dict[str, Any]:
    """List composite alert groups for an org."""
    try:
        groups = _get_ml_engine().list_composite_groups(org_id=org_id, limit=limit)
    except Exception as exc:
        _logger.exception("composite_alerts.list failed")
        raise HTTPException(status_code=500, detail=f"list failed: {exc}")
    return {"groups": groups, "count": len(groups)}


@router.get("/groups/{group_id}")
def get_group(group_id: str) -> Dict[str, Any]:
    """Fetch a single composite group by id, with its member signal ids."""
    try:
        group = _get_ml_engine().get_composite_group(group_id)
    except Exception as exc:
        _logger.exception("composite_alerts.get failed")
        raise HTTPException(status_code=500, detail=f"get failed: {exc}")
    if group is None:
        raise HTTPException(status_code=404, detail="group not found")
    return group


@router.get("/stats")
def stats(org_id: str = Query(..., min_length=1)) -> Dict[str, Any]:
    """Aggregate stats for composite alert groups belonging to an org."""
    try:
        groups = _get_ml_engine().list_composite_groups(org_id=org_id, limit=500)
    except Exception as exc:
        _logger.exception("composite_alerts.stats failed")
        raise HTTPException(status_code=500, detail=f"stats failed: {exc}")

    total = len(groups)
    total_signals = sum(int(g.get("signal_count", 0)) for g in groups)
    if total:
        avg_score = round(
            sum(float(g.get("correlation_score", 0.0)) for g in groups) / total, 4
        )
        max_score = max(float(g.get("correlation_score", 0.0)) for g in groups)
    else:
        avg_score = 0.0
        max_score = 0.0

    return {
        "org_id": org_id,
        "group_count": total,
        "total_grouped_signals": total_signals,
        "avg_correlation_score": avg_score,
        "max_correlation_score": max_score,
    }
