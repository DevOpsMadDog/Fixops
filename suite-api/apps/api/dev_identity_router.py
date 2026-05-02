"""Dev Identity Router — ALDECI (GAP-016).

Unifies 4 engines for developer-identity behavioral analysis via SCM commit signals:
  - behavioral_analytics_engine — analyze_commit_signals (5 signal types, persistence)
  - uba_engine                   — score_developer_behavior (weighted aggregate)
  - access_anomaly_engine        — record_scm_anomaly (anomaly store)
  - insider_threat_engine        — watchlist (watch/unwatch/list)

Prefix: /api/v1/dev-identity
Auth:   api_key_auth dependency

Routes:
  POST /api/v1/dev-identity/analyze          analyze commit signals
  GET  /api/v1/dev-identity/score            weighted developer risk score
  POST /api/v1/dev-identity/watch            add to watchlist
  POST /api/v1/dev-identity/unwatch          remove from watchlist
  GET  /api/v1/dev-identity/watchlist        list active watched developers
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/dev-identity",
    tags=["Dev Identity Behavioral"],
    dependencies=[Depends(api_key_auth)],
)

# ---------------------------------------------------------------------------
# Lazy engine accessors
# ---------------------------------------------------------------------------

_behavioral = None
_uba = None
_access_anomaly = None
_insider = None


def _get_behavioral():
    global _behavioral
    if _behavioral is None:
        from core.behavioral_analytics_engine import BehavioralAnalyticsEngine
        _behavioral = BehavioralAnalyticsEngine()
    return _behavioral


def _get_uba():
    global _uba
    if _uba is None:
        from core.uba_engine import UBAEngine
        _uba = UBAEngine()
    return _uba


def _get_access_anomaly():
    global _access_anomaly
    if _access_anomaly is None:
        from core.access_anomaly_engine import AccessAnomalyEngine
        _access_anomaly = AccessAnomalyEngine()
    return _access_anomaly


def _get_insider():
    global _insider
    if _insider is None:
        from core.insider_threat_engine import InsiderThreatEngine
        _insider = InsiderThreatEngine()
    return _insider


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class AnalyzeRequest(BaseModel):
    org_id: str = "default"
    author_email: str
    commits: List[Dict[str, Any]] = Field(default_factory=list)
    # If true, also mirror detected signals into access_anomaly_engine
    mirror_to_access_anomaly: bool = True


class WatchRequest(BaseModel):
    org_id: str = "default"
    author_email: str
    reason: str = ""
    watched_by: str = ""


class UnwatchRequest(BaseModel):
    org_id: str = "default"
    author_email: str
    unwatched_by: str = ""


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/analyze")
def analyze_dev_commits(body: AnalyzeRequest) -> Dict[str, Any]:
    """Analyze SCM commits for a developer identity across 5 signal types.

    Persists signals to behavioral commit_signals table. If
    mirror_to_access_anomaly=True, also records each signal into
    access_anomaly_engine.scm_anomaly_signals for cross-engine visibility.
    """
    try:
        result = _get_behavioral().analyze_commit_signals(
            org_id=body.org_id,
            author_email=body.author_email,
            commits=body.commits,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    if body.mirror_to_access_anomaly:
        aa = _get_access_anomaly()
        for sig in result.get("signals", []):
            try:
                aa.record_scm_anomaly(
                    org_id=body.org_id,
                    author_email=body.author_email,
                    anomaly_type=sig["type"],
                    evidence_json={
                        "count": sig["count"],
                        "examples": sig.get("examples", []),
                    },
                )
            except Exception as exc:  # noqa: BLE001
                _logger.warning("mirror_to_access_anomaly failed: %s", exc)

    return result


@router.get("/score")
def score_dev_behavior(
    org_id: str = Query("default"),
    author_email: str = Query(...),
    lookback_days: int = Query(30, ge=1, le=365),
) -> Dict[str, Any]:
    """Compute weighted developer-behavior risk score via UBA engine.

    Reads commit_signals directly from the behavioral_analytics.db (shared DB,
    no cross-engine import).
    """
    try:
        return _get_uba().score_developer_behavior(
            org_id=org_id,
            author_email=author_email,
            lookback_days=lookback_days,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/watch")
def watch_developer(body: WatchRequest) -> Dict[str, Any]:
    """Add a developer to the active watchlist (insider_threat_engine)."""
    try:
        return _get_insider().watch_developer(
            org_id=body.org_id,
            author_email=body.author_email,
            reason=body.reason,
            watched_by=body.watched_by,
        )
    except ValueError as exc:
        # IntegrityError surfaces as ValueError with our engine's wrapper
        raise HTTPException(status_code=409, detail=str(exc))


@router.post("/unwatch")
def unwatch_developer(body: UnwatchRequest) -> Dict[str, Any]:
    """Remove a developer from the active watchlist."""
    try:
        return _get_insider().unwatch_developer(
            org_id=body.org_id,
            author_email=body.author_email,
            unwatched_by=body.unwatched_by,
        )
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/watchlist")
def list_watchlist(
    org_id: str = Query("default"),
    include_inactive: bool = Query(False),
) -> List[Dict[str, Any]]:
    """List watched developers for an org (active only by default)."""
    return _get_insider().list_watched_developers(
        org_id=org_id,
        include_inactive=include_inactive,
    )


@router.get("/health")
def health() -> Dict[str, str]:
    return {"status": "ok", "router": "dev_identity"}


@router.get("/status")
def status() -> Dict[str, str]:
    return {"status": "ok", "router": "dev_identity"}
