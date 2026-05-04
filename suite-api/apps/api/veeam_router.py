"""Veeam Backup Enterprise Manager Router — ALDECI.

Wraps Veeam Backup Enterprise Manager REST v1 surface under prefix
``/api/v1/veeam``:

  - GET  /                                                  capability summary
  - POST /api/oauth2/token                                   OAuth2 token (password / refresh)
  - GET  /api/v1/backupSessions                              session list
  - GET  /api/v1/backupSessions/{session_id}                 single session
  - GET  /api/v1/jobs                                        job list
  - GET  /api/v1/jobs/{job_id}                               single job
  - POST /api/v1/jobs/{job_id}/start                         start job (202)
  - POST /api/v1/jobs/{job_id}/stop                          stop job (202)
  - GET  /api/v1/backups                                     backup list
  - GET  /api/v1/restorePoints?BackupUid=                    restore points
  - GET  /api/v1/managedServers                              managed servers

NO MOCKS rule
-------------
* When any of VEEAM_BASE_URL / VEEAM_USERNAME / VEEAM_PASSWORD is unset:
    - Capability summary surfaces ``status="unavailable"``.
    - All live endpoints return HTTP 503.
* No fabricated payloads.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Body, Depends, Form, HTTPException, Path, Query
from pydantic import BaseModel

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/veeam",
    tags=["Veeam"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Engine accessor (lazy import so tests can patch the singleton)
# ---------------------------------------------------------------------------


def _engine():
    from core.veeam_engine import get_veeam_engine

    return get_veeam_engine()


def _serve(callable_):
    """Run a Veeam call, translating engine errors to HTTP responses.

    VeeamUnavailableError -> 503 (creds missing, network, upstream error)
    ValueError            -> 422 (input validation)
    """
    from core.veeam_engine import VeeamUnavailableError

    try:
        return callable_()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except VeeamUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


# ---------------------------------------------------------------------------
# Capability summary
# ---------------------------------------------------------------------------


@router.get("/", summary="Veeam Backup Enterprise Manager capability summary")
def capability_summary() -> Dict[str, Any]:
    eng = _engine()
    base_ok = eng.base_url_present()
    user_ok = eng.username_present()
    pass_ok = eng.password_present()
    creds = base_ok and user_ok and pass_ok
    return {
        "service": "Veeam Backup Enterprise Manager",
        "endpoints": [
            "/api/oauth2/token",
            "/api/v1/backupSessions",
            "/api/v1/jobs",
            "/api/v1/backups",
            "/api/v1/restorePoints",
            "/api/v1/managedServers",
        ],
        "veeam_base_url_present": base_ok,
        "veeam_username_present": user_ok,
        "veeam_password_present": pass_ok,
        "status": "ok" if creds else "unavailable",
    }


# ---------------------------------------------------------------------------
# OAuth2 token
# ---------------------------------------------------------------------------


@router.post("/api/oauth2/token", summary="Veeam OAuth2 token")
def oauth_token(
    grant_type: str = Form(...),
    username: Optional[str] = Form(default=None),
    password: Optional[str] = Form(default=None),
    refresh_token: Optional[str] = Form(default=None),
) -> Dict[str, Any]:
    if grant_type not in ("password", "refresh_token"):
        raise HTTPException(
            status_code=422,
            detail=f"unsupported grant_type: {grant_type}",
        )
    return _serve(
        lambda: _engine().fetch_token(
            grant_type=grant_type,
            username=username,
            password=password,
            refresh_token=refresh_token,
        )
    )


# ---------------------------------------------------------------------------
# Backup sessions
# ---------------------------------------------------------------------------


@router.get("/api/v1/backupSessions", summary="List backup sessions")
def list_backup_sessions(
    Filter: Optional[str] = Query(default=None, description="CEL-style filter"),
    Skip: Optional[int] = Query(default=None, ge=0),
    Take: Optional[int] = Query(default=None, ge=1, le=10000),
    OrderColumn: Optional[str] = Query(default=None),
    OrderAsc: Optional[bool] = Query(default=None),
) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().backup_sessions(
            filter_=Filter,
            skip=Skip,
            take=Take,
            order_column=OrderColumn,
            order_asc=OrderAsc,
        )
    )


@router.get(
    "/api/v1/backupSessions/{session_id}",
    summary="Single backup session",
)
def get_backup_session(
    session_id: str = Path(..., min_length=1),
) -> Dict[str, Any]:
    return _serve(lambda: _engine().backup_session(session_id))


# ---------------------------------------------------------------------------
# Jobs
# ---------------------------------------------------------------------------


@router.get("/api/v1/jobs", summary="List backup jobs")
def list_jobs(
    Filter: Optional[str] = Query(default=None),
    Skip: Optional[int] = Query(default=None, ge=0),
    Take: Optional[int] = Query(default=None, ge=1, le=10000),
    OrderColumn: Optional[str] = Query(default=None),
    OrderAsc: Optional[bool] = Query(default=None),
) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().jobs(
            filter_=Filter,
            skip=Skip,
            take=Take,
            order_column=OrderColumn,
            order_asc=OrderAsc,
        )
    )


@router.get("/api/v1/jobs/{job_id}", summary="Single backup job")
def get_job(job_id: str = Path(..., min_length=1)) -> Dict[str, Any]:
    return _serve(lambda: _engine().job(job_id))


@router.post("/api/v1/jobs/{job_id}/start", summary="Start backup job", status_code=202)
def start_job(job_id: str = Path(..., min_length=1)) -> Dict[str, Any]:
    return _serve(lambda: _engine().start_job(job_id))


@router.post("/api/v1/jobs/{job_id}/stop", summary="Stop backup job", status_code=202)
def stop_job(job_id: str = Path(..., min_length=1)) -> Dict[str, Any]:
    return _serve(lambda: _engine().stop_job(job_id))


# ---------------------------------------------------------------------------
# Backups
# ---------------------------------------------------------------------------


@router.get("/api/v1/backups", summary="List backups")
def list_backups(
    Filter: Optional[str] = Query(default=None),
    Skip: Optional[int] = Query(default=None, ge=0),
    Take: Optional[int] = Query(default=None, ge=1, le=10000),
) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().backups(filter_=Filter, skip=Skip, take=Take)
    )


# ---------------------------------------------------------------------------
# Restore points
# ---------------------------------------------------------------------------


@router.get("/api/v1/restorePoints", summary="List restore points")
def list_restore_points(
    BackupUid: str = Query(..., min_length=1, description="Backup UID"),
    Skip: Optional[int] = Query(default=None, ge=0),
    Take: Optional[int] = Query(default=None, ge=1, le=10000),
) -> Dict[str, Any]:
    return _serve(
        lambda: _engine().restore_points(
            backup_uid=BackupUid,
            skip=Skip,
            take=Take,
        )
    )


# ---------------------------------------------------------------------------
# Managed servers
# ---------------------------------------------------------------------------


@router.get("/api/v1/managedServers", summary="List managed Veeam servers")
def list_managed_servers(
    Filter: Optional[str] = Query(default=None),
) -> Dict[str, Any]:
    return _serve(lambda: _engine().managed_servers(filter_=Filter))


__all__ = ["router"]
