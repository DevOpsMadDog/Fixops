"""IDE Backend Router — ALDECI (NEW-G071).

Endpoints for the in-browser IDE-style UI backend.

Prefix: /api/v1/ide
Auth:   api_key_auth dependency

Routes:
  POST  /api/v1/ide/tree/build                build_repo_tree
  GET   /api/v1/ide/tree                       get_repo_tree
  GET   /api/v1/ide/file-content               get_file_content
  GET   /api/v1/ide/snapshots                  list_analysis_snapshots
  POST  /api/v1/ide/snapshot                   snapshot_analysis
  GET   /api/v1/ide/snapshots/{id}/replay      replay_snapshot
  POST  /api/v1/ide/snapshots/diff             diff_snapshots
  GET   /api/v1/ide/stats                      stats
  GET   /api/v1/ide/health                     health
  GET   /api/v1/ide/status                     status (alias of health)
"""
from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/ide",
    tags=["IDE Backend"],
    dependencies=[Depends(api_key_auth)],
)

_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.ide_backend_engine import IDEBackendEngine

        _engine = IDEBackendEngine()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class TreeBuildRequest(BaseModel):
    org_id: str = "default"
    repo_ref: str = Field(..., min_length=1, max_length=256)
    root_path: str = Field(..., min_length=1, max_length=4096)
    commit_sha: str = ""


class SnapshotRequest(BaseModel):
    org_id: str = "default"
    repo_ref: str = Field(..., min_length=1, max_length=256)
    scan_id: str = ""


class DiffRequest(BaseModel):
    snapshot_id_a: str = Field(..., min_length=1, max_length=128)
    snapshot_id_b: str = Field(..., min_length=1, max_length=128)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/health")
def health() -> Dict[str, Any]:
    """Liveness probe — engine initialises on first call."""
    try:
        _get_engine()
        return {"status": "ok", "engine": "ide_backend", "version": "v0"}
    except Exception as exc:  # noqa: BLE001 — health endpoints must never raise
        return {"status": "degraded", "engine": "ide_backend", "error": str(exc)}


@router.get("/status")
def status() -> Dict[str, Any]:
    """Alias of /health (enterprise demo requires both)."""
    return health()


@router.post("/tree/build")
def build_repo_tree(body: TreeBuildRequest) -> Dict[str, Any]:
    try:
        return _get_engine().build_repo_tree(
            org_id=body.org_id,
            repo_ref=body.repo_ref,
            root_path=body.root_path,
            commit_sha=body.commit_sha,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        _logger.exception("ide_backend: build_repo_tree failed")
        raise HTTPException(status_code=500, detail=f"build failed: {exc}") from exc


@router.get("/tree")
def get_repo_tree(
    org_id: str = Query("default", min_length=1, max_length=128),
    repo_ref: str = Query(..., min_length=1, max_length=256),
) -> Dict[str, Any]:
    record = _get_engine().get_repo_tree(org_id=org_id, repo_ref=repo_ref)
    if record is None:
        raise HTTPException(status_code=404, detail="tree not found — call /tree/build first")
    return record


@router.get("/file-content")
def get_file_content(
    org_id: str = Query("default", min_length=1, max_length=128),
    repo_ref: str = Query(..., min_length=1, max_length=256),
    path: str = Query(..., min_length=1, max_length=4096),
    root_path: Optional[str] = Query(None, max_length=4096),
) -> Dict[str, Any]:
    try:
        return _get_engine().get_file_content(
            org_id=org_id,
            repo_ref=repo_ref,
            file_path=path,
            root_path=root_path,
        )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        _logger.exception("ide_backend: get_file_content failed")
        raise HTTPException(status_code=500, detail=f"read failed: {exc}") from exc


@router.get("/snapshots")
def list_analysis_snapshots(
    org_id: str = Query("default", min_length=1, max_length=128),
    repo_ref: str = Query(..., min_length=1, max_length=256),
    limit: int = Query(20, ge=1, le=200),
) -> Dict[str, Any]:
    rows = _get_engine().list_analysis_snapshots(
        org_id=org_id, repo_ref=repo_ref, limit=limit
    )
    return {
        "org_id": org_id,
        "repo_ref": repo_ref,
        "count": len(rows),
        "snapshots": rows,
    }


@router.post("/snapshot")
def snapshot_analysis(body: SnapshotRequest) -> Dict[str, Any]:
    try:
        return _get_engine().snapshot_analysis(
            org_id=body.org_id,
            repo_ref=body.repo_ref,
            scan_id=body.scan_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        _logger.exception("ide_backend: snapshot_analysis failed")
        raise HTTPException(status_code=500, detail=f"snapshot failed: {exc}") from exc


@router.get("/snapshots/{snapshot_id}/replay")
def replay_snapshot(snapshot_id: str) -> Dict[str, Any]:
    try:
        return _get_engine().replay_snapshot(snapshot_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        _logger.exception("ide_backend: replay_snapshot failed")
        raise HTTPException(status_code=500, detail=f"replay failed: {exc}") from exc


@router.post("/snapshots/diff")
def diff_snapshots(body: DiffRequest) -> Dict[str, Any]:
    try:
        return _get_engine().diff_snapshots(
            snapshot_id_a=body.snapshot_id_a,
            snapshot_id_b=body.snapshot_id_b,
        )
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        _logger.exception("ide_backend: diff_snapshots failed")
        raise HTTPException(status_code=500, detail=f"diff failed: {exc}") from exc


@router.get("/stats")
def stats(
    org_id: str = Query("default", min_length=1, max_length=128),
) -> Dict[str, Any]:
    return _get_engine().stats(org_id=org_id)
