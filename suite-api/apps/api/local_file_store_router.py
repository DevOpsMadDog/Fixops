"""Local File Store Router — ALDECI (GAP-064).

Thin FastAPI wrapper over :class:`core.local_file_store_engine.LocalFileStoreEngine`
so the UI / CLI can drive a local `.fixops/` JSON store without Postgres/Redis.

Prefix: /api/v1/local-store
Auth:   api_key_auth dependency on every route.

Endpoints:
  POST  /api/v1/local-store/acquire-lock   acquire an exclusive lock on a repo
  POST  /api/v1/local-store/release-lock   release a previously-acquired lock
  POST  /api/v1/local-store/save-analysis  save an analysis payload atomically
  GET   /api/v1/local-store/latest         read the LATEST.json payload
  GET   /api/v1/local-store/history        list history descriptors
  GET   /api/v1/local-store/config         read config.json
  POST  /api/v1/local-store/config         write config.json
  DELETE /api/v1/local-store/config        clear config (equivalent to write({}))
  DELETE /api/v1/local-store/clear         delete the entire `.fixops/` subtree

The router takes ``repo_path`` as a body or query parameter — callers running
the CLI locally pass the cwd / target repository path. No org_id: this is a
zero-server, single-user local mode.
"""
from __future__ import annotations

import base64
import binascii
import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/local-store",
    tags=["Local File Store"],
)

# Lazily-instantiated engine so test isolation works via monkeypatch
_engine = None


def _get_engine():
    global _engine
    if _engine is None:
        from core.local_file_store_engine import get_engine as _ge
        _engine = _ge()
    return _engine


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class AcquireLockRequest(BaseModel):
    repo_path: str = Field(..., min_length=1, description="Absolute path to repo root")
    timeout: float = Field(default=30.0, ge=0.0, le=3600.0)


class ReleaseLockRequest(BaseModel):
    repo_path: str = Field(..., min_length=1)
    owner_token: Optional[str] = Field(default=None, description="Token returned from acquire-lock")


class SaveAnalysisRequest(BaseModel):
    """Payload for save-analysis.

    One of ``payload`` (JSON dict) or ``payload_base64`` (base64-encoded
    UTF-8 JSON) must be supplied. ``payload_base64`` is provided so clients
    that need to send multipart-adjacent content (raw scanner output) can
    wrap it without escaping. The server always stores the decoded dict.
    """

    repo_path: str = Field(..., min_length=1)
    payload: Optional[Dict[str, Any]] = None
    payload_base64: Optional[str] = None


class WriteConfigRequest(BaseModel):
    repo_path: str = Field(..., min_length=1)
    config: Dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Endpoints — lock
# ---------------------------------------------------------------------------


@router.post("/acquire-lock", dependencies=[Depends(api_key_auth)])
def acquire_lock(body: AcquireLockRequest) -> Dict[str, Any]:
    """Acquire the exclusive `.analyze.lock` for a repo.

    Returns the owner descriptor (``owner_token``, ``pid``, ``acquired_at``).
    Callers MUST pass ``owner_token`` back to `/release-lock` to safely
    release without clobbering another process's lock.
    """
    try:
        from core.local_file_store_engine import LockAcquireError
    except ImportError:
        raise HTTPException(status_code=500, detail="engine not available")
    try:
        meta = _get_engine().acquire_lock(body.repo_path, timeout=body.timeout)
        return {"status": "acquired", **meta}
    except LockAcquireError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # pragma: no cover — defensive
        _logger.exception("acquire_lock failed")
        raise HTTPException(status_code=500, detail="acquire_lock failed") from exc


@router.post("/release-lock", dependencies=[Depends(api_key_auth)])
def release_lock(body: ReleaseLockRequest) -> Dict[str, Any]:
    """Release a previously acquired lock."""
    try:
        from core.local_file_store_engine import LockNotHeldError
    except ImportError:
        raise HTTPException(status_code=500, detail="engine not available")
    try:
        _get_engine().release_lock(body.repo_path, owner_token=body.owner_token)
        return {"status": "released", "repo_path": body.repo_path}
    except LockNotHeldError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:  # pragma: no cover — defensive
        _logger.exception("release_lock failed")
        raise HTTPException(status_code=500, detail="release_lock failed") from exc


# ---------------------------------------------------------------------------
# Endpoints — analyses
# ---------------------------------------------------------------------------


@router.post("/save-analysis", dependencies=[Depends(api_key_auth)])
def save_analysis(body: SaveAnalysisRequest) -> Dict[str, Any]:
    """Persist an analysis payload atomically.

    Exactly one of ``payload`` (JSON dict) or ``payload_base64`` (b64 UTF-8
    JSON) must be provided.
    """
    provided = [p for p in (body.payload, body.payload_base64) if p is not None]
    if len(provided) != 1:
        raise HTTPException(
            status_code=400,
            detail="exactly one of 'payload' or 'payload_base64' required",
        )
    if body.payload is not None:
        payload: Any = body.payload
    else:
        import json as _json
        try:
            decoded = base64.b64decode(body.payload_base64 or "", validate=True)
        except (binascii.Error, ValueError) as exc:
            raise HTTPException(status_code=400, detail=f"invalid base64: {exc}") from exc
        try:
            payload = _json.loads(decoded.decode("utf-8"))
        except (UnicodeDecodeError, ValueError) as exc:
            raise HTTPException(
                status_code=400,
                detail=f"payload_base64 must decode to UTF-8 JSON: {exc}",
            ) from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="payload must decode to a JSON object")
    try:
        return _get_engine().save_analysis(body.repo_path, payload)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # pragma: no cover — defensive
        _logger.exception("save_analysis failed")
        raise HTTPException(status_code=500, detail="save_analysis failed") from exc


@router.get("/latest", dependencies=[Depends(api_key_auth)])
def latest(
    repo_path: str = Query(..., min_length=1),
) -> Dict[str, Any]:
    """Return the LATEST.json payload, or 404 if none exists."""
    result = _get_engine().get_latest(repo_path)
    if not result:
        raise HTTPException(status_code=404, detail="no analysis stored")
    return result


@router.get("/history", dependencies=[Depends(api_key_auth)])
def history(
    repo_path: str = Query(..., min_length=1),
    limit: int = Query(default=50, ge=1, le=1000),
) -> Dict[str, Any]:
    """Return up to ``limit`` history descriptors, newest-first."""
    items: List[Dict[str, Any]] = _get_engine().list_history(repo_path, limit=limit)
    return {"repo_path": repo_path, "count": len(items), "items": items}


# ---------------------------------------------------------------------------
# Endpoints — config
# ---------------------------------------------------------------------------


@router.get("/config", dependencies=[Depends(api_key_auth)])
def read_config(
    repo_path: str = Query(..., min_length=1),
) -> Dict[str, Any]:
    """Read `config.json` — empty dict if missing."""
    return {"repo_path": repo_path, "config": _get_engine().read_config(repo_path)}


@router.post("/config", dependencies=[Depends(api_key_auth)])
def write_config(body: WriteConfigRequest) -> Dict[str, Any]:
    """Write (overwrite) `config.json`."""
    try:
        stored = _get_engine().write_config(body.repo_path, body.config)
        return {"repo_path": body.repo_path, "config": stored}
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:  # pragma: no cover — defensive
        _logger.exception("write_config failed")
        raise HTTPException(status_code=500, detail="write_config failed") from exc


@router.delete("/clear", dependencies=[Depends(api_key_auth)])
def clear(
    repo_path: str = Query(..., min_length=1),
) -> Dict[str, Any]:
    """Delete the entire `.fixops/` subtree. Returns file count deleted."""
    try:
        removed = _get_engine().clear_store(repo_path)
        return {"repo_path": repo_path, "removed_files": removed}
    except Exception as exc:  # pragma: no cover — defensive
        _logger.exception("clear failed")
        raise HTTPException(status_code=500, detail="clear failed") from exc
