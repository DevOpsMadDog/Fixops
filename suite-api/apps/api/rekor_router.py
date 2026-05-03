"""Sigstore Rekor transparency log router.

Prefix: /api/v1/rekor
Auth:   api_key_auth on every endpoint.

Routes:
  GET  /api/v1/rekor/                        capability summary
  GET  /api/v1/rekor/api/v1/log              tree state
  GET  /api/v1/rekor/api/v1/log/proof        consistency proof
  GET  /api/v1/rekor/api/v1/log/entries/{u}  entry by uuid
  GET  /api/v1/rekor/api/v1/log/entries      entry by logIndex
  POST /api/v1/rekor/api/v1/log/entries      submit entry
  POST /api/v1/rekor/api/v1/index/retrieve   search index

NO MOCKS — when REKOR_URL is unreachable the GET / endpoint reports
``status="unavailable"`` and other endpoints raise HTTP 503.  See
``core.rekor_engine.RekorEngine`` for the read-through proxy implementation.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/rekor",
    tags=["Sigstore Rekor"],
)


def _engine():
    """Lazy import — keeps router import cheap."""
    from core.rekor_engine import get_rekor_engine

    return get_rekor_engine()


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class CreateEntryBody(BaseModel):
    kind: str = Field(
        ...,
        description=(
            "Entry kind — one of: hashedrekord, rekord, intoto, alpine, cose, "
            "dsse, helm, jar, rfc3161, rpm, tuf"
        ),
    )
    apiVersion: str = Field("0.0.1", description="Schema version of the kind")
    spec: Dict[str, Any] = Field(
        default_factory=dict,
        description="Kind-specific spec body — passed through to upstream Rekor",
    )


class IndexRetrieveBody(BaseModel):
    hash: Optional[str] = Field(
        default=None,
        description="sha256: prefixed digest of the artefact, e.g. sha256:abc...",
    )
    publicKey: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Public key descriptor — {format: 'x509', content: <base64>}",
    )
    email: Optional[str] = Field(
        default=None, description="Subject email to search by"
    )


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/", dependencies=[Depends(api_key_auth)])
def rekor_health() -> Dict[str, Any]:
    """Capability summary + reachability probe of the upstream Rekor."""
    try:
        return _engine().health()
    except Exception as exc:  # pragma: no cover - extremely defensive
        _logger.warning("rekor health probe failed: %s", exc)
        return {
            "service": "Sigstore Rekor",
            "endpoints": [
                "/api/v1/log",
                "/api/v1/log/entries",
                "/api/v1/log/proof",
                "/api/v1/index/retrieve",
            ],
            "rekor_url": "",
            "status": "unavailable",
        }


@router.get("/api/v1/log", dependencies=[Depends(api_key_auth)])
def get_log() -> Dict[str, Any]:
    """Return the current state of the transparency tree."""
    from core.rekor_engine import RekorUnavailable

    try:
        return _engine().get_log()
    except RekorUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc))


@router.get("/api/v1/log/proof", dependencies=[Depends(api_key_auth)])
def get_proof(
    lastSize: int = Query(..., ge=1, description="Tree size at the proof endpoint"),
    firstSize: Optional[int] = Query(
        default=None, ge=0, description="Tree size at the proof startpoint"
    ),
    treeID: Optional[str] = Query(default=None, description="Optional tree id"),
) -> Dict[str, Any]:
    """Return a consistency proof between two tree sizes."""
    from core.rekor_engine import RekorUnavailable

    try:
        return _engine().get_proof(
            last_size=lastSize, first_size=firstSize, tree_id=treeID
        )
    except RekorUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc))


@router.get("/api/v1/log/entries/{uuid}", dependencies=[Depends(api_key_auth)])
def get_entry_by_uuid(uuid: str) -> Dict[str, Any]:
    """Return a single transparency log entry by uuid."""
    from core.rekor_engine import RekorUnavailable

    try:
        body = _engine().get_entry_by_uuid(uuid)
    except RekorUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    if isinstance(body, dict) and body.get("_error"):
        status = body.get("status", 502)
        raise HTTPException(
            status_code=404 if status == 404 else 502,
            detail=body.get("detail", "rekor upstream error"),
        )
    return body


@router.get("/api/v1/log/entries", dependencies=[Depends(api_key_auth)])
def get_entry_by_index(
    logIndex: int = Query(..., ge=0, description="0-based log index"),
) -> Dict[str, Any]:
    """Return a single transparency log entry by log index."""
    from core.rekor_engine import RekorUnavailable

    try:
        body = _engine().get_entry_by_index(logIndex)
    except RekorUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    if isinstance(body, dict) and body.get("_error"):
        status = body.get("status", 502)
        raise HTTPException(
            status_code=404 if status == 404 else 502,
            detail=body.get("detail", "rekor upstream error"),
        )
    return body


@router.post(
    "/api/v1/log/entries",
    dependencies=[Depends(api_key_auth)],
    status_code=201,
)
def create_entry(body: CreateEntryBody) -> Dict[str, Any]:
    """Submit a new entry to the transparency log."""
    from core.rekor_engine import RekorUnavailable

    payload = body.model_dump(exclude_none=True)
    try:
        result = _engine().create_entry(payload)
    except RekorUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    if isinstance(result, dict) and result.get("_error"):
        status = int(result.get("status", 502))
        raise HTTPException(
            status_code=status if 400 <= status < 500 else 502,
            detail=result.get("detail", "rekor upstream error"),
        )
    return result


@router.post(
    "/api/v1/index/retrieve",
    dependencies=[Depends(api_key_auth)],
)
def index_retrieve(body: IndexRetrieveBody) -> List[str]:
    """Search the transparency log index by hash/email/publicKey."""
    from core.rekor_engine import RekorUnavailable

    payload = body.model_dump(exclude_none=True)
    if not payload:
        raise HTTPException(
            status_code=422,
            detail="At least one of {hash, email, publicKey} is required",
        )
    try:
        return _engine().index_retrieve(payload)
    except RekorUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc))
