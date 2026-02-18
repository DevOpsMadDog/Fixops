"""Common FastAPI dependencies (auth, payload validation)."""

from __future__ import annotations

import json
from typing import Any, Dict

from fastapi import Depends, HTTPException, Request, status
from src.config.settings import get_settings


async def authenticate(request: Request) -> None:
    """Ensure the request carries a valid bearer token."""

    settings = get_settings()
    header = request.headers.get("Authorization")
    if not header or not header.lower().startswith("bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token"
        )
    token = header.split(" ", 1)[1].strip()
    if token != settings.FIXOPS_API_KEY:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Invalid API token"
        )


async def validated_payload(request: Request) -> Dict[str, Any]:
    """Validate request payload size and MIME type, returning parsed JSON."""

    settings = get_settings()
    raw = await request.body()
    if len(raw) > settings.FIXOPS_MAX_PAYLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="Payload too large",
        )

    content_type = (
        request.headers.get("content-type", "application/json").split(";")[0].strip()
    )
    if content_type not in {"application/json", "application/sarif+json"}:
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Unsupported content type",
        )

    try:
        payload = json.loads(raw.decode("utf-8") or "{}")
    except (
        json.JSONDecodeError
    ) as exc:  # pragma: no cover - FastAPI handles JSON validation
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    if not isinstance(payload, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Payload must be an object"
        )
    request.state.payload = payload
    return payload


async def authenticated_payload(
    payload: Dict[str, Any] = Depends(validated_payload),
    _: None = Depends(authenticate),
) -> Dict[str, Any]:
    """Compound dependency returning validated payload after authentication."""

    return payload
