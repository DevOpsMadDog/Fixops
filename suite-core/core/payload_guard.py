"""Payload validation middleware for ALDECI webhook and API endpoints.

Provides:
- PayloadGuard class — configurable size, content-type, and structure checks
- payload_guard(max_size, allowed_types) — FastAPI dependency factory

Usage:
    from core.payload_guard import payload_guard

    @router.post("/webhook")
    async def webhook(
        request: Request,
        _: None = Depends(payload_guard(max_size=1024 * 1024, allowed_types=["application/json"])),
    ):
        ...
"""

from __future__ import annotations

import json
from typing import Any, Callable, List, Optional

from fastapi import HTTPException, Request

from core.exceptions import ValidationError

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

_DEFAULT_MAX_BODY_SIZE = 1 * 1024 * 1024  # 1 MB — webhooks
_FILE_UPLOAD_MAX_BODY_SIZE = 10 * 1024 * 1024  # 10 MB — file uploads
_DEFAULT_MAX_JSON_DEPTH = 10
_DEFAULT_MAX_JSON_KEYS = 1000


# ---------------------------------------------------------------------------
# PayloadGuard
# ---------------------------------------------------------------------------


class PayloadGuard:
    """Validates inbound HTTP payload size, content type, and JSON structure.

    Attributes:
        max_body_size: Maximum allowed request body in bytes.
        max_json_depth: Maximum allowed nesting depth for JSON payloads.
        max_json_keys: Maximum allowed total key count across all JSON objects.
    """

    def __init__(
        self,
        max_body_size: int = _DEFAULT_MAX_BODY_SIZE,
        max_json_depth: int = _DEFAULT_MAX_JSON_DEPTH,
        max_json_keys: int = _DEFAULT_MAX_JSON_KEYS,
    ) -> None:
        self.max_body_size = max_body_size
        self.max_json_depth = max_json_depth
        self.max_json_keys = max_json_keys

    # ------------------------------------------------------------------
    # Content-Type validation
    # ------------------------------------------------------------------

    def validate_content_type(
        self,
        request: Request,
        allowed: List[str],
    ) -> None:
        """Raise HTTPException(415) if Content-Type is not in *allowed*.

        Comparison is case-insensitive and ignores charset/boundary params.
        If *allowed* is empty, no check is performed.
        """
        if not allowed:
            return

        raw_ct = request.headers.get("content-type", "")
        # Strip parameters (e.g. "; charset=utf-8")
        content_type = raw_ct.split(";")[0].strip().lower()

        normalised_allowed = [a.split(";")[0].strip().lower() for a in allowed]
        if content_type not in normalised_allowed:
            raise HTTPException(
                status_code=415,
                detail=(
                    f"Unsupported content type '{content_type}'. "
                    f"Expected one of: {normalised_allowed}"
                ),
            )

    # ------------------------------------------------------------------
    # JSON structure validation
    # ------------------------------------------------------------------

    def validate_json_depth(self, data: Any, max_depth: Optional[int] = None) -> None:
        """Raise ValidationError if *data* is nested deeper than *max_depth*.

        Prevents deeply nested JSON DoS (stack exhaustion, quadratic parse).
        """
        limit = max_depth if max_depth is not None else self.max_json_depth
        if _json_depth(data) > limit:
            raise ValidationError(
                f"JSON payload exceeds maximum nesting depth of {limit}"
            )

    def validate_json_keys(self, data: Any, max_keys: Optional[int] = None) -> None:
        """Raise ValidationError if total key count in *data* exceeds *max_keys*.

        Counts keys across all nested dicts to prevent key-explosion attacks.
        """
        limit = max_keys if max_keys is not None else self.max_json_keys
        total = _count_keys(data)
        if total > limit:
            raise ValidationError(
                f"JSON payload contains {total} keys, exceeding the limit of {limit}"
            )

    # ------------------------------------------------------------------
    # Body size validation
    # ------------------------------------------------------------------

    async def validate_body_size(self, request: Request) -> bytes:
        """Read and return the raw request body, raising HTTPException(413) if oversized.

        FastAPI streams request bodies; this reads the body up to max_body_size + 1
        bytes to detect oversize without loading the whole body into memory first.
        """
        body = b""
        limit = self.max_body_size
        async for chunk in request.stream():
            body += chunk
            if len(body) > limit:
                raise HTTPException(
                    status_code=413,
                    detail=(
                        f"Request body exceeds the maximum allowed size of "
                        f"{limit} bytes ({limit // 1024} KB)"
                    ),
                )
        return body

    # ------------------------------------------------------------------
    # Full validation pipeline
    # ------------------------------------------------------------------

    async def validate_request(
        self,
        request: Request,
        allowed_types: Optional[List[str]] = None,
    ) -> bytes:
        """Run all validations and return the raw body bytes.

        Steps:
        1. Validate Content-Type (if allowed_types provided)
        2. Read body with size limit
        3. If JSON content type, parse and validate depth + key count
        """
        if allowed_types:
            self.validate_content_type(request, allowed_types)

        body = await self.validate_body_size(request)

        # JSON structure checks
        raw_ct = request.headers.get("content-type", "")
        content_type = raw_ct.split(";")[0].strip().lower()
        if content_type == "application/json" and body:
            try:
                data = json.loads(body)
            except (json.JSONDecodeError, UnicodeDecodeError):
                raise HTTPException(status_code=400, detail="Malformed JSON body")

            self.validate_json_depth(data)
            self.validate_json_keys(data)

        return body


# ---------------------------------------------------------------------------
# FastAPI dependency factory
# ---------------------------------------------------------------------------


def payload_guard(
    max_size: int = _DEFAULT_MAX_BODY_SIZE,
    allowed_types: Optional[List[str]] = None,
    max_json_depth: int = _DEFAULT_MAX_JSON_DEPTH,
    max_json_keys: int = _DEFAULT_MAX_JSON_KEYS,
) -> Callable:
    """Return a FastAPI dependency that enforces payload constraints.

    Usage:
        @router.post("/webhook")
        async def webhook(
            request: Request,
            _: None = Depends(payload_guard(max_size=1_048_576, allowed_types=["application/json"])),
        ):
            body = await request.body()  # already validated, safe to read
            ...

    Args:
        max_size: Maximum body size in bytes (default 1 MB).
        allowed_types: Allowed Content-Type values (default: no restriction).
        max_json_depth: Maximum JSON nesting depth (default 10).
        max_json_keys: Maximum total JSON key count (default 1000).
    """
    guard = PayloadGuard(
        max_body_size=max_size,
        max_json_depth=max_json_depth,
        max_json_keys=max_json_keys,
    )

    async def _dependency(request: Request) -> None:
        await guard.validate_request(request, allowed_types=allowed_types)

    return _dependency


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _json_depth(data: Any, _current: int = 0) -> int:
    """Recursively compute the maximum nesting depth of *data*."""
    if isinstance(data, dict):
        if not data:
            return _current + 1
        return max(_json_depth(v, _current + 1) for v in data.values())
    if isinstance(data, list):
        if not data:
            return _current + 1
        return max(_json_depth(item, _current + 1) for item in data)
    return _current


def _count_keys(data: Any) -> int:
    """Recursively count all dict keys in *data*."""
    if isinstance(data, dict):
        count = len(data)
        for v in data.values():
            count += _count_keys(v)
        return count
    if isinstance(data, list):
        return sum(_count_keys(item) for item in data)
    return 0
