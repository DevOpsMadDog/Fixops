"""API versioning middleware and version endpoint for ALDECI API.

Adds to every response:
  - X-API-Version: current API version (1.0.0)
  - Deprecation headers (Sunset / Deprecation / Link) for deprecated paths

The X-Request-ID, X-Response-Time, and X-RateLimit-Remaining headers are
already emitted by RequestTracingMiddleware, RequestLoggingMiddleware, and
RateLimitMiddleware respectively — this middleware does not duplicate them.

Deprecated endpoint registry
------------------------------
Add entries to DEPRECATED_ENDPOINTS to automatically attach the three
RFC 8594 / RFC 9110 deprecation headers to matching path prefixes:

    DEPRECATED_ENDPOINTS["/api/v1/old-endpoint"] = {
        "sunset": "2026-12-31",          # ISO-8601 date (RFC 7231 Date header format)
        "successor": "/api/v2/new-endpoint",
    }
"""

from __future__ import annotations

import os
from typing import Callable, Dict, Optional

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

# ---------------------------------------------------------------------------
# Current API version — override with env var FIXOPS_API_VERSION
# ---------------------------------------------------------------------------
API_VERSION: str = os.getenv("FIXOPS_API_VERSION", "1.0.0")

# ---------------------------------------------------------------------------
# Deprecated endpoint registry
# Key   = exact path prefix to match (str)
# Value = dict with keys:
#   "sunset"    — ISO-8601 date string (e.g. "2026-12-31")
#   "successor" — URL for the replacement endpoint (optional)
# ---------------------------------------------------------------------------
DEPRECATED_ENDPOINTS: Dict[str, Dict[str, str]] = {
    # Example (uncomment to activate):
    # "/api/v0": {
    #     "sunset": "2026-06-30",
    #     "successor": "/api/v1",
    # },
}


class APIVersioningMiddleware(BaseHTTPMiddleware):
    """Starlette middleware that stamps every response with X-API-Version.

    For paths listed in DEPRECATED_ENDPOINTS it additionally attaches:
      - Sunset: <date>           (RFC 8594)
      - Deprecation: true        (draft-ietf-httpapi-deprecation-header)
      - Link: <url>; rel="successor-version"  (RFC 8288, only when successor set)
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)

        # Always stamp the API version
        response.headers["X-API-Version"] = API_VERSION

        # Check if this path matches a deprecated prefix
        path = request.url.path
        deprecation_info = _match_deprecated(path)
        if deprecation_info:
            response.headers["Deprecation"] = "true"
            if "sunset" in deprecation_info:
                response.headers["Sunset"] = deprecation_info["sunset"]
            if "successor" in deprecation_info:
                response.headers["Link"] = (
                    f'<{deprecation_info["successor"]}>; rel="successor-version"'
                )

        return response


def _match_deprecated(path: str) -> Optional[Dict[str, str]]:
    """Return the deprecation info dict for the first matching prefix, or None."""
    for prefix, info in DEPRECATED_ENDPOINTS.items():
        if path == prefix or path.startswith(prefix + "/") or path.startswith(prefix + "?"):
            return info
    return None
