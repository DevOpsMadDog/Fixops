"""A missing credential is a configuration state, not a server fault.

Integrations that need the customer's credentials used to answer HTTP 503 when those
credentials were absent. 503 means "the service is unavailable": it trips uptime
monitors, turns dashboards red, and during an evaluation it reads as *your product is
broken* rather than *I have not given it my Jira token yet*.

That is exactly backwards for us. The integration surface — 34 scanner normalizers and
45 connector classes — is the thing we want a buyer to notice, and a buyer's first hour
is spent connecting tools. Unconnected integrations must look like the next step, not
like failures.

So: absent credentials return **200** with the uniform payload built here, naming the
exact environment variables required. A 5xx is reserved for a genuine fault — credentials
present but the upstream failed, or our own code raised — which stays loud, because a
configured integration that cannot reach its upstream *is* a real problem.

See docs/architecture/adr/007-credential-gated-integrations.md.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional

from fastapi import Request
from fastapi.responses import JSONResponse

__all__ = [
    "NotConfigured",
    "not_configured_payload",
    "not_configured_handler",
    "register_not_configured_handler",
]

# Environment variable names as they appear in the human-readable messages the routers
# already carry, e.g. "KONG_ADMIN_URL environment variable is not configured".
_ENV_TOKEN = re.compile(r"\b([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)\b")

_DOCS_BASE = "https://docs.aldeci.io/integrations"


class NotConfigured(Exception):
    """Raised when an integration lacks the credentials it needs to do anything.

    Deliberately not an ``HTTPException``: the point of this type is that the raise site
    declares *intent* ("this is unconfigured") and rendering is decided centrally, so the
    status code cannot drift back to 5xx one router at a time.

    Args:
        service: Stable identifier for the integration, e.g. ``"kong"``.
        message: Human-readable explanation. Environment variable names are extracted
            from it when ``required_env`` is not given.
        required_env: Environment variables the operator must set. Derived from
            ``message`` when omitted.
        docs_url: Where to read the setup steps.
    """

    def __init__(
        self,
        service: str,
        message: str,
        required_env: Optional[Iterable[str]] = None,
        docs_url: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.service = service
        self.message = message
        self.required_env: List[str] = (
            list(required_env)
            if required_env is not None
            else _env_vars_from_message(message)
        )
        self.docs_url = docs_url or f"{_DOCS_BASE}/{service}"


def _env_vars_from_message(message: str) -> List[str]:
    """Pull SCREAMING_SNAKE_CASE variable names out of an existing message.

    The routers already state precisely which variables they need, so migration keeps
    that wording rather than inventing a second, drifting source of truth.
    """
    seen: List[str] = []
    for match in _ENV_TOKEN.findall(message or ""):
        if match not in seen:
            seen.append(match)
    return seen


def not_configured_payload(
    service: str,
    message: str,
    required_env: Optional[Iterable[str]] = None,
    docs_url: Optional[str] = None,
) -> Dict[str, Any]:
    """Build the uniform body. Every integration answers in this shape."""
    exc = NotConfigured(service, message, required_env, docs_url)
    return {
        "service": exc.service,
        "configured": False,
        "status": "not_configured",
        "required_env": exc.required_env,
        "message": exc.message,
        "docs_url": exc.docs_url,
        # Present so a UI can render this as an onboarding step without string-matching
        # the message, and so health checks can tell it apart from a real outage.
        "healthy": True,
    }


async def not_configured_handler(_request: Request, exc: Exception) -> JSONResponse:
    """Render :class:`NotConfigured` as 200 rather than an error."""
    assert isinstance(exc, NotConfigured)  # registered only for this type
    return JSONResponse(
        status_code=200,
        content=not_configured_payload(
            exc.service, exc.message, exc.required_env, exc.docs_url
        ),
    )


def register_not_configured_handler(app: Any) -> None:
    """Attach the handler to a FastAPI app."""
    app.add_exception_handler(NotConfigured, not_configured_handler)
