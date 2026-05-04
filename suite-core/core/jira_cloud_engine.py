"""ALDECI Jira Cloud Engine.

Thin pass-through client for the **Jira Cloud REST API v3**, designed for
direct ticket-management workflows from ALDECI personas (vs. the bidirectional
finding-sync engine in `core/jira_sync.py`).

Configuration is environment-driven — NO SQLite cache, NO mocks. When the
required env vars are unset the engine reports ``status="unavailable"`` and
lookup endpoints return HTTP 503.

Environment variables
---------------------
JIRA_URL   — base Jira Cloud URL, e.g. ``https://example.atlassian.net``
JIRA_AUTH  — one of:
              * ``Basic <base64(email:token)>``  (Jira Cloud)
              * ``Bearer <PAT>``                 (Jira Data Center 9+ / Server)
              * ``email:token``                  (auto-encoded as Basic)
              * ``<token>``                      (treated as Bearer)

The engine is a process-level singleton accessible via
:func:`get_jira_cloud_engine`.

This engine is intentionally minimal — Pydantic models live in the router; the
engine just shapes auth headers and returns parsed JSON / raises HTTP errors.
"""

from __future__ import annotations

import base64
import logging
import os
from threading import Lock
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urljoin

import httpx

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except ImportError:
    _get_tg_bus = None  # type: ignore

logger = logging.getLogger(__name__)

_API_PATH = "/rest/api/3/"

# Endpoints we expose — surfaced via the capability summary GET /
_ENDPOINT_CATALOG: List[str] = [
    "/rest/api/3/issue",
    "/rest/api/3/search",
    "/rest/api/3/issue/{key}",
    "/rest/api/3/issue/{key}/transitions",
    "/rest/api/3/project",
]


class JiraCloudUnavailable(RuntimeError):
    """Raised when JIRA_URL or JIRA_AUTH are not configured."""


class JiraCloudHTTPError(RuntimeError):
    """Raised when Jira returns a non-2xx response.

    Carries the upstream status code so the router can map it to a sensible
    HTTPException (e.g. 401/403/404/409/429 are surfaced verbatim, everything
    else collapses to 502 Bad Gateway).
    """

    def __init__(self, status_code: int, message: str, payload: Any = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.payload = payload


def _normalise_auth_header(raw: str) -> str:
    """Coerce JIRA_AUTH into a valid ``Authorization`` header value.

    Accepts:
      * already-formed ``Basic ...`` / ``Bearer ...``
      * ``email:token``  -> Basic <b64(email:token)>
      * bare token       -> Bearer <token>
    """
    raw = (raw or "").strip()
    if not raw:
        return ""
    lower = raw.lower()
    if lower.startswith("basic ") or lower.startswith("bearer "):
        return raw
    if ":" in raw and "@" in raw.split(":", 1)[0]:
        # "email:token" → Basic
        encoded = base64.b64encode(raw.encode("utf-8")).decode("ascii")
        return f"Basic {encoded}"
    # Default: treat as a raw PAT
    return f"Bearer {raw}"


class JiraCloudEngine:
    """Pass-through Jira Cloud client backed by ``httpx.Client``."""

    def __init__(
        self,
        jira_url: Optional[str] = None,
        jira_auth: Optional[str] = None,
        timeout: float = 15.0,
        client: Optional[httpx.Client] = None,
    ) -> None:
        self._jira_url = (jira_url if jira_url is not None else os.environ.get("JIRA_URL", "")).strip()
        self._jira_auth_raw = (jira_auth if jira_auth is not None else os.environ.get("JIRA_AUTH", "")).strip()
        self._auth_header = _normalise_auth_header(self._jira_auth_raw)
        self._timeout = timeout
        # Allow tests to inject a stub httpx.Client
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None

    # ------------------------------------------------------------------ status

    @property
    def jira_url_present(self) -> bool:
        return bool(self._jira_url)

    @property
    def jira_auth_present(self) -> bool:
        return bool(self._auth_header)

    @property
    def configured(self) -> bool:
        return self.jira_url_present and self.jira_auth_present

    def status(self) -> str:
        """Return ok | empty | unavailable."""
        if not self.configured:
            return "unavailable"
        # We cannot ping Jira on every status call without burning quota; treat
        # configured-but-unverified as ok. The router surfaces empty when an
        # endpoint comes back with no data.
        return "ok"

    def capability_summary(self) -> Dict[str, Any]:
        return {
            "service": "Jira Cloud",
            "endpoints": list(_ENDPOINT_CATALOG),
            "jira_url_present": self.jira_url_present,
            "jira_auth_present": self.jira_auth_present,
            "status": self.status(),
        }

    # ------------------------------------------------------------------ http

    def _require_configured(self) -> None:
        if not self.configured:
            raise JiraCloudUnavailable(
                "JIRA_URL and JIRA_AUTH must be set to call Jira Cloud endpoints"
            )

    def _url(self, path: str) -> str:
        base = self._jira_url.rstrip("/") + _API_PATH
        return urljoin(base, path.lstrip("/"))

    def _headers(self) -> Dict[str, str]:
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": self._auth_header,
        }

    def _request(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
        expect_204: bool = False,
    ) -> Any:
        self._require_configured()
        url = self._url(path)
        try:
            resp = self._client.request(
                method,
                url,
                json=json_body,
                params=params,
                headers=self._headers(),
            )
        except httpx.HTTPError as exc:
            logger.warning("jira-cloud upstream error %s %s: %s", method, path, type(exc).__name__)
            raise JiraCloudHTTPError(502, f"Upstream Jira request failed: {type(exc).__name__}") from exc

        if expect_204 and resp.status_code in (200, 204):
            return None

        if 200 <= resp.status_code < 300:
            if not resp.content:
                return None
            try:
                return resp.json()
            except ValueError:
                return {"raw": resp.text}

        # Non-2xx: surface upstream payload when it's JSON
        payload: Any
        try:
            payload = resp.json()
        except ValueError:
            payload = resp.text or None
        raise JiraCloudHTTPError(resp.status_code, f"Jira returned {resp.status_code}", payload)

    # ------------------------------------------------------------------ ops

    def create_issue(self, fields: Dict[str, Any]) -> Dict[str, Any]:
        result = self._request("POST", "issue", json_body={"fields": fields}) or {}
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit(
                        "incident.created",
                        {
                            "entity_id": result.get("key", "unknown"),
                            "type": "jira_issue",
                            "severity": str(fields.get("priority", {}).get("name", "unknown")).lower() if isinstance(fields.get("priority"), dict) else "unknown",
                            "source_engine": "jira_cloud",
                            "summary": str(fields.get("summary", ""))[:120],
                        },
                    )
            except Exception:
                pass
        return result

    def get_issue(
        self,
        issue_key: str,
        fields: Optional[Iterable[str]] = None,
        expand: Optional[Iterable[str]] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {}
        if fields:
            params["fields"] = ",".join(fields)
        if expand:
            params["expand"] = ",".join(expand)
        return self._request("GET", f"issue/{issue_key}", params=params or None) or {}

    def search(
        self,
        jql: str,
        start_at: int = 0,
        max_results: int = 50,
        fields: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = {
            "jql": jql,
            "startAt": start_at,
            "maxResults": max_results,
        }
        if fields is not None:
            body["fields"] = fields
        return self._request("POST", "search", json_body=body) or {}

    def get_transitions(self, issue_key: str) -> Dict[str, Any]:
        return self._request("GET", f"issue/{issue_key}/transitions") or {"transitions": []}

    def transition_issue(self, issue_key: str, transition_id: str) -> None:
        self._request(
            "POST",
            f"issue/{issue_key}/transitions",
            json_body={"transition": {"id": str(transition_id)}},
            expect_204=True,
        )

    def list_projects(self) -> List[Dict[str, Any]]:
        result = self._request("GET", "project") or []
        if isinstance(result, list):
            return result
        # Some Jira deployments paginate under {values: [...]}
        if isinstance(result, dict) and "values" in result:
            return list(result["values"])
        return []

    # ------------------------------------------------------------------ lifecycle

    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except Exception:  # pragma: no cover - defensive
                pass


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_engine: Optional[JiraCloudEngine] = None
_engine_lock = Lock()


def get_jira_cloud_engine() -> JiraCloudEngine:
    """Return (or create) the process-wide JiraCloudEngine singleton.

    Picks up ``JIRA_URL`` / ``JIRA_AUTH`` lazily from the environment so tests
    that monkeypatch env vars before first call get a fresh, env-aligned engine.
    """
    global _engine
    with _engine_lock:
        if _engine is None:
            _engine = JiraCloudEngine()
    return _engine


def reset_jira_cloud_engine() -> None:
    """Test helper — drop the cached singleton so the next ``get_*`` call re-reads env."""
    global _engine
    with _engine_lock:
        if _engine is not None:
            _engine.close()
        _engine = None
