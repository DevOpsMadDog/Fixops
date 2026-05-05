"""ALDECI Proofpoint TAP engine — REAL httpx only, NO MOCKS.

Wraps the Proofpoint Targeted Attack Protection (TAP) v2 SIEM API.

Capability summary returns ``status="unavailable"`` and lookup endpoints
raise ``ProofpointTAPUnavailableError`` (HTTP 503 at the router) when
``PROOFPOINT_TAP_PRINCIPAL`` / ``PROOFPOINT_TAP_SECRET`` are not configured.

NO SQLite cache. NO mock data.

Singleton:
    eng = get_proofpoint_tap_engine()

Reset (tests):
    reset_proofpoint_tap_engine()
"""
from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# TrustGraph event-bus wiring (optional, never blocks)
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload: Dict[str, Any]) -> None:
    """Best-effort TrustGraph emit. Never raises. Handles async bus.emit safely."""
    if _get_tg_bus is None:
        return
    try:
        import asyncio
        import inspect
        bus = _get_tg_bus()
        if bus is None:
            return
        emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
        if emit is None:
            return
        result = emit(event_type, payload)
        if inspect.isawaitable(result):
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(result)
            except RuntimeError:
                result.close()
    except Exception:  # pragma: no cover
        pass


class ProofpointTAPUnavailableError(RuntimeError):
    """Raised when Proofpoint TAP cannot be reached or is misconfigured."""


class ProofpointTAPEngine:
    """Real httpx-backed Proofpoint TAP API client.

    All public methods raise ``ProofpointTAPUnavailableError`` when
    credentials are not configured. Routers translate this to HTTP 503.

    Tests can inject a stubbed ``httpx.Client`` via the ``client=`` kwarg.
    """

    BASE_URL = "https://tap-api-v2.proofpoint.com"
    DEFAULT_TIMEOUT = 30.0

    def __init__(
        self,
        principal: Optional[str] = None,
        secret: Optional[str] = None,
        client: Any = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._principal: str = (
            principal
            or os.environ.get("PROOFPOINT_TAP_PRINCIPAL", "")
            or ""
        ).strip()
        self._secret: str = (
            secret
            or os.environ.get("PROOFPOINT_TAP_SECRET", "")
            or ""
        ).strip()
        self._timeout = timeout
        self._client: Any = client

    # ------------------------------------------------------------------ utils

    def is_configured(self) -> bool:
        return bool(self._principal and self._secret)

    def _require_configured(self) -> None:
        if not self.is_configured():
            raise ProofpointTAPUnavailableError(
                "PROOFPOINT_TAP_PRINCIPAL/PROOFPOINT_TAP_SECRET not set — "
                "set both env vars to call Proofpoint TAP"
            )

    def _ensure_client(self) -> httpx.Client:
        if self._client is not None:
            return self._client
        self._require_configured()
        try:
            self._client = httpx.Client(timeout=self._timeout)
        except Exception as exc:  # noqa: BLE001
            raise ProofpointTAPUnavailableError(
                f"Failed to build httpx client: {exc}"
            ) from exc
        return self._client

    def _auth(self) -> httpx.BasicAuth:
        return httpx.BasicAuth(self._principal, self._secret)

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        client = self._ensure_client()
        url = f"{self.BASE_URL}{path}"
        try:
            resp = client.get(url, params=params or {}, auth=self._auth())
        except Exception as exc:  # noqa: BLE001
            raise ProofpointTAPUnavailableError(
                f"Proofpoint TAP GET {path} failed: {exc}"
            ) from exc
        if resp.status_code >= 400:
            raise ProofpointTAPUnavailableError(
                f"Proofpoint TAP GET {path} returned {resp.status_code}: {resp.text[:300]}"
            )
        try:
            return resp.json()
        except Exception as exc:  # noqa: BLE001
            raise ProofpointTAPUnavailableError(
                f"Proofpoint TAP GET {path} returned non-JSON body: {exc}"
            ) from exc

    def _post(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        client = self._ensure_client()
        url = f"{self.BASE_URL}{path}"
        try:
            resp = client.post(url, json=body, auth=self._auth())
        except Exception as exc:  # noqa: BLE001
            raise ProofpointTAPUnavailableError(
                f"Proofpoint TAP POST {path} failed: {exc}"
            ) from exc
        if resp.status_code >= 400:
            raise ProofpointTAPUnavailableError(
                f"Proofpoint TAP POST {path} returned {resp.status_code}: {resp.text[:300]}"
            )
        try:
            return resp.json()
        except Exception as exc:  # noqa: BLE001
            raise ProofpointTAPUnavailableError(
                f"Proofpoint TAP POST {path} returned non-JSON body: {exc}"
            ) from exc

    # ----------------------------------------------------------------- summary

    def capability_summary(self) -> Dict[str, Any]:
        configured = self.is_configured()
        status = "ok" if configured else "unavailable"
        return {
            "service": "Proofpoint TAP",
            "endpoints": [
                "/v2/siem/all",
                "/v2/siem/clicks/blocked",
                "/v2/siem/messages/delivered",
                "/v2/forensics",
                "/v2/url/decode",
            ],
            "proofpoint_principal_present": bool(self._principal),
            "proofpoint_secret_present": bool(self._secret),
            "status": status,
        }

    # ------------------------------------------------------------------- SIEM

    def siem_all(
        self,
        format: str = "json",
        sinceSeconds: Optional[int] = None,
        interval: Optional[str] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {"format": format}
        if sinceSeconds is not None:
            params["sinceSeconds"] = int(sinceSeconds)
        if interval:
            params["interval"] = interval
        out = self._get("/v2/siem/all", params=params)
        try:
            _emit_event(
                "proofpoint_tap.siem_all",
                {
                    "messages_delivered": len(out.get("messagesDelivered", [])),
                    "messages_blocked": len(out.get("messagesBlocked", [])),
                    "clicks_blocked": len(out.get("clicksBlocked", [])),
                    "clicks_permitted": len(out.get("clicksPermitted", [])),
                },
            )
        except Exception:  # pragma: no cover
            pass
        return out

    def siem_clicks_blocked(
        self, format: str = "json", sinceSeconds: Optional[int] = None
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {"format": format}
        if sinceSeconds is not None:
            params["sinceSeconds"] = int(sinceSeconds)
        return self._get("/v2/siem/clicks/blocked", params=params)

    def siem_messages_delivered(
        self, format: str = "json", sinceSeconds: Optional[int] = None
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {"format": format}
        if sinceSeconds is not None:
            params["sinceSeconds"] = int(sinceSeconds)
        return self._get("/v2/siem/messages/delivered", params=params)

    # ------------------------------------------------------------- forensics

    def forensics(
        self,
        threatId: Optional[str] = None,
        campaignId: Optional[str] = None,
        aggregate: Optional[bool] = None,
    ) -> Dict[str, Any]:
        if not threatId and not campaignId:
            raise ProofpointTAPUnavailableError(
                "Either threatId or campaignId is required for /v2/forensics"
            )
        params: Dict[str, Any] = {}
        if threatId:
            params["threatId"] = threatId
        if campaignId:
            params["campaignId"] = campaignId
        if aggregate is not None:
            params["aggregate"] = "true" if aggregate else "false"
        return self._get("/v2/forensics", params=params)

    # ------------------------------------------------------------ URL decode

    def url_decode_get(self, urls: str) -> Dict[str, Any]:
        # Proofpoint accepts comma-separated URL-encoded strings via GET
        return self._get("/v2/url/decode", params={"urls": urls})

    def url_decode_post(self, urls: List[str]) -> Dict[str, Any]:
        return self._post("/v2/url/decode", {"urls": list(urls)})

    # --------------------------------------------------------------- people

    def people_vap(
        self,
        window: str = "14d",
        size: Optional[int] = None,
        page: Optional[int] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {"window": window}
        if size is not None:
            params["size"] = int(size)
        if page is not None:
            params["page"] = int(page)
        return self._get("/v2/people/vap", params=params)

    def people_top_clickers(
        self,
        window: str = "14d",
        size: Optional[int] = None,
        page: Optional[int] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {"window": window}
        if size is not None:
            params["size"] = int(size)
        if page is not None:
            params["page"] = int(page)
        return self._get("/v2/people/top-clickers", params=params)


# ---------------------------------------------------------------------------
# Singleton accessors
# ---------------------------------------------------------------------------

_singleton: Optional[ProofpointTAPEngine] = None
_singleton_lock = threading.RLock()


def get_proofpoint_tap_engine(
    principal: Optional[str] = None,
    secret: Optional[str] = None,
    client: Any = None,
    force_refresh: bool = False,
) -> ProofpointTAPEngine:
    """Return the process-wide ProofpointTAPEngine singleton.

    Tests may pass ``force_refresh=True`` (or call ``reset_proofpoint_tap_engine()``)
    to bind a stubbed httpx.Client.
    """
    global _singleton
    with _singleton_lock:
        if _singleton is None or force_refresh or any(
            v is not None for v in (principal, secret, client)
        ):
            _singleton = ProofpointTAPEngine(
                principal=principal,
                secret=secret,
                client=client,
            )
        return _singleton


def reset_proofpoint_tap_engine() -> None:
    global _singleton
    with _singleton_lock:
        _singleton = None


# Module-load heartbeat
try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass

__all__ = [
    "ProofpointTAPEngine",
    "ProofpointTAPUnavailableError",
    "get_proofpoint_tap_engine",
    "reset_proofpoint_tap_engine",
]
