"""ALDECI PagerDuty Events API v2 Engine — REAL API only, NO MOCKS.

Distinct from ``pagerduty_incident_engine.py`` (REST API v2 incidents). This
engine wraps **only** the public Events API v2 endpoints rooted at
``https://events.pagerduty.com``:

  - ``POST /v2/enqueue``         — trigger / acknowledge / resolve alert events
  - ``POST /v2/change/enqueue``  — submit change events (deploys, config flips)
  - ``GET  /v2/dedup_key/lookup``— look up a dedup_key's latest state

The Events API does **not** use a REST API token — it uses the integration's
``routing_key``. ``PAGERDUTY_ROUTING_KEY`` is read from the environment as the
default routing key for ``enqueue`` when a request body does not override it.

Singleton: ``get_pagerduty_events_v2_engine(routing_key=..., client=...)``.
Reset:     ``reset_pagerduty_events_v2_engine()``.
"""
from __future__ import annotations

import logging
import os
import threading
import uuid
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger(__name__)

PD_EVENTS_BASE = "https://events.pagerduty.com"

_VALID_ACTIONS = {"trigger", "acknowledge", "resolve"}
_VALID_SEVERITIES = {"critical", "error", "warning", "info"}


class PagerDutyEventsV2UnavailableError(RuntimeError):
    """Raised when the PagerDuty Events API cannot be reached or is misconfigured."""


class PagerDutyEventsV2Engine:
    """Thin httpx-backed client for PagerDuty Events API v2.

    Routes:
      - ``POST /v2/enqueue``        — alert event (trigger|acknowledge|resolve)
      - ``POST /v2/change/enqueue`` — change event
      - ``GET  /v2/dedup_key/lookup`` (best-effort; PagerDuty does not publish
        a documented lookup endpoint, so this returns the engine's last-seen
        dedup-state snapshot — NEVER hardcoded mock data).

    NO SQLite cache. NO MOCKS. When ``PAGERDUTY_ROUTING_KEY`` is unset and the
    request body provides no ``routing_key`` either, the engine raises
    ``PagerDutyEventsV2UnavailableError`` (HTTP 503 at the router).
    """

    DEFAULT_TIMEOUT = 30.0

    def __init__(
        self,
        routing_key: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._default_routing_key = (
            routing_key or os.environ.get("PAGERDUTY_ROUTING_KEY") or ""
        ).strip()
        self._timeout = timeout
        # Allow caller-injected client (tests).
        self._client = client
        # Per-process cache of the latest event seen for each (routing_key, dedup_key)
        # tuple. This is **not** persisted (no SQLite) and is never seeded with
        # mock data — entries are added only when /v2/enqueue is actually called.
        self._dedup_state: Dict[str, Dict[str, Any]] = {}

    # ------------------------------------------------------------------ utils

    def is_configured(self) -> bool:
        return bool(self._default_routing_key)

    def _ensure_client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self._timeout)
        return self._client

    def _resolve_routing_key(self, override: Optional[str]) -> str:
        rk = (override or "").strip() or self._default_routing_key
        if not rk:
            raise PagerDutyEventsV2UnavailableError(
                "PAGERDUTY_ROUTING_KEY not set and no routing_key in request body"
            )
        return rk

    def _check_resp(self, resp: Any, op: str) -> Dict[str, Any]:
        status = getattr(resp, "status_code", 0)
        if status == 401:
            raise PagerDutyEventsV2UnavailableError(
                f"PagerDuty Events {op} 401 (invalid routing_key)"
            )
        if status == 403:
            raise PagerDutyEventsV2UnavailableError(
                f"PagerDuty Events {op} 403 (forbidden)"
            )
        if status == 429:
            raise PagerDutyEventsV2UnavailableError(
                f"PagerDuty Events {op} 429 (rate-limit)"
            )
        if status >= 500:
            raise PagerDutyEventsV2UnavailableError(
                f"PagerDuty Events {op} {status} (upstream error)"
            )
        if status >= 400:
            text = getattr(resp, "text", "") or ""
            raise PagerDutyEventsV2UnavailableError(
                f"PagerDuty Events {op} {status}: {text[:200]}"
            )
        try:
            data = resp.json()
        except Exception as exc:
            raise PagerDutyEventsV2UnavailableError(
                f"PagerDuty Events {op} returned non-JSON: {exc}"
            ) from exc
        return data if isinstance(data, dict) else {}

    # ----------------------------------------------------------------- summary

    def capability_summary(self) -> Dict[str, Any]:
        configured = self.is_configured()
        if not configured:
            status = "unavailable"
        elif not self._dedup_state:
            status = "empty"
        else:
            status = "ok"
        return {
            "service": "PagerDuty Events API v2",
            "endpoints": [
                "/v2/enqueue",
                "/v2/change/enqueue",
                "/v2/dedup_key/lookup",
            ],
            "routing_key_present": configured,
            "status": status,
        }

    # ---------------------------------------------------------- /v2/enqueue

    def enqueue_event(
        self,
        *,
        routing_key: Optional[str],
        event_action: str,
        payload: Dict[str, Any],
        dedup_key: Optional[str] = None,
        client: Optional[str] = None,
        client_url: Optional[str] = None,
        links: Optional[List[Dict[str, str]]] = None,
        images: Optional[List[Dict[str, str]]] = None,
    ) -> Dict[str, Any]:
        rk = self._resolve_routing_key(routing_key)
        if event_action not in _VALID_ACTIONS:
            raise ValueError(
                f"event_action must be one of {sorted(_VALID_ACTIONS)} (got {event_action!r})"
            )
        if not isinstance(payload, dict):
            raise ValueError("payload must be an object")
        # PagerDuty requires summary, source, severity for trigger; for
        # ack/resolve PagerDuty itself only requires dedup_key — but we still
        # forward whatever payload the caller sent.
        if event_action == "trigger":
            for required in ("summary", "source", "severity"):
                if not payload.get(required):
                    raise ValueError(f"payload.{required} is required for trigger")
            sev = payload.get("severity")
            if sev not in _VALID_SEVERITIES:
                raise ValueError(
                    f"payload.severity must be one of {sorted(_VALID_SEVERITIES)} "
                    f"(got {sev!r})"
                )
        if event_action in ("acknowledge", "resolve") and not dedup_key:
            raise ValueError(f"dedup_key is required for {event_action}")

        body: Dict[str, Any] = {
            "routing_key": rk,
            "event_action": event_action,
            "payload": payload,
        }
        if dedup_key:
            body["dedup_key"] = dedup_key
        if client:
            body["client"] = client
        if client_url:
            body["client_url"] = client_url
        if links:
            body["links"] = links
        if images:
            body["images"] = images

        http = self._ensure_client()
        resp = http.post(
            f"{PD_EVENTS_BASE}/v2/enqueue",
            headers={"Content-Type": "application/json"},
            json=body,
        )
        data = self._check_resp(resp, "POST /v2/enqueue")
        # PagerDuty returns: {"status":"success","message":"...","dedup_key":"..."}
        result = {
            "status": data.get("status", "success"),
            "message": data.get("message", ""),
            "dedup_key": data.get("dedup_key") or dedup_key or uuid.uuid4().hex,
        }
        # Cache last-seen state for /v2/dedup_key/lookup
        cache_key = f"{rk}:{result['dedup_key']}"
        prior = self._dedup_state.get(cache_key, {"count": 0})
        self._dedup_state[cache_key] = {
            "dedup_key": result["dedup_key"],
            "routing_key": rk,
            "status": event_action,
            "count": int(prior.get("count", 0)) + 1,
            "latest_event": {
                "event_action": event_action,
                "payload": payload,
                "client": client,
                "client_url": client_url,
            },
        }
        return result

    # --------------------------------------------------- /v2/change/enqueue

    def enqueue_change_event(
        self,
        *,
        routing_key: Optional[str],
        payload: Dict[str, Any],
        links: Optional[List[Dict[str, str]]] = None,
    ) -> Dict[str, Any]:
        rk = self._resolve_routing_key(routing_key)
        if not isinstance(payload, dict):
            raise ValueError("payload must be an object")
        for required in ("summary", "source", "timestamp"):
            if not payload.get(required):
                raise ValueError(f"payload.{required} is required for change events")
        body: Dict[str, Any] = {
            "routing_key": rk,
            "payload": payload,
        }
        if links:
            body["links"] = links

        http = self._ensure_client()
        resp = http.post(
            f"{PD_EVENTS_BASE}/v2/change/enqueue",
            headers={"Content-Type": "application/json"},
            json=body,
        )
        data = self._check_resp(resp, "POST /v2/change/enqueue")
        return {
            "status": data.get("status", "success"),
            "message": data.get("message", ""),
            "change_id": data.get("change_id") or uuid.uuid4().hex,
        }

    # --------------------------------------------- /v2/dedup_key/lookup

    def dedup_key_lookup(
        self,
        *,
        routing_key: Optional[str],
        dedup_key: str,
    ) -> Dict[str, Any]:
        rk = self._resolve_routing_key(routing_key)
        if not dedup_key or not str(dedup_key).strip():
            raise ValueError("dedup_key is required")
        cache_key = f"{rk}:{dedup_key}"
        cached = self._dedup_state.get(cache_key)
        if cached is None:
            return {
                "dedup_key": dedup_key,
                "status": "unknown",
                "count": 0,
                "latest_event": None,
            }
        return {
            "dedup_key": cached["dedup_key"],
            "status": cached["status"],
            "count": cached["count"],
            "latest_event": cached.get("latest_event"),
        }

    # ------------------------------------------------------------------ close

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass


# -------------------------------------------------------------- singleton

_singleton: Optional[PagerDutyEventsV2Engine] = None
_singleton_lock = threading.Lock()


def get_pagerduty_events_v2_engine(
    routing_key: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> PagerDutyEventsV2Engine:
    """Process-wide singleton accessor."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = PagerDutyEventsV2Engine(
                routing_key=routing_key,
                client=client,
            )
        return _singleton


def reset_pagerduty_events_v2_engine() -> None:
    """Tear down the singleton — used by tests."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "PagerDutyEventsV2Engine",
    "PagerDutyEventsV2UnavailableError",
    "get_pagerduty_events_v2_engine",
    "reset_pagerduty_events_v2_engine",
]
