"""ALDECI PagerDuty Incident Management Engine — REAL API only, NO MOCKS.

Wraps PagerDuty REST API v2 via httpx. Returns ``status="unavailable"``
in the capability summary and raises ``PagerDutyUnavailableError`` (HTTP 503
at the router layer) when ``PAGERDUTY_API_TOKEN`` is not set.

Endpoints supported:
  - GET    /incidents
  - POST   /incidents
  - PUT    /incidents/{id}
  - POST   /incidents/{id}/notes
  - GET    /services
  - GET    /oncalls
  - GET    /escalation_policies
  - POST   change_events.eu/v2/enqueue (Events API)

Singleton: ``get_pagerduty_incident_engine(api_token=..., from_email=..., client=...)``
Reset:     ``reset_pagerduty_incident_engine()``
"""
from __future__ import annotations

import logging
import os
import threading
import uuid
from typing import Any, Dict, List, Optional

import httpx

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except ImportError:
    _get_tg_bus = None  # type: ignore

logger = logging.getLogger(__name__)

PD_API_BASE = "https://api.pagerduty.com"
PD_EVENTS_BASE = "https://events.pagerduty.com"


class PagerDutyUnavailableError(RuntimeError):
    """Raised when the PagerDuty REST API cannot be reached or is misconfigured."""


class PagerDutyIncidentEngine:
    """Thin httpx-backed client for PagerDuty REST API v2 + Events API v2.

    All methods raise ``PagerDutyUnavailableError`` when the token is not
    configured (NO MOCKS). Routers translate that to HTTP 503.
    """

    DEFAULT_TIMEOUT = 30.0

    def __init__(
        self,
        api_token: Optional[str] = None,
        from_email: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        self._api_token = (api_token or os.environ.get("PAGERDUTY_API_TOKEN") or "").strip()
        self._from_email = (from_email or os.environ.get("PAGERDUTY_FROM_EMAIL") or "").strip()
        self._timeout = timeout
        # Allow caller-injected client (tests). When not configured we still
        # accept a stub so happy-path tests can drive the parsing layer.
        self._client = client

    # ------------------------------------------------------------------ utils

    def is_configured(self) -> bool:
        return bool(self._api_token)

    def _ensure_client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self._timeout)
        return self._client

    def _require_token(self) -> None:
        if not self._api_token:
            raise PagerDutyUnavailableError(
                "PAGERDUTY_API_TOKEN not set — set the env var to call PagerDuty"
            )

    def _headers(self, *, with_from: bool = False) -> Dict[str, str]:
        headers: Dict[str, str] = {
            "Authorization": f"Token token={self._api_token}",
            "Accept": "application/vnd.pagerduty+json;version=2",
            "Content-Type": "application/json",
        }
        if with_from and self._from_email:
            headers["From"] = self._from_email
        return headers

    def _check_resp(self, resp: Any, op: str) -> Any:
        status = getattr(resp, "status_code", 0)
        if status == 401:
            raise PagerDutyUnavailableError(f"PagerDuty 401 (invalid token) for {op}")
        if status == 403:
            raise PagerDutyUnavailableError(f"PagerDuty 403 (forbidden) for {op}")
        if status == 404:
            raise PagerDutyUnavailableError(f"PagerDuty 404 for {op}")
        if status == 429:
            raise PagerDutyUnavailableError(f"PagerDuty 429 (rate-limit) for {op}")
        if status >= 500:
            raise PagerDutyUnavailableError(
                f"PagerDuty {status} (upstream error) for {op}"
            )
        if status >= 400:
            text = getattr(resp, "text", "") or ""
            raise PagerDutyUnavailableError(
                f"PagerDuty {status} for {op}: {text[:200]}"
            )
        try:
            return resp.json()
        except Exception as exc:
            raise PagerDutyUnavailableError(
                f"PagerDuty returned non-JSON for {op}: {exc}"
            ) from exc

    # ----------------------------------------------------------------- summary

    def capability_summary(self) -> Dict[str, Any]:
        """Return capability metadata for the GET / endpoint."""
        configured = self.is_configured()
        if not configured:
            status = "unavailable"
        else:
            # We don't burn a real API call on summary — just report 'ok'
            status = "ok"
        return {
            "service": "PagerDuty",
            "endpoints": [
                "/incidents",
                "/services",
                "/oncalls",
                "/change_events/enqueue",
                "/escalation_policies",
            ],
            "api_token_present": configured,
            "from_email_present": bool(self._from_email),
            "status": status,
        }

    # --------------------------------------------------------------- incidents

    def list_incidents(
        self,
        statuses: Optional[List[str]] = None,
        service_ids: Optional[List[str]] = None,
        limit: int = 25,
        offset: int = 0,
    ) -> Dict[str, Any]:
        self._require_token()
        params: List[tuple] = [("limit", str(min(max(limit, 1), 100))), ("offset", str(max(offset, 0)))]
        for s in statuses or []:
            params.append(("statuses[]", s))
        for sid in service_ids or []:
            params.append(("service_ids[]", sid))
        client = self._ensure_client()
        resp = client.get(
            f"{PD_API_BASE}/incidents",
            headers=self._headers(),
            params=params,
        )
        data = self._check_resp(resp, "GET /incidents")
        if not isinstance(data, dict):
            data = {}
        return {
            "incidents": list(data.get("incidents") or []),
            "offset": int(data.get("offset", offset)),
            "limit": int(data.get("limit", limit)),
            "more": bool(data.get("more", False)),
            "total": data.get("total"),
        }

    def create_incident(self, body: Dict[str, Any]) -> Dict[str, Any]:
        self._require_token()
        if not self._from_email:
            raise PagerDutyUnavailableError(
                "PAGERDUTY_FROM_EMAIL not set — required by PagerDuty for POST /incidents"
            )
        client = self._ensure_client()
        resp = client.post(
            f"{PD_API_BASE}/incidents",
            headers=self._headers(with_from=True),
            json=body,
        )
        data = self._check_resp(resp, "POST /incidents")
        incident = data["incident"] if isinstance(data, dict) and "incident" in data else data
        if _get_tg_bus and isinstance(incident, dict):
            iid = incident.get("id") or incident.get("incident_number")
            if iid:
                try:
                    _bus = _get_tg_bus()
                    if _bus:
                        _bus.emit(
                            "incident.created",
                            {
                                "entity_id": str(iid),
                                "type": "pagerduty_incident",
                                "severity": incident.get("urgency") or "unknown",
                                "source_engine": "pagerduty_incident",
                                "title": incident.get("title"),
                                "status": incident.get("status"),
                            },
                        )
                except Exception:
                    pass
        return {"incident": incident}

    def update_incident(self, incident_id: str, body: Dict[str, Any]) -> Dict[str, Any]:
        self._require_token()
        if not incident_id or not str(incident_id).strip():
            raise ValueError("incident_id required")
        if not self._from_email:
            raise PagerDutyUnavailableError(
                "PAGERDUTY_FROM_EMAIL not set — required for PUT /incidents/{id}"
            )
        client = self._ensure_client()
        resp = client.put(
            f"{PD_API_BASE}/incidents/{incident_id}",
            headers=self._headers(with_from=True),
            json=body,
        )
        data = self._check_resp(resp, f"PUT /incidents/{incident_id}")
        if isinstance(data, dict) and "incident" in data:
            return {"incident": data["incident"]}
        return {"incident": data}

    def add_incident_note(self, incident_id: str, note_content: str) -> Dict[str, Any]:
        self._require_token()
        if not incident_id or not str(incident_id).strip():
            raise ValueError("incident_id required")
        if not note_content or not str(note_content).strip():
            raise ValueError("note.content required")
        if not self._from_email:
            raise PagerDutyUnavailableError(
                "PAGERDUTY_FROM_EMAIL not set — required for POST /incidents/{id}/notes"
            )
        client = self._ensure_client()
        resp = client.post(
            f"{PD_API_BASE}/incidents/{incident_id}/notes",
            headers=self._headers(with_from=True),
            json={"note": {"content": note_content}},
        )
        data = self._check_resp(resp, f"POST /incidents/{incident_id}/notes")
        if isinstance(data, dict) and "note" in data:
            return {"note": data["note"]}
        return {"note": data}

    # ----------------------------------------------------------------- services

    def list_services(self, limit: int = 25) -> Dict[str, Any]:
        self._require_token()
        client = self._ensure_client()
        resp = client.get(
            f"{PD_API_BASE}/services",
            headers=self._headers(),
            params={"limit": min(max(limit, 1), 100)},
        )
        data = self._check_resp(resp, "GET /services")
        if not isinstance(data, dict):
            data = {}
        return {"services": list(data.get("services") or [])}

    # ------------------------------------------------------------------ oncalls

    def list_oncalls(
        self,
        escalation_policy_ids: Optional[List[str]] = None,
        time_zone: str = "UTC",
    ) -> Dict[str, Any]:
        self._require_token()
        params: List[tuple] = [("time_zone", time_zone)]
        for eid in escalation_policy_ids or []:
            params.append(("escalation_policy_ids[]", eid))
        client = self._ensure_client()
        resp = client.get(
            f"{PD_API_BASE}/oncalls",
            headers=self._headers(),
            params=params,
        )
        data = self._check_resp(resp, "GET /oncalls")
        if not isinstance(data, dict):
            data = {}
        return {"oncalls": list(data.get("oncalls") or [])}

    # -------------------------------------------------------- change_events api

    def enqueue_change_event(
        self,
        routing_key: str,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        # Events API does NOT use the REST API token but DOES require the
        # integration's routing_key. We treat absence of REST token as
        # 'unavailable' too, since the engine needs at least one PD link.
        self._require_token()
        if not routing_key or not str(routing_key).strip():
            raise ValueError("routing_key required")
        if not isinstance(payload, dict) or "summary" not in payload:
            raise ValueError("payload.summary required")
        client = self._ensure_client()
        body = {
            "routing_key": routing_key,
            "payload": payload,
        }
        resp = client.post(
            f"{PD_EVENTS_BASE}/v2/change/enqueue",
            headers={"Content-Type": "application/json"},
            json=body,
        )
        data = self._check_resp(resp, "POST events/v2/change/enqueue")
        # PagerDuty Events API returns: {"status":"success","message":"...","change_id":"..."}
        if not isinstance(data, dict):
            data = {}
        return {
            "status": data.get("status", "success"),
            "message": data.get("message", ""),
            "change_id": data.get("change_id") or uuid.uuid4().hex,
        }

    # --------------------------------------------------- escalation_policies

    def list_escalation_policies(self, limit: int = 25) -> Dict[str, Any]:
        self._require_token()
        client = self._ensure_client()
        resp = client.get(
            f"{PD_API_BASE}/escalation_policies",
            headers=self._headers(),
            params={"limit": min(max(limit, 1), 100)},
        )
        data = self._check_resp(resp, "GET /escalation_policies")
        if not isinstance(data, dict):
            data = {}
        return {"escalation_policies": list(data.get("escalation_policies") or [])}

    # ------------------------------------------------------------------ close

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass


# -------------------------------------------------------------- singleton

_singleton: Optional[PagerDutyIncidentEngine] = None
_singleton_lock = threading.Lock()


def get_pagerduty_incident_engine(
    api_token: Optional[str] = None,
    from_email: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> PagerDutyIncidentEngine:
    """Process-wide singleton accessor."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = PagerDutyIncidentEngine(
                api_token=api_token,
                from_email=from_email,
                client=client,
            )
        return _singleton


def reset_pagerduty_incident_engine() -> None:
    """Tear down the singleton — used by tests."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "PagerDutyIncidentEngine",
    "PagerDutyUnavailableError",
    "get_pagerduty_incident_engine",
    "reset_pagerduty_incident_engine",
]
