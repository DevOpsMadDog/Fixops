"""
ALdeci PagerDuty Integration — Incident management, on-call schedules, escalation policies.

Connects to the PagerDuty REST API v2 to create/update/resolve incidents,
look up on-call schedules, fetch escalation policies, and report service health.

Usage:
    client = PagerDutyClient(api_token="u+xxxx")
    if client.is_configured():
        result = client.create_incident(title="High CVE detected", service_id="PABC123")

Vision Pillars: V1 (APP_ID-Centric), V3 (Decision Intelligence), V9 (Air-Gapped)
"""

from __future__ import annotations

import logging
import os
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-memory incident history (keyed by org_id)
# ---------------------------------------------------------------------------
_incident_history: Dict[str, List[Dict[str, Any]]] = {}
_history_lock: Optional[threading.Lock] = None


def _get_lock() -> threading.Lock:
    global _history_lock
    if _history_lock is None:
        _history_lock = threading.Lock()
    return _history_lock


# ---------------------------------------------------------------------------
# PagerDuty REST API v2 base URL
# ---------------------------------------------------------------------------
_PD_API_BASE = "https://api.pagerduty.com"

# ---------------------------------------------------------------------------
# Mock data returned when no API token is configured
# ---------------------------------------------------------------------------

_MOCK_INCIDENTS: List[Dict[str, Any]] = [
    {
        "id": "MOCK-INC-001",
        "incident_number": 1001,
        "title": "High severity CVE detected in production service",
        "status": "triggered",
        "urgency": "high",
        "created_at": "2026-01-10T00:00:00Z",
        "updated_at": "2026-01-10T00:01:00Z",
        "html_url": "https://acme.pagerduty.com/incidents/MOCK-INC-001",
        "service": {"id": "PSVC001", "summary": "Production API"},
        "assignments": [{"assignee": {"id": "PUSR001", "summary": "Alice"}}],
        "is_mock": True,
    },
    {
        "id": "MOCK-INC-002",
        "incident_number": 1002,
        "title": "Container image vulnerability — critical CVSS 9.8",
        "status": "acknowledged",
        "urgency": "high",
        "created_at": "2026-01-09T12:00:00Z",
        "updated_at": "2026-01-09T12:05:00Z",
        "html_url": "https://acme.pagerduty.com/incidents/MOCK-INC-002",
        "service": {"id": "PSVC002", "summary": "Container Registry"},
        "assignments": [{"assignee": {"id": "PUSR002", "summary": "Bob"}}],
        "is_mock": True,
    },
]

_MOCK_SCHEDULES: List[Dict[str, Any]] = [
    {
        "id": "PSCHED001",
        "name": "Security On-Call Primary",
        "time_zone": "UTC",
        "description": "Primary security team on-call rotation",
        "users": [
            {"id": "PUSR001", "summary": "Alice (Security Lead)"},
            {"id": "PUSR002", "summary": "Bob (Security Engineer)"},
        ],
        "is_mock": True,
    },
    {
        "id": "PSCHED002",
        "name": "Security On-Call Secondary",
        "time_zone": "UTC",
        "description": "Secondary escalation rotation",
        "users": [
            {"id": "PUSR003", "summary": "Carol (DevSecOps)"},
        ],
        "is_mock": True,
    },
]

_MOCK_ESCALATION_POLICIES: List[Dict[str, Any]] = [
    {
        "id": "PESC001",
        "name": "Security Critical Response",
        "description": "Escalation for critical CVEs and active exploits",
        "num_loops": 2,
        "escalation_rules": [
            {
                "escalation_delay_in_minutes": 15,
                "targets": [{"id": "PSCHED001", "type": "schedule_reference"}],
            },
            {
                "escalation_delay_in_minutes": 30,
                "targets": [{"id": "PSCHED002", "type": "schedule_reference"}],
            },
        ],
        "is_mock": True,
    },
]

_MOCK_SERVICES: List[Dict[str, Any]] = [
    {
        "id": "PSVC001",
        "name": "Production API",
        "status": "active",
        "description": "Core production API service",
        "escalation_policy": {"id": "PESC001", "summary": "Security Critical Response"},
        "incident_urgency_rule": {"type": "constant", "urgency": "high"},
        "is_mock": True,
    },
    {
        "id": "PSVC002",
        "name": "Container Registry",
        "status": "active",
        "description": "Internal container image registry",
        "escalation_policy": {"id": "PESC001", "summary": "Security Critical Response"},
        "incident_urgency_rule": {"type": "constant", "urgency": "high"},
        "is_mock": True,
    },
]


# ---------------------------------------------------------------------------
# HTTP session with retry
# ---------------------------------------------------------------------------

def _make_session(api_token: str, retries: int = 3, backoff: float = 0.5):
    """Build a requests.Session with retry logic and PagerDuty auth headers."""
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry

    session = requests.Session()
    session.headers.update({
        "Authorization": f"Token token={api_token}",
        "Content-Type": "application/json",
        "Accept": "application/vnd.pagerduty+json;version=2",
    })
    retry_strategy = Retry(
        total=retries,
        backoff_factor=backoff,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST", "PUT", "PATCH"],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


# ---------------------------------------------------------------------------
# PagerDutyClient
# ---------------------------------------------------------------------------

class PagerDutyClient:
    """
    REST API v2 client for PagerDuty incident management.

    Falls back to mock data when no API token is configured so that the
    rest of the pipeline can be exercised without real credentials.
    """

    DEFAULT_TIMEOUT = 30

    def __init__(
        self,
        api_token: Optional[str] = None,
        from_email: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        self._api_token: str = (
            api_token or os.environ.get("PAGERDUTY_API_TOKEN", "") or ""
        ).strip()
        # PagerDuty requires a From: header for incident mutation requests
        self._from_email: str = (
            from_email or os.environ.get("PAGERDUTY_FROM_EMAIL", "") or ""
        ).strip()
        self.timeout = timeout
        self._session = None  # lazy-init

    # ------------------------------------------------------------------
    # Configuration check
    # ------------------------------------------------------------------

    def is_configured(self) -> bool:
        """Return True if an API token is set."""
        return bool(self._api_token)

    # ------------------------------------------------------------------
    # Internal HTTP helpers
    # ------------------------------------------------------------------

    def _get_session(self):
        if self._session is None:
            if not self._api_token:
                return None
            self._session = _make_session(self._api_token)
        return self._session

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_body: Optional[Dict[str, Any]] = None,
        require_from: bool = False,
    ) -> Any:
        """
        Execute an HTTP request against the PagerDuty REST API v2.

        Returns parsed JSON. Raises RuntimeError on HTTP errors.
        """
        session = self._get_session()
        if session is None:
            return None

        url = f"{_PD_API_BASE}{path}"
        extra_headers: Dict[str, str] = {}
        if require_from and self._from_email:
            extra_headers["From"] = self._from_email

        try:
            resp = session.request(
                method.upper(),
                url,
                params=params,
                json=json_body,
                headers=extra_headers,
                timeout=self.timeout,
            )
        except Exception as exc:
            raise RuntimeError(
                f"PagerDuty API request failed for {method} {path}: {exc}"
            ) from exc

        if resp.status_code == 401:
            raise RuntimeError("PagerDuty API: Invalid or expired API token (401)")
        if resp.status_code == 403:
            raise RuntimeError(
                f"PagerDuty API: Insufficient permissions for {method} {path} (403)"
            )
        if resp.status_code == 404:
            raise RuntimeError(
                f"PagerDuty API: Resource not found: {path} (404)"
            )
        if resp.status_code == 429:
            raise RuntimeError("PagerDuty API: Rate limit exceeded (429)")
        if not resp.ok:
            raise RuntimeError(
                f"PagerDuty API error {resp.status_code} for {method} {path}: "
                f"{resp.text[:300]}"
            )

        if resp.status_code == 204 or not resp.content:
            return {}

        try:
            return resp.json()
        except Exception as exc:
            raise RuntimeError(
                f"PagerDuty API returned invalid JSON for {method} {path}: {exc}"
            ) from exc

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        return self._request("GET", path, params=params)

    def _post(self, path: str, json_body: Dict[str, Any]) -> Any:
        return self._request("POST", path, json_body=json_body, require_from=True)

    def _put(self, path: str, json_body: Dict[str, Any]) -> Any:
        return self._request("PUT", path, json_body=json_body, require_from=True)

    # ------------------------------------------------------------------
    # Incident management
    # ------------------------------------------------------------------

    def create_incident(
        self,
        title: str,
        service_id: str,
        urgency: str = "high",
        body_details: Optional[str] = None,
        escalation_policy_id: Optional[str] = None,
        priority_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create a new PagerDuty incident.

        Args:
            title:                 Incident summary/title (required).
            service_id:            PagerDuty service ID (required).
            urgency:               "high" or "low".
            body_details:          Optional details body (plain text).
            escalation_policy_id:  Override the service's default policy.
            priority_id:           Priority object ID.

        Returns:
            Dict representing the created incident. Mock when unconfigured.
        """
        if not title or not title.strip():
            raise ValueError("title must be a non-empty string")
        if not service_id or not service_id.strip():
            raise ValueError("service_id must be a non-empty string")

        if not self.is_configured():
            logger.warning(
                "PagerDuty token not configured — returning mock incident for service=%s.",
                service_id,
            )
            mock = dict(_MOCK_INCIDENTS[0])
            mock["id"] = f"MOCK-{uuid.uuid4().hex[:8].upper()}"
            mock["title"] = title
            mock["urgency"] = urgency
            mock["service"] = {"id": service_id, "summary": "Mock Service"}
            mock["created_at"] = datetime.now(timezone.utc).isoformat()
            mock["is_mock"] = True
            return mock

        payload: Dict[str, Any] = {
            "incident": {
                "type": "incident",
                "title": title,
                "service": {"id": service_id, "type": "service_reference"},
                "urgency": urgency,
            }
        }
        if body_details:
            payload["incident"]["body"] = {
                "type": "incident_body",
                "details": body_details,
            }
        if escalation_policy_id:
            payload["incident"]["escalation_policy"] = {
                "id": escalation_policy_id,
                "type": "escalation_policy_reference",
            }
        if priority_id:
            payload["incident"]["priority"] = {
                "id": priority_id,
                "type": "priority_reference",
            }

        data = self._post("/incidents", payload)
        incident = data.get("incident", data) if isinstance(data, dict) else data
        self._record_history(incident, "created")
        return incident

    def update_incident(
        self,
        incident_id: str,
        status: Optional[str] = None,
        title: Optional[str] = None,
        urgency: Optional[str] = None,
        resolution: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Update an existing PagerDuty incident.

        Args:
            incident_id:  PagerDuty incident ID (required).
            status:       "acknowledged" | "resolved".
            title:        New incident title.
            urgency:      "high" | "low".
            resolution:   Resolution note (only relevant when status="resolved").

        Returns:
            Dict of the updated incident. Mock when unconfigured.
        """
        if not incident_id or not incident_id.strip():
            raise ValueError("incident_id must be a non-empty string")

        if not self.is_configured():
            logger.warning(
                "PagerDuty token not configured — returning mock update for incident=%s.",
                incident_id,
            )
            mock = dict(_MOCK_INCIDENTS[0])
            mock["id"] = incident_id
            mock["status"] = status or mock["status"]
            mock["updated_at"] = datetime.now(timezone.utc).isoformat()
            mock["is_mock"] = True
            return mock

        update: Dict[str, Any] = {"type": "incident"}
        if status:
            update["status"] = status
        if title:
            update["title"] = title
        if urgency:
            update["urgency"] = urgency
        if resolution:
            update["resolution"] = resolution

        data = self._put(f"/incidents/{incident_id}", {"incident": update})
        incident = data.get("incident", data) if isinstance(data, dict) else data
        return incident

    def resolve_incident(self, incident_id: str, resolution: Optional[str] = None) -> Dict[str, Any]:
        """
        Convenience wrapper: resolve an incident.

        Args:
            incident_id:  PagerDuty incident ID.
            resolution:   Optional resolution note.

        Returns:
            Updated incident dict.
        """
        return self.update_incident(
            incident_id=incident_id,
            status="resolved",
            resolution=resolution or "Resolved by ALDECI automation",
        )

    def list_incidents(
        self,
        statuses: Optional[List[str]] = None,
        service_ids: Optional[List[str]] = None,
        limit: int = 25,
    ) -> List[Dict[str, Any]]:
        """
        List incidents with optional filtering.

        Args:
            statuses:    Filter by status list (e.g. ["triggered", "acknowledged"]).
            service_ids: Filter by service ID list.
            limit:       Max incidents to return (default 25, max 100).

        Returns:
            List of incident dicts. Mock when unconfigured.
        """
        if not self.is_configured():
            logger.warning(
                "PagerDuty token not configured — returning mock incident list."
            )
            mock_incidents = list(_MOCK_INCIDENTS)
            # Emit mock incidents as incident.created too (is_mock=True flag)
            try:
                from core.trustgraph_event_bus import get_event_bus
                bus = get_event_bus()
                for f in mock_incidents:
                    bus.emit("incident.created", {
                        "org_id": "default",
                        "engine": "pagerduty",
                        "id": f.get("id") or f.get("incident_id"),
                        "cve_id": f.get("cve_id"),
                        "severity": f.get("urgency") or f.get("severity", "unknown"),
                        "title": f.get("title") or f.get("description"),
                        "asset_id": f.get("asset_id"),
                        "is_mock": True,
                        **f,
                    })
            except Exception:
                pass
            return mock_incidents

        params: Dict[str, Any] = {"limit": min(limit, 100)}
        if statuses:
            params["statuses[]"] = statuses
        if service_ids:
            params["service_ids[]"] = service_ids

        data = self._get("/incidents", params=params)
        if not data:
            incidents: List[Dict[str, Any]] = []
        else:
            incidents = data.get("incidents", []) if isinstance(data, dict) else []

        # Emit each incident as incident.created on the TrustGraph event bus
        try:
            from core.trustgraph_event_bus import get_event_bus
            bus = get_event_bus()
            for f in incidents:
                bus.emit("incident.created", {
                    "org_id": "default",
                    "engine": "pagerduty",
                    "id": f.get("id") or f.get("incident_id"),
                    "cve_id": f.get("cve_id"),
                    "severity": f.get("urgency") or f.get("severity", "unknown"),
                    "title": f.get("title") or f.get("description"),
                    "asset_id": f.get("asset_id"),
                    "is_mock": f.get("is_mock", False),
                    **f,
                })
        except Exception:
            pass

        return incidents

    def get_incident(self, incident_id: str) -> Dict[str, Any]:
        """
        Retrieve a single incident by ID.

        Args:
            incident_id: PagerDuty incident ID.

        Returns:
            Incident dict. Mock when unconfigured.
        """
        if not incident_id or not incident_id.strip():
            raise ValueError("incident_id must be a non-empty string")

        if not self.is_configured():
            logger.warning(
                "PagerDuty token not configured — returning mock incident for id=%s.",
                incident_id,
            )
            mock = dict(_MOCK_INCIDENTS[0])
            mock["id"] = incident_id
            mock["is_mock"] = True
            return mock

        data = self._get(f"/incidents/{incident_id}")
        return data.get("incident", data) if isinstance(data, dict) else data

    # ------------------------------------------------------------------
    # On-call schedule lookup
    # ------------------------------------------------------------------

    def list_schedules(self, query: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List on-call schedules.

        Args:
            query: Optional text filter for schedule names.

        Returns:
            List of schedule dicts. Mock when unconfigured.
        """
        if not self.is_configured():
            logger.warning(
                "PagerDuty token not configured — returning mock schedules."
            )
            return list(_MOCK_SCHEDULES)

        params: Dict[str, Any] = {}
        if query:
            params["query"] = query

        data = self._get("/schedules", params=params)
        if not data:
            return []
        return data.get("schedules", []) if isinstance(data, dict) else []

    def get_oncall_users(
        self,
        schedule_id: str,
        since: Optional[str] = None,
        until: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Get users currently on-call for a given schedule.

        Args:
            schedule_id: PagerDuty schedule ID.
            since:       ISO8601 start time (defaults to now).
            until:       ISO8601 end time (defaults to now + 1 hour).

        Returns:
            List of user dicts. Mock when unconfigured.
        """
        if not schedule_id or not schedule_id.strip():
            raise ValueError("schedule_id must be a non-empty string")

        if not self.is_configured():
            logger.warning(
                "PagerDuty token not configured — returning mock on-call users for schedule=%s.",
                schedule_id,
            )
            mock_schedule = next(
                (s for s in _MOCK_SCHEDULES if s["id"] == schedule_id),
                _MOCK_SCHEDULES[0],
            )
            return mock_schedule.get("users", [])

        params: Dict[str, Any] = {}
        if since:
            params["since"] = since
        if until:
            params["until"] = until

        data = self._get(f"/schedules/{schedule_id}", params=params)
        if not data:
            return []
        schedule = data.get("schedule", data) if isinstance(data, dict) else {}
        final_schedule = schedule.get("final_schedule", {})
        return final_schedule.get("rendered_schedule_entries", [])

    # ------------------------------------------------------------------
    # Escalation policies
    # ------------------------------------------------------------------

    def list_escalation_policies(self, query: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List escalation policies.

        Args:
            query: Optional text filter for policy names.

        Returns:
            List of escalation policy dicts. Mock when unconfigured.
        """
        if not self.is_configured():
            logger.warning(
                "PagerDuty token not configured — returning mock escalation policies."
            )
            return list(_MOCK_ESCALATION_POLICIES)

        params: Dict[str, Any] = {}
        if query:
            params["query"] = query

        data = self._get("/escalation_policies", params=params)
        if not data:
            return []
        return data.get("escalation_policies", []) if isinstance(data, dict) else []

    def get_escalation_policy(self, policy_id: str) -> Dict[str, Any]:
        """
        Retrieve a single escalation policy.

        Args:
            policy_id: PagerDuty escalation policy ID.

        Returns:
            Escalation policy dict. Mock when unconfigured.
        """
        if not policy_id or not policy_id.strip():
            raise ValueError("policy_id must be a non-empty string")

        if not self.is_configured():
            mock = next(
                (p for p in _MOCK_ESCALATION_POLICIES if p["id"] == policy_id),
                dict(_MOCK_ESCALATION_POLICIES[0]),
            )
            mock["is_mock"] = True
            return mock

        data = self._get(f"/escalation_policies/{policy_id}")
        return data.get("escalation_policy", data) if isinstance(data, dict) else data

    # ------------------------------------------------------------------
    # Service health
    # ------------------------------------------------------------------

    def list_services(self, query: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        List PagerDuty services and their health status.

        Args:
            query: Optional text filter for service names.

        Returns:
            List of service dicts. Mock when unconfigured.
        """
        if not self.is_configured():
            logger.warning(
                "PagerDuty token not configured — returning mock services."
            )
            return list(_MOCK_SERVICES)

        params: Dict[str, Any] = {}
        if query:
            params["query"] = query

        data = self._get("/services", params=params)
        if not data:
            return []
        return data.get("services", []) if isinstance(data, dict) else []

    def get_service_health(self, service_id: str) -> Dict[str, Any]:
        """
        Get health summary for a specific service.

        Returns:
            Dict with service metadata and open incident count. Mock when unconfigured.
        """
        if not service_id or not service_id.strip():
            raise ValueError("service_id must be a non-empty string")

        if not self.is_configured():
            mock = next(
                (s for s in _MOCK_SERVICES if s["id"] == service_id),
                dict(_MOCK_SERVICES[0]),
            )
            mock["is_mock"] = True
            mock["open_incidents"] = 1
            return mock

        data = self._get(f"/services/{service_id}")
        service = data.get("service", data) if isinstance(data, dict) else {}

        # Fetch open incident count for this service
        try:
            inc_data = self._get(
                "/incidents",
                params={"service_ids[]": [service_id], "statuses[]": ["triggered", "acknowledged"]},
            )
            open_count = len(inc_data.get("incidents", [])) if isinstance(inc_data, dict) else 0
        except Exception as exc:
            logger.warning("Could not fetch incident count for service %s: %s", service_id, exc)
            open_count = 0

        service["open_incidents"] = open_count
        return service

    # ------------------------------------------------------------------
    # History
    # ------------------------------------------------------------------

    def get_incident_history(self, org_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Return locally tracked incident creation history (most recent first).

        Args:
            org_id: Organisation identifier (defaults to "default").

        Returns:
            List of incident summary dicts.
        """
        effective_org = (org_id or "default").strip()
        with _get_lock():
            entries = list(_incident_history.get(effective_org, []))
        return list(reversed(entries))

    def _record_history(self, incident: Dict[str, Any], action: str) -> None:
        """Store an incident action in local history."""
        entry = {
            "action": action,
            "incident_id": incident.get("id", "unknown"),
            "title": incident.get("title", ""),
            "status": incident.get("status", ""),
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "is_mock": incident.get("is_mock", False),
        }
        org_id = "default"
        with _get_lock():
            _incident_history.setdefault(org_id, []).append(entry)
