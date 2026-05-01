"""Enterprise simulation service connectors for locally-runnable security tools.

Provides REAL integrations (no mocks) with open-source enterprise tools that
can be started locally via Docker — no paid accounts required.

Services and how to start them
-------------------------------
Wazuh SIEM (port 55000):
    docker run -d --name aldeci-wazuh -p 55000:55000 wazuh/wazuh-single:4.8.0
    Default credentials: admin / SecretPassword (set via WAZUH_PASSWORD env)

Shuffle SOAR (port 3001):
    docker run -d --name aldeci-shuffle -p 3001:3001 ghcr.io/shuffle/shuffle:latest

TheHive (port 9000):
    docker run -d --name aldeci-thehive -p 9000:9000 strangebee/thehive:5

NetBox CMDB (port 8080):
    docker run -d --name aldeci-netbox -p 8080:8080 \\
        -e SECRET_KEY=aldeci-sim netboxcommunity/netbox:latest

ntfy.sh Notifications (no Docker needed — free public service):
    https://ntfy.sh — push to any topic without an account.

Run the convenience script to start all services:
    bash scripts/start_enterprise_sim.sh
"""

from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional

import requests
from requests import RequestException
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Shared dataclasses (mirror connectors.py for standalone use)
# ---------------------------------------------------------------------------


@dataclass
class ConnectorOutcome:
    """Structured response from a connector invocation."""

    status: str
    details: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        payload = dict(self.details)
        payload.setdefault("status", self.status)
        return payload

    @property
    def success(self) -> bool:
        return self.status in ("sent", "success", "fetched", "created")

    @property
    def data(self) -> Any:
        return self.details.get("data")


@dataclass
class ConnectorHealth:
    """Health check result for a connector."""

    healthy: bool
    latency_ms: float
    message: str
    checked_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "healthy": self.healthy,
            "latency_ms": self.latency_ms,
            "message": self.message,
            "checked_at": self.checked_at,
        }


# ---------------------------------------------------------------------------
# Thin HTTP base — no circuit breaker complexity for local services
# ---------------------------------------------------------------------------


class _LocalConnector:
    """Lightweight base connector for locally-running Docker services.

    Uses a single requests.Session with a short timeout. All methods
    gracefully return failure outcomes when the service is unavailable.
    """

    _DEFAULT_TIMEOUT: float = 5.0

    def __init__(self, base_url: str, timeout: float = _DEFAULT_TIMEOUT) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        adapter = HTTPAdapter(
            max_retries=Retry(total=0),  # no retries for local health checks
            pool_connections=2,
            pool_maxsize=4,
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def _get(self, path: str, **kwargs: Any) -> requests.Response:
        return self.session.get(
            f"{self.base_url}{path}", timeout=self.timeout, **kwargs
        )

    def _post(self, path: str, **kwargs: Any) -> requests.Response:
        return self.session.post(
            f"{self.base_url}{path}", timeout=self.timeout, **kwargs
        )

    def health_check(self) -> ConnectorHealth:
        raise NotImplementedError


# ---------------------------------------------------------------------------
# 1. Wazuh SIEM Connector
# ---------------------------------------------------------------------------


class WazuhSIEMConnector(_LocalConnector):
    """Real integration with Wazuh SIEM via the Wazuh REST API (v4.8).

    Start the service:
        docker run -d --name aldeci-wazuh -p 55000:55000 wazuh/wazuh-single:4.8.0

    API docs: https://documentation.wazuh.com/current/user-manual/api/reference.html

    Authentication uses basic auth. Default credentials for the single-node
    Docker image are ``admin`` / ``SecretPassword``. Override via env vars
    WAZUH_USER and WAZUH_PASSWORD.
    """

    def __init__(
        self,
        base_url: str = "https://localhost:55000",
        user: Optional[str] = None,
        password: Optional[str] = None,
        timeout: float = 5.0,
    ) -> None:
        super().__init__(base_url, timeout=timeout)
        self.user = user or os.getenv("WAZUH_USER", "wazuh")
        self.password = password or os.getenv("WAZUH_PASSWORD", "wazuh")
        # Wazuh uses self-signed certs in the default Docker image
        self._verify_ssl = False
        self._token: Optional[str] = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _auth_token(self) -> Optional[str]:
        """Obtain a JWT token from Wazuh API. Returns None on failure."""
        try:
            resp = self.session.post(
                f"{self.base_url}/security/user/authenticate",
                auth=(self.user, self.password),
                timeout=self.timeout,
                verify=self._verify_ssl,
            )
            if resp.status_code == 200:
                return resp.json().get("data", {}).get("token")
            logger.warning("Wazuh auth failed: HTTP %s", resp.status_code)
            return None
        except (RequestException, ValueError) as exc:
            logger.debug("Wazuh auth error: %s", type(exc).__name__)
            return None

    def _auth_headers(self) -> Dict[str, str]:
        if not self._token:
            self._token = self._auth_token()
        if self._token:
            return {"Authorization": f"Bearer {self._token}"}
        return {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def health_check(self) -> ConnectorHealth:
        """Check if the Wazuh manager API is reachable."""
        start = time.time()
        try:
            resp = self.session.get(
                f"{self.base_url}/",
                timeout=self.timeout,
                verify=self._verify_ssl,
            )
            ms = (time.time() - start) * 1000
            if resp.status_code in (200, 401):
                # 401 means the API is running but unauthenticated — still healthy
                return ConnectorHealth(healthy=True, latency_ms=ms, message="Wazuh API reachable")
            return ConnectorHealth(healthy=False, latency_ms=ms, message=f"HTTP {resp.status_code}")
        except (RequestException, OSError) as exc:
            ms = (time.time() - start) * 1000
            return ConnectorHealth(healthy=False, latency_ms=ms, message=type(exc).__name__)

    def push_event(self, event: Mapping[str, Any]) -> ConnectorOutcome:
        """Push a security event to Wazuh via the events endpoint.

        Args:
            event: Dict with at minimum ``message`` and optionally
                   ``location``, ``log_format``, ``agent`` fields.

        Returns:
            ConnectorOutcome with status ``sent`` on success or ``failed``.
        """
        headers = self._auth_headers()
        if not headers:
            return ConnectorOutcome("failed", {"reason": "wazuh authentication failed"})
        payload = {
            "events": [dict(event)],
        }
        try:
            resp = self.session.post(
                f"{self.base_url}/events",
                json=payload,
                headers=headers,
                timeout=self.timeout,
                verify=self._verify_ssl,
            )
            if resp.status_code in (200, 201):
                return ConnectorOutcome("sent", {"wazuh_response": resp.status_code})
            return ConnectorOutcome(
                "failed", {"reason": f"HTTP {resp.status_code}", "body": resp.text[:200]}
            )
        except (RequestException, OSError, ValueError) as exc:
            return ConnectorOutcome("failed", {"error": type(exc).__name__})

    def get_alerts(
        self,
        limit: int = 50,
        severity_min: int = 7,
    ) -> ConnectorOutcome:
        """Pull recent alerts from Wazuh.

        Args:
            limit: Maximum number of alerts to return.
            severity_min: Minimum rule level (0-15).

        Returns:
            ConnectorOutcome with ``alerts`` list in details.
        """
        headers = self._auth_headers()
        if not headers:
            return ConnectorOutcome("failed", {"reason": "wazuh authentication failed"})
        params = {"limit": str(limit), "level": str(severity_min)}
        try:
            resp = self.session.get(
                f"{self.base_url}/security/events",
                headers=headers,
                params=params,
                timeout=self.timeout,
                verify=self._verify_ssl,
            )
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                alerts = data.get("affected_items", [])

                # Emit each alert as finding.created on the TrustGraph event bus
                try:
                    from core.trustgraph_event_bus import get_event_bus
                    bus = get_event_bus()
                    for f in alerts:
                        if not isinstance(f, dict):
                            continue
                        bus.emit("finding.created", {
                            "org_id": "default",
                            "engine": "wazuh",
                            "id": f.get("id") or f.get("finding_id"),
                            "cve_id": f.get("cve_id"),
                            "severity": f.get("severity") or str(f.get("rule", {}).get("level", "unknown")) if isinstance(f.get("rule"), dict) else f.get("severity", "unknown"),
                            "title": f.get("title") or f.get("description") or (f.get("rule", {}) or {}).get("description"),
                            "asset_id": f.get("asset_id") or (f.get("agent", {}) or {}).get("id"),
                            "cvss": f.get("cvss"),
                            "epss": f.get("epss"),
                            "is_mock": f.get("is_mock", False),
                            **f,
                        })
                except Exception:
                    pass

                return ConnectorOutcome(
                    "fetched",
                    {"alerts": alerts, "count": len(alerts), "total": data.get("total_affected_items", 0)},
                )
            return ConnectorOutcome(
                "failed", {"reason": f"HTTP {resp.status_code}", "body": resp.text[:200]}
            )
        except (RequestException, OSError, ValueError) as exc:
            return ConnectorOutcome("failed", {"error": type(exc).__name__})


# ---------------------------------------------------------------------------
# 2. Shuffle SOAR Connector
# ---------------------------------------------------------------------------


class ShuffleSOARConnector(_LocalConnector):
    """Real integration with Shuffle SOAR via its REST API.

    Start the service:
        docker run -d --name aldeci-shuffle -p 3001:3001 ghcr.io/shuffle/shuffle:latest

    API docs: https://shuffler.io/docs/api

    Authentication uses an API key that is generated upon first login at
    http://localhost:3001. Store it in the env var SHUFFLE_API_KEY or pass
    as the ``api_key`` constructor argument.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:3001",
        api_key: Optional[str] = None,
        timeout: float = 5.0,
    ) -> None:
        super().__init__(base_url, timeout=timeout)
        self.api_key = api_key or os.getenv("SHUFFLE_API_KEY", "")

    def _headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def health_check(self) -> ConnectorHealth:
        """Check if the Shuffle API is reachable."""
        start = time.time()
        try:
            resp = self._get("/api/v1/health")
            ms = (time.time() - start) * 1000
            if resp.status_code in (200, 401, 403):
                return ConnectorHealth(healthy=True, latency_ms=ms, message="Shuffle API reachable")
            return ConnectorHealth(healthy=False, latency_ms=ms, message=f"HTTP {resp.status_code}")
        except (RequestException, OSError) as exc:
            ms = (time.time() - start) * 1000
            return ConnectorHealth(healthy=False, latency_ms=ms, message=type(exc).__name__)

    def list_workflows(self) -> ConnectorOutcome:
        """List available SOAR workflows.

        Returns:
            ConnectorOutcome with ``workflows`` list in details.
        """
        try:
            resp = self._get("/api/v1/workflows", headers=self._headers())
            if resp.status_code == 200:
                workflows = resp.json() or []
                return ConnectorOutcome(
                    "fetched", {"workflows": workflows, "count": len(workflows)}
                )
            return ConnectorOutcome(
                "failed", {"reason": f"HTTP {resp.status_code}", "body": resp.text[:200]}
            )
        except (RequestException, OSError, ValueError) as exc:
            return ConnectorOutcome("failed", {"error": type(exc).__name__})

    def trigger_workflow(
        self,
        workflow_id: str,
        execution_argument: Optional[str] = None,
        extra_data: Optional[Dict[str, Any]] = None,
    ) -> ConnectorOutcome:
        """Trigger a Shuffle workflow execution.

        Args:
            workflow_id: UUID of the workflow to execute.
            execution_argument: Optional string argument passed to the workflow.
            extra_data: Optional dict of additional execution parameters.

        Returns:
            ConnectorOutcome with ``execution_id`` in details on success.
        """
        payload: Dict[str, Any] = {"execution_argument": execution_argument or ""}
        if extra_data:
            payload.update(extra_data)
        try:
            resp = self._post(
                f"/api/v1/workflows/{workflow_id}/execute",
                json=payload,
                headers=self._headers(),
            )
            if resp.status_code in (200, 201):
                data = resp.json()
                return ConnectorOutcome(
                    "sent",
                    {"execution_id": data.get("execution_id", ""), "workflow_id": workflow_id},
                )
            return ConnectorOutcome(
                "failed", {"reason": f"HTTP {resp.status_code}", "body": resp.text[:200]}
            )
        except (RequestException, OSError, ValueError) as exc:
            return ConnectorOutcome("failed", {"error": type(exc).__name__})

    def create_ir_playbook(self, name: str, description: str = "") -> ConnectorOutcome:
        """Create a new IR playbook workflow in Shuffle.

        This creates a minimal skeleton workflow that can be further edited
        in the Shuffle UI at http://localhost:3001.

        Args:
            name: Workflow name.
            description: Optional workflow description.

        Returns:
            ConnectorOutcome with ``workflow_id`` in details on success.
        """
        payload = {
            "name": name,
            "description": description,
            "tags": ["ir", "playbook", "aldeci"],
            "actions": [],
            "triggers": [],
        }
        try:
            resp = self._post("/api/v1/workflows", json=payload, headers=self._headers())
            if resp.status_code in (200, 201):
                data = resp.json()
                return ConnectorOutcome(
                    "created",
                    {"workflow_id": data.get("id", ""), "name": name},
                )
            return ConnectorOutcome(
                "failed", {"reason": f"HTTP {resp.status_code}", "body": resp.text[:200]}
            )
        except (RequestException, OSError, ValueError) as exc:
            return ConnectorOutcome("failed", {"error": type(exc).__name__})


# ---------------------------------------------------------------------------
# 3. TheHive Connector
# ---------------------------------------------------------------------------


class TheHiveConnector(_LocalConnector):
    """Real integration with TheHive 5 incident management platform.

    Start the service:
        docker run -d --name aldeci-thehive -p 9000:9000 strangebee/thehive:5

    API docs: https://docs.strangebee.com/thehive/api-docs/

    Authentication uses an API key. Create one in the TheHive UI under
    My Profile → API Key, or set it in the THEHIVE_API_KEY env var.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:9000",
        api_key: Optional[str] = None,
        organisation: str = "admin",
        timeout: float = 5.0,
    ) -> None:
        super().__init__(base_url, timeout=timeout)
        self.api_key = api_key or os.getenv("THEHIVE_API_KEY", "")
        self.organisation = organisation

    def _headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {
            "Content-Type": "application/json",
            "X-Organisation": self.organisation,
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers

    def health_check(self) -> ConnectorHealth:
        """Check if TheHive API is reachable."""
        start = time.time()
        try:
            resp = self._get("/api/v1/status")
            ms = (time.time() - start) * 1000
            if resp.status_code in (200, 401, 403):
                return ConnectorHealth(healthy=True, latency_ms=ms, message="TheHive API reachable")
            return ConnectorHealth(healthy=False, latency_ms=ms, message=f"HTTP {resp.status_code}")
        except (RequestException, OSError) as exc:
            ms = (time.time() - start) * 1000
            return ConnectorHealth(healthy=False, latency_ms=ms, message=type(exc).__name__)

    def create_case(
        self,
        title: str,
        description: str,
        severity: int = 2,
        tlp: int = 2,
        tags: Optional[List[str]] = None,
    ) -> ConnectorOutcome:
        """Create an incident case in TheHive.

        Args:
            title: Case title.
            description: Case summary.
            severity: 1=Low, 2=Medium, 3=High, 4=Critical.
            tlp: Traffic Light Protocol: 0=White,1=Green,2=Amber,3=Red.
            tags: Optional list of string tags.

        Returns:
            ConnectorOutcome with ``case_id`` and ``case_number`` in details.
        """
        payload: Dict[str, Any] = {
            "title": title,
            "description": description,
            "severity": severity,
            "tlp": tlp,
            "tags": tags or ["aldeci"],
            "flag": False,
        }
        try:
            resp = self._post("/api/v1/case", json=payload, headers=self._headers())
            if resp.status_code in (200, 201):
                data = resp.json()
                case_id = data.get("_id", "")
                case_number = data.get("number", 0)

                # Emit case as incident.created on the TrustGraph event bus
                try:
                    from core.trustgraph_event_bus import get_event_bus
                    bus = get_event_bus()
                    bus.emit("incident.created", {
                        "org_id": "default",
                        "engine": "thehive",
                        "id": case_id or f"case_{case_number}",
                        "cve_id": None,
                        "severity": str(severity),
                        "title": title,
                        "description": description,
                        "asset_id": None,
                        "tlp": tlp,
                        "tags": tags or ["aldeci"],
                        "case_number": case_number,
                        "is_mock": False,
                    })
                except Exception:
                    pass

                return ConnectorOutcome(
                    "created",
                    {
                        "case_id": case_id,
                        "case_number": case_number,
                        "title": title,
                    },
                )
            return ConnectorOutcome(
                "failed", {"reason": f"HTTP {resp.status_code}", "body": resp.text[:200]}
            )
        except (RequestException, OSError, ValueError) as exc:
            return ConnectorOutcome("failed", {"error": type(exc).__name__})

    def add_observable(
        self,
        case_id: str,
        data_type: str,
        data: str,
        message: str = "",
        tlp: int = 2,
        tags: Optional[List[str]] = None,
    ) -> ConnectorOutcome:
        """Add an observable (IOC) to an existing TheHive case.

        Args:
            case_id: TheHive internal case ID (``_id`` field).
            data_type: Observable type, e.g. ``ip``, ``domain``, ``hash``,
                       ``url``, ``filename``, ``other``.
            data: The observable value.
            message: Optional description.
            tlp: Traffic Light Protocol level.
            tags: Optional list of tags.

        Returns:
            ConnectorOutcome with ``observable_id`` in details.
        """
        payload: Dict[str, Any] = {
            "dataType": data_type,
            "data": data,
            "message": message,
            "tlp": tlp,
            "tags": tags or [],
            "ioc": True,
            "sighted": False,
        }
        try:
            resp = self._post(
                f"/api/v1/case/{case_id}/observable",
                json=payload,
                headers=self._headers(),
            )
            if resp.status_code in (200, 201):
                result = resp.json()
                # TheHive may return a list when bulk-creating
                obs_id = ""
                if isinstance(result, list) and result:
                    obs_id = result[0].get("_id", "")
                elif isinstance(result, dict):
                    obs_id = result.get("_id", "")
                return ConnectorOutcome(
                    "created",
                    {"observable_id": obs_id, "data_type": data_type, "data": data},
                )
            return ConnectorOutcome(
                "failed", {"reason": f"HTTP {resp.status_code}", "body": resp.text[:200]}
            )
        except (RequestException, OSError, ValueError) as exc:
            return ConnectorOutcome("failed", {"error": type(exc).__name__})

    def list_cases(self, limit: int = 20) -> ConnectorOutcome:
        """List recent cases from TheHive.

        Args:
            limit: Maximum number of cases to return.

        Returns:
            ConnectorOutcome with ``cases`` list in details.
        """
        payload = {
            "query": [{"_name": "listCase"}],
            "from": 0,
            "to": limit,
        }
        try:
            resp = self._post(
                "/api/v1/query?name=cases",
                json=payload,
                headers=self._headers(),
            )
            if resp.status_code == 200:
                cases = resp.json() or []
                return ConnectorOutcome(
                    "fetched", {"cases": cases, "count": len(cases)}
                )
            return ConnectorOutcome(
                "failed", {"reason": f"HTTP {resp.status_code}", "body": resp.text[:200]}
            )
        except (RequestException, OSError, ValueError) as exc:
            return ConnectorOutcome("failed", {"error": type(exc).__name__})


# ---------------------------------------------------------------------------
# 4. NetBox CMDB Connector
# ---------------------------------------------------------------------------


class NetBoxCMDBConnector(_LocalConnector):
    """Real integration with NetBox CMDB via its REST API (v4.x).

    Start the service:
        docker run -d --name aldeci-netbox -p 8080:8080 \\
            -e SECRET_KEY=aldeci-sim netboxcommunity/netbox:latest

    API docs: https://demo.netbox.dev/api/

    Authentication uses an API token. Create one in NetBox under
    Admin → API Tokens, or set it in the NETBOX_API_TOKEN env var.
    The default superuser token for fresh installs is often ``0123456789abcdef0123456789abcdef01234567``.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:8080",
        api_token: Optional[str] = None,
        timeout: float = 5.0,
    ) -> None:
        super().__init__(base_url, timeout=timeout)
        self.api_token = api_token or os.getenv("NETBOX_API_TOKEN", "")

    def _headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if self.api_token:
            headers["Authorization"] = f"Token {self.api_token}"
        return headers

    def health_check(self) -> ConnectorHealth:
        """Check if the NetBox API is reachable."""
        start = time.time()
        try:
            resp = self._get("/api/status/")
            ms = (time.time() - start) * 1000
            if resp.status_code in (200, 401, 403):
                return ConnectorHealth(healthy=True, latency_ms=ms, message="NetBox API reachable")
            return ConnectorHealth(healthy=False, latency_ms=ms, message=f"HTTP {resp.status_code}")
        except (RequestException, OSError) as exc:
            ms = (time.time() - start) * 1000
            return ConnectorHealth(healthy=False, latency_ms=ms, message=type(exc).__name__)

    def create_device(
        self,
        name: str,
        device_type_id: int,
        site_id: int,
        role_id: int,
        status: str = "active",
        comments: str = "",
    ) -> ConnectorOutcome:
        """Create a device record in NetBox CMDB.

        Args:
            name: Device hostname.
            device_type_id: NetBox device type ID (must pre-exist).
            site_id: NetBox site ID (must pre-exist).
            role_id: NetBox device role ID (must pre-exist).
            status: Device status, e.g. ``active``, ``planned``, ``decommissioning``.
            comments: Free-text notes.

        Returns:
            ConnectorOutcome with ``device_id`` and ``device_url`` in details.
        """
        payload: Dict[str, Any] = {
            "name": name,
            "device_type": device_type_id,
            "site": site_id,
            "role": role_id,
            "status": status,
            "comments": comments,
        }
        try:
            resp = self._post("/api/dcim/devices/", json=payload, headers=self._headers())
            if resp.status_code in (200, 201):
                data = resp.json()
                return ConnectorOutcome(
                    "created",
                    {
                        "device_id": data.get("id"),
                        "device_url": data.get("url", ""),
                        "name": name,
                    },
                )
            return ConnectorOutcome(
                "failed", {"reason": f"HTTP {resp.status_code}", "body": resp.text[:200]}
            )
        except (RequestException, OSError, ValueError) as exc:
            return ConnectorOutcome("failed", {"error": type(exc).__name__})

    def update_device(
        self, device_id: int, fields: Mapping[str, Any]
    ) -> ConnectorOutcome:
        """Partially update a NetBox device record (HTTP PATCH).

        Args:
            device_id: NetBox internal device ID.
            fields: Dict of fields to update (e.g. ``{"status": "active"}``).

        Returns:
            ConnectorOutcome with ``device_id`` in details.
        """
        try:
            resp = self.session.patch(
                f"{self.base_url}/api/dcim/devices/{device_id}/",
                json=dict(fields),
                headers=self._headers(),
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                return ConnectorOutcome("success", {"device_id": device_id})
            return ConnectorOutcome(
                "failed", {"reason": f"HTTP {resp.status_code}", "body": resp.text[:200]}
            )
        except (RequestException, OSError, ValueError) as exc:
            return ConnectorOutcome("failed", {"error": type(exc).__name__})

    def list_devices(
        self, site: Optional[str] = None, status: Optional[str] = None, limit: int = 50
    ) -> ConnectorOutcome:
        """List devices from the NetBox CMDB.

        Args:
            site: Optional site slug to filter by.
            status: Optional status filter, e.g. ``active``.
            limit: Maximum records to return.

        Returns:
            ConnectorOutcome with ``devices`` list in details.
        """
        params: Dict[str, Any] = {"limit": limit}
        if site:
            params["site"] = site
        if status:
            params["status"] = status
        try:
            resp = self._get("/api/dcim/devices/", params=params, headers=self._headers())
            if resp.status_code == 200:
                data = resp.json()
                devices = data.get("results", [])
                return ConnectorOutcome(
                    "fetched",
                    {"devices": devices, "count": data.get("count", 0)},
                )
            return ConnectorOutcome(
                "failed", {"reason": f"HTTP {resp.status_code}", "body": resp.text[:200]}
            )
        except (RequestException, OSError, ValueError) as exc:
            return ConnectorOutcome("failed", {"error": type(exc).__name__})

    def create_ip_address(
        self,
        address: str,
        status: str = "active",
        description: str = "",
        assigned_object_type: Optional[str] = None,
        assigned_object_id: Optional[int] = None,
    ) -> ConnectorOutcome:
        """Create an IP address record in NetBox.

        Args:
            address: CIDR notation, e.g. ``192.168.1.10/24``.
            status: IP status, e.g. ``active``, ``reserved``, ``deprecated``.
            description: Optional description.
            assigned_object_type: Optional content-type string for assignment,
                e.g. ``dcim.interface``.
            assigned_object_id: Optional object ID to assign this IP to.

        Returns:
            ConnectorOutcome with ``ip_id`` in details.
        """
        payload: Dict[str, Any] = {
            "address": address,
            "status": status,
            "description": description,
        }
        if assigned_object_type and assigned_object_id is not None:
            payload["assigned_object_type"] = assigned_object_type
            payload["assigned_object_id"] = assigned_object_id
        try:
            resp = self._post(
                "/api/ipam/ip-addresses/", json=payload, headers=self._headers()
            )
            if resp.status_code in (200, 201):
                data = resp.json()
                return ConnectorOutcome(
                    "created", {"ip_id": data.get("id"), "address": address}
                )
            return ConnectorOutcome(
                "failed", {"reason": f"HTTP {resp.status_code}", "body": resp.text[:200]}
            )
        except (RequestException, OSError, ValueError) as exc:
            return ConnectorOutcome("failed", {"error": type(exc).__name__})


# ---------------------------------------------------------------------------
# 5. ntfy.sh Notification Connector
# ---------------------------------------------------------------------------


class NtfyNotificationConnector(_LocalConnector):
    """Push notifications to ntfy.sh topics — free, no account required.

    No Docker needed. Uses the public ntfy.sh service (or a self-hosted
    instance). Any subscriber to the topic will receive the message.

    ntfy.sh docs: https://docs.ntfy.sh/

    Self-hosted ntfy (optional):
        docker run -d --name aldeci-ntfy -p 8090:80 binwiederhier/ntfy serve

    Default server: https://ntfy.sh (public, no auth, no account).
    """

    def __init__(
        self,
        server: str = "https://ntfy.sh",
        default_topic: str = "aldeci-alerts",
        access_token: Optional[str] = None,
        timeout: float = 5.0,
    ) -> None:
        super().__init__(server, timeout=timeout)
        self.default_topic = default_topic
        self.access_token = access_token or os.getenv("NTFY_ACCESS_TOKEN", "")

    def _headers(
        self,
        title: str = "",
        priority: str = "default",
        tags: Optional[List[str]] = None,
    ) -> Dict[str, str]:
        headers: Dict[str, str] = {"Content-Type": "text/plain"}
        if self.access_token:
            headers["Authorization"] = f"Bearer {self.access_token}"
        if title:
            headers["Title"] = title
        if priority and priority != "default":
            headers["Priority"] = priority
        if tags:
            headers["Tags"] = ",".join(tags)
        return headers

    def health_check(self) -> ConnectorHealth:
        """Check if the ntfy server is reachable."""
        start = time.time()
        try:
            resp = self._get("/v1/health")
            ms = (time.time() - start) * 1000
            if resp.status_code == 200:
                return ConnectorHealth(healthy=True, latency_ms=ms, message="ntfy server healthy")
            return ConnectorHealth(healthy=False, latency_ms=ms, message=f"HTTP {resp.status_code}")
        except (RequestException, OSError) as exc:
            ms = (time.time() - start) * 1000
            return ConnectorHealth(healthy=False, latency_ms=ms, message=type(exc).__name__)

    def send_alert(
        self,
        message: str,
        title: str = "ALDECI Alert",
        topic: Optional[str] = None,
        priority: str = "default",
        tags: Optional[List[str]] = None,
    ) -> ConnectorOutcome:
        """Push an alert message to an ntfy.sh topic.

        Priority levels: ``max``, ``high``, ``default``, ``low``, ``min``.
        Tags become emoji prefixes on phones (e.g. ``["warning"]``).

        Args:
            message: The notification body.
            title: Notification title shown in the OS notification.
            topic: Override the default topic.
            priority: ntfy priority level.
            tags: List of ntfy tag strings (maps to emoji).

        Returns:
            ConnectorOutcome with ``message_id`` in details on success.
        """
        dest_topic = topic or self.default_topic
        try:
            resp = self.session.post(
                f"{self.base_url}/{dest_topic}",
                data=message.encode(),
                headers=self._headers(title=title, priority=priority, tags=tags),
                timeout=self.timeout,
            )
            if resp.status_code == 200:
                data = resp.json()
                return ConnectorOutcome(
                    "sent",
                    {"message_id": data.get("id", ""), "topic": dest_topic},
                )
            return ConnectorOutcome(
                "failed", {"reason": f"HTTP {resp.status_code}", "body": resp.text[:200]}
            )
        except (RequestException, OSError, ValueError) as exc:
            return ConnectorOutcome("failed", {"error": type(exc).__name__})

    def send_finding(
        self,
        finding: Mapping[str, Any],
        topic: Optional[str] = None,
    ) -> ConnectorOutcome:
        """Send a security finding as a formatted ntfy notification.

        Args:
            finding: Dict with keys like ``title``, ``severity``, ``cve_id``,
                     ``asset``, ``description``.
            topic: Override the default topic.

        Returns:
            ConnectorOutcome.
        """
        severity = str(finding.get("severity", "medium")).lower()
        priority_map = {
            "critical": "max",
            "high": "high",
            "medium": "default",
            "low": "low",
            "info": "min",
        }
        priority = priority_map.get(severity, "default")
        title = str(finding.get("title", "Security Finding"))
        cve = finding.get("cve_id", "")
        asset = finding.get("asset", "unknown")
        desc = str(finding.get("description", ""))[:300]
        body = f"[{severity.upper()}] {title}\nAsset: {asset}"
        if cve:
            body += f"\nCVE: {cve}"
        if desc:
            body += f"\n{desc}"
        tags = [severity] if severity in ("warning", "rotating_light", "skull") else []
        return self.send_alert(
            message=body,
            title=f"ALDECI: {title}",
            topic=topic,
            priority=priority,
            tags=tags or None,
        )


# ---------------------------------------------------------------------------
# Convenience: registry of all local connectors
# ---------------------------------------------------------------------------


def get_all_connectors(
    wazuh_url: str = "https://localhost:55000",
    shuffle_url: str = "http://localhost:3001",
    thehive_url: str = "http://localhost:9000",
    netbox_url: str = "http://localhost:8080",
    ntfy_server: str = "https://ntfy.sh",
    ntfy_topic: str = "aldeci-alerts",
) -> Dict[str, _LocalConnector]:
    """Instantiate all enterprise sim connectors with default local URLs.

    Settings are read from environment variables when available:
      WAZUH_USER, WAZUH_PASSWORD
      SHUFFLE_API_KEY
      THEHIVE_API_KEY
      NETBOX_API_TOKEN
      NTFY_ACCESS_TOKEN

    Returns:
        Dict mapping service name to connector instance.
    """
    return {
        "wazuh": WazuhSIEMConnector(base_url=wazuh_url),
        "shuffle": ShuffleSOARConnector(base_url=shuffle_url),
        "thehive": TheHiveConnector(base_url=thehive_url),
        "netbox": NetBoxCMDBConnector(base_url=netbox_url),
        "ntfy": NtfyNotificationConnector(server=ntfy_server, default_topic=ntfy_topic),
    }


def health_check_all(
    connectors: Optional[Dict[str, _LocalConnector]] = None,
) -> Dict[str, Dict[str, Any]]:
    """Run health checks on all connectors and return results dict.

    Args:
        connectors: Optional dict of connectors. Uses ``get_all_connectors()``
                    defaults when not provided.

    Returns:
        Dict mapping service name → health dict (``healthy``, ``message``, etc.).
    """
    if connectors is None:
        connectors = get_all_connectors()
    results: Dict[str, Dict[str, Any]] = {}
    for name, connector in connectors.items():
        try:
            health = connector.health_check()
            results[name] = health.to_dict()
        except Exception as exc:  # noqa: BLE001 — catch-all for health summary
            results[name] = {
                "healthy": False,
                "latency_ms": 0,
                "message": type(exc).__name__,
            }
    return results
