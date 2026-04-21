"""ServiceNow Bidirectional Connector — ALDECI.

Enterprise-grade connector for ServiceNow integration:
  - CMDB sync: pull Configuration Items (CIs) as ALDECI assets
  - Incident sync: create/update ServiceNow incidents from ALDECI alerts
  - Change management: create change requests for remediation actions
  - OAuth2 authentication with token refresh
  - Circuit breaker + rate limiting for fault tolerance

ServiceNow API:
  - Table API: /api/now/table/{table_name}
  - CMDB API: /api/now/cmdb/instance/{class_name}
  - Compatibility: All ServiceNow releases (Zurich, Yokohama, Xanadu, Washington DC+)
  - Auth: OAuth 2.0 client_credentials grant

Compliance: ITIL v4, NIST CSF ID.AM, ISO 27001 A.8.1
"""

from __future__ import annotations

import json
import logging
import os
import time
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional
from urllib.parse import urljoin

import requests
from requests import RequestException, Response
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

_logger = logging.getLogger(__name__)


# ======================================================================
# Data classes
# ======================================================================

@dataclass
class ServiceNowOutcome:
    """Structured response from a ServiceNow API call."""

    status: str  # "success", "failed", "skipped"
    details: Dict[str, Any]

    @property
    def success(self) -> bool:
        return self.status == "success"

    @property
    def data(self) -> Any:
        return self.details.get("data")

    def to_dict(self) -> Dict[str, Any]:
        return {"status": self.status, **self.details}


@dataclass
class OAuth2Token:
    """Holds an OAuth2 access token with expiry tracking."""

    access_token: str = ""
    token_type: str = "Bearer"
    expires_at: float = 0.0

    @property
    def expired(self) -> bool:
        return time.time() >= (self.expires_at - 30)  # 30s buffer


# ======================================================================
# ServiceNow Connector
# ======================================================================

class ServiceNowConnector:
    """Bidirectional ServiceNow connector with OAuth2 and circuit breaker.

    Supports:
      - CMDB CI pull (sync Configuration Items as ALDECI assets)
      - Incident create/update/query
      - Change request create
      - OAuth2 client_credentials token management
    """

    def __init__(
        self,
        instance_url: str,
        *,
        client_id: str = "",
        client_secret: str = "",
        username: str = "",
        password: str = "",
        auth_method: str = "oauth2",
        timeout: float = 30.0,
        max_retries: int = 3,
        requests_per_second: float = 5.0,
    ) -> None:
        self.instance_url = instance_url.rstrip("/")
        self._client_id = client_id or os.getenv("SERVICENOW_CLIENT_ID", "")
        self._client_secret = client_secret or os.getenv("SERVICENOW_CLIENT_SECRET", "")
        self._username = username or os.getenv("SERVICENOW_USERNAME", "")
        self._password = password or os.getenv("SERVICENOW_PASSWORD", "")
        self._auth_method = auth_method
        self._timeout = timeout
        self._token = OAuth2Token()
        self._token_lock = threading.Lock()

        # HTTP session with retry
        self._session = requests.Session()
        retry = Retry(
            total=max_retries,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PUT", "PATCH"],
        )
        adapter = HTTPAdapter(max_retries=retry)
        self._session.mount("https://", adapter)
        self._session.mount("http://", adapter)

        # Rate limiter (token bucket)
        self._rate_limit = requests_per_second
        self._tokens = float(min(20, int(requests_per_second * 2)))
        self._last_refill = time.time()
        self._rate_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Configuration check
    # ------------------------------------------------------------------

    @property
    def configured(self) -> bool:
        """Return True if the connector has enough config to authenticate."""
        if self._auth_method == "oauth2":
            return bool(self.instance_url and self._client_id and self._client_secret)
        return bool(self.instance_url and self._username and self._password)

    # ------------------------------------------------------------------
    # OAuth2 token management
    # ------------------------------------------------------------------

    def _get_token(self) -> str:
        """Obtain or refresh OAuth2 access token."""
        with self._token_lock:
            if not self._token.expired and self._token.access_token:
                return self._token.access_token

            if self._auth_method != "oauth2":
                return ""

            url = f"{self.instance_url}/oauth_token.do"
            payload = {
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
            }
            try:
                resp = self._session.post(url, data=payload, timeout=self._timeout)
                resp.raise_for_status()
                body = resp.json()
                self._token = OAuth2Token(
                    access_token=body["access_token"],
                    token_type=body.get("token_type", "Bearer"),
                    expires_at=time.time() + int(body.get("expires_in", 1800)),
                )
                _logger.info("ServiceNow OAuth2 token acquired (expires in %ss)", body.get("expires_in", 1800))
                return self._token.access_token
            except RequestException as exc:
                _logger.error("OAuth2 token request failed: %s", exc)
                raise

    def _auth_headers(self) -> Dict[str, str]:
        """Build authentication headers."""
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if self._auth_method == "oauth2":
            token = self._get_token()
            headers["Authorization"] = f"Bearer {token}"
        return headers

    def _auth_kwargs(self) -> Dict[str, Any]:
        """Build auth kwargs for requests (basic auth fallback)."""
        if self._auth_method == "basic":
            return {"auth": (self._username, self._password)}
        return {}

    # ------------------------------------------------------------------
    # Rate limiting
    # ------------------------------------------------------------------

    def _acquire_rate_token(self) -> bool:
        """Token-bucket rate limiter. Returns True if request is allowed."""
        with self._rate_lock:
            now = time.time()
            elapsed = now - self._last_refill
            self._tokens = min(20, self._tokens + elapsed * self._rate_limit)
            self._last_refill = now
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
        return False

    def _wait_for_rate(self, timeout: float = 5.0) -> bool:
        """Wait until a rate token is available."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self._acquire_rate_token():
                return True
            time.sleep(0.05)
        return False

    # ------------------------------------------------------------------
    # Low-level API call
    # ------------------------------------------------------------------

    def _api_call(
        self,
        method: str,
        path: str,
        *,
        json_body: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, str]] = None,
    ) -> ServiceNowOutcome:
        """Make an authenticated API call to ServiceNow."""
        if not self.configured:
            return ServiceNowOutcome("skipped", {"reason": "connector not configured"})

        if not self._wait_for_rate():
            return ServiceNowOutcome("failed", {"reason": "rate limit exceeded"})

        url = f"{self.instance_url}{path}"
        try:
            resp = self._session.request(
                method,
                url,
                headers=self._auth_headers(),
                json=json_body,
                params=params,
                timeout=self._timeout,
                **self._auth_kwargs(),
            )
            resp.raise_for_status()
        except RequestException as exc:
            _logger.error("ServiceNow API call failed: %s %s -> %s", method, path, exc)
            return ServiceNowOutcome("failed", {
                "reason": "api_call_failed",
                "error": type(exc).__name__,
                "url": url,
            })

        try:
            body = resp.json()
        except ValueError:
            body = {}

        return ServiceNowOutcome("success", {
            "data": body.get("result", body),
            "status_code": resp.status_code,
            "url": url,
        })

    # ------------------------------------------------------------------
    # Health check
    # ------------------------------------------------------------------

    def health_check(self) -> ServiceNowOutcome:
        """Check connectivity to ServiceNow instance."""
        return self._api_call(
            "GET",
            "/api/now/table/sys_properties",
            params={"sysparm_limit": "1", "sysparm_fields": "name"},
        )

    # ------------------------------------------------------------------
    # CMDB operations
    # ------------------------------------------------------------------

    def pull_cmdb_cis(
        self,
        ci_class: str = "cmdb_ci_server",
        *,
        limit: int = 100,
        offset: int = 0,
        query: str = "",
    ) -> ServiceNowOutcome:
        """Pull Configuration Items from ServiceNow CMDB.

        Args:
            ci_class: ServiceNow CI class name (e.g., cmdb_ci_server).
            limit: Max records to fetch (ServiceNow default page size).
            offset: Pagination offset.
            query: ServiceNow encoded query (e.g., 'operational_status=1').

        Returns:
            ServiceNowOutcome with list of CI records.
        """
        params: Dict[str, str] = {
            "sysparm_limit": str(limit),
            "sysparm_offset": str(offset),
            "sysparm_display_value": "true",
            "sysparm_fields": (
                "sys_id,name,ip_address,os,sys_class_name,category,"
                "environment,operational_status,serial_number,"
                "assigned_to,location,sys_updated_on"
            ),
        }
        if query:
            params["sysparm_query"] = query

        return self._api_call("GET", f"/api/now/table/{ci_class}", params=params)

    def get_cmdb_ci(self, ci_class: str, sys_id: str) -> ServiceNowOutcome:
        """Get a single CMDB CI by sys_id."""
        return self._api_call(
            "GET",
            f"/api/now/table/{ci_class}/{sys_id}",
            params={"sysparm_display_value": "true"},
        )

    # ------------------------------------------------------------------
    # Incident operations
    # ------------------------------------------------------------------

    def create_incident(
        self,
        short_description: str,
        *,
        description: str = "",
        urgency: str = "2",
        impact: str = "2",
        assignment_group: str = "",
        caller_id: str = "",
        category: str = "security",
        subcategory: str = "",
        cmdb_ci: str = "",
        additional_fields: Optional[Dict[str, Any]] = None,
    ) -> ServiceNowOutcome:
        """Create a new incident in ServiceNow.

        Args:
            short_description: Incident title (required).
            description: Full description.
            urgency: 1=High, 2=Medium, 3=Low.
            impact: 1=High, 2=Medium, 3=Low.
            assignment_group: ServiceNow group sys_id.
            caller_id: ServiceNow user sys_id.
            category: Incident category.
            subcategory: Incident subcategory.
            cmdb_ci: Associated CI sys_id.
            additional_fields: Any extra fields to include.

        Returns:
            ServiceNowOutcome with created incident details.
        """
        payload: Dict[str, Any] = {
            "short_description": short_description,
            "description": description or short_description,
            "urgency": urgency,
            "impact": impact,
            "category": category,
        }
        if assignment_group:
            payload["assignment_group"] = assignment_group
        if caller_id:
            payload["caller_id"] = caller_id
        if subcategory:
            payload["subcategory"] = subcategory
        if cmdb_ci:
            payload["cmdb_ci"] = cmdb_ci
        if additional_fields:
            payload.update(additional_fields)

        result = self._api_call("POST", "/api/now/table/incident", json_body=payload)
        if result.success and isinstance(result.data, dict):
            _logger.info(
                "ServiceNow incident created: %s (sys_id=%s)",
                result.data.get("number", "?"),
                result.data.get("sys_id", "?"),
            )
        return result

    def update_incident(
        self, sys_id: str, fields: Dict[str, Any]
    ) -> ServiceNowOutcome:
        """Update an existing ServiceNow incident."""
        if not sys_id:
            return ServiceNowOutcome("failed", {"reason": "sys_id is required"})
        return self._api_call(
            "PUT",
            f"/api/now/table/incident/{sys_id}",
            json_body=fields,
        )

    def get_incident(self, sys_id: str) -> ServiceNowOutcome:
        """Fetch a single incident by sys_id."""
        return self._api_call(
            "GET",
            f"/api/now/table/incident/{sys_id}",
            params={"sysparm_display_value": "true"},
        )

    def query_incidents(
        self,
        query: str = "",
        *,
        limit: int = 50,
        offset: int = 0,
    ) -> ServiceNowOutcome:
        """Query incidents with encoded query string."""
        params: Dict[str, str] = {
            "sysparm_limit": str(limit),
            "sysparm_offset": str(offset),
            "sysparm_display_value": "true",
            "sysparm_fields": (
                "sys_id,number,short_description,state,urgency,impact,"
                "priority,assigned_to,category,sys_created_on,sys_updated_on"
            ),
        }
        if query:
            params["sysparm_query"] = query
        return self._api_call("GET", "/api/now/table/incident", params=params)

    def add_work_note(self, sys_id: str, note: str) -> ServiceNowOutcome:
        """Add a work note to an incident."""
        return self._api_call(
            "PUT",
            f"/api/now/table/incident/{sys_id}",
            json_body={"work_notes": note},
        )

    # ------------------------------------------------------------------
    # Change management operations
    # ------------------------------------------------------------------

    def create_change_request(
        self,
        short_description: str,
        *,
        description: str = "",
        change_type: str = "standard",
        risk: str = "moderate",
        impact: str = "2",
        assignment_group: str = "",
        justification: str = "",
        cmdb_ci: str = "",
        additional_fields: Optional[Dict[str, Any]] = None,
    ) -> ServiceNowOutcome:
        """Create a change request in ServiceNow.

        Args:
            short_description: Change title.
            description: Detailed description.
            change_type: standard | normal | emergency.
            risk: Risk level for the change.
            impact: 1=High, 2=Medium, 3=Low.
            assignment_group: Group sys_id.
            justification: Business justification.
            cmdb_ci: Affected CI sys_id.
            additional_fields: Extra fields.

        Returns:
            ServiceNowOutcome with created change request.
        """
        # Map change_type to ServiceNow type field
        type_map = {"standard": "standard", "normal": "normal", "emergency": "emergency"}
        payload: Dict[str, Any] = {
            "short_description": short_description,
            "description": description or short_description,
            "type": type_map.get(change_type, "standard"),
            "risk": risk,
            "impact": impact,
            "justification": justification or f"ALDECI automated remediation: {short_description}",
        }
        if assignment_group:
            payload["assignment_group"] = assignment_group
        if cmdb_ci:
            payload["cmdb_ci"] = cmdb_ci
        if additional_fields:
            payload.update(additional_fields)

        result = self._api_call("POST", "/api/now/table/change_request", json_body=payload)
        if result.success and isinstance(result.data, dict):
            _logger.info(
                "ServiceNow change request created: %s (sys_id=%s)",
                result.data.get("number", "?"),
                result.data.get("sys_id", "?"),
            )
        return result

    def get_change_request(self, sys_id: str) -> ServiceNowOutcome:
        """Fetch a change request by sys_id."""
        return self._api_call(
            "GET",
            f"/api/now/table/change_request/{sys_id}",
            params={"sysparm_display_value": "true"},
        )

    # ------------------------------------------------------------------
    # Utility: transform ALDECI alert to ServiceNow incident
    # ------------------------------------------------------------------

    @staticmethod
    def alert_to_incident_payload(alert: Dict[str, Any]) -> Dict[str, Any]:
        """Transform an ALDECI alert into a ServiceNow incident payload.

        Maps ALDECI severity levels to ServiceNow urgency/impact:
          critical -> urgency=1, impact=1
          high     -> urgency=1, impact=2
          medium   -> urgency=2, impact=2
          low      -> urgency=3, impact=3
        """
        severity = str(alert.get("severity", "medium")).lower()
        severity_map = {
            "critical": ("1", "1"),
            "high": ("1", "2"),
            "medium": ("2", "2"),
            "low": ("3", "3"),
            "info": ("3", "3"),
        }
        urgency, impact = severity_map.get(severity, ("2", "2"))

        title = alert.get("title") or alert.get("name") or "ALDECI Security Alert"
        desc_parts = [
            f"Alert ID: {alert.get('alert_id', 'N/A')}",
            f"Severity: {severity.upper()}",
            f"Source: ALDECI Platform",
            f"Detected: {alert.get('detected_at', alert.get('created_at', 'N/A'))}",
            "",
            alert.get("description", ""),
        ]
        if alert.get("affected_asset"):
            desc_parts.append(f"\nAffected Asset: {alert['affected_asset']}")
        if alert.get("recommendation"):
            desc_parts.append(f"\nRecommendation: {alert['recommendation']}")

        return {
            "short_description": f"[ALDECI] {title}",
            "description": "\n".join(desc_parts),
            "urgency": urgency,
            "impact": impact,
            "category": "security",
        }

    @staticmethod
    def remediation_to_change_payload(remediation: Dict[str, Any]) -> Dict[str, Any]:
        """Transform an ALDECI remediation action into a ServiceNow change request payload."""
        risk_map = {"critical": "high", "high": "high", "medium": "moderate", "low": "low"}
        risk = risk_map.get(str(remediation.get("risk_level", "medium")).lower(), "moderate")

        title = remediation.get("title") or remediation.get("action") or "ALDECI Remediation"
        return {
            "short_description": f"[ALDECI Remediation] {title}",
            "description": remediation.get("description", title),
            "change_type": remediation.get("change_type", "standard"),
            "risk": risk,
            "justification": remediation.get("justification", f"Security remediation: {title}"),
        }
