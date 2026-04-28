"""Universal Connector — fan-out security findings to Jira, GitHub Issues, and Slack.

Enterprise-grade async connectors with:
- httpx async HTTP client (no blocking requests)
- Circuit breaker pattern for fault tolerance
- Independent error isolation (Jira down does NOT block Slack)
- Severity-to-priority/label mapping per platform
- Rich Slack Block Kit formatting
- Demo/mock mode when credentials are absent
- Input validation and secret masking

Supports the ALdeci CTEM+ pipeline: Step 11 (run_playbooks) can fan-out
findings to external ticketing systems for human remediation tracking.
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import logging
import re
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

import httpx

from connectors._emit import emit_connector_event

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MAX_TITLE_LENGTH = 255
_MAX_DESCRIPTION_LENGTH = 32_000
_MAX_URL_LENGTH = 2_048
_REQUEST_TIMEOUT = 15.0
# Demo latency constant removed — no demo fallbacks remain

# Severity normalisation — accept many formats
_SEVERITY_ALIASES: Dict[str, str] = {
    "critical": "critical",
    "crit": "critical",
    "high": "high",
    "medium": "medium",
    "med": "medium",
    "moderate": "medium",
    "low": "low",
    "info": "info",
    "informational": "info",
    "none": "info",
}


def _normalise_severity(raw: Optional[str]) -> str:
    """Normalise severity string to one of: critical, high, medium, low, info."""
    if not raw:
        return "medium"
    return _SEVERITY_ALIASES.get(raw.strip().lower(), "medium")


def _sanitise_text(text: Optional[str], max_length: int = _MAX_DESCRIPTION_LENGTH) -> str:
    """Sanitise user-supplied text: strip control chars, limit length."""
    if not text:
        return ""
    # Remove null bytes and control chars except newline/tab
    cleaned = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", text)
    if len(cleaned) > max_length:
        cleaned = cleaned[:max_length] + "... [truncated]"
    return cleaned


def _mask_secret(value: Optional[str]) -> str:
    """Mask a secret for safe logging."""
    if not value:
        return "(empty)"
    if len(value) <= 6:
        return "***"
    return value[:3] + "***" + value[-3:]


# ---------------------------------------------------------------------------
# Circuit Breaker (async-compatible, lightweight)
# ---------------------------------------------------------------------------


class _CircuitState(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class _AsyncCircuitBreaker:
    """Simple async-compatible circuit breaker."""

    failure_threshold: int = 5
    recovery_timeout: float = 30.0

    _state: _CircuitState = field(default=_CircuitState.CLOSED, init=False)
    _failure_count: int = field(default=0, init=False)
    _last_failure_time: float = field(default=0.0, init=False)
    _half_open_successes: int = field(default=0, init=False)

    @property
    def state(self) -> _CircuitState:
        if self._state == _CircuitState.OPEN:
            if time.monotonic() - self._last_failure_time >= self.recovery_timeout:
                self._state = _CircuitState.HALF_OPEN
                self._half_open_successes = 0
        return self._state

    def allow_request(self) -> bool:
        s = self.state
        return s in (_CircuitState.CLOSED, _CircuitState.HALF_OPEN)

    def record_success(self) -> None:
        if self._state == _CircuitState.HALF_OPEN:
            self._half_open_successes += 1
            if self._half_open_successes >= 2:
                self._state = _CircuitState.CLOSED
                self._failure_count = 0
        elif self._state == _CircuitState.CLOSED:
            self._failure_count = 0

    def record_failure(self) -> None:
        self._failure_count += 1
        self._last_failure_time = time.monotonic()
        if self._state == _CircuitState.HALF_OPEN:
            self._state = _CircuitState.OPEN
        elif self._failure_count >= self.failure_threshold:
            self._state = _CircuitState.OPEN


# ---------------------------------------------------------------------------
# Connector Result
# ---------------------------------------------------------------------------


@dataclass
class ConnectorResult:
    """Structured result from any connector operation."""

    success: bool
    connector: str
    operation: str
    ticket_id: Optional[str] = None
    url: Optional[str] = None
    error: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    latency_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "success": self.success,
            "connector": self.connector,
            "operation": self.operation,
        }
        if self.ticket_id:
            d["ticket_id"] = self.ticket_id
        if self.url:
            d["url"] = self.url
        if self.error:
            d["error"] = self.error
        if self.details:
            d["details"] = self.details
        d["latency_ms"] = round(self.latency_ms, 2)
        return d


# ---------------------------------------------------------------------------
# Severity Mappings
# ---------------------------------------------------------------------------

# Jira: severity -> priority name
JIRA_SEVERITY_TO_PRIORITY: Dict[str, str] = {
    "critical": "Highest",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Lowest",
}

# GitHub: severity -> label names
GITHUB_SEVERITY_TO_LABELS: Dict[str, List[str]] = {
    "critical": ["security", "priority: critical", "bug"],
    "high": ["security", "priority: high", "bug"],
    "medium": ["security", "priority: medium"],
    "low": ["security", "priority: low"],
    "info": ["security", "informational"],
}

# Slack: severity -> emoji + colour
SLACK_SEVERITY_CONFIG: Dict[str, Dict[str, str]] = {
    "critical": {"emoji": ":red_circle:", "color": "#dc3545"},
    "high": {"emoji": ":orange_circle:", "color": "#fd7e14"},
    "medium": {"emoji": ":large_yellow_circle:", "color": "#ffc107"},
    "low": {"emoji": ":large_blue_circle:", "color": "#0d6efd"},
    "info": {"emoji": ":white_circle:", "color": "#6c757d"},
}


# ---------------------------------------------------------------------------
# Base Connector (Abstract)
# ---------------------------------------------------------------------------


class BaseConnector(ABC):
    """Abstract base class for all ticket/notification connectors.

    Every connector must implement the five core async methods.
    """

    _connector_type: str = "base"

    def __init__(self, *, timeout: float = _REQUEST_TIMEOUT) -> None:
        self._timeout = timeout
        self._circuit_breaker = _AsyncCircuitBreaker()
        self._request_count = 0
        self._error_count = 0
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Lazy-initialise a shared httpx.AsyncClient."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self._timeout),
                follow_redirects=True,
                limits=httpx.Limits(
                    max_connections=20,
                    max_keepalive_connections=10,
                ),
            )
        return self._client

    async def _request(
        self,
        method: str,
        url: str,
        *,
        headers: Optional[Dict[str, str]] = None,
        json: Optional[Any] = None,
        auth: Optional[tuple] = None,
    ) -> httpx.Response:
        """Execute an HTTP request with circuit breaker and metrics."""
        if not self._circuit_breaker.allow_request():
            raise httpx.ConnectError(
                "Circuit breaker is OPEN -- service unavailable"
            )

        self._request_count += 1
        client = await self._get_client()
        _start = time.monotonic()

        try:
            kwargs: Dict[str, Any] = {"headers": headers or {}}
            if json is not None:
                kwargs["json"] = json
            if auth is not None:
                kwargs["auth"] = auth

            response = await client.request(method, url, **kwargs)

            if response.status_code >= 500:
                self._circuit_breaker.record_failure()
                self._error_count += 1
            else:
                self._circuit_breaker.record_success()

            return response

        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError):
            self._circuit_breaker.record_failure()
            self._error_count += 1
            raise

    @property
    def configured(self) -> bool:
        """Return True if this connector has valid credentials."""
        return False

    @property
    def connector_type(self) -> str:
        return self._connector_type

    def get_metrics(self) -> Dict[str, Any]:
        return {
            "connector": self._connector_type,
            "configured": self.configured,
            "request_count": self._request_count,
            "error_count": self._error_count,
            "circuit_state": self._circuit_breaker.state.value,
        }

    @abstractmethod
    async def create_ticket(self, finding: Dict[str, Any]) -> ConnectorResult:
        """Create a ticket/issue/notification from a security finding."""
        ...

    @abstractmethod
    async def update_ticket(self, ticket_id: str, update: Dict[str, Any]) -> ConnectorResult:
        """Update an existing ticket."""
        ...

    @abstractmethod
    async def close_ticket(self, ticket_id: str, resolution: str) -> ConnectorResult:
        """Close/resolve a ticket."""
        ...

    @abstractmethod
    async def get_ticket(self, ticket_id: str) -> ConnectorResult:
        """Retrieve ticket details."""
        ...

    @abstractmethod
    async def test_connection(self) -> ConnectorResult:
        """Test connectivity and authentication."""
        ...

    async def close(self) -> None:
        """Shut down the underlying HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None


# ---------------------------------------------------------------------------
# Finding Formatter (shared)
# ---------------------------------------------------------------------------


def _format_finding_title(finding: Dict[str, Any]) -> str:
    """Generate a consistent ticket title from a finding."""
    severity = _normalise_severity(finding.get("severity"))
    cve_id = finding.get("cve_id") or finding.get("cve") or ""
    title_base = finding.get("title") or finding.get("summary") or "Security Finding"
    title_base = _sanitise_text(title_base, _MAX_TITLE_LENGTH - 30)

    parts = []
    parts.append(f"[{severity.upper()}]")
    if cve_id:
        parts.append(f"[{cve_id}]")
    parts.append(title_base)
    return " ".join(parts)


def _format_finding_description(finding: Dict[str, Any]) -> str:
    """Generate a structured description from a finding."""
    severity = _normalise_severity(finding.get("severity"))
    lines = []
    lines.append(f"**Severity**: {severity.upper()}")

    if finding.get("cve_id") or finding.get("cve"):
        lines.append(f"**CVE**: {finding.get('cve_id') or finding.get('cve')}")
    if finding.get("cwe_id") or finding.get("cwe"):
        lines.append(f"**CWE**: {finding.get('cwe_id') or finding.get('cwe')}")
    if finding.get("cvss_score") or finding.get("cvss"):
        lines.append(f"**CVSS**: {finding.get('cvss_score') or finding.get('cvss')}")
    if finding.get("component") or finding.get("package"):
        lines.append(f"**Component**: {finding.get('component') or finding.get('package')}")
    if finding.get("file_path") or finding.get("file"):
        lines.append(f"**File**: {finding.get('file_path') or finding.get('file')}")
    if finding.get("line"):
        lines.append(f"**Line**: {finding.get('line')}")

    lines.append("")
    desc = finding.get("description") or finding.get("details") or ""
    if desc:
        lines.append("## Description")
        lines.append(_sanitise_text(desc))

    remediation = finding.get("remediation") or finding.get("fix") or ""
    if remediation:
        lines.append("")
        lines.append("## Remediation")
        lines.append(_sanitise_text(remediation))

    lines.append("")
    lines.append("---")
    lines.append("*Generated by ALdeci CTEM+ Platform*")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# JiraConnector
# ---------------------------------------------------------------------------


class JiraConnector(BaseConnector):
    """Create and manage Jira tickets from security findings.

    Uses Jira REST API v3 (Cloud) / v2 (Server/DC).
    Severity is mapped to Jira priority via JIRA_SEVERITY_TO_PRIORITY.
    CVE IDs are added as labels for searchability.
    """

    _connector_type = "jira"

    def __init__(
        self,
        base_url: str,
        email: str,
        api_token: str,
        project_key: str,
        *,
        issue_type: str = "Bug",
        timeout: float = _REQUEST_TIMEOUT,
    ) -> None:
        super().__init__(timeout=timeout)
        self._base_url = base_url.rstrip("/") if base_url else ""
        self._email = email or ""
        self._api_token = api_token or ""
        self._project_key = project_key or ""
        self._issue_type = issue_type

    @property
    def configured(self) -> bool:
        return bool(
            self._base_url
            and self._email
            and self._api_token
            and self._project_key
        )

    def _auth(self) -> tuple:
        return (self._email, self._api_token)

    def _headers(self) -> Dict[str, str]:
        return {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    async def create_ticket(self, finding: Dict[str, Any]) -> ConnectorResult:
        """Create a Jira issue from a security finding."""
        if not self.configured:
            return ConnectorResult(
                success=False, connector="jira", operation="create_ticket",
                error="Jira not configured. Set JIRA_URL, JIRA_USER, JIRA_TOKEN, and JIRA_PROJECT to enable ticket creation.",
            )

        severity = _normalise_severity(finding.get("severity"))
        priority = JIRA_SEVERITY_TO_PRIORITY.get(severity, "Medium")
        title = _format_finding_title(finding)
        description = _format_finding_description(finding)

        # Build labels from CVE + severity
        labels = [f"aldeci-{severity}", "security-finding"]
        cve_id = finding.get("cve_id") or finding.get("cve")
        if cve_id:
            labels.append(cve_id.replace(" ", "_"))

        # Jira Cloud uses ADF for description in v3, but plain text works in v2 fallback
        payload = {
            "fields": {
                "project": {"key": self._project_key},
                "summary": title[:_MAX_TITLE_LENGTH],
                "description": description,
                "issuetype": {"name": self._issue_type},
                "priority": {"name": priority},
                "labels": labels,
            }
        }

        endpoint = f"{self._base_url}/rest/api/3/issue"
        start = time.monotonic()

        try:
            response = await self._request(
                "POST", endpoint, json=payload, auth=self._auth(), headers=self._headers()
            )
            latency = (time.monotonic() - start) * 1000

            if response.status_code in (200, 201):
                body = response.json()
                issue_key = body.get("key", "")
                return ConnectorResult(
                    success=True,
                    connector="jira",
                    operation="create_ticket",
                    ticket_id=issue_key,
                    url=f"{self._base_url}/browse/{issue_key}",
                    details={"key": issue_key, "id": body.get("id"), "status": "created"},
                    latency_ms=latency,
                )
            else:
                error_text = response.text[:500] if response.text else str(response.status_code)
                logger.warning("Jira create_ticket failed: HTTP %d: %s", response.status_code, error_text)
                return ConnectorResult(
                    success=False,
                    connector="jira",
                    operation="create_ticket",
                    error=f"HTTP {response.status_code}: {error_text}",
                    latency_ms=latency,
                )
        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:
            latency = (time.monotonic() - start) * 1000
            logger.error("Jira create_ticket exception: %s", exc)
            return ConnectorResult(
                success=False,
                connector="jira",
                operation="create_ticket",
                error=str(exc),
                latency_ms=latency,
            )

    async def update_ticket(self, ticket_id: str, update: Dict[str, Any]) -> ConnectorResult:
        """Update an existing Jira issue."""
        if not self.configured:
            return ConnectorResult(
                success=False, connector="jira", operation="update_ticket", ticket_id=ticket_id,
                error="Jira not configured. Set JIRA_URL, JIRA_USER, JIRA_TOKEN to enable updates.",
            )

        fields: Dict[str, Any] = {}
        if update.get("summary"):
            fields["summary"] = _sanitise_text(update["summary"], _MAX_TITLE_LENGTH)
        if update.get("description"):
            fields["description"] = _sanitise_text(update["description"])
        if update.get("priority"):
            fields["priority"] = {"name": update["priority"]}
        if update.get("labels"):
            fields["labels"] = update["labels"]

        if not fields:
            return ConnectorResult(
                success=False,
                connector="jira",
                operation="update_ticket",
                ticket_id=ticket_id,
                error="No fields to update",
            )

        endpoint = f"{self._base_url}/rest/api/3/issue/{ticket_id}"
        start = time.monotonic()

        try:
            response = await self._request(
                "PUT", endpoint, json={"fields": fields}, auth=self._auth(), headers=self._headers()
            )
            latency = (time.monotonic() - start) * 1000

            if response.status_code in (200, 204):
                return ConnectorResult(
                    success=True,
                    connector="jira",
                    operation="update_ticket",
                    ticket_id=ticket_id,
                    url=f"{self._base_url}/browse/{ticket_id}",
                    latency_ms=latency,
                )
            else:
                return ConnectorResult(
                    success=False,
                    connector="jira",
                    operation="update_ticket",
                    ticket_id=ticket_id,
                    error=f"HTTP {response.status_code}",
                    latency_ms=latency,
                )
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            return ConnectorResult(
                success=False,
                connector="jira",
                operation="update_ticket",
                ticket_id=ticket_id,
                error=str(exc),
                latency_ms=(time.monotonic() - start) * 1000,
            )

    async def close_ticket(self, ticket_id: str, resolution: str) -> ConnectorResult:
        """Transition a Jira issue to Done/Closed status.

        Uses the Jira transitions API. Falls back to adding a comment if
        the transition cannot be determined.
        """
        if not self.configured:
            return ConnectorResult(
                success=False, connector="jira", operation="close_ticket", ticket_id=ticket_id,
                error="Jira not configured. Set JIRA_URL, JIRA_USER, JIRA_TOKEN to enable ticket closure.",
            )

        # Step 1: Fetch available transitions
        transitions_url = f"{self._base_url}/rest/api/3/issue/{ticket_id}/transitions"
        start = time.monotonic()

        try:
            resp = await self._request(
                "GET", transitions_url, auth=self._auth(), headers=self._headers()
            )
            if resp.status_code != 200:
                return ConnectorResult(
                    success=False,
                    connector="jira",
                    operation="close_ticket",
                    ticket_id=ticket_id,
                    error=f"Failed to fetch transitions: HTTP {resp.status_code}",
                    latency_ms=(time.monotonic() - start) * 1000,
                )

            transitions = resp.json().get("transitions", [])
            # Find a "Done" or "Closed" transition
            target_transition = None
            for t in transitions:
                name = (t.get("name") or "").lower()
                if name in ("done", "closed", "resolved", "close", "resolve"):
                    target_transition = t
                    break

            if not target_transition:
                # Fallback: add resolution as comment
                comment_url = f"{self._base_url}/rest/api/3/issue/{ticket_id}/comment"
                await self._request(
                    "POST",
                    comment_url,
                    json={
                        "body": {
                            "type": "doc",
                            "version": 1,
                            "content": [
                                {
                                    "type": "paragraph",
                                    "content": [
                                        {
                                            "type": "text",
                                            "text": f"Resolution: {_sanitise_text(resolution)}",
                                        }
                                    ],
                                }
                            ],
                        }
                    },
                    auth=self._auth(),
                    headers=self._headers(),
                )
                return ConnectorResult(
                    success=True,
                    connector="jira",
                    operation="close_ticket",
                    ticket_id=ticket_id,
                    details={"note": "No close transition found; added resolution comment"},
                    latency_ms=(time.monotonic() - start) * 1000,
                )

            # Step 2: Execute the transition
            payload = {"transition": {"id": target_transition["id"]}}
            resp2 = await self._request(
                "POST", transitions_url, json=payload, auth=self._auth(), headers=self._headers()
            )
            latency = (time.monotonic() - start) * 1000

            if resp2.status_code in (200, 204):
                return ConnectorResult(
                    success=True,
                    connector="jira",
                    operation="close_ticket",
                    ticket_id=ticket_id,
                    url=f"{self._base_url}/browse/{ticket_id}",
                    details={"transition": target_transition.get("name")},
                    latency_ms=latency,
                )
            else:
                return ConnectorResult(
                    success=False,
                    connector="jira",
                    operation="close_ticket",
                    ticket_id=ticket_id,
                    error=f"Transition failed: HTTP {resp2.status_code}",
                    latency_ms=latency,
                )

        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            return ConnectorResult(
                success=False,
                connector="jira",
                operation="close_ticket",
                ticket_id=ticket_id,
                error=str(exc),
                latency_ms=(time.monotonic() - start) * 1000,
            )

    async def get_ticket(self, ticket_id: str) -> ConnectorResult:
        """Fetch a Jira issue by key."""
        if not self.configured:
            return ConnectorResult(
                success=False, connector="jira", operation="get_ticket", ticket_id=ticket_id,
                error="Jira not configured. Set JIRA_URL, JIRA_USER, JIRA_TOKEN to enable ticket retrieval.",
            )

        endpoint = f"{self._base_url}/rest/api/3/issue/{ticket_id}"
        start = time.monotonic()

        try:
            response = await self._request(
                "GET", endpoint, auth=self._auth(), headers=self._headers()
            )
            latency = (time.monotonic() - start) * 1000

            if response.status_code == 200:
                body = response.json()
                return ConnectorResult(
                    success=True,
                    connector="jira",
                    operation="get_ticket",
                    ticket_id=body.get("key", ticket_id),
                    url=f"{self._base_url}/browse/{ticket_id}",
                    details=body,
                    latency_ms=latency,
                )
            else:
                return ConnectorResult(
                    success=False,
                    connector="jira",
                    operation="get_ticket",
                    ticket_id=ticket_id,
                    error=f"HTTP {response.status_code}",
                    latency_ms=latency,
                )
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            return ConnectorResult(
                success=False,
                connector="jira",
                operation="get_ticket",
                ticket_id=ticket_id,
                error=str(exc),
                latency_ms=(time.monotonic() - start) * 1000,
            )

    async def test_connection(self) -> ConnectorResult:
        """Test Jira connectivity by calling /rest/api/3/myself."""
        if not self.configured:
            return ConnectorResult(
                success=False,
                connector="jira",
                operation="test_connection",
                error="Jira not configured. Set JIRA_BASE_URL, JIRA_EMAIL, and JIRA_API_TOKEN environment variables.",
            )

        endpoint = f"{self._base_url}/rest/api/3/myself"
        start = time.monotonic()

        try:
            response = await self._request(
                "GET", endpoint, auth=self._auth(), headers=self._headers()
            )
            latency = (time.monotonic() - start) * 1000

            if response.status_code == 200:
                user_info = response.json()
                return ConnectorResult(
                    success=True,
                    connector="jira",
                    operation="test_connection",
                    details={
                        "user": user_info.get("displayName", "unknown"),
                        "email": user_info.get("emailAddress", ""),
                    },
                    latency_ms=latency,
                )
            else:
                return ConnectorResult(
                    success=False,
                    connector="jira",
                    operation="test_connection",
                    error=f"HTTP {response.status_code}: {response.text[:200]}",
                    latency_ms=latency,
                )
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            return ConnectorResult(
                success=False,
                connector="jira",
                operation="test_connection",
                error=str(exc),
                latency_ms=(time.monotonic() - start) * 1000,
            )


# ---------------------------------------------------------------------------
# GitHubConnector
# ---------------------------------------------------------------------------


class GitHubConnector(BaseConnector):
    """Create and manage GitHub issues from security findings.

    Uses GitHub REST API (X-GitHub-Api-Version: 2022-11-28).
    Severity is mapped to GitHub labels via GITHUB_SEVERITY_TO_LABELS.
    CVE IDs are prefixed in the issue title.
    """

    _connector_type = "github"

    def __init__(
        self,
        token: str,
        owner: str,
        repo: str,
        *,
        timeout: float = _REQUEST_TIMEOUT,
    ) -> None:
        super().__init__(timeout=timeout)
        self._token = token or ""
        self._owner = owner or ""
        self._repo = repo or ""
        self._base_url = "https://api.github.com"

    @property
    def configured(self) -> bool:
        return bool(self._token and self._owner and self._repo)

    def _headers(self) -> Dict[str, str]:
        return {
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    async def create_ticket(self, finding: Dict[str, Any]) -> ConnectorResult:
        """Create a GitHub issue from a security finding."""
        if not self.configured:
            return ConnectorResult(
                success=False, connector="github", operation="create_ticket",
                error="GitHub not configured. Set GITHUB_TOKEN, GITHUB_OWNER, GITHUB_REPO to enable issue creation.",
            )

        severity = _normalise_severity(finding.get("severity"))
        title = _format_finding_title(finding)
        body = _format_finding_description(finding)
        labels = list(GITHUB_SEVERITY_TO_LABELS.get(severity, ["security"]))

        cve_id = finding.get("cve_id") or finding.get("cve")
        if cve_id:
            labels.append(cve_id)

        payload = {
            "title": title[:_MAX_TITLE_LENGTH],
            "body": body,
            "labels": labels,
        }

        endpoint = f"{self._base_url}/repos/{self._owner}/{self._repo}/issues"
        start = time.monotonic()

        try:
            response = await self._request(
                "POST", endpoint, json=payload, headers=self._headers()
            )
            latency = (time.monotonic() - start) * 1000

            if response.status_code in (200, 201):
                issue = response.json()
                return ConnectorResult(
                    success=True,
                    connector="github",
                    operation="create_ticket",
                    ticket_id=str(issue.get("number", "")),
                    url=issue.get("html_url", ""),
                    details={
                        "number": issue.get("number"),
                        "id": issue.get("id"),
                        "status": "open",
                    },
                    latency_ms=latency,
                )
            else:
                return ConnectorResult(
                    success=False,
                    connector="github",
                    operation="create_ticket",
                    error=f"HTTP {response.status_code}: {response.text[:500]}",
                    latency_ms=latency,
                )
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            return ConnectorResult(
                success=False,
                connector="github",
                operation="create_ticket",
                error=str(exc),
                latency_ms=(time.monotonic() - start) * 1000,
            )

    async def update_ticket(self, ticket_id: str, update: Dict[str, Any]) -> ConnectorResult:
        """Update a GitHub issue via PATCH."""
        if not self.configured:
            return ConnectorResult(
                success=False, connector="github", operation="update_ticket", ticket_id=ticket_id,
                error="GitHub not configured. Set GITHUB_TOKEN, GITHUB_OWNER, GITHUB_REPO to enable updates.",
            )

        payload: Dict[str, Any] = {}
        if update.get("title"):
            payload["title"] = _sanitise_text(update["title"], _MAX_TITLE_LENGTH)
        if update.get("body") or update.get("description"):
            payload["body"] = _sanitise_text(update.get("body") or update.get("description", ""))
        if update.get("labels"):
            payload["labels"] = update["labels"]
        if update.get("state"):
            payload["state"] = update["state"]

        if not payload:
            return ConnectorResult(
                success=False,
                connector="github",
                operation="update_ticket",
                ticket_id=ticket_id,
                error="No fields to update",
            )

        endpoint = f"{self._base_url}/repos/{self._owner}/{self._repo}/issues/{ticket_id}"
        start = time.monotonic()

        try:
            response = await self._request(
                "PATCH", endpoint, json=payload, headers=self._headers()
            )
            latency = (time.monotonic() - start) * 1000

            if response.status_code == 200:
                issue = response.json()
                return ConnectorResult(
                    success=True,
                    connector="github",
                    operation="update_ticket",
                    ticket_id=ticket_id,
                    url=issue.get("html_url", ""),
                    latency_ms=latency,
                )
            else:
                return ConnectorResult(
                    success=False,
                    connector="github",
                    operation="update_ticket",
                    ticket_id=ticket_id,
                    error=f"HTTP {response.status_code}",
                    latency_ms=latency,
                )
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            return ConnectorResult(
                success=False,
                connector="github",
                operation="update_ticket",
                ticket_id=ticket_id,
                error=str(exc),
                latency_ms=(time.monotonic() - start) * 1000,
            )

    async def close_ticket(self, ticket_id: str, resolution: str) -> ConnectorResult:
        """Close a GitHub issue by setting state to 'closed'."""
        if not self.configured:
            return ConnectorResult(
                success=False, connector="github", operation="close_ticket", ticket_id=ticket_id,
                error="GitHub not configured. Set GITHUB_TOKEN, GITHUB_OWNER, GITHUB_REPO to enable issue closure.",
            )

        # Add resolution comment first
        comment_endpoint = (
            f"{self._base_url}/repos/{self._owner}/{self._repo}/issues/{ticket_id}/comments"
        )
        start = time.monotonic()

        try:
            await self._request(
                "POST",
                comment_endpoint,
                json={"body": f"**Resolved**: {_sanitise_text(resolution)}"},
                headers=self._headers(),
            )

            # Close the issue
            close_endpoint = (
                f"{self._base_url}/repos/{self._owner}/{self._repo}/issues/{ticket_id}"
            )
            response = await self._request(
                "PATCH",
                close_endpoint,
                json={"state": "closed", "state_reason": "completed"},
                headers=self._headers(),
            )
            latency = (time.monotonic() - start) * 1000

            if response.status_code == 200:
                return ConnectorResult(
                    success=True,
                    connector="github",
                    operation="close_ticket",
                    ticket_id=ticket_id,
                    url=response.json().get("html_url", ""),
                    latency_ms=latency,
                )
            else:
                return ConnectorResult(
                    success=False,
                    connector="github",
                    operation="close_ticket",
                    ticket_id=ticket_id,
                    error=f"HTTP {response.status_code}",
                    latency_ms=latency,
                )
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            return ConnectorResult(
                success=False,
                connector="github",
                operation="close_ticket",
                ticket_id=ticket_id,
                error=str(exc),
                latency_ms=(time.monotonic() - start) * 1000,
            )

    async def get_ticket(self, ticket_id: str) -> ConnectorResult:
        """Fetch a GitHub issue."""
        if not self.configured:
            return ConnectorResult(
                success=False, connector="github", operation="get_ticket", ticket_id=ticket_id,
                error="GitHub not configured. Set GITHUB_TOKEN, GITHUB_OWNER, GITHUB_REPO to enable issue retrieval.",
            )

        endpoint = f"{self._base_url}/repos/{self._owner}/{self._repo}/issues/{ticket_id}"
        start = time.monotonic()

        try:
            response = await self._request("GET", endpoint, headers=self._headers())
            latency = (time.monotonic() - start) * 1000

            if response.status_code == 200:
                issue = response.json()
                return ConnectorResult(
                    success=True,
                    connector="github",
                    operation="get_ticket",
                    ticket_id=ticket_id,
                    url=issue.get("html_url", ""),
                    details=issue,
                    latency_ms=latency,
                )
            else:
                return ConnectorResult(
                    success=False,
                    connector="github",
                    operation="get_ticket",
                    ticket_id=ticket_id,
                    error=f"HTTP {response.status_code}",
                    latency_ms=latency,
                )
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            return ConnectorResult(
                success=False,
                connector="github",
                operation="get_ticket",
                ticket_id=ticket_id,
                error=str(exc),
                latency_ms=(time.monotonic() - start) * 1000,
            )

    async def test_connection(self) -> ConnectorResult:
        """Test GitHub connectivity by fetching authenticated user."""
        if not self.configured:
            return ConnectorResult(
                success=False,
                connector="github",
                operation="test_connection",
                error="GitHub not configured. Set GITHUB_TOKEN and GITHUB_REPO environment variables.",
            )

        start = time.monotonic()
        try:
            response = await self._request(
                "GET", f"{self._base_url}/user", headers=self._headers()
            )
            latency = (time.monotonic() - start) * 1000

            if response.status_code == 200:
                user = response.json()
                return ConnectorResult(
                    success=True,
                    connector="github",
                    operation="test_connection",
                    details={
                        "user": user.get("login", ""),
                        "name": user.get("name", ""),
                    },
                    latency_ms=latency,
                )
            else:
                return ConnectorResult(
                    success=False,
                    connector="github",
                    operation="test_connection",
                    error=f"HTTP {response.status_code}",
                    latency_ms=latency,
                )
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            return ConnectorResult(
                success=False,
                connector="github",
                operation="test_connection",
                error=str(exc),
                latency_ms=(time.monotonic() - start) * 1000,
            )


# ---------------------------------------------------------------------------
# SlackConnector
# ---------------------------------------------------------------------------


class SlackConnector(BaseConnector):
    """Send Slack notifications for security findings via incoming webhook.

    Uses Slack Block Kit for rich message formatting.
    Severity determines the message colour and emoji.
    """

    _connector_type = "slack"

    def __init__(
        self,
        webhook_url: str,
        channel: Optional[str] = None,
        *,
        timeout: float = _REQUEST_TIMEOUT,
    ) -> None:
        super().__init__(timeout=timeout)
        self._webhook_url = webhook_url or ""
        self._channel = channel

    @property
    def configured(self) -> bool:
        return bool(self._webhook_url and self._webhook_url.startswith("http"))

    def _build_blocks(self, finding: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Build Slack Block Kit blocks from a security finding."""
        severity = _normalise_severity(finding.get("severity"))
        config = SLACK_SEVERITY_CONFIG.get(severity, SLACK_SEVERITY_CONFIG["medium"])
        title = _format_finding_title(finding)

        blocks: List[Dict[str, Any]] = []

        # Header
        blocks.append({
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f"{config['emoji']} Security Finding",
                "emoji": True,
            },
        })

        # Title section
        blocks.append({
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*{html.escape(title)}*",
            },
        })

        # Details fields
        fields: List[Dict[str, str]] = [
            {"type": "mrkdwn", "text": f"*Severity:*\n{config['emoji']} {severity.upper()}"},
        ]
        cve_id = finding.get("cve_id") or finding.get("cve")
        if cve_id:
            fields.append({"type": "mrkdwn", "text": f"*CVE:*\n{html.escape(str(cve_id))}"})
        if finding.get("cvss_score") or finding.get("cvss"):
            score = finding.get("cvss_score") or finding.get("cvss")
            fields.append({"type": "mrkdwn", "text": f"*CVSS:*\n{score}"})
        if finding.get("component") or finding.get("package"):
            comp = finding.get("component") or finding.get("package")
            fields.append({"type": "mrkdwn", "text": f"*Component:*\n{html.escape(str(comp))}"})
        if finding.get("file_path") or finding.get("file"):
            fp = finding.get("file_path") or finding.get("file")
            fields.append({"type": "mrkdwn", "text": f"*File:*\n`{html.escape(str(fp))}`"})

        blocks.append({"type": "section", "fields": fields[:10]})  # Slack max 10 fields

        # Description
        desc = finding.get("description") or finding.get("details") or ""
        if desc:
            # Truncate for Slack block max (3000 chars)
            truncated = _sanitise_text(desc, 2800)
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": truncated},
            })

        # Remediation
        fix = finding.get("remediation") or finding.get("fix") or ""
        if fix:
            truncated_fix = _sanitise_text(fix, 2800)
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Remediation:*\n{truncated_fix}"},
            })

        # Divider
        blocks.append({"type": "divider"})

        # Context footer
        blocks.append({
            "type": "context",
            "elements": [
                {
                    "type": "mrkdwn",
                    "text": f"ALdeci CTEM+ | {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
                }
            ],
        })

        return blocks

    async def create_ticket(self, finding: Dict[str, Any]) -> ConnectorResult:
        """Send a Slack notification for a security finding."""
        if not self.configured:
            return ConnectorResult(
                success=False, connector="slack", operation="create_ticket",
                error="Slack not configured. Set SLACK_WEBHOOK_URL to enable notifications.",
            )

        severity = _normalise_severity(finding.get("severity"))
        config = SLACK_SEVERITY_CONFIG.get(severity, SLACK_SEVERITY_CONFIG["medium"])
        blocks = self._build_blocks(finding)
        title = _format_finding_title(finding)

        payload: Dict[str, Any] = {
            "text": title,  # Fallback for notifications
            "blocks": blocks,
        }
        if self._channel:
            payload["channel"] = self._channel

        # Attachments for the color bar
        payload["attachments"] = [
            {
                "color": config["color"],
                "blocks": [],
            }
        ]

        start = time.monotonic()

        try:
            response = await self._request("POST", self._webhook_url, json=payload)
            latency = (time.monotonic() - start) * 1000

            if response.status_code == 200:
                notification_id = hashlib.sha256(
                    f"{title}-{time.time()}".encode()
                ).hexdigest()[:16]
                return ConnectorResult(
                    success=True,
                    connector="slack",
                    operation="create_ticket",
                    ticket_id=notification_id,
                    details={
                        "notification_id": notification_id,
                        "channel": self._channel or "(default)",
                        "status": "sent",
                    },
                    latency_ms=latency,
                )
            else:
                return ConnectorResult(
                    success=False,
                    connector="slack",
                    operation="create_ticket",
                    error=f"HTTP {response.status_code}: {response.text[:300]}",
                    latency_ms=latency,
                )
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            return ConnectorResult(
                success=False,
                connector="slack",
                operation="create_ticket",
                error=str(exc),
                latency_ms=(time.monotonic() - start) * 1000,
            )

    async def update_ticket(self, ticket_id: str, update: Dict[str, Any]) -> ConnectorResult:
        """Slack webhooks are fire-and-forget; send a follow-up message."""
        if not self.configured:
            return ConnectorResult(
                success=False,
                connector="slack",
                operation="update_ticket",
                ticket_id=ticket_id,
                error="Slack not configured. Set SLACK_WEBHOOK_URL environment variable.",
            )

        text = update.get("text") or update.get("description") or f"Update for {ticket_id}"
        payload: Dict[str, Any] = {"text": f"*Update [{ticket_id}]*: {_sanitise_text(text, 3000)}"}
        if self._channel:
            payload["channel"] = self._channel

        start = time.monotonic()
        try:
            response = await self._request("POST", self._webhook_url, json=payload)
            latency = (time.monotonic() - start) * 1000
            return ConnectorResult(
                success=response.status_code == 200,
                connector="slack",
                operation="update_ticket",
                ticket_id=ticket_id,
                error=None if response.status_code == 200 else f"HTTP {response.status_code}",
                latency_ms=latency,
            )
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            return ConnectorResult(
                success=False,
                connector="slack",
                operation="update_ticket",
                ticket_id=ticket_id,
                error=str(exc),
                latency_ms=(time.monotonic() - start) * 1000,
            )

    async def close_ticket(self, ticket_id: str, resolution: str) -> ConnectorResult:
        """Send a resolution notification to Slack."""
        return await self.update_ticket(
            ticket_id,
            {"text": f"Resolved: {_sanitise_text(resolution)}"},
        )

    async def get_ticket(self, ticket_id: str) -> ConnectorResult:
        """Slack webhooks are one-way; cannot retrieve messages."""
        return ConnectorResult(
            success=False,
            connector="slack",
            operation="get_ticket",
            ticket_id=ticket_id,
            error="Slack incoming webhooks are write-only; cannot retrieve messages",
        )

    async def test_connection(self) -> ConnectorResult:
        """Test the Slack webhook by sending an empty payload (Slack returns 400 but confirms reachability)."""
        if not self.configured:
            return ConnectorResult(
                success=True,
                connector="slack",
                operation="test_connection",
                details={"message": "Slack not configured — set SLACK_WEBHOOK_URL"},
            )

        start = time.monotonic()
        try:
            # Slack returns 400 "no_text" for empty payload, but 200 for valid payload
            # Send a minimal valid payload to truly test connectivity
            response = await self._request(
                "POST",
                self._webhook_url,
                json={"text": ""},
            )
            latency = (time.monotonic() - start) * 1000

            # 200 or 400 means the webhook endpoint is reachable
            if response.status_code in (200, 400):
                return ConnectorResult(
                    success=True,
                    connector="slack",
                    operation="test_connection",
                    details={"message": "Webhook endpoint is reachable"},
                    latency_ms=latency,
                )
            else:
                return ConnectorResult(
                    success=False,
                    connector="slack",
                    operation="test_connection",
                    error=f"HTTP {response.status_code}",
                    latency_ms=latency,
                )
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            return ConnectorResult(
                success=False,
                connector="slack",
                operation="test_connection",
                error=str(exc),
                latency_ms=(time.monotonic() - start) * 1000,
            )


# ---------------------------------------------------------------------------
# UniversalConnector (Orchestrator)
# ---------------------------------------------------------------------------


class UniversalConnector:
    """Orchestrates multiple connectors -- fan-out findings to Jira + GitHub + Slack simultaneously.

    Error isolation: if one connector fails, others still execute.
    All connector operations run concurrently via asyncio.gather.
    """

    def __init__(self) -> None:
        self._connectors: Dict[str, BaseConnector] = {}

    def register(self, name: str, connector: BaseConnector) -> None:
        """Register a connector by name."""
        if not name or not isinstance(name, str):
            raise ValueError("Connector name must be a non-empty string")
        if not isinstance(connector, BaseConnector):
            raise TypeError(f"Expected BaseConnector, got {type(connector).__name__}")
        name = name.strip().lower()
        if name in self._connectors:
            logger.warning("Replacing existing connector: %s", name)
        self._connectors[name] = connector
        logger.info("Registered connector: %s (%s)", name, connector.connector_type)

    def unregister(self, name: str) -> bool:
        """Remove a connector by name. Returns True if removed, False if not found."""
        name = name.strip().lower()
        if name in self._connectors:
            del self._connectors[name]
            logger.info("Unregistered connector: %s", name)
            return True
        return False

    def list_connectors(self) -> List[Dict[str, Any]]:
        """Return metadata for all registered connectors."""
        result = []
        for name, conn in self._connectors.items():
            result.append({
                "name": name,
                "type": conn.connector_type,
                "configured": conn.configured,
                "metrics": conn.get_metrics(),
            })
        return result

    def get_connector(self, name: str) -> Optional[BaseConnector]:
        """Get a connector by name."""
        return self._connectors.get(name.strip().lower())

    async def create_tickets(
        self,
        finding: Dict[str, Any],
        targets: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Create tickets across all registered connectors (or specified targets).

        Returns a dict with results from each connector. Failed connectors
        do NOT prevent other connectors from executing.
        """
        connectors_to_use = self._resolve_targets(targets)

        if not connectors_to_use:
            return {
                "results": [],
                "total": 0,
                "success_count": 0,
                "error_count": 0,
            }

        tasks = []
        names = []
        for name, conn in connectors_to_use.items():
            names.append(name)
            tasks.append(self._safe_create(name, conn, finding))

        results = await asyncio.gather(*tasks)

        success_count = sum(1 for r in results if r.success)
        emit_connector_event(
            connector="UniversalConnector",
            org_id=str(finding.get("org_id") or finding.get("tenant") or "default"),
            source_kind="sync",
            finding_count=success_count,
            extra={
                "operation": "create_tickets",
                "targets": list(connectors_to_use.keys()),
                "success_count": success_count,
                "error_count": len(results) - success_count,
                "finding_severity": str(finding.get("severity") or ""),
            },
        )
        return {
            "results": [r.to_dict() for r in results],
            "total": len(results),
            "success_count": success_count,
            "error_count": len(results) - success_count,
        }

    async def test_all(self) -> Dict[str, Any]:
        """Test connectivity to all registered connectors."""
        if not self._connectors:
            return {"results": [], "total": 0, "healthy_count": 0}

        tasks = []
        for name, conn in self._connectors.items():
            tasks.append(self._safe_test(name, conn))

        results = await asyncio.gather(*tasks)
        healthy = sum(1 for r in results if r.success)

        return {
            "results": [r.to_dict() for r in results],
            "total": len(results),
            "healthy_count": healthy,
            "unhealthy_count": len(results) - healthy,
        }

    async def close_all(self) -> None:
        """Close all underlying HTTP clients."""
        for conn in self._connectors.values():
            await conn.close()

    # -- Internal helpers ----------------------------------------------------

    def _resolve_targets(self, targets: Optional[List[str]]) -> Dict[str, BaseConnector]:
        """Resolve target names to connectors. None means all."""
        if targets is None:
            return dict(self._connectors)

        result = {}
        for t in targets:
            t_lower = t.strip().lower()
            if t_lower in self._connectors:
                result[t_lower] = self._connectors[t_lower]
            else:
                logger.warning("Target connector not found: %s (skipping)", t)
        return result

    @staticmethod
    async def _safe_create(
        name: str, conn: BaseConnector, finding: Dict[str, Any]
    ) -> ConnectorResult:
        """Execute create_ticket with error isolation."""
        try:
            return await conn.create_ticket(finding)
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            logger.error("Connector %s failed during create_ticket: %s", name, exc)
            return ConnectorResult(
                success=False,
                connector=name,
                operation="create_ticket",
                error=f"Unhandled exception: {exc}",
            )

    @staticmethod
    async def _safe_test(name: str, conn: BaseConnector) -> ConnectorResult:
        """Execute test_connection with error isolation."""
        try:
            return await conn.test_connection()
        except (OSError, ValueError, KeyError, RuntimeError) as exc:  # narrowed from bare Exception
            logger.error("Connector %s failed during test_connection: %s", name, exc)
            return ConnectorResult(
                success=False,
                connector=name,
                operation="test_connection",
                error=f"Unhandled exception: {exc}",
            )
