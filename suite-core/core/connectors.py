"""External automation connectors for delivering policy actions.

Enterprise-grade connectors with:
- Automatic retry with exponential backoff
- Circuit breaker pattern for fault tolerance
- Rate limiting to respect API limits
- Health checks for connectivity validation
- Bidirectional operations (push AND pull) for agent-based data collection
- Structured logging and metrics
- Marketplace-ready configuration patterns

Supported APIs and Versions (as of January 2026):

Jira:
    - API: REST API v3 (/rest/api/3/)
    - Compatibility: Jira Cloud (all versions), Jira Data Center 9.x+, Jira Server 8.x+
    - Auth: API Token (Cloud) or Personal Access Token (Data Center/Server)
    - Docs: https://developer.atlassian.com/cloud/jira/platform/rest/v3/

ServiceNow:
    - API: Table API (/api/now/table/)
    - Compatibility: All ServiceNow releases (Zurich, Yokohama, Xanadu, Washington DC+)
    - Auth: Basic Auth (username/password) or OAuth 2.0
    - Docs: https://www.servicenow.com/docs/bundle/zurich-api-reference/

GitLab:
    - API: REST API v4 (/api/v4/)
    - Compatibility: GitLab.com, GitLab Self-Managed 14.0+, GitLab Dedicated
    - Latest tested: GitLab 18.7.1 (January 2026)
    - Auth: Personal Access Token or OAuth 2.0
    - Docs: https://docs.gitlab.com/ee/api/rest/

Azure DevOps:
    - API: REST API v7.2 (api-version=7.2)
    - Compatibility: Azure DevOps Services, Azure DevOps Server 2022+
    - Auth: Personal Access Token (PAT) with Base64 encoding
    - Docs: https://learn.microsoft.com/en-us/rest/api/azure/devops/

GitHub:
    - API: REST API (X-GitHub-Api-Version: 2022-11-28)
    - Compatibility: GitHub.com, GitHub Enterprise Server 3.9+
    - Auth: Personal Access Token or GitHub App
    - Docs: https://docs.github.com/en/rest
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from threading import Lock
from typing import Any, Dict, List, Mapping, Optional
from urllib.parse import urljoin

import requests  # type: ignore[import-untyped]
from requests import RequestException, Response
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

try:  # TrustGraph event bus — optional, never blocks on failure
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except ImportError:  # pragma: no cover - bus is optional
    _get_tg_bus = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)


def _mask(value: Optional[str]) -> Optional[str]:
    if not value:
        return value
    if len(value) <= 4:
        return "*" * len(value)
    return value[:2] + "***" + value[-2:]


class CircuitState(Enum):
    """Circuit breaker states."""

    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


@dataclass
class CircuitBreaker:
    """Circuit breaker for fault tolerance.

    Prevents cascading failures by stopping requests to failing services.
    """

    failure_threshold: int = 5
    recovery_timeout: float = 30.0
    half_open_max_calls: int = 3

    _state: CircuitState = field(default=CircuitState.CLOSED, init=False)
    _failure_count: int = field(default=0, init=False)
    _last_failure_time: Optional[float] = field(default=None, init=False)
    _half_open_calls: int = field(default=0, init=False)
    _lock: Lock = field(default_factory=Lock, init=False)

    @property
    def state(self) -> CircuitState:
        with self._lock:
            if self._state == CircuitState.OPEN:
                if (
                    self._last_failure_time
                    and time.time() - self._last_failure_time >= self.recovery_timeout
                ):
                    self._state = CircuitState.HALF_OPEN
                    self._half_open_calls = 0
            return self._state

    def record_success(self) -> None:
        with self._lock:
            if self._state == CircuitState.HALF_OPEN:
                self._half_open_calls += 1
                if self._half_open_calls >= self.half_open_max_calls:
                    self._state = CircuitState.CLOSED
                    self._failure_count = 0
            elif self._state == CircuitState.CLOSED:
                self._failure_count = 0

    def record_failure(self) -> None:
        with self._lock:
            self._failure_count += 1
            self._last_failure_time = time.time()
            if self._state == CircuitState.HALF_OPEN:
                self._state = CircuitState.OPEN
            elif self._failure_count >= self.failure_threshold:
                self._state = CircuitState.OPEN

    def allow_request(self) -> bool:
        state = self.state
        if state == CircuitState.CLOSED:
            return True
        if state == CircuitState.HALF_OPEN:
            return True
        return False


@dataclass
class RateLimiter:
    """Token bucket rate limiter.

    Prevents exceeding API rate limits.
    """

    requests_per_second: float = 10.0
    burst_size: int = 20

    _tokens: float = field(default=0.0, init=False)
    _last_update: float = field(default=0.0, init=False)
    _lock: Lock = field(default_factory=Lock, init=False)

    def __post_init__(self) -> None:
        self._tokens = float(self.burst_size)
        self._last_update = time.time()

    def acquire(self, timeout: float = 5.0) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self._lock:
                now = time.time()
                elapsed = now - self._last_update
                self._tokens = min(
                    self.burst_size, self._tokens + elapsed * self.requests_per_second
                )
                self._last_update = now

                if self._tokens >= 1.0:
                    self._tokens -= 1.0
                    return True

            time.sleep(0.05)
        return False


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
        return self.status in ("sent", "success", "fetched")

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


class _BaseConnector:
    """Enterprise-grade base connector with reliability features.

    Features:
    - Automatic retry with exponential backoff
    - Circuit breaker for fault tolerance
    - Rate limiting to respect API limits
    - Connection pooling for performance
    - Health check capability
    - Structured logging
    """

    def __init__(
        self,
        timeout: float = 10.0,
        max_retries: int = 3,
        backoff_factor: float = 0.5,
        rate_limit: float = 10.0,
        circuit_breaker_threshold: int = 5,
    ) -> None:
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor

        self.session = requests.Session()
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=backoff_factor,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=[
                "HEAD",
                "GET",
                "PUT",
                "DELETE",
                "OPTIONS",
                "TRACE",
                "POST",
                "PATCH",
            ],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(
            max_retries=retry_strategy, pool_connections=10, pool_maxsize=20
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        self._circuit_breaker = CircuitBreaker(
            failure_threshold=circuit_breaker_threshold
        )
        self._rate_limiter = RateLimiter(requests_per_second=rate_limit)
        self._metrics_lock = Lock()
        self._request_count = 0
        self._error_count = 0

    def _request(self, method: str, url: str, **kwargs: Any) -> Response:
        if not self._circuit_breaker.allow_request():
            raise RequestException(
                "Circuit breaker is open - service appears unavailable"
            )

        if not self._rate_limiter.acquire(timeout=self.timeout):
            raise RequestException("Rate limit exceeded - too many requests")

        with self._metrics_lock:
            self._request_count += 1
        start_time = time.time()

        try:
            response = self.session.request(
                method=method, url=url, timeout=self.timeout, **kwargs
            )
            elapsed = time.time() - start_time

            if response.status_code >= 500:
                self._circuit_breaker.record_failure()
                with self._metrics_lock:
                    self._error_count += 1
                logger.warning(
                    "Request failed: %s %s -> %s (%.2fs)",
                    method, url, response.status_code, elapsed,
                )
            else:
                self._circuit_breaker.record_success()
                logger.debug(
                    "Request succeeded: %s %s -> %s (%.2fs)",
                    method, url, response.status_code, elapsed,
                )
                # Only emit on state-changing successful calls. GETs are too noisy
                # (health-checks, list operations, polling); state-changing ops
                # are the meaningful side-effects we want to broadcast.
                if (
                    method.upper() in ("POST", "PUT", "PATCH", "DELETE")
                    and 200 <= response.status_code < 300
                ):
                    self._emit_event(
                        "connector.request.success",
                        {
                            "connector": type(self).__name__,
                            "method": method.upper(),
                            "status_code": response.status_code,
                            "elapsed_ms": int(elapsed * 1000),
                        },
                    )

            return response

        except RequestException as exc:
            self._circuit_breaker.record_failure()
            with self._metrics_lock:
                self._error_count += 1
            # Security: Never log str(exc) — may contain creds or tokens
            logger.error(
                "Request exception: %s %s (error: %s)",
                method, url, type(exc).__name__,
            )
            raise

    def health_check(self) -> ConnectorHealth:
        raise NotImplementedError("Subclasses must implement health_check")

    def get_metrics(self) -> Dict[str, Any]:
        return {
            "request_count": self._request_count,
            "error_count": self._error_count,
            "circuit_state": self._circuit_breaker.state.value,
            "error_rate": (
                self._error_count / self._request_count
                if self._request_count > 0
                else 0.0
            ),
        }

    # ------------------------------------------------------------------
    # TrustGraph event emission (best-effort, non-blocking)
    # ------------------------------------------------------------------

    def _emit_event(self, event_type: str, payload: Dict[str, Any]) -> None:
        """Emit an event to the TrustGraph event bus. Never raises.

        Inherited by all 6 connector subclasses (Jira, Confluence, Slack,
        ServiceNow, GitLab, AzureDevOps, GitHub) so any of them can fire
        bus events on key actions (issue created, ticket transitioned,
        message posted, etc.) without a per-class import.
        """
        if _get_tg_bus is None:
            return
        try:
            bus = _get_tg_bus()
            if bus is None:
                return
            emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
            if emit is None:
                return
            result = emit(event_type, payload)
            try:
                import asyncio
                import inspect
                if inspect.iscoroutine(result):
                    try:
                        loop = asyncio.get_running_loop()
                        loop.create_task(result)
                    except RuntimeError:
                        result.close()
            except Exception:  # pragma: no cover
                pass
        except Exception:  # pragma: no cover - best-effort telemetry
            pass


class JiraConnector(_BaseConnector):
    """Create Jira issues for guardrail automation via `/rest/api/3/issue` (Atlassian Cloud/Server)."""

    def __init__(self, settings: Mapping[str, Any]):
        super().__init__(timeout=float(settings.get("timeout", 10.0) or 10.0))
        self.base_url = str(settings.get("url") or "").rstrip("/")
        self.project_key = settings.get("project_key")
        self.default_issue_type = settings.get("default_issue_type", "Task")
        self.user = settings.get("user_email") or settings.get("user")
        token = settings.get("token")
        token_env = settings.get("token_env")
        if token_env:
            token_env_value = os.getenv(str(token_env))
            if token_env_value:
                token = token_env_value
        self.token = token

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.user and self.token and self.project_key)

    def create_issue(self, action: Mapping[str, Any]) -> ConnectorOutcome:
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "jira connector not fully configured"}
            )

        summary = action.get("summary") or "FixOps automation task"
        description = action.get("description") or json.dumps(action, indent=2)
        project_key = action.get("project_key") or self.project_key
        issue_type = action.get("issue_type") or self.default_issue_type

        payload = {
            "fields": {
                "project": {"key": project_key},
                "summary": summary,
                "description": description,
                "issuetype": {"name": issue_type},
                "priority": {"name": action.get("priority", "High")},
            }
        }

        endpoint = urljoin(self.base_url + "/", "rest/api/3/issue")
        try:
            response = self._request(
                "POST",
                endpoint,
                json=payload,
                auth=(self.user, str(self.token)),
                headers={"Accept": "application/json"},
            )
            response.raise_for_status()
        except RequestException as exc:  # pragma: no cover - network failure surface
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "jira delivery failed",
                    "error": type(exc).__name__,
                    "endpoint": endpoint,
                },
            )

        body: Dict[str, Any]
        try:
            body = response.json()
        except ValueError:
            body = {}

        return ConnectorOutcome(
            "sent",
            {
                "endpoint": endpoint,
                "issue_key": body.get("key"),
                "project": project_key,
            },
        )

    def update_issue(self, action: Mapping[str, Any]) -> ConnectorOutcome:
        """Update an existing Jira issue via PUT /rest/api/3/issue/{issueIdOrKey}."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "jira connector not fully configured"}
            )

        issue_key = action.get("issue_key")
        if not issue_key:
            return ConnectorOutcome(
                "failed", {"reason": "issue_key is required for update"}
            )

        fields: Dict[str, Any] = {}
        if action.get("summary"):
            fields["summary"] = action["summary"]
        if action.get("description"):
            fields["description"] = action["description"]
        if action.get("priority"):
            fields["priority"] = {"name": action["priority"]}
        if action.get("assignee"):
            fields["assignee"] = {"accountId": action["assignee"]}
        if action.get("labels"):
            fields["labels"] = action["labels"]

        if not fields:
            return ConnectorOutcome("skipped", {"reason": "no fields to update"})

        payload = {"fields": fields}
        endpoint = urljoin(self.base_url + "/", f"rest/api/3/issue/{issue_key}")

        try:
            response = self._request(
                "PUT",
                endpoint,
                json=payload,
                auth=(self.user, str(self.token)),
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "jira update failed",
                    "error": type(exc).__name__,
                    "endpoint": endpoint,
                },
            )

        return ConnectorOutcome(
            "sent",
            {
                "endpoint": endpoint,
                "issue_key": issue_key,
                "operation": "update",
            },
        )

    def transition_issue(self, action: Mapping[str, Any]) -> ConnectorOutcome:
        """Transition a Jira issue to a new status via POST /rest/api/3/issue/{issueIdOrKey}/transitions."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "jira connector not fully configured"}
            )

        issue_key = action.get("issue_key")
        transition_id = action.get("transition_id")
        transition_name = action.get("transition_name")

        if not issue_key:
            return ConnectorOutcome(
                "failed", {"reason": "issue_key is required for transition"}
            )

        if not transition_id and not transition_name:
            return ConnectorOutcome(
                "failed", {"reason": "transition_id or transition_name is required"}
            )

        # If only transition_name provided, fetch available transitions to get ID
        if not transition_id and transition_name:
            transitions_endpoint = urljoin(
                self.base_url + "/", f"rest/api/3/issue/{issue_key}/transitions"
            )
            try:
                response = self._request(
                    "GET",
                    transitions_endpoint,
                    auth=(self.user, str(self.token)),
                    headers={"Accept": "application/json"},
                )
                response.raise_for_status()
                transitions = response.json().get("transitions", [])
                for t in transitions:
                    if t.get("name", "").lower() == transition_name.lower():
                        transition_id = t.get("id")
                        break
                if not transition_id:
                    return ConnectorOutcome(
                        "failed",
                        {
                            "reason": f"transition '{transition_name}' not found",
                            "available_transitions": [
                                t.get("name") for t in transitions
                            ],
                        },
                    )
            except RequestException as exc:
                return ConnectorOutcome(
                    "failed",
                    {
                        "reason": "failed to fetch transitions",
                        "error": type(exc).__name__,
                    },
                )

        payload = {"transition": {"id": str(transition_id)}}
        endpoint = urljoin(
            self.base_url + "/", f"rest/api/3/issue/{issue_key}/transitions"
        )

        try:
            response = self._request(
                "POST",
                endpoint,
                json=payload,
                auth=(self.user, str(self.token)),
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "jira transition failed",
                    "error": type(exc).__name__,
                    "endpoint": endpoint,
                },
            )

        return ConnectorOutcome(
            "sent",
            {
                "endpoint": endpoint,
                "issue_key": issue_key,
                "transition_id": transition_id,
                "operation": "transition",
            },
        )

    def add_comment(self, action: Mapping[str, Any]) -> ConnectorOutcome:
        """Add a comment to a Jira issue via POST /rest/api/3/issue/{issueIdOrKey}/comment."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "jira connector not fully configured"}
            )

        issue_key = action.get("issue_key")
        comment_body = action.get("comment") or action.get("body")

        if not issue_key:
            return ConnectorOutcome(
                "failed", {"reason": "issue_key is required for comment"}
            )

        if not comment_body:
            return ConnectorOutcome("failed", {"reason": "comment body is required"})

        # Jira Cloud uses Atlassian Document Format (ADF) for comments
        payload = {
            "body": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [{"type": "text", "text": comment_body}],
                    }
                ],
            }
        }

        endpoint = urljoin(self.base_url + "/", f"rest/api/3/issue/{issue_key}/comment")

        try:
            response = self._request(
                "POST",
                endpoint,
                json=payload,
                auth=(self.user, str(self.token)),
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "jira comment failed",
                    "error": type(exc).__name__,
                    "endpoint": endpoint,
                },
            )

        body: Dict[str, Any]
        try:
            body = response.json()
        except ValueError:
            body = {}

        return ConnectorOutcome(
            "sent",
            {
                "endpoint": endpoint,
                "issue_key": issue_key,
                "comment_id": body.get("id"),
                "operation": "comment",
            },
        )

    def get_issue(
        self, issue_key: str, fields: Optional[List[str]] = None
    ) -> ConnectorOutcome:
        """Fetch a single Jira issue by key (Agent READ operation)."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "jira connector not fully configured"}
            )

        endpoint = urljoin(self.base_url + "/", f"rest/api/3/issue/{issue_key}")
        params: Dict[str, str] = {}
        if fields:
            params["fields"] = ",".join(fields)

        try:
            response = self._request(
                "GET",
                endpoint,
                params=params,
                auth=(self.user, str(self.token)),
                headers={"Accept": "application/json"},
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "jira fetch failed",
                    "error": type(exc).__name__,
                    "endpoint": endpoint,
                },
            )

        try:
            data = response.json()
        except ValueError:
            data = {}

        return ConnectorOutcome(
            "fetched",
            {
                "endpoint": endpoint,
                "issue_key": data.get("key"),
                "data": data,
                "operation": "get_issue",
            },
        )

    def search_issues(
        self,
        jql: str,
        max_results: int = 50,
        start_at: int = 0,
        fields: Optional[List[str]] = None,
    ) -> ConnectorOutcome:
        """Search Jira issues using JQL (Agent READ operation)."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "jira connector not fully configured"}
            )

        endpoint = urljoin(self.base_url + "/", "rest/api/3/search")
        payload: Dict[str, Any] = {
            "jql": jql,
            "maxResults": max_results,
            "startAt": start_at,
        }
        if fields:
            payload["fields"] = fields

        try:
            response = self._request(
                "POST",
                endpoint,
                json=payload,
                auth=(self.user, str(self.token)),
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "jira search failed",
                    "error": type(exc).__name__,
                    "endpoint": endpoint,
                },
            )

        try:
            data = response.json()
        except ValueError:
            data = {}

        return ConnectorOutcome(
            "fetched",
            {
                "endpoint": endpoint,
                "total": data.get("total", 0),
                "issues": data.get("issues", []),
                "data": data,
                "operation": "search_issues",
            },
        )

    def list_project_issues(
        self,
        project_key: Optional[str] = None,
        status: Optional[str] = None,
        max_results: int = 50,
    ) -> ConnectorOutcome:
        """List issues in a project with optional status filter (Agent READ operation)."""
        project = project_key or self.project_key
        jql_parts = [f"project = {project}"]
        if status:
            jql_parts.append(f"status = '{status}'")
        jql = " AND ".join(jql_parts) + " ORDER BY updated DESC"
        return self.search_issues(jql, max_results=max_results)

    def get_comments(self, issue_key: str, max_results: int = 50) -> ConnectorOutcome:
        """Fetch comments for a Jira issue (Agent READ operation)."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "jira connector not fully configured"}
            )

        endpoint = urljoin(self.base_url + "/", f"rest/api/3/issue/{issue_key}/comment")
        params = {"maxResults": str(max_results)}

        try:
            response = self._request(
                "GET",
                endpoint,
                params=params,
                auth=(self.user, str(self.token)),
                headers={"Accept": "application/json"},
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "jira comments fetch failed",
                    "error": type(exc).__name__,
                    "endpoint": endpoint,
                },
            )

        try:
            data = response.json()
        except ValueError:
            data = {}

        return ConnectorOutcome(
            "fetched",
            {
                "endpoint": endpoint,
                "issue_key": issue_key,
                "comments": data.get("comments", []),
                "total": data.get("total", 0),
                "data": data,
                "operation": "get_comments",
            },
        )

    def bulk_search(
        self,
        jql: str,
        fields: Optional[List[str]] = None,
        max_results: int = 500,
        page_size: int = 50,
    ) -> ConnectorOutcome:
        """Paginated JQL bulk query — fetches all matching issues up to max_results.

        Returns all issues in a single ConnectorOutcome with automatic pagination.
        Uses POST /rest/api/3/search with startAt advancement.
        """
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "jira connector not fully configured"}
            )

        all_issues: List[Dict[str, Any]] = []
        start_at = 0
        total = None

        while len(all_issues) < max_results:
            batch_size = min(page_size, max_results - len(all_issues))
            endpoint = urljoin(self.base_url + "/", "rest/api/3/search")
            payload: Dict[str, Any] = {
                "jql": jql,
                "maxResults": batch_size,
                "startAt": start_at,
            }
            if fields:
                payload["fields"] = fields

            try:
                response = self._request(
                    "POST",
                    endpoint,
                    json=payload,
                    auth=(self.user, str(self.token)),
                    headers={
                        "Accept": "application/json",
                        "Content-Type": "application/json",
                    },
                )
                response.raise_for_status()
            except RequestException as exc:
                return ConnectorOutcome(
                    "failed",
                    {
                        "reason": "jira bulk search failed",
                        "error": type(exc).__name__,
                        "endpoint": endpoint,
                        "fetched_so_far": len(all_issues),
                    },
                )

            try:
                data = response.json()
            except ValueError:
                break

            issues = data.get("issues", [])
            if total is None:
                total = data.get("total", 0)
            all_issues.extend(issues)
            start_at += len(issues)

            if not issues or start_at >= (total or 0):
                break

        return ConnectorOutcome(
            "fetched",
            {
                "total": total or len(all_issues),
                "fetched": len(all_issues),
                "issues": all_issues,
                "operation": "bulk_search",
                "pages_fetched": (start_at // page_size) + (1 if start_at % page_size else 0),
            },
        )

    def create_issue_with_custom_fields(
        self,
        action: Mapping[str, Any],
        custom_fields: Optional[Dict[str, Any]] = None,
    ) -> ConnectorOutcome:
        """Create a Jira issue with support for custom fields.

        custom_fields should be a dict mapping Jira custom field IDs to values,
        e.g. {"customfield_10001": "value", "customfield_10042": {"id": "10100"}}
        """
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "jira connector not fully configured"}
            )

        summary = action.get("summary") or "FixOps automation task"
        description = action.get("description") or json.dumps(action, indent=2)
        project_key = action.get("project_key") or self.project_key
        issue_type = action.get("issue_type") or self.default_issue_type

        fields_payload: Dict[str, Any] = {
            "project": {"key": project_key},
            "summary": summary,
            "description": description,
            "issuetype": {"name": issue_type},
            "priority": {"name": action.get("priority", "High")},
        }

        # Merge custom fields
        merged_custom = {**(action.get("custom_fields") or {}), **(custom_fields or {})}
        for cf_key, cf_value in merged_custom.items():
            fields_payload[cf_key] = cf_value

        # Optional: labels, components, assignee
        if action.get("labels"):
            fields_payload["labels"] = action["labels"]
        if action.get("components"):
            fields_payload["components"] = [
                {"name": c} for c in action["components"]
            ]
        if action.get("assignee"):
            fields_payload["assignee"] = {"accountId": action["assignee"]}

        payload = {"fields": fields_payload}
        endpoint = urljoin(self.base_url + "/", "rest/api/3/issue")
        try:
            response = self._request(
                "POST",
                endpoint,
                json=payload,
                auth=(self.user, str(self.token)),
                headers={"Accept": "application/json"},
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "jira issue creation failed",
                    "error": type(exc).__name__,
                    "endpoint": endpoint,
                },
            )

        try:
            body = response.json()
        except ValueError:
            body = {}

        return ConnectorOutcome(
            "sent",
            {
                "endpoint": endpoint,
                "issue_key": body.get("key"),
                "project": project_key,
                "custom_fields_applied": list(merged_custom.keys()),
                "operation": "create_issue_with_custom_fields",
            },
        )

    def assign_to_sprint(
        self, issue_key: str, sprint_id: int
    ) -> ConnectorOutcome:
        """Move an issue into an Agile sprint via POST /rest/agile/1.0/sprint/{sprintId}/issue.

        Requires Jira Software (Agile) board access.
        """
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "jira connector not fully configured"}
            )

        endpoint = urljoin(
            self.base_url + "/", f"rest/agile/1.0/sprint/{sprint_id}/issue"
        )
        payload = {"issues": [issue_key]}

        try:
            response = self._request(
                "POST",
                endpoint,
                json=payload,
                auth=(self.user, str(self.token)),
                headers={"Accept": "application/json"},
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "sprint assignment failed",
                    "error": type(exc).__name__,
                    "endpoint": endpoint,
                },
            )

        return ConnectorOutcome(
            "sent",
            {
                "endpoint": endpoint,
                "issue_key": issue_key,
                "sprint_id": sprint_id,
                "operation": "assign_to_sprint",
            },
        )

    def health_check(self) -> ConnectorHealth:
        """Check Jira connectivity and authentication."""
        if not self.configured:
            return ConnectorHealth(
                healthy=False, latency_ms=0, message="Connector not configured"
            )

        start_time = time.time()
        endpoint = urljoin(self.base_url + "/", "rest/api/3/myself")

        try:
            response = self._request(
                "GET",
                endpoint,
                auth=(self.user, str(self.token)),
                headers={"Accept": "application/json"},
            )
            latency_ms = (time.time() - start_time) * 1000

            if response.status_code == 200:
                return ConnectorHealth(
                    healthy=True,
                    latency_ms=latency_ms,
                    message="Connected successfully",
                )
            return ConnectorHealth(
                healthy=False,
                latency_ms=latency_ms,
                message=f"HTTP {response.status_code}: {response.text[:100]}",
            )
        except RequestException as exc:
            latency_ms = (time.time() - start_time) * 1000
            return ConnectorHealth(
                healthy=False,
                latency_ms=latency_ms,
                message=f"Connection failed: {exc}",
            )


class ConfluenceConnector(_BaseConnector):
    """Publish Confluence pages for audit evidence via `/rest/api/content` (storage representation)."""

    def __init__(self, settings: Mapping[str, Any]):
        super().__init__(timeout=float(settings.get("timeout", 10.0) or 10.0))
        self.base_url = str(settings.get("base_url") or "").rstrip("/")
        self.space_key = settings.get("space_key")
        self.parent_page_id = settings.get("parent_page_id")
        self.user = settings.get("user") or settings.get("user_email")
        token = settings.get("token")
        token_env = settings.get("token_env")
        if token_env:
            token_env_value = os.getenv(str(token_env))
            if token_env_value:
                token = token_env_value
        self.token = token

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.space_key and self.user and self.token)

    def create_page(self, action: Mapping[str, Any]) -> ConnectorOutcome:
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "confluence connector not fully configured"}
            )

        title = action.get("title") or f"FixOps Automation {action.get('id')}"
        body = (
            action.get("body") or action.get("content") or json.dumps(action, indent=2)
        )

        payload = {
            "type": "page",
            "title": title,
            "space": {"key": action.get("space") or self.space_key},
            "body": {
                "storage": {
                    "value": body,
                    "representation": action.get("representation", "storage"),
                }
            },
        }
        ancestors = []
        parent_id = action.get("parent_page_id") or self.parent_page_id
        if parent_id:
            ancestors.append({"id": str(parent_id)})
        if ancestors:
            payload["ancestors"] = ancestors

        endpoint = urljoin(self.base_url + "/", "rest/api/content")
        try:
            response = self._request(
                "POST",
                endpoint,
                json=payload,
                auth=(self.user, str(self.token)),
                headers={"Content-Type": "application/json"},
            )
            response.raise_for_status()
        except RequestException as exc:  # pragma: no cover - network failure surface
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "confluence delivery failed",
                    "error": type(exc).__name__,
                    "endpoint": endpoint,
                },
            )

        body_payload: Dict[str, Any]
        try:
            body_payload = response.json()
        except ValueError:
            body_payload = {}

        return ConnectorOutcome(
            "sent",
            {
                "endpoint": endpoint,
                "page_id": body_payload.get("id"),
                "space": payload["space"]["key"],  # type: ignore[index]
            },
        )

    def update_page(self, action: Mapping[str, Any]) -> ConnectorOutcome:
        """Update an existing Confluence page via PUT /rest/api/content/{id}.

        Bidirectional sync: This method enables updating pages that were previously
        created or fetched, completing the sync cycle.

        Required action fields:
        - page_id: The Confluence page ID to update

        Optional action fields:
        - title: New page title
        - body/content: New page content (storage format)
        - version: Current version number (auto-fetched if not provided)
        """
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "confluence connector not fully configured"}
            )

        page_id = action.get("page_id")
        if not page_id:
            return ConnectorOutcome(
                "failed", {"reason": "page_id is required for update"}
            )

        # Fetch current page to get version number if not provided
        version = action.get("version")
        current_title = None
        if not version:
            get_result = self.get_page(str(page_id))
            if not get_result.success:
                return ConnectorOutcome(
                    "failed",
                    {
                        "reason": "failed to fetch current page version",
                        "page_id": page_id,
                    },
                )
            page_data = get_result.data or {}
            version = page_data.get("version", {}).get("number", 1)
            current_title = page_data.get("title")

        title = action.get("title") or current_title or f"FixOps Page {page_id}"
        body = (
            action.get("body") or action.get("content") or json.dumps(action, indent=2)
        )

        payload = {
            "type": "page",
            "title": title,
            "version": {"number": int(version) + 1},
            "body": {
                "storage": {
                    "value": body,
                    "representation": action.get("representation", "storage"),
                }
            },
        }

        endpoint = urljoin(self.base_url + "/", f"rest/api/content/{page_id}")
        try:
            response = self._request(
                "PUT",
                endpoint,
                json=payload,
                auth=(self.user, str(self.token)),
                headers={"Content-Type": "application/json"},
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "confluence update failed",
                    "error": type(exc).__name__,
                    "endpoint": endpoint,
                },
            )

        body_payload: Dict[str, Any]
        try:
            body_payload = response.json()
        except ValueError:
            body_payload = {}

        return ConnectorOutcome(
            "sent",
            {
                "endpoint": endpoint,
                "page_id": body_payload.get("id"),
                "title": body_payload.get("title"),
                "version": body_payload.get("version", {}).get("number"),
                "operation": "update_page",
            },
        )

    def get_page(self, page_id: str) -> ConnectorOutcome:
        """Fetch a single Confluence page by ID (Agent READ operation)."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "confluence connector not fully configured"}
            )

        endpoint = urljoin(
            self.base_url + "/",
            f"rest/api/content/{page_id}?expand=body.storage,version",
        )

        try:
            response = self._request(
                "GET",
                endpoint,
                auth=(self.user, str(self.token)),
                headers={"Accept": "application/json"},
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "confluence fetch failed",
                    "error": type(exc).__name__,
                    "endpoint": endpoint,
                },
            )

        try:
            data = response.json()
        except ValueError:
            data = {}

        return ConnectorOutcome(
            "fetched",
            {
                "endpoint": endpoint,
                "page_id": data.get("id"),
                "title": data.get("title"),
                "data": data,
                "operation": "get_page",
            },
        )

    def search_pages(self, cql: str, max_results: int = 50) -> ConnectorOutcome:
        """Search Confluence pages using CQL (Agent READ operation)."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "confluence connector not fully configured"}
            )

        endpoint = urljoin(self.base_url + "/", "rest/api/content/search")
        params = {"cql": cql, "limit": str(max_results)}

        try:
            response = self._request(
                "GET",
                endpoint,
                params=params,
                auth=(self.user, str(self.token)),
                headers={"Accept": "application/json"},
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "confluence search failed",
                    "error": type(exc).__name__,
                    "endpoint": endpoint,
                },
            )

        try:
            data = response.json()
        except ValueError:
            data = {}

        return ConnectorOutcome(
            "fetched",
            {
                "endpoint": endpoint,
                "results": data.get("results", []),
                "count": len(data.get("results", [])),
                "data": data,
                "operation": "search_pages",
            },
        )

    def list_pages(
        self, space_key: Optional[str] = None, max_results: int = 50
    ) -> ConnectorOutcome:
        """List Confluence pages in a space (Agent READ operation)."""
        space = space_key or self.space_key
        cql = f"space = '{space}' AND type = page ORDER BY lastmodified DESC"
        return self.search_pages(cql, max_results=max_results)

    def health_check(self) -> ConnectorHealth:
        """Check Confluence connectivity and authentication."""
        if not self.configured:
            return ConnectorHealth(
                healthy=False, latency_ms=0, message="Connector not configured"
            )

        start_time = time.time()
        endpoint = urljoin(self.base_url + "/", "rest/api/space")

        try:
            response = self._request(
                "GET",
                endpoint,
                auth=(self.user, str(self.token)),
                headers={"Accept": "application/json"},
            )
            latency_ms = (time.time() - start_time) * 1000

            if response.status_code == 200:
                return ConnectorHealth(
                    healthy=True,
                    latency_ms=latency_ms,
                    message="Connected successfully",
                )
            return ConnectorHealth(
                healthy=False,
                latency_ms=latency_ms,
                message=f"HTTP {response.status_code}: {response.text[:100]}",
            )
        except RequestException as exc:
            latency_ms = (time.time() - start_time) * 1000
            return ConnectorHealth(
                healthy=False,
                latency_ms=latency_ms,
                message=f"Connection failed: {exc}",
            )


class SlackConnector(_BaseConnector):
    """Send Slack notifications via incoming webhook."""

    def __init__(self, settings: Mapping[str, Any]):
        super().__init__(timeout=float(settings.get("timeout", 6.0) or 6.0))
        self.default_webhook = settings.get("webhook_url")
        webhook_env = settings.get("webhook_env") or settings.get("slack_webhook_env")
        if webhook_env:
            env_value = os.getenv(str(webhook_env))
            if env_value:
                self.default_webhook = env_value

    def post_message(self, action: Mapping[str, Any]) -> ConnectorOutcome:
        webhook = action.get("webhook_url") or self.default_webhook
        if not webhook:
            return ConnectorOutcome(
                "skipped", {"reason": "slack webhook not configured"}
            )

        payload = {
            "text": action.get("text")
            or action.get("summary")
            or "FixOps automation notification",
        }
        if action.get("channel"):
            payload["channel"] = action["channel"]

        try:
            response = self._request("POST", webhook, json=payload)
            response.raise_for_status()
        except RequestException as exc:  # pragma: no cover - network failure surface
            return ConnectorOutcome(
                "failed", {"reason": "slack delivery failed", "error": type(exc).__name__}
            )

        return ConnectorOutcome("sent", {"webhook": webhook})

    def post_blocks(self, action: Mapping[str, Any]) -> ConnectorOutcome:
        """Send a Slack Block Kit message via webhook or Bot API.

        Supports rich formatting with sections, buttons, dividers, and context blocks.
        action["blocks"] should be a list of Slack Block Kit block dicts.
        """
        webhook = action.get("webhook_url") or self.default_webhook
        bot_token = action.get("bot_token") or getattr(self, "bot_token", None)

        blocks = action.get("blocks", [])
        text = action.get("text") or action.get("summary") or "ALdeci notification"

        if bot_token and action.get("channel"):
            # Use Slack Web API (chat.postMessage) for richer features
            payload: Dict[str, Any] = {
                "channel": action["channel"],
                "text": text,
                "blocks": blocks,
            }
            if action.get("thread_ts"):
                payload["thread_ts"] = action["thread_ts"]
            try:
                response = self._request(
                    "POST",
                    "https://slack.com/api/chat.postMessage",
                    json=payload,
                    headers={"Authorization": f"Bearer {bot_token}"},
                )
                response.raise_for_status()
                data = response.json()
                if not data.get("ok"):
                    return ConnectorOutcome(
                        "failed",
                        {"reason": "slack api error", "error": data.get("error", "unknown")},
                    )
                return ConnectorOutcome(
                    "sent",
                    {
                        "channel": data.get("channel"),
                        "ts": data.get("ts"),
                        "operation": "post_blocks",
                    },
                )
            except RequestException as exc:
                return ConnectorOutcome(
                    "failed", {"reason": "slack api failed", "error": type(exc).__name__}
                )

        if not webhook:
            return ConnectorOutcome(
                "skipped", {"reason": "slack webhook not configured"}
            )

        payload = {"text": text, "blocks": blocks}
        if action.get("channel"):
            payload["channel"] = action["channel"]

        try:
            response = self._request("POST", webhook, json=payload)
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed", {"reason": "slack block delivery failed", "error": type(exc).__name__}
            )

        return ConnectorOutcome("sent", {"webhook": webhook, "operation": "post_blocks"})

    def post_interactive(self, action: Mapping[str, Any]) -> ConnectorOutcome:
        """Send a Slack interactive message with action buttons.

        Convenience wrapper that builds Block Kit blocks with action buttons.
        action["buttons"] should be a list of dicts with text, action_id, and optional style/value.
        """
        text = action.get("text") or action.get("summary") or "Action required"
        buttons = action.get("buttons", [])

        blocks: List[Dict[str, Any]] = [
            {"type": "section", "text": {"type": "mrkdwn", "text": text}},
        ]

        if buttons:
            elements = []
            for btn in buttons[:5]:  # Slack max 5 buttons per action block
                element: Dict[str, Any] = {
                    "type": "button",
                    "text": {"type": "plain_text", "text": str(btn.get("text", "Click"))},
                    "action_id": str(btn.get("action_id", f"btn_{len(elements)}")),
                }
                if btn.get("value"):
                    element["value"] = str(btn["value"])
                if btn.get("style") in ("primary", "danger"):
                    element["style"] = btn["style"]
                if btn.get("url"):
                    element["url"] = str(btn["url"])
                elements.append(element)
            blocks.append({"type": "actions", "elements": elements})

        return self.post_blocks({**action, "blocks": blocks, "text": text})

    def list_channels(
        self, bot_token: str, types: str = "public_channel", limit: int = 200
    ) -> ConnectorOutcome:
        """List Slack channels using Bot token via conversations.list API.

        Requires bot token with channels:read scope.
        """
        try:
            response = self._request(
                "GET",
                "https://slack.com/api/conversations.list",
                params={"types": types, "limit": str(limit), "exclude_archived": "true"},
                headers={"Authorization": f"Bearer {bot_token}"},
            )
            response.raise_for_status()
            data = response.json()
            if not data.get("ok"):
                return ConnectorOutcome(
                    "failed",
                    {"reason": "slack api error", "error": data.get("error", "unknown")},
                )
            channels = data.get("channels", [])
            return ConnectorOutcome(
                "fetched",
                {
                    "channels": [
                        {"id": c["id"], "name": c.get("name", ""), "topic": c.get("topic", {}).get("value", "")}
                        for c in channels
                    ],
                    "count": len(channels),
                    "operation": "list_channels",
                },
            )
        except RequestException as exc:
            return ConnectorOutcome(
                "failed", {"reason": "slack channels fetch failed", "error": type(exc).__name__}
            )

    def health_check(self) -> ConnectorHealth:
        """Check Slack webhook configuration.

        Note: Slack webhooks don't have a dedicated health endpoint.
        This check validates the webhook URL is configured and reachable.
        """
        if not self.default_webhook:
            return ConnectorHealth(
                healthy=False, latency_ms=0, message="Webhook URL not configured"
            )

        start_time = time.time()
        try:
            response = self._request(
                "POST",
                self.default_webhook,
                json={"text": ""},
            )
            latency_ms = (time.time() - start_time) * 1000

            if response.status_code in (200, 400):
                return ConnectorHealth(
                    healthy=True,
                    latency_ms=latency_ms,
                    message="Webhook endpoint reachable",
                )
            return ConnectorHealth(
                healthy=False,
                latency_ms=latency_ms,
                message=f"HTTP {response.status_code}: {response.text[:100]}",
            )
        except RequestException as exc:
            latency_ms = (time.time() - start_time) * 1000
            return ConnectorHealth(
                healthy=False,
                latency_ms=latency_ms,
                message=f"Connection failed: {exc}",
            )


class ServiceNowConnector(_BaseConnector):
    """Create and manage ServiceNow incidents via REST API."""

    def __init__(self, settings: Mapping[str, Any]):
        super().__init__(timeout=float(settings.get("timeout", 15.0) or 15.0))
        self.instance_url = str(
            settings.get("instance_url") or settings.get("url") or ""
        ).rstrip("/")
        self.user = settings.get("user") or settings.get("username")
        token = settings.get("token") or settings.get("password")
        token_env = settings.get("token_env")
        if token_env:
            token_env_value = os.getenv(str(token_env))
            if token_env_value:
                token = token_env_value
        self.token = token
        self.default_assignment_group = settings.get("assignment_group")
        self.default_caller_id = settings.get("caller_id")

    @property
    def configured(self) -> bool:
        return bool(self.instance_url and self.user and self.token)

    def create_incident(self, action: Mapping[str, Any]) -> ConnectorOutcome:
        """Create a ServiceNow incident via POST /api/now/table/incident."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "servicenow connector not fully configured"}
            )

        payload: Dict[str, Any] = {
            "short_description": action.get("summary")
            or action.get("short_description")
            or "FixOps automation incident",
            "description": action.get("description") or json.dumps(action, indent=2),
            "urgency": action.get("urgency", "2"),
            "impact": action.get("impact", "2"),
        }

        if action.get("assignment_group") or self.default_assignment_group:
            payload["assignment_group"] = (
                action.get("assignment_group") or self.default_assignment_group
            )
        if action.get("caller_id") or self.default_caller_id:
            payload["caller_id"] = action.get("caller_id") or self.default_caller_id
        if action.get("category"):
            payload["category"] = action["category"]
        if action.get("subcategory"):
            payload["subcategory"] = action["subcategory"]

        endpoint = f"{self.instance_url}/api/now/table/incident"

        try:
            response = self._request(
                "POST",
                endpoint,
                json=payload,
                auth=(self.user, str(self.token)),
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "servicenow incident creation failed",
                    "error": type(exc).__name__,
                    "endpoint": endpoint,
                },
            )

        body: Dict[str, Any]
        try:
            body = response.json().get("result", {})
        except ValueError:
            body = {}

        return ConnectorOutcome(
            "sent",
            {
                "endpoint": endpoint,
                "sys_id": body.get("sys_id"),
                "number": body.get("number"),
                "operation": "create_incident",
            },
        )

    def update_incident(self, action: Mapping[str, Any]) -> ConnectorOutcome:
        """Update a ServiceNow incident via PUT /api/now/table/incident/{sys_id}."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "servicenow connector not fully configured"}
            )

        sys_id = action.get("sys_id") or action.get("incident_id")
        if not sys_id:
            return ConnectorOutcome(
                "failed", {"reason": "sys_id is required for update"}
            )

        payload: Dict[str, Any] = {}
        if action.get("short_description"):
            payload["short_description"] = action["short_description"]
        if action.get("description"):
            payload["description"] = action["description"]
        if action.get("state"):
            payload["state"] = action["state"]
        if action.get("urgency"):
            payload["urgency"] = action["urgency"]
        if action.get("impact"):
            payload["impact"] = action["impact"]
        if action.get("assignment_group"):
            payload["assignment_group"] = action["assignment_group"]
        if action.get("assigned_to"):
            payload["assigned_to"] = action["assigned_to"]
        if action.get("close_code"):
            payload["close_code"] = action["close_code"]
        if action.get("close_notes"):
            payload["close_notes"] = action["close_notes"]

        if not payload:
            return ConnectorOutcome("skipped", {"reason": "no fields to update"})

        endpoint = f"{self.instance_url}/api/now/table/incident/{sys_id}"

        try:
            response = self._request(
                "PUT",
                endpoint,
                json=payload,
                auth=(self.user, str(self.token)),
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "servicenow incident update failed",
                    "error": type(exc).__name__,
                    "endpoint": endpoint,
                },
            )

        return ConnectorOutcome(
            "sent",
            {
                "endpoint": endpoint,
                "sys_id": sys_id,
                "operation": "update_incident",
            },
        )

    def add_work_note(self, action: Mapping[str, Any]) -> ConnectorOutcome:
        """Add a work note to a ServiceNow incident via PUT /api/now/table/incident/{sys_id}."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "servicenow connector not fully configured"}
            )

        sys_id = action.get("sys_id") or action.get("incident_id")
        work_note = (
            action.get("work_note") or action.get("comment") or action.get("body")
        )

        if not sys_id:
            return ConnectorOutcome(
                "failed", {"reason": "sys_id is required for work note"}
            )

        if not work_note:
            return ConnectorOutcome(
                "failed", {"reason": "work_note content is required"}
            )

        payload = {"work_notes": work_note}
        endpoint = f"{self.instance_url}/api/now/table/incident/{sys_id}"

        try:
            response = self._request(
                "PUT",
                endpoint,
                json=payload,
                auth=(self.user, str(self.token)),
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                },
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "servicenow work note failed",
                    "error": type(exc).__name__,
                    "endpoint": endpoint,
                },
            )

        return ConnectorOutcome(
            "sent",
            {
                "endpoint": endpoint,
                "sys_id": sys_id,
                "operation": "add_work_note",
            },
        )

    def get_incident(self, sys_id: str) -> ConnectorOutcome:
        """Fetch a single ServiceNow incident by sys_id (Agent READ operation)."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "servicenow connector not fully configured"}
            )

        endpoint = f"{self.instance_url}/api/now/table/incident/{sys_id}"

        try:
            response = self._request(
                "GET",
                endpoint,
                auth=(self.user, str(self.token)),
                headers={"Accept": "application/json"},
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "servicenow fetch failed",
                    "error": type(exc).__name__,
                    "endpoint": endpoint,
                },
            )

        try:
            data = response.json().get("result", {})
        except ValueError:
            data = {}

        return ConnectorOutcome(
            "fetched",
            {
                "endpoint": endpoint,
                "sys_id": data.get("sys_id"),
                "number": data.get("number"),
                "data": data,
                "operation": "get_incident",
            },
        )

    def search_incidents(
        self, query: str, max_results: int = 50, fields: Optional[List[str]] = None
    ) -> ConnectorOutcome:
        """Search ServiceNow incidents using encoded query (Agent READ operation)."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "servicenow connector not fully configured"}
            )

        endpoint = f"{self.instance_url}/api/now/table/incident"
        params: Dict[str, str] = {
            "sysparm_query": query,
            "sysparm_limit": str(max_results),
        }
        if fields:
            params["sysparm_fields"] = ",".join(fields)

        try:
            response = self._request(
                "GET",
                endpoint,
                params=params,
                auth=(self.user, str(self.token)),
                headers={"Accept": "application/json"},
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "servicenow search failed",
                    "error": type(exc).__name__,
                    "endpoint": endpoint,
                },
            )

        try:
            data = response.json()
        except ValueError:
            data = {}

        return ConnectorOutcome(
            "fetched",
            {
                "endpoint": endpoint,
                "incidents": data.get("result", []),
                "count": len(data.get("result", [])),
                "data": data,
                "operation": "search_incidents",
            },
        )

    def list_incidents(
        self,
        state: Optional[str] = None,
        assignment_group: Optional[str] = None,
        max_results: int = 50,
    ) -> ConnectorOutcome:
        """List ServiceNow incidents with optional filters (Agent READ operation)."""
        query_parts = []
        if state:
            query_parts.append(f"state={state}")
        if assignment_group:
            query_parts.append(f"assignment_group={assignment_group}")
        query_parts.append("ORDERBYDESCsys_updated_on")
        query = "^".join(query_parts) if query_parts else "ORDERBYDESCsys_updated_on"
        return self.search_incidents(query, max_results=max_results)

    def health_check(self) -> ConnectorHealth:
        """Check ServiceNow connectivity and authentication."""
        if not self.configured:
            return ConnectorHealth(
                healthy=False, latency_ms=0, message="Connector not configured"
            )

        start_time = time.time()
        endpoint = f"{self.instance_url}/api/now/table/sys_user?sysparm_limit=1"

        try:
            response = self._request(
                "GET",
                endpoint,
                auth=(self.user, str(self.token)),
                headers={"Accept": "application/json"},
            )
            latency_ms = (time.time() - start_time) * 1000

            if response.status_code == 200:
                return ConnectorHealth(
                    healthy=True,
                    latency_ms=latency_ms,
                    message="Connected successfully",
                )
            return ConnectorHealth(
                healthy=False,
                latency_ms=latency_ms,
                message=f"HTTP {response.status_code}: {response.text[:100]}",
            )
        except RequestException as exc:
            latency_ms = (time.time() - start_time) * 1000
            return ConnectorHealth(
                healthy=False,
                latency_ms=latency_ms,
                message=f"Connection failed: {exc}",
            )


class GitLabConnector(_BaseConnector):
    """Create and manage GitLab issues via REST API v4."""

    def __init__(self, settings: Mapping[str, Any]):
        super().__init__(timeout=float(settings.get("timeout", 10.0) or 10.0))
        self.base_url = str(
            settings.get("base_url") or settings.get("url") or "https://gitlab.com"
        ).rstrip("/")
        self.project_id = settings.get("project_id")
        token = settings.get("token") or settings.get("private_token")
        token_env = settings.get("token_env")
        if token_env:
            token_env_value = os.getenv(str(token_env))
            if token_env_value:
                token = token_env_value
        self.token = token

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.project_id and self.token)

    def create_issue(self, action: Mapping[str, Any]) -> ConnectorOutcome:
        """Create a GitLab issue via POST /api/v4/projects/{id}/issues."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "gitlab connector not fully configured"}
            )

        project_id = action.get("project_id") or self.project_id
        payload: Dict[str, Any] = {
            "title": action.get("title")
            or action.get("summary")
            or "FixOps automation issue",
        }

        if action.get("description"):
            payload["description"] = action["description"]
        if action.get("labels"):
            payload["labels"] = (
                action["labels"]
                if isinstance(action["labels"], str)
                else ",".join(action["labels"])
            )
        if action.get("assignee_ids"):
            payload["assignee_ids"] = action["assignee_ids"]
        if action.get("milestone_id"):
            payload["milestone_id"] = action["milestone_id"]
        if action.get("due_date"):
            payload["due_date"] = action["due_date"]

        endpoint = f"{self.base_url}/api/v4/projects/{project_id}/issues"

        try:
            response = self._request(
                "POST",
                endpoint,
                json=payload,
                headers={
                    "PRIVATE-TOKEN": str(self.token),
                    "Content-Type": "application/json",
                },
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "gitlab issue creation failed",
                    "error": type(exc).__name__,
                    "endpoint": endpoint,
                },
            )

        body: Dict[str, Any]
        try:
            body = response.json()
        except ValueError:
            body = {}

        return ConnectorOutcome(
            "sent",
            {
                "endpoint": endpoint,
                "issue_iid": body.get("iid"),
                "issue_id": body.get("id"),
                "web_url": body.get("web_url"),
                "operation": "create_issue",
            },
        )

    def update_issue(self, action: Mapping[str, Any]) -> ConnectorOutcome:
        """Update a GitLab issue via PUT /api/v4/projects/{id}/issues/{issue_iid}."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "gitlab connector not fully configured"}
            )

        project_id = action.get("project_id") or self.project_id
        issue_iid = action.get("issue_iid") or action.get("issue_id")

        if not issue_iid:
            return ConnectorOutcome(
                "failed", {"reason": "issue_iid is required for update"}
            )

        payload: Dict[str, Any] = {}
        if action.get("title"):
            payload["title"] = action["title"]
        if action.get("description"):
            payload["description"] = action["description"]
        if action.get("labels"):
            payload["labels"] = (
                action["labels"]
                if isinstance(action["labels"], str)
                else ",".join(action["labels"])
            )
        if action.get("state_event"):
            payload["state_event"] = action["state_event"]
        if action.get("assignee_ids"):
            payload["assignee_ids"] = action["assignee_ids"]

        if not payload:
            return ConnectorOutcome("skipped", {"reason": "no fields to update"})

        endpoint = f"{self.base_url}/api/v4/projects/{project_id}/issues/{issue_iid}"

        try:
            response = self._request(
                "PUT",
                endpoint,
                json=payload,
                headers={
                    "PRIVATE-TOKEN": str(self.token),
                    "Content-Type": "application/json",
                },
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "gitlab issue update failed",
                    "error": type(exc).__name__,
                    "endpoint": endpoint,
                },
            )

        return ConnectorOutcome(
            "sent",
            {
                "endpoint": endpoint,
                "issue_iid": issue_iid,
                "operation": "update_issue",
            },
        )

    def add_comment(self, action: Mapping[str, Any]) -> ConnectorOutcome:
        """Add a comment (note) to a GitLab issue via POST /api/v4/projects/{id}/issues/{issue_iid}/notes."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "gitlab connector not fully configured"}
            )

        project_id = action.get("project_id") or self.project_id
        issue_iid = action.get("issue_iid") or action.get("issue_id")
        comment_body = action.get("comment") or action.get("body")

        if not issue_iid:
            return ConnectorOutcome(
                "failed", {"reason": "issue_iid is required for comment"}
            )

        if not comment_body:
            return ConnectorOutcome("failed", {"reason": "comment body is required"})

        payload = {"body": comment_body}
        endpoint = (
            f"{self.base_url}/api/v4/projects/{project_id}/issues/{issue_iid}/notes"
        )

        try:
            response = self._request(
                "POST",
                endpoint,
                json=payload,
                headers={
                    "PRIVATE-TOKEN": str(self.token),
                    "Content-Type": "application/json",
                },
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "gitlab comment failed",
                    "error": type(exc).__name__,
                    "endpoint": endpoint,
                },
            )

        body: Dict[str, Any]
        try:
            body = response.json()
        except ValueError:
            body = {}

        return ConnectorOutcome(
            "sent",
            {
                "endpoint": endpoint,
                "issue_iid": issue_iid,
                "note_id": body.get("id"),
                "operation": "add_comment",
            },
        )

    def get_issue(
        self, issue_iid: int, project_id: Optional[str] = None
    ) -> ConnectorOutcome:
        """Fetch a single GitLab issue by IID (Agent READ operation)."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "gitlab connector not fully configured"}
            )

        proj = project_id or self.project_id
        endpoint = f"{self.base_url}/api/v4/projects/{proj}/issues/{issue_iid}"

        try:
            response = self._request(
                "GET",
                endpoint,
                headers={"PRIVATE-TOKEN": str(self.token)},
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "gitlab fetch failed",
                    "error": type(exc).__name__,
                    "endpoint": endpoint,
                },
            )

        try:
            data = response.json()
        except ValueError:
            data = {}

        return ConnectorOutcome(
            "fetched",
            {
                "endpoint": endpoint,
                "issue_iid": data.get("iid"),
                "issue_id": data.get("id"),
                "data": data,
                "operation": "get_issue",
            },
        )

    def search_issues(
        self,
        search: Optional[str] = None,
        labels: Optional[str] = None,
        state: str = "opened",
        max_results: int = 50,
    ) -> ConnectorOutcome:
        """Search GitLab issues (Agent READ operation)."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "gitlab connector not fully configured"}
            )

        endpoint = f"{self.base_url}/api/v4/projects/{self.project_id}/issues"
        params: Dict[str, str] = {"state": state, "per_page": str(max_results)}
        if search:
            params["search"] = search
        if labels:
            params["labels"] = labels

        try:
            response = self._request(
                "GET",
                endpoint,
                params=params,
                headers={"PRIVATE-TOKEN": str(self.token)},
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "gitlab search failed",
                    "error": type(exc).__name__,
                    "endpoint": endpoint,
                },
            )

        try:
            data = response.json()
        except ValueError:
            data = []

        return ConnectorOutcome(
            "fetched",
            {
                "endpoint": endpoint,
                "issues": data,
                "count": len(data),
                "operation": "search_issues",
            },
        )

    def list_issues(
        self, state: str = "opened", max_results: int = 50
    ) -> ConnectorOutcome:
        """List GitLab issues with optional state filter (Agent READ operation)."""
        return self.search_issues(state=state, max_results=max_results)

    def health_check(self) -> ConnectorHealth:
        """Check GitLab connectivity and authentication."""
        if not self.configured:
            return ConnectorHealth(
                healthy=False, latency_ms=0, message="Connector not configured"
            )

        start_time = time.time()
        endpoint = f"{self.base_url}/api/v4/user"

        try:
            response = self._request(
                "GET",
                endpoint,
                headers={"PRIVATE-TOKEN": str(self.token)},
            )
            latency_ms = (time.time() - start_time) * 1000

            if response.status_code == 200:
                return ConnectorHealth(
                    healthy=True,
                    latency_ms=latency_ms,
                    message="Connected successfully",
                )
            return ConnectorHealth(
                healthy=False,
                latency_ms=latency_ms,
                message=f"HTTP {response.status_code}: {response.text[:100]}",
            )
        except RequestException as exc:
            latency_ms = (time.time() - start_time) * 1000
            return ConnectorHealth(
                healthy=False,
                latency_ms=latency_ms,
                message=f"Connection failed: {exc}",
            )


class AzureDevOpsConnector(_BaseConnector):
    """Create and manage Azure DevOps work items via REST API."""

    def __init__(self, settings: Mapping[str, Any]):
        super().__init__(timeout=float(settings.get("timeout", 10.0) or 10.0))
        self.organization = settings.get("organization") or settings.get("org")
        self.project = settings.get("project")
        self.base_url = str(settings.get("base_url") or "https://dev.azure.com").rstrip(
            "/"
        )
        token = settings.get("token") or settings.get("pat")
        token_env = settings.get("token_env")
        if token_env:
            token_env_value = os.getenv(str(token_env))
            if token_env_value:
                token = token_env_value
        self.token = token
        self.default_work_item_type = settings.get("work_item_type", "Bug")

    @property
    def configured(self) -> bool:
        return bool(self.organization and self.project and self.token)

    def _get_auth_header(self) -> Dict[str, str]:
        """Generate Basic auth header for Azure DevOps PAT."""
        import base64

        auth_string = base64.b64encode(f":{self.token}".encode()).decode()
        return {"Authorization": f"Basic {auth_string}"}

    def create_work_item(self, action: Mapping[str, Any]) -> ConnectorOutcome:
        """Create an Azure DevOps work item via POST /{org}/{project}/_apis/wit/workitems/${type}."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "azure devops connector not fully configured"}
            )

        org = action.get("organization") or self.organization
        project = action.get("project") or self.project
        work_item_type = action.get("work_item_type") or self.default_work_item_type

        # Azure DevOps uses JSON Patch format for work item creation
        operations = [
            {
                "op": "add",
                "path": "/fields/System.Title",
                "value": action.get("title")
                or action.get("summary")
                or "FixOps automation work item",
            }
        ]

        if action.get("description"):
            operations.append(
                {
                    "op": "add",
                    "path": "/fields/System.Description",
                    "value": action["description"],
                }
            )
        if action.get("priority"):
            operations.append(
                {
                    "op": "add",
                    "path": "/fields/Microsoft.VSTS.Common.Priority",
                    "value": action["priority"],
                }
            )
        if action.get("severity"):
            operations.append(
                {
                    "op": "add",
                    "path": "/fields/Microsoft.VSTS.Common.Severity",
                    "value": action["severity"],
                }
            )
        if action.get("assigned_to"):
            operations.append(
                {
                    "op": "add",
                    "path": "/fields/System.AssignedTo",
                    "value": action["assigned_to"],
                }
            )
        if action.get("area_path"):
            operations.append(
                {
                    "op": "add",
                    "path": "/fields/System.AreaPath",
                    "value": action["area_path"],
                }
            )
        if action.get("iteration_path"):
            operations.append(
                {
                    "op": "add",
                    "path": "/fields/System.IterationPath",
                    "value": action["iteration_path"],
                }
            )

        endpoint = f"{self.base_url}/{org}/{project}/_apis/wit/workitems/${work_item_type}?api-version=7.0"

        try:
            headers = self._get_auth_header()
            headers["Content-Type"] = "application/json-patch+json"
            response = self._request(
                "POST",
                endpoint,
                json=operations,
                headers=headers,
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "azure devops work item creation failed",
                    "error": type(exc).__name__,
                    "endpoint": endpoint,
                },
            )

        body: Dict[str, Any]
        try:
            body = response.json()
        except ValueError:
            body = {}

        return ConnectorOutcome(
            "sent",
            {
                "endpoint": endpoint,
                "work_item_id": body.get("id"),
                "url": body.get("url"),
                "operation": "create_work_item",
            },
        )

    def update_work_item(self, action: Mapping[str, Any]) -> ConnectorOutcome:
        """Update an Azure DevOps work item via PATCH /{org}/{project}/_apis/wit/workitems/{id}."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "azure devops connector not fully configured"}
            )

        org = action.get("organization") or self.organization
        project = action.get("project") or self.project
        work_item_id = action.get("work_item_id") or action.get("id")

        if not work_item_id:
            return ConnectorOutcome(
                "failed", {"reason": "work_item_id is required for update"}
            )

        operations = []
        if action.get("title"):
            operations.append(
                {
                    "op": "replace",
                    "path": "/fields/System.Title",
                    "value": action["title"],
                }
            )
        if action.get("description"):
            operations.append(
                {
                    "op": "replace",
                    "path": "/fields/System.Description",
                    "value": action["description"],
                }
            )
        if action.get("state"):
            operations.append(
                {
                    "op": "replace",
                    "path": "/fields/System.State",
                    "value": action["state"],
                }
            )
        if action.get("priority"):
            operations.append(
                {
                    "op": "replace",
                    "path": "/fields/Microsoft.VSTS.Common.Priority",
                    "value": action["priority"],
                }
            )
        if action.get("assigned_to"):
            operations.append(
                {
                    "op": "replace",
                    "path": "/fields/System.AssignedTo",
                    "value": action["assigned_to"],
                }
            )

        if not operations:
            return ConnectorOutcome("skipped", {"reason": "no fields to update"})

        endpoint = f"{self.base_url}/{org}/{project}/_apis/wit/workitems/{work_item_id}?api-version=7.0"

        try:
            headers = self._get_auth_header()
            headers["Content-Type"] = "application/json-patch+json"
            response = self._request(
                "PATCH",
                endpoint,
                json=operations,
                headers=headers,
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "azure devops work item update failed",
                    "error": type(exc).__name__,
                    "endpoint": endpoint,
                },
            )

        return ConnectorOutcome(
            "sent",
            {
                "endpoint": endpoint,
                "work_item_id": work_item_id,
                "operation": "update_work_item",
            },
        )

    def add_comment(self, action: Mapping[str, Any]) -> ConnectorOutcome:
        """Add a comment to an Azure DevOps work item via POST /{org}/{project}/_apis/wit/workitems/{id}/comments."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "azure devops connector not fully configured"}
            )

        org = action.get("organization") or self.organization
        project = action.get("project") or self.project
        work_item_id = action.get("work_item_id") or action.get("id")
        comment_text = action.get("comment") or action.get("body") or action.get("text")

        if not work_item_id:
            return ConnectorOutcome(
                "failed", {"reason": "work_item_id is required for comment"}
            )

        if not comment_text:
            return ConnectorOutcome("failed", {"reason": "comment text is required"})

        payload = {"text": comment_text}
        endpoint = f"{self.base_url}/{org}/{project}/_apis/wit/workitems/{work_item_id}/comments?api-version=7.0-preview.3"

        try:
            headers = self._get_auth_header()
            headers["Content-Type"] = "application/json"
            response = self._request(
                "POST",
                endpoint,
                json=payload,
                headers=headers,
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "azure devops comment failed",
                    "error": type(exc).__name__,
                    "endpoint": endpoint,
                },
            )

        body: Dict[str, Any]
        try:
            body = response.json()
        except ValueError:
            body = {}

        return ConnectorOutcome(
            "sent",
            {
                "endpoint": endpoint,
                "work_item_id": work_item_id,
                "comment_id": body.get("id"),
                "operation": "add_comment",
            },
        )

    def get_work_item(self, work_item_id: int) -> ConnectorOutcome:
        """Fetch a single Azure DevOps work item by ID (Agent READ operation)."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "azure devops connector not fully configured"}
            )

        endpoint = f"{self.base_url}/{self.organization}/{self.project}/_apis/wit/workitems/{work_item_id}?api-version=7.0"

        try:
            response = self._request(
                "GET",
                endpoint,
                headers=self._get_auth_header(),
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "azure devops fetch failed",
                    "error": type(exc).__name__,
                    "endpoint": endpoint,
                },
            )

        try:
            data = response.json()
        except ValueError:
            data = {}

        return ConnectorOutcome(
            "fetched",
            {
                "endpoint": endpoint,
                "work_item_id": data.get("id"),
                "data": data,
                "operation": "get_work_item",
            },
        )

    def search_work_items(self, wiql: str, max_results: int = 50) -> ConnectorOutcome:
        """Search Azure DevOps work items using WIQL (Agent READ operation)."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "azure devops connector not fully configured"}
            )

        endpoint = f"{self.base_url}/{self.organization}/{self.project}/_apis/wit/wiql?api-version=7.0&$top={max_results}"
        payload = {"query": wiql}

        try:
            headers = self._get_auth_header()
            headers["Content-Type"] = "application/json"
            response = self._request(
                "POST",
                endpoint,
                json=payload,
                headers=headers,
            )
            response.raise_for_status()
        except RequestException as exc:
            logger.debug("Azure DevOps search failed: %s", exc)
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "azure devops search failed",
                    "error": type(exc).__name__,
                    "endpoint": endpoint,
                },
            )

        try:
            data = response.json()
        except ValueError:
            data = {}

        work_items = data.get("workItems", [])
        return ConnectorOutcome(
            "fetched",
            {
                "endpoint": endpoint,
                "work_items": work_items,
                "count": len(work_items),
                "data": data,
                "operation": "search_work_items",
            },
        )

    @staticmethod
    def _sanitize_wiql_value(value: str) -> str:
        """Sanitize a value for safe WIQL interpolation.

        WIQL uses single quotes for string literals. Escape single quotes
        and strip control characters to prevent WIQL injection.
        """
        # Strip control characters (newlines, tabs, etc.)
        sanitized = "".join(c for c in value if c.isprintable())
        # Escape single quotes (WIQL string delimiter)
        sanitized = sanitized.replace("'", "''")
        # Limit length to prevent abuse
        return sanitized[:256]

    def list_work_items(
        self,
        work_item_type: Optional[str] = None,
        state: Optional[str] = None,
        max_results: int = 50,
    ) -> ConnectorOutcome:
        """List Azure DevOps work items with optional filters (Agent READ operation)."""
        safe_project = self._sanitize_wiql_value(self.project)
        conditions = [f"[System.TeamProject] = '{safe_project}'"]
        if work_item_type:
            safe_type = self._sanitize_wiql_value(work_item_type)
            conditions.append(f"[System.WorkItemType] = '{safe_type}'")
        if state:
            safe_state = self._sanitize_wiql_value(state)
            conditions.append(f"[System.State] = '{safe_state}'")
        wiql = f"SELECT [System.Id], [System.Title], [System.State] FROM WorkItems WHERE {' AND '.join(conditions)} ORDER BY [System.ChangedDate] DESC"  # nosec B608 — WIQL (not SQL), values sanitized by _sanitize_wiql_value
        return self.search_work_items(wiql, max_results=max_results)

    def health_check(self) -> ConnectorHealth:
        """Check Azure DevOps connectivity and authentication."""
        if not self.configured:
            return ConnectorHealth(
                healthy=False, latency_ms=0, message="Connector not configured"
            )

        start_time = time.time()
        endpoint = f"{self.base_url}/{self.organization}/_apis/projects/{self.project}?api-version=7.0"

        try:
            response = self._request(
                "GET",
                endpoint,
                headers=self._get_auth_header(),
            )
            latency_ms = (time.time() - start_time) * 1000

            if response.status_code == 200:
                return ConnectorHealth(
                    healthy=True,
                    latency_ms=latency_ms,
                    message="Connected successfully",
                )
            return ConnectorHealth(
                healthy=False,
                latency_ms=latency_ms,
                message=f"HTTP {response.status_code}: {response.text[:100]}",
            )
        except RequestException as exc:
            latency_ms = (time.time() - start_time) * 1000
            return ConnectorHealth(
                healthy=False,
                latency_ms=latency_ms,
                message=f"Connection failed: {exc}",
            )


class GitHubConnector(_BaseConnector):
    """Create and manage GitHub issues via REST API."""

    def __init__(self, settings: Mapping[str, Any]):
        super().__init__(timeout=float(settings.get("timeout", 10.0) or 10.0))
        self.base_url = str(
            settings.get("base_url") or "https://api.github.com"
        ).rstrip("/")
        self.owner = settings.get("owner") or settings.get("org")
        self.repo = settings.get("repo") or settings.get("repository")
        token = settings.get("token")
        token_env = settings.get("token_env")
        if token_env:
            token_env_value = os.getenv(str(token_env))
            if token_env_value:
                token = token_env_value
        self.token = token

    @property
    def configured(self) -> bool:
        return bool(self.owner and self.repo and self.token)

    def create_issue(self, action: Mapping[str, Any]) -> ConnectorOutcome:
        """Create a GitHub issue via POST /repos/{owner}/{repo}/issues."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "github connector not fully configured"}
            )

        owner = action.get("owner") or self.owner
        repo = action.get("repo") or self.repo

        payload: Dict[str, Any] = {
            "title": action.get("title")
            or action.get("summary")
            or "FixOps automation issue",
        }

        if action.get("body") or action.get("description"):
            payload["body"] = action.get("body") or action.get("description")
        if action.get("labels"):
            payload["labels"] = action["labels"]
        if action.get("assignees"):
            payload["assignees"] = action["assignees"]
        if action.get("milestone"):
            payload["milestone"] = action["milestone"]

        endpoint = f"{self.base_url}/repos/{owner}/{repo}/issues"

        try:
            response = self._request(
                "POST",
                endpoint,
                json=payload,
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "github issue creation failed",
                    "error": type(exc).__name__,
                    "endpoint": endpoint,
                },
            )

        body: Dict[str, Any]
        try:
            body = response.json()
        except ValueError:
            body = {}

        return ConnectorOutcome(
            "sent",
            {
                "endpoint": endpoint,
                "issue_number": body.get("number"),
                "issue_id": body.get("id"),
                "html_url": body.get("html_url"),
                "operation": "create_issue",
            },
        )

    def update_issue(self, action: Mapping[str, Any]) -> ConnectorOutcome:
        """Update a GitHub issue via PATCH /repos/{owner}/{repo}/issues/{issue_number}."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "github connector not fully configured"}
            )

        owner = action.get("owner") or self.owner
        repo = action.get("repo") or self.repo
        issue_number = action.get("issue_number") or action.get("issue_id")

        if not issue_number:
            return ConnectorOutcome(
                "failed", {"reason": "issue_number is required for update"}
            )

        payload: Dict[str, Any] = {}
        if action.get("title"):
            payload["title"] = action["title"]
        if action.get("body"):
            payload["body"] = action["body"]
        if action.get("state"):
            payload["state"] = action["state"]
        if action.get("labels"):
            payload["labels"] = action["labels"]
        if action.get("assignees"):
            payload["assignees"] = action["assignees"]
        if action.get("milestone"):
            payload["milestone"] = action["milestone"]

        if not payload:
            return ConnectorOutcome("skipped", {"reason": "no fields to update"})

        endpoint = f"{self.base_url}/repos/{owner}/{repo}/issues/{issue_number}"

        try:
            response = self._request(
                "PATCH",
                endpoint,
                json=payload,
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "github issue update failed",
                    "error": type(exc).__name__,
                    "endpoint": endpoint,
                },
            )

        return ConnectorOutcome(
            "sent",
            {
                "endpoint": endpoint,
                "issue_number": issue_number,
                "operation": "update_issue",
            },
        )

    def add_comment(self, action: Mapping[str, Any]) -> ConnectorOutcome:
        """Add a comment to a GitHub issue via POST /repos/{owner}/{repo}/issues/{issue_number}/comments."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "github connector not fully configured"}
            )

        owner = action.get("owner") or self.owner
        repo = action.get("repo") or self.repo
        issue_number = action.get("issue_number") or action.get("issue_id")
        comment_body = action.get("comment") or action.get("body")

        if not issue_number:
            return ConnectorOutcome(
                "failed", {"reason": "issue_number is required for comment"}
            )

        if not comment_body:
            return ConnectorOutcome("failed", {"reason": "comment body is required"})

        payload = {"body": comment_body}
        endpoint = (
            f"{self.base_url}/repos/{owner}/{repo}/issues/{issue_number}/comments"
        )

        try:
            response = self._request(
                "POST",
                endpoint,
                json=payload,
                headers={
                    "Authorization": f"Bearer {self.token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "github comment failed",
                    "error": type(exc).__name__,
                    "endpoint": endpoint,
                },
            )

        body: Dict[str, Any]
        try:
            body = response.json()
        except ValueError:
            body = {}

        return ConnectorOutcome(
            "sent",
            {
                "endpoint": endpoint,
                "issue_number": issue_number,
                "comment_id": body.get("id"),
                "html_url": body.get("html_url"),
                "operation": "add_comment",
            },
        )

    def _get_headers(self) -> Dict[str, str]:
        """Get standard GitHub API headers."""
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def get_issue(
        self, issue_number: int, owner: Optional[str] = None, repo: Optional[str] = None
    ) -> ConnectorOutcome:
        """Fetch a single GitHub issue by number (Agent READ operation)."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "github connector not fully configured"}
            )

        o = owner or self.owner
        r = repo or self.repo
        endpoint = f"{self.base_url}/repos/{o}/{r}/issues/{issue_number}"

        try:
            response = self._request(
                "GET",
                endpoint,
                headers=self._get_headers(),
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "github fetch failed",
                    "error": type(exc).__name__,
                    "endpoint": endpoint,
                },
            )

        try:
            data = response.json()
        except ValueError:
            data = {}

        return ConnectorOutcome(
            "fetched",
            {
                "endpoint": endpoint,
                "issue_number": data.get("number"),
                "html_url": data.get("html_url"),
                "data": data,
                "operation": "get_issue",
            },
        )

    def search_issues(
        self,
        state: str = "open",
        labels: Optional[str] = None,
        max_results: int = 50,
        exclude_pull_requests: bool = True,
    ) -> ConnectorOutcome:
        """Search GitHub issues (Agent READ operation).

        Args:
            state: Filter by issue state ('open', 'closed', 'all')
            labels: Comma-separated list of label names to filter by
            max_results: Maximum number of results to return
            exclude_pull_requests: If True, filter out pull requests from results
        """
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "github connector not fully configured"}
            )

        endpoint = f"{self.base_url}/repos/{self.owner}/{self.repo}/issues"
        params: Dict[str, str] = {"state": state, "per_page": str(max_results)}
        if labels:
            params["labels"] = labels

        try:
            response = self._request(
                "GET",
                endpoint,
                params=params,
                headers=self._get_headers(),
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "github search failed",
                    "error": type(exc).__name__,
                    "endpoint": endpoint,
                },
            )

        try:
            data = response.json()
        except ValueError:
            data = []

        issues = (
            [i for i in data if "pull_request" not in i]
            if exclude_pull_requests
            else data
        )
        return ConnectorOutcome(
            "fetched",
            {
                "endpoint": endpoint,
                "issues": issues,
                "count": len(issues),
                "operation": "search_issues",
            },
        )

    def list_issues(
        self, state: str = "open", max_results: int = 50
    ) -> ConnectorOutcome:
        """List GitHub issues with optional state filter (Agent READ operation)."""
        return self.search_issues(state=state, max_results=max_results)

    def get_comments(
        self, issue_number: int, max_results: int = 50
    ) -> ConnectorOutcome:
        """Fetch comments for a GitHub issue (Agent READ operation)."""
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "github connector not fully configured"}
            )

        endpoint = f"{self.base_url}/repos/{self.owner}/{self.repo}/issues/{issue_number}/comments"
        params = {"per_page": str(max_results)}

        try:
            response = self._request(
                "GET",
                endpoint,
                params=params,
                headers=self._get_headers(),
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "github comments fetch failed",
                    "error": type(exc).__name__,
                    "endpoint": endpoint,
                },
            )

        try:
            data = response.json()
        except ValueError:
            data = []

        return ConnectorOutcome(
            "fetched",
            {
                "endpoint": endpoint,
                "issue_number": issue_number,
                "comments": data,
                "count": len(data),
                "operation": "get_comments",
            },
        )

    def create_check_run(
        self,
        head_sha: str,
        name: str = "ALdeci Security Gate",
        status: str = "completed",
        conclusion: str = "success",
        title: Optional[str] = None,
        summary: Optional[str] = None,
        annotations: Optional[List[Dict[str, Any]]] = None,
        owner: Optional[str] = None,
        repo: Optional[str] = None,
    ) -> ConnectorOutcome:
        """Create a GitHub Check Run for CI/CD gate integration.

        POST /repos/{owner}/{repo}/check-runs
        Requires the `checks:write` permission on the GitHub App or PAT.

        Args:
            head_sha: The SHA of the commit to associate the check run with.
            name: The name of the check (e.g. 'ALdeci Security Gate').
            status: queued | in_progress | completed
            conclusion: action_required | cancelled | failure | neutral | success | skipped | timed_out
            title: Title shown in check run output.
            summary: Markdown summary for the check run details.
            annotations: List of file-level annotations (path, start_line, end_line, annotation_level, message).
        """
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "github connector not fully configured"}
            )

        o = owner or self.owner
        r = repo or self.repo
        endpoint = f"{self.base_url}/repos/{o}/{r}/check-runs"

        output: Dict[str, Any] = {
            "title": title or name,
            "summary": summary or "ALdeci security analysis complete.",
        }
        if annotations:
            # GitHub API limits to 50 annotations per request
            output["annotations"] = annotations[:50]

        payload: Dict[str, Any] = {
            "name": name,
            "head_sha": head_sha,
            "status": status,
            "output": output,
        }
        if status == "completed":
            payload["conclusion"] = conclusion

        try:
            response = self._request(
                "POST",
                endpoint,
                json=payload,
                headers=self._get_headers(),
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "github check run creation failed",
                    "error": type(exc).__name__,
                    "endpoint": endpoint,
                },
            )

        try:
            body = response.json()
        except ValueError:
            body = {}

        return ConnectorOutcome(
            "sent",
            {
                "endpoint": endpoint,
                "check_run_id": body.get("id"),
                "html_url": body.get("html_url"),
                "conclusion": conclusion,
                "operation": "create_check_run",
            },
        )

    def list_code_scanning_alerts(
        self,
        state: str = "open",
        severity: Optional[str] = None,
        max_results: int = 50,
        owner: Optional[str] = None,
        repo: Optional[str] = None,
    ) -> ConnectorOutcome:
        """List code scanning alerts for a repository.

        GET /repos/{owner}/{repo}/code-scanning/alerts
        Requires `security_events` scope.
        """
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "github connector not fully configured"}
            )

        o = owner or self.owner
        r = repo or self.repo
        endpoint = f"{self.base_url}/repos/{o}/{r}/code-scanning/alerts"
        params: Dict[str, str] = {
            "state": state,
            "per_page": str(max_results),
        }
        if severity:
            params["severity"] = severity

        try:
            response = self._request(
                "GET", endpoint, params=params, headers=self._get_headers()
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "github code scanning fetch failed",
                    "error": type(exc).__name__,
                    "endpoint": endpoint,
                },
            )

        try:
            data = response.json()
        except ValueError:
            data = []

        return ConnectorOutcome(
            "fetched",
            {
                "endpoint": endpoint,
                "alerts": data,
                "count": len(data),
                "operation": "list_code_scanning_alerts",
            },
        )

    def dismiss_code_scanning_alert(
        self,
        alert_number: int,
        dismissed_reason: str = "used in tests",
        owner: Optional[str] = None,
        repo: Optional[str] = None,
    ) -> ConnectorOutcome:
        """Dismiss (close) a code scanning alert.

        PATCH /repos/{owner}/{repo}/code-scanning/alerts/{alert_number}
        dismissed_reason: false positive | won't fix | used in tests
        """
        if not self.configured:
            return ConnectorOutcome(
                "skipped", {"reason": "github connector not fully configured"}
            )

        o = owner or self.owner
        r = repo or self.repo
        endpoint = f"{self.base_url}/repos/{o}/{r}/code-scanning/alerts/{alert_number}"
        payload = {
            "state": "dismissed",
            "dismissed_reason": dismissed_reason,
        }

        try:
            response = self._request(
                "PATCH", endpoint, json=payload, headers=self._get_headers()
            )
            response.raise_for_status()
        except RequestException as exc:
            return ConnectorOutcome(
                "failed",
                {
                    "reason": "github alert dismissal failed",
                    "error": type(exc).__name__,
                    "endpoint": endpoint,
                },
            )

        return ConnectorOutcome(
            "sent",
            {
                "endpoint": endpoint,
                "alert_number": alert_number,
                "dismissed_reason": dismissed_reason,
                "operation": "dismiss_code_scanning_alert",
            },
        )

    def health_check(self) -> ConnectorHealth:
        """Check GitHub connectivity and authentication."""
        if not self.configured:
            return ConnectorHealth(
                healthy=False, latency_ms=0, message="Connector not configured"
            )

        start_time = time.time()
        endpoint = f"{self.base_url}/user"

        try:
            response = self._request(
                "GET",
                endpoint,
                headers=self._get_headers(),
            )
            latency_ms = (time.time() - start_time) * 1000

            if response.status_code == 200:
                return ConnectorHealth(
                    healthy=True,
                    latency_ms=latency_ms,
                    message="Connected successfully",
                )
            return ConnectorHealth(
                healthy=False,
                latency_ms=latency_ms,
                message=f"HTTP {response.status_code}: {response.text[:100]}",
            )
        except RequestException as exc:
            latency_ms = (time.time() - start_time) * 1000
            return ConnectorHealth(
                healthy=False,
                latency_ms=latency_ms,
                message=f"Connection failed: {exc}",
            )


class AutomationConnectors:
    """Registry that routes actions to configured delivery connectors."""

    def __init__(
        self,
        overlay_settings: Mapping[str, Any],
        toggles: Mapping[str, Any],
        flag_provider: Any = None,
    ):
        self.enforce_sync = bool(toggles.get("enforce_ticket_sync", True))
        self.flag_provider = flag_provider
        self.jira = JiraConnector(overlay_settings.get("jira", {}))
        self.confluence = ConfluenceConnector(overlay_settings.get("confluence", {}))
        slack_settings = overlay_settings.get("policy_automation", {})
        self.slack = SlackConnector(slack_settings)
        self.servicenow = ServiceNowConnector(overlay_settings.get("servicenow", {}))
        self.gitlab = GitLabConnector(overlay_settings.get("gitlab", {}))
        self.azure_devops = AzureDevOpsConnector(
            overlay_settings.get("azure_devops", {})
        )
        self.github = GitHubConnector(overlay_settings.get("github", {}))

    def _check_feature_flag(self, flag_name: str, default: bool = True) -> bool:
        if self.flag_provider:
            try:
                return self.flag_provider.bool(flag_name, default)
            except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
                pass
        return default

    def deliver(self, action: Mapping[str, Any]) -> ConnectorOutcome:
        action_type = str(action.get("type") or "").lower()
        operation = str(action.get("operation") or "").lower()

        if action_type == "jira_issue" or action_type == "jira":
            if not self._check_feature_flag("fixops.feature.connector.jira"):
                return ConnectorOutcome(
                    "skipped", {"reason": "jira connector disabled"}
                )
            if not self.enforce_sync and not action.get("force_delivery"):
                return ConnectorOutcome("skipped", {"reason": "ticket sync disabled"})
            if operation == "update":
                return self.jira.update_issue(action)
            if operation == "transition":
                return self.jira.transition_issue(action)
            if operation == "comment":
                return self.jira.add_comment(action)
            if operation == "bulk_search":
                return self.jira.bulk_search(
                    jql=str(action.get("jql", "")),
                    fields=action.get("fields"),
                    max_results=int(action.get("max_results", 500)),
                    page_size=int(action.get("page_size", 50)),
                )
            if operation == "create_with_custom_fields":
                return self.jira.create_issue_with_custom_fields(
                    action, custom_fields=action.get("custom_fields")
                )
            if operation == "assign_sprint":
                return self.jira.assign_to_sprint(
                    issue_key=str(action.get("issue_key", "")),
                    sprint_id=int(action.get("sprint_id", 0)),
                )
            return self.jira.create_issue(action)

        if action_type == "confluence_page" or action_type == "confluence":
            if not self._check_feature_flag("fixops.feature.connector.confluence"):
                return ConnectorOutcome(
                    "skipped", {"reason": "confluence connector disabled"}
                )
            if not self.enforce_sync and not action.get("force_delivery"):
                return ConnectorOutcome(
                    "skipped", {"reason": "knowledge sync disabled"}
                )
            return self.confluence.create_page(action)

        if action_type == "slack":
            if not self._check_feature_flag("fixops.feature.connector.slack"):
                return ConnectorOutcome(
                    "skipped", {"reason": "slack connector disabled"}
                )
            if operation == "post_blocks" or operation == "block_kit":
                return self.slack.post_blocks(action)
            if operation == "post_interactive" or operation == "interactive":
                return self.slack.post_interactive(action)
            if operation == "list_channels":
                bot_token = str(action.get("bot_token", ""))
                return self.slack.list_channels(
                    bot_token=bot_token,
                    types=str(action.get("channel_types", "public_channel")),
                    limit=int(action.get("limit", 200)),
                )
            return self.slack.post_message(action)

        if action_type == "servicenow_incident" or action_type == "servicenow":
            if not self._check_feature_flag("fixops.feature.connector.servicenow"):
                return ConnectorOutcome(
                    "skipped", {"reason": "servicenow connector disabled"}
                )
            if not self.enforce_sync and not action.get("force_delivery"):
                return ConnectorOutcome("skipped", {"reason": "ticket sync disabled"})
            if operation == "update":
                return self.servicenow.update_incident(action)
            if operation == "work_note" or operation == "comment":
                return self.servicenow.add_work_note(action)
            return self.servicenow.create_incident(action)

        if action_type == "gitlab_issue" or action_type == "gitlab":
            if not self._check_feature_flag("fixops.feature.connector.gitlab"):
                return ConnectorOutcome(
                    "skipped", {"reason": "gitlab connector disabled"}
                )
            if not self.enforce_sync and not action.get("force_delivery"):
                return ConnectorOutcome("skipped", {"reason": "ticket sync disabled"})
            if operation == "update":
                return self.gitlab.update_issue(action)
            if operation == "comment":
                return self.gitlab.add_comment(action)
            return self.gitlab.create_issue(action)

        if action_type == "azure_devops_work_item" or action_type == "azure_devops":
            if not self._check_feature_flag("fixops.feature.connector.azure_devops"):
                return ConnectorOutcome(
                    "skipped", {"reason": "azure devops connector disabled"}
                )
            if not self.enforce_sync and not action.get("force_delivery"):
                return ConnectorOutcome("skipped", {"reason": "ticket sync disabled"})
            if operation == "update":
                return self.azure_devops.update_work_item(action)
            if operation == "comment":
                return self.azure_devops.add_comment(action)
            return self.azure_devops.create_work_item(action)

        if action_type == "github_issue" or action_type == "github":
            if not self._check_feature_flag("fixops.feature.connector.github"):
                return ConnectorOutcome(
                    "skipped", {"reason": "github connector disabled"}
                )
            if not self.enforce_sync and not action.get("force_delivery"):
                return ConnectorOutcome("skipped", {"reason": "ticket sync disabled"})
            if operation == "update":
                return self.github.update_issue(action)
            if operation == "comment":
                return self.github.add_comment(action)
            if operation == "check_run" or operation == "create_check_run":
                return self.github.create_check_run(
                    head_sha=str(action.get("head_sha", "")),
                    name=str(action.get("name", "ALdeci Security Gate")),
                    status=str(action.get("status", "completed")),
                    conclusion=str(action.get("conclusion", "success")),
                    title=action.get("title"),
                    summary=action.get("summary"),
                    annotations=action.get("annotations"),
                    owner=action.get("owner"),
                    repo=action.get("repo"),
                )
            if operation == "list_code_scanning_alerts":
                return self.github.list_code_scanning_alerts(
                    state=str(action.get("state", "open")),
                    severity=action.get("severity"),
                    max_results=int(action.get("max_results", 50)),
                    owner=action.get("owner"),
                    repo=action.get("repo"),
                )
            if operation == "dismiss_code_scanning_alert":
                return self.github.dismiss_code_scanning_alert(
                    alert_number=int(action.get("alert_number", 0)),
                    dismissed_reason=str(action.get("dismissed_reason", "used in tests")),
                    owner=action.get("owner"),
                    repo=action.get("repo"),
                )
            return self.github.create_issue(action)

        return ConnectorOutcome(
            "skipped",
            {"reason": f"no connector registered for action type '{action_type}'"},
        )


def summarise_connector(connector: _BaseConnector) -> Dict[str, Any]:
    """Return non-sensitive configuration state for diagnostics."""

    if isinstance(connector, JiraConnector):
        return {
            "configured": connector.configured,
            "project_key": connector.project_key,
            "url": connector.base_url,
            "user": connector.user,
            "token": _mask(str(connector.token) if connector.token else None),
        }
    if isinstance(connector, ConfluenceConnector):
        return {
            "configured": connector.configured,
            "space_key": connector.space_key,
            "url": connector.base_url,
            "user": connector.user,
            "token": _mask(str(connector.token) if connector.token else None),
        }
    if isinstance(connector, SlackConnector):
        return {
            "configured": bool(connector.default_webhook),
            "webhook": _mask(connector.default_webhook),
        }
    if isinstance(connector, ServiceNowConnector):
        return {
            "configured": connector.configured,
            "instance_url": connector.instance_url,
            "user": connector.user,
            "token": _mask(str(connector.token) if connector.token else None),
        }
    if isinstance(connector, GitLabConnector):
        return {
            "configured": connector.configured,
            "base_url": connector.base_url,
            "project_id": connector.project_id,
            "token": _mask(str(connector.token) if connector.token else None),
        }
    if isinstance(connector, AzureDevOpsConnector):
        return {
            "configured": connector.configured,
            "base_url": connector.base_url,
            "organization": connector.organization,
            "project": connector.project,
            "token": _mask(str(connector.token) if connector.token else None),
        }
    if isinstance(connector, GitHubConnector):
        return {
            "configured": connector.configured,
            "base_url": connector.base_url,
            "owner": connector.owner,
            "repo": connector.repo,
            "token": _mask(str(connector.token) if connector.token else None),
        }
    return {"configured": False}


__all__ = [
    "AutomationConnectors",
    "ConnectorOutcome",
    "summarise_connector",
]
