"""Comprehensive tests for enterprise-grade connectors.

Tests cover:
- CircuitBreaker pattern (CLOSED/OPEN/HALF_OPEN states)
- RateLimiter (token bucket algorithm)
- ConnectorOutcome and ConnectorHealth dataclasses
- _BaseConnector reliability features
- All connector READ operations for agent-based data collection
- Health checks for all connectors
"""

import json
import time
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest
from requests import RequestException

from core.connectors import (
    AutomationConnectors,
    AzureDevOpsConnector,
    CircuitBreaker,
    CircuitState,
    ConfluenceConnector,
    ConnectorHealth,
    ConnectorOutcome,
    GitHubConnector,
    GitLabConnector,
    JiraConnector,
    RateLimiter,
    ServiceNowConnector,
    SlackConnector,
    _BaseConnector,
    _mask,
)


class MockResponse:
    """Mock HTTP response for testing."""

    def __init__(
        self,
        status_code: int = 200,
        json_data: Dict[str, Any] | None = None,
        text: str = "",
        raise_on_json: bool = False,
    ):
        self.status_code = status_code
        self._json_data = json_data or {}
        self.text = text or json.dumps(self._json_data)
        self._raise_on_json = raise_on_json

    def json(self) -> Dict[str, Any]:
        if self._raise_on_json:
            raise ValueError("Invalid JSON")
        return self._json_data

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise RequestException(f"HTTP {self.status_code}")


class TestMaskFunction:
    """Tests for the _mask utility function."""

    def test_mask_none(self) -> None:
        assert _mask(None) is None

    def test_mask_empty(self) -> None:
        assert _mask("") == ""

    def test_mask_short(self) -> None:
        assert _mask("abc") == "***"
        assert _mask("ab") == "**"

    def test_mask_long(self) -> None:
        result = _mask("secret-token")
        assert result == "se***en"


class TestCircuitBreaker:
    """Tests for CircuitBreaker pattern."""

    def test_initial_state_is_closed(self) -> None:
        cb = CircuitBreaker()
        assert cb.state == CircuitState.CLOSED
        assert cb.allow_request() is True

    def test_record_success_in_closed_state(self) -> None:
        cb = CircuitBreaker()
        cb._failure_count = 3
        cb.record_success()
        assert cb._failure_count == 0

    def test_record_failure_opens_circuit(self) -> None:
        cb = CircuitBreaker(failure_threshold=3)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.CLOSED
        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        assert cb.allow_request() is False

    def test_circuit_transitions_to_half_open(self) -> None:
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=0.1)
        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        time.sleep(0.15)
        assert cb.state == CircuitState.HALF_OPEN
        assert cb.allow_request() is True

    def test_half_open_success_closes_circuit(self) -> None:
        cb = CircuitBreaker(
            failure_threshold=1, recovery_timeout=0.01, half_open_max_calls=2
        )
        cb.record_failure()
        time.sleep(0.02)
        assert cb.state == CircuitState.HALF_OPEN
        cb.record_success()
        assert cb._half_open_calls == 1
        cb.record_success()
        assert cb.state == CircuitState.CLOSED

    def test_half_open_failure_opens_circuit(self) -> None:
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=0.01)
        cb.record_failure()
        time.sleep(0.02)
        assert cb.state == CircuitState.HALF_OPEN
        cb.record_failure()
        assert cb.state == CircuitState.OPEN


class TestRateLimiter:
    """Tests for RateLimiter (token bucket)."""

    def test_initial_tokens(self) -> None:
        rl = RateLimiter(requests_per_second=10.0, burst_size=20)
        assert rl._tokens == 20.0

    def test_acquire_success(self) -> None:
        rl = RateLimiter(requests_per_second=100.0, burst_size=10)
        assert rl.acquire(timeout=1.0) is True

    def test_acquire_depletes_tokens(self) -> None:
        rl = RateLimiter(requests_per_second=1.0, burst_size=2)
        assert rl.acquire(timeout=0.1) is True
        assert rl.acquire(timeout=0.1) is True
        assert rl.acquire(timeout=0.1) is False

    def test_tokens_replenish(self) -> None:
        rl = RateLimiter(requests_per_second=100.0, burst_size=1)
        assert rl.acquire(timeout=0.1) is True
        time.sleep(0.02)
        assert rl.acquire(timeout=0.1) is True


class TestConnectorOutcome:
    """Tests for ConnectorOutcome dataclass."""

    def test_to_dict(self) -> None:
        outcome = ConnectorOutcome(status="sent", details={"key": "value"})
        result = outcome.to_dict()
        assert result["status"] == "sent"
        assert result["key"] == "value"

    def test_success_property(self) -> None:
        assert ConnectorOutcome("sent", {}).success is True
        assert ConnectorOutcome("success", {}).success is True
        assert ConnectorOutcome("fetched", {}).success is True
        assert ConnectorOutcome("failed", {}).success is False
        assert ConnectorOutcome("skipped", {}).success is False

    def test_data_property(self) -> None:
        outcome = ConnectorOutcome("fetched", {"data": {"id": 123}})
        assert outcome.data == {"id": 123}

    def test_data_property_missing(self) -> None:
        outcome = ConnectorOutcome("sent", {})
        assert outcome.data is None


class TestConnectorHealth:
    """Tests for ConnectorHealth dataclass."""

    def test_to_dict(self) -> None:
        health = ConnectorHealth(healthy=True, latency_ms=50.0, message="OK")
        result = health.to_dict()
        assert result["healthy"] is True
        assert result["latency_ms"] == 50.0
        assert result["message"] == "OK"
        assert "checked_at" in result


class TestBaseConnector:
    """Tests for _BaseConnector reliability features."""

    def test_get_metrics(self) -> None:
        connector = _BaseConnector()
        metrics = connector.get_metrics()
        assert metrics["request_count"] == 0
        assert metrics["error_count"] == 0
        assert metrics["circuit_state"] == "closed"
        assert metrics["error_rate"] == 0.0

    def test_health_check_not_implemented(self) -> None:
        connector = _BaseConnector()
        with pytest.raises(NotImplementedError):
            connector.health_check()

    def test_request_circuit_breaker_open(self) -> None:
        connector = _BaseConnector(circuit_breaker_threshold=1)
        connector._circuit_breaker.record_failure()
        with pytest.raises(RequestException, match="Circuit breaker is open"):
            connector._request("GET", "http://example.com")

    def test_request_rate_limit_exceeded(self) -> None:
        # Use very low rate limit so tokens don't replenish quickly
        connector = _BaseConnector(rate_limit=0.001)
        # Deplete all tokens
        connector._rate_limiter._tokens = 0.0
        # Override the rate limiter's acquire timeout by patching
        original_acquire = connector._rate_limiter.acquire
        connector._rate_limiter.acquire = lambda timeout=5.0: False
        with pytest.raises(RequestException, match="Rate limit exceeded"):
            connector._request("GET", "http://example.com")
        connector._rate_limiter.acquire = original_acquire

    @patch("requests.Session.request")
    def test_request_success(self, mock_request: MagicMock) -> None:
        mock_request.return_value = MockResponse(200, {"result": "ok"})
        connector = _BaseConnector()
        response = connector._request("GET", "http://example.com")
        assert response.status_code == 200
        assert connector._request_count == 1
        assert connector._error_count == 0

    @patch("requests.Session.request")
    def test_request_server_error(self, mock_request: MagicMock) -> None:
        mock_request.return_value = MockResponse(500, text="Server Error")
        connector = _BaseConnector()
        response = connector._request("GET", "http://example.com")
        assert response.status_code == 500
        assert connector._error_count == 1

    @patch("requests.Session.request")
    def test_request_exception(self, mock_request: MagicMock) -> None:
        mock_request.side_effect = RequestException("Connection failed")
        connector = _BaseConnector()
        with pytest.raises(RequestException):
            connector._request("GET", "http://example.com")
        assert connector._error_count == 1


class TestJiraConnector:
    """Tests for JiraConnector READ operations and health check."""

    @pytest.fixture
    def configured_jira(self) -> JiraConnector:
        return JiraConnector(
            {
                "url": "https://jira.example.com",
                "project_key": "TEST",
                "user_email": "user@example.com",
                "token": "test-token",
            }
        )

    @pytest.fixture
    def unconfigured_jira(self) -> JiraConnector:
        return JiraConnector({})

    def test_not_configured(self, unconfigured_jira: JiraConnector) -> None:
        assert unconfigured_jira.configured is False

    def test_configured(self, configured_jira: JiraConnector) -> None:
        assert configured_jira.configured is True

    def test_get_issue_not_configured(self, unconfigured_jira: JiraConnector) -> None:
        result = unconfigured_jira.get_issue("TEST-1")
        assert result.status == "skipped"

    @patch("requests.Session.request")
    def test_get_issue_success(
        self, mock_request: MagicMock, configured_jira: JiraConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, {"key": "TEST-1", "fields": {}})
        result = configured_jira.get_issue("TEST-1")
        assert result.status == "fetched"
        assert result.details["issue_key"] == "TEST-1"

    @patch("requests.Session.request")
    def test_get_issue_with_fields(
        self, mock_request: MagicMock, configured_jira: JiraConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, {"key": "TEST-1"})
        result = configured_jira.get_issue("TEST-1", fields=["summary", "status"])
        assert result.status == "fetched"

    @patch("requests.Session.request")
    def test_get_issue_failure(
        self, mock_request: MagicMock, configured_jira: JiraConnector
    ) -> None:
        mock_request.side_effect = RequestException("Connection failed")
        result = configured_jira.get_issue("TEST-1")
        assert result.status == "failed"

    @patch("requests.Session.request")
    def test_get_issue_invalid_json(
        self, mock_request: MagicMock, configured_jira: JiraConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, raise_on_json=True)
        result = configured_jira.get_issue("TEST-1")
        assert result.status == "fetched"

    def test_search_issues_not_configured(
        self, unconfigured_jira: JiraConnector
    ) -> None:
        result = unconfigured_jira.search_issues("project = TEST")
        assert result.status == "skipped"

    @patch("requests.Session.request")
    def test_search_issues_success(
        self, mock_request: MagicMock, configured_jira: JiraConnector
    ) -> None:
        mock_request.return_value = MockResponse(
            200, {"total": 5, "issues": [{"key": "TEST-1"}]}
        )
        result = configured_jira.search_issues("project = TEST")
        assert result.status == "fetched"
        assert result.details["total"] == 5

    @patch("requests.Session.request")
    def test_search_issues_with_fields(
        self, mock_request: MagicMock, configured_jira: JiraConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, {"total": 1, "issues": []})
        result = configured_jira.search_issues("project = TEST", fields=["summary"])
        assert result.status == "fetched"

    @patch("requests.Session.request")
    def test_search_issues_failure(
        self, mock_request: MagicMock, configured_jira: JiraConnector
    ) -> None:
        mock_request.side_effect = RequestException("Connection failed")
        result = configured_jira.search_issues("project = TEST")
        assert result.status == "failed"

    @patch("requests.Session.request")
    def test_search_issues_invalid_json(
        self, mock_request: MagicMock, configured_jira: JiraConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, raise_on_json=True)
        result = configured_jira.search_issues("project = TEST")
        assert result.status == "fetched"

    @patch("requests.Session.request")
    def test_list_project_issues(
        self, mock_request: MagicMock, configured_jira: JiraConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, {"total": 3, "issues": []})
        result = configured_jira.list_project_issues()
        assert result.status == "fetched"

    @patch("requests.Session.request")
    def test_list_project_issues_with_status(
        self, mock_request: MagicMock, configured_jira: JiraConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, {"total": 1, "issues": []})
        result = configured_jira.list_project_issues(status="Open")
        assert result.status == "fetched"

    def test_get_comments_not_configured(
        self, unconfigured_jira: JiraConnector
    ) -> None:
        result = unconfigured_jira.get_comments("TEST-1")
        assert result.status == "skipped"

    @patch("requests.Session.request")
    def test_get_comments_success(
        self, mock_request: MagicMock, configured_jira: JiraConnector
    ) -> None:
        mock_request.return_value = MockResponse(
            200, {"comments": [{"id": "1"}], "total": 1}
        )
        result = configured_jira.get_comments("TEST-1")
        assert result.status == "fetched"
        assert result.details["total"] == 1

    @patch("requests.Session.request")
    def test_get_comments_failure(
        self, mock_request: MagicMock, configured_jira: JiraConnector
    ) -> None:
        mock_request.side_effect = RequestException("Connection failed")
        result = configured_jira.get_comments("TEST-1")
        assert result.status == "failed"

    @patch("requests.Session.request")
    def test_get_comments_invalid_json(
        self, mock_request: MagicMock, configured_jira: JiraConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, raise_on_json=True)
        result = configured_jira.get_comments("TEST-1")
        assert result.status == "fetched"

    def test_health_check_not_configured(
        self, unconfigured_jira: JiraConnector
    ) -> None:
        result = unconfigured_jira.health_check()
        assert result.healthy is False
        assert "not configured" in result.message.lower()

    @patch("requests.Session.request")
    def test_health_check_success(
        self, mock_request: MagicMock, configured_jira: JiraConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, {"accountId": "123"})
        result = configured_jira.health_check()
        assert result.healthy is True

    @patch("requests.Session.request")
    def test_health_check_http_error(
        self, mock_request: MagicMock, configured_jira: JiraConnector
    ) -> None:
        mock_request.return_value = MockResponse(401, text="Unauthorized")
        result = configured_jira.health_check()
        assert result.healthy is False
        assert "401" in result.message

    @patch("requests.Session.request")
    def test_health_check_exception(
        self, mock_request: MagicMock, configured_jira: JiraConnector
    ) -> None:
        mock_request.side_effect = RequestException("Connection failed")
        result = configured_jira.health_check()
        assert result.healthy is False
        assert "Connection failed" in result.message

    def test_update_issue_not_configured(
        self, unconfigured_jira: JiraConnector
    ) -> None:
        result = unconfigured_jira.update_issue(
            {"issue_key": "TEST-1", "summary": "New"}
        )
        assert result.status == "skipped"

    def test_update_issue_no_key(self, configured_jira: JiraConnector) -> None:
        result = configured_jira.update_issue({"summary": "New"})
        assert result.status == "failed"
        assert "issue_key is required" in result.details["reason"]

    def test_update_issue_no_fields(self, configured_jira: JiraConnector) -> None:
        result = configured_jira.update_issue({"issue_key": "TEST-1"})
        assert result.status == "skipped"
        assert "no fields to update" in result.details["reason"]

    @patch("requests.Session.request")
    def test_update_issue_success(
        self, mock_request: MagicMock, configured_jira: JiraConnector
    ) -> None:
        mock_request.return_value = MockResponse(204)
        result = configured_jira.update_issue(
            {
                "issue_key": "TEST-1",
                "summary": "Updated",
                "description": "New desc",
                "priority": "High",
                "assignee": "user123",
                "labels": ["bug"],
            }
        )
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_update_issue_failure(
        self, mock_request: MagicMock, configured_jira: JiraConnector
    ) -> None:
        mock_request.side_effect = RequestException("Failed")
        result = configured_jira.update_issue({"issue_key": "TEST-1", "summary": "New"})
        assert result.status == "failed"

    def test_transition_issue_not_configured(
        self, unconfigured_jira: JiraConnector
    ) -> None:
        result = unconfigured_jira.transition_issue(
            {"issue_key": "TEST-1", "transition_id": "5"}
        )
        assert result.status == "skipped"

    def test_transition_issue_no_key(self, configured_jira: JiraConnector) -> None:
        result = configured_jira.transition_issue({"transition_id": "5"})
        assert result.status == "failed"
        assert "issue_key is required" in result.details["reason"]

    def test_transition_issue_no_transition(
        self, configured_jira: JiraConnector
    ) -> None:
        result = configured_jira.transition_issue({"issue_key": "TEST-1"})
        assert result.status == "failed"
        assert (
            "transition_id or transition_name is required" in result.details["reason"]
        )

    @patch("requests.Session.request")
    def test_transition_issue_by_id(
        self, mock_request: MagicMock, configured_jira: JiraConnector
    ) -> None:
        mock_request.return_value = MockResponse(204)
        result = configured_jira.transition_issue(
            {"issue_key": "TEST-1", "transition_id": "5"}
        )
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_transition_issue_by_name(
        self, mock_request: MagicMock, configured_jira: JiraConnector
    ) -> None:
        mock_request.side_effect = [
            MockResponse(200, {"transitions": [{"id": "5", "name": "Done"}]}),
            MockResponse(204),
        ]
        result = configured_jira.transition_issue(
            {"issue_key": "TEST-1", "transition_name": "Done"}
        )
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_transition_issue_name_not_found(
        self, mock_request: MagicMock, configured_jira: JiraConnector
    ) -> None:
        mock_request.return_value = MockResponse(
            200, {"transitions": [{"id": "5", "name": "Done"}]}
        )
        result = configured_jira.transition_issue(
            {"issue_key": "TEST-1", "transition_name": "Invalid"}
        )
        assert result.status == "failed"
        assert "not found" in result.details["reason"]

    @patch("requests.Session.request")
    def test_transition_issue_fetch_failure(
        self, mock_request: MagicMock, configured_jira: JiraConnector
    ) -> None:
        mock_request.side_effect = RequestException("Failed")
        result = configured_jira.transition_issue(
            {"issue_key": "TEST-1", "transition_name": "Done"}
        )
        assert result.status == "failed"

    @patch("requests.Session.request")
    def test_transition_issue_post_failure(
        self, mock_request: MagicMock, configured_jira: JiraConnector
    ) -> None:
        mock_request.side_effect = [
            MockResponse(200, {"transitions": [{"id": "5", "name": "Done"}]}),
            RequestException("Failed"),
        ]
        result = configured_jira.transition_issue(
            {"issue_key": "TEST-1", "transition_name": "Done"}
        )
        assert result.status == "failed"

    def test_add_comment_not_configured(self, unconfigured_jira: JiraConnector) -> None:
        result = unconfigured_jira.add_comment(
            {"issue_key": "TEST-1", "comment": "Test"}
        )
        assert result.status == "skipped"

    def test_add_comment_no_key(self, configured_jira: JiraConnector) -> None:
        result = configured_jira.add_comment({"comment": "Test"})
        assert result.status == "failed"
        assert "issue_key is required" in result.details["reason"]

    def test_add_comment_no_body(self, configured_jira: JiraConnector) -> None:
        result = configured_jira.add_comment({"issue_key": "TEST-1"})
        assert result.status == "failed"
        assert "comment body is required" in result.details["reason"]

    @patch("requests.Session.request")
    def test_add_comment_success(
        self, mock_request: MagicMock, configured_jira: JiraConnector
    ) -> None:
        mock_request.return_value = MockResponse(201, {"id": "12345"})
        result = configured_jira.add_comment(
            {"issue_key": "TEST-1", "comment": "Test comment"}
        )
        assert result.status == "sent"
        assert result.details["comment_id"] == "12345"

    @patch("requests.Session.request")
    def test_add_comment_with_body_key(
        self, mock_request: MagicMock, configured_jira: JiraConnector
    ) -> None:
        mock_request.return_value = MockResponse(201, {"id": "12345"})
        result = configured_jira.add_comment(
            {"issue_key": "TEST-1", "body": "Test comment"}
        )
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_add_comment_failure(
        self, mock_request: MagicMock, configured_jira: JiraConnector
    ) -> None:
        mock_request.side_effect = RequestException("Failed")
        result = configured_jira.add_comment({"issue_key": "TEST-1", "comment": "Test"})
        assert result.status == "failed"

    @patch("requests.Session.request")
    def test_add_comment_invalid_json(
        self, mock_request: MagicMock, configured_jira: JiraConnector
    ) -> None:
        mock_request.return_value = MockResponse(201, raise_on_json=True)
        result = configured_jira.add_comment({"issue_key": "TEST-1", "comment": "Test"})
        assert result.status == "sent"


class TestConfluenceConnector:
    """Tests for ConfluenceConnector READ operations and health check."""

    @pytest.fixture
    def configured_confluence(self) -> ConfluenceConnector:
        return ConfluenceConnector(
            {
                "base_url": "https://confluence.example.com",
                "space_key": "TEST",
                "user": "user@example.com",
                "token": "test-token",
            }
        )

    @pytest.fixture
    def unconfigured_confluence(self) -> ConfluenceConnector:
        return ConfluenceConnector({})

    def test_get_page_not_configured(
        self, unconfigured_confluence: ConfluenceConnector
    ) -> None:
        result = unconfigured_confluence.get_page("12345")
        assert result.status == "skipped"

    @patch("requests.Session.request")
    def test_get_page_success(
        self, mock_request: MagicMock, configured_confluence: ConfluenceConnector
    ) -> None:
        mock_request.return_value = MockResponse(
            200, {"id": "12345", "title": "Test Page"}
        )
        result = configured_confluence.get_page("12345")
        assert result.status == "fetched"
        assert result.details["page_id"] == "12345"

    @patch("requests.Session.request")
    def test_get_page_failure(
        self, mock_request: MagicMock, configured_confluence: ConfluenceConnector
    ) -> None:
        mock_request.side_effect = RequestException("Connection failed")
        result = configured_confluence.get_page("12345")
        assert result.status == "failed"

    @patch("requests.Session.request")
    def test_get_page_invalid_json(
        self, mock_request: MagicMock, configured_confluence: ConfluenceConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, raise_on_json=True)
        result = configured_confluence.get_page("12345")
        assert result.status == "fetched"

    def test_search_pages_not_configured(
        self, unconfigured_confluence: ConfluenceConnector
    ) -> None:
        result = unconfigured_confluence.search_pages("test query")
        assert result.status == "skipped"

    @patch("requests.Session.request")
    def test_search_pages_success(
        self, mock_request: MagicMock, configured_confluence: ConfluenceConnector
    ) -> None:
        mock_request.return_value = MockResponse(
            200, {"results": [{"id": "1"}], "size": 1}
        )
        result = configured_confluence.search_pages("test query")
        assert result.status == "fetched"

    @patch("requests.Session.request")
    def test_search_pages_failure(
        self, mock_request: MagicMock, configured_confluence: ConfluenceConnector
    ) -> None:
        mock_request.side_effect = RequestException("Connection failed")
        result = configured_confluence.search_pages("test query")
        assert result.status == "failed"

    @patch("requests.Session.request")
    def test_search_pages_invalid_json(
        self, mock_request: MagicMock, configured_confluence: ConfluenceConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, raise_on_json=True)
        result = configured_confluence.search_pages("test query")
        assert result.status == "fetched"

    @patch("requests.Session.request")
    def test_list_pages(
        self, mock_request: MagicMock, configured_confluence: ConfluenceConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, {"results": [], "size": 0})
        result = configured_confluence.list_pages()
        assert result.status == "fetched"

    def test_health_check_not_configured(
        self, unconfigured_confluence: ConfluenceConnector
    ) -> None:
        result = unconfigured_confluence.health_check()
        assert result.healthy is False

    @patch("requests.Session.request")
    def test_health_check_success(
        self, mock_request: MagicMock, configured_confluence: ConfluenceConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, {"results": []})
        result = configured_confluence.health_check()
        assert result.healthy is True

    @patch("requests.Session.request")
    def test_health_check_http_error(
        self, mock_request: MagicMock, configured_confluence: ConfluenceConnector
    ) -> None:
        mock_request.return_value = MockResponse(401, text="Unauthorized")
        result = configured_confluence.health_check()
        assert result.healthy is False

    @patch("requests.Session.request")
    def test_health_check_exception(
        self, mock_request: MagicMock, configured_confluence: ConfluenceConnector
    ) -> None:
        mock_request.side_effect = RequestException("Connection failed")
        result = configured_confluence.health_check()
        assert result.healthy is False


class TestSlackConnector:
    """Tests for SlackConnector health check."""

    @pytest.fixture
    def configured_slack(self) -> SlackConnector:
        return SlackConnector({"webhook_url": "https://hooks.slack.com/services/xxx"})

    @pytest.fixture
    def unconfigured_slack(self) -> SlackConnector:
        return SlackConnector({})

    def test_health_check_not_configured(
        self, unconfigured_slack: SlackConnector
    ) -> None:
        result = unconfigured_slack.health_check()
        assert result.healthy is False
        assert "not configured" in result.message.lower()

    @patch("requests.Session.request")
    def test_health_check_success(
        self, mock_request: MagicMock, configured_slack: SlackConnector
    ) -> None:
        mock_request.return_value = MockResponse(200)
        result = configured_slack.health_check()
        assert result.healthy is True

    @patch("requests.Session.request")
    def test_health_check_http_error(
        self, mock_request: MagicMock, configured_slack: SlackConnector
    ) -> None:
        mock_request.return_value = MockResponse(404, text="Not Found")
        result = configured_slack.health_check()
        assert result.healthy is False

    @patch("requests.Session.request")
    def test_health_check_exception(
        self, mock_request: MagicMock, configured_slack: SlackConnector
    ) -> None:
        mock_request.side_effect = RequestException("Connection failed")
        result = configured_slack.health_check()
        assert result.healthy is False


class TestServiceNowConnector:
    """Tests for ServiceNowConnector READ operations and health check."""

    @pytest.fixture
    def configured_servicenow(self) -> ServiceNowConnector:
        return ServiceNowConnector(
            {
                "instance_url": "https://test.service-now.com",
                "user": "admin",
                "password": "password",
            }
        )

    @pytest.fixture
    def unconfigured_servicenow(self) -> ServiceNowConnector:
        return ServiceNowConnector({})

    def test_get_incident_not_configured(
        self, unconfigured_servicenow: ServiceNowConnector
    ) -> None:
        result = unconfigured_servicenow.get_incident("INC0001")
        assert result.status == "skipped"

    @patch("requests.Session.request")
    def test_get_incident_success(
        self, mock_request: MagicMock, configured_servicenow: ServiceNowConnector
    ) -> None:
        mock_request.return_value = MockResponse(
            200, {"result": {"sys_id": "123", "number": "INC0001"}}
        )
        result = configured_servicenow.get_incident("123")
        assert result.status == "fetched"

    @patch("requests.Session.request")
    def test_get_incident_failure(
        self, mock_request: MagicMock, configured_servicenow: ServiceNowConnector
    ) -> None:
        mock_request.side_effect = RequestException("Connection failed")
        result = configured_servicenow.get_incident("123")
        assert result.status == "failed"

    @patch("requests.Session.request")
    def test_get_incident_invalid_json(
        self, mock_request: MagicMock, configured_servicenow: ServiceNowConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, raise_on_json=True)
        result = configured_servicenow.get_incident("123")
        assert result.status == "fetched"

    def test_search_incidents_not_configured(
        self, unconfigured_servicenow: ServiceNowConnector
    ) -> None:
        result = unconfigured_servicenow.search_incidents("short_description LIKE test")
        assert result.status == "skipped"

    @patch("requests.Session.request")
    def test_search_incidents_success(
        self, mock_request: MagicMock, configured_servicenow: ServiceNowConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, {"result": [{"sys_id": "1"}]})
        result = configured_servicenow.search_incidents("short_description LIKE test")
        assert result.status == "fetched"

    @patch("requests.Session.request")
    def test_search_incidents_with_fields(
        self, mock_request: MagicMock, configured_servicenow: ServiceNowConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, {"result": []})
        result = configured_servicenow.search_incidents(
            "test", fields=["number", "short_description"]
        )
        assert result.status == "fetched"

    @patch("requests.Session.request")
    def test_search_incidents_failure(
        self, mock_request: MagicMock, configured_servicenow: ServiceNowConnector
    ) -> None:
        mock_request.side_effect = RequestException("Connection failed")
        result = configured_servicenow.search_incidents("test")
        assert result.status == "failed"

    @patch("requests.Session.request")
    def test_search_incidents_invalid_json(
        self, mock_request: MagicMock, configured_servicenow: ServiceNowConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, raise_on_json=True)
        result = configured_servicenow.search_incidents("test")
        assert result.status == "fetched"

    @patch("requests.Session.request")
    def test_list_incidents(
        self, mock_request: MagicMock, configured_servicenow: ServiceNowConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, {"result": []})
        result = configured_servicenow.list_incidents()
        assert result.status == "fetched"

    @patch("requests.Session.request")
    def test_list_incidents_with_filters(
        self, mock_request: MagicMock, configured_servicenow: ServiceNowConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, {"result": []})
        result = configured_servicenow.list_incidents(state="1", assignment_group="IT")
        assert result.status == "fetched"

    def test_health_check_not_configured(
        self, unconfigured_servicenow: ServiceNowConnector
    ) -> None:
        result = unconfigured_servicenow.health_check()
        assert result.healthy is False

    @patch("requests.Session.request")
    def test_health_check_success(
        self, mock_request: MagicMock, configured_servicenow: ServiceNowConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, {"result": []})
        result = configured_servicenow.health_check()
        assert result.healthy is True

    @patch("requests.Session.request")
    def test_health_check_http_error(
        self, mock_request: MagicMock, configured_servicenow: ServiceNowConnector
    ) -> None:
        mock_request.return_value = MockResponse(401, text="Unauthorized")
        result = configured_servicenow.health_check()
        assert result.healthy is False

    @patch("requests.Session.request")
    def test_health_check_exception(
        self, mock_request: MagicMock, configured_servicenow: ServiceNowConnector
    ) -> None:
        mock_request.side_effect = RequestException("Connection failed")
        result = configured_servicenow.health_check()
        assert result.healthy is False

    def test_update_incident_not_configured(
        self, unconfigured_servicenow: ServiceNowConnector
    ) -> None:
        result = unconfigured_servicenow.update_incident({"sys_id": "123"})
        assert result.status == "skipped"

    def test_update_incident_no_sys_id(
        self, configured_servicenow: ServiceNowConnector
    ) -> None:
        result = configured_servicenow.update_incident({})
        assert result.status == "failed"

    def test_update_incident_no_fields(
        self, configured_servicenow: ServiceNowConnector
    ) -> None:
        result = configured_servicenow.update_incident({"sys_id": "123"})
        assert result.status == "skipped"

    @patch("requests.Session.request")
    def test_update_incident_success(
        self, mock_request: MagicMock, configured_servicenow: ServiceNowConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, {"result": {"sys_id": "123"}})
        result = configured_servicenow.update_incident(
            {
                "sys_id": "123",
                "short_description": "Updated",
                "description": "New desc",
                "state": "2",
                "priority": "1",
                "assignment_group": "IT",
            }
        )
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_update_incident_failure(
        self, mock_request: MagicMock, configured_servicenow: ServiceNowConnector
    ) -> None:
        mock_request.side_effect = RequestException("Failed")
        result = configured_servicenow.update_incident({"sys_id": "123", "state": "2"})
        assert result.status == "failed"

    def test_add_work_note_not_configured(
        self, unconfigured_servicenow: ServiceNowConnector
    ) -> None:
        result = unconfigured_servicenow.add_work_note(
            {"sys_id": "123", "work_note": "Test"}
        )
        assert result.status == "skipped"

    def test_add_work_note_no_sys_id(
        self, configured_servicenow: ServiceNowConnector
    ) -> None:
        result = configured_servicenow.add_work_note({"work_note": "Test"})
        assert result.status == "failed"

    def test_add_work_note_no_note(
        self, configured_servicenow: ServiceNowConnector
    ) -> None:
        result = configured_servicenow.add_work_note({"sys_id": "123"})
        assert result.status == "failed"

    @patch("requests.Session.request")
    def test_add_work_note_success(
        self, mock_request: MagicMock, configured_servicenow: ServiceNowConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, {"result": {"sys_id": "123"}})
        result = configured_servicenow.add_work_note(
            {"sys_id": "123", "work_note": "Test note"}
        )
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_add_work_note_failure(
        self, mock_request: MagicMock, configured_servicenow: ServiceNowConnector
    ) -> None:
        mock_request.side_effect = RequestException("Failed")
        result = configured_servicenow.add_work_note(
            {"sys_id": "123", "work_note": "Test"}
        )
        assert result.status == "failed"


class TestGitLabConnector:
    """Tests for GitLabConnector READ operations and health check."""

    @pytest.fixture
    def configured_gitlab(self) -> GitLabConnector:
        return GitLabConnector(
            {
                "url": "https://gitlab.example.com",
                "project_id": "123",
                "token": "test-token",
            }
        )

    @pytest.fixture
    def unconfigured_gitlab(self) -> GitLabConnector:
        return GitLabConnector({})

    def test_get_issue_not_configured(
        self, unconfigured_gitlab: GitLabConnector
    ) -> None:
        result = unconfigured_gitlab.get_issue(1)
        assert result.status == "skipped"

    @patch("requests.Session.request")
    def test_get_issue_success(
        self, mock_request: MagicMock, configured_gitlab: GitLabConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, {"iid": 1, "title": "Test"})
        result = configured_gitlab.get_issue(1)
        assert result.status == "fetched"

    @patch("requests.Session.request")
    def test_get_issue_with_project_id(
        self, mock_request: MagicMock, configured_gitlab: GitLabConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, {"iid": 1})
        result = configured_gitlab.get_issue(1, project_id="456")
        assert result.status == "fetched"

    @patch("requests.Session.request")
    def test_get_issue_failure(
        self, mock_request: MagicMock, configured_gitlab: GitLabConnector
    ) -> None:
        mock_request.side_effect = RequestException("Connection failed")
        result = configured_gitlab.get_issue(1)
        assert result.status == "failed"

    @patch("requests.Session.request")
    def test_get_issue_invalid_json(
        self, mock_request: MagicMock, configured_gitlab: GitLabConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, raise_on_json=True)
        result = configured_gitlab.get_issue(1)
        assert result.status == "fetched"

    def test_search_issues_not_configured(
        self, unconfigured_gitlab: GitLabConnector
    ) -> None:
        result = unconfigured_gitlab.search_issues()
        assert result.status == "skipped"

    @patch("requests.Session.request")
    def test_search_issues_success(
        self, mock_request: MagicMock, configured_gitlab: GitLabConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, json_data=None)
        mock_request.return_value._json_data = [{"iid": 1}]
        result = configured_gitlab.search_issues()
        assert result.status == "fetched"

    @patch("requests.Session.request")
    def test_search_issues_with_params(
        self, mock_request: MagicMock, configured_gitlab: GitLabConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, json_data=None)
        mock_request.return_value._json_data = []
        result = configured_gitlab.search_issues(
            search="bug", labels=["critical"], state="opened"
        )
        assert result.status == "fetched"

    @patch("requests.Session.request")
    def test_search_issues_failure(
        self, mock_request: MagicMock, configured_gitlab: GitLabConnector
    ) -> None:
        mock_request.side_effect = RequestException("Connection failed")
        result = configured_gitlab.search_issues()
        assert result.status == "failed"

    @patch("requests.Session.request")
    def test_search_issues_invalid_json(
        self, mock_request: MagicMock, configured_gitlab: GitLabConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, raise_on_json=True)
        result = configured_gitlab.search_issues()
        assert result.status == "fetched"

    @patch("requests.Session.request")
    def test_list_issues(
        self, mock_request: MagicMock, configured_gitlab: GitLabConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, json_data=None)
        mock_request.return_value._json_data = []
        result = configured_gitlab.list_issues()
        assert result.status == "fetched"

    def test_health_check_not_configured(
        self, unconfigured_gitlab: GitLabConnector
    ) -> None:
        result = unconfigured_gitlab.health_check()
        assert result.healthy is False

    @patch("requests.Session.request")
    def test_health_check_success(
        self, mock_request: MagicMock, configured_gitlab: GitLabConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, {"id": 123})
        result = configured_gitlab.health_check()
        assert result.healthy is True

    @patch("requests.Session.request")
    def test_health_check_http_error(
        self, mock_request: MagicMock, configured_gitlab: GitLabConnector
    ) -> None:
        mock_request.return_value = MockResponse(401, text="Unauthorized")
        result = configured_gitlab.health_check()
        assert result.healthy is False

    @patch("requests.Session.request")
    def test_health_check_exception(
        self, mock_request: MagicMock, configured_gitlab: GitLabConnector
    ) -> None:
        mock_request.side_effect = RequestException("Connection failed")
        result = configured_gitlab.health_check()
        assert result.healthy is False

    def test_update_issue_not_configured(
        self, unconfigured_gitlab: GitLabConnector
    ) -> None:
        result = unconfigured_gitlab.update_issue({"issue_iid": 1})
        assert result.status == "skipped"

    def test_update_issue_no_iid(self, configured_gitlab: GitLabConnector) -> None:
        result = configured_gitlab.update_issue({})
        assert result.status == "failed"

    def test_update_issue_no_fields(self, configured_gitlab: GitLabConnector) -> None:
        result = configured_gitlab.update_issue({"issue_iid": 1})
        assert result.status == "skipped"

    @patch("requests.Session.request")
    def test_update_issue_success(
        self, mock_request: MagicMock, configured_gitlab: GitLabConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, {"iid": 1})
        result = configured_gitlab.update_issue(
            {
                "issue_iid": 1,
                "title": "Updated",
                "description": "New desc",
                "labels": ["bug"],
                "state_event": "close",
            }
        )
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_update_issue_failure(
        self, mock_request: MagicMock, configured_gitlab: GitLabConnector
    ) -> None:
        mock_request.side_effect = RequestException("Failed")
        result = configured_gitlab.update_issue({"issue_iid": 1, "title": "New"})
        assert result.status == "failed"

    def test_add_comment_not_configured(
        self, unconfigured_gitlab: GitLabConnector
    ) -> None:
        result = unconfigured_gitlab.add_comment({"issue_iid": 1, "body": "Test"})
        assert result.status == "skipped"

    def test_add_comment_no_iid(self, configured_gitlab: GitLabConnector) -> None:
        result = configured_gitlab.add_comment({"body": "Test"})
        assert result.status == "failed"

    def test_add_comment_no_body(self, configured_gitlab: GitLabConnector) -> None:
        result = configured_gitlab.add_comment({"issue_iid": 1})
        assert result.status == "failed"

    @patch("requests.Session.request")
    def test_add_comment_success(
        self, mock_request: MagicMock, configured_gitlab: GitLabConnector
    ) -> None:
        mock_request.return_value = MockResponse(201, {"id": 123})
        result = configured_gitlab.add_comment({"issue_iid": 1, "body": "Test comment"})
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_add_comment_failure(
        self, mock_request: MagicMock, configured_gitlab: GitLabConnector
    ) -> None:
        mock_request.side_effect = RequestException("Failed")
        result = configured_gitlab.add_comment({"issue_iid": 1, "body": "Test"})
        assert result.status == "failed"


class TestAzureDevOpsConnector:
    """Tests for AzureDevOpsConnector READ operations and health check."""

    @pytest.fixture
    def configured_azure(self) -> AzureDevOpsConnector:
        return AzureDevOpsConnector(
            {
                "organization": "test-org",
                "project": "test-project",
                "token": "test-token",
            }
        )

    @pytest.fixture
    def unconfigured_azure(self) -> AzureDevOpsConnector:
        return AzureDevOpsConnector({})

    def test_get_work_item_not_configured(
        self, unconfigured_azure: AzureDevOpsConnector
    ) -> None:
        result = unconfigured_azure.get_work_item(1)
        assert result.status == "skipped"

    @patch("requests.Session.request")
    def test_get_work_item_success(
        self, mock_request: MagicMock, configured_azure: AzureDevOpsConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, {"id": 1, "fields": {}})
        result = configured_azure.get_work_item(1)
        assert result.status == "fetched"

    @patch("requests.Session.request")
    def test_get_work_item_failure(
        self, mock_request: MagicMock, configured_azure: AzureDevOpsConnector
    ) -> None:
        mock_request.side_effect = RequestException("Connection failed")
        result = configured_azure.get_work_item(1)
        assert result.status == "failed"

    @patch("requests.Session.request")
    def test_get_work_item_invalid_json(
        self, mock_request: MagicMock, configured_azure: AzureDevOpsConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, raise_on_json=True)
        result = configured_azure.get_work_item(1)
        assert result.status == "fetched"

    def test_search_work_items_not_configured(
        self, unconfigured_azure: AzureDevOpsConnector
    ) -> None:
        result = unconfigured_azure.search_work_items("SELECT * FROM WorkItems")
        assert result.status == "skipped"

    @patch("requests.Session.request")
    def test_search_work_items_success(
        self, mock_request: MagicMock, configured_azure: AzureDevOpsConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, {"workItems": [{"id": 1}]})
        result = configured_azure.search_work_items("SELECT * FROM WorkItems")
        assert result.status == "fetched"

    @patch("requests.Session.request")
    def test_search_work_items_failure(
        self, mock_request: MagicMock, configured_azure: AzureDevOpsConnector
    ) -> None:
        mock_request.side_effect = RequestException("Connection failed")
        result = configured_azure.search_work_items("SELECT * FROM WorkItems")
        assert result.status == "failed"

    @patch("requests.Session.request")
    def test_search_work_items_invalid_json(
        self, mock_request: MagicMock, configured_azure: AzureDevOpsConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, raise_on_json=True)
        result = configured_azure.search_work_items("SELECT * FROM WorkItems")
        assert result.status == "fetched"

    @patch("requests.Session.request")
    def test_list_work_items(
        self, mock_request: MagicMock, configured_azure: AzureDevOpsConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, {"workItems": []})
        result = configured_azure.list_work_items()
        assert result.status == "fetched"

    @patch("requests.Session.request")
    def test_list_work_items_with_filters(
        self, mock_request: MagicMock, configured_azure: AzureDevOpsConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, {"workItems": []})
        result = configured_azure.list_work_items(work_item_type="Bug", state="Active")
        assert result.status == "fetched"

    def test_health_check_not_configured(
        self, unconfigured_azure: AzureDevOpsConnector
    ) -> None:
        result = unconfigured_azure.health_check()
        assert result.healthy is False

    @patch("requests.Session.request")
    def test_health_check_success(
        self, mock_request: MagicMock, configured_azure: AzureDevOpsConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, {"id": "123"})
        result = configured_azure.health_check()
        assert result.healthy is True

    @patch("requests.Session.request")
    def test_health_check_http_error(
        self, mock_request: MagicMock, configured_azure: AzureDevOpsConnector
    ) -> None:
        mock_request.return_value = MockResponse(401, text="Unauthorized")
        result = configured_azure.health_check()
        assert result.healthy is False

    @patch("requests.Session.request")
    def test_health_check_exception(
        self, mock_request: MagicMock, configured_azure: AzureDevOpsConnector
    ) -> None:
        mock_request.side_effect = RequestException("Connection failed")
        result = configured_azure.health_check()
        assert result.healthy is False

    def test_update_work_item_not_configured(
        self, unconfigured_azure: AzureDevOpsConnector
    ) -> None:
        result = unconfigured_azure.update_work_item({"work_item_id": 1})
        assert result.status == "skipped"

    def test_update_work_item_no_id(
        self, configured_azure: AzureDevOpsConnector
    ) -> None:
        result = configured_azure.update_work_item({})
        assert result.status == "failed"

    def test_update_work_item_no_fields(
        self, configured_azure: AzureDevOpsConnector
    ) -> None:
        result = configured_azure.update_work_item({"work_item_id": 1})
        assert result.status == "skipped"

    @patch("requests.Session.request")
    def test_update_work_item_success(
        self, mock_request: MagicMock, configured_azure: AzureDevOpsConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, {"id": 1})
        result = configured_azure.update_work_item(
            {
                "work_item_id": 1,
                "title": "Updated",
                "description": "New desc",
                "state": "Active",
                "assigned_to": "user@example.com",
            }
        )
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_update_work_item_failure(
        self, mock_request: MagicMock, configured_azure: AzureDevOpsConnector
    ) -> None:
        mock_request.side_effect = RequestException("Failed")
        result = configured_azure.update_work_item({"work_item_id": 1, "title": "New"})
        assert result.status == "failed"

    def test_add_comment_not_configured(
        self, unconfigured_azure: AzureDevOpsConnector
    ) -> None:
        result = unconfigured_azure.add_comment({"work_item_id": 1, "text": "Test"})
        assert result.status == "skipped"

    def test_add_comment_no_id(self, configured_azure: AzureDevOpsConnector) -> None:
        result = configured_azure.add_comment({"text": "Test"})
        assert result.status == "failed"

    def test_add_comment_no_text(self, configured_azure: AzureDevOpsConnector) -> None:
        result = configured_azure.add_comment({"work_item_id": 1})
        assert result.status == "failed"

    @patch("requests.Session.request")
    def test_add_comment_success(
        self, mock_request: MagicMock, configured_azure: AzureDevOpsConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, {"id": 123})
        result = configured_azure.add_comment(
            {"work_item_id": 1, "text": "Test comment"}
        )
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_add_comment_failure(
        self, mock_request: MagicMock, configured_azure: AzureDevOpsConnector
    ) -> None:
        mock_request.side_effect = RequestException("Failed")
        result = configured_azure.add_comment({"work_item_id": 1, "text": "Test"})
        assert result.status == "failed"


class TestGitHubConnector:
    """Tests for GitHubConnector READ operations and health check."""

    @pytest.fixture
    def configured_github(self) -> GitHubConnector:
        return GitHubConnector(
            {
                "owner": "test-owner",
                "repo": "test-repo",
                "token": "test-token",
            }
        )

    @pytest.fixture
    def unconfigured_github(self) -> GitHubConnector:
        return GitHubConnector({})

    def test_get_issue_not_configured(
        self, unconfigured_github: GitHubConnector
    ) -> None:
        result = unconfigured_github.get_issue(1)
        assert result.status == "skipped"

    @patch("requests.Session.request")
    def test_get_issue_success(
        self, mock_request: MagicMock, configured_github: GitHubConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, {"number": 1, "title": "Test"})
        result = configured_github.get_issue(1)
        assert result.status == "fetched"

    @patch("requests.Session.request")
    def test_get_issue_with_owner_repo(
        self, mock_request: MagicMock, configured_github: GitHubConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, {"number": 1})
        result = configured_github.get_issue(1, owner="other-owner", repo="other-repo")
        assert result.status == "fetched"

    @patch("requests.Session.request")
    def test_get_issue_failure(
        self, mock_request: MagicMock, configured_github: GitHubConnector
    ) -> None:
        mock_request.side_effect = RequestException("Connection failed")
        result = configured_github.get_issue(1)
        assert result.status == "failed"

    @patch("requests.Session.request")
    def test_get_issue_invalid_json(
        self, mock_request: MagicMock, configured_github: GitHubConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, raise_on_json=True)
        result = configured_github.get_issue(1)
        assert result.status == "fetched"

    def test_search_issues_not_configured(
        self, unconfigured_github: GitHubConnector
    ) -> None:
        result = unconfigured_github.search_issues()
        assert result.status == "skipped"

    @patch("requests.Session.request")
    def test_search_issues_success(
        self, mock_request: MagicMock, configured_github: GitHubConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, json_data=None)
        mock_request.return_value._json_data = [{"number": 1}]
        result = configured_github.search_issues()
        assert result.status == "fetched"

    @patch("requests.Session.request")
    def test_search_issues_with_params(
        self, mock_request: MagicMock, configured_github: GitHubConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, json_data=None)
        mock_request.return_value._json_data = []
        result = configured_github.search_issues(
            state="open", labels="critical", exclude_pull_requests=True
        )
        assert result.status == "fetched"

    @patch("requests.Session.request")
    def test_search_issues_failure(
        self, mock_request: MagicMock, configured_github: GitHubConnector
    ) -> None:
        mock_request.side_effect = RequestException("Connection failed")
        result = configured_github.search_issues()
        assert result.status == "failed"

    @patch("requests.Session.request")
    def test_search_issues_invalid_json(
        self, mock_request: MagicMock, configured_github: GitHubConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, raise_on_json=True)
        result = configured_github.search_issues()
        assert result.status == "fetched"

    @patch("requests.Session.request")
    def test_list_issues(
        self, mock_request: MagicMock, configured_github: GitHubConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, json_data=None)
        mock_request.return_value._json_data = []
        result = configured_github.list_issues()
        assert result.status == "fetched"

    def test_get_comments_not_configured(
        self, unconfigured_github: GitHubConnector
    ) -> None:
        result = unconfigured_github.get_comments(1)
        assert result.status == "skipped"

    @patch("requests.Session.request")
    def test_get_comments_success(
        self, mock_request: MagicMock, configured_github: GitHubConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, json_data=None)
        mock_request.return_value._json_data = [{"id": 1, "body": "Test"}]
        result = configured_github.get_comments(1)
        assert result.status == "fetched"

    @patch("requests.Session.request")
    def test_get_comments_failure(
        self, mock_request: MagicMock, configured_github: GitHubConnector
    ) -> None:
        mock_request.side_effect = RequestException("Connection failed")
        result = configured_github.get_comments(1)
        assert result.status == "failed"

    @patch("requests.Session.request")
    def test_get_comments_invalid_json(
        self, mock_request: MagicMock, configured_github: GitHubConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, raise_on_json=True)
        result = configured_github.get_comments(1)
        assert result.status == "fetched"

    def test_health_check_not_configured(
        self, unconfigured_github: GitHubConnector
    ) -> None:
        result = unconfigured_github.health_check()
        assert result.healthy is False

    @patch("requests.Session.request")
    def test_health_check_success(
        self, mock_request: MagicMock, configured_github: GitHubConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, {"id": 123})
        result = configured_github.health_check()
        assert result.healthy is True

    @patch("requests.Session.request")
    def test_health_check_http_error(
        self, mock_request: MagicMock, configured_github: GitHubConnector
    ) -> None:
        mock_request.return_value = MockResponse(401, text="Unauthorized")
        result = configured_github.health_check()
        assert result.healthy is False

    @patch("requests.Session.request")
    def test_health_check_exception(
        self, mock_request: MagicMock, configured_github: GitHubConnector
    ) -> None:
        mock_request.side_effect = RequestException("Connection failed")
        result = configured_github.health_check()
        assert result.healthy is False

    def test_update_issue_not_configured(
        self, unconfigured_github: GitHubConnector
    ) -> None:
        result = unconfigured_github.update_issue({"issue_number": 1})
        assert result.status == "skipped"

    def test_update_issue_no_number(self, configured_github: GitHubConnector) -> None:
        result = configured_github.update_issue({})
        assert result.status == "failed"

    def test_update_issue_no_fields(self, configured_github: GitHubConnector) -> None:
        result = configured_github.update_issue({"issue_number": 1})
        assert result.status == "skipped"

    @patch("requests.Session.request")
    def test_update_issue_success(
        self, mock_request: MagicMock, configured_github: GitHubConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, {"number": 1})
        result = configured_github.update_issue(
            {
                "issue_number": 1,
                "title": "Updated",
                "body": "New desc",
                "state": "closed",
                "labels": ["bug"],
                "assignees": ["user1"],
            }
        )
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_update_issue_failure(
        self, mock_request: MagicMock, configured_github: GitHubConnector
    ) -> None:
        mock_request.side_effect = RequestException("Failed")
        result = configured_github.update_issue({"issue_number": 1, "title": "New"})
        assert result.status == "failed"

    def test_add_comment_not_configured(
        self, unconfigured_github: GitHubConnector
    ) -> None:
        result = unconfigured_github.add_comment({"issue_number": 1, "body": "Test"})
        assert result.status == "skipped"

    def test_add_comment_no_number(self, configured_github: GitHubConnector) -> None:
        result = configured_github.add_comment({"body": "Test"})
        assert result.status == "failed"

    def test_add_comment_no_body(self, configured_github: GitHubConnector) -> None:
        result = configured_github.add_comment({"issue_number": 1})
        assert result.status == "failed"

    @patch("requests.Session.request")
    def test_add_comment_success(
        self, mock_request: MagicMock, configured_github: GitHubConnector
    ) -> None:
        mock_request.return_value = MockResponse(201, {"id": 123})
        result = configured_github.add_comment(
            {"issue_number": 1, "body": "Test comment"}
        )
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_add_comment_failure(
        self, mock_request: MagicMock, configured_github: GitHubConnector
    ) -> None:
        mock_request.side_effect = RequestException("Failed")
        result = configured_github.add_comment({"issue_number": 1, "body": "Test"})
        assert result.status == "failed"

    def test_get_headers(self, configured_github: GitHubConnector) -> None:
        headers = configured_github._get_headers()
        assert "Authorization" in headers
        assert "Accept" in headers

    # CREATE operation tests
    def test_create_issue_not_configured(
        self, unconfigured_github: GitHubConnector
    ) -> None:
        result = unconfigured_github.create_issue({"title": "Test"})
        assert result.status == "skipped"

    @patch("requests.Session.request")
    def test_create_issue_success(
        self, mock_request: MagicMock, configured_github: GitHubConnector
    ) -> None:
        mock_request.return_value = MockResponse(
            201, {"number": 1, "html_url": "https://github.com/test/1"}
        )
        result = configured_github.create_issue(
            {"title": "Test Issue", "body": "Test body"}
        )
        assert result.status == "sent"
        assert result.details["issue_number"] == 1

    @patch("requests.Session.request")
    def test_create_issue_with_labels(
        self, mock_request: MagicMock, configured_github: GitHubConnector
    ) -> None:
        mock_request.return_value = MockResponse(201, {"number": 2})
        result = configured_github.create_issue(
            {
                "title": "Test",
                "body": "Body",
                "labels": ["bug", "urgent"],
                "assignees": ["user1"],
            }
        )
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_create_issue_failure(
        self, mock_request: MagicMock, configured_github: GitHubConnector
    ) -> None:
        mock_request.side_effect = RequestException("Failed")
        result = configured_github.create_issue({"title": "Test"})
        assert result.status == "failed"

    @patch("requests.Session.request")
    def test_create_issue_invalid_json(
        self, mock_request: MagicMock, configured_github: GitHubConnector
    ) -> None:
        mock_request.return_value = MockResponse(201, raise_on_json=True)
        result = configured_github.create_issue({"title": "Test"})
        assert result.status == "sent"


class TestJiraConnectorCreate:
    """Tests for JiraConnector CREATE operations."""

    @pytest.fixture
    def configured_jira(self) -> JiraConnector:
        return JiraConnector(
            {
                "url": "https://test.atlassian.net",
                "user_email": "test@example.com",
                "token": "test-token",
                "project_key": "TEST",
            }
        )

    @pytest.fixture
    def unconfigured_jira(self) -> JiraConnector:
        return JiraConnector({})

    def test_create_issue_not_configured(
        self, unconfigured_jira: JiraConnector
    ) -> None:
        result = unconfigured_jira.create_issue({"summary": "Test"})
        assert result.status == "skipped"

    @patch("requests.Session.request")
    def test_create_issue_success(
        self, mock_request: MagicMock, configured_jira: JiraConnector
    ) -> None:
        mock_request.return_value = MockResponse(201, {"key": "TEST-1", "id": "12345"})
        result = configured_jira.create_issue(
            {"summary": "Test Issue", "description": "Test desc"}
        )
        assert result.status == "sent"
        assert result.details["issue_key"] == "TEST-1"

    @patch("requests.Session.request")
    def test_create_issue_with_options(
        self, mock_request: MagicMock, configured_jira: JiraConnector
    ) -> None:
        mock_request.return_value = MockResponse(201, {"key": "TEST-2"})
        result = configured_jira.create_issue(
            {
                "summary": "Test",
                "description": "Desc",
                "project_key": "OTHER",
                "issue_type": "Bug",
                "priority": "Critical",
            }
        )
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_create_issue_failure(
        self, mock_request: MagicMock, configured_jira: JiraConnector
    ) -> None:
        mock_request.side_effect = RequestException("Failed")
        result = configured_jira.create_issue({"summary": "Test"})
        assert result.status == "failed"

    @patch("requests.Session.request")
    def test_create_issue_invalid_json(
        self, mock_request: MagicMock, configured_jira: JiraConnector
    ) -> None:
        mock_request.return_value = MockResponse(201, raise_on_json=True)
        result = configured_jira.create_issue({"summary": "Test"})
        assert result.status == "sent"

    def test_token_env_loading(self) -> None:
        """Test that token_env loads token from environment."""
        import os

        os.environ["TEST_JIRA_TOKEN"] = "env-token-value"
        connector = JiraConnector(
            {
                "url": "https://test.atlassian.net",
                "user_email": "test@example.com",
                "token_env": "TEST_JIRA_TOKEN",
                "project_key": "TEST",
            }
        )
        assert connector.token == "env-token-value"
        del os.environ["TEST_JIRA_TOKEN"]


class TestConfluenceConnectorCreate:
    """Tests for ConfluenceConnector CREATE operations."""

    @pytest.fixture
    def configured_confluence(self) -> ConfluenceConnector:
        return ConfluenceConnector(
            {
                "base_url": "https://test.atlassian.net/wiki",
                "user_email": "test@example.com",
                "token": "test-token",
                "space_key": "TEST",
            }
        )

    @pytest.fixture
    def unconfigured_confluence(self) -> ConfluenceConnector:
        return ConfluenceConnector({})

    def test_create_page_not_configured(
        self, unconfigured_confluence: ConfluenceConnector
    ) -> None:
        result = unconfigured_confluence.create_page({"title": "Test"})
        assert result.status == "skipped"

    @patch("requests.Session.request")
    def test_create_page_success(
        self, mock_request: MagicMock, configured_confluence: ConfluenceConnector
    ) -> None:
        mock_request.return_value = MockResponse(
            200, {"id": "12345", "title": "Test Page"}
        )
        result = configured_confluence.create_page(
            {"title": "Test Page", "body": "Test content"}
        )
        assert result.status == "sent"
        assert result.details["page_id"] == "12345"

    @patch("requests.Session.request")
    def test_create_page_with_parent(
        self, mock_request: MagicMock, configured_confluence: ConfluenceConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, {"id": "12346"})
        result = configured_confluence.create_page(
            {
                "title": "Child Page",
                "body": "Content",
                "parent_id": "12345",
                "space_key": "OTHER",
            }
        )
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_create_page_failure(
        self, mock_request: MagicMock, configured_confluence: ConfluenceConnector
    ) -> None:
        mock_request.side_effect = RequestException("Failed")
        result = configured_confluence.create_page({"title": "Test"})
        assert result.status == "failed"

    @patch("requests.Session.request")
    def test_create_page_invalid_json(
        self, mock_request: MagicMock, configured_confluence: ConfluenceConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, raise_on_json=True)
        result = configured_confluence.create_page({"title": "Test"})
        assert result.status == "sent"

    def test_update_page_not_configured(
        self, unconfigured_confluence: ConfluenceConnector
    ) -> None:
        result = unconfigured_confluence.update_page({"page_id": "12345"})
        assert result.status == "skipped"

    def test_update_page_no_page_id(
        self, configured_confluence: ConfluenceConnector
    ) -> None:
        result = configured_confluence.update_page({"title": "New Title"})
        assert result.status == "failed"
        assert "page_id is required" in result.details["reason"]

    @patch("requests.Session.request")
    def test_update_page_success_with_version(
        self, mock_request: MagicMock, configured_confluence: ConfluenceConnector
    ) -> None:
        mock_request.return_value = MockResponse(
            200,
            {
                "id": "12345",
                "title": "Updated Page",
                "version": {"number": 3},
            },
        )
        result = configured_confluence.update_page(
            {
                "page_id": "12345",
                "title": "Updated Page",
                "body": "New content",
                "version": 2,
            }
        )
        assert result.status == "sent"
        assert result.details["page_id"] == "12345"
        assert result.details["operation"] == "update_page"

    @patch("requests.Session.request")
    def test_update_page_auto_fetch_version(
        self, mock_request: MagicMock, configured_confluence: ConfluenceConnector
    ) -> None:
        # First call returns current page with version, second call is the update
        mock_request.side_effect = [
            MockResponse(
                200,
                {
                    "id": "12345",
                    "title": "Original Title",
                    "version": {"number": 5},
                    "body": {"storage": {"value": "old content"}},
                },
            ),
            MockResponse(
                200,
                {
                    "id": "12345",
                    "title": "Updated Title",
                    "version": {"number": 6},
                },
            ),
        ]
        result = configured_confluence.update_page(
            {"page_id": "12345", "title": "Updated Title", "body": "New content"}
        )
        assert result.status == "sent"
        assert result.details["version"] == 6

    @patch("requests.Session.request")
    def test_update_page_fetch_version_failure(
        self, mock_request: MagicMock, configured_confluence: ConfluenceConnector
    ) -> None:
        mock_request.side_effect = RequestException("Connection failed")
        result = configured_confluence.update_page(
            {"page_id": "12345", "body": "New content"}
        )
        assert result.status == "failed"
        assert "failed to fetch current page version" in result.details["reason"]

    @patch("requests.Session.request")
    def test_update_page_update_failure(
        self, mock_request: MagicMock, configured_confluence: ConfluenceConnector
    ) -> None:
        # First call succeeds (get version), second call fails (update)
        mock_request.side_effect = [
            MockResponse(200, {"id": "12345", "version": {"number": 1}}),
            RequestException("Update failed"),
        ]
        result = configured_confluence.update_page(
            {"page_id": "12345", "body": "New content"}
        )
        assert result.status == "failed"
        assert "confluence update failed" in result.details["reason"]

    @patch("requests.Session.request")
    def test_update_page_invalid_json_response(
        self, mock_request: MagicMock, configured_confluence: ConfluenceConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, raise_on_json=True)
        result = configured_confluence.update_page(
            {"page_id": "12345", "body": "New content", "version": 1}
        )
        assert result.status == "sent"


class TestSlackConnectorPost:
    """Tests for SlackConnector post_message operation."""

    @pytest.fixture
    def configured_slack(self) -> SlackConnector:
        return SlackConnector({"webhook_url": "https://hooks.slack.com/services/test"})

    @pytest.fixture
    def unconfigured_slack(self) -> SlackConnector:
        return SlackConnector({})

    def test_post_message_not_configured(
        self, unconfigured_slack: SlackConnector
    ) -> None:
        result = unconfigured_slack.post_message({"text": "Test"})
        assert result.status == "skipped"

    @patch("requests.Session.request")
    def test_post_message_success(
        self, mock_request: MagicMock, configured_slack: SlackConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, text="ok")
        result = configured_slack.post_message({"text": "Test message"})
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_post_message_with_blocks(
        self, mock_request: MagicMock, configured_slack: SlackConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, text="ok")
        result = configured_slack.post_message(
            {
                "text": "Test",
                "blocks": [
                    {"type": "section", "text": {"type": "mrkdwn", "text": "Hello"}}
                ],
            }
        )
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_post_message_failure(
        self, mock_request: MagicMock, configured_slack: SlackConnector
    ) -> None:
        mock_request.side_effect = RequestException("Failed")
        result = configured_slack.post_message({"text": "Test"})
        assert result.status == "failed"


class TestServiceNowConnectorCreate:
    """Tests for ServiceNowConnector CREATE operations."""

    @pytest.fixture
    def configured_servicenow(self) -> ServiceNowConnector:
        return ServiceNowConnector(
            {
                "instance_url": "https://test.service-now.com",
                "user": "admin",
                "password": "password",
            }
        )

    @pytest.fixture
    def unconfigured_servicenow(self) -> ServiceNowConnector:
        return ServiceNowConnector({})

    def test_create_incident_not_configured(
        self, unconfigured_servicenow: ServiceNowConnector
    ) -> None:
        result = unconfigured_servicenow.create_incident({"summary": "Test"})
        assert result.status == "skipped"

    @patch("requests.Session.request")
    def test_create_incident_success(
        self, mock_request: MagicMock, configured_servicenow: ServiceNowConnector
    ) -> None:
        mock_request.return_value = MockResponse(
            201, {"result": {"sys_id": "123", "number": "INC0001"}}
        )
        result = configured_servicenow.create_incident(
            {"summary": "Test Incident", "description": "Test desc"}
        )
        assert result.status == "sent"
        assert result.details["number"] == "INC0001"
        assert result.details["sys_id"] == "123"

    @patch("requests.Session.request")
    def test_create_incident_with_options(
        self, mock_request: MagicMock, configured_servicenow: ServiceNowConnector
    ) -> None:
        mock_request.return_value = MockResponse(
            201, {"result": {"sys_id": "124", "number": "INC0002"}}
        )
        result = configured_servicenow.create_incident(
            {
                "summary": "Test",
                "description": "Desc",
                "urgency": "1",
                "impact": "1",
                "assignment_group": "IT Support",
                "caller_id": "user123",
                "category": "Software",
                "subcategory": "Bug",
            }
        )
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_create_incident_failure(
        self, mock_request: MagicMock, configured_servicenow: ServiceNowConnector
    ) -> None:
        mock_request.side_effect = RequestException("Failed")
        result = configured_servicenow.create_incident({"summary": "Test"})
        assert result.status == "failed"

    @patch("requests.Session.request")
    def test_create_incident_invalid_json(
        self, mock_request: MagicMock, configured_servicenow: ServiceNowConnector
    ) -> None:
        mock_request.return_value = MockResponse(201, raise_on_json=True)
        result = configured_servicenow.create_incident({"summary": "Test"})
        assert result.status == "sent"

    def test_token_env_loading(self) -> None:
        """Test that token_env loads token from environment."""
        import os

        os.environ["TEST_SNOW_TOKEN"] = "env-token-value"
        connector = ServiceNowConnector(
            {
                "instance_url": "https://test.service-now.com",
                "user": "admin",
                "token_env": "TEST_SNOW_TOKEN",
            }
        )
        assert connector.token == "env-token-value"
        del os.environ["TEST_SNOW_TOKEN"]


class TestGitLabConnectorCreate:
    """Tests for GitLabConnector CREATE operations."""

    @pytest.fixture
    def configured_gitlab(self) -> GitLabConnector:
        return GitLabConnector(
            {
                "token": "test-token",
                "project_id": "12345",
            }
        )

    @pytest.fixture
    def unconfigured_gitlab(self) -> GitLabConnector:
        return GitLabConnector({})

    def test_create_issue_not_configured(
        self, unconfigured_gitlab: GitLabConnector
    ) -> None:
        result = unconfigured_gitlab.create_issue({"title": "Test"})
        assert result.status == "skipped"

    @patch("requests.Session.request")
    def test_create_issue_success(
        self, mock_request: MagicMock, configured_gitlab: GitLabConnector
    ) -> None:
        mock_request.return_value = MockResponse(
            201, {"iid": 1, "web_url": "https://gitlab.com/test/1"}
        )
        result = configured_gitlab.create_issue(
            {"title": "Test Issue", "description": "Test desc"}
        )
        assert result.status == "sent"
        assert result.details["issue_iid"] == 1

    @patch("requests.Session.request")
    def test_create_issue_with_options(
        self, mock_request: MagicMock, configured_gitlab: GitLabConnector
    ) -> None:
        mock_request.return_value = MockResponse(201, {"iid": 2})
        result = configured_gitlab.create_issue(
            {
                "title": "Test",
                "description": "Desc",
                "labels": "bug,urgent",
                "assignee_ids": [1, 2],
                "milestone_id": 5,
            }
        )
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_create_issue_failure(
        self, mock_request: MagicMock, configured_gitlab: GitLabConnector
    ) -> None:
        mock_request.side_effect = RequestException("Failed")
        result = configured_gitlab.create_issue({"title": "Test"})
        assert result.status == "failed"

    @patch("requests.Session.request")
    def test_create_issue_invalid_json(
        self, mock_request: MagicMock, configured_gitlab: GitLabConnector
    ) -> None:
        mock_request.return_value = MockResponse(201, raise_on_json=True)
        result = configured_gitlab.create_issue({"title": "Test"})
        assert result.status == "sent"


class TestAzureDevOpsConnectorCreate:
    """Tests for AzureDevOpsConnector CREATE operations."""

    @pytest.fixture
    def configured_azure(self) -> AzureDevOpsConnector:
        return AzureDevOpsConnector(
            {
                "token": "test-token",
                "organization": "test-org",
                "project": "test-project",
            }
        )

    @pytest.fixture
    def unconfigured_azure(self) -> AzureDevOpsConnector:
        return AzureDevOpsConnector({})

    def test_create_work_item_not_configured(
        self, unconfigured_azure: AzureDevOpsConnector
    ) -> None:
        result = unconfigured_azure.create_work_item({"title": "Test"})
        assert result.status == "skipped"

    @patch("requests.Session.request")
    def test_create_work_item_success(
        self, mock_request: MagicMock, configured_azure: AzureDevOpsConnector
    ) -> None:
        mock_request.return_value = MockResponse(
            200,
            {"id": 123, "_links": {"html": {"href": "https://dev.azure.com/test/123"}}},
        )
        result = configured_azure.create_work_item(
            {"title": "Test Work Item", "description": "Test desc"}
        )
        assert result.status == "sent"
        assert result.details["work_item_id"] == 123

    @patch("requests.Session.request")
    def test_create_work_item_with_options(
        self, mock_request: MagicMock, configured_azure: AzureDevOpsConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, {"id": 124})
        result = configured_azure.create_work_item(
            {
                "title": "Test",
                "description": "Desc",
                "work_item_type": "Bug",
                "area_path": "Test\\Area",
                "iteration_path": "Test\\Sprint1",
                "assigned_to": "user@example.com",
                "priority": 1,
                "tags": "urgent;critical",
            }
        )
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_create_work_item_failure(
        self, mock_request: MagicMock, configured_azure: AzureDevOpsConnector
    ) -> None:
        mock_request.side_effect = RequestException("Failed")
        result = configured_azure.create_work_item({"title": "Test"})
        assert result.status == "failed"

    @patch("requests.Session.request")
    def test_create_work_item_invalid_json(
        self, mock_request: MagicMock, configured_azure: AzureDevOpsConnector
    ) -> None:
        mock_request.return_value = MockResponse(200, raise_on_json=True)
        result = configured_azure.create_work_item({"title": "Test"})
        assert result.status == "sent"

    def test_get_auth_header(self, configured_azure: AzureDevOpsConnector) -> None:
        header = configured_azure._get_auth_header()
        assert "Authorization" in header
        assert header["Authorization"].startswith("Basic ")


class TestAutomationConnectors:
    """Tests for AutomationConnectors class."""

    def test_init_with_settings(self) -> None:
        from core.connectors import AutomationConnectors

        settings = {
            "jira": {
                "url": "https://test.atlassian.net",
                "user_email": "test@example.com",
                "token": "token",
                "project_key": "TEST",
            },
            "policy_automation": {"webhook_url": "https://hooks.slack.com/test"},
        }
        toggles = {"enforce_ticket_sync": True}
        connectors = AutomationConnectors(settings, toggles)
        assert connectors.jira is not None
        assert connectors.slack is not None

    def test_check_feature_flag_no_provider(self) -> None:
        from core.connectors import AutomationConnectors

        connectors = AutomationConnectors({}, {})
        # Without a flag provider, should return default
        assert connectors._check_feature_flag("test_feature") is True
        assert connectors._check_feature_flag("test_feature", default=False) is False

    def test_check_feature_flag_with_provider(self) -> None:
        from core.connectors import AutomationConnectors

        class MockFlagProvider:
            def bool(self, flag_name: str, default: bool) -> bool:
                if flag_name == "enabled_flag":
                    return True
                if flag_name == "disabled_flag":
                    return False
                return default

        connectors = AutomationConnectors({}, {}, flag_provider=MockFlagProvider())
        assert connectors._check_feature_flag("enabled_flag") is True
        assert connectors._check_feature_flag("disabled_flag") is False

    def test_check_feature_flag_provider_exception(self) -> None:
        from core.connectors import AutomationConnectors

        class FailingFlagProvider:
            def bool(self, flag_name: str, default: bool) -> bool:
                raise RuntimeError("Provider failed")

        connectors = AutomationConnectors({}, {}, flag_provider=FailingFlagProvider())
        # Should return default when provider fails
        assert connectors._check_feature_flag("test_feature", default=True) is True

    @patch("requests.Session.request")
    def test_deliver_jira_create(self, mock_request: MagicMock) -> None:
        from core.connectors import AutomationConnectors

        mock_request.return_value = MockResponse(201, {"key": "TEST-1"})
        settings = {
            "jira": {
                "url": "https://test.atlassian.net",
                "user_email": "test@example.com",
                "token": "token",
                "project_key": "TEST",
            },
        }
        connectors = AutomationConnectors(settings, {"enforce_ticket_sync": True})
        result = connectors.deliver({"type": "jira", "summary": "Test"})
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_deliver_jira_update(self, mock_request: MagicMock) -> None:
        from core.connectors import AutomationConnectors

        mock_request.return_value = MockResponse(204)
        settings = {
            "jira": {
                "url": "https://test.atlassian.net",
                "user_email": "test@example.com",
                "token": "token",
                "project_key": "TEST",
            },
        }
        connectors = AutomationConnectors(settings, {"enforce_ticket_sync": True})
        result = connectors.deliver(
            {
                "type": "jira",
                "operation": "update",
                "issue_key": "TEST-1",
                "summary": "Updated",
            }
        )
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_deliver_jira_transition(self, mock_request: MagicMock) -> None:
        from core.connectors import AutomationConnectors

        mock_request.return_value = MockResponse(204)
        settings = {
            "jira": {
                "url": "https://test.atlassian.net",
                "user_email": "test@example.com",
                "token": "token",
                "project_key": "TEST",
            },
        }
        connectors = AutomationConnectors(settings, {"enforce_ticket_sync": True})
        result = connectors.deliver(
            {
                "type": "jira",
                "operation": "transition",
                "issue_key": "TEST-1",
                "transition_id": "31",
            }
        )
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_deliver_jira_comment(self, mock_request: MagicMock) -> None:
        from core.connectors import AutomationConnectors

        mock_request.return_value = MockResponse(201, {"id": "123"})
        settings = {
            "jira": {
                "url": "https://test.atlassian.net",
                "user_email": "test@example.com",
                "token": "token",
                "project_key": "TEST",
            },
        }
        connectors = AutomationConnectors(settings, {"enforce_ticket_sync": True})
        result = connectors.deliver(
            {
                "type": "jira",
                "operation": "comment",
                "issue_key": "TEST-1",
                "comment": "Test comment",
            }
        )
        assert result.status == "sent"

    def test_deliver_jira_sync_disabled(self) -> None:
        from core.connectors import AutomationConnectors

        settings = {
            "jira": {
                "url": "https://test.atlassian.net",
                "user_email": "test@example.com",
                "token": "token",
                "project_key": "TEST",
            },
        }
        connectors = AutomationConnectors(settings, {"enforce_ticket_sync": False})
        result = connectors.deliver({"type": "jira", "summary": "Test"})
        assert result.status == "skipped"
        assert "sync disabled" in result.details["reason"]

    @patch("requests.Session.request")
    def test_deliver_jira_force_delivery(self, mock_request: MagicMock) -> None:
        from core.connectors import AutomationConnectors

        mock_request.return_value = MockResponse(201, {"key": "TEST-1"})
        settings = {
            "jira": {
                "url": "https://test.atlassian.net",
                "user_email": "test@example.com",
                "token": "token",
                "project_key": "TEST",
            },
        }
        connectors = AutomationConnectors(settings, {"enforce_ticket_sync": False})
        result = connectors.deliver(
            {"type": "jira", "summary": "Test", "force_delivery": True}
        )
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_deliver_slack(self, mock_request: MagicMock) -> None:
        from core.connectors import AutomationConnectors

        mock_request.return_value = MockResponse(200, text="ok")
        settings = {
            "policy_automation": {"webhook_url": "https://hooks.slack.com/test"},
        }
        connectors = AutomationConnectors(settings, {})
        result = connectors.deliver({"type": "slack", "text": "Test message"})
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_deliver_servicenow_create(self, mock_request: MagicMock) -> None:
        from core.connectors import AutomationConnectors

        mock_request.return_value = MockResponse(
            201, {"result": {"sys_id": "123", "number": "INC0001"}}
        )
        settings = {
            "servicenow": {
                "instance_url": "https://test.service-now.com",
                "user": "admin",
                "password": "pass",
            },
        }
        connectors = AutomationConnectors(settings, {"enforce_ticket_sync": True})
        result = connectors.deliver({"type": "servicenow", "summary": "Test"})
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_deliver_servicenow_update(self, mock_request: MagicMock) -> None:
        from core.connectors import AutomationConnectors

        mock_request.return_value = MockResponse(200, {"result": {"sys_id": "123"}})
        settings = {
            "servicenow": {
                "instance_url": "https://test.service-now.com",
                "user": "admin",
                "password": "pass",
            },
        }
        connectors = AutomationConnectors(settings, {"enforce_ticket_sync": True})
        result = connectors.deliver(
            {
                "type": "servicenow",
                "operation": "update",
                "sys_id": "123",
                "short_description": "Updated",
            }
        )
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_deliver_servicenow_work_note(self, mock_request: MagicMock) -> None:
        from core.connectors import AutomationConnectors

        mock_request.return_value = MockResponse(200, {"result": {"sys_id": "123"}})
        settings = {
            "servicenow": {
                "instance_url": "https://test.service-now.com",
                "user": "admin",
                "password": "pass",
            },
        }
        connectors = AutomationConnectors(settings, {"enforce_ticket_sync": True})
        result = connectors.deliver(
            {
                "type": "servicenow",
                "operation": "work_note",
                "sys_id": "123",
                "work_note": "Note",
            }
        )
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_deliver_gitlab_create(self, mock_request: MagicMock) -> None:
        from core.connectors import AutomationConnectors

        mock_request.return_value = MockResponse(201, {"iid": 1})
        settings = {
            "gitlab": {"token": "token", "project_id": "123"},
        }
        connectors = AutomationConnectors(settings, {"enforce_ticket_sync": True})
        result = connectors.deliver({"type": "gitlab", "title": "Test"})
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_deliver_gitlab_update(self, mock_request: MagicMock) -> None:
        from core.connectors import AutomationConnectors

        mock_request.return_value = MockResponse(200, {"iid": 1})
        settings = {
            "gitlab": {"token": "token", "project_id": "123"},
        }
        connectors = AutomationConnectors(settings, {"enforce_ticket_sync": True})
        result = connectors.deliver(
            {
                "type": "gitlab",
                "operation": "update",
                "issue_iid": 1,
                "title": "Updated",
            }
        )
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_deliver_gitlab_comment(self, mock_request: MagicMock) -> None:
        from core.connectors import AutomationConnectors

        mock_request.return_value = MockResponse(201, {"id": 1})
        settings = {
            "gitlab": {"token": "token", "project_id": "123"},
        }
        connectors = AutomationConnectors(settings, {"enforce_ticket_sync": True})
        result = connectors.deliver(
            {
                "type": "gitlab",
                "operation": "comment",
                "issue_iid": 1,
                "body": "Comment",
            }
        )
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_deliver_azure_devops_create(self, mock_request: MagicMock) -> None:
        from core.connectors import AutomationConnectors

        mock_request.return_value = MockResponse(200, {"id": 123})
        settings = {
            "azure_devops": {
                "token": "token",
                "organization": "org",
                "project": "proj",
            },
        }
        connectors = AutomationConnectors(settings, {"enforce_ticket_sync": True})
        result = connectors.deliver({"type": "azure_devops", "title": "Test"})
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_deliver_azure_devops_update(self, mock_request: MagicMock) -> None:
        from core.connectors import AutomationConnectors

        mock_request.return_value = MockResponse(200, {"id": 123})
        settings = {
            "azure_devops": {
                "token": "token",
                "organization": "org",
                "project": "proj",
            },
        }
        connectors = AutomationConnectors(settings, {"enforce_ticket_sync": True})
        result = connectors.deliver(
            {
                "type": "azure_devops",
                "operation": "update",
                "work_item_id": 123,
                "title": "Updated",
            }
        )
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_deliver_azure_devops_comment(self, mock_request: MagicMock) -> None:
        from core.connectors import AutomationConnectors

        mock_request.return_value = MockResponse(200, {"id": 1})
        settings = {
            "azure_devops": {
                "token": "token",
                "organization": "org",
                "project": "proj",
            },
        }
        connectors = AutomationConnectors(settings, {"enforce_ticket_sync": True})
        result = connectors.deliver(
            {
                "type": "azure_devops",
                "operation": "comment",
                "work_item_id": 123,
                "text": "Comment",
            }
        )
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_deliver_github_create(self, mock_request: MagicMock) -> None:
        from core.connectors import AutomationConnectors

        mock_request.return_value = MockResponse(201, {"number": 1})
        settings = {
            "github": {"token": "token", "owner": "owner", "repo": "repo"},
        }
        connectors = AutomationConnectors(settings, {"enforce_ticket_sync": True})
        result = connectors.deliver({"type": "github", "title": "Test"})
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_deliver_github_update(self, mock_request: MagicMock) -> None:
        from core.connectors import AutomationConnectors

        mock_request.return_value = MockResponse(200, {"number": 1})
        settings = {
            "github": {"token": "token", "owner": "owner", "repo": "repo"},
        }
        connectors = AutomationConnectors(settings, {"enforce_ticket_sync": True})
        result = connectors.deliver(
            {
                "type": "github",
                "operation": "update",
                "issue_number": 1,
                "title": "Updated",
            }
        )
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_deliver_github_comment(self, mock_request: MagicMock) -> None:
        from core.connectors import AutomationConnectors

        mock_request.return_value = MockResponse(201, {"id": 1})
        settings = {
            "github": {"token": "token", "owner": "owner", "repo": "repo"},
        }
        connectors = AutomationConnectors(settings, {"enforce_ticket_sync": True})
        result = connectors.deliver(
            {
                "type": "github",
                "operation": "comment",
                "issue_number": 1,
                "body": "Comment",
            }
        )
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_deliver_confluence(self, mock_request: MagicMock) -> None:
        from core.connectors import AutomationConnectors

        mock_request.return_value = MockResponse(200, {"id": "123"})
        settings = {
            "confluence": {
                "base_url": "https://test.atlassian.net/wiki",
                "user_email": "test@example.com",
                "token": "token",
                "space_key": "TEST",
            },
        }
        connectors = AutomationConnectors(settings, {"enforce_ticket_sync": True})
        result = connectors.deliver({"type": "confluence", "title": "Test Page"})
        assert result.status == "sent"

    def test_deliver_confluence_sync_disabled(self) -> None:
        from core.connectors import AutomationConnectors

        settings = {
            "confluence": {
                "url": "https://test.atlassian.net/wiki",
                "user_email": "test@example.com",
                "token": "token",
                "space_key": "TEST",
            },
        }
        connectors = AutomationConnectors(settings, {"enforce_ticket_sync": False})
        result = connectors.deliver({"type": "confluence", "title": "Test Page"})
        assert result.status == "skipped"
        assert "sync disabled" in result.details["reason"]

    def test_deliver_unknown_type(self) -> None:
        from core.connectors import AutomationConnectors

        connectors = AutomationConnectors({}, {})
        result = connectors.deliver({"type": "unknown"})
        assert result.status == "skipped"
        assert "no connector registered" in result.details["reason"]

    def test_deliver_empty_type(self) -> None:
        from core.connectors import AutomationConnectors

        connectors = AutomationConnectors({}, {})
        result = connectors.deliver({})
        assert result.status == "skipped"


class TestSummariseConnector:
    """Tests for summarise_connector function."""

    def test_summarise_jira_connector(self) -> None:
        from core.connectors import summarise_connector

        connector = JiraConnector(
            {
                "url": "https://test.atlassian.net",
                "user_email": "test@example.com",
                "token": "secret-token",
                "project_key": "TEST",
            }
        )
        summary = summarise_connector(connector)
        assert summary["configured"] is True
        assert summary["project_key"] == "TEST"
        assert summary["url"] == "https://test.atlassian.net"
        assert "***" in summary["token"]  # masked token

    def test_summarise_unconfigured_jira_connector(self) -> None:
        from core.connectors import summarise_connector

        connector = JiraConnector({})
        summary = summarise_connector(connector)
        assert summary["configured"] is False

    def test_summarise_slack_connector(self) -> None:
        from core.connectors import summarise_connector

        connector = SlackConnector(
            {"webhook_url": "https://hooks.slack.com/services/secret"}
        )
        summary = summarise_connector(connector)
        assert summary["configured"] is True
        assert "***" in summary["webhook"]  # masked webhook

    def test_summarise_servicenow_connector(self) -> None:
        from core.connectors import summarise_connector

        connector = ServiceNowConnector(
            {
                "instance_url": "https://test.service-now.com",
                "user": "admin",
                "password": "secret",
            }
        )
        summary = summarise_connector(connector)
        assert summary["configured"] is True
        assert summary["instance_url"] == "https://test.service-now.com"
        assert summary["user"] == "admin"

    def test_summarise_github_connector(self) -> None:
        from core.connectors import summarise_connector

        connector = GitHubConnector(
            {
                "token": "ghp_secret",
                "owner": "owner",
                "repo": "repo",
            }
        )
        summary = summarise_connector(connector)
        assert summary["configured"] is True
        assert summary["owner"] == "owner"
        assert summary["repo"] == "repo"

    def test_summarise_gitlab_connector(self) -> None:
        from core.connectors import summarise_connector

        connector = GitLabConnector(
            {
                "token": "glpat-secret",
                "project_id": "123",
            }
        )
        summary = summarise_connector(connector)
        assert summary["configured"] is True
        assert summary["project_id"] == "123"

    def test_summarise_azure_devops_connector(self) -> None:
        from core.connectors import summarise_connector

        connector = AzureDevOpsConnector(
            {
                "token": "secret-pat",
                "organization": "org",
                "project": "proj",
            }
        )
        summary = summarise_connector(connector)
        assert summary["configured"] is True
        assert summary["organization"] == "org"
        assert summary["project"] == "proj"

    def test_summarise_confluence_connector(self) -> None:
        from core.connectors import summarise_connector

        connector = ConfluenceConnector(
            {
                "base_url": "https://test.atlassian.net/wiki",
                "user_email": "test@example.com",
                "token": "secret",
                "space_key": "TEST",
            }
        )
        summary = summarise_connector(connector)
        assert summary["configured"] is True
        assert summary["space_key"] == "TEST"

    def test_summarise_unknown_connector(self) -> None:
        from core.connectors import summarise_connector

        # Test with base connector (not a specific type)
        connector = _BaseConnector()
        summary = summarise_connector(connector)
        assert summary["configured"] is False


class TestTokenEnvLoading:
    """Tests for token loading from environment variables."""

    @patch.dict("os.environ", {"CONFLUENCE_TOKEN_ENV": "env-token-value"})
    def test_confluence_token_env(self) -> None:
        connector = ConfluenceConnector(
            {
                "base_url": "https://test.atlassian.net/wiki",
                "user_email": "test@example.com",
                "token_env": "CONFLUENCE_TOKEN_ENV",
                "space_key": "TEST",
            }
        )
        assert connector.token == "env-token-value"
        assert connector.configured is True

    @patch.dict("os.environ", {"CONFLUENCE_TOKEN_ENV": ""})
    def test_confluence_token_env_empty(self) -> None:
        connector = ConfluenceConnector(
            {
                "base_url": "https://test.atlassian.net/wiki",
                "user_email": "test@example.com",
                "token_env": "CONFLUENCE_TOKEN_ENV",
                "space_key": "TEST",
            }
        )
        # Empty env var should not override
        assert connector.token is None

    @patch.dict("os.environ", {"SLACK_WEBHOOK_ENV": "https://hooks.slack.com/env"})
    def test_slack_webhook_env(self) -> None:
        connector = SlackConnector({"webhook_env": "SLACK_WEBHOOK_ENV"})
        assert connector.default_webhook == "https://hooks.slack.com/env"

    @patch.dict("os.environ", {"SLACK_WEBHOOK_ENV": ""})
    def test_slack_webhook_env_empty(self) -> None:
        connector = SlackConnector({"webhook_env": "SLACK_WEBHOOK_ENV"})
        # Empty env var should not override
        assert connector.default_webhook is None

    @patch.dict("os.environ", {"GITLAB_TOKEN_ENV": "glpat-env-token"})
    def test_gitlab_token_env(self) -> None:
        connector = GitLabConnector(
            {
                "project_id": "123",
                "token_env": "GITLAB_TOKEN_ENV",
            }
        )
        assert connector.token == "glpat-env-token"
        assert connector.configured is True

    @patch.dict("os.environ", {"GITLAB_TOKEN_ENV": ""})
    def test_gitlab_token_env_empty(self) -> None:
        connector = GitLabConnector(
            {
                "project_id": "123",
                "token_env": "GITLAB_TOKEN_ENV",
            }
        )
        # Empty env var should not override
        assert connector.token is None

    @patch.dict("os.environ", {"AZURE_TOKEN_ENV": "azure-pat-env"})
    def test_azure_devops_token_env(self) -> None:
        connector = AzureDevOpsConnector(
            {
                "organization": "org",
                "project": "proj",
                "token_env": "AZURE_TOKEN_ENV",
            }
        )
        assert connector.token == "azure-pat-env"
        assert connector.configured is True

    @patch.dict("os.environ", {"AZURE_TOKEN_ENV": ""})
    def test_azure_devops_token_env_empty(self) -> None:
        connector = AzureDevOpsConnector(
            {
                "organization": "org",
                "project": "proj",
                "token_env": "AZURE_TOKEN_ENV",
            }
        )
        # Empty env var should not override
        assert connector.token is None

    @patch.dict("os.environ", {"GITHUB_TOKEN_ENV": "ghp-env-token"})
    def test_github_token_env(self) -> None:
        connector = GitHubConnector(
            {
                "owner": "owner",
                "repo": "repo",
                "token_env": "GITHUB_TOKEN_ENV",
            }
        )
        assert connector.token == "ghp-env-token"
        assert connector.configured is True

    @patch.dict("os.environ", {"GITHUB_TOKEN_ENV": ""})
    def test_github_token_env_empty(self) -> None:
        connector = GitHubConnector(
            {
                "owner": "owner",
                "repo": "repo",
                "token_env": "GITHUB_TOKEN_ENV",
            }
        )
        # Empty env var should not override
        assert connector.token is None


class TestAutomationConnectorsFeatureFlags:
    """Tests for feature flag disabled paths in AutomationConnectors.deliver()."""

    def _make_connectors_with_flag_provider(
        self, flag_values: Dict[str, bool]
    ) -> "AutomationConnectors":
        from core.connectors import AutomationConnectors

        class MockFlagProvider:
            def bool(self, flag_name: str, default: bool = True) -> bool:
                return flag_values.get(flag_name, default)

        settings = {
            "jira": {
                "token": "test",
                "project_key": "TEST",
                "base_url": "https://jira.test",
            },
            "confluence": {
                "base_url": "https://conf.test",
                "user_email": "u@t.com",
                "token": "t",
                "space_key": "S",
            },
            "slack": {"webhook_url": "https://hooks.slack.com/test"},
            "servicenow": {
                "instance": "test.service-now.com",
                "user": "admin",
                "password": "pass",
            },
            "gitlab": {"token": "glpat-test", "project_id": "123"},
            "azure_devops": {"token": "pat", "organization": "org", "project": "proj"},
            "github": {"token": "ghp_test", "owner": "owner", "repo": "repo"},
        }
        toggles = {"enforce_ticket_sync": True}
        connectors = AutomationConnectors(settings, toggles)
        connectors.flag_provider = MockFlagProvider()
        return connectors

    def test_jira_feature_flag_disabled(self) -> None:
        connectors = self._make_connectors_with_flag_provider(
            {"fixops.feature.connector.jira": False}
        )
        result = connectors.deliver({"type": "jira", "summary": "Test"})
        assert result.status == "skipped"
        assert "disabled" in result.details["reason"]

    def test_confluence_feature_flag_disabled(self) -> None:
        connectors = self._make_connectors_with_flag_provider(
            {"fixops.feature.connector.confluence": False}
        )
        result = connectors.deliver({"type": "confluence", "title": "Test"})
        assert result.status == "skipped"
        assert "disabled" in result.details["reason"]

    def test_slack_feature_flag_disabled(self) -> None:
        connectors = self._make_connectors_with_flag_provider(
            {"fixops.feature.connector.slack": False}
        )
        result = connectors.deliver({"type": "slack", "text": "Test"})
        assert result.status == "skipped"
        assert "disabled" in result.details["reason"]

    def test_servicenow_feature_flag_disabled(self) -> None:
        connectors = self._make_connectors_with_flag_provider(
            {"fixops.feature.connector.servicenow": False}
        )
        result = connectors.deliver({"type": "servicenow", "summary": "Test"})
        assert result.status == "skipped"
        assert "disabled" in result.details["reason"]

    def test_gitlab_feature_flag_disabled(self) -> None:
        connectors = self._make_connectors_with_flag_provider(
            {"fixops.feature.connector.gitlab": False}
        )
        result = connectors.deliver({"type": "gitlab", "title": "Test"})
        assert result.status == "skipped"
        assert "disabled" in result.details["reason"]

    def test_azure_devops_feature_flag_disabled(self) -> None:
        connectors = self._make_connectors_with_flag_provider(
            {"fixops.feature.connector.azure_devops": False}
        )
        result = connectors.deliver({"type": "azure_devops", "title": "Test"})
        assert result.status == "skipped"
        assert "disabled" in result.details["reason"]

    def test_github_feature_flag_disabled(self) -> None:
        connectors = self._make_connectors_with_flag_provider(
            {"fixops.feature.connector.github": False}
        )
        result = connectors.deliver({"type": "github", "title": "Test"})
        assert result.status == "skipped"
        assert "disabled" in result.details["reason"]

    def test_servicenow_sync_disabled(self) -> None:
        from core.connectors import AutomationConnectors

        settings = {
            "servicenow": {
                "instance": "test.service-now.com",
                "user": "admin",
                "password": "pass",
            },
        }
        toggles = {"enforce_ticket_sync": False}
        connectors = AutomationConnectors(settings, toggles)
        result = connectors.deliver({"type": "servicenow", "summary": "Test"})
        assert result.status == "skipped"
        assert "sync disabled" in result.details["reason"]

    def test_gitlab_sync_disabled(self) -> None:
        from core.connectors import AutomationConnectors

        settings = {
            "gitlab": {"token": "glpat-test", "project_id": "123"},
        }
        toggles = {"enforce_ticket_sync": False}
        connectors = AutomationConnectors(settings, toggles)
        result = connectors.deliver({"type": "gitlab", "title": "Test"})
        assert result.status == "skipped"
        assert "sync disabled" in result.details["reason"]

    def test_azure_devops_sync_disabled(self) -> None:
        from core.connectors import AutomationConnectors

        settings = {
            "azure_devops": {"token": "pat", "organization": "org", "project": "proj"},
        }
        toggles = {"enforce_ticket_sync": False}
        connectors = AutomationConnectors(settings, toggles)
        result = connectors.deliver({"type": "azure_devops", "title": "Test"})
        assert result.status == "skipped"
        assert "sync disabled" in result.details["reason"]

    def test_github_sync_disabled(self) -> None:
        from core.connectors import AutomationConnectors

        settings = {
            "github": {"token": "ghp_test", "owner": "owner", "repo": "repo"},
        }
        toggles = {"enforce_ticket_sync": False}
        connectors = AutomationConnectors(settings, toggles)
        result = connectors.deliver({"type": "github", "title": "Test"})
        assert result.status == "skipped"
        assert "sync disabled" in result.details["reason"]

    def test_confluence_sync_disabled(self) -> None:
        from core.connectors import AutomationConnectors

        settings = {
            "confluence": {
                "base_url": "https://conf.test",
                "user_email": "u@t.com",
                "token": "t",
                "space_key": "S",
            },
        }
        toggles = {"enforce_ticket_sync": False}
        connectors = AutomationConnectors(settings, toggles)
        result = connectors.deliver({"type": "confluence", "title": "Test"})
        assert result.status == "skipped"
        assert "sync disabled" in result.details["reason"]


class TestEdgeCasesForCoverage:
    """Tests for edge cases to achieve 100% coverage."""

    @patch("requests.Session.request")
    def test_confluence_create_page_with_parent_id(
        self, mock_request: MagicMock
    ) -> None:
        """Test Confluence create_page with parent_page_id (lines 854, 856)."""
        mock_request.return_value = MockResponse(200, {"id": "123", "title": "Test"})
        connector = ConfluenceConnector(
            {
                "base_url": "https://test.atlassian.net/wiki",
                "user_email": "test@example.com",
                "token": "test-token",
                "space_key": "TEST",
                "parent_page_id": "456",
            }
        )
        result = connector.create_page({"title": "Test Page", "body": "Content"})
        assert result.status == "sent"
        # Verify parent_page_id was included in the request
        call_args = mock_request.call_args
        assert "ancestors" in call_args.kwargs.get("json", {})

    @patch("requests.Session.request")
    def test_slack_post_message_with_channel(self, mock_request: MagicMock) -> None:
        """Test Slack post_message with channel parameter (line 1056)."""
        mock_request.return_value = MockResponse(200)
        connector = SlackConnector(
            {"webhook_url": "https://hooks.slack.com/services/xxx"}
        )
        result = connector.post_message({"text": "Test", "channel": "#general"})
        assert result.status == "sent"
        # Verify channel was included in the request
        call_args = mock_request.call_args
        assert call_args.kwargs.get("json", {}).get("channel") == "#general"

    @patch("requests.Session.request")
    def test_servicenow_update_incident_all_fields(
        self, mock_request: MagicMock
    ) -> None:
        """Test ServiceNow update_incident with all optional fields (lines 1219-1229)."""
        mock_request.return_value = MockResponse(200, {"result": {"sys_id": "123"}})
        connector = ServiceNowConnector(
            {
                "instance_url": "https://test.service-now.com",
                "user": "admin",
                "password": "pass",
            }
        )
        result = connector.update_incident(
            {
                "sys_id": "123",
                "short_description": "Updated",
                "description": "Updated desc",
                "state": "2",
                "urgency": "1",
                "impact": "1",
                "assignment_group": "group1",
                "assigned_to": "user1",
                "close_code": "Solved",
                "close_notes": "Fixed the issue",
            }
        )
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_gitlab_create_issue_with_due_date(self, mock_request: MagicMock) -> None:
        """Test GitLab create_issue with due_date (line 1521)."""
        mock_request.return_value = MockResponse(
            201, {"id": 1, "iid": 1, "web_url": "https://gitlab.com/test"}
        )
        connector = GitLabConnector({"token": "glpat-test", "project_id": "123"})
        result = connector.create_issue(
            {
                "title": "Test Issue",
                "description": "Test desc",
                "labels": ["bug", "urgent"],
                "assignee_ids": [1, 2],
                "milestone_id": 5,
                "due_date": "2026-02-01",
            }
        )
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_gitlab_update_issue_with_assignee_ids(
        self, mock_request: MagicMock
    ) -> None:
        """Test GitLab update_issue with assignee_ids (line 1592)."""
        mock_request.return_value = MockResponse(200, {"id": 1, "iid": 1})
        connector = GitLabConnector({"token": "glpat-test", "project_id": "123"})
        result = connector.update_issue(
            {
                "issue_iid": 1,
                "title": "Updated",
                "description": "Updated desc",
                "labels": "bug,urgent",
                "state_event": "close",
                "assignee_ids": [1, 2],
            }
        )
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_gitlab_add_comment_invalid_json(self, mock_request: MagicMock) -> None:
        """Test GitLab add_comment with invalid JSON response (lines 1677-1678)."""
        mock_request.return_value = MockResponse(201, raise_on_json=True)
        connector = GitLabConnector({"token": "glpat-test", "project_id": "123"})
        result = connector.add_comment({"issue_iid": 1, "comment": "Test comment"})
        assert result.status == "sent"
        assert result.details.get("note_id") is None

    @patch("requests.Session.request")
    def test_azure_devops_create_work_item_with_all_fields(
        self, mock_request: MagicMock
    ) -> None:
        """Test Azure DevOps create_work_item with all optional fields (lines 1901, 2013)."""
        mock_request.return_value = MockResponse(
            200, {"id": 1, "url": "https://dev.azure.com/test"}
        )
        connector = AzureDevOpsConnector(
            {"token": "pat", "organization": "org", "project": "proj"}
        )
        result = connector.create_work_item(
            {
                "title": "Test Work Item",
                "description": "Test desc",
                "work_item_type": "Task",
                "assigned_to": "user@example.com",
                "area_path": "Project\\Area",
                "iteration_path": "Project\\Sprint1",
                "tags": "tag1,tag2",
                "priority": 1,
            }
        )
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_azure_devops_update_work_item_with_all_fields(
        self, mock_request: MagicMock
    ) -> None:
        """Test Azure DevOps update_work_item with all optional fields (lines 2109-2110)."""
        mock_request.return_value = MockResponse(200, {"id": 1})
        connector = AzureDevOpsConnector(
            {"token": "pat", "organization": "org", "project": "proj"}
        )
        result = connector.update_work_item(
            {
                "work_item_id": 1,
                "title": "Updated",
                "description": "Updated desc",
                "state": "Active",
                "assigned_to": "user@example.com",
                "tags": "tag1,tag2",
            }
        )
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_github_create_issue_with_all_fields(self, mock_request: MagicMock) -> None:
        """Test GitHub create_issue with all optional fields (lines 2308, 2379)."""
        mock_request.return_value = MockResponse(
            201, {"number": 1, "html_url": "https://github.com/test"}
        )
        connector = GitHubConnector(
            {"token": "ghp_test", "owner": "owner", "repo": "repo"}
        )
        result = connector.create_issue(
            {
                "title": "Test Issue",
                "body": "Test body",
                "labels": ["bug", "urgent"],
                "assignees": ["user1", "user2"],
                "milestone": 1,
            }
        )
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_github_update_issue_with_all_fields(self, mock_request: MagicMock) -> None:
        """Test GitHub update_issue with all optional fields (lines 2467-2468)."""
        mock_request.return_value = MockResponse(200, {"number": 1})
        connector = GitHubConnector(
            {"token": "ghp_test", "owner": "owner", "repo": "repo"}
        )
        result = connector.update_issue(
            {
                "issue_number": 1,
                "title": "Updated",
                "body": "Updated body",
                "state": "closed",
                "labels": ["bug"],
                "assignees": ["user1"],
            }
        )
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_github_add_comment_invalid_json(self, mock_request: MagicMock) -> None:
        """Test GitHub add_comment with invalid JSON response."""
        mock_request.return_value = MockResponse(201, raise_on_json=True)
        connector = GitHubConnector(
            {"token": "ghp_test", "owner": "owner", "repo": "repo"}
        )
        result = connector.add_comment({"issue_number": 1, "comment": "Test comment"})
        assert result.status == "sent"
        assert result.details.get("comment_id") is None

    @patch("requests.Session.request")
    def test_azure_devops_create_work_item_with_severity(
        self, mock_request: MagicMock
    ) -> None:
        """Test Azure DevOps create_work_item with severity (line 1901)."""
        mock_request.return_value = MockResponse(
            200, {"id": 1, "url": "https://dev.azure.com/test"}
        )
        connector = AzureDevOpsConnector(
            {"token": "pat", "organization": "org", "project": "proj"}
        )
        result = connector.create_work_item(
            {
                "title": "Test Work Item",
                "severity": "1 - Critical",
            }
        )
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_azure_devops_update_work_item_with_priority(
        self, mock_request: MagicMock
    ) -> None:
        """Test Azure DevOps update_work_item with priority (line 2013)."""
        mock_request.return_value = MockResponse(200, {"id": 1})
        connector = AzureDevOpsConnector(
            {"token": "pat", "organization": "org", "project": "proj"}
        )
        result = connector.update_work_item(
            {
                "work_item_id": 1,
                "priority": 1,
            }
        )
        assert result.status == "sent"

    @patch("requests.Session.request")
    def test_azure_devops_add_comment_invalid_json(
        self, mock_request: MagicMock
    ) -> None:
        """Test Azure DevOps add_comment with invalid JSON response (lines 2109-2110)."""
        mock_request.return_value = MockResponse(201, raise_on_json=True)
        connector = AzureDevOpsConnector(
            {"token": "pat", "organization": "org", "project": "proj"}
        )
        result = connector.add_comment({"work_item_id": 1, "comment": "Test comment"})
        assert result.status == "sent"
        assert result.details.get("comment_id") is None

    @patch("requests.Session.request")
    def test_github_update_issue_with_milestone(self, mock_request: MagicMock) -> None:
        """Test GitHub update_issue with milestone (line 2379)."""
        mock_request.return_value = MockResponse(200, {"number": 1})
        connector = GitHubConnector(
            {"token": "ghp_test", "owner": "owner", "repo": "repo"}
        )
        result = connector.update_issue(
            {
                "issue_number": 1,
                "milestone": 5,
            }
        )
        assert result.status == "sent"
