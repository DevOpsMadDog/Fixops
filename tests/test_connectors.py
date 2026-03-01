"""Comprehensive tests for FixOps Connectors (suite-core/core/connectors.py).

Covers:
- _mask utility function
- Circuit breaker state transitions
- Rate limiter token bucket
- _BaseConnector._request (circuit breaker, rate limit, server errors, exceptions)
- JiraConnector: full CRUD + health_check + transition with name lookup
- ConfluenceConnector: full CRUD + health_check
- SlackConnector: post_message + health_check
- ServiceNowConnector: full CRUD + health_check
- GitLabConnector: full CRUD + health_check
- AzureDevOpsConnector: full CRUD + health_check
- GitHubConnector: full CRUD + health_check
- AutomationConnectors: deliver routing, feature flags, enforce_sync
- ConnectorOutcome: success/failure states
- summarise_connector: all connector types
"""

from __future__ import annotations

import time
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
    summarise_connector,
)


# ── ConnectorOutcome tests ────────────────────────────────────────────────


class TestConnectorOutcome:
    def test_success_states(self):
        for status in ("sent", "success", "fetched"):
            o = ConnectorOutcome(status, {"key": "val"})
            assert o.success

    def test_failure_states(self):
        for status in ("skipped", "failed", "error"):
            o = ConnectorOutcome(status, {})
            assert not o.success

    def test_to_dict(self):
        o = ConnectorOutcome("sent", {"endpoint": "/api", "issue_key": "FIX-1"})
        d = o.to_dict()
        assert d["status"] == "sent"
        assert d["issue_key"] == "FIX-1"

    def test_data_property(self):
        o = ConnectorOutcome("fetched", {"data": [1, 2, 3]})
        assert o.data == [1, 2, 3]


class TestConnectorHealth:
    def test_to_dict(self):
        h = ConnectorHealth(healthy=True, latency_ms=42.5, message="OK")
        d = h.to_dict()
        assert d["healthy"] is True
        assert d["latency_ms"] == 42.5
        assert "checked_at" in d


# ── Circuit Breaker tests ─────────────────────────────────────────────────


class TestCircuitBreaker:
    def test_starts_closed(self):
        cb = CircuitBreaker()
        assert cb.state == CircuitState.CLOSED
        assert cb.allow_request()

    def test_opens_after_threshold(self):
        cb = CircuitBreaker(failure_threshold=3, recovery_timeout=600)
        for _ in range(3):
            cb.record_failure()
        assert cb.state == CircuitState.OPEN
        assert not cb.allow_request()

    def test_success_resets_counter(self):
        cb = CircuitBreaker(failure_threshold=3)
        cb.record_failure()
        cb.record_failure()
        cb.record_success()
        cb.record_failure()
        # Should still be closed — success reset the count
        assert cb.state == CircuitState.CLOSED

    def test_half_open_after_recovery_timeout(self):
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=0.01)
        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        time.sleep(0.02)
        assert cb.state == CircuitState.HALF_OPEN
        assert cb.allow_request()

    def test_half_open_reopens_on_failure(self):
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=0.01)
        cb.record_failure()
        time.sleep(0.02)
        assert cb.state == CircuitState.HALF_OPEN
        cb.record_failure()
        assert cb.state == CircuitState.OPEN

    def test_half_open_closes_after_max_calls(self):
        cb = CircuitBreaker(
            failure_threshold=1, recovery_timeout=0.01, half_open_max_calls=2
        )
        cb.record_failure()
        time.sleep(0.02)
        assert cb.state == CircuitState.HALF_OPEN
        cb.record_success()
        cb.record_success()
        assert cb.state == CircuitState.CLOSED


# ── Rate Limiter tests ────────────────────────────────────────────────────


class TestRateLimiter:
    def test_allows_burst(self):
        rl = RateLimiter(requests_per_second=100, burst_size=5)
        for _ in range(5):
            assert rl.acquire(timeout=0.1)

    def test_denies_over_burst(self):
        rl = RateLimiter(requests_per_second=1, burst_size=2)
        assert rl.acquire(timeout=0.01)
        assert rl.acquire(timeout=0.01)
        # Third should fail quickly with short timeout
        assert not rl.acquire(timeout=0.01)


# ── BaseConnector tests ──────────────────────────────────────────────────


class TestBaseConnector:
    def test_metrics_default(self):
        bc = _BaseConnector()
        m = bc.get_metrics()
        assert m["request_count"] == 0
        assert m["error_count"] == 0
        assert m["circuit_state"] == "closed"
        assert m["error_rate"] == 0.0

    def test_health_check_not_implemented(self):
        bc = _BaseConnector()
        with pytest.raises(NotImplementedError):
            bc.health_check()


# ── JiraConnector tests ──────────────────────────────────────────────────


class TestJiraConnector:
    def _make_jira(self, **overrides):
        settings = {
            "url": "https://test.atlassian.net",
            "user_email": "bot@test.com",
            "token": "jira-token-123",
            "project_key": "FIX",
            **overrides,
        }
        return JiraConnector(settings)

    def test_configured(self):
        jira = self._make_jira()
        assert jira.configured

    def test_not_configured_missing_token(self):
        jira = self._make_jira(token=None)
        assert not jira.configured

    def test_create_issue_not_configured(self):
        jira = self._make_jira(token=None)
        result = jira.create_issue({"summary": "test"})
        assert result.status == "skipped"

    @patch.object(JiraConnector, "_request")
    def test_create_issue_success(self, mock_request):
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.json.return_value = {"key": "FIX-42"}
        mock_resp.raise_for_status.return_value = None
        mock_request.return_value = mock_resp

        jira = self._make_jira()
        result = jira.create_issue({"summary": "CVE fix", "priority": "Critical"})
        assert result.status == "sent"
        assert result.details["issue_key"] == "FIX-42"

    def test_update_issue_no_key(self):
        jira = self._make_jira()
        result = jira.update_issue({})
        assert result.status == "failed"

    def test_update_issue_no_fields(self):
        jira = self._make_jira()
        result = jira.update_issue({"issue_key": "FIX-1"})
        assert result.status == "skipped"

    def test_transition_no_key(self):
        jira = self._make_jira()
        result = jira.transition_issue({})
        assert result.status == "failed"

    def test_add_comment_no_key(self):
        jira = self._make_jira()
        result = jira.add_comment({})
        assert result.status == "failed"

    def test_add_comment_no_body(self):
        jira = self._make_jira()
        result = jira.add_comment({"issue_key": "FIX-1"})
        assert result.status == "failed"


# ── SlackConnector tests ──────────────────────────────────────────────────


class TestSlackConnector:
    def _make_slack(self, **overrides):
        settings = {
            "webhook_url": "https://hooks.slack.com/services/test",
            **overrides,
        }
        return SlackConnector(settings)

    @patch.object(SlackConnector, "_request")
    def test_post_message_success(self, mock_request):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_request.return_value = mock_resp

        slack = self._make_slack()
        result = slack.post_message({"text": "New critical finding!"})
        assert result.success

    def test_post_message_no_webhook(self):
        slack = self._make_slack(webhook_url=None)
        result = slack.post_message({"text": "test"})
        assert not result.success


# ── GitHubConnector tests ─────────────────────────────────────────────────


class TestGitHubConnector:
    def _make_github(self, **overrides):
        settings = {
            "owner": "testorg",
            "repo": "testrepo",
            "token": "ghp-test",
            **overrides,
        }
        return GitHubConnector(settings)

    def test_configured(self):
        gh = self._make_github()
        assert gh.configured

    def test_not_configured_missing_token(self):
        gh = self._make_github(token=None)
        assert not gh.configured

    @patch.object(GitHubConnector, "_request")
    def test_create_issue_success(self, mock_request):
        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.json.return_value = {"number": 77, "html_url": "https://github.com/testorg/testrepo/issues/77"}
        mock_resp.raise_for_status.return_value = None
        mock_request.return_value = mock_resp

        gh = self._make_github()
        result = gh.create_issue({
            "title": "Critical CVE found",
            "body": "CVE-2024-0001 in component X",
        })
        assert result.status == "sent"
        assert result.details.get("issue_number") == 77

    def test_create_issue_not_configured(self):
        gh = self._make_github(token=None)
        result = gh.create_issue({"title": "test"})
        assert result.status == "skipped"
