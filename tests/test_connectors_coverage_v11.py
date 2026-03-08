"""Comprehensive coverage tests for core.connectors — v11 swarm coverage push.

Targets: _mask, CircuitBreaker, RateLimiter, ConnectorOutcome, ConnectorHealth,
         _BaseConnector, JiraConnector, ServiceNowConnector, GitLabConnector,
         AzureDevOpsConnector, GitHubConnector, SlackConnector, ConfluenceConnector,
         AutomationConnectors (the top-level dispatcher).
"""

import os
import sys
import time
from unittest.mock import MagicMock, patch

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.connectors import (
    CircuitBreaker,
    CircuitState,
    ConnectorHealth,
    ConnectorOutcome,
    RateLimiter,
    _mask,
)


# ---------------------------------------------------------------------------
# _mask helper
# ---------------------------------------------------------------------------


class TestMaskHelper:
    def test_mask_none(self):
        assert _mask(None) is None

    def test_mask_empty(self):
        assert _mask("") == ""

    def test_mask_short_string(self):
        assert _mask("abc") == "***"
        assert _mask("ab") == "**"

    def test_mask_long_string(self):
        result = _mask("my-secret-token")
        assert result.startswith("my")
        assert result.endswith("en")
        assert "***" in result

    def test_mask_exactly_four_chars(self):
        assert _mask("abcd") == "****"

    def test_mask_five_chars(self):
        result = _mask("abcde")
        assert result == "ab***de"


# ---------------------------------------------------------------------------
# CircuitBreaker
# ---------------------------------------------------------------------------


class TestCircuitBreaker:
    def test_initial_state_is_closed(self):
        cb = CircuitBreaker()
        assert cb.state == CircuitState.CLOSED

    def test_allows_request_when_closed(self):
        cb = CircuitBreaker()
        assert cb.allow_request() is True

    def test_opens_after_threshold_failures(self):
        cb = CircuitBreaker(failure_threshold=3)
        for _ in range(3):
            cb.record_failure()
        assert cb.state == CircuitState.OPEN

    def test_blocks_requests_when_open(self):
        cb = CircuitBreaker(failure_threshold=2)
        cb.record_failure()
        cb.record_failure()
        assert cb.allow_request() is False

    def test_transitions_to_half_open_after_timeout(self):
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.01)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        time.sleep(0.02)
        assert cb.state == CircuitState.HALF_OPEN
        assert cb.allow_request() is True

    def test_half_open_closes_after_enough_successes(self):
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.01, half_open_max_calls=2)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.02)
        assert cb.state == CircuitState.HALF_OPEN
        cb.record_success()
        cb.record_success()
        assert cb.state == CircuitState.CLOSED

    def test_half_open_reopens_on_failure(self):
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.01)
        cb.record_failure()
        cb.record_failure()
        time.sleep(0.02)
        _ = cb.state  # transition to HALF_OPEN
        cb.record_failure()
        assert cb.state == CircuitState.OPEN

    def test_success_resets_failure_count_when_closed(self):
        cb = CircuitBreaker(failure_threshold=5)
        cb.record_failure()
        cb.record_failure()
        cb.record_success()
        # Should NOT be open because success reset the count
        cb.record_failure()
        cb.record_failure()
        cb.record_failure()
        # Total failures: 3 after reset — still below 5
        assert cb.state == CircuitState.CLOSED

    def test_circuit_state_enum_values(self):
        assert CircuitState.CLOSED.value == "closed"
        assert CircuitState.OPEN.value == "open"
        assert CircuitState.HALF_OPEN.value == "half_open"


# ---------------------------------------------------------------------------
# RateLimiter
# ---------------------------------------------------------------------------


class TestRateLimiter:
    def test_acquires_within_burst(self):
        rl = RateLimiter(requests_per_second=100.0, burst_size=10)
        for _ in range(10):
            assert rl.acquire(timeout=0.1) is True

    def test_rate_limit_exceeded_returns_false(self):
        rl = RateLimiter(requests_per_second=1.0, burst_size=1)
        assert rl.acquire(timeout=0.1) is True
        # Second request should fail quickly
        assert rl.acquire(timeout=0.05) is False

    def test_tokens_replenish_over_time(self):
        rl = RateLimiter(requests_per_second=100.0, burst_size=2)
        assert rl.acquire(timeout=0.01) is True
        assert rl.acquire(timeout=0.01) is True
        time.sleep(0.05)  # Let tokens replenish
        assert rl.acquire(timeout=0.01) is True


# ---------------------------------------------------------------------------
# ConnectorOutcome
# ---------------------------------------------------------------------------


class TestConnectorOutcome:
    def test_to_dict(self):
        outcome = ConnectorOutcome(status="sent", details={"key": "123"})
        d = outcome.to_dict()
        assert d["status"] == "sent"
        assert d["key"] == "123"

    def test_success_property(self):
        assert ConnectorOutcome("sent", {}).success is True
        assert ConnectorOutcome("success", {}).success is True
        assert ConnectorOutcome("fetched", {}).success is True
        assert ConnectorOutcome("failed", {}).success is False
        assert ConnectorOutcome("skipped", {}).success is False

    def test_data_property(self):
        outcome = ConnectorOutcome("success", {"data": [1, 2, 3]})
        assert outcome.data == [1, 2, 3]

    def test_data_property_missing(self):
        outcome = ConnectorOutcome("success", {})
        assert outcome.data is None

    def test_to_dict_sets_default_status(self):
        outcome = ConnectorOutcome("sent", {"foo": "bar"})
        d = outcome.to_dict()
        assert d["status"] == "sent"
        assert d["foo"] == "bar"


# ---------------------------------------------------------------------------
# ConnectorHealth
# ---------------------------------------------------------------------------


class TestConnectorHealth:
    def test_to_dict(self):
        h = ConnectorHealth(healthy=True, latency_ms=42.5, message="OK")
        d = h.to_dict()
        assert d["healthy"] is True
        assert d["latency_ms"] == 42.5
        assert d["message"] == "OK"
        assert "checked_at" in d

    def test_unhealthy(self):
        h = ConnectorHealth(healthy=False, latency_ms=0.0, message="Connection refused")
        assert h.healthy is False

    def test_default_checked_at(self):
        h = ConnectorHealth(healthy=True, latency_ms=1.0, message="up")
        # checked_at should be a valid ISO timestamp
        assert "T" in h.checked_at


# ---------------------------------------------------------------------------
# JiraConnector
# ---------------------------------------------------------------------------


class TestJiraConnector:
    def test_init_basic(self):
        from core.connectors import JiraConnector

        jira = JiraConnector({
            "url": "https://test.atlassian.net/",
            "user_email": "test@example.com",
            "token": "test-token",
            "project_key": "TEST",
        })
        assert jira.configured is True
        assert jira.base_url == "https://test.atlassian.net"
        assert jira.project_key == "TEST"
        assert jira.default_issue_type == "Task"

    def test_not_configured_missing_url(self):
        from core.connectors import JiraConnector

        jira = JiraConnector({})
        assert jira.configured is False

    def test_create_issue_not_configured(self):
        from core.connectors import JiraConnector

        jira = JiraConnector({})
        result = jira.create_issue({"summary": "Test"})
        assert result.status == "skipped"
        assert result.success is False

    def test_token_from_env(self):
        from core.connectors import JiraConnector

        with patch.dict(os.environ, {"MY_JIRA_TOKEN": "env-token"}):
            jira = JiraConnector({
                "url": "https://test.atlassian.net",
                "user_email": "test@example.com",
                "token_env": "MY_JIRA_TOKEN",
                "project_key": "PROJ",
            })
            assert jira.token == "env-token"

    def test_token_env_missing_falls_back(self):
        from core.connectors import JiraConnector

        jira = JiraConnector({
            "url": "https://test.atlassian.net",
            "user_email": "test@example.com",
            "token": "fallback-token",
            "token_env": "NONEXISTENT_ENV_VAR",
            "project_key": "PROJ",
        })
        assert jira.token == "fallback-token"


# ---------------------------------------------------------------------------
# ServiceNowConnector
# ---------------------------------------------------------------------------


class TestServiceNowConnector:
    def test_init(self):
        from core.connectors import ServiceNowConnector

        sn = ServiceNowConnector({
            "url": "https://dev12345.service-now.com",
            "user": "admin",
            "password": "password123",
        })
        assert sn.configured is True

    def test_not_configured(self):
        from core.connectors import ServiceNowConnector

        sn = ServiceNowConnector({})
        assert sn.configured is False

    def test_create_incident_not_configured(self):
        from core.connectors import ServiceNowConnector

        sn = ServiceNowConnector({})
        result = sn.create_incident({"summary": "test"})
        assert result.status == "skipped"


# ---------------------------------------------------------------------------
# GitLabConnector
# ---------------------------------------------------------------------------


class TestGitLabConnector:
    def test_init(self):
        from core.connectors import GitLabConnector

        gl = GitLabConnector({
            "url": "https://gitlab.example.com",
            "token": "glpat-xxx",
            "project_id": "42",
        })
        assert gl.configured is True

    def test_not_configured(self):
        from core.connectors import GitLabConnector

        gl = GitLabConnector({})
        assert gl.configured is False

    def test_create_issue_not_configured(self):
        from core.connectors import GitLabConnector

        gl = GitLabConnector({})
        result = gl.create_issue({"summary": "test"})
        assert result.status == "skipped"


# ---------------------------------------------------------------------------
# AzureDevOpsConnector
# ---------------------------------------------------------------------------


class TestAzureDevOpsConnector:
    def test_init(self):
        from core.connectors import AzureDevOpsConnector

        az = AzureDevOpsConnector({
            "organization": "myorg",
            "project": "myproject",
            "token": "pat-xxx",
        })
        assert az.configured is True

    def test_not_configured(self):
        from core.connectors import AzureDevOpsConnector

        az = AzureDevOpsConnector({})
        assert az.configured is False


# ---------------------------------------------------------------------------
# GitHubConnector
# ---------------------------------------------------------------------------


class TestGitHubConnector:
    def test_init(self):
        from core.connectors import GitHubConnector

        gh = GitHubConnector({
            "token": "ghp_xxx",
            "owner": "myorg",
            "repo": "myrepo",
        })
        assert gh.configured is True

    def test_not_configured(self):
        from core.connectors import GitHubConnector

        gh = GitHubConnector({})
        assert gh.configured is False


# ---------------------------------------------------------------------------
# SlackConnector
# ---------------------------------------------------------------------------


class TestSlackConnector:
    def test_init_with_webhook(self):
        from core.connectors import SlackConnector

        sl = SlackConnector({
            "webhook_url": "https://hooks.slack.com/services/T00/B00/xxx",
        })
        assert sl.default_webhook == "https://hooks.slack.com/services/T00/B00/xxx"

    def test_init_no_webhook(self):
        from core.connectors import SlackConnector

        sl = SlackConnector({})
        assert sl.default_webhook is None

    def test_post_message_not_configured(self):
        from core.connectors import SlackConnector

        sl = SlackConnector({})
        result = sl.post_message({"text": "test"})
        assert result.status == "skipped"

    def test_webhook_from_env(self):
        from core.connectors import SlackConnector

        with patch.dict(os.environ, {"SLACK_WH": "https://hooks.slack.com/xxx"}):
            sl = SlackConnector({"webhook_env": "SLACK_WH"})
            assert sl.default_webhook == "https://hooks.slack.com/xxx"


# ---------------------------------------------------------------------------
# ConfluenceConnector
# ---------------------------------------------------------------------------


class TestConfluenceConnector:
    def test_init(self):
        from core.connectors import ConfluenceConnector

        cf = ConfluenceConnector({
            "base_url": "https://wiki.atlassian.net",
            "user_email": "test@example.com",
            "token": "token-xxx",
            "space_key": "DEV",
        })
        assert cf.configured is True

    def test_not_configured(self):
        from core.connectors import ConfluenceConnector

        cf = ConfluenceConnector({})
        assert cf.configured is False

    def test_create_page_not_configured(self):
        from core.connectors import ConfluenceConnector

        cf = ConfluenceConnector({})
        result = cf.create_page({"title": "test"})
        assert result.status == "skipped"


# ---------------------------------------------------------------------------
# AutomationConnectors (top-level dispatcher)
# ---------------------------------------------------------------------------


class TestAutomationConnectors:
    def _make_ac(self):
        from core.connectors import AutomationConnectors
        return AutomationConnectors(
            overlay_settings={},
            toggles={},
        )

    def test_init(self):
        ac = self._make_ac()
        assert hasattr(ac, "jira")
        assert hasattr(ac, "slack")
        assert hasattr(ac, "confluence")
        assert hasattr(ac, "servicenow")
        assert hasattr(ac, "gitlab")
        assert hasattr(ac, "azure_devops")
        assert hasattr(ac, "github")

    def test_deliver_jira_unconfigured(self):
        ac = self._make_ac()
        result = ac.deliver({"type": "jira_issue", "summary": "test"})
        assert isinstance(result, ConnectorOutcome)
        # Should skip because jira is not configured
        assert result.status == "skipped"

    def test_deliver_slack_unconfigured(self):
        ac = self._make_ac()
        result = ac.deliver({"type": "slack", "text": "test"})
        assert isinstance(result, ConnectorOutcome)
        assert result.status == "skipped"

    def test_deliver_confluence_unconfigured(self):
        ac = self._make_ac()
        result = ac.deliver({"type": "confluence_page", "title": "test"})
        assert isinstance(result, ConnectorOutcome)
        assert result.status == "skipped"

    def test_enforce_sync(self):
        from core.connectors import AutomationConnectors
        ac = AutomationConnectors(
            overlay_settings={},
            toggles={"enforce_ticket_sync": False},
        )
        result = ac.deliver({"type": "jira_issue", "summary": "test"})
        assert result.status == "skipped"

    def test_feature_flag_check(self):
        ac = self._make_ac()
        assert ac._check_feature_flag("test.flag") is True  # default

    def test_feature_flag_with_provider(self):
        from core.connectors import AutomationConnectors
        mock_provider = MagicMock()
        mock_provider.bool.return_value = False
        ac = AutomationConnectors(
            overlay_settings={},
            toggles={},
            flag_provider=mock_provider,
        )
        assert ac._check_feature_flag("test.flag") is False


# ---------------------------------------------------------------------------
# _BaseConnector
# ---------------------------------------------------------------------------


class TestBaseConnector:
    def test_get_metrics(self):
        from core.connectors import _BaseConnector

        bc = _BaseConnector()
        metrics = bc.get_metrics()
        assert metrics["request_count"] == 0
        assert metrics["error_count"] == 0
        assert metrics["error_rate"] == 0.0
        assert metrics["circuit_state"] == "closed"

    def test_health_check_not_implemented(self):
        from core.connectors import _BaseConnector

        bc = _BaseConnector()
        with pytest.raises(NotImplementedError):
            bc.health_check()
