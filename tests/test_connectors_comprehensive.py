"""
Comprehensive unit tests for suite-core/core/connectors.py.

Covers:
  - _mask helper utility
  - CircuitBreaker: state transitions (closed, open, half_open), thresholds
  - RateLimiter: token bucket acquire, burst, timeout
  - ConnectorOutcome: status, success, data, to_dict
  - ConnectorHealth: serialization
  - _BaseConnector: request wrapper, circuit breaker integration, rate limiter, metrics
  - JiraConnector: create_issue, update_issue, transition_issue, add_comment,
                   get_issue, search_issues, list_project_issues, get_comments,
                   health_check, unconfigured guard
  - ConfluenceConnector: create_page, update_page, get_page, search_pages,
                          list_pages, health_check, unconfigured guard
  - SlackConnector: post_message, health_check, unconfigured guard
  - ServiceNowConnector: create_incident, update_incident, add_work_note,
                          get_incident, search_incidents, list_incidents,
                          health_check, unconfigured guard
  - GitLabConnector: create_issue, update_issue, add_comment, get_issue,
                     search_issues, list_issues, health_check, unconfigured guard
  - AzureDevOpsConnector: create_work_item, update_work_item, add_comment,
                           get_work_item, search_work_items, list_work_items,
                           health_check, unconfigured guard
  - GitHubConnector: create_issue, update_issue, add_comment, get_issue,
                     search_issues, list_issues, get_comments, health_check,
                     unconfigured guard
  - AutomationConnectors: deliver routing, feature flags, ticket sync
  - summarise_connector: diagnostic output for each connector type
"""

from __future__ import annotations

import time
from threading import Lock
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from core.connectors import (
    _mask,
    CircuitBreaker,
    CircuitState,
    RateLimiter,
    ConnectorOutcome,
    ConnectorHealth,
    _BaseConnector,
    JiraConnector,
    ConfluenceConnector,
    SlackConnector,
    ServiceNowConnector,
    GitLabConnector,
    AzureDevOpsConnector,
    GitHubConnector,
    AutomationConnectors,
    summarise_connector,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def jira_settings():
    return {
        "url": "https://test.atlassian.net",
        "user_email": "user@test.com",
        "token": "jira-connector-credential",
        "project_key": "TEST",
        "default_issue_type": "Bug",
    }


@pytest.fixture
def confluence_settings():
    return {
        "base_url": "https://test.atlassian.net/wiki",
        "space_key": "TESTSPACE",
        "user": "user@test.com",
        "token": "confluence-connector-credential",
        "parent_page_id": "12345",
    }


@pytest.fixture
def slack_settings():
    return {"webhook_url": "https://hooks.slack.com/services/T00/B00/xxx"}


@pytest.fixture
def servicenow_settings():
    return {
        "instance_url": "https://test.service-now.com",
        "user": "admin",
        "token": "snow-token",
        "assignment_group": "Security",
    }


@pytest.fixture
def gitlab_settings():
    return {
        "base_url": "https://gitlab.com",
        "project_id": "12345",
        "token": "glpat-test-token",
    }


@pytest.fixture
def azure_devops_settings():
    return {
        "organization": "test-org",
        "project": "TestProject",
        "token": "ado-pat-token",
    }


@pytest.fixture
def github_settings():
    return {
        "owner": "test-owner",
        "repo": "test-repo",
        "token": "ghp_test_token",
    }


def _mock_response(status_code=200, json_data=None, text=""):
    """Create a mock requests.Response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    if json_data is not None:
        resp.json.return_value = json_data
    else:
        resp.json.side_effect = ValueError("No JSON")
    resp.raise_for_status.return_value = None
    if status_code >= 400:
        from requests import HTTPError
        resp.raise_for_status.side_effect = HTTPError(f"{status_code} Error")
    return resp


# ===========================================================================
# _mask helper
# ===========================================================================


class TestMask:
    def test_none_value(self):
        assert _mask(None) is None

    def test_empty_string(self):
        assert _mask("") == ""

    def test_short_string(self):
        assert _mask("abc") == "***"

    def test_four_char_string(self):
        assert _mask("abcd") == "****"

    def test_long_string(self):
        result = _mask("abcdef")
        assert result == "ab***ef"

    def test_token_mask(self):
        result = _mask("ghp_1234567890abcdef")
        assert result.startswith("gh")
        assert result.endswith("ef")
        assert "***" in result


# ===========================================================================
# CircuitBreaker
# ===========================================================================


class TestCircuitBreaker:
    def test_initial_state_is_closed(self):
        cb = CircuitBreaker()
        assert cb.state == CircuitState.CLOSED

    def test_allow_request_when_closed(self):
        cb = CircuitBreaker()
        assert cb.allow_request() is True

    def test_stays_closed_below_threshold(self):
        cb = CircuitBreaker(failure_threshold=5)
        for _ in range(4):
            cb.record_failure()
        assert cb.state == CircuitState.CLOSED
        assert cb.allow_request() is True

    def test_opens_at_threshold(self):
        cb = CircuitBreaker(failure_threshold=3)
        for _ in range(3):
            cb.record_failure()
        assert cb.state == CircuitState.OPEN
        assert cb.allow_request() is False

    def test_transitions_to_half_open_after_timeout(self):
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=0.01)
        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        time.sleep(0.02)
        assert cb.state == CircuitState.HALF_OPEN
        assert cb.allow_request() is True

    def test_half_open_to_closed_after_successes(self):
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=0.01, half_open_max_calls=2)
        cb.record_failure()
        time.sleep(0.02)
        assert cb.state == CircuitState.HALF_OPEN
        cb.record_success()
        cb.record_success()
        assert cb.state == CircuitState.CLOSED

    def test_half_open_to_open_on_failure(self):
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=0.01)
        cb.record_failure()
        time.sleep(0.02)
        assert cb.state == CircuitState.HALF_OPEN
        cb.record_failure()
        assert cb.state == CircuitState.OPEN

    def test_success_resets_failure_count(self):
        cb = CircuitBreaker(failure_threshold=5)
        for _ in range(4):
            cb.record_failure()
        cb.record_success()
        # After reset, need 5 more failures to open
        for _ in range(4):
            cb.record_failure()
        assert cb.state == CircuitState.CLOSED


# ===========================================================================
# RateLimiter
# ===========================================================================


class TestRateLimiter:
    def test_initial_burst_available(self):
        rl = RateLimiter(requests_per_second=100.0, burst_size=10)
        for _ in range(10):
            assert rl.acquire(timeout=0.01) is True

    def test_acquire_fails_after_burst(self):
        rl = RateLimiter(requests_per_second=0.1, burst_size=1)
        assert rl.acquire(timeout=0.01) is True
        # Second request should fail quickly with tiny timeout
        assert rl.acquire(timeout=0.01) is False

    def test_acquire_replenishes(self):
        rl = RateLimiter(requests_per_second=100.0, burst_size=1)
        assert rl.acquire(timeout=0.01) is True
        time.sleep(0.02)
        assert rl.acquire(timeout=0.05) is True


# ===========================================================================
# ConnectorOutcome
# ===========================================================================


class TestConnectorOutcome:
    def test_success_statuses(self):
        for status in ("sent", "success", "fetched"):
            outcome = ConnectorOutcome(status=status, details={})
            assert outcome.success is True

    def test_failure_statuses(self):
        for status in ("failed", "skipped", "error"):
            outcome = ConnectorOutcome(status=status, details={})
            assert outcome.success is False

    def test_data_property(self):
        outcome = ConnectorOutcome(status="fetched", details={"data": {"key": "value"}})
        assert outcome.data == {"key": "value"}

    def test_data_property_missing(self):
        outcome = ConnectorOutcome(status="sent", details={})
        assert outcome.data is None

    def test_to_dict(self):
        outcome = ConnectorOutcome(status="sent", details={"endpoint": "/test"})
        d = outcome.to_dict()
        assert d["status"] == "sent"
        assert d["endpoint"] == "/test"

    def test_to_dict_preserves_existing_status(self):
        outcome = ConnectorOutcome(status="sent", details={"status": "custom"})
        d = outcome.to_dict()
        assert d["status"] == "custom"


# ===========================================================================
# ConnectorHealth
# ===========================================================================


class TestConnectorHealth:
    def test_to_dict(self):
        health = ConnectorHealth(healthy=True, latency_ms=42.5, message="OK")
        d = health.to_dict()
        assert d["healthy"] is True
        assert d["latency_ms"] == 42.5
        assert d["message"] == "OK"
        assert "checked_at" in d

    def test_unhealthy(self):
        health = ConnectorHealth(healthy=False, latency_ms=0, message="Down")
        assert health.healthy is False


# ===========================================================================
# JiraConnector
# ===========================================================================


class TestJiraConnector:
    def test_configured_when_all_fields_set(self, jira_settings):
        conn = JiraConnector(jira_settings)
        assert conn.configured is True

    def test_not_configured_when_missing_fields(self):
        conn = JiraConnector({})
        assert conn.configured is False

    def test_create_issue_skipped_when_not_configured(self):
        conn = JiraConnector({})
        result = conn.create_issue({"summary": "test"})
        assert result.status == "skipped"

    @patch.object(_BaseConnector, "_request")
    def test_create_issue_success(self, mock_req, jira_settings):
        mock_req.return_value = _mock_response(201, {"key": "TEST-123"})
        conn = JiraConnector(jira_settings)
        result = conn.create_issue({"summary": "Test issue"})
        assert result.status == "sent"
        assert result.details["issue_key"] == "TEST-123"

    def test_update_issue_skipped_when_not_configured(self):
        conn = JiraConnector({})
        result = conn.update_issue({"issue_key": "TEST-1"})
        assert result.status == "skipped"

    @patch.object(_BaseConnector, "_request")
    def test_update_issue_success(self, mock_req, jira_settings):
        mock_req.return_value = _mock_response(204)
        conn = JiraConnector(jira_settings)
        result = conn.update_issue({"issue_key": "TEST-1", "summary": "Updated"})
        assert result.status == "sent"

    def test_update_issue_no_fields(self, jira_settings):
        conn = JiraConnector(jira_settings)
        result = conn.update_issue({"issue_key": "TEST-1"})
        assert result.status == "skipped"
        assert "no fields" in result.details["reason"]

    def test_update_issue_no_key(self, jira_settings):
        conn = JiraConnector(jira_settings)
        result = conn.update_issue({})
        assert result.status == "failed"

    def test_transition_issue_no_key(self, jira_settings):
        conn = JiraConnector(jira_settings)
        result = conn.transition_issue({})
        assert result.status == "failed"

    def test_transition_issue_no_transition(self, jira_settings):
        conn = JiraConnector(jira_settings)
        result = conn.transition_issue({"issue_key": "TEST-1"})
        assert result.status == "failed"

    @patch.object(_BaseConnector, "_request")
    def test_transition_issue_by_id(self, mock_req, jira_settings):
        mock_req.return_value = _mock_response(204)
        conn = JiraConnector(jira_settings)
        result = conn.transition_issue({"issue_key": "TEST-1", "transition_id": "31"})
        assert result.status == "sent"

    def test_add_comment_no_key(self, jira_settings):
        conn = JiraConnector(jira_settings)
        result = conn.add_comment({})
        assert result.status == "failed"

    def test_add_comment_no_body(self, jira_settings):
        conn = JiraConnector(jira_settings)
        result = conn.add_comment({"issue_key": "TEST-1"})
        assert result.status == "failed"

    @patch.object(_BaseConnector, "_request")
    def test_add_comment_success(self, mock_req, jira_settings):
        mock_req.return_value = _mock_response(201, {"id": "10001"})
        conn = JiraConnector(jira_settings)
        result = conn.add_comment({"issue_key": "TEST-1", "comment": "Hello"})
        assert result.status == "sent"

    @patch.object(_BaseConnector, "_request")
    def test_get_issue_success(self, mock_req, jira_settings):
        mock_req.return_value = _mock_response(200, {"key": "TEST-1", "fields": {}})
        conn = JiraConnector(jira_settings)
        result = conn.get_issue("TEST-1")
        assert result.status == "fetched"
        assert result.success is True

    @patch.object(_BaseConnector, "_request")
    def test_get_issue_with_fields(self, mock_req, jira_settings):
        mock_req.return_value = _mock_response(200, {"key": "TEST-1"})
        conn = JiraConnector(jira_settings)
        result = conn.get_issue("TEST-1", fields=["summary", "status"])
        assert result.status == "fetched"

    @patch.object(_BaseConnector, "_request")
    def test_search_issues_success(self, mock_req, jira_settings):
        mock_req.return_value = _mock_response(200, {"total": 2, "issues": [{"key": "TEST-1"}, {"key": "TEST-2"}]})
        conn = JiraConnector(jira_settings)
        result = conn.search_issues("project = TEST")
        assert result.status == "fetched"
        assert result.details["total"] == 2

    @patch.object(_BaseConnector, "_request")
    def test_list_project_issues(self, mock_req, jira_settings):
        mock_req.return_value = _mock_response(200, {"total": 1, "issues": [{"key": "TEST-1"}]})
        conn = JiraConnector(jira_settings)
        result = conn.list_project_issues(status="Open")
        assert result.status == "fetched"

    @patch.object(_BaseConnector, "_request")
    def test_get_comments_success(self, mock_req, jira_settings):
        mock_req.return_value = _mock_response(200, {"comments": [{"id": "1"}], "total": 1})
        conn = JiraConnector(jira_settings)
        result = conn.get_comments("TEST-1")
        assert result.status == "fetched"
        assert result.details["total"] == 1

    @patch.object(_BaseConnector, "_request")
    def test_health_check_healthy(self, mock_req, jira_settings):
        mock_req.return_value = _mock_response(200, {})
        conn = JiraConnector(jira_settings)
        health = conn.health_check()
        assert health.healthy is True

    def test_health_check_not_configured(self):
        conn = JiraConnector({})
        health = conn.health_check()
        assert health.healthy is False

    def test_token_from_env(self, monkeypatch):
        monkeypatch.setenv("JIRA_TOKEN_VAR", "env-token-value")
        conn = JiraConnector({
            "url": "https://jira.example.com",
            "user_email": "u@e.com",
            "project_key": "P",
            "token_env": "JIRA_TOKEN_VAR",
        })
        assert conn.token == "env-token-value"
        assert conn.configured is True


# ===========================================================================
# ConfluenceConnector
# ===========================================================================


class TestConfluenceConnector:
    def test_configured(self, confluence_settings):
        conn = ConfluenceConnector(confluence_settings)
        assert conn.configured is True

    def test_not_configured(self):
        conn = ConfluenceConnector({})
        assert conn.configured is False

    def test_create_page_skipped_when_not_configured(self):
        conn = ConfluenceConnector({})
        result = conn.create_page({"title": "Test"})
        assert result.status == "skipped"

    @patch.object(_BaseConnector, "_request")
    def test_create_page_success(self, mock_req, confluence_settings):
        mock_req.return_value = _mock_response(200, {"id": "54321"})
        conn = ConfluenceConnector(confluence_settings)
        result = conn.create_page({"title": "Test Page", "body": "<p>Hello</p>"})
        assert result.status == "sent"
        assert result.details["page_id"] == "54321"

    @patch.object(_BaseConnector, "_request")
    def test_create_page_with_parent(self, mock_req, confluence_settings):
        mock_req.return_value = _mock_response(200, {"id": "54321"})
        conn = ConfluenceConnector(confluence_settings)
        result = conn.create_page({"title": "Child", "parent_page_id": "99"})
        assert result.status == "sent"

    def test_update_page_no_page_id(self, confluence_settings):
        conn = ConfluenceConnector(confluence_settings)
        result = conn.update_page({})
        assert result.status == "failed"

    @patch.object(_BaseConnector, "_request")
    def test_get_page_success(self, mock_req, confluence_settings):
        mock_req.return_value = _mock_response(200, {"id": "123", "title": "Test", "version": {"number": 1}})
        conn = ConfluenceConnector(confluence_settings)
        result = conn.get_page("123")
        assert result.status == "fetched"

    @patch.object(_BaseConnector, "_request")
    def test_search_pages_success(self, mock_req, confluence_settings):
        mock_req.return_value = _mock_response(200, {"results": [{"id": "1"}]})
        conn = ConfluenceConnector(confluence_settings)
        result = conn.search_pages("space = TESTSPACE AND type = page")
        assert result.status == "fetched"
        assert result.details["count"] == 1

    @patch.object(_BaseConnector, "_request")
    def test_list_pages(self, mock_req, confluence_settings):
        mock_req.return_value = _mock_response(200, {"results": []})
        conn = ConfluenceConnector(confluence_settings)
        result = conn.list_pages()
        assert result.status == "fetched"

    @patch.object(_BaseConnector, "_request")
    def test_health_check_healthy(self, mock_req, confluence_settings):
        mock_req.return_value = _mock_response(200, {})
        conn = ConfluenceConnector(confluence_settings)
        health = conn.health_check()
        assert health.healthy is True

    def test_health_check_not_configured(self):
        conn = ConfluenceConnector({})
        health = conn.health_check()
        assert health.healthy is False


# ===========================================================================
# SlackConnector
# ===========================================================================


class TestSlackConnector:
    def test_post_message_skipped_when_no_webhook(self):
        conn = SlackConnector({})
        result = conn.post_message({"text": "hello"})
        assert result.status == "skipped"

    @patch.object(_BaseConnector, "_request")
    def test_post_message_success(self, mock_req, slack_settings):
        mock_req.return_value = _mock_response(200, text="ok")
        conn = SlackConnector(slack_settings)
        result = conn.post_message({"text": "Hello team"})
        assert result.status == "sent"

    @patch.object(_BaseConnector, "_request")
    def test_post_message_with_channel(self, mock_req, slack_settings):
        mock_req.return_value = _mock_response(200, text="ok")
        conn = SlackConnector(slack_settings)
        result = conn.post_message({"text": "Alert", "channel": "#security"})
        assert result.status == "sent"

    @patch.object(_BaseConnector, "_request")
    def test_health_check_reachable(self, mock_req, slack_settings):
        mock_req.return_value = _mock_response(200)
        conn = SlackConnector(slack_settings)
        health = conn.health_check()
        assert health.healthy is True

    @patch.object(_BaseConnector, "_request")
    def test_health_check_400_still_reachable(self, mock_req, slack_settings):
        """Slack returns 400 for empty text but the endpoint is reachable."""
        resp = MagicMock()
        resp.status_code = 400
        resp.text = "no_text"
        resp.raise_for_status.return_value = None
        mock_req.return_value = resp
        conn = SlackConnector(slack_settings)
        health = conn.health_check()
        assert health.healthy is True

    def test_health_check_no_webhook(self):
        conn = SlackConnector({})
        health = conn.health_check()
        assert health.healthy is False

    def test_webhook_from_env(self, monkeypatch):
        monkeypatch.setenv("MY_SLACK_HOOK", "https://hooks.slack.com/test")
        conn = SlackConnector({"webhook_env": "MY_SLACK_HOOK"})
        assert conn.default_webhook == "https://hooks.slack.com/test"


# ===========================================================================
# ServiceNowConnector
# ===========================================================================


class TestServiceNowConnector:
    def test_configured(self, servicenow_settings):
        conn = ServiceNowConnector(servicenow_settings)
        assert conn.configured is True

    def test_not_configured(self):
        conn = ServiceNowConnector({})
        assert conn.configured is False

    def test_create_incident_skipped_when_not_configured(self):
        conn = ServiceNowConnector({})
        result = conn.create_incident({"summary": "test"})
        assert result.status == "skipped"

    @patch.object(_BaseConnector, "_request")
    def test_create_incident_success(self, mock_req, servicenow_settings):
        mock_req.return_value = _mock_response(201, {"result": {"sys_id": "abc123", "number": "INC001"}})
        conn = ServiceNowConnector(servicenow_settings)
        result = conn.create_incident({"summary": "Security incident"})
        assert result.status == "sent"
        assert result.details["sys_id"] == "abc123"

    def test_update_incident_no_sys_id(self, servicenow_settings):
        conn = ServiceNowConnector(servicenow_settings)
        result = conn.update_incident({})
        assert result.status == "failed"

    def test_update_incident_no_fields(self, servicenow_settings):
        conn = ServiceNowConnector(servicenow_settings)
        result = conn.update_incident({"sys_id": "abc"})
        assert result.status == "skipped"

    @patch.object(_BaseConnector, "_request")
    def test_update_incident_success(self, mock_req, servicenow_settings):
        mock_req.return_value = _mock_response(200, {})
        conn = ServiceNowConnector(servicenow_settings)
        result = conn.update_incident({"sys_id": "abc", "state": "resolved"})
        assert result.status == "sent"

    def test_add_work_note_no_sys_id(self, servicenow_settings):
        conn = ServiceNowConnector(servicenow_settings)
        result = conn.add_work_note({})
        assert result.status == "failed"

    def test_add_work_note_no_body(self, servicenow_settings):
        conn = ServiceNowConnector(servicenow_settings)
        result = conn.add_work_note({"sys_id": "abc"})
        assert result.status == "failed"

    @patch.object(_BaseConnector, "_request")
    def test_add_work_note_success(self, mock_req, servicenow_settings):
        mock_req.return_value = _mock_response(200, {})
        conn = ServiceNowConnector(servicenow_settings)
        result = conn.add_work_note({"sys_id": "abc", "work_note": "Investigating..."})
        assert result.status == "sent"

    @patch.object(_BaseConnector, "_request")
    def test_get_incident(self, mock_req, servicenow_settings):
        mock_req.return_value = _mock_response(200, {"result": {"sys_id": "abc"}})
        conn = ServiceNowConnector(servicenow_settings)
        result = conn.get_incident("abc")
        assert result.status == "fetched"

    @patch.object(_BaseConnector, "_request")
    def test_search_incidents(self, mock_req, servicenow_settings):
        mock_req.return_value = _mock_response(200, {"result": [{"sys_id": "a"}]})
        conn = ServiceNowConnector(servicenow_settings)
        result = conn.search_incidents("urgency=1")
        assert result.status == "fetched"

    @patch.object(_BaseConnector, "_request")
    def test_list_incidents(self, mock_req, servicenow_settings):
        mock_req.return_value = _mock_response(200, {"result": []})
        conn = ServiceNowConnector(servicenow_settings)
        result = conn.list_incidents(state="1")
        assert result.status == "fetched"

    @patch.object(_BaseConnector, "_request")
    def test_health_check_healthy(self, mock_req, servicenow_settings):
        mock_req.return_value = _mock_response(200, {})
        conn = ServiceNowConnector(servicenow_settings)
        health = conn.health_check()
        assert health.healthy is True

    def test_health_check_not_configured(self):
        conn = ServiceNowConnector({})
        health = conn.health_check()
        assert health.healthy is False


# ===========================================================================
# GitLabConnector
# ===========================================================================


class TestGitLabConnector:
    def test_configured(self, gitlab_settings):
        conn = GitLabConnector(gitlab_settings)
        assert conn.configured is True

    def test_not_configured(self):
        conn = GitLabConnector({})
        assert conn.configured is False

    @patch.object(_BaseConnector, "_request")
    def test_create_issue_success(self, mock_req, gitlab_settings):
        mock_req.return_value = _mock_response(201, {"iid": 1, "id": 100, "web_url": "https://gitlab.com/test/issues/1"})
        conn = GitLabConnector(gitlab_settings)
        result = conn.create_issue({"title": "Test issue"})
        assert result.status == "sent"
        assert result.details["issue_iid"] == 1

    @patch.object(_BaseConnector, "_request")
    def test_create_issue_with_labels_list(self, mock_req, gitlab_settings):
        mock_req.return_value = _mock_response(201, {"iid": 1})
        conn = GitLabConnector(gitlab_settings)
        result = conn.create_issue({"title": "Test", "labels": ["bug", "security"]})
        assert result.status == "sent"

    def test_update_issue_no_iid(self, gitlab_settings):
        conn = GitLabConnector(gitlab_settings)
        result = conn.update_issue({})
        assert result.status == "failed"

    def test_update_issue_no_fields(self, gitlab_settings):
        conn = GitLabConnector(gitlab_settings)
        result = conn.update_issue({"issue_iid": "1"})
        assert result.status == "skipped"

    @patch.object(_BaseConnector, "_request")
    def test_update_issue_success(self, mock_req, gitlab_settings):
        mock_req.return_value = _mock_response(200, {})
        conn = GitLabConnector(gitlab_settings)
        result = conn.update_issue({"issue_iid": "1", "title": "Updated"})
        assert result.status == "sent"

    def test_add_comment_no_iid(self, gitlab_settings):
        conn = GitLabConnector(gitlab_settings)
        result = conn.add_comment({})
        assert result.status == "failed"

    def test_add_comment_no_body(self, gitlab_settings):
        conn = GitLabConnector(gitlab_settings)
        result = conn.add_comment({"issue_iid": "1"})
        assert result.status == "failed"

    @patch.object(_BaseConnector, "_request")
    def test_add_comment_success(self, mock_req, gitlab_settings):
        mock_req.return_value = _mock_response(201, {"id": 200})
        conn = GitLabConnector(gitlab_settings)
        result = conn.add_comment({"issue_iid": "1", "comment": "Fixed"})
        assert result.status == "sent"

    @patch.object(_BaseConnector, "_request")
    def test_get_issue(self, mock_req, gitlab_settings):
        mock_req.return_value = _mock_response(200, {"iid": 1, "id": 100})
        conn = GitLabConnector(gitlab_settings)
        result = conn.get_issue(1)
        assert result.status == "fetched"

    @patch.object(_BaseConnector, "_request")
    def test_search_issues(self, mock_req, gitlab_settings):
        mock_req.return_value = _mock_response(200, [{"iid": 1}])
        conn = GitLabConnector(gitlab_settings)
        result = conn.search_issues(search="security")
        assert result.status == "fetched"

    @patch.object(_BaseConnector, "_request")
    def test_list_issues(self, mock_req, gitlab_settings):
        mock_req.return_value = _mock_response(200, [])
        conn = GitLabConnector(gitlab_settings)
        result = conn.list_issues()
        assert result.status == "fetched"

    @patch.object(_BaseConnector, "_request")
    def test_health_check(self, mock_req, gitlab_settings):
        mock_req.return_value = _mock_response(200, {})
        conn = GitLabConnector(gitlab_settings)
        health = conn.health_check()
        assert health.healthy is True

    def test_health_check_not_configured(self):
        conn = GitLabConnector({})
        health = conn.health_check()
        assert health.healthy is False


# ===========================================================================
# AzureDevOpsConnector
# ===========================================================================


class TestAzureDevOpsConnector:
    def test_configured(self, azure_devops_settings):
        conn = AzureDevOpsConnector(azure_devops_settings)
        assert conn.configured is True

    def test_not_configured(self):
        conn = AzureDevOpsConnector({})
        assert conn.configured is False

    @patch.object(_BaseConnector, "_request")
    def test_create_work_item_success(self, mock_req, azure_devops_settings):
        mock_req.return_value = _mock_response(200, {"id": 42, "url": "https://dev.azure.com/..."})
        conn = AzureDevOpsConnector(azure_devops_settings)
        result = conn.create_work_item({"title": "Security bug"})
        assert result.status == "sent"
        assert result.details["work_item_id"] == 42

    def test_update_work_item_no_id(self, azure_devops_settings):
        conn = AzureDevOpsConnector(azure_devops_settings)
        result = conn.update_work_item({})
        assert result.status == "failed"

    def test_update_work_item_no_fields(self, azure_devops_settings):
        conn = AzureDevOpsConnector(azure_devops_settings)
        result = conn.update_work_item({"work_item_id": 42})
        assert result.status == "skipped"

    @patch.object(_BaseConnector, "_request")
    def test_update_work_item_success(self, mock_req, azure_devops_settings):
        mock_req.return_value = _mock_response(200, {})
        conn = AzureDevOpsConnector(azure_devops_settings)
        result = conn.update_work_item({"work_item_id": 42, "title": "Updated"})
        assert result.status == "sent"

    def test_add_comment_no_id(self, azure_devops_settings):
        conn = AzureDevOpsConnector(azure_devops_settings)
        result = conn.add_comment({})
        assert result.status == "failed"

    def test_add_comment_no_body(self, azure_devops_settings):
        conn = AzureDevOpsConnector(azure_devops_settings)
        result = conn.add_comment({"work_item_id": 42})
        assert result.status == "failed"

    @patch.object(_BaseConnector, "_request")
    def test_add_comment_success(self, mock_req, azure_devops_settings):
        mock_req.return_value = _mock_response(200, {"id": 1})
        conn = AzureDevOpsConnector(azure_devops_settings)
        result = conn.add_comment({"work_item_id": 42, "comment": "test"})
        assert result.status == "sent"

    @patch.object(_BaseConnector, "_request")
    def test_get_work_item(self, mock_req, azure_devops_settings):
        mock_req.return_value = _mock_response(200, {"id": 42})
        conn = AzureDevOpsConnector(azure_devops_settings)
        result = conn.get_work_item(42)
        assert result.status == "fetched"

    @patch.object(_BaseConnector, "_request")
    def test_search_work_items(self, mock_req, azure_devops_settings):
        mock_req.return_value = _mock_response(200, {"workItems": [{"id": 1}]})
        conn = AzureDevOpsConnector(azure_devops_settings)
        result = conn.search_work_items("SELECT [System.Id] FROM WorkItems")
        assert result.status == "fetched"
        assert result.details["count"] == 1

    @patch.object(_BaseConnector, "_request")
    def test_list_work_items(self, mock_req, azure_devops_settings):
        mock_req.return_value = _mock_response(200, {"workItems": []})
        conn = AzureDevOpsConnector(azure_devops_settings)
        result = conn.list_work_items(work_item_type="Bug")
        assert result.status == "fetched"

    @patch.object(_BaseConnector, "_request")
    def test_health_check(self, mock_req, azure_devops_settings):
        mock_req.return_value = _mock_response(200, {})
        conn = AzureDevOpsConnector(azure_devops_settings)
        health = conn.health_check()
        assert health.healthy is True

    def test_health_check_not_configured(self):
        conn = AzureDevOpsConnector({})
        health = conn.health_check()
        assert health.healthy is False

    def test_auth_header_format(self, azure_devops_settings):
        conn = AzureDevOpsConnector(azure_devops_settings)
        headers = conn._get_auth_header()
        assert "Authorization" in headers
        assert headers["Authorization"].startswith("Basic ")


# ===========================================================================
# GitHubConnector
# ===========================================================================


class TestGitHubConnector:
    def test_configured(self, github_settings):
        conn = GitHubConnector(github_settings)
        assert conn.configured is True

    def test_not_configured(self):
        conn = GitHubConnector({})
        assert conn.configured is False

    @patch.object(_BaseConnector, "_request")
    def test_create_issue_success(self, mock_req, github_settings):
        mock_req.return_value = _mock_response(201, {"number": 7, "id": 700, "html_url": "https://github.com/..."})
        conn = GitHubConnector(github_settings)
        result = conn.create_issue({"title": "Bug report"})
        assert result.status == "sent"
        assert result.details["issue_number"] == 7

    @patch.object(_BaseConnector, "_request")
    def test_create_issue_with_labels(self, mock_req, github_settings):
        mock_req.return_value = _mock_response(201, {"number": 8})
        conn = GitHubConnector(github_settings)
        result = conn.create_issue({"title": "Fix", "labels": ["security"], "assignees": ["dev1"]})
        assert result.status == "sent"

    def test_update_issue_no_number(self, github_settings):
        conn = GitHubConnector(github_settings)
        result = conn.update_issue({})
        assert result.status == "failed"

    def test_update_issue_no_fields(self, github_settings):
        conn = GitHubConnector(github_settings)
        result = conn.update_issue({"issue_number": 1})
        assert result.status == "skipped"

    @patch.object(_BaseConnector, "_request")
    def test_update_issue_success(self, mock_req, github_settings):
        mock_req.return_value = _mock_response(200, {})
        conn = GitHubConnector(github_settings)
        result = conn.update_issue({"issue_number": 1, "title": "Updated"})
        assert result.status == "sent"

    def test_add_comment_no_number(self, github_settings):
        conn = GitHubConnector(github_settings)
        result = conn.add_comment({})
        assert result.status == "failed"

    def test_add_comment_no_body(self, github_settings):
        conn = GitHubConnector(github_settings)
        result = conn.add_comment({"issue_number": 1})
        assert result.status == "failed"

    @patch.object(_BaseConnector, "_request")
    def test_add_comment_success(self, mock_req, github_settings):
        mock_req.return_value = _mock_response(201, {"id": 300, "html_url": "https://..."})
        conn = GitHubConnector(github_settings)
        result = conn.add_comment({"issue_number": 1, "comment": "LGTM"})
        assert result.status == "sent"

    @patch.object(_BaseConnector, "_request")
    def test_get_issue(self, mock_req, github_settings):
        mock_req.return_value = _mock_response(200, {"number": 1, "html_url": "..."})
        conn = GitHubConnector(github_settings)
        result = conn.get_issue(1)
        assert result.status == "fetched"

    @patch.object(_BaseConnector, "_request")
    def test_search_issues_excludes_prs(self, mock_req, github_settings):
        mock_req.return_value = _mock_response(200, [
            {"number": 1, "title": "Issue"},
            {"number": 2, "title": "PR", "pull_request": {}},
        ])
        conn = GitHubConnector(github_settings)
        result = conn.search_issues(exclude_pull_requests=True)
        assert result.details["count"] == 1

    @patch.object(_BaseConnector, "_request")
    def test_search_issues_includes_prs(self, mock_req, github_settings):
        mock_req.return_value = _mock_response(200, [
            {"number": 1},
            {"number": 2, "pull_request": {}},
        ])
        conn = GitHubConnector(github_settings)
        result = conn.search_issues(exclude_pull_requests=False)
        assert result.details["count"] == 2

    @patch.object(_BaseConnector, "_request")
    def test_list_issues(self, mock_req, github_settings):
        mock_req.return_value = _mock_response(200, [])
        conn = GitHubConnector(github_settings)
        result = conn.list_issues()
        assert result.status == "fetched"

    @patch.object(_BaseConnector, "_request")
    def test_get_comments(self, mock_req, github_settings):
        mock_req.return_value = _mock_response(200, [{"id": 1, "body": "test"}])
        conn = GitHubConnector(github_settings)
        result = conn.get_comments(1)
        assert result.status == "fetched"
        assert result.details["count"] == 1

    @patch.object(_BaseConnector, "_request")
    def test_health_check(self, mock_req, github_settings):
        mock_req.return_value = _mock_response(200, {})
        conn = GitHubConnector(github_settings)
        health = conn.health_check()
        assert health.healthy is True

    def test_health_check_not_configured(self):
        conn = GitHubConnector({})
        health = conn.health_check()
        assert health.healthy is False

    def test_get_headers(self, github_settings):
        conn = GitHubConnector(github_settings)
        headers = conn._get_headers()
        assert headers["Authorization"] == f"Bearer {github_settings['token']}"
        assert "X-GitHub-Api-Version" in headers


# ===========================================================================
# AutomationConnectors deliver routing
# ===========================================================================


class TestAutomationConnectors:
    def _make_connectors(self, **overrides):
        overlay = {
            "jira": {"url": "https://j.com", "user_email": "u@e.com", "token": "t", "project_key": "P"},
            "confluence": {"base_url": "https://c.com", "space_key": "S", "user": "u@e.com", "token": "t"},
            "policy_automation": {"webhook_url": "https://hooks.slack.com/test"},
            "servicenow": {},
            "gitlab": {},
            "azure_devops": {},
            "github": {},
            **overrides,
        }
        toggles = {"enforce_ticket_sync": True}
        return AutomationConnectors(overlay, toggles)

    def test_unknown_action_type_skipped(self):
        ac = self._make_connectors()
        result = ac.deliver({"type": "unknown_type"})
        assert result.status == "skipped"
        assert "no connector registered" in result.details["reason"]

    @patch.object(JiraConnector, "create_issue")
    def test_deliver_jira_create(self, mock_create):
        mock_create.return_value = ConnectorOutcome("sent", {"issue_key": "TEST-1"})
        ac = self._make_connectors()
        result = ac.deliver({"type": "jira_issue", "summary": "test"})
        assert result.status == "sent"
        mock_create.assert_called_once()

    @patch.object(JiraConnector, "update_issue")
    def test_deliver_jira_update(self, mock_update):
        mock_update.return_value = ConnectorOutcome("sent", {})
        ac = self._make_connectors()
        result = ac.deliver({"type": "jira", "operation": "update", "issue_key": "P-1", "summary": "x"})
        assert result.status == "sent"

    @patch.object(JiraConnector, "transition_issue")
    def test_deliver_jira_transition(self, mock_tr):
        mock_tr.return_value = ConnectorOutcome("sent", {})
        ac = self._make_connectors()
        result = ac.deliver({"type": "jira", "operation": "transition", "issue_key": "P-1", "transition_id": "31"})
        assert result.status == "sent"

    @patch.object(JiraConnector, "add_comment")
    def test_deliver_jira_comment(self, mock_comment):
        mock_comment.return_value = ConnectorOutcome("sent", {})
        ac = self._make_connectors()
        result = ac.deliver({"type": "jira", "operation": "comment", "issue_key": "P-1", "comment": "done"})
        assert result.status == "sent"

    @patch.object(ConfluenceConnector, "create_page")
    def test_deliver_confluence(self, mock_create):
        mock_create.return_value = ConnectorOutcome("sent", {})
        ac = self._make_connectors()
        result = ac.deliver({"type": "confluence_page", "title": "Report"})
        assert result.status == "sent"

    @patch.object(SlackConnector, "post_message")
    def test_deliver_slack(self, mock_post):
        mock_post.return_value = ConnectorOutcome("sent", {})
        ac = self._make_connectors()
        result = ac.deliver({"type": "slack", "text": "Alert"})
        assert result.status == "sent"

    @patch.object(ServiceNowConnector, "create_incident")
    def test_deliver_servicenow_create(self, mock_create):
        mock_create.return_value = ConnectorOutcome("sent", {})
        ac = self._make_connectors()
        result = ac.deliver({"type": "servicenow", "summary": "Incident"})
        assert result.status == "sent"

    @patch.object(GitLabConnector, "create_issue")
    def test_deliver_gitlab_create(self, mock_create):
        mock_create.return_value = ConnectorOutcome("sent", {})
        ac = self._make_connectors()
        result = ac.deliver({"type": "gitlab", "title": "Issue"})
        assert result.status == "sent"

    @patch.object(AzureDevOpsConnector, "create_work_item")
    def test_deliver_azure_devops_create(self, mock_create):
        mock_create.return_value = ConnectorOutcome("sent", {})
        ac = self._make_connectors()
        result = ac.deliver({"type": "azure_devops", "title": "Work item"})
        assert result.status == "sent"

    @patch.object(GitHubConnector, "create_issue")
    def test_deliver_github_create(self, mock_create):
        mock_create.return_value = ConnectorOutcome("sent", {})
        ac = self._make_connectors()
        result = ac.deliver({"type": "github", "title": "Issue"})
        assert result.status == "sent"

    def test_ticket_sync_disabled_skips(self):
        overlay = {
            "jira": {"url": "https://j.com", "user_email": "u@e.com", "token": "t", "project_key": "P"},
        }
        toggles = {"enforce_ticket_sync": False}
        ac = AutomationConnectors(overlay, toggles)
        result = ac.deliver({"type": "jira_issue", "summary": "test"})
        assert result.status == "skipped"
        assert "sync disabled" in result.details["reason"]

    def test_ticket_sync_disabled_but_force_delivery(self):
        overlay = {
            "jira": {"url": "https://j.com", "user_email": "u@e.com", "token": "t", "project_key": "P"},
        }
        toggles = {"enforce_ticket_sync": False}
        ac = AutomationConnectors(overlay, toggles)
        with patch.object(JiraConnector, "create_issue") as mock_create:
            mock_create.return_value = ConnectorOutcome("sent", {})
            result = ac.deliver({"type": "jira_issue", "force_delivery": True, "summary": "urgent"})
            assert result.status == "sent"

    def test_feature_flag_disables_connector(self):
        overlay = {
            "jira": {"url": "https://j.com", "user_email": "u@e.com", "token": "t", "project_key": "P"},
        }
        toggles = {"enforce_ticket_sync": True}
        flag_provider = MagicMock()
        flag_provider.bool.return_value = False
        ac = AutomationConnectors(overlay, toggles, flag_provider=flag_provider)
        result = ac.deliver({"type": "jira_issue", "summary": "test"})
        assert result.status == "skipped"
        assert "disabled" in result.details["reason"]


# ===========================================================================
# summarise_connector
# ===========================================================================


class TestSummariseConnector:
    def test_jira(self, jira_settings):
        conn = JiraConnector(jira_settings)
        summary = summarise_connector(conn)
        assert summary["configured"] is True
        assert summary["project_key"] == "TEST"
        assert "***" in summary["token"]

    def test_confluence(self, confluence_settings):
        conn = ConfluenceConnector(confluence_settings)
        summary = summarise_connector(conn)
        assert summary["configured"] is True
        assert summary["space_key"] == "TESTSPACE"

    def test_slack(self, slack_settings):
        conn = SlackConnector(slack_settings)
        summary = summarise_connector(conn)
        assert summary["configured"] is True
        assert "***" in summary["webhook"]

    def test_servicenow(self, servicenow_settings):
        conn = ServiceNowConnector(servicenow_settings)
        summary = summarise_connector(conn)
        assert summary["configured"] is True

    def test_gitlab(self, gitlab_settings):
        conn = GitLabConnector(gitlab_settings)
        summary = summarise_connector(conn)
        assert summary["configured"] is True
        assert summary["project_id"] == "12345"

    def test_azure_devops(self, azure_devops_settings):
        conn = AzureDevOpsConnector(azure_devops_settings)
        summary = summarise_connector(conn)
        assert summary["configured"] is True
        assert summary["organization"] == "test-org"

    def test_github(self, github_settings):
        conn = GitHubConnector(github_settings)
        summary = summarise_connector(conn)
        assert summary["configured"] is True
        assert summary["owner"] == "test-owner"

    def test_unknown_connector(self):
        summary = summarise_connector(MagicMock(spec=_BaseConnector))
        assert summary["configured"] is False


# ===========================================================================
# _BaseConnector metrics
# ===========================================================================


class TestBaseConnectorMetrics:
    @patch.object(_BaseConnector, "_request")
    def test_get_metrics(self, mock_req, jira_settings):
        conn = JiraConnector(jira_settings)
        metrics = conn.get_metrics()
        assert metrics["request_count"] == 0
        assert metrics["error_count"] == 0
        assert metrics["error_rate"] == 0.0
        assert metrics["circuit_state"] == "closed"
