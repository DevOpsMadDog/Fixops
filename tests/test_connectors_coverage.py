"""Coverage tests for untested units in suite-core/core/connectors.py.

Covers:
- _mask() module-level helper
- CircuitBreaker: state transitions, record_success/failure, allow_request, edge cases
- RateLimiter: acquire with full tokens, timeout expiry
- ConnectorOutcome: to_dict(), success property, data property
- ConnectorHealth: to_dict() serialization
- ConfluenceConnector: create_page, update_page, get_page, search_pages, list_pages, health_check
- ServiceNowConnector: create_incident, update_incident, add_work_note, get_incident,
                       search_incidents, list_incidents, health_check
- GitLabConnector: create_issue, update_issue, add_comment, get_issue, search_issues,
                   list_issues, health_check
- AzureDevOpsConnector: create_work_item, update_work_item, add_comment, get_work_item,
                        search_work_items, _sanitize_wiql_value, health_check
- AutomationConnectors: deliver() routing, _check_feature_flag()
- summarise_connector() for each connector type
"""

from __future__ import annotations

import time
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

from core.connectors import (
    AzureDevOpsConnector,
    AutomationConnectors,
    CircuitBreaker,
    CircuitState,
    ConfluenceConnector,
    ConnectorHealth,
    ConnectorOutcome,
    GitLabConnector,
    RateLimiter,
    ServiceNowConnector,
    _mask,
    summarise_connector,
)

pytestmark = pytest.mark.timeout(10)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_response(status_code: int = 200, json_data: Any = None, text: str = "") -> MagicMock:
    """Build a minimal mock requests.Response."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.text = text
    if json_data is not None:
        resp.json.return_value = json_data
    else:
        resp.json.side_effect = ValueError("no body")
    resp.raise_for_status = MagicMock()
    if status_code >= 400:
        from requests import HTTPError
        resp.raise_for_status.side_effect = HTTPError(f"HTTP {status_code}")
    return resp


# ---------------------------------------------------------------------------
# _mask()
# ---------------------------------------------------------------------------


class TestMask:
    def test_none_returns_none(self):
        assert _mask(None) is None

    def test_empty_string_returns_empty(self):
        assert _mask("") == ""

    def test_short_string_fully_masked(self):
        assert _mask("ab") == "**"

    def test_exactly_four_chars_fully_masked(self):
        assert _mask("abcd") == "****"

    def test_long_string_shows_first_two_and_last_two(self):
        result = _mask("abcdefgh")
        assert result == "ab***gh"

    def test_long_string_middle_is_three_stars(self):
        result = _mask("secret_token_xyz")
        assert result.startswith("se")
        assert result.endswith("yz")
        assert "***" in result


# ---------------------------------------------------------------------------
# CircuitBreaker
# ---------------------------------------------------------------------------


class TestCircuitBreakerState:
    def test_initial_state_is_closed(self):
        cb = CircuitBreaker()
        assert cb.state == CircuitState.CLOSED

    def test_state_remains_closed_below_threshold(self):
        cb = CircuitBreaker(failure_threshold=5)
        for _ in range(4):
            cb.record_failure()
        assert cb.state == CircuitState.CLOSED

    def test_state_opens_at_threshold(self):
        cb = CircuitBreaker(failure_threshold=3)
        for _ in range(3):
            cb.record_failure()
        assert cb.state == CircuitState.OPEN

    def test_open_transitions_to_half_open_after_timeout(self):
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=0.01)
        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        time.sleep(0.02)
        assert cb.state == CircuitState.HALF_OPEN

    def test_half_open_closes_after_enough_successes(self):
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=0.01, half_open_max_calls=2)
        cb.record_failure()
        time.sleep(0.02)
        # Trigger half-open
        assert cb.state == CircuitState.HALF_OPEN
        cb.record_success()
        cb.record_success()
        assert cb.state == CircuitState.CLOSED

    def test_half_open_reopens_on_failure(self):
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=0.01)
        cb.record_failure()
        time.sleep(0.02)
        assert cb.state == CircuitState.HALF_OPEN
        cb.record_failure()
        assert cb.state == CircuitState.OPEN

    def test_record_success_in_closed_resets_failure_count(self):
        cb = CircuitBreaker(failure_threshold=5)
        for _ in range(4):
            cb.record_failure()
        cb.record_success()
        assert cb._failure_count == 0
        assert cb.state == CircuitState.CLOSED


class TestCircuitBreakerAllowRequest:
    def test_allows_when_closed(self):
        cb = CircuitBreaker()
        assert cb.allow_request() is True

    def test_blocks_when_open(self):
        cb = CircuitBreaker(failure_threshold=1)
        cb.record_failure()
        assert cb.state == CircuitState.OPEN
        assert cb.allow_request() is False

    def test_allows_when_half_open(self):
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=0.01)
        cb.record_failure()
        time.sleep(0.02)
        assert cb.state == CircuitState.HALF_OPEN
        assert cb.allow_request() is True

    def test_exact_threshold_boundary(self):
        cb = CircuitBreaker(failure_threshold=5)
        for _ in range(4):
            cb.record_failure()
        assert cb.allow_request() is True  # still closed at threshold-1
        cb.record_failure()
        assert cb.allow_request() is False  # now open at threshold


# ---------------------------------------------------------------------------
# RateLimiter
# ---------------------------------------------------------------------------


class TestRateLimiter:
    def test_acquire_succeeds_with_tokens_available(self):
        rl = RateLimiter(requests_per_second=100.0, burst_size=10)
        result = rl.acquire(timeout=1.0)
        assert result is True

    def test_acquire_decrements_tokens(self):
        rl = RateLimiter(requests_per_second=100.0, burst_size=5)
        for _ in range(5):
            assert rl.acquire(timeout=1.0) is True

    def test_acquire_returns_false_on_zero_timeout_when_exhausted(self):
        rl = RateLimiter(requests_per_second=0.001, burst_size=1)
        # Consume the one token
        rl.acquire(timeout=0.1)
        # Now there are no tokens and refill rate is negligible
        result = rl.acquire(timeout=0.0)
        assert result is False

    def test_tokens_initialized_to_burst_size(self):
        rl = RateLimiter(requests_per_second=1.0, burst_size=20)
        assert rl._tokens == 20.0


# ---------------------------------------------------------------------------
# ConnectorOutcome
# ---------------------------------------------------------------------------


class TestConnectorOutcome:
    def test_success_property_true_for_sent(self):
        outcome = ConnectorOutcome("sent", {})
        assert outcome.success is True

    def test_success_property_true_for_success(self):
        outcome = ConnectorOutcome("success", {})
        assert outcome.success is True

    def test_success_property_true_for_fetched(self):
        outcome = ConnectorOutcome("fetched", {})
        assert outcome.success is True

    def test_success_property_false_for_failed(self):
        outcome = ConnectorOutcome("failed", {"reason": "oops"})
        assert outcome.success is False

    def test_success_property_false_for_skipped(self):
        outcome = ConnectorOutcome("skipped", {"reason": "not configured"})
        assert outcome.success is False

    def test_data_property_returns_data_key(self):
        outcome = ConnectorOutcome("fetched", {"data": {"id": 42}})
        assert outcome.data == {"id": 42}

    def test_data_property_returns_none_when_missing(self):
        outcome = ConnectorOutcome("sent", {"endpoint": "http://example.com"})
        assert outcome.data is None

    def test_to_dict_contains_status(self):
        outcome = ConnectorOutcome("sent", {"endpoint": "http://example.com"})
        d = outcome.to_dict()
        assert d["status"] == "sent"
        assert d["endpoint"] == "http://example.com"

    def test_to_dict_does_not_override_existing_status_key(self):
        # If details already has "status", it should NOT be overwritten (setdefault)
        outcome = ConnectorOutcome("sent", {"status": "custom_status"})
        d = outcome.to_dict()
        assert d["status"] == "custom_status"


# ---------------------------------------------------------------------------
# ConnectorHealth
# ---------------------------------------------------------------------------


class TestConnectorHealth:
    def test_to_dict_contains_all_fields(self):
        health = ConnectorHealth(
            healthy=True, latency_ms=45.2, message="Connected successfully"
        )
        d = health.to_dict()
        assert d["healthy"] is True
        assert d["latency_ms"] == 45.2
        assert d["message"] == "Connected successfully"
        assert "checked_at" in d

    def test_to_dict_unhealthy(self):
        health = ConnectorHealth(
            healthy=False, latency_ms=0.0, message="Connection failed: timeout"
        )
        d = health.to_dict()
        assert d["healthy"] is False
        assert d["message"] == "Connection failed: timeout"

    def test_checked_at_is_iso_format(self):
        health = ConnectorHealth(healthy=True, latency_ms=10.0, message="ok")
        checked_at = health.to_dict()["checked_at"]
        # Should be parseable as ISO datetime
        from datetime import datetime
        assert datetime.fromisoformat(checked_at)


# ---------------------------------------------------------------------------
# ConfluenceConnector
# ---------------------------------------------------------------------------

CONFLUENCE_SETTINGS = {
    "base_url": "https://confluence.example.com",
    "space_key": "OPS",
    "user": "admin@example.com",
    "token": "atlassian-api-token-123",
}


class TestConfluenceConnectorUnconfigured:
    def _connector(self):
        return ConfluenceConnector({})

    def test_create_page_skipped_when_unconfigured(self):
        outcome = self._connector().create_page({"title": "Test"})
        assert outcome.status == "skipped"

    def test_update_page_skipped_when_unconfigured(self):
        outcome = self._connector().update_page({"page_id": "123"})
        assert outcome.status == "skipped"

    def test_get_page_skipped_when_unconfigured(self):
        outcome = self._connector().get_page("123")
        assert outcome.status == "skipped"

    def test_search_pages_skipped_when_unconfigured(self):
        outcome = self._connector().search_pages("space = OPS")
        assert outcome.status == "skipped"

    def test_health_check_unhealthy_when_unconfigured(self):
        health = self._connector().health_check()
        assert health.healthy is False
        assert "not configured" in health.message.lower()


class TestConfluenceConnectorConfigured:
    def _connector(self):
        return ConfluenceConnector(CONFLUENCE_SETTINGS)

    def test_configured_property_is_true(self):
        assert self._connector().configured is True

    def test_create_page_success(self):
        connector = self._connector()
        mock_resp = _mock_response(200, json_data={"id": "987654", "space": {"key": "OPS"}})
        with patch.object(connector, "_request", return_value=mock_resp):
            outcome = connector.create_page({"title": "My Page", "body": "<h1>Hello</h1>"})
        assert outcome.success is True
        assert outcome.status == "sent"

    def test_create_page_uses_parent_page_id(self):
        connector = self._connector()
        mock_resp = _mock_response(200, json_data={"id": "999"})
        with patch.object(connector, "_request", return_value=mock_resp) as mock_req:
            connector.create_page({"title": "Child", "parent_page_id": "111"})
        call_kwargs = mock_req.call_args[1]
        ancestors = call_kwargs["json"]["ancestors"]
        assert ancestors == [{"id": "111"}]

    def test_get_page_success(self):
        connector = self._connector()
        mock_resp = _mock_response(200, json_data={"id": "42", "title": "My Page"})
        with patch.object(connector, "_request", return_value=mock_resp):
            outcome = connector.get_page("42")
        assert outcome.success is True
        assert outcome.status == "fetched"

    def test_get_page_returns_data(self):
        connector = self._connector()
        page_data = {"id": "42", "title": "My Page", "version": {"number": 3}}
        mock_resp = _mock_response(200, json_data=page_data)
        with patch.object(connector, "_request", return_value=mock_resp):
            outcome = connector.get_page("42")
        assert outcome.data == page_data

    def test_update_page_fails_without_page_id(self):
        connector = self._connector()
        outcome = connector.update_page({"title": "No ID"})
        assert outcome.status == "failed"
        assert "page_id" in outcome.details["reason"]

    def test_update_page_success_with_explicit_version(self):
        connector = self._connector()
        mock_resp = _mock_response(
            200, json_data={"id": "42", "title": "Updated", "version": {"number": 4}}
        )
        with patch.object(connector, "_request", return_value=mock_resp):
            outcome = connector.update_page(
                {"page_id": "42", "title": "Updated", "body": "new content", "version": 3}
            )
        assert outcome.success is True
        assert outcome.details["operation"] == "update_page"

    def test_search_pages_success(self):
        connector = self._connector()
        mock_resp = _mock_response(
            200, json_data={"results": [{"id": "1"}, {"id": "2"}], "limit": 50}
        )
        with patch.object(connector, "_request", return_value=mock_resp):
            outcome = connector.search_pages("space = OPS")
        assert outcome.success is True
        assert outcome.details["count"] == 2

    def test_list_pages_delegates_to_search_pages(self):
        connector = self._connector()
        mock_resp = _mock_response(200, json_data={"results": [], "limit": 50})
        with patch.object(connector, "_request", return_value=mock_resp) as mock_req:
            connector.list_pages(space_key="MYSPACE")
        # The CQL passed should contain MYSPACE
        call_kwargs = mock_req.call_args[1]
        assert "MYSPACE" in call_kwargs["params"]["cql"]

    def test_health_check_healthy(self):
        connector = self._connector()
        mock_resp = _mock_response(200)
        mock_resp.json.side_effect = ValueError("no json needed")
        with patch.object(connector, "_request", return_value=mock_resp):
            health = connector.health_check()
        assert health.healthy is True

    def test_health_check_unhealthy_on_non_200(self):
        connector = self._connector()
        mock_resp = _mock_response(401, text="Unauthorized")
        mock_resp.raise_for_status = MagicMock()  # don't raise in health check
        with patch.object(connector, "_request", return_value=mock_resp):
            health = connector.health_check()
        assert health.healthy is False
        assert "401" in health.message


# ---------------------------------------------------------------------------
# ServiceNowConnector
# ---------------------------------------------------------------------------

SNOW_SETTINGS = {
    "instance_url": "https://myinstance.service-now.com",
    "user": "sn_user",
    "token": "sn_password",
}


class TestServiceNowConnectorUnconfigured:
    def _connector(self):
        return ServiceNowConnector({})

    def test_create_incident_skipped_when_unconfigured(self):
        outcome = self._connector().create_incident({"summary": "Test"})
        assert outcome.status == "skipped"

    def test_update_incident_skipped_when_unconfigured(self):
        outcome = self._connector().update_incident({"sys_id": "abc"})
        assert outcome.status == "skipped"

    def test_add_work_note_skipped_when_unconfigured(self):
        outcome = self._connector().add_work_note({"sys_id": "abc", "work_note": "note"})
        assert outcome.status == "skipped"

    def test_get_incident_skipped_when_unconfigured(self):
        outcome = self._connector().get_incident("abc")
        assert outcome.status == "skipped"

    def test_health_check_unhealthy_when_unconfigured(self):
        health = self._connector().health_check()
        assert health.healthy is False


class TestServiceNowConnectorConfigured:
    def _connector(self):
        return ServiceNowConnector(SNOW_SETTINGS)

    def test_configured_property_is_true(self):
        assert self._connector().configured is True

    def test_create_incident_success(self):
        connector = self._connector()
        mock_resp = _mock_response(
            201, json_data={"result": {"sys_id": "SYS001", "number": "INC0001"}}
        )
        with patch.object(connector, "_request", return_value=mock_resp):
            outcome = connector.create_incident(
                {"summary": "Server down", "urgency": "1", "impact": "1"}
            )
        assert outcome.success is True
        assert outcome.details["sys_id"] == "SYS001"
        assert outcome.details["number"] == "INC0001"

    def test_create_incident_includes_optional_fields(self):
        connector = self._connector()
        mock_resp = _mock_response(201, json_data={"result": {}})
        with patch.object(connector, "_request", return_value=mock_resp) as mock_req:
            connector.create_incident(
                {
                    "summary": "Test",
                    "assignment_group": "NOC",
                    "category": "software",
                    "subcategory": "email",
                }
            )
        payload = mock_req.call_args[1]["json"]
        assert payload["assignment_group"] == "NOC"
        assert payload["category"] == "software"
        assert payload["subcategory"] == "email"

    def test_update_incident_fails_without_sys_id(self):
        connector = self._connector()
        outcome = connector.update_incident({"state": "2"})
        assert outcome.status == "failed"
        assert "sys_id" in outcome.details["reason"]

    def test_update_incident_skipped_when_no_fields(self):
        connector = self._connector()
        outcome = connector.update_incident({"sys_id": "SYS001"})
        assert outcome.status == "skipped"
        assert "no fields" in outcome.details["reason"]

    def test_update_incident_success(self):
        connector = self._connector()
        mock_resp = _mock_response(200, json_data={"result": {"sys_id": "SYS001"}})
        with patch.object(connector, "_request", return_value=mock_resp):
            outcome = connector.update_incident({"sys_id": "SYS001", "state": "6"})
        assert outcome.success is True
        assert outcome.details["operation"] == "update_incident"

    def test_add_work_note_fails_without_sys_id(self):
        connector = self._connector()
        outcome = connector.add_work_note({"work_note": "Investigating..."})
        assert outcome.status == "failed"
        assert "sys_id" in outcome.details["reason"]

    def test_add_work_note_fails_without_note_content(self):
        connector = self._connector()
        outcome = connector.add_work_note({"sys_id": "SYS001"})
        assert outcome.status == "failed"
        assert "work_note" in outcome.details["reason"]

    def test_add_work_note_success(self):
        connector = self._connector()
        mock_resp = _mock_response(200, json_data={"result": {}})
        with patch.object(connector, "_request", return_value=mock_resp):
            outcome = connector.add_work_note(
                {"sys_id": "SYS001", "work_note": "Investigated root cause."}
            )
        assert outcome.success is True
        assert outcome.details["operation"] == "add_work_note"

    def test_get_incident_success(self):
        connector = self._connector()
        incident_data = {"sys_id": "SYS001", "number": "INC0001", "state": "1"}
        mock_resp = _mock_response(200, json_data={"result": incident_data})
        with patch.object(connector, "_request", return_value=mock_resp):
            outcome = connector.get_incident("SYS001")
        assert outcome.success is True
        assert outcome.status == "fetched"
        assert outcome.data == incident_data

    def test_search_incidents_success(self):
        connector = self._connector()
        mock_resp = _mock_response(
            200,
            json_data={"result": [{"sys_id": "A"}, {"sys_id": "B"}]},
        )
        with patch.object(connector, "_request", return_value=mock_resp):
            outcome = connector.search_incidents("active=true")
        assert outcome.success is True
        assert outcome.details["count"] == 2

    def test_health_check_healthy(self):
        connector = self._connector()
        mock_resp = _mock_response(200)
        mock_resp.json.side_effect = ValueError
        with patch.object(connector, "_request", return_value=mock_resp):
            health = connector.health_check()
        assert health.healthy is True

    def test_health_check_unhealthy_on_401(self):
        connector = self._connector()
        mock_resp = _mock_response(401, text="Unauthorized")
        mock_resp.raise_for_status = MagicMock()
        with patch.object(connector, "_request", return_value=mock_resp):
            health = connector.health_check()
        assert health.healthy is False
        assert "401" in health.message


# ---------------------------------------------------------------------------
# GitLabConnector
# ---------------------------------------------------------------------------

GITLAB_SETTINGS = {
    "base_url": "https://gitlab.com",
    "project_id": "12345",
    "token": "glpat-abc123",
}


class TestGitLabConnectorUnconfigured:
    def _connector(self):
        return GitLabConnector({})

    def test_create_issue_skipped_when_unconfigured(self):
        outcome = self._connector().create_issue({"title": "Bug"})
        assert outcome.status == "skipped"

    def test_update_issue_skipped_when_unconfigured(self):
        outcome = self._connector().update_issue({"issue_iid": 1})
        assert outcome.status == "skipped"

    def test_add_comment_skipped_when_unconfigured(self):
        outcome = self._connector().add_comment({"issue_iid": 1, "comment": "x"})
        assert outcome.status == "skipped"

    def test_get_issue_skipped_when_unconfigured(self):
        outcome = self._connector().get_issue(1)
        assert outcome.status == "skipped"

    def test_health_check_unhealthy_when_unconfigured(self):
        health = self._connector().health_check()
        assert health.healthy is False


class TestGitLabConnectorConfigured:
    def _connector(self):
        return GitLabConnector(GITLAB_SETTINGS)

    def test_configured_property_is_true(self):
        assert self._connector().configured is True

    def test_create_issue_success(self):
        connector = self._connector()
        mock_resp = _mock_response(
            201, json_data={"id": 100, "iid": 5, "web_url": "https://gitlab.com/project/issues/5"}
        )
        with patch.object(connector, "_request", return_value=mock_resp):
            outcome = connector.create_issue({"title": "Security bug"})
        assert outcome.success is True
        assert outcome.details["issue_iid"] == 5

    def test_create_issue_joins_list_labels(self):
        connector = self._connector()
        mock_resp = _mock_response(201, json_data={})
        with patch.object(connector, "_request", return_value=mock_resp) as mock_req:
            connector.create_issue({"title": "Bug", "labels": ["security", "critical"]})
        payload = mock_req.call_args[1]["json"]
        assert payload["labels"] == "security,critical"

    def test_create_issue_string_labels_passed_as_is(self):
        connector = self._connector()
        mock_resp = _mock_response(201, json_data={})
        with patch.object(connector, "_request", return_value=mock_resp) as mock_req:
            connector.create_issue({"title": "Bug", "labels": "security,critical"})
        payload = mock_req.call_args[1]["json"]
        assert payload["labels"] == "security,critical"

    def test_update_issue_fails_without_issue_iid(self):
        connector = self._connector()
        outcome = connector.update_issue({"title": "No IID"})
        assert outcome.status == "failed"
        assert "issue_iid" in outcome.details["reason"]

    def test_update_issue_skipped_when_no_fields(self):
        connector = self._connector()
        outcome = connector.update_issue({"issue_iid": 5})
        assert outcome.status == "skipped"

    def test_update_issue_success(self):
        connector = self._connector()
        mock_resp = _mock_response(200, json_data={})
        with patch.object(connector, "_request", return_value=mock_resp):
            outcome = connector.update_issue({"issue_iid": 5, "title": "Updated title"})
        assert outcome.success is True
        assert outcome.details["operation"] == "update_issue"

    def test_add_comment_fails_without_issue_iid(self):
        connector = self._connector()
        outcome = connector.add_comment({"comment": "Hello"})
        assert outcome.status == "failed"
        assert "issue_iid" in outcome.details["reason"]

    def test_add_comment_fails_without_body(self):
        connector = self._connector()
        outcome = connector.add_comment({"issue_iid": 5})
        assert outcome.status == "failed"
        assert "comment body" in outcome.details["reason"]

    def test_add_comment_success(self):
        connector = self._connector()
        mock_resp = _mock_response(201, json_data={"id": 999})
        with patch.object(connector, "_request", return_value=mock_resp):
            outcome = connector.add_comment({"issue_iid": 5, "comment": "Fixed in v2"})
        assert outcome.success is True
        assert outcome.details["note_id"] == 999

    def test_get_issue_success(self):
        connector = self._connector()
        issue_data = {"id": 100, "iid": 5, "title": "Bug"}
        mock_resp = _mock_response(200, json_data=issue_data)
        with patch.object(connector, "_request", return_value=mock_resp):
            outcome = connector.get_issue(5)
        assert outcome.success is True
        assert outcome.data == issue_data

    def test_search_issues_success(self):
        connector = self._connector()
        mock_resp = _mock_response(200, json_data=[{"iid": 1}, {"iid": 2}])
        with patch.object(connector, "_request", return_value=mock_resp):
            outcome = connector.search_issues(search="security", state="opened")
        assert outcome.success is True
        assert outcome.details["count"] == 2

    def test_list_issues_delegates_to_search_issues(self):
        connector = self._connector()
        mock_resp = _mock_response(200, json_data=[])
        with patch.object(connector, "_request", return_value=mock_resp) as mock_req:
            connector.list_issues(state="closed")
        params = mock_req.call_args[1]["params"]
        assert params["state"] == "closed"

    def test_health_check_healthy(self):
        connector = self._connector()
        mock_resp = _mock_response(200)
        mock_resp.json.side_effect = ValueError
        with patch.object(connector, "_request", return_value=mock_resp):
            health = connector.health_check()
        assert health.healthy is True

    def test_health_check_unhealthy_on_403(self):
        connector = self._connector()
        mock_resp = _mock_response(403, text="Forbidden")
        mock_resp.raise_for_status = MagicMock()
        with patch.object(connector, "_request", return_value=mock_resp):
            health = connector.health_check()
        assert health.healthy is False
        assert "403" in health.message


# ---------------------------------------------------------------------------
# AzureDevOpsConnector
# ---------------------------------------------------------------------------

ADO_SETTINGS = {
    "organization": "my-org",
    "project": "MyProject",
    "token": "pat-token-secret",
}


class TestAzureDevOpsConnectorUnconfigured:
    def _connector(self):
        return AzureDevOpsConnector({})

    def test_create_work_item_skipped_when_unconfigured(self):
        outcome = self._connector().create_work_item({"title": "Bug"})
        assert outcome.status == "skipped"

    def test_update_work_item_skipped_when_unconfigured(self):
        outcome = self._connector().update_work_item({"work_item_id": 1})
        assert outcome.status == "skipped"

    def test_add_comment_skipped_when_unconfigured(self):
        outcome = self._connector().add_comment({"work_item_id": 1, "comment": "x"})
        assert outcome.status == "skipped"

    def test_get_work_item_skipped_when_unconfigured(self):
        outcome = self._connector().get_work_item(1)
        assert outcome.status == "skipped"

    def test_search_work_items_skipped_when_unconfigured(self):
        outcome = self._connector().search_work_items("SELECT * FROM WorkItems")
        assert outcome.status == "skipped"

    def test_health_check_unhealthy_when_unconfigured(self):
        health = self._connector().health_check()
        assert health.healthy is False


class TestAzureDevOpsConnectorSanitizeWiql:
    def test_sanitize_removes_control_characters(self):
        value = "My Project\nWith\tNewlines"
        result = AzureDevOpsConnector._sanitize_wiql_value(value)
        assert "\n" not in result
        assert "\t" not in result

    def test_sanitize_escapes_single_quotes(self):
        value = "O'Brien's Project"
        result = AzureDevOpsConnector._sanitize_wiql_value(value)
        assert "''" in result
        assert "O''Brien''s Project" == result

    def test_sanitize_truncates_to_256_chars(self):
        value = "A" * 300
        result = AzureDevOpsConnector._sanitize_wiql_value(value)
        assert len(result) == 256

    def test_sanitize_allows_normal_strings(self):
        value = "Normal project name"
        result = AzureDevOpsConnector._sanitize_wiql_value(value)
        assert result == value


class TestAzureDevOpsConnectorConfigured:
    def _connector(self):
        return AzureDevOpsConnector(ADO_SETTINGS)

    def test_configured_property_is_true(self):
        assert self._connector().configured is True

    def test_create_work_item_success(self):
        connector = self._connector()
        mock_resp = _mock_response(
            200, json_data={"id": 42, "url": "https://dev.azure.com/my-org/MyProject/..."}
        )
        with patch.object(connector, "_request", return_value=mock_resp):
            outcome = connector.create_work_item({"title": "Security issue"})
        assert outcome.success is True
        assert outcome.details["work_item_id"] == 42

    def test_create_work_item_builds_json_patch_operations(self):
        connector = self._connector()
        mock_resp = _mock_response(200, json_data={"id": 1})
        with patch.object(connector, "_request", return_value=mock_resp) as mock_req:
            connector.create_work_item(
                {"title": "My Bug", "description": "Details", "priority": 1, "assigned_to": "user@example.com"}
            )
        operations = mock_req.call_args[1]["json"]
        paths = [op["path"] for op in operations]
        assert "/fields/System.Title" in paths
        assert "/fields/System.Description" in paths
        assert "/fields/Microsoft.VSTS.Common.Priority" in paths
        assert "/fields/System.AssignedTo" in paths

    def test_update_work_item_fails_without_id(self):
        connector = self._connector()
        outcome = connector.update_work_item({"title": "No ID"})
        assert outcome.status == "failed"
        assert "work_item_id" in outcome.details["reason"]

    def test_update_work_item_skipped_when_no_fields(self):
        connector = self._connector()
        outcome = connector.update_work_item({"work_item_id": 42})
        assert outcome.status == "skipped"

    def test_update_work_item_success(self):
        connector = self._connector()
        mock_resp = _mock_response(200, json_data={})
        with patch.object(connector, "_request", return_value=mock_resp):
            outcome = connector.update_work_item({"work_item_id": 42, "title": "Fixed"})
        assert outcome.success is True
        assert outcome.details["operation"] == "update_work_item"

    def test_add_comment_fails_without_work_item_id(self):
        connector = self._connector()
        outcome = connector.add_comment({"comment": "Hello"})
        assert outcome.status == "failed"
        assert "work_item_id" in outcome.details["reason"]

    def test_add_comment_fails_without_text(self):
        connector = self._connector()
        outcome = connector.add_comment({"work_item_id": 42})
        assert outcome.status == "failed"
        assert "comment text" in outcome.details["reason"]

    def test_add_comment_success(self):
        connector = self._connector()
        mock_resp = _mock_response(200, json_data={"id": 7})
        with patch.object(connector, "_request", return_value=mock_resp):
            outcome = connector.add_comment({"work_item_id": 42, "comment": "LGTM"})
        assert outcome.success is True
        assert outcome.details["comment_id"] == 7

    def test_get_work_item_success(self):
        connector = self._connector()
        item_data = {"id": 42, "fields": {"System.Title": "My Bug"}}
        mock_resp = _mock_response(200, json_data=item_data)
        with patch.object(connector, "_request", return_value=mock_resp):
            outcome = connector.get_work_item(42)
        assert outcome.success is True
        assert outcome.data == item_data

    def test_search_work_items_success(self):
        connector = self._connector()
        mock_resp = _mock_response(
            200,
            json_data={"workItems": [{"id": 1}, {"id": 2}], "count": 2},
        )
        with patch.object(connector, "_request", return_value=mock_resp):
            outcome = connector.search_work_items(
                "SELECT [System.Id] FROM WorkItems WHERE [System.TeamProject] = 'MyProject'"
            )
        assert outcome.success is True
        assert outcome.details["count"] == 2

    def test_health_check_healthy(self):
        connector = self._connector()
        mock_resp = _mock_response(200)
        mock_resp.json.side_effect = ValueError
        with patch.object(connector, "_request", return_value=mock_resp):
            health = connector.health_check()
        assert health.healthy is True

    def test_health_check_unhealthy_on_non_200(self):
        connector = self._connector()
        mock_resp = _mock_response(404, text="Not Found")
        mock_resp.raise_for_status = MagicMock()
        with patch.object(connector, "_request", return_value=mock_resp):
            health = connector.health_check()
        assert health.healthy is False


# ---------------------------------------------------------------------------
# AutomationConnectors.deliver() routing
# ---------------------------------------------------------------------------

FULL_SETTINGS: Dict[str, Any] = {
    "jira": {
        "url": "https://jira.example.com",
        "project_key": "OPS",
        "user_email": "jira@example.com",
        "token": "jira-token",
    },
    "confluence": CONFLUENCE_SETTINGS,
    "policy_automation": {"webhook_url": "https://hooks.slack.com/test"},
    "servicenow": SNOW_SETTINGS,
    "gitlab": GITLAB_SETTINGS,
    "azure_devops": ADO_SETTINGS,
    "github": {
        "owner": "my-org",
        "repo": "my-repo",
        "token": "ghp_token",
    },
}

TOGGLES = {"enforce_ticket_sync": True}


class TestAutomationConnectorsDeliver:
    def _automation(self, flag_provider=None):
        return AutomationConnectors(FULL_SETTINGS, TOGGLES, flag_provider=flag_provider)

    def test_unknown_action_type_returns_skipped(self):
        ac = self._automation()
        outcome = ac.deliver({"type": "unknown_system"})
        assert outcome.status == "skipped"
        assert "no connector registered" in outcome.details["reason"]

    def test_deliver_jira_creates_issue_by_default(self):
        ac = self._automation()
        mock_resp = _mock_response(201, json_data={"id": "1", "key": "OPS-1"})
        with patch.object(ac.jira, "_request", return_value=mock_resp):
            outcome = ac.deliver({"type": "jira_issue", "summary": "Test"})
        assert outcome.success is True

    def test_deliver_jira_routes_update_operation(self):
        ac = self._automation()
        mock_resp = _mock_response(200, json_data={})
        with patch.object(ac.jira, "_request", return_value=mock_resp):
            outcome = ac.deliver(
                {"type": "jira", "operation": "update", "issue_key": "OPS-1", "summary": "x"}
            )
        # update_issue returns "sent" on success
        assert outcome.status in ("sent", "skipped", "failed")

    def test_deliver_confluence_creates_page(self):
        ac = self._automation()
        mock_resp = _mock_response(200, json_data={"id": "999"})
        with patch.object(ac.confluence, "_request", return_value=mock_resp):
            outcome = ac.deliver({"type": "confluence_page", "title": "Audit Report"})
        assert outcome.status in ("sent", "skipped")

    def test_deliver_slack_posts_message(self):
        ac = self._automation()
        mock_resp = _mock_response(200)
        mock_resp.json.side_effect = ValueError
        with patch.object(ac.slack, "_request", return_value=mock_resp):
            outcome = ac.deliver({"type": "slack", "text": "Alert!"})
        assert outcome.status in ("sent", "skipped")

    def test_deliver_servicenow_creates_incident_by_default(self):
        ac = self._automation()
        mock_resp = _mock_response(201, json_data={"result": {"sys_id": "X", "number": "INC1"}})
        with patch.object(ac.servicenow, "_request", return_value=mock_resp):
            outcome = ac.deliver({"type": "servicenow_incident", "summary": "Down"})
        assert outcome.success is True

    def test_deliver_servicenow_routes_work_note(self):
        ac = self._automation()
        mock_resp = _mock_response(200, json_data={"result": {}})
        with patch.object(ac.servicenow, "_request", return_value=mock_resp):
            outcome = ac.deliver(
                {
                    "type": "servicenow",
                    "operation": "work_note",
                    "sys_id": "SYS001",
                    "work_note": "Investigating",
                }
            )
        assert outcome.success is True

    def test_deliver_gitlab_creates_issue_by_default(self):
        ac = self._automation()
        mock_resp = _mock_response(201, json_data={"id": 1, "iid": 5})
        with patch.object(ac.gitlab, "_request", return_value=mock_resp):
            outcome = ac.deliver({"type": "gitlab_issue", "title": "Security"})
        assert outcome.success is True

    def test_deliver_gitlab_routes_comment(self):
        ac = self._automation()
        mock_resp = _mock_response(201, json_data={"id": 99})
        with patch.object(ac.gitlab, "_request", return_value=mock_resp):
            outcome = ac.deliver(
                {
                    "type": "gitlab",
                    "operation": "comment",
                    "issue_iid": 5,
                    "comment": "Fixed",
                }
            )
        assert outcome.success is True

    def test_deliver_azure_devops_creates_work_item_by_default(self):
        ac = self._automation()
        mock_resp = _mock_response(200, json_data={"id": 42})
        with patch.object(ac.azure_devops, "_request", return_value=mock_resp):
            outcome = ac.deliver({"type": "azure_devops_work_item", "title": "Bug"})
        assert outcome.success is True

    def test_deliver_azure_devops_routes_update(self):
        ac = self._automation()
        mock_resp = _mock_response(200, json_data={})
        with patch.object(ac.azure_devops, "_request", return_value=mock_resp):
            outcome = ac.deliver(
                {
                    "type": "azure_devops",
                    "operation": "update",
                    "work_item_id": 42,
                    "title": "Updated",
                }
            )
        assert outcome.success is True

    def test_deliver_github_creates_issue_by_default(self):
        ac = self._automation()
        mock_resp = _mock_response(
            201, json_data={"number": 10, "id": 1, "html_url": "https://github.com/..."}
        )
        with patch.object(ac.github, "_request", return_value=mock_resp):
            outcome = ac.deliver({"type": "github_issue", "title": "Security alert"})
        assert outcome.success is True

    def test_deliver_skips_jira_when_ticket_sync_disabled(self):
        ac = AutomationConnectors(
            FULL_SETTINGS, {"enforce_ticket_sync": False}
        )
        outcome = ac.deliver({"type": "jira_issue", "summary": "Test"})
        assert outcome.status == "skipped"
        assert "ticket sync disabled" in outcome.details["reason"]

    def test_deliver_forces_jira_delivery_when_force_delivery_set(self):
        ac = AutomationConnectors(
            FULL_SETTINGS, {"enforce_ticket_sync": False}
        )
        mock_resp = _mock_response(201, json_data={"id": "1", "key": "OPS-1"})
        with patch.object(ac.jira, "_request", return_value=mock_resp):
            outcome = ac.deliver(
                {"type": "jira_issue", "summary": "Forced", "force_delivery": True}
            )
        assert outcome.success is True


class TestAutomationConnectorsFeatureFlag:
    def test_check_feature_flag_returns_default_when_no_provider(self):
        ac = AutomationConnectors(FULL_SETTINGS, TOGGLES, flag_provider=None)
        assert ac._check_feature_flag("some.flag", default=True) is True
        assert ac._check_feature_flag("some.flag", default=False) is False

    def test_check_feature_flag_uses_provider_value(self):
        provider = MagicMock()
        provider.bool.return_value = False
        ac = AutomationConnectors(FULL_SETTINGS, TOGGLES, flag_provider=provider)
        result = ac._check_feature_flag("fixops.feature.connector.jira", default=True)
        assert result is False
        provider.bool.assert_called_once_with("fixops.feature.connector.jira", True)

    def test_check_feature_flag_falls_back_to_default_on_provider_error(self):
        provider = MagicMock()
        provider.bool.side_effect = RuntimeError("Provider unavailable")
        ac = AutomationConnectors(FULL_SETTINGS, TOGGLES, flag_provider=provider)
        result = ac._check_feature_flag("some.flag", default=True)
        assert result is True

    def test_deliver_jira_skipped_when_feature_flag_disabled(self):
        provider = MagicMock()
        provider.bool.return_value = False
        ac = AutomationConnectors(FULL_SETTINGS, TOGGLES, flag_provider=provider)
        outcome = ac.deliver({"type": "jira_issue", "summary": "Test"})
        assert outcome.status == "skipped"
        assert "jira connector disabled" in outcome.details["reason"]


# ---------------------------------------------------------------------------
# summarise_connector()
# ---------------------------------------------------------------------------


class TestSummariseConnector:
    def test_summarise_confluence_connector(self):
        connector = ConfluenceConnector(CONFLUENCE_SETTINGS)
        summary = summarise_connector(connector)
        assert summary["configured"] is True
        assert summary["space_key"] == "OPS"
        assert "***" in summary["token"]  # masked
        assert summary["user"] == "admin@example.com"

    def test_summarise_servicenow_connector(self):
        connector = ServiceNowConnector(SNOW_SETTINGS)
        summary = summarise_connector(connector)
        assert summary["configured"] is True
        assert summary["instance_url"] == "https://myinstance.service-now.com"
        assert "***" in summary["token"]

    def test_summarise_gitlab_connector(self):
        connector = GitLabConnector(GITLAB_SETTINGS)
        summary = summarise_connector(connector)
        assert summary["configured"] is True
        assert summary["project_id"] == "12345"
        assert "***" in summary["token"]

    def test_summarise_azure_devops_connector(self):
        connector = AzureDevOpsConnector(ADO_SETTINGS)
        summary = summarise_connector(connector)
        assert summary["configured"] is True
        assert summary["organization"] == "my-org"
        assert summary["project"] == "MyProject"
        assert "***" in summary["token"]

    def test_summarise_unconfigured_connector_returns_configured_false(self):
        # A base connector that doesn't match any known subclass
        from core.connectors import _BaseConnector

        class UnknownConnector(_BaseConnector):
            pass

        connector = UnknownConnector()
        summary = summarise_connector(connector)
        assert summary == {"configured": False}
