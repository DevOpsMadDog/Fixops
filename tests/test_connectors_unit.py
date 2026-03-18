"""
Comprehensive unit tests for the Universal Connector
(suite-core/connectors/universal_connector.py).

Covers:
  - _normalise_severity: all aliases, None, unknown strings
  - _sanitise_text: control chars, truncation, empty/None
  - _mask_secret: short, long, empty
  - _AsyncCircuitBreaker: state transitions closed->open->half_open->closed
  - ConnectorResult: to_dict() with/without optional fields
  - _format_finding_title: severity prefix, CVE prefix, sanitisation
  - _format_finding_description: all optional fields
  - JiraConnector: configured property, unconfigured CRUD
  - GitHubConnector: configured property, unconfigured CRUD
  - SlackConnector: configured property, block building, get_ticket error
  - UniversalConnector: register, unregister, list, create_tickets fan-out, test_all
  - BaseConnector: metrics, close
"""

from __future__ import annotations

import asyncio
import time

import pytest

from connectors.universal_connector import (
    ConnectorResult,
    GitHubConnector,
    JiraConnector,
    SlackConnector,
    UniversalConnector,
    _AsyncCircuitBreaker,
    _CircuitState,
    _format_finding_description,
    _format_finding_title,
    _mask_secret,
    _normalise_severity,
    _sanitise_text,
    JIRA_SEVERITY_TO_PRIORITY,
    GITHUB_SEVERITY_TO_LABELS,
    SLACK_SEVERITY_CONFIG,
)


# ---------------------------------------------------------------------------
# Helper to run async functions synchronously in tests
# ---------------------------------------------------------------------------


def run_async(coro):
    """Run an async coroutine synchronously for testing."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# _normalise_severity tests
# ---------------------------------------------------------------------------


class TestNormaliseSeverity:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("critical", "critical"),
            ("crit", "critical"),
            ("CRITICAL", "critical"),
            ("high", "high"),
            ("HIGH", "high"),
            ("medium", "medium"),
            ("med", "medium"),
            ("moderate", "medium"),
            ("low", "low"),
            ("info", "info"),
            ("informational", "info"),
            ("none", "info"),
        ],
    )
    def test_known_aliases(self, raw, expected):
        assert _normalise_severity(raw) == expected

    def test_none_returns_medium(self):
        assert _normalise_severity(None) == "medium"

    def test_empty_string_returns_medium(self):
        assert _normalise_severity("") == "medium"

    def test_unknown_string_returns_medium(self):
        assert _normalise_severity("urgent") == "medium"

    def test_whitespace_stripped(self):
        assert _normalise_severity("  critical  ") == "critical"

    def test_case_insensitive(self):
        assert _normalise_severity("CrItIcAl") == "critical"


# ---------------------------------------------------------------------------
# _sanitise_text tests
# ---------------------------------------------------------------------------


class TestSanitiseText:
    def test_none_returns_empty(self):
        assert _sanitise_text(None) == ""

    def test_empty_returns_empty(self):
        assert _sanitise_text("") == ""

    def test_normal_text_unchanged(self):
        assert _sanitise_text("Hello world") == "Hello world"

    def test_null_bytes_removed(self):
        assert _sanitise_text("hello\x00world") == "helloworld"

    def test_control_chars_removed(self):
        text = "hello\x01\x02\x03world"
        result = _sanitise_text(text)
        assert "\x01" not in result
        assert "helloworld" == result

    def test_newlines_preserved(self):
        assert _sanitise_text("line1\nline2") == "line1\nline2"

    def test_tabs_preserved(self):
        assert _sanitise_text("col1\tcol2") == "col1\tcol2"

    def test_truncation_with_marker(self):
        long_text = "x" * 100
        result = _sanitise_text(long_text, max_length=50)
        assert len(result) <= 50 + len("... [truncated]")
        assert result.endswith("... [truncated]")

    def test_exact_length_not_truncated(self):
        text = "x" * 50
        result = _sanitise_text(text, max_length=50)
        assert result == text
        assert "truncated" not in result


# ---------------------------------------------------------------------------
# _mask_secret tests
# ---------------------------------------------------------------------------


class TestMaskSecret:
    def test_none_returns_empty_marker(self):
        assert _mask_secret(None) == "(empty)"

    def test_empty_returns_empty_marker(self):
        assert _mask_secret("") == "(empty)"

    def test_short_secret_fully_masked(self):
        assert _mask_secret("abc") == "***"
        assert _mask_secret("abcdef") == "***"

    def test_long_secret_partially_masked(self):
        result = _mask_secret("my-secret-token-value")
        assert result.startswith("my-")
        assert result.endswith("lue")
        assert "***" in result

    def test_seven_char_secret_shows_first_and_last_3(self):
        result = _mask_secret("1234567")
        assert result == "123***567"


# ---------------------------------------------------------------------------
# _AsyncCircuitBreaker tests
# ---------------------------------------------------------------------------


class TestAsyncCircuitBreaker:
    def test_starts_closed(self):
        cb = _AsyncCircuitBreaker()
        assert cb.state == _CircuitState.CLOSED
        assert cb.allow_request() is True

    def test_opens_after_threshold_failures(self):
        cb = _AsyncCircuitBreaker(failure_threshold=3, recovery_timeout=600.0)
        for _ in range(3):
            cb.record_failure()
        # After threshold failures without hitting HALF_OPEN, should be OPEN
        assert cb._state == _CircuitState.OPEN
        assert cb.allow_request() is False

    def test_success_resets_failure_count_in_closed(self):
        cb = _AsyncCircuitBreaker(failure_threshold=5)
        cb.record_failure()
        cb.record_failure()
        cb.record_success()
        assert cb._failure_count == 0
        assert cb.state == _CircuitState.CLOSED

    def test_transitions_to_half_open_after_timeout(self):
        cb = _AsyncCircuitBreaker(failure_threshold=1, recovery_timeout=0.01)
        cb.record_failure()
        assert cb._state == _CircuitState.OPEN
        time.sleep(0.02)
        # Accessing state property triggers the transition
        assert cb.state == _CircuitState.HALF_OPEN
        assert cb.allow_request() is True

    def test_half_open_failure_reopens(self):
        cb = _AsyncCircuitBreaker(failure_threshold=1, recovery_timeout=0.01)
        cb.record_failure()
        time.sleep(0.02)
        _ = cb.state  # trigger half_open
        assert cb.state == _CircuitState.HALF_OPEN
        cb.record_failure()
        assert cb._state == _CircuitState.OPEN

    def test_half_open_two_successes_closes(self):
        cb = _AsyncCircuitBreaker(failure_threshold=1, recovery_timeout=0.01)
        cb.record_failure()
        time.sleep(0.02)
        _ = cb.state  # trigger half_open
        cb.record_success()
        assert cb._state == _CircuitState.HALF_OPEN  # still half-open after 1
        cb.record_success()
        assert cb._state == _CircuitState.CLOSED

    def test_closed_state_allows_request(self):
        cb = _AsyncCircuitBreaker()
        assert cb.allow_request() is True

    def test_open_state_blocks_request(self):
        cb = _AsyncCircuitBreaker(failure_threshold=1, recovery_timeout=9999.0)
        cb.record_failure()
        assert cb.allow_request() is False


# ---------------------------------------------------------------------------
# ConnectorResult tests
# ---------------------------------------------------------------------------


class TestConnectorResult:
    def test_success_to_dict_minimal(self):
        r = ConnectorResult(
            success=True,
            connector="jira",
            operation="create_ticket",
        )
        d = r.to_dict()
        assert d["success"] is True
        assert d["connector"] == "jira"
        assert d["operation"] == "create_ticket"
        assert d["latency_ms"] == 0.0
        assert "ticket_id" not in d
        assert "url" not in d
        assert "error" not in d

    def test_to_dict_with_all_fields(self):
        r = ConnectorResult(
            success=True,
            connector="github",
            operation="create_ticket",
            ticket_id="42",
            url="https://github.com/org/repo/issues/42",
            details={"number": 42, "status": "open"},
            latency_ms=123.456,
        )
        d = r.to_dict()
        assert d["ticket_id"] == "42"
        assert d["url"] == "https://github.com/org/repo/issues/42"
        assert d["details"]["number"] == 42
        assert d["latency_ms"] == 123.46

    def test_to_dict_error_included_when_present(self):
        r = ConnectorResult(
            success=False,
            connector="slack",
            operation="create_ticket",
            error="HTTP 500: Internal Server Error",
        )
        d = r.to_dict()
        assert d["error"] == "HTTP 500: Internal Server Error"


# ---------------------------------------------------------------------------
# _format_finding_title tests
# ---------------------------------------------------------------------------


class TestFormatFindingTitle:
    def test_basic_finding_title(self):
        finding = {"severity": "critical", "title": "SQL Injection"}
        title = _format_finding_title(finding)
        assert "[CRITICAL]" in title
        assert "SQL Injection" in title

    def test_cve_included_in_title(self):
        finding = {"severity": "high", "cve_id": "CVE-2024-1234", "title": "Buffer Overflow"}
        title = _format_finding_title(finding)
        assert "[CVE-2024-1234]" in title

    def test_missing_title_uses_default(self):
        finding = {"severity": "medium"}
        title = _format_finding_title(finding)
        assert "Security Finding" in title

    def test_uses_cve_key_fallback(self):
        finding = {"severity": "low", "cve": "CVE-2024-9999", "title": "XSS"}
        title = _format_finding_title(finding)
        assert "[CVE-2024-9999]" in title


# ---------------------------------------------------------------------------
# _format_finding_description tests
# ---------------------------------------------------------------------------


class TestFormatFindingDescription:
    def test_basic_description(self):
        finding = {"severity": "critical", "cve_id": "CVE-2024-1234"}
        desc = _format_finding_description(finding)
        assert "CRITICAL" in desc
        assert "CVE-2024-1234" in desc

    def test_includes_component(self):
        finding = {"severity": "high", "component": "openssl"}
        desc = _format_finding_description(finding)
        assert "openssl" in desc

    def test_includes_file_path(self):
        finding = {"severity": "medium", "file_path": "/src/main.py"}
        desc = _format_finding_description(finding)
        assert "/src/main.py" in desc

    def test_includes_remediation(self):
        finding = {"severity": "low", "remediation": "Upgrade to v2.0"}
        desc = _format_finding_description(finding)
        assert "Upgrade to v2.0" in desc

    def test_footer_present(self):
        finding = {"severity": "info"}
        desc = _format_finding_description(finding)
        assert "ALdeci CTEM+" in desc


# ---------------------------------------------------------------------------
# Severity mapping constants tests
# ---------------------------------------------------------------------------


class TestSeverityMappings:
    def test_jira_all_severities_mapped(self):
        for sev in ["critical", "high", "medium", "low", "info"]:
            assert sev in JIRA_SEVERITY_TO_PRIORITY

    def test_github_all_severities_mapped(self):
        for sev in ["critical", "high", "medium", "low", "info"]:
            assert sev in GITHUB_SEVERITY_TO_LABELS

    def test_slack_all_severities_mapped(self):
        for sev in ["critical", "high", "medium", "low", "info"]:
            assert sev in SLACK_SEVERITY_CONFIG
            assert "emoji" in SLACK_SEVERITY_CONFIG[sev]
            assert "color" in SLACK_SEVERITY_CONFIG[sev]


# ---------------------------------------------------------------------------
# JiraConnector tests
# ---------------------------------------------------------------------------


class TestJiraConnector:
    def _make_jira(self, **kwargs):
        defaults = {
            "base_url": "https://test.atlassian.net",
            "email": "bot@test.com",
            "api_token": "jira-token-123",
            "project_key": "FIX",
        }
        defaults.update(kwargs)
        return JiraConnector(**defaults)

    def test_configured_with_all_fields(self):
        jira = self._make_jira()
        assert jira.configured is True

    def test_not_configured_missing_token(self):
        jira = self._make_jira(api_token="")
        assert jira.configured is False

    def test_not_configured_missing_url(self):
        jira = self._make_jira(base_url="")
        assert jira.configured is False

    def test_not_configured_missing_email(self):
        jira = self._make_jira(email="")
        assert jira.configured is False

    def test_not_configured_missing_project(self):
        jira = self._make_jira(project_key="")
        assert jira.configured is False

    def test_connector_type_is_jira(self):
        jira = self._make_jira()
        assert jira.connector_type == "jira"

    def test_demo_create_ticket(self):
        jira = self._make_jira(api_token="")  # unconfigured
        finding = {"severity": "critical", "title": "SQL Injection", "cve_id": "CVE-2024-1234"}
        result = run_async(jira.create_ticket(finding))
        assert result.success is False
        assert result.ticket_id is None
        assert result.error is not None
        assert result.connector == "jira"
        assert result.operation == "create_ticket"

    def test_demo_update_ticket(self):
        jira = self._make_jira(api_token="")
        result = run_async(jira.update_ticket("DEMO-ABC", {"summary": "Updated"}))
        assert result.success is False
        assert result.error is not None

    def test_demo_close_ticket(self):
        jira = self._make_jira(api_token="")
        result = run_async(jira.close_ticket("DEMO-ABC", "Fixed"))
        assert result.success is False
        assert result.error is not None

    def test_demo_get_ticket(self):
        jira = self._make_jira(api_token="")
        result = run_async(jira.get_ticket("DEMO-ABC"))
        assert result.success is False
        assert result.error is not None

    def test_demo_test_connection(self):
        jira = self._make_jira(api_token="")
        result = run_async(jira.test_connection())
        assert result.success is False
        assert result.error is not None

    def test_metrics_default(self):
        jira = self._make_jira()
        m = jira.get_metrics()
        assert m["connector"] == "jira"
        assert m["configured"] is True
        assert m["request_count"] == 0
        assert m["error_count"] == 0
        assert m["circuit_state"] == "closed"

    def test_base_url_trailing_slash_stripped(self):
        jira = self._make_jira(base_url="https://test.atlassian.net/")
        assert jira._base_url == "https://test.atlassian.net"


# ---------------------------------------------------------------------------
# GitHubConnector tests
# ---------------------------------------------------------------------------


class TestGitHubConnector:
    def _make_github(self, **kwargs):
        defaults = {
            "token": "ghp_test_token_123",
            "owner": "testorg",
            "repo": "testrepo",
        }
        defaults.update(kwargs)
        return GitHubConnector(**defaults)

    def test_configured_with_all_fields(self):
        gh = self._make_github()
        assert gh.configured is True

    def test_not_configured_missing_token(self):
        gh = self._make_github(token="")
        assert gh.configured is False

    def test_not_configured_missing_owner(self):
        gh = self._make_github(owner="")
        assert gh.configured is False

    def test_not_configured_missing_repo(self):
        gh = self._make_github(repo="")
        assert gh.configured is False

    def test_connector_type_is_github(self):
        gh = self._make_github()
        assert gh.connector_type == "github"

    def test_demo_create_ticket(self):
        gh = self._make_github(token="")
        finding = {"severity": "high", "title": "XSS Vulnerability"}
        result = run_async(gh.create_ticket(finding))
        assert result.success is False
        assert result.error is not None
        assert result.connector == "github"

    def test_demo_update_ticket(self):
        gh = self._make_github(token="")
        result = run_async(gh.update_ticket("42", {"title": "Updated"}))
        assert result.success is False
        assert result.error is not None

    def test_demo_close_ticket(self):
        gh = self._make_github(token="")
        result = run_async(gh.close_ticket("42", "Resolved"))
        assert result.success is False
        assert result.error is not None

    def test_demo_get_ticket(self):
        gh = self._make_github(token="")
        result = run_async(gh.get_ticket("42"))
        assert result.success is False
        assert result.error is not None

    def test_demo_test_connection(self):
        gh = self._make_github(token="")
        result = run_async(gh.test_connection())
        assert result.success is False
        assert result.error is not None


# ---------------------------------------------------------------------------
# SlackConnector tests
# ---------------------------------------------------------------------------


class TestSlackConnector:
    def _make_slack(self, **kwargs):
        defaults = {"webhook_url": "https://hooks.slack.com/services/T00/B00/xxx"}
        defaults.update(kwargs)
        return SlackConnector(**defaults)

    def test_configured_with_valid_url(self):
        slack = self._make_slack()
        assert slack.configured is True

    def test_not_configured_empty_url(self):
        slack = self._make_slack(webhook_url="")
        assert slack.configured is False

    def test_not_configured_non_http_url(self):
        slack = self._make_slack(webhook_url="ftp://not-http")
        assert slack.configured is False

    def test_connector_type_is_slack(self):
        slack = self._make_slack()
        assert slack.connector_type == "slack"

    def test_demo_create_ticket(self):
        slack = self._make_slack(webhook_url="")
        finding = {"severity": "critical", "title": "Critical Alert"}
        result = run_async(slack.create_ticket(finding))
        assert result.success is False
        assert result.error is not None
        assert result.connector == "slack"

    def test_get_ticket_always_fails(self):
        slack = self._make_slack()
        result = run_async(slack.get_ticket("some-id"))
        assert result.success is False
        assert "write-only" in result.error

    def test_demo_test_connection(self):
        slack = self._make_slack(webhook_url="")
        result = run_async(slack.test_connection())
        assert result.success is True

    def test_build_blocks_returns_list(self):
        slack = self._make_slack()
        finding = {
            "severity": "high",
            "title": "Test Finding",
            "cve_id": "CVE-2024-001",
            "cvss_score": 8.5,
            "component": "openssl",
            "description": "A vulnerability in OpenSSL",
            "remediation": "Upgrade to 3.0.14",
        }
        blocks = slack._build_blocks(finding)
        assert isinstance(blocks, list)
        assert len(blocks) >= 4  # header, title, fields, divider, context

    def test_build_blocks_includes_header(self):
        slack = self._make_slack()
        finding = {"severity": "critical", "title": "Test"}
        blocks = slack._build_blocks(finding)
        header_types = [b["type"] for b in blocks]
        assert "header" in header_types

    def test_update_ticket_unconfigured_returns_error(self):
        slack = self._make_slack(webhook_url="")
        result = run_async(slack.update_ticket("id-123", {"text": "update"}))
        assert result.success is False
        assert result.error is not None


# ---------------------------------------------------------------------------
# UniversalConnector tests
# ---------------------------------------------------------------------------


class TestUniversalConnector:
    def test_register_and_list(self):
        uc = UniversalConnector()
        jira = JiraConnector("", "", "", "")
        uc.register("jira", jira)
        connectors = uc.list_connectors()
        assert len(connectors) == 1
        assert connectors[0]["name"] == "jira"
        assert connectors[0]["type"] == "jira"

    def test_register_invalid_name_raises(self):
        uc = UniversalConnector()
        with pytest.raises(ValueError):
            uc.register("", JiraConnector("", "", "", ""))

    def test_register_invalid_connector_type_raises(self):
        uc = UniversalConnector()
        with pytest.raises(TypeError):
            uc.register("bad", "not-a-connector")

    def test_unregister_returns_true(self):
        uc = UniversalConnector()
        jira = JiraConnector("", "", "", "")
        uc.register("jira", jira)
        assert uc.unregister("jira") is True
        assert len(uc.list_connectors()) == 0

    def test_unregister_nonexistent_returns_false(self):
        uc = UniversalConnector()
        assert uc.unregister("nonexistent") is False

    def test_get_connector(self):
        uc = UniversalConnector()
        jira = JiraConnector("", "", "", "")
        uc.register("jira", jira)
        assert uc.get_connector("jira") is jira
        assert uc.get_connector("missing") is None

    def test_create_tickets_no_connectors(self):
        uc = UniversalConnector()
        result = run_async(uc.create_tickets({"severity": "high", "title": "Test"}))
        assert result["total"] == 0
        assert result["success_count"] == 0

    def test_create_tickets_fan_out_unconfigured(self):
        uc = UniversalConnector()
        # Register unconfigured connectors — all return success=False
        uc.register("jira", JiraConnector("", "", "", ""))
        uc.register("github", GitHubConnector("", "", ""))
        uc.register("slack", SlackConnector(""))

        finding = {"severity": "critical", "title": "Demo Test", "cve_id": "CVE-2024-9999"}
        result = run_async(uc.create_tickets(finding))
        assert result["total"] == 3
        assert result["success_count"] == 0
        assert result["error_count"] == 3

    def test_create_tickets_with_targets(self):
        uc = UniversalConnector()
        uc.register("jira", JiraConnector("", "", "", ""))
        uc.register("github", GitHubConnector("", "", ""))
        uc.register("slack", SlackConnector(""))

        finding = {"severity": "high", "title": "Targeted Test"}
        result = run_async(uc.create_tickets(finding, targets=["jira"]))
        assert result["total"] == 1

    def test_create_tickets_unknown_target_skipped(self):
        uc = UniversalConnector()
        uc.register("jira", JiraConnector("", "", "", ""))
        finding = {"severity": "high", "title": "Test"}
        result = run_async(uc.create_tickets(finding, targets=["nonexistent"]))
        assert result["total"] == 0

    def test_test_all_no_connectors(self):
        uc = UniversalConnector()
        result = run_async(uc.test_all())
        assert result["total"] == 0

    def test_test_all_unconfigured(self):
        uc = UniversalConnector()
        # Jira unconfigured → success=False (unhealthy)
        # Slack unconfigured → success=True (special case: not configured is still "OK")
        uc.register("jira", JiraConnector("", "", "", ""))
        uc.register("slack", SlackConnector(""))
        result = run_async(uc.test_all())
        assert result["total"] == 2
        assert result["healthy_count"] == 1

    def test_close_all(self):
        uc = UniversalConnector()
        uc.register("jira", JiraConnector("", "", "", ""))
        # close_all should not raise
        run_async(uc.close_all())

    def test_register_normalises_name(self):
        uc = UniversalConnector()
        uc.register("  JIRA  ", JiraConnector("", "", "", ""))
        assert uc.get_connector("jira") is not None

    def test_register_replaces_existing(self):
        uc = UniversalConnector()
        j1 = JiraConnector("url1", "", "", "")
        j2 = JiraConnector("url2", "", "", "")
        uc.register("jira", j1)
        uc.register("jira", j2)
        assert uc.get_connector("jira") is j2
        assert len(uc.list_connectors()) == 1


# ---------------------------------------------------------------------------
# BaseConnector close
# ---------------------------------------------------------------------------


class TestBaseConnectorClose:
    def test_close_without_client(self):
        jira = JiraConnector("", "", "", "")
        # Should not raise
        run_async(jira.close())

    def test_metrics_count_starts_zero(self):
        gh = GitHubConnector("", "", "")
        m = gh.get_metrics()
        assert m["request_count"] == 0
        assert m["error_count"] == 0
