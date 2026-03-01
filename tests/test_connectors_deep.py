"""Deep tests for Universal Connector — Jira, GitHub, Slack connectors + circuit breaker.

Covers:
- JiraConnector: create/update/close/get ticket, demo mode, auth, severity mapping
- GitHubConnector: create/update/close/get issue, demo mode, label mapping
- SlackConnector: notification, Block Kit builder, demo mode, webhook validation
- _AsyncCircuitBreaker: state transitions, failure threshold, recovery timeout
- ConnectorResult: serialization
- UniversalConnector (orchestrator): register, unregister, fan-out, error isolation
- Severity normalization and text sanitization helpers
- Demo mode: all connectors produce valid results without network

All httpx calls are mocked. No network. Tests run in < 1 second.
At least 25 real test functions.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from connectors.universal_connector import (
    GITHUB_SEVERITY_TO_LABELS,
    JIRA_SEVERITY_TO_PRIORITY,
    SLACK_SEVERITY_CONFIG,
    BaseConnector,
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
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def sample_finding() -> Dict[str, Any]:
    return {
        "title": "SQL Injection in login",
        "severity": "critical",
        "cve_id": "CVE-2024-1234",
        "cwe_id": "CWE-89",
        "cvss_score": 9.8,
        "component": "auth-service",
        "file_path": "auth/login.py",
        "line": 42,
        "description": "User input concatenated into SQL query.",
        "remediation": "Use parameterized queries.",
    }


@pytest.fixture
def jira_configured() -> JiraConnector:
    return JiraConnector(
        base_url="https://test.atlassian.net",
        email="user@test.com",
        api_token="token-abc-123",
        project_key="SEC",
    )


@pytest.fixture
def jira_demo() -> JiraConnector:
    """Jira with empty credentials = demo mode."""
    return JiraConnector(base_url="", email="", api_token="", project_key="")


@pytest.fixture
def github_configured() -> GitHubConnector:
    return GitHubConnector(
        token="ghp_test123456789",
        owner="test-org",
        repo="test-repo",
    )


@pytest.fixture
def github_demo() -> GitHubConnector:
    return GitHubConnector(token="", owner="", repo="")


@pytest.fixture
def slack_configured() -> SlackConnector:
    return SlackConnector(
        webhook_url="https://hooks.slack.com/services/T00/B00/xxx",
        channel="#security-alerts",
    )


@pytest.fixture
def slack_demo() -> SlackConnector:
    return SlackConnector(webhook_url="")


# ============================================================================
# Severity Normalization
# ============================================================================


class TestSeverityNormalization:
    """Validate _normalise_severity handles all input formats."""

    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("critical", "critical"),
            ("CRITICAL", "critical"),
            ("crit", "critical"),
            ("high", "high"),
            ("HIGH", "high"),
            ("medium", "medium"),
            ("med", "medium"),
            ("moderate", "medium"),
            ("low", "low"),
            ("info", "info"),
            ("informational", "info"),
            ("none", "info"),
            (None, "medium"),
            ("", "medium"),
            ("unknown_value", "medium"),
            ("  high  ", "high"),
        ],
    )
    def test_normalise_severity(self, raw, expected):
        assert _normalise_severity(raw) == expected


# ============================================================================
# Text Sanitization
# ============================================================================


class TestTextSanitization:
    """Validate _sanitise_text strips control chars and truncates."""

    def test_strips_null_bytes(self):
        result = _sanitise_text("hello\x00world")
        assert "\x00" not in result
        assert "helloworld" in result

    def test_preserves_newlines_and_tabs(self):
        result = _sanitise_text("line1\nline2\ttab")
        assert "\n" in result
        assert "\t" in result

    def test_truncates_long_text(self):
        long_text = "x" * 40_000
        result = _sanitise_text(long_text, max_length=1000)
        assert len(result) <= 1020  # 1000 + "... [truncated]"
        assert "[truncated]" in result

    def test_empty_input(self):
        assert _sanitise_text(None) == ""
        assert _sanitise_text("") == ""


# ============================================================================
# Secret Masking
# ============================================================================


class TestSecretMasking:
    """Validate _mask_secret hides sensitive data."""

    def test_masks_long_secret(self):
        result = _mask_secret("ghp_xxxxxxxxxxxx")
        assert result.startswith("ghp")
        assert result.endswith("xxx")
        assert "***" in result

    def test_masks_short_secret(self):
        assert _mask_secret("ab") == "***"
        assert _mask_secret("abcdef") == "***"

    def test_masks_empty(self):
        assert _mask_secret(None) == "(empty)"
        assert _mask_secret("") == "(empty)"


# ============================================================================
# Circuit Breaker
# ============================================================================


class TestAsyncCircuitBreaker:
    """Validate circuit breaker state machine."""

    def test_initial_state_closed(self):
        cb = _AsyncCircuitBreaker()
        assert cb.state == _CircuitState.CLOSED

    def test_allows_request_when_closed(self):
        cb = _AsyncCircuitBreaker()
        assert cb.allow_request() is True

    def test_opens_after_threshold_failures(self):
        cb = _AsyncCircuitBreaker(failure_threshold=3)
        for _ in range(3):
            cb.record_failure()
        assert cb.state == _CircuitState.OPEN

    def test_blocks_request_when_open(self):
        cb = _AsyncCircuitBreaker(failure_threshold=2)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == _CircuitState.OPEN
        assert cb.allow_request() is False

    def test_transitions_to_half_open_after_timeout(self):
        cb = _AsyncCircuitBreaker(failure_threshold=1, recovery_timeout=0.0)
        cb.record_failure()
        assert cb._state == _CircuitState.OPEN
        # recovery_timeout=0.0 means immediate transition on next state check
        time.sleep(0.01)
        assert cb.state == _CircuitState.HALF_OPEN

    def test_half_open_allows_request(self):
        cb = _AsyncCircuitBreaker(failure_threshold=1, recovery_timeout=0.0)
        cb.record_failure()
        time.sleep(0.01)
        assert cb.allow_request() is True

    def test_half_open_closes_after_2_successes(self):
        cb = _AsyncCircuitBreaker(failure_threshold=1, recovery_timeout=0.0)
        cb.record_failure()
        time.sleep(0.01)
        _ = cb.state  # trigger transition to half_open
        cb.record_success()
        assert cb._state == _CircuitState.HALF_OPEN
        cb.record_success()
        assert cb._state == _CircuitState.CLOSED

    def test_half_open_reopens_on_failure(self):
        cb = _AsyncCircuitBreaker(failure_threshold=1, recovery_timeout=0.0)
        cb.record_failure()
        time.sleep(0.01)
        _ = cb.state  # trigger half_open
        cb.record_failure()
        assert cb._state == _CircuitState.OPEN

    def test_success_resets_failure_count(self):
        cb = _AsyncCircuitBreaker(failure_threshold=3)
        cb.record_failure()
        cb.record_failure()
        cb.record_success()
        assert cb._failure_count == 0
        # After reset, 2 more failures should not open
        cb.record_failure()
        cb.record_failure()
        assert cb.state == _CircuitState.CLOSED


# ============================================================================
# ConnectorResult
# ============================================================================


class TestConnectorResult:
    """Validate ConnectorResult serialization."""

    def test_to_dict_success(self):
        r = ConnectorResult(
            success=True,
            connector="jira",
            operation="create_ticket",
            ticket_id="SEC-123",
            url="https://test.atlassian.net/browse/SEC-123",
            latency_ms=150.456,
        )
        d = r.to_dict()
        assert d["success"] is True
        assert d["connector"] == "jira"
        assert d["ticket_id"] == "SEC-123"
        assert d["latency_ms"] == 150.46

    def test_to_dict_error(self):
        r = ConnectorResult(
            success=False,
            connector="github",
            operation="create_ticket",
            error="HTTP 500: Internal Server Error",
        )
        d = r.to_dict()
        assert d["success"] is False
        assert d["error"] == "HTTP 500: Internal Server Error"

    def test_to_dict_demo_mode(self):
        r = ConnectorResult(
            success=True,
            connector="slack",
            operation="create_ticket",
            demo_mode=True,
            latency_ms=5.0,
        )
        d = r.to_dict()
        assert d["demo_mode"] is True


# ============================================================================
# Finding Formatters
# ============================================================================


class TestFindingFormatters:
    """Validate _format_finding_title and _format_finding_description."""

    def test_title_includes_severity_and_cve(self, sample_finding):
        title = _format_finding_title(sample_finding)
        assert "[CRITICAL]" in title
        assert "[CVE-2024-1234]" in title
        assert "SQL Injection" in title

    def test_title_without_cve(self):
        finding = {"title": "Open redirect", "severity": "medium"}
        title = _format_finding_title(finding)
        assert "[MEDIUM]" in title
        assert "Open redirect" in title

    def test_description_has_severity_and_sections(self, sample_finding):
        desc = _format_finding_description(sample_finding)
        assert "**Severity**: CRITICAL" in desc
        assert "**CVE**: CVE-2024-1234" in desc
        assert "**CVSS**: 9.8" in desc
        assert "## Description" in desc
        assert "## Remediation" in desc
        assert "ALdeci CTEM+" in desc


# ============================================================================
# Severity Mappings
# ============================================================================


class TestSeverityMappings:
    """Validate platform-specific severity mappings."""

    @pytest.mark.parametrize(
        "severity, priority",
        [
            ("critical", "Highest"),
            ("high", "High"),
            ("medium", "Medium"),
            ("low", "Low"),
            ("info", "Lowest"),
        ],
    )
    def test_jira_mapping(self, severity, priority):
        assert JIRA_SEVERITY_TO_PRIORITY[severity] == priority

    @pytest.mark.parametrize(
        "severity",
        ["critical", "high", "medium", "low", "info"],
    )
    def test_github_labels_include_security(self, severity):
        labels = GITHUB_SEVERITY_TO_LABELS[severity]
        assert "security" in labels

    @pytest.mark.parametrize(
        "severity",
        ["critical", "high", "medium", "low", "info"],
    )
    def test_slack_config_has_emoji_and_color(self, severity):
        cfg = SLACK_SEVERITY_CONFIG[severity]
        assert "emoji" in cfg
        assert "color" in cfg
        assert cfg["color"].startswith("#")


# ============================================================================
# JiraConnector — Demo Mode
# ============================================================================


class TestJiraDemoMode:
    """Jira connector in demo mode (no credentials) produces valid results."""

    def test_not_configured(self, jira_demo):
        assert jira_demo.configured is False

    def test_configured_with_creds(self, jira_configured):
        assert jira_configured.configured is True

    @pytest.mark.asyncio
    async def test_demo_create_ticket(self, jira_demo, sample_finding):
        result = await jira_demo.create_ticket(sample_finding)
        assert result.success is True
        assert result.demo_mode is True
        assert result.ticket_id.startswith("DEMO-")
        assert result.connector == "jira"

    @pytest.mark.asyncio
    async def test_demo_update_ticket(self, jira_demo):
        result = await jira_demo.update_ticket("DEMO-ABC", {"summary": "updated"})
        assert result.success is True
        assert result.demo_mode is True

    @pytest.mark.asyncio
    async def test_demo_close_ticket(self, jira_demo):
        result = await jira_demo.close_ticket("DEMO-ABC", "Fixed")
        assert result.success is True
        assert result.demo_mode is True

    @pytest.mark.asyncio
    async def test_demo_get_ticket(self, jira_demo):
        result = await jira_demo.get_ticket("DEMO-ABC")
        assert result.success is True
        assert result.demo_mode is True

    @pytest.mark.asyncio
    async def test_demo_test_connection(self, jira_demo):
        result = await jira_demo.test_connection()
        assert result.success is True
        assert result.demo_mode is True


# ============================================================================
# JiraConnector — Mocked HTTP
# ============================================================================


class TestJiraConnectorHTTP:
    """Jira connector with mocked httpx client."""

    @pytest.mark.asyncio
    async def test_create_ticket_success(self, jira_configured, sample_finding):
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 201
        mock_response.json.return_value = {"key": "SEC-42", "id": "10042"}

        with patch.object(jira_configured, "_request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = mock_response
            result = await jira_configured.create_ticket(sample_finding)

        assert result.success is True
        assert result.ticket_id == "SEC-42"
        assert "SEC-42" in result.url

    @pytest.mark.asyncio
    async def test_create_ticket_failure(self, jira_configured, sample_finding):
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 400
        mock_response.text = "Bad Request"

        with patch.object(jira_configured, "_request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = mock_response
            result = await jira_configured.create_ticket(sample_finding)

        assert result.success is False
        assert "400" in result.error

    @pytest.mark.asyncio
    async def test_create_ticket_exception(self, jira_configured, sample_finding):
        with patch.object(jira_configured, "_request", new_callable=AsyncMock) as mock_req:
            mock_req.side_effect = httpx.ConnectError("Connection refused")
            result = await jira_configured.create_ticket(sample_finding)

        assert result.success is False
        assert "Connection refused" in result.error

    @pytest.mark.asyncio
    async def test_update_ticket_no_fields(self, jira_configured):
        result = await jira_configured.update_ticket("SEC-1", {})
        assert result.success is False
        assert "No fields" in result.error

    @pytest.mark.asyncio
    async def test_get_ticket_success(self, jira_configured):
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "key": "SEC-1",
            "fields": {"summary": "Test", "status": {"name": "Open"}},
        }

        with patch.object(jira_configured, "_request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = mock_response
            result = await jira_configured.get_ticket("SEC-1")

        assert result.success is True
        assert result.ticket_id == "SEC-1"


# ============================================================================
# GitHubConnector — Demo Mode
# ============================================================================


class TestGitHubDemoMode:
    """GitHub connector in demo mode."""

    def test_not_configured(self, github_demo):
        assert github_demo.configured is False

    def test_configured_with_creds(self, github_configured):
        assert github_configured.configured is True

    @pytest.mark.asyncio
    async def test_demo_create_ticket(self, github_demo, sample_finding):
        result = await github_demo.create_ticket(sample_finding)
        assert result.success is True
        assert result.demo_mode is True
        assert result.connector == "github"
        assert result.ticket_id is not None

    @pytest.mark.asyncio
    async def test_demo_close_ticket(self, github_demo):
        result = await github_demo.close_ticket("42", "Fixed")
        assert result.success is True
        assert result.demo_mode is True
        assert result.details.get("state") == "closed"


# ============================================================================
# GitHubConnector — Mocked HTTP
# ============================================================================


class TestGitHubConnectorHTTP:
    """GitHub connector with mocked httpx client."""

    @pytest.mark.asyncio
    async def test_create_issue_success(self, github_configured, sample_finding):
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 201
        mock_response.json.return_value = {
            "number": 99,
            "id": 12345,
            "html_url": "https://github.com/test-org/test-repo/issues/99",
        }

        with patch.object(github_configured, "_request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = mock_response
            result = await github_configured.create_ticket(sample_finding)

        assert result.success is True
        assert result.ticket_id == "99"
        assert "issues/99" in result.url

    @pytest.mark.asyncio
    async def test_update_issue_no_fields(self, github_configured):
        result = await github_configured.update_ticket("99", {})
        assert result.success is False
        assert "No fields" in result.error

    @pytest.mark.asyncio
    async def test_test_connection_success(self, github_configured):
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.json.return_value = {"login": "testuser", "name": "Test User"}

        with patch.object(github_configured, "_request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = mock_response
            result = await github_configured.test_connection()

        assert result.success is True
        assert result.details["user"] == "testuser"

    @pytest.mark.asyncio
    async def test_test_connection_demo(self, github_demo):
        result = await github_demo.test_connection()
        assert result.success is True
        assert result.demo_mode is True


# ============================================================================
# SlackConnector — Demo Mode
# ============================================================================


class TestSlackDemoMode:
    """Slack connector in demo mode."""

    def test_not_configured(self, slack_demo):
        assert slack_demo.configured is False

    def test_configured_with_webhook(self, slack_configured):
        assert slack_configured.configured is True

    @pytest.mark.asyncio
    async def test_demo_create_notification(self, slack_demo, sample_finding):
        result = await slack_demo.create_ticket(sample_finding)
        assert result.success is True
        assert result.demo_mode is True
        assert result.connector == "slack"
        assert result.ticket_id is not None

    @pytest.mark.asyncio
    async def test_get_ticket_is_unsupported(self, slack_demo):
        result = await slack_demo.get_ticket("abc123")
        assert result.success is False
        assert "write-only" in result.error

    @pytest.mark.asyncio
    async def test_demo_test_connection(self, slack_demo):
        result = await slack_demo.test_connection()
        assert result.success is True
        assert result.demo_mode is True


# ============================================================================
# SlackConnector — Block Kit Builder
# ============================================================================


class TestSlackBlockKit:
    """Validate Slack Block Kit message construction."""

    def test_build_blocks_has_header(self, slack_configured, sample_finding):
        blocks = slack_configured._build_blocks(sample_finding)
        header = blocks[0]
        assert header["type"] == "header"

    def test_build_blocks_has_severity_field(self, slack_configured, sample_finding):
        blocks = slack_configured._build_blocks(sample_finding)
        # Find the section with fields
        field_section = None
        for b in blocks:
            if b.get("type") == "section" and "fields" in b:
                field_section = b
                break
        assert field_section is not None
        field_texts = [f["text"] for f in field_section["fields"]]
        severity_field = [t for t in field_texts if "Severity" in t]
        assert len(severity_field) > 0

    def test_build_blocks_has_divider(self, slack_configured, sample_finding):
        blocks = slack_configured._build_blocks(sample_finding)
        types = [b["type"] for b in blocks]
        assert "divider" in types

    def test_build_blocks_has_context_footer(self, slack_configured, sample_finding):
        blocks = slack_configured._build_blocks(sample_finding)
        context_blocks = [b for b in blocks if b["type"] == "context"]
        assert len(context_blocks) > 0
        footer_text = context_blocks[0]["elements"][0]["text"]
        assert "ALdeci CTEM+" in footer_text


# ============================================================================
# SlackConnector — Mocked HTTP
# ============================================================================


class TestSlackConnectorHTTP:
    """Slack connector with mocked httpx client."""

    @pytest.mark.asyncio
    async def test_create_notification_success(self, slack_configured, sample_finding):
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 200
        mock_response.text = "ok"

        with patch.object(slack_configured, "_request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = mock_response
            result = await slack_configured.create_ticket(sample_finding)

        assert result.success is True
        assert result.connector == "slack"
        assert result.ticket_id is not None  # sha256 notification ID

    @pytest.mark.asyncio
    async def test_create_notification_failure(self, slack_configured, sample_finding):
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 500
        mock_response.text = "Internal error"

        with patch.object(slack_configured, "_request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = mock_response
            result = await slack_configured.create_ticket(sample_finding)

        assert result.success is False
        assert "500" in result.error

    @pytest.mark.asyncio
    async def test_test_connection_reachable(self, slack_configured):
        mock_response = MagicMock(spec=httpx.Response)
        mock_response.status_code = 400  # Slack returns 400 for empty text, but reachable

        with patch.object(slack_configured, "_request", new_callable=AsyncMock) as mock_req:
            mock_req.return_value = mock_response
            result = await slack_configured.test_connection()

        assert result.success is True
        assert "reachable" in result.details["message"].lower()


# ============================================================================
# UniversalConnector — Orchestrator
# ============================================================================


class TestUniversalConnector:
    """Validate the UniversalConnector orchestrator."""

    def test_register_and_list(self):
        uc = UniversalConnector()
        jira = JiraConnector(
            base_url="https://x.atlassian.net", email="a@b.c",
            api_token="tok", project_key="P",
        )
        uc.register("my-jira", jira)
        connectors = uc.list_connectors()
        assert len(connectors) == 1
        assert connectors[0]["name"] == "my-jira"
        assert connectors[0]["type"] == "jira"

    def test_register_validates_name(self):
        uc = UniversalConnector()
        with pytest.raises(ValueError):
            uc.register("", JiraConnector("", "", "", ""))
        with pytest.raises(TypeError):
            uc.register("bad", "not a connector")  # type: ignore

    def test_unregister(self):
        uc = UniversalConnector()
        slack = SlackConnector(webhook_url="https://hooks.slack.com/xxx")
        uc.register("alerts", slack)
        assert uc.unregister("alerts") is True
        assert uc.unregister("alerts") is False  # already removed

    def test_get_connector(self):
        uc = UniversalConnector()
        gh = GitHubConnector(token="t", owner="o", repo="r")
        uc.register("gh", gh)
        assert uc.get_connector("gh") is gh
        assert uc.get_connector("nonexistent") is None

    @pytest.mark.asyncio
    async def test_create_tickets_fan_out(self, sample_finding):
        uc = UniversalConnector()
        # Register demo connectors (no real HTTP)
        uc.register("jira", JiraConnector("", "", "", ""))
        uc.register("github", GitHubConnector("", "", ""))
        uc.register("slack", SlackConnector(""))

        results = await uc.create_tickets(sample_finding)
        assert results["total"] == 3
        assert results["success_count"] == 3  # all demo mode
        assert results["error_count"] == 0

    @pytest.mark.asyncio
    async def test_create_tickets_with_targets(self, sample_finding):
        uc = UniversalConnector()
        uc.register("jira", JiraConnector("", "", "", ""))
        uc.register("slack", SlackConnector(""))

        results = await uc.create_tickets(sample_finding, targets=["slack"])
        assert results["total"] == 1
        assert results["results"][0]["connector"] == "slack"

    @pytest.mark.asyncio
    async def test_create_tickets_empty_connectors(self, sample_finding):
        uc = UniversalConnector()
        results = await uc.create_tickets(sample_finding)
        assert results["total"] == 0
        assert results["success_count"] == 0

    @pytest.mark.asyncio
    async def test_test_all(self):
        uc = UniversalConnector()
        uc.register("jira", JiraConnector("", "", "", ""))
        uc.register("github", GitHubConnector("", "", ""))

        results = await uc.test_all()
        assert results["total"] == 2
        assert results["healthy_count"] == 2  # demo mode = healthy

    @pytest.mark.asyncio
    async def test_test_all_empty(self):
        uc = UniversalConnector()
        results = await uc.test_all()
        assert results["total"] == 0

    @pytest.mark.asyncio
    async def test_error_isolation(self, sample_finding):
        """If one connector throws, others still succeed."""
        uc = UniversalConnector()

        # Register a demo slack (will succeed)
        uc.register("slack", SlackConnector(""))

        # Register a connector that will raise
        class BrokenConnector(BaseConnector):
            _connector_type = "broken"

            async def create_ticket(self, finding):
                raise RuntimeError("Kaboom")

            async def update_ticket(self, ticket_id, update):
                pass

            async def close_ticket(self, ticket_id, resolution):
                pass

            async def get_ticket(self, ticket_id):
                pass

            async def test_connection(self):
                pass

        uc.register("broken", BrokenConnector())

        results = await uc.create_tickets(sample_finding)
        assert results["total"] == 2
        assert results["success_count"] == 1  # slack demo
        assert results["error_count"] == 1  # broken
        # Verify the broken one reported the error
        broken_result = [r for r in results["results"] if r["connector"] == "broken"]
        assert len(broken_result) == 1
        assert "Kaboom" in broken_result[0]["error"]

    @pytest.mark.asyncio
    async def test_close_all(self):
        uc = UniversalConnector()
        uc.register("jira", JiraConnector("", "", "", ""))
        # Should not raise even if clients are not opened
        await uc.close_all()


# ============================================================================
# BaseConnector Metrics
# ============================================================================


class TestBaseConnectorMetrics:
    """Validate metrics tracking on connectors."""

    def test_metrics_initial(self, jira_configured):
        m = jira_configured.get_metrics()
        assert m["connector"] == "jira"
        assert m["configured"] is True
        assert m["request_count"] == 0
        assert m["error_count"] == 0
        assert m["circuit_state"] == "closed"

    def test_connector_type(self, jira_configured, github_configured, slack_configured):
        assert jira_configured.connector_type == "jira"
        assert github_configured.connector_type == "github"
        assert slack_configured.connector_type == "slack"


# ============================================================================
# BaseConnector — Circuit Breaker integration
# ============================================================================


class TestCircuitBreakerIntegration:
    """Verify circuit breaker blocks requests when open."""

    @pytest.mark.asyncio
    async def test_request_blocked_when_circuit_open(self, jira_configured):
        # Manually force circuit open
        jira_configured._circuit_breaker._state = _CircuitState.OPEN
        jira_configured._circuit_breaker._last_failure_time = time.monotonic()
        jira_configured._circuit_breaker.recovery_timeout = 9999.0

        with pytest.raises(httpx.ConnectError, match="Circuit breaker is OPEN"):
            await jira_configured._request("GET", "https://example.com/test")
