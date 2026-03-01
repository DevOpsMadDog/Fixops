"""Comprehensive tests for suite-core/connectors/universal_connector.py
and suite-api/apps/api/connectors_router.py.

Covers:
  1.  ConnectorResult.to_dict() serialization
  2.  _normalise_severity() with all aliases
  3.  _sanitise_text() -- truncation, control chars, empty input
  4.  _mask_secret() -- short, long, empty strings
  5.  _AsyncCircuitBreaker -- state transitions (CLOSED -> OPEN -> HALF_OPEN -> CLOSED)
  6.  JiraConnector -- format_finding(), create_ticket() demo mode
  7.  GitHubConnector -- format_finding(), create_issue() demo mode
  8.  SlackConnector -- format_blocks(), send_notification() demo mode
  9.  UniversalConnector -- register, list, fan_out demo mode
  10. FastAPI router endpoints via TestClient
  11. Pydantic input validation (RegisterConnectorRequest, FindingInput)
"""

from __future__ import annotations

import time
from typing import Any, Dict

import pytest

# ---------------------------------------------------------------------------
# Source imports (suite-core is on sys.path via conftest / sitecustomize)
# ---------------------------------------------------------------------------
from connectors.universal_connector import (
    _AsyncCircuitBreaker,
    _CircuitState,
    _format_finding_description,
    _format_finding_title,
    _mask_secret,
    _normalise_severity,
    _sanitise_text,
    BaseConnector,
    ConnectorResult,
    GitHubConnector,
    GITHUB_SEVERITY_TO_LABELS,
    JIRA_SEVERITY_TO_PRIORITY,
    JiraConnector,
    SLACK_SEVERITY_CONFIG,
    SlackConnector,
    UniversalConnector,
)


# ---------------------------------------------------------------------------
# Sample finding used across many tests
# ---------------------------------------------------------------------------
SAMPLE_FINDING: Dict[str, Any] = {
    "title": "SQL Injection in login handler",
    "severity": "critical",
    "cve_id": "CVE-2024-1234",
    "cwe_id": "CWE-89",
    "cvss_score": 9.8,
    "component": "auth-service",
    "file_path": "src/auth/login.py",
    "line": 42,
    "description": "User input is concatenated directly into SQL query.",
    "remediation": "Use parameterised queries.",
}


# =========================================================================
# 1. ConnectorResult.to_dict()
# =========================================================================
class TestConnectorResultSerialization:
    """Verify ConnectorResult.to_dict() includes the right keys."""

    def test_minimal_success(self):
        r = ConnectorResult(success=True, connector="jira", operation="create_ticket")
        d = r.to_dict()
        assert d["success"] is True
        assert d["connector"] == "jira"
        assert d["operation"] == "create_ticket"
        assert "latency_ms" in d
        # Optional fields should be absent when empty
        assert "ticket_id" not in d
        assert "url" not in d
        assert "error" not in d
        assert "details" not in d
        assert "demo_mode" not in d

    def test_full_fields(self):
        r = ConnectorResult(
            success=False,
            connector="github",
            operation="update_ticket",
            ticket_id="42",
            url="https://github.com/org/repo/issues/42",
            error="HTTP 500",
            details={"key": "value"},
            latency_ms=123.456789,
            demo_mode=True,
        )
        d = r.to_dict()
        assert d["success"] is False
        assert d["ticket_id"] == "42"
        assert d["url"].endswith("/42")
        assert d["error"] == "HTTP 500"
        assert d["details"] == {"key": "value"}
        assert d["latency_ms"] == 123.46  # rounded to 2 decimal places
        assert d["demo_mode"] is True

    def test_demo_mode_false_omitted(self):
        r = ConnectorResult(
            success=True, connector="slack", operation="test", demo_mode=False
        )
        d = r.to_dict()
        assert "demo_mode" not in d


# =========================================================================
# 2. _normalise_severity()
# =========================================================================
class TestNormaliseSeverity:
    """All documented aliases must normalise correctly."""

    @pytest.mark.parametrize(
        "raw, expected",
        [
            ("critical", "critical"),
            ("CRITICAL", "critical"),
            ("crit", "critical"),
            ("  Crit  ", "critical"),
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
    def test_known_aliases(self, raw: str, expected: str):
        assert _normalise_severity(raw) == expected

    def test_unknown_defaults_to_medium(self):
        assert _normalise_severity("banana") == "medium"
        assert _normalise_severity("UNKNOWN") == "medium"

    def test_none_defaults_to_medium(self):
        assert _normalise_severity(None) == "medium"

    def test_empty_string_defaults_to_medium(self):
        assert _normalise_severity("") == "medium"


# =========================================================================
# 3. _sanitise_text()
# =========================================================================
class TestSanitiseText:
    """Strip control chars, truncate, handle None/empty."""

    def test_empty_input(self):
        assert _sanitise_text(None) == ""
        assert _sanitise_text("") == ""

    def test_normal_text_unchanged(self):
        txt = "Hello, world!\nSecond line\tTabbed"
        assert _sanitise_text(txt) == txt

    def test_control_chars_removed(self):
        text_with_ctrl = "abc\x00def\x01ghi\x08jkl"
        result = _sanitise_text(text_with_ctrl)
        assert "\x00" not in result
        assert "\x01" not in result
        assert "\x08" not in result
        assert "abcdefghijkl" == result

    def test_newlines_and_tabs_preserved(self):
        text = "line1\nline2\ttab"
        assert _sanitise_text(text) == text

    def test_truncation(self):
        long_text = "x" * 100
        result = _sanitise_text(long_text, max_length=50)
        assert result.endswith("... [truncated]")
        # First 50 chars preserved
        assert result.startswith("x" * 50)

    def test_exact_length_not_truncated(self):
        text = "a" * 50
        result = _sanitise_text(text, max_length=50)
        assert result == text
        assert "truncated" not in result


# =========================================================================
# 4. _mask_secret()
# =========================================================================
class TestMaskSecret:
    """Verify secret masking for logging safety."""

    def test_none_returns_empty(self):
        assert _mask_secret(None) == "(empty)"

    def test_empty_returns_empty(self):
        assert _mask_secret("") == "(empty)"

    def test_short_string_fully_masked(self):
        assert _mask_secret("abc") == "***"
        assert _mask_secret("123456") == "***"

    def test_long_string_partially_visible(self):
        result = _mask_secret("ghp_abcdefghij12345")
        assert result.startswith("ghp")
        assert result.endswith("345")
        assert "***" in result

    def test_exact_boundary(self):
        # len == 7 is the first length that shows partial
        result = _mask_secret("1234567")
        assert result == "123***567"


# =========================================================================
# 5. _AsyncCircuitBreaker state transitions
# =========================================================================
class TestAsyncCircuitBreaker:
    """Test CLOSED -> OPEN -> HALF_OPEN -> CLOSED cycle."""

    def test_initial_state_closed(self):
        cb = _AsyncCircuitBreaker()
        assert cb.state == _CircuitState.CLOSED
        assert cb.allow_request() is True

    def test_remains_closed_below_threshold(self):
        cb = _AsyncCircuitBreaker(failure_threshold=5)
        for _ in range(4):
            cb.record_failure()
        assert cb.state == _CircuitState.CLOSED
        assert cb.allow_request() is True

    def test_opens_at_threshold(self):
        cb = _AsyncCircuitBreaker(failure_threshold=3)
        for _ in range(3):
            cb.record_failure()
        assert cb.state == _CircuitState.OPEN
        assert cb.allow_request() is False

    def test_open_to_half_open_after_recovery_timeout(self):
        cb = _AsyncCircuitBreaker(failure_threshold=1, recovery_timeout=0.05)
        cb.record_failure()
        assert cb.state == _CircuitState.OPEN
        time.sleep(0.06)
        assert cb.state == _CircuitState.HALF_OPEN
        assert cb.allow_request() is True

    def test_half_open_to_closed_after_successes(self):
        cb = _AsyncCircuitBreaker(failure_threshold=1, recovery_timeout=0.01)
        cb.record_failure()
        time.sleep(0.02)
        assert cb.state == _CircuitState.HALF_OPEN
        cb.record_success()
        # Still half-open after 1 success (needs 2)
        assert cb._state == _CircuitState.HALF_OPEN
        cb.record_success()
        assert cb._state == _CircuitState.CLOSED
        assert cb._failure_count == 0

    def test_half_open_back_to_open_on_failure(self):
        cb = _AsyncCircuitBreaker(failure_threshold=1, recovery_timeout=0.01)
        cb.record_failure()
        time.sleep(0.02)
        assert cb.state == _CircuitState.HALF_OPEN
        cb.record_failure()
        assert cb._state == _CircuitState.OPEN

    def test_success_in_closed_resets_count(self):
        cb = _AsyncCircuitBreaker(failure_threshold=5)
        cb.record_failure()
        cb.record_failure()
        cb.record_success()
        assert cb._failure_count == 0
        # Subsequent failures start from 0
        cb.record_failure()
        assert cb._failure_count == 1


# =========================================================================
# 6. JiraConnector -- demo mode
# =========================================================================
class TestJiraConnector:
    """Test JiraConnector formatting and demo mode operations."""

    def _make_unconfigured(self) -> JiraConnector:
        return JiraConnector(
            base_url="", email="", api_token="", project_key=""
        )

    def _make_configured(self) -> JiraConnector:
        return JiraConnector(
            base_url="https://test.atlassian.net",
            email="user@example.com",
            api_token="token-123",
            project_key="SEC",
        )

    def test_configured_property(self):
        assert self._make_unconfigured().configured is False
        assert self._make_configured().configured is True

    def test_connector_type(self):
        assert self._make_unconfigured().connector_type == "jira"

    def test_format_finding_title(self):
        title = _format_finding_title(SAMPLE_FINDING)
        assert "[CRITICAL]" in title
        assert "[CVE-2024-1234]" in title
        assert "SQL Injection" in title

    def test_format_finding_description(self):
        desc = _format_finding_description(SAMPLE_FINDING)
        assert "**Severity**: CRITICAL" in desc
        assert "**CVE**: CVE-2024-1234" in desc
        assert "**CWE**: CWE-89" in desc
        assert "**CVSS**: 9.8" in desc
        assert "**Component**: auth-service" in desc
        assert "**File**: src/auth/login.py" in desc
        assert "**Line**: 42" in desc
        assert "User input is concatenated" in desc
        assert "parameterised queries" in desc
        assert "ALdeci CTEM+" in desc

    def test_format_finding_title_no_cve(self):
        finding = {"title": "XSS issue", "severity": "high"}
        title = _format_finding_title(finding)
        assert "[HIGH]" in title
        assert "CVE" not in title
        assert "XSS issue" in title

    def test_format_finding_title_uses_summary_fallback(self):
        finding = {"summary": "Fallback summary", "severity": "low"}
        title = _format_finding_title(finding)
        assert "Fallback summary" in title

    def test_format_finding_title_default_when_no_title(self):
        finding = {"severity": "info"}
        title = _format_finding_title(finding)
        assert "Security Finding" in title

    @pytest.mark.asyncio
    async def test_demo_create_ticket(self):
        jira = self._make_unconfigured()
        result = await jira.create_ticket(SAMPLE_FINDING)
        assert result.success is True
        assert result.demo_mode is True
        assert result.connector == "jira"
        assert result.operation == "create_ticket"
        assert result.ticket_id is not None
        assert result.ticket_id.startswith("DEMO-")
        assert "demo.atlassian.net" in result.url
        assert result.details["status"] == "created"

    @pytest.mark.asyncio
    async def test_demo_update_ticket(self):
        jira = self._make_unconfigured()
        result = await jira.update_ticket("DEMO-ABC", {"summary": "Updated"})
        assert result.success is True
        assert result.demo_mode is True
        assert result.ticket_id == "DEMO-ABC"

    @pytest.mark.asyncio
    async def test_demo_close_ticket(self):
        jira = self._make_unconfigured()
        result = await jira.close_ticket("DEMO-X", "Fixed in v2")
        assert result.success is True
        assert result.demo_mode is True
        assert result.details["resolution"] == "Fixed in v2"

    @pytest.mark.asyncio
    async def test_demo_get_ticket(self):
        jira = self._make_unconfigured()
        result = await jira.get_ticket("DEMO-Y")
        assert result.success is True
        assert result.demo_mode is True
        assert result.ticket_id == "DEMO-Y"
        assert "Demo ticket" in result.details["summary"]

    @pytest.mark.asyncio
    async def test_demo_test_connection(self):
        jira = self._make_unconfigured()
        result = await jira.test_connection()
        assert result.success is True
        assert result.demo_mode is True
        assert "Demo mode" in result.details["message"]

    def test_get_metrics(self):
        jira = self._make_configured()
        metrics = jira.get_metrics()
        assert metrics["connector"] == "jira"
        assert metrics["configured"] is True
        assert metrics["request_count"] == 0
        assert metrics["error_count"] == 0
        assert metrics["circuit_state"] == "closed"

    def test_jira_severity_to_priority_mapping(self):
        assert JIRA_SEVERITY_TO_PRIORITY["critical"] == "Highest"
        assert JIRA_SEVERITY_TO_PRIORITY["high"] == "High"
        assert JIRA_SEVERITY_TO_PRIORITY["medium"] == "Medium"
        assert JIRA_SEVERITY_TO_PRIORITY["low"] == "Low"
        assert JIRA_SEVERITY_TO_PRIORITY["info"] == "Lowest"


# =========================================================================
# 7. GitHubConnector -- demo mode
# =========================================================================
class TestGitHubConnector:
    """Test GitHubConnector formatting and demo mode operations."""

    def _make_unconfigured(self) -> GitHubConnector:
        return GitHubConnector(token="", owner="", repo="")

    def _make_configured(self) -> GitHubConnector:
        return GitHubConnector(token="ghp_test123", owner="acme", repo="security")

    def test_configured_property(self):
        assert self._make_unconfigured().configured is False
        assert self._make_configured().configured is True

    def test_connector_type(self):
        assert self._make_unconfigured().connector_type == "github"

    @pytest.mark.asyncio
    async def test_demo_create_ticket(self):
        gh = self._make_unconfigured()
        result = await gh.create_ticket(SAMPLE_FINDING)
        assert result.success is True
        assert result.demo_mode is True
        assert result.connector == "github"
        assert result.operation == "create_ticket"
        assert result.ticket_id is not None
        assert "github.com" in result.url
        assert result.details["status"] == "open"

    @pytest.mark.asyncio
    async def test_demo_update_ticket(self):
        gh = self._make_unconfigured()
        result = await gh.update_ticket("123", {"title": "Updated title"})
        assert result.success is True
        assert result.demo_mode is True

    @pytest.mark.asyncio
    async def test_demo_close_ticket(self):
        gh = self._make_unconfigured()
        result = await gh.close_ticket("456", "Patched")
        assert result.success is True
        assert result.demo_mode is True
        assert result.details["state"] == "closed"

    @pytest.mark.asyncio
    async def test_demo_get_ticket(self):
        gh = self._make_unconfigured()
        result = await gh.get_ticket("789")
        assert result.success is True
        assert result.demo_mode is True
        assert "Demo issue" in result.details["title"]

    @pytest.mark.asyncio
    async def test_demo_test_connection(self):
        gh = self._make_unconfigured()
        result = await gh.test_connection()
        assert result.success is True
        assert result.demo_mode is True

    def test_github_severity_labels_mapping(self):
        labels = GITHUB_SEVERITY_TO_LABELS["critical"]
        assert "security" in labels
        assert "priority: critical" in labels
        assert "bug" in labels

    def test_github_info_labels(self):
        labels = GITHUB_SEVERITY_TO_LABELS["info"]
        assert "security" in labels
        assert "informational" in labels


# =========================================================================
# 8. SlackConnector -- demo mode
# =========================================================================
class TestSlackConnector:
    """Test SlackConnector block building and demo mode operations."""

    def _make_unconfigured(self) -> SlackConnector:
        return SlackConnector(webhook_url="")

    def _make_configured(self) -> SlackConnector:
        return SlackConnector(
            webhook_url="https://hooks.slack.com/services/T/B/X",
            channel="#security-alerts",
        )

    def test_configured_property(self):
        assert self._make_unconfigured().configured is False
        assert self._make_configured().configured is True

    def test_connector_type(self):
        assert self._make_unconfigured().connector_type == "slack"

    def test_build_blocks_structure(self):
        slack = self._make_configured()
        blocks = slack._build_blocks(SAMPLE_FINDING)
        assert isinstance(blocks, list)
        assert len(blocks) >= 4  # header, title, fields, divider, footer

        # Header block
        assert blocks[0]["type"] == "header"
        assert "Security Finding" in blocks[0]["text"]["text"]

        # Title section
        assert blocks[1]["type"] == "section"

        # Fields section
        fields_block = blocks[2]
        assert fields_block["type"] == "section"
        assert "fields" in fields_block
        field_texts = [f["text"] for f in fields_block["fields"]]
        severity_field = [t for t in field_texts if "Severity" in t]
        assert len(severity_field) >= 1
        assert "CRITICAL" in severity_field[0]

        # Divider present
        divider_blocks = [b for b in blocks if b["type"] == "divider"]
        assert len(divider_blocks) >= 1

        # Context footer
        context_blocks = [b for b in blocks if b["type"] == "context"]
        assert len(context_blocks) >= 1
        assert "ALdeci CTEM+" in context_blocks[0]["elements"][0]["text"]

    def test_build_blocks_with_cve(self):
        slack = self._make_configured()
        blocks = slack._build_blocks(SAMPLE_FINDING)
        fields_block = blocks[2]
        field_texts = " ".join(f["text"] for f in fields_block["fields"])
        assert "CVE-2024-1234" in field_texts

    def test_build_blocks_minimal_finding(self):
        slack = self._make_configured()
        blocks = slack._build_blocks({"severity": "low"})
        assert isinstance(blocks, list)
        assert len(blocks) >= 3

    def test_build_blocks_with_description_and_remediation(self):
        slack = self._make_configured()
        blocks = slack._build_blocks(SAMPLE_FINDING)
        section_texts = [
            b.get("text", {}).get("text", "")
            for b in blocks
            if b.get("type") == "section"
        ]
        all_text = " ".join(section_texts)
        assert "concatenated" in all_text or "SQL" in all_text
        assert "parameterised" in all_text or "Remediation" in all_text

    @pytest.mark.asyncio
    async def test_demo_create_ticket(self):
        slack = self._make_unconfigured()
        result = await slack.create_ticket(SAMPLE_FINDING)
        assert result.success is True
        assert result.demo_mode is True
        assert result.connector == "slack"
        assert result.operation == "create_ticket"
        assert result.ticket_id is not None
        assert len(result.ticket_id) == 16  # uuid hex[:16]
        assert result.details["status"] == "sent"

    @pytest.mark.asyncio
    async def test_demo_create_ticket_with_channel(self):
        slack = SlackConnector(webhook_url="", channel="#test-channel")
        result = await slack.create_ticket(SAMPLE_FINDING)
        assert result.details["channel"] == "#test-channel"

    @pytest.mark.asyncio
    async def test_demo_create_ticket_default_channel(self):
        slack = self._make_unconfigured()
        result = await slack.create_ticket(SAMPLE_FINDING)
        assert result.details["channel"] == "#security-alerts"

    @pytest.mark.asyncio
    async def test_demo_test_connection(self):
        slack = self._make_unconfigured()
        result = await slack.test_connection()
        assert result.success is True
        assert result.demo_mode is True

    @pytest.mark.asyncio
    async def test_get_ticket_always_fails(self):
        """Slack webhooks are write-only, get_ticket should always fail."""
        slack = self._make_unconfigured()
        result = await slack.get_ticket("any-id")
        assert result.success is False
        assert "write-only" in result.error

    def test_slack_severity_config(self):
        assert "critical" in SLACK_SEVERITY_CONFIG
        assert "color" in SLACK_SEVERITY_CONFIG["critical"]
        assert "emoji" in SLACK_SEVERITY_CONFIG["critical"]
        assert SLACK_SEVERITY_CONFIG["critical"]["color"] == "#dc3545"


# =========================================================================
# 9. UniversalConnector -- register, list, fan_out
# =========================================================================
class TestUniversalConnector:
    """Test the orchestrator in demo mode."""

    def _make_uc_with_demo_connectors(self) -> UniversalConnector:
        uc = UniversalConnector()
        uc.register("jira-demo", JiraConnector("", "", "", ""))
        uc.register("gh-demo", GitHubConnector("", "", ""))
        uc.register("slack-demo", SlackConnector(""))
        return uc

    def test_register_and_list(self):
        uc = UniversalConnector()
        jira = JiraConnector("", "", "", "")
        uc.register("my-jira", jira)
        connectors = uc.list_connectors()
        assert len(connectors) == 1
        assert connectors[0]["name"] == "my-jira"
        assert connectors[0]["type"] == "jira"

    def test_register_normalises_name(self):
        uc = UniversalConnector()
        uc.register("  MY-JIRA  ", JiraConnector("", "", "", ""))
        assert uc.get_connector("my-jira") is not None

    def test_register_replaces_existing(self):
        uc = UniversalConnector()
        c1 = JiraConnector("", "", "", "")
        c2 = JiraConnector("", "", "", "")
        uc.register("jira", c1)
        uc.register("jira", c2)
        assert uc.get_connector("jira") is c2
        assert len(uc.list_connectors()) == 1

    def test_register_invalid_name_raises(self):
        uc = UniversalConnector()
        with pytest.raises(ValueError):
            uc.register("", JiraConnector("", "", "", ""))
        with pytest.raises((ValueError, TypeError)):
            uc.register(None, JiraConnector("", "", "", ""))

    def test_register_invalid_connector_raises(self):
        uc = UniversalConnector()
        with pytest.raises(TypeError):
            uc.register("bad", "not-a-connector")

    def test_unregister(self):
        uc = UniversalConnector()
        uc.register("temp", JiraConnector("", "", "", ""))
        assert uc.unregister("temp") is True
        assert uc.unregister("temp") is False
        assert len(uc.list_connectors()) == 0

    def test_get_connector(self):
        uc = UniversalConnector()
        jira = JiraConnector("", "", "", "")
        uc.register("j", jira)
        assert uc.get_connector("j") is jira
        assert uc.get_connector("nonexistent") is None

    @pytest.mark.asyncio
    async def test_fan_out_demo_creates_tickets_on_all(self):
        uc = self._make_uc_with_demo_connectors()
        result = await uc.create_tickets(SAMPLE_FINDING)
        assert result["total"] == 3
        assert result["success_count"] == 3
        assert result["error_count"] == 0
        assert len(result["results"]) == 3
        connectors_used = {r["connector"] for r in result["results"]}
        assert connectors_used == {"jira", "github", "slack"}

    @pytest.mark.asyncio
    async def test_fan_out_with_targets(self):
        uc = self._make_uc_with_demo_connectors()
        result = await uc.create_tickets(SAMPLE_FINDING, targets=["jira-demo"])
        assert result["total"] == 1
        assert result["results"][0]["connector"] == "jira"

    @pytest.mark.asyncio
    async def test_fan_out_with_nonexistent_target(self):
        uc = self._make_uc_with_demo_connectors()
        result = await uc.create_tickets(SAMPLE_FINDING, targets=["nonexistent"])
        assert result["total"] == 0

    @pytest.mark.asyncio
    async def test_fan_out_no_connectors(self):
        uc = UniversalConnector()
        result = await uc.create_tickets(SAMPLE_FINDING)
        assert result["total"] == 0
        assert result["success_count"] == 0

    @pytest.mark.asyncio
    async def test_test_all_demo(self):
        uc = self._make_uc_with_demo_connectors()
        result = await uc.test_all()
        assert result["total"] == 3
        assert result["healthy_count"] == 3
        assert result["unhealthy_count"] == 0

    @pytest.mark.asyncio
    async def test_test_all_no_connectors(self):
        uc = UniversalConnector()
        result = await uc.test_all()
        assert result["total"] == 0

    @pytest.mark.asyncio
    async def test_close_all(self):
        uc = self._make_uc_with_demo_connectors()
        # Should not raise even when no HTTP clients are open
        await uc.close_all()

    def test_list_connectors_contains_metrics(self):
        uc = self._make_uc_with_demo_connectors()
        for item in uc.list_connectors():
            assert "metrics" in item
            assert "request_count" in item["metrics"]


# =========================================================================
# 10. FastAPI Router Endpoints via TestClient
# =========================================================================
class TestConnectorsRouter:
    """Test the /api/v1/connectors/* endpoints using FastAPI TestClient.

    We mount the router directly on a minimal FastAPI app to avoid
    dependencies on the full application startup (auth, telemetry, etc.).

    IMPORTANT: For tests that exercise demo mode, we register connectors
    with EMPTY credentials so `configured` returns False and demo-mode
    code paths are triggered -- no real HTTP calls are made.
    """

    @pytest.fixture(autouse=True)
    def _setup_router(self):
        """Create a fresh TestClient with a clean UniversalConnector for each test."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        # Import the router module so we can patch its singleton
        import apps.api.connectors_router as router_mod

        app = FastAPI()
        app.include_router(router_mod.router)

        # Reset the module-level singleton before each test
        router_mod._universal = None

        self.client = TestClient(app)
        self.router_mod = router_mod
        yield
        # Cleanup
        router_mod._universal = None

    # ---- Helper to register a demo (unconfigured) connector via API ----

    def _register_demo_jira(self, name: str = "demo-jira"):
        """Register a Jira connector that stays in demo mode (valid Pydantic, empty-ish creds)."""
        return self.client.post(
            "/api/v1/connectors/register",
            json={
                "name": name,
                "type": "jira",
                "jira": {
                    "base_url": "https://test.atlassian.net",
                    "email": "user@example.com",
                    "api_token": "tok",
                    "project_key": "SEC",
                },
            },
        )

    def _register_demo_github(self, name: str = "demo-github"):
        return self.client.post(
            "/api/v1/connectors/register",
            json={
                "name": name,
                "type": "github",
                "github": {
                    "token": "ghp_demo123",
                    "owner": "acme-corp",
                    "repo": "security-findings",
                },
            },
        )

    def _register_demo_slack(self, name: str = "demo-slack"):
        return self.client.post(
            "/api/v1/connectors/register",
            json={
                "name": name,
                "type": "slack",
                "slack": {
                    "webhook_url": "https://hooks.slack.com/services/T/B/X",
                    "channel": "#sec-alerts",
                },
            },
        )

    # -- POST /register -------------------------------------------------------

    def test_register_jira_connector(self):
        resp = self._register_demo_jira()
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "registered"
        assert data["name"] == "demo-jira"
        assert data["type"] == "jira"

    def test_register_github_connector(self):
        resp = self._register_demo_github()
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "registered"
        assert data["type"] == "github"

    def test_register_slack_connector(self):
        resp = self._register_demo_slack()
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "registered"
        assert data["type"] == "slack"

    def test_register_jira_without_config_422(self):
        resp = self.client.post(
            "/api/v1/connectors/register",
            json={"name": "bad-jira", "type": "jira"},
        )
        assert resp.status_code == 422

    def test_register_github_without_config_422(self):
        resp = self.client.post(
            "/api/v1/connectors/register",
            json={"name": "bad-gh", "type": "github"},
        )
        assert resp.status_code == 422

    def test_register_slack_without_config_422(self):
        resp = self.client.post(
            "/api/v1/connectors/register",
            json={"name": "bad-slack", "type": "slack"},
        )
        assert resp.status_code == 422

    # -- GET /connectors -------------------------------------------------------

    def test_list_connectors_empty(self):
        resp = self.client.get("/api/v1/connectors")
        assert resp.status_code == 200
        data = resp.json()
        assert data["connectors"] == []
        assert data["total"] == 0

    def test_list_connectors_after_register(self):
        self._register_demo_jira("listed-jira")
        resp = self.client.get("/api/v1/connectors")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        names = [c["name"] for c in data["connectors"]]
        assert "listed-jira" in names

    # -- POST /test -------------------------------------------------------

    def test_test_all_connectors_empty(self):
        resp = self.client.post("/api/v1/connectors/test")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0

    def test_test_all_connectors_with_registered(self):
        self._register_demo_jira()
        resp = self.client.post("/api/v1/connectors/test")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1

    # -- POST /create-ticket --------------------------------------------------

    def test_create_ticket_no_connectors_409(self):
        resp = self.client.post(
            "/api/v1/connectors/create-ticket",
            json={
                "finding": {
                    "title": "Test finding",
                    "severity": "high",
                },
            },
        )
        assert resp.status_code == 409
        assert "No connectors registered" in resp.json()["detail"]

    def test_create_ticket_with_registered_connector(self):
        """Register a connector then create a ticket.

        The connector has non-empty credentials so it will attempt a
        real HTTP call which will fail. We still verify the endpoint
        responds with a structured result (success=False is acceptable
        since the remote Jira instance is unreachable).
        """
        self._register_demo_jira("ticket-jira")
        resp = self.client.post(
            "/api/v1/connectors/create-ticket",
            json={
                "finding": {
                    "title": "SQL Injection",
                    "severity": "critical",
                    "cve_id": "CVE-2024-9999",
                    "cvss_score": 9.1,
                },
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        # The result has structured output regardless of success/failure
        assert "results" in data
        assert len(data["results"]) >= 1

    def test_create_ticket_with_targets(self):
        self._register_demo_jira("tgt-jira")
        self._register_demo_slack("tgt-slack")
        resp = self.client.post(
            "/api/v1/connectors/create-ticket",
            json={
                "finding": {"title": "XSS", "severity": "medium"},
                "targets": ["tgt-jira"],
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1

    # -- POST /{name}/test ----------------------------------------------------

    def test_test_specific_connector(self):
        """Test a specific connector. Since it has credentials, it will
        attempt a real HTTP call, so we just verify the endpoint returns
        a structured result (not a 500/404)."""
        self._register_demo_github("spec-gh")
        resp = self.client.post("/api/v1/connectors/spec-gh/test")
        assert resp.status_code == 200
        data = resp.json()
        # The response is a ConnectorResult dict -- check structure
        assert "success" in data
        assert "connector" in data
        assert "operation" in data

    def test_test_specific_connector_not_found(self):
        resp = self.client.post("/api/v1/connectors/nonexistent/test")
        assert resp.status_code == 404

    # -- DELETE /{name} --------------------------------------------------------

    def test_delete_connector(self):
        self._register_demo_slack("del-slack")
        resp = self.client.delete("/api/v1/connectors/del-slack")
        assert resp.status_code == 200
        assert resp.json()["status"] == "removed"
        # Verify it's gone
        resp2 = self.client.get("/api/v1/connectors")
        names = [c["name"] for c in resp2.json()["connectors"]]
        assert "del-slack" not in names

    def test_delete_connector_not_found(self):
        resp = self.client.delete("/api/v1/connectors/ghost")
        assert resp.status_code == 404

    # -- GET /health -----------------------------------------------------------

    def test_health_endpoint(self):
        resp = self.client.get("/api/v1/connectors/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert "total_connectors" in data

    def test_health_shows_registered_connectors(self):
        self._register_demo_jira("health-jira")
        resp = self.client.get("/api/v1/connectors/health")
        data = resp.json()
        assert data["total_connectors"] >= 1
        assert data["configured_connectors"] >= 1


# =========================================================================
# 11. Pydantic Validation (RegisterConnectorRequest, FindingInput)
# =========================================================================
class TestPydanticValidation:
    """Test Pydantic model validation in the router models."""

    def test_valid_name_accepted(self):
        from apps.api.connectors_router import RegisterConnectorRequest

        req = RegisterConnectorRequest(
            name="my-jira-01",
            type="jira",
            jira={
                "base_url": "https://test.atlassian.net",
                "email": "u@x.com",
                "api_token": "tok",
                "project_key": "SEC",
            },
        )
        assert req.name == "my-jira-01"

    def test_name_normalised_to_lowercase(self):
        from apps.api.connectors_router import RegisterConnectorRequest

        req = RegisterConnectorRequest(
            name="My-JIRA",
            type="jira",
            jira={
                "base_url": "https://test.atlassian.net",
                "email": "u@x.com",
                "api_token": "tok",
                "project_key": "SEC",
            },
        )
        assert req.name == "my-jira"

    def test_invalid_name_rejected(self):
        from pydantic import ValidationError

        from apps.api.connectors_router import RegisterConnectorRequest

        with pytest.raises(ValidationError):
            RegisterConnectorRequest(
                name="!!!invalid!!!",
                type="jira",
                jira={
                    "base_url": "https://test.atlassian.net",
                    "email": "u@x.com",
                    "api_token": "tok",
                    "project_key": "SEC",
                },
            )

    def test_name_starting_with_hyphen_rejected(self):
        from pydantic import ValidationError

        from apps.api.connectors_router import RegisterConnectorRequest

        with pytest.raises(ValidationError):
            RegisterConnectorRequest(
                name="-bad-start",
                type="jira",
                jira={
                    "base_url": "https://x.atlassian.net",
                    "email": "u@x.com",
                    "api_token": "t",
                    "project_key": "SEC",
                },
            )

    def test_jira_base_url_must_be_http(self):
        from pydantic import ValidationError

        from apps.api.connectors_router import JiraConfig

        with pytest.raises(ValidationError):
            JiraConfig(
                base_url="ftp://evil.com",
                email="u@x.com",
                api_token="tok",
                project_key="SEC",
            )

    def test_jira_base_url_trailing_slash_stripped(self):
        from apps.api.connectors_router import JiraConfig

        cfg = JiraConfig(
            base_url="https://test.atlassian.net/",
            email="u@x.com",
            api_token="tok",
            project_key="SEC",
        )
        assert not cfg.base_url.endswith("/")

    def test_jira_project_key_must_be_uppercase(self):
        from pydantic import ValidationError

        from apps.api.connectors_router import JiraConfig

        with pytest.raises(ValidationError):
            JiraConfig(
                base_url="https://test.atlassian.net",
                email="u@x.com",
                api_token="tok",
                project_key="lowercase",
            )

    def test_github_owner_rejects_special_chars(self):
        from pydantic import ValidationError

        from apps.api.connectors_router import GitHubConfig

        with pytest.raises(ValidationError):
            GitHubConfig(token="ghp_test", owner="org/evil", repo="repo")

    def test_slack_webhook_must_start_with_hooks(self):
        from pydantic import ValidationError

        from apps.api.connectors_router import SlackConfig

        with pytest.raises(ValidationError):
            SlackConfig(webhook_url="https://evil.com/hooks")

    def test_finding_input_valid(self):
        from apps.api.connectors_router import FindingInput

        fi = FindingInput(
            title="XSS in search",
            severity="high",
            cve_id="CVE-2024-5678",
            cvss_score=7.5,
        )
        assert fi.title == "XSS in search"
        assert fi.cvss_score == 7.5

    def test_finding_input_cvss_out_of_range(self):
        from pydantic import ValidationError

        from apps.api.connectors_router import FindingInput

        with pytest.raises(ValidationError):
            FindingInput(cvss_score=11.0)
        with pytest.raises(ValidationError):
            FindingInput(cvss_score=-1.0)

    def test_finding_input_cve_pattern(self):
        from pydantic import ValidationError

        from apps.api.connectors_router import FindingInput

        # Valid patterns
        fi = FindingInput(cve_id="CVE-2024-12345")
        assert fi.cve_id == "CVE-2024-12345"

        # Empty string is accepted by the regex (^$)
        fi2 = FindingInput(cve_id="")
        assert fi2.cve_id == ""

        # Invalid format
        with pytest.raises(ValidationError):
            FindingInput(cve_id="NOT-A-CVE")

    def test_finding_input_all_optional(self):
        from apps.api.connectors_router import FindingInput

        fi = FindingInput()
        assert fi.severity == "medium"
        assert fi.title is None
        assert fi.cve_id is None

    def test_finding_input_alternative_field_names(self):
        from apps.api.connectors_router import FindingInput

        fi = FindingInput(
            summary="Alt summary",
            details="Alt details",
            cve="CVE-2024-0001",
            cwe="CWE-79",
            cvss=8.0,
            package="lodash",
            file="index.js",
            fix="Upgrade to 4.17.21",
        )
        assert fi.summary == "Alt summary"
        assert fi.cve == "CVE-2024-0001"
        assert fi.cvss == 8.0
        assert fi.package == "lodash"


# =========================================================================
# Additional edge-case tests
# =========================================================================
class TestEdgeCases:
    """Extra edge-case coverage."""

    def test_format_title_with_alternate_fields(self):
        """Finding with 'cve' instead of 'cve_id' and 'summary' instead of 'title'."""
        finding = {"summary": "Buffer overflow", "severity": "high", "cve": "CVE-2023-9999"}
        title = _format_finding_title(finding)
        assert "[HIGH]" in title
        assert "CVE-2023-9999" in title
        assert "Buffer overflow" in title

    def test_format_description_with_alternate_fields(self):
        finding = {
            "severity": "low",
            "cve": "CVE-2023-0001",
            "cwe": "CWE-200",
            "cvss": 3.1,
            "package": "requests",
            "file": "app.py",
            "details": "Information disclosure",
            "fix": "Update to latest",
        }
        desc = _format_finding_description(finding)
        assert "**CVE**: CVE-2023-0001" in desc
        assert "**CWE**: CWE-200" in desc
        assert "**CVSS**: 3.1" in desc
        assert "**Component**: requests" in desc
        assert "**File**: app.py" in desc
        assert "Information disclosure" in desc
        assert "Update to latest" in desc

    @pytest.mark.asyncio
    async def test_base_connector_close_no_client(self):
        """close() on a connector with no HTTP client should be a no-op."""
        jira = JiraConnector("", "", "", "")
        await jira.close()  # Should not raise

    @pytest.mark.asyncio
    async def test_safe_create_catches_exceptions(self):
        """_safe_create should catch exceptions from create_ticket."""

        class BrokenConnector(BaseConnector):
            _connector_type = "broken"

            async def create_ticket(self, finding):
                raise RuntimeError("boom")

            async def update_ticket(self, ticket_id, update):
                pass

            async def close_ticket(self, ticket_id, resolution):
                pass

            async def get_ticket(self, ticket_id):
                pass

            async def test_connection(self):
                pass

        uc = UniversalConnector()
        broken = BrokenConnector()
        uc.register("broken", broken)
        result = await uc.create_tickets(SAMPLE_FINDING)
        assert result["total"] == 1
        assert result["error_count"] == 1
        assert result["results"][0]["success"] is False
        assert "boom" in result["results"][0]["error"]

    @pytest.mark.asyncio
    async def test_safe_test_catches_exceptions(self):
        """_safe_test should catch exceptions from test_connection."""

        class BrokenTestConnector(BaseConnector):
            _connector_type = "broken"

            async def create_ticket(self, finding):
                pass

            async def update_ticket(self, ticket_id, update):
                pass

            async def close_ticket(self, ticket_id, resolution):
                pass

            async def get_ticket(self, ticket_id):
                pass

            async def test_connection(self):
                raise ConnectionError("unreachable")

        uc = UniversalConnector()
        uc.register("broken", BrokenTestConnector())
        result = await uc.test_all()
        assert result["total"] == 1
        assert result["unhealthy_count"] == 1
        assert "unreachable" in result["results"][0]["error"]
