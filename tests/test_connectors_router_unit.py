"""
Unit tests for Connectors Router (suite-api/apps/api/connectors_router.py).

Covers:
  - Pydantic model validation (ConnectorType, JiraConfig, GitHubConfig, SlackConfig)
  - RegisterConnectorRequest validation (name pattern, type matching)
  - FindingInput and CreateTicketRequest validation
  - POST /register endpoint with mocked UniversalConnector
  - GET / list connectors endpoint
  - POST /create-ticket endpoint
  - POST /{name}/test endpoint
  - DELETE /{name} endpoint
  - GET /health endpoint
  - Error handling: 404 for missing connector, 422 for validation, 409 for no connectors
"""

from __future__ import annotations

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

os.environ.setdefault("FIXOPS_API_TOKEN", "aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh")
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-jwt-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from pydantic import ValidationError

from apps.api.connectors_router import (
    ConnectorType,
    CreateTicketRequest,
    FindingInput,
    GitHubConfig,
    JiraConfig,
    RegisterConnectorRequest,
    SlackConfig,
)


# ---------------------------------------------------------------------------
# Pydantic Model Validation
# ---------------------------------------------------------------------------


class TestConnectorType:
    def test_valid_types(self):
        assert ConnectorType.jira == "jira"
        assert ConnectorType.github == "github"
        assert ConnectorType.slack == "slack"

    def test_enum_values(self):
        assert set(ConnectorType) == {ConnectorType.jira, ConnectorType.github, ConnectorType.slack}


class TestJiraConfig:
    def test_valid_jira_config(self):
        cfg = JiraConfig(
            base_url="https://company.atlassian.net",
            email="user@company.com",
            api_token="abc123",
            project_key="PROJ",
        )
        assert cfg.base_url == "https://company.atlassian.net"
        assert cfg.issue_type == "Bug"  # default

    def test_url_stripped_and_trailing_slash_removed(self):
        cfg = JiraConfig(
            base_url="  https://company.atlassian.net/  ",
            email="u@c.com",
            api_token="tok",
            project_key="ABC",
        )
        assert not cfg.base_url.endswith("/")
        assert not cfg.base_url.startswith(" ")

    def test_invalid_base_url_no_http(self):
        with pytest.raises(ValidationError, match="base_url"):
            JiraConfig(
                base_url="ftp://company.atlassian.net",
                email="u@c.com",
                api_token="tok",
                project_key="PROJ",
            )

    def test_invalid_project_key_lowercase(self):
        with pytest.raises(ValidationError, match="project_key"):
            JiraConfig(
                base_url="https://c.atlassian.net",
                email="u@c.com",
                api_token="tok",
                project_key="proj",
            )

    def test_project_key_must_start_with_letter(self):
        with pytest.raises(ValidationError, match="project_key"):
            JiraConfig(
                base_url="https://c.atlassian.net",
                email="u@c.com",
                api_token="tok",
                project_key="123",
            )


class TestGitHubConfig:
    def test_valid_github_config(self):
        cfg = GitHubConfig(token="ghp_test123", owner="myorg", repo="myrepo")
        assert cfg.owner == "myorg"

    def test_invalid_owner_special_chars(self):
        with pytest.raises(ValidationError):
            GitHubConfig(token="ghp_test", owner="my org!", repo="myrepo")

    def test_invalid_repo_special_chars(self):
        with pytest.raises(ValidationError):
            GitHubConfig(token="ghp_test", owner="myorg", repo="my repo!")

    def test_owner_allows_dots_hyphens(self):
        cfg = GitHubConfig(token="tok", owner="my-org.name", repo="my-repo")
        assert cfg.owner == "my-org.name"


class TestSlackConfig:
    def test_valid_slack_config(self):
        cfg = SlackConfig(webhook_url="https://hooks.slack.com/services/T01/B02/xyz")
        assert cfg.channel is None

    def test_with_channel(self):
        cfg = SlackConfig(
            webhook_url="https://hooks.slack.com/services/T01/B02/xyz",
            channel="#security-alerts",
        )
        assert cfg.channel == "#security-alerts"

    def test_invalid_webhook_url(self):
        with pytest.raises(ValidationError, match="webhook_url"):
            SlackConfig(webhook_url="https://example.com/webhook")


class TestRegisterConnectorRequest:
    def test_valid_request(self):
        req = RegisterConnectorRequest(
            name="my-jira",
            type=ConnectorType.jira,
            jira=JiraConfig(
                base_url="https://c.atlassian.net",
                email="u@c.com",
                api_token="tok",
                project_key="PROJ",
            ),
        )
        assert req.name == "my-jira"

    def test_name_lowercased(self):
        req = RegisterConnectorRequest(
            name="MyJira",
            type=ConnectorType.jira,
            jira=JiraConfig(
                base_url="https://c.atlassian.net",
                email="u@c.com",
                api_token="tok",
                project_key="PROJ",
            ),
        )
        assert req.name == "myjira"

    def test_name_invalid_pattern(self):
        with pytest.raises(ValidationError, match="name"):
            RegisterConnectorRequest(
                name="!invalid name!",
                type=ConnectorType.jira,
            )

    def test_name_starting_with_hyphen_invalid(self):
        with pytest.raises(ValidationError, match="name"):
            RegisterConnectorRequest(
                name="-badname",
                type=ConnectorType.github,
            )


class TestFindingInput:
    def test_defaults(self):
        finding = FindingInput()
        assert finding.severity == "medium"
        assert finding.title is None

    def test_with_cve(self):
        finding = FindingInput(
            title="SQL Injection",
            cve_id="CVE-2024-1234",
            cvss_score=8.5,
            severity="critical",
        )
        assert finding.cve_id == "CVE-2024-1234"
        assert finding.cvss_score == 8.5

    def test_cvss_out_of_range(self):
        with pytest.raises(ValidationError):
            FindingInput(cvss_score=11.0)

    def test_cvss_negative(self):
        with pytest.raises(ValidationError):
            FindingInput(cvss_score=-1.0)

    def test_cve_pattern_validation(self):
        """cve_id must match CVE-YYYY-NNNN+ pattern."""
        finding = FindingInput(cve_id="CVE-2024-12345")
        assert finding.cve_id == "CVE-2024-12345"

    def test_invalid_cve_pattern(self):
        with pytest.raises(ValidationError):
            FindingInput(cve_id="not-a-cve")


class TestCreateTicketRequest:
    def test_valid_request(self):
        req = CreateTicketRequest(
            finding=FindingInput(title="Test vuln", severity="high"),
            targets=["my-jira"],
        )
        assert req.targets == ["my-jira"]
        assert req.finding.title == "Test vuln"

    def test_targets_optional(self):
        req = CreateTicketRequest(
            finding=FindingInput(title="Test"),
        )
        assert req.targets is None


# ---------------------------------------------------------------------------
# API Endpoint Tests (with mocked UniversalConnector)
# ---------------------------------------------------------------------------


class TestConnectorsAPI:
    @pytest.fixture(scope="class")
    def client(self):
        """Build a TestClient with the connectors_router mounted, mocking _get_universal."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        from apps.api.connectors_router import router

        app = FastAPI()
        app.include_router(router)
        return TestClient(app, raise_server_exceptions=False)

    @pytest.fixture(autouse=True)
    def mock_universal(self):
        """Mock the lazy-loaded UniversalConnector for every test."""
        mock_uc = MagicMock()
        mock_uc.list_connectors.return_value = [
            {"name": "jira-prod", "type": "jira", "configured": True},
            {"name": "slack-sec", "type": "slack", "configured": True},
        ]
        mock_uc.get_connector.return_value = None  # Default: not found
        mock_uc.test_all = AsyncMock(return_value={"jira-prod": {"ok": True}})

        with patch("apps.api.connectors_router._get_universal", return_value=mock_uc):
            self._mock_uc = mock_uc
            yield mock_uc

    def test_list_connectors(self, client, mock_universal):
        resp = client.get("/api/v1/connectors")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 2
        assert len(data["connectors"]) == 2

    def test_health_endpoint(self, client, mock_universal):
        resp = client.get("/api/v1/connectors/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["total_connectors"] == 2
        assert data["configured_connectors"] == 2

    def test_register_jira_missing_config_returns_422(self, client, mock_universal):
        """When type is jira but jira config is missing, should return 422."""
        resp = client.post(
            "/api/v1/connectors/register",
            json={"name": "test-jira", "type": "jira"},
        )
        assert resp.status_code == 422

    def test_register_github_missing_config_returns_422(self, client, mock_universal):
        resp = client.post(
            "/api/v1/connectors/register",
            json={"name": "test-gh", "type": "github"},
        )
        assert resp.status_code == 422

    def test_register_slack_missing_config_returns_422(self, client, mock_universal):
        resp = client.post(
            "/api/v1/connectors/register",
            json={"name": "test-slack", "type": "slack"},
        )
        assert resp.status_code == 422

    @patch("connectors.universal_connector.JiraConnector")
    def test_register_jira_success(self, mock_jira_cls, client, mock_universal):
        mock_connector = MagicMock()
        mock_connector.configured = True
        mock_jira_cls.return_value = mock_connector

        resp = client.post(
            "/api/v1/connectors/register",
            json={
                "name": "prod-jira",
                "type": "jira",
                "jira": {
                    "base_url": "https://test.atlassian.net",
                    "email": "u@c.com",
                    "api_token": "tok123",
                    "project_key": "SEC",
                },
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "registered"
        assert data["type"] == "jira"
        mock_universal.register.assert_called_once()

    def test_test_connector_not_found(self, client, mock_universal):
        mock_universal.get_connector.return_value = None
        resp = client.post("/api/v1/connectors/missing-conn/test")
        assert resp.status_code == 404

    def test_test_connector_success(self, client, mock_universal):
        mock_conn = MagicMock()
        mock_result = MagicMock()
        mock_result.to_dict.return_value = {"status": "ok", "latency_ms": 42}
        mock_conn.test_connection = AsyncMock(return_value=mock_result)
        mock_universal.get_connector.return_value = mock_conn

        resp = client.post("/api/v1/connectors/jira-prod/test")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"

    def test_remove_connector_not_found(self, client, mock_universal):
        mock_universal.get_connector.return_value = None
        resp = client.delete("/api/v1/connectors/missing-conn")
        assert resp.status_code == 404

    def test_remove_connector_success(self, client, mock_universal):
        mock_conn = MagicMock()
        mock_conn.close = AsyncMock()
        mock_universal.get_connector.return_value = mock_conn

        resp = client.delete("/api/v1/connectors/jira-prod")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "removed"
        mock_universal.unregister.assert_called_once_with("jira-prod")

    def test_create_ticket_no_connectors_registered(self, client, mock_universal):
        mock_universal.list_connectors.return_value = []  # Empty
        resp = client.post(
            "/api/v1/connectors/create-ticket",
            json={
                "finding": {"title": "SQL Injection", "severity": "critical"},
            },
        )
        assert resp.status_code == 409

    def test_create_ticket_success(self, client, mock_universal):
        mock_universal.create_tickets = AsyncMock(
            return_value={
                "jira-prod": {"status": "sent", "issue_key": "SEC-42"},
                "slack-sec": {"status": "sent"},
            }
        )
        resp = client.post(
            "/api/v1/connectors/create-ticket",
            json={
                "finding": {
                    "title": "CVE-2024-1234 in openssl",
                    "severity": "critical",
                    "cve_id": "CVE-2024-1234",
                    "cvss_score": 9.8,
                },
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "jira-prod" in data

    def test_create_ticket_with_targets(self, client, mock_universal):
        mock_universal.create_tickets = AsyncMock(
            return_value={"jira-prod": {"status": "sent"}}
        )
        resp = client.post(
            "/api/v1/connectors/create-ticket",
            json={
                "finding": {"title": "Test", "severity": "medium"},
                "targets": ["jira-prod"],
            },
        )
        assert resp.status_code == 200

    def test_test_all_connectors(self, client, mock_universal):
        resp = client.post("/api/v1/connectors/test")
        assert resp.status_code == 200

    def test_invalid_name_in_register(self, client, mock_universal):
        resp = client.post(
            "/api/v1/connectors/register",
            json={"name": "!invalid!", "type": "jira"},
        )
        assert resp.status_code == 422

    @patch("connectors.universal_connector.GitHubConnector")
    def test_register_github_success(self, mock_gh_cls, client, mock_universal):
        """Register a GitHub connector with valid config."""
        mock_connector = MagicMock()
        mock_connector.configured = True
        mock_gh_cls.return_value = mock_connector

        resp = client.post(
            "/api/v1/connectors/register",
            json={
                "name": "prod-github",
                "type": "github",
                "github": {
                    "token": "ghp_test123abc",
                    "owner": "myorg",
                    "repo": "myrepo",
                },
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "registered"
        assert data["type"] == "github"
        assert data["configured"] is True

    @patch("connectors.universal_connector.SlackConnector")
    def test_register_slack_success(self, mock_slack_cls, client, mock_universal):
        """Register a Slack connector with valid config."""
        mock_connector = MagicMock()
        mock_connector.configured = True
        mock_slack_cls.return_value = mock_connector

        resp = client.post(
            "/api/v1/connectors/register",
            json={
                "name": "sec-slack",
                "type": "slack",
                "slack": {
                    "webhook_url": "https://hooks.slack.com/services/T01/B02/xyz",
                    "channel": "#security-alerts",
                },
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "registered"
        assert data["type"] == "slack"

    def test_connector_name_normalized_lowercase(self, client, mock_universal):
        """Connector test endpoint normalizes name to lowercase."""
        mock_universal.get_connector.return_value = None
        resp = client.post("/api/v1/connectors/MyConnector/test")
        assert resp.status_code == 404
        # Verify the lookup was done with lowercase
        mock_universal.get_connector.assert_called_with("myconnector")

    def test_remove_connector_name_normalized(self, client, mock_universal):
        """Delete endpoint normalizes name to lowercase."""
        mock_universal.get_connector.return_value = None
        resp = client.delete("/api/v1/connectors/MyConn")
        assert resp.status_code == 404
        mock_universal.get_connector.assert_called_with("myconn")

    def test_health_with_no_connectors(self, client, mock_universal):
        """Health when no connectors registered."""
        mock_universal.list_connectors.return_value = []
        resp = client.get("/api/v1/connectors/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["total_connectors"] == 0
        assert data["configured_connectors"] == 0

    def test_health_with_unconfigured_connectors(self, client, mock_universal):
        """Health reports unconfigured connectors correctly."""
        mock_universal.list_connectors.return_value = [
            {"name": "broken-jira", "type": "jira", "configured": False},
        ]
        resp = client.get("/api/v1/connectors/health")
        data = resp.json()
        assert data["total_connectors"] == 1
        assert data["configured_connectors"] == 0


# ---------------------------------------------------------------------------
# Extended Pydantic Validation
# ---------------------------------------------------------------------------


class TestJiraConfigExtended:
    """Additional JiraConfig validation tests."""

    def test_empty_api_token_rejected(self):
        with pytest.raises(ValidationError):
            JiraConfig(
                base_url="https://c.atlassian.net",
                email="u@c.com",
                api_token="",
                project_key="PROJ",
            )

    def test_http_url_accepted(self):
        """HTTP (not HTTPS) URLs are accepted."""
        cfg = JiraConfig(
            base_url="http://internal-jira.company.local",
            email="u@c.com",
            api_token="tok",
            project_key="PROJ",
        )
        assert cfg.base_url.startswith("http://")


class TestSlackConfigExtended:
    """Additional SlackConfig validation tests."""

    def test_webhook_url_stripped(self):
        cfg = SlackConfig(
            webhook_url="  https://hooks.slack.com/services/T01/B02/xyz  "
        )
        assert not cfg.webhook_url.startswith(" ")


class TestFindingInputExtended:
    """Additional FindingInput validation tests."""

    def test_empty_cve_id_accepted(self):
        """Empty string for cve_id is accepted (pattern allows it)."""
        finding = FindingInput(cve_id="")
        assert finding.cve_id == ""

    def test_all_fields_populated(self):
        """FindingInput with all fields set."""
        finding = FindingInput(
            title="Full Finding",
            summary="Summary text",
            description="Detailed description",
            details="More details",
            severity="critical",
            cve_id="CVE-2024-9999",
            cve="CVE-2024-9999",
            cwe_id="CWE-89",
            cwe="CWE-89",
            cvss_score=9.8,
            cvss=9.8,
            component="openssl",
            package="openssl-1.1.1",
            file_path="/src/main.py",
            file="/src/main.py",
            line=42,
            remediation="Upgrade to latest version",
            fix="pip install --upgrade openssl",
        )
        assert finding.title == "Full Finding"
        assert finding.line == 42
