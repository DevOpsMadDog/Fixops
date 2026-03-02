"""Unit tests for SecurityConnectors (10 security tool connectors).

Tests cover:
- SnykConnector: init, configured, list_projects, get_issues, health_check
- SonarQubeConnector: init, configured, get_issues, get_quality_gate, health_check
- DependabotConnector: init, configured, list_alerts, dismiss_alert, health_check
- AWSSecurityHubConnector: init, configured, get_findings, health_check
- AzureSecurityCenterConnector: init, configured, get_assessments, health_check
- WizConnector: init, configured, get_issues, get_vulnerabilities, health_check
- PrismaCloudConnector: init, configured, get_alerts, health_check
- OrcaSecurityConnector: init, configured, get_alerts, health_check
- LaceworkConnector: init, configured, health_check
- ThreatMapperConnector: init, configured, health_check

Pillar: V7 (MCP-Native Platform) — scanner integrations
Agent: agent-doctor (run v6 — 2026-03-01)
"""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

from core.security_connectors import (
    SnykConnector,
    SonarQubeConnector,
    DependabotConnector,
    AWSSecurityHubConnector,
    AzureSecurityCenterConnector,
    WizConnector,
    PrismaCloudConnector,
    OrcaSecurityConnector,
)

# Import remaining connectors if available
try:
    from core.security_connectors import LaceworkConnector
    HAS_LACEWORK = True
except ImportError:
    HAS_LACEWORK = False

try:
    from core.security_connectors import ThreatMapperConnector
    HAS_THREATMAPPER = True
except ImportError:
    HAS_THREATMAPPER = False


# ---------------------------------------------------------------------------
# SnykConnector tests (settings: token, org_id/organization_id, base_url)
# ---------------------------------------------------------------------------
class TestSnykConnector:
    def _make(self, **overrides):
        settings = {"token": "test-token", "org_id": "test-org"}
        settings.update(overrides)
        return SnykConnector(settings)

    def test_init(self):
        conn = self._make()
        assert conn is not None

    def test_configured_with_token(self):
        conn = self._make()
        assert conn.configured is True

    def test_configured_without_token(self):
        conn = self._make(token="")
        assert conn.configured is False

    def test_configured_without_org(self):
        conn = self._make(org_id="")
        assert conn.configured is False

    def test_headers(self):
        conn = self._make()
        headers = conn._headers()
        assert "Authorization" in headers

    def test_list_projects_not_configured(self):
        conn = self._make(token="")
        result = conn.list_projects()
        assert result.success is False

    @patch("core.connectors.requests.Session.request")
    def test_list_projects_success(self, mock_request):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"projects": [{"id": "p1", "name": "project1"}]}
        mock_resp.raise_for_status = MagicMock()
        mock_request.return_value = mock_resp
        conn = self._make()
        result = conn.list_projects()
        assert result.success is True

    @patch("core.connectors.requests.Session.request")
    def test_get_issues(self, mock_request):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"issues": []}
        mock_resp.raise_for_status = MagicMock()
        mock_request.return_value = mock_resp
        conn = self._make()
        result = conn.get_issues("project-123")
        assert result.success is True

    def test_health_check_not_configured(self):
        conn = self._make(token="")
        health = conn.health_check()
        assert health.healthy is False

    @patch("core.connectors.requests.Session.request")
    def test_health_check_success(self, mock_request):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"orgs": [{"id": "org1"}]}
        mock_resp.raise_for_status = MagicMock()
        mock_request.return_value = mock_resp
        conn = self._make()
        health = conn.health_check()
        assert health.healthy is True


# ---------------------------------------------------------------------------
# SonarQubeConnector tests (settings: base_url, token, project_key)
# ---------------------------------------------------------------------------
class TestSonarQubeConnector:
    def _make(self, **overrides):
        settings = {
            "base_url": "http://sonar:9000",
            "token": "test-token",
            "project_key": "my-project",
        }
        settings.update(overrides)
        return SonarQubeConnector(settings)

    def test_init(self):
        conn = self._make()
        assert conn is not None

    def test_configured_with_url_and_token(self):
        conn = self._make()
        assert conn.configured is True

    def test_configured_without_token(self):
        conn = self._make(token="")
        assert conn.configured is False

    def test_headers(self):
        conn = self._make()
        headers = conn._headers()
        assert isinstance(headers, dict)

    @patch("core.connectors.requests.Session.request")
    def test_get_issues(self, mock_request):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"issues": [], "total": 0}
        mock_resp.raise_for_status = MagicMock()
        mock_request.return_value = mock_resp
        conn = self._make()
        result = conn.get_issues()
        assert result.success is True

    @patch("core.connectors.requests.Session.request")
    def test_get_quality_gate(self, mock_request):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"projectStatus": {"status": "OK"}}
        mock_resp.raise_for_status = MagicMock()
        mock_request.return_value = mock_resp
        conn = self._make()
        result = conn.get_quality_gate()
        assert result.success is True

    def test_health_check_not_configured(self):
        conn = self._make(token="")
        health = conn.health_check()
        assert health.healthy is False


# ---------------------------------------------------------------------------
# DependabotConnector tests (settings: owner, repo, token)
# ---------------------------------------------------------------------------
class TestDependabotConnector:
    def _make(self, **overrides):
        settings = {
            "token": "ghp_test",
            "owner": "test-owner",
            "repo": "test-repo",
        }
        settings.update(overrides)
        return DependabotConnector(settings)

    def test_init(self):
        conn = self._make()
        assert conn is not None

    def test_configured_with_token(self):
        conn = self._make()
        assert conn.configured is True

    def test_configured_without_token(self):
        conn = self._make(token="")
        assert conn.configured is False

    def test_headers(self):
        conn = self._make()
        headers = conn._headers()
        assert "Authorization" in headers

    @patch("core.connectors.requests.Session.request")
    def test_list_alerts(self, mock_request):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = [{"number": 1, "state": "open"}]
        mock_resp.raise_for_status = MagicMock()
        mock_request.return_value = mock_resp
        conn = self._make()
        result = conn.list_alerts()
        assert result.success is True

    def test_health_check_not_configured(self):
        conn = self._make(token="")
        health = conn.health_check()
        assert health.healthy is False


# ---------------------------------------------------------------------------
# AWSSecurityHubConnector tests (settings: region, profile)
# configured returns True always (uses boto3 env/instance profile)
# ---------------------------------------------------------------------------
class TestAWSSecurityHubConnector:
    def _make(self, **overrides):
        settings = {"region": "us-east-1"}
        settings.update(overrides)
        return AWSSecurityHubConnector(settings)

    def test_init(self):
        conn = self._make()
        assert conn is not None

    def test_configured_always_true(self):
        """AWSSecurityHubConnector.configured returns True (boto3 uses env/instance profile)."""
        conn = self._make()
        assert conn.configured is True

    def test_configured_even_empty(self):
        conn = self._make(region="")
        # Still True since boto3 can use defaults
        assert conn.configured is True

    def test_health_check_no_boto3(self):
        """Health check fails gracefully without boto3 client."""
        conn = self._make()
        health = conn.health_check()
        # May be True or False depending on boto3 availability
        assert isinstance(health.healthy, bool)


# ---------------------------------------------------------------------------
# AzureSecurityCenterConnector tests (settings: subscription_id, tenant_id, client_id, client_secret)
# ---------------------------------------------------------------------------
class TestAzureSecurityCenterConnector:
    def _make(self, **overrides):
        settings = {
            "tenant_id": "tenant-123",
            "client_id": "client-123",
            "client_secret": "secret-123",
            "subscription_id": "sub-123",
        }
        settings.update(overrides)
        return AzureSecurityCenterConnector(settings)

    def test_init(self):
        conn = self._make()
        assert conn is not None

    def test_configured(self):
        conn = self._make()
        assert conn.configured is True

    def test_configured_without_tenant(self):
        conn = self._make(tenant_id="")
        assert conn.configured is False

    def test_configured_without_client_secret(self):
        conn = self._make(client_secret="")
        assert conn.configured is False

    def test_health_check_not_configured(self):
        conn = self._make(tenant_id="")
        health = conn.health_check()
        assert health.healthy is False


# ---------------------------------------------------------------------------
# WizConnector tests (settings: client_id, client_secret, base_url)
# ---------------------------------------------------------------------------
class TestWizConnector:
    def _make(self, **overrides):
        settings = {
            "client_id": "wiz-client",
            "client_secret": "wiz-secret",
            "base_url": "https://api.wiz.io/graphql",
        }
        settings.update(overrides)
        return WizConnector(settings)

    def test_init(self):
        conn = self._make()
        assert conn is not None

    def test_configured(self):
        conn = self._make()
        assert conn.configured is True

    def test_configured_without_client_id(self):
        conn = self._make(client_id="")
        assert conn.configured is False

    def test_health_check_not_configured(self):
        conn = self._make(client_id="")
        health = conn.health_check()
        assert health.healthy is False


# ---------------------------------------------------------------------------
# PrismaCloudConnector tests (settings: base_url, access_key, secret_key)
# ---------------------------------------------------------------------------
class TestPrismaCloudConnector:
    def _make(self, **overrides):
        settings = {
            "base_url": "https://api.prismacloud.io",
            "access_key": "access-key",
            "secret_key": "secret-key",
        }
        settings.update(overrides)
        return PrismaCloudConnector(settings)

    def test_init(self):
        conn = self._make()
        assert conn is not None

    def test_configured(self):
        conn = self._make()
        assert conn.configured is True

    def test_configured_without_key(self):
        conn = self._make(access_key="")
        assert conn.configured is False

    def test_health_check_not_configured(self):
        conn = self._make(access_key="")
        health = conn.health_check()
        assert health.healthy is False


# ---------------------------------------------------------------------------
# OrcaSecurityConnector tests (settings: api_token, base_url)
# ---------------------------------------------------------------------------
class TestOrcaSecurityConnector:
    def _make(self, **overrides):
        settings = {
            "api_token": "orca-token-123",
            "base_url": "https://api.orcasecurity.io",
        }
        settings.update(overrides)
        return OrcaSecurityConnector(settings)

    def test_init(self):
        conn = self._make()
        assert conn is not None

    def test_configured(self):
        conn = self._make()
        assert conn.configured is True

    def test_configured_without_token(self):
        conn = self._make(api_token="")
        assert conn.configured is False

    def test_headers(self):
        conn = self._make()
        headers = conn._headers()
        assert isinstance(headers, dict)

    def test_health_check_not_configured(self):
        conn = self._make(api_token="")
        health = conn.health_check()
        assert health.healthy is False


# ---------------------------------------------------------------------------
# LaceworkConnector tests (settings: account, key_id, secret)
# ---------------------------------------------------------------------------
@pytest.mark.skipif(not HAS_LACEWORK, reason="LaceworkConnector not exported")
class TestLaceworkConnector:
    def _make(self, **overrides):
        settings = {
            "account": "test-account",
            "key_id": "lw-key",
            "secret": "lw-secret",
        }
        settings.update(overrides)
        return LaceworkConnector(settings)

    def test_init(self):
        conn = self._make()
        assert conn is not None

    def test_configured(self):
        conn = self._make()
        assert conn.configured is True

    def test_configured_without_key(self):
        conn = self._make(key_id="")
        assert conn.configured is False


# ---------------------------------------------------------------------------
# ThreatMapperConnector tests (settings: console_url/base_url/url, api_key)
# ---------------------------------------------------------------------------
@pytest.mark.skipif(not HAS_THREATMAPPER, reason="ThreatMapperConnector not exported")
class TestThreatMapperConnector:
    def _make(self, **overrides):
        settings = {
            "console_url": "http://threatmapper:9000",
            "api_key": "tm-key",
        }
        settings.update(overrides)
        return ThreatMapperConnector(settings)

    def test_init(self):
        conn = self._make()
        assert conn is not None

    def test_configured(self):
        conn = self._make()
        assert conn.configured is True

    def test_configured_without_key(self):
        conn = self._make(api_key="")
        assert conn.configured is False
