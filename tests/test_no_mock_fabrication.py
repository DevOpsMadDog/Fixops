"""
Tests proving that gcp_scc, github_security, and pagerduty_integration
never fabricate mock data when unconfigured (default allow_mock=False).

Contract:
  - Unconfigured + allow_mock=False (default) → empty list / not-configured dict
  - Specific _MOCK_* identifiers must NOT appear in unconfigured output
  - allow_mock=True still works for existing test infrastructure

Multica: #9023 (gcp_scc) #9024 (github_security) #9025 (pagerduty)
"""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# GCP SCC — gcp_scc.py
# ---------------------------------------------------------------------------

class TestGCPSCCHonestNotConfigured:
    """GCPSecurityClient(allow_mock=False) must never return _MOCK_* data."""

    def _unconfigured(self):
        from core.gcp_scc import GCPSecurityClient
        return GCPSecurityClient(project_id="", credentials_file="")

    # --- get_findings ---

    def test_get_findings_returns_empty_list_when_unconfigured(self):
        client = self._unconfigured()
        result = client.get_findings()
        assert result == []

    def test_get_findings_no_mock_name_when_unconfigured(self):
        """_MOCK_FINDINGS have names like 'organizations/123456789/.../mock-001'."""
        client = self._unconfigured()
        result = client.get_findings()
        for finding in result:
            assert "mock-" not in finding.get("name", "").lower()

    def test_get_findings_mock_ids_absent_from_output(self):
        """The specific mock finding IDs from _MOCK_FINDINGS must not appear."""
        from core.gcp_scc import _MOCK_FINDINGS
        client = self._unconfigured()
        result = client.get_findings()
        result_str = str(result)
        for mock_finding in _MOCK_FINDINGS:
            assert mock_finding["name"] not in result_str

    # --- get_sources ---

    def test_get_sources_returns_empty_list_when_unconfigured(self):
        client = self._unconfigured()
        result = client.get_sources()
        assert result == []

    def test_get_sources_mock_ids_absent_from_output(self):
        from core.gcp_scc import _MOCK_SOURCES
        client = self._unconfigured()
        result = client.get_sources()
        result_str = str(result)
        for src in _MOCK_SOURCES:
            assert src["name"] not in result_str

    # --- get_assets ---

    def test_get_assets_returns_empty_list_when_unconfigured(self):
        client = self._unconfigured()
        result = client.get_assets()
        assert result == []

    def test_get_assets_mock_ids_absent_from_output(self):
        from core.gcp_scc import _MOCK_ASSETS
        client = self._unconfigured()
        result = client.get_assets()
        result_str = str(result)
        for asset in _MOCK_ASSETS:
            assert asset["name"] not in result_str

    # --- import_findings ---

    def test_import_findings_has_zero_findings_when_unconfigured(self):
        client = self._unconfigured()
        result = client.import_findings(org_id="no_mock_test")
        assert result["findings_count"] == 0
        assert result["findings"] == []

    def test_import_findings_configured_false_when_unconfigured(self):
        client = self._unconfigured()
        result = client.import_findings(org_id="no_mock_test_cfg")
        assert result["configured"] is False

    def test_import_findings_is_mock_false_by_default(self):
        """is_mock must be False on the default production path."""
        client = self._unconfigured()
        result = client.import_findings(org_id="no_mock_test_flag")
        assert result["is_mock"] is False

    def test_import_findings_status_completed_with_zero_findings(self):
        client = self._unconfigured()
        result = client.import_findings(org_id="no_mock_zero")
        assert result["status"] == "completed"

    def test_import_findings_mock_org_ids_absent(self):
        """Mock findings reference 'my-gcp-project' — must not appear."""
        client = self._unconfigured()
        result = client.import_findings(org_id="no_mock_org")
        for finding in result["findings"]:
            assert "my-gcp-project" not in str(finding)
            assert "mock-001" not in str(finding)
            assert "mock-002" not in str(finding)


class TestGCPSCCAllowMockPath:
    """allow_mock=True must still deliver mock data (test infrastructure path)."""

    def _mock_client(self):
        from core.gcp_scc import GCPSecurityClient
        return GCPSecurityClient(project_id="", credentials_file="", allow_mock=True)

    def test_get_findings_returns_mock_when_allow_mock(self):
        client = self._mock_client()
        result = client.get_findings()
        assert len(result) > 0
        assert "name" in result[0]

    def test_get_sources_returns_mock_when_allow_mock(self):
        client = self._mock_client()
        result = client.get_sources()
        assert len(result) > 0

    def test_get_assets_returns_mock_when_allow_mock(self):
        client = self._mock_client()
        result = client.get_assets()
        assert len(result) > 0

    def test_import_findings_is_mock_true_when_allow_mock(self):
        from unittest.mock import MagicMock
        client = self._mock_client()
        client._try_ingest_to_pipeline = MagicMock()
        result = client.import_findings(org_id="mock_test")
        assert result["is_mock"] is True
        assert result["findings_count"] > 0


# ---------------------------------------------------------------------------
# GitHub Security — github_security.py
# ---------------------------------------------------------------------------

class TestGitHubSecurityHonestNotConfigured:
    """GitHubSecurityClient(allow_mock=False) must never return _MOCK_* data."""

    def _unconfigured(self):
        from core.github_security import GitHubSecurityClient
        # Patch out env vars to guarantee unconfigured
        with patch.dict("os.environ", {}, clear=True):
            return GitHubSecurityClient()

    # --- get_code_scanning_alerts ---

    def test_code_scanning_returns_empty_list(self):
        client = self._unconfigured()
        result = client.get_code_scanning_alerts()
        assert result == []

    def test_code_scanning_no_mock_flag(self):
        from core.github_security import _MOCK_CODE_SCANNING_ALERTS
        client = self._unconfigured()
        result = client.get_code_scanning_alerts()
        result_str = str(result)
        for alert in _MOCK_CODE_SCANNING_ALERTS:
            # The specific mock HTML URL must not appear
            assert alert.get("html_url", "") not in result_str

    def test_code_scanning_no_mock_repo_url(self):
        client = self._unconfigured()
        result = client.get_code_scanning_alerts()
        for alert in result:
            assert alert.get("_mock") is not True
            assert "mock-owner" not in str(alert)
            assert "mock-repo" not in str(alert)

    # --- get_dependabot_alerts ---

    def test_dependabot_returns_empty_list(self):
        client = self._unconfigured()
        result = client.get_dependabot_alerts()
        assert result == []

    def test_dependabot_no_ghsa_mock(self):
        """_MOCK_DEPENDABOT_ALERTS use GHSA-mock-XXXX identifiers."""
        client = self._unconfigured()
        result = client.get_dependabot_alerts()
        result_str = str(result)
        assert "GHSA-mock" not in result_str

    def test_dependabot_no_mock_cve(self):
        """The specific mock CVEs from _MOCK_DEPENDABOT_ALERTS must not appear."""
        from core.github_security import _MOCK_DEPENDABOT_ALERTS
        client = self._unconfigured()
        result = client.get_dependabot_alerts()
        result_str = str(result)
        for alert in _MOCK_DEPENDABOT_ALERTS:
            advisory = alert.get("security_advisory", {})
            cve = advisory.get("cve_id", "")
            if cve:
                assert cve not in result_str

    # --- get_secret_scanning_alerts ---

    def test_secret_scanning_returns_empty_list(self):
        client = self._unconfigured()
        result = client.get_secret_scanning_alerts()
        assert result == []

    def test_secret_scanning_no_mock_token(self):
        """_MOCK_SECRET_SCANNING_ALERTS contain 'ghp_mock_redacted'."""
        client = self._unconfigured()
        result = client.get_secret_scanning_alerts()
        result_str = str(result)
        assert "ghp_mock_redacted" not in result_str

    def test_secret_scanning_no_mock_flag(self):
        client = self._unconfigured()
        result = client.get_secret_scanning_alerts()
        for alert in result:
            assert alert.get("_mock") is not True

    # --- import_all ---

    def test_import_all_zero_findings(self):
        client = self._unconfigured()
        result = client.import_all(org_id="no_mock_import")
        assert result["total_findings"] == 0

    def test_import_all_configured_false(self):
        client = self._unconfigured()
        result = client.import_all(org_id="no_mock_cfg")
        assert result["configured"] is False

    def test_import_all_is_mock_false_by_default(self):
        client = self._unconfigured()
        result = client.import_all(org_id="no_mock_flag")
        assert result["is_mock"] is False

    def test_import_all_owner_repo_empty(self):
        """No 'mock-owner' or 'mock-repo' placeholders in result."""
        client = self._unconfigured()
        result = client.import_all(org_id="no_mock_owner")
        assert result["owner"] == ""
        assert result["repo"] == ""
        assert "mock-owner" not in str(result)
        assert "mock-repo" not in str(result)

    def test_import_all_no_mock_cve_ids_in_findings(self):
        client = self._unconfigured()
        result = client.import_all(org_id="no_mock_cve")
        result_str = str(result["findings"])
        assert "GHSA-mock" not in result_str
        assert "ghp_mock_redacted" not in result_str


class TestGitHubSecurityAllowMockPath:
    """allow_mock=True must still deliver mock data (test infrastructure path)."""

    def _mock_client(self):
        from core.github_security import GitHubSecurityClient
        with patch.dict("os.environ", {}, clear=True):
            return GitHubSecurityClient(allow_mock=True)

    def test_code_scanning_returns_mock_when_allow_mock(self):
        client = self._mock_client()
        result = client.get_code_scanning_alerts()
        assert len(result) > 0
        assert result[0].get("_mock") is True

    def test_dependabot_returns_mock_when_allow_mock(self):
        client = self._mock_client()
        result = client.get_dependabot_alerts()
        assert len(result) > 0
        assert result[0].get("_mock") is True

    def test_secret_scanning_returns_mock_when_allow_mock(self):
        client = self._mock_client()
        result = client.get_secret_scanning_alerts()
        assert len(result) > 0
        assert result[0].get("_mock") is True

    def test_import_all_is_mock_true_when_allow_mock(self):
        client = self._mock_client()
        result = client.import_all(org_id="mock_test")
        assert result["is_mock"] is True
        assert result["total_findings"] > 0


# ---------------------------------------------------------------------------
# PagerDuty Integration — pagerduty_integration.py
# ---------------------------------------------------------------------------

class TestPagerDutyHonestNotConfigured:
    """PagerDutyClient(allow_mock=False) must never return _MOCK_* data."""

    def _unconfigured(self):
        from core.pagerduty_integration import PagerDutyClient
        return PagerDutyClient(api_token="")

    # --- list_incidents ---

    def test_list_incidents_returns_empty_list(self):
        client = self._unconfigured()
        result = client.list_incidents()
        assert result == []

    def test_list_incidents_no_mock_incident_ids(self):
        """_MOCK_INCIDENTS use IDs like 'MOCK-INC-001'."""
        client = self._unconfigured()
        result = client.list_incidents()
        result_str = str(result)
        assert "MOCK-INC-001" not in result_str
        assert "MOCK-INC-002" not in result_str

    def test_list_incidents_no_mock_pagerduty_domains(self):
        """Mock data references 'acme.pagerduty.com' — must not appear."""
        client = self._unconfigured()
        result = client.list_incidents()
        result_str = str(result)
        assert "acme.pagerduty.com" not in result_str

    # --- get_incident ---

    def test_get_incident_returns_not_configured_dict(self):
        client = self._unconfigured()
        result = client.get_incident("INC123")
        assert isinstance(result, dict)
        assert result.get("configured") is False
        assert result.get("incident_id") == "INC123"

    def test_get_incident_no_mock_ids(self):
        from core.pagerduty_integration import _MOCK_INCIDENTS
        client = self._unconfigured()
        result = client.get_incident("INC123")
        result_str = str(result)
        for inc in _MOCK_INCIDENTS:
            assert inc["id"] not in result_str

    # --- update_incident ---

    def test_update_incident_returns_not_configured_dict(self):
        client = self._unconfigured()
        result = client.update_incident("INC123", status="resolved")
        assert isinstance(result, dict)
        assert result.get("configured") is False

    def test_update_incident_no_mock_ids(self):
        from core.pagerduty_integration import _MOCK_INCIDENTS
        client = self._unconfigured()
        result = client.update_incident("INC456")
        result_str = str(result)
        for inc in _MOCK_INCIDENTS:
            assert inc["id"] not in result_str

    # --- list_schedules ---

    def test_list_schedules_returns_empty_list(self):
        client = self._unconfigured()
        result = client.list_schedules()
        assert result == []

    def test_list_schedules_no_mock_schedule_ids(self):
        """_MOCK_SCHEDULES use IDs like 'PSCHED001'."""
        client = self._unconfigured()
        result = client.list_schedules()
        result_str = str(result)
        assert "PSCHED001" not in result_str
        assert "PSCHED002" not in result_str

    # --- get_oncall_users ---

    def test_get_oncall_users_returns_empty_list(self):
        client = self._unconfigured()
        result = client.get_oncall_users("PSCHED001")
        assert result == []

    def test_get_oncall_users_no_mock_user_ids(self):
        """_MOCK_SCHEDULES users have IDs like 'PUSR001'."""
        client = self._unconfigured()
        result = client.get_oncall_users("PSCHED001")
        result_str = str(result)
        assert "PUSR001" not in result_str
        assert "Alice" not in result_str

    # --- list_escalation_policies ---

    def test_list_escalation_policies_returns_empty_list(self):
        client = self._unconfigured()
        result = client.list_escalation_policies()
        assert result == []

    def test_list_escalation_policies_no_mock_ids(self):
        """_MOCK_ESCALATION_POLICIES use IDs like 'PESC001'."""
        client = self._unconfigured()
        result = client.list_escalation_policies()
        result_str = str(result)
        assert "PESC001" not in result_str

    # --- get_escalation_policy ---

    def test_get_escalation_policy_returns_not_configured_dict(self):
        client = self._unconfigured()
        result = client.get_escalation_policy("PESC001")
        assert isinstance(result, dict)
        assert result.get("configured") is False
        assert result.get("policy_id") == "PESC001"

    def test_get_escalation_policy_no_mock_names(self):
        """Mock policy is named 'Security Critical Response'."""
        client = self._unconfigured()
        result = client.get_escalation_policy("PESC001")
        result_str = str(result)
        assert "Security Critical Response" not in result_str

    # --- list_services ---

    def test_list_services_returns_empty_list(self):
        client = self._unconfigured()
        result = client.list_services()
        assert result == []

    def test_list_services_no_mock_service_ids(self):
        """_MOCK_SERVICES use IDs like 'PSVC001'."""
        client = self._unconfigured()
        result = client.list_services()
        result_str = str(result)
        assert "PSVC001" not in result_str
        assert "PSVC002" not in result_str

    # --- get_service_health ---

    def test_get_service_health_returns_not_configured_dict(self):
        client = self._unconfigured()
        result = client.get_service_health("PSVC001")
        assert isinstance(result, dict)
        assert result.get("configured") is False
        assert result.get("service_id") == "PSVC001"

    def test_get_service_health_no_mock_data(self):
        """Mock service has name 'Production API'."""
        client = self._unconfigured()
        result = client.get_service_health("PSVC001")
        result_str = str(result)
        assert "Production API" not in result_str
        assert "PSVC001" not in result.get("name", "")

    # --- create_incident (already has is_mock=True, verify it still works) ---

    def test_create_incident_is_mock_true_when_unconfigured(self):
        """create_incident already had is_mock=True on mock path — preserve."""
        client = self._unconfigured()
        result = client.create_incident(title="Test CVE", service_id="SVC001")
        # create_incident mock path returns is_mock=True (pre-existing behaviour)
        assert result.get("is_mock") is True


class TestPagerDutyAllowMockPath:
    """allow_mock=True must still deliver mock data (test infrastructure path)."""

    def _mock_client(self):
        from core.pagerduty_integration import PagerDutyClient
        return PagerDutyClient(api_token="", allow_mock=True)

    def test_list_incidents_returns_mock_when_allow_mock(self):
        client = self._mock_client()
        result = client.list_incidents()
        assert len(result) > 0
        assert result[0].get("is_mock") is True

    def test_list_schedules_returns_mock_when_allow_mock(self):
        client = self._mock_client()
        result = client.list_schedules()
        assert len(result) > 0

    def test_list_escalation_policies_returns_mock_when_allow_mock(self):
        client = self._mock_client()
        result = client.list_escalation_policies()
        assert len(result) > 0

    def test_list_services_returns_mock_when_allow_mock(self):
        client = self._mock_client()
        result = client.list_services()
        assert len(result) > 0

    def test_get_incident_returns_mock_when_allow_mock(self):
        client = self._mock_client()
        result = client.get_incident("MOCK-INC-001")
        assert result.get("is_mock") is True

    def test_get_escalation_policy_returns_mock_when_allow_mock(self):
        client = self._mock_client()
        result = client.get_escalation_policy("PESC001")
        assert result.get("is_mock") is True

    def test_get_service_health_returns_mock_when_allow_mock(self):
        client = self._mock_client()
        result = client.get_service_health("PSVC001")
        assert result.get("is_mock") is True

    def test_get_oncall_users_returns_mock_when_allow_mock(self):
        client = self._mock_client()
        result = client.get_oncall_users("PSCHED001")
        assert len(result) > 0

    def test_update_incident_returns_mock_when_allow_mock(self):
        client = self._mock_client()
        result = client.update_incident("INC-X", status="resolved")
        assert result.get("is_mock") is True
