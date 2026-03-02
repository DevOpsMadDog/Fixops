"""Comprehensive unit tests for suite-integrations/integrations/mpte_service.py.

Tests cover:
- AdvancedMPTEService: init, close, vulnerability mapping, severity scoring,
  exploitability determination, evidence formatting, artifact extraction
- trigger_pen_test_from_finding flow
- _process_test_results for various finding scenarios
- _map_vulnerability_to_test_type for all categories
- _format_evidence with various finding configurations
- run_comprehensive_scan with default and custom scan types

Pillar: V5 (MPTE Verification) — Advanced MPTE service integration
"""

from unittest.mock import AsyncMock, MagicMock

import pytest

from core.mpte_models import (
    ExploitabilityLevel,
    PenTestStatus,
)
from integrations.mpte_client import (
    MPTEFinding,
    MPTESeverity,
    MPTETestResult,
    MPTETestType,
)
from integrations.mpte_service import AdvancedMPTEService


# ── Helper factories ─────────────────────────────────────────────────


def make_finding(
    id="f-001",
    title="Test Vuln",
    severity=MPTESeverity.HIGH,
    vulnerability_type="sqli",
    exploit_successful=False,
    verified=False,
    false_positive=False,
    confidence=0.8,
    cvss_score=None,
    cwe_id=None,
    cve_id=None,
    evidence="",
    steps=None,
    description="A vulnerability",
    metadata=None,
):
    return MPTEFinding(
        id=id,
        title=title,
        description=description,
        severity=severity,
        vulnerability_type=vulnerability_type,
        exploitability="confirmed" if exploit_successful else "unknown",
        cvss_score=cvss_score,
        cwe_id=cwe_id,
        cve_id=cve_id,
        evidence=evidence,
        steps_to_reproduce=steps or [],
        remediation="Fix it",
        affected_components=[],
        attack_vector="network",
        impact="high",
        confidence=confidence,
        false_positive=false_positive,
        verified=verified,
        exploit_successful=exploit_successful,
        metadata=metadata or {},
    )


def make_test_result(
    test_id="t-001",
    findings=None,
    duration=10.0,
    status="completed",
):
    return MPTETestResult(
        test_id=test_id,
        test_type=MPTETestType.WEB_APPLICATION,
        target="https://target.example.com",
        status=status,
        findings=findings or [],
        duration_seconds=duration,
    )


# ── AdvancedMPTEService init/close ──────────────────────────────────


class TestAdvancedMPTEServiceInit:
    """Tests for AdvancedMPTEService initialization."""

    def test_init_with_defaults(self):
        svc = AdvancedMPTEService(mpte_url="https://mpte.example.com")
        assert svc.client is not None
        assert svc.db is not None
        assert svc._monitoring_jobs == {}

    def test_init_with_api_key(self):
        svc = AdvancedMPTEService(
            mpte_url="https://mpte.example.com",
            api_key="test-key",
        )
        assert svc.client.api_key == "test-key"

    def test_init_with_custom_db(self):
        mock_db = MagicMock()
        svc = AdvancedMPTEService(
            mpte_url="https://mpte.example.com",
            db=mock_db,
        )
        assert svc.db == mock_db

    @pytest.mark.asyncio
    async def test_close(self):
        svc = AdvancedMPTEService(mpte_url="https://mpte.example.com")
        svc.client = AsyncMock()
        await svc.close()
        svc.client.close.assert_called_once()


# ── _map_vulnerability_to_test_type ─────────────────────────────────


class TestMapVulnerabilityToTestType:
    """Tests for vulnerability-to-test-type mapping."""

    def setup_method(self):
        self.svc = AdvancedMPTEService(mpte_url="https://mpte.example.com")

    def test_sql_injection(self):
        assert self.svc._map_vulnerability_to_test_type("sql_injection") == MPTETestType.WEB_APPLICATION

    def test_xss(self):
        assert self.svc._map_vulnerability_to_test_type("xss") == MPTETestType.WEB_APPLICATION

    def test_csrf(self):
        assert self.svc._map_vulnerability_to_test_type("csrf") == MPTETestType.WEB_APPLICATION

    def test_injection_generic(self):
        assert self.svc._map_vulnerability_to_test_type("command_injection") == MPTETestType.WEB_APPLICATION

    def test_api_security(self):
        assert self.svc._map_vulnerability_to_test_type("api_auth_bypass") == MPTETestType.API_SECURITY

    def test_rest_api(self):
        assert self.svc._map_vulnerability_to_test_type("rest_misconfiguration") == MPTETestType.API_SECURITY

    def test_graphql(self):
        # "graphql_injection" contains "injection" which matches WEB_APPLICATION first
        # Pure "graphql_misconfiguration" matches API_SECURITY
        assert self.svc._map_vulnerability_to_test_type("graphql_misconfiguration") == MPTETestType.API_SECURITY

    def test_network(self):
        assert self.svc._map_vulnerability_to_test_type("network_exposure") == MPTETestType.NETWORK_SCAN

    def test_port_scan(self):
        assert self.svc._map_vulnerability_to_test_type("open_port") == MPTETestType.NETWORK_SCAN

    def test_service_vuln(self):
        assert self.svc._map_vulnerability_to_test_type("service_misconfiguration") == MPTETestType.NETWORK_SCAN

    def test_code_analysis(self):
        assert self.svc._map_vulnerability_to_test_type("code_smell") == MPTETestType.CODE_ANALYSIS

    def test_sast(self):
        assert self.svc._map_vulnerability_to_test_type("sast_finding") == MPTETestType.CODE_ANALYSIS

    def test_static(self):
        assert self.svc._map_vulnerability_to_test_type("static_analysis") == MPTETestType.CODE_ANALYSIS

    def test_cloud(self):
        assert self.svc._map_vulnerability_to_test_type("cloud_misconfiguration") == MPTETestType.CLOUD_SECURITY

    def test_aws(self):
        assert self.svc._map_vulnerability_to_test_type("aws_s3_public") == MPTETestType.CLOUD_SECURITY

    def test_azure(self):
        assert self.svc._map_vulnerability_to_test_type("azure_rbac") == MPTETestType.CLOUD_SECURITY

    def test_container(self):
        assert self.svc._map_vulnerability_to_test_type("container_escape") == MPTETestType.CONTAINER_SECURITY

    def test_docker(self):
        assert self.svc._map_vulnerability_to_test_type("docker_misconfiguration") == MPTETestType.CONTAINER_SECURITY

    def test_kubernetes(self):
        assert self.svc._map_vulnerability_to_test_type("kubernetes_rbac") == MPTETestType.CONTAINER_SECURITY

    def test_unknown_defaults_web(self):
        assert self.svc._map_vulnerability_to_test_type("unknown_type") == MPTETestType.WEB_APPLICATION

    def test_empty_defaults_web(self):
        assert self.svc._map_vulnerability_to_test_type("") == MPTETestType.WEB_APPLICATION


# ── _severity_to_score ──────────────────────────────────────────────


class TestSeverityToScore:
    """Tests for severity scoring."""

    def setup_method(self):
        self.svc = AdvancedMPTEService(mpte_url="https://mpte.example.com")

    def test_critical(self):
        assert self.svc._severity_to_score(MPTESeverity.CRITICAL) == 4

    def test_high(self):
        assert self.svc._severity_to_score(MPTESeverity.HIGH) == 3

    def test_medium(self):
        assert self.svc._severity_to_score(MPTESeverity.MEDIUM) == 2

    def test_low(self):
        assert self.svc._severity_to_score(MPTESeverity.LOW) == 1

    def test_info(self):
        assert self.svc._severity_to_score(MPTESeverity.INFO) == 0

    def test_ordering(self):
        scores = [
            self.svc._severity_to_score(s)
            for s in [MPTESeverity.INFO, MPTESeverity.LOW, MPTESeverity.MEDIUM, MPTESeverity.HIGH, MPTESeverity.CRITICAL]
        ]
        assert scores == sorted(scores)


# ── _determine_exploitability ───────────────────────────────────────


class TestDetermineExploitability:
    """Tests for exploitability determination."""

    def setup_method(self):
        self.svc = AdvancedMPTEService(mpte_url="https://mpte.example.com")

    def test_exploit_successful(self):
        finding = make_finding(exploit_successful=True)
        assert self.svc._determine_exploitability(finding) == ExploitabilityLevel.CONFIRMED_EXPLOITABLE

    def test_verified_critical(self):
        finding = make_finding(verified=True, severity=MPTESeverity.CRITICAL)
        assert self.svc._determine_exploitability(finding) == ExploitabilityLevel.LIKELY_EXPLOITABLE

    def test_verified_high(self):
        finding = make_finding(verified=True, severity=MPTESeverity.HIGH)
        assert self.svc._determine_exploitability(finding) == ExploitabilityLevel.LIKELY_EXPLOITABLE

    def test_medium_severity(self):
        finding = make_finding(severity=MPTESeverity.MEDIUM)
        assert self.svc._determine_exploitability(finding) == ExploitabilityLevel.INCONCLUSIVE

    def test_false_positive(self):
        finding = make_finding(false_positive=True, severity=MPTESeverity.LOW)
        assert self.svc._determine_exploitability(finding) == ExploitabilityLevel.BLOCKED

    def test_low_unverified(self):
        finding = make_finding(severity=MPTESeverity.LOW, verified=False)
        assert self.svc._determine_exploitability(finding) == ExploitabilityLevel.UNEXPLOITABLE


# ── _format_evidence ────────────────────────────────────────────────


class TestFormatEvidence:
    """Tests for evidence formatting."""

    def setup_method(self):
        self.svc = AdvancedMPTEService(mpte_url="https://mpte.example.com")

    def test_basic_evidence(self):
        finding = make_finding(title="SQLi", vulnerability_type="sqli")
        evidence = self.svc._format_evidence(finding, [finding])
        assert "SQLi" in evidence
        assert "sqli" in evidence

    def test_with_cvss_and_cwe(self):
        finding = make_finding(cvss_score=9.8, cwe_id="CWE-89")
        evidence = self.svc._format_evidence(finding, [finding])
        assert "9.8" in evidence
        assert "CWE-89" in evidence

    def test_with_additional_findings(self):
        f1 = make_finding(id="f-001")
        f2 = make_finding(id="f-002")
        f3 = make_finding(id="f-003")
        evidence = self.svc._format_evidence(f1, [f1, f2, f3])
        assert "2 more" in evidence

    def test_single_finding_no_additional(self):
        f1 = make_finding()
        evidence = self.svc._format_evidence(f1, [f1])
        assert "Additional" not in evidence

    def test_with_description(self):
        finding = make_finding(description="SQL injection via login form")
        evidence = self.svc._format_evidence(finding, [finding])
        assert "SQL injection via login form" in evidence

    def test_with_evidence_field(self):
        finding = make_finding(evidence="' OR 1=1 --")
        evidence = self.svc._format_evidence(finding, [finding])
        assert "' OR 1=1 --" in evidence


# ── _extract_artifacts ──────────────────────────────────────────────


class TestExtractArtifacts:
    """Tests for artifact extraction."""

    def setup_method(self):
        self.svc = AdvancedMPTEService(mpte_url="https://mpte.example.com")

    def test_empty_findings(self):
        result = make_test_result(findings=[])
        artifacts = self.svc._extract_artifacts(result)
        assert artifacts == []

    def test_finding_with_screenshot(self):
        f = make_finding(metadata={"screenshot": "screenshots/vuln1.png"})
        result = make_test_result(findings=[f])
        artifacts = self.svc._extract_artifacts(result)
        assert "screenshots/vuln1.png" in artifacts

    def test_finding_with_payload(self):
        f = make_finding(metadata={"payload": "payloads/sqli.txt"})
        result = make_test_result(findings=[f])
        artifacts = self.svc._extract_artifacts(result)
        assert "payloads/sqli.txt" in artifacts

    def test_finding_with_log_file(self):
        f = make_finding(metadata={"log_file": "logs/test.log"})
        result = make_test_result(findings=[f])
        artifacts = self.svc._extract_artifacts(result)
        assert "logs/test.log" in artifacts

    def test_finding_with_all_artifacts(self):
        f = make_finding(metadata={
            "screenshot": "s.png",
            "payload": "p.txt",
            "log_file": "l.log",
        })
        result = make_test_result(findings=[f])
        artifacts = self.svc._extract_artifacts(result)
        assert len(artifacts) == 3

    def test_multiple_findings(self):
        f1 = make_finding(id="f-001", metadata={"screenshot": "s1.png"})
        f2 = make_finding(id="f-002", metadata={"payload": "p2.txt"})
        result = make_test_result(findings=[f1, f2])
        artifacts = self.svc._extract_artifacts(result)
        assert len(artifacts) == 2

    def test_no_artifact_metadata(self):
        f = make_finding(metadata={"other": "value"})
        result = make_test_result(findings=[f])
        artifacts = self.svc._extract_artifacts(result)
        assert artifacts == []


# ── _process_test_results ───────────────────────────────────────────


class TestProcessTestResults:
    """Tests for test result processing."""

    def setup_method(self):
        self.svc = AdvancedMPTEService(mpte_url="https://mpte.example.com")
        self.svc.db = MagicMock()
        self.svc.db.create_result.return_value = MagicMock()
        self.svc.db.update_request.return_value = MagicMock()

    @pytest.mark.asyncio
    async def test_no_findings(self):
        request = MagicMock()
        request.id = "req-001"
        request.finding_id = "find-001"
        result = make_test_result(findings=[])

        await self.svc._process_test_results(request, result)

        # Should create result with UNEXPLOITABLE
        self.svc.db.create_result.assert_called_once()
        created_result = self.svc.db.create_result.call_args[0][0]
        assert created_result.exploitability == ExploitabilityLevel.UNEXPLOITABLE
        assert created_result.exploit_successful is False

    @pytest.mark.asyncio
    async def test_with_critical_finding(self):
        request = MagicMock()
        request.id = "req-002"
        request.finding_id = "find-002"
        finding = make_finding(
            severity=MPTESeverity.CRITICAL,
            exploit_successful=True,
            confidence=0.99,
            cvss_score=9.8,
        )
        result = make_test_result(findings=[finding])

        await self.svc._process_test_results(request, result)

        self.svc.db.create_result.assert_called_once()
        created_result = self.svc.db.create_result.call_args[0][0]
        assert created_result.exploitability == ExploitabilityLevel.CONFIRMED_EXPLOITABLE
        assert created_result.exploit_successful is True

    @pytest.mark.asyncio
    async def test_updates_request_status(self):
        request = MagicMock()
        request.id = "req-003"
        request.finding_id = "find-003"
        result = make_test_result(findings=[])

        await self.svc._process_test_results(request, result)

        self.svc.db.update_request.assert_called_once()
        assert request.status == PenTestStatus.COMPLETED
        assert request.completed_at is not None

    @pytest.mark.asyncio
    async def test_multiple_findings_uses_highest_severity(self):
        request = MagicMock()
        request.id = "req-004"
        request.finding_id = "find-004"
        findings = [
            make_finding(id="f1", severity=MPTESeverity.LOW),
            make_finding(id="f2", severity=MPTESeverity.CRITICAL, exploit_successful=True),
            make_finding(id="f3", severity=MPTESeverity.MEDIUM),
        ]
        result = make_test_result(findings=findings)

        await self.svc._process_test_results(request, result)

        created_result = self.svc.db.create_result.call_args[0][0]
        assert created_result.exploitability == ExploitabilityLevel.CONFIRMED_EXPLOITABLE


# ── trigger_pen_test_from_finding ───────────────────────────────────


class TestTriggerPenTest:
    """Tests for triggering pen tests from findings."""

    def setup_method(self):
        self.svc = AdvancedMPTEService(mpte_url="https://mpte.example.com")
        self.svc.db = MagicMock()
        self.svc.client = AsyncMock()

    @pytest.mark.asyncio
    async def test_trigger_success(self):
        mock_request = MagicMock()
        mock_request.id = "req-001"
        mock_request.status = PenTestStatus.PENDING
        self.svc.db.create_request.return_value = mock_request
        self.svc.db.update_request.return_value = mock_request
        self.svc.client.create_test.return_value = "mpte-test-001"

        result = await self.svc.trigger_pen_test_from_finding(
            finding_id="find-001",
            target_url="https://target.example.com",
            vulnerability_type="sql_injection",
            test_case="Test SQL injection in login",
        )

        assert result is not None
        self.svc.db.create_request.assert_called_once()
        self.svc.client.create_test.assert_called_once()

    @pytest.mark.asyncio
    async def test_trigger_failure_updates_status(self):
        mock_request = MagicMock()
        mock_request.id = "req-002"
        mock_request.status = PenTestStatus.PENDING
        self.svc.db.create_request.return_value = mock_request
        self.svc.db.update_request.return_value = mock_request
        self.svc.client.create_test.side_effect = Exception("Connection failed")

        await self.svc.trigger_pen_test_from_finding(
            finding_id="find-002",
            target_url="https://unreachable.example.com",
            vulnerability_type="xss",
            test_case="Test XSS",
        )

        assert mock_request.status == PenTestStatus.FAILED


# ── run_comprehensive_scan ──────────────────────────────────────────


class TestRunComprehensiveScan:
    """Tests for comprehensive scanning."""

    def setup_method(self):
        self.svc = AdvancedMPTEService(mpte_url="https://mpte.example.com")
        self.svc.db = MagicMock()
        self.svc.client = AsyncMock()

    @pytest.mark.asyncio
    async def test_default_scan_types(self):
        mock_request = MagicMock()
        mock_request.id = "req-001"
        self.svc.db.create_request.return_value = mock_request
        self.svc.client.create_test.return_value = "mpte-scan-001"

        requests = await self.svc.run_comprehensive_scan("https://target.com")

        assert len(requests) == 4  # Default 4 scan types
        assert self.svc.client.create_test.call_count == 4

    @pytest.mark.asyncio
    async def test_custom_scan_types(self):
        mock_request = MagicMock()
        mock_request.id = "req-002"
        self.svc.db.create_request.return_value = mock_request
        self.svc.client.create_test.return_value = "mpte-scan-002"

        requests = await self.svc.run_comprehensive_scan(
            "https://target.com",
            scan_types=[MPTETestType.WEB_APPLICATION],
        )

        assert len(requests) == 1
        assert self.svc.client.create_test.call_count == 1

    @pytest.mark.asyncio
    async def test_partial_failure(self):
        """Test that scan continues even if some types fail."""
        mock_request = MagicMock()
        mock_request.id = "req-003"
        self.svc.db.create_request.return_value = mock_request
        self.svc.client.create_test.side_effect = [
            "scan-001",
            Exception("Failed"),
            "scan-003",
            "scan-004",
        ]

        requests = await self.svc.run_comprehensive_scan("https://target.com")

        # Should have 3 successful requests (1 failed)
        assert len(requests) == 3
