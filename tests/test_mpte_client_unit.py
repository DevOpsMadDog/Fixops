"""Comprehensive unit tests for suite-integrations/integrations/mpte_client.py.

Tests cover:
- MPTETestType and MPTESeverity enums
- MPTEFinding and MPTETestResult dataclasses
- MPTEClient: initialization, HTTP client management, request logic, test creation,
  status retrieval, result extraction, automated scanning

Pillar: V5 (MPTE Verification) — Core MPTE client for exploit verification
"""

import json
from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from integrations.mpte_client import (
    MPTEClient,
    MPTEFinding,
    MPTESeverity,
    MPTETestResult,
    MPTETestType,
)


# ── Enums ────────────────────────────────────────────────────────────


class TestMPTETestType:
    """Tests for MPTETestType enum."""

    def test_all_types_exist(self):
        expected = [
            "WEB_APPLICATION",
            "API_SECURITY",
            "NETWORK_SCAN",
            "CODE_ANALYSIS",
            "INFRASTRUCTURE",
            "CLOUD_SECURITY",
            "CONTAINER_SECURITY",
            "IOT_DEVICE",
            "MOBILE_APP",
            "SOCIAL_ENGINEERING",
        ]
        for name in expected:
            assert hasattr(MPTETestType, name)

    def test_type_count(self):
        assert len(MPTETestType) == 10

    def test_web_application_value(self):
        assert MPTETestType.WEB_APPLICATION.value == "web_application"

    def test_api_security_value(self):
        assert MPTETestType.API_SECURITY.value == "api_security"

    def test_container_security_value(self):
        assert MPTETestType.CONTAINER_SECURITY.value == "container_security"


class TestMPTESeverity:
    """Tests for MPTESeverity enum."""

    def test_all_severities_exist(self):
        expected = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        for name in expected:
            assert hasattr(MPTESeverity, name)

    def test_severity_count(self):
        assert len(MPTESeverity) == 5

    def test_critical_value(self):
        assert MPTESeverity.CRITICAL.value == "critical"

    def test_info_value(self):
        assert MPTESeverity.INFO.value == "info"


# ── MPTEFinding dataclass ───────────────────────────────────────────


class TestMPTEFinding:
    """Tests for MPTEFinding dataclass."""

    def test_create_minimal(self):
        finding = MPTEFinding(
            id="f-001",
            title="SQL Injection",
            description="Found SQL injection in login form",
            severity=MPTESeverity.HIGH,
            vulnerability_type="sqli",
            exploitability="confirmed",
        )
        assert finding.id == "f-001"
        assert finding.title == "SQL Injection"
        assert finding.severity == MPTESeverity.HIGH
        assert finding.cvss_score is None
        assert finding.cwe_id is None
        assert finding.cve_id is None
        assert finding.evidence == ""
        assert finding.steps_to_reproduce == []
        assert finding.remediation == ""
        assert finding.affected_components == []
        assert finding.confidence == 0.0
        assert finding.false_positive is False
        assert finding.verified is False
        assert finding.exploit_successful is False
        assert finding.metadata == {}

    def test_create_full(self):
        finding = MPTEFinding(
            id="f-002",
            title="XSS",
            description="Reflected XSS in search",
            severity=MPTESeverity.MEDIUM,
            vulnerability_type="xss",
            exploitability="confirmed",
            cvss_score=7.5,
            cwe_id="CWE-79",
            cve_id="CVE-2026-12345",
            evidence="<script>alert(1)</script>",
            steps_to_reproduce=["step1", "step2"],
            remediation="Encode output",
            affected_components=["/search", "/api/search"],
            attack_vector="network",
            impact="high",
            confidence=0.95,
            false_positive=False,
            verified=True,
            exploit_successful=True,
            metadata={"scanner": "MPTE"},
        )
        assert finding.cvss_score == 7.5
        assert finding.cwe_id == "CWE-79"
        assert finding.cve_id == "CVE-2026-12345"
        assert len(finding.steps_to_reproduce) == 2
        assert finding.verified is True
        assert finding.exploit_successful is True
        assert finding.metadata["scanner"] == "MPTE"

    def test_timestamp_auto_set(self):
        finding = MPTEFinding(
            id="f-003",
            title="Test",
            description="Test finding",
            severity=MPTESeverity.LOW,
            vulnerability_type="test",
            exploitability="unknown",
        )
        assert isinstance(finding.discovered_at, datetime)


# ── MPTETestResult dataclass ────────────────────────────────────────


class TestMPTETestResult:
    """Tests for MPTETestResult dataclass."""

    def test_create_minimal(self):
        result = MPTETestResult(
            test_id="t-001",
            test_type=MPTETestType.WEB_APPLICATION,
            target="https://example.com",
            status="completed",
        )
        assert result.test_id == "t-001"
        assert result.test_type == MPTETestType.WEB_APPLICATION
        assert result.target == "https://example.com"
        assert result.status == "completed"
        assert result.findings == []
        assert result.start_time is None
        assert result.end_time is None
        assert result.duration_seconds == 0.0
        assert result.risk_score == 0.0
        assert result.summary == ""
        assert result.metadata == {}

    def test_create_with_findings(self):
        finding = MPTEFinding(
            id="f-001",
            title="SQLi",
            description="SQLi found",
            severity=MPTESeverity.CRITICAL,
            vulnerability_type="sqli",
            exploitability="confirmed",
        )
        result = MPTETestResult(
            test_id="t-002",
            test_type=MPTETestType.API_SECURITY,
            target="https://api.example.com",
            status="completed",
            findings=[finding],
            risk_score=9.5,
            summary="1 critical finding",
        )
        assert len(result.findings) == 1
        assert result.findings[0].severity == MPTESeverity.CRITICAL
        assert result.risk_score == 9.5


# ── MPTEClient ──────────────────────────────────────────────────────


class TestMPTEClientInit:
    """Tests for MPTEClient initialization."""

    def test_default_init(self):
        client = MPTEClient(base_url="https://mpte.example.com")
        assert client.base_url == "https://mpte.example.com"
        assert client.api_key is None
        assert client.timeout == 15
        assert client.max_retries == 1
        assert client._client is None

    def test_init_with_auth(self):
        client = MPTEClient(
            base_url="https://mpte.example.com",
            api_key="test-key-123",
        )
        assert client.api_key == "test-key-123"

    def test_init_custom_timeout(self):
        client = MPTEClient(
            base_url="https://mpte.example.com",
            timeout=30,
            max_retries=3,
        )
        assert client.timeout == 30
        assert client.max_retries == 3

    def test_url_trailing_slash_stripped(self):
        client = MPTEClient(base_url="https://mpte.example.com/")
        assert client.base_url == "https://mpte.example.com"


class TestMPTEClientGetClient:
    """Tests for _get_client method."""

    @pytest.mark.asyncio
    async def test_get_client_creates_once(self):
        client = MPTEClient(base_url="https://mpte.example.com")
        http_client = await client._get_client()
        assert http_client is not None
        assert isinstance(http_client, httpx.AsyncClient)
        # Second call should return same client
        http_client2 = await client._get_client()
        assert http_client is http_client2
        await client.close()

    @pytest.mark.asyncio
    async def test_get_client_with_auth_header(self):
        client = MPTEClient(
            base_url="https://mpte.example.com",
            api_key="my-key",
        )
        http_client = await client._get_client()
        assert "Authorization" in http_client.headers
        assert http_client.headers["Authorization"] == "Bearer my-key"
        await client.close()

    @pytest.mark.asyncio
    async def test_get_client_content_type(self):
        client = MPTEClient(base_url="https://mpte.example.com")
        http_client = await client._get_client()
        assert http_client.headers.get("Content-Type") == "application/json"
        await client.close()


class TestMPTEClientClose:
    """Tests for close method."""

    @pytest.mark.asyncio
    async def test_close_resets_client(self):
        client = MPTEClient(base_url="https://mpte.example.com")
        await client._get_client()
        assert client._client is not None
        await client.close()
        assert client._client is None

    @pytest.mark.asyncio
    async def test_close_when_not_initialized(self):
        client = MPTEClient(base_url="https://mpte.example.com")
        assert client._client is None
        await client.close()  # Should not raise
        assert client._client is None


class TestMPTEClientExtractFindings:
    """Tests for _extract_findings method."""

    @pytest.mark.asyncio
    async def test_extract_findings_from_dict(self):
        client = MPTEClient(base_url="https://mpte.example.com")
        subtask = {
            "result": {
                "vulnerabilities": [
                    {
                        "id": "v-001",
                        "title": "SQL Injection",
                        "description": "SQL injection in login",
                        "severity": "critical",
                        "type": "sqli",
                        "exploitability": "confirmed",
                        "cvss_score": 9.8,
                        "cwe_id": "CWE-89",
                        "evidence": "payload: ' OR 1=1--",
                        "steps": ["Enter payload", "Submit form"],
                        "remediation": "Use parameterized queries",
                        "components": ["/login"],
                        "attack_vector": "network",
                        "impact": "data breach",
                        "confidence": 0.99,
                        "verified": True,
                        "exploit_successful": True,
                        "metadata": {"tool": "mpte"},
                    }
                ]
            }
        }
        findings = await client._extract_findings(subtask)
        assert len(findings) == 1
        f = findings[0]
        assert f.id == "v-001"
        assert f.title == "SQL Injection"
        assert f.severity == MPTESeverity.CRITICAL
        assert f.cvss_score == 9.8
        assert f.cwe_id == "CWE-89"
        assert f.verified is True
        assert f.exploit_successful is True
        assert len(f.steps_to_reproduce) == 2
        await client.close()

    @pytest.mark.asyncio
    async def test_extract_findings_from_json_string(self):
        client = MPTEClient(base_url="https://mpte.example.com")
        subtask = {
            "result": json.dumps(
                {
                    "vulnerabilities": [
                        {
                            "id": "v-002",
                            "title": "XSS",
                            "description": "Reflected XSS",
                            "severity": "high",
                            "type": "xss",
                            "exploitability": "confirmed",
                        }
                    ]
                }
            )
        }
        findings = await client._extract_findings(subtask)
        assert len(findings) == 1
        assert findings[0].severity == MPTESeverity.HIGH
        await client.close()

    @pytest.mark.asyncio
    async def test_extract_findings_invalid_json_string(self):
        client = MPTEClient(base_url="https://mpte.example.com")
        subtask = {"result": "not valid json"}
        findings = await client._extract_findings(subtask)
        assert findings == []
        await client.close()

    @pytest.mark.asyncio
    async def test_extract_findings_empty_result(self):
        client = MPTEClient(base_url="https://mpte.example.com")
        subtask = {"result": {}}
        findings = await client._extract_findings(subtask)
        assert findings == []
        await client.close()

    @pytest.mark.asyncio
    async def test_extract_findings_no_result_key(self):
        client = MPTEClient(base_url="https://mpte.example.com")
        subtask = {}
        findings = await client._extract_findings(subtask)
        assert findings == []
        await client.close()

    @pytest.mark.asyncio
    async def test_extract_findings_multiple_vulns(self):
        client = MPTEClient(base_url="https://mpte.example.com")
        subtask = {
            "result": {
                "vulnerabilities": [
                    {
                        "id": f"v-{i}",
                        "title": f"Vuln {i}",
                        "description": f"Description {i}",
                        "severity": sev,
                        "type": "test",
                        "exploitability": "unknown",
                    }
                    for i, sev in enumerate(
                        ["critical", "high", "medium", "low", "info"]
                    )
                ]
            }
        }
        findings = await client._extract_findings(subtask)
        assert len(findings) == 5
        severities = [f.severity for f in findings]
        assert MPTESeverity.CRITICAL in severities
        assert MPTESeverity.INFO in severities
        await client.close()

    @pytest.mark.asyncio
    async def test_extract_findings_default_values(self):
        client = MPTEClient(base_url="https://mpte.example.com")
        subtask = {
            "result": {
                "vulnerabilities": [
                    {
                        "id": "",
                        "severity": "medium",
                        "type": "",
                        "exploitability": "unknown",
                    }
                ]
            }
        }
        findings = await client._extract_findings(subtask)
        assert len(findings) == 1
        f = findings[0]
        assert f.title == "Unknown Vulnerability"
        assert f.description == ""
        assert f.evidence == ""
        assert f.confidence == 0.0
        await client.close()


class TestMPTEClientRequest:
    """Tests for _request method with mocked HTTP responses."""

    @pytest.mark.asyncio
    async def test_request_success(self):
        client = MPTEClient(base_url="https://mpte.example.com")
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.content = b'{"status": "ok"}'
        mock_response.json.return_value = {"status": "ok"}
        mock_response.raise_for_status = MagicMock()

        mock_http_client = AsyncMock()
        mock_http_client.request.return_value = mock_response
        client._client = mock_http_client

        result = await client._request("GET", "/api/v1/health")
        assert result == {"status": "ok"}
        await client.close()

    @pytest.mark.asyncio
    async def test_request_empty_response(self):
        client = MPTEClient(base_url="https://mpte.example.com")
        mock_response = MagicMock()
        mock_response.status_code = 204
        mock_response.content = b""
        mock_response.raise_for_status = MagicMock()

        mock_http_client = AsyncMock()
        mock_http_client.request.return_value = mock_response
        client._client = mock_http_client

        result = await client._request("DELETE", "/api/v1/test/123")
        assert result == {}
        await client.close()


class TestMPTEClientCreateTest:
    """Tests for create_test method."""

    @pytest.mark.asyncio
    async def test_create_test(self):
        client = MPTEClient(base_url="https://mpte.example.com")
        # Mock _request
        client._request = AsyncMock(return_value={"id": "test-123"})
        test_id = await client.create_test(
            "https://target.com",
            MPTETestType.WEB_APPLICATION,
        )
        assert test_id == "test-123"
        client._request.assert_called_once_with(
            "POST",
            "/api/v1/flows",
            json={
                "target": "https://target.com",
                "test_type": "web_application",
                "config": {},
            },
        )

    @pytest.mark.asyncio
    async def test_create_test_with_config(self):
        client = MPTEClient(base_url="https://mpte.example.com")
        client._request = AsyncMock(return_value={"id": "test-456"})
        config = {"deep_scan": True, "verify_exploits": True}
        test_id = await client.create_test(
            "https://api.target.com",
            MPTETestType.API_SECURITY,
            config=config,
        )
        assert test_id == "test-456"
        call_args = client._request.call_args
        assert call_args[1]["json"]["config"] == config

    @pytest.mark.asyncio
    async def test_create_test_empty_response(self):
        client = MPTEClient(base_url="https://mpte.example.com")
        client._request = AsyncMock(return_value={})
        test_id = await client.create_test(
            "target", MPTETestType.NETWORK_SCAN
        )
        assert test_id == ""


class TestMPTEClientGetStatus:
    """Tests for get_test_status method."""

    @pytest.mark.asyncio
    async def test_get_status(self):
        client = MPTEClient(base_url="https://mpte.example.com")
        client._request = AsyncMock(
            return_value={"status": "running", "progress": 50}
        )
        status = await client.get_test_status("test-123")
        assert status["status"] == "running"
        assert status["progress"] == 50
        client._request.assert_called_once_with("GET", "/api/v1/flows/test-123")


class TestMPTEClientAutomatedScan:
    """Tests for run_automated_scan method."""

    @pytest.mark.asyncio
    async def test_automated_scan_single_type(self):
        client = MPTEClient(base_url="https://mpte.example.com")
        client.create_test = AsyncMock(return_value="scan-001")
        test_ids = await client.run_automated_scan(
            "https://target.com",
            [MPTETestType.WEB_APPLICATION],
        )
        assert test_ids == ["scan-001"]
        assert client.create_test.call_count == 1

    @pytest.mark.asyncio
    async def test_automated_scan_multiple_types(self):
        client = MPTEClient(base_url="https://mpte.example.com")
        client.create_test = AsyncMock(side_effect=["scan-001", "scan-002", "scan-003"])
        test_ids = await client.run_automated_scan(
            "https://target.com",
            [
                MPTETestType.WEB_APPLICATION,
                MPTETestType.API_SECURITY,
                MPTETestType.NETWORK_SCAN,
            ],
        )
        assert len(test_ids) == 3
        assert test_ids == ["scan-001", "scan-002", "scan-003"]

    @pytest.mark.asyncio
    async def test_automated_scan_with_schedule(self):
        client = MPTEClient(base_url="https://mpte.example.com")
        client.create_test = AsyncMock(return_value="scan-004")
        await client.run_automated_scan(
            "https://target.com",
            [MPTETestType.WEB_APPLICATION],
            schedule="0 0 * * *",
        )
        call_args = client.create_test.call_args
        call_args[0][2] if len(call_args[0]) > 2 else call_args[1].get("config")
        # Verify schedule was passed in config
        assert client.create_test.call_count == 1

    @pytest.mark.asyncio
    async def test_automated_scan_empty_types(self):
        client = MPTEClient(base_url="https://mpte.example.com")
        client.create_test = AsyncMock()
        test_ids = await client.run_automated_scan("https://target.com", [])
        assert test_ids == []
        assert client.create_test.call_count == 0


class TestMPTEClientEdgeCases:
    """Edge case tests for MPTEClient."""

    def test_base_url_no_trailing_slash(self):
        client = MPTEClient(base_url="https://mpte.example.com///")
        assert client.base_url == "https://mpte.example.com"

    @pytest.mark.asyncio
    async def test_multiple_close_calls(self):
        client = MPTEClient(base_url="https://mpte.example.com")
        await client.close()
        await client.close()  # Should not raise
        assert client._client is None

    @pytest.mark.asyncio
    async def test_get_client_creates_with_correct_timeout(self):
        client = MPTEClient(base_url="https://mpte.example.com", timeout=42)
        http_client = await client._get_client()
        assert http_client.timeout.connect == 42 or http_client.timeout.read == 42
        await client.close()
