"""
Comprehensive unit tests for suite-core/core/iac_scanner.py

Covers:
- ScannerType and ScanStatus enums
- ScanResult and ScannerConfig dataclasses
- IaCScanner._map_severity
- IaCScanner._parse_checkov_output
- IaCScanner._parse_tfsec_output
- IaCScanner.get_available_scanners
- IaCScanner.to_dict() on ScanResult and IaCFinding
- ScannerConfig.from_env()
- Singleton get_iac_scanner()
- Edge cases: malformed JSON, empty inputs, null results, missing fields
"""

import json
import os
import sys
from datetime import datetime
from typing import Any, Dict, List, Optional

import pytest

# Ensure the suite-core directory is on the path
sys.path.insert(0, "/Users/devops.ai/developement/fixops/Fixops/suite-core")

# Set FIXOPS env vars before any imports so the module initialises cleanly
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-jwt-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from core.iac_models import IaCFinding, IaCFindingStatus, IaCProvider
from core.iac_scanner import (
    IaCScanner,
    ScannerConfig,
    ScannerType,
    ScanResult,
    ScanStatus,
    get_iac_scanner,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_scanner(config: Optional[ScannerConfig] = None) -> IaCScanner:
    """Return an IaCScanner with a minimal config (no external tools needed)."""
    cfg = config or ScannerConfig(
        checkov_path="checkov_does_not_exist",
        tfsec_path="tfsec_does_not_exist",
        timeout_seconds=30,
    )
    return IaCScanner(cfg)


def _make_finding(
    *,
    severity: str = "high",
    provider: IaCProvider = IaCProvider.TERRAFORM,
    status: IaCFindingStatus = IaCFindingStatus.OPEN,
    rule_id: str = "CKV_AWS_1",
) -> IaCFinding:
    return IaCFinding(
        id="test-id",
        provider=provider,
        status=status,
        severity=severity,
        title="Test finding",
        description="Test description",
        file_path="main.tf",
        line_number=10,
        resource_type="aws_s3_bucket",
        resource_name="my_bucket",
        rule_id=rule_id,
        remediation="Fix it",
        metadata={"scanner": "checkov"},
    )


def _checkov_json(failed_checks: List[Dict[str, Any]]) -> str:
    return json.dumps({"results": {"failed_checks": failed_checks}})


def _tfsec_json(results: List[Dict[str, Any]]) -> str:
    return json.dumps({"results": results})


# ---------------------------------------------------------------------------
# ScannerType enum
# ---------------------------------------------------------------------------

class TestScannerTypeEnum:
    def test_values_exist(self):
        assert ScannerType.CHECKOV == "checkov"
        assert ScannerType.TFSEC == "tfsec"

    def test_is_str_subclass(self):
        assert isinstance(ScannerType.CHECKOV, str)

    def test_members(self):
        members = {m.value for m in ScannerType}
        assert members == {"checkov", "tfsec"}

    def test_from_value_checkov(self):
        assert ScannerType("checkov") == ScannerType.CHECKOV

    def test_from_value_tfsec(self):
        assert ScannerType("tfsec") == ScannerType.TFSEC

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError):
            ScannerType("unknown")


# ---------------------------------------------------------------------------
# ScanStatus enum
# ---------------------------------------------------------------------------

class TestScanStatusEnum:
    def test_all_values_exist(self):
        assert ScanStatus.PENDING == "pending"
        assert ScanStatus.RUNNING == "running"
        assert ScanStatus.COMPLETED == "completed"
        assert ScanStatus.FAILED == "failed"
        assert ScanStatus.CANCELLED == "cancelled"

    def test_is_str_subclass(self):
        assert isinstance(ScanStatus.COMPLETED, str)

    def test_member_count(self):
        assert len(list(ScanStatus)) == 5

    def test_round_trip(self):
        for status in ScanStatus:
            assert ScanStatus(status.value) == status

    def test_invalid_raises(self):
        with pytest.raises(ValueError):
            ScanStatus("does_not_exist")


# ---------------------------------------------------------------------------
# ScannerConfig dataclass
# ---------------------------------------------------------------------------

class TestScannerConfig:
    def test_defaults(self):
        cfg = ScannerConfig()
        assert cfg.checkov_path == "checkov"
        assert cfg.tfsec_path == "tfsec"
        assert cfg.timeout_seconds == 300
        assert cfg.max_file_size_mb == 50
        assert cfg.skip_download is False
        assert cfg.excluded_checks == []
        assert cfg.soft_fail is False

    def test_custom_values(self):
        cfg = ScannerConfig(
            checkov_path="/usr/local/bin/checkov",
            tfsec_path="/usr/bin/tfsec",
            timeout_seconds=60,
            max_file_size_mb=10,
            skip_download=True,
            excluded_checks=["CKV_AWS_1", "CKV_AWS_2"],
            soft_fail=True,
        )
        assert cfg.checkov_path == "/usr/local/bin/checkov"
        assert cfg.timeout_seconds == 60
        assert cfg.excluded_checks == ["CKV_AWS_1", "CKV_AWS_2"]
        assert cfg.soft_fail is True

    def test_from_env_defaults(self, monkeypatch):
        # Remove overriding env vars so defaults kick in
        for key in [
            "FIXOPS_CHECKOV_PATH", "FIXOPS_TFSEC_PATH", "FIXOPS_SCAN_TIMEOUT",
            "FIXOPS_MAX_FILE_SIZE_MB", "FIXOPS_SKIP_DOWNLOAD",
            "FIXOPS_EXCLUDED_CHECKS", "FIXOPS_SOFT_FAIL",
        ]:
            monkeypatch.delenv(key, raising=False)

        cfg = ScannerConfig.from_env()
        assert cfg.checkov_path == "checkov"
        assert cfg.tfsec_path == "tfsec"
        assert cfg.timeout_seconds == 300
        assert cfg.max_file_size_mb == 50
        assert cfg.skip_download is False
        assert cfg.excluded_checks == []
        assert cfg.soft_fail is False

    def test_from_env_custom_checkov_path(self, monkeypatch):
        monkeypatch.setenv("FIXOPS_CHECKOV_PATH", "/opt/checkov")
        cfg = ScannerConfig.from_env()
        assert cfg.checkov_path == "/opt/checkov"

    def test_from_env_custom_tfsec_path(self, monkeypatch):
        monkeypatch.setenv("FIXOPS_TFSEC_PATH", "/opt/tfsec")
        cfg = ScannerConfig.from_env()
        assert cfg.tfsec_path == "/opt/tfsec"

    def test_from_env_timeout(self, monkeypatch):
        monkeypatch.setenv("FIXOPS_SCAN_TIMEOUT", "120")
        cfg = ScannerConfig.from_env()
        assert cfg.timeout_seconds == 120

    def test_from_env_skip_download_true(self, monkeypatch):
        monkeypatch.setenv("FIXOPS_SKIP_DOWNLOAD", "true")
        cfg = ScannerConfig.from_env()
        assert cfg.skip_download is True

    def test_from_env_skip_download_false(self, monkeypatch):
        monkeypatch.setenv("FIXOPS_SKIP_DOWNLOAD", "false")
        cfg = ScannerConfig.from_env()
        assert cfg.skip_download is False

    def test_from_env_soft_fail_true(self, monkeypatch):
        monkeypatch.setenv("FIXOPS_SOFT_FAIL", "true")
        cfg = ScannerConfig.from_env()
        assert cfg.soft_fail is True

    def test_from_env_excluded_checks(self, monkeypatch):
        monkeypatch.setenv("FIXOPS_EXCLUDED_CHECKS", "CKV_AWS_1,CKV_AWS_2")
        cfg = ScannerConfig.from_env()
        assert cfg.excluded_checks == ["CKV_AWS_1", "CKV_AWS_2"]

    def test_from_env_excluded_checks_empty(self, monkeypatch):
        monkeypatch.delenv("FIXOPS_EXCLUDED_CHECKS", raising=False)
        cfg = ScannerConfig.from_env()
        assert cfg.excluded_checks == []

    def test_from_env_max_file_size(self, monkeypatch):
        monkeypatch.setenv("FIXOPS_MAX_FILE_SIZE_MB", "100")
        cfg = ScannerConfig.from_env()
        assert cfg.max_file_size_mb == 100

    def test_excluded_checks_default_factory_is_independent(self):
        cfg1 = ScannerConfig()
        cfg2 = ScannerConfig()
        cfg1.excluded_checks.append("X")
        assert cfg2.excluded_checks == []


# ---------------------------------------------------------------------------
# ScanResult dataclass
# ---------------------------------------------------------------------------

class TestScanResult:
    def _make_result(self, status=ScanStatus.COMPLETED, findings=None) -> ScanResult:
        return ScanResult(
            scan_id="scan-001",
            status=status,
            scanner=ScannerType.CHECKOV,
            provider=IaCProvider.TERRAFORM,
            target_path="main.tf",
            findings=findings or [],
            started_at=datetime(2026, 3, 1, 10, 0, 0),
            completed_at=datetime(2026, 3, 1, 10, 0, 5),
            duration_seconds=5.0,
        )

    def test_to_dict_fields(self):
        result = self._make_result()
        d = result.to_dict()
        assert d["scan_id"] == "scan-001"
        assert d["status"] == "completed"
        assert d["scanner"] == "checkov"
        assert d["provider"] == "terraform"
        assert d["target_path"] == "main.tf"
        assert d["findings_count"] == 0
        assert d["findings"] == []
        assert d["duration_seconds"] == 5.0
        assert d["error_message"] is None
        assert d["metadata"] == {}

    def test_to_dict_timestamps(self):
        result = self._make_result()
        d = result.to_dict()
        assert d["started_at"] == "2026-03-01T10:00:00"
        assert d["completed_at"] == "2026-03-01T10:00:05"

    def test_to_dict_with_none_timestamps(self):
        result = ScanResult(
            scan_id="scan-002",
            status=ScanStatus.PENDING,
            scanner=ScannerType.CHECKOV,
            provider=IaCProvider.KUBERNETES,
            target_path="k8s.yaml",
        )
        d = result.to_dict()
        assert d["started_at"] is None
        assert d["completed_at"] is None
        assert d["duration_seconds"] is None

    def test_to_dict_findings_count(self):
        f1 = _make_finding()
        f2 = _make_finding(severity="medium")
        result = self._make_result(findings=[f1, f2])
        d = result.to_dict()
        assert d["findings_count"] == 2
        assert len(d["findings"]) == 2

    def test_to_dict_error_message(self):
        result = ScanResult(
            scan_id="scan-fail",
            status=ScanStatus.FAILED,
            scanner=ScannerType.TFSEC,
            provider=IaCProvider.TERRAFORM,
            target_path="main.tf",
            error_message="Tool not found",
        )
        d = result.to_dict()
        assert d["error_message"] == "Tool not found"

    def test_to_dict_metadata(self):
        result = ScanResult(
            scan_id="s1",
            status=ScanStatus.COMPLETED,
            scanner=ScannerType.CHECKOV,
            provider=IaCProvider.TERRAFORM,
            target_path="x.tf",
            metadata={"fallback": "builtin_scanner"},
        )
        d = result.to_dict()
        assert d["metadata"] == {"fallback": "builtin_scanner"}

    def test_findings_default_empty_list(self):
        result = ScanResult(
            scan_id="s2",
            status=ScanStatus.PENDING,
            scanner=ScannerType.CHECKOV,
            provider=IaCProvider.HELM,
            target_path="chart/",
        )
        assert result.findings == []

    def test_metadata_default_empty_dict(self):
        result = ScanResult(
            scan_id="s3",
            status=ScanStatus.PENDING,
            scanner=ScannerType.CHECKOV,
            provider=IaCProvider.HELM,
            target_path="chart/",
        )
        assert result.metadata == {}


# ---------------------------------------------------------------------------
# IaCFinding.to_dict (from iac_models)
# ---------------------------------------------------------------------------

class TestIaCFindingToDict:
    def test_basic_fields(self):
        f = _make_finding()
        d = f.to_dict()
        assert d["id"] == "test-id"
        assert d["provider"] == "terraform"
        assert d["status"] == "open"
        assert d["severity"] == "high"
        assert d["title"] == "Test finding"
        assert d["description"] == "Test description"
        assert d["file_path"] == "main.tf"
        assert d["line_number"] == 10
        assert d["resource_type"] == "aws_s3_bucket"
        assert d["resource_name"] == "my_bucket"
        assert d["rule_id"] == "CKV_AWS_1"
        assert d["remediation"] == "Fix it"
        assert "detected_at" in d
        assert d["resolved_at"] is None

    def test_resolved_at_none(self):
        f = _make_finding()
        assert f.to_dict()["resolved_at"] is None

    def test_resolved_at_set(self):
        f = _make_finding()
        f.resolved_at = datetime(2026, 3, 2, 12, 0, 0)
        d = f.to_dict()
        assert d["resolved_at"] == "2026-03-02T12:00:00"

    def test_metadata_included(self):
        f = _make_finding()
        assert f.to_dict()["metadata"] == {"scanner": "checkov"}

    def test_all_providers_serialise(self):
        for provider in IaCProvider:
            f = _make_finding(provider=provider)
            d = f.to_dict()
            assert d["provider"] == provider.value

    def test_all_statuses_serialise(self):
        for status in IaCFindingStatus:
            f = _make_finding(status=status)
            d = f.to_dict()
            assert d["status"] == status.value


# ---------------------------------------------------------------------------
# IaCScanner._map_severity
# ---------------------------------------------------------------------------

class TestMapSeverity:
    @pytest.fixture(autouse=True)
    def scanner(self):
        self.scanner = _make_scanner()

    def test_critical_maps_to_high(self):
        assert self.scanner._map_severity("critical") == "high"

    def test_high_maps_to_high(self):
        assert self.scanner._map_severity("high") == "high"

    def test_CRITICAL_uppercase(self):
        assert self.scanner._map_severity("CRITICAL") == "high"

    def test_HIGH_uppercase(self):
        assert self.scanner._map_severity("HIGH") == "high"

    def test_medium_maps_to_medium(self):
        assert self.scanner._map_severity("medium") == "medium"

    def test_moderate_maps_to_medium(self):
        assert self.scanner._map_severity("moderate") == "medium"

    def test_MEDIUM_uppercase(self):
        assert self.scanner._map_severity("MEDIUM") == "medium"

    def test_MODERATE_uppercase(self):
        assert self.scanner._map_severity("MODERATE") == "medium"

    def test_low_maps_to_low(self):
        assert self.scanner._map_severity("low") == "low"

    def test_info_maps_to_low(self):
        assert self.scanner._map_severity("info") == "low"

    def test_informational_maps_to_low(self):
        assert self.scanner._map_severity("informational") == "low"

    def test_LOW_uppercase(self):
        assert self.scanner._map_severity("LOW") == "low"

    def test_INFO_uppercase(self):
        assert self.scanner._map_severity("INFO") == "low"

    def test_unknown_defaults_to_medium(self):
        assert self.scanner._map_severity("unknown_severity") == "medium"

    def test_empty_string_defaults_to_medium(self):
        assert self.scanner._map_severity("") == "medium"

    def test_FAILED_defaults_to_medium(self):
        # checkov result field "FAILED" is not a severity — should default
        assert self.scanner._map_severity("FAILED") == "medium"

    def test_mixed_case_critical(self):
        assert self.scanner._map_severity("Critical") == "high"

    def test_mixed_case_medium(self):
        assert self.scanner._map_severity("Medium") == "medium"

    def test_mixed_case_low(self):
        assert self.scanner._map_severity("Low") == "low"


# ---------------------------------------------------------------------------
# IaCScanner._parse_checkov_output
# ---------------------------------------------------------------------------

class TestParseCheckovOutput:
    @pytest.fixture(autouse=True)
    def scanner(self):
        self.scanner = _make_scanner()

    def test_empty_string_returns_empty_list(self):
        results = self.scanner._parse_checkov_output("", IaCProvider.TERRAFORM, "main.tf")
        assert results == []

    def test_invalid_json_returns_empty_list(self):
        results = self.scanner._parse_checkov_output("not json", IaCProvider.TERRAFORM, "main.tf")
        assert results == []

    def test_json_without_results_key_returns_empty(self):
        results = self.scanner._parse_checkov_output("{}", IaCProvider.TERRAFORM, "main.tf")
        assert results == []

    def test_empty_failed_checks_returns_empty(self):
        payload = _checkov_json([])
        results = self.scanner._parse_checkov_output(payload, IaCProvider.TERRAFORM, "main.tf")
        assert results == []

    def test_single_failed_check_creates_finding(self):
        check = {
            "check_id": "CKV_AWS_18",
            "check": {"name": "Ensure S3 bucket logging is enabled"},
            "check_result": {"result": "FAILED"},
            "file_path": "main.tf",
            "file_line_range": [5, 10],
            "resource": "aws_s3_bucket",
            "resource_address": "aws_s3_bucket.example",
            "guideline": "Enable bucket logging",
            "check_type": "terraform",
            "bc_check_id": "BC_AWS_S3_13",
        }
        payload = _checkov_json([check])
        results = self.scanner._parse_checkov_output(payload, IaCProvider.TERRAFORM, "main.tf")
        assert len(results) == 1
        f = results[0]
        assert f.rule_id == "CKV_AWS_18"
        assert f.title == "CKV_AWS_18"
        assert f.description == "Ensure S3 bucket logging is enabled"
        assert f.file_path == "main.tf"
        assert f.line_number == 5
        assert f.resource_type == "aws_s3_bucket"
        assert f.resource_name == "aws_s3_bucket.example"
        assert f.remediation == "Enable bucket logging"
        assert f.provider == IaCProvider.TERRAFORM
        assert f.status == IaCFindingStatus.OPEN

    def test_finding_has_unique_id(self):
        check = {"check_id": "CKV_AWS_1", "check": {}, "check_result": {}}
        payload = _checkov_json([check])
        r1 = self.scanner._parse_checkov_output(payload, IaCProvider.TERRAFORM, "x.tf")
        r2 = self.scanner._parse_checkov_output(payload, IaCProvider.TERRAFORM, "x.tf")
        # Each call should produce new UUIDs
        assert r1[0].id != r2[0].id

    def test_multiple_failed_checks(self):
        checks = [
            {"check_id": f"CKV_AWS_{i}", "check": {}, "check_result": {}}
            for i in range(5)
        ]
        payload = _checkov_json(checks)
        results = self.scanner._parse_checkov_output(payload, IaCProvider.TERRAFORM, "main.tf")
        assert len(results) == 5

    def test_severity_mapping_failed_to_medium(self):
        check = {
            "check_id": "CKV_AWS_99",
            "check": {"name": "Test check"},
            "check_result": {"result": "FAILED"},
        }
        payload = _checkov_json([check])
        results = self.scanner._parse_checkov_output(payload, IaCProvider.TERRAFORM, "t.tf")
        # "FAILED" maps to default "medium"
        assert results[0].severity == "medium"

    def test_metadata_scanner_field(self):
        check = {
            "check_id": "CKV_AWS_1",
            "check": {},
            "check_result": {},
            "check_type": "terraform",
            "bc_check_id": "BC-1",
        }
        payload = _checkov_json([check])
        results = self.scanner._parse_checkov_output(payload, IaCProvider.TERRAFORM, "t.tf")
        assert results[0].metadata["scanner"] == "checkov"
        assert results[0].metadata["check_type"] == "terraform"
        assert results[0].metadata["bc_check_id"] == "BC-1"

    def test_missing_optional_fields_no_error(self):
        # Minimal check with no optional fields
        check = {}
        payload = _checkov_json([check])
        results = self.scanner._parse_checkov_output(payload, IaCProvider.TERRAFORM, "t.tf")
        assert len(results) == 1
        f = results[0]
        assert f.rule_id == "UNKNOWN"
        assert f.line_number == 0  # default from [0,0]

    def test_file_path_fallback_to_target(self):
        check = {"check_id": "CKV_K8S_1", "check": {}, "check_result": {}}
        payload = _checkov_json([check])
        results = self.scanner._parse_checkov_output(
            payload, IaCProvider.KUBERNETES, "pod.yaml"
        )
        assert results[0].file_path == "pod.yaml"

    def test_cloudformation_provider_preserved(self):
        check = {"check_id": "CKV_AWS_1", "check": {}, "check_result": {}}
        payload = _checkov_json([check])
        results = self.scanner._parse_checkov_output(
            payload, IaCProvider.CLOUDFORMATION, "template.yaml"
        )
        assert results[0].provider == IaCProvider.CLOUDFORMATION

    def test_results_key_missing_returns_empty(self):
        payload = json.dumps({"other_key": {}})
        results = self.scanner._parse_checkov_output(payload, IaCProvider.TERRAFORM, "t.tf")
        assert results == []

    def test_guideline_none_when_missing(self):
        check = {"check_id": "CKV_AWS_1", "check": {}, "check_result": {}}
        payload = _checkov_json([check])
        results = self.scanner._parse_checkov_output(payload, IaCProvider.TERRAFORM, "t.tf")
        assert results[0].remediation is None

    def test_file_line_range_used_for_line_number(self):
        check = {
            "check_id": "CKV_AWS_1",
            "check": {},
            "check_result": {},
            "file_line_range": [42, 50],
        }
        payload = _checkov_json([check])
        results = self.scanner._parse_checkov_output(payload, IaCProvider.TERRAFORM, "t.tf")
        assert results[0].line_number == 42

    def test_file_line_range_in_metadata(self):
        check = {
            "check_id": "CKV_AWS_1",
            "check": {},
            "check_result": {},
            "file_line_range": [5, 10],
        }
        payload = _checkov_json([check])
        results = self.scanner._parse_checkov_output(payload, IaCProvider.TERRAFORM, "t.tf")
        assert results[0].metadata["file_line_range"] == [5, 10]

    def test_evaluations_in_metadata(self):
        check = {
            "check_id": "CKV_AWS_1",
            "check": {},
            "check_result": {},
            "evaluations": {"var.bucket_name": "my-bucket"},
        }
        payload = _checkov_json([check])
        results = self.scanner._parse_checkov_output(payload, IaCProvider.TERRAFORM, "t.tf")
        assert results[0].metadata["evaluations"] == {"var.bucket_name": "my-bucket"}


# ---------------------------------------------------------------------------
# IaCScanner._parse_tfsec_output
# ---------------------------------------------------------------------------

class TestParseTfsecOutput:
    @pytest.fixture(autouse=True)
    def scanner(self):
        self.scanner = _make_scanner()

    def test_empty_string_returns_empty(self):
        results = self.scanner._parse_tfsec_output("", IaCProvider.TERRAFORM, "main.tf")
        assert results == []

    def test_invalid_json_returns_empty(self):
        results = self.scanner._parse_tfsec_output("}{invalid", IaCProvider.TERRAFORM, "main.tf")
        assert results == []

    def test_empty_results_list(self):
        payload = _tfsec_json([])
        results = self.scanner._parse_tfsec_output(payload, IaCProvider.TERRAFORM, "main.tf")
        assert results == []

    def test_null_results_returns_empty(self):
        payload = json.dumps({"results": None})
        results = self.scanner._parse_tfsec_output(payload, IaCProvider.TERRAFORM, "main.tf")
        assert results == []

    def test_missing_results_key_returns_empty(self):
        payload = json.dumps({})
        results = self.scanner._parse_tfsec_output(payload, IaCProvider.TERRAFORM, "main.tf")
        assert results == []

    def test_single_result_creates_finding(self):
        result = {
            "rule_id": "aws-s3-enable-bucket-logging",
            "long_id": "aws-s3-enable-bucket-logging",
            "rule_description": "Bucket does not have logging enabled",
            "description": "Bucket missing logging",
            "severity": "HIGH",
            "resource": "aws_s3_bucket.example",
            "resolution": "Enable bucket logging",
            "location": {
                "filename": "main.tf",
                "start_line": 10,
                "end_line": 20,
            },
            "rule_provider": "aws",
            "rule_service": "s3",
            "impact": "Log loss risk",
            "links": ["https://registry.terraform.io/providers/aws"],
        }
        payload = _tfsec_json([result])
        findings = self.scanner._parse_tfsec_output(payload, IaCProvider.TERRAFORM, "main.tf")
        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "aws-s3-enable-bucket-logging"
        assert f.title == "aws-s3-enable-bucket-logging"
        assert f.description == "Bucket missing logging"
        assert f.file_path == "main.tf"
        assert f.line_number == 10
        assert f.resource_type == "aws_s3_bucket.example"
        assert f.resource_name == "aws_s3_bucket.example"
        assert f.severity == "high"
        assert f.remediation == "Enable bucket logging"
        assert f.provider == IaCProvider.TERRAFORM
        assert f.status == IaCFindingStatus.OPEN

    def test_metadata_scanner_tfsec(self):
        result = {
            "rule_id": "aws-vpc-no-public-ingress",
            "description": "Public ingress",
            "severity": "MEDIUM",
            "resource": "aws_security_group.sg",
            "location": {},
            "rule_provider": "aws",
            "rule_service": "vpc",
            "impact": "Data exfiltration",
            "links": ["https://example.com"],
        }
        payload = _tfsec_json([result])
        findings = self.scanner._parse_tfsec_output(payload, IaCProvider.TERRAFORM, "sg.tf")
        assert findings[0].metadata["scanner"] == "tfsec"
        assert findings[0].metadata["rule_provider"] == "aws"
        assert findings[0].metadata["impact"] == "Data exfiltration"
        assert findings[0].metadata["links"] == ["https://example.com"]

    def test_severity_low(self):
        result = {
            "rule_id": "some-rule",
            "severity": "LOW",
            "location": {},
        }
        payload = _tfsec_json([result])
        findings = self.scanner._parse_tfsec_output(payload, IaCProvider.TERRAFORM, "t.tf")
        assert findings[0].severity == "low"

    def test_severity_info(self):
        result = {
            "rule_id": "some-rule",
            "severity": "INFO",
            "location": {},
        }
        payload = _tfsec_json([result])
        findings = self.scanner._parse_tfsec_output(payload, IaCProvider.TERRAFORM, "t.tf")
        assert findings[0].severity == "low"

    def test_file_path_fallback_to_target(self):
        result = {
            "rule_id": "some-rule",
            "severity": "HIGH",
            "location": {},  # no filename
        }
        payload = _tfsec_json([result])
        findings = self.scanner._parse_tfsec_output(payload, IaCProvider.TERRAFORM, "fallback.tf")
        assert findings[0].file_path == "fallback.tf"

    def test_rule_id_fallback_to_long_id(self):
        result = {
            "long_id": "aws-s3-enable-versioning",
            "severity": "HIGH",
            "location": {},
        }
        payload = _tfsec_json([result])
        findings = self.scanner._parse_tfsec_output(payload, IaCProvider.TERRAFORM, "t.tf")
        assert findings[0].rule_id == "aws-s3-enable-versioning"

    def test_rule_id_unknown_when_both_missing(self):
        result = {"severity": "HIGH", "location": {}}
        payload = _tfsec_json([result])
        findings = self.scanner._parse_tfsec_output(payload, IaCProvider.TERRAFORM, "t.tf")
        assert findings[0].rule_id == "UNKNOWN"

    def test_multiple_results(self):
        results_list = [
            {"rule_id": f"rule-{i}", "severity": "HIGH", "location": {}}
            for i in range(7)
        ]
        payload = _tfsec_json(results_list)
        findings = self.scanner._parse_tfsec_output(payload, IaCProvider.TERRAFORM, "t.tf")
        assert len(findings) == 7

    def test_end_line_in_metadata(self):
        result = {
            "rule_id": "some-rule",
            "severity": "MEDIUM",
            "location": {"start_line": 5, "end_line": 15},
        }
        payload = _tfsec_json([result])
        findings = self.scanner._parse_tfsec_output(payload, IaCProvider.TERRAFORM, "t.tf")
        assert findings[0].metadata["end_line"] == 15

    def test_description_falls_back_to_rule_description(self):
        result = {
            "rule_id": "some-rule",
            "severity": "HIGH",
            "rule_description": "From rule_description",
            "location": {},
        }
        payload = _tfsec_json([result])
        findings = self.scanner._parse_tfsec_output(payload, IaCProvider.TERRAFORM, "t.tf")
        assert findings[0].description == "From rule_description"

    def test_resolution_none_when_missing(self):
        result = {"rule_id": "r1", "severity": "HIGH", "location": {}}
        payload = _tfsec_json([result])
        findings = self.scanner._parse_tfsec_output(payload, IaCProvider.TERRAFORM, "t.tf")
        assert findings[0].remediation is None

    def test_unique_ids_generated(self):
        result = {"rule_id": "r1", "severity": "HIGH", "location": {}}
        payload = _tfsec_json([result])
        f1 = self.scanner._parse_tfsec_output(payload, IaCProvider.TERRAFORM, "t.tf")
        f2 = self.scanner._parse_tfsec_output(payload, IaCProvider.TERRAFORM, "t.tf")
        assert f1[0].id != f2[0].id

    def test_links_empty_list_when_missing(self):
        result = {"rule_id": "r1", "severity": "HIGH", "location": {}}
        payload = _tfsec_json([result])
        findings = self.scanner._parse_tfsec_output(payload, IaCProvider.TERRAFORM, "t.tf")
        assert findings[0].metadata["links"] == []

    def test_start_line_zero_default(self):
        result = {"rule_id": "r1", "severity": "HIGH", "location": {}}
        payload = _tfsec_json([result])
        findings = self.scanner._parse_tfsec_output(payload, IaCProvider.TERRAFORM, "t.tf")
        assert findings[0].line_number == 0


# ---------------------------------------------------------------------------
# IaCScanner.get_available_scanners
# ---------------------------------------------------------------------------

class TestGetAvailableScanners:
    def test_no_tools_available_returns_empty(self):
        scanner = _make_scanner(
            ScannerConfig(
                checkov_path="__no_such_checkov__",
                tfsec_path="__no_such_tfsec__",
            )
        )
        available = scanner.get_available_scanners()
        assert available == []

    def test_caches_checkov_availability(self):
        scanner = _make_scanner()
        # First call sets the cache
        scanner.get_available_scanners()
        cached = scanner._checkov_available
        # Second call should use cache (same value)
        scanner.get_available_scanners()
        assert scanner._checkov_available == cached

    def test_caches_tfsec_availability(self):
        scanner = _make_scanner()
        scanner.get_available_scanners()
        cached = scanner._tfsec_available
        scanner.get_available_scanners()
        assert scanner._tfsec_available == cached

    def test_returns_list_type(self):
        scanner = _make_scanner()
        result = scanner.get_available_scanners()
        assert isinstance(result, list)

    def test_scanner_type_values_in_list(self):
        scanner = _make_scanner()
        result = scanner.get_available_scanners()
        for item in result:
            assert isinstance(item, ScannerType)


# ---------------------------------------------------------------------------
# IaCScanner availability flags
# ---------------------------------------------------------------------------

class TestAvailabilityFlags:
    def test_initial_state_none(self):
        scanner = _make_scanner()
        assert scanner._checkov_available is None
        assert scanner._tfsec_available is None

    def test_after_check_not_none(self):
        scanner = _make_scanner()
        scanner._is_checkov_available()
        assert scanner._checkov_available is not None

    def test_bogus_path_not_available(self):
        scanner = _make_scanner(
            ScannerConfig(checkov_path="__no_such_tool__", tfsec_path="__no_such_tool__")
        )
        assert scanner._is_checkov_available() is False
        assert scanner._is_tfsec_available() is False

    def test_cached_after_first_call(self):
        scanner = _make_scanner(
            ScannerConfig(checkov_path="__no_such_tool__", tfsec_path="__no_such_tool__")
        )
        # First call
        r1 = scanner._is_checkov_available()
        # Should be cached now
        assert scanner._checkov_available is not None
        # Second call returns same value
        r2 = scanner._is_checkov_available()
        assert r1 == r2


# ---------------------------------------------------------------------------
# Singleton get_iac_scanner
# ---------------------------------------------------------------------------

class TestGetIacScannerSingleton:
    def test_returns_iac_scanner_instance(self):
        scanner = get_iac_scanner()
        assert isinstance(scanner, IaCScanner)

    def test_returns_same_instance_on_second_call(self):
        s1 = get_iac_scanner()
        s2 = get_iac_scanner()
        assert s1 is s2

    def test_singleton_has_config(self):
        scanner = get_iac_scanner()
        assert scanner.config is not None
        assert isinstance(scanner.config, ScannerConfig)

    def test_singleton_availability_flags_are_none_initially(self):
        # Reset the singleton to test initial state
        import core.iac_scanner as _mod
        original = _mod._default_scanner
        try:
            _mod._default_scanner = None
            scanner = get_iac_scanner()
            # A freshly-created scanner should have None availability flags
            assert scanner._checkov_available is None
            assert scanner._tfsec_available is None
        finally:
            _mod._default_scanner = original


# ---------------------------------------------------------------------------
# IaCProvider enum (from iac_models)
# ---------------------------------------------------------------------------

class TestIaCProviderEnum:
    def test_all_values(self):
        assert IaCProvider.TERRAFORM == "terraform"
        assert IaCProvider.CLOUDFORMATION == "cloudformation"
        assert IaCProvider.KUBERNETES == "kubernetes"
        assert IaCProvider.ANSIBLE == "ansible"
        assert IaCProvider.HELM == "helm"

    def test_member_count(self):
        assert len(list(IaCProvider)) == 5

    def test_is_str_subclass(self):
        assert isinstance(IaCProvider.TERRAFORM, str)

    def test_round_trip(self):
        for provider in IaCProvider:
            assert IaCProvider(provider.value) == provider

    def test_invalid_value_raises(self):
        with pytest.raises(ValueError):
            IaCProvider("docker")


# ---------------------------------------------------------------------------
# IaCFindingStatus enum (from iac_models)
# ---------------------------------------------------------------------------

class TestIaCFindingStatusEnum:
    def test_all_values(self):
        assert IaCFindingStatus.OPEN == "open"
        assert IaCFindingStatus.RESOLVED == "resolved"
        assert IaCFindingStatus.SUPPRESSED == "suppressed"

    def test_member_count(self):
        assert len(list(IaCFindingStatus)) == 3

    def test_round_trip(self):
        for status in IaCFindingStatus:
            assert IaCFindingStatus(status.value) == status

    def test_invalid_raises(self):
        with pytest.raises(ValueError):
            IaCFindingStatus("ignored")


# ---------------------------------------------------------------------------
# Cross-cutting / integration-style tests (deterministic, no I/O)
# ---------------------------------------------------------------------------

class TestCheckovParseIntegration:
    """Larger checkov payloads to verify end-to-end parsing logic."""

    def setup_method(self):
        self.scanner = _make_scanner()

    def test_kubernetes_provider_preserved_in_findings(self):
        check = {
            "check_id": "CKV_K8S_15",
            "check": {"name": "Image should use allowed registries"},
            "check_result": {"result": "FAILED"},
            "file_path": "pod.yaml",
            "file_line_range": [1, 20],
            "resource": "Pod",
            "resource_address": "Pod.default.nginx",
        }
        payload = _checkov_json([check])
        findings = self.scanner._parse_checkov_output(
            payload, IaCProvider.KUBERNETES, "pod.yaml"
        )
        assert findings[0].provider == IaCProvider.KUBERNETES

    def test_helm_provider_preserved(self):
        check = {
            "check_id": "CKV_HELM_1",
            "check": {"name": "Helm chart security check"},
            "check_result": {"result": "FAILED"},
            "file_path": "Chart.yaml",
            "file_line_range": [1, 5],
            "resource": "Chart",
            "resource_address": "Chart.my-app",
        }
        payload = _checkov_json([check])
        findings = self.scanner._parse_checkov_output(
            payload, IaCProvider.HELM, "Chart.yaml"
        )
        assert findings[0].provider == IaCProvider.HELM

    def test_ansible_provider_preserved(self):
        check = {
            "check_id": "CKV2_ANSIBLE_1",
            "check": {"name": "Ansible task check"},
            "check_result": {"result": "FAILED"},
            "file_path": "playbook.yml",
            "file_line_range": [10, 15],
            "resource": "task",
            "resource_address": "task.example_task",
        }
        payload = _checkov_json([check])
        findings = self.scanner._parse_checkov_output(
            payload, IaCProvider.ANSIBLE, "playbook.yml"
        )
        assert findings[0].provider == IaCProvider.ANSIBLE

    def test_large_payload_all_findings_returned(self):
        checks = [
            {
                "check_id": f"CKV_AWS_{i}",
                "check": {"name": f"Check {i}"},
                "check_result": {"result": "FAILED"},
                "file_path": "main.tf",
                "file_line_range": [i, i + 5],
                "resource": "aws_s3_bucket",
                "resource_address": f"aws_s3_bucket.bucket_{i}",
            }
            for i in range(20)
        ]
        payload = _checkov_json(checks)
        findings = self.scanner._parse_checkov_output(payload, IaCProvider.TERRAFORM, "main.tf")
        assert len(findings) == 20

    def test_all_findings_are_open_status(self):
        checks = [
            {"check_id": f"CKV_AWS_{i}", "check": {}, "check_result": {}}
            for i in range(5)
        ]
        payload = _checkov_json(checks)
        findings = self.scanner._parse_checkov_output(payload, IaCProvider.TERRAFORM, "t.tf")
        assert all(f.status == IaCFindingStatus.OPEN for f in findings)

    def test_rule_ids_match_check_ids(self):
        checks = [
            {"check_id": f"CKV_AWS_{i}", "check": {}, "check_result": {}}
            for i in range(3)
        ]
        payload = _checkov_json(checks)
        findings = self.scanner._parse_checkov_output(payload, IaCProvider.TERRAFORM, "t.tf")
        for i, f in enumerate(findings):
            assert f.rule_id == f"CKV_AWS_{i}"

    def test_description_from_check_name(self):
        check = {
            "check_id": "CKV_AWS_1",
            "check": {"name": "Ensure the S3 bucket has access logging enabled"},
            "check_result": {},
        }
        payload = _checkov_json([check])
        findings = self.scanner._parse_checkov_output(payload, IaCProvider.TERRAFORM, "t.tf")
        assert findings[0].description == "Ensure the S3 bucket has access logging enabled"

    def test_description_fallback_to_check_id_when_no_name(self):
        check = {
            "check_id": "CKV_AWS_55",
            "check": {},  # no "name"
            "check_result": {},
        }
        payload = _checkov_json([check])
        findings = self.scanner._parse_checkov_output(payload, IaCProvider.TERRAFORM, "t.tf")
        # description falls back to check.get("name", check_id)
        assert findings[0].description == "CKV_AWS_55"


class TestTfsecParseIntegration:
    """Larger tfsec payloads to verify end-to-end parsing logic."""

    def setup_method(self):
        self.scanner = _make_scanner()

    def test_all_findings_are_open_status(self):
        results_list = [
            {"rule_id": f"rule-{i}", "severity": "HIGH", "location": {}}
            for i in range(5)
        ]
        payload = _tfsec_json(results_list)
        findings = self.scanner._parse_tfsec_output(payload, IaCProvider.TERRAFORM, "t.tf")
        assert all(f.status == IaCFindingStatus.OPEN for f in findings)

    def test_provider_preserved_in_all_findings(self):
        results_list = [
            {"rule_id": f"r{i}", "severity": "MEDIUM", "location": {}}
            for i in range(3)
        ]
        payload = _tfsec_json(results_list)
        findings = self.scanner._parse_tfsec_output(payload, IaCProvider.TERRAFORM, "t.tf")
        assert all(f.provider == IaCProvider.TERRAFORM for f in findings)

    def test_mixed_severity_levels(self):
        results_list = [
            {"rule_id": "r1", "severity": "CRITICAL", "location": {}},
            {"rule_id": "r2", "severity": "HIGH", "location": {}},
            {"rule_id": "r3", "severity": "MEDIUM", "location": {}},
            {"rule_id": "r4", "severity": "LOW", "location": {}},
            {"rule_id": "r5", "severity": "INFO", "location": {}},
        ]
        payload = _tfsec_json(results_list)
        findings = self.scanner._parse_tfsec_output(payload, IaCProvider.TERRAFORM, "t.tf")
        severities = [f.severity for f in findings]
        assert severities == ["high", "high", "medium", "low", "low"]

    def test_rule_service_in_metadata(self):
        result = {
            "rule_id": "aws-s3-enable-versioning",
            "severity": "MEDIUM",
            "location": {},
            "rule_provider": "aws",
            "rule_service": "s3",
        }
        payload = _tfsec_json([result])
        findings = self.scanner._parse_tfsec_output(payload, IaCProvider.TERRAFORM, "t.tf")
        assert findings[0].metadata["rule_service"] == "s3"

    def test_large_tfsec_payload(self):
        results_list = [
            {
                "rule_id": f"aws-rule-{i}",
                "severity": "HIGH",
                "description": f"Rule {i} description",
                "resource": f"aws_resource_{i}",
                "location": {"filename": f"file_{i}.tf", "start_line": i * 10},
                "resolution": f"Fix rule {i}",
            }
            for i in range(15)
        ]
        payload = _tfsec_json(results_list)
        findings = self.scanner._parse_tfsec_output(payload, IaCProvider.TERRAFORM, "default.tf")
        assert len(findings) == 15
        # All rule_ids should match
        for i, f in enumerate(findings):
            assert f.rule_id == f"aws-rule-{i}"


# ---------------------------------------------------------------------------
# ScanResult.to_dict — findings serialisation
# ---------------------------------------------------------------------------

class TestScanResultFindingsSerialisation:
    def test_findings_serialised_via_to_dict(self):
        f = _make_finding(severity="high")
        result = ScanResult(
            scan_id="s1",
            status=ScanStatus.COMPLETED,
            scanner=ScannerType.CHECKOV,
            provider=IaCProvider.TERRAFORM,
            target_path="main.tf",
            findings=[f],
        )
        d = result.to_dict()
        assert len(d["findings"]) == 1
        finding_dict = d["findings"][0]
        assert finding_dict["severity"] == "high"
        assert finding_dict["rule_id"] == "CKV_AWS_1"

    def test_raw_output_not_in_to_dict(self):
        result = ScanResult(
            scan_id="s1",
            status=ScanStatus.COMPLETED,
            scanner=ScannerType.CHECKOV,
            provider=IaCProvider.TERRAFORM,
            target_path="t.tf",
            raw_output="some raw output",
        )
        d = result.to_dict()
        # raw_output is intentionally not in to_dict
        assert "raw_output" not in d

    def test_multiple_findings_all_serialised(self):
        findings = [_make_finding(rule_id=f"CKV_{i}") for i in range(10)]
        result = ScanResult(
            scan_id="s2",
            status=ScanStatus.COMPLETED,
            scanner=ScannerType.CHECKOV,
            provider=IaCProvider.TERRAFORM,
            target_path="t.tf",
            findings=findings,
        )
        d = result.to_dict()
        assert d["findings_count"] == 10
        assert len(d["findings"]) == 10

    def test_all_scan_statuses_serialise_correctly(self):
        for status in ScanStatus:
            result = ScanResult(
                scan_id="x",
                status=status,
                scanner=ScannerType.CHECKOV,
                provider=IaCProvider.TERRAFORM,
                target_path="t.tf",
            )
            d = result.to_dict()
            assert d["status"] == status.value

    def test_all_providers_serialise_correctly(self):
        for provider in IaCProvider:
            result = ScanResult(
                scan_id="x",
                status=ScanStatus.COMPLETED,
                scanner=ScannerType.CHECKOV,
                provider=provider,
                target_path="t.tf",
            )
            d = result.to_dict()
            assert d["provider"] == provider.value


# ---------------------------------------------------------------------------
# ScannerConfig field mutation independence
# ---------------------------------------------------------------------------

class TestScannerConfigIsolation:
    def test_two_instances_excluded_checks_independent(self):
        cfg1 = ScannerConfig(excluded_checks=["A"])
        cfg2 = ScannerConfig(excluded_checks=["B"])
        assert cfg1.excluded_checks == ["A"]
        assert cfg2.excluded_checks == ["B"]

    def test_default_instances_excluded_checks_independent(self):
        cfg1 = ScannerConfig()
        cfg2 = ScannerConfig()
        cfg1.excluded_checks.append("X")
        assert cfg2.excluded_checks == []


# ---------------------------------------------------------------------------
# Edge cases for severity mapping
# ---------------------------------------------------------------------------

class TestMapSeverityEdgeCases:
    def setup_method(self):
        self.scanner = _make_scanner()

    def test_whitespace_around_severity(self):
        # The method does .lower() only; leading whitespace keeps it unknown -> medium
        result = self.scanner._map_severity("  high  ")
        assert result == "medium"  # no strip, so spaces make it fall through to default

    def test_numeric_severity_defaults_to_medium(self):
        assert self.scanner._map_severity("1") == "medium"
        assert self.scanner._map_severity("3") == "medium"

    def test_none_like_string(self):
        assert self.scanner._map_severity("none") == "medium"

    def test_warning_severity_defaults_to_medium(self):
        assert self.scanner._map_severity("warning") == "medium"

    def test_error_severity_defaults_to_medium(self):
        assert self.scanner._map_severity("error") == "medium"

    def test_notice_severity_defaults_to_medium(self):
        assert self.scanner._map_severity("notice") == "medium"
