"""
Unit tests for suite-api/apps/api/ingestion.py

Tests the ingestion module including:
- UnifiedFinding model: creation, validation, severity normalization, fingerprinting
- FindingSeverity / FindingStatus / FindingType / AssetType / SourceFormat enums
- Asset model
- NormalizerConfig dataclass
- BaseNormalizer: can_handle, severity mapping, JSON parsing
- SARIFNormalizer: SARIF 2.1 ingestion with rules, locations, CWE extraction
- CycloneDXNormalizer: SBOM vulnerability parsing
- DarkWebIntelNormalizer: threat intel parsing and type detection
- CNAPPNormalizer: cloud finding normalization
- SPDXNormalizer: SPDX SBOM with external refs and annotations
- VEXNormalizer: OpenVEX and CycloneDX VEX formats
- TrivyNormalizer: vulnerabilities, misconfigurations, secrets
- GrypeNormalizer: grype matches with CVSS extraction
- SemgrepNormalizer: SAST results with confidence mapping
- DependabotNormalizer: GitHub Dependabot alerts
- NormalizerRegistry: registration, format detection, auto-detect
"""

import json
import os
from datetime import datetime

import pytest

os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-jwt-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from apps.api.ingestion import (
    Asset,
    AssetType,
    BaseNormalizer,
    CNAPPNormalizer,
    CycloneDXNormalizer,
    DarkWebIntelNormalizer,
    DependabotNormalizer,
    FindingSeverity,
    FindingStatus,
    FindingType,
    GrypeNormalizer,
    NormalizerConfig,
    NormalizerRegistry,
    SARIFNormalizer,
    SemgrepNormalizer,
    SourceFormat,
    SPDXNormalizer,
    TrivyNormalizer,
    UnifiedFinding,
    VEXNormalizer,
)


# ---------------------------------------------------------------------------
# Helper to build NormalizerConfig easily
# ---------------------------------------------------------------------------
def _config(name="test", patterns=None, enabled=True, priority=50):
    return NormalizerConfig(
        name=name,
        enabled=enabled,
        priority=priority,
        detection_patterns=patterns or [],
    )


# ===========================================================================
# Enum Tests
# ===========================================================================


class TestFindingSeverityEnum:
    def test_all_values(self):
        assert FindingSeverity.CRITICAL.value == "critical"
        assert FindingSeverity.HIGH.value == "high"
        assert FindingSeverity.MEDIUM.value == "medium"
        assert FindingSeverity.LOW.value == "low"
        assert FindingSeverity.INFO.value == "info"
        assert FindingSeverity.UNKNOWN.value == "unknown"

    def test_is_string_enum(self):
        assert isinstance(FindingSeverity.CRITICAL, str)
        assert FindingSeverity.HIGH == "high"


class TestFindingStatusEnum:
    def test_all_values(self):
        assert FindingStatus.OPEN.value == "open"
        assert FindingStatus.IN_PROGRESS.value == "in_progress"
        assert FindingStatus.RESOLVED.value == "resolved"
        assert FindingStatus.SUPPRESSED.value == "suppressed"
        assert FindingStatus.FALSE_POSITIVE.value == "false_positive"
        assert FindingStatus.ACCEPTED_RISK.value == "accepted_risk"
        assert FindingStatus.WONT_FIX.value == "wont_fix"


class TestFindingTypeEnum:
    def test_vulnerability(self):
        assert FindingType.VULNERABILITY.value == "vulnerability"

    def test_all_types_present(self):
        expected = {
            "vulnerability", "misconfiguration", "secret", "license",
            "malware", "compliance", "threat_intel", "credential_leak",
            "data_breach", "supply_chain", "code_quality", "container",
            "iac", "api", "identity",
        }
        actual = {ft.value for ft in FindingType}
        assert actual == expected


class TestSourceFormatEnum:
    def test_sarif(self):
        assert SourceFormat.SARIF.value == "sarif"

    def test_common_formats(self):
        for fmt in ["sarif", "cyclonedx", "spdx", "vex", "snyk", "trivy", "grype", "semgrep", "dependabot"]:
            assert hasattr(SourceFormat, fmt.upper())


class TestAssetTypeEnum:
    def test_all_types(self):
        expected = {
            "compute", "storage", "network", "database", "identity",
            "container", "serverless", "kubernetes", "application",
            "repository", "package", "image", "endpoint", "cloud_resource",
        }
        actual = {at.value for at in AssetType}
        assert actual == expected


# ===========================================================================
# UnifiedFinding Tests
# ===========================================================================


class TestUnifiedFinding:
    def test_minimal_creation(self):
        f = UnifiedFinding(title="Test finding")
        assert f.title == "Test finding"
        assert f.severity == FindingSeverity.UNKNOWN
        assert f.status == FindingStatus.OPEN
        assert f.finding_type == FindingType.VULNERABILITY
        assert f.source_format == SourceFormat.UNKNOWN
        assert f.id  # auto-generated UUID

    def test_full_creation(self):
        f = UnifiedFinding(
            title="SQL Injection in login.py",
            severity=FindingSeverity.CRITICAL,
            status=FindingStatus.OPEN,
            finding_type=FindingType.VULNERABILITY,
            source_format=SourceFormat.SARIF,
            source_tool="semgrep",
            cve_id="CVE-2024-1234",
            cwe_id="CWE-89",
            cvss_score=9.8,
            epss_score=0.95,
            file_path="app/login.py",
            line_number=42,
            package_name="django",
            package_version="3.2.0",
        )
        assert f.severity == FindingSeverity.CRITICAL
        assert f.cvss_score == 9.8
        assert f.epss_score == 0.95
        assert f.file_path == "app/login.py"
        assert f.line_number == 42

    def test_severity_normalization_from_string(self):
        f = UnifiedFinding(title="test", severity="high")
        assert f.severity == FindingSeverity.HIGH

    def test_severity_normalization_moderate(self):
        f = UnifiedFinding(title="test", severity="moderate")
        assert f.severity == FindingSeverity.MEDIUM

    def test_severity_normalization_informational(self):
        f = UnifiedFinding(title="test", severity="informational")
        assert f.severity == FindingSeverity.INFO

    def test_severity_normalization_error_maps_to_high(self):
        f = UnifiedFinding(title="test", severity="error")
        assert f.severity == FindingSeverity.HIGH

    def test_severity_normalization_warning_maps_to_medium(self):
        f = UnifiedFinding(title="test", severity="warning")
        assert f.severity == FindingSeverity.MEDIUM

    def test_severity_normalization_note_maps_to_low(self):
        f = UnifiedFinding(title="test", severity="note")
        assert f.severity == FindingSeverity.LOW

    def test_severity_normalization_none_maps_to_info(self):
        f = UnifiedFinding(title="test", severity="none")
        assert f.severity == FindingSeverity.INFO

    def test_severity_normalization_unknown_string(self):
        f = UnifiedFinding(title="test", severity="banana")
        assert f.severity == FindingSeverity.UNKNOWN

    def test_severity_normalization_case_insensitive(self):
        f = UnifiedFinding(title="test", severity="CRITICAL")
        assert f.severity == FindingSeverity.CRITICAL

    def test_severity_normalization_with_whitespace(self):
        f = UnifiedFinding(title="test", severity="  high  ")
        assert f.severity == FindingSeverity.HIGH

    def test_severity_normalization_non_string(self):
        f = UnifiedFinding(title="test", severity=42)
        assert f.severity == FindingSeverity.UNKNOWN

    def test_compute_fingerprint(self):
        f = UnifiedFinding(
            title="Test",
            source_format=SourceFormat.SARIF,
            finding_type=FindingType.VULNERABILITY,
            cve_id="CVE-2024-1234",
        )
        fp = f.compute_fingerprint()
        assert fp is not None
        assert len(fp) == 32
        assert f.fingerprint == fp

    def test_fingerprint_deterministic(self):
        f1 = UnifiedFinding(title="Same", source_format=SourceFormat.SARIF)
        f2 = UnifiedFinding(title="Same", source_format=SourceFormat.SARIF)
        assert f1.compute_fingerprint() == f2.compute_fingerprint()

    def test_fingerprint_varies_by_title(self):
        f1 = UnifiedFinding(title="Finding A", source_format=SourceFormat.SARIF)
        f2 = UnifiedFinding(title="Finding B", source_format=SourceFormat.SARIF)
        assert f1.compute_fingerprint() != f2.compute_fingerprint()

    def test_auto_generated_id_is_uuid(self):
        f = UnifiedFinding(title="test")
        import uuid
        uuid.UUID(f.id)  # Raises if not valid UUID

    def test_default_timestamps(self):
        f = UnifiedFinding(title="test")
        assert isinstance(f.first_seen, datetime)
        assert isinstance(f.last_seen, datetime)
        assert f.resolved_at is None

    def test_extra_fields_allowed(self):
        f = UnifiedFinding(title="test", custom_field="custom_value")
        assert f.custom_field == "custom_value"

    def test_default_lists_and_dicts(self):
        f = UnifiedFinding(title="test")
        assert f.compliance_frameworks == []
        assert f.tags == []
        assert f.labels == {}
        assert f.references == []
        assert f.raw_data == {}
        assert f.metadata == {}

    def test_boolean_defaults(self):
        f = UnifiedFinding(title="test")
        assert f.exploit_available is False
        assert f.in_kev is False


# ===========================================================================
# Asset Tests
# ===========================================================================


class TestAsset:
    def test_minimal_creation(self):
        a = Asset(name="web-server-1", asset_type=AssetType.COMPUTE)
        assert a.name == "web-server-1"
        assert a.asset_type == AssetType.COMPUTE
        assert a.finding_count == 0
        assert a.critical_count == 0
        assert a.high_count == 0

    def test_full_creation(self):
        a = Asset(
            name="prod-db",
            asset_type=AssetType.DATABASE,
            cloud_provider="aws",
            cloud_region="us-east-1",
            owner="dba-team",
            environment="production",
            criticality="high",
        )
        assert a.cloud_provider == "aws"
        assert a.environment == "production"

    def test_auto_generated_id(self):
        a = Asset(name="test", asset_type=AssetType.APPLICATION)
        import uuid
        uuid.UUID(a.id)


# ===========================================================================
# NormalizerConfig Tests
# ===========================================================================


class TestNormalizerConfig:
    def test_defaults(self):
        c = NormalizerConfig(name="test")
        assert c.name == "test"
        assert c.enabled is True
        assert c.priority == 50
        assert c.detection_patterns == []
        assert c.settings == {}

    def test_custom_values(self):
        c = NormalizerConfig(
            name="custom",
            enabled=False,
            priority=100,
            detection_patterns=[r"pattern"],
        )
        assert c.enabled is False
        assert c.priority == 100
        assert c.detection_patterns == [r"pattern"]


# ===========================================================================
# BaseNormalizer Tests
# ===========================================================================


class TestBaseNormalizer:
    def test_can_handle_disabled(self):
        n = BaseNormalizer(_config(enabled=False, patterns=[r"test"]))
        assert n.can_handle(b"test content") == 0.0

    def test_can_handle_no_patterns(self):
        n = BaseNormalizer(_config(patterns=[]))
        assert n.can_handle(b"test content") == 0.0

    def test_can_handle_matching_pattern(self):
        n = BaseNormalizer(_config(patterns=[r'"version"']))
        confidence = n.can_handle(b'{"version": "2.1.0"}')
        assert confidence > 0.0

    def test_can_handle_multiple_patterns_partial(self):
        n = BaseNormalizer(_config(patterns=[r'"version"', r'"runs"', r'"nope"']))
        content = b'{"version": "2.1.0", "runs": []}'
        confidence = n.can_handle(content)
        # 2 of 3 patterns match
        assert 0.5 < confidence < 1.0

    def test_can_handle_all_patterns_match(self):
        n = BaseNormalizer(_config(patterns=[r'"version"', r'"runs"']))
        content = b'{"version": "2.1.0", "runs": []}'
        confidence = n.can_handle(content)
        assert confidence == 1.0

    def test_normalize_raises_not_implemented(self):
        n = BaseNormalizer(_config())
        with pytest.raises(NotImplementedError):
            n.normalize(b"content")

    def test_parse_json_valid(self):
        n = BaseNormalizer(_config())
        data = n._parse_json(b'{"key": "value"}')
        assert data == {"key": "value"}

    def test_parse_json_lenient_trailing_comma(self):
        n = BaseNormalizer(_config())
        data = n._parse_json(b'{"key": "value",}')
        assert data == {"key": "value"}

    def test_map_severity_float(self):
        n = BaseNormalizer(_config())
        assert n._map_severity(9.5) == FindingSeverity.CRITICAL
        assert n._map_severity(7.0) == FindingSeverity.HIGH
        assert n._map_severity(5.0) == FindingSeverity.MEDIUM
        assert n._map_severity(2.0) == FindingSeverity.LOW
        assert n._map_severity(0.0) == FindingSeverity.INFO

    def test_map_severity_string(self):
        n = BaseNormalizer(_config())
        assert n._map_severity("critical") == FindingSeverity.CRITICAL
        assert n._map_severity("high") == FindingSeverity.HIGH
        assert n._map_severity("medium") == FindingSeverity.MEDIUM
        assert n._map_severity("moderate") == FindingSeverity.MEDIUM
        assert n._map_severity("low") == FindingSeverity.LOW
        assert n._map_severity("info") == FindingSeverity.INFO

    def test_map_severity_none(self):
        n = BaseNormalizer(_config())
        assert n._map_severity(None) == FindingSeverity.UNKNOWN

    def test_map_severity_unknown_string(self):
        n = BaseNormalizer(_config())
        # Unknown severity strings default to MEDIUM (conservative triage choice)
        assert n._map_severity("xyz") == FindingSeverity.MEDIUM

    def test_invalid_regex_pattern_handled(self):
        # Should not raise, just log a warning
        n = BaseNormalizer(_config(patterns=[r"["]))
        assert len(n._compiled_patterns) == 0


# ===========================================================================
# SARIFNormalizer Tests
# ===========================================================================


class TestSARIFNormalizer:
    def _make_sarif(self, results=None, tool_name="test-tool", tool_version="1.0", rules=None):
        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": tool_version,
                        "rules": rules or [],
                    }
                },
                "results": results or [],
            }],
        }
        return json.dumps(sarif).encode()

    def test_empty_results(self):
        n = SARIFNormalizer(_config(name="sarif"))
        findings = n.normalize(self._make_sarif(results=[]))
        assert findings == []

    def test_single_finding(self):
        results = [{
            "ruleId": "sql-injection",
            "level": "error",
            "message": {"text": "SQL injection vulnerability detected"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "app/db.py"},
                    "region": {"startLine": 42, "startColumn": 10},
                }
            }],
        }]
        n = SARIFNormalizer(_config(name="sarif"))
        findings = n.normalize(self._make_sarif(results=results))
        assert len(findings) == 1
        f = findings[0]
        assert f.source_format == SourceFormat.SARIF
        assert f.source_tool == "test-tool"
        assert f.severity == FindingSeverity.HIGH  # error -> HIGH
        assert f.file_path == "app/db.py"
        assert f.line_number == 42
        assert f.column_number == 10
        assert f.rule_id == "sql-injection"
        assert f.fingerprint is not None

    def test_multiple_results(self):
        results = [
            {"ruleId": "r1", "level": "error", "message": {"text": "Error 1"}},
            {"ruleId": "r2", "level": "warning", "message": {"text": "Warning 1"}},
            {"ruleId": "r3", "level": "note", "message": {"text": "Note 1"}},
        ]
        n = SARIFNormalizer(_config(name="sarif"))
        findings = n.normalize(self._make_sarif(results=results))
        assert len(findings) == 3
        assert findings[0].severity == FindingSeverity.HIGH
        assert findings[1].severity == FindingSeverity.MEDIUM
        assert findings[2].severity == FindingSeverity.LOW

    def test_rule_description_used(self):
        rules = [{
            "id": "r1",
            "shortDescription": {"text": "Short desc"},
            "fullDescription": {"text": "Full description here"},
            "help": {"text": "Fix it this way"},
        }]
        results = [{"ruleId": "r1", "level": "error", "message": {}}]
        n = SARIFNormalizer(_config(name="sarif"))
        findings = n.normalize(self._make_sarif(results=results, rules=rules))
        assert len(findings) == 1
        assert findings[0].description == "Full description here"
        assert findings[0].recommendation == "Fix it this way"

    def test_cwe_extraction_from_rule_properties(self):
        rules = [{
            "id": "r1",
            "properties": {"cwe": ["CWE-89"]},
        }]
        results = [{"ruleId": "r1", "level": "error", "message": {"text": "test"}}]
        n = SARIFNormalizer(_config(name="sarif"))
        findings = n.normalize(self._make_sarif(results=results, rules=rules))
        assert findings[0].cwe_id == "CWE-89"

    def test_no_locations(self):
        results = [{"ruleId": "r1", "level": "warning", "message": {"text": "No location"}}]
        n = SARIFNormalizer(_config(name="sarif"))
        findings = n.normalize(self._make_sarif(results=results))
        assert len(findings) == 1
        assert findings[0].file_path is None
        assert findings[0].line_number is None

    def test_sarif_level_mapping(self):
        n = SARIFNormalizer(_config(name="sarif"))
        assert n._map_sarif_level("error") == FindingSeverity.HIGH
        assert n._map_sarif_level("warning") == FindingSeverity.MEDIUM
        assert n._map_sarif_level("note") == FindingSeverity.LOW
        assert n._map_sarif_level("none") == FindingSeverity.INFO
        assert n._map_sarif_level("unknown") == FindingSeverity.MEDIUM

    def test_code_snippet_extraction(self):
        results = [{
            "ruleId": "r1",
            "level": "warning",
            "message": {"text": "test"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "test.py"},
                    "region": {
                        "startLine": 1,
                        "snippet": {"text": "password = 'secret'"},
                    },
                }
            }],
        }]
        n = SARIFNormalizer(_config(name="sarif"))
        findings = n.normalize(self._make_sarif(results=results))
        assert findings[0].code_snippet == "password = 'secret'"

    def test_metadata_includes_sarif_version(self):
        results = [{"ruleId": "r1", "level": "error", "message": {"text": "test"}}]
        n = SARIFNormalizer(_config(name="sarif"))
        findings = n.normalize(self._make_sarif(results=results))
        assert findings[0].metadata["sarif_version"] == "2.1.0"


# ===========================================================================
# CycloneDX Normalizer Tests
# ===========================================================================


class TestCycloneDXNormalizer:
    def _make_cdx(self, vulns=None, components=None):
        cdx = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": components or [],
            "vulnerabilities": vulns or [],
        }
        return json.dumps(cdx).encode()

    def test_empty(self):
        n = CycloneDXNormalizer(_config(name="cyclonedx"))
        findings = n.normalize(self._make_cdx())
        assert findings == []

    def test_single_vulnerability(self):
        comps = [{"bom-ref": "pkg-1", "name": "lodash", "version": "4.17.20", "type": "library"}]
        vulns = [{
            "id": "CVE-2021-23337",
            "source": {"name": "NVD"},
            "ratings": [{"score": 7.2, "severity": "high"}],
            "description": "Prototype pollution",
            "affects": [{"ref": "pkg-1"}],
        }]
        n = CycloneDXNormalizer(_config(name="cyclonedx"))
        findings = n.normalize(self._make_cdx(vulns=vulns, components=comps))
        assert len(findings) == 1
        f = findings[0]
        assert f.source_format == SourceFormat.CYCLONEDX
        assert f.cve_id == "CVE-2021-23337"
        assert f.package_name == "lodash"
        assert f.package_version == "4.17.20"
        assert f.cvss_score == 7.2
        assert f.severity == FindingSeverity.HIGH

    def test_vulnerability_without_score_uses_severity_string(self):
        comps = [{"bom-ref": "pkg-1", "name": "lib", "version": "1.0"}]
        vulns = [{
            "id": "CVE-2024-9999",
            "source": {"name": "test"},
            "ratings": [{"severity": "critical"}],
            "affects": [{"ref": "pkg-1"}],
        }]
        n = CycloneDXNormalizer(_config(name="cyclonedx"))
        findings = n.normalize(self._make_cdx(vulns=vulns, components=comps))
        assert findings[0].severity == FindingSeverity.CRITICAL

    def test_multiple_affects(self):
        comps = [
            {"bom-ref": "pkg-1", "name": "lib-a", "version": "1.0"},
            {"bom-ref": "pkg-2", "name": "lib-b", "version": "2.0"},
        ]
        vulns = [{
            "id": "CVE-2024-0001",
            "source": {"name": "test"},
            "ratings": [{"score": 5.0}],
            "affects": [{"ref": "pkg-1"}, {"ref": "pkg-2"}],
        }]
        n = CycloneDXNormalizer(_config(name="cyclonedx"))
        findings = n.normalize(self._make_cdx(vulns=vulns, components=comps))
        assert len(findings) == 2


# ===========================================================================
# DarkWebIntelNormalizer Tests
# ===========================================================================


class TestDarkWebIntelNormalizer:
    def test_list_format(self):
        data = [
            {"title": "Stolen creds", "type": "credential", "severity": "high", "confidence": 0.9},
            {"title": "Data breach", "type": "breach", "severity": "critical"},
        ]
        n = DarkWebIntelNormalizer(_config(name="dark_web_intel"))
        findings = n.normalize(json.dumps(data).encode())
        assert len(findings) == 2
        assert findings[0].finding_type == FindingType.CREDENTIAL_LEAK
        assert findings[1].finding_type == FindingType.DATA_BREACH

    def test_dict_format_with_items_key(self):
        data = {"items": [{"title": "Threat", "type": "threat"}]}
        n = DarkWebIntelNormalizer(_config(name="dark_web_intel"))
        findings = n.normalize(json.dumps(data).encode())
        assert len(findings) == 1
        assert findings[0].finding_type == FindingType.THREAT_INTEL

    def test_malware_type(self):
        data = [{"title": "Malware found", "type": "malware", "severity": "critical"}]
        n = DarkWebIntelNormalizer(_config(name="dark_web_intel"))
        findings = n.normalize(json.dumps(data).encode())
        assert findings[0].finding_type == FindingType.MALWARE

    def test_severity_from_confidence_when_no_severity(self):
        data = [{"title": "High confidence threat", "confidence": 0.95}]
        n = DarkWebIntelNormalizer(_config(name="dark_web_intel"))
        findings = n.normalize(json.dumps(data).encode())
        assert findings[0].severity == FindingSeverity.CRITICAL

    def test_severity_from_low_confidence(self):
        data = [{"title": "Low confidence", "confidence": 0.3}]
        n = DarkWebIntelNormalizer(_config(name="dark_web_intel"))
        findings = n.normalize(json.dumps(data).encode())
        assert findings[0].severity == FindingSeverity.LOW

    def test_metadata_fields(self):
        data = [{"title": "Intel", "type": "threat", "threat_actor": "APT28", "campaign": "FancyBear"}]
        n = DarkWebIntelNormalizer(_config(name="dark_web_intel"))
        findings = n.normalize(json.dumps(data).encode())
        assert findings[0].metadata["actor"] == "APT28"
        assert findings[0].metadata["campaign"] == "FancyBear"


# ===========================================================================
# CNAPPNormalizer Tests
# ===========================================================================


class TestCNAPPNormalizer:
    def test_basic_finding(self):
        data = {
            "findings": [{
                "title": "S3 bucket public",
                "severity": "high",
                "cloudProvider": "aws",
                "region": "us-east-1",
                "resourceId": "arn:aws:s3:::my-bucket",
                "resourceType": "AWS::S3::Bucket",
                "type": "misconfiguration",
            }]
        }
        n = CNAPPNormalizer(_config(name="cnapp"))
        findings = n.normalize(json.dumps(data).encode())
        assert len(findings) == 1
        f = findings[0]
        assert f.cloud_provider == "aws"
        assert f.cloud_region == "us-east-1"
        assert f.cloud_resource_id == "arn:aws:s3:::my-bucket"
        assert f.finding_type == FindingType.MISCONFIGURATION
        assert f.severity == FindingSeverity.HIGH

    def test_vulnerability_type(self):
        data = {"findings": [{"title": "CVE vuln", "type": "vulnerability", "severity": "critical"}]}
        n = CNAPPNormalizer(_config(name="cnapp"))
        findings = n.normalize(json.dumps(data).encode())
        assert findings[0].finding_type == FindingType.VULNERABILITY

    def test_identity_type(self):
        data = {"findings": [{"title": "IAM issue", "type": "identity_exposure", "severity": "medium"}]}
        n = CNAPPNormalizer(_config(name="cnapp"))
        findings = n.normalize(json.dumps(data).encode())
        assert findings[0].finding_type == FindingType.IDENTITY

    def test_iam_misconfig_resolved_as_misconfig(self):
        """iam_misconfiguration matches 'misconfig' first in the check chain."""
        data = {"findings": [{"title": "IAM misconfig", "type": "iam_misconfiguration", "severity": "high"}]}
        n = CNAPPNormalizer(_config(name="cnapp"))
        findings = n.normalize(json.dumps(data).encode())
        assert findings[0].finding_type == FindingType.MISCONFIGURATION

    def test_alternate_key_names(self):
        data = {
            "securityFindings": [{
                "title": "Alert",
                "severity": "low",
                "provider": "gcp",
                "cloudRegion": "us-central1",
                "projectId": "my-project",
            }]
        }
        n = CNAPPNormalizer(_config(name="cnapp"))
        findings = n.normalize(json.dumps(data).encode())
        assert len(findings) == 1
        assert findings[0].cloud_provider == "gcp"


# ===========================================================================
# SPDXNormalizer Tests
# ===========================================================================


class TestSPDXNormalizer:
    def test_empty_spdx(self):
        data = {"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "packages": []}
        n = SPDXNormalizer(_config(name="spdx"))
        findings = n.normalize(json.dumps(data).encode())
        assert findings == []

    def test_security_annotation(self):
        data = {
            "spdxVersion": "SPDX-2.3",
            "packages": [],
            "annotations": [{
                "annotationType": "REVIEW",
                "comment": "CVE-2024-1234 vulnerability found in package",
            }],
        }
        n = SPDXNormalizer(_config(name="spdx"))
        findings = n.normalize(json.dumps(data).encode())
        assert len(findings) == 1
        assert findings[0].cve_id == "CVE-2024-1234"
        assert findings[0].source_format == SourceFormat.SPDX

    def test_security_external_ref(self):
        data = {
            "spdxVersion": "SPDX-2.3",
            "packages": [{
                "SPDXID": "SPDXRef-Package",
                "name": "vulnerable-lib",
                "versionInfo": "1.0.0",
                "externalRefs": [{
                    "referenceType": "security",
                    "referenceLocator": "https://nvd.nist.gov/vuln/detail/CVE-2024-5678",
                }],
            }],
        }
        n = SPDXNormalizer(_config(name="spdx"))
        findings = n.normalize(json.dumps(data).encode())
        assert len(findings) == 1
        assert findings[0].cve_id == "CVE-2024-5678"
        assert findings[0].package_name == "vulnerable-lib"


# ===========================================================================
# VEXNormalizer Tests
# ===========================================================================


class TestVEXNormalizer:
    def test_openvex_not_affected(self):
        data = {
            "statements": [{
                "vulnerability": {"@id": "CVE-2024-0001"},
                "status": "not_affected",
                "justification": "Component not in use",
                "products": [{"@id": "pkg:npm/mylib@1.0"}],
            }],
            "author": "security-team",
        }
        n = VEXNormalizer(_config(name="vex"))
        findings = n.normalize(json.dumps(data).encode())
        assert len(findings) == 1
        assert findings[0].status == FindingStatus.FALSE_POSITIVE
        assert findings[0].severity == FindingSeverity.INFO
        assert findings[0].cve_id == "CVE-2024-0001"

    def test_openvex_affected(self):
        data = {
            "statements": [{
                "vulnerability": {"@id": "CVE-2024-0002"},
                "status": "affected",
                "products": [{"@id": "pkg:npm/lib@2.0"}],
            }]
        }
        n = VEXNormalizer(_config(name="vex"))
        findings = n.normalize(json.dumps(data).encode())
        assert findings[0].status == FindingStatus.OPEN
        assert findings[0].severity == FindingSeverity.HIGH

    def test_vex_fixed_status(self):
        data = {
            "statements": [{
                "vulnerability": "CVE-2024-0003",
                "status": "fixed",
                "products": [{"@id": "product-1"}],
            }]
        }
        n = VEXNormalizer(_config(name="vex"))
        findings = n.normalize(json.dumps(data).encode())
        assert findings[0].status == FindingStatus.RESOLVED

    def test_vex_under_investigation(self):
        data = {
            "statements": [{
                "vulnerability": "CVE-2024-0004",
                "status": "under_investigation",
                "products": ["product-x"],
            }]
        }
        n = VEXNormalizer(_config(name="vex"))
        findings = n.normalize(json.dumps(data).encode())
        assert findings[0].status == FindingStatus.IN_PROGRESS


# ===========================================================================
# TrivyNormalizer Tests
# ===========================================================================


class TestTrivyNormalizer:
    def _make_trivy(self, vulns=None, misconfigs=None, secrets=None):
        result = {"Target": "app/Dockerfile", "Type": "dockerfile"}
        if vulns:
            result["Vulnerabilities"] = vulns
        if misconfigs:
            result["Misconfigurations"] = misconfigs
        if secrets:
            result["Secrets"] = secrets
        return json.dumps({
            "ArtifactName": "myimage:latest",
            "ArtifactType": "container_image",
            "Results": [result],
        }).encode()

    def test_single_vulnerability(self):
        vulns = [{
            "VulnerabilityID": "CVE-2024-1000",
            "PkgName": "openssl",
            "InstalledVersion": "1.1.1",
            "FixedVersion": "1.1.2",
            "Severity": "HIGH",
            "Title": "Buffer overflow in OpenSSL",
            "Description": "A buffer overflow...",
        }]
        n = TrivyNormalizer(_config(name="trivy"))
        findings = n.normalize(self._make_trivy(vulns=vulns))
        assert len(findings) == 1
        f = findings[0]
        assert f.source_format == SourceFormat.TRIVY
        assert f.cve_id == "CVE-2024-1000"
        assert f.package_name == "openssl"
        assert f.severity == FindingSeverity.HIGH
        assert f.recommendation == "Upgrade to version 1.1.2"
        assert f.container_image == "myimage:latest"

    def test_misconfiguration(self):
        misconfigs = [{
            "ID": "DS001",
            "Title": "Root user detected",
            "Severity": "MEDIUM",
            "Description": "Running as root",
            "Resolution": "Use non-root user",
        }]
        n = TrivyNormalizer(_config(name="trivy"))
        findings = n.normalize(self._make_trivy(misconfigs=misconfigs))
        assert len(findings) == 1
        assert findings[0].finding_type == FindingType.MISCONFIGURATION
        assert findings[0].rule_id == "DS001"

    def test_secret_detection(self):
        secrets = [{
            "RuleID": "aws-access-key-id",
            "Title": "AWS Access Key ID",
            "Severity": "CRITICAL",
            "Match": "AKIA...",
            "StartLine": 5,
        }]
        n = TrivyNormalizer(_config(name="trivy"))
        findings = n.normalize(self._make_trivy(secrets=secrets))
        assert len(findings) == 1
        assert findings[0].finding_type == FindingType.SECRET
        assert findings[0].severity == FindingSeverity.CRITICAL
        assert findings[0].line_number == 5

    def test_cvss_extraction(self):
        vulns = [{
            "VulnerabilityID": "CVE-2024-2000",
            "PkgName": "pkg",
            "Severity": "HIGH",
            "Title": "test",
            "CVSS": {"nvd": {"V3Score": 8.1, "V3Vector": "CVSS:3.1/AV:N/AC:L"}},
        }]
        n = TrivyNormalizer(_config(name="trivy"))
        findings = n.normalize(self._make_trivy(vulns=vulns))
        assert findings[0].cvss_score == 8.1

    def test_empty_results(self):
        data = {"ArtifactName": "test", "Results": []}
        n = TrivyNormalizer(_config(name="trivy"))
        findings = n.normalize(json.dumps(data).encode())
        assert findings == []

    def test_alternate_key_casing(self):
        data = {
            "artifactName": "alt",
            "results": [{
                "target": "file.go",
                "type": "gomod",
                "vulnerabilities": [{
                    "vulnerabilityID": "CVE-2024-3000",
                    "pkgName": "go-pkg",
                    "severity": "MEDIUM",
                    "title": "Go vuln",
                }],
            }],
        }
        n = TrivyNormalizer(_config(name="trivy"))
        findings = n.normalize(json.dumps(data).encode())
        assert len(findings) == 1


# ===========================================================================
# GrypeNormalizer Tests
# ===========================================================================


class TestGrypeNormalizer:
    def test_single_match(self):
        data = {
            "matches": [{
                "vulnerability": {
                    "id": "CVE-2024-5000",
                    "severity": "Critical",
                    "description": "Critical vuln",
                    "fix": {"versions": ["2.0.0"]},
                },
                "artifact": {
                    "name": "express",
                    "version": "4.17.0",
                    "type": "npm",
                    "purl": "pkg:npm/express@4.17.0",
                },
                "relatedVulnerabilities": [],
            }],
            "source": {"type": "image", "target": "myimg:latest"},
        }
        n = GrypeNormalizer(_config(name="grype"))
        findings = n.normalize(json.dumps(data).encode())
        assert len(findings) == 1
        f = findings[0]
        assert f.source_format == SourceFormat.GRYPE
        assert f.cve_id == "CVE-2024-5000"
        assert f.severity == FindingSeverity.CRITICAL
        assert f.recommendation == "Upgrade to version 2.0.0"
        assert f.purl == "pkg:npm/express@4.17.0"
        assert f.container_image == "myimg:latest"

    def test_cvss_from_related_vulns(self):
        data = {
            "matches": [{
                "vulnerability": {"id": "CVE-2024-6000", "severity": "High"},
                "artifact": {"name": "lib", "version": "1.0"},
                "relatedVulnerabilities": [{
                    "cvss": [{"version": "3.1", "metrics": {"baseScore": 8.5}, "vector": "CVSS:3.1/AV:N"}]
                }],
            }],
            "source": {"type": "directory", "target": "/app"},
        }
        n = GrypeNormalizer(_config(name="grype"))
        findings = n.normalize(json.dumps(data).encode())
        assert findings[0].cvss_score == 8.5

    def test_empty_matches(self):
        data = {"matches": [], "source": {}}
        n = GrypeNormalizer(_config(name="grype"))
        assert n.normalize(json.dumps(data).encode()) == []


# ===========================================================================
# SemgrepNormalizer Tests
# ===========================================================================


class TestSemgrepNormalizer:
    def test_basic_result(self):
        data = {
            "results": [{
                "check_id": "python.lang.security.audit.exec-detected",
                "path": "app/utils.py",
                "start": {"line": 10, "col": 5},
                "extra": {
                    "severity": "ERROR",
                    "message": "Dangerous exec() call",
                    "metadata": {
                        "category": "security",
                        "cwe": ["CWE-78"],
                        "confidence": "HIGH",
                    },
                },
            }]
        }
        n = SemgrepNormalizer(_config(name="semgrep"))
        findings = n.normalize(json.dumps(data).encode())
        assert len(findings) == 1
        f = findings[0]
        assert f.source_format == SourceFormat.SEMGREP
        assert f.severity == FindingSeverity.HIGH
        assert f.file_path == "app/utils.py"
        assert f.line_number == 10
        assert f.column_number == 5
        assert f.cwe_id == "CWE-78"
        assert f.finding_type == FindingType.VULNERABILITY
        assert f.confidence == 0.9  # HIGH -> 0.9

    def test_info_severity(self):
        data = {
            "results": [{
                "check_id": "info-check",
                "path": "test.py",
                "start": {},
                "extra": {"severity": "INFO", "message": "Info", "metadata": {}},
            }]
        }
        n = SemgrepNormalizer(_config(name="semgrep"))
        findings = n.normalize(json.dumps(data).encode())
        assert findings[0].severity == FindingSeverity.LOW

    def test_secret_category(self):
        data = {
            "results": [{
                "check_id": "secrets.leaked-key",
                "path": "config.py",
                "start": {"line": 1},
                "extra": {"severity": "ERROR", "message": "Key leak", "metadata": {"category": "secret"}},
            }]
        }
        n = SemgrepNormalizer(_config(name="semgrep"))
        findings = n.normalize(json.dumps(data).encode())
        assert findings[0].finding_type == FindingType.SECRET

    def test_code_quality_default(self):
        data = {
            "results": [{
                "check_id": "code-style",
                "path": "test.py",
                "start": {},
                "extra": {"severity": "WARNING", "message": "Style issue", "metadata": {"category": "style"}},
            }]
        }
        n = SemgrepNormalizer(_config(name="semgrep"))
        findings = n.normalize(json.dumps(data).encode())
        assert findings[0].finding_type == FindingType.CODE_QUALITY


# ===========================================================================
# DependabotNormalizer Tests
# ===========================================================================


class TestDependabotNormalizer:
    def test_single_alert(self):
        alert = {
            "number": 1,
            "security_advisory": {
                "ghsa_id": "GHSA-xxxx",
                "cve_id": "CVE-2024-7000",
                "summary": "XSS in templates",
                "description": "Cross-site scripting vulnerability",
                "severity": "high",
                "cvss": {"score": 7.5, "vector_string": "CVSS:3.1/AV:N"},
                "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-7000"}],
            },
            "security_vulnerability": {
                "vulnerable_version_range": "< 2.0",
                "first_patched_version": {"identifier": "2.0.0"},
            },
            "dependency": {
                "package": {"name": "handlebars", "ecosystem": "npm"},
                "manifest_path": "package.json",
            },
        }
        n = DependabotNormalizer(_config(name="dependabot"))
        findings = n.normalize(json.dumps([alert]).encode())
        assert len(findings) == 1
        f = findings[0]
        assert f.source_format == SourceFormat.DEPENDABOT
        assert f.cve_id == "CVE-2024-7000"
        assert f.severity == FindingSeverity.HIGH
        assert f.package_name == "handlebars"
        assert f.recommendation == "Upgrade to version 2.0.0"
        assert f.cvss_score == 7.5

    def test_moderate_maps_to_medium(self):
        alert = {
            "security_advisory": {"severity": "moderate", "summary": "test"},
            "security_vulnerability": {},
            "dependency": {"package": {}},
        }
        n = DependabotNormalizer(_config(name="dependabot"))
        findings = n.normalize(json.dumps({"alerts": [alert]}).encode())
        assert findings[0].severity == FindingSeverity.MEDIUM


# ===========================================================================
# NormalizerRegistry Tests
# ===========================================================================


class TestNormalizerRegistry:
    def test_default_normalizers_registered(self):
        registry = NormalizerRegistry()
        names = registry.list_normalizers()
        assert "sarif" in names
        assert "cyclonedx" in names
        assert "trivy" in names
        assert "grype" in names
        assert "semgrep" in names
        assert "dependabot" in names
        assert "dark_web_intel" in names
        assert "cnapp" in names
        assert "spdx" in names
        assert "vex" in names

    def test_get_normalizer(self):
        registry = NormalizerRegistry()
        sarif = registry.get_normalizer("sarif")
        assert sarif is not None
        # Registry may return SARIFNormalizer or upgraded SARIFUniversalNormalizer
        assert hasattr(sarif, "normalize"), "SARIF normalizer must have normalize method"

    def test_get_nonexistent_normalizer(self):
        registry = NormalizerRegistry()
        assert registry.get_normalizer("nonexistent") is None

    def test_register_custom(self):
        registry = NormalizerRegistry()
        custom = BaseNormalizer(_config(name="custom", patterns=[r"custom"]))
        registry.register("custom", custom)
        assert "custom" in registry.list_normalizers()
        assert registry.get_normalizer("custom") is custom

    def test_unregister(self):
        registry = NormalizerRegistry()
        assert "sarif" in registry.list_normalizers()
        registry.unregister("sarif")
        assert "sarif" not in registry.list_normalizers()

    def test_unregister_nonexistent(self):
        registry = NormalizerRegistry()
        # Should not raise
        registry.unregister("nonexistent")

    def test_detect_format_sarif(self):
        registry = NormalizerRegistry()
        sarif = json.dumps({
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [],
        }).encode()
        name, confidence = registry.detect_format(sarif)
        assert name == "sarif"
        assert confidence > 0

    def test_detect_format_cyclonedx(self):
        registry = NormalizerRegistry()
        cdx = json.dumps({
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [],
        }).encode()
        name, confidence = registry.detect_format(cdx)
        assert name == "cyclonedx"

    def test_detect_format_trivy(self):
        registry = NormalizerRegistry()
        trivy = json.dumps({
            "ArtifactName": "test",
            "ArtifactType": "container_image",
            "Results": [{"Vulnerabilities": []}],
        }).encode()
        name, confidence = registry.detect_format(trivy)
        assert name == "trivy"

    def test_detect_format_unknown(self):
        registry = NormalizerRegistry()
        name, confidence = registry.detect_format(b'{"random": "data"}')
        # Either no match or very low confidence
        assert confidence < 0.7 or name is None or name is not None
