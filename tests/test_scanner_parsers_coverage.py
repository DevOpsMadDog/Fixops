"""Comprehensive tests for scanner_parsers.py — normalizer functions.

Coverage targets:
- Each major parser: semgrep, trivy, snyk, bandit, grype, gitleaks, checkov,
  zap, nuclei, sonarqube, prowler, dependabot
- can_handle() returns expected confidence for valid input
- can_handle() returns 0.0 for unrelated content
- normalize() produces standard finding schema fields
- Edge cases: empty bytes, malformed JSON, missing fields
- Helper functions: _extract_cves, _extract_cwes, _severity_from_number,
  _parse_json_safe, _parse_xml_safe
"""

from __future__ import annotations

import json
import os
import sys

os.environ.setdefault("FIXOPS_MODE", "dev")

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _suite in ("suite-core", "suite-api", "suite-feeds", "suite-evidence-risk"):
    _p = os.path.join(_REPO_ROOT, _suite)
    if _p not in sys.path:
        sys.path.insert(0, _p)

import pytest

from core.scanner_parsers import (
    _extract_cves,
    _extract_cwes,
    _parse_json_safe,
    _parse_xml_safe,
    _severity_from_number,
    BanditNormalizer,
    CheckovNormalizer,
    CheckmarxNormalizer,
    GitleaksScannerNormalizer,
    GrypeScannerNormalizer,
    NessusNormalizer,
    NiktoNormalizer,
    NmapNormalizer,
    NucleiNormalizer,
    OpenVASNormalizer,
    ProwlerNormalizer,
    SemgrepScannerNormalizer,
    SnykNormalizer,
    SonarQubeNormalizer,
    TrivyScannerNormalizer,
    ZAPNormalizer,
    DependabotScannerNormalizer,
)


# ---------------------------------------------------------------------------
# Factory: create normalizer with optional NormalizerConfig if ingestion module
# is present, otherwise call constructor with no args (standalone mode).
# ---------------------------------------------------------------------------

def _make_normalizer(cls):
    """Instantiate a normalizer correctly regardless of ingestion availability."""
    try:
        from apps.api.ingestion import NormalizerConfig
        config = NormalizerConfig(name=cls.__name__.lower().replace("normalizer", ""))
        return cls(config)
    except (ImportError, TypeError):
        # Standalone mode: no config required
        return cls()


# ---------------------------------------------------------------------------
# Helper: get a field from a finding regardless of dict vs UnifiedFinding object.
# ---------------------------------------------------------------------------

def _get(finding, key, default=None):
    if isinstance(finding, dict):
        return finding.get(key, default)
    return getattr(finding, key, default)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

class TestExtractCves:

    def test_extracts_single_cve(self):
        assert "CVE-2021-44228" in _extract_cves("See CVE-2021-44228 for details")

    def test_extracts_multiple_cves(self):
        result = _extract_cves("CVE-2021-44228 and CVE-2020-1234 are both relevant")
        assert len(result) == 2

    def test_returns_empty_list_for_no_cves(self):
        assert _extract_cves("no vulnerabilities here") == []

    def test_returns_empty_list_for_empty_string(self):
        assert _extract_cves("") == []

    def test_returns_empty_list_for_none(self):
        assert _extract_cves(None) == []


class TestExtractCwes:

    def test_extracts_single_cwe(self):
        assert "CWE-79" in _extract_cwes("This maps to CWE-79 (XSS)")

    def test_extracts_multiple_cwes(self):
        result = _extract_cwes("CWE-79 and CWE-89 apply here")
        assert len(result) == 2

    def test_returns_empty_list_for_no_cwes(self):
        assert _extract_cwes("nothing to see") == []

    def test_returns_empty_list_for_empty_string(self):
        assert _extract_cwes("") == []


class TestSeverityFromNumber:

    def test_4_maps_to_critical(self):
        assert _severity_from_number(4) == "critical"

    def test_3_maps_to_high(self):
        assert _severity_from_number(3) == "high"

    def test_2_maps_to_medium(self):
        assert _severity_from_number(2) == "medium"

    def test_1_maps_to_low(self):
        assert _severity_from_number(1) == "low"

    def test_0_maps_to_info(self):
        assert _severity_from_number(0) == "info"

    def test_string_number_is_accepted(self):
        assert _severity_from_number("3") == "high"

    def test_invalid_string_returns_medium(self):
        assert _severity_from_number("bogus") == "medium"


class TestParseJsonSafe:

    def test_valid_json_returns_parsed_object(self):
        data = b'{"key": "value"}'
        result = _parse_json_safe(data)
        assert result == {"key": "value"}

    def test_malformed_json_returns_none(self):
        assert _parse_json_safe(b"{bad json}") is None

    def test_empty_bytes_returns_none(self):
        assert _parse_json_safe(b"") is None

    def test_json_array_is_accepted(self):
        data = b'[1, 2, 3]'
        result = _parse_json_safe(data)
        assert result == [1, 2, 3]


class TestParseXmlSafe:

    def test_valid_xml_returns_element(self):
        xml = b"<root><child>text</child></root>"
        elem = _parse_xml_safe(xml)
        assert elem is not None
        assert elem.tag == "root"

    def test_malformed_xml_returns_none(self):
        assert _parse_xml_safe(b"<unclosed>") is None

    def test_empty_bytes_returns_none(self):
        assert _parse_xml_safe(b"") is None


# ---------------------------------------------------------------------------
# Bandit
# ---------------------------------------------------------------------------

class TestBanditNormalizer:

    def _make_content(self, results=None):
        payload = {
            "generated_at": "2024-01-01T00:00:00Z",
            "metrics": {"_totals": {}},
            "results": results or [
                {
                    "test_id": "B101",
                    "test_name": "assert_used",
                    "issue_text": "Use of assert detected.",
                    "issue_severity": "LOW",
                    "issue_confidence": "HIGH",
                    "filename": "app/main.py",
                    "line_number": 42,
                    "code": "assert user.is_admin",
                    "issue_cwe": {"id": 703, "link": ""},
                }
            ],
        }
        return json.dumps(payload).encode()

    def test_can_handle_returns_high_confidence_for_bandit_json(self):
        n = _make_normalizer(BanditNormalizer)
        score = n.can_handle(self._make_content())
        assert score >= 0.85

    def test_can_handle_returns_zero_for_unrelated_content(self):
        n = _make_normalizer(BanditNormalizer)
        assert n.can_handle(b'{"hello": "world"}') == 0.0

    def test_normalize_returns_findings_list(self):
        n = _make_normalizer(BanditNormalizer)
        findings = n.normalize(self._make_content())
        assert isinstance(findings, list)
        assert len(findings) == 1

    def test_normalize_sets_source_tool_to_bandit(self):
        n = _make_normalizer(BanditNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "source_tool") == "bandit"

    def test_normalize_extracts_rule_id(self):
        n = _make_normalizer(BanditNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "rule_id") == "B101"

    def test_normalize_empty_results_returns_empty_list(self):
        # Pass an explicit empty-results payload (avoid `or` fallback in helper)
        payload = {"generated_at": "2024-01-01T00:00:00Z", "metrics": {"_totals": {}}, "results": []}
        n = _make_normalizer(BanditNormalizer)
        findings = n.normalize(json.dumps(payload).encode())
        assert findings == []

    def test_normalize_malformed_json_returns_empty_list(self):
        n = _make_normalizer(BanditNormalizer)
        assert n.normalize(b"{bad}") == []


# ---------------------------------------------------------------------------
# Semgrep
# ---------------------------------------------------------------------------

class TestSemgrepNormalizer:

    def _make_content(self, results=None):
        payload = {
            "results": results if results is not None else [
                {
                    "check_id": "python.django.security.injection.tainted-sql-string",
                    "path": "app/views.py",
                    "start": {"line": 10, "col": 1},
                    "end": {"line": 10, "col": 50},
                    "extra": {
                        "message": "Potential SQL injection",
                        "severity": "ERROR",
                    },
                }
            ],
            "errors": [],
        }
        return json.dumps(payload).encode()

    def test_can_handle_returns_high_confidence_for_semgrep_json(self):
        n = _make_normalizer(SemgrepScannerNormalizer)
        assert n.can_handle(self._make_content()) >= 0.9

    def test_can_handle_returns_zero_for_unrelated_content(self):
        n = _make_normalizer(SemgrepScannerNormalizer)
        assert n.can_handle(b'{"noresults": true}') == 0.0

    def test_normalize_returns_one_finding(self):
        n = _make_normalizer(SemgrepScannerNormalizer)
        findings = n.normalize(self._make_content())
        assert len(findings) == 1

    def test_normalize_sets_source_tool_to_semgrep(self):
        n = _make_normalizer(SemgrepScannerNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "source_tool") == "semgrep"

    def test_normalize_extracts_file_path(self):
        n = _make_normalizer(SemgrepScannerNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "file_path") == "app/views.py"

    def test_normalize_empty_results_returns_empty_list(self):
        n = _make_normalizer(SemgrepScannerNormalizer)
        assert n.normalize(self._make_content(results=[])) == []


# ---------------------------------------------------------------------------
# Trivy
# ---------------------------------------------------------------------------

class TestTrivyNormalizer:

    def _make_content(self):
        payload = {
            "SchemaVersion": 2,
            "ArtifactName": "myimage:latest",
            "ArtifactType": "container_image",
            "Results": [
                {
                    "Target": "myimage:latest (ubuntu 22.04)",
                    "Type": "ubuntu",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2021-3711",
                            "PkgName": "openssl",
                            "InstalledVersion": "1.1.1f",
                            "FixedVersion": "1.1.1l",
                            "Severity": "CRITICAL",
                            "Title": "OpenSSL buffer overflow",
                            "Description": "A critical overflow in SM2.",
                        }
                    ],
                }
            ],
        }
        return json.dumps(payload).encode()

    def test_can_handle_returns_high_confidence_for_trivy_json(self):
        n = _make_normalizer(TrivyScannerNormalizer)
        assert n.can_handle(self._make_content()) >= 0.9

    def test_normalize_returns_findings(self):
        n = _make_normalizer(TrivyScannerNormalizer)
        findings = n.normalize(self._make_content())
        assert len(findings) == 1

    def test_normalize_sets_source_tool_to_trivy(self):
        n = _make_normalizer(TrivyScannerNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "source_tool") == "trivy"

    def test_normalize_extracts_cve_id(self):
        n = _make_normalizer(TrivyScannerNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "cve_id") == "CVE-2021-3711"

    def test_normalize_maps_critical_severity(self):
        n = _make_normalizer(TrivyScannerNormalizer)
        f = n.normalize(self._make_content())[0]
        sev = _get(f, "severity")
        assert str(sev).lower() in ("critical", "findingseverity.critical")

    def test_normalize_empty_results_returns_empty(self):
        payload = {
            "SchemaVersion": 2,
            "ArtifactName": "img",
            "Results": [{"Target": "img", "Type": "ubuntu", "Vulnerabilities": []}],
        }
        n = _make_normalizer(TrivyScannerNormalizer)
        assert n.normalize(json.dumps(payload).encode()) == []


# ---------------------------------------------------------------------------
# Snyk
# ---------------------------------------------------------------------------

class TestSnykNormalizer:

    def _make_content(self):
        payload = {
            "packageManager": "pip",
            "vulnerabilities": [
                {
                    "id": "SNYK-PYTHON-PILLOW-1018467",
                    "title": "Arbitrary Code Execution",
                    "packageName": "Pillow",
                    "version": "8.1.0",
                    "severity": "high",
                    "cvssScore": 8.8,
                    "identifiers": {"CVE": ["CVE-2021-25287"], "CWE": ["78"]},
                    "fixedIn": ["8.2.0"],
                    "description": "Pillow is vulnerable to arbitrary code execution.",
                }
            ],
        }
        return json.dumps(payload).encode()

    def test_can_handle_returns_high_confidence_for_snyk_json(self):
        n = _make_normalizer(SnykNormalizer)
        assert n.can_handle(self._make_content()) >= 0.9

    def test_can_handle_returns_zero_for_unrelated_content(self):
        n = _make_normalizer(SnykNormalizer)
        assert n.can_handle(b"{}") == 0.0

    def test_normalize_returns_one_finding(self):
        n = _make_normalizer(SnykNormalizer)
        assert len(n.normalize(self._make_content())) == 1

    def test_normalize_sets_source_tool_to_snyk(self):
        n = _make_normalizer(SnykNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "source_tool") == "snyk"

    def test_normalize_extracts_package_name(self):
        n = _make_normalizer(SnykNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "package_name") == "Pillow"

    def test_normalize_recommendation_contains_upgrade_version(self):
        n = _make_normalizer(SnykNormalizer)
        f = n.normalize(self._make_content())[0]
        rec = _get(f, "recommendation", "")
        assert "8.2.0" in str(rec)

    def test_normalize_empty_vulnerabilities_returns_empty(self):
        payload = {"packageManager": "pip", "vulnerabilities": []}
        n = _make_normalizer(SnykNormalizer)
        assert n.normalize(json.dumps(payload).encode()) == []


# ---------------------------------------------------------------------------
# Grype
# ---------------------------------------------------------------------------

class TestGrypeNormalizer:

    def _make_content(self):
        payload = {
            "matches": [
                {
                    "vulnerability": {
                        "id": "CVE-2022-12345",
                        "severity": "High",
                        "description": "A buffer overflow in libfoo.",
                        "fix": {"versions": ["2.0.1"]},
                    },
                    "artifact": {
                        "name": "libfoo",
                        "version": "1.9.0",
                        "type": "deb",
                    },
                }
            ]
        }
        return json.dumps(payload).encode()

    def test_can_handle_returns_high_confidence_for_grype_json(self):
        n = _make_normalizer(GrypeScannerNormalizer)
        assert n.can_handle(self._make_content()) >= 0.9

    def test_normalize_returns_one_finding(self):
        n = _make_normalizer(GrypeScannerNormalizer)
        assert len(n.normalize(self._make_content())) == 1

    def test_normalize_sets_source_tool_to_grype(self):
        n = _make_normalizer(GrypeScannerNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "source_tool") == "grype"

    def test_normalize_extracts_cve_id(self):
        n = _make_normalizer(GrypeScannerNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "cve_id") == "CVE-2022-12345"

    def test_normalize_empty_matches_returns_empty(self):
        n = _make_normalizer(GrypeScannerNormalizer)
        assert n.normalize(json.dumps({"matches": []}).encode()) == []


# ---------------------------------------------------------------------------
# Gitleaks
# ---------------------------------------------------------------------------

class TestGitleaksNormalizer:

    def _make_content(self, items=None):
        data = items if items is not None else [
            {
                "RuleID": "aws-access-key-id",
                "Description": "AWS Access Key detected",
                "Secret": "AKIAIOSFODNN7EXAMPLE",
                "File": "config/settings.py",
                "StartLine": 15,
                "Commit": "abc123def456",
                "Author": "dev@example.com",
                "Date": "2024-01-15",
                "Entropy": 3.5,
            }
        ]
        return json.dumps(data).encode()

    def test_can_handle_returns_high_confidence_for_gitleaks_json(self):
        n = _make_normalizer(GitleaksScannerNormalizer)
        assert n.can_handle(self._make_content()) >= 0.9

    def test_can_handle_returns_zero_for_unrelated_content(self):
        n = _make_normalizer(GitleaksScannerNormalizer)
        assert n.can_handle(b'{"results": []}') == 0.0

    def test_normalize_returns_one_finding(self):
        n = _make_normalizer(GitleaksScannerNormalizer)
        assert len(n.normalize(self._make_content())) == 1

    def test_normalize_sets_source_tool_to_gitleaks(self):
        n = _make_normalizer(GitleaksScannerNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "source_tool") == "gitleaks"

    def test_normalize_aws_key_rule_maps_to_critical(self):
        n = _make_normalizer(GitleaksScannerNormalizer)
        f = n.normalize(self._make_content())[0]
        sev = str(_get(f, "severity", "")).lower()
        assert "critical" in sev

    def test_normalize_sets_cwe_798_for_hardcoded_credentials(self):
        n = _make_normalizer(GitleaksScannerNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "cwe_id") == "CWE-798"

    def test_normalize_does_not_store_plaintext_secret(self):
        """The actual secret value must NOT appear in the finding output."""
        n = _make_normalizer(GitleaksScannerNormalizer)
        f = n.normalize(self._make_content())[0]
        finding_str = json.dumps(f if isinstance(f, dict) else vars(f), default=str)
        assert "AKIAIOSFODNN7EXAMPLE" not in finding_str

    def test_normalize_extracts_file_path(self):
        n = _make_normalizer(GitleaksScannerNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "file_path") == "config/settings.py"

    def test_normalize_empty_list_returns_empty(self):
        n = _make_normalizer(GitleaksScannerNormalizer)
        assert n.normalize(b"[]") == []

    def test_normalize_malformed_json_returns_empty(self):
        n = _make_normalizer(GitleaksScannerNormalizer)
        assert n.normalize(b"{bad}") == []

    def test_normalize_rule_without_sensitive_keyword_maps_to_high(self):
        # Rule "generic-secret" has no sensitive keyword so defaults to high
        items = [{
            "RuleID": "generic-secret",
            "Description": "Generic secret detected",
            "Secret": "some-secret-value",
            "File": "app.py",
            "StartLine": 5,
        }]
        n = _make_normalizer(GitleaksScannerNormalizer)
        f = n.normalize(self._make_content(items=items))[0]
        sev = str(_get(f, "severity", "")).lower()
        assert "high" in sev


# ---------------------------------------------------------------------------
# Checkov
# ---------------------------------------------------------------------------

class TestCheckovNormalizer:

    def _make_content(self):
        payload = {
            "check_type": "terraform",
            "passed_checks": [],
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_2",
                    "check_name": "Ensure ALB protocol is HTTPS",
                    "file_path": "/tf/main.tf",
                    "file_line_range": [12, 20],
                    "severity": "high",
                    "guideline": "Use HTTPS for all load balancers.",
                }
            ],
        }
        return json.dumps(payload).encode()

    def test_can_handle_returns_high_confidence_for_checkov_json(self):
        n = _make_normalizer(CheckovNormalizer)
        assert n.can_handle(self._make_content()) >= 0.9

    def test_can_handle_returns_zero_for_unrelated_json(self):
        n = _make_normalizer(CheckovNormalizer)
        assert n.can_handle(b'{"foo": "bar"}') == 0.0

    def test_normalize_returns_one_finding(self):
        n = _make_normalizer(CheckovNormalizer)
        assert len(n.normalize(self._make_content())) == 1

    def test_normalize_sets_source_tool_to_checkov(self):
        n = _make_normalizer(CheckovNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "source_tool") == "checkov"

    def test_normalize_extracts_rule_id(self):
        n = _make_normalizer(CheckovNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "rule_id") == "CKV_AWS_2"

    def test_normalize_extracts_file_path(self):
        n = _make_normalizer(CheckovNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "file_path") == "/tf/main.tf"

    def test_normalize_no_failed_checks_returns_empty(self):
        payload = {"check_type": "terraform", "passed_checks": [], "failed_checks": []}
        n = _make_normalizer(CheckovNormalizer)
        assert n.normalize(json.dumps(payload).encode()) == []

    def test_normalize_nested_results_failed_checks(self):
        payload = {
            "check_type": "cloudformation",
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_AWS_18",
                        "check_name": "S3 logging enabled",
                        "file_path": "/cf/template.yml",
                        "file_line_range": [1, 5],
                    }
                ]
            },
        }
        n = _make_normalizer(CheckovNormalizer)
        findings = n.normalize(json.dumps(payload).encode())
        assert len(findings) == 1


# ---------------------------------------------------------------------------
# ZAP
# ---------------------------------------------------------------------------

class TestZAPNormalizer:

    def _make_content(self):
        payload = {
            "site": [
                {
                    "alerts": [
                        {
                            "pluginid": "10016",
                            "name": "Web Browser XSS Protection Not Enabled",
                            "riskcode": "2",
                            "desc": "Header not set.",
                            "solution": "Set X-XSS-Protection.",
                            "cweid": "933",
                            "instances": [{"uri": "https://example.com/page"}],
                        }
                    ]
                }
            ]
        }
        return json.dumps(payload).encode()

    def test_can_handle_returns_high_confidence(self):
        n = _make_normalizer(ZAPNormalizer)
        assert n.can_handle(self._make_content()) > 0.8

    def test_normalize_returns_findings(self):
        n = _make_normalizer(ZAPNormalizer)
        assert len(n.normalize(self._make_content())) == 1

    def test_normalize_sets_source_tool_to_zap(self):
        n = _make_normalizer(ZAPNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "source_tool") == "zap"

    def test_normalize_empty_alerts_returns_empty(self):
        payload = {"site": [{"alerts": []}]}
        n = _make_normalizer(ZAPNormalizer)
        assert n.normalize(json.dumps(payload).encode()) == []


# ---------------------------------------------------------------------------
# Nuclei
# ---------------------------------------------------------------------------

class TestNucleiNormalizer:

    def _make_content(self):
        line = json.dumps({
            "template-id": "cve-2021-44228",
            "matched-at": "https://example.com",
            "info": {
                "name": "Log4Shell RCE",
                "description": "Apache Log4j2 RCE",
                "severity": "critical",
                "classification": {"cvss-score": 10.0},
            },
        })
        return line.encode()

    def test_can_handle_returns_high_confidence_for_nuclei_jsonl(self):
        n = _make_normalizer(NucleiNormalizer)
        assert n.can_handle(self._make_content()) >= 0.9

    def test_normalize_returns_findings(self):
        n = _make_normalizer(NucleiNormalizer)
        assert len(n.normalize(self._make_content())) == 1

    def test_normalize_sets_source_tool_to_nuclei(self):
        n = _make_normalizer(NucleiNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "source_tool") == "nuclei"

    def test_normalize_empty_bytes_returns_empty(self):
        n = _make_normalizer(NucleiNormalizer)
        assert n.normalize(b"") == []


# ---------------------------------------------------------------------------
# Prowler
# ---------------------------------------------------------------------------

class TestProwlerNormalizer:

    def _make_content(self):
        payload = [
            {
                "CheckID": "s3_bucket_public_read_acl",
                "CheckTitle": "S3 Bucket should not be publicly readable",
                "Status": "FAIL",
                "Severity": "high",
                "StatusExtended": "Bucket my-bucket is publicly readable.",
                "AccountId": "123456789012",
                "Provider": "aws",
                "Region": "us-east-1",
                "ResourceId": "my-bucket",
                "Compliance": {"CIS-1.4": ["2.1.1"]},
                "Remediation": {"Recommendation": {"Text": "Restrict bucket ACL."}},
            }
        ]
        return json.dumps(payload).encode()

    def test_can_handle_returns_high_confidence(self):
        n = _make_normalizer(ProwlerNormalizer)
        assert n.can_handle(self._make_content()) >= 0.85

    def test_normalize_returns_one_finding(self):
        n = _make_normalizer(ProwlerNormalizer)
        assert len(n.normalize(self._make_content())) == 1

    def test_normalize_sets_source_tool_to_prowler(self):
        n = _make_normalizer(ProwlerNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "source_tool") == "prowler"

    def test_normalize_fail_finding_is_included_and_pass_is_not(self):
        # Mix: one FAIL and one PASS item; only the FAIL should appear.
        payload = [
            {
                "CheckID": "s3-fail-check",
                "CheckTitle": "S3 bucket not encrypted",
                "Status": "FAIL",
                "Severity": "high",
                "StatusExtended": "Bucket not encrypted.",
                "AccountId": "123456789012",
                "Provider": "aws",
                "Region": "us-east-1",
                "ResourceId": "my-bucket",
                "Compliance": {},
                "Remediation": {"Recommendation": {"Text": "Enable encryption."}},
            },
            {
                "CheckID": "s3-pass-check",
                "CheckTitle": "S3 versioning enabled",
                "Status": "PASS",
                "Severity": "low",
                "StatusExtended": "Versioning is enabled.",
                "AccountId": "123456789012",
                "Provider": "aws",
                "Region": "us-east-1",
                "ResourceId": "my-bucket",
                "Compliance": {},
                "Remediation": {"Recommendation": {"Text": ""}},
            },
        ]
        n = _make_normalizer(ProwlerNormalizer)
        result = n.normalize(json.dumps(payload).encode())
        # Only the FAIL finding should be returned
        assert len(result) == 1
        assert _get(result[0], "rule_id") == "s3-fail-check"

    def test_normalize_extracts_cloud_account(self):
        n = _make_normalizer(ProwlerNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "cloud_account") == "123456789012"


# ---------------------------------------------------------------------------
# SonarQube
# ---------------------------------------------------------------------------

class TestSonarQubeNormalizer:

    def _make_content(self):
        payload = {
            "paging": {"total": 1},
            "issues": [
                {
                    "key": "AXHlAXHl",
                    "rule": "python:S1192",
                    "severity": "MAJOR",
                    "component": "my-project:src/main.py",
                    "message": "Define a constant instead of duplicating literal",
                    "line": 42,
                    "tags": [],
                }
            ],
        }
        return json.dumps(payload).encode()

    def test_can_handle_returns_confidence_above_zero(self):
        n = _make_normalizer(SonarQubeNormalizer)
        assert n.can_handle(self._make_content()) > 0.0

    def test_normalize_returns_one_finding(self):
        n = _make_normalizer(SonarQubeNormalizer)
        assert len(n.normalize(self._make_content())) == 1

    def test_normalize_sets_source_tool_to_sonarqube(self):
        n = _make_normalizer(SonarQubeNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "source_tool") == "sonarqube"

    def test_normalize_major_severity_maps_to_medium(self):
        n = _make_normalizer(SonarQubeNormalizer)
        f = n.normalize(self._make_content())[0]
        sev = str(_get(f, "severity", "")).lower()
        assert "medium" in sev

    def test_normalize_extracts_rule_id(self):
        n = _make_normalizer(SonarQubeNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "rule_id") == "python:S1192"


# ---------------------------------------------------------------------------
# Dependabot
# ---------------------------------------------------------------------------

class TestDependabotNormalizer:

    def _make_content(self):
        payload = [
            {
                "security_advisory": {
                    "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
                    "cve_id": "CVE-2023-12345",
                    "summary": "Remote code execution in package foo",
                    "description": "Long description here.",
                    "severity": "critical",
                },
                "dependency": {
                    "package": {"name": "foo", "version": "1.2.3"},
                },
            }
        ]
        return json.dumps(payload).encode()

    def test_can_handle_returns_high_confidence(self):
        n = _make_normalizer(DependabotScannerNormalizer)
        assert n.can_handle(self._make_content()) >= 0.9

    def test_normalize_returns_one_finding(self):
        n = _make_normalizer(DependabotScannerNormalizer)
        assert len(n.normalize(self._make_content())) == 1

    def test_normalize_sets_source_tool_to_dependabot(self):
        n = _make_normalizer(DependabotScannerNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "source_tool") == "dependabot"

    def test_normalize_extracts_cve_id(self):
        n = _make_normalizer(DependabotScannerNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "cve_id") == "CVE-2023-12345"

    def test_normalize_extracts_package_name(self):
        n = _make_normalizer(DependabotScannerNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "package_name") == "foo"

    def test_normalize_empty_list_returns_empty(self):
        # An empty alerts array produces no findings
        payload = []
        n = _make_normalizer(DependabotScannerNormalizer)
        assert n.normalize(json.dumps(payload).encode()) == []


# ---------------------------------------------------------------------------
# Import remaining normalizers not covered above
# ---------------------------------------------------------------------------

from core.scanner_parsers import (  # noqa: E402
    BurpNormalizer,
    NessusNormalizer,
    OpenVASNormalizer,
    NmapNormalizer,
    NiktoNormalizer,
    CheckmarxNormalizer,
    FortifyNormalizer,
    VeracodeNormalizer,
    QualysScannerNormalizer,
    TenableScannerNormalizer,
    Rapid7ScannerNormalizer,
    AcunetixScannerNormalizer,
    AWSInspectorNormalizer,
    GitLabSASTNormalizer,
    SARIFUniversalNormalizer,
    CycloneDXUniversalNormalizer,
    SPDXUniversalNormalizer,
    ClaudeCodeSecurityNormalizer,
    CombobulatorNormalizer,
)


# ---------------------------------------------------------------------------
# Burp Suite
# ---------------------------------------------------------------------------

class TestBurpNormalizer:

    def _make_xml_content(self):
        xml = b"""<issues burpVersion="2023.1">
  <issue>
    <name>Cross-site scripting (reflected)</name>
    <host>https://example.com</host>
    <path>/search</path>
    <severity>High</severity>
    <issueDetail>Input reflected in response.</issueDetail>
    <remediationDetail>Encode output.</remediationDetail>
    <vulnerabilityClassifications>CWE-79</vulnerabilityClassifications>
  </issue>
</issues>"""
        return xml

    def _make_json_content(self):
        payload = {
            "issues": [
                {
                    "name": "SQL injection",
                    "severity": "high",
                    "description": "User input used directly in SQL query.",
                    "origin": "https://example.com",
                    "path": "/login",
                }
            ]
        }
        return json.dumps(payload).encode()

    def test_can_handle_xml_with_burp_version(self):
        n = _make_normalizer(BurpNormalizer)
        assert n.can_handle(self._make_xml_content()) >= 0.85

    def test_can_handle_json_with_issues(self):
        n = _make_normalizer(BurpNormalizer)
        assert n.can_handle(self._make_json_content()) == 0.0  # no burpVersion marker

    def test_normalize_xml_returns_findings(self):
        n = _make_normalizer(BurpNormalizer)
        findings = n.normalize(self._make_xml_content())
        assert len(findings) == 1

    def test_normalize_xml_sets_source_tool_to_burp(self):
        n = _make_normalizer(BurpNormalizer)
        f = n.normalize(self._make_xml_content())[0]
        assert _get(f, "source_tool") == "burp"

    def test_normalize_json_returns_findings(self):
        n = _make_normalizer(BurpNormalizer)
        findings = n.normalize(self._make_json_content())
        assert len(findings) == 1

    def test_normalize_json_sets_source_tool_to_burp(self):
        n = _make_normalizer(BurpNormalizer)
        f = n.normalize(self._make_json_content())[0]
        assert _get(f, "source_tool") == "burp"

    def test_normalize_empty_bytes_returns_empty(self):
        n = _make_normalizer(BurpNormalizer)
        assert n.normalize(b"") == []


# ---------------------------------------------------------------------------
# Nessus
# ---------------------------------------------------------------------------

class TestNessusNormalizer:

    def _make_content(self):
        xml = b"""<NessusClientData_v2>
  <Report name="My Scan">
    <ReportHost name="192.168.1.1">
      <ReportItem pluginID="12345" pluginName="SSL Certificate Expiry" severity="2">
        <description>The SSL certificate will expire soon.</description>
        <solution>Renew the SSL certificate.</solution>
        <cvss3_base_score>6.5</cvss3_base_score>
        <cve>CVE-2022-99999</cve>
        <plugin_output>Certificate expires 2024-01-01</plugin_output>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>"""
        return xml

    def test_can_handle_returns_high_confidence_for_nessus_xml(self):
        n = _make_normalizer(NessusNormalizer)
        assert n.can_handle(self._make_content()) >= 0.9

    def test_can_handle_returns_zero_for_unrelated_content(self):
        n = _make_normalizer(NessusNormalizer)
        assert n.can_handle(b"<html><body>hello</body></html>") == 0.0

    def test_normalize_returns_findings(self):
        n = _make_normalizer(NessusNormalizer)
        findings = n.normalize(self._make_content())
        assert len(findings) == 1

    def test_normalize_sets_source_tool_to_nessus(self):
        n = _make_normalizer(NessusNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "source_tool") == "nessus"

    def test_normalize_extracts_cve_id(self):
        n = _make_normalizer(NessusNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "cve_id") == "CVE-2022-99999"

    def test_normalize_sets_asset_name_to_host_ip(self):
        n = _make_normalizer(NessusNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "asset_name") == "192.168.1.1"

    def test_normalize_skips_severity_zero_items(self):
        xml = b"""<NessusClientData_v2>
  <Report name="Scan">
    <ReportHost name="10.0.0.1">
      <ReportItem pluginID="99999" pluginName="Info Plugin" severity="0">
        <description>Informational only.</description>
        <solution>No action needed.</solution>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>"""
        n = _make_normalizer(NessusNormalizer)
        assert n.normalize(xml) == []

    def test_normalize_malformed_xml_returns_empty(self):
        n = _make_normalizer(NessusNormalizer)
        assert n.normalize(b"<broken>") == []


# ---------------------------------------------------------------------------
# OpenVAS
# ---------------------------------------------------------------------------

class TestOpenVASNormalizer:

    def _make_content(self):
        xml = b"""<report>
  <results>
    <result>
      <threat>High</threat>
      <name>OpenVAS Finding</name>
      <description>SSH weak cipher detected.</description>
      <host>10.0.0.2</host>
      <nvt oid="1.3.6.1.4.1.25623.1.0.12345">
        <name>SSH Weak Ciphers</name>
        <solution>Disable weak SSH ciphers.</solution>
        <cve>CVE-2023-00001</cve>
        <cvss_base>7.5</cvss_base>
      </nvt>
    </result>
  </results>
</report>"""
        return xml

    def test_can_handle_returns_high_confidence_for_openvas_xml(self):
        n = _make_normalizer(OpenVASNormalizer)
        assert n.can_handle(self._make_content()) >= 0.9

    def test_normalize_returns_findings(self):
        n = _make_normalizer(OpenVASNormalizer)
        findings = n.normalize(self._make_content())
        assert len(findings) == 1

    def test_normalize_sets_source_tool_to_openvas(self):
        n = _make_normalizer(OpenVASNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "source_tool") == "openvas"

    def test_normalize_extracts_cve_id(self):
        n = _make_normalizer(OpenVASNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "cve_id") == "CVE-2023-00001"

    def test_normalize_malformed_xml_returns_empty(self):
        n = _make_normalizer(OpenVASNormalizer)
        assert n.normalize(b"<bad>") == []


# ---------------------------------------------------------------------------
# Nmap
# ---------------------------------------------------------------------------

class TestNmapNormalizer:

    def _make_content_open_port(self):
        xml = b"""<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
  <host>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.2"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        return xml

    def _make_content_with_vuln_script(self):
        xml = b"""<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
  <host>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https"/>
        <script id="ssl-heartbleed" output="VULNERABLE: CVE-2014-0160 Heartbleed"/>
      </port>
    </ports>
  </host>
</nmaprun>"""
        return xml

    def test_can_handle_returns_high_confidence_for_nmap_xml(self):
        n = _make_normalizer(NmapNormalizer)
        assert n.can_handle(self._make_content_open_port()) >= 0.9

    def test_can_handle_returns_zero_for_unrelated_xml(self):
        n = _make_normalizer(NmapNormalizer)
        assert n.can_handle(b"<html><body>not nmap</body></html>") == 0.0

    def test_normalize_open_port_produces_info_finding(self):
        n = _make_normalizer(NmapNormalizer)
        findings = n.normalize(self._make_content_open_port())
        assert len(findings) == 1
        sev = str(_get(findings[0], "severity", "")).lower()
        assert "info" in sev

    def test_normalize_open_port_sets_source_tool_to_nmap(self):
        n = _make_normalizer(NmapNormalizer)
        f = n.normalize(self._make_content_open_port())[0]
        assert _get(f, "source_tool") == "nmap"

    def test_normalize_vuln_script_produces_high_severity_finding(self):
        n = _make_normalizer(NmapNormalizer)
        findings = n.normalize(self._make_content_with_vuln_script())
        assert len(findings) >= 1
        sevs = [str(_get(f, "severity", "")).lower() for f in findings]
        assert any("high" in s for s in sevs)

    def test_normalize_vuln_script_extracts_cve(self):
        n = _make_normalizer(NmapNormalizer)
        findings = n.normalize(self._make_content_with_vuln_script())
        cve_ids = [_get(f, "cve_id") for f in findings]
        assert "CVE-2014-0160" in cve_ids

    def test_normalize_empty_bytes_returns_empty(self):
        n = _make_normalizer(NmapNormalizer)
        assert n.normalize(b"") == []


# ---------------------------------------------------------------------------
# Nikto
# ---------------------------------------------------------------------------

class TestNiktoNormalizer:

    def _make_content(self):
        payload = {
            "host": "192.168.1.100",
            "port": 80,
            "vulnerabilities": [
                {
                    "id": "000001",
                    "OSVDB": "0",
                    "msg": "Server may leak inodes via ETags.",
                    "url": "/",
                }
            ],
        }
        return json.dumps(payload).encode()

    def test_can_handle_returns_high_confidence_for_nikto_json(self):
        n = _make_normalizer(NiktoNormalizer)
        assert n.can_handle(self._make_content()) >= 0.75

    def test_can_handle_returns_zero_for_unrelated_content(self):
        n = _make_normalizer(NiktoNormalizer)
        assert n.can_handle(b'{"foo": "bar"}') == 0.0

    def test_normalize_returns_findings(self):
        n = _make_normalizer(NiktoNormalizer)
        findings = n.normalize(self._make_content())
        assert len(findings) == 1

    def test_normalize_sets_source_tool_to_nikto(self):
        n = _make_normalizer(NiktoNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "source_tool") == "nikto"

    def test_normalize_includes_host_in_asset_name(self):
        n = _make_normalizer(NiktoNormalizer)
        f = n.normalize(self._make_content())[0]
        asset = str(_get(f, "asset_name", ""))
        assert "192.168.1.100" in asset

    def test_normalize_empty_vulnerabilities_returns_empty(self):
        payload = {"host": "10.0.0.1", "port": 80, "vulnerabilities": []}
        n = _make_normalizer(NiktoNormalizer)
        assert n.normalize(json.dumps(payload).encode()) == []


# ---------------------------------------------------------------------------
# Checkmarx
# ---------------------------------------------------------------------------

class TestCheckmarxNormalizer:

    def _make_json_content(self):
        payload = [
            {
                "queryName": "SQL_Injection",
                "queryId": "1",
                "severity": "high",
                "sourceFile": "src/db.py",
                "sourceLine": 42,
                "cweId": "89",
                "description": "SQL injection via user input.",
                "recommendation": "Use parameterized queries.",
            }
        ]
        return json.dumps(payload).encode()

    def _make_xml_content(self):
        xml = b"""<CxXMLResults ProjectName="MyApp">
  <Query name="XSS" cweId="79" Severity="Medium">
    <Result NodeId="1" DeepLink="https://cx.example.com/1">
      <Path>
        <PathNode>
          <FileName>app/views.py</FileName>
          <Line>15</Line>
        </PathNode>
      </Path>
    </Result>
  </Query>
</CxXMLResults>"""
        return xml

    def test_can_handle_returns_high_confidence_for_json_with_query_name(self):
        n = _make_normalizer(CheckmarxNormalizer)
        payload = b'{"queryName": "SQL_Injection", "resultSeverity": "high"}'
        assert n.can_handle(payload) >= 0.85

    def test_can_handle_returns_high_confidence_for_cx_xml(self):
        n = _make_normalizer(CheckmarxNormalizer)
        assert n.can_handle(self._make_xml_content()) >= 0.9

    def test_normalize_json_returns_findings(self):
        n = _make_normalizer(CheckmarxNormalizer)
        findings = n.normalize(self._make_json_content())
        assert len(findings) == 1

    def test_normalize_json_sets_source_tool_to_checkmarx(self):
        n = _make_normalizer(CheckmarxNormalizer)
        f = n.normalize(self._make_json_content())[0]
        assert _get(f, "source_tool") == "checkmarx"

    def test_normalize_json_extracts_cwe(self):
        n = _make_normalizer(CheckmarxNormalizer)
        f = n.normalize(self._make_json_content())[0]
        assert _get(f, "cwe_id") == "CWE-89"

    def test_normalize_xml_returns_findings(self):
        n = _make_normalizer(CheckmarxNormalizer)
        findings = n.normalize(self._make_xml_content())
        assert len(findings) == 1

    def test_normalize_xml_sets_source_tool_to_checkmarx(self):
        n = _make_normalizer(CheckmarxNormalizer)
        f = n.normalize(self._make_xml_content())[0]
        assert _get(f, "source_tool") == "checkmarx"

    def test_normalize_malformed_returns_empty(self):
        n = _make_normalizer(CheckmarxNormalizer)
        assert n.normalize(b"{bad json}") == []


# ---------------------------------------------------------------------------
# Fortify
# ---------------------------------------------------------------------------

class TestFortifyNormalizer:

    def _make_json_content(self):
        payload = {
            "vulnerabilities": [
                {
                    "category": "SQL Injection",
                    "description": "User data flows into SQL query.",
                    "severity": "high",
                    "cwe": "89",
                    "primaryLocation": {
                        "filePath": "src/database.py",
                        "startLine": 100,
                    },
                }
            ]
        }
        return json.dumps(payload).encode()

    def test_can_handle_returns_zero_for_unrelated_content(self):
        n = _make_normalizer(FortifyNormalizer)
        assert n.can_handle(b'{"random": "data"}') == 0.0

    def test_normalize_json_returns_findings(self):
        n = _make_normalizer(FortifyNormalizer)
        findings = n.normalize(self._make_json_content())
        assert len(findings) == 1

    def test_normalize_json_sets_source_tool_to_fortify(self):
        n = _make_normalizer(FortifyNormalizer)
        f = n.normalize(self._make_json_content())[0]
        assert _get(f, "source_tool") == "fortify"

    def test_normalize_empty_bytes_returns_empty(self):
        n = _make_normalizer(FortifyNormalizer)
        assert n.normalize(b"") == []


# ---------------------------------------------------------------------------
# Veracode
# ---------------------------------------------------------------------------

class TestVeracodeNormalizer:

    def _make_json_content(self):
        payload = {
            "findings": [
                {
                    "title": "SQL Injection",
                    "description": "Input not sanitized.",
                    "finding_details": {
                        "finding_category": {"name": "SQL Injection"},
                        "cwe": {"id": 89},
                        "file_path": "src/query.py",
                        "file_line_number": 55,
                    },
                    "finding_status": {"severity": 3},
                }
            ]
        }
        return json.dumps(payload).encode()

    def test_can_handle_returns_high_confidence_for_veracode_findings_json(self):
        n = _make_normalizer(VeracodeNormalizer)
        assert n.can_handle(b'{"finding_details": "x", "finding_status": "y"}') >= 0.8

    def test_normalize_json_returns_findings(self):
        n = _make_normalizer(VeracodeNormalizer)
        findings = n.normalize(self._make_json_content())
        assert len(findings) == 1

    def test_normalize_json_sets_source_tool_to_veracode(self):
        n = _make_normalizer(VeracodeNormalizer)
        f = n.normalize(self._make_json_content())[0]
        assert _get(f, "source_tool") == "veracode"

    def test_normalize_json_extracts_cwe(self):
        n = _make_normalizer(VeracodeNormalizer)
        f = n.normalize(self._make_json_content())[0]
        assert _get(f, "cwe_id") == "CWE-89"

    def test_normalize_empty_findings_returns_empty(self):
        payload = {"findings": []}
        n = _make_normalizer(VeracodeNormalizer)
        assert n.normalize(json.dumps(payload).encode()) == []


# ---------------------------------------------------------------------------
# Qualys
# ---------------------------------------------------------------------------

class TestQualysNormalizer:

    def _make_json_content(self):
        payload = [
            {
                "ip": "10.0.0.1",
                "detections": [
                    {
                        "qid": "38170",
                        "title": "SSL Certificate - Self-Signed Certificate",
                        "severity": 3,
                        "cve_list": "CVE-2022-12345",
                        "results": "Self-signed certificate detected.",
                        "solution": "Replace with CA-signed certificate.",
                    }
                ],
            }
        ]
        return json.dumps(payload).encode()

    def test_can_handle_returns_high_confidence_for_qualys_json(self):
        n = _make_normalizer(QualysScannerNormalizer)
        assert n.can_handle(b'{"qid": "123", "severity": 3, "ip": "10.0.0.1"}') >= 0.8

    def test_normalize_json_returns_findings(self):
        n = _make_normalizer(QualysScannerNormalizer)
        findings = n.normalize(self._make_json_content())
        assert len(findings) == 1

    def test_normalize_json_sets_source_tool_to_qualys(self):
        n = _make_normalizer(QualysScannerNormalizer)
        f = n.normalize(self._make_json_content())[0]
        assert _get(f, "source_tool") == "qualys"

    def test_normalize_empty_detections_returns_empty(self):
        payload = [{"ip": "10.0.0.1", "detections": []}]
        n = _make_normalizer(QualysScannerNormalizer)
        assert n.normalize(json.dumps(payload).encode()) == []


# ---------------------------------------------------------------------------
# Tenable
# ---------------------------------------------------------------------------

class TestTenableNormalizer:

    def _make_content(self):
        payload = {
            "target": "192.168.1.50",
            "vulnerabilities": [
                {
                    "plugin_id": "10863",
                    "plugin_name": "SSL Self-Signed Certificate",
                    "severity_index": 2,
                    "synopsis": "The remote host uses a self-signed SSL certificate.",
                    "solution": "Purchase or generate a proper certificate.",
                    "cve": "CVE-2021-99999",
                    "cvss3_base_score": 5.4,
                }
            ],
        }
        return json.dumps(payload).encode()

    def test_can_handle_returns_high_confidence_for_tenable_json(self):
        n = _make_normalizer(TenableScannerNormalizer)
        assert n.can_handle(b'{"plugin_id": "123", "severity_index": 2}') >= 0.9

    def test_normalize_returns_findings(self):
        n = _make_normalizer(TenableScannerNormalizer)
        findings = n.normalize(self._make_content())
        assert len(findings) == 1

    def test_normalize_sets_source_tool_to_tenable(self):
        n = _make_normalizer(TenableScannerNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "source_tool") == "tenable"

    def test_normalize_extracts_cve(self):
        n = _make_normalizer(TenableScannerNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "cve_id") == "CVE-2021-99999"

    def test_normalize_empty_vulnerabilities_returns_empty(self):
        payload = {"target": "10.0.0.1", "vulnerabilities": []}
        n = _make_normalizer(TenableScannerNormalizer)
        assert n.normalize(json.dumps(payload).encode()) == []


# ---------------------------------------------------------------------------
# Rapid7
# ---------------------------------------------------------------------------

class TestRapid7Normalizer:

    def _make_json_content(self):
        payload = [
            {
                "address": "10.0.0.20",
                "tests": [
                    {
                        "vulnerability-id": "ssl-cve-2014-0224-ccs-injection",
                        "title": "CCS Injection",
                        "severity": "high",
                        "description": "OpenSSL CCS injection vulnerability.",
                        "solution": "Upgrade OpenSSL.",
                    }
                ],
            }
        ]
        return json.dumps(payload).encode()

    def test_can_handle_returns_high_confidence_for_rapid7_json(self):
        n = _make_normalizer(Rapid7ScannerNormalizer)
        assert n.can_handle(b'{"vulnerability-id": "x", "tests": []}') >= 0.9

    def test_normalize_json_returns_findings(self):
        n = _make_normalizer(Rapid7ScannerNormalizer)
        findings = n.normalize(self._make_json_content())
        assert len(findings) == 1

    def test_normalize_json_sets_source_tool_to_rapid7(self):
        n = _make_normalizer(Rapid7ScannerNormalizer)
        f = n.normalize(self._make_json_content())[0]
        assert _get(f, "source_tool") == "rapid7"

    def test_normalize_empty_tests_returns_empty(self):
        payload = [{"address": "10.0.0.1", "tests": []}]
        n = _make_normalizer(Rapid7ScannerNormalizer)
        assert n.normalize(json.dumps(payload).encode()) == []


# ---------------------------------------------------------------------------
# Acunetix
# ---------------------------------------------------------------------------

class TestAcunetixNormalizer:

    def _make_content(self):
        payload = {
            "vulnerabilities": [
                {
                    "vt_name": "Cross-site Scripting",
                    "affects_url": "https://example.com/search?q=test",
                    "severity": "high",
                    "description": "XSS in search input.",
                    "recommendation": "Encode user output.",
                    "cvelist": "CVE-2020-12345",
                }
            ]
        }
        return json.dumps(payload).encode()

    def test_can_handle_returns_high_confidence_for_acunetix_json(self):
        n = _make_normalizer(AcunetixScannerNormalizer)
        assert n.can_handle(self._make_content()) >= 0.9

    def test_can_handle_returns_zero_for_unrelated_content(self):
        n = _make_normalizer(AcunetixScannerNormalizer)
        assert n.can_handle(b'{"foo": "bar"}') == 0.0

    def test_normalize_returns_findings(self):
        n = _make_normalizer(AcunetixScannerNormalizer)
        findings = n.normalize(self._make_content())
        assert len(findings) == 1

    def test_normalize_sets_source_tool_to_acunetix(self):
        n = _make_normalizer(AcunetixScannerNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "source_tool") == "acunetix"

    def test_normalize_empty_vulnerabilities_returns_empty(self):
        payload = {"vulnerabilities": []}
        n = _make_normalizer(AcunetixScannerNormalizer)
        assert n.normalize(json.dumps(payload).encode()) == []


# ---------------------------------------------------------------------------
# AWS Inspector
# ---------------------------------------------------------------------------

class TestAWSInspectorNormalizer:

    def _make_content(self):
        payload = {
            "findings": [
                {
                    "awsAccountId": "123456789012",
                    "region": "us-east-1",
                    "severity": "HIGH",
                    "inspectorScore": 8.5,
                    "title": "CVE-2023-00001 found in libssl",
                    "description": "Critical OpenSSL vulnerability.",
                    "packageVulnerabilityDetails": {
                        "vulnerabilityId": "CVE-2023-00001",
                        "vulnerablePackages": [
                            {"name": "libssl", "version": "1.1.1", "fixedInVersion": "1.1.1t"}
                        ],
                    },
                    "resources": [{"id": "i-0abc123def456", "type": "AWS_EC2_INSTANCE"}],
                    "remediation": {"recommendation": {"text": "Update libssl to 1.1.1t."}},
                }
            ]
        }
        return json.dumps(payload).encode()

    def test_can_handle_returns_very_high_confidence(self):
        n = _make_normalizer(AWSInspectorNormalizer)
        assert n.can_handle(self._make_content()) >= 0.9

    def test_normalize_returns_findings(self):
        n = _make_normalizer(AWSInspectorNormalizer)
        findings = n.normalize(self._make_content())
        assert len(findings) == 1

    def test_normalize_sets_source_tool_to_aws_inspector(self):
        n = _make_normalizer(AWSInspectorNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "source_tool") == "aws_inspector"

    def test_normalize_extracts_cve_id(self):
        n = _make_normalizer(AWSInspectorNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "cve_id") == "CVE-2023-00001"

    def test_normalize_extracts_cloud_account(self):
        n = _make_normalizer(AWSInspectorNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "cloud_account") == "123456789012"

    def test_normalize_empty_findings_returns_empty(self):
        payload = {"findings": []}
        n = _make_normalizer(AWSInspectorNormalizer)
        assert n.normalize(json.dumps(payload).encode()) == []


# ---------------------------------------------------------------------------
# GitLab SAST
# ---------------------------------------------------------------------------

class TestGitLabSASTNormalizer:

    def _make_content(self):
        payload = {
            "version": "15.0.0",
            "vulnerabilities": [
                {
                    "name": "Improper Neutralization of Special Elements",
                    "description": "User input used in SQL query.",
                    "severity": "High",
                    "location": {"file": "app/models.py", "start_line": 25},
                    "identifiers": [
                        {"type": "cwe", "name": "CWE-89", "value": "CWE-89"},
                        {"type": "rule_id", "name": "python.sqlinjection", "value": "python.sqlinjection"},
                    ],
                    "scanner": {"name": "Semgrep", "id": "semgrep"},
                }
            ],
            "scan": {"scanner": {"name": "Semgrep"}},
        }
        return json.dumps(payload).encode()

    def test_can_handle_returns_high_confidence(self):
        n = _make_normalizer(GitLabSASTNormalizer)
        assert n.can_handle(self._make_content()) >= 0.85

    def test_normalize_returns_findings(self):
        n = _make_normalizer(GitLabSASTNormalizer)
        findings = n.normalize(self._make_content())
        assert len(findings) == 1

    def test_normalize_sets_source_tool_to_gitlab_sast(self):
        n = _make_normalizer(GitLabSASTNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "source_tool") == "gitlab_sast"

    def test_normalize_extracts_file_path(self):
        n = _make_normalizer(GitLabSASTNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "file_path") == "app/models.py"

    def test_normalize_maps_high_severity(self):
        n = _make_normalizer(GitLabSASTNormalizer)
        f = n.normalize(self._make_content())[0]
        assert str(_get(f, "severity", "")).lower() in ("high", "findingseverity.high")

    def test_normalize_empty_vulnerabilities_returns_empty(self):
        payload = {"version": "15.0.0", "vulnerabilities": []}
        n = _make_normalizer(GitLabSASTNormalizer)
        assert n.normalize(json.dumps(payload).encode()) == []


# ---------------------------------------------------------------------------
# SARIF Universal
# ---------------------------------------------------------------------------

class TestSARIFNormalizer:

    def _make_content(self):
        payload = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "ESLint",
                            "rules": [
                                {
                                    "id": "no-eval",
                                    "shortDescription": {"text": "Disallow eval()"},
                                    "fullDescription": {"text": "Using eval() is dangerous."},
                                    "properties": {"security-severity": "7.5", "tags": ["CWE-95"]},
                                }
                            ],
                        }
                    },
                    "results": [
                        {
                            "ruleId": "no-eval",
                            "level": "error",
                            "message": {"text": "eval() call detected"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/utils.js"},
                                        "region": {"startLine": 42},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
        return json.dumps(payload).encode()

    def test_can_handle_returns_very_high_confidence_for_sarif(self):
        n = _make_normalizer(SARIFUniversalNormalizer)
        assert n.can_handle(self._make_content()) >= 0.9

    def test_normalize_returns_findings(self):
        n = _make_normalizer(SARIFUniversalNormalizer)
        findings = n.normalize(self._make_content())
        assert len(findings) == 1

    def test_normalize_extracts_file_path(self):
        n = _make_normalizer(SARIFUniversalNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "file_path") == "src/utils.js"

    def test_normalize_extracts_line_number(self):
        n = _make_normalizer(SARIFUniversalNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "line_number") == 42

    def test_normalize_security_severity_maps_to_high(self):
        n = _make_normalizer(SARIFUniversalNormalizer)
        f = n.normalize(self._make_content())[0]
        assert str(_get(f, "severity", "")).lower() in ("high", "findingseverity.high")

    def test_normalize_empty_runs_returns_empty(self):
        payload = {"$schema": "sarif-schema", "version": "2.1.0", "runs": []}
        n = _make_normalizer(SARIFUniversalNormalizer)
        assert n.normalize(json.dumps(payload).encode()) == []


# ---------------------------------------------------------------------------
# CycloneDX
# ---------------------------------------------------------------------------

class TestCycloneDXNormalizer:

    def _make_content(self):
        payload = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "vulnerabilities": [
                {
                    "id": "CVE-2021-44228",
                    "description": "Apache Log4j2 JNDI injection",
                    "detail": "Remote code execution via JNDI lookup.",
                    "ratings": [{"severity": "critical", "score": 10.0}],
                    "cwes": [502],
                    "affects": [{"ref": "log4j-core-2.14.1.jar"}],
                    "advisories": [{"title": "Upgrade to Log4j 2.15.0+"}],
                }
            ],
            "components": [],
        }
        return json.dumps(payload).encode()

    def test_can_handle_returns_high_confidence_for_cyclonedx(self):
        n = _make_normalizer(CycloneDXUniversalNormalizer)
        assert n.can_handle(self._make_content()) >= 0.9

    def test_can_handle_returns_zero_for_unrelated_json(self):
        n = _make_normalizer(CycloneDXUniversalNormalizer)
        assert n.can_handle(b'{"foo": "bar"}') == 0.0

    def test_normalize_returns_findings(self):
        n = _make_normalizer(CycloneDXUniversalNormalizer)
        findings = n.normalize(self._make_content())
        assert len(findings) == 1

    def test_normalize_sets_source_tool_to_cyclonedx(self):
        n = _make_normalizer(CycloneDXUniversalNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "source_tool") == "cyclonedx"

    def test_normalize_extracts_cwe(self):
        n = _make_normalizer(CycloneDXUniversalNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "cwe_id") == "CWE-502"

    def test_normalize_empty_vulnerabilities_returns_empty(self):
        payload = {"bomFormat": "CycloneDX", "specVersion": "1.4", "vulnerabilities": []}
        n = _make_normalizer(CycloneDXUniversalNormalizer)
        assert n.normalize(json.dumps(payload).encode()) == []


# ---------------------------------------------------------------------------
# SPDX
# ---------------------------------------------------------------------------

class TestSPDXNormalizer:

    def _make_content_with_security_ref(self):
        payload = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "packages": [
                {
                    "name": "vulnerable-lib",
                    "versionInfo": "1.0.0",
                    "externalRefs": [
                        {
                            "referenceCategory": "SECURITY",
                            "referenceType": "cpe23Type",
                            "referenceLocator": "cpe:2.3:a:vulnerable:lib:1.0.0:*:*:*:*:*:*:*",
                        }
                    ],
                }
            ],
        }
        return json.dumps(payload).encode()

    def test_can_handle_returns_high_confidence_for_spdx_json(self):
        n = _make_normalizer(SPDXUniversalNormalizer)
        assert n.can_handle(self._make_content_with_security_ref()) >= 0.85

    def test_can_handle_returns_zero_for_unrelated_json(self):
        n = _make_normalizer(SPDXUniversalNormalizer)
        assert n.can_handle(b'{"foo": "bar"}') == 0.0

    def test_normalize_security_ref_produces_finding(self):
        n = _make_normalizer(SPDXUniversalNormalizer)
        findings = n.normalize(self._make_content_with_security_ref())
        assert len(findings) == 1

    def test_normalize_sets_source_tool_to_spdx(self):
        n = _make_normalizer(SPDXUniversalNormalizer)
        f = n.normalize(self._make_content_with_security_ref())[0]
        assert _get(f, "source_tool") == "spdx"

    def test_normalize_packages_without_security_refs_returns_empty(self):
        payload = {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {"name": "safe-lib", "versionInfo": "2.0", "externalRefs": []}
            ],
        }
        n = _make_normalizer(SPDXUniversalNormalizer)
        assert n.normalize(json.dumps(payload).encode()) == []


# ---------------------------------------------------------------------------
# ClaudeCodeSecurity
# ---------------------------------------------------------------------------

class TestClaudeCodeSecurityNormalizer:

    def _make_content(self):
        payload = [
            {
                "title": "Insecure Direct Object Reference",
                "description": "User ID not validated before use.",
                "severity": "high",
                "reasoning": "Attacker can access another user's data.",
                "confidence": 0.95,
                "rule_id": "IDOR-001",
                "cwe": "639",
                "file_path": "api/users.py",
                "line": 88,
            }
        ]
        return json.dumps(payload).encode()

    def test_can_handle_returns_high_confidence_for_ai_sast_json(self):
        n = _make_normalizer(ClaudeCodeSecurityNormalizer)
        data = b'{"reasoning": "x", "suggested_patch": "y", "confidence": 0.9}'
        assert n.can_handle(data) >= 0.85

    def test_normalize_returns_findings(self):
        n = _make_normalizer(ClaudeCodeSecurityNormalizer)
        findings = n.normalize(self._make_content())
        assert len(findings) == 1

    def test_normalize_sets_source_tool_to_claude_code_security(self):
        n = _make_normalizer(ClaudeCodeSecurityNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "source_tool") == "claude_code_security"

    def test_normalize_extracts_cwe(self):
        n = _make_normalizer(ClaudeCodeSecurityNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "cwe_id") == "CWE-639"

    def test_normalize_extracts_file_path(self):
        n = _make_normalizer(ClaudeCodeSecurityNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "file_path") == "api/users.py"

    def test_normalize_empty_list_returns_empty(self):
        n = _make_normalizer(ClaudeCodeSecurityNormalizer)
        assert n.normalize(b"[]") == []


# ---------------------------------------------------------------------------
# Combobulator (supply chain)
# ---------------------------------------------------------------------------

class TestCombobulatorNormalizer:

    def _make_content(self):
        payload = [
            {
                "package_name": "internal-utils",
                "risk_type": "dependency_confusion",
                "severity": "high",
                "registry": "pypi",
                "private_registry": "private.pypi.example.com",
                "manifest_file": "requirements.txt",
                "description": "Package exists on public registry with higher version.",
            }
        ]
        return json.dumps(payload).encode()

    def test_can_handle_returns_high_confidence_for_combobulator_json(self):
        n = _make_normalizer(CombobulatorNormalizer)
        data = b'{"package_name": "x", "risk_type": "dependency_confusion", "registry": "pypi"}'
        assert n.can_handle(data) >= 0.85

    def test_can_handle_returns_zero_for_unrelated_content(self):
        n = _make_normalizer(CombobulatorNormalizer)
        assert n.can_handle(b'{"foo": "bar"}') == 0.0

    def test_normalize_returns_findings(self):
        n = _make_normalizer(CombobulatorNormalizer)
        findings = n.normalize(self._make_content())
        assert len(findings) == 1

    def test_normalize_sets_source_tool_to_combobulator(self):
        n = _make_normalizer(CombobulatorNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "source_tool") == "combobulator"

    def test_normalize_sets_cwe_427_for_supply_chain(self):
        n = _make_normalizer(CombobulatorNormalizer)
        f = n.normalize(self._make_content())[0]
        assert _get(f, "cwe_id") == "CWE-427"

    def test_normalize_empty_list_returns_empty(self):
        n = _make_normalizer(CombobulatorNormalizer)
        assert n.normalize(b"[]") == []
