"""Comprehensive tests for scanner_parsers.py — 32 normalizer functions.

Coverage targets:
- Each major parser: semgrep, trivy, snyk, bandit, grype, gitleaks, checkov,
  trufflehog (no trufflehog class found — covered via gitleaks secrets pattern),
  zap, burp, nessus, nuclei, sonarqube, nikto, nmap, checkov, prowler,
  dependabot, checkmarx, openvas
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
# Helper: get a value from a finding regardless of whether it is a dict or
# UnifiedFinding dataclass (when ingestion module is available).
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
        n = BanditNormalizer()
        score = n.can_handle(self._make_content())
        assert score >= 0.85

    def test_can_handle_returns_zero_for_unrelated_content(self):
        n = BanditNormalizer()
        assert n.can_handle(b'{"hello": "world"}') == 0.0

    def test_normalize_returns_findings_list(self):
        n = BanditNormalizer()
        findings = n.normalize(self._make_content())
        assert isinstance(findings, list)
        assert len(findings) == 1

    def test_normalize_sets_source_tool_to_bandit(self):
        n = BanditNormalizer()
        f = n.normalize(self._make_content())[0]
        assert _get(f, "source_tool") == "bandit"

    def test_normalize_extracts_rule_id(self):
        n = BanditNormalizer()
        f = n.normalize(self._make_content())[0]
        assert _get(f, "rule_id") == "B101"

    def test_normalize_empty_results_returns_empty_list(self):
        n = BanditNormalizer()
        findings = n.normalize(self._make_content(results=[]))
        assert findings == []

    def test_normalize_malformed_json_returns_empty_list(self):
        n = BanditNormalizer()
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
        n = SemgrepScannerNormalizer()
        assert n.can_handle(self._make_content()) >= 0.9

    def test_can_handle_returns_zero_for_unrelated_content(self):
        n = SemgrepScannerNormalizer()
        assert n.can_handle(b'{"noresults": true}') == 0.0

    def test_normalize_returns_one_finding(self):
        n = SemgrepScannerNormalizer()
        findings = n.normalize(self._make_content())
        assert len(findings) == 1

    def test_normalize_sets_source_tool_to_semgrep(self):
        n = SemgrepScannerNormalizer()
        f = n.normalize(self._make_content())[0]
        assert _get(f, "source_tool") == "semgrep"

    def test_normalize_extracts_file_path(self):
        n = SemgrepScannerNormalizer()
        f = n.normalize(self._make_content())[0]
        assert _get(f, "file_path") == "app/views.py"

    def test_normalize_empty_results_returns_empty_list(self):
        n = SemgrepScannerNormalizer()
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
        n = TrivyScannerNormalizer()
        assert n.can_handle(self._make_content()) >= 0.9

    def test_normalize_returns_findings(self):
        n = TrivyScannerNormalizer()
        findings = n.normalize(self._make_content())
        assert len(findings) == 1

    def test_normalize_sets_source_tool_to_trivy(self):
        n = TrivyScannerNormalizer()
        f = n.normalize(self._make_content())[0]
        assert _get(f, "source_tool") == "trivy"

    def test_normalize_extracts_cve_id(self):
        n = TrivyScannerNormalizer()
        f = n.normalize(self._make_content())[0]
        assert _get(f, "cve_id") == "CVE-2021-3711"

    def test_normalize_maps_critical_severity(self):
        n = TrivyScannerNormalizer()
        f = n.normalize(self._make_content())[0]
        sev = _get(f, "severity")
        # severity may be enum or string; normalise for comparison
        assert str(sev).lower() in ("critical", "findingseverity.critical")


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
        n = SnykNormalizer()
        assert n.can_handle(self._make_content()) >= 0.9

    def test_can_handle_returns_zero_for_unrelated_content(self):
        n = SnykNormalizer()
        assert n.can_handle(b"{}") == 0.0

    def test_normalize_returns_one_finding(self):
        n = SnykNormalizer()
        assert len(n.normalize(self._make_content())) == 1

    def test_normalize_sets_source_tool_to_snyk(self):
        n = SnykNormalizer()
        f = n.normalize(self._make_content())[0]
        assert _get(f, "source_tool") == "snyk"

    def test_normalize_extracts_package_name(self):
        n = SnykNormalizer()
        f = n.normalize(self._make_content())[0]
        assert _get(f, "package_name") == "Pillow"

    def test_normalize_recommendation_contains_upgrade_version(self):
        n = SnykNormalizer()
        f = n.normalize(self._make_content())[0]
        rec = _get(f, "recommendation", "")
        assert "8.2.0" in str(rec)

    def test_normalize_empty_vulnerabilities_returns_empty(self):
        payload = {"packageManager": "pip", "vulnerabilities": []}
        n = SnykNormalizer()
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
        n = GrypeScannerNormalizer()
        assert n.can_handle(self._make_content()) >= 0.9

    def test_normalize_returns_one_finding(self):
        n = GrypeScannerNormalizer()
        assert len(n.normalize(self._make_content())) == 1

    def test_normalize_sets_source_tool_to_grype(self):
        n = GrypeScannerNormalizer()
        f = n.normalize(self._make_content())[0]
        assert _get(f, "source_tool") == "grype"

    def test_normalize_extracts_cve_id(self):
        n = GrypeScannerNormalizer()
        f = n.normalize(self._make_content())[0]
        assert _get(f, "cve_id") == "CVE-2022-12345"

    def test_normalize_empty_matches_returns_empty(self):
        n = GrypeScannerNormalizer()
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
        n = GitleaksScannerNormalizer()
        assert n.can_handle(self._make_content()) >= 0.9

    def test_can_handle_returns_zero_for_unrelated_content(self):
        n = GitleaksScannerNormalizer()
        assert n.can_handle(b'{"results": []}') == 0.0

    def test_normalize_returns_one_finding(self):
        n = GitleaksScannerNormalizer()
        assert len(n.normalize(self._make_content())) == 1

    def test_normalize_sets_source_tool_to_gitleaks(self):
        n = GitleaksScannerNormalizer()
        f = n.normalize(self._make_content())[0]
        assert _get(f, "source_tool") == "gitleaks"

    def test_normalize_aws_key_rule_maps_to_critical(self):
        n = GitleaksScannerNormalizer()
        f = n.normalize(self._make_content())[0]
        sev = str(_get(f, "severity", "")).lower()
        assert "critical" in sev

    def test_normalize_sets_cwe_798_for_hardcoded_credentials(self):
        n = GitleaksScannerNormalizer()
        f = n.normalize(self._make_content())[0]
        assert _get(f, "cwe_id") == "CWE-798"

    def test_normalize_does_not_store_plaintext_secret(self):
        """The actual secret value must NOT appear in the finding output."""
        n = GitleaksScannerNormalizer()
        f = n.normalize(self._make_content())[0]
        finding_str = json.dumps(f if isinstance(f, dict) else vars(f), default=str)
        assert "AKIAIOSFODNN7EXAMPLE" not in finding_str

    def test_normalize_extracts_file_path(self):
        n = GitleaksScannerNormalizer()
        f = n.normalize(self._make_content())[0]
        assert _get(f, "file_path") == "config/settings.py"

    def test_normalize_empty_list_returns_empty(self):
        n = GitleaksScannerNormalizer()
        assert n.normalize(b"[]") == []

    def test_normalize_malformed_json_returns_empty(self):
        n = GitleaksScannerNormalizer()
        assert n.normalize(b"{bad}") == []


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
        n = CheckovNormalizer()
        assert n.can_handle(self._make_content()) >= 0.9

    def test_can_handle_returns_zero_for_unrelated_json(self):
        n = CheckovNormalizer()
        assert n.can_handle(b'{"foo": "bar"}') == 0.0

    def test_normalize_returns_one_finding(self):
        n = CheckovNormalizer()
        assert len(n.normalize(self._make_content())) == 1

    def test_normalize_sets_source_tool_to_checkov(self):
        n = CheckovNormalizer()
        f = n.normalize(self._make_content())[0]
        assert _get(f, "source_tool") == "checkov"

    def test_normalize_extracts_rule_id(self):
        n = CheckovNormalizer()
        f = n.normalize(self._make_content())[0]
        assert _get(f, "rule_id") == "CKV_AWS_2"

    def test_normalize_extracts_file_path(self):
        n = CheckovNormalizer()
        f = n.normalize(self._make_content())[0]
        assert _get(f, "file_path") == "/tf/main.tf"

    def test_normalize_no_failed_checks_returns_empty(self):
        payload = {"check_type": "terraform", "passed_checks": [], "failed_checks": []}
        n = CheckovNormalizer()
        assert n.normalize(json.dumps(payload).encode()) == []


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
        n = ZAPNormalizer()
        assert n.can_handle(self._make_content()) > 0.8

    def test_normalize_returns_findings(self):
        n = ZAPNormalizer()
        assert len(n.normalize(self._make_content())) == 1

    def test_normalize_sets_source_tool_to_zap(self):
        n = ZAPNormalizer()
        f = n.normalize(self._make_content())[0]
        assert _get(f, "source_tool") == "zap"

    def test_normalize_empty_alerts_returns_empty(self):
        payload = {"site": [{"alerts": []}]}
        n = ZAPNormalizer()
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
        n = NucleiNormalizer()
        assert n.can_handle(self._make_content()) >= 0.9

    def test_normalize_returns_findings(self):
        n = NucleiNormalizer()
        assert len(n.normalize(self._make_content())) == 1

    def test_normalize_sets_source_tool_to_nuclei(self):
        n = NucleiNormalizer()
        f = n.normalize(self._make_content())[0]
        assert _get(f, "source_tool") == "nuclei"


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
        n = ProwlerNormalizer()
        assert n.can_handle(self._make_content()) >= 0.85

    def test_normalize_returns_one_finding(self):
        n = ProwlerNormalizer()
        assert len(n.normalize(self._make_content())) == 1

    def test_normalize_sets_source_tool_to_prowler(self):
        n = ProwlerNormalizer()
        f = n.normalize(self._make_content())[0]
        assert _get(f, "source_tool") == "prowler"

    def test_normalize_pass_status_findings_are_excluded(self):
        payload = [
            {
                "CheckID": "test-check",
                "CheckTitle": "A passing check",
                "Status": "PASS",
                "Severity": "low",
            }
        ]
        n = ProwlerNormalizer()
        assert n.normalize(json.dumps(payload).encode()) == []


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
                    "message": "Define a constant instead of duplicating this literal 'foo' 3 times",
                    "line": 42,
                    "tags": [],
                }
            ],
        }
        return json.dumps(payload).encode()

    def test_can_handle_returns_confidence_above_zero(self):
        n = SonarQubeNormalizer()
        assert n.can_handle(self._make_content()) > 0.0

    def test_normalize_returns_one_finding(self):
        n = SonarQubeNormalizer()
        assert len(n.normalize(self._make_content())) == 1

    def test_normalize_sets_source_tool_to_sonarqube(self):
        n = SonarQubeNormalizer()
        f = n.normalize(self._make_content())[0]
        assert _get(f, "source_tool") == "sonarqube"

    def test_normalize_major_severity_maps_to_medium(self):
        n = SonarQubeNormalizer()
        f = n.normalize(self._make_content())[0]
        sev = str(_get(f, "severity", "")).lower()
        assert "medium" in sev


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
        n = DependabotScannerNormalizer()
        assert n.can_handle(self._make_content()) >= 0.9

    def test_normalize_returns_one_finding(self):
        n = DependabotScannerNormalizer()
        assert len(n.normalize(self._make_content())) == 1

    def test_normalize_sets_source_tool_to_dependabot(self):
        n = DependabotScannerNormalizer()
        f = n.normalize(self._make_content())[0]
        assert _get(f, "source_tool") == "dependabot"

    def test_normalize_extracts_cve_id(self):
        n = DependabotScannerNormalizer()
        f = n.normalize(self._make_content())[0]
        assert _get(f, "cve_id") == "CVE-2023-12345"

    def test_normalize_malformed_returns_empty(self):
        n = DependabotScannerNormalizer()
        assert n.normalize(b"{bad json}") == []
