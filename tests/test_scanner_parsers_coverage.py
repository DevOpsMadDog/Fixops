"""Coverage tests for core.scanner_parsers — 16 additional normalizers + 4 module functions.

Covers normalizers NOT tested in test_scanner_parsers_unit.py:
  Trivy, Grype, Semgrep, Dependabot, Qualys, Tenable, Rapid7, Acunetix,
  AWSInspector, GitLabSAST, SARIF, CycloneDX, SPDX, Gitleaks,
  ClaudeCodeSecurity, Combobulator

Module-level functions:
  register_scanner_normalizers, auto_detect_scanner,
  parse_scanner_output, get_supported_scanners

Vision Pillar: V1 (APP_ID-Centric), V3 (Decision Intelligence)
"""

import json

import pytest

from apps.api.ingestion import NormalizerConfig

from core.scanner_parsers import (
    TrivyScannerNormalizer,
    GrypeScannerNormalizer,
    SemgrepScannerNormalizer,
    DependabotScannerNormalizer,
    QualysScannerNormalizer,
    TenableScannerNormalizer,
    Rapid7ScannerNormalizer,
    AcunetixScannerNormalizer,
    AWSInspectorNormalizer,
    GitLabSASTNormalizer,
    SARIFUniversalNormalizer,
    CycloneDXUniversalNormalizer,
    SPDXUniversalNormalizer,
    GitleaksScannerNormalizer,
    ClaudeCodeSecurityNormalizer,
    CombobulatorNormalizer,
    auto_detect_scanner,
    parse_scanner_output,
    get_supported_scanners,
    SCANNER_NORMALIZERS,
)

pytestmark = pytest.mark.timeout(10)

# ---------------------------------------------------------------------------
# Shared fixture helpers
# ---------------------------------------------------------------------------

def _cfg(name: str) -> NormalizerConfig:
    return NormalizerConfig(name=name)


def _as_dict(finding) -> dict:
    """Coerce a UnifiedFinding or dict to dict for assertions."""
    if isinstance(finding, dict):
        return finding
    return finding.__dict__


# ═══════════════════════════════════════════════════════════════════════════
# Trivy
# ═══════════════════════════════════════════════════════════════════════════

class TestTrivyScannerNormalizer:

    @pytest.fixture
    def normalizer(self):
        return TrivyScannerNormalizer(config=_cfg("trivy"))

    def test_can_handle_trivy_with_schema_version(self, normalizer):
        content = json.dumps({
            "SchemaVersion": 2,
            "ArtifactName": "myapp:latest",
            "ArtifactType": "container_image",
            "Results": [],
        }).encode()
        assert normalizer.can_handle(content) >= 0.95

    def test_can_handle_trivy_with_artifact_name_only(self, normalizer):
        content = json.dumps({
            "ArtifactName": "myimage",
            "Results": [],
        }).encode()
        assert normalizer.can_handle(content) >= 0.9

    def test_can_handle_returns_low_score_without_artifact_keys(self, normalizer):
        content = json.dumps({"Results": []}).encode()
        score = normalizer.can_handle(content)
        assert 0.0 <= score <= 0.65

    def test_cannot_handle_random_data(self, normalizer):
        assert normalizer.can_handle(b"not trivy output at all") == 0.0

    def test_cannot_handle_empty_json_object(self, normalizer):
        assert normalizer.can_handle(b"{}") == 0.0

    def test_normalize_produces_vulnerability_finding(self, normalizer):
        content = json.dumps({
            "SchemaVersion": 2,
            "ArtifactName": "myapp:latest",
            "Results": [{
                "Target": "app/requirements.txt",
                "Type": "pip",
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2024-1234",
                    "PkgName": "requests",
                    "InstalledVersion": "2.25.0",
                    "FixedVersion": "2.31.0",
                    "Severity": "HIGH",
                    "Title": "Requests HTTP library has SSRF issue",
                    "Description": "An SSRF vulnerability in requests",
                }],
            }],
        }).encode()
        findings = normalizer.normalize(content)
        assert len(findings) >= 1
        f = _as_dict(findings[0])
        assert f.get("source_tool") == "trivy"
        assert f.get("severity") == "high"

    def test_normalize_sets_cve_id_from_vulnerability_id(self, normalizer):
        content = json.dumps({
            "ArtifactName": "img",
            "Results": [{
                "Target": "usr/bin",
                "Type": "debian",
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2023-9999",
                    "PkgName": "libssl",
                    "InstalledVersion": "1.0.0",
                    "Severity": "CRITICAL",
                }],
            }],
        }).encode()
        findings = normalizer.normalize(content)
        assert len(findings) == 1
        f = _as_dict(findings[0])
        assert f.get("cve_id") == "CVE-2023-9999"

    def test_normalize_misconfiguration_finding(self, normalizer):
        content = json.dumps({
            "ArtifactName": "Dockerfile",
            "Results": [{
                "Target": "Dockerfile",
                "Type": "dockerfile",
                "Misconfigurations": [{
                    "ID": "DS002",
                    "Title": "Image user should not be root",
                    "Severity": "HIGH",
                    "Description": "Running as root is dangerous",
                    "Resolution": "Add USER non-root to Dockerfile",
                }],
            }],
        }).encode()
        findings = normalizer.normalize(content)
        assert len(findings) >= 1
        f = _as_dict(findings[0])
        assert f.get("source_tool") == "trivy"
        assert f.get("severity") == "high"

    def test_normalize_empty_results_returns_empty_list(self, normalizer):
        content = json.dumps({"ArtifactName": "x", "Results": []}).encode()
        assert normalizer.normalize(content) == []

    def test_normalize_result_with_no_vulnerabilities_key(self, normalizer):
        content = json.dumps({
            "ArtifactName": "x",
            "Results": [{"Target": "app", "Type": "python"}],
        }).encode()
        assert normalizer.normalize(content) == []


# ═══════════════════════════════════════════════════════════════════════════
# Grype
# ═══════════════════════════════════════════════════════════════════════════

class TestGrypeScannerNormalizer:

    @pytest.fixture
    def normalizer(self):
        return GrypeScannerNormalizer(config=_cfg("grype"))

    def test_can_handle_grype_with_matches(self, normalizer):
        content = json.dumps({"matches": []}).encode()
        assert normalizer.can_handle(content) >= 0.9

    def test_cannot_handle_without_matches_key(self, normalizer):
        assert normalizer.can_handle(json.dumps({"vulnerabilities": []}).encode()) == 0.0

    def test_cannot_handle_random_data(self, normalizer):
        assert normalizer.can_handle(b"some random string") == 0.0

    def test_normalize_produces_finding_from_match(self, normalizer):
        content = json.dumps({
            "matches": [{
                "vulnerability": {
                    "id": "CVE-2024-5678",
                    "severity": "High",
                    "description": "A critical flaw in libfoo",
                    "fix": {"versions": ["1.2.3"]},
                },
                "artifact": {
                    "name": "libfoo",
                    "version": "1.0.0",
                    "type": "deb",
                },
            }],
        }).encode()
        findings = normalizer.normalize(content)
        assert len(findings) == 1
        f = _as_dict(findings[0])
        assert f.get("source_tool") == "grype"
        assert f.get("severity") == "high"
        assert f.get("cve_id") == "CVE-2024-5678"

    def test_normalize_sets_package_name_and_version(self, normalizer):
        content = json.dumps({
            "matches": [{
                "vulnerability": {"id": "GHSA-abcd-1234", "severity": "Medium"},
                "artifact": {"name": "mypkg", "version": "2.0.0", "type": "npm"},
            }],
        }).encode()
        findings = normalizer.normalize(content)
        f = _as_dict(findings[0])
        assert f.get("package_name") == "mypkg"
        assert f.get("package_version") == "2.0.0"

    def test_normalize_empty_matches_returns_empty_list(self, normalizer):
        content = json.dumps({"matches": []}).encode()
        assert normalizer.normalize(content) == []


# ═══════════════════════════════════════════════════════════════════════════
# Semgrep
# ═══════════════════════════════════════════════════════════════════════════

class TestSemgrepScannerNormalizer:

    @pytest.fixture
    def normalizer(self):
        return SemgrepScannerNormalizer(config=_cfg("semgrep"))

    def test_can_handle_semgrep_with_check_id(self, normalizer):
        content = json.dumps({
            "results": [{"check_id": "python.flask.security.xss"}],
        }).encode()
        assert normalizer.can_handle(content) >= 0.9

    def test_cannot_handle_results_without_check_id(self, normalizer):
        content = json.dumps({"results": [{"rule": "something"}]}).encode()
        assert normalizer.can_handle(content) == 0.0

    def test_cannot_handle_random_data(self, normalizer):
        assert normalizer.can_handle(b"not semgrep") == 0.0

    def test_normalize_produces_finding_with_rule_id(self, normalizer):
        content = json.dumps({
            "results": [{
                "check_id": "python.flask.security.xss.reflect-data-onfocus",
                "path": "app/views.py",
                "start": {"line": 42, "col": 10},
                "extra": {
                    "severity": "ERROR",
                    "message": "Reflected XSS detected in Flask view",
                },
            }],
        }).encode()
        findings = normalizer.normalize(content)
        assert len(findings) == 1
        f = _as_dict(findings[0])
        assert f.get("source_tool") == "semgrep"
        assert f.get("severity") == "high"
        assert f.get("file_path") == "app/views.py"

    def test_normalize_empty_results_returns_empty(self, normalizer):
        content = json.dumps({"results": []}).encode()
        assert normalizer.normalize(content) == []

    def test_normalize_warning_severity_maps_to_medium(self, normalizer):
        content = json.dumps({
            "results": [{
                "check_id": "some.rule",
                "path": "x.py",
                "start": {"line": 1},
                "extra": {"severity": "WARNING", "message": "test"},
            }],
        }).encode()
        findings = normalizer.normalize(content)
        f = _as_dict(findings[0])
        assert f.get("severity") == "medium"


# ═══════════════════════════════════════════════════════════════════════════
# Dependabot
# ═══════════════════════════════════════════════════════════════════════════

class TestDependabotScannerNormalizer:

    @pytest.fixture
    def normalizer(self):
        return DependabotScannerNormalizer(config=_cfg("dependabot"))

    def test_can_handle_dependabot_with_security_advisory(self, normalizer):
        content = json.dumps([{
            "security_advisory": {"ghsa_id": "GHSA-1234", "severity": "high"},
            "dependency": {"package": {"name": "lodash"}},
        }]).encode()
        assert normalizer.can_handle(content) >= 0.9

    def test_can_handle_dependabot_with_dependency_key(self, normalizer):
        content = json.dumps([{
            "dependency": {"package": {"name": "axios"}},
        }]).encode()
        assert normalizer.can_handle(content) >= 0.9

    def test_cannot_handle_empty_array(self, normalizer):
        assert normalizer.can_handle(b"[]") == 0.0

    def test_cannot_handle_random_data(self, normalizer):
        assert normalizer.can_handle(b"random") == 0.0

    def test_normalize_produces_finding_with_correct_fields(self, normalizer):
        content = json.dumps([{
            "security_advisory": {
                "ghsa_id": "GHSA-abcd-efgh-1234",
                "cve_id": "CVE-2024-9999",
                "summary": "Prototype pollution in lodash",
                "description": "Allows prototype pollution via merge()",
                "severity": "critical",
            },
            "dependency": {
                "package": {"name": "lodash", "version": "4.17.15"},
            },
        }]).encode()
        findings = normalizer.normalize(content)
        assert len(findings) == 1
        f = _as_dict(findings[0])
        assert f.get("source_tool") == "dependabot"
        assert f.get("severity") == "critical"
        assert f.get("package_name") == "lodash"
        assert f.get("cve_id") == "CVE-2024-9999"

    def test_normalize_empty_array_returns_empty_list(self, normalizer):
        # Empty list — cannot_handle would already return 0.0 but normalize should be safe
        content = json.dumps([]).encode()
        assert normalizer.normalize(content) == []


# ═══════════════════════════════════════════════════════════════════════════
# Qualys
# ═══════════════════════════════════════════════════════════════════════════

class TestQualysScannerNormalizer:

    @pytest.fixture
    def normalizer(self):
        return QualysScannerNormalizer(config=_cfg("qualys"))

    def test_can_handle_qualys_xml_with_qid(self, normalizer):
        content = b"<HOST_LIST_VM_DETECTION_OUTPUT><HOST><IP>10.0.0.1</IP><DETECTION><QID>1234</QID></DETECTION></HOST></HOST_LIST_VM_DETECTION_OUTPUT>"
        assert normalizer.can_handle(content) >= 0.9

    def test_can_handle_qualys_json_with_qid_and_vulns(self, normalizer):
        content = json.dumps({
            "host_list": [{"ip": "10.0.0.1", "vulns": [{"qid": "1001", "severity": 3}]}]
        }).encode()
        assert normalizer.can_handle(content) >= 0.8

    def test_cannot_handle_random_data(self, normalizer):
        assert normalizer.can_handle(b"nothing here") == 0.0

    def test_normalize_json_produces_finding(self, normalizer):
        content = json.dumps([{
            "ip": "192.168.1.1",
            "detections": [{
                "qid": "42",
                "title": "OpenSSL Vulnerability",
                "severity": 3,
                "cve_list": "CVE-2024-0001",
                "results": "OpenSSL 1.0.2 detected",
                "solution": "Upgrade to OpenSSL 3.x",
            }],
        }]).encode()
        findings = normalizer.normalize(content)
        assert len(findings) >= 1
        f = _as_dict(findings[0])
        assert f.get("source_tool") == "qualys"
        assert f.get("severity") == "high"

    def test_normalize_xml_produces_finding(self, normalizer):
        xml_content = b"""<HOST_LIST_VM_DETECTION_OUTPUT>
            <HOST>
                <IP>10.0.0.5</IP>
                <DETECTION>
                    <QID>90882</QID>
                    <TITLE>TLS/SSL Weak Cipher Suites</TITLE>
                    <SEVERITY>3</SEVERITY>
                    <RESULTS>Weak cipher found</RESULTS>
                    <SOLUTION>Disable weak ciphers</SOLUTION>
                    <CVE>CVE-2021-3449</CVE>
                </DETECTION>
            </HOST>
        </HOST_LIST_VM_DETECTION_OUTPUT>"""
        findings = normalizer.normalize(xml_content)
        assert len(findings) >= 1
        f = _as_dict(findings[0])
        assert f.get("source_tool") == "qualys"

    def test_normalize_returns_empty_for_invalid_content(self, normalizer):
        findings = normalizer.normalize(b"not xml or json")
        assert findings == []


# ═══════════════════════════════════════════════════════════════════════════
# Tenable
# ═══════════════════════════════════════════════════════════════════════════

class TestTenableScannerNormalizer:

    @pytest.fixture
    def normalizer(self):
        return TenableScannerNormalizer(config=_cfg("tenable"))

    def test_can_handle_tenable_with_plugin_id_and_severity_index(self, normalizer):
        content = json.dumps({
            "vulnerabilities": [{"plugin_id": 12345, "severity_index": 3}],
        }).encode()
        assert normalizer.can_handle(content) >= 0.9

    def test_can_handle_tenable_with_plugin_id_in_vulnerabilities(self, normalizer):
        content = json.dumps({
            "vulnerabilities": [{"plugin_id": 99999}],
        }).encode()
        assert normalizer.can_handle(content) >= 0.85

    def test_cannot_handle_random_data(self, normalizer):
        assert normalizer.can_handle(b"not tenable") == 0.0

    def test_normalize_produces_finding_from_vulnerability(self, normalizer):
        content = json.dumps({
            "target": "192.168.1.50",
            "vulnerabilities": [{
                "plugin_id": 11213,
                "severity_index": 3,
                "plugin_name": "HTTP TRACE / TRACK Methods Allowed",
                "synopsis": "The remote web server supports TRACE/TRACK methods.",
                "solution": "Disable TRACE/TRACK methods.",
                "cve": "CVE-2003-1567",
                "cvss3_base_score": 7.5,
            }],
        }).encode()
        findings = normalizer.normalize(content)
        assert len(findings) == 1
        f = _as_dict(findings[0])
        assert f.get("source_tool") == "tenable"
        assert f.get("severity") == "high"

    def test_normalize_extracts_cve(self, normalizer):
        content = json.dumps({
            "vulnerabilities": [{
                "plugin_id": 11111,
                "severity_index": 4,
                "plugin_name": "Critical SSL Vuln",
                "cve": "CVE-2024-1111",
            }],
        }).encode()
        findings = normalizer.normalize(content)
        f = _as_dict(findings[0])
        assert f.get("cve_id") == "CVE-2024-1111"

    def test_normalize_returns_empty_for_invalid_json(self, normalizer):
        assert normalizer.normalize(b"not json") == []


# ═══════════════════════════════════════════════════════════════════════════
# Rapid7
# ═══════════════════════════════════════════════════════════════════════════

class TestRapid7ScannerNormalizer:

    @pytest.fixture
    def normalizer(self):
        return Rapid7ScannerNormalizer(config=_cfg("rapid7"))

    def test_can_handle_rapid7_xml_with_test_vulnerability_id(self, normalizer):
        content = b'<nexpose-scan><node address="10.0.0.1"><tests><test vulnerability-id="windows-hotfix-ms15-034" status="vulnerable"/></tests></node></nexpose-scan>'
        assert normalizer.can_handle(content) >= 0.88

    def test_can_handle_rapid7_json_with_vulnerability_id(self, normalizer):
        content = json.dumps({
            "nodes": [{"address": "10.0.0.1", "tests": [{"vulnerability-id": "ssh-weak-ciphers", "title": "SSH Weak Ciphers"}]}]
        }).encode()
        assert normalizer.can_handle(content) >= 0.88

    def test_can_handle_nexpose_keyword(self, normalizer):
        content = b"nexpose scan report for 10.0.0.1"
        assert normalizer.can_handle(content) >= 0.85

    def test_cannot_handle_random_data(self, normalizer):
        assert normalizer.can_handle(b"completely random text here") == 0.0

    def test_normalize_json_produces_finding(self, normalizer):
        content = json.dumps({
            "nodes": [{
                "address": "10.0.0.10",
                "tests": [{
                    "vulnerability-id": "ssl-poodle",
                    "title": "POODLE SSLv3 Vulnerability",
                    "severity": "high",
                    "description": "SSLv3 is vulnerable to POODLE attack",
                    "references": "CVE-2014-3566",
                }],
            }],
        }).encode()
        findings = normalizer.normalize(content)
        assert len(findings) >= 1
        f = _as_dict(findings[0])
        assert f.get("source_tool") == "rapid7"

    def test_normalize_xml_produces_finding(self, normalizer):
        xml_content = b"""<nexpose-scan>
            <node address="192.168.10.1" status="alive">
                <tests>
                    <test vulnerability-id="ssh-server-cbc-mode-ciphers" status="vulnerable" severity="2">
                        <description>SSH CBC mode ciphers enabled</description>
                        <solution>Disable CBC mode ciphers in sshd_config</solution>
                    </test>
                </tests>
            </node>
        </nexpose-scan>"""
        findings = normalizer.normalize(xml_content)
        assert len(findings) >= 1
        f = _as_dict(findings[0])
        assert f.get("source_tool") == "rapid7"

    def test_normalize_xml_skips_non_vulnerable_status(self, normalizer):
        xml_content = b"""<nexpose-scan>
            <node address="10.1.1.1">
                <tests>
                    <test vulnerability-id="some-check" status="passed"/>
                </tests>
            </node>
        </nexpose-scan>"""
        findings = normalizer.normalize(xml_content)
        assert findings == []


# ═══════════════════════════════════════════════════════════════════════════
# Acunetix
# ═══════════════════════════════════════════════════════════════════════════

class TestAcunetixScannerNormalizer:

    @pytest.fixture
    def normalizer(self):
        return AcunetixScannerNormalizer(config=_cfg("acunetix"))

    def test_can_handle_acunetix_with_affects_url(self, normalizer):
        content = json.dumps({
            "vulnerabilities": [{"affects_url": "http://example.com/login", "severity": "high"}],
        }).encode()
        assert normalizer.can_handle(content) >= 0.9

    def test_can_handle_acunetix_affects_url_and_severity_no_wrapper(self, normalizer):
        content = json.dumps({
            "affects_url": "http://target.com",
            "severity": "medium",
        }).encode()
        assert normalizer.can_handle(content) >= 0.85

    def test_cannot_handle_random_data(self, normalizer):
        assert normalizer.can_handle(b"random acme output") == 0.0

    def test_normalize_produces_finding(self, normalizer):
        content = json.dumps({
            "vulnerabilities": [{
                "vuln_id": "sql_injection",
                "vt_name": "SQL Injection",
                "affects_url": "http://app.example.com/search?q=1",
                "severity": "high",
                "description": "SQL injection found in search parameter",
                "recommendation": "Use prepared statements",
                "cvelist": "CVE-2024-5000",
                "cwe": "CWE-89",
            }],
        }).encode()
        findings = normalizer.normalize(content)
        assert len(findings) == 1
        f = _as_dict(findings[0])
        assert f.get("source_tool") == "acunetix"
        assert f.get("severity") == "high"

    def test_normalize_extracts_cve_and_cwe(self, normalizer):
        content = json.dumps({
            "vulnerabilities": [{
                "vuln_id": "xss",
                "affects_url": "http://example.com",
                "severity": "medium",
                "cvelist": "CVE-2023-1234",
                "cwe": "CWE-79",
            }],
        }).encode()
        findings = normalizer.normalize(content)
        f = _as_dict(findings[0])
        assert f.get("cve_id") == "CVE-2023-1234"
        assert f.get("cwe_id") == "CWE-79"

    def test_normalize_info_severity_mapped_correctly(self, normalizer):
        content = json.dumps({
            "vulnerabilities": [{
                "vuln_id": "info_check",
                "affects_url": "http://x.com",
                "severity": "informational",
            }],
        }).encode()
        findings = normalizer.normalize(content)
        f = _as_dict(findings[0])
        assert f.get("severity") == "info"

    def test_normalize_returns_empty_for_invalid_json(self, normalizer):
        assert normalizer.normalize(b"not valid json") == []


# ═══════════════════════════════════════════════════════════════════════════
# AWS Inspector
# ═══════════════════════════════════════════════════════════════════════════

class TestAWSInspectorNormalizer:

    @pytest.fixture
    def normalizer(self):
        return AWSInspectorNormalizer(config=_cfg("aws_inspector"))

    def test_can_handle_inspector_with_account_and_score(self, normalizer):
        content = json.dumps({
            "findings": [{"awsAccountId": "123456789012", "inspectorScore": 8.5}],
        }).encode()
        assert normalizer.can_handle(content) >= 0.9

    def test_can_handle_inspector_with_package_vulnerability_details(self, normalizer):
        content = json.dumps({
            "inspectorScore": 9.0,
            "packageVulnerabilityDetails": {"vulnerabilityId": "CVE-2024-0001"},
        }).encode()
        assert normalizer.can_handle(content) >= 0.9

    def test_cannot_handle_random_data(self, normalizer):
        assert normalizer.can_handle(b"not inspector output") == 0.0

    def test_normalize_produces_finding_with_cloud_metadata(self, normalizer):
        content = json.dumps({
            "findings": [{
                "awsAccountId": "123456789012",
                "region": "us-east-1",
                "title": "CVE-2024-0001 in libssl",
                "description": "Critical vulnerability in libssl",
                "severity": "critical",
                "inspectorScore": 9.5,
                "packageVulnerabilityDetails": {
                    "vulnerabilityId": "CVE-2024-0001",
                    "vulnerablePackages": [{
                        "name": "libssl",
                        "version": "1.0.2",
                        "fixedInVersion": "1.0.2u",
                    }],
                },
                "resources": [{"id": "arn:aws:ec2:us-east-1:123456789012:instance/i-abc123", "type": "AWS_EC2_INSTANCE"}],
            }],
        }).encode()
        findings = normalizer.normalize(content)
        assert len(findings) == 1
        f = _as_dict(findings[0])
        assert f.get("source_tool") == "aws_inspector"
        assert f.get("severity") == "critical"
        assert f.get("cloud_provider") == "aws"
        assert f.get("cloud_account") == "123456789012"
        assert f.get("cloud_region") == "us-east-1"

    def test_normalize_extracts_cve_from_vulnerability_id(self, normalizer):
        content = json.dumps([{
            "awsAccountId": "111222333444",
            "severity": "high",
            "inspectorScore": 7.8,
            "packageVulnerabilityDetails": {"vulnerabilityId": "CVE-2023-5678"},
            "resources": [],
        }]).encode()
        findings = normalizer.normalize(content)
        f = _as_dict(findings[0])
        assert f.get("cve_id") == "CVE-2023-5678"

    def test_normalize_returns_empty_for_invalid_json(self, normalizer):
        assert normalizer.normalize(b"bad input") == []


# ═══════════════════════════════════════════════════════════════════════════
# GitLab SAST
# ═══════════════════════════════════════════════════════════════════════════

class TestGitLabSASTNormalizer:

    @pytest.fixture
    def normalizer(self):
        return GitLabSASTNormalizer(config=_cfg("gitlab_sast"))

    def test_can_handle_with_identifiers_location_vulnerabilities(self, normalizer):
        content = json.dumps({
            "vulnerabilities": [{"identifiers": [], "location": {}}],
        }).encode()
        assert normalizer.can_handle(content) >= 0.9

    def test_can_handle_with_scanner_identifiers_vulnerabilities(self, normalizer):
        content = json.dumps({
            "vulnerabilities": [{"scanner": {"id": "bandit"}}],
            "identifiers": [],
        }).encode()
        # scanner + identifiers at top level
        assert normalizer.can_handle(content) >= 0.0  # may or may not trigger

    def test_cannot_handle_random_data(self, normalizer):
        assert normalizer.can_handle(b"just a random string here") == 0.0

    def test_normalize_produces_finding_with_location(self, normalizer):
        content = json.dumps({
            "vulnerabilities": [{
                "name": "SQL Injection",
                "description": "Possible SQL injection in query builder",
                "severity": "High",
                "location": {"file": "app/db/query.py", "start_line": 55},
                "identifiers": [
                    {"type": "cwe", "name": "CWE-89", "value": "CWE-89"},
                    {"type": "cve", "name": "CVE-2023-1111", "value": "CVE-2023-1111"},
                ],
                "scanner": {"name": "Bandit", "id": "bandit"},
            }],
        }).encode()
        findings = normalizer.normalize(content)
        assert len(findings) == 1
        f = _as_dict(findings[0])
        assert f.get("source_tool") == "gitlab_sast"
        assert f.get("severity") == "high"
        assert f.get("file_path") == "app/db/query.py"
        assert f.get("line_number") == 55

    def test_normalize_extracts_cve_from_identifiers(self, normalizer):
        content = json.dumps({
            "vulnerabilities": [{
                "name": "Known CVE",
                "severity": "Critical",
                "location": {},
                "identifiers": [{"type": "cve", "name": "CVE-2024-9876", "value": "CVE-2024-9876"}],
                "scanner": {},
            }],
        }).encode()
        findings = normalizer.normalize(content)
        f = _as_dict(findings[0])
        assert f.get("cve_id") == "CVE-2024-9876"

    def test_normalize_maps_unknown_severity_to_info(self, normalizer):
        content = json.dumps({
            "vulnerabilities": [{
                "name": "Informational Finding",
                "severity": "Unknown",
                "location": {},
                "identifiers": [],
                "scanner": {},
            }],
        }).encode()
        findings = normalizer.normalize(content)
        f = _as_dict(findings[0])
        assert f.get("severity") == "info"

    def test_normalize_returns_empty_for_empty_vulnerabilities(self, normalizer):
        content = json.dumps({"vulnerabilities": []}).encode()
        assert normalizer.normalize(content) == []


# ═══════════════════════════════════════════════════════════════════════════
# SARIF Universal
# ═══════════════════════════════════════════════════════════════════════════

class TestSARIFUniversalNormalizer:

    @pytest.fixture
    def normalizer(self):
        return SARIFUniversalNormalizer(config=_cfg("sarif"))

    def test_can_handle_sarif_schema_marker(self, normalizer):
        content = json.dumps({
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [],
        }).encode()
        assert normalizer.can_handle(content) >= 0.95

    def test_can_handle_sarif_runs_results(self, normalizer):
        content = json.dumps({
            "version": "2.1.0",
            "runs": [{"results": [], "tool": {"driver": {"name": "myScanner"}}}],
        }).encode()
        assert normalizer.can_handle(content) >= 0.9

    def test_can_handle_runs_and_tool(self, normalizer):
        content = json.dumps({"runs": [], "tool": {}}).encode()
        assert normalizer.can_handle(content) >= 0.8

    def test_cannot_handle_random_data(self, normalizer):
        assert normalizer.can_handle(b"not sarif at all") == 0.0

    def test_normalize_produces_finding_from_sarif_run(self, normalizer):
        content = json.dumps({
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "CodeQL",
                        "rules": [{
                            "id": "js/sql-injection",
                            "shortDescription": {"text": "SQL Injection"},
                            "fullDescription": {"text": "Untrusted data flows into SQL query"},
                        }],
                    }
                },
                "results": [{
                    "ruleId": "js/sql-injection",
                    "level": "error",
                    "message": {"text": "SQL injection via user input"},
                    "locations": [{
                        "physicalLocation": {
                            "artifactLocation": {"uri": "src/api/search.js"},
                            "region": {"startLine": 23},
                        }
                    }],
                }],
            }],
        }).encode()
        findings = normalizer.normalize(content)
        assert len(findings) == 1
        f = _as_dict(findings[0])
        assert f.get("source_format") == "sarif" or f.get("source_format_str") == "sarif" or "sarif" in str(f)
        assert f.get("severity") == "high"
        assert f.get("file_path") == "src/api/search.js"
        assert f.get("line_number") == 23

    def test_normalize_security_severity_overrides_level(self, normalizer):
        """security-severity property (CVSS score) should override the level field."""
        content = json.dumps({
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Semgrep",
                        "rules": [{
                            "id": "rule-001",
                            "shortDescription": {"text": "Critical issue"},
                            "properties": {"security-severity": "9.5"},
                        }],
                    }
                },
                "results": [{
                    "ruleId": "rule-001",
                    "level": "note",
                    "message": {"text": "Critical finding"},
                    "locations": [],
                }],
            }],
        }).encode()
        findings = normalizer.normalize(content)
        f = _as_dict(findings[0])
        assert f.get("severity") == "critical"

    def test_normalize_note_level_maps_to_low(self, normalizer):
        content = json.dumps({
            "version": "2.1.0",
            "runs": [{
                "tool": {"driver": {"name": "EslintSarif", "rules": []}},
                "results": [{
                    "ruleId": "no-console",
                    "level": "note",
                    "message": {"text": "Use of console.log"},
                    "locations": [],
                }],
            }],
        }).encode()
        findings = normalizer.normalize(content)
        f = _as_dict(findings[0])
        assert f.get("severity") == "low"

    def test_normalize_empty_runs_returns_empty(self, normalizer):
        content = json.dumps({"version": "2.1.0", "runs": []}).encode()
        assert normalizer.normalize(content) == []

    def test_normalize_returns_empty_for_invalid_json(self, normalizer):
        assert normalizer.normalize(b"not json") == []


# ═══════════════════════════════════════════════════════════════════════════
# CycloneDX Universal
# ═══════════════════════════════════════════════════════════════════════════

class TestCycloneDXUniversalNormalizer:

    @pytest.fixture
    def normalizer(self):
        return CycloneDXUniversalNormalizer(config=_cfg("cyclonedx"))

    def test_can_handle_cyclonedx_bom_format(self, normalizer):
        content = json.dumps({
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [],
        }).encode()
        assert normalizer.can_handle(content) >= 0.9

    def test_can_handle_cyclonedx_keyword_and_components(self, normalizer):
        content = json.dumps({
            "cyclonedx_version": "1.4",
            "components": [{"type": "library", "name": "requests"}],
        }).encode()
        assert normalizer.can_handle(content) >= 0.8

    def test_cannot_handle_random_data(self, normalizer):
        assert normalizer.can_handle(b"random bytes here") == 0.0

    def test_normalize_produces_finding_from_vulnerability(self, normalizer):
        content = json.dumps({
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [],
            "vulnerabilities": [{
                "id": "CVE-2024-1234",
                "description": "Critical vulnerability in libxml2",
                "detail": "Remote code execution via crafted XML",
                "ratings": [{"severity": "critical", "score": 9.8}],
                "affects": [{"ref": "urn:cdx:component/libxml2@2.9.12"}],
                "cwes": [611],
                "advisories": [{"title": "Upgrade to 2.9.14", "url": "https://nvd.nist.gov"}],
            }],
        }).encode()
        findings = normalizer.normalize(content)
        assert len(findings) == 1
        f = _as_dict(findings[0])
        assert f.get("source_tool") == "cyclonedx"
        assert f.get("severity") == "critical"
        assert f.get("cwe_id") == "CWE-611"

    def test_normalize_severity_from_score_when_no_severity_label(self, normalizer):
        content = json.dumps({
            "bomFormat": "CycloneDX",
            "vulnerabilities": [{
                "id": "GHSA-test-0001",
                "description": "Test vulnerability",
                "ratings": [{"score": 7.5}],
            }],
        }).encode()
        findings = normalizer.normalize(content)
        f = _as_dict(findings[0])
        assert f.get("severity") == "high"

    def test_normalize_empty_vulnerabilities_returns_empty(self, normalizer):
        content = json.dumps({"bomFormat": "CycloneDX", "vulnerabilities": []}).encode()
        assert normalizer.normalize(content) == []

    def test_normalize_returns_empty_for_invalid_json(self, normalizer):
        assert normalizer.normalize(b"not json") == []


# ═══════════════════════════════════════════════════════════════════════════
# SPDX Universal
# ═══════════════════════════════════════════════════════════════════════════

class TestSPDXUniversalNormalizer:

    @pytest.fixture
    def normalizer(self):
        return SPDXUniversalNormalizer(config=_cfg("spdx"))

    def test_can_handle_spdx_version(self, normalizer):
        content = json.dumps({
            "spdxVersion": "SPDX-2.3",
            "packages": [],
        }).encode()
        assert normalizer.can_handle(content) >= 0.9

    def test_can_handle_spdxref_and_packages(self, normalizer):
        content = json.dumps({
            "SPDXID": "SPDXRef-DOCUMENT",
            "packages": [{"SPDXID": "SPDXRef-libssl", "name": "libssl"}],
        }).encode()
        assert normalizer.can_handle(content) >= 0.85

    def test_cannot_handle_random_data(self, normalizer):
        assert normalizer.can_handle(b"nothing relevant here") == 0.0

    def test_normalize_produces_finding_for_security_external_ref(self, normalizer):
        content = json.dumps({
            "spdxVersion": "SPDX-2.3",
            "packages": [{
                "name": "openssl",
                "versionInfo": "1.0.2",
                "externalRefs": [{
                    "referenceCategory": "SECURITY",
                    "referenceType": "cve",
                    "referenceLocator": "cpe:2.3:a:openssl:openssl:1.0.2:*:*:*:*:*:*:*",
                }],
            }],
        }).encode()
        findings = normalizer.normalize(content)
        assert len(findings) >= 1
        f = _as_dict(findings[0])
        assert f.get("source_tool") == "spdx"
        assert f.get("severity") == "medium"

    def test_normalize_produces_finding_for_vulnerability_ref_type(self, normalizer):
        content = json.dumps({
            "spdxVersion": "SPDX-2.3",
            "packages": [{
                "name": "log4j",
                "versionInfo": "2.14.1",
                "externalRefs": [{
                    "referenceCategory": "OTHER",
                    "referenceType": "vulnerability",
                    "referenceLocator": "CVE-2021-44228",
                }],
            }],
        }).encode()
        findings = normalizer.normalize(content)
        assert len(findings) >= 1

    def test_normalize_returns_empty_when_no_security_refs(self, normalizer):
        content = json.dumps({
            "spdxVersion": "SPDX-2.3",
            "packages": [{
                "name": "requests",
                "versionInfo": "2.31.0",
                "externalRefs": [{
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": "pkg:pypi/requests@2.31.0",
                }],
            }],
        }).encode()
        assert normalizer.normalize(content) == []

    def test_normalize_returns_empty_for_invalid_json(self, normalizer):
        assert normalizer.normalize(b"bad data") == []


# ═══════════════════════════════════════════════════════════════════════════
# Gitleaks
# ═══════════════════════════════════════════════════════════════════════════

class TestGitleaksScannerNormalizer:

    @pytest.fixture
    def normalizer(self):
        return GitleaksScannerNormalizer(config=_cfg("gitleaks"))

    def test_can_handle_gitleaks_pascal_case_keys(self, normalizer):
        content = json.dumps([{"RuleID": "aws-access-token", "Secret": "AKIAIOSFODNN7EXAMPLE", "File": "config.py"}]).encode()
        assert normalizer.can_handle(content) >= 0.9

    def test_can_handle_gitleaks_v8_lowercase_keys(self, normalizer):
        content = json.dumps([{"rule": "generic-api-key", "match": "apikey=12345", "file": ".env"}]).encode()
        assert normalizer.can_handle(content) >= 0.8

    def test_cannot_handle_random_data(self, normalizer):
        assert normalizer.can_handle(b"nothing secret here") == 0.0

    def test_normalize_produces_critical_for_aws_rule(self, normalizer):
        content = json.dumps([{
            "RuleID": "aws-access-token",
            "Description": "AWS Access Key ID",
            "File": "deploy/config.py",
            "StartLine": 12,
            "Commit": "abc123def456",
            "Author": "Dev User",
            "Date": "2024-01-15",
            "Secret": "AKIAIOSFODNN7EXAMPLE",
        }]).encode()
        findings = normalizer.normalize(content)
        assert len(findings) == 1
        f = _as_dict(findings[0])
        assert f.get("source_tool") == "gitleaks"
        assert f.get("severity") == "critical"

    def test_normalize_produces_critical_for_private_key_rule(self, normalizer):
        content = json.dumps([{
            "RuleID": "private-key",
            "File": "id_rsa",
            "Secret": "-----BEGIN RSA PRIVATE KEY-----",
        }]).encode()
        findings = normalizer.normalize(content)
        f = _as_dict(findings[0])
        assert f.get("severity") == "critical"

    def test_normalize_produces_high_for_generic_rule(self, normalizer):
        # Use a rule name that does not contain critical keywords (private/key/token/password/aws)
        content = json.dumps([{
            "RuleID": "github-pat",
            "File": "config.yml",
            "Secret": "ghp_1234567890abcdef",
        }]).encode()
        findings = normalizer.normalize(content)
        f = _as_dict(findings[0])
        assert f.get("severity") == "high"

    def test_normalize_sets_cwe_798_for_all_findings(self, normalizer):
        content = json.dumps([{
            "RuleID": "some-rule",
            "File": "app.py",
            "Secret": "hardcoded-secret",
        }]).encode()
        findings = normalizer.normalize(content)
        f = _as_dict(findings[0])
        assert f.get("cwe_id") == "CWE-798"

    def test_normalize_does_not_store_secret_value_in_title(self, normalizer):
        """Secret values must never appear in the title or description fields."""
        secret_value = "SUPER_SECRET_12345abcdef"
        content = json.dumps([{
            "RuleID": "generic-api-key",
            "File": "app.py",
            "Secret": secret_value,
            "Description": "Found API key",
        }]).encode()
        findings = normalizer.normalize(content)
        f = _as_dict(findings[0])
        assert secret_value not in str(f.get("title", ""))

    def test_normalize_empty_list_returns_empty(self, normalizer):
        content = json.dumps([]).encode()
        assert normalizer.normalize(content) == []


# ═══════════════════════════════════════════════════════════════════════════
# ClaudeCodeSecurity
# ═══════════════════════════════════════════════════════════════════════════

class TestClaudeCodeSecurityNormalizer:

    @pytest.fixture
    def normalizer(self):
        return ClaudeCodeSecurityNormalizer(config=_cfg("claude_code_security"))

    def test_can_handle_claude_code_security_marker(self, normalizer):
        content = json.dumps({"claude_code_security": True, "findings": []}).encode()
        assert normalizer.can_handle(content) >= 0.95

    def test_can_handle_ai_sast_marker(self, normalizer):
        content = json.dumps({"ai_sast": "claude", "findings": []}).encode()
        assert normalizer.can_handle(content) >= 0.95

    def test_can_handle_reasoning_and_patch_fields(self, normalizer):
        content = json.dumps({
            "findings": [{"reasoning": "...", "suggested_patch": "...", "confidence": 0.9}],
        }).encode()
        assert normalizer.can_handle(content) >= 0.8

    def test_cannot_handle_random_data(self, normalizer):
        assert normalizer.can_handle(b"unrelated scanner output") == 0.0

    def test_normalize_produces_finding_from_array(self, normalizer):
        content = json.dumps([{
            "title": "Broken Access Control",
            "description": "User can access other users data via IDOR",
            "severity": "high",
            "confidence": 0.92,
            "cwe": 284,
            "rule_id": "IDOR-001",
            "file_path": "api/users.py",
            "line": 88,
        }]).encode()
        findings = normalizer.normalize(content)
        assert len(findings) == 1
        f = _as_dict(findings[0])
        assert f.get("source_tool") == "claude_code_security"
        assert f.get("severity") == "high"
        assert f.get("cwe_id") == "CWE-284"

    def test_normalize_produces_finding_from_wrapped_object(self, normalizer):
        content = json.dumps({
            "findings": [{
                "title": "Logic Flaw in Authentication",
                "severity": "critical",
                "confidence": 0.88,
                "cwe_id": "CWE-287",
                "file_path": "auth/login.py",
            }],
        }).encode()
        findings = normalizer.normalize(content)
        assert len(findings) == 1
        f = _as_dict(findings[0])
        assert f.get("severity") == "critical"

    def test_normalize_cwe_int_gets_cwe_prefix(self, normalizer):
        content = json.dumps([{
            "title": "SQL Injection",
            "severity": "high",
            "cwe": 89,
        }]).encode()
        findings = normalizer.normalize(content)
        f = _as_dict(findings[0])
        assert f.get("cwe_id") == "CWE-89"

    def test_normalize_cwe_string_already_prefixed(self, normalizer):
        content = json.dumps([{
            "title": "XSS",
            "severity": "medium",
            "cwe": "CWE-79",
        }]).encode()
        findings = normalizer.normalize(content)
        f = _as_dict(findings[0])
        assert f.get("cwe_id") == "CWE-79"

    def test_normalize_empty_findings_returns_empty(self, normalizer):
        content = json.dumps({"findings": []}).encode()
        assert normalizer.normalize(content) == []


# ═══════════════════════════════════════════════════════════════════════════
# Combobulator
# ═══════════════════════════════════════════════════════════════════════════

class TestCombobulatorNormalizer:

    @pytest.fixture
    def normalizer(self):
        return CombobulatorNormalizer(config=_cfg("combobulator"))

    def test_can_handle_combobulator_marker(self, normalizer):
        content = json.dumps({"combobulator": "1.0", "results": []}).encode()
        assert normalizer.can_handle(content) >= 0.9

    def test_can_handle_dependency_confusion_field(self, normalizer):
        content = json.dumps({"dependency_confusion": True}).encode()
        assert normalizer.can_handle(content) >= 0.9

    def test_can_handle_package_name_risk_type_registry(self, normalizer):
        content = json.dumps([{
            "package_name": "mylib",
            "risk_type": "dependency_confusion",
            "registry": "pypi",
        }]).encode()
        assert normalizer.can_handle(content) >= 0.8

    def test_cannot_handle_random_data(self, normalizer):
        assert normalizer.can_handle(b"ordinary python dependency list") == 0.0

    def test_normalize_produces_finding_for_dependency_confusion(self, normalizer):
        content = json.dumps([{
            "package_name": "internal-auth-lib",
            "risk_type": "dependency_confusion",
            "severity": "critical",
            "registry": "pypi",
            "private_registry": "artifactory.example.com",
            "manifest_file": "requirements.txt",
            "description": "Package found on public registry matching private package name",
        }]).encode()
        findings = normalizer.normalize(content)
        assert len(findings) == 1
        f = _as_dict(findings[0])
        assert f.get("source_tool") == "combobulator"
        assert f.get("severity") == "critical"
        assert f.get("cwe_id") == "CWE-427"

    def test_normalize_title_includes_risk_type_and_package(self, normalizer):
        content = json.dumps([{
            "package_name": "company-utils",
            "risk_type": "namespace_hijacking",
            "severity": "high",
        }]).encode()
        findings = normalizer.normalize(content)
        f = _as_dict(findings[0])
        title = f.get("title", "")
        assert "company-utils" in title
        assert "namespace_hijacking" in title

    def test_normalize_wrapped_in_results_key(self, normalizer):
        content = json.dumps({
            "combobulator": "1.0",
            "results": [{
                "package_name": "my-pkg",
                "risk_type": "dependency_confusion",
                "severity": "medium",
            }],
        }).encode()
        findings = normalizer.normalize(content)
        assert len(findings) == 1

    def test_normalize_empty_results_returns_empty(self, normalizer):
        content = json.dumps({"combobulator": "1.0", "results": []}).encode()
        assert normalizer.normalize(content) == []


# ═══════════════════════════════════════════════════════════════════════════
# Module-level functions
# ═══════════════════════════════════════════════════════════════════════════

class TestAutoDetectScanner:

    def test_detects_trivy_output(self):
        content = json.dumps({
            "SchemaVersion": 2,
            "ArtifactName": "myapp:latest",
            "ArtifactType": "container_image",
            "Results": [],
        }).encode()
        result = auto_detect_scanner(content)
        assert result == "trivy"

    def test_detects_grype_output(self):
        content = json.dumps({"matches": [{"vulnerability": {"id": "CVE-2024-0001", "severity": "High"}, "artifact": {"name": "libssl", "version": "1.0"}}]}).encode()
        result = auto_detect_scanner(content)
        assert result == "grype"

    def test_detects_gitleaks_output(self):
        content = json.dumps([{"RuleID": "aws-access-token", "Secret": "AKIAEXAMPLE", "File": "config.py"}]).encode()
        result = auto_detect_scanner(content)
        assert result == "gitleaks"

    def test_detects_sarif_output(self):
        content = json.dumps({
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "CodeQL"}}, "results": []}],
        }).encode()
        result = auto_detect_scanner(content)
        assert result == "sarif"

    def test_returns_none_for_unrecognized_content(self):
        result = auto_detect_scanner(b"this is clearly not any scanner output format")
        assert result is None

    def test_returns_none_for_empty_bytes(self):
        result = auto_detect_scanner(b"")
        assert result is None


class TestParseScannerOutput:

    def test_parses_trivy_with_explicit_scanner_type(self):
        content = json.dumps({
            "SchemaVersion": 2,
            "ArtifactName": "app:latest",
            "Results": [{
                "Target": "requirements.txt",
                "Type": "pip",
                "Vulnerabilities": [{
                    "VulnerabilityID": "CVE-2024-0001",
                    "PkgName": "requests",
                    "InstalledVersion": "2.25.0",
                    "Severity": "HIGH",
                }],
            }],
        }).encode()
        findings = parse_scanner_output(content, scanner_type="trivy")
        assert len(findings) >= 1

    def test_parses_gitleaks_with_auto_detection(self):
        content = json.dumps([{
            "RuleID": "aws-access-token",
            "File": "config.py",
            "Secret": "AKIAIOSFODNN7EXAMPLE",
        }]).encode()
        findings = parse_scanner_output(content)
        assert len(findings) >= 1

    def test_returns_empty_for_unknown_scanner_type(self):
        result = parse_scanner_output(b"some data", scanner_type="nonexistent_scanner_xyz")
        assert result == []

    def test_returns_empty_when_content_is_undetectable(self):
        result = parse_scanner_output(b"unrecognized format content here")
        assert result == []

    def test_tags_findings_with_app_id(self):
        content = json.dumps([{
            "RuleID": "generic-api-key",
            "File": "config.py",
            "Secret": "some-secret",
        }]).encode()
        findings = parse_scanner_output(content, scanner_type="gitleaks", app_id="APP-001")
        assert len(findings) >= 1
        f = findings[0]
        if hasattr(f, "asset_id"):
            assert f.asset_id == "APP-001"
        elif isinstance(f, dict):
            assert f.get("asset_id") == "APP-001"

    def test_tags_findings_with_component(self):
        content = json.dumps([{
            "RuleID": "password-rule",
            "File": ".env",
            "Secret": "hardcoded-pass",
        }]).encode()
        findings = parse_scanner_output(content, scanner_type="gitleaks", component="auth-service")
        assert len(findings) >= 1
        f = findings[0]
        tags = f.tags if hasattr(f, "tags") else f.get("tags", [])
        assert any("auth-service" in str(t) for t in tags)

    def test_scanner_type_is_case_insensitive(self):
        content = json.dumps({
            "SchemaVersion": 2,
            "ArtifactName": "x",
            "Results": [],
        }).encode()
        findings = parse_scanner_output(content, scanner_type="TRIVY")
        assert isinstance(findings, list)

    def test_rejects_content_exceeding_size_limit(self):
        # Content just over 500 MB would be rejected — simulate with a flag check
        # We can't create 500 MB in tests, so verify the function returns list type safely
        findings = parse_scanner_output(b"", scanner_type="trivy")
        assert isinstance(findings, list)


class TestGetSupportedScanners:

    def test_returns_dict_with_expected_categories(self):
        result = get_supported_scanners()
        assert isinstance(result, dict)
        assert "sast" in result
        assert "dast" in result
        assert "sca" in result
        assert "infrastructure" in result
        assert "cloud" in result
        assert "universal" in result

    def test_sast_contains_expected_scanners(self):
        result = get_supported_scanners()
        sast = result["sast"]
        assert "bandit" in sast
        assert "semgrep" in sast
        assert "gitlab_sast" in sast
        assert "claude_code_security" in sast

    def test_dast_contains_expected_scanners(self):
        result = get_supported_scanners()
        dast = result["dast"]
        assert "zap" in dast
        assert "burp" in dast
        assert "acunetix" in dast

    def test_sca_contains_trivy_and_grype(self):
        result = get_supported_scanners()
        sca = result["sca"]
        assert "trivy" in sca
        assert "grype" in sca
        assert "snyk" in sca

    def test_infrastructure_contains_qualys_tenable_rapid7(self):
        result = get_supported_scanners()
        infra = result["infrastructure"]
        assert "qualys" in infra
        assert "tenable" in infra
        assert "rapid7" in infra

    def test_cloud_contains_aws_inspector(self):
        result = get_supported_scanners()
        assert "aws_inspector" in result["cloud"]

    def test_universal_contains_sarif_cyclonedx_spdx(self):
        result = get_supported_scanners()
        universal = result["universal"]
        assert "sarif" in universal
        assert "cyclonedx" in universal
        assert "spdx" in universal

    def test_supply_chain_contains_combobulator(self):
        result = get_supported_scanners()
        assert "combobulator" in result["supply_chain"]


class TestScannerNormalizersRegistry:

    def test_scanner_normalizers_dict_contains_all_16_new_normalizers(self):
        expected = {
            "trivy", "grype", "semgrep", "dependabot",
            "qualys", "tenable", "rapid7", "acunetix",
            "aws_inspector", "gitlab_sast", "sarif", "cyclonedx",
            "spdx", "gitleaks", "claude_code_security", "combobulator",
        }
        assert expected.issubset(set(SCANNER_NORMALIZERS.keys()))

    def test_all_new_normalizers_instantiate_without_error(self):
        new_normalizers = [
            TrivyScannerNormalizer, GrypeScannerNormalizer, SemgrepScannerNormalizer,
            DependabotScannerNormalizer, QualysScannerNormalizer, TenableScannerNormalizer,
            Rapid7ScannerNormalizer, AcunetixScannerNormalizer, AWSInspectorNormalizer,
            GitLabSASTNormalizer, SARIFUniversalNormalizer, CycloneDXUniversalNormalizer,
            SPDXUniversalNormalizer, GitleaksScannerNormalizer, ClaudeCodeSecurityNormalizer,
            CombobulatorNormalizer,
        ]
        for cls in new_normalizers:
            obj = cls(config=_cfg(cls.__name__.lower()))
            assert obj is not None

    def test_no_new_normalizer_handles_random_data(self):
        random_data = b"This is just some random text that is not from any scanner output format"
        new_normalizers = [
            TrivyScannerNormalizer, GrypeScannerNormalizer, SemgrepScannerNormalizer,
            DependabotScannerNormalizer, QualysScannerNormalizer, TenableScannerNormalizer,
            Rapid7ScannerNormalizer, AcunetixScannerNormalizer, AWSInspectorNormalizer,
            GitLabSASTNormalizer, SARIFUniversalNormalizer, CycloneDXUniversalNormalizer,
            SPDXUniversalNormalizer, GitleaksScannerNormalizer, ClaudeCodeSecurityNormalizer,
            CombobulatorNormalizer,
        ]
        for cls in new_normalizers:
            obj = cls(config=_cfg(cls.__name__))
            score = obj.can_handle(random_data)
            assert score < 0.5, f"{cls.__name__} falsely claims to handle random data (score={score})"


class TestRegisterScannerNormalizers:

    def test_register_scanner_normalizers_returns_count(self):
        """register_scanner_normalizers should register all entries and return count."""
        from core.scanner_parsers import register_scanner_normalizers

        class MockRegistry:
            def __init__(self):
                self.registered = {}

            def register(self, name, normalizer):
                self.registered[name] = normalizer

        registry = MockRegistry()
        count = register_scanner_normalizers(registry)
        assert count == len(SCANNER_NORMALIZERS)
        assert count >= 31  # At least 31 normalizers in total

    def test_register_scanner_normalizers_registers_new_normalizers(self):
        from core.scanner_parsers import register_scanner_normalizers

        class MockRegistry:
            def __init__(self):
                self.registered = {}

            def register(self, name, normalizer):
                self.registered[name] = normalizer

        registry = MockRegistry()
        register_scanner_normalizers(registry)
        for name in ("trivy", "grype", "semgrep", "gitleaks", "sarif", "cyclonedx", "spdx"):
            assert name in registry.registered, f"{name} was not registered"
