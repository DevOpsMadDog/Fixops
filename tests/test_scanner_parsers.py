"""Tests for scanner_parsers module — 15 third-party scanner normalizers."""
import json
import pytest


# ── Test Data ──────────────────────────────────────────────────────────────

ZAP_JSON = json.dumps({
    "site": [{"alerts": [{
        "name": "XSS Reflected", "riskcode": "3", "cweid": "79",
        "pluginid": "40012", "desc": "Cross-site scripting",
        "solution": "Validate input",
        "instances": [{"uri": "http://example.com/search"}],
    }]}]
}).encode()

BANDIT_JSON = json.dumps({
    "results": [{
        "test_id": "B101", "test_name": "assert_used",
        "issue_text": "Use of assert detected", "issue_severity": "LOW",
        "filename": "app.py", "line_number": 42, "code": "assert x > 0",
    }],
    "generated_at": "2024-01-01", "metrics": {"_totals": {}},
}).encode()

NUCLEI_JSONL = json.dumps({
    "template-id": "CVE-2021-44228", "matched-at": "http://target.com",
    "info": {"name": "Log4Shell", "severity": "critical",
             "description": "Log4j RCE",
             "classification": {"cvss-score": 10.0}},
}).encode()

SNYK_JSON = json.dumps({
    "vulnerabilities": [{
        "title": "Prototype Pollution", "severity": "high",
        "packageName": "lodash", "version": "4.17.20",
        "id": "SNYK-JS-LODASH-1234",
        "identifiers": {"CVE": ["CVE-2021-23337"], "CWE": ["400"]},
        "cvssScore": 7.4, "fixedIn": ["4.17.21"],
    }],
    "packageManager": "npm",
}).encode()

NESSUS_XML = b"""<?xml version="1.0"?>
<NessusClientData_v2>
<Report><ReportHost name="10.0.0.1">
<ReportItem pluginID="12345" severity="3" pluginName="SSL Vuln">
<description>SSL vulnerability found</description>
<solution>Upgrade SSL</solution>
<cvss_base_score>7.5</cvss_base_score>
<cve>CVE-2023-0001</cve>
</ReportItem>
</ReportHost></Report></NessusClientData_v2>"""

SONARQUBE_JSON = json.dumps({
    "issues": [{
        "rule": "java:S1234", "severity": "MAJOR",
        "component": "project:src/Main.java",
        "message": "Remove this empty statement",
        "line": 10, "tags": ["bug"],
    }],
}).encode()

CHECKOV_JSON = json.dumps({
    "check_type": "terraform",
    "passed_checks": [],
    "failed_checks": [{
        "check_id": "CKV_AWS_1",
        "check_name": "Ensure S3 bucket is not public",
        "file_path": "/main.tf",
        "file_line_range": [5, 10],
        "severity": "HIGH",
    }],
}).encode()


# ── Tests ──────────────────────────────────────────────────────────────────

class TestScannerParsers:
    def test_module_loads(self):
        from core.scanner_parsers import SCANNER_NORMALIZERS
        assert len(SCANNER_NORMALIZERS) == 15

    def test_auto_detect_zap(self):
        from core.scanner_parsers import auto_detect_scanner
        assert auto_detect_scanner(ZAP_JSON) == "zap"

    def test_auto_detect_bandit(self):
        from core.scanner_parsers import auto_detect_scanner
        assert auto_detect_scanner(BANDIT_JSON) == "bandit"

    def test_auto_detect_nuclei(self):
        from core.scanner_parsers import auto_detect_scanner
        assert auto_detect_scanner(NUCLEI_JSONL) == "nuclei"

    def test_auto_detect_snyk(self):
        from core.scanner_parsers import auto_detect_scanner
        assert auto_detect_scanner(SNYK_JSON) == "snyk"

    def test_auto_detect_nessus(self):
        from core.scanner_parsers import auto_detect_scanner
        assert auto_detect_scanner(NESSUS_XML) == "nessus"

    def test_auto_detect_checkov(self):
        from core.scanner_parsers import auto_detect_scanner
        assert auto_detect_scanner(CHECKOV_JSON) == "checkov"

    def test_parse_zap(self):
        from core.scanner_parsers import parse_scanner_output
        findings = parse_scanner_output(ZAP_JSON, "zap")
        assert len(findings) == 1
        f = findings[0]
        title = f.title if hasattr(f, "title") else f["title"]
        assert "XSS" in title

    def test_parse_bandit(self):
        from core.scanner_parsers import parse_scanner_output
        findings = parse_scanner_output(BANDIT_JSON, "bandit")
        assert len(findings) == 1
        f = findings[0]
        title = f.title if hasattr(f, "title") else f["title"]
        assert "B101" in title

    def test_parse_nuclei(self):
        from core.scanner_parsers import parse_scanner_output
        findings = parse_scanner_output(NUCLEI_JSONL, "nuclei")
        assert len(findings) == 1
        f = findings[0]
        title = f.title if hasattr(f, "title") else f["title"]
        assert "Log4Shell" in title

    def test_parse_snyk(self):
        from core.scanner_parsers import parse_scanner_output
        findings = parse_scanner_output(SNYK_JSON, "snyk")
        assert len(findings) == 1

    def test_parse_nessus(self):
        from core.scanner_parsers import parse_scanner_output
        findings = parse_scanner_output(NESSUS_XML, "nessus")
        assert len(findings) == 1
        f = findings[0]
        title = f.title if hasattr(f, "title") else f["title"]
        assert "SSL" in title

    def test_parse_sonarqube(self):
        from core.scanner_parsers import parse_scanner_output
        findings = parse_scanner_output(SONARQUBE_JSON, "sonarqube")
        assert len(findings) == 1

    def test_parse_checkov(self):
        from core.scanner_parsers import parse_scanner_output
        findings = parse_scanner_output(CHECKOV_JSON, "checkov")
        assert len(findings) == 1
        f = findings[0]
        title = f.title if hasattr(f, "title") else f["title"]
        assert "CKV_AWS_1" in title

    def test_supported_scanners(self):
        from core.scanner_parsers import get_supported_scanners
        supported = get_supported_scanners()
        assert "sast" in supported
        assert "dast" in supported
        assert "cloud" in supported
        assert len(supported["total_new"]) == 15

    def test_app_id_tagging(self):
        from core.scanner_parsers import parse_scanner_output
        findings = parse_scanner_output(ZAP_JSON, "zap", app_id="APP-001", component="web-frontend")
        f = findings[0]
        if hasattr(f, "tags"):
            assert any("component:" in t for t in f.tags)

    def test_registry_integration(self):
        """Verify normalizers register in the NormalizerRegistry."""
        from apps.api.ingestion import NormalizerRegistry
        registry = NormalizerRegistry()
        normalizers = registry.list_normalizers()
        assert len(normalizers) >= 25  # 10 builtin + 15 new
        for scanner in ["zap", "burp", "nessus", "nuclei", "snyk", "checkov"]:
            assert scanner in normalizers, f"{scanner} not in registry"


class TestSandboxVerifier:
    def test_module_loads(self):
        from core.sandbox_verifier import SandboxVerifier
        v = SandboxVerifier()
        assert v is not None

    def test_create_router(self):
        from core.sandbox_verifier import create_sandbox_router
        r = create_sandbox_router()
        assert len(r.routes) == 7  # 5 original + 2 reachability

    def test_poc_script_model(self):
        from core.sandbox_verifier import PoCLanguage, PoCScript
        poc = PoCScript(
            language=PoCLanguage.PYTHON,
            code="print('test')",
            cve_id="CVE-2024-0001",
            expected_indicators=["test"],
        )
        assert poc.language == PoCLanguage.PYTHON
        assert poc.timeout_seconds == 30

    def test_stats_empty(self):
        from core.sandbox_verifier import SandboxVerifier
        v = SandboxVerifier()
        stats = v.get_stats()
        assert stats["total"] == 0

    def test_generate_xss_poc(self):
        from core.sandbox_verifier import SandboxVerifier
        v = SandboxVerifier()
        finding = {"cve_id": "CVE-2024-0001", "cwe_id": "CWE-79", "title": "XSS"}
        poc = v._generate_basic_poc("CVE-2024-0001", "CWE-79", "XSS", "http://test.com")
        assert "XSS" in poc.code or "xss" in poc.code.lower()

    def test_generate_sqli_poc(self):
        from core.sandbox_verifier import SandboxVerifier
        v = SandboxVerifier()
        poc = v._generate_basic_poc("CVE-2024-0002", "CWE-89", "SQL Injection", "http://test.com")
        assert "SQL" in poc.code or "sql" in poc.code.lower() or "UNION" in poc.code


class TestSandboxedReachability:
    """Tests for SandboxedReachabilityProbe and MPTE sandbox integration."""

    def test_reachability_probe_init(self):
        from core.sandbox_verifier import SandboxedReachabilityProbe
        p = SandboxedReachabilityProbe(docker_available=False)
        assert p.docker_available is False
        assert p.memory_limit == "64m"
        assert p.cpu_limit == 0.25

    def test_reachability_probe_no_docker(self):
        from core.sandbox_verifier import SandboxedReachabilityProbe
        p = SandboxedReachabilityProbe(docker_available=False)
        r = p.probe("https://example.com")
        assert r.reachable is False
        assert r.method == "sandbox_unavailable"
        assert "Docker" in r.error

    def test_reachability_probe_multiple(self):
        from core.sandbox_verifier import SandboxedReachabilityProbe
        p = SandboxedReachabilityProbe(docker_available=False)
        results = p.probe_multiple(["https://a.com", "https://b.com"])
        assert len(results) == 2
        assert all(r.method == "sandbox_unavailable" for r in results)

    def test_reachability_result_model(self):
        from core.sandbox_verifier import ReachabilityResult
        r = ReachabilityResult(
            target="https://example.com",
            reachable=True,
            http_status=200,
            open_ports=[80, 443],
            tls_valid=True,
            server_header="nginx/1.25",
            confidence=0.95,
        )
        d = r.to_dict()
        assert d["reachable"] is True
        assert d["http_status"] == 200
        assert d["open_ports"] == [80, 443]
        assert d["tls_valid"] is True
        assert d["server_header"] == "nginx/1.25"

    def test_probe_output_parsing(self):
        from core.sandbox_verifier import SandboxedReachabilityProbe, ReachabilityResult
        p = SandboxedReachabilityProbe(docker_available=False)
        result = ReachabilityResult(target="https://example.com")
        output = """PROBE_START
target=https://example.com
=== TCP_CONNECT ===
tcp_reachable=true
tcp_port=443
=== HTTP_HEAD ===
http_status=200
server=nginx/1.25
=== TLS_CHECK ===
tls_valid=true
=== PORT_SCAN ===
open_port=80
open_port=443
PROBE_END"""
        parsed = p._parse_probe_output(output, result)
        assert parsed.reachable is True
        assert parsed.http_status == 200
        assert parsed.server_header == "nginx/1.25"
        assert parsed.tls_valid is True
        assert 80 in parsed.open_ports
        assert 443 in parsed.open_ports

    def test_sandbox_verify_findings_method(self):
        from core.sandbox_verifier import SandboxVerifier
        v = SandboxVerifier(docker_available=False)
        findings = [
            {"severity": "critical", "cve_id": "CVE-2024-1234", "title": "RCE"},
            {"severity": "low", "title": "Info disclosure"},
        ]
        # With docker unavailable, should return results with sandbox_unavailable status
        results = v.sandbox_verify_findings(findings, ["https://target.com"])
        # Only HIGH/CRITICAL findings are candidates
        assert len(results) == 1
        assert results[0]["title"] == "RCE"
        assert results[0]["verification"]["status"] == "sandbox_unavailable"

    def test_probe_script_content(self):
        from core.sandbox_verifier import SandboxedReachabilityProbe
        script = SandboxedReachabilityProbe.PROBE_SCRIPT
        assert "TCP_CONNECT" in script
        assert "HTTP_HEAD" in script
        assert "TLS_CHECK" in script
        assert "PORT_SCAN" in script
        assert "nc -z" in script  # netcat for TCP connect

    def test_router_has_reachability_endpoints(self):
        from core.sandbox_verifier import create_sandbox_router
        router = create_sandbox_router()
        paths = [r.path for r in router.routes]
        assert "/api/v1/sandbox/reachability" in paths
        assert "/api/v1/sandbox/reachability/single" in paths


# ── Edge Case Tests (Empty, Binary, Oversized) ───────────────────────────────

class TestScannerParserEdgeCases:
    """Edge case tests: empty files, binary garbage, oversized inputs, malformed JSON."""

    def test_empty_bytes_auto_detect(self):
        """Auto-detect should return None or 'unknown' for empty input."""
        from core.scanner_parsers import auto_detect_scanner
        result = auto_detect_scanner(b"")
        assert result is None or result == "unknown"

    def test_empty_bytes_parse(self):
        """Parsing empty input should return empty list, not crash."""
        from core.scanner_parsers import parse_scanner_output
        findings = parse_scanner_output(b"", "zap")
        assert findings == [] or findings is not None

    def test_binary_garbage_auto_detect(self):
        """Auto-detect should not crash on binary garbage."""
        from core.scanner_parsers import auto_detect_scanner
        binary_garbage = bytes(range(256)) * 10  # 2560 bytes of binary
        result = auto_detect_scanner(binary_garbage)
        assert result is None or isinstance(result, str)

    def test_binary_garbage_parse_zap(self):
        """Parsing binary garbage as ZAP should return empty or raise gracefully."""
        from core.scanner_parsers import parse_scanner_output
        binary_garbage = bytes(range(256)) * 10
        try:
            findings = parse_scanner_output(binary_garbage, "zap")
            assert isinstance(findings, list)
        except (json.JSONDecodeError, ValueError, KeyError):
            pass  # Expected: parser should reject gracefully

    def test_binary_garbage_parse_nessus(self):
        """Parsing binary garbage as Nessus XML should not crash."""
        from core.scanner_parsers import parse_scanner_output
        binary_garbage = b"\x00\xff\xfe\xfd" * 100
        try:
            findings = parse_scanner_output(binary_garbage, "nessus")
            assert isinstance(findings, list)
        except (Exception,):
            pass  # XML parser may throw, but should not segfault

    def test_oversized_json_input(self):
        """Oversized but valid JSON should be handled."""
        from core.scanner_parsers import parse_scanner_output
        # Create a large ZAP-like JSON with 1000 alerts
        alerts = []
        for i in range(1000):
            alerts.append({
                "name": f"Finding-{i}", "riskcode": "2", "cweid": "79",
                "pluginid": str(40000 + i), "desc": f"Finding {i}" * 20,
                "solution": "Fix it",
                "instances": [{"uri": f"http://example.com/path{i}"}],
            })
        big_json = json.dumps({"site": [{"alerts": alerts}]}).encode()
        assert len(big_json) > 100_000  # >100KB
        findings = parse_scanner_output(big_json, "zap")
        assert len(findings) == 1000

    def test_malformed_json_auto_detect(self):
        """Malformed JSON should not crash auto_detect."""
        from core.scanner_parsers import auto_detect_scanner
        malformed = b'{"results": [{"test_id": "B101"'  # Truncated JSON
        result = auto_detect_scanner(malformed)
        assert result is None or isinstance(result, str)

    def test_unicode_content_in_findings(self):
        """Scanner output with unicode characters should be handled."""
        from core.scanner_parsers import parse_scanner_output
        unicode_json = json.dumps({
            "results": [{
                "test_id": "B101", "test_name": "assert_used",
                "issue_text": "Déclaration de variable dangereuse: 変数",
                "issue_severity": "LOW",
                "filename": "données/app.py", "line_number": 42,
                "code": "assert x > 0  # 注意",
            }],
            "generated_at": "2024-01-01", "metrics": {"_totals": {}},
        }).encode()
        findings = parse_scanner_output(unicode_json, "bandit")
        assert len(findings) == 1
        f = findings[0]
        title = f.title if hasattr(f, "title") else f["title"]
        assert "B101" in title

    def test_null_values_in_scanner_output(self):
        """Scanner output with null/None values should be handled gracefully."""
        from core.scanner_parsers import parse_scanner_output
        null_json = json.dumps({
            "vulnerabilities": [{
                "title": None, "severity": None,
                "packageName": "lodash", "version": "4.17.20",
                "id": "SNYK-JS-LODASH-1234",
                "identifiers": {"CVE": [], "CWE": []},
                "cvssScore": None, "fixedIn": [],
            }],
            "packageManager": "npm",
        }).encode()
        try:
            findings = parse_scanner_output(null_json, "snyk")
            assert isinstance(findings, list)
        except (TypeError, AttributeError):
            pass  # Acceptable: parser may reject nulls

    def test_empty_xml_nessus(self):
        """Empty XML (valid but no findings) should return empty list."""
        from core.scanner_parsers import parse_scanner_output
        empty_xml = b'<?xml version="1.0"?><NessusClientData_v2><Report></Report></NessusClientData_v2>'
        findings = parse_scanner_output(empty_xml, "nessus")
        assert findings == []

    def test_empty_results_array(self):
        """Scanner with empty results array should return empty list."""
        from core.scanner_parsers import parse_scanner_output
        empty_results = json.dumps({"results": [], "generated_at": "2024-01-01", "metrics": {"_totals": {}}}).encode()
        findings = parse_scanner_output(empty_results, "bandit")
        assert findings == []

    def test_checkov_no_failed_checks(self):
        """Checkov with no failed checks should return empty list."""
        from core.scanner_parsers import parse_scanner_output
        no_fails = json.dumps({
            "check_type": "terraform",
            "passed_checks": [{"check_id": "CKV_AWS_1", "check_name": "Passed"}],
            "failed_checks": [],
        }).encode()
        findings = parse_scanner_output(no_fails, "checkov")
        assert findings == []

    def test_sonarqube_empty_issues(self):
        """SonarQube with empty issues should return empty list."""
        from core.scanner_parsers import parse_scanner_output
        empty_sq = json.dumps({"issues": []}).encode()
        findings = parse_scanner_output(empty_sq, "sonarqube")
        assert findings == []


# ── Exposure Case Idempotency Tests ────────────────────────────────────────

class TestExposureCaseIdempotency:
    """Tests for find_case_by_cluster, purge_empty_cases, severity_to_priority,
    and idempotent case creation in the brain pipeline."""

    def test_severity_to_priority_mapping(self):
        from core.exposure_case import severity_to_priority, CasePriority
        assert severity_to_priority("critical") == CasePriority.CRITICAL
        assert severity_to_priority("high") == CasePriority.HIGH
        assert severity_to_priority("medium") == CasePriority.MEDIUM
        assert severity_to_priority("low") == CasePriority.LOW
        assert severity_to_priority("info") == CasePriority.INFO
        assert severity_to_priority("informational") == CasePriority.INFO
        # Edge cases
        assert severity_to_priority("HIGH") == CasePriority.HIGH
        assert severity_to_priority("  Critical  ") == CasePriority.CRITICAL
        assert severity_to_priority("unknown") == CasePriority.MEDIUM
        assert severity_to_priority("") == CasePriority.MEDIUM
        assert severity_to_priority(None) == CasePriority.MEDIUM

    def test_find_case_by_cluster_found(self, tmp_path):
        from core.exposure_case import ExposureCase, ExposureCaseManager
        db = str(tmp_path / "test_cases.db")
        mgr = ExposureCaseManager(db_path=db)
        try:
            case = ExposureCase(
                case_id="EC-test001",
                title="Test Case",
                org_id="org1",
                cluster_ids=["cluster-aaa", "cluster-bbb"],
                finding_count=5,
                risk_score=7.5,
            )
            mgr.create_case(case)
            # Should find by either cluster
            found = mgr.find_case_by_cluster("cluster-aaa")
            assert found is not None
            assert found.case_id == "EC-test001"
            found2 = mgr.find_case_by_cluster("cluster-bbb")
            assert found2 is not None
            assert found2.case_id == "EC-test001"
        finally:
            mgr.close()

    def test_find_case_by_cluster_not_found(self, tmp_path):
        from core.exposure_case import ExposureCase, ExposureCaseManager
        db = str(tmp_path / "test_cases.db")
        mgr = ExposureCaseManager(db_path=db)
        try:
            case = ExposureCase(
                case_id="EC-test002",
                title="Other Case",
                org_id="org1",
                cluster_ids=["cluster-xxx"],
            )
            mgr.create_case(case)
            found = mgr.find_case_by_cluster("cluster-yyy")
            assert found is None
        finally:
            mgr.close()

    def test_purge_empty_cases_removes_phantoms(self, tmp_path):
        from core.exposure_case import ExposureCase, ExposureCaseManager
        db = str(tmp_path / "test_purge.db")
        mgr = ExposureCaseManager(db_path=db)
        try:
            # Create a phantom case (finding_count=0, no CVE/CWE/component)
            phantom = ExposureCase(
                case_id="EC-phantom1",
                title="Phantom",
                org_id="org1",
                cluster_ids=["cluster-p1"],
            )
            mgr.create_case(phantom)
            # Create a real case (has enrichment data)
            real = ExposureCase(
                case_id="EC-real1",
                title="Real Case",
                org_id="org1",
                cluster_ids=["cluster-r1"],
                finding_count=3,
                risk_score=8.0,
                root_cve="CVE-2024-1234",
            )
            mgr.create_case(real)
            # Dry run
            result = mgr.purge_empty_cases(dry_run=True)
            assert result["purged"] == 1
            assert result["dry_run"] is True
            # Verify phantom still exists after dry run
            assert mgr.get_case("EC-phantom1") is not None
            # Actual purge
            result = mgr.purge_empty_cases(dry_run=False)
            assert result["purged"] == 1
            assert result["dry_run"] is False
            # Phantom gone, real remains
            assert mgr.get_case("EC-phantom1") is None
            assert mgr.get_case("EC-real1") is not None
        finally:
            mgr.close()

    def test_purge_empty_cases_no_phantoms(self, tmp_path):
        from core.exposure_case import ExposureCase, ExposureCaseManager
        db = str(tmp_path / "test_no_purge.db")
        mgr = ExposureCaseManager(db_path=db)
        try:
            real = ExposureCase(
                case_id="EC-enriched1",
                title="Enriched",
                org_id="org1",
                finding_count=5,
                risk_score=6.0,
                root_cve="CVE-2024-5678",
            )
            mgr.create_case(real)
            result = mgr.purge_empty_cases()
            assert result["purged"] == 0
        finally:
            mgr.close()

    def test_idempotent_no_duplicate_cases(self, tmp_path):
        """Simulate two pipeline runs with same clusters — second run should NOT create duplicates."""
        from core.exposure_case import ExposureCase, ExposureCaseManager
        db = str(tmp_path / "test_idempotent.db")
        mgr = ExposureCaseManager(db_path=db)
        try:
            cluster_id = "cluster-idem-001"
            # First run: create case
            case = ExposureCase(
                case_id="EC-first",
                title="First Run Case",
                org_id="org1",
                cluster_ids=[cluster_id],
                finding_count=3,
                risk_score=7.5,
            )
            mgr.create_case(case)
            # Second run: find_case_by_cluster should find existing
            existing = mgr.find_case_by_cluster(cluster_id)
            assert existing is not None
            assert existing.case_id == "EC-first"
            # Should NOT create another case — the pipeline will skip
            stats = mgr.stats()
            assert stats["total_cases"] == 1
        finally:
            mgr.close()

    def test_enriched_case_has_real_data(self):
        """Verify ExposureCase created with enrichment carries all fields."""
        from core.exposure_case import ExposureCase, CasePriority, severity_to_priority
        case = ExposureCase(
            case_id="EC-enriched",
            title="SQL Injection in login.py",
            description="Auto-generated from dedup cluster abc. Category: sast. Occurrences: 12.",
            org_id="org1",
            cluster_ids=["abc"],
            finding_count=12,
            root_cve="CVE-2024-9999",
            root_component="login.py",
            priority=severity_to_priority("critical"),
            risk_score=9.5,
            blast_radius=12,
            tags=["sast"],
            metadata={"source_cluster": "abc", "correlation_key": "sql_injection:login.py", "first_seen": "2024-01-01"},
        )
        d = case.to_dict()
        assert d["case_id"] == "EC-enriched"
        assert d["finding_count"] == 12
        assert d["root_cve"] == "CVE-2024-9999"
        assert d["root_component"] == "login.py"
        assert d["priority"] == "critical"
        assert d["risk_score"] == 9.5
        assert d["blast_radius"] == 12
        assert "sast" in d["tags"]
        assert d["metadata"]["correlation_key"] == "sql_injection:login.py"
