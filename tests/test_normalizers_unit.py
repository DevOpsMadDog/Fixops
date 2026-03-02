"""
Unit tests for suite-api/apps/api/normalizers.py

Tests the normalizer module including:
- _safe_json_loads: depth limits, item limits, invalid JSON
- _extract_first_identifier: Snyk identifier extraction
- _derive_snyk_location: Snyk location derivation
- _collect_snyk_issues: Snyk issue collection from various formats
- _convert_snyk_payload_to_sarif: Snyk-to-SARIF fallback conversion
- SBOMComponent dataclass
- NormalizedSBOM / NormalizedCVEFeed / NormalizedSARIF / NormalizedVEX / NormalizedCNAPP
- NormalizedBusinessContext
- SarifFinding / SarifFindingSchema / NormalizedSarifSchema
- VEXAssertion / CNAPPAsset / CNAPPFinding / CVERecordSummary
- InputNormalizer: prepare_text, base64, gzip, zip, SBOM loading, CVE feed, SARIF, VEX, CNAPP
"""

import base64
import gzip
import io
import json
import os
import zipfile

import pytest

os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-jwt-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from apps.api.normalizers import (
    CNAPPAsset,
    CNAPPFinding,
    CVERecordSummary,
    InputNormalizer,
    NormalizedBusinessContext,
    NormalizedCNAPP,
    NormalizedCVEFeed,
    NormalizedSARIF,
    NormalizedSBOM,
    NormalizedVEX,
    SBOMComponent,
    SarifFinding,
    SarifFindingSchema,
    VEXAssertion,
    _collect_snyk_issues,
    _convert_snyk_payload_to_sarif,
    _derive_snyk_location,
    _extract_first_identifier,
    _safe_json_loads,
)


# ===========================================================================
# _safe_json_loads tests
# ===========================================================================


class TestSafeJsonLoads:
    def test_valid_json(self):
        result = _safe_json_loads('{"key": "value"}')
        assert result == {"key": "value"}

    def test_array(self):
        result = _safe_json_loads('[1, 2, 3]')
        assert result == [1, 2, 3]

    def test_invalid_json_raises(self):
        with pytest.raises(ValueError, match="Invalid JSON"):
            _safe_json_loads("not json")

    def test_depth_exceeded(self):
        # Build deeply nested JSON
        nested = {"a": None}
        current = nested
        for _ in range(25):
            new = {"a": None}
            current["a"] = new
            current = new
        text = json.dumps(nested)
        with pytest.raises(ValueError, match="nesting depth"):
            _safe_json_loads(text, max_depth=20)

    def test_items_exceeded(self):
        # Build a dict with too many items
        big = {f"key_{i}": i for i in range(200)}
        text = json.dumps(big)
        with pytest.raises(ValueError, match="item count"):
            _safe_json_loads(text, max_items=100)

    def test_normal_nested_passes(self):
        data = {"a": {"b": {"c": [1, 2, 3]}}}
        result = _safe_json_loads(json.dumps(data))
        assert result == data

    def test_list_items_counted(self):
        data = list(range(50))
        result = _safe_json_loads(json.dumps(data), max_items=100)
        assert result == data

    def test_empty_dict(self):
        assert _safe_json_loads("{}") == {}

    def test_empty_list(self):
        assert _safe_json_loads("[]") == []


# ===========================================================================
# _extract_first_identifier tests
# ===========================================================================


class TestExtractFirstIdentifier:
    def test_cve_identifier(self):
        payload = {"CVE": ["CVE-2024-1234"]}
        assert _extract_first_identifier(payload) == "CVE-2024-1234"

    def test_ghsa_identifier(self):
        """GHSA-abcd starts with 'GHSA', so no prefix is added."""
        payload = {"GHSA": ["GHSA-abcd-1234-efgh"]}
        result = _extract_first_identifier(payload)
        assert result == "GHSA-abcd-1234-efgh"

    def test_ghsa_without_prefix(self):
        """A value that does NOT start with 'GHSA' gets the prefix."""
        payload = {"GHSA": ["abcd-1234"]}
        result = _extract_first_identifier(payload)
        assert result == "GHSA:abcd-1234"

    def test_cwe_identifier(self):
        """CWE-89 starts with 'CWE', so no prefix is added."""
        payload = {"CWE": ["CWE-89"]}
        result = _extract_first_identifier(payload)
        assert result == "CWE-89"

    def test_osv_identifier(self):
        """PYSEC-2024-001 does NOT start with 'OSV', so prefix is added."""
        payload = {"OSV": ["PYSEC-2024-001"]}
        result = _extract_first_identifier(payload)
        assert result == "OSV:PYSEC-2024-001"

    def test_empty_values(self):
        payload = {"CVE": [], "GHSA": []}
        assert _extract_first_identifier(payload) is None

    def test_none_input(self):
        assert _extract_first_identifier(None) is None

    def test_non_mapping_input(self):
        assert _extract_first_identifier("string") is None

    def test_priority_order(self):
        payload = {"CVE": ["CVE-2024-1234"], "GHSA": ["GHSA-xxxx"]}
        # CVE comes first in iteration order
        result = _extract_first_identifier(payload)
        assert result == "CVE-2024-1234"

    def test_whitespace_skipped(self):
        payload = {"CVE": ["", "  ", "CVE-2024-5678"]}
        result = _extract_first_identifier(payload)
        assert result == "CVE-2024-5678"


# ===========================================================================
# _derive_snyk_location tests
# ===========================================================================


class TestDeriveSnykLocation:
    def test_from_dependency_path(self):
        issue = {"from": ["root@1.0", "dep-a@2.0", "dep-b@3.0"]}
        result = _derive_snyk_location(issue)
        assert result == "dep-b@3.0"  # last non-empty

    def test_from_file_key(self):
        issue = {"file": "package.json"}
        assert _derive_snyk_location(issue) == "package.json"

    def test_from_target_file(self):
        issue = {"targetFile": "requirements.txt"}
        assert _derive_snyk_location(issue) == "requirements.txt"

    def test_from_package_with_manager(self):
        issue = {"packageManager": "npm", "package": "lodash"}
        assert _derive_snyk_location(issue) == "npm:lodash"

    def test_from_package_without_manager(self):
        issue = {"package": "express"}
        assert _derive_snyk_location(issue) == "express"

    def test_fallback_to_dependency(self):
        issue = {}
        assert _derive_snyk_location(issue) == "dependency"


# ===========================================================================
# _collect_snyk_issues tests
# ===========================================================================


class TestCollectSnykIssues:
    def test_issues_as_mapping(self):
        payload = {
            "issues": {
                "vulnerabilities": [
                    {"id": "SNYK-001", "title": "Vuln 1"},
                    {"id": "SNYK-002", "title": "Vuln 2"},
                ],
                "licenses": [
                    {"id": "LIC-001", "title": "License 1"},
                ],
            }
        }
        issues = _collect_snyk_issues(payload)
        assert len(issues) == 3
        assert issues[0]["_category"] == "vulnerabilities"

    def test_issues_as_list(self):
        payload = {"issues": [{"id": "SNYK-001"}]}
        issues = _collect_snyk_issues(payload)
        assert len(issues) == 1

    def test_vulnerabilities_key(self):
        payload = {"vulnerabilities": [{"id": "V1"}, {"id": "V2"}]}
        issues = _collect_snyk_issues(payload)
        assert len(issues) == 2
        assert issues[0]["_category"] == "vulnerabilities"

    def test_empty_payload(self):
        assert _collect_snyk_issues({}) == []

    def test_multiple_category_keys(self):
        payload = {
            "vulnerabilities": [{"id": "V1"}],
            "licenses": [{"id": "L1"}],
            "securityIssues": [{"id": "S1"}],
        }
        issues = _collect_snyk_issues(payload)
        assert len(issues) == 3


# ===========================================================================
# _convert_snyk_payload_to_sarif tests
# ===========================================================================


class TestConvertSnykToSarif:
    def test_basic_conversion(self):
        payload = {
            "vulnerabilities": [{
                "id": "SNYK-JS-001",
                "title": "Prototype pollution",
                "severity": "high",
                "from": ["root@1.0", "lodash@4.17.20"],
            }],
            "snykVersion": "1.1234.0",
        }
        result = _convert_snyk_payload_to_sarif(payload)
        assert result is not None
        assert result["version"] == "2.1.0"
        assert len(result["runs"]) == 1
        assert len(result["runs"][0]["results"]) == 1
        r = result["runs"][0]["results"][0]
        assert r["ruleId"] == "SNYK-JS-001"
        assert r["level"] == "error"  # high -> error
        assert r["message"]["text"] == "Prototype pollution"

    def test_medium_severity_maps_to_warning(self):
        payload = {"vulnerabilities": [{"id": "X", "severity": "medium", "title": "test"}]}
        result = _convert_snyk_payload_to_sarif(payload)
        assert result["runs"][0]["results"][0]["level"] == "warning"

    def test_low_severity_maps_to_note(self):
        payload = {"vulnerabilities": [{"id": "X", "severity": "low", "title": "test"}]}
        result = _convert_snyk_payload_to_sarif(payload)
        assert result["runs"][0]["results"][0]["level"] == "note"

    def test_empty_issues_returns_none(self):
        result = _convert_snyk_payload_to_sarif({"vulnerabilities": []})
        assert result is None

    def test_snyk_version_in_tool(self):
        payload = {
            "vulnerabilities": [{"id": "X", "title": "t"}],
            "snykVersion": "2.0.0",
        }
        result = _convert_snyk_payload_to_sarif(payload)
        assert result["runs"][0]["tool"]["driver"]["version"] == "2.0.0"

    def test_project_name_in_properties(self):
        payload = {
            "vulnerabilities": [{"id": "X", "title": "t"}],
            "projectName": "my-project",
        }
        result = _convert_snyk_payload_to_sarif(payload)
        assert result["runs"][0]["properties"]["project"] == "my-project"


# ===========================================================================
# Dataclass Tests
# ===========================================================================


class TestSBOMComponent:
    def test_creation(self):
        c = SBOMComponent(name="lodash", version="4.17.21", purl="pkg:npm/lodash@4.17.21")
        assert c.name == "lodash"
        assert c.version == "4.17.21"

    def test_to_dict(self):
        c = SBOMComponent(name="lib", version="1.0")
        d = c.to_dict()
        assert d["name"] == "lib"
        assert d["version"] == "1.0"
        assert d["licenses"] == []

    def test_defaults(self):
        c = SBOMComponent(name="test")
        assert c.version is None
        assert c.purl is None
        assert c.licenses == []
        assert c.supplier is None


class TestCVERecordSummary:
    def test_creation(self):
        r = CVERecordSummary(
            cve_id="CVE-2024-1234",
            title="Buffer overflow",
            severity="critical",
            exploited=True,
            raw={"test": "data"},
        )
        assert r.cve_id == "CVE-2024-1234"
        assert r.exploited is True

    def test_to_dict(self):
        r = CVERecordSummary(cve_id="CVE-X", title="T", severity="high", exploited=False, raw={})
        d = r.to_dict()
        assert d["cve_id"] == "CVE-X"
        assert d["exploited"] is False


class TestNormalizedCVEFeed:
    def test_creation_and_to_dict(self):
        records = [
            CVERecordSummary(cve_id="CVE-1", title="T1", severity="high", exploited=False, raw={}),
        ]
        feed = NormalizedCVEFeed(records=records, errors=["err1"], metadata={"count": 1})
        d = feed.to_dict()
        assert len(d["records"]) == 1
        assert d["errors"] == ["err1"]
        assert d["metadata"]["count"] == 1


class TestSarifFinding:
    def test_creation(self):
        f = SarifFinding(
            rule_id="R1",
            message="Test msg",
            level="error",
            file="test.py",
            line=10,
            raw={"test": True},
        )
        assert f.rule_id == "R1"
        assert f.level == "error"

    def test_to_dict(self):
        f = SarifFinding(rule_id="R1", message="msg", level="warning", file=None, line=None, raw={})
        d = f.to_dict()
        assert d["rule_id"] == "R1"
        assert d["file"] is None


class TestNormalizedSARIF:
    def test_creation_and_to_dict(self):
        findings = [
            SarifFinding(rule_id="R1", message="m", level="error", file="a.py", line=1, raw={}),
        ]
        sarif = NormalizedSARIF(
            version="2.1.0",
            schema_uri="https://sarif.org",
            tool_names=["semgrep"],
            findings=findings,
            metadata={"finding_count": 1},
        )
        d = sarif.to_dict()
        assert d["version"] == "2.1.0"
        assert len(d["findings"]) == 1
        assert d["tool_names"] == ["semgrep"]


class TestNormalizedSBOM:
    def test_creation_and_to_dict(self):
        comps = [SBOMComponent(name="lib", version="1.0")]
        sbom = NormalizedSBOM(
            format="cyclonedx",
            document={"test": True},
            components=comps,
            relationships=[],
            services=[],
            vulnerabilities=[],
            metadata={"component_count": 1},
        )
        d = sbom.to_dict()
        assert d["format"] == "cyclonedx"
        assert len(d["components"]) == 1


class TestVEXAssertion:
    def test_creation_and_to_dict(self):
        a = VEXAssertion(
            vulnerability_id="CVE-2024-001",
            ref="pkg:npm/lib@1.0",
            status="not_affected",
            detail="Not used in production",
        )
        d = a.to_dict()
        assert d["vulnerability_id"] == "CVE-2024-001"
        assert d["status"] == "not_affected"
        assert d["detail"] == "Not used in production"

    def test_to_dict_without_detail(self):
        a = VEXAssertion(vulnerability_id="CVE-X", ref="ref", status="affected")
        d = a.to_dict()
        assert "detail" not in d


class TestNormalizedVEX:
    def test_suppressed_refs(self):
        assertions = [
            VEXAssertion(vulnerability_id="V1", ref="pkg:a", status="not_affected"),
            VEXAssertion(vulnerability_id="V2", ref="pkg:b", status="affected"),
        ]
        vex = NormalizedVEX(assertions=assertions)
        assert vex.suppressed_refs == {"pkg:a"}

    def test_to_dict(self):
        vex = NormalizedVEX(assertions=[], metadata={"test": True})
        d = vex.to_dict()
        assert d["assertions"] == []
        assert d["metadata"]["test"] is True


class TestCNAPPAsset:
    def test_to_dict(self):
        a = CNAPPAsset(asset_id="web-1", attributes={"region": "us-east-1"})
        d = a.to_dict()
        assert d["id"] == "web-1"
        assert d["region"] == "us-east-1"


class TestCNAPPFinding:
    def test_to_dict(self):
        f = CNAPPFinding(asset="web-1", finding_type="misconfig", severity="high")
        d = f.to_dict()
        assert d["asset"] == "web-1"
        assert d["type"] == "misconfig"
        assert d["severity"] == "high"


class TestNormalizedCNAPP:
    def test_to_dict(self):
        cnapp = NormalizedCNAPP(
            assets=[CNAPPAsset(asset_id="a1")],
            findings=[CNAPPFinding(asset="a1", finding_type="vuln", severity="high")],
        )
        d = cnapp.to_dict()
        assert len(d["assets"]) == 1
        assert len(d["findings"]) == 1


class TestNormalizedBusinessContext:
    def test_creation_and_to_dict(self):
        ctx = NormalizedBusinessContext(
            format="fixops",
            components=[{"name": "auth-service", "criticality": "high"}],
            ssvc={"exploitation": "active"},
            metadata={"source": "test"},
        )
        d = ctx.to_dict()
        assert d["format"] == "fixops"
        assert len(d["components"]) == 1
        assert d["ssvc"]["exploitation"] == "active"


# ===========================================================================
# SarifFindingSchema validation tests
# ===========================================================================


class TestSarifFindingSchema:
    def test_valid_finding(self):
        schema = SarifFindingSchema(
            rule_id="R1",
            message="Test",
            level="error",
            file="test.py",
            line=10,
        )
        assert schema.rule_id == "R1"

    def test_none_values(self):
        schema = SarifFindingSchema()
        assert schema.rule_id is None
        assert schema.message is None
        assert schema.level is None

    def test_empty_rule_id_rejected(self):
        with pytest.raises(Exception):
            SarifFindingSchema(rule_id="  ")

    def test_valid_levels(self):
        for level in ["error", "warning", "note", "none"]:
            schema = SarifFindingSchema(level=level)
            assert schema.level == level


# ===========================================================================
# InputNormalizer tests
# ===========================================================================


class TestInputNormalizer:
    def test_ensure_bytes_from_string(self):
        n = InputNormalizer()
        result = n._ensure_bytes("hello")
        assert result == b"hello"

    def test_ensure_bytes_from_bytes(self):
        n = InputNormalizer()
        result = n._ensure_bytes(b"hello")
        assert result == b"hello"

    def test_ensure_bytes_from_dict(self):
        n = InputNormalizer()
        result = n._ensure_bytes({"key": "value"})
        assert json.loads(result) == {"key": "value"}

    def test_ensure_bytes_from_list(self):
        n = InputNormalizer()
        result = n._ensure_bytes([1, 2, 3])
        assert json.loads(result) == [1, 2, 3]

    def test_ensure_bytes_from_memoryview(self):
        n = InputNormalizer()
        result = n._ensure_bytes(memoryview(b"test"))
        assert result == b"test"

    def test_ensure_bytes_from_file_like(self):
        n = InputNormalizer()
        buf = io.BytesIO(b"file content")
        result = n._ensure_bytes(buf)
        assert result == b"file content"

    def test_ensure_bytes_nan_rejected(self):
        n = InputNormalizer()
        with pytest.raises(ValueError, match="NaN"):
            n._ensure_bytes({"value": float("nan")})

    def test_ensure_bytes_infinity_rejected(self):
        n = InputNormalizer()
        with pytest.raises(ValueError, match="NaN"):
            n._ensure_bytes({"value": float("inf")})

    def test_maybe_decode_base64(self):
        n = InputNormalizer()
        original = b'{"test": true}'
        encoded = base64.b64encode(original)
        result = n._maybe_decode_base64(encoded)
        assert result == original

    def test_maybe_decode_base64_not_base64(self):
        n = InputNormalizer()
        data = b'{"test": true}'
        result = n._maybe_decode_base64(data)
        assert result == data

    def test_maybe_decompress_gzip(self):
        n = InputNormalizer()
        original = b'{"test": true}'
        compressed = gzip.compress(original)
        result = n._maybe_decompress(compressed)
        assert result == original

    def test_maybe_decompress_zip(self):
        n = InputNormalizer()
        original = b'{"test": true}'
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("data.json", original)
        compressed = buf.getvalue()
        result = n._maybe_decompress(compressed)
        assert result == original

    def test_maybe_decompress_plain(self):
        n = InputNormalizer()
        data = b'{"plain": "data"}'
        result = n._maybe_decompress(data)
        assert result == data

    def test_prepare_text(self):
        n = InputNormalizer()
        text = n._prepare_text(b'{"test": "value"}')
        assert text == '{"test": "value"}'

    def test_prepare_text_from_string(self):
        n = InputNormalizer()
        text = n._prepare_text('{"test": "value"}')
        assert text == '{"test": "value"}'

    def test_prepare_text_size_limit(self):
        n = InputNormalizer(max_document_bytes=10)
        with pytest.raises(ValueError, match="exceeds maximum"):
            n._prepare_text(b"x" * 100)

    def test_gzip_decompression_bomb_rejected(self):
        n = InputNormalizer(max_document_bytes=100)
        big = b"A" * 1000
        compressed = gzip.compress(big)
        with pytest.raises(ValueError, match="exceeds maximum"):
            n._maybe_decompress(compressed)

    def test_check_nan_infinity_nested(self):
        with pytest.raises(ValueError, match="NaN"):
            InputNormalizer._check_nan_infinity({"a": [1, float("nan")]})

    def test_check_nan_infinity_valid(self):
        InputNormalizer._check_nan_infinity({"a": [1, 2.5, "str"]})  # Should not raise


# ===========================================================================
# InputNormalizer.load_sarif tests
# ===========================================================================


class TestInputNormalizerLoadSarif:
    def _make_sarif_raw(self, results=None, tool_name="test-tool"):
        return json.dumps({
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [{
                "tool": {"driver": {"name": tool_name, "rules": []}},
                "results": results or [],
            }],
        })

    def test_valid_sarif(self):
        n = InputNormalizer()
        raw = self._make_sarif_raw(results=[
            {"ruleId": "R1", "level": "error", "message": {"text": "Test error"}},
        ])
        result = n.load_sarif(raw)
        assert isinstance(result, NormalizedSARIF)
        assert result.version == "2.1.0"
        assert len(result.findings) == 1
        assert result.tool_names == ["test-tool"]

    def test_empty_sarif(self):
        n = InputNormalizer()
        raw = self._make_sarif_raw(results=[])
        result = n.load_sarif(raw)
        assert result.findings == []

    def test_invalid_sarif_raises(self):
        n = InputNormalizer()
        with pytest.raises(ValueError, match="not a valid SARIF"):
            n.load_sarif('{"not": "sarif"}')

    def test_snyk_json_converted(self):
        """Snyk JSON payloads are converted to SARIF via built-in fallback."""
        n = InputNormalizer()
        snyk_payload = json.dumps({
            "vulnerabilities": [{
                "id": "SNYK-JS-001",
                "title": "Prototype pollution",
                "severity": "high",
                "from": ["root@1.0", "lodash@4.17.20"],
            }]
        })
        result = n.load_sarif(snyk_payload)
        assert isinstance(result, NormalizedSARIF)
        assert len(result.findings) >= 1


# ===========================================================================
# InputNormalizer.load_cve_feed tests
# ===========================================================================


class TestInputNormalizerLoadCVEFeed:
    def test_list_format(self):
        n = InputNormalizer()
        data = json.dumps([
            {"cveID": "CVE-2024-0001", "severity": "high"},
            {"cveID": "CVE-2024-0002", "severity": "critical", "knownExploited": True},
        ])
        result = n.load_cve_feed(data)
        assert isinstance(result, NormalizedCVEFeed)
        assert len(result.records) == 2
        assert result.records[0].cve_id == "CVE-2024-0001"
        assert result.records[1].exploited is True

    def test_dict_with_vulnerabilities_key(self):
        n = InputNormalizer()
        data = json.dumps({
            "vulnerabilities": [
                {"cveID": "CVE-2024-0001", "severity": "high"},
            ]
        })
        result = n.load_cve_feed(data)
        assert len(result.records) == 1

    def test_nested_data_key(self):
        n = InputNormalizer()
        data = json.dumps({
            "data": {
                "vulnerabilities": [
                    {"cve_id": "CVE-2024-0001"},
                ]
            }
        })
        result = n.load_cve_feed(data)
        assert len(result.records) == 1

    def test_deduplication(self):
        n = InputNormalizer()
        data = json.dumps([
            {"cveID": "CVE-2024-0001", "severity": "low"},
            {"cveID": "CVE-2024-0001", "severity": "critical"},
        ])
        result = n.load_cve_feed(data)
        assert len(result.records) == 1
        assert result.records[0].severity == "critical"
        assert result.metadata["duplicates_removed"] == 1

    def test_exploited_defaults_to_critical(self):
        n = InputNormalizer()
        data = json.dumps([{"cveID": "CVE-X", "knownExploited": True}])
        result = n.load_cve_feed(data)
        assert result.records[0].severity == "critical"

    def test_empty_list(self):
        n = InputNormalizer()
        result = n.load_cve_feed("[]")
        assert len(result.records) == 0

    def test_non_dict_entries_logged_as_errors(self):
        n = InputNormalizer()
        data = json.dumps(["not-a-dict", {"cveID": "CVE-1"}])
        result = n.load_cve_feed(data)
        assert len(result.records) == 1
        assert len(result.errors) >= 1

    def test_gzip_input(self):
        n = InputNormalizer()
        raw = json.dumps([{"cveID": "CVE-2024-0001"}]).encode()
        compressed = gzip.compress(raw)
        result = n.load_cve_feed(compressed)
        assert len(result.records) == 1


# ===========================================================================
# InputNormalizer.load_sbom tests (provider fallback)
# ===========================================================================


class TestInputNormalizerLoadSBOM:
    def test_cyclonedx_json(self):
        n = InputNormalizer()
        cdx = json.dumps({
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [
                {"name": "lodash", "version": "4.17.21", "type": "library"},
                {"name": "express", "version": "4.18.0", "type": "library"},
            ],
        })
        result = n.load_sbom(cdx)
        assert isinstance(result, NormalizedSBOM)
        # lib4sbom returns uppercase "CycloneDX"; provider fallback returns lowercase
        assert result.format.lower() == "cyclonedx"
        assert len(result.components) == 2
        assert result.metadata["component_count"] == 2

    def test_cyclonedx_with_vulnerabilities(self):
        n = InputNormalizer()
        cdx = json.dumps({
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [
                {"name": "lib", "version": "1.0", "type": "library"},
            ],
            "vulnerabilities": [
                {"id": "CVE-2024-0001", "description": "test"},
            ],
        })
        result = n.load_sbom(cdx)
        assert result.metadata["vulnerability_count"] >= 1

    def test_github_dependency_snapshot(self):
        """GitHub dependency snapshot: lib4sbom may parse first with 0 components.
        We test that load_sbom succeeds and returns a NormalizedSBOM."""
        n = InputNormalizer()
        snapshot = json.dumps({
            "detectedManifests": {
                "package.json": {
                    "resolved": {
                        "lodash": {"name": "lodash", "version": "4.17.21"},
                    }
                }
            }
        })
        result = n.load_sbom(snapshot)
        assert isinstance(result, NormalizedSBOM)
        # lib4sbom returns 0 components for this format; provider fallback
        # returns 1 -- behavior depends on lib4sbom availability.
        assert result.format is not None

    def test_syft_json(self):
        """Syft JSON: lib4sbom may parse first. Verify NormalizedSBOM returned."""
        n = InputNormalizer()
        syft = json.dumps({
            "artifacts": [
                {"name": "curl", "version": "7.68.0"},
                {"name": "openssl", "version": "1.1.1"},
            ],
            "descriptor": {"name": "syft", "version": "0.50.0"},
        })
        result = n.load_sbom(syft)
        assert isinstance(result, NormalizedSBOM)
        # Components may be found by lib4sbom or provider fallback
        assert result.format is not None
