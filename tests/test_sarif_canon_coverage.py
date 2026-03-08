"""Tests for core.sarif_canon — SARIF canonicalization."""

import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.sarif_canon import (
    _normalize_severity,
    _normalize_path,
    _extract_tool_info,
    _extract_cwe,
    _extract_cvss,
    normalize_sarif,
    write_normalized_sarif,
)


# ── Severity Normalization ───────────────────────────────────────────

class TestNormalizeSeverity:
    def test_error_maps_to_high(self):
        assert _normalize_severity("error") == "HIGH"

    def test_warning_maps_to_medium(self):
        assert _normalize_severity("warning") == "MEDIUM"

    def test_note_maps_to_low(self):
        assert _normalize_severity("note") == "LOW"

    def test_none_string_maps_to_info(self):
        assert _normalize_severity("none") == "INFO"

    def test_critical_maps_to_critical(self):
        assert _normalize_severity("critical") == "CRITICAL"

    def test_case_insensitive(self):
        assert _normalize_severity("HIGH") == "HIGH"
        assert _normalize_severity("Medium") == "MEDIUM"
        assert _normalize_severity("LOW") == "LOW"

    def test_none_input(self):
        assert _normalize_severity(None) == "INFO"

    def test_empty_string(self):
        assert _normalize_severity("") == "INFO"

    def test_unknown_defaults_to_medium(self):
        assert _normalize_severity("unknown_level") == "MEDIUM"

    def test_informational(self):
        assert _normalize_severity("informational") == "INFO"

    def test_whitespace_stripped(self):
        assert _normalize_severity("  high  ") == "HIGH"


# ── Path Normalization ───────────────────────────────────────────────

class TestNormalizePath:
    def test_forward_slash_preserved(self):
        assert _normalize_path("src/main.py") == "src/main.py"

    def test_backslash_converted(self):
        assert _normalize_path("src\\main.py") == "src/main.py"

    def test_absolute_path_stripped(self):
        result = _normalize_path("/home/user/project/src/main.py")
        assert not result.startswith("/")

    def test_empty_string(self):
        assert _normalize_path("") == ""

    def test_single_component(self):
        assert _normalize_path("file.py") == "file.py"


# ── Tool Info Extraction ─────────────────────────────────────────────

class TestExtractToolInfo:
    def test_basic_extraction(self):
        sarif = {
            "runs": [
                {
                    "tool": {
                        "driver": {"name": "Semgrep", "version": "1.0.0"}
                    }
                }
            ]
        }
        info = _extract_tool_info(sarif)
        assert info["name"] == "semgrep"
        assert info["version"] == "1.0.0"

    def test_no_runs(self):
        info = _extract_tool_info({"runs": []})
        assert info["name"] == "unknown"
        assert info["version"] == "unknown"

    def test_missing_runs(self):
        info = _extract_tool_info({})
        assert info["name"] == "unknown"

    def test_semantic_version(self):
        sarif = {
            "runs": [
                {
                    "tool": {
                        "driver": {"name": "ESLint", "semanticVersion": "8.15.0"}
                    }
                }
            ]
        }
        info = _extract_tool_info(sarif)
        assert info["version"] == "8.15.0"

    def test_no_version(self):
        sarif = {
            "runs": [{"tool": {"driver": {"name": "MyTool"}}}]
        }
        info = _extract_tool_info(sarif)
        assert info["version"] == "unknown"


# ── CWE Extraction ──────────────────────────────────────────────────

class TestExtractCWE:
    def test_cwe_from_taxa(self):
        result = {"taxa": [{"id": "CWE-79"}]}
        cwes = _extract_cwe(result)
        assert "CWE-79" in cwes

    def test_cwe_from_properties_string(self):
        result = {"properties": {"cwe": "CWE-89"}}
        cwes = _extract_cwe(result)
        assert "CWE-89" in cwes

    def test_cwe_from_properties_list(self):
        result = {"properties": {"cwe": ["CWE-79", "CWE-89"]}}
        cwes = _extract_cwe(result)
        assert "CWE-79" in cwes
        assert "CWE-89" in cwes

    def test_no_cwe(self):
        cwes = _extract_cwe({})
        assert cwes == []

    def test_deduplicated(self):
        result = {
            "taxa": [{"id": "CWE-79"}],
            "properties": {"cwe": "CWE-79"},
        }
        cwes = _extract_cwe(result)
        assert cwes == ["CWE-79"]

    def test_sorted(self):
        result = {"properties": {"cwe": ["CWE-89", "CWE-22", "CWE-79"]}}
        cwes = _extract_cwe(result)
        assert cwes == sorted(cwes)

    def test_uppercase_cwe(self):
        result = {"properties": {"CWE": "CWE-200"}}
        cwes = _extract_cwe(result)
        assert "CWE-200" in cwes


# ── CVSS Extraction ─────────────────────────────────────────────────

class TestExtractCVSS:
    def test_basic_cvss(self):
        result = {"properties": {"cvss": 7.5}}
        cvss = _extract_cvss(result)
        assert cvss is not None
        assert cvss["score"] == 7.5

    def test_cvss_with_vector(self):
        result = {
            "properties": {
                "cvssScore": 9.8,
                "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            }
        }
        cvss = _extract_cvss(result)
        assert cvss is not None
        assert cvss["score"] == 9.8
        assert "CVSS:3.1" in cvss["vector"]

    def test_no_cvss(self):
        assert _extract_cvss({}) is None

    def test_invalid_cvss(self):
        result = {"properties": {"cvss": "not_a_number"}}
        assert _extract_cvss(result) is None

    def test_string_cvss_score(self):
        result = {"properties": {"cvss": "8.5"}}
        cvss = _extract_cvss(result)
        assert cvss is not None
        assert cvss["score"] == 8.5


# ── Full SARIF Normalization ────────────────────────────────────────

def _make_sarif(findings=None):
    """Helper to create a minimal valid SARIF document."""
    if findings is None:
        findings = [
            {
                "ruleId": "TEST-001",
                "level": "error",
                "message": {"text": "Test finding"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": "src/main.py"},
                            "region": {"startLine": 42},
                        }
                    }
                ],
            }
        ]
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "TestScanner", "version": "1.0"}},
                "results": findings,
            }
        ],
    }


class TestNormalizeSarif:
    def test_basic_normalization(self, tmp_path):
        sarif_file = tmp_path / "test.sarif"
        sarif_file.write_text(json.dumps(_make_sarif()))
        result = normalize_sarif(sarif_file)
        assert "metadata" in result
        assert "findings" in result
        assert len(result["findings"]) == 1
        finding = result["findings"][0]
        assert finding["rule_id"] == "TEST-001"
        assert finding["severity"] == "HIGH"
        assert finding["file_path"] == "src/main.py"
        assert finding["line_number"] == 42

    def test_multiple_findings(self, tmp_path):
        findings = [
            {
                "ruleId": f"RULE-{i:03d}",
                "level": "warning",
                "message": {"text": f"Finding {i}"},
            }
            for i in range(5)
        ]
        sarif_file = tmp_path / "multi.sarif"
        sarif_file.write_text(json.dumps(_make_sarif(findings)))
        result = normalize_sarif(sarif_file)
        assert len(result["findings"]) == 5

    def test_empty_findings(self, tmp_path):
        sarif_file = tmp_path / "empty.sarif"
        sarif_file.write_text(json.dumps(_make_sarif([])))
        result = normalize_sarif(sarif_file)
        assert result["findings"] == []

    def test_tool_metadata(self, tmp_path):
        sarif_file = tmp_path / "meta.sarif"
        sarif_file.write_text(json.dumps(_make_sarif()))
        result = normalize_sarif(sarif_file)
        assert result["metadata"]["tool"]["name"] == "testscanner"
        assert result["metadata"]["tool"]["version"] == "1.0"
        assert "source_hash" in result["metadata"]
        assert "generated_at" in result["metadata"]

    def test_findings_sorted(self, tmp_path):
        findings = [
            {"ruleId": "Z-001", "level": "note", "message": {"text": "z"}},
            {"ruleId": "A-001", "level": "error", "message": {"text": "a"}},
            {"ruleId": "M-001", "level": "warning", "message": {"text": "m"}},
        ]
        sarif_file = tmp_path / "sort.sarif"
        sarif_file.write_text(json.dumps(_make_sarif(findings)))
        result = normalize_sarif(sarif_file)
        rule_ids = [f["rule_id"] for f in result["findings"]]
        assert rule_ids == sorted(rule_ids)


class TestWriteNormalizedSarif:
    def test_writes_file(self, tmp_path):
        sarif_file = tmp_path / "input.sarif"
        sarif_file.write_text(json.dumps(_make_sarif()))
        dest = tmp_path / "output" / "normalized.json"
        write_normalized_sarif(sarif_file, dest)
        assert dest.exists()
        written = json.loads(dest.read_text())
        assert "findings" in written
        assert len(written["findings"]) == 1

    def test_strict_schema_valid(self, tmp_path):
        sarif_file = tmp_path / "input.sarif"
        sarif_file.write_text(json.dumps(_make_sarif()))
        dest = tmp_path / "strict.json"
        write_normalized_sarif(sarif_file, dest, strict_schema=True)
        assert dest.exists()

    def test_strict_schema_invalid(self, tmp_path):
        findings = [
            {"level": "warning", "message": {"text": "missing ruleId"}}
        ]
        sarif_data = _make_sarif(findings)
        # The normalize_sarif gives "unknown" as default ruleId so it passes
        sarif_file = tmp_path / "bad.sarif"
        sarif_file.write_text(json.dumps(sarif_data))
        dest = tmp_path / "bad_out.json"
        # Should not raise since ruleId defaults to "unknown"
        result = write_normalized_sarif(sarif_file, dest, strict_schema=True)
        assert "findings" in result

    def test_creates_parent_dirs(self, tmp_path):
        sarif_file = tmp_path / "input.sarif"
        sarif_file.write_text(json.dumps(_make_sarif()))
        dest = tmp_path / "deep" / "nested" / "out.json"
        write_normalized_sarif(sarif_file, dest)
        assert dest.exists()
