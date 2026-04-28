"""
Tests for scripts/render_self_scan_html.py

Verifies:
  - Valid HTML produced from fixture JSON
  - Required sections present: title, scan_date, severity_counts, top_findings_table
  - HTML file < 50 KB
  - Edge cases: empty findings, missing optional fields
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Load render module without installing it as a package
# ---------------------------------------------------------------------------
_RENDER_PATH = Path(__file__).resolve().parent.parent / "scripts" / "render_self_scan_html.py"


def _load_render():
    spec = importlib.util.spec_from_file_location("render_self_scan_html", _RENDER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


render_mod = _load_render()
render = render_mod.render


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

_FIXTURE_REPORT = {
    "scan_id": "aaaabbbb-1234-5678-abcd-000000000001",
    "scanned_at": "2026-04-27T10:00:00+00:00",
    "project_root": "/workspace/Fixops",
    "duration_seconds": 3.45,
    "risk_score": 42.5,
    "grade": "C",
    "files_scanned": 312,
    "lines_scanned": 87654,
    "findings_by_severity": {
        "critical": 2,
        "high": 5,
        "medium": 10,
        "low": 8,
        "info": 3,
    },
    "findings_by_category": {
        "sast": 12,
        "dependency": 7,
        "container": 3,
        "config": 4,
        "api_surface": 2,
    },
    "findings": [
        {
            "finding_id": "f1",
            "category": "sast",
            "severity": "critical",
            "title": "Use of eval()",
            "description": "eval() executes arbitrary code",
            "file_path": "suite-core/core/brain_pipeline.py",
            "line_number": 99,
            "code_snippet": "eval(user_input)",
            "cwe_id": "CWE-95",
            "owasp": "A03:2021",
            "recommendation": "Replace with ast.literal_eval",
            "confidence": 0.95,
            "remediation_effort": "low",
            "tags": ["sast", "eval"],
        },
        {
            "finding_id": "f2",
            "category": "dependency",
            "severity": "high",
            "title": "CVE-2023-49083 in cryptography",
            "description": "NULL pointer dereference in PKCS12 parsing",
            "file_path": "requirements.txt",
            "line_number": None,
            "code_snippet": None,
            "cwe_id": "CWE-476",
            "owasp": "A06:2021",
            "recommendation": "Upgrade cryptography to >= 42.0.0",
            "confidence": 0.9,
            "remediation_effort": "low",
            "tags": ["dependency", "cve"],
        },
    ],
    "dependencies": [],
    "compliance_gaps": ["SOC2-CC6.1: Missing encryption at rest controls", "PCI-DSS 6.5.1: eval() usage"],
    "remediation_priorities": ["Fix 2 CRITICAL findings immediately", "Upgrade vulnerable dependencies"],
    "ci_workflow_yaml": None,
}

_EMPTY_REPORT = {
    "scan_id": "empty-0000",
    "scanned_at": "2026-04-27T00:00:00+00:00",
    "project_root": "/workspace/Fixops",
    "duration_seconds": 1.0,
    "risk_score": 0.0,
    "grade": "A",
    "files_scanned": 0,
    "lines_scanned": 0,
    "findings_by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
    "findings_by_category": {"sast": 0, "dependency": 0, "container": 0, "config": 0, "api_surface": 0},
    "findings": [],
    "dependencies": [],
    "compliance_gaps": [],
    "remediation_priorities": [],
    "ci_workflow_yaml": None,
}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestRenderProducesValidHTML:
    def test_returns_string(self):
        out = render(_FIXTURE_REPORT)
        assert isinstance(out, str)

    def test_starts_with_doctype(self):
        out = render(_FIXTURE_REPORT)
        assert out.strip().startswith("<!DOCTYPE html>")

    def test_contains_html_and_body_tags(self):
        out = render(_FIXTURE_REPORT)
        assert "<html" in out
        assert "</html>" in out
        assert "<body" in out
        assert "</body>" in out


class TestRequiredSections:
    def test_title_present(self):
        """Page must have ALDECI self-scan branding in <title>."""
        out = render(_FIXTURE_REPORT)
        assert "<title>ALDECI Self-Scan Dashboard</title>" in out

    def test_scan_date_present(self):
        """scan_date must appear in the output (id=scan_date element)."""
        out = render(_FIXTURE_REPORT)
        assert 'id="scan_date"' in out
        assert "2026-04-27" in out

    def test_severity_counts_present(self):
        """All five severity levels must appear with their counts."""
        out = render(_FIXTURE_REPORT)
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            assert sev in out
        # Actual counts
        assert "2" in out   # critical count
        assert "5" in out   # high count
        assert "10" in out  # medium count

    def test_top_findings_table_present(self):
        """Must include a top_findings_table section."""
        out = render(_FIXTURE_REPORT)
        assert 'id="top_findings_table"' in out
        assert "<table>" in out or "<table" in out

    def test_top_findings_table_contains_findings(self):
        out = render(_FIXTURE_REPORT)
        assert "Use of eval()" in out
        assert "CWE-95" in out
        assert "A03:2021" in out

    def test_category_breakdown_present(self):
        out = render(_FIXTURE_REPORT)
        for label in ("SAST", "Dependency", "Container", "Config", "API Surface"):
            assert label in out

    def test_remediation_priorities_present(self):
        out = render(_FIXTURE_REPORT)
        assert "Fix 2 CRITICAL" in out

    def test_compliance_gaps_present(self):
        out = render(_FIXTURE_REPORT)
        assert "SOC2-CC6.1" in out


class TestHTMLSize:
    def test_under_50kb_fixture(self):
        out = render(_FIXTURE_REPORT)
        size = len(out.encode("utf-8"))
        assert size < 51200, f"HTML too large: {size} bytes (limit 50 KB)"

    def test_under_50kb_empty(self):
        out = render(_EMPTY_REPORT)
        size = len(out.encode("utf-8"))
        assert size < 51200, f"HTML too large: {size} bytes (limit 50 KB)"


class TestEdgeCases:
    def test_empty_findings_renders(self):
        out = render(_EMPTY_REPORT)
        assert "ALDECI Self-Scan Dashboard" in out
        assert "None identified." in out

    def test_xss_escaping(self):
        """File paths or titles with HTML special chars must be escaped."""
        malicious = dict(_FIXTURE_REPORT)
        malicious["findings"] = [
            {
                "finding_id": "f-xss",
                "category": "sast",
                "severity": "high",
                "title": '<script>alert("xss")</script>',
                "description": "xss test",
                "file_path": "<img src=x onerror=alert(1)>",
                "line_number": 1,
                "code_snippet": None,
                "cwe_id": None,
                "owasp": None,
                "recommendation": "fix it",
                "confidence": 0.9,
                "remediation_effort": "low",
                "tags": [],
            }
        ]
        out = render(malicious)
        assert "<script>" not in out
        assert "&lt;script&gt;" in out

    def test_grade_a_colour(self):
        out = render(_EMPTY_REPORT)
        assert "#22c55e" in out  # green for A

    def test_grade_c_colour(self):
        out = render(_FIXTURE_REPORT)
        assert "#eab308" in out  # yellow for C

    def test_missing_optional_fields_no_crash(self):
        minimal = {
            "scan_id": "min-001",
            "scanned_at": "2026-04-27T00:00:00Z",
            "project_root": "/tmp",
            "duration_seconds": 0,
            "risk_score": 0,
            "grade": "A",
            "files_scanned": 0,
            "lines_scanned": 0,
        }
        out = render(minimal)
        assert "ALDECI Self-Scan Dashboard" in out


class TestCLI:
    def test_cli_writes_file(self, tmp_path):
        input_file = tmp_path / "report.json"
        input_file.write_text(json.dumps(_FIXTURE_REPORT), encoding="utf-8")
        out_file = tmp_path / "out" / "index.html"

        # Simulate CLI
        old_argv = sys.argv
        sys.argv = ["render_self_scan_html.py", str(input_file), "--out", str(out_file)]
        try:
            render_mod.main()
        finally:
            sys.argv = old_argv

        assert out_file.exists()
        content = out_file.read_text(encoding="utf-8")
        assert "ALDECI Self-Scan Dashboard" in content
        assert len(content.encode()) < 51200
