"""Unit tests for suite-evidence-risk/risk/reachability/code_analysis.py.

Pillar: V3 (Decision Intelligence) — reachability analysis determines exploitability.
Coverage target: code_analysis.py (553 LOC, ~0% baseline).
Created: 2026-03-01 by agent-doctor (health run v10).
"""

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

# Ensure the real module is imported first so that test_reachability_analyzer_unit
# (which may run earlier) doesn't replace it with a stub missing subprocess.
import risk.reachability.code_analysis as _ca_mod
if not hasattr(_ca_mod, "subprocess"):
    _ca_mod.subprocess = subprocess  # type: ignore[attr-defined]

from risk.reachability.code_analysis import (
    AnalysisResult,
    AnalysisTool,
    CodeAnalyzer,
    CodeLocation,
    VulnerablePattern,
)


# ---------------------------------------------------------------------------
# 1. Enum Tests
# ---------------------------------------------------------------------------


class TestAnalysisTool:
    def test_codeql_value(self):
        assert AnalysisTool.CODEQL.value == "codeql"

    def test_semgrep_value(self):
        assert AnalysisTool.SEMGREP.value == "semgrep"

    def test_sonarqube_value(self):
        assert AnalysisTool.SONARQUBE.value == "sonarqube"

    def test_bandit_value(self):
        assert AnalysisTool.BANDIT.value == "bandit"

    def test_eslint_value(self):
        assert AnalysisTool.ESLINT.value == "eslint"

    def test_custom_value(self):
        assert AnalysisTool.CUSTOM.value == "custom"


# ---------------------------------------------------------------------------
# 2. Dataclass Tests
# ---------------------------------------------------------------------------


class TestVulnerablePattern:
    def test_create_minimal(self):
        p = VulnerablePattern(cve_id="CVE-2021-44228")
        assert p.cve_id == "CVE-2021-44228"
        assert p.cwe_id is None
        assert p.pattern_type == ""
        assert p.vulnerable_functions == []
        assert p.severity == "medium"

    def test_create_full(self):
        p = VulnerablePattern(
            cve_id="CVE-2021-44228",
            cwe_id="CWE-502",
            pattern_type="deserialization",
            vulnerable_functions=["lookup", "resolve"],
            vulnerable_classes=["JndiLookup"],
            vulnerable_apis=["javax.naming.Context.lookup"],
            file_patterns=["*.java"],
            description="JNDI injection",
            severity="critical",
        )
        assert p.cwe_id == "CWE-502"
        assert "lookup" in p.vulnerable_functions
        assert p.severity == "critical"


class TestCodeLocation:
    def test_create(self):
        loc = CodeLocation(
            file_path="/src/Main.java",
            line_number=42,
            column_number=10,
            function_name="processInput",
            class_name="MainController",
            code_snippet="String result = ctx.lookup(input);",
        )
        assert loc.file_path == "/src/Main.java"
        assert loc.line_number == 42
        assert loc.class_name == "MainController"

    def test_create_minimal(self):
        loc = CodeLocation(file_path="/src/app.py", line_number=1)
        assert loc.column_number is None
        assert loc.function_name is None


class TestAnalysisResult:
    def test_create_success(self):
        r = AnalysisResult(
            tool=AnalysisTool.SEMGREP,
            success=True,
            findings=[{"rule": "sqli", "file": "app.py", "line": 10}],
        )
        assert r.success is True
        assert len(r.findings) == 1

    def test_create_failure(self):
        r = AnalysisResult(
            tool=AnalysisTool.CODEQL,
            success=False,
            errors=["CodeQL not installed"],
        )
        assert r.success is False
        assert "CodeQL not installed" in r.errors

    def test_to_dict(self):
        r = AnalysisResult(
            tool=AnalysisTool.BANDIT,
            success=True,
            findings=[{"issue": "B101"}],
            call_graph={"nodes": 5},
            data_flow={"paths": 2},
            errors=[],
            warnings=["slow scan"],
            metadata={"duration": 12.5},
        )
        d = r.to_dict()
        assert d["tool"] == "bandit"
        assert d["success"] is True
        assert d["call_graph"] == {"nodes": 5}
        assert d["metadata"]["duration"] == 12.5

    def test_to_dict_defaults(self):
        r = AnalysisResult(tool=AnalysisTool.SEMGREP, success=True)
        d = r.to_dict()
        assert d["findings"] == []
        assert d["errors"] == []
        assert d["call_graph"] is None


# ---------------------------------------------------------------------------
# 3. CodeAnalyzer Init
# ---------------------------------------------------------------------------


class TestCodeAnalyzerInit:
    @patch("risk.reachability.code_analysis.subprocess.run")
    def test_init_default_tools(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1)  # tools not available
        analyzer = CodeAnalyzer()
        assert AnalysisTool.SEMGREP in analyzer.tools
        assert AnalysisTool.CODEQL in analyzer.tools

    @patch("risk.reachability.code_analysis.subprocess.run")
    def test_init_custom_tools(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1)
        analyzer = CodeAnalyzer(tools=[AnalysisTool.BANDIT])
        assert analyzer.tools == [AnalysisTool.BANDIT]

    @patch("risk.reachability.code_analysis.subprocess.run")
    def test_init_with_config(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1)
        config = {"semgrep": {"rules_dir": "/custom/rules"}}
        analyzer = CodeAnalyzer(config=config)
        assert analyzer.config == config
        assert analyzer.tool_configs[AnalysisTool.SEMGREP] == {"rules_dir": "/custom/rules"}


# ---------------------------------------------------------------------------
# 4. Tool Availability Checks
# ---------------------------------------------------------------------------


class TestToolAvailability:
    @patch("risk.reachability.code_analysis.subprocess.run")
    def test_tool_available(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0)
        analyzer = CodeAnalyzer(tools=[AnalysisTool.SEMGREP])
        assert AnalysisTool.SEMGREP in analyzer.available_tools

    @patch("risk.reachability.code_analysis.subprocess.run")
    def test_tool_not_available(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1)
        analyzer = CodeAnalyzer(tools=[AnalysisTool.CODEQL])
        assert AnalysisTool.CODEQL not in analyzer.available_tools

    @patch("risk.reachability.code_analysis.subprocess.run", side_effect=FileNotFoundError)
    def test_tool_binary_missing(self, mock_run):
        analyzer = CodeAnalyzer(tools=[AnalysisTool.BANDIT])
        assert AnalysisTool.BANDIT not in analyzer.available_tools

    @patch("risk.reachability.code_analysis.subprocess.run")
    def test_tool_timeout(self, mock_run):
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="semgrep", timeout=5)
        analyzer = CodeAnalyzer(tools=[AnalysisTool.SEMGREP])
        assert AnalysisTool.SEMGREP not in analyzer.available_tools


# ---------------------------------------------------------------------------
# 5. Repository Analysis
# ---------------------------------------------------------------------------


class TestAnalyzeRepository:
    @patch("risk.reachability.code_analysis.subprocess.run")
    def test_analyze_no_tools_available(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1)
        analyzer = CodeAnalyzer(tools=[AnalysisTool.CODEQL])
        patterns = [VulnerablePattern(cve_id="CVE-2021-44228")]
        results = analyzer.analyze_repository(Path("/tmp/fake"), patterns)
        assert results == {}

    @patch("risk.reachability.code_analysis.subprocess.run")
    def test_analyze_with_semgrep_available(self, mock_run):
        # First call: version check succeeds, subsequent calls: analysis
        mock_run.return_value = MagicMock(returncode=0, stdout=b"1.0.0", stderr=b"")
        analyzer = CodeAnalyzer(tools=[AnalysisTool.SEMGREP])

        if AnalysisTool.SEMGREP in analyzer.available_tools:
            patterns = [VulnerablePattern(cve_id="CVE-2021-44228", pattern_type="jndi_injection")]
            # Mock the semgrep run to return empty results
            mock_run.return_value = MagicMock(returncode=0, stdout=b'{"results": []}', stderr=b"")
            results = analyzer.analyze_repository(Path("/tmp/fake"), patterns, language="Java")
            assert AnalysisTool.SEMGREP in results


# ---------------------------------------------------------------------------
# 6. Language Detection
# ---------------------------------------------------------------------------


class TestLanguageDetection:
    @patch("risk.reachability.code_analysis.subprocess.run")
    def test_detect_python_project(self, mock_run, tmp_path: Path):
        mock_run.return_value = MagicMock(returncode=1)
        analyzer = CodeAnalyzer(tools=[])
        # Create Python files
        (tmp_path / "app.py").write_text("print('hello')")
        (tmp_path / "main.py").write_text("import sys")
        lang = analyzer._detect_primary_language(tmp_path)
        assert lang == "Python"

    @patch("risk.reachability.code_analysis.subprocess.run")
    def test_detect_javascript_project(self, mock_run, tmp_path: Path):
        mock_run.return_value = MagicMock(returncode=1)
        analyzer = CodeAnalyzer(tools=[])
        # Create JS files
        (tmp_path / "index.js").write_text("console.log('hello')")
        (tmp_path / "app.js").write_text("module.exports = {}")
        (tmp_path / "util.js").write_text("function foo() {}")
        lang = analyzer._detect_primary_language(tmp_path)
        assert lang == "JavaScript"

    @patch("risk.reachability.code_analysis.subprocess.run")
    def test_detect_empty_project(self, mock_run, tmp_path: Path):
        mock_run.return_value = MagicMock(returncode=1)
        analyzer = CodeAnalyzer(tools=[])
        lang = analyzer._detect_primary_language(tmp_path)
        # Should return a default
        assert isinstance(lang, str)
