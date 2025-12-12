"""Rigorous tests for CodeAnalyzer and related code analysis functionality.

These tests verify code analysis tools, pattern matching, and language detection
with realistic scenarios and proper assertions.
"""

import subprocess
from unittest.mock import MagicMock, patch

from risk.reachability.code_analysis import (
    AnalysisResult,
    AnalysisTool,
    CodeAnalyzer,
    CodeLocation,
    VulnerablePattern,
)


class TestAnalysisTool:
    """Tests for AnalysisTool enum."""

    def test_tool_values(self):
        """Verify all analysis tools have expected string values."""
        assert AnalysisTool.CODEQL.value == "codeql"
        assert AnalysisTool.SEMGREP.value == "semgrep"
        assert AnalysisTool.SONARQUBE.value == "sonarqube"
        assert AnalysisTool.BANDIT.value == "bandit"
        assert AnalysisTool.ESLINT.value == "eslint"
        assert AnalysisTool.CUSTOM.value == "custom"


class TestVulnerablePattern:
    """Tests for VulnerablePattern dataclass."""

    def test_default_values(self):
        """Verify VulnerablePattern has correct defaults."""
        pattern = VulnerablePattern(cve_id="CVE-2023-12345")
        assert pattern.cve_id == "CVE-2023-12345"
        assert pattern.cwe_id is None
        assert pattern.pattern_type == ""
        assert pattern.vulnerable_functions == []
        assert pattern.vulnerable_classes == []
        assert pattern.vulnerable_apis == []
        assert pattern.file_patterns == []
        assert pattern.description == ""
        assert pattern.severity == "medium"

    def test_full_pattern(self):
        """Verify VulnerablePattern stores all fields correctly."""
        pattern = VulnerablePattern(
            cve_id="CVE-2023-54321",
            cwe_id="CWE-89",
            pattern_type="sql_injection",
            vulnerable_functions=["execute", "query"],
            vulnerable_classes=["Database", "Connection"],
            vulnerable_apis=["db.execute", "conn.query"],
            file_patterns=["*.py", "*.sql"],
            description="SQL injection vulnerability",
            severity="critical",
        )
        assert pattern.cve_id == "CVE-2023-54321"
        assert pattern.cwe_id == "CWE-89"
        assert pattern.pattern_type == "sql_injection"
        assert len(pattern.vulnerable_functions) == 2
        assert len(pattern.vulnerable_classes) == 2
        assert len(pattern.vulnerable_apis) == 2
        assert len(pattern.file_patterns) == 2
        assert pattern.severity == "critical"


class TestCodeLocation:
    """Tests for CodeLocation dataclass."""

    def test_minimal_location(self):
        """Verify CodeLocation with minimal fields."""
        loc = CodeLocation(file_path="src/main.py", line_number=42)
        assert loc.file_path == "src/main.py"
        assert loc.line_number == 42
        assert loc.column_number is None
        assert loc.function_name is None
        assert loc.class_name is None
        assert loc.code_snippet is None

    def test_full_location(self):
        """Verify CodeLocation with all fields."""
        loc = CodeLocation(
            file_path="src/db.py",
            line_number=100,
            column_number=8,
            function_name="execute_query",
            class_name="DatabaseConnection",
            code_snippet="cursor.execute(query)",
        )
        assert loc.file_path == "src/db.py"
        assert loc.line_number == 100
        assert loc.column_number == 8
        assert loc.function_name == "execute_query"
        assert loc.class_name == "DatabaseConnection"
        assert loc.code_snippet == "cursor.execute(query)"


class TestAnalysisResult:
    """Tests for AnalysisResult dataclass."""

    def test_default_values(self):
        """Verify AnalysisResult has correct defaults."""
        result = AnalysisResult(tool=AnalysisTool.SEMGREP, success=True)
        assert result.tool == AnalysisTool.SEMGREP
        assert result.success is True
        assert result.findings == []
        assert result.call_graph is None
        assert result.data_flow is None
        assert result.errors == []
        assert result.warnings == []
        assert result.metadata == {}

    def test_to_dict(self):
        """Verify to_dict produces correct dictionary structure."""
        result = AnalysisResult(
            tool=AnalysisTool.CODEQL,
            success=True,
            findings=[{"id": "finding1", "severity": "high"}],
            call_graph={"nodes": ["main", "handler"]},
            data_flow={"sources": ["input"], "sinks": ["output"]},
            errors=["error1"],
            warnings=["warning1"],
            metadata={"version": "1.0"},
        )
        d = result.to_dict()
        assert d["tool"] == "codeql"
        assert d["success"] is True
        assert len(d["findings"]) == 1
        assert d["call_graph"]["nodes"] == ["main", "handler"]
        assert d["data_flow"]["sources"] == ["input"]
        assert d["errors"] == ["error1"]
        assert d["warnings"] == ["warning1"]
        assert d["metadata"]["version"] == "1.0"

    def test_failed_result(self):
        """Verify failed result structure."""
        result = AnalysisResult(
            tool=AnalysisTool.BANDIT,
            success=False,
            errors=["Tool not found", "Analysis failed"],
        )
        assert result.success is False
        assert len(result.errors) == 2


class TestCodeAnalyzerInit:
    """Tests for CodeAnalyzer initialization."""

    def test_default_initialization(self):
        """Verify analyzer initializes with default settings."""
        with patch.object(CodeAnalyzer, "_check_tool_availability", return_value=set()):
            analyzer = CodeAnalyzer()
            assert analyzer.config == {}
            assert AnalysisTool.SEMGREP in analyzer.tools
            assert AnalysisTool.CODEQL in analyzer.tools

    def test_custom_tools(self):
        """Verify analyzer uses custom tool list."""
        with patch.object(CodeAnalyzer, "_check_tool_availability", return_value=set()):
            analyzer = CodeAnalyzer(tools=[AnalysisTool.BANDIT])
            assert analyzer.tools == [AnalysisTool.BANDIT]

    def test_custom_config(self):
        """Verify analyzer uses custom configuration."""
        config = {
            "semgrep": {"rules": ["p/security-audit"]},
            "bandit": {"severity": "high"},
        }
        with patch.object(CodeAnalyzer, "_check_tool_availability", return_value=set()):
            analyzer = CodeAnalyzer(config=config)
            assert analyzer.tool_configs[AnalysisTool.SEMGREP] == {
                "rules": ["p/security-audit"]
            }
            assert analyzer.tool_configs[AnalysisTool.BANDIT] == {"severity": "high"}


class TestToolAvailability:
    """Tests for tool availability checking."""

    def test_tool_not_available_file_not_found(self):
        """Verify tool marked unavailable when not found."""
        with patch("subprocess.run", side_effect=FileNotFoundError()):
            analyzer = CodeAnalyzer(tools=[AnalysisTool.CODEQL])
            assert AnalysisTool.CODEQL not in analyzer.available_tools

    def test_tool_not_available_timeout(self):
        """Verify tool marked unavailable on timeout."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 5)):
            analyzer = CodeAnalyzer(tools=[AnalysisTool.SEMGREP])
            assert AnalysisTool.SEMGREP not in analyzer.available_tools

    def test_tool_available_success(self):
        """Verify tool marked available when command succeeds."""
        mock_result = MagicMock()
        mock_result.returncode = 0
        with patch("subprocess.run", return_value=mock_result):
            analyzer = CodeAnalyzer(tools=[AnalysisTool.SEMGREP])
            assert AnalysisTool.SEMGREP in analyzer.available_tools

    def test_tool_unavailable_nonzero_return(self):
        """Verify tool marked unavailable on non-zero return code."""
        mock_result = MagicMock()
        mock_result.returncode = 1
        with patch("subprocess.run", return_value=mock_result):
            analyzer = CodeAnalyzer(tools=[AnalysisTool.CODEQL])
            assert AnalysisTool.CODEQL not in analyzer.available_tools


class TestLanguageDetection:
    """Tests for primary language detection."""

    def test_detect_python(self, tmp_path):
        """Verify Python detected as primary language."""
        # Create Python files
        (tmp_path / "main.py").write_text("print('hello')")
        (tmp_path / "utils.py").write_text("def helper(): pass")
        (tmp_path / "test.py").write_text("import pytest")

        with patch.object(CodeAnalyzer, "_check_tool_availability", return_value=set()):
            analyzer = CodeAnalyzer()
            lang = analyzer._detect_primary_language(tmp_path)
            assert lang == "Python"

    def test_detect_javascript(self, tmp_path):
        """Verify JavaScript detected as primary language."""
        # Create JavaScript files
        (tmp_path / "index.js").write_text("console.log('hello')")
        (tmp_path / "app.js").write_text("const x = 1")
        (tmp_path / "utils.js").write_text("export default {}")

        with patch.object(CodeAnalyzer, "_check_tool_availability", return_value=set()):
            analyzer = CodeAnalyzer()
            lang = analyzer._detect_primary_language(tmp_path)
            assert lang == "JavaScript"

    def test_detect_typescript(self, tmp_path):
        """Verify TypeScript detected as primary language."""
        # Create TypeScript files
        (tmp_path / "index.ts").write_text("const x: number = 1")
        (tmp_path / "app.ts").write_text("interface User {}")
        (tmp_path / "utils.ts").write_text("export type T = string")

        with patch.object(CodeAnalyzer, "_check_tool_availability", return_value=set()):
            analyzer = CodeAnalyzer()
            lang = analyzer._detect_primary_language(tmp_path)
            assert lang == "TypeScript"

    def test_detect_java(self, tmp_path):
        """Verify Java detected as primary language."""
        # Create Java files
        (tmp_path / "Main.java").write_text("public class Main {}")
        (tmp_path / "App.java").write_text("public class App {}")

        with patch.object(CodeAnalyzer, "_check_tool_availability", return_value=set()):
            analyzer = CodeAnalyzer()
            lang = analyzer._detect_primary_language(tmp_path)
            assert lang == "Java"

    def test_detect_go(self, tmp_path):
        """Verify Go detected as primary language."""
        # Create Go files
        (tmp_path / "main.go").write_text("package main")
        (tmp_path / "utils.go").write_text("package utils")

        with patch.object(CodeAnalyzer, "_check_tool_availability", return_value=set()):
            analyzer = CodeAnalyzer()
            lang = analyzer._detect_primary_language(tmp_path)
            assert lang == "Go"

    def test_detect_unknown_empty_dir(self, tmp_path):
        """Verify Unknown returned for empty directory."""
        with patch.object(CodeAnalyzer, "_check_tool_availability", return_value=set()):
            analyzer = CodeAnalyzer()
            lang = analyzer._detect_primary_language(tmp_path)
            assert lang == "Unknown"

    def test_ignores_git_directory(self, tmp_path):
        """Verify .git directory is ignored."""
        # Create .git directory with Python files
        git_dir = tmp_path / ".git"
        git_dir.mkdir()
        (git_dir / "hooks.py").write_text("# git hook")

        # Create JavaScript files in main directory
        (tmp_path / "app.js").write_text("console.log('hello')")

        with patch.object(CodeAnalyzer, "_check_tool_availability", return_value=set()):
            analyzer = CodeAnalyzer()
            lang = analyzer._detect_primary_language(tmp_path)
            assert lang == "JavaScript"

    def test_ignores_node_modules(self, tmp_path):
        """Verify node_modules directory is ignored."""
        # Create node_modules with many JS files
        node_modules = tmp_path / "node_modules"
        node_modules.mkdir()
        for i in range(10):
            (node_modules / f"lib{i}.js").write_text("module.exports = {}")

        # Create Python files in main directory
        (tmp_path / "main.py").write_text("print('hello')")

        with patch.object(CodeAnalyzer, "_check_tool_availability", return_value=set()):
            analyzer = CodeAnalyzer()
            lang = analyzer._detect_primary_language(tmp_path)
            assert lang == "Python"


class TestSemgrepRuleBuilding:
    """Tests for Semgrep rule building."""

    def test_build_sql_injection_rule(self):
        """Verify SQL injection rule is built correctly."""
        with patch.object(CodeAnalyzer, "_check_tool_availability", return_value=set()):
            analyzer = CodeAnalyzer()
            patterns = [
                VulnerablePattern(
                    cve_id="CVE-2023-12345",
                    pattern_type="sql_injection",
                    vulnerable_functions=["execute", "query"],
                    description="SQL injection",
                    severity="high",
                )
            ]
            rules = analyzer._build_semgrep_rules(patterns, "Python")
            assert len(rules) == 1
            assert rules[0]["id"] == "sql-injection-CVE-2023-12345"
            assert "python" in rules[0]["languages"]
            assert rules[0]["severity"] == "high"

    def test_build_command_injection_rule(self):
        """Verify command injection rule is built correctly."""
        with patch.object(CodeAnalyzer, "_check_tool_availability", return_value=set()):
            analyzer = CodeAnalyzer()
            patterns = [
                VulnerablePattern(
                    cve_id="CVE-2023-54321",
                    pattern_type="command_injection",
                    vulnerable_functions=["exec", "system"],
                    description="Command injection",
                    severity="critical",
                )
            ]
            rules = analyzer._build_semgrep_rules(patterns, "Python")
            assert len(rules) == 1
            assert rules[0]["id"] == "command-injection-CVE-2023-54321"

    def test_build_rules_for_javascript(self):
        """Verify rules use correct language for JavaScript."""
        with patch.object(CodeAnalyzer, "_check_tool_availability", return_value=set()):
            analyzer = CodeAnalyzer()
            patterns = [
                VulnerablePattern(
                    cve_id="CVE-2023-11111",
                    pattern_type="sql_injection",
                    vulnerable_functions=["query"],
                )
            ]
            rules = analyzer._build_semgrep_rules(patterns, "JavaScript")
            assert "javascript" in rules[0]["languages"]

    def test_build_rules_for_typescript(self):
        """Verify rules use correct language for TypeScript."""
        with patch.object(CodeAnalyzer, "_check_tool_availability", return_value=set()):
            analyzer = CodeAnalyzer()
            patterns = [
                VulnerablePattern(
                    cve_id="CVE-2023-22222",
                    pattern_type="sql_injection",
                    vulnerable_functions=["query"],
                )
            ]
            rules = analyzer._build_semgrep_rules(patterns, "TypeScript")
            assert "typescript" in rules[0]["languages"]

    def test_build_rules_unknown_pattern_type(self):
        """Verify no rules built for unknown pattern type."""
        with patch.object(CodeAnalyzer, "_check_tool_availability", return_value=set()):
            analyzer = CodeAnalyzer()
            patterns = [
                VulnerablePattern(
                    cve_id="CVE-2023-33333",
                    pattern_type="unknown_type",
                    vulnerable_functions=["func"],
                )
            ]
            rules = analyzer._build_semgrep_rules(patterns, "Python")
            assert len(rules) == 0


class TestAnalyzeRepository:
    """Tests for repository analysis."""

    def test_analyze_with_no_available_tools(self, tmp_path):
        """Verify empty results when no tools available."""
        (tmp_path / "main.py").write_text("print('hello')")

        with patch.object(CodeAnalyzer, "_check_tool_availability", return_value=set()):
            analyzer = CodeAnalyzer()
            patterns = [VulnerablePattern(cve_id="CVE-2023-12345")]
            results = analyzer.analyze_repository(tmp_path, patterns)
            assert results == {}

    def test_analyze_auto_detects_language(self, tmp_path):
        """Verify language is auto-detected when not provided."""
        (tmp_path / "main.py").write_text("print('hello')")

        with patch.object(CodeAnalyzer, "_check_tool_availability", return_value=set()):
            analyzer = CodeAnalyzer()
            # Mock _detect_primary_language to verify it's called
            with patch.object(
                analyzer, "_detect_primary_language", return_value="Python"
            ) as mock_detect:
                patterns = [VulnerablePattern(cve_id="CVE-2023-12345")]
                analyzer.analyze_repository(tmp_path, patterns)
                mock_detect.assert_called_once_with(tmp_path)

    def test_analyze_uses_provided_language(self, tmp_path):
        """Verify provided language is used instead of auto-detection."""
        (tmp_path / "main.py").write_text("print('hello')")

        with patch.object(CodeAnalyzer, "_check_tool_availability", return_value=set()):
            analyzer = CodeAnalyzer()
            with patch.object(analyzer, "_detect_primary_language") as mock_detect:
                patterns = [VulnerablePattern(cve_id="CVE-2023-12345")]
                analyzer.analyze_repository(tmp_path, patterns, language="Java")
                mock_detect.assert_not_called()

    def test_analyze_handles_tool_exception(self, tmp_path):
        """Verify analysis continues when tool raises exception."""
        (tmp_path / "main.py").write_text("print('hello')")

        mock_result = MagicMock()
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            analyzer = CodeAnalyzer(tools=[AnalysisTool.SEMGREP])

            # Make semgrep analysis raise an exception
            with patch.object(
                analyzer, "_analyze_with_semgrep", side_effect=Exception("Tool error")
            ):
                patterns = [VulnerablePattern(cve_id="CVE-2023-12345")]
                results = analyzer.analyze_repository(
                    tmp_path, patterns, language="Python"
                )

                # Should have a failed result for semgrep
                assert AnalysisTool.SEMGREP in results
                assert results[AnalysisTool.SEMGREP].success is False
                assert "Tool error" in results[AnalysisTool.SEMGREP].errors[0]


class TestESLintAnalysis:
    """Tests for ESLint analysis."""

    def test_eslint_not_implemented(self, tmp_path):
        """Verify ESLint returns not implemented error."""
        with patch.object(CodeAnalyzer, "_check_tool_availability", return_value=set()):
            analyzer = CodeAnalyzer()
            patterns = [VulnerablePattern(cve_id="CVE-2023-12345")]
            result = analyzer._analyze_with_eslint(tmp_path, patterns)
            assert result.success is False
            assert "not yet implemented" in result.errors[0].lower()


class TestCodeQLQuery:
    """Tests for CodeQL query methods."""

    def test_get_codeql_query_returns_none(self):
        """Verify _get_codeql_query returns None (not implemented)."""
        with patch.object(CodeAnalyzer, "_check_tool_availability", return_value=set()):
            analyzer = CodeAnalyzer()
            result = analyzer._get_codeql_query("sql_injection", "Python")
            assert result is None
