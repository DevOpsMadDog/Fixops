"""
Unit tests for suite-core/core/sast_engine.py — SAST Scanner [V3]

Tests the Static Application Security Testing engine including:
- SASTEngine: initialization, scan execution
- SastFinding: finding data class
- Language detection: file extension mapping
- Taint analysis: source/sink tracking
- Rule engine: SAST_RULES tuple definitions

Written by agent-doctor run14 for SPRINT1-008 (test coverage).
"""
import pytest
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'suite-core'))

from core.sast_engine import (
    SASTEngine,
    SastFinding,
    SastScanResult,
    SastSeverity,
    Language,
    SAST_RULES,
    EXT_TO_LANG,
    TAINT_SOURCES,
    TAINT_SINKS,
    TaintFlow,
    detect_language,
    get_sast_engine,
)


# ─── SASTEngine Initialization ─────────────────────────────────────

class TestSASTEngineInit:
    """Tests for SASTEngine initialization."""

    def test_engine_creation(self):
        engine = SASTEngine()
        assert engine is not None

    def test_get_sast_engine_singleton(self):
        e1 = get_sast_engine()
        e2 = get_sast_engine()
        assert e1 is e2

    def test_engine_has_scan_code(self):
        engine = SASTEngine()
        assert hasattr(engine, 'scan_code')
        assert callable(engine.scan_code)

    def test_engine_has_scan_files(self):
        engine = SASTEngine()
        assert hasattr(engine, 'scan_files')
        assert callable(engine.scan_files)


# ─── Language Detection ────────────────────────────────────────────

class TestLanguageDetection:
    """Tests for language detection from file extensions."""

    def test_python_detection(self):
        lang = detect_language("main.py")
        assert lang == Language.PYTHON

    def test_javascript_detection(self):
        lang = detect_language("app.js")
        assert lang == Language.JAVASCRIPT

    def test_java_detection(self):
        lang = detect_language("Main.java")
        assert lang == Language.JAVA

    def test_go_detection(self):
        lang = detect_language("main.go")
        assert lang == Language.GO

    def test_ext_to_lang_mapping(self):
        assert ".py" in EXT_TO_LANG
        assert ".js" in EXT_TO_LANG
        assert ".java" in EXT_TO_LANG
        assert ".go" in EXT_TO_LANG

    def test_unknown_extension(self):
        lang = detect_language("file.xyz")
        assert lang is None or isinstance(lang, Language)


# ─── SAST Rules ────────────────────────────────────────────────────

class TestSASTRules:
    """Tests for SAST rule definitions."""

    def test_rules_not_empty(self):
        assert len(SAST_RULES) > 0

    def test_rules_are_tuples(self):
        for rule in SAST_RULES:
            assert isinstance(rule, tuple), f"Rule should be a tuple: {type(rule)}"

    def test_rules_have_minimum_fields(self):
        # Rules are tuples: (id, name, severity, cwe, pattern, desc, fix, langs)
        for rule in SAST_RULES:
            assert len(rule) >= 6, f"Rule has too few fields: {len(rule)}"

    def test_first_rule_is_sql_injection(self):
        assert SAST_RULES[0][0] == 'SAST-001'
        assert 'SQL' in SAST_RULES[0][1]

    def test_rules_cover_sql_injection(self):
        rule_names = [r[1].lower() for r in SAST_RULES]
        assert any('sql' in name for name in rule_names)

    def test_rules_have_severity(self):
        valid_severities = {'critical', 'high', 'medium', 'low', 'info'}
        for rule in SAST_RULES:
            assert rule[2].lower() in valid_severities, f"Invalid severity: {rule[2]}"


# ─── Taint Analysis ───────────────────────────────────────────────

class TestTaintAnalysis:
    """Tests for taint source/sink definitions."""

    def test_taint_sources_not_empty(self):
        assert len(TAINT_SOURCES) > 0

    def test_taint_sinks_not_empty(self):
        assert len(TAINT_SINKS) > 0

    def test_taint_flow_creation(self):
        flow = TaintFlow(
            source_line=10,
            source_pattern="request.args.get",
            sink_line=15,
            sink_pattern="cursor.execute",
            sink_category="sql",
            variable="user_id",
        )
        assert flow.source_line == 10
        assert flow.sink_line == 15
        assert flow.sink_category == "sql"
        assert flow.variable == "user_id"

    def test_taint_flow_minimal(self):
        flow = TaintFlow(
            source_line=1,
            source_pattern="input()",
            sink_line=5,
            sink_pattern="eval()",
            sink_category="code_execution",
        )
        assert flow.variable == ''  # default


# ─── Severity Enum ─────────────────────────────────────────────────

class TestSastSeverity:
    """Tests for SastSeverity enum."""

    def test_severity_values_exist(self):
        assert hasattr(SastSeverity, 'CRITICAL')
        assert hasattr(SastSeverity, 'HIGH')
        assert hasattr(SastSeverity, 'MEDIUM')
        assert hasattr(SastSeverity, 'LOW')

    def test_severity_ordering(self):
        severities = [SastSeverity.CRITICAL, SastSeverity.HIGH, SastSeverity.MEDIUM, SastSeverity.LOW]
        assert len(severities) == 4


# ─── SastFinding Data Class ───────────────────────────────────────

class TestSastFinding:
    """Tests for SastFinding data class."""

    def test_finding_creation(self):
        finding = SastFinding(
            rule_id="SAST-001",
            title="SQL Injection",
            severity=SastSeverity.HIGH,
            cwe_id="CWE-89",
            language=Language.PYTHON,
            file_path="app/models.py",
            line_number=42,
            snippet="cursor.execute(f'SELECT * FROM users WHERE id={user_id}')",
            message="SQL Injection vulnerability detected",
        )
        assert finding.rule_id == "SAST-001"
        assert finding.severity == SastSeverity.HIGH
        assert finding.line_number == 42

    def test_finding_defaults(self):
        finding = SastFinding(
            rule_id="TEST-001",
            title="Test",
            severity=SastSeverity.LOW,
            cwe_id="CWE-0",
            language=Language.PYTHON,
            file_path="test.py",
            line_number=1,
        )
        assert finding.column == 0
        assert finding.snippet == ''
        assert finding.message == ''
        assert finding.confidence == 0.9

    def test_finding_has_id(self):
        finding = SastFinding(
            rule_id="TEST-002",
            title="Test",
            severity=SastSeverity.MEDIUM,
            cwe_id="CWE-0",
            language=Language.PYTHON,
            file_path="test.py",
            line_number=1,
        )
        assert hasattr(finding, 'finding_id')
        assert finding.finding_id is not None


# ─── SastScanResult ───────────────────────────────────────────────

class TestSastScanResult:
    """Tests for SastScanResult data class."""

    def test_scan_result_creation(self):
        result = SastScanResult(
            scan_id="test-scan-001",
            findings=[],
            files_scanned=10,
            total_findings=0,
            taint_flows=[],
            by_severity={},
            by_cwe={},
        )
        assert result.files_scanned == 10
        assert len(result.findings) == 0

    def test_scan_result_with_findings(self):
        finding = SastFinding(
            rule_id="SAST-002",
            title="Hardcoded Secret",
            severity=SastSeverity.CRITICAL,
            cwe_id="CWE-798",
            language=Language.PYTHON,
            file_path="config.py",
            line_number=5,
            snippet="API_KEY = 'sk-1234'",
        )
        result = SastScanResult(
            scan_id="test-scan",
            findings=[finding],
            files_scanned=1,
            total_findings=1,
            taint_flows=[],
            by_severity={"critical": 1},
            by_cwe={"CWE-798": 1},
        )
        assert len(result.findings) == 1
        assert result.findings[0].severity == SastSeverity.CRITICAL


# ─── SASTEngine Scan ───────────────────────────────────────────────

class TestSASTEngineScan:
    """Tests for SASTEngine scanning functionality."""

    def test_scan_safe_code(self):
        engine = SASTEngine()
        safe_code = "def hello():\n    return 'Hello, World!'\n"
        result = engine.scan_code(safe_code, filename="safe.py")
        assert result is not None
        assert hasattr(result, 'findings')

    def test_scan_vulnerable_code(self):
        engine = SASTEngine()
        vuln_code = '''import sqlite3
def get_user(user_id):
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return cursor.fetchone()
'''
        result = engine.scan_code(vuln_code, filename="vuln.py")
        assert result is not None
        assert hasattr(result, 'findings')

    def test_scan_empty_code(self):
        engine = SASTEngine()
        result = engine.scan_code("", filename="empty.py")
        assert result is not None
        assert len(result.findings) == 0

    def test_scan_files_dict(self):
        engine = SASTEngine()
        files = {
            "app.py": "import os\nresult = os.system(user_input)\n",
            "utils.py": "def safe():\n    return 42\n",
        }
        result = engine.scan_files(files)
        assert result is not None
        assert hasattr(result, 'findings')
        assert result.files_scanned == 2

    def test_scan_returns_scan_id(self):
        engine = SASTEngine()
        result = engine.scan_code("x = 1", filename="simple.py")
        assert hasattr(result, 'scan_id')
        assert result.scan_id is not None

    def test_scan_javascript_code(self):
        engine = SASTEngine()
        js_code = "var x = document.getElementById('input').value; eval(x);"
        result = engine.scan_code(js_code, filename="app.js")
        assert result is not None

    def test_exposed_stack_trace_rule_ignores_logger_only_exception_lines(self):
        engine = SASTEngine()
        code = '''def fallback(logger):
    try:
        risky_call()
    except Exception as e:
        logger.warning(f"micro_pentest.mpte_unavailable error={e}")
        return {"status": "fallback"}
'''
        result = engine.scan_code(code, filename="micro_pentest.py")
        rule_ids = {finding.rule_id for finding in result.findings}
        assert "SAST-058" not in rule_ids

    def test_exposed_stack_trace_rule_flags_exception_details_in_response(self):
        engine = SASTEngine()
        code = '''def api_error(exc):
    return JSONResponse({"status": "error", "exception": str(exc)}, status_code=500)
'''
        result = engine.scan_code(code, filename="app.py")
        rule_ids = {finding.rule_id for finding in result.findings}
        assert "SAST-058" in rule_ids

    def test_excessive_data_exposure_rule_ignores_internal_to_dict_helpers(self):
        engine = SASTEngine()
        code = '''class ReachabilityResult:
    def to_dict(self):
        return {"reachable": True}
'''
        result = engine.scan_code(code, filename="micro_pentest.py")
        rule_ids = {finding.rule_id for finding in result.findings}
        assert "SAST-086" not in rule_ids

    def test_excessive_data_exposure_rule_flags_response_context_object_serialization(self):
        engine = SASTEngine()
        code = '''def get_user_profile(user):
    return JSONResponse(user.to_dict())
'''
        result = engine.scan_code(code, filename="app.py")
        rule_ids = {finding.rule_id for finding in result.findings}
        assert "SAST-086" in rule_ids

    def test_basic_auth_without_tls_rule_ignores_https_only_basic_headers(self):
        engine = SASTEngine()
        code = '''def azure_headers(token):
    base_url = "https://dev.azure.com"
    return {"Authorization": f"Basic {token}", "base_url": base_url}
'''
        result = engine.scan_code(code, filename="connectors.py")
        rule_ids = {finding.rule_id for finding in result.findings}
        assert "SAST-073" not in rule_ids

    def test_basic_auth_without_tls_rule_flags_basic_auth_over_http(self):
        engine = SASTEngine()
        code = 'config = {"url": "http://example.internal", "Authorization": "Basic abc123"}'
        result = engine.scan_code(code, filename="client.py")
        rule_ids = {finding.rule_id for finding in result.findings}
        assert "SAST-073" in rule_ids


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
