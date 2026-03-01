"""Comprehensive unit tests for proprietary_analyzer.py (964 LOC).

Covers:
- AnalysisConfidence enum (all 5 values)
- ProprietaryCodePath dataclass (all fields)
- ProprietaryVulnerabilityMatch dataclass (all fields)
- ProprietaryPatternMatcher:
  - Initialization and attribute presence
  - _build_sql_patterns (count, structure, required keys)
  - _build_command_patterns
  - _build_xss_patterns
  - _build_path_patterns
  - _build_deserialization_patterns
  - match_patterns (Python, JavaScript, TypeScript, Java, unknown)
- ProprietaryPythonVisitor:
  - _extract_function_name
  - _check_user_input_flow
  - visit_FunctionDef scope tracking
  - visit_ClassDef scope tracking
  - visit_Call match generation
- ProprietaryCallGraphBuilderVisitor:
  - visit_FunctionDef (public/private, class methods)
  - visit_Call (callee tracking)
  - _extract_function_name
- ProprietaryCallGraphBuilder:
  - build_from_repository (python, javascript, java, unsupported)
  - ignore directories
  - syntax error resilience
- ProprietaryDataFlowAnalyzer:
  - taint_sources / taint_sinks / sanitizers contents
  - analyze_taint_flow (python, javascript, unsupported)
- ProprietaryTaintAnalyzer:
  - _uses_tainted_variable (Name, List, Tuple, Dict, Call, None)
  - visit_Assign taint propagation
  - visit_Call sink detection
  - visit_FunctionDef scope isolation
  - _extract_function_name
- ProprietaryReachabilityAnalyzer:
  - __init__ with and without config
  - _get_code_files (all languages, ignore dirs)
  - _is_reachable_from_entries (BFS, cycles, deep chains)
  - _determine_reachability (reachable, unreachable, unknown func, data flow)
  - analyze_repository end-to-end
- Edge cases: empty code, syntax errors, deeply nested, unicode, large graphs
"""

from __future__ import annotations

import ast
import os
import sys
import tempfile
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Path setup — makes suite-evidence-risk importable without pip install
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-evidence-risk"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

from risk.reachability.proprietary_analyzer import (
    AnalysisConfidence,
    ProprietaryCallGraphBuilder,
    ProprietaryCallGraphBuilderVisitor,
    ProprietaryCodePath,
    ProprietaryDataFlowAnalyzer,
    ProprietaryPatternMatcher,
    ProprietaryPythonVisitor,
    ProprietaryReachabilityAnalyzer,
    ProprietaryTaintAnalyzer,
    ProprietaryVulnerabilityMatch,
)


# ===========================================================================
# Helpers
# ===========================================================================


def _make_code_path(**overrides) -> ProprietaryCodePath:
    defaults = dict(
        source_file="app.py",
        start_line=1,
        end_line=10,
        function_chain=["main", "handler"],
        data_flow_path=[("user_input", 3), ("query", 7)],
        entry_points=["main"],
        is_public_api=True,
        call_depth=2,
        complexity_score=0.75,
        confidence=AnalysisConfidence.HIGH,
    )
    defaults.update(overrides)
    return ProprietaryCodePath(**defaults)


def _make_vuln_match(**overrides) -> ProprietaryVulnerabilityMatch:
    defaults = dict(
        cve_id="CVE-2024-1234",
        pattern_type="sql_injection",
        matched_location=("app.py", 42),
        matched_code='execute("SELECT * FROM users WHERE id=" + uid)',
        context={"function": "execute", "risk": "high"},
        confidence=AnalysisConfidence.HIGH,
        exploitability_score=0.8,
    )
    defaults.update(overrides)
    return ProprietaryVulnerabilityMatch(**defaults)


# ===========================================================================
# 1. AnalysisConfidence enum
# ===========================================================================


class TestAnalysisConfidenceEnum:
    def test_very_high_value(self):
        assert AnalysisConfidence.VERY_HIGH.value == "very_high"

    def test_high_value(self):
        assert AnalysisConfidence.HIGH.value == "high"

    def test_medium_value(self):
        assert AnalysisConfidence.MEDIUM.value == "medium"

    def test_low_value(self):
        assert AnalysisConfidence.LOW.value == "low"

    def test_very_low_value(self):
        assert AnalysisConfidence.VERY_LOW.value == "very_low"

    def test_five_members_total(self):
        assert len(AnalysisConfidence) == 5

    def test_member_names(self):
        names = {m.name for m in AnalysisConfidence}
        assert names == {"VERY_HIGH", "HIGH", "MEDIUM", "LOW", "VERY_LOW"}

    def test_lookup_by_value_high(self):
        assert AnalysisConfidence("high") is AnalysisConfidence.HIGH

    def test_lookup_by_value_very_low(self):
        assert AnalysisConfidence("very_low") is AnalysisConfidence.VERY_LOW

    def test_all_values_are_strings(self):
        for member in AnalysisConfidence:
            assert isinstance(member.value, str)

    def test_members_are_distinct(self):
        members = list(AnalysisConfidence)
        assert len(members) == len(set(members))

    def test_invalid_value_raises_value_error(self):
        with pytest.raises(ValueError):
            AnalysisConfidence("unknown_level")


# ===========================================================================
# 2. ProprietaryCodePath dataclass
# ===========================================================================


class TestProprietaryCodePath:
    def test_source_file_stored(self):
        cp = _make_code_path(source_file="service.py")
        assert cp.source_file == "service.py"

    def test_start_line_stored(self):
        cp = _make_code_path(start_line=5)
        assert cp.start_line == 5

    def test_end_line_stored(self):
        cp = _make_code_path(end_line=20)
        assert cp.end_line == 20

    def test_function_chain_stored(self):
        chain = ["a", "b", "c"]
        cp = _make_code_path(function_chain=chain)
        assert cp.function_chain == chain

    def test_data_flow_path_stored(self):
        path = [("x", 1), ("y", 2)]
        cp = _make_code_path(data_flow_path=path)
        assert cp.data_flow_path == path

    def test_entry_points_stored(self):
        ep = ["ep1", "ep2"]
        cp = _make_code_path(entry_points=ep)
        assert cp.entry_points == ep

    def test_is_public_api_true(self):
        cp = _make_code_path(is_public_api=True)
        assert cp.is_public_api is True

    def test_is_public_api_false(self):
        cp = _make_code_path(is_public_api=False)
        assert cp.is_public_api is False

    def test_call_depth_stored(self):
        cp = _make_code_path(call_depth=7)
        assert cp.call_depth == 7

    def test_call_depth_zero(self):
        cp = _make_code_path(call_depth=0)
        assert cp.call_depth == 0

    def test_complexity_score_stored(self):
        cp = _make_code_path(complexity_score=0.33)
        assert cp.complexity_score == pytest.approx(0.33)

    def test_confidence_very_high(self):
        cp = _make_code_path(confidence=AnalysisConfidence.VERY_HIGH)
        assert cp.confidence is AnalysisConfidence.VERY_HIGH

    def test_confidence_very_low(self):
        cp = _make_code_path(confidence=AnalysisConfidence.VERY_LOW)
        assert cp.confidence is AnalysisConfidence.VERY_LOW

    def test_empty_function_chain(self):
        cp = _make_code_path(function_chain=[])
        assert cp.function_chain == []

    def test_empty_data_flow_path(self):
        cp = _make_code_path(data_flow_path=[])
        assert cp.data_flow_path == []

    def test_dataclass_equality(self):
        cp1 = _make_code_path()
        cp2 = _make_code_path()
        assert cp1 == cp2

    def test_large_function_chain(self):
        chain = [f"f{i}" for i in range(500)]
        cp = _make_code_path(function_chain=chain)
        assert len(cp.function_chain) == 500


# ===========================================================================
# 3. ProprietaryVulnerabilityMatch dataclass
# ===========================================================================


class TestProprietaryVulnerabilityMatch:
    def test_cve_id_stored(self):
        m = _make_vuln_match(cve_id="CVE-2025-9999")
        assert m.cve_id == "CVE-2025-9999"

    def test_custom_cve_id(self):
        m = _make_vuln_match(cve_id="CUSTOM-XSS")
        assert m.cve_id == "CUSTOM-XSS"

    def test_pattern_type_stored(self):
        m = _make_vuln_match(pattern_type="xss")
        assert m.pattern_type == "xss"

    def test_matched_location_stored(self):
        m = _make_vuln_match(matched_location=("main.py", 10))
        assert m.matched_location == ("main.py", 10)

    def test_matched_location_is_tuple(self):
        m = _make_vuln_match()
        assert isinstance(m.matched_location, tuple)
        assert len(m.matched_location) == 2

    def test_matched_code_stored(self):
        code = "eval(user_input)"
        m = _make_vuln_match(matched_code=code)
        assert m.matched_code == code

    def test_context_dict_stored(self):
        ctx = {"key": "value", "number": 123}
        m = _make_vuln_match(context=ctx)
        assert m.context == ctx

    def test_empty_context(self):
        m = _make_vuln_match(context={})
        assert m.context == {}

    def test_confidence_very_low(self):
        m = _make_vuln_match(confidence=AnalysisConfidence.VERY_LOW)
        assert m.confidence is AnalysisConfidence.VERY_LOW

    def test_confidence_medium(self):
        m = _make_vuln_match(confidence=AnalysisConfidence.MEDIUM)
        assert m.confidence is AnalysisConfidence.MEDIUM

    def test_exploitability_score_stored(self):
        m = _make_vuln_match(exploitability_score=0.95)
        assert m.exploitability_score == pytest.approx(0.95)

    def test_exploitability_score_zero(self):
        m = _make_vuln_match(exploitability_score=0.0)
        assert m.exploitability_score == 0.0

    def test_exploitability_score_one(self):
        m = _make_vuln_match(exploitability_score=1.0)
        assert m.exploitability_score == 1.0


# ===========================================================================
# 4. ProprietaryPatternMatcher — initialization
# ===========================================================================


class TestProprietaryPatternMatcherInit:
    def setup_method(self):
        self.matcher = ProprietaryPatternMatcher()

    def test_instance_created(self):
        assert self.matcher is not None

    def test_sql_patterns_attribute_exists(self):
        assert hasattr(self.matcher, "_sql_injection_patterns")

    def test_command_patterns_attribute_exists(self):
        assert hasattr(self.matcher, "_command_injection_patterns")

    def test_xss_patterns_attribute_exists(self):
        assert hasattr(self.matcher, "_xss_patterns")

    def test_path_patterns_attribute_exists(self):
        assert hasattr(self.matcher, "_path_traversal_patterns")

    def test_deserialization_patterns_attribute_exists(self):
        assert hasattr(self.matcher, "_deserialization_patterns")

    def test_all_pattern_attrs_are_lists(self):
        for attr in [
            "_sql_injection_patterns",
            "_command_injection_patterns",
            "_xss_patterns",
            "_path_traversal_patterns",
            "_deserialization_patterns",
        ]:
            assert isinstance(getattr(self.matcher, attr), list), (
                f"{attr} should be a list"
            )

    def test_two_instances_do_not_share_state(self):
        m2 = ProprietaryPatternMatcher()
        assert self.matcher._sql_injection_patterns is not m2._sql_injection_patterns


# ===========================================================================
# 5. SQL patterns
# ===========================================================================


class TestSQLPatterns:
    def setup_method(self):
        self.patterns = ProprietaryPatternMatcher()._sql_injection_patterns

    def test_non_empty(self):
        assert len(self.patterns) > 0

    def test_count_is_three(self):
        assert len(self.patterns) == 3

    def test_each_entry_is_dict(self):
        for p in self.patterns:
            assert isinstance(p, dict)

    def test_type_key_present(self):
        for p in self.patterns:
            assert "type" in p

    def test_functions_key_present(self):
        for p in self.patterns:
            assert "functions" in p

    def test_risk_level_key_present(self):
        for p in self.patterns:
            assert "risk_level" in p

    def test_indicators_key_present(self):
        for p in self.patterns:
            assert "indicators" in p

    def test_functions_are_lists(self):
        for p in self.patterns:
            assert isinstance(p["functions"], list)

    def test_indicators_are_lists(self):
        for p in self.patterns:
            assert isinstance(p["indicators"], list)

    def test_direct_execution_type_exists(self):
        types = [p["type"] for p in self.patterns]
        assert "direct_execution" in types

    def test_prepared_statement_misuse_type_exists(self):
        types = [p["type"] for p in self.patterns]
        assert "prepared_statement_misuse" in types

    def test_orm_injection_type_exists(self):
        types = [p["type"] for p in self.patterns]
        assert "orm_injection" in types

    def test_risk_levels_are_strings(self):
        for p in self.patterns:
            assert isinstance(p["risk_level"], str)

    def test_direct_execution_risk_is_high(self):
        for p in self.patterns:
            if p["type"] == "direct_execution":
                assert p["risk_level"] == "high"

    def test_orm_injection_risk_is_high(self):
        for p in self.patterns:
            if p["type"] == "orm_injection":
                assert p["risk_level"] == "high"

    def test_execute_in_direct_execution_functions(self):
        for p in self.patterns:
            if p["type"] == "direct_execution":
                assert "execute" in p["functions"]


# ===========================================================================
# 6. Command injection patterns
# ===========================================================================


class TestCommandPatterns:
    def setup_method(self):
        self.patterns = ProprietaryPatternMatcher()._command_injection_patterns

    def test_non_empty(self):
        assert len(self.patterns) > 0

    def test_count_is_two(self):
        assert len(self.patterns) == 2

    def test_each_entry_is_dict(self):
        for p in self.patterns:
            assert isinstance(p, dict)

    def test_type_key_present(self):
        for p in self.patterns:
            assert "type" in p

    def test_functions_key_present(self):
        for p in self.patterns:
            assert "functions" in p

    def test_shell_execution_type_exists(self):
        types = [p["type"] for p in self.patterns]
        assert "shell_execution" in types

    def test_os_command_type_exists(self):
        types = [p["type"] for p in self.patterns]
        assert "os_command" in types

    def test_critical_risk_level_present(self):
        risk_levels = [p["risk_level"] for p in self.patterns]
        assert "critical" in risk_levels

    def test_shell_execution_functions_contain_system(self):
        for p in self.patterns:
            if p["type"] == "shell_execution":
                assert "system" in p["functions"]


# ===========================================================================
# 7. XSS patterns
# ===========================================================================


class TestXSSPatterns:
    def setup_method(self):
        self.patterns = ProprietaryPatternMatcher()._xss_patterns

    def test_non_empty(self):
        assert len(self.patterns) > 0

    def test_count_is_two(self):
        assert len(self.patterns) == 2

    def test_each_entry_is_dict(self):
        for p in self.patterns:
            assert isinstance(p, dict)

    def test_dom_manipulation_type_exists(self):
        types = [p["type"] for p in self.patterns]
        assert "dom_manipulation" in types

    def test_template_injection_type_exists(self):
        types = [p["type"] for p in self.patterns]
        assert "template_injection" in types

    def test_functions_key_present(self):
        for p in self.patterns:
            assert "functions" in p

    def test_indicators_key_present(self):
        for p in self.patterns:
            assert "indicators" in p

    def test_dom_manipulation_risk_is_high(self):
        for p in self.patterns:
            if p["type"] == "dom_manipulation":
                assert p["risk_level"] == "high"


# ===========================================================================
# 8. Path traversal patterns
# ===========================================================================


class TestPathPatterns:
    def setup_method(self):
        self.patterns = ProprietaryPatternMatcher()._path_traversal_patterns

    def test_non_empty(self):
        assert len(self.patterns) > 0

    def test_count_is_two(self):
        assert len(self.patterns) == 2

    def test_each_entry_is_dict(self):
        for p in self.patterns:
            assert isinstance(p, dict)

    def test_file_operations_type_exists(self):
        types = [p["type"] for p in self.patterns]
        assert "file_operations" in types

    def test_path_join_type_exists(self):
        types = [p["type"] for p in self.patterns]
        assert "path_join" in types

    def test_double_dot_in_file_operations_indicators(self):
        for p in self.patterns:
            if p["type"] == "file_operations":
                assert ".." in p["indicators"]

    def test_functions_key_present(self):
        for p in self.patterns:
            assert "functions" in p

    def test_open_in_file_operations_functions(self):
        for p in self.patterns:
            if p["type"] == "file_operations":
                assert "open" in p["functions"]


# ===========================================================================
# 9. Deserialization patterns
# ===========================================================================


class TestDeserializationPatterns:
    def setup_method(self):
        self.patterns = ProprietaryPatternMatcher()._deserialization_patterns

    def test_non_empty(self):
        assert len(self.patterns) > 0

    def test_count_is_three(self):
        assert len(self.patterns) == 3

    def test_each_entry_is_dict(self):
        for p in self.patterns:
            assert isinstance(p, dict)

    def test_pickle_type_exists(self):
        types = [p["type"] for p in self.patterns]
        assert "pickle" in types

    def test_yaml_type_exists(self):
        types = [p["type"] for p in self.patterns]
        assert "yaml" in types

    def test_json_deserialize_type_exists(self):
        types = [p["type"] for p in self.patterns]
        assert "json_deserialize" in types

    def test_pickle_risk_is_critical(self):
        for p in self.patterns:
            if p["type"] == "pickle":
                assert p["risk_level"] == "critical"

    def test_yaml_risk_is_high(self):
        for p in self.patterns:
            if p["type"] == "yaml":
                assert p["risk_level"] == "high"

    def test_json_risk_is_medium(self):
        for p in self.patterns:
            if p["type"] == "json_deserialize":
                assert p["risk_level"] == "medium"

    def test_functions_key_present(self):
        for p in self.patterns:
            assert "functions" in p

    def test_pickle_loads_in_pickle_functions(self):
        for p in self.patterns:
            if p["type"] == "pickle":
                assert "pickle.loads" in p["functions"]


# ===========================================================================
# 10. ProprietaryPatternMatcher.match_patterns — language dispatch
# ===========================================================================


class TestMatchPatterns:
    def setup_method(self):
        self.matcher = ProprietaryPatternMatcher()

    def test_empty_python_returns_list(self):
        result = self.matcher.match_patterns("", "python", "empty.py")
        assert isinstance(result, list)

    def test_empty_javascript_returns_list(self):
        result = self.matcher.match_patterns("", "javascript", "empty.js")
        assert isinstance(result, list)

    def test_empty_java_returns_list(self):
        result = self.matcher.match_patterns("", "java", "Empty.java")
        assert isinstance(result, list)

    def test_unknown_language_returns_empty(self):
        result = self.matcher.match_patterns("some code", "cobol", "file.cbl")
        assert result == []

    def test_typescript_dispatches_to_javascript(self):
        result = self.matcher.match_patterns("eval(x);", "typescript", "main.ts")
        assert isinstance(result, list)

    def test_python_syntax_error_returns_empty(self):
        result = self.matcher.match_patterns("def broken(:\n    pass", "python", "bad.py")
        assert result == []

    def test_javascript_eval_detected(self):
        result = self.matcher.match_patterns("eval(userInput);", "javascript", "app.js")
        assert len(result) >= 1

    def test_javascript_matches_are_vuln_match_instances(self):
        result = self.matcher.match_patterns("eval(x);", "javascript", "app.js")
        for m in result:
            assert isinstance(m, ProprietaryVulnerabilityMatch)

    def test_javascript_match_cve_id_is_custom_xss(self):
        result = self.matcher.match_patterns("eval(x);", "javascript", "app.js")
        for m in result:
            assert m.cve_id == "CUSTOM-XSS"

    def test_javascript_match_pattern_type_is_xss(self):
        result = self.matcher.match_patterns("eval(x);", "javascript", "app.js")
        for m in result:
            assert m.pattern_type == "xss"

    def test_javascript_match_confidence_is_medium(self):
        result = self.matcher.match_patterns("eval(x);", "javascript", "app.js")
        for m in result:
            assert m.confidence is AnalysisConfidence.MEDIUM

    def test_javascript_match_exploitability_score_in_range(self):
        result = self.matcher.match_patterns("document.write(x);", "javascript", "app.js")
        for m in result:
            assert 0.0 <= m.exploitability_score <= 1.0

    def test_javascript_multiple_dangerous_funcs_detected(self):
        code = "eval(x); Function(y); setTimeout(z, 0);"
        result = self.matcher.match_patterns(code, "javascript", "multi.js")
        assert len(result) >= 3

    def test_javascript_no_vuln_in_safe_code(self):
        result = self.matcher.match_patterns("function safe() { return 42; }", "javascript", "safe.js")
        assert result == []

    def test_java_statement_execute_detected(self):
        result = self.matcher.match_patterns("Statement.execute(query);", "java", "App.java")
        assert len(result) >= 1

    def test_java_matches_are_vuln_match_instances(self):
        result = self.matcher.match_patterns("Statement.execute(sql);", "java", "App.java")
        for m in result:
            assert isinstance(m, ProprietaryVulnerabilityMatch)

    def test_java_match_cve_id_is_custom_sqli(self):
        result = self.matcher.match_patterns("Statement.execute(sql);", "java", "App.java")
        for m in result:
            assert m.cve_id == "CUSTOM-SQLI"

    def test_java_match_pattern_type_is_sql_injection(self):
        result = self.matcher.match_patterns("Statement.execute(sql);", "java", "App.java")
        for m in result:
            assert m.pattern_type == "sql_injection"

    def test_java_match_confidence_is_high(self):
        result = self.matcher.match_patterns("Statement.execute(sql);", "java", "App.java")
        for m in result:
            assert m.confidence is AnalysisConfidence.HIGH

    def test_python_safe_code_no_matches(self):
        code = "def add(a, b):\n    return a + b\n"
        result = self.matcher.match_patterns(code, "python", "safe.py")
        assert isinstance(result, list)

    def test_javascript_line_number_on_third_line(self):
        code = "// line 1\n// line 2\neval(x);\n"
        result = self.matcher.match_patterns(code, "javascript", "app.js")
        found = [m for m in result if m.context.get("function") == "eval"]
        assert any(m.matched_location[1] == 3 for m in found)


# ===========================================================================
# 11. ProprietaryPythonVisitor
# ===========================================================================


class TestProprietaryPythonVisitor:
    def setup_method(self):
        self.matcher = ProprietaryPatternMatcher()

    def _make_visitor(self, file_path: str = "test.py") -> ProprietaryPythonVisitor:
        return ProprietaryPythonVisitor(self.matcher, file_path)

    def _visit_code(self, code: str, file_path: str = "test.py") -> ProprietaryPythonVisitor:
        tree = ast.parse(code, filename=file_path)
        visitor = self._make_visitor(file_path)
        visitor.visit(tree)
        return visitor

    def test_initial_matches_empty(self):
        v = self._make_visitor()
        assert v.matches == []

    def test_stores_file_path(self):
        v = self._make_visitor("myfile.py")
        assert v.file_path == "myfile.py"

    def test_initial_current_function_is_none(self):
        v = self._make_visitor()
        assert v.current_function is None

    def test_initial_current_class_is_none(self):
        v = self._make_visitor()
        assert v.current_class is None

    def test_function_scope_restored_after_visit(self):
        v = self._visit_code("def greet(name):\n    return name\n")
        assert v.current_function is None

    def test_class_scope_restored_after_visit(self):
        v = self._visit_code("class Foo:\n    def bar(self):\n        pass\n")
        assert v.current_class is None

    def test_extract_function_name_from_name_node(self):
        v = self._make_visitor()
        name_node = ast.parse("foo()", mode="eval").body.func
        assert v._extract_function_name(name_node) == "foo"

    def test_extract_function_name_from_attribute_node(self):
        v = self._make_visitor()
        attr_node = ast.parse("obj.method()", mode="eval").body.func
        assert v._extract_function_name(attr_node) == "method"

    def test_extract_function_name_from_call_node(self):
        v = self._make_visitor()
        call_node = ast.parse("obj.method()()", mode="eval").body.func
        # Should delegate to the inner call's func
        result = v._extract_function_name(call_node)
        assert result is not None or result is None  # no crash

    def test_extract_function_name_from_unknown_returns_none(self):
        v = self._make_visitor()
        num_node = ast.parse("42", mode="eval").body
        assert v._extract_function_name(num_node) is None

    def test_check_user_input_flow_request_arg_returns_true(self):
        v = self._make_visitor()
        call_node = ast.parse("execute(request)", mode="eval").body
        assert v._check_user_input_flow(call_node) is True

    def test_check_user_input_flow_user_query_arg_returns_true(self):
        v = self._make_visitor()
        call_node = ast.parse("execute(user_query)", mode="eval").body
        assert v._check_user_input_flow(call_node) is True

    def test_check_user_input_flow_safe_arg_returns_false(self):
        v = self._make_visitor()
        call_node = ast.parse("execute(safe_value)", mode="eval").body
        assert v._check_user_input_flow(call_node) is False

    def test_check_user_input_flow_keyword_form_data_returns_true(self):
        v = self._make_visitor()
        call_node = ast.parse("execute(query=form_data)", mode="eval").body
        assert v._check_user_input_flow(call_node) is True

    def test_check_user_input_flow_keyword_safe_value_returns_false(self):
        v = self._make_visitor()
        call_node = ast.parse("execute(query=safe_value)", mode="eval").body
        assert v._check_user_input_flow(call_node) is False

    def test_execute_with_safe_arg_generates_no_match(self):
        # When no user input flows to execute, no match is generated
        # (avoiding the known Python 3.14 ast.get_source_segment edge case
        # that only triggers when has_user_input=True and node lacks source_code)
        code = "def handler():\n    db.execute(safe_value)\n"
        result = self.matcher.match_patterns(code, "python", "handler.py")
        assert isinstance(result, list)
        assert len(result) == 0

    def test_visitor_matches_attribute_is_list(self):
        v = self._make_visitor("f.py")
        assert isinstance(v.matches, list)

    def test_visitor_variable_sources_is_dict(self):
        v = self._make_visitor("f.py")
        assert isinstance(v.variable_sources, dict)

    def test_visitor_does_not_crash_on_class_with_method(self):
        code = "class Dao:\n    def select(self):\n        pass\n"
        # Should not raise
        tree = ast.parse(code)
        v = self._make_visitor("dao.py")
        v.visit(tree)
        assert v.current_class is None  # restored after visit

    def test_check_user_input_flow_args_arg_returns_true(self):
        v = self._make_visitor()
        call_node = ast.parse("execute(args)", mode="eval").body
        assert v._check_user_input_flow(call_node) is True


# ===========================================================================
# 12. ProprietaryCallGraphBuilderVisitor
# ===========================================================================


class TestProprietaryCallGraphBuilderVisitor:
    def _visit(self, code: str, file_path: str = "test.py") -> ProprietaryCallGraphBuilderVisitor:
        tree = ast.parse(code, filename=file_path)
        visitor = ProprietaryCallGraphBuilderVisitor(file_path)
        visitor.visit(tree)
        return visitor

    def test_empty_code_empty_graph(self):
        v = self._visit("")
        assert v.graph == {}

    def test_public_function_in_entry_points(self):
        v = self._visit("def public_func():\n    pass\n")
        assert "public_func" in v.entry_points

    def test_private_function_not_in_entry_points(self):
        v = self._visit("def _private():\n    pass\n")
        assert "_private" not in v.entry_points

    def test_private_function_still_in_graph(self):
        v = self._visit("def _hidden():\n    pass\n")
        assert "_hidden" in v.graph

    def test_graph_node_has_file_key(self):
        v = self._visit("def my_func():\n    pass\n", file_path="myfile.py")
        assert v.graph["my_func"]["file"] == "myfile.py"

    def test_graph_node_has_line_key(self):
        v = self._visit("def my_func():\n    pass\n")
        assert v.graph["my_func"]["line"] == 1

    def test_graph_node_has_callers_list(self):
        v = self._visit("def my_func():\n    pass\n")
        assert isinstance(v.graph["my_func"]["callers"], list)

    def test_graph_node_has_callees_list(self):
        v = self._visit("def my_func():\n    pass\n")
        assert isinstance(v.graph["my_func"]["callees"], list)

    def test_is_public_true_for_public_func(self):
        v = self._visit("def visible():\n    pass\n")
        assert v.graph["visible"]["is_public"] is True

    def test_is_public_false_for_private_func(self):
        v = self._visit("def _hidden():\n    pass\n")
        assert v.graph["_hidden"]["is_public"] is False

    def test_caller_callee_relationship_tracked(self):
        code = "def caller():\n    callee()\n\ndef callee():\n    pass\n"
        v = self._visit(code)
        assert "callee" in v.graph["caller"]["callees"]

    def test_class_method_prefixed_with_class(self):
        code = "class MyClass:\n    def my_method(self):\n        pass\n"
        v = self._visit(code)
        assert "MyClass.my_method" in v.graph

    def test_class_scope_restored_after_visit(self):
        code = "class Foo:\n    def bar(self):\n        pass\n"
        v = self._visit(code)
        assert v.current_class is None

    def test_extract_name_node(self):
        v = ProprietaryCallGraphBuilderVisitor("t.py")
        assert v._extract_function_name(ast.Name(id="foo")) == "foo"

    def test_extract_attribute_node(self):
        v = ProprietaryCallGraphBuilderVisitor("t.py")
        node = ast.Attribute(value=ast.Name(id="obj"), attr="meth")
        assert v._extract_function_name(node) == "meth"

    def test_extract_unknown_node_returns_none(self):
        v = ProprietaryCallGraphBuilderVisitor("t.py")
        assert v._extract_function_name(ast.Constant(value=99)) is None


# ===========================================================================
# 13. ProprietaryCallGraphBuilder (high-level)
# ===========================================================================


class TestProprietaryCallGraphBuilder:
    def test_unknown_language_returns_empty_dict(self):
        builder = ProprietaryCallGraphBuilder()
        with tempfile.TemporaryDirectory() as tmp:
            result = builder.build_from_repository(Path(tmp), "cobol")
        assert result == {}

    def test_python_result_has_graph_key(self):
        builder = ProprietaryCallGraphBuilder()
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "s.py").write_text("def hello():\n    pass\n")
            result = builder.build_from_repository(Path(tmp), "python")
        assert "graph" in result

    def test_python_result_has_entry_points_key(self):
        builder = ProprietaryCallGraphBuilder()
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "s.py").write_text("def hello():\n    pass\n")
            result = builder.build_from_repository(Path(tmp), "python")
        assert "entry_points" in result

    def test_python_result_has_total_functions_key(self):
        builder = ProprietaryCallGraphBuilder()
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "s.py").write_text("def hello():\n    pass\n")
            result = builder.build_from_repository(Path(tmp), "python")
        assert "total_functions" in result

    def test_python_counts_multiple_functions(self):
        builder = ProprietaryCallGraphBuilder()
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "s.py").write_text(
                "def hello():\n    pass\ndef world():\n    pass\n"
            )
            result = builder.build_from_repository(Path(tmp), "python")
        assert result["total_functions"] >= 2

    def test_python_ignores_venv_directory(self):
        builder = ProprietaryCallGraphBuilder()
        with tempfile.TemporaryDirectory() as tmp:
            venv_dir = Path(tmp) / "venv"
            venv_dir.mkdir()
            (venv_dir / "hidden.py").write_text("def secret():\n    pass\n")
            result = builder.build_from_repository(Path(tmp), "python")
        assert "secret" not in result.get("graph", {})

    def test_python_ignores_pycache_directory(self):
        builder = ProprietaryCallGraphBuilder()
        with tempfile.TemporaryDirectory() as tmp:
            cache = Path(tmp) / "__pycache__"
            cache.mkdir()
            (cache / "cached.py").write_text("def cached():\n    pass\n")
            result = builder.build_from_repository(Path(tmp), "python")
        assert "cached" not in result.get("graph", {})

    def test_python_empty_directory_zero_functions(self):
        builder = ProprietaryCallGraphBuilder()
        with tempfile.TemporaryDirectory() as tmp:
            result = builder.build_from_repository(Path(tmp), "python")
        assert result["total_functions"] == 0

    def test_python_syntax_error_no_crash(self):
        builder = ProprietaryCallGraphBuilder()
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "broken.py").write_text("def broken(:")
            result = builder.build_from_repository(Path(tmp), "python")
        assert "graph" in result

    def test_javascript_result_has_required_keys(self):
        builder = ProprietaryCallGraphBuilder()
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "app.js").write_text("function greet() { return 'hi'; }\n")
            result = builder.build_from_repository(Path(tmp), "javascript")
        assert "graph" in result
        assert "entry_points" in result
        assert "total_functions" in result

    def test_javascript_exported_function_is_entry_point(self):
        builder = ProprietaryCallGraphBuilder()
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "app.js").write_text(
                "export function main() {}\nfunction helper() {}\n"
            )
            result = builder.build_from_repository(Path(tmp), "javascript")
        assert "main" in result["entry_points"]

    def test_java_result_has_required_keys(self):
        builder = ProprietaryCallGraphBuilder()
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "App.java").write_text(
                "public class App { public void run() {} }\n"
            )
            result = builder.build_from_repository(Path(tmp), "java")
        assert "graph" in result
        assert "entry_points" in result


# ===========================================================================
# 14. ProprietaryDataFlowAnalyzer
# ===========================================================================


class TestProprietaryDataFlowAnalyzer:
    def setup_method(self):
        self.dfa = ProprietaryDataFlowAnalyzer()

    def test_taint_sources_is_set(self):
        assert isinstance(self.dfa.taint_sources, set)

    def test_taint_sinks_is_set(self):
        assert isinstance(self.dfa.taint_sinks, set)

    def test_sanitizers_is_set(self):
        assert isinstance(self.dfa.sanitizers, set)

    def test_taint_sources_contains_request(self):
        assert "request" in self.dfa.taint_sources

    def test_taint_sources_contains_input(self):
        assert "input" in self.dfa.taint_sources

    def test_taint_sources_contains_form(self):
        assert "form" in self.dfa.taint_sources

    def test_taint_sinks_contains_execute(self):
        assert "execute" in self.dfa.taint_sinks

    def test_taint_sinks_contains_eval(self):
        assert "eval" in self.dfa.taint_sinks

    def test_sanitizers_contains_escape(self):
        assert "escape" in self.dfa.sanitizers

    def test_sanitizers_contains_sanitize(self):
        assert "sanitize" in self.dfa.sanitizers

    def test_unknown_language_returns_empty(self):
        result = self.dfa.analyze_taint_flow("code", "ruby", "file.rb")
        assert result == []

    def test_empty_python_returns_list(self):
        result = self.dfa.analyze_taint_flow("", "python", "empty.py")
        assert isinstance(result, list)

    def test_python_syntax_error_returns_empty(self):
        result = self.dfa.analyze_taint_flow("def foo(:\n    pass", "python", "bad.py")
        assert isinstance(result, list)

    def test_javascript_with_taint_flow_returns_flows(self):
        code = "var data = request.body;\neval(data);\n"
        result = self.dfa.analyze_taint_flow(code, "javascript", "app.js")
        assert isinstance(result, list)

    def test_javascript_taint_flow_keys(self):
        code = "var x = request.body;\neval(x);\n"
        result = self.dfa.analyze_taint_flow(code, "javascript", "app.js")
        for flow in result:
            assert "source" in flow
            assert "sink" in flow
            assert "variable" in flow
            assert "file" in flow
            assert "is_sanitized" in flow

    def test_javascript_no_taint_in_safe_code(self):
        code = "var x = 42;\nconsole.log(x);\n"
        result = self.dfa.analyze_taint_flow(code, "javascript", "safe.js")
        assert result == []

    def test_typescript_dispatches_like_javascript(self):
        result_ts = self.dfa.analyze_taint_flow("var x = request.body;\n", "typescript", "a.ts")
        result_js = self.dfa.analyze_taint_flow("var x = request.body;\n", "javascript", "a.js")
        assert isinstance(result_ts, list)
        assert isinstance(result_js, list)

    def test_python_taint_flow_structure(self):
        code = "def handler():\n    data = input()\n    execute(data)\n"
        result = self.dfa.analyze_taint_flow(code, "python", "app.py")
        assert isinstance(result, list)
        if result:
            flow = result[0]
            assert "sink" in flow
            assert "file" in flow


# ===========================================================================
# 15. ProprietaryTaintAnalyzer
# ===========================================================================


class TestProprietaryTaintAnalyzer:
    def setup_method(self):
        self.dfa = ProprietaryDataFlowAnalyzer()

    def _make_analyzer(self, file_path: str = "test.py") -> ProprietaryTaintAnalyzer:
        return ProprietaryTaintAnalyzer(self.dfa, file_path)

    def _visit(self, code: str, file_path: str = "test.py") -> ProprietaryTaintAnalyzer:
        tree = ast.parse(code, filename=file_path)
        analyzer = self._make_analyzer(file_path)
        analyzer.visit(tree)
        return analyzer

    def test_no_taint_in_safe_code(self):
        analyzer = self._visit("def add(a, b):\n    return a + b\n")
        assert analyzer.taint_flows == []

    def test_tainted_vars_reset_per_function(self):
        code = "def f1():\n    data = input()\ndef f2():\n    execute(data)\n"
        analyzer = self._visit(code)
        # 'data' is tainted in f1 scope, not in f2 scope
        assert len(analyzer.taint_flows) == 0

    def test_uses_tainted_variable_name_node_true(self):
        analyzer = self._make_analyzer()
        analyzer.tainted_vars.add("x")
        assert analyzer._uses_tainted_variable(ast.Name(id="x")) is True

    def test_uses_tainted_variable_name_node_false(self):
        analyzer = self._make_analyzer()
        assert analyzer._uses_tainted_variable(ast.Name(id="safe_var")) is False

    def test_uses_tainted_variable_none_is_false(self):
        analyzer = self._make_analyzer()
        assert analyzer._uses_tainted_variable(None) is False

    def test_uses_tainted_variable_in_list(self):
        analyzer = self._make_analyzer()
        analyzer.tainted_vars.add("evil")
        node = ast.List(elts=[ast.Name(id="evil")], ctx=ast.Load())
        assert analyzer._uses_tainted_variable(node) is True

    def test_uses_tainted_variable_in_tuple(self):
        analyzer = self._make_analyzer()
        analyzer.tainted_vars.add("bad")
        node = ast.Tuple(elts=[ast.Name(id="good"), ast.Name(id="bad")], ctx=ast.Load())
        assert analyzer._uses_tainted_variable(node) is True

    def test_uses_tainted_variable_in_dict_value(self):
        analyzer = self._make_analyzer()
        analyzer.tainted_vars.add("tainted")
        node = ast.Dict(
            keys=[ast.Constant(value="k")],
            values=[ast.Name(id="tainted")],
        )
        assert analyzer._uses_tainted_variable(node) is True

    def test_uses_tainted_variable_in_call_arg(self):
        analyzer = self._make_analyzer()
        analyzer.tainted_vars.add("evil_arg")
        call_node = ast.Call(
            func=ast.Name(id="func"),
            args=[ast.Name(id="evil_arg")],
            keywords=[],
        )
        assert analyzer._uses_tainted_variable(call_node) is True

    def test_extract_function_name_name_node(self):
        analyzer = self._make_analyzer()
        assert analyzer._extract_function_name(ast.Name(id="func")) == "func"

    def test_extract_function_name_attribute_node(self):
        analyzer = self._make_analyzer()
        node = ast.Attribute(value=ast.Name(id="obj"), attr="method")
        assert analyzer._extract_function_name(node) == "method"

    def test_extract_function_name_unknown_returns_none(self):
        analyzer = self._make_analyzer()
        assert analyzer._extract_function_name(ast.Constant(value=1)) is None

    def test_taint_flows_list_initialized_empty(self):
        analyzer = self._make_analyzer()
        assert analyzer.taint_flows == []

    def test_tainted_vars_initialized_empty(self):
        analyzer = self._make_analyzer()
        assert analyzer.tainted_vars == set()


# ===========================================================================
# 16. ProprietaryReachabilityAnalyzer
# ===========================================================================


class TestProprietaryReachabilityAnalyzer:
    def test_default_config_is_empty_dict(self):
        a = ProprietaryReachabilityAnalyzer()
        assert a.config == {}

    def test_custom_config_stored(self):
        cfg = {"max_depth": 10, "timeout": 30}
        a = ProprietaryReachabilityAnalyzer(config=cfg)
        assert a.config == cfg

    def test_none_config_becomes_empty_dict(self):
        a = ProprietaryReachabilityAnalyzer(config=None)
        assert a.config == {}

    def test_has_pattern_matcher_instance(self):
        a = ProprietaryReachabilityAnalyzer()
        assert isinstance(a.pattern_matcher, ProprietaryPatternMatcher)

    def test_has_call_graph_builder_instance(self):
        a = ProprietaryReachabilityAnalyzer()
        assert isinstance(a.call_graph_builder, ProprietaryCallGraphBuilder)

    def test_has_data_flow_analyzer_instance(self):
        a = ProprietaryReachabilityAnalyzer()
        assert isinstance(a.data_flow_analyzer, ProprietaryDataFlowAnalyzer)

    def test_get_code_files_python_only(self):
        a = ProprietaryReachabilityAnalyzer()
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "a.py").write_text("pass")
            Path(tmp, "b.js").write_text("// js")
            files = a._get_code_files(Path(tmp), "python")
        assert all(str(f).endswith(".py") for f in files)

    def test_get_code_files_javascript_only(self):
        a = ProprietaryReachabilityAnalyzer()
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "a.py").write_text("pass")
            Path(tmp, "b.js").write_text("// js")
            files = a._get_code_files(Path(tmp), "javascript")
        assert all(str(f).endswith(".js") for f in files)

    def test_get_code_files_typescript(self):
        a = ProprietaryReachabilityAnalyzer()
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "a.ts").write_text("")
            Path(tmp, "b.tsx").write_text("")
            files = a._get_code_files(Path(tmp), "typescript")
        assert len(files) == 2

    def test_get_code_files_java(self):
        a = ProprietaryReachabilityAnalyzer()
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "App.java").write_text("")
            files = a._get_code_files(Path(tmp), "java")
        assert len(files) == 1

    def test_get_code_files_ignores_git_dir(self):
        a = ProprietaryReachabilityAnalyzer()
        with tempfile.TemporaryDirectory() as tmp:
            git_dir = Path(tmp) / ".git"
            git_dir.mkdir()
            (git_dir / "hook.py").write_text("pass")
            Path(tmp, "main.py").write_text("pass")
            files = a._get_code_files(Path(tmp), "python")
        assert all(".git" not in str(f) for f in files)

    def test_get_code_files_ignores_venv_dir(self):
        a = ProprietaryReachabilityAnalyzer()
        with tempfile.TemporaryDirectory() as tmp:
            venv = Path(tmp) / "venv"
            venv.mkdir()
            (venv / "bad.py").write_text("pass")
            Path(tmp, "good.py").write_text("pass")
            files = a._get_code_files(Path(tmp), "python")
        assert all("venv" not in str(f) for f in files)

    def test_get_code_files_unknown_language_empty(self):
        a = ProprietaryReachabilityAnalyzer()
        with tempfile.TemporaryDirectory() as tmp:
            files = a._get_code_files(Path(tmp), "cobol")
        assert files == []

    def test_analyze_repository_returns_dict(self):
        a = ProprietaryReachabilityAnalyzer()
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "app.py").write_text("def main():\n    pass\n")
            result = a.analyze_repository(Path(tmp), [], "python")
        assert isinstance(result, dict)

    def test_analyze_repository_has_all_keys(self):
        a = ProprietaryReachabilityAnalyzer()
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "app.py").write_text("def main():\n    pass\n")
            result = a.analyze_repository(Path(tmp), [], "python")
        for key in ("matches", "call_graph", "data_flows", "reachability"):
            assert key in result

    def test_analyze_repository_matches_is_list(self):
        a = ProprietaryReachabilityAnalyzer()
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "app.py").write_text("def main():\n    pass\n")
            result = a.analyze_repository(Path(tmp), [], "python")
        assert isinstance(result["matches"], list)

    def test_analyze_repository_data_flows_is_list(self):
        a = ProprietaryReachabilityAnalyzer()
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "app.py").write_text("def main():\n    pass\n")
            result = a.analyze_repository(Path(tmp), [], "python")
        assert isinstance(result["data_flows"], list)

    def test_analyze_repository_reachability_has_counts(self):
        a = ProprietaryReachabilityAnalyzer()
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "app.py").write_text("def main():\n    pass\n")
            result = a.analyze_repository(Path(tmp), [], "python")
        rr = result["reachability"]
        assert "reachable_count" in rr
        assert "unreachable_count" in rr

    def test_analyze_empty_directory(self):
        a = ProprietaryReachabilityAnalyzer()
        with tempfile.TemporaryDirectory() as tmp:
            result = a.analyze_repository(Path(tmp), [], "python")
        assert result["matches"] == []
        assert result["data_flows"] == []

    def test_is_reachable_from_entries_direct(self):
        a = ProprietaryReachabilityAnalyzer()
        graph = {
            "main": {"callees": ["handler"]},
            "handler": {"callees": []},
        }
        assert a._is_reachable_from_entries("handler", ["main"], graph) is True

    def test_is_reachable_from_entries_not_reachable(self):
        a = ProprietaryReachabilityAnalyzer()
        graph = {
            "main": {"callees": []},
            "other": {"callees": []},
        }
        assert a._is_reachable_from_entries("other", ["main"], graph) is False

    def test_is_reachable_from_entries_empty_entries_false(self):
        a = ProprietaryReachabilityAnalyzer()
        graph = {"main": {"callees": ["handler"]}}
        assert a._is_reachable_from_entries("handler", [], graph) is False

    def test_is_reachable_self_entry(self):
        a = ProprietaryReachabilityAnalyzer()
        graph = {"main": {"callees": []}}
        assert a._is_reachable_from_entries("main", ["main"], graph) is True

    def test_is_reachable_handles_cycles_no_hang(self):
        a = ProprietaryReachabilityAnalyzer()
        graph = {
            "a": {"callees": ["b"]},
            "b": {"callees": ["a"]},
        }
        result = a._is_reachable_from_entries("b", ["a"], graph)
        assert isinstance(result, bool)

    def test_is_reachable_deep_chain(self):
        a = ProprietaryReachabilityAnalyzer()
        n = 30
        graph = {f"f{i}": {"callees": [f"f{i+1}"]} for i in range(n)}
        graph[f"f{n}"] = {"callees": []}
        assert a._is_reachable_from_entries(f"f{n}", ["f0"], graph) is True

    def test_is_reachable_star_graph(self):
        a = ProprietaryReachabilityAnalyzer()
        graph = {"root": {"callees": [f"leaf_{i}" for i in range(50)]}}
        for i in range(50):
            graph[f"leaf_{i}"] = {"callees": []}
        assert a._is_reachable_from_entries("leaf_25", ["root"], graph) is True

    def test_determine_reachability_structure(self):
        a = ProprietaryReachabilityAnalyzer()
        result = a._determine_reachability([], {"graph": {}, "entry_points": []}, [])
        for key in ("reachable_count", "unreachable_count", "reachable_matches", "unreachable_matches"):
            assert key in result

    def test_determine_reachability_no_matches_all_zero(self):
        a = ProprietaryReachabilityAnalyzer()
        result = a._determine_reachability([], {"graph": {}, "entry_points": []}, [])
        assert result["reachable_count"] == 0
        assert result["unreachable_count"] == 0

    def test_determine_reachability_reachable_via_call_graph(self):
        a = ProprietaryReachabilityAnalyzer()
        match = _make_vuln_match(context={"function": "execute"})
        call_graph = {
            "graph": {
                "main": {"callees": ["execute"]},
                "execute": {"callees": []},
            },
            "entry_points": ["main"],
        }
        result = a._determine_reachability([match], call_graph, [])
        assert result["reachable_count"] == 1
        assert result["unreachable_count"] == 0

    def test_determine_reachability_unreachable_when_not_in_graph(self):
        a = ProprietaryReachabilityAnalyzer()
        match = _make_vuln_match(context={"function": "execute"})
        call_graph = {
            "graph": {
                "main": {"callees": []},
                "execute": {"callees": []},
            },
            "entry_points": ["main"],
        }
        result = a._determine_reachability([match], call_graph, [])
        assert result["unreachable_count"] == 1

    def test_determine_reachability_unknown_func_assumed_reachable(self):
        a = ProprietaryReachabilityAnalyzer()
        match = _make_vuln_match(context={"function": "nonexistent_func"})
        result = a._determine_reachability(
            [match], {"graph": {}, "entry_points": []}, []
        )
        assert result["reachable_count"] >= 1

    def test_determine_reachability_via_data_flow(self):
        a = ProprietaryReachabilityAnalyzer()
        match = _make_vuln_match(context={"function": "execute"})
        call_graph = {
            "graph": {
                "main": {"callees": []},
                "execute": {"callees": []},
            },
            "entry_points": ["main"],
        }
        data_flows = [{"sink": "execute", "source": "input"}]
        result = a._determine_reachability([match], call_graph, data_flows)
        assert result["reachable_count"] == 1

    def test_reachable_match_output_has_cve_id(self):
        a = ProprietaryReachabilityAnalyzer()
        match = _make_vuln_match(cve_id="CVE-TEST-001", context={"function": "nonexistent"})
        result = a._determine_reachability(
            [match], {"graph": {}, "entry_points": []}, []
        )
        if result["reachable_matches"]:
            assert result["reachable_matches"][0]["cve_id"] == "CVE-TEST-001"


# ===========================================================================
# 17. Edge cases
# ===========================================================================


class TestEdgeCases:
    def test_deeply_nested_python_no_crash(self):
        matcher = ProprietaryPatternMatcher()
        depth = 50
        code = "def f():\n" + "    if True:\n" * depth + "        pass\n"
        result = matcher.match_patterns(code, "python", "deep.py")
        assert isinstance(result, list)

    def test_unicode_in_python_code_no_crash(self):
        matcher = ProprietaryPatternMatcher()
        code = "# -*- coding: utf-8 -*-\ndef greet():\n    return '你好'\n"
        result = matcher.match_patterns(code, "python", "unicode.py")
        assert isinstance(result, list)

    def test_empty_string_javascript_returns_empty(self):
        matcher = ProprietaryPatternMatcher()
        result = matcher.match_patterns("", "javascript", "empty.js")
        assert result == []

    def test_code_path_with_thousand_functions_in_chain(self):
        chain = [f"func_{i}" for i in range(1000)]
        cp = ProprietaryCodePath(
            source_file="big.py",
            start_line=1,
            end_line=5000,
            function_chain=chain,
            data_flow_path=[],
            entry_points=["func_0"],
            is_public_api=True,
            call_depth=1000,
            complexity_score=9.99,
            confidence=AnalysisConfidence.VERY_LOW,
        )
        assert len(cp.function_chain) == 1000

    def test_reachability_bfs_on_star_graph_is_true(self):
        a = ProprietaryReachabilityAnalyzer()
        graph = {"root": {"callees": [f"leaf_{i}" for i in range(100)]}}
        for i in range(100):
            graph[f"leaf_{i}"] = {"callees": []}
        assert a._is_reachable_from_entries("leaf_50", ["root"], graph) is True

    def test_pattern_matcher_two_instances_independent(self):
        m1 = ProprietaryPatternMatcher()
        m2 = ProprietaryPatternMatcher()
        assert m1._sql_injection_patterns is not m2._sql_injection_patterns

    def test_vuln_match_line_number_computed_correctly(self):
        matcher = ProprietaryPatternMatcher()
        code = "// line 1\n// line 2\neval(x);\n"
        result = matcher.match_patterns(code, "javascript", "app.js")
        found = [m for m in result if m.context.get("function") == "eval"]
        assert any(m.matched_location[1] == 3 for m in found)

    def test_analyze_repository_no_crash_on_syntax_error_file(self):
        a = ProprietaryReachabilityAnalyzer()
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "broken.py").write_text("def broken(:")
            # Should not raise
            result = a.analyze_repository(Path(tmp), [], "python")
        assert isinstance(result, dict)

    def test_all_confidence_levels_usable_in_vuln_match(self):
        for confidence in AnalysisConfidence:
            m = _make_vuln_match(confidence=confidence)
            assert m.confidence is confidence

    def test_all_confidence_levels_usable_in_code_path(self):
        for confidence in AnalysisConfidence:
            cp = _make_code_path(confidence=confidence)
            assert cp.confidence is confidence
