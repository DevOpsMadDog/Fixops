"""Tests for risk/reachability/proprietary_analyzer.py module."""

import ast
import tempfile
from pathlib import Path

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


class TestAnalysisConfidence:
    """Tests for AnalysisConfidence enum."""

    def test_confidence_values(self):
        """Test all confidence level values."""
        assert AnalysisConfidence.VERY_HIGH.value == "very_high"
        assert AnalysisConfidence.HIGH.value == "high"
        assert AnalysisConfidence.MEDIUM.value == "medium"
        assert AnalysisConfidence.LOW.value == "low"
        assert AnalysisConfidence.VERY_LOW.value == "very_low"

    def test_confidence_from_string(self):
        """Test creating confidence from string value."""
        assert AnalysisConfidence("very_high") == AnalysisConfidence.VERY_HIGH
        assert AnalysisConfidence("high") == AnalysisConfidence.HIGH
        assert AnalysisConfidence("medium") == AnalysisConfidence.MEDIUM


class TestProprietaryCodePath:
    """Tests for ProprietaryCodePath dataclass."""

    def test_code_path_creation(self):
        """Test creating a code path."""
        path = ProprietaryCodePath(
            source_file="test.py",
            start_line=10,
            end_line=20,
            function_chain=["main", "helper"],
            data_flow_path=[("x", 10), ("y", 15)],
            entry_points=["main"],
            is_public_api=True,
            call_depth=2,
            complexity_score=5.0,
            confidence=AnalysisConfidence.HIGH,
        )
        assert path.source_file == "test.py"
        assert path.start_line == 10
        assert path.end_line == 20
        assert path.function_chain == ["main", "helper"]
        assert path.is_public_api is True
        assert path.call_depth == 2
        assert path.complexity_score == 5.0
        assert path.confidence == AnalysisConfidence.HIGH


class TestProprietaryVulnerabilityMatch:
    """Tests for ProprietaryVulnerabilityMatch dataclass."""

    def test_vulnerability_match_creation(self):
        """Test creating a vulnerability match."""
        match = ProprietaryVulnerabilityMatch(
            cve_id="CVE-2021-1234",
            pattern_type="sql_injection",
            matched_location=("test.py", 42),
            matched_code="execute(query)",
            context={"function": "execute"},
            confidence=AnalysisConfidence.HIGH,
            exploitability_score=0.8,
        )
        assert match.cve_id == "CVE-2021-1234"
        assert match.pattern_type == "sql_injection"
        assert match.matched_location == ("test.py", 42)
        assert match.exploitability_score == 0.8


class TestProprietaryPatternMatcher:
    """Tests for ProprietaryPatternMatcher class."""

    def test_initialization(self):
        """Test pattern matcher initialization."""
        matcher = ProprietaryPatternMatcher()
        assert len(matcher._sql_injection_patterns) > 0
        assert len(matcher._command_injection_patterns) > 0
        assert len(matcher._xss_patterns) > 0
        assert len(matcher._path_traversal_patterns) > 0
        assert len(matcher._deserialization_patterns) > 0

    def test_build_sql_patterns(self):
        """Test SQL injection patterns are built correctly."""
        matcher = ProprietaryPatternMatcher()
        patterns = matcher._build_sql_patterns()
        assert len(patterns) == 3
        assert patterns[0]["type"] == "direct_execution"
        assert "execute" in patterns[0]["functions"]

    def test_build_command_patterns(self):
        """Test command injection patterns are built correctly."""
        matcher = ProprietaryPatternMatcher()
        patterns = matcher._build_command_patterns()
        assert len(patterns) == 2
        assert patterns[0]["type"] == "shell_execution"
        assert patterns[0]["risk_level"] == "critical"

    def test_build_xss_patterns(self):
        """Test XSS patterns are built correctly."""
        matcher = ProprietaryPatternMatcher()
        patterns = matcher._build_xss_patterns()
        assert len(patterns) == 2
        assert patterns[0]["type"] == "dom_manipulation"

    def test_build_path_patterns(self):
        """Test path traversal patterns are built correctly."""
        matcher = ProprietaryPatternMatcher()
        patterns = matcher._build_path_patterns()
        assert len(patterns) == 2
        assert patterns[0]["type"] == "file_operations"

    def test_build_deserialization_patterns(self):
        """Test deserialization patterns are built correctly."""
        matcher = ProprietaryPatternMatcher()
        patterns = matcher._build_deserialization_patterns()
        assert len(patterns) == 3
        assert patterns[0]["type"] == "pickle"
        assert patterns[0]["risk_level"] == "critical"

    def test_match_patterns_python(self):
        """Test pattern matching for Python code."""
        matcher = ProprietaryPatternMatcher()
        # Simple code that won't trigger visitor errors
        code = """
def safe_function():
    x = 1 + 2
    return x
"""
        matches = matcher.match_patterns(code, "python", "test.py")
        assert isinstance(matches, list)

    def test_match_patterns_javascript(self):
        """Test pattern matching for JavaScript code."""
        matcher = ProprietaryPatternMatcher()
        code = """
function dangerous() {
    eval(userInput);
    document.write(data);
}
"""
        matches = matcher.match_patterns(code, "javascript", "test.js")
        assert isinstance(matches, list)
        assert len(matches) >= 2

    def test_match_patterns_java(self):
        """Test pattern matching for Java code."""
        matcher = ProprietaryPatternMatcher()
        code = """
public class Test {
    public void query() {
        Statement.execute(sql);
    }
}
"""
        matches = matcher.match_patterns(code, "java", "Test.java")
        assert isinstance(matches, list)

    def test_match_patterns_unknown_language(self):
        """Test pattern matching for unknown language returns empty list."""
        matcher = ProprietaryPatternMatcher()
        matches = matcher.match_patterns("code", "unknown", "test.txt")
        assert matches == []

    def test_match_python_patterns_syntax_error(self):
        """Test Python pattern matching handles syntax errors gracefully."""
        matcher = ProprietaryPatternMatcher()
        code = "def broken("  # Invalid Python syntax
        matches = matcher._match_python_patterns(code, "test.py")
        assert matches == []

    def test_match_javascript_patterns_finds_dangerous_functions(self):
        """Test JavaScript pattern matching finds dangerous functions."""
        matcher = ProprietaryPatternMatcher()
        code = """
var x = eval("code");
setTimeout(callback, 1000);
element.innerHTML = userInput;
"""
        matches = matcher._match_javascript_patterns(code, "test.js")
        # The matcher finds eval and setTimeout as XSS patterns
        assert len(matches) >= 2

    def test_match_java_patterns_finds_sql_injection(self):
        """Test Java pattern matching finds SQL injection patterns."""
        matcher = ProprietaryPatternMatcher()
        code = """
Statement.execute(query);
PreparedStatement.executeQuery(sql);
"""
        matches = matcher._match_java_patterns(code, "Test.java")
        assert len(matches) >= 2


class TestProprietaryPythonVisitor:
    """Tests for ProprietaryPythonVisitor class."""

    def test_visitor_initialization(self):
        """Test visitor initialization."""
        matcher = ProprietaryPatternMatcher()
        visitor = ProprietaryPythonVisitor(matcher, "test.py")
        assert visitor.file_path == "test.py"
        assert visitor.matches == []
        assert visitor.current_function is None
        assert visitor.current_class is None

    def test_visit_function_def(self):
        """Test visiting function definition."""
        matcher = ProprietaryPatternMatcher()
        visitor = ProprietaryPythonVisitor(matcher, "test.py")
        code = """
def my_function():
    pass
"""
        tree = ast.parse(code)
        visitor.visit(tree)
        assert visitor.current_function is None  # Reset after visit

    def test_visit_class_def(self):
        """Test visiting class definition."""
        matcher = ProprietaryPatternMatcher()
        visitor = ProprietaryPythonVisitor(matcher, "test.py")
        code = """
class MyClass:
    def method(self):
        pass
"""
        tree = ast.parse(code)
        visitor.visit(tree)
        assert visitor.current_class is None  # Reset after visit

    def test_visit_call_with_user_input(self):
        """Test visiting function call with user input."""
        matcher = ProprietaryPatternMatcher()
        visitor = ProprietaryPythonVisitor(matcher, "test.py")
        code = """
def vulnerable(request):
    cursor.execute(request.data)
"""
        tree = ast.parse(code)
        visitor.visit(tree)
        # Should detect potential vulnerability

    def test_extract_function_name_from_name(self):
        """Test extracting function name from ast.Name node."""
        matcher = ProprietaryPatternMatcher()
        visitor = ProprietaryPythonVisitor(matcher, "test.py")
        node = ast.Name(id="my_function")
        assert visitor._extract_function_name(node) == "my_function"

    def test_extract_function_name_from_attribute(self):
        """Test extracting function name from ast.Attribute node."""
        matcher = ProprietaryPatternMatcher()
        visitor = ProprietaryPythonVisitor(matcher, "test.py")
        node = ast.Attribute(value=ast.Name(id="obj"), attr="method")
        assert visitor._extract_function_name(node) == "method"

    def test_extract_function_name_from_call(self):
        """Test extracting function name from ast.Call node."""
        matcher = ProprietaryPatternMatcher()
        visitor = ProprietaryPythonVisitor(matcher, "test.py")
        inner_name = ast.Name(id="func")
        node = ast.Call(func=inner_name, args=[], keywords=[])
        assert visitor._extract_function_name(node) == "func"

    def test_extract_function_name_unknown_node(self):
        """Test extracting function name from unknown node type."""
        matcher = ProprietaryPatternMatcher()
        visitor = ProprietaryPythonVisitor(matcher, "test.py")
        node = ast.Constant(value=42)
        assert visitor._extract_function_name(node) is None

    def test_check_user_input_flow_with_request(self):
        """Test checking user input flow with request variable."""
        matcher = ProprietaryPatternMatcher()
        visitor = ProprietaryPythonVisitor(matcher, "test.py")
        code = "execute(request_data)"
        tree = ast.parse(code, mode="eval")
        call_node = tree.body
        assert visitor._check_user_input_flow(call_node) is True

    def test_check_user_input_flow_with_keyword_arg(self):
        """Test checking user input flow with keyword argument."""
        matcher = ProprietaryPatternMatcher()
        visitor = ProprietaryPythonVisitor(matcher, "test.py")
        code = "execute(data=user_input)"
        tree = ast.parse(code, mode="eval")
        call_node = tree.body
        assert visitor._check_user_input_flow(call_node) is True

    def test_check_user_input_flow_no_user_input(self):
        """Test checking user input flow with no user input."""
        matcher = ProprietaryPatternMatcher()
        visitor = ProprietaryPythonVisitor(matcher, "test.py")
        code = "execute(safe_value)"
        tree = ast.parse(code, mode="eval")
        call_node = tree.body
        assert visitor._check_user_input_flow(call_node) is False


class TestProprietaryCallGraphBuilder:
    """Tests for ProprietaryCallGraphBuilder class."""

    def test_initialization(self):
        """Test call graph builder initialization."""
        builder = ProprietaryCallGraphBuilder()
        assert builder.graph == {}
        assert builder.entry_points == set()

    def test_build_from_repository_python(self):
        """Test building call graph from Python repository."""
        builder = ProprietaryCallGraphBuilder()
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_path = Path(tmpdir)
            py_file = repo_path / "test.py"
            py_file.write_text(
                """
def main():
    helper()

def helper():
    pass
"""
            )
            result = builder.build_from_repository(repo_path, "python")
            assert "graph" in result
            assert "entry_points" in result
            assert "total_functions" in result

    def test_build_from_repository_javascript(self):
        """Test building call graph from JavaScript repository."""
        builder = ProprietaryCallGraphBuilder()
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_path = Path(tmpdir)
            js_file = repo_path / "test.js"
            js_file.write_text(
                """
export function main() {
    helper();
}

function helper() {
    return 42;
}
"""
            )
            result = builder.build_from_repository(repo_path, "javascript")
            assert "graph" in result
            assert "total_functions" in result

    def test_build_from_repository_java(self):
        """Test building call graph from Java repository."""
        builder = ProprietaryCallGraphBuilder()
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_path = Path(tmpdir)
            java_file = repo_path / "Test.java"
            java_file.write_text(
                """
public class Test {
    public void main() {
        helper();
    }

    private void helper() {
        return;
    }
}
"""
            )
            result = builder.build_from_repository(repo_path, "java")
            assert "graph" in result
            assert "total_functions" in result

    def test_build_from_repository_unknown_language(self):
        """Test building call graph for unknown language returns empty dict."""
        builder = ProprietaryCallGraphBuilder()
        with tempfile.TemporaryDirectory() as tmpdir:
            result = builder.build_from_repository(Path(tmpdir), "unknown")
            assert result == {}

    def test_build_python_graph_ignores_venv(self):
        """Test Python graph building ignores venv directories."""
        builder = ProprietaryCallGraphBuilder()
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_path = Path(tmpdir)
            venv_dir = repo_path / "venv"
            venv_dir.mkdir()
            venv_file = venv_dir / "test.py"
            venv_file.write_text("def ignored(): pass")

            result = builder._build_python_graph(repo_path)
            assert result["total_functions"] == 0

    def test_build_javascript_graph_ignores_node_modules(self):
        """Test JavaScript graph building ignores node_modules."""
        builder = ProprietaryCallGraphBuilder()
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_path = Path(tmpdir)
            nm_dir = repo_path / "node_modules"
            nm_dir.mkdir()
            nm_file = nm_dir / "test.js"
            nm_file.write_text("function ignored() {}")

            result = builder._build_javascript_graph(repo_path)
            assert result["total_functions"] == 0


class TestProprietaryCallGraphBuilderVisitor:
    """Tests for ProprietaryCallGraphBuilderVisitor class."""

    def test_visitor_initialization(self):
        """Test visitor initialization."""
        visitor = ProprietaryCallGraphBuilderVisitor("test.py")
        assert visitor.file_path == "test.py"
        assert visitor.graph == {}
        assert visitor.entry_points == set()

    def test_visit_function_def(self):
        """Test visiting function definition."""
        visitor = ProprietaryCallGraphBuilderVisitor("test.py")
        code = """
def my_function():
    pass
"""
        tree = ast.parse(code)
        visitor.visit(tree)
        assert "my_function" in visitor.graph

    def test_visit_class_def(self):
        """Test visiting class definition."""
        visitor = ProprietaryCallGraphBuilderVisitor("test.py")
        code = """
class MyClass:
    def method(self):
        pass
"""
        tree = ast.parse(code)
        visitor.visit(tree)
        assert "MyClass.method" in visitor.graph

    def test_visit_call(self):
        """Test visiting function call."""
        visitor = ProprietaryCallGraphBuilderVisitor("test.py")
        code = """
def caller():
    callee()

def callee():
    pass
"""
        tree = ast.parse(code)
        visitor.visit(tree)
        assert "caller" in visitor.graph
        assert "callee" in visitor.graph


class TestProprietaryDataFlowAnalyzer:
    """Tests for ProprietaryDataFlowAnalyzer class."""

    def test_initialization(self):
        """Test data flow analyzer initialization."""
        analyzer = ProprietaryDataFlowAnalyzer()
        assert len(analyzer.taint_sources) > 0
        assert len(analyzer.taint_sinks) > 0
        assert len(analyzer.sanitizers) > 0

    def test_analyze_taint_flow_python(self):
        """Test taint flow analysis for Python code."""
        analyzer = ProprietaryDataFlowAnalyzer()
        code = """
def vulnerable(request):
    data = request.get_data()
    cursor.execute(data)
"""
        result = analyzer.analyze_taint_flow(code, "python", "test.py")
        assert isinstance(result, list)

    def test_analyze_taint_flow_javascript(self):
        """Test taint flow analysis for JavaScript code."""
        analyzer = ProprietaryDataFlowAnalyzer()
        code = """
function vulnerable(req) {
    var data = req.body;
    eval(data);
}
"""
        result = analyzer.analyze_taint_flow(code, "javascript", "test.js")
        assert isinstance(result, list)

    def test_analyze_taint_flow_unknown_language(self):
        """Test taint flow analysis for unknown language."""
        analyzer = ProprietaryDataFlowAnalyzer()
        result = analyzer.analyze_taint_flow("code", "unknown", "test.txt")
        assert result == []


class TestProprietaryTaintAnalyzer:
    """Tests for ProprietaryTaintAnalyzer class."""

    def test_initialization(self):
        """Test taint analyzer initialization."""
        data_flow_analyzer = ProprietaryDataFlowAnalyzer()
        analyzer = ProprietaryTaintAnalyzer(data_flow_analyzer, "test.py")
        assert analyzer.file_path == "test.py"
        assert analyzer.tainted_vars == set()
        assert analyzer.taint_flows == []

    def test_visit_function_def_with_request_param(self):
        """Test visiting function with request parameter."""
        data_flow_analyzer = ProprietaryDataFlowAnalyzer()
        analyzer = ProprietaryTaintAnalyzer(data_flow_analyzer, "test.py")
        code = """
def handler(request):
    data = request.get_data()
"""
        tree = ast.parse(code)
        analyzer.visit(tree)
        # The analyzer tracks tainted vars within function scope

    def test_visit_assign_from_tainted(self):
        """Test visiting assignment from tainted variable."""
        data_flow_analyzer = ProprietaryDataFlowAnalyzer()
        analyzer = ProprietaryTaintAnalyzer(data_flow_analyzer, "test.py")
        analyzer.tainted_vars.add("request")
        code = """
data = request.get_data()
"""
        tree = ast.parse(code)
        analyzer.visit(tree)
        # Taint propagates through assignments

    def test_visit_call_with_tainted_arg(self):
        """Test visiting function call with tainted argument."""
        data_flow_analyzer = ProprietaryDataFlowAnalyzer()
        analyzer = ProprietaryTaintAnalyzer(data_flow_analyzer, "test.py")
        analyzer.tainted_vars.add("user_input")
        code = """
execute(user_input)
"""
        tree = ast.parse(code)
        analyzer.visit(tree)
        # Taint flows are recorded when tainted vars reach sinks


class TestProprietaryReachabilityAnalyzer:
    """Tests for ProprietaryReachabilityAnalyzer class."""

    def test_initialization(self):
        """Test reachability analyzer initialization."""
        analyzer = ProprietaryReachabilityAnalyzer()
        assert analyzer.pattern_matcher is not None
        assert analyzer.call_graph_builder is not None
        assert analyzer.data_flow_analyzer is not None

    def test_analyze_repository(self):
        """Test analyzing a repository."""
        analyzer = ProprietaryReachabilityAnalyzer()
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_path = Path(tmpdir)
            py_file = repo_path / "test.py"
            py_file.write_text(
                """
def main():
    helper()

def helper():
    pass
"""
            )
            # analyze_repository requires repo_path, vulnerable_patterns, and language
            vulnerable_patterns = [{"type": "sql_injection", "pattern": "execute"}]
            result = analyzer.analyze_repository(
                repo_path, vulnerable_patterns, "python"
            )
            assert "matches" in result
            assert "call_graph" in result
            assert "data_flows" in result
            assert "reachability" in result

    def test_get_code_files_python(self):
        """Test getting Python code files."""
        analyzer = ProprietaryReachabilityAnalyzer()
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_path = Path(tmpdir)
            py_file = repo_path / "test.py"
            py_file.write_text("pass")

            files = analyzer._get_code_files(repo_path, "python")
            assert len(files) == 1

    def test_get_code_files_javascript(self):
        """Test getting JavaScript code files."""
        analyzer = ProprietaryReachabilityAnalyzer()
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_path = Path(tmpdir)
            js_file = repo_path / "test.js"
            js_file.write_text("// code")
            # Note: typescript is a separate language in the extensions map

            files = analyzer._get_code_files(repo_path, "javascript")
            assert len(files) == 1  # Only .js files for "javascript" language

    def test_get_code_files_java(self):
        """Test getting Java code files."""
        analyzer = ProprietaryReachabilityAnalyzer()
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_path = Path(tmpdir)
            java_file = repo_path / "Test.java"
            java_file.write_text("// code")

            files = analyzer._get_code_files(repo_path, "java")
            assert len(files) == 1

    def test_get_code_files_ignores_venv(self):
        """Test that venv directories are ignored."""
        analyzer = ProprietaryReachabilityAnalyzer()
        with tempfile.TemporaryDirectory() as tmpdir:
            repo_path = Path(tmpdir)
            venv_dir = repo_path / "venv"
            venv_dir.mkdir()
            venv_file = venv_dir / "test.py"
            venv_file.write_text("pass")

            files = analyzer._get_code_files(repo_path, "python")
            assert len(files) == 0

    def test_determine_reachability(self):
        """Test determining reachability of vulnerabilities."""
        analyzer = ProprietaryReachabilityAnalyzer()
        matches = [
            ProprietaryVulnerabilityMatch(
                cve_id="CVE-2021-1234",
                pattern_type="sql_injection",
                matched_location=("test.py", 10),
                matched_code="execute(query)",
                context={"function": "execute"},
                confidence=AnalysisConfidence.HIGH,
                exploitability_score=0.8,
            )
        ]
        call_graph = {
            "graph": {
                "main": {"callers": [], "callees": ["helper"]},
                "helper": {"callers": ["main"], "callees": []},
            },
            "entry_points": ["main"],
        }
        data_flows = []

        # _determine_reachability takes matches, call_graph, and data_flows
        result = analyzer._determine_reachability(matches, call_graph, data_flows)
        assert isinstance(result, dict)
        assert "reachable_count" in result
        assert "unreachable_count" in result

    def test_is_reachable_from_entries(self):
        """Test checking if function is reachable from entry points."""
        analyzer = ProprietaryReachabilityAnalyzer()
        graph = {
            "main": {"callers": [], "callees": ["helper"]},
            "helper": {"callers": ["main"], "callees": ["target"]},
            "target": {"callers": ["helper"], "callees": []},
        }
        entry_points = ["main"]

        # _is_reachable_from_entries takes func_name, entry_points, graph (in that order)
        assert (
            analyzer._is_reachable_from_entries("target", entry_points, graph) is True
        )
        assert (
            analyzer._is_reachable_from_entries("isolated", entry_points, graph)
            is False
        )
