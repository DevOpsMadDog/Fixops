"""Rigorous tests for ReachabilityAnalyzer core functionality.

These tests exercise the internal helper methods of ReachabilityAnalyzer
with realistic data structures and verify semantic correctness.
"""


from risk.reachability.analyzer import (
    CodePath,
    ReachabilityAnalyzer,
    ReachabilityConfidence,
    VulnerabilityReachability,
)
from risk.reachability.code_analysis import AnalysisResult, AnalysisTool


class TestReachabilityConfidence:
    """Tests for ReachabilityConfidence enum."""

    def test_confidence_values(self):
        """Verify all confidence levels have expected string values."""
        assert ReachabilityConfidence.HIGH.value == "high"
        assert ReachabilityConfidence.MEDIUM.value == "medium"
        assert ReachabilityConfidence.LOW.value == "low"
        assert ReachabilityConfidence.UNKNOWN.value == "unknown"


class TestCodePath:
    """Tests for CodePath dataclass."""

    def test_code_path_defaults(self):
        """Verify CodePath has correct default values."""
        path = CodePath(file_path="src/main.py")
        assert path.file_path == "src/main.py"
        assert path.function_name is None
        assert path.line_number is None
        assert path.column_number is None
        assert path.is_invoked is False
        assert path.call_chain == []
        assert path.entry_points == []
        assert path.data_flow_path is None
        assert path.code_snippet is None

    def test_code_path_with_all_fields(self):
        """Verify CodePath correctly stores all fields."""
        path = CodePath(
            file_path="src/db.py",
            function_name="execute_query",
            line_number=42,
            column_number=8,
            is_invoked=True,
            call_chain=["main", "handler", "execute_query"],
            entry_points=["main"],
            data_flow_path=["user_input", "sanitize", "execute_query"],
            code_snippet="cursor.execute(query)",
        )
        assert path.file_path == "src/db.py"
        assert path.function_name == "execute_query"
        assert path.line_number == 42
        assert path.column_number == 8
        assert path.is_invoked is True
        assert len(path.call_chain) == 3
        assert len(path.entry_points) == 1
        assert len(path.data_flow_path) == 3


class TestVulnerabilityReachability:
    """Tests for VulnerabilityReachability dataclass."""

    def test_vulnerability_reachability_to_dict(self):
        """Verify to_dict produces correct dictionary structure."""
        code_path = CodePath(
            file_path="src/api.py",
            function_name="handle_request",
            line_number=100,
            is_invoked=True,
            call_chain=["main", "handle_request"],
            entry_points=["main"],
        )
        result = VulnerabilityReachability(
            cve_id="CVE-2023-12345",
            component_name="vulnerable-lib",
            component_version="1.0.0",
            is_reachable=True,
            confidence=ReachabilityConfidence.HIGH,
            confidence_score=0.85,
            code_paths=[code_path],
            call_graph_depth=2,
            data_flow_depth=3,
            analysis_method="hybrid",
            design_time_analysis={"tool": "semgrep", "findings": 5},
            runtime_analysis={"tool": "iast", "findings": 3},
            discrepancy_detected=True,
            discrepancy_details="Design found 5, runtime found 3",
            metadata={"repo": "test-repo"},
        )

        d = result.to_dict()
        assert d["cve_id"] == "CVE-2023-12345"
        assert d["component_name"] == "vulnerable-lib"
        assert d["component_version"] == "1.0.0"
        assert d["is_reachable"] is True
        assert d["confidence"] == "high"
        assert d["confidence_score"] == 0.85
        assert len(d["code_paths"]) == 1
        assert d["code_paths"][0]["file_path"] == "src/api.py"
        assert d["call_graph_depth"] == 2
        assert d["data_flow_depth"] == 3
        assert d["analysis_method"] == "hybrid"
        assert d["discrepancy_detected"] is True


class TestReachabilityAnalyzerInit:
    """Tests for ReachabilityAnalyzer initialization."""

    def test_default_initialization(self):
        """Verify analyzer initializes with default config."""
        analyzer = ReachabilityAnalyzer()
        assert analyzer.config == {}
        assert analyzer.enable_design_time is True
        assert analyzer.enable_runtime is True
        assert analyzer.enable_discrepancy_detection is True
        assert analyzer.min_confidence_threshold == 0.5
        assert analyzer.use_proprietary is True

    def test_custom_config(self):
        """Verify analyzer respects custom configuration."""
        config = {
            "enable_design_time": False,
            "enable_runtime": False,
            "enable_discrepancy_detection": False,
            "min_confidence_threshold": 0.8,
            "use_proprietary": False,
        }
        analyzer = ReachabilityAnalyzer(config=config)
        assert analyzer.enable_design_time is False
        assert analyzer.enable_runtime is False
        assert analyzer.enable_discrepancy_detection is False
        assert analyzer.min_confidence_threshold == 0.8
        assert analyzer.use_proprietary is False


class TestExtractVulnerablePatterns:
    """Tests for _extract_vulnerable_patterns method."""

    def test_sql_injection_pattern(self):
        """Verify SQL injection CWE-89 produces correct pattern."""
        analyzer = ReachabilityAnalyzer()
        patterns = analyzer._extract_vulnerable_patterns(
            "CVE-2023-12345",
            {"cwe_ids": ["CWE-89"], "description": "SQL injection in query builder"},
        )
        assert len(patterns) == 1
        pattern = patterns[0]
        assert pattern.cve_id == "CVE-2023-12345"
        assert pattern.cwe_id == "CWE-89"
        assert pattern.pattern_type == "sql_injection"
        assert "executeQuery" in pattern.vulnerable_functions
        assert "execute" in pattern.vulnerable_functions
        assert pattern.severity == "medium"

    def test_command_injection_pattern(self):
        """Verify command injection CWE-78 produces correct pattern."""
        analyzer = ReachabilityAnalyzer()
        patterns = analyzer._extract_vulnerable_patterns(
            "CVE-2023-54321",
            {
                "cwe_ids": ["CWE-78"],
                "description": "Command injection via shell",
                "severity": "critical",
            },
        )
        assert len(patterns) == 1
        pattern = patterns[0]
        assert pattern.pattern_type == "command_injection"
        assert "exec" in pattern.vulnerable_functions
        assert "system" in pattern.vulnerable_functions
        assert "subprocess" in pattern.vulnerable_functions
        assert pattern.severity == "critical"

    def test_xss_pattern(self):
        """Verify XSS CWE-79 produces correct pattern."""
        analyzer = ReachabilityAnalyzer()
        patterns = analyzer._extract_vulnerable_patterns(
            "CVE-2023-11111",
            {"cwe_ids": ["CWE-79"], "description": "XSS vulnerability"},
        )
        assert len(patterns) == 1
        pattern = patterns[0]
        assert pattern.pattern_type == "xss"
        assert "innerHTML" in pattern.vulnerable_functions
        assert "document.write" in pattern.vulnerable_functions

    def test_path_traversal_pattern(self):
        """Verify path traversal CWE-22 produces correct pattern."""
        analyzer = ReachabilityAnalyzer()
        patterns = analyzer._extract_vulnerable_patterns(
            "CVE-2023-22222",
            {"cwe_ids": ["CWE-22"], "description": "Path traversal"},
        )
        assert len(patterns) == 1
        pattern = patterns[0]
        assert pattern.pattern_type == "path_traversal"
        assert "open" in pattern.vulnerable_functions
        assert "read" in pattern.vulnerable_functions
        assert "*.txt" in pattern.file_patterns

    def test_multiple_cwe_ids(self):
        """Verify multiple CWE IDs produce multiple patterns."""
        analyzer = ReachabilityAnalyzer()
        patterns = analyzer._extract_vulnerable_patterns(
            "CVE-2023-99999",
            {"cwe_ids": ["CWE-89", "CWE-78"], "description": "Multiple vulns"},
        )
        assert len(patterns) == 2
        pattern_types = {p.pattern_type for p in patterns}
        assert "sql_injection" in pattern_types
        assert "command_injection" in pattern_types

    def test_string_cwe_id(self):
        """Verify string CWE ID is handled correctly."""
        analyzer = ReachabilityAnalyzer()
        patterns = analyzer._extract_vulnerable_patterns(
            "CVE-2023-33333",
            {"cwe_ids": "CWE-89", "description": "Single string CWE"},
        )
        assert len(patterns) == 1
        assert patterns[0].pattern_type == "sql_injection"

    def test_unknown_cwe_produces_generic_pattern(self):
        """Verify unknown CWE produces generic pattern."""
        analyzer = ReachabilityAnalyzer()
        patterns = analyzer._extract_vulnerable_patterns(
            "CVE-2023-44444",
            {"cwe_ids": ["CWE-999"], "description": "Unknown vulnerability type"},
        )
        assert len(patterns) == 1
        assert patterns[0].pattern_type == "generic"
        assert patterns[0].cwe_id == "CWE-999"

    def test_no_cwe_produces_generic_pattern(self):
        """Verify missing CWE produces generic pattern."""
        analyzer = ReachabilityAnalyzer()
        patterns = analyzer._extract_vulnerable_patterns(
            "CVE-2023-55555",
            {"description": "Vulnerability without CWE"},
        )
        assert len(patterns) == 1
        assert patterns[0].pattern_type == "generic"
        assert patterns[0].cwe_id is None


class TestConfidenceCalculation:
    """Tests for confidence calculation methods."""

    def test_confidence_level_high(self):
        """Verify high confidence threshold."""
        analyzer = ReachabilityAnalyzer()
        assert analyzer._confidence_level(0.8) == ReachabilityConfidence.HIGH
        assert analyzer._confidence_level(0.9) == ReachabilityConfidence.HIGH
        assert analyzer._confidence_level(1.0) == ReachabilityConfidence.HIGH

    def test_confidence_level_medium(self):
        """Verify medium confidence threshold."""
        analyzer = ReachabilityAnalyzer()
        assert analyzer._confidence_level(0.5) == ReachabilityConfidence.MEDIUM
        assert analyzer._confidence_level(0.6) == ReachabilityConfidence.MEDIUM
        assert analyzer._confidence_level(0.79) == ReachabilityConfidence.MEDIUM

    def test_confidence_level_low(self):
        """Verify low confidence threshold."""
        analyzer = ReachabilityAnalyzer()
        assert analyzer._confidence_level(0.1) == ReachabilityConfidence.LOW
        assert analyzer._confidence_level(0.3) == ReachabilityConfidence.LOW
        assert analyzer._confidence_level(0.49) == ReachabilityConfidence.LOW

    def test_confidence_level_unknown(self):
        """Verify unknown confidence for zero score."""
        analyzer = ReachabilityAnalyzer()
        assert analyzer._confidence_level(0.0) == ReachabilityConfidence.UNKNOWN

    def test_calculate_confidence_no_paths(self):
        """Verify zero confidence when no reachable paths."""
        analyzer = ReachabilityAnalyzer()
        score = analyzer._calculate_confidence(
            reachable_paths=[],
            vulnerable_patterns=[],
            call_graph={},
            design_time_result=None,
            runtime_result=None,
            data_flow_result=None,
        )
        assert score == 0.0

    def test_calculate_confidence_no_call_graph(self):
        """Verify low confidence without call graph."""
        analyzer = ReachabilityAnalyzer()
        path = CodePath(file_path="test.py", is_invoked=True)
        score = analyzer._calculate_confidence(
            reachable_paths=[path],
            vulnerable_patterns=[],
            call_graph={},
            design_time_result=None,
            runtime_result=None,
            data_flow_result=None,
        )
        assert score == 0.3

    def test_calculate_confidence_with_paths_and_graph(self):
        """Verify confidence increases with paths and call graph."""
        analyzer = ReachabilityAnalyzer()
        paths = [
            CodePath(
                file_path="test.py",
                is_invoked=True,
                call_chain=["main", "handler"],
                entry_points=["main"],
            ),
            CodePath(
                file_path="test2.py",
                is_invoked=True,
                call_chain=["api", "process"],
                entry_points=["api"],
            ),
        ]
        call_graph = {"main": {}, "handler": {}, "api": {}, "process": {}}
        score = analyzer._calculate_confidence(
            reachable_paths=paths,
            vulnerable_patterns=[],
            call_graph=call_graph,
            design_time_result=None,
            runtime_result=None,
            data_flow_result=None,
        )
        assert score > 0.3  # Should be higher than no-call-graph case

    def test_calculate_confidence_with_design_time_result(self):
        """Verify design-time analysis boosts confidence."""
        analyzer = ReachabilityAnalyzer()
        path = CodePath(
            file_path="test.py",
            is_invoked=True,
            call_chain=["main"],
            entry_points=["main"],
        )
        design_result = AnalysisResult(
            tool=AnalysisTool.SEMGREP,
            success=True,
            findings=[{"id": "finding1"}, {"id": "finding2"}],
        )
        score_without = analyzer._calculate_confidence(
            reachable_paths=[path],
            vulnerable_patterns=[],
            call_graph={"main": {}},
            design_time_result=None,
            runtime_result=None,
            data_flow_result=None,
        )
        score_with = analyzer._calculate_confidence(
            reachable_paths=[path],
            vulnerable_patterns=[],
            call_graph={"main": {}},
            design_time_result=design_result,
            runtime_result=None,
            data_flow_result=None,
        )
        assert score_with > score_without


class TestDiscrepancyDetection:
    """Tests for discrepancy detection between design-time and runtime analysis."""

    def test_no_discrepancy_similar_findings(self):
        """Verify no discrepancy when findings are similar."""
        analyzer = ReachabilityAnalyzer()
        design_result = AnalysisResult(
            tool=AnalysisTool.SEMGREP,
            success=True,
            findings=[{"id": f"finding{i}"} for i in range(10)],
        )
        runtime_result = AnalysisResult(
            tool=AnalysisTool.BANDIT,
            success=True,
            findings=[{"id": f"finding{i}"} for i in range(8)],
        )
        detected, details = analyzer._detect_discrepancy(design_result, runtime_result)
        assert detected is False
        assert details is None

    def test_discrepancy_large_difference(self):
        """Verify discrepancy detected when findings differ significantly."""
        analyzer = ReachabilityAnalyzer()
        design_result = AnalysisResult(
            tool=AnalysisTool.SEMGREP,
            success=True,
            findings=[{"id": f"finding{i}"} for i in range(10)],
        )
        runtime_result = AnalysisResult(
            tool=AnalysisTool.BANDIT,
            success=True,
            findings=[{"id": "finding1"}],
        )
        detected, details = analyzer._detect_discrepancy(design_result, runtime_result)
        assert detected is True
        assert "10" in details
        assert "1" in details

    def test_discrepancy_with_failed_analysis(self):
        """Verify no discrepancy when analysis failed."""
        analyzer = ReachabilityAnalyzer()
        design_result = AnalysisResult(
            tool=AnalysisTool.SEMGREP,
            success=False,
            findings=[],
        )
        runtime_result = AnalysisResult(
            tool=AnalysisTool.BANDIT,
            success=True,
            findings=[{"id": "finding1"}],
        )
        detected, details = analyzer._detect_discrepancy(design_result, runtime_result)
        assert detected is False


class TestAnalysisMethodDetermination:
    """Tests for _determine_analysis_method."""

    def test_hybrid_method(self):
        """Verify hybrid when both design and runtime results exist."""
        analyzer = ReachabilityAnalyzer()
        design = AnalysisResult(tool=AnalysisTool.SEMGREP, success=True)
        runtime = AnalysisResult(tool=AnalysisTool.BANDIT, success=True)
        assert analyzer._determine_analysis_method(design, runtime) == "hybrid"

    def test_design_time_only(self):
        """Verify design-time when only design result exists."""
        analyzer = ReachabilityAnalyzer()
        design = AnalysisResult(tool=AnalysisTool.SEMGREP, success=True)
        assert analyzer._determine_analysis_method(design, None) == "design-time"

    def test_runtime_only(self):
        """Verify runtime when only runtime result exists."""
        analyzer = ReachabilityAnalyzer()
        runtime = AnalysisResult(tool=AnalysisTool.BANDIT, success=True)
        assert analyzer._determine_analysis_method(None, runtime) == "runtime"

    def test_static_fallback(self):
        """Verify static when no results exist."""
        analyzer = ReachabilityAnalyzer()
        assert analyzer._determine_analysis_method(None, None) == "static"


class TestCallChainAndEntryPoints:
    """Tests for call chain and entry point methods."""

    def test_max_call_depth_empty(self):
        """Verify zero depth for empty paths."""
        analyzer = ReachabilityAnalyzer()
        assert analyzer._max_call_depth([]) == 0

    def test_max_call_depth_single_path(self):
        """Verify correct depth for single path."""
        analyzer = ReachabilityAnalyzer()
        path = CodePath(
            file_path="test.py",
            call_chain=["main", "handler", "process", "execute"],
        )
        assert analyzer._max_call_depth([path]) == 4

    def test_max_call_depth_multiple_paths(self):
        """Verify max depth across multiple paths."""
        analyzer = ReachabilityAnalyzer()
        paths = [
            CodePath(file_path="a.py", call_chain=["a", "b"]),
            CodePath(file_path="b.py", call_chain=["x", "y", "z", "w", "v"]),
            CodePath(file_path="c.py", call_chain=["p", "q", "r"]),
        ]
        assert analyzer._max_call_depth(paths) == 5

    def test_find_entry_points_public_api(self):
        """Verify entry points found for public APIs."""
        analyzer = ReachabilityAnalyzer()
        call_chain = ["api_handler", "process_request"]
        call_graph = {
            "api_handler": {"is_public": True},
            "process_request": {},
        }
        entry_points = analyzer._find_entry_points(call_chain, call_graph)
        assert "api_handler" in entry_points

    def test_find_entry_points_main_function(self):
        """Verify main function detected as entry point."""
        analyzer = ReachabilityAnalyzer()
        call_chain = ["main", "run"]
        call_graph = {"main": {}, "run": {}}
        entry_points = analyzer._find_entry_points(call_chain, call_graph)
        assert "main" in entry_points

    def test_find_entry_points_handler_pattern(self):
        """Verify handler pattern detected as entry point."""
        analyzer = ReachabilityAnalyzer()
        call_chain = ["request_handler", "process"]
        call_graph = {"request_handler": {}, "process": {}}
        entry_points = analyzer._find_entry_points(call_chain, call_graph)
        assert "request_handler" in entry_points

    def test_find_entry_points_empty_chain(self):
        """Verify empty result for empty call chain."""
        analyzer = ReachabilityAnalyzer()
        entry_points = analyzer._find_entry_points([], {})
        assert entry_points == []

    def test_build_call_chain_simple(self):
        """Verify call chain building with simple graph."""
        analyzer = ReachabilityAnalyzer()
        start_node = {"function": "caller", "parent": None}
        call_graph = {"caller": {"callers": []}}
        chain = analyzer._build_call_chain(start_node, call_graph, "target_func")
        assert "target_func" in chain
        assert "caller" in chain


class TestProprietaryAnalysis:
    """Tests for proprietary analysis methods."""

    def test_extract_proprietary_paths_empty(self):
        """Verify empty paths for empty result."""
        analyzer = ReachabilityAnalyzer()
        paths = analyzer._extract_proprietary_paths({})
        assert paths == []

    def test_extract_proprietary_paths_with_matches(self):
        """Verify paths extracted from proprietary result."""
        analyzer = ReachabilityAnalyzer()
        result = {
            "reachability": {
                "reachable_matches": [
                    {"location": ("src/api.py", 42)},
                    {"location": ("src/db.py", 100)},
                ]
            }
        }
        paths = analyzer._extract_proprietary_paths(result)
        assert len(paths) == 2
        assert paths[0].file_path == "src/api.py"
        assert paths[0].line_number == 42
        assert paths[1].file_path == "src/db.py"
        assert paths[1].line_number == 100

    def test_calculate_proprietary_confidence_no_results(self):
        """Verify zero confidence for empty proprietary result."""
        analyzer = ReachabilityAnalyzer()
        score = analyzer._calculate_proprietary_confidence({}, [])
        assert score == 0.0

    def test_calculate_proprietary_confidence_reachable_only(self):
        """Verify confidence when only reachable paths found."""
        analyzer = ReachabilityAnalyzer()
        result = {
            "reachability": {
                "reachable_count": 5,
                "unreachable_count": 0,
            }
        }
        score = analyzer._calculate_proprietary_confidence(result, [])
        assert score == 0.7

    def test_calculate_proprietary_confidence_mixed(self):
        """Verify higher confidence when both reachable and unreachable found."""
        analyzer = ReachabilityAnalyzer()
        result = {
            "reachability": {
                "reachable_count": 5,
                "unreachable_count": 10,
            }
        }
        score = analyzer._calculate_proprietary_confidence(result, [])
        assert score == 0.85

    def test_calculate_proprietary_confidence_unreachable_only(self):
        """Verify lower confidence when nothing reachable."""
        analyzer = ReachabilityAnalyzer()
        result = {
            "reachability": {
                "reachable_count": 0,
                "unreachable_count": 10,
            }
        }
        score = analyzer._calculate_proprietary_confidence(result, [])
        assert score == 0.5


class TestCreateUnknownResult:
    """Tests for _create_unknown_result method."""

    def test_unknown_result_structure(self):
        """Verify unknown result has correct structure."""
        analyzer = ReachabilityAnalyzer()
        result = analyzer._create_unknown_result(
            "CVE-2023-99999", "unknown-lib", "0.0.1"
        )
        assert result.cve_id == "CVE-2023-99999"
        assert result.component_name == "unknown-lib"
        assert result.component_version == "0.0.1"
        assert result.is_reachable is False
        assert result.confidence == ReachabilityConfidence.UNKNOWN
        assert result.confidence_score == 0.0
        assert result.code_paths == []
        assert result.call_graph_depth == 0
        assert result.data_flow_depth == 0
        assert result.analysis_method == "unknown"
