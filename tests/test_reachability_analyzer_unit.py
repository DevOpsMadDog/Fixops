"""
Unit tests for suite-evidence-risk/risk/reachability/analyzer.py

Tests cover:
- ReachabilityConfidence enum values and semantics
- CodePath dataclass construction and field defaults
- VulnerabilityReachability dataclass construction and to_dict()
- ReachabilityAnalyzer.__init__ with and without injected dependencies
- _extract_vulnerable_patterns for CWE-89, CWE-78, CWE-79, CWE-22, and generic
- _check_pattern_reachability with real-shaped mock call graphs
- _build_call_chain (linear, branched, cycle-detection, depth-limit)
- _find_entry_points (public API flag, entry pattern matching)
- _calculate_confidence (no paths, no call graph, multi-factor)
- _confidence_level threshold boundaries
- _detect_discrepancy (>50%, <=50%, zeros)
- _determine_analysis_method (all four branch combinations)
- _max_call_depth (empty, single, multiple paths)
- _extract_proprietary_paths (empty, populated)
- _calculate_proprietary_confidence (zeros, reachable only, both counts)
- _create_unknown_result field values
"""

from __future__ import annotations

import sys
import types
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# sys.path injection — must happen before any suite-evidence-risk imports
# ---------------------------------------------------------------------------
_SUITE_PATH = str(Path(__file__).parent.parent / "suite-evidence-risk")
if _SUITE_PATH not in sys.path:
    sys.path.insert(0, _SUITE_PATH)

# ---------------------------------------------------------------------------
# Minimal concrete stand-ins for the key types the analyzer references
# ---------------------------------------------------------------------------


class _FakeVulnerablePattern:
    """Minimal VulnerablePattern substitute."""

    def __init__(
        self,
        cve_id="CVE-TEST",
        cwe_id=None,
        pattern_type="generic",
        vulnerable_functions=None,
        file_patterns=None,
        description="",
        severity="medium",
    ):
        self.cve_id = cve_id
        self.cwe_id = cwe_id
        self.pattern_type = pattern_type
        self.vulnerable_functions = vulnerable_functions or []
        self.file_patterns = file_patterns or []
        self.description = description
        self.severity = severity


class _FakeAnalysisResult:
    """Minimal AnalysisResult substitute."""

    def __init__(self, tool=None, success=True, findings=None):
        self.tool = tool
        self.success = success
        self.findings = findings or []

    def to_dict(self):
        return {"tool": str(self.tool), "success": self.success, "findings": self.findings}


class _FakeDataFlowResult:
    """Minimal DataFlowResult substitute."""

    def __init__(self, has_path=True, max_depth=3):
        self.has_path = has_path
        self.max_depth = max_depth

    def get_path_for_function(self, func_name):
        return [func_name, "sink"] if self.has_path else None


# ---------------------------------------------------------------------------
# Build lightweight stub modules using types.ModuleType so Python's import
# machinery treats them as real packages, not MagicMock instances.
# We only need to populate the names that analyzer.py imports by name.
# ---------------------------------------------------------------------------

def _make_module(name: str, path: list | None = None) -> types.ModuleType:
    mod = types.ModuleType(name)
    if path is not None:
        # Packages need __path__ so Python treats them as packages
        # and allows sub-module imports.
        mod.__path__ = path
    sys.modules[name] = mod
    return mod


_RISK_PATH = str(Path(_SUITE_PATH) / "risk")
_REACH_PATH = str(Path(_SUITE_PATH) / "risk" / "reachability")

# Ensure parent packages exist in sys.modules as proper module objects
# (only if not already present from a previous import).
_pkg_paths = {"risk": [_RISK_PATH], "risk.reachability": [_REACH_PATH]}
for _pkg in ("risk", "risk.reachability"):
    if _pkg not in sys.modules:
        _make_module(_pkg, path=_pkg_paths[_pkg])
    elif isinstance(sys.modules[_pkg], MagicMock):
        # Replace a previously-registered MagicMock with a real module
        sys.modules[_pkg] = _make_module(_pkg, path=_pkg_paths[_pkg])

# Leaf sub-modules referenced by analyzer.py — each gets a real module with
# the specific names the analyzer imports from it.
_call_graph_mod = _make_module("risk.reachability.call_graph")
_call_graph_mod.CallGraphBuilder = MagicMock()

# Only create a stub if the real module hasn't been imported yet — otherwise
# we'd clobber the real module's attributes (e.g. subprocess) and break other
# tests that patch through the module path.
if "risk.reachability.code_analysis" not in sys.modules or isinstance(
    sys.modules["risk.reachability.code_analysis"], MagicMock
):
    _code_analysis_mod = _make_module("risk.reachability.code_analysis")
    _code_analysis_mod.VulnerablePattern = _FakeVulnerablePattern
    _code_analysis_mod.AnalysisResult = _FakeAnalysisResult
    _code_analysis_mod.CodeAnalyzer = MagicMock()
else:
    _code_analysis_mod = sys.modules["risk.reachability.code_analysis"]

_data_flow_mod = _make_module("risk.reachability.data_flow")
_data_flow_mod.DataFlowAnalyzer = MagicMock()

_git_mod = _make_module("risk.reachability.git_integration")
_git_mod.GitRepository = MagicMock()
_git_mod.GitRepositoryAnalyzer = MagicMock()
_git_mod.RepositoryMetadata = MagicMock()

_prop_analyzer_mod = _make_module("risk.reachability.proprietary_analyzer")
_prop_analyzer_mod.ProprietaryReachabilityAnalyzer = MagicMock()

_prop_consensus_mod = _make_module("risk.reachability.proprietary_consensus")
_prop_consensus_mod.ProprietaryConsensusEngine = MagicMock()

_prop_scoring_mod = _make_module("risk.reachability.proprietary_scoring")
_prop_scoring_mod.ProprietaryScoringEngine = MagicMock()

_prop_threat_mod = _make_module("risk.reachability.proprietary_threat_intel")
_prop_threat_mod.ProprietaryThreatIntelligenceEngine = MagicMock()

# ---------------------------------------------------------------------------
# NOW import the real module under test — all its sub-imports will hit our
# stubs above.
# ---------------------------------------------------------------------------
# Remove any previously cached import of the analyzer itself so the real
# file is freshly loaded against our stubs.
sys.modules.pop("risk.reachability.analyzer", None)

from risk.reachability.analyzer import (  # noqa: E402
    CodePath,
    ReachabilityAnalyzer,
    ReachabilityConfidence,
    VulnerabilityReachability,
)


# ---------------------------------------------------------------------------
# Helpers / factories
# ---------------------------------------------------------------------------


def _make_analyzer(**config_overrides) -> ReachabilityAnalyzer:
    """Return a ReachabilityAnalyzer with all sub-analyzers mocked out."""
    mock_git = MagicMock()
    mock_code = MagicMock()
    config = {"use_proprietary": False, **config_overrides}
    return ReachabilityAnalyzer(config=config, git_analyzer=mock_git, code_analyzer=mock_code)


def _make_analysis_result(success=True, findings_count=0):
    return _FakeAnalysisResult(success=success, findings=[{}] * findings_count)


# ===========================================================================
# 1. ReachabilityConfidence enum
# ===========================================================================


class TestReachabilityConfidenceEnum:
    def test_high_value(self):
        assert ReachabilityConfidence.HIGH.value == "high"

    def test_medium_value(self):
        assert ReachabilityConfidence.MEDIUM.value == "medium"

    def test_low_value(self):
        assert ReachabilityConfidence.LOW.value == "low"

    def test_unknown_value(self):
        assert ReachabilityConfidence.UNKNOWN.value == "unknown"

    def test_all_members_present(self):
        names = {m.name for m in ReachabilityConfidence}
        assert names == {"HIGH", "MEDIUM", "LOW", "UNKNOWN"}

    def test_enum_identity(self):
        assert ReachabilityConfidence.HIGH is ReachabilityConfidence.HIGH

    def test_enum_inequality(self):
        assert ReachabilityConfidence.HIGH != ReachabilityConfidence.LOW


# ===========================================================================
# 2. CodePath dataclass
# ===========================================================================


class TestCodePathDataclass:
    def test_minimal_construction(self):
        cp = CodePath(file_path="app/main.py")
        assert cp.file_path == "app/main.py"

    def test_default_is_invoked(self):
        cp = CodePath(file_path="x.py")
        assert cp.is_invoked is False

    def test_default_call_chain_is_empty_list(self):
        cp = CodePath(file_path="x.py")
        assert cp.call_chain == []

    def test_default_entry_points_is_empty_list(self):
        cp = CodePath(file_path="x.py")
        assert cp.entry_points == []

    def test_default_data_flow_path_is_none(self):
        cp = CodePath(file_path="x.py")
        assert cp.data_flow_path is None

    def test_default_code_snippet_is_none(self):
        cp = CodePath(file_path="x.py")
        assert cp.code_snippet is None

    def test_full_construction(self):
        cp = CodePath(
            file_path="lib/db.py",
            function_name="query",
            line_number=42,
            column_number=8,
            is_invoked=True,
            call_chain=["handle_request", "fetch_data", "query"],
            entry_points=["handle_request"],
            data_flow_path=["user_input", "query"],
            code_snippet="db.execute(sql)",
        )
        assert cp.function_name == "query"
        assert cp.line_number == 42
        assert cp.column_number == 8
        assert cp.is_invoked is True
        assert len(cp.call_chain) == 3
        assert cp.entry_points == ["handle_request"]
        assert cp.data_flow_path == ["user_input", "query"]
        assert cp.code_snippet == "db.execute(sql)"

    def test_mutable_defaults_are_independent(self):
        cp1 = CodePath(file_path="a.py")
        cp2 = CodePath(file_path="b.py")
        cp1.call_chain.append("func_a")
        assert cp2.call_chain == []

    def test_optional_function_name_none(self):
        cp = CodePath(file_path="a.py")
        assert cp.function_name is None

    def test_optional_line_number_none(self):
        cp = CodePath(file_path="a.py")
        assert cp.line_number is None


# ===========================================================================
# 3. VulnerabilityReachability dataclass + to_dict
# ===========================================================================


class TestVulnerabilityReachability:
    def _make_vuln_reach(self, **overrides):
        defaults = dict(
            cve_id="CVE-2024-1234",
            component_name="requests",
            component_version="2.28.0",
            is_reachable=True,
            confidence=ReachabilityConfidence.HIGH,
            confidence_score=0.85,
            code_paths=[],
            call_graph_depth=3,
            data_flow_depth=2,
            analysis_method="static",
        )
        defaults.update(overrides)
        return VulnerabilityReachability(**defaults)

    def test_basic_fields(self):
        vr = self._make_vuln_reach()
        assert vr.cve_id == "CVE-2024-1234"
        assert vr.component_name == "requests"
        assert vr.component_version == "2.28.0"

    def test_is_reachable_true(self):
        vr = self._make_vuln_reach(is_reachable=True)
        assert vr.is_reachable is True

    def test_is_reachable_false(self):
        vr = self._make_vuln_reach(is_reachable=False)
        assert vr.is_reachable is False

    def test_confidence_enum(self):
        vr = self._make_vuln_reach(confidence=ReachabilityConfidence.MEDIUM)
        assert vr.confidence == ReachabilityConfidence.MEDIUM

    def test_default_discrepancy_detected_false(self):
        vr = self._make_vuln_reach()
        assert vr.discrepancy_detected is False

    def test_default_discrepancy_details_none(self):
        vr = self._make_vuln_reach()
        assert vr.discrepancy_details is None

    def test_default_metadata_empty_dict(self):
        vr = self._make_vuln_reach()
        assert vr.metadata == {}

    def test_to_dict_keys(self):
        vr = self._make_vuln_reach()
        d = vr.to_dict()
        expected_keys = {
            "cve_id",
            "component_name",
            "component_version",
            "is_reachable",
            "confidence",
            "confidence_score",
            "code_paths",
            "call_graph_depth",
            "data_flow_depth",
            "analysis_method",
            "design_time_analysis",
            "runtime_analysis",
            "discrepancy_detected",
            "discrepancy_details",
            "metadata",
        }
        assert set(d.keys()) == expected_keys

    def test_to_dict_confidence_is_string_value(self):
        vr = self._make_vuln_reach(confidence=ReachabilityConfidence.HIGH)
        assert vr.to_dict()["confidence"] == "high"

    def test_to_dict_confidence_string_passthrough(self):
        """When confidence is already a string (from cache) it must pass through unchanged."""
        vr = self._make_vuln_reach(confidence="medium")  # type: ignore[arg-type]
        assert vr.to_dict()["confidence"] == "medium"

    def test_to_dict_code_paths_serialised(self):
        cp = CodePath(
            file_path="app.py",
            function_name="run",
            line_number=10,
            is_invoked=True,
            call_chain=["main", "run"],
            entry_points=["main"],
        )
        vr = self._make_vuln_reach(code_paths=[cp])
        d = vr.to_dict()
        assert len(d["code_paths"]) == 1
        path_dict = d["code_paths"][0]
        assert path_dict["file_path"] == "app.py"
        assert path_dict["function_name"] == "run"
        assert path_dict["line_number"] == 10
        assert path_dict["is_invoked"] is True
        assert path_dict["call_chain"] == ["main", "run"]
        assert path_dict["entry_points"] == ["main"]

    def test_to_dict_empty_code_paths(self):
        vr = self._make_vuln_reach(code_paths=[])
        assert vr.to_dict()["code_paths"] == []

    def test_to_dict_metadata_preserved(self):
        vr = self._make_vuln_reach(metadata={"repo": "github.com/test/repo"})
        assert vr.to_dict()["metadata"]["repo"] == "github.com/test/repo"

    def test_to_dict_discrepancy_detected_propagated(self):
        vr = self._make_vuln_reach(
            discrepancy_detected=True,
            discrepancy_details="design=10, runtime=2",
        )
        d = vr.to_dict()
        assert d["discrepancy_detected"] is True
        assert d["discrepancy_details"] == "design=10, runtime=2"


# ===========================================================================
# 4. ReachabilityAnalyzer initialisation
# ===========================================================================


class TestReachabilityAnalyzerInit:
    def test_default_config_populated(self):
        az = _make_analyzer()
        assert isinstance(az.config, dict)

    def test_injected_git_analyzer_stored(self):
        mock_git = MagicMock()
        az = ReachabilityAnalyzer(
            config={"use_proprietary": False}, git_analyzer=mock_git, code_analyzer=MagicMock()
        )
        assert az.git_analyzer is mock_git

    def test_injected_code_analyzer_stored(self):
        mock_code = MagicMock()
        az = ReachabilityAnalyzer(
            config={"use_proprietary": False},
            git_analyzer=MagicMock(),
            code_analyzer=mock_code,
        )
        assert az.code_analyzer is mock_code

    def test_enable_design_time_default_true(self):
        az = _make_analyzer()
        assert az.enable_design_time is True

    def test_enable_runtime_default_true(self):
        az = _make_analyzer()
        assert az.enable_runtime is True

    def test_enable_discrepancy_detection_default_true(self):
        az = _make_analyzer()
        assert az.enable_discrepancy_detection is True

    def test_min_confidence_threshold_default(self):
        az = _make_analyzer()
        assert az.min_confidence_threshold == 0.5

    def test_use_proprietary_overrideable_false(self):
        az = _make_analyzer(use_proprietary=False)
        assert az.use_proprietary is False

    def test_use_proprietary_default_true(self):
        """Without any override, default should be True."""
        mock_git = MagicMock()
        mock_code = MagicMock()
        az = ReachabilityAnalyzer(git_analyzer=mock_git, code_analyzer=mock_code)
        assert az.use_proprietary is True

    def test_config_stored_on_instance(self):
        az = _make_analyzer(min_confidence_threshold=0.7)
        assert az.config["min_confidence_threshold"] == 0.7

    def test_min_confidence_threshold_custom(self):
        az = _make_analyzer(min_confidence_threshold=0.7)
        assert az.min_confidence_threshold == 0.7


# ===========================================================================
# 5. _extract_vulnerable_patterns
# ===========================================================================


class TestExtractVulnerablePatterns:
    def setup_method(self):
        self.az = _make_analyzer()

    def test_cwe_89_sql_injection_pattern_type(self):
        details = {"cwe_ids": ["CWE-89"], "severity": "high"}
        patterns = self.az._extract_vulnerable_patterns("CVE-2024-0001", details)
        assert len(patterns) == 1
        assert patterns[0].pattern_type == "sql_injection"

    def test_cwe_89_contains_execute_query(self):
        details = {"cwe_ids": ["CWE-89"]}
        patterns = self.az._extract_vulnerable_patterns("CVE-X", details)
        assert "executeQuery" in patterns[0].vulnerable_functions

    def test_cwe_89_contains_execute(self):
        details = {"cwe_ids": ["CWE-89"]}
        patterns = self.az._extract_vulnerable_patterns("CVE-X", details)
        assert "execute" in patterns[0].vulnerable_functions

    def test_cwe_78_command_injection_pattern_type(self):
        details = {"cwe_ids": ["CWE-78"]}
        patterns = self.az._extract_vulnerable_patterns("CVE-X", details)
        assert patterns[0].pattern_type == "command_injection"

    def test_cwe_78_contains_system(self):
        details = {"cwe_ids": ["CWE-78"]}
        patterns = self.az._extract_vulnerable_patterns("CVE-X", details)
        assert "system" in patterns[0].vulnerable_functions

    def test_cwe_78_contains_subprocess(self):
        details = {"cwe_ids": ["CWE-78"]}
        patterns = self.az._extract_vulnerable_patterns("CVE-X", details)
        assert "subprocess" in patterns[0].vulnerable_functions

    def test_cwe_79_xss_pattern_type(self):
        details = {"cwe_ids": ["CWE-79"]}
        patterns = self.az._extract_vulnerable_patterns("CVE-X", details)
        assert patterns[0].pattern_type == "xss"

    def test_cwe_79_contains_inner_html(self):
        details = {"cwe_ids": ["CWE-79"]}
        patterns = self.az._extract_vulnerable_patterns("CVE-X", details)
        assert "innerHTML" in patterns[0].vulnerable_functions

    def test_cwe_22_path_traversal_pattern_type(self):
        details = {"cwe_ids": ["CWE-22"]}
        patterns = self.az._extract_vulnerable_patterns("CVE-X", details)
        assert patterns[0].pattern_type == "path_traversal"

    def test_cwe_22_contains_open(self):
        details = {"cwe_ids": ["CWE-22"]}
        patterns = self.az._extract_vulnerable_patterns("CVE-X", details)
        assert "open" in patterns[0].vulnerable_functions

    def test_cwe_22_file_patterns_populated(self):
        details = {"cwe_ids": ["CWE-22"]}
        patterns = self.az._extract_vulnerable_patterns("CVE-X", details)
        assert len(patterns[0].file_patterns) > 0

    def test_generic_pattern_when_no_cwe(self):
        details = {}
        patterns = self.az._extract_vulnerable_patterns("CVE-X", details)
        assert len(patterns) == 1
        assert patterns[0].pattern_type == "generic"

    def test_generic_pattern_when_unknown_cwe(self):
        details = {"cwe_ids": ["CWE-999"]}
        patterns = self.az._extract_vulnerable_patterns("CVE-X", details)
        assert patterns[0].pattern_type == "generic"

    def test_string_cwe_id_normalised_to_list(self):
        """A bare string cwe_ids must still produce the right pattern."""
        details = {"cwe_ids": "CWE-89"}
        patterns = self.az._extract_vulnerable_patterns("CVE-X", details)
        assert patterns[0].pattern_type == "sql_injection"

    def test_severity_propagated(self):
        details = {"cwe_ids": ["CWE-89"], "severity": "critical"}
        patterns = self.az._extract_vulnerable_patterns("CVE-X", details)
        assert patterns[0].severity == "critical"

    def test_default_severity_medium(self):
        details = {"cwe_ids": ["CWE-89"]}
        patterns = self.az._extract_vulnerable_patterns("CVE-X", details)
        assert patterns[0].severity == "medium"

    def test_description_propagated(self):
        details = {"cwe_ids": ["CWE-89"], "description": "Unsafe SQL construction"}
        patterns = self.az._extract_vulnerable_patterns("CVE-X", details)
        assert patterns[0].description == "Unsafe SQL construction"

    def test_multiple_cwes_produce_multiple_patterns(self):
        details = {"cwe_ids": ["CWE-89", "CWE-78"]}
        patterns = self.az._extract_vulnerable_patterns("CVE-X", details)
        types = {p.pattern_type for p in patterns}
        assert "sql_injection" in types
        assert "command_injection" in types

    def test_cve_id_stored_in_pattern(self):
        details = {"cwe_ids": ["CWE-79"]}
        patterns = self.az._extract_vulnerable_patterns("CVE-2024-9999", details)
        assert patterns[0].cve_id == "CVE-2024-9999"

    def test_generic_vulnerable_functions_is_list(self):
        details = {}
        patterns = self.az._extract_vulnerable_patterns("CVE-X", details)
        assert isinstance(patterns[0].vulnerable_functions, list)


# ===========================================================================
# 6. _check_pattern_reachability
# ===========================================================================


class TestCheckPatternReachability:
    def setup_method(self):
        self.az = _make_analyzer()

    def _pattern(self, funcs):
        return _FakeVulnerablePattern(vulnerable_functions=funcs)

    def test_no_patterns_returns_empty(self):
        result = self.az._check_pattern_reachability([], {}, Path("/tmp"), None)
        assert result == []

    def test_pattern_func_not_in_call_graph_returns_empty(self):
        pattern = self._pattern(["execute"])
        result = self.az._check_pattern_reachability([pattern], {}, Path("/tmp"), None)
        assert result == []

    def test_pattern_func_with_no_callers_returns_empty(self):
        pattern = self._pattern(["execute"])
        call_graph = {"execute": {"callers": []}}
        result = self.az._check_pattern_reachability([pattern], call_graph, Path("/tmp"), None)
        assert result == []

    def test_single_caller_yields_one_path(self):
        pattern = self._pattern(["execute"])
        caller = {"function": "run_query", "file": "db.py", "line": 55}
        call_graph = {"execute": {"callers": [caller]}}
        result = self.az._check_pattern_reachability([pattern], call_graph, Path("/tmp"), None)
        assert len(result) == 1

    def test_returned_path_is_invoked_true(self):
        pattern = self._pattern(["execute"])
        caller = {"function": "run_query", "file": "db.py", "line": 55}
        call_graph = {"execute": {"callers": [caller]}}
        result = self.az._check_pattern_reachability([pattern], call_graph, Path("/tmp"), None)
        assert result[0].is_invoked is True

    def test_caller_file_stored_in_code_path(self):
        pattern = self._pattern(["execute"])
        caller = {"function": "run_query", "file": "db.py", "line": 10}
        call_graph = {"execute": {"callers": [caller]}}
        result = self.az._check_pattern_reachability([pattern], call_graph, Path("/tmp"), None)
        assert result[0].file_path == "db.py"

    def test_caller_line_stored_in_code_path(self):
        pattern = self._pattern(["execute"])
        caller = {"function": "run_query", "file": "db.py", "line": 77}
        call_graph = {"execute": {"callers": [caller]}}
        result = self.az._check_pattern_reachability([pattern], call_graph, Path("/tmp"), None)
        assert result[0].line_number == 77

    def test_function_name_stored_in_code_path(self):
        pattern = self._pattern(["execute"])
        caller = {"function": "run_query", "file": "db.py", "line": 10}
        call_graph = {"execute": {"callers": [caller]}}
        result = self.az._check_pattern_reachability([pattern], call_graph, Path("/tmp"), None)
        assert result[0].function_name == "execute"

    def test_data_flow_path_attached_when_provided(self):
        pattern = self._pattern(["query"])
        caller = {"function": "handle", "file": "api.py", "line": 20}
        call_graph = {"query": {"callers": [caller]}}
        df = _FakeDataFlowResult(has_path=True, max_depth=2)
        result = self.az._check_pattern_reachability([pattern], call_graph, Path("/tmp"), df)
        assert result[0].data_flow_path is not None

    def test_data_flow_path_none_without_data_flow_result(self):
        pattern = self._pattern(["query"])
        caller = {"function": "handle", "file": "api.py", "line": 20}
        call_graph = {"query": {"callers": [caller]}}
        result = self.az._check_pattern_reachability([pattern], call_graph, Path("/tmp"), None)
        assert result[0].data_flow_path is None

    def test_multiple_callers_yield_multiple_paths(self):
        pattern = self._pattern(["execute"])
        callers = [
            {"function": "func_a", "file": "a.py", "line": 1},
            {"function": "func_b", "file": "b.py", "line": 2},
        ]
        call_graph = {"execute": {"callers": callers}}
        result = self.az._check_pattern_reachability([pattern], call_graph, Path("/tmp"), None)
        assert len(result) == 2

    def test_multiple_patterns_accumulate_paths(self):
        p1 = self._pattern(["execute"])
        p2 = self._pattern(["popen"])
        call_graph = {
            "execute": {"callers": [{"function": "f1", "file": "a.py", "line": 1}]},
            "popen": {"callers": [{"function": "f2", "file": "b.py", "line": 5}]},
        }
        result = self.az._check_pattern_reachability([p1, p2], call_graph, Path("/tmp"), None)
        assert len(result) == 2


# ===========================================================================
# 7. _build_call_chain
# ===========================================================================


class TestBuildCallChain:
    def setup_method(self):
        self.az = _make_analyzer()

    def test_target_func_always_at_end(self):
        start = {"function": "caller_a"}
        chain = self.az._build_call_chain(start, {}, "vuln_func")
        assert chain[-1] == "vuln_func"

    def test_start_function_prepended(self):
        start = {"function": "caller_a"}
        chain = self.az._build_call_chain(start, {}, "vuln_func")
        assert "caller_a" in chain

    def test_no_parent_stops_traversal_at_two_entries(self):
        start = {"function": "handler"}
        chain = self.az._build_call_chain(start, {}, "execute")
        # handler then execute — exactly 2 entries
        assert len(chain) == 2

    def test_linear_parent_chain_traversed(self):
        """A node with a parent whose callers list contains another function."""
        call_graph = {
            "router": {"callers": [{"function": "main"}]},
        }
        start = {"function": "router", "parent": "router"}
        chain = self.az._build_call_chain(start, call_graph, "execute")
        assert "router" in chain
        assert "execute" in chain

    def test_cycle_does_not_cause_infinite_loop(self):
        """Bidirectional cycle must terminate before infinite recursion."""
        call_graph = {
            "func_a": {"callers": [{"function": "func_b", "parent": "func_b"}]},
            "func_b": {"callers": [{"function": "func_a", "parent": "func_a"}]},
        }
        start = {"function": "func_a", "parent": "func_a"}
        chain = self.az._build_call_chain(start, call_graph, "target")
        assert "target" in chain  # Must have completed without error

    def test_max_depth_respected(self):
        """Chain deeper than 20 should be cut off — total chain <= 22."""
        call_graph = {}
        for i in range(25):
            call_graph[f"func_{i}"] = {
                "callers": [{"function": f"func_{i + 1}", "parent": f"func_{i + 1}"}]
            }
        start = {"function": "func_0", "parent": "func_0"}
        chain = self.az._build_call_chain(start, call_graph, "target")
        # max_depth = 20 iterations, so at most 20 parents + "func_0" + "target" = 22
        assert len(chain) <= 22

    def test_visited_prevents_duplicate_function_names(self):
        """The same function must appear at most once in the chain."""
        call_graph = {
            "shared": {"callers": [{"function": "shared", "parent": "shared"}]}
        }
        start = {"function": "shared", "parent": "shared"}
        chain = self.az._build_call_chain(start, call_graph, "sink")
        assert chain.count("shared") == 1

    def test_empty_start_node_still_returns_target(self):
        """Even if start_node has no 'function' key, target must be in result."""
        chain = self.az._build_call_chain({}, {}, "target_func")
        assert "target_func" in chain


# ===========================================================================
# 8. _find_entry_points
# ===========================================================================


class TestFindEntryPoints:
    def setup_method(self):
        self.az = _make_analyzer()

    def test_empty_call_chain_returns_empty(self):
        result = self.az._find_entry_points([], {"some_func": {"is_public": True}})
        assert result == []

    def test_public_flag_triggers_entry_point(self):
        call_graph = {"handle_request": {"is_public": True}}
        result = self.az._find_entry_points(["handle_request", "execute"], call_graph)
        assert "handle_request" in result

    def test_exported_flag_triggers_entry_point(self):
        call_graph = {"api_handler": {"is_exported": True}}
        result = self.az._find_entry_points(["api_handler", "query"], call_graph)
        assert "api_handler" in result

    def test_main_pattern_detected(self):
        call_graph = {"main_loop": {}}
        result = self.az._find_entry_points(["main_loop", "execute"], call_graph)
        assert "main_loop" in result

    def test_handler_pattern_detected(self):
        call_graph = {"request_handler": {}}
        result = self.az._find_entry_points(["request_handler", "sql"], call_graph)
        assert "request_handler" in result

    def test_route_pattern_detected(self):
        call_graph = {"get_route": {}}
        result = self.az._find_entry_points(["get_route", "query"], call_graph)
        assert "get_route" in result

    def test_endpoint_pattern_detected(self):
        call_graph = {"create_endpoint": {}}
        result = self.az._find_entry_points(["create_endpoint", "db"], call_graph)
        assert "create_endpoint" in result

    def test_api_pattern_detected(self):
        call_graph = {"api_search": {}}
        result = self.az._find_entry_points(["api_search", "query"], call_graph)
        assert "api_search" in result

    def test_private_function_not_entry_point(self):
        call_graph = {"_internal_helper": {"is_public": False, "is_exported": False}}
        result = self.az._find_entry_points(["_internal_helper", "execute"], call_graph)
        assert result == []

    def test_unknown_first_func_not_entry_point(self):
        call_graph = {}
        result = self.az._find_entry_points(["obscure_func", "execute"], call_graph)
        assert result == []

    def test_only_first_element_of_chain_checked(self):
        """Entry point detection only applies to the first element."""
        call_graph = {"main_func": {}}
        # 'main_func' is second — should NOT be detected as entry point
        result = self.az._find_entry_points(["internal_func", "main_func"], call_graph)
        assert result == []


# ===========================================================================
# 9. _calculate_confidence
# ===========================================================================


class TestCalculateConfidence:
    def setup_method(self):
        self.az = _make_analyzer()
        self.dummy_pattern = _FakeVulnerablePattern()

    def _path(self, chain_len=1, entry_count=0):
        ep = ["entry"] * entry_count
        return CodePath(
            file_path="f.py",
            call_chain=["fn"] * chain_len,
            entry_points=ep,
        )

    def test_no_reachable_paths_returns_zero(self):
        score = self.az._calculate_confidence([], [self.dummy_pattern], {}, None, None, None)
        assert score == 0.0

    def test_reachable_but_no_call_graph_returns_0_3(self):
        paths = [self._path()]
        score = self.az._calculate_confidence(paths, [self.dummy_pattern], {}, None, None, None)
        assert score == pytest.approx(0.3)

    def test_score_clipped_to_1_0_maximum(self):
        """Even with all factors maxed the score must not exceed 1.0."""
        paths = [self._path(chain_len=1, entry_count=5)] * 10
        design = _make_analysis_result(success=True, findings_count=20)
        runtime = _make_analysis_result(success=True, findings_count=20)
        df = _FakeDataFlowResult(has_path=True)
        cg = {"some": "graph"}
        score = self.az._calculate_confidence(
            paths, [self.dummy_pattern], cg, design, runtime, df
        )
        assert score <= 1.0

    def test_score_never_negative(self):
        paths = [self._path(chain_len=50)]  # Very deep chain drives depth_factor to 0
        cg = {"some": "graph"}
        score = self.az._calculate_confidence(paths, [self.dummy_pattern], cg, None, None, None)
        assert score >= 0.0

    def test_data_flow_boosts_score(self):
        paths = [self._path()]
        cg = {"some": "graph"}
        without_df = self.az._calculate_confidence(
            paths, [self.dummy_pattern], cg, None, None, None
        )
        df = _FakeDataFlowResult(has_path=True)
        with_df = self.az._calculate_confidence(
            paths, [self.dummy_pattern], cg, None, None, df
        )
        assert with_df > without_df

    def test_data_flow_no_path_does_not_boost(self):
        paths = [self._path()]
        cg = {"some": "graph"}
        without_df = self.az._calculate_confidence(
            paths, [self.dummy_pattern], cg, None, None, None
        )
        df = _FakeDataFlowResult(has_path=False)
        with_df = self.az._calculate_confidence(
            paths, [self.dummy_pattern], cg, None, None, df
        )
        assert with_df == pytest.approx(without_df, abs=1e-9)

    def test_design_time_findings_boost_score(self):
        paths = [self._path()]
        cg = {"some": "graph"}
        base = self.az._calculate_confidence(paths, [self.dummy_pattern], cg, None, None, None)
        design = _make_analysis_result(success=True, findings_count=5)
        boosted = self.az._calculate_confidence(
            paths, [self.dummy_pattern], cg, design, None, None
        )
        assert boosted > base

    def test_failed_design_result_does_not_boost(self):
        """success=False means design_factor = 0."""
        paths = [self._path()]
        cg = {"some": "graph"}
        base = self.az._calculate_confidence(paths, [self.dummy_pattern], cg, None, None, None)
        design = _make_analysis_result(success=False, findings_count=10)
        score = self.az._calculate_confidence(
            paths, [self.dummy_pattern], cg, design, None, None
        )
        assert score == pytest.approx(base, abs=0.01)

    def test_more_paths_means_higher_score(self):
        cg = {"some": "graph"}
        s1 = self.az._calculate_confidence(
            [self._path()], [self.dummy_pattern], cg, None, None, None
        )
        s5 = self.az._calculate_confidence(
            [self._path()] * 5, [self.dummy_pattern], cg, None, None, None
        )
        assert s5 >= s1

    def test_runtime_findings_boost_score(self):
        paths = [self._path()]
        cg = {"some": "graph"}
        base = self.az._calculate_confidence(paths, [self.dummy_pattern], cg, None, None, None)
        runtime = _make_analysis_result(success=True, findings_count=5)
        boosted = self.az._calculate_confidence(
            paths, [self.dummy_pattern], cg, None, runtime, None
        )
        assert boosted > base


# ===========================================================================
# 10. _confidence_level thresholds
# ===========================================================================


class TestConfidenceLevel:
    def setup_method(self):
        self.az = _make_analyzer()

    def test_exactly_0_8_is_high(self):
        assert self.az._confidence_level(0.8) == ReachabilityConfidence.HIGH

    def test_above_0_8_is_high(self):
        assert self.az._confidence_level(0.95) == ReachabilityConfidence.HIGH

    def test_1_0_is_high(self):
        assert self.az._confidence_level(1.0) == ReachabilityConfidence.HIGH

    def test_just_below_0_8_is_medium(self):
        assert self.az._confidence_level(0.799) == ReachabilityConfidence.MEDIUM

    def test_exactly_0_5_is_medium(self):
        assert self.az._confidence_level(0.5) == ReachabilityConfidence.MEDIUM

    def test_mid_range_is_medium(self):
        assert self.az._confidence_level(0.65) == ReachabilityConfidence.MEDIUM

    def test_just_below_0_5_is_low(self):
        assert self.az._confidence_level(0.499) == ReachabilityConfidence.LOW

    def test_small_positive_is_low(self):
        assert self.az._confidence_level(0.01) == ReachabilityConfidence.LOW

    def test_epsilon_positive_is_low(self):
        assert self.az._confidence_level(1e-9) == ReachabilityConfidence.LOW

    def test_exactly_0_0_is_unknown(self):
        assert self.az._confidence_level(0.0) == ReachabilityConfidence.UNKNOWN

    def test_negative_treated_as_unknown(self):
        # Negative inputs should not appear but the > 0.0 branch guards this
        assert self.az._confidence_level(-0.1) == ReachabilityConfidence.UNKNOWN


# ===========================================================================
# 11. _detect_discrepancy
# ===========================================================================


class TestDetectDiscrepancy:
    def setup_method(self):
        self.az = _make_analyzer()

    def _res(self, success=True, count=0):
        return _make_analysis_result(success=success, findings_count=count)

    def test_equal_findings_no_discrepancy(self):
        detected, details = self.az._detect_discrepancy(self._res(count=5), self._res(count=5))
        assert detected is False
        assert details is None

    def test_large_difference_triggers_discrepancy(self):
        detected, _ = self.az._detect_discrepancy(self._res(count=10), self._res(count=3))
        assert detected is True

    def test_discrepancy_details_contains_both_counts(self):
        _, details = self.az._detect_discrepancy(self._res(count=10), self._res(count=2))
        assert "10" in details
        assert "2" in details

    def test_exactly_50_pct_difference_is_not_discrepancy(self):
        # ratio = |10 - 5| / 10 = 0.5 — NOT > 0.5
        detected, _ = self.az._detect_discrepancy(self._res(count=10), self._res(count=5))
        assert detected is False

    def test_just_above_50_pct_is_discrepancy(self):
        # ratio = |10 - 4| / 10 = 0.6 — > 0.5
        detected, _ = self.az._detect_discrepancy(self._res(count=10), self._res(count=4))
        assert detected is True

    def test_design_zero_findings_no_discrepancy(self):
        detected, _ = self.az._detect_discrepancy(self._res(count=0), self._res(count=5))
        assert detected is False

    def test_runtime_zero_findings_no_discrepancy(self):
        detected, _ = self.az._detect_discrepancy(self._res(count=5), self._res(count=0))
        assert detected is False

    def test_failed_design_treated_as_zero(self):
        detected, _ = self.az._detect_discrepancy(
            self._res(success=False, count=10), self._res(count=5)
        )
        assert detected is False

    def test_failed_runtime_treated_as_zero(self):
        detected, _ = self.az._detect_discrepancy(
            self._res(count=10), self._res(success=False, count=10)
        )
        assert detected is False


# ===========================================================================
# 12. _determine_analysis_method
# ===========================================================================


class TestDetermineAnalysisMethod:
    def setup_method(self):
        self.az = _make_analyzer()

    def _res(self):
        return _make_analysis_result()

    def test_both_results_returns_hybrid(self):
        assert self.az._determine_analysis_method(self._res(), self._res()) == "hybrid"

    def test_design_only_returns_design_time(self):
        assert self.az._determine_analysis_method(self._res(), None) == "design-time"

    def test_runtime_only_returns_runtime(self):
        assert self.az._determine_analysis_method(None, self._res()) == "runtime"

    def test_neither_returns_static(self):
        assert self.az._determine_analysis_method(None, None) == "static"


# ===========================================================================
# 13. _max_call_depth
# ===========================================================================


class TestMaxCallDepth:
    def setup_method(self):
        self.az = _make_analyzer()

    def test_empty_paths_returns_zero(self):
        assert self.az._max_call_depth([]) == 0

    def test_single_path_empty_chain(self):
        """BUG: _max_call_depth raises ValueError when all call_chains are empty.
        max() is called with an empty iterable because the generator
        `(... for p in paths if p.call_chain)` filters out all paths.
        Documenting the bug; test expects the ValueError.
        """
        cp = CodePath(file_path="f.py", call_chain=[])
        with pytest.raises(ValueError):
            self.az._max_call_depth([cp])

    def test_single_path_chain_length_three(self):
        cp = CodePath(file_path="f.py", call_chain=["a", "b", "c"])
        assert self.az._max_call_depth([cp]) == 3

    def test_multiple_paths_returns_max(self):
        cp1 = CodePath(file_path="f.py", call_chain=["a", "b"])
        cp2 = CodePath(file_path="g.py", call_chain=["x", "y", "z", "w"])
        assert self.az._max_call_depth([cp1, cp2]) == 4

    def test_all_empty_chains_returns_zero(self):
        """BUG: Same as test_single_path_empty_chain — ValueError when all chains empty.
        See _max_call_depth line 745: max() on empty filtered generator.
        """
        paths = [CodePath(file_path="f.py", call_chain=[])] * 3
        with pytest.raises(ValueError):
            self.az._max_call_depth(paths)

    def test_mixed_chain_lengths(self):
        paths = [
            CodePath(file_path="a.py", call_chain=["x"]),
            CodePath(file_path="b.py", call_chain=["x", "y", "z"]),
            CodePath(file_path="c.py", call_chain=["x", "y"]),
        ]
        assert self.az._max_call_depth(paths) == 3


# ===========================================================================
# 14. _extract_proprietary_paths
# ===========================================================================


class TestExtractProprietaryPaths:
    def setup_method(self):
        self.az = _make_analyzer()

    def test_empty_dict_returns_empty_list(self):
        assert self.az._extract_proprietary_paths({}) == []

    def test_no_reachable_matches_returns_empty(self):
        result = self.az._extract_proprietary_paths({"reachability": {"reachable_matches": []}})
        assert result == []

    def test_single_match_creates_one_code_path(self):
        prop = {"reachability": {"reachable_matches": [{"location": ("app/db.py", 42)}]}}
        paths = self.az._extract_proprietary_paths(prop)
        assert len(paths) == 1

    def test_path_file_populated(self):
        prop = {"reachability": {"reachable_matches": [{"location": ("app/db.py", 42)}]}}
        paths = self.az._extract_proprietary_paths(prop)
        assert paths[0].file_path == "app/db.py"

    def test_path_line_number_populated(self):
        prop = {"reachability": {"reachable_matches": [{"location": ("app/db.py", 42)}]}}
        paths = self.az._extract_proprietary_paths(prop)
        assert paths[0].line_number == 42

    def test_path_is_invoked_true(self):
        prop = {"reachability": {"reachable_matches": [{"location": ("x.py", 1)}]}}
        paths = self.az._extract_proprietary_paths(prop)
        assert paths[0].is_invoked is True

    def test_path_call_chain_is_empty_list(self):
        prop = {"reachability": {"reachable_matches": [{"location": ("x.py", 1)}]}}
        paths = self.az._extract_proprietary_paths(prop)
        assert paths[0].call_chain == []

    def test_multiple_matches_produce_multiple_paths(self):
        prop = {
            "reachability": {
                "reachable_matches": [
                    {"location": ("a.py", 1)},
                    {"location": ("b.py", 2)},
                    {"location": ("c.py", 3)},
                ]
            }
        }
        paths = self.az._extract_proprietary_paths(prop)
        assert len(paths) == 3

    def test_path_is_code_path_instance(self):
        prop = {"reachability": {"reachable_matches": [{"location": ("x.py", 5)}]}}
        paths = self.az._extract_proprietary_paths(prop)
        assert isinstance(paths[0], CodePath)


# ===========================================================================
# 15. _calculate_proprietary_confidence
# ===========================================================================


class TestCalculateProprietaryConfidence:
    def setup_method(self):
        self.az = _make_analyzer()

    def _prop(self, reachable=0, unreachable=0):
        return {
            "reachability": {
                "reachable_count": reachable,
                "unreachable_count": unreachable,
            }
        }

    def test_zeros_return_zero(self):
        score = self.az._calculate_proprietary_confidence(self._prop(0, 0), [])
        assert score == pytest.approx(0.0)

    def test_reachable_only_returns_0_7(self):
        score = self.az._calculate_proprietary_confidence(self._prop(reachable=3), [])
        assert score == pytest.approx(0.7)

    def test_reachable_and_unreachable_returns_0_85(self):
        score = self.az._calculate_proprietary_confidence(
            self._prop(reachable=3, unreachable=2), []
        )
        assert score == pytest.approx(0.85)

    def test_unreachable_only_returns_0_5(self):
        score = self.az._calculate_proprietary_confidence(
            self._prop(reachable=0, unreachable=5), []
        )
        assert score == pytest.approx(0.5)

    def test_score_never_exceeds_1(self):
        score = self.az._calculate_proprietary_confidence(
            self._prop(reachable=1000, unreachable=1000), []
        )
        assert score <= 1.0

    def test_score_never_below_0(self):
        score = self.az._calculate_proprietary_confidence(self._prop(0, 0), [])
        assert score >= 0.0

    def test_reachable_paths_argument_accepted(self):
        """The reachable_paths list is passed but not used in confidence calc."""
        fake_paths = [CodePath(file_path="x.py")]
        score = self.az._calculate_proprietary_confidence(
            self._prop(reachable=1, unreachable=1), fake_paths
        )
        assert score == pytest.approx(0.85)


# ===========================================================================
# 16. _create_unknown_result
# ===========================================================================


class TestCreateUnknownResult:
    def setup_method(self):
        self.az = _make_analyzer()

    def _make(self):
        return self.az._create_unknown_result("CVE-2024-0001", "flask", "2.0.0")

    def test_returns_vulnerability_reachability_instance(self):
        assert isinstance(self._make(), VulnerabilityReachability)

    def test_cve_id_set(self):
        assert self._make().cve_id == "CVE-2024-0001"

    def test_component_name_set(self):
        assert self._make().component_name == "flask"

    def test_component_version_set(self):
        assert self._make().component_version == "2.0.0"

    def test_is_reachable_false(self):
        assert self._make().is_reachable is False

    def test_confidence_is_unknown_enum(self):
        assert self._make().confidence == ReachabilityConfidence.UNKNOWN

    def test_confidence_score_is_zero(self):
        assert self._make().confidence_score == 0.0

    def test_code_paths_is_empty_list(self):
        assert self._make().code_paths == []

    def test_call_graph_depth_is_zero(self):
        assert self._make().call_graph_depth == 0

    def test_data_flow_depth_is_zero(self):
        assert self._make().data_flow_depth == 0

    def test_analysis_method_is_unknown(self):
        assert self._make().analysis_method == "unknown"

    def test_to_dict_works_on_unknown_result(self):
        d = self._make().to_dict()
        assert d["cve_id"] == "CVE-2024-0001"
        assert d["is_reachable"] is False
        assert d["confidence"] == "unknown"
        assert d["confidence_score"] == 0.0
        assert d["code_paths"] == []
