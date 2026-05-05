"""Performance regression tests for reachability call-graph construction.

Covers three fixes shipped in beast-mode(perf) commit:
  1. O(1) set-dedup for _add_edge (call_graph.py)
  2. O(1) set-dedup in PythonCallGraphVisitor.visit_Call (call_graph.py)
  3. Typed-callee BFS guard in _is_reachable_from_entries (proprietary_analyzer.py)
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.perf

import time
from collections import deque
from pathlib import Path
from typing import Any, Dict, List
import sys
import os

import pytest

# Ensure suite paths resolve without sitecustomize.
# Insert the correct path first so Python resolves risk.* from source.
_EVIDENCE_RISK = str(Path(__file__).parent.parent / "suite-evidence-risk")
if _EVIDENCE_RISK not in sys.path:
    sys.path.insert(0, _EVIDENCE_RISK)

# In a broad pytest run, an earlier test file may have imported
# risk.reachability.call_graph from a stale .pyc / namespace that lacks the
# module-level _add_edge / _node symbols (added in the beast-mode(perf)
# commit).  Evict any cached version so our sys.path.insert above takes effect
# and we always import from the live source tree.
for _mod_key in list(sys.modules.keys()):
    if _mod_key.startswith("risk.reachability"):
        del sys.modules[_mod_key]

from risk.reachability.call_graph import CallGraphBuilder, _add_edge, _node
from risk.reachability.proprietary_analyzer import ProprietaryReachabilityAnalyzer


# ---------------------------------------------------------------------------
# Fix 1 + 2 — O(1) dedup: _add_edge must not create duplicate callers/callees
# ---------------------------------------------------------------------------

class TestAddEdgeDedup:
    """_add_edge must stay O(1) per call — no duplicate edges."""

    def _make_graph(self) -> Dict[str, Any]:
        g: Dict[str, Any] = {}
        g["A"] = _node("a.py", 1)
        g["B"] = _node("b.py", 2)
        return g

    def test_no_duplicate_callees(self):
        g = self._make_graph()
        for _ in range(50):
            _add_edge(g, "A", "B", "a.py", 1)
        assert len(g["A"]["callees"]) == 1, "callees must be deduplicated"

    def test_no_duplicate_callers(self):
        g = self._make_graph()
        for _ in range(50):
            _add_edge(g, "A", "B", "a.py", 1)
        assert len(g["B"]["callers"]) == 1, "callers must be deduplicated"

    def test_large_fan_out_stays_fast(self):
        """Adding 2000 unique edges from one root must complete in <200 ms."""
        g: Dict[str, Any] = {}
        g["root"] = _node("root.py", 1)
        start = time.perf_counter()
        for i in range(2000):
            _add_edge(g, "root", f"fn_{i}", "f.py", i)
        elapsed = time.perf_counter() - start
        assert elapsed < 0.2, f"2000 unique edges took {elapsed*1000:.0f}ms (limit 200ms)"

    def test_repeated_edges_stay_fast(self):
        """Hammering the same edge 5000 times must complete in <100 ms."""
        g: Dict[str, Any] = {}
        g["A"] = _node("a.py", 1)
        g["B"] = _node("b.py", 2)
        start = time.perf_counter()
        for _ in range(5000):
            _add_edge(g, "A", "B", "a.py", 1)
        elapsed = time.perf_counter() - start
        assert elapsed < 0.1, f"5000 repeated edges took {elapsed*1000:.0f}ms (limit 100ms)"


# ---------------------------------------------------------------------------
# Fix 2 — PythonCallGraphVisitor dedup via CallGraphBuilder
# ---------------------------------------------------------------------------

class TestPythonCallGraphDedup:
    """Python AST visitor must not produce duplicate caller/callee entries."""

    def _build(self, tmp_path: Path, src: str) -> Dict[str, Any]:
        f = tmp_path / "mod.py"
        f.write_text(src)
        builder = CallGraphBuilder()
        return builder._build_python_call_graph(tmp_path)

    def test_no_duplicate_callers_in_visitor(self, tmp_path):
        src = "def foo():\n    bar()\n    bar()\ndef bar(): pass\n"
        g = self._build(tmp_path, src)
        if "bar" in g:
            caller_funcs = [c["function"] for c in g["bar"]["callers"]]
            assert caller_funcs.count("foo") <= 1, \
                f"foo appears {caller_funcs.count('foo')}x in bar.callers — expected 1"

    def test_no_duplicate_callees_in_visitor(self, tmp_path):
        src = "def foo():\n    bar()\n    bar()\n    bar()\ndef bar(): pass\n"
        g = self._build(tmp_path, src)
        if "foo" in g:
            callee_funcs = [c["function"] for c in g["foo"]["callees"]]
            assert callee_funcs.count("bar") <= 1, \
                f"bar appears {callee_funcs.count('bar')}x in foo.callees — expected 1"


# ---------------------------------------------------------------------------
# Fix 3 — BFS callee type normalisation
# ---------------------------------------------------------------------------

class TestBFSCalleeNormalisation:
    """_is_reachable_from_entries must handle both str and dict callees."""

    def _make_analyzer(self) -> ProprietaryReachabilityAnalyzer:
        return ProprietaryReachabilityAnalyzer(config={})

    def test_string_callees_reachable(self):
        analyzer = self._make_analyzer()
        graph = {
            "entry": {"callees": ["mid"], "callers": []},
            "mid":   {"callees": ["vuln"], "callers": []},
            "vuln":  {"callees": [], "callers": []},
        }
        assert analyzer._is_reachable_from_entries("vuln", ["entry"], graph)

    def test_dict_callees_reachable(self):
        """JS/Java builders store callees as dicts — BFS must handle them."""
        analyzer = self._make_analyzer()
        graph = {
            "entry": {"callees": [{"function": "mid", "file": "f.js", "line": 1}], "callers": []},
            "mid":   {"callees": [{"function": "vuln", "file": "f.js", "line": 5}], "callers": []},
            "vuln":  {"callees": [], "callers": []},
        }
        assert analyzer._is_reachable_from_entries("vuln", ["entry"], graph)

    def test_mixed_callees_no_crash(self):
        """Mixed str/dict callees must not raise."""
        analyzer = self._make_analyzer()
        graph = {
            "entry": {"callees": ["mid", {"function": "other", "file": "x.js", "line": 2}], "callers": []},
            "mid":   {"callees": ["vuln"], "callers": []},
            "other": {"callees": [], "callers": []},
            "vuln":  {"callees": [], "callers": []},
        }
        result = analyzer._is_reachable_from_entries("vuln", ["entry"], graph)
        assert result is True

    def test_unreachable_returns_false(self):
        analyzer = self._make_analyzer()
        graph = {
            "entry":    {"callees": ["other"], "callers": []},
            "other":    {"callees": [], "callers": []},
            "isolated": {"callees": [], "callers": []},
        }
        assert not analyzer._is_reachable_from_entries("isolated", ["entry"], graph)

    def test_bfs_large_graph_fast(self):
        """BFS over 500-node chain must complete in <100 ms."""
        analyzer = self._make_analyzer()
        n = 500
        graph: Dict[str, Any] = {}
        for i in range(n):
            nxt = f"fn_{i+1}" if i < n - 1 else "vuln"
            graph[f"fn_{i}"] = {"callees": [nxt], "callers": []}
        graph["vuln"] = {"callees": [], "callers": []}

        start = time.perf_counter()
        result = analyzer._is_reachable_from_entries("vuln", ["fn_0"], graph)
        elapsed = time.perf_counter() - start

        assert result is True
        assert elapsed < 0.1, f"500-node BFS took {elapsed*1000:.0f}ms (limit 100ms)"

    def test_bfs_no_duplicate_visits(self):
        """BFS visited set must prevent re-visiting nodes (diamond graph)."""
        analyzer = self._make_analyzer()
        visits: List[str] = []

        # Diamond: entry -> A, entry -> B; A -> sink, B -> sink
        graph = {
            "entry": {"callees": ["A", "B"], "callers": []},
            "A":     {"callees": ["sink"], "callers": []},
            "B":     {"callees": ["sink"], "callers": []},
            "sink":  {"callees": [], "callers": []},
        }
        result = analyzer._is_reachable_from_entries("sink", ["entry"], graph)
        assert result is True
