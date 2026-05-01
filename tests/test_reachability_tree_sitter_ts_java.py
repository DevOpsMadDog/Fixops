"""Tests for tree-sitter TS/Java parsers in function_reachability_engine.

Targets the parse_typescript_repo + parse_java_repo paths added in Wave 3F.
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

import pytest


def _engine(tmp_path):
    from core.function_reachability_engine import FunctionReachabilityEngine

    db = tmp_path / "fr.db"
    cache = tmp_path / "fr_cache.db"
    return FunctionReachabilityEngine(db_path=str(db), cache_db_path=str(cache))


def _has_ts() -> bool:
    try:
        import tree_sitter  # noqa: F401
        import tree_sitter_typescript  # noqa: F401

        return True
    except ImportError:
        return False


def _has_java() -> bool:
    try:
        import tree_sitter  # noqa: F401
        import tree_sitter_java  # noqa: F401

        return True
    except ImportError:
        return False


@pytest.mark.skipif(not _has_ts(), reason="tree-sitter-typescript not installed")
def test_parse_typescript_simple(tmp_path):
    """Two TS functions, one calls the other; nodes + edge captured."""
    eng = _engine(tmp_path)

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.ts").write_text(
        textwrap.dedent(
            """\
            function helper() { return 1; }
            function main() { return helper(); }
            """
        )
    )

    inserted = eng.parse_typescript_repo("org-1", "repo-sha-1", str(repo))
    assert inserted >= 2, f"expected >=2 nodes, got {inserted}"

    cg = eng.list_callgraph("org-1", "repo-sha-1")
    fqns = {n["function_fqn"] for n in cg["nodes"]}
    assert any(f.endswith(".helper") for f in fqns)
    assert any(f.endswith(".main") for f in fqns)
    # At least one edge from main -> helper resolved
    assert cg["edge_count"] >= 1


@pytest.mark.skipif(not _has_ts(), reason="tree-sitter-typescript not installed")
def test_parse_typescript_handles_arrow_functions(tmp_path):
    """`const f = () => {}` arrow defs are captured under the variable name."""
    eng = _engine(tmp_path)

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "arrow.ts").write_text(
        textwrap.dedent(
            """\
            const greet = () => { return 'hi'; };
            const callIt = () => greet();
            """
        )
    )

    inserted = eng.parse_typescript_repo("org-1", "repo-sha-2", str(repo))
    assert inserted >= 2

    cg = eng.list_callgraph("org-1", "repo-sha-2")
    fqns = {n["function_fqn"] for n in cg["nodes"]}
    # Arrow attached to a variable_declarator should resolve to "greet"/"callIt"
    assert any(f.endswith(".greet") for f in fqns), f"missing greet in {fqns}"
    assert any(f.endswith(".callIt") for f in fqns), f"missing callIt in {fqns}"


@pytest.mark.skipif(not _has_ts(), reason="tree-sitter-typescript not installed")
def test_parse_typescript_skips_node_modules(tmp_path):
    """Files under node_modules/ MUST NOT be parsed."""
    eng = _engine(tmp_path)

    repo = tmp_path / "repo"
    (repo / "node_modules" / "lib").mkdir(parents=True)
    (repo / "node_modules" / "lib" / "vendor.ts").write_text(
        "function vendorFn() { return 0; }"
    )
    (repo / "src.ts").write_text("function realFn() { return 1; }")

    eng.parse_typescript_repo("org-1", "repo-sha-3", str(repo))

    cg = eng.list_callgraph("org-1", "repo-sha-3")
    fqns = {n["function_fqn"] for n in cg["nodes"]}
    assert not any("vendorFn" in f for f in fqns), (
        f"node_modules leaked into callgraph: {fqns}"
    )
    assert any(f.endswith(".realFn") for f in fqns)


@pytest.mark.skipif(not _has_java(), reason="tree-sitter-java not installed")
def test_parse_java_simple(tmp_path):
    """Java class with two methods + one invocation -> node + edge."""
    eng = _engine(tmp_path)

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "App.java").write_text(
        textwrap.dedent(
            """\
            public class App {
                public int helper() { return 1; }
                public int main() { return helper(); }
            }
            """
        )
    )

    inserted = eng.parse_java_repo("org-j", "repo-sha-j1", str(repo))
    assert inserted >= 2, f"expected >=2 nodes, got {inserted}"

    cg = eng.list_callgraph("org-j", "repo-sha-j1")
    fqns = {n["function_fqn"] for n in cg["nodes"]}
    assert any("App.helper" in f for f in fqns), fqns
    assert any("App.main" in f for f in fqns), fqns
    assert cg["edge_count"] >= 1


def test_parse_typescript_no_treesitter_raises(tmp_path, monkeypatch):
    """When tree-sitter-typescript missing, raise NotImplementedError with hint."""
    eng = _engine(tmp_path)

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "x.ts").write_text("function f(){}")

    real_import = __builtins__["__import__"] if isinstance(__builtins__, dict) else __builtins__.__import__

    def _blocked_import(name, *a, **kw):
        if name == "tree_sitter_typescript":
            raise ImportError("blocked for test")
        return real_import(name, *a, **kw)

    # Drop any cached module so the import inside parse_typescript_repo re-runs.
    monkeypatch.delitem(sys.modules, "tree_sitter_typescript", raising=False)
    monkeypatch.setattr("builtins.__import__", _blocked_import)

    with pytest.raises(NotImplementedError) as excinfo:
        eng.parse_typescript_repo("org-x", "repo-sha-x", str(repo))
    assert "tree-sitter-typescript" in str(excinfo.value)
    assert "pip install" in str(excinfo.value)
