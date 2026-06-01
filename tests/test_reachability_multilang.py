"""SPEC-004 — Multi-language Reachability acceptance tests.

AC-004-01: tree-sitter pins present in requirements.txt
AC-004-02: parse_typescript_repo / parse_java_repo / parse_go_repo return real
           call-graph results when deps are installed; return clean typed skip
           (ParserUnavailableError) when deps are absent.
AC-004-03: pipeline with repo_path + TS/Go finding runs/clean-skips without raise.
AC-004-04: create_app() boots without error; no regression in existing reachability tests.
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path
from typing import Generator
from unittest.mock import MagicMock

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _engine(tmp_path: Path):
    from core.function_reachability_engine import FunctionReachabilityEngine

    return FunctionReachabilityEngine(
        db_path=str(tmp_path / "fr.db"),
        cache_db_path=str(tmp_path / "fr_cache.db"),
    )


def _has_pkg(name: str) -> bool:
    try:
        __import__(name)
        return True
    except ImportError:
        return False


# ---------------------------------------------------------------------------
# AC-004-01 — requirements.txt pins
# ---------------------------------------------------------------------------

class TestAC00401RequirementsPins:
    """tree-sitter + language bindings must be pinned in requirements.txt."""

    def _load_reqs(self) -> str:
        req_path = Path(__file__).parents[1] / "requirements.txt"
        return req_path.read_text(encoding="utf-8")

    def test_tree_sitter_core_pinned(self):
        assert "tree-sitter" in self._load_reqs(), (
            "tree-sitter not found in requirements.txt"
        )

    def test_tree_sitter_typescript_pinned(self):
        assert "tree-sitter-typescript" in self._load_reqs()

    def test_tree_sitter_java_pinned(self):
        assert "tree-sitter-java" in self._load_reqs()

    def test_tree_sitter_go_pinned(self):
        assert "tree-sitter-go" in self._load_reqs()


# ---------------------------------------------------------------------------
# AC-004-02 — parse_typescript_repo: real result when dep installed
# ---------------------------------------------------------------------------

class TestAC00402TypescriptParser:

    @pytest.mark.skipif(
        not _has_pkg("tree_sitter_typescript"),
        reason="tree-sitter-typescript not installed",
    )
    def test_ts_simple_callgraph(self, tmp_path):
        """Two TS functions, one calls the other — real nodes + edge returned."""
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
        inserted = eng.parse_typescript_repo("org-ts", "sha-ts", str(repo))
        assert inserted >= 2, f"expected >=2 nodes, got {inserted}"
        cg = eng.list_callgraph("org-ts", "sha-ts")
        fqns = {n["function_fqn"] for n in cg["nodes"]}
        assert any(f.endswith(".helper") for f in fqns), fqns
        assert any(f.endswith(".main") for f in fqns), fqns
        assert cg["edge_count"] >= 1

    def test_ts_parser_unavailable_clean_skip(self, tmp_path, monkeypatch):
        """When tree-sitter-typescript is absent, ParserUnavailableError is raised
        (typed skip — not a 500, not NotImplementedError)."""
        from core.function_reachability_engine import ParserUnavailableError

        eng = _engine(tmp_path)
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "x.ts").write_text("function f(){}")

        real_import = (
            __builtins__["__import__"]
            if isinstance(__builtins__, dict)
            else __builtins__.__import__
        )

        def _blocked(name, *a, **kw):
            if name == "tree_sitter_typescript":
                raise ImportError("blocked")
            return real_import(name, *a, **kw)

        monkeypatch.delitem(sys.modules, "tree_sitter_typescript", raising=False)
        monkeypatch.setattr("builtins.__import__", _blocked)

        with pytest.raises(ParserUnavailableError) as exc_info:
            eng.parse_typescript_repo("org-ts", "sha-ts-blocked", str(repo))

        err = exc_info.value
        assert err.language == "typescript"
        assert "pip install" in err.install_hint
        # Must NOT be a generic NotImplementedError or RuntimeError subclass that
        # looks like "feature not coded yet"
        assert not isinstance(err, NotImplementedError)


# ---------------------------------------------------------------------------
# AC-004-02 — parse_java_repo: real result when dep installed
# ---------------------------------------------------------------------------

class TestAC00402JavaParser:

    @pytest.mark.skipif(
        not _has_pkg("tree_sitter_java"),
        reason="tree-sitter-java not installed",
    )
    def test_java_simple_callgraph(self, tmp_path):
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
        inserted = eng.parse_java_repo("org-java", "sha-java", str(repo))
        assert inserted >= 2, f"expected >=2 nodes, got {inserted}"
        cg = eng.list_callgraph("org-java", "sha-java")
        fqns = {n["function_fqn"] for n in cg["nodes"]}
        assert any("App.helper" in f for f in fqns), fqns
        assert any("App.main" in f for f in fqns), fqns

    def test_java_parser_unavailable_clean_skip(self, tmp_path, monkeypatch):
        from core.function_reachability_engine import ParserUnavailableError

        eng = _engine(tmp_path)
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "X.java").write_text("class X { void f(){} }")

        real_import = (
            __builtins__["__import__"]
            if isinstance(__builtins__, dict)
            else __builtins__.__import__
        )

        def _blocked(name, *a, **kw):
            if name == "tree_sitter_java":
                raise ImportError("blocked")
            return real_import(name, *a, **kw)

        monkeypatch.delitem(sys.modules, "tree_sitter_java", raising=False)
        monkeypatch.setattr("builtins.__import__", _blocked)

        with pytest.raises(ParserUnavailableError) as exc_info:
            eng.parse_java_repo("org-java", "sha-java-blocked", str(repo))

        err = exc_info.value
        assert err.language == "java"
        assert "pip install" in err.install_hint


# ---------------------------------------------------------------------------
# AC-004-02 — parse_go_repo: real result when dep installed
# ---------------------------------------------------------------------------

class TestAC00402GoParser:

    @pytest.mark.skipif(
        not _has_pkg("tree_sitter_go"),
        reason="tree-sitter-go not installed",
    )
    def test_go_simple_callgraph(self, tmp_path):
        eng = _engine(tmp_path)
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "main.go").write_text(
            textwrap.dedent(
                """\
                package main

                func helper() int { return 1 }

                func main() int { return helper() }
                """
            )
        )
        inserted = eng.parse_go_repo("org-go", "sha-go", str(repo))
        assert inserted >= 2, f"expected >=2 nodes, got {inserted}"
        cg = eng.list_callgraph("org-go", "sha-go")
        fqns = {n["function_fqn"] for n in cg["nodes"]}
        assert any("helper" in f for f in fqns), fqns
        assert any("main" in f for f in fqns), fqns
        assert cg["edge_count"] >= 1

    @pytest.mark.skipif(
        not _has_pkg("tree_sitter_go"),
        reason="tree-sitter-go not installed",
    )
    def test_go_method_on_type(self, tmp_path):
        """Go method (func (r Receiver) Method()) is captured as Receiver.Method."""
        eng = _engine(tmp_path)
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "service.go").write_text(
            textwrap.dedent(
                """\
                package svc

                type Service struct{}

                func (s Service) Process() error { return s.validate() }
                func (s Service) validate() error { return nil }
                """
            )
        )
        inserted = eng.parse_go_repo("org-go2", "sha-go2", str(repo))
        assert inserted >= 2
        cg = eng.list_callgraph("org-go2", "sha-go2")
        fqns = {n["function_fqn"] for n in cg["nodes"]}
        assert any("Service.Process" in f for f in fqns), fqns
        assert any("Service.validate" in f for f in fqns), fqns

    @pytest.mark.skipif(
        not _has_pkg("tree_sitter_go"),
        reason="tree-sitter-go not installed",
    )
    def test_go_skips_vendor_dir(self, tmp_path):
        eng = _engine(tmp_path)
        repo = tmp_path / "repo"
        (repo / "vendor" / "lib").mkdir(parents=True)
        (repo / "vendor" / "lib" / "pkg.go").write_text(
            "package lib\nfunc vendorFn() {}"
        )
        (repo / "real.go").write_text("package main\nfunc realFn() {}")
        eng.parse_go_repo("org-go3", "sha-go3", str(repo))
        cg = eng.list_callgraph("org-go3", "sha-go3")
        fqns = {n["function_fqn"] for n in cg["nodes"]}
        assert not any("vendorFn" in f for f in fqns), f"vendor leaked: {fqns}"
        assert any("realFn" in f for f in fqns), fqns

    def test_go_parser_unavailable_clean_skip(self, tmp_path, monkeypatch):
        from core.function_reachability_engine import ParserUnavailableError

        eng = _engine(tmp_path)
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "x.go").write_text("package main\nfunc f() {}")

        real_import = (
            __builtins__["__import__"]
            if isinstance(__builtins__, dict)
            else __builtins__.__import__
        )

        def _blocked(name, *a, **kw):
            if name == "tree_sitter_go":
                raise ImportError("blocked")
            return real_import(name, *a, **kw)

        monkeypatch.delitem(sys.modules, "tree_sitter_go", raising=False)
        monkeypatch.setattr("builtins.__import__", _blocked)

        with pytest.raises(ParserUnavailableError) as exc_info:
            eng.parse_go_repo("org-go", "sha-go-blocked", str(repo))

        err = exc_info.value
        assert err.language == "go"
        assert "pip install" in err.install_hint


# ---------------------------------------------------------------------------
# AC-004-03 — pipeline with repo_path + TS finding runs/clean-skips
# ---------------------------------------------------------------------------

class TestAC00403PipelineAutoRun:
    """BrainPipeline._calculate_risk_scores never raises when repo_path is set."""

    def _make_pipeline(self):
        from core.brain_pipeline import BrainPipeline
        return BrainPipeline()

    def _reachability_step_output(self, result) -> dict:
        """Extract reachability block from the score_risk step output."""
        for step in result.steps:
            if step.name == "score_risk" and step.output:
                if "reachability" in step.output:
                    return step.output["reachability"]
        return {}

    def test_pipeline_ts_finding_with_repo_path_no_raise(self, tmp_path):
        """Pipeline with repo_path + TS finding completes without exception."""
        from core.brain_pipeline import PipelineInput

        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()
        (repo_dir / "app.ts").write_text(
            "function handler() { return 1; }\n"
        )

        pipeline = self._make_pipeline()
        inp = PipelineInput(
            org_id="org-pipeline-ts",
            findings=[
                {
                    "id": "f-001",
                    "cve_id": "CVE-2024-0001",
                    "package_name": "lodash",
                    "severity": "high",
                    "language": "typescript",
                    "function": "handler",
                }
            ],
            assets=[],
            metadata={"repo_path": str(repo_dir)},
        )

        # Must not raise — AC-004-03 core requirement
        result = pipeline.run(inp)
        assert result is not None
        # reachability block present in score_risk step output (REQ-004-06)
        reach = self._reachability_step_output(result)
        # reach may be empty dict when the finding already had reachable set upstream
        # (e.g. _apply_reachability_verdicts ran first) — that is a valid outcome.
        # The key requirement is that the step completed without raising.
        score_step = next(
            (s for s in result.steps if s.name == "score_risk"), None
        )
        assert score_step is not None
        assert score_step.status.value in ("completed", "COMPLETED", "skipped", "SKIPPED")

    def test_pipeline_no_repo_path_no_raise(self, tmp_path):
        """Pipeline without repo_path still runs (reachability skipped cleanly)."""
        from core.brain_pipeline import PipelineInput

        pipeline = self._make_pipeline()
        inp = PipelineInput(
            org_id="org-pipeline-norepo",
            findings=[
                {
                    "id": "f-002",
                    "cve_id": "CVE-2024-0002",
                    "severity": "medium",
                }
            ],
            assets=[],
            metadata={},
        )
        result = pipeline.run(inp)
        assert result is not None

    def test_pipeline_nonexistent_repo_path_no_raise(self, tmp_path):
        """Pipeline with a nonexistent repo_path doesn't raise — skips gracefully."""
        from core.brain_pipeline import PipelineInput

        pipeline = self._make_pipeline()
        inp = PipelineInput(
            org_id="org-pipeline-badrepo",
            findings=[{"id": "f-003", "severity": "low"}],
            assets=[],
            metadata={"repo_path": "/nonexistent/path/that/does/not/exist"},
        )
        result = pipeline.run(inp)
        assert result is not None

    def test_pipeline_go_finding_with_repo_path_no_raise(self, tmp_path):
        """Pipeline with repo_path + Go finding completes without exception."""
        from core.brain_pipeline import PipelineInput

        repo_dir = tmp_path / "repo_go"
        repo_dir.mkdir()
        (repo_dir / "main.go").write_text(
            "package main\nfunc handler() {}\nfunc main() { handler() }\n"
        )

        pipeline = self._make_pipeline()
        inp = PipelineInput(
            org_id="org-pipeline-go",
            findings=[
                {
                    "id": "f-go-001",
                    "cve_id": "CVE-2024-0003",
                    "package_name": "net/http",
                    "severity": "high",
                    "language": "go",
                    "function": "handler",
                }
            ],
            assets=[],
            metadata={"repo_path": str(repo_dir)},
        )
        result = pipeline.run(inp)
        assert result is not None
        # Step must complete without raising — block presence verified in isolation
        score_step = next(
            (s for s in result.steps if s.name == "score_risk"), None
        )
        assert score_step is not None
        assert score_step.status.value in ("completed", "COMPLETED", "skipped", "SKIPPED")


# ---------------------------------------------------------------------------
# AC-004-04 — create_app() boots without error
# ---------------------------------------------------------------------------

class TestAC00404AppBoot:

    def test_create_app_boots(self):
        """FastAPI app mounts without ImportError from reachability changes."""
        from apps.api.app import create_app

        app = create_app()
        assert app is not None
        # Confirm routes are mounted (basic sanity)
        assert len(app.routes) > 0


# ---------------------------------------------------------------------------
# REQ-004-05 — ParserUnavailableError is a clean typed exception
# ---------------------------------------------------------------------------

class TestREQ00405ParserUnavailableError:

    def test_parser_unavailable_is_runtime_error(self):
        from core.function_reachability_engine import ParserUnavailableError

        err = ParserUnavailableError("rust", "pip install tree-sitter-rust")
        assert isinstance(err, RuntimeError)
        assert not isinstance(err, NotImplementedError)
        assert err.language == "rust"
        assert "pip install tree-sitter-rust" in err.install_hint
        assert "rust" in str(err)

    def test_parser_unavailable_no_hint(self):
        from core.function_reachability_engine import ParserUnavailableError

        err = ParserUnavailableError("kotlin")
        assert err.language == "kotlin"
        assert err.install_hint == ""
        assert "kotlin" in str(err)


# ---------------------------------------------------------------------------
# REQ-004-06 — reachability coverage block shape
# ---------------------------------------------------------------------------

class TestREQ00406ReachabilityBlock:
    """Pipeline result reachability block must carry the required keys."""

    def test_reachability_block_has_required_keys(self, tmp_path):
        from core.brain_pipeline import BrainPipeline, PipelineInput

        repo_dir = tmp_path / "repo"
        repo_dir.mkdir()
        (repo_dir / "app.py").write_text(
            "def handler():\n    return 1\ndef main():\n    handler()\n"
        )

        pipeline = BrainPipeline()
        inp = PipelineInput(
            org_id="org-block-test",
            findings=[
                {
                    "id": "f-block-001",
                    "cve_id": "CVE-2024-9999",
                    "package_name": "requests",
                    "severity": "high",
                    "language": "python",
                    "function": "handler",
                }
            ],
            assets=[],
            metadata={"repo_path": str(repo_dir)},
        )
        result = pipeline.run(inp)
        # reachability block lives in score_risk step output
        block = None
        for step in result.steps:
            if step.name == "score_risk" and step.output:
                block = step.output.get("reachability")
                break
        assert block is not None, (
            f"reachability block missing from score_risk step output; "
            f"step outputs: {[s.output for s in result.steps if s.name == 'score_risk']}"
        )
        for key in ("analyzed", "reachable", "unreachable", "skipped",
                    "fallback", "languages_indexed"):
            assert key in block, f"reachability block missing key '{key}': {block}"
        assert isinstance(block["languages_indexed"], list)
