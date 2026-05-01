"""Real call-graph reachability tests for FunctionReachabilityEngine.

Covers the 5 capabilities added by the GAP-010 follow-up:

1. test_reachable_via_http_handler         — entry-point → vuln BFS path
2. test_unreachable_dead_code              — vuln nobody calls → is_reachable=False
3. test_dynamic_dispatch_returns_conservative
                                            — eval/getattr in vuln body →
                                              is_reachable=True, low confidence,
                                              analysis_method="fallback_conservative"
4. test_caches_results                     — second call hits SQLite cache
5. test_emits_trustgraph_event             — bus.emit called once with correct
                                              event_type ("reachability.analyzed")
"""

from __future__ import annotations

import textwrap
import uuid
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from core.function_reachability_engine import (
    FunctionReachabilityEngine,
    FunctionReachabilityResult,
)


# ---------------------------------------------------------------------------
# Fixture — engine wired to two tmp DBs (graph + cache)
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    return FunctionReachabilityEngine(
        db_path=str(tmp_path / "fr.db"),
        cache_db_path=str(tmp_path / "cache.db"),
    )


def _seed_repo(root: Path, *, with_dynamic_dispatch: bool = False) -> None:
    """Tiny repo with one HTTP handler that calls a vuln function.

    With ``with_dynamic_dispatch=True`` the vuln body uses ``getattr`` so the
    engine should treat it as conservatively reachable.
    """
    pkg = root / "app"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("", encoding="utf-8")

    # Entry-point: the name "handler" matches _ENTRY_POINT_NAME_PATTERNS.
    (pkg / "router.py").write_text(
        textwrap.dedent(
            """
            from app.vuln import vulnerable_func

            def http_handler(request):
                return vulnerable_func(request.body)
            """
        ).strip(),
        encoding="utf-8",
    )

    if with_dynamic_dispatch:
        vuln_body = textwrap.dedent(
            """
            def vulnerable_func(payload):
                # Dynamic dispatch — engine cannot statically follow this.
                method = getattr(payload, "execute", None)
                return method() if method else None
            """
        ).strip()
    else:
        vuln_body = textwrap.dedent(
            """
            def vulnerable_func(payload):
                return len(payload)
            """
        ).strip()
    (pkg / "vuln.py").write_text(vuln_body, encoding="utf-8")

    # An island module — defines a function nobody calls (dead code).
    (pkg / "deadcode.py").write_text(
        textwrap.dedent(
            """
            def isolated_helper():
                return 42
            """
        ).strip(),
        encoding="utf-8",
    )


# ---------------------------------------------------------------------------
# 1) Reachable via HTTP handler
# ---------------------------------------------------------------------------


def test_reachable_via_http_handler(engine, tmp_path):
    repo_root = tmp_path / "repo1"
    repo_root.mkdir()
    _seed_repo(repo_root)

    org = "org-test-1"
    repo_sha = "sha-aaa"
    engine.parse_python_repo(org, repo_sha, str(repo_root))

    result = engine.analyse_vulnerable_symbol(
        org_id=org,
        repo_sha=repo_sha,
        vuln_function_fqn="app.vuln.vulnerable_func",
        cve_id="CVE-9999-0001",
    )

    assert isinstance(result, FunctionReachabilityResult)
    assert result.is_reachable is True
    assert result.analysis_method == "call_graph"
    assert result.entry_point == "app.router.http_handler"
    assert "app.router.http_handler" in result.call_path
    assert "app.vuln.vulnerable_func" in result.call_path
    assert result.confidence >= 0.5
    assert result.cached is False


# ---------------------------------------------------------------------------
# 2) Dead code — unreachable
# ---------------------------------------------------------------------------


def test_unreachable_dead_code(engine, tmp_path):
    repo_root = tmp_path / "repo2"
    repo_root.mkdir()
    _seed_repo(repo_root)

    org = "org-test-2"
    repo_sha = "sha-bbb"
    engine.parse_python_repo(org, repo_sha, str(repo_root))

    result = engine.analyse_vulnerable_symbol(
        org_id=org,
        repo_sha=repo_sha,
        vuln_function_fqn="app.deadcode.isolated_helper",
        cve_id="CVE-9999-0002",
    )

    assert result.is_reachable is False
    assert result.call_path == []
    assert result.entry_point is None
    assert result.analysis_method == "call_graph"
    # We had coverage and ran BFS — confidence should be high.
    assert result.confidence >= 0.7


# ---------------------------------------------------------------------------
# 3) Dynamic dispatch → conservative fallback
# ---------------------------------------------------------------------------


def test_dynamic_dispatch_returns_conservative(engine, tmp_path, monkeypatch):
    repo_root = tmp_path / "repo3"
    repo_root.mkdir()
    _seed_repo(repo_root, with_dynamic_dispatch=True)

    # The engine reads the vuln body to detect dynamic dispatch.  Source paths
    # are stored relative to the repo root, so chdir there for the read.
    monkeypatch.chdir(repo_root)

    org = "org-test-3"
    repo_sha = "sha-ccc"
    engine.parse_python_repo(org, repo_sha, str(repo_root))

    result = engine.analyse_vulnerable_symbol(
        org_id=org,
        repo_sha=repo_sha,
        vuln_function_fqn="app.vuln.vulnerable_func",
        cve_id="CVE-9999-0003",
    )

    assert result.is_reachable is True, "must conservatively flag as reachable"
    assert result.analysis_method == "fallback_conservative"
    assert result.confidence < 0.5
    assert result.call_path == []


# ---------------------------------------------------------------------------
# 4) Cache hit on the second call
# ---------------------------------------------------------------------------


def test_caches_results(engine, tmp_path):
    repo_root = tmp_path / "repo4"
    repo_root.mkdir()
    _seed_repo(repo_root)

    org = "org-test-4"
    repo_sha = "sha-ddd"
    engine.parse_python_repo(org, repo_sha, str(repo_root))

    first = engine.analyse_vulnerable_symbol(
        org_id=org,
        repo_sha=repo_sha,
        vuln_function_fqn="app.vuln.vulnerable_func",
        cve_id="CVE-9999-0004",
    )
    assert first.cached is False

    # Verify the cache row landed in SQLite.
    import sqlite3

    with sqlite3.connect(engine.cache_db_path) as conn:
        rows = conn.execute(
            "SELECT repo_sha, vuln_function_signature, is_reachable "
            "FROM reachability_cache "
            "WHERE repo_sha=? AND vuln_function_signature=?",
            (repo_sha, "app.vuln.vulnerable_func"),
        ).fetchall()
    assert len(rows) == 1
    assert rows[0][2] == 1  # is_reachable

    second = engine.analyse_vulnerable_symbol(
        org_id=org,
        repo_sha=repo_sha,
        vuln_function_fqn="app.vuln.vulnerable_func",
        cve_id="CVE-9999-0004",
    )
    assert second.cached is True
    assert second.is_reachable is first.is_reachable
    assert second.entry_point == first.entry_point


# ---------------------------------------------------------------------------
# 5) TrustGraph event emission
# ---------------------------------------------------------------------------


def test_emits_trustgraph_event(engine, tmp_path, monkeypatch):
    repo_root = tmp_path / "repo5"
    repo_root.mkdir()
    _seed_repo(repo_root)

    org = "org-test-5"
    repo_sha = "sha-eee"
    engine.parse_python_repo(org, repo_sha, str(repo_root))

    fake_bus = MagicMock()
    fake_bus.publish = MagicMock(return_value=None)
    # No emit attr — engine should fall through to publish.
    if hasattr(fake_bus, "emit"):
        del fake_bus.emit

    monkeypatch.setattr(
        "core.function_reachability_engine._get_tg_bus",
        lambda: fake_bus,
    )

    engine.analyse_vulnerable_symbol(
        org_id=org,
        repo_sha=repo_sha,
        vuln_function_fqn="app.vuln.vulnerable_func",
        cve_id="CVE-9999-0005",
    )

    assert fake_bus.publish.called, "expected TrustGraph emit on reachability.analyzed"
    call_args = fake_bus.publish.call_args
    assert call_args.args[0] == "reachability.analyzed"
    payload = call_args.args[1]
    assert payload["cve_id"] == "CVE-9999-0005"
    assert payload["vuln_function_fqn"] == "app.vuln.vulnerable_func"
    assert payload["repo_sha"] == repo_sha
    assert payload["is_reachable"] is True
    assert payload["entry_point"] == "app.router.http_handler"
    assert payload["analysis_method"] == "call_graph"
