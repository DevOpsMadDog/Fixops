"""Reachability router — deep HTTP-layer tests (exploit-paths / path-analysis).

Targets endpoints NOT covered by unit tests or smoke files:
  POST /api/v1/reachability/vulnerable   — exploit-paths (caller -> CVE sink)
  POST /api/v1/reachability/query        — BFS path-analysis
  GET  /api/v1/reachability/callgraph/{repo_ref}  — graph visualisation payload
  POST /api/v1/reachability/parse        — Python AST ingestion
  Validation errors on /query and /vulnerable

Auth: FIXOPS_MODE=demo pass-through (same pattern as test_persona_walkthrough_us_gates).
Engine: real FunctionReachabilityEngine backed by a per-test tmp-path SQLite DB,
injected via FastAPI dependency_overrides — zero mocks, no external I/O.
"""

from __future__ import annotations

import importlib
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
for _sub in ("suite-core", "suite-api", "suite-attack", "suite-feeds",
             "suite-evidence-risk", "suite-integrations"):
    sys.path.insert(0, str(ROOT / _sub))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

# ---------------------------------------------------------------------------
# Auth env — demo mode pass-through (no token required)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def _demo_auth_env():
    mp = pytest.MonkeyPatch()
    mp.setenv("FIXOPS_MODE", "demo")
    mp.delenv("FIXOPS_API_TOKEN", raising=False)
    mp.delenv("FIXOPS_JWT_SECRET", raising=False)
    mp.setenv("FIXOPS_DISABLE_TELEMETRY", "1")
    mp.setenv("FIXOPS_DISABLE_RATE_LIMIT", "1")
    import apps.api.auth_deps as _auth_mod
    importlib.reload(_auth_mod)
    yield
    mp.undo()


# ---------------------------------------------------------------------------
# Mini Python repo fixture (3 files, 2 call hops)
#
#   app.py        def handler  ->  calls service.process
#   service.py    def process  ->  calls requests.Session.send
#   util.py       def unused   (no callers — reachability dead end)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def mini_repo(tmp_path_factory):
    root = tmp_path_factory.mktemp("repo")
    (root / "app.py").write_text(textwrap.dedent("""
        from service import process

        def handler(req):
            return process(req)
    """), encoding="utf-8")

    (root / "service.py").write_text(textwrap.dedent("""
        import requests

        def process(req):
            s = requests.Session()
            return s.send(req)
    """), encoding="utf-8")

    (root / "util.py").write_text(textwrap.dedent("""
        def unused():
            pass
    """), encoding="utf-8")

    return root


# ---------------------------------------------------------------------------
# Client + engine fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def engine(tmp_path_factory):
    from core.function_reachability_engine import FunctionReachabilityEngine
    db = tmp_path_factory.mktemp("db") / "reach.db"
    return FunctionReachabilityEngine(db_path=str(db))


@pytest.fixture(scope="module")
def client(engine):
    import apps.api.function_reachability_router as _mod
    importlib.reload(_mod)

    app = FastAPI()

    # Override the singleton getter so every request gets our tmp engine.
    def _override():
        return engine

    app.include_router(_mod.router)
    app.dependency_overrides[_mod._get_engine] = _override
    return TestClient(app)


# ---------------------------------------------------------------------------
# Pre-load: parse the mini repo so later tests have real nodes + edges
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module", autouse=True)
def _parse_mini_repo(client, mini_repo):
    """POST /parse once per module so all tests share the same graph."""
    r = client.post("/api/v1/reachability/parse", json={
        "org_id": "test-org",
        "repo_ref": "mini@main",
        "language": "python",
        "root_path": str(mini_repo),
    })
    assert r.status_code == 200, r.text


# ---------------------------------------------------------------------------
# Test 1 — POST /parse happy path
# ---------------------------------------------------------------------------

def test_parse_returns_nodes_added(client, mini_repo):
    r = client.post("/api/v1/reachability/parse", json={
        "org_id": "test-org",
        "repo_ref": "mini@v2",
        "language": "python",
        "root_path": str(mini_repo),
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["language"] == "python"
    assert isinstance(body["nodes_added"], int)
    assert body["nodes_added"] >= 0


# ---------------------------------------------------------------------------
# Test 2 — POST /query (path-analysis) — reachable path returned
# ---------------------------------------------------------------------------

def test_query_path_analysis_response_shape(client):
    """POST /query returns the correct response envelope.

    Uses a known FQN from the mini repo parsed by _parse_mini_repo.
    BFS may find the node reachable or not — we only assert the HTTP shape.
    """
    # handler is defined in app.py; parse_python_repo builds FQN as
    # "<module>.handler" where <module> matches the file stem.
    r = client.post("/api/v1/reachability/query", json={
        "org_id": "test-org",
        "start_fqn": "app.handler",
        "target_fqn": "service.process",
        "max_depth": 5,
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["org_id"] == "test-org"
    assert body["start_fqn"] == "app.handler"
    assert body["target_fqn"] == "service.process"
    assert isinstance(body["reachable"], bool)
    assert isinstance(body["path"], (list, type(None)))
    assert body["max_depth"] == 5


# ---------------------------------------------------------------------------
# Test 3 — POST /query validation — missing FQNs yields 422
# ---------------------------------------------------------------------------

def test_query_missing_fqn_yields_422(client):
    r = client.post("/api/v1/reachability/query", json={
        "org_id": "test-org",
        # start_fqn and target_fqn omitted
    })
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# Test 4 — POST /vulnerable (exploit-paths) — shape + caller list
# ---------------------------------------------------------------------------

def test_vulnerable_returns_caller_list(client):
    r = client.post("/api/v1/reachability/vulnerable", json={
        "org_id": "test-org",
        "cve_id": "CVE-2024-0001",
        "dependency_fqn_pattern": "requests.%",
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["org_id"] == "test-org"
    assert body["cve_id"] == "CVE-2024-0001"
    assert body["dependency_fqn_pattern"] == "requests.%"
    assert isinstance(body["caller_count"], int)
    assert isinstance(body["callers"], list)
    # Each caller record must have the required fields
    for caller in body["callers"]:
        assert "caller_fqn" in caller
        assert "target_fqn" in caller
        assert "path" in caller


# ---------------------------------------------------------------------------
# Test 5 — POST /vulnerable — empty cve_id yields 422
# ---------------------------------------------------------------------------

def test_vulnerable_empty_cve_yields_422(client):
    r = client.post("/api/v1/reachability/vulnerable", json={
        "org_id": "test-org",
        "cve_id": "",
        "dependency_fqn_pattern": "requests.%",
    })
    # Engine raises ValueError("cve_id is required") -> router maps to 422
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# Test 6 — GET /callgraph/{repo_ref} — graph visualisation payload shape
# ---------------------------------------------------------------------------

def test_callgraph_returns_nodes_and_edges(client):
    r = client.get(
        "/api/v1/reachability/callgraph/mini@main",
        params={"org_id": "test-org"},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert "nodes" in body
    assert "edges" in body
    assert isinstance(body["nodes"], list)
    assert isinstance(body["edges"], list)
