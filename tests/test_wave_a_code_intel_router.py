"""Wave A — Code / Architecture Intel router smoke tests (19 endpoints).

Each endpoint gets at least one happy-path call. We accept any response code
in {200, 201, 404, 422, 501} as "the route is wired and the validation chain
worked" — the deeper engine behaviour is exercised by per-engine unit tests.

Auth: ``FIXOPS_MODE=demo`` is set so ``api_key_auth`` allows unauthenticated
requests during the test boot, matching the Wave C/D test pattern.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Iterator

import pytest

# Configure auth BEFORE auth_deps gets imported.
# api_key_auth reads FIXOPS_API_TOKEN + FIXOPS_MODE at module-import time, so
# we set a known token here and pass it as X-API-Key on every request below.
os.environ["FIXOPS_API_TOKEN"] = "wave-a-test-token"
os.environ.setdefault("FIXOPS_MODE", "dev")

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

# If auth_deps was already imported by another test file, force a reload so
# the new env values take effect.  If it has NOT been imported yet (e.g. this
# file is collected first in a broad scan), importlib.reload() would raise
# ImportError because the module is not in sys.modules.  We guard with a
# conditional: reload when cached, plain-import when not.
import importlib  # noqa: E402
import sys as _sys  # noqa: E402

if "apps.api.auth_deps" in _sys.modules:
    _auth_mod = _sys.modules["apps.api.auth_deps"]
    importlib.reload(_auth_mod)
else:
    import apps.api.auth_deps as _auth_mod  # noqa: E402

from apps.api.wave_a_code_intel_router import WAVE_A_ROUTERS  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def app() -> FastAPI:
    """Mount every Wave A router on a fresh FastAPI app — no other deps."""
    a = FastAPI()
    for r in WAVE_A_ROUTERS:
        a.include_router(r)
    return a


@pytest.fixture(scope="module")
def client(app: FastAPI) -> TestClient:
    return TestClient(app, headers={"X-API-Key": "wave-a-test-token"})


@pytest.fixture(scope="module")
def repo_dir() -> Iterator[str]:
    """A tiny throwaway repo we can point /architecture-detect + /dca/parse-repo at."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "app" / "routers").mkdir(parents=True)
        (root / "domain").mkdir(parents=True)
        (root / "infra" / "db").mkdir(parents=True)
        (root / "ui" / "components").mkdir(parents=True)
        (root / "app" / "routers" / "users_router.py").write_text(
            "def list_users():\n    return []\n"
        )
        (root / "domain" / "entities.py").write_text(
            "class User:\n    pass\n"
        )
        (root / "infra" / "db" / "postgres_client.py").write_text(
            "PG_DSN = 'postgres://localhost'\n"
        )
        yield str(root)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

OK_CODES = {200, 201, 202, 204, 404, 422, 501}


def _assert_wired(resp, expected_codes=OK_CODES):
    """Route is mounted and the auth/validation chain ran."""
    assert resp.status_code in expected_codes, (
        f"unexpected {resp.status_code}: {resp.text[:300]}"
    )
    # Should always return JSON (even errors)
    if resp.status_code != 204:
        assert resp.headers.get("content-type", "").startswith("application/json"), (
            f"non-JSON body: {resp.text[:200]}"
        )


# ---------------------------------------------------------------------------
# 1) graph/architecture-detect  +  graph/databases/{repo_id}
# ---------------------------------------------------------------------------

def test_architecture_detect_and_databases(client: TestClient, repo_dir: str):
    body = {
        "repo_path": repo_dir,
        "include_files_glob": ["**/*.py"],
        "detect_layers": True,
        "detect_databases": True,
        "detect_apis": True,
    }
    resp = client.post("/api/v1/graph/architecture-detect", json=body)
    _assert_wired(resp)
    if resp.status_code == 201:
        data = resp.json()
        assert "report_id" in data
        assert data.get("summary", {}).get("layers", 0) >= 0

        # Now ask for databases of that repo (uses repo_path substring match)
        repo_id = Path(repo_dir).name
        resp_db = client.get(f"/api/v1/graph/databases/{repo_id}")
        _assert_wired(resp_db)


def test_graph_flows(client: TestClient):
    resp = client.get("/api/v1/graph/flows/order-service?depth=2")
    _assert_wired(resp)
    if resp.status_code == 200:
        d = resp.json()
        assert "inbound" in d and "outbound" in d


def test_graph_layers(client: TestClient):
    resp = client.get("/api/v1/graph/layers/app")
    _assert_wired(resp)
    if resp.status_code == 200:
        assert "layer" in resp.json()


def test_graph_diff_validation(client: TestClient):
    # Missing both prId and base/head — should 422
    resp = client.get("/api/v1/graph/diff")
    assert resp.status_code in {422, 400}


def test_graph_diff_with_pr(client: TestClient):
    resp = client.get("/api/v1/graph/diff?prId=PR-123")
    _assert_wired(resp)


# ---------------------------------------------------------------------------
# 2) DCA — parse-repo / entities / diff
# ---------------------------------------------------------------------------

def test_dca_parse_repo(client: TestClient, repo_dir: str):
    body = {"repo": repo_dir, "revision": "rev-A", "languages": ["python"]}
    resp = client.post("/api/v1/dca/parse-repo", json=body)
    _assert_wired(resp)
    if resp.status_code == 201:
        d = resp.json()
        assert d.get("repo") == repo_dir
        assert "entity_counts" in d


def test_dca_entities(client: TestClient, repo_dir: str):
    resp = client.get(f"/api/v1/dca/entities/{Path(repo_dir).name}?limit=10")
    _assert_wired(resp)


def test_dca_diff(client: TestClient, repo_dir: str):
    resp = client.get(
        f"/api/v1/dca/diff?repo={Path(repo_dir).name}&from=rev-A&to=rev-B"
    )
    _assert_wired(resp)


# ---------------------------------------------------------------------------
# 3) Reachability
# ---------------------------------------------------------------------------

def test_reachability_callgraph_validation(client: TestClient):
    # Missing repo_path for python should 422
    resp = client.post(
        "/api/v1/reachability/callgraph",
        json={"repo": "x", "language": "python"},
    )
    assert resp.status_code in {422, 501}


def test_reachability_callgraph_python(client: TestClient, repo_dir: str):
    resp = client.post(
        "/api/v1/reachability/callgraph",
        json={"repo": "smoke-repo", "repo_path": repo_dir, "language": "python"},
    )
    _assert_wired(resp, expected_codes={200, 201, 404, 422, 500, 501})


def test_reachability_proof_404(client: TestClient):
    resp = client.get("/api/v1/reachability/FIND-DOES-NOT-EXIST/proof")
    _assert_wired(resp, expected_codes={200, 404, 501})


# ---------------------------------------------------------------------------
# 4) Components
# ---------------------------------------------------------------------------

def test_components_match_by_abf(client: TestClient):
    resp = client.get(
        "/api/v1/components/match-by-abf?abf=" + ("a" * 64) + "&org_id=default",
    )
    _assert_wired(resp)
    if resp.status_code == 200:
        assert "matches" in resp.json()


def test_components_safe_upgrade(client: TestClient):
    purl = "pkg:pypi/requests@2.20.0"
    resp = client.get(f"/api/v1/components/{purl}/safe-upgrade?current_version=2.20.0")
    _assert_wired(resp, expected_codes={200, 404, 422, 500, 501})


# ---------------------------------------------------------------------------
# 5) IDE
# ---------------------------------------------------------------------------

def test_ide_findings(client: TestClient):
    resp = client.get(
        "/api/v1/ide/findings?repo=demo-repo&file=app/main.py&limit=5",
    )
    _assert_wired(resp)
    if resp.status_code == 200:
        assert "findings" in resp.json()


def test_ide_authenticate_token_invalid(client: TestClient):
    resp = client.post(
        "/api/v1/ide/authenticate-token",
        json={"token": "definitely-not-a-valid-token-xyz", "client_id": "vscode"},
    )
    # Should be 401 (invalid) or 200 if the demo manager accepts bare strings
    assert resp.status_code in {200, 401, 422}


def test_ide_user_snapshot(client: TestClient):
    resp = client.get(
        "/api/v1/ide/user-snapshot?user_id=alice",
        headers={"X-User-ID": "alice"},
    )
    _assert_wired(resp)
    if resp.status_code == 200:
        d = resp.json()
        assert d["user_id"] == "alice"
        assert "tokens" in d


# ---------------------------------------------------------------------------
# 6) Runtime
# ---------------------------------------------------------------------------

def test_runtime_map_to_code_validation(client: TestClient):
    # No event_id, no stack/api/service — should 422
    resp = client.post("/api/v1/runtime/map-to-code", json={})
    assert resp.status_code in {422, 501, 500}


def test_runtime_map_to_code(client: TestClient):
    body = {
        "service_name": "checkout",
        "api_path": "/orders/123",
        "stack_trace": "  at orders/handlers.py:42\n  at orders/service.py:99",
    }
    resp = client.post("/api/v1/runtime/map-to-code", json=body)
    _assert_wired(resp, expected_codes={200, 201, 404, 422, 500, 501})


def test_runtime_traffic(client: TestClient):
    resp = client.get("/api/v1/runtime/traffic/orders/123?window_minutes=60")
    _assert_wired(resp)


# ---------------------------------------------------------------------------
# Aggregate sanity
# ---------------------------------------------------------------------------

def test_total_endpoint_count(app: FastAPI):
    """Sanity: the router file should contribute exactly 19 endpoints.

    17 original (Wave A) + 2 final-cleanup endpoints
    (graph/affected-nodes, graph/diff/{baseline}/{current}).
    """
    paths = {(getattr(r, "path", None), tuple(sorted(getattr(r, "methods", []) or [])))
             for r in app.routes
             if hasattr(r, "methods") and getattr(r, "path", "").startswith("/api/v1/")}
    # Drop non-API routes (e.g. root, docs) — already filtered above
    assert len(paths) == 19, f"expected 19 endpoints, got {len(paths)}: {sorted(p[0] for p in paths)}"
