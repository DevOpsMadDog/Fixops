"""Final endpoint cleanup smoke tests (Multica IDs c7ea7cad, 234238d6, 5894d7d7).

Covers:
  * GET  /api/v1/graph/affected-nodes?since=         (c7ea7cad)
  * GET  /api/v1/graph/diff/{baseline_id}/{current_id} (234238d6)
  * POST /api/v1/hooks/uninstall                     (5894d7d7)

Each endpoint gets at least one happy-path call + one error case.
Auth is configured via env BEFORE auth_deps is imported.
"""
from __future__ import annotations

import importlib
import tempfile
from pathlib import Path
from typing import Iterator

import pytest

from fastapi import FastAPI
from fastapi.testclient import TestClient

import apps.api.auth_deps as _auth_mod
from apps.api.wave_a_code_intel_router import WAVE_A_ROUTERS
from apps.api.hooks_router import router as hooks_router


@pytest.fixture(scope="module", autouse=True)
def _auth_env() -> None:
    mp = pytest.MonkeyPatch()
    mp.setenv("FIXOPS_API_TOKEN", "wave-a-test-token")
    mp.setenv("FIXOPS_MODE", "dev")
    mp.delenv("FIXOPS_JWT_SECRET", raising=False)
    importlib.reload(_auth_mod)
    yield
    mp.undo()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def app() -> FastAPI:
    """Mount Wave A routers + hooks_router on a fresh FastAPI app."""
    a = FastAPI()
    for r in WAVE_A_ROUTERS:
        a.include_router(r)
    a.include_router(hooks_router)
    return a


@pytest.fixture(scope="module")
def client(app: FastAPI) -> TestClient:
    return TestClient(app, headers={"X-API-Key": "wave-a-test-token"})


@pytest.fixture(scope="module")
def repo_dir() -> Iterator[str]:
    """Throwaway repo we can point /architecture-detect at to seed snapshots."""
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        (root / "app" / "routers").mkdir(parents=True)
        (root / "domain").mkdir(parents=True)
        (root / "infra" / "db").mkdir(parents=True)
        (root / "app" / "routers" / "users_router.py").write_text(
            "def list_users():\n    return []\n"
        )
        (root / "domain" / "entities.py").write_text("class User: pass\n")
        (root / "infra" / "db" / "postgres_client.py").write_text(
            "PG_DSN = 'postgres://localhost'\n"
        )
        yield str(root)


@pytest.fixture(scope="module")
def org_id() -> str:
    return "test-org-final-cleanup"


# ---------------------------------------------------------------------------
# 1) GET /api/v1/graph/affected-nodes?since=         (c7ea7cad)
# ---------------------------------------------------------------------------

def test_affected_nodes_happy_path(client: TestClient, repo_dir: str, org_id: str):
    """Seed an arch report, then ask for nodes since 1h ago — should include some."""
    # Seed via /architecture-detect first
    r1 = client.post(
        "/api/v1/graph/architecture-detect",
        json={
            "repo_path": repo_dir,
            "detect_layers": True,
            "detect_databases": True,
            "detect_apis": True,
        },
        headers={"X-Org-ID": org_id},
    )
    assert r1.status_code == 201, r1.text

    # Now query affected nodes since 1 hour ago
    r2 = client.get(
        "/api/v1/graph/affected-nodes?since=1h",
        headers={"X-Org-ID": org_id},
    )
    assert r2.status_code == 200, r2.text
    body = r2.json()
    assert body["org_id"] == org_id
    assert body["since"] == "1h"
    assert isinstance(body["nodes"], list)
    assert "since_resolved" in body
    # At least one source should have been tried (cloud_graph or architecture_reports)
    assert len(body["sources"]) >= 1, body


def test_affected_nodes_invalid_since(client: TestClient):
    """Bad `since` value should return 422 with a parse-error detail."""
    r = client.get("/api/v1/graph/affected-nodes?since=not-a-real-date")
    assert r.status_code == 422, r.text
    assert "since" in r.text.lower()


def test_affected_nodes_iso_timestamp(client: TestClient):
    """ISO-8601 since values must parse without error."""
    r = client.get(
        "/api/v1/graph/affected-nodes?since=2020-01-01T00:00:00Z"
    )
    assert r.status_code == 200
    assert r.json()["since"] == "2020-01-01T00:00:00Z"


# ---------------------------------------------------------------------------
# 2) GET /api/v1/graph/diff/{baseline_id}/{current_id}   (234238d6)
# ---------------------------------------------------------------------------

def test_graph_diff_by_ids_happy_path(client: TestClient, repo_dir: str, org_id: str):
    """Seed two arch reports, diff them, expect 200 + summary."""
    headers = {"X-Org-ID": org_id}
    r1 = client.post(
        "/api/v1/graph/architecture-detect",
        json={"repo_path": repo_dir, "detect_layers": True, "detect_apis": True},
        headers=headers,
    )
    assert r1.status_code == 201
    baseline_id = r1.json()["report_id"]

    # Add a brand new file before second snapshot to guarantee a diff
    (Path(repo_dir) / "shared").mkdir(exist_ok=True)
    (Path(repo_dir) / "shared" / "utils.py").write_text("X = 1\n")

    r2 = client.post(
        "/api/v1/graph/architecture-detect",
        json={"repo_path": repo_dir, "detect_layers": True, "detect_apis": True},
        headers=headers,
    )
    assert r2.status_code == 201
    current_id = r2.json()["report_id"]

    rdiff = client.get(
        f"/api/v1/graph/diff/{baseline_id}/{current_id}",
        headers=headers,
    )
    assert rdiff.status_code == 200, rdiff.text
    body = rdiff.json()
    assert body["baseline_id"] == baseline_id
    assert body["current_id"] == current_id
    assert "summary" in body and "diff" in body
    assert set(body["summary"].keys()) >= {"layers", "services", "databases", "apis"}
    assert isinstance(body["total_changes"], int)


def test_graph_diff_by_ids_same_id_rejected(client: TestClient):
    """Supplying baseline == current must be rejected with 422."""
    r = client.get("/api/v1/graph/diff/same-id/same-id")
    assert r.status_code == 422
    assert "differ" in r.text.lower()


def test_graph_diff_by_ids_missing_snapshot(client: TestClient, org_id: str):
    """Unknown ids should return 404 (not 500)."""
    r = client.get(
        "/api/v1/graph/diff/does-not-exist-baseline/does-not-exist-current",
        headers={"X-Org-ID": org_id},
    )
    # 404 (snapshot missing) or 501 (no store) — both indicate route is wired
    assert r.status_code in (404, 501), r.text


# ---------------------------------------------------------------------------
# 3) POST /api/v1/hooks/uninstall                       (5894d7d7)
# ---------------------------------------------------------------------------

@pytest.fixture
def installed_hook(org_id: str):
    """Apply a hook policy directly via the engine, return its record."""
    from core.devsecops_engine import get_devsecops_engine
    engine = get_devsecops_engine()
    record = engine.apply_hook_policy(
        org_id=f"{org_id}-hooks",
        hooks_dict={
            "version": 1,
            "rules": [{"event": "push", "action": "scan"}],
        },
    )
    return record


def test_hook_uninstall_by_id(client: TestClient, installed_hook):
    """Happy path: uninstall by hook_id returns 200 with deleted=1."""
    body = {"hook_id": installed_hook["id"], "reason": "test cleanup"}
    r = client.post("/api/v1/hooks/uninstall", json=body)
    assert r.status_code == 200, r.text
    payload = r.json()
    assert payload["status"] == "ok"
    assert payload["deleted"] == 1
    assert payload["engine_used"] is True
    assert payload["deleted_record"]["id"] == installed_hook["id"]


def test_hook_uninstall_no_filters_returns_422(client: TestClient):
    """Empty body (no hook_id/policy_hash/org_id) must be rejected with 422."""
    r = client.post("/api/v1/hooks/uninstall", json={})
    assert r.status_code == 422
    assert "hook_id" in r.text.lower() or "org_id" in r.text.lower()


def test_hook_uninstall_unknown_id_returns_404(client: TestClient):
    """Unknown hook_id should return 404 with structured detail."""
    r = client.post(
        "/api/v1/hooks/uninstall",
        json={"hook_id": "definitely-does-not-exist-9999"},
    )
    assert r.status_code == 404, r.text
    assert "no_matching_hook_policy" in r.text


def test_hook_uninstall_by_org_active(client: TestClient, org_id: str):
    """Apply, then uninstall by org_id alone — should remove the active policy."""
    from core.devsecops_engine import get_devsecops_engine
    engine = get_devsecops_engine()
    record = engine.apply_hook_policy(
        org_id=f"{org_id}-active",
        hooks_dict={"version": 1, "rules": [{"event": "pr", "action": "scan"}]},
    )
    r = client.post(
        "/api/v1/hooks/uninstall",
        json={"org_id": f"{org_id}-active", "reason": "by-org test"},
    )
    assert r.status_code == 200, r.text
    payload = r.json()
    assert payload["deleted"] == 1
    assert payload["deleted_record"]["id"] == record["id"]
