"""Router-level HTTP tests for kube-bench CIS Kubernetes Benchmark capability API.

Covers /api/v1/kube-bench/* via FastAPI TestClient with a fresh tmp_path-backed
engine per test (no singleton bleed). NO MOCKS — real KubeBenchScanEngine,
real SQLite, real Pydantic round-trips.

When the kube-bench CLI is absent (the common CI case), the engine records
scans with status="unavailable" rather than fabricating findings — these tests
assert exactly that contract.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

for _p in ["suite-core", "suite-api"]:
    _abs = str(Path(__file__).parent.parent / _p)
    if _abs not in sys.path:
        sys.path.insert(0, _abs)

from core.kube_bench_scan_engine import (  # noqa: E402
    BENCHMARK_VERSIONS,
    STATUS_LEVELS,
    TARGET_NODE_ROLES,
    KubeBenchScanEngine,
)
import apps.api.kube_bench_router as _router_mod  # noqa: E402
from apps.api.kube_bench_router import router  # noqa: E402


@pytest.fixture
def engine(tmp_path):
    return KubeBenchScanEngine(db_path=str(tmp_path / "kube_bench_test.db"))


@pytest.fixture
def client(engine, monkeypatch):
    monkeypatch.setattr(_router_mod, "_get_engine", lambda: engine)

    app = FastAPI()
    app.include_router(router)

    # Override auth so 401s don't fire in unit context
    try:
        from apps.api.auth_deps import api_key_auth as _auth
        app.dependency_overrides[_auth] = lambda: None
    except ImportError:
        pass

    return TestClient(app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# 1. GET /  — empty / unavailable capability summary
# ---------------------------------------------------------------------------

def test_capability_summary_initial(client, engine):
    resp = client.get("/api/v1/kube-bench/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "kube-bench"
    assert body["status_levels"] == ["PASS", "FAIL", "WARN", "INFO"]
    assert body["scan_count"] == 0
    # Either "unavailable" (no kube-bench CLI) or "empty" (CLI present, no scans).
    assert body["status"] in ("unavailable", "empty")
    assert body["binary_present"] is engine.is_kube_bench_available()
    # All required CIS benchmark versions present
    for required in ("cis-1.6", "cis-1.7", "cis-1.8", "cis-1.9", "cis-1.10"):
        assert required in body["benchmarks"]
    # All required target node roles present
    for required in (
        "master",
        "node",
        "etcd",
        "policies",
        "controlplane",
        "managedservices",
    ):
        assert required in body["target_node_roles"]


# ---------------------------------------------------------------------------
# 2. GET /benchmarks — full catalog
# ---------------------------------------------------------------------------

def test_list_benchmarks_returns_full_catalog(client):
    resp = client.get("/api/v1/kube-bench/benchmarks")
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == len(BENCHMARK_VERSIONS)
    assert body["count"] >= 5
    ids = [b["id"] for b in body["benchmarks"]]
    for required in ("cis-1.6", "cis-1.7", "cis-1.8", "cis-1.9", "cis-1.10"):
        assert required in ids
    for entry in body["benchmarks"]:
        assert set(entry.keys()) >= {"id", "name", "default_check_count"}
        assert entry["default_check_count"] > 0
        assert entry["name"].startswith("CIS Kubernetes Benchmark")


# ---------------------------------------------------------------------------
# 3. POST /scan — queues + persists, returns 202 with envelope
# ---------------------------------------------------------------------------

def test_post_scan_queues_and_persists(client, engine):
    resp = client.post(
        "/api/v1/kube-bench/scan",
        json={
            "benchmark_version": "cis-1.10",
            "target_node_role": "master",
        },
    )
    assert resp.status_code == 202
    body = resp.json()
    assert body["benchmark_version"] == "cis-1.10"
    assert body["target_node_role"] == "master"
    assert "scan_id" in body and body["scan_id"]
    assert "queued_at" in body and body["queued_at"]

    # Persisted in SQLite
    persisted = engine.get_scan(body["scan_id"])
    assert persisted is not None
    assert persisted["benchmark_version"] == "cis-1.10"
    assert persisted["target_node_role"] == "master"
    # status will be "completed" (CLI ran), "unavailable" (CLI missing) or
    # "failed" (CLI exited unexpectedly); never "queued" because we run inline.
    assert persisted["status"] in ("completed", "unavailable", "failed")
    # status_counts always has all four keys regardless of run outcome
    assert set(persisted["status_counts"].keys()) >= set(STATUS_LEVELS)
    # findings is always a list (no fake findings on unavailable)
    assert isinstance(persisted["findings"], list)
    assert isinstance(persisted["total_checks"], int)


# ---------------------------------------------------------------------------
# 4. POST /scan — defaults applied when fields omitted
# ---------------------------------------------------------------------------

def test_post_scan_defaults_when_omitted(client, engine):
    resp = client.post("/api/v1/kube-bench/scan", json={})
    assert resp.status_code == 202
    body = resp.json()
    # Default benchmark = newest
    assert body["benchmark_version"] in BENCHMARK_VERSIONS
    assert body["benchmark_version"] == "cis-1.10"
    # Default role = node
    assert body["target_node_role"] == "node"
    persisted = engine.get_scan(body["scan_id"])
    assert persisted is not None
    assert persisted["target_node_role"] == "node"


# ---------------------------------------------------------------------------
# 5. POST /scan — bad benchmark_version → 422
# ---------------------------------------------------------------------------

def test_post_scan_invalid_benchmark_returns_422(client):
    resp = client.post(
        "/api/v1/kube-bench/scan",
        json={"benchmark_version": "cis-99.99"},
    )
    assert resp.status_code == 422
    assert "benchmark_version" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# 6. POST /scan — bad target_node_role → 422
# ---------------------------------------------------------------------------

def test_post_scan_invalid_role_returns_422(client):
    resp = client.post(
        "/api/v1/kube-bench/scan",
        json={"target_node_role": "edge-router"},
    )
    assert resp.status_code == 422
    assert "target_node_role" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# 7. GET /scan/{scan_id} — fetch existing record
# ---------------------------------------------------------------------------

def test_get_scan_returns_record(client, engine):
    queued = client.post(
        "/api/v1/kube-bench/scan",
        json={"benchmark_version": "cis-1.9", "target_node_role": "etcd"},
    )
    assert queued.status_code == 202
    scan_id = queued.json()["scan_id"]

    fetched = client.get(f"/api/v1/kube-bench/scan/{scan_id}")
    assert fetched.status_code == 200
    body = fetched.json()
    assert body["scan_id"] == scan_id
    assert body["benchmark_version"] == "cis-1.9"
    assert body["target_node_role"] == "etcd"
    assert body["status"] in ("completed", "unavailable", "failed")
    # status_counts always populated with PASS/FAIL/WARN/INFO
    assert set(body["status_counts"].keys()) >= set(STATUS_LEVELS)
    # findings is always a list
    assert isinstance(body["findings"], list)
    assert isinstance(body["total_checks"], int)


# ---------------------------------------------------------------------------
# 8. GET /scan/{scan_id} — unknown id → 404
# ---------------------------------------------------------------------------

def test_get_scan_unknown_returns_404(client):
    resp = client.get("/api/v1/kube-bench/scan/does-not-exist")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# 9. Capability summary flips to "ok" or "unavailable" after a scan
# ---------------------------------------------------------------------------

def test_capability_summary_after_scan(client, engine):
    queued = client.post(
        "/api/v1/kube-bench/scan",
        json={"benchmark_version": "cis-1.8", "target_node_role": "policies"},
    )
    assert queued.status_code == 202

    resp = client.get("/api/v1/kube-bench/")
    assert resp.status_code == 200
    body = resp.json()
    # scan_count incremented
    assert body["scan_count"] == 1
    # status: ok if binary present, unavailable otherwise
    if body["binary_present"]:
        assert body["status"] == "ok"
    else:
        assert body["status"] == "unavailable"


# ---------------------------------------------------------------------------
# 10. Engine round-trip (no HTTP) — schema + record persistence
# ---------------------------------------------------------------------------

def test_engine_round_trip(engine):
    assert engine.count_scans() == 0
    queued = engine.queue_scan(
        benchmark_version="cis-1.7",
        target_node_role="controlplane",
    )
    assert queued["benchmark_version"] == "cis-1.7"
    assert queued["target_node_role"] == "controlplane"
    assert queued["scan_id"]

    assert engine.count_scans() == 1

    record = engine.get_scan(queued["scan_id"])
    assert record is not None
    assert record["status"] in ("completed", "unavailable", "failed")
    # benchmarks catalog still reachable
    benchmarks = engine.list_benchmarks()
    assert len(benchmarks) == len(BENCHMARK_VERSIONS)
    assert all("default_check_count" in b for b in benchmarks)


# ---------------------------------------------------------------------------
# 11. All target node roles accepted
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("role", TARGET_NODE_ROLES)
def test_all_node_roles_accepted(client, role):
    resp = client.post(
        "/api/v1/kube-bench/scan",
        json={"target_node_role": role},
    )
    assert resp.status_code == 202
    assert resp.json()["target_node_role"] == role


# ---------------------------------------------------------------------------
# 12. All benchmark versions accepted
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("ver", BENCHMARK_VERSIONS)
def test_all_benchmark_versions_accepted(client, ver):
    resp = client.post(
        "/api/v1/kube-bench/scan",
        json={"benchmark_version": ver},
    )
    assert resp.status_code == 202
    assert resp.json()["benchmark_version"] == ver
