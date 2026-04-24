"""GAP-065 — Architecture-aware graph tests.

Covers:
  - classify_layer heuristics on 5 sample paths (data/api/ui/standalone/service)
  - confidence bounds 0..1
  - UNIQUE upsert on (org_id, node_ref)
  - link_to_layer on api_discovery + data_discovery
  - trace_flow returns layer per hop
  - boundary_crossings detected between 3 layers
  - org_id isolation
  - endpoint smoke
"""

from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.api_discovery_engine import APIDiscoveryEngine
from core.arch_flow_tracer import trace_flow
from core.data_discovery_engine import DataDiscoveryEngine
from core.security_dependency_mapping_engine import SecurityDependencyMappingEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def dep_engine(tmp_path):
    return SecurityDependencyMappingEngine(db_path=str(tmp_path / "dep.db"))


@pytest.fixture
def api_engine(tmp_path):
    return APIDiscoveryEngine(db_path=str(tmp_path / "api.db"))


@pytest.fixture
def data_engine(tmp_path):
    return DataDiscoveryEngine(db_path=str(tmp_path / "data.db"))


@pytest.fixture
def shared_dep_engine(tmp_path, monkeypatch):
    """Shared dep engine that both api/data discovery will write into.

    We patch the class so `link_to_layer` constructs a SecurityDependencyMappingEngine()
    pointing at our tmp_path db (instead of the default .fixops_data path).
    """
    db_path = str(tmp_path / "shared_dep.db")
    shared = SecurityDependencyMappingEngine(db_path=db_path)

    from core import api_discovery_engine as ade
    from core import data_discovery_engine as dde
    from core import security_dependency_mapping_engine as sdme

    orig_cls = sdme.SecurityDependencyMappingEngine

    class _PinnedEngine(orig_cls):
        def __init__(self, db_path=db_path):
            super().__init__(db_path=db_path)

    monkeypatch.setattr(sdme, "SecurityDependencyMappingEngine", _PinnedEngine)
    # api_discovery + data_discovery import at call site, so the monkeypatch
    # above is sufficient because link_to_layer uses
    # `from core.security_dependency_mapping_engine import SecurityDependencyMappingEngine`.
    return shared


# ---------------------------------------------------------------------------
# classify_layer — 5 sample paths + confidence bounds
# ---------------------------------------------------------------------------


def test_classify_data_layer_from_path(dep_engine):
    res = dep_engine.classify_layer(node_ref="core/database/user_orm.py")
    assert res["layer"] == "data"
    assert 0.0 <= res["confidence"] <= 1.0
    assert any("path_keyword" in s for s in res["signals"])


def test_classify_api_layer_from_path(dep_engine):
    res = dep_engine.classify_layer(node_ref="apps/api/user_router.py")
    assert res["layer"] == "api"
    assert 0.0 <= res["confidence"] <= 1.0


def test_classify_ui_layer_from_path(dep_engine):
    res = dep_engine.classify_layer(node_ref="frontend/components/Header.tsx")
    assert res["layer"] == "ui"
    assert 0.0 <= res["confidence"] <= 1.0


def test_classify_standalone_no_importers(dep_engine):
    res = dep_engine.classify_layer(
        node_ref="tools/migrate_helper",
        context={"imports": ["os", "sys"], "importers": []},
    )
    assert res["layer"] == "standalone"
    assert 0.0 <= res["confidence"] <= 1.0


def test_classify_service_both_imports_and_importers(dep_engine):
    res = dep_engine.classify_layer(
        node_ref="core/business_logic",
        context={"imports": ["x"], "importers": ["y"]},
    )
    assert res["layer"] == "service"
    assert 0.0 <= res["confidence"] <= 1.0


def test_classify_migrations_is_data(dep_engine):
    res = dep_engine.classify_layer(node_ref="backend/migrations/001_init.sql")
    assert res["layer"] == "data"


def test_classify_confidence_within_bounds(dep_engine):
    # Run many classifications and assert confidence always in [0,1]
    samples = [
        "x/db/y.py",
        "api/z.py",
        "components/A.tsx",
        "isolated_tool",
        "",
    ]
    for s in samples:
        if not s:
            with pytest.raises(ValueError):
                dep_engine.classify_layer(node_ref=s)
            continue
        res = dep_engine.classify_layer(node_ref=s)
        assert 0.0 <= res["confidence"] <= 1.0


def test_classify_topology_boost_api_with_importers(dep_engine):
    res = dep_engine.classify_layer(
        node_ref="apps/api/user_router.py",
        context={"imports": ["db"], "importers": ["main"]},
    )
    assert res["layer"] == "api"
    # Expect boost applied
    assert any("topology_boost" in s for s in res["signals"])


# ---------------------------------------------------------------------------
# UNIQUE upsert on (org_id, node_ref)
# ---------------------------------------------------------------------------


def test_classify_upsert_same_org_node(dep_engine):
    r1 = dep_engine.classify_layer(node_ref="apps/api/x.py", org_id="org1")
    r2 = dep_engine.classify_layer(node_ref="apps/api/x.py", org_id="org1")
    all_rows = dep_engine.list_classifications("org1")
    # Only one row per (org_id, node_ref)
    matching = [r for r in all_rows if r["node_ref"] == "apps/api/x.py"]
    assert len(matching) == 1
    assert r2["layer"] == r1["layer"]


def test_classify_multiple_orgs_isolated(dep_engine):
    dep_engine.classify_layer(node_ref="apps/api/x.py", org_id="orgA")
    dep_engine.classify_layer(node_ref="apps/api/x.py", org_id="orgB")
    a = dep_engine.list_classifications("orgA")
    b = dep_engine.list_classifications("orgB")
    assert len(a) == 1
    assert len(b) == 1
    # Re-classify orgA same node — should still be 1 row for orgA
    dep_engine.classify_layer(node_ref="apps/api/x.py", org_id="orgA")
    a2 = dep_engine.list_classifications("orgA")
    assert len(a2) == 1


def test_upsert_layer_explicit(dep_engine):
    rec = dep_engine.upsert_layer(
        org_id="org1", node_ref="custom:endpoint:/foo", layer="api", confidence=0.95,
    )
    assert rec["layer"] == "api"
    fetched = dep_engine.get_layer("org1", "custom:endpoint:/foo")
    assert fetched is not None
    assert fetched["layer"] == "api"


def test_upsert_layer_invalid_layer(dep_engine):
    with pytest.raises(ValueError):
        dep_engine.upsert_layer(org_id="org1", node_ref="x", layer="invalid")


def test_upsert_layer_requires_node_ref(dep_engine):
    with pytest.raises(ValueError):
        dep_engine.upsert_layer(org_id="org1", node_ref="", layer="api")


def test_classify_requires_node_ref(dep_engine):
    with pytest.raises(ValueError):
        dep_engine.classify_layer(node_ref="")


def test_list_classifications_filter_by_layer(dep_engine):
    dep_engine.classify_layer(node_ref="api/a.py", org_id="o1")
    dep_engine.classify_layer(node_ref="db/b.py", org_id="o1")
    dep_engine.classify_layer(node_ref="ui/c.tsx", org_id="o1")
    api_only = dep_engine.list_classifications("o1", layer="api")
    assert all(r["layer"] == "api" for r in api_only)
    assert len(api_only) == 1


def test_get_layer_missing_returns_none(dep_engine):
    assert dep_engine.get_layer("org1", "nonexistent") is None


# ---------------------------------------------------------------------------
# link_to_layer — api_discovery + data_discovery
# ---------------------------------------------------------------------------


def test_api_discovery_link_to_layer(shared_dep_engine, api_engine):
    rec = api_engine.link_to_layer(org_id="org1", endpoint_path="/api/v1/users", layer="api")
    assert rec["linked"] is True
    assert rec["layer"] == "api"
    # Verify it was persisted in the dep-mapping classifications
    fetched = shared_dep_engine.get_layer("org1", "/api/v1/users")
    assert fetched is not None
    assert fetched["layer"] == "api"


def test_data_discovery_link_to_layer(shared_dep_engine, data_engine):
    rec = data_engine.link_to_layer(
        org_id="org1", datastore_ref="prod-users-db", layer="data",
    )
    assert rec["linked"] is True
    assert rec["layer"] == "data"
    fetched = shared_dep_engine.get_layer("org1", "prod-users-db")
    assert fetched is not None
    assert fetched["layer"] == "data"


def test_link_to_layer_requires_ref(api_engine, data_engine):
    with pytest.raises(ValueError):
        api_engine.link_to_layer(org_id="org1", endpoint_path="", layer="api")
    with pytest.raises(ValueError):
        data_engine.link_to_layer(org_id="org1", datastore_ref="", layer="data")


# ---------------------------------------------------------------------------
# trace_flow — layer per hop + boundary crossings
# ---------------------------------------------------------------------------


def _build_layered_graph(dep_engine, org_id="org1"):
    """Build a 3-layer graph: ui → api → service → data."""
    ui = dep_engine.register_service(org_id=org_id, service_name="frontend/components/dashboard")
    api = dep_engine.register_service(org_id=org_id, service_name="apps/api/users_router")
    svc = dep_engine.register_service(org_id=org_id, service_name="business/user_service")
    db = dep_engine.register_service(org_id=org_id, service_name="core/database/user_orm")
    dep_engine.add_dependency(
        org_id=org_id, source_service_id=ui["id"], target_service_id=api["id"],
    )
    dep_engine.add_dependency(
        org_id=org_id, source_service_id=api["id"], target_service_id=svc["id"],
    )
    dep_engine.add_dependency(
        org_id=org_id, source_service_id=svc["id"], target_service_id=db["id"],
    )
    return {"ui": ui, "api": api, "svc": svc, "db": db}


def test_trace_flow_returns_layer_per_hop(tmp_path, monkeypatch):
    db = str(tmp_path / "dep.db")
    dep = SecurityDependencyMappingEngine(db_path=db)

    from core import arch_flow_tracer as aft

    def _pinned():
        return SecurityDependencyMappingEngine(db_path=db)

    monkeypatch.setattr(aft, "_get_engine", _pinned)

    nodes = _build_layered_graph(dep, org_id="org1")

    result = trace_flow(org_id="org1", start_ref=nodes["ui"]["id"], max_hops=5)
    assert result["resolved"] is True
    assert len(result["path"]) >= 1
    for hop in result["path"]:
        assert "layer" in hop
        assert "depth" in hop
        assert hop["layer"] in {"data", "api", "ui", "service", "standalone"}


def test_trace_flow_boundary_crossings_detected(tmp_path, monkeypatch):
    db = str(tmp_path / "dep.db")
    dep = SecurityDependencyMappingEngine(db_path=db)

    from core import arch_flow_tracer as aft
    monkeypatch.setattr(
        aft, "_get_engine", lambda: SecurityDependencyMappingEngine(db_path=db),
    )

    nodes = _build_layered_graph(dep, org_id="org1")
    result = trace_flow(org_id="org1", start_ref=nodes["ui"]["id"], max_hops=5)
    # Expect at least 2 boundary crossings across 3+ distinct layers
    layers = {h["layer"] for h in result["path"]}
    assert len(layers) >= 3
    assert len(result["boundary_crossings"]) >= 2
    for xing in result["boundary_crossings"]:
        assert xing["from_layer"] != xing["to_layer"]
        assert "from_node" in xing and "to_node" in xing


def test_trace_flow_max_hops_clamped(tmp_path, monkeypatch):
    db = str(tmp_path / "dep.db")
    dep = SecurityDependencyMappingEngine(db_path=db)
    from core import arch_flow_tracer as aft
    monkeypatch.setattr(
        aft, "_get_engine", lambda: SecurityDependencyMappingEngine(db_path=db),
    )
    nodes = _build_layered_graph(dep, org_id="org1")
    # Hop=1 should only include start + neighbors at depth 1
    result = trace_flow(org_id="org1", start_ref=nodes["ui"]["id"], max_hops=1)
    depths = {h["depth"] for h in result["path"]}
    assert max(depths) <= 1


def test_trace_flow_requires_start(tmp_path, monkeypatch):
    db = str(tmp_path / "dep.db")
    SecurityDependencyMappingEngine(db_path=db)
    from core import arch_flow_tracer as aft
    monkeypatch.setattr(
        aft, "_get_engine", lambda: SecurityDependencyMappingEngine(db_path=db),
    )
    with pytest.raises(ValueError):
        trace_flow(org_id="org1", start_ref="", max_hops=5)


def test_trace_flow_unresolvable_classifies_only(tmp_path, monkeypatch):
    db = str(tmp_path / "dep.db")
    SecurityDependencyMappingEngine(db_path=db)
    from core import arch_flow_tracer as aft
    monkeypatch.setattr(
        aft, "_get_engine", lambda: SecurityDependencyMappingEngine(db_path=db),
    )
    result = trace_flow(org_id="org1", start_ref="no/such/service", max_hops=3)
    assert result["resolved"] is False
    assert len(result["path"]) == 1
    assert result["path"][0]["layer"] in {"data", "api", "ui", "service", "standalone"}
    assert result["boundary_crossings"] == []


def test_trace_flow_org_isolation(tmp_path, monkeypatch):
    db = str(tmp_path / "dep.db")
    dep = SecurityDependencyMappingEngine(db_path=db)
    from core import arch_flow_tracer as aft
    monkeypatch.setattr(
        aft, "_get_engine", lambda: SecurityDependencyMappingEngine(db_path=db),
    )
    nodes_a = _build_layered_graph(dep, org_id="orgA")
    _ = _build_layered_graph(dep, org_id="orgB")
    # Walk from orgA's ui — should not traverse orgB
    res_a = trace_flow(org_id="orgA", start_ref=nodes_a["ui"]["id"], max_hops=5)
    node_ids = {h.get("node_id") for h in res_a["path"] if "node_id" in h}
    # All visited node_ids must belong to orgA — verify by re-querying
    with dep._conn() as conn:
        for nid in node_ids:
            if nid is None:
                continue
            row = conn.execute(
                "SELECT org_id FROM services WHERE id=?", (nid,)
            ).fetchone()
            assert row["org_id"] == "orgA"


def test_trace_flow_hard_cap_enforced(tmp_path, monkeypatch):
    db = str(tmp_path / "dep.db")
    dep = SecurityDependencyMappingEngine(db_path=db)
    from core import arch_flow_tracer as aft
    monkeypatch.setattr(
        aft, "_get_engine", lambda: SecurityDependencyMappingEngine(db_path=db),
    )
    nodes = _build_layered_graph(dep, org_id="org1")
    # Request huge max_hops — should clamp silently to 25
    res = trace_flow(org_id="org1", start_ref=nodes["ui"]["id"], max_hops=9999)
    assert res["resolved"] is True


# ---------------------------------------------------------------------------
# org_id isolation — classification table
# ---------------------------------------------------------------------------


def test_classification_org_isolation(dep_engine):
    dep_engine.classify_layer(node_ref="api/x.py", org_id="orgA")
    dep_engine.classify_layer(node_ref="api/y.py", org_id="orgB")
    a = dep_engine.list_classifications("orgA")
    b = dep_engine.list_classifications("orgB")
    assert len(a) == 1 and a[0]["node_ref"] == "api/x.py"
    assert len(b) == 1 and b[0]["node_ref"] == "api/y.py"


def test_list_classifications_empty(dep_engine):
    assert dep_engine.list_classifications("nonexistent-org") == []


# ---------------------------------------------------------------------------
# Router smoke tests
# ---------------------------------------------------------------------------


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Build a minimal FastAPI app with just the arch_graph_router mounted."""
    # Patch the auth dependency to a no-op
    from apps.api import auth_deps
    async def _noop():
        return "test-key"
    monkeypatch.setattr(auth_deps, "api_key_auth", _noop)

    # Ensure engines use tmp db paths
    dep_db = str(tmp_path / "dep.db")
    api_db = str(tmp_path / "api.db")
    data_db = str(tmp_path / "data.db")

    from core import security_dependency_mapping_engine as sdme
    from core import api_discovery_engine as ade
    from core import data_discovery_engine as dde
    from core import arch_flow_tracer as aft

    orig_sdme = sdme.SecurityDependencyMappingEngine
    orig_ade = ade.APIDiscoveryEngine
    orig_dde = dde.DataDiscoveryEngine

    class _PinnedDep(orig_sdme):
        def __init__(self, db_path=dep_db):
            super().__init__(db_path=db_path)

    class _PinnedApi(orig_ade):
        def __init__(self, db_path=api_db):
            super().__init__(db_path=db_path)

    class _PinnedData(orig_dde):
        def __init__(self, db_path=data_db):
            super().__init__(db_path=db_path)

    monkeypatch.setattr(sdme, "SecurityDependencyMappingEngine", _PinnedDep)
    monkeypatch.setattr(ade, "APIDiscoveryEngine", _PinnedApi)
    monkeypatch.setattr(dde, "DataDiscoveryEngine", _PinnedData)
    monkeypatch.setattr(aft, "_get_engine", lambda: _PinnedDep())

    # Reload router so it picks up patched engines
    import importlib
    from apps.api import arch_graph_router
    importlib.reload(arch_graph_router)

    app = FastAPI()
    app.include_router(arch_graph_router.router)
    return TestClient(app)


def test_endpoint_classify(client):
    r = client.post(
        "/api/v1/arch-graph/classify",
        json={"node_ref": "apps/api/users_router.py"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["layer"] == "api"
    assert 0.0 <= body["confidence"] <= 1.0


def test_endpoint_classifications_list(client):
    client.post(
        "/api/v1/arch-graph/classify",
        json={"node_ref": "apps/api/a.py"},
    )
    r = client.get("/api/v1/arch-graph/classifications?layer=api")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_endpoint_link_api(client):
    r = client.post(
        "/api/v1/arch-graph/link-api",
        json={"endpoint_path": "/api/v1/users", "layer": "api"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["layer"] == "api"


def test_endpoint_link_datastore(client):
    r = client.post(
        "/api/v1/arch-graph/link-datastore",
        json={"datastore_ref": "users-db", "layer": "data"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["layer"] == "data"


def test_endpoint_trace_flow_unresolved(client):
    r = client.post(
        "/api/v1/arch-graph/trace-flow",
        json={"start_ref": "nonexistent-service", "max_hops": 3},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["resolved"] is False
    assert len(body["path"]) == 1


def test_endpoint_classify_invalid_body(client):
    r = client.post("/api/v1/arch-graph/classify", json={})
    assert r.status_code == 422


def test_endpoint_classifications_invalid_layer(client):
    r = client.get("/api/v1/arch-graph/classifications?layer=bogus")
    assert r.status_code == 422


def test_endpoint_trace_flow_max_hops_validation(client):
    r = client.post(
        "/api/v1/arch-graph/trace-flow",
        json={"start_ref": "x", "max_hops": 0},
    )
    assert r.status_code == 422


def test_endpoint_link_api_requires_path(client):
    r = client.post(
        "/api/v1/arch-graph/link-api",
        json={"endpoint_path": "", "layer": "api"},
    )
    assert r.status_code == 422
