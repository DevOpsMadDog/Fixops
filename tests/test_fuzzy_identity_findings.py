"""Tests for fuzzy_identity_router /findings endpoint — real engine wiring."""
from __future__ import annotations

import sys
import os

import pytest
from fastapi.testclient import TestClient

# Ensure suite paths are on sys.path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-api"))


@pytest.fixture()
def client(tmp_path):
    """Isolated TestClient with an in-memory fuzzy identity resolver."""
    from fastapi import FastAPI
    from core.services.fuzzy_identity import FuzzyIdentityResolver

    # Reset singleton so each test gets a fresh DB
    FuzzyIdentityResolver.reset_instance()
    db_path = str(tmp_path / "fuzzy_test.db")

    import core.services.fuzzy_identity as _fi_mod
    original_get = _fi_mod.get_fuzzy_resolver

    def _patched_get(**_kwargs):
        return FuzzyIdentityResolver.get_instance(db_path=db_path)

    _fi_mod.get_fuzzy_resolver = _patched_get

    # Patch the router module's import too
    import apps.api.fuzzy_identity_router as _router_mod
    _router_mod.get_fuzzy_resolver = _patched_get

    app = FastAPI()
    from apps.api.fuzzy_identity_router import router
    app.include_router(router)

    yield TestClient(app)

    # Restore
    _fi_mod.get_fuzzy_resolver = original_get
    _router_mod.get_fuzzy_resolver = original_get
    FuzzyIdentityResolver.reset_instance()


def _seed(client, canonical_id: str, aliases: list[str], org_id: str = "test-org"):
    """Register a canonical asset and add aliases."""
    r = client.post("/api/v1/identity/canonical", json={"canonical_id": canonical_id, "org_id": org_id})
    assert r.status_code == 200, r.text
    for alias in aliases:
        r2 = client.post(
            "/api/v1/identity/alias",
            json={"canonical_id": canonical_id, "alias_name": alias, "source": "scanner"},
        )
        assert r2.status_code == 200, r2.text


class TestFindingsEndpointBasic:
    def test_empty_returns_ok(self, client):
        r = client.get("/api/v1/identity/findings")
        assert r.status_code == 200
        body = r.json()
        assert "findings" in body
        assert "total" in body
        assert "stats" in body
        assert body["engine"] == "fuzzy-identity"

    def test_no_findings_when_no_aliases(self, client):
        _seed(client, "server-001", [])
        r = client.get("/api/v1/identity/findings?min_aliases=2")
        assert r.status_code == 200
        assert r.json()["total"] == 0

    def test_finding_returned_for_multi_alias_asset(self, client):
        _seed(client, "db-prod", ["database-prod", "prod-db", "db_production"])
        r = client.get("/api/v1/identity/findings?min_aliases=2")
        assert r.status_code == 200
        body = r.json()
        assert body["total"] >= 1
        finding = body["findings"][0]
        assert finding["canonical_id"] == "db-prod"
        assert finding["alias_count"] >= 3
        assert "aliases" in finding
        assert "severity" in finding
        assert "description" in finding

    def test_severity_low_for_two_aliases(self, client):
        _seed(client, "app-svc", ["application-service", "app-service"])
        r = client.get("/api/v1/identity/findings?min_aliases=2")
        assert r.status_code == 200
        findings = r.json()["findings"]
        match = next((f for f in findings if f["canonical_id"] == "app-svc"), None)
        assert match is not None
        assert match["severity"] == "low"

    def test_severity_medium_for_three_aliases(self, client):
        _seed(client, "web-srv", ["web-server", "webserver", "http-srv"])
        r = client.get("/api/v1/identity/findings?min_aliases=2")
        assert r.status_code == 200
        findings = r.json()["findings"]
        match = next((f for f in findings if f["canonical_id"] == "web-srv"), None)
        assert match is not None
        assert match["severity"] == "medium"

    def test_severity_high_for_five_plus_aliases(self, client):
        _seed(client, "k8s-node", ["k8s-node-1", "node1", "worker-1", "kube-worker", "k8s-worker-1"])
        r = client.get("/api/v1/identity/findings?min_aliases=2")
        assert r.status_code == 200
        findings = r.json()["findings"]
        match = next((f for f in findings if f["canonical_id"] == "k8s-node"), None)
        assert match is not None
        assert match["severity"] == "high"

    def test_sorted_by_alias_count_descending(self, client):
        _seed(client, "low-conf", ["alias-a", "alias-b"])
        _seed(client, "high-conf", ["x", "y", "z", "w", "v"])
        r = client.get("/api/v1/identity/findings?min_aliases=2")
        assert r.status_code == 200
        findings = r.json()["findings"]
        counts = [f["alias_count"] for f in findings]
        assert counts == sorted(counts, reverse=True)

    def test_min_aliases_filter_respected(self, client):
        _seed(client, "asset-a", ["alias-1", "alias-2"])
        _seed(client, "asset-b", ["alias-x", "alias-y", "alias-z"])
        r = client.get("/api/v1/identity/findings?min_aliases=3")
        assert r.status_code == 200
        findings = r.json()["findings"]
        assert all(f["alias_count"] >= 3 for f in findings)
        cids = [f["canonical_id"] for f in findings]
        assert "asset-b" in cids
        assert "asset-a" not in cids
