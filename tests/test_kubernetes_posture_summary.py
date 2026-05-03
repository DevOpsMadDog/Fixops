"""
Tests for GET /api/v1/kubernetes-security (posture summary endpoint).

Covers: empty-org baseline, single cluster, finding aggregation,
org isolation, critical-only count, avg_cis_score calculation.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# App fixture — isolated engine per test via monkeypatch
# ---------------------------------------------------------------------------

@pytest.fixture()
def client(tmp_path, monkeypatch):
    """Build a TestClient with a fresh in-process engine backed by tmp_path."""
    from core.kubernetes_security_engine import KubernetesSecurityEngine
    fresh_engine = KubernetesSecurityEngine(db_path=str(tmp_path / "k8s_test.db"))

    import apps.api.kubernetes_security_router as router_mod
    monkeypatch.setattr(router_mod, "_engine", fresh_engine)

    from fastapi import FastAPI
    from apps.api.kubernetes_security_router import router
    app = FastAPI()
    app.include_router(router)

    # Bypass API key auth for tests
    from apps.api.auth_deps import api_key_auth
    app.dependency_overrides[api_key_auth] = lambda: True

    return TestClient(app)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _register_cluster(client, org_id: str = "org-test") -> str:
    r = client.post(
        "/api/v1/kubernetes-security/clusters",
        params={"org_id": org_id},
        json={
            "cluster_name": "ci-cluster",
            "provider": "eks",
            "k8s_version": "1.29",
            "node_count": 3,
            "namespace_count": 4,
        },
    )
    assert r.status_code == 201
    return r.json()["id"]


def _record_finding(client, cluster_id: str, severity: str = "critical", org_id: str = "org-test") -> dict:
    r = client.post(
        "/api/v1/kubernetes-security/findings",
        params={"org_id": org_id},
        json={
            "cluster_id": cluster_id,
            "finding_type": "privileged_container",
            "severity": severity,
            "namespace": "kube-system",
            "resource_name": "busybox",
            "resource_type": "Pod",
            "description": "Privileged container",
            "remediation": "Remove securityContext.privileged",
        },
    )
    assert r.status_code == 201
    return r.json()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestKubernetesPostureSummary:
    def test_empty_org_returns_zeros(self, client):
        r = client.get("/api/v1/kubernetes-security/", params={"org_id": "empty-org"})
        assert r.status_code == 200
        body = r.json()
        assert body["total_clusters"] == 0
        assert body["total_findings"] == 0
        assert body["critical_open"] == 0
        assert body["avg_cis_score"] == 100.0

    def test_single_cluster_counted(self, client):
        _register_cluster(client, "org-a")
        r = client.get("/api/v1/kubernetes-security/", params={"org_id": "org-a"})
        assert r.status_code == 200
        assert r.json()["total_clusters"] == 1

    def test_critical_finding_reflected(self, client):
        cid = _register_cluster(client, "org-b")
        _record_finding(client, cid, severity="critical", org_id="org-b")
        r = client.get("/api/v1/kubernetes-security/", params={"org_id": "org-b"})
        body = r.json()
        assert body["critical_open"] == 1
        assert body["total_findings"] == 1

    def test_cis_score_degrades_with_open_findings(self, client):
        cid = _register_cluster(client, "org-c")
        _record_finding(client, cid, severity="high", org_id="org-c")
        _record_finding(client, cid, severity="medium", org_id="org-c")
        r = client.get("/api/v1/kubernetes-security/", params={"org_id": "org-c"})
        score = r.json()["avg_cis_score"]
        assert score < 100.0, "CIS score must drop when open findings exist"
        assert score >= 0.0

    def test_org_isolation(self, client):
        cid = _register_cluster(client, "org-d")
        _record_finding(client, cid, severity="critical", org_id="org-d")

        # org-e should see no data
        r = client.get("/api/v1/kubernetes-security/", params={"org_id": "org-e"})
        body = r.json()
        assert body["total_clusters"] == 0
        assert body["total_findings"] == 0

    def test_simulation_warning_present(self, client):
        r = client.get("/api/v1/kubernetes-security/", params={"org_id": "org-f"})
        assert r.status_code == 200
        warn = r.json().get("_simulation_warning", {})
        assert warn.get("is_simulated") is True
