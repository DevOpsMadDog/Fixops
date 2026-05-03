"""Tests for cloud_security_router — POST/GET accounts, findings, resources, benchmarks, stats."""
import sys
import pytest

sys.path.insert(0, "/Users/devops.ai/fixops/Fixops/suite-core")
sys.path.insert(0, "/Users/devops.ai/fixops/Fixops/suite-api")

from fastapi.testclient import TestClient
from fastapi import FastAPI

# ---- minimal app fixture ----
@pytest.fixture(scope="module")
def client(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("cloud_sec_db")
    # Patch DB dir so tests don't pollute production data
    import core.cloud_security_engine as cse_mod
    cse_mod._DEFAULT_DB_DIR = tmp

    from apps.api.cloud_security_router import router, _get_engine
    _get_engine.cache_clear()

    app = FastAPI()

    # Bypass auth
    from apps.api.auth_deps import api_key_auth
    app.dependency_overrides[api_key_auth] = lambda: None

    from apps.api.dependencies import get_org_id
    app.dependency_overrides[get_org_id] = lambda: "test-org"

    app.include_router(router)
    return TestClient(app)


def test_add_account(client):
    r = client.post("/api/v1/cloud-security/accounts", json={
        "account_id": "123456789012",
        "account_name": "prod-aws",
        "provider": "aws",
        "region": "us-east-1",
    })
    assert r.status_code == 201
    body = r.json()
    assert body["account_id"] == "123456789012"
    assert body["provider"] == "aws"
    assert "id" in body


def test_list_accounts(client):
    r = client.get("/api/v1/cloud-security/accounts")
    assert r.status_code == 200
    items = r.json()
    assert isinstance(items, list)
    assert any(a["account_id"] == "123456789012" for a in items)


def test_list_accounts_filter_provider(client):
    r = client.get("/api/v1/cloud-security/accounts?provider=aws")
    assert r.status_code == 200
    for a in r.json():
        assert a["provider"] == "aws"


def test_add_finding(client):
    r = client.post("/api/v1/cloud-security/findings", json={
        "account_id": "123456789012",
        "severity": "high",
        "category": "iam",
        "title": "Over-privileged role",
        "compliance_frameworks": ["CIS AWS 1.5"],
    })
    assert r.status_code == 201
    body = r.json()
    assert body["severity"] == "high"
    assert body["category"] == "iam"
    assert "id" in body


def test_list_findings(client):
    r = client.get("/api/v1/cloud-security/findings")
    assert r.status_code == 200
    items = r.json()
    assert isinstance(items, list)
    assert len(items) >= 1


def test_list_findings_filter_severity(client):
    r = client.get("/api/v1/cloud-security/findings?severity=high")
    assert r.status_code == 200
    for f in r.json():
        assert f["severity"] == "high"


def test_resolve_finding(client):
    # Create a finding then resolve it
    cr = client.post("/api/v1/cloud-security/findings", json={
        "account_id": "123456789012",
        "severity": "medium",
        "category": "network",
        "title": "SG open to 0.0.0.0/0",
    })
    assert cr.status_code == 201
    fid = cr.json()["id"]
    rr = client.post(f"/api/v1/cloud-security/findings/{fid}/resolve")
    assert rr.status_code == 200
    assert rr.json()["status"] == "resolved"


def test_resolve_finding_404(client):
    r = client.post("/api/v1/cloud-security/findings/nonexistent-id/resolve")
    assert r.status_code == 404


def test_add_resource(client):
    r = client.post("/api/v1/cloud-security/resources", json={
        "account_id": "123456789012",
        "resource_id": "bucket-aldeci-logs",
        "resource_type": "s3_bucket",
        "is_public": False,
        "is_encrypted": True,
    })
    assert r.status_code == 201
    body = r.json()
    assert body["resource_id"] == "bucket-aldeci-logs"
    assert body["is_public"] is False


def test_list_resources(client):
    r = client.get("/api/v1/cloud-security/resources")
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_add_benchmark(client):
    r = client.post("/api/v1/cloud-security/benchmarks", json={
        "account_id": "123456789012",
        "benchmark": "cis_aws_v1.5",
        "score": 78.5,
        "controls_passed": 47,
        "controls_failed": 13,
        "controls_total": 60,
    })
    assert r.status_code == 201
    body = r.json()
    assert body["benchmark"] == "cis_aws_v1.5"
    assert body["score"] == 78.5


def test_list_benchmarks(client):
    r = client.get("/api/v1/cloud-security/benchmarks")
    assert r.status_code == 200
    items = r.json()
    assert isinstance(items, list)
    assert len(items) >= 1


def test_get_stats(client):
    r = client.get("/api/v1/cloud-security/stats")
    assert r.status_code == 200
    body = r.json()
    assert "total_accounts" in body or "accounts" in body or isinstance(body, dict)


def test_add_account_invalid_provider(client):
    r = client.post("/api/v1/cloud-security/accounts", json={
        "account_id": "bad-prov",
        "provider": "unknown_cloud",
    })
    assert r.status_code == 422
