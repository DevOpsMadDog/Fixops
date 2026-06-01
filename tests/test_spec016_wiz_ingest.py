"""SPEC-016 increment 1 — WIZ /ingest → normalize → findings + correlation brain.

Locks the debate-hardened acceptance criteria:
  AC-016-01  WIZ env unset -> honest 503 (no fake findings)
  AC-016-02  real issues+vulns -> 200, ingested>0, brain nodes grow, correlated=True
  REQ-016-07 enforced air-gap + vendor-SaaS URL -> 503 (egress guard, no silent egress)
  REQ-016-07 SSRF: cloud-metadata IP blocked; on-prem RFC-1918 allowed
  REQ-016-11 every brain node carries a classification_level marking
  REQ-016-12 ingest uses the engine's typed methods, not the raw /graphql passthrough
"""
from __future__ import annotations

import os

import pytest

# Build the app once at import time — create_app() boots in ~10s which exceeds the
# suite's per-test pytest-timeout if done inside a (timed) fixture.
os.environ.setdefault("FIXOPS_API_TOKEN", "spec016token123456")
from fastapi.testclient import TestClient  # noqa: E402
from apps.api.app import create_app  # noqa: E402

_APP = create_app()


@pytest.fixture(scope="module")
def client():
    return TestClient(_APP)


@pytest.fixture
def _H(auth_headers):
    # auth_headers (from conftest) carries the suite's valid X-API-Key.
    return {**auth_headers, "X-Org-ID": "spec016-org"}


class _FakeWiz:
    def list_issues(self, severity=None, first=50, after=None):
        if after:
            return {"issues": [], "pageInfo": {"hasNextPage": False}}
        return {"issues": [
            {"id": "I1", "severity": "CRITICAL", "type": "EXPOSURE",
             "sourceRule": {"id": "R1", "name": "Public bucket"},
             "entitySnapshot": {"id": "A1", "name": "prod-bucket", "type": "BUCKET"},
             "status": "OPEN"},
        ], "pageInfo": {"hasNextPage": False}}

    def list_vulnerabilities(self, severity=None, first=50, after=None):
        if after:
            return {"nodes": [], "pageInfo": {"hasNextPage": False}}
        return {"nodes": [
            {"id": "V1", "name": "CVE-2024-1234", "vendorSeverity": "CRITICAL",
             "cvss31": {"score": 9.1}},
        ], "pageInfo": {"hasNextPage": False}}


def test_ac_016_01_unset_returns_503(client, _H):
    os.environ.pop("WIZ_API_URL", None)
    r = client.post("/api/v1/wiz/ingest", headers=_H, json={})
    assert r.status_code == 503
    assert "unavailable" in r.json()["detail"].lower()


def test_ac_016_02_ingest_correlates(client, monkeypatch, _H):
    import core.wiz_cnapp_engine as WE
    monkeypatch.setattr(WE, "get_wiz_cnapp_engine", lambda: _FakeWiz())
    monkeypatch.setenv("WIZ_API_URL", "https://wiz.acme.local/graphql")
    r = client.post("/api/v1/wiz/ingest", headers=_H, json={})
    assert r.status_code == 200
    j = r.json()
    assert j["ingested"] == 2          # 1 issue + 1 vuln
    assert j["brain_nodes_added"] > 0
    assert j["correlated"] is True
    assert j["source"] == "wiz"


def test_req_016_07_enforced_blocks_saas(client, monkeypatch, _H):
    import core.wiz_cnapp_engine as WE
    monkeypatch.setattr(WE, "get_wiz_cnapp_engine", lambda: _FakeWiz())
    monkeypatch.setenv("FIXOPS_AIRGAP_MODE", "enforced")
    monkeypatch.setenv("WIZ_API_URL", "https://api.us17.app.wiz.io/graphql")
    r = client.post("/api/v1/wiz/ingest", headers=_H, json={})
    assert r.status_code == 503
    assert "saas" in r.json()["detail"].lower() or "blocked" in r.json()["detail"].lower()


def test_req_016_07_egress_guard_ssrf_and_onprem():
    from core.airgap_config import assert_egress_allowed, EgressBlocked
    # cloud-metadata link-local blocked (SSRF primitive)
    with pytest.raises(EgressBlocked):
        assert_egress_allowed("http://169.254.169.254/latest/meta-data/", "wiz")
    # on-prem RFC-1918 allowed (SCIF reality — tools live on 10.x)
    assert assert_egress_allowed("https://10.20.30.40/graphql", "wiz") is True
    # empty/unset -> blocked
    with pytest.raises(EgressBlocked):
        assert_egress_allowed("", "wiz")


def test_req_016_11_classification_marking():
    from apps.api.scanner_ingest_router import _index_findings_into_brain
    from core.knowledge_brain import get_brain
    res = _index_findings_into_brain(
        [{"id": "spec016-cls-node", "title": "t", "severity": "high"}],
        "spec016-org",
    )
    assert res["nodes_added"] >= 1
    node = get_brain().get_node("spec016-cls-node")
    assert node is not None
    # get_node may return a dict or an object; properties may be nested or flattened.
    props = node.get("properties") if isinstance(node, dict) else getattr(node, "properties", {})
    if isinstance(props, str):
        import json
        props = json.loads(props)
    classification = (props or {}).get("classification_level") or (
        node.get("classification_level") if isinstance(node, dict) else None
    )
    assert classification  # marking present (default UNCLASSIFIED)
