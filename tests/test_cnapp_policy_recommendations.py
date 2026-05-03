"""
Tests for CNAPPEngine.get_policy_recommendations and GET /api/v1/cnapp/ root.

6 tests covering:
  - empty org returns no recommendations
  - open findings produce recommendations sorted by priority
  - suppressed findings are excluded
  - already_covered flag set when matching enabled policy exists
  - org isolation
  - GET / root endpoint returns live stats (no mocks)
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from core.cnapp_engine import CNAPPEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    return CNAPPEngine(db_path=str(tmp_path / "rec_test.db"))


@pytest.fixture
def org():
    return "org-rec-test"


def _workload(engine, org_id, **kw):
    data = {"name": "wl", "workload_type": "container", "cloud_provider": "aws",
            "region": "us-east-1", "running": True, "privileged": False}
    data.update(kw)
    return engine.register_workload(org_id, data)


def _finding(engine, org_id, wid, **kw):
    data = {"category": "misconfiguration", "severity": "high",
            "title": "t", "description": "d", "remediation": "r"}
    data.update(kw)
    return engine.add_finding(org_id, wid, data)


# ---------------------------------------------------------------------------
# Engine unit tests
# ---------------------------------------------------------------------------

def test_recommendations_empty_org(engine, org):
    recs = engine.get_policy_recommendations(org)
    assert recs == []


def test_recommendations_returns_sorted_by_priority(engine, org):
    wl = _workload(engine, org)
    wid = wl["workload_id"]
    _finding(engine, org, wid, category="misconfiguration", severity="high")
    _finding(engine, org, wid, category="vulnerability", severity="critical")
    _finding(engine, org, wid, category="network_exposure", severity="medium")

    recs = engine.get_policy_recommendations(org)
    assert len(recs) == 3
    # critical must be first
    assert recs[0]["severity"] == "critical"
    assert recs[0]["priority"] == 1
    # medium must be last
    assert recs[-1]["severity"] == "medium"


def test_recommendations_suppressed_findings_excluded(engine, org):
    wl = _workload(engine, org)
    wid = wl["workload_id"]
    f = _finding(engine, org, wid, category="misconfiguration", severity="critical")
    engine.suppress_finding(org, f["finding_id"])

    recs = engine.get_policy_recommendations(org)
    # suppressed finding must not produce a recommendation
    assert recs == []


def test_recommendations_already_covered_flag(engine, org):
    wl = _workload(engine, org)
    wid = wl["workload_id"]
    # network_exposure finding -> suggested policy_type=network, action=block
    _finding(engine, org, wid, category="network_exposure", severity="high")
    # create matching enabled policy
    engine.create_policy(org, {"name": "block-net", "policy_type": "network",
                                "action": "block", "enabled": True})

    recs = engine.get_policy_recommendations(org)
    assert len(recs) == 1
    assert recs[0]["already_covered"] is True


def test_recommendations_org_isolation(engine):
    org_a, org_b = "rec-org-a", "rec-org-b"
    wl = _workload(engine, org_a)
    _finding(engine, org_a, wl["workload_id"], severity="critical")
    # org_b must see nothing
    assert engine.get_policy_recommendations(org_b) == []


# ---------------------------------------------------------------------------
# Router integration test — GET /api/v1/cnapp/ returns live stats
# ---------------------------------------------------------------------------

def test_cnapp_root_endpoint_live(tmp_path):
    import sys
    import os
    # Ensure suite-api is importable
    suite_api = os.path.join(os.path.dirname(__file__), "..", "suite-api")
    if suite_api not in sys.path:
        sys.path.insert(0, suite_api)

    from apps.api.cnapp_router import router
    from fastapi import FastAPI

    app = FastAPI()
    app.include_router(router)
    client = TestClient(app)

    resp = client.get("/api/v1/cnapp/", params={"org_id": "test-root-org"})
    assert resp.status_code == 200
    data = resp.json()
    # Must contain real engine fields — no mocks
    assert "total_workloads" in data
    assert "open_findings" in data
    assert "by_category" in data
    assert data["total_workloads"] == 0  # fresh org, no seed data
