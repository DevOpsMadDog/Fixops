"""Tests for AWSCostExplorerConnector → /api/v1/cloud-cost/snapshots fallback.

Validates the engine fallback added in
``cloud_cost_security_engine.list_snapshots_with_cost_explorer_fallback``:

1. Org with recorded snapshots → returns those rows untouched
   (source="org_registered").
2. Org with no rows + connector unconfigured (no AWS creds + no boto3)
   → structured needs_credentials hint (NEVER mocks).
3. Org with no rows + injected fake connector returning {status:"ok"} with
   per-service rows → projects each into a snapshot envelope tagged
   source="aws_cost_explorer". Anomaly flag derived from change_pct >200%.
4. Connector returning {status:"api_error"} → connector_error envelope.
5. Filters apply against derived rows (account_id, anomaly).
6. Org-registered rows take precedence over derived projection.
7. Router end-to-end through TestClient.
"""
from __future__ import annotations

import os
import sys
import uuid
from typing import Any, Dict, List

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def _make_engine(tmp_path):
    from core.cloud_cost_security_engine import CloudCostSecurityEngine
    db = os.path.join(str(tmp_path), f"cloud_cost_{uuid.uuid4().hex}.db")
    return CloudCostSecurityEngine(db_path=db)


class _FakeCostExplorer:
    def __init__(self, status: str = "ok", snapshots: List[Dict[str, Any]] = None,
                 error: str = ""):
        self._status = status
        self._snapshots = snapshots or []
        self._error = error

    def fetch_snapshots(self, org_id: str):
        if self._status == "ok":
            return {
                "status": "ok",
                "mode": "live",
                "org_id": org_id,
                "account_id": "111122223333",
                "snapshots_count": len(self._snapshots),
                "snapshots": self._snapshots,
                "ingested_at": "2026-05-03T00:00:00Z",
            }
        if self._status == "needs_credentials":
            return {
                "status": "needs_credentials",
                "hint": "Set AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY",
                "reason": "boto3_import_failed: no module named boto3",
            }
        if self._status == "api_error":
            return {"status": "api_error", "error": self._error or "boom"}
        return {"status": self._status}


def test_returns_org_registered_when_snapshots_exist(tmp_path):
    eng = _make_engine(tmp_path)
    eng.record_snapshot("acme", {
        "account_id": "111", "provider": "aws", "service_name": "EC2",
        "region": "us-east-1", "cost_usd": 100.0, "previous_cost_usd": 50.0,
        "change_pct": 100.0, "snapshot_date": "2026-05-02",
    })
    out = eng.list_snapshots_with_cost_explorer_fallback("acme")
    assert out["source"] == "org_registered"
    assert out["total"] == 1
    assert out["snapshots"][0]["service_name"] == "EC2"


def test_returns_needs_credentials_when_no_data_and_no_creds(tmp_path, monkeypatch):
    eng = _make_engine(tmp_path)
    for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_PROFILE",
              "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE"):
        monkeypatch.delenv(k, raising=False)
    out = eng.list_snapshots_with_cost_explorer_fallback("brand-new-org")
    assert out["snapshots"] == []
    assert out["total"] == 0
    assert out["source"] == "needs_credentials"
    assert "AWS_ACCESS_KEY_ID" in out["hint"]


def test_projects_cost_explorer_rows_with_anomaly_flag(tmp_path):
    eng = _make_engine(tmp_path)
    fake = _FakeCostExplorer(
        status="ok",
        snapshots=[
            {"account_id": "111", "provider": "aws",
             "service_name": "Amazon EC2", "region": "us-east-1",
             "cost_usd": 1000.0, "previous_cost_usd": 200.0,
             "change_pct": 400.0, "snapshot_date": "2026-05-02"},
            {"account_id": "111", "provider": "aws",
             "service_name": "Amazon S3", "region": "us-east-1",
             "cost_usd": 50.0, "previous_cost_usd": 45.0,
             "change_pct": 11.0, "snapshot_date": "2026-05-02"},
        ],
    )
    out = eng.list_snapshots_with_cost_explorer_fallback(
        "acme", cost_connector=fake,
    )
    assert out["source"] == "aws_cost_explorer"
    assert out["total"] == 2
    by_svc = {s["service_name"]: s for s in out["snapshots"]}
    ec2 = by_svc["Amazon EC2"]
    # 400% > 200% spike threshold → anomaly=1
    assert ec2["anomaly"] == 1
    assert ec2["anomaly_type"] == "spike"
    s3 = by_svc["Amazon S3"]
    assert s3["anomaly"] == 0
    assert s3["anomaly_type"] is None
    assert all(r["source"] == "aws_cost_explorer" for r in out["snapshots"])


def test_connector_api_error_returns_envelope(tmp_path):
    eng = _make_engine(tmp_path)
    fake = _FakeCostExplorer(status="api_error", error="ThrottlingException")
    out = eng.list_snapshots_with_cost_explorer_fallback(
        "acme", cost_connector=fake,
    )
    assert out["source"] == "connector_error"
    assert "ThrottlingException" in out["error"]


def test_filters_account_id_and_anomaly_against_derived_rows(tmp_path):
    eng = _make_engine(tmp_path)
    fake = _FakeCostExplorer(
        status="ok",
        snapshots=[
            {"account_id": "111", "service_name": "EC2", "region": "us-east-1",
             "cost_usd": 100.0, "previous_cost_usd": 10.0, "change_pct": 900.0,
             "snapshot_date": "2026-05-02"},
            {"account_id": "222", "service_name": "S3", "region": "us-east-1",
             "cost_usd": 5.0, "previous_cost_usd": 5.0, "change_pct": 0.0,
             "snapshot_date": "2026-05-02"},
        ],
    )
    only_111 = eng.list_snapshots_with_cost_explorer_fallback(
        "acme", account_id="111", cost_connector=fake,
    )
    assert only_111["total"] == 1
    assert only_111["snapshots"][0]["service_name"] == "EC2"

    only_anom = eng.list_snapshots_with_cost_explorer_fallback(
        "acme", anomaly=True, cost_connector=fake,
    )
    assert only_anom["total"] == 1
    assert only_anom["snapshots"][0]["service_name"] == "EC2"


def test_org_rows_take_precedence_over_cost_explorer(tmp_path):
    eng = _make_engine(tmp_path)
    eng.record_snapshot("acme", {
        "account_id": "real", "provider": "aws", "service_name": "real-svc",
        "region": "us-east-1", "cost_usd": 1.0, "previous_cost_usd": 1.0,
        "change_pct": 0.0, "snapshot_date": "2026-05-02",
    })
    fake = _FakeCostExplorer(
        status="ok",
        snapshots=[{"account_id": "x", "service_name": "EC2", "region": "us",
                    "cost_usd": 100.0, "previous_cost_usd": 1.0,
                    "change_pct": 9900.0, "snapshot_date": "2026-05-02"}],
    )
    out = eng.list_snapshots_with_cost_explorer_fallback(
        "acme", cost_connector=fake,
    )
    assert out["source"] == "org_registered"
    assert out["snapshots"][0]["service_name"] == "real-svc"


def test_router_wired_to_fallback(tmp_path, monkeypatch):
    """End-to-end through the FastAPI router."""
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    from apps.api.cloud_cost_security_router import router as cc_router
    from apps.api.auth_deps import api_key_auth
    import apps.api.cloud_cost_security_router as cc_module

    cc_module._engine = None
    monkeypatch.setattr(
        "core.cloud_cost_security_engine._DATA_DIR",
        __import__("pathlib").Path(str(tmp_path)),
        raising=False,
    )
    for k in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_PROFILE",
              "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE"):
        monkeypatch.delenv(k, raising=False)

    app = FastAPI()
    app.include_router(cc_router)
    app.dependency_overrides[api_key_auth] = lambda: True
    client = TestClient(app)

    r = client.get("/api/v1/cloud-cost/snapshots?org_id=brand-new-org")
    assert r.status_code == 200, r.text
    body = r.json()
    assert isinstance(body, dict)
    assert "snapshots" in body
    assert "source" in body
    assert body["source"] == "needs_credentials"


def test_router_error_path_terminate_missing(tmp_path, monkeypatch):
    """Sanity error path — POST terminate on missing resource → 404."""
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    from apps.api.cloud_cost_security_router import router as cc_router
    from apps.api.auth_deps import api_key_auth
    import apps.api.cloud_cost_security_router as cc_module

    cc_module._engine = None
    monkeypatch.setattr(
        "core.cloud_cost_security_engine._DATA_DIR",
        __import__("pathlib").Path(str(tmp_path)),
        raising=False,
    )

    app = FastAPI()
    app.include_router(cc_router)
    app.dependency_overrides[api_key_auth] = lambda: True
    client = TestClient(app)

    r = client.post(
        "/api/v1/cloud-cost/abandoned-resources/no-such-id/terminate?org_id=acme"
    )
    assert r.status_code == 404
