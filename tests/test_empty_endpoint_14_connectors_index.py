"""Test: GET /api/v1/connectors/ now returns real vendor list (was stub empty []).

Wire: commercial_vendor_router.connectors_index -> inline vendor manifest
Tests the router directly (not the full app) to isolate the fix.
"""
from __future__ import annotations

import os

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# Use the same canonical token conftest.py injects so auth passes in all run modes
_API_TOKEN = os.getenv(
    "FIXOPS_API_TOKEN",
    "aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh",
)
os.environ["FIXOPS_API_TOKEN"] = _API_TOKEN
_HEADERS = {"X-API-Key": _API_TOKEN}


@pytest.fixture(scope="module")
def client():
    """Mount only the commercial_vendor_router on a minimal FastAPI app."""
    from apps.api.commercial_vendor_router import router
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


def test_connectors_index_not_empty(client):
    """Index must return 4 vendor entries, never []."""
    resp = client.get("/api/v1/connectors/", headers=_HEADERS)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["count"] == 4
    assert len(body["items"]) == 4


def test_connectors_index_item_shape(client):
    """Each item must carry vendor, ingest_endpoint and sample_endpoint keys."""
    resp = client.get("/api/v1/connectors/", headers=_HEADERS)
    assert resp.status_code == 200
    for item in resp.json()["items"]:
        assert "vendor" in item
        assert "ingest_endpoint" in item
        assert "sample_endpoint" in item
        assert item["vendor"] in {"lacework", "sysdig", "recorded_future", "mandiant"}
