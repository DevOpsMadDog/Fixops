"""Tests for phishing simulation endpoints — empty-endpoint #11 wire-up."""
import sys
import pytest

sys.path.insert(0, "suite-api")
sys.path.insert(0, "suite-core")

from fastapi import FastAPI
from fastapi.testclient import TestClient

from apps.api.phishing_router import router

app = FastAPI()
app.include_router(router)
client = TestClient(app)

ORG = "test-org-phishing"


def test_stats_returns_risk_shape():
    r = client.get("/api/v1/phishing/stats", params={"org_id": ORG})
    assert r.status_code == 200
    body = r.json()
    assert "total_campaigns" in body
    assert "risk_level" in body
    assert body["risk_level"] in ("low", "medium", "high", "critical")


def test_campaigns_list_returns_list():
    r = client.get("/api/v1/phishing/campaigns", params={"org_id": ORG})
    assert r.status_code == 200
    assert isinstance(r.json(), list)


def test_index_count_matches_items():
    r = client.get("/api/v1/phishing/", params={"org_id": ORG})
    assert r.status_code == 200
    body = r.json()
    assert "items" in body
    assert isinstance(body["items"], list)
    assert body["count"] == len(body["items"])
