"""Tests: GET /api/v1/incidents/ wired to IncidentResponseManager.list_incidents.

Verifies:
  1. Envelope shape — items/total/stats/limit/offset always present
  2. Pagination — limit/offset echoed correctly
  3. status/severity filters accepted without crash
  4. org_id echoed back
"""
from __future__ import annotations

import os

import pytest

API_KEY = "fixops_test_key_incidents_index"
os.environ["FIXOPS_API_TOKEN"] = API_KEY
os.environ.setdefault("FIXOPS_MODE", "dev")

from apps.api.app import create_app  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

HEADERS = {"X-API-Key": API_KEY}


@pytest.fixture(scope="module")
def client():
    return TestClient(create_app(), headers=HEADERS)


def test_incidents_index_envelope_shape(client):
    resp = client.get("/api/v1/incidents/")
    assert resp.status_code == 200
    body = resp.json()
    assert "items" in body
    assert "total" in body
    assert "stats" in body
    assert "limit" in body
    assert "offset" in body
    assert isinstance(body["items"], list)
    assert isinstance(body["total"], int)


def test_incidents_index_pagination_echoed(client):
    resp = client.get("/api/v1/incidents/?limit=10&offset=5")
    assert resp.status_code == 200
    body = resp.json()
    assert body["limit"] == 10
    assert body["offset"] == 5


def test_incidents_index_status_filter_accepted(client):
    resp = client.get("/api/v1/incidents/?status=open")
    assert resp.status_code == 200


def test_incidents_index_severity_filter_accepted(client):
    resp = client.get("/api/v1/incidents/?severity=critical")
    assert resp.status_code == 200


def test_incidents_index_invalid_filter_does_not_crash(client):
    # Unknown enum values fall back to no filter — must not 422 or 500
    resp = client.get("/api/v1/incidents/?status=unknown_status&severity=extreme")
    assert resp.status_code == 200
    body = resp.json()
    assert "items" in body


def test_incidents_index_org_id_echoed(client):
    resp = client.get("/api/v1/incidents/?org_id=acme-corp")
    assert resp.status_code == 200
    assert resp.json()["org_id"] == "acme-corp"
