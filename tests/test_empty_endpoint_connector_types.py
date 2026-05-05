"""Regression test: GET /api/v1/connectors/types is no longer a hardcoded stub.

Three cases:
  1. 200 response with types list and total count.
  2. Type IDs derived from ConnectorType enum (not hardcoded strings).
  3. required_fields for jira derived from JiraConfig Pydantic model_fields.
"""
from __future__ import annotations

import os
import sys

# Ensure suite paths are on sys.path (mirrors sitecustomize.py)
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _sub in ("suite-api", "suite-core", "suite-attack", "suite-feeds", "suite-evidence-risk"):
    _p = os.path.join(_ROOT, _sub)
    if _p not in sys.path:
        sys.path.insert(0, _p)

_API_KEY = "test-connectors-types-key-x1"
os.environ["FIXOPS_API_TOKEN"] = _API_KEY

import pytest
from fastapi.testclient import TestClient

_HEADERS = {"X-API-Key": _API_KEY}


@pytest.fixture(scope="module")
def client():
    os.environ["FIXOPS_API_TOKEN"] = _API_KEY
    from apps.api.app import create_app
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


def test_connector_types_returns_200(client):
    """GET /api/v1/connectors/types must return 200 with types list."""
    resp = client.get("/api/v1/connectors/types", headers=_HEADERS)
    assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text[:300]}"
    body = resp.json()
    assert "types" in body, "Response must have 'types' key"
    assert "total" in body, "Response must have 'total' key"
    types = body["types"]
    assert len(types) >= 3, f"Must return at least 3 connector types (jira/github/slack), got {len(types)}"
    assert body["total"] == len(types), "total must match len(types)"


def test_connector_types_derived_from_enum(client):
    """Connector type IDs must match ConnectorType enum values (not hardcoded)."""
    from apps.api.connectors_router import ConnectorType

    resp = client.get("/api/v1/connectors/types", headers=_HEADERS)
    assert resp.status_code == 200
    returned_ids = {t["type"] for t in resp.json()["types"]}
    enum_values = {ct.value for ct in ConnectorType}
    assert returned_ids == enum_values, (
        f"Returned type IDs {returned_ids} must match ConnectorType enum {enum_values}"
    )


def test_connector_types_required_fields_from_pydantic(client):
    """Jira required_fields must be derived from JiraConfig model, not hardcoded."""
    from apps.api.connectors_router import JiraConfig

    resp = client.get("/api/v1/connectors/types", headers=_HEADERS)
    assert resp.status_code == 200

    jira_entry = next((t for t in resp.json()["types"] if t["type"] == "jira"), None)
    assert jira_entry is not None, "jira connector type must be present"

    # Introspect JiraConfig for expected required fields
    expected_required = [
        name for name, fi in JiraConfig.model_fields.items() if fi.is_required()
    ]
    assert set(jira_entry["required_fields"]) == set(expected_required), (
        f"Jira required_fields {jira_entry['required_fields']} must match "
        f"JiraConfig model required fields {expected_required}"
    )
