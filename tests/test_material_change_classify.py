"""Tests for material_change_router /classify — empty-endpoint wire-up."""
from __future__ import annotations

import os

import pytest
from fastapi.testclient import TestClient

# Use the same token as conftest.py so auth passes in the token strategy.
_API_TOKEN = os.getenv(
    "FIXOPS_API_TOKEN",
    "aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh",
)
_AUTH = {"X-API-Key": _API_TOKEN}


@pytest.fixture(scope="module")
def client():
    from apps.api.app import create_app
    return TestClient(create_app(), raise_server_exceptions=False)


def test_classify_python_file(client):
    resp = client.post(
        "/api/v1/changes/classify",
        json={"file_diffs": [{"path": "core/auth.py", "diff": "+secret_key = os.getenv('SECRET')"}]},
        headers=_AUTH,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "results" in data
    assert len(data["results"]) == 1
    result = data["results"][0]
    assert result["path"] == "core/auth.py"
    assert result["classification"] in ("BREAKING", "MATERIAL", "COSMETIC")


def test_classify_multiple_files(client):
    resp = client.post(
        "/api/v1/changes/classify",
        json={"file_diffs": [
            {"path": "requirements.txt", "diff": "+requests==2.31.0"},
            {"path": "README.md", "diff": "+# Updated docs"},
        ]},
        headers=_AUTH,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["results"]) == 2
    paths = [r["path"] for r in data["results"]]
    assert "requirements.txt" in paths
    assert "README.md" in paths
    # requirements.txt is a dependency file -> MATERIAL or BREAKING
    req_result = next(r for r in data["results"] if r["path"] == "requirements.txt")
    assert req_result["classification"] in ("MATERIAL", "BREAKING")
