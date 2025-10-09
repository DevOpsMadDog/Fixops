"""API tests for unified artefact ingestion."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from src.main import create_app
from src.services import run_registry


def _client(monkeypatch, tmp_path: Path) -> TestClient:
    monkeypatch.setattr(run_registry, "ARTEFACTS_ROOT", tmp_path)
    app = create_app()
    return TestClient(app)


def test_submit_requirements_payload(monkeypatch, tmp_path: Path) -> None:
    client = _client(monkeypatch, tmp_path)
    response = client.post(
        "/api/v1/artefacts",
        json={"type": "requirements", "payload": {"hello": "world"}, "app_id": "APP-999"},
        headers={"Authorization": "Bearer local-dev-key"},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["app_id"] == "APP-999"
    stored = Path(tmp_path) / body["app_id"] / body["run_id"] / body["stored_as"]
    assert stored.exists()
    assert stored.read_text().strip().startswith("{")


def test_submit_with_unknown_type(monkeypatch, tmp_path: Path) -> None:
    client = _client(monkeypatch, tmp_path)
    response = client.post(
        "/api/v1/artefacts",
        json={"type": "unknown", "payload": {}},
        headers={"Authorization": "Bearer local-dev-key"},
    )
    assert response.status_code == 400


def test_submit_reuses_existing_run(monkeypatch, tmp_path: Path) -> None:
    client = _client(monkeypatch, tmp_path)
    first = client.post(
        "/api/v1/artefacts",
        json={"type": "design", "payload": {"components": []}, "app_id": "APP-101"},
        headers={"Authorization": "Bearer local-dev-key"},
    )
    run_id = first.json()["run_id"]
    second = client.post(
        "/api/v1/artefacts",
        json={"type": "sbom", "payload": {"components": []}, "run_id": run_id, "app_id": "APP-101"},
        headers={"Authorization": "Bearer local-dev-key"},
    )
    assert second.status_code == 201
    assert second.json()["run_id"] == run_id


def test_design_submission_generates_manifest(monkeypatch, tmp_path: Path) -> None:
    client = _client(monkeypatch, tmp_path)
    payload = {
        "app_name": "life-claims-portal",
        "components": [
            {"name": "login-ui", "tier": "tier-0", "exposure": "internet", "pii": True},
            {"name": "claims-core", "tier": "tier-0", "exposure": "internal", "pii": True},
        ],
    }
    response = client.post(
        "/api/v1/artefacts",
        json={"type": "design", "payload": payload},
        headers={"Authorization": "Bearer local-dev-key"},
    )
    assert response.status_code == 201
    body = response.json()
    outputs_dir = Path(tmp_path) / body["app_id"] / body["run_id"] / "outputs"
    manifest_path = outputs_dir / "design.manifest.json"
    assert manifest_path.exists()
    manifest = json.loads(manifest_path.read_text())
    assert manifest["components"][0]["component_id"].startswith("C-")
    assert manifest["design_risk_score"] >= 0.5
