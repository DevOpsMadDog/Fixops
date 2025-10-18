from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

REPO_ROOT = Path(__file__).resolve().parent.parent
SIM_ROOT = REPO_ROOT / "simulations" / "demo_pack"


@pytest.fixture()
def api_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("FIXOPS_ARTEFACTS_ROOT", str(tmp_path))
    monkeypatch.setenv("FIXOPS_API_KEY", "test-key")
    # Ensure settings pick up the patched environment
    settings_module = importlib.import_module("src.config.settings")
    importlib.reload(settings_module)
    from src.main import create_app

    app = create_app()
    return TestClient(app)


def _post_stage(
    client: TestClient, stage: str, input_name: str | None
) -> dict[str, str | list[str] | bool | None]:
    files = None
    if input_name is not None:
        path = SIM_ROOT / input_name
        files = {"payload": (path.name, path.read_bytes(), "application/json")}
    response = client.post(
        "/api/v1/artefacts",
        data={"type": stage, "app_name": "life-claims-portal"},
        files=files,
        headers={"Authorization": "Bearer test-key"},
    )
    assert response.status_code == 201, response.text
    return response.json()


def test_artefact_ingest_persists_outputs(
    api_client: TestClient, tmp_path: Path
) -> None:
    summary_requirements = _post_stage(
        api_client, "requirements", "requirements-input.csv"
    )
    req_output = Path(summary_requirements["output_file"])
    assert req_output.exists()
    json.loads(req_output.read_text(encoding="utf-8"))

    summary_design = _post_stage(api_client, "design", "design-input.json")
    design_output = Path(summary_design["output_file"])
    assert design_output.exists()
    document = json.loads(design_output.read_text(encoding="utf-8"))
    assert document.get("app_id", "").startswith("APP-")
    assert summary_design["run_id"] != summary_requirements["run_id"]


def test_downstream_stages_reuse_design_run(
    api_client: TestClient, tmp_path: Path
) -> None:
    summary_requirements = _post_stage(
        api_client, "requirements", "requirements-input.csv"
    )
    summary_design = _post_stage(api_client, "design", "design-input.json")

    assert summary_design["run_id"] != summary_requirements["run_id"]

    summary_build = _post_stage(api_client, "build", "sbom.json")
    assert summary_build["run_id"] == summary_design["run_id"]
    assert summary_build["app_id"] == summary_design["app_id"]
