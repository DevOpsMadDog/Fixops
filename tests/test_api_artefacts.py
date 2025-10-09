from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from fixops-blended-enterprise.src.main import create_app


APP_ID = "life-claims-portal"
SIM_DIR = Path("simulations/demo_pack")
EXPECTED_OUTPUTS = {
    "requirements": "requirements.json",
    "design": "design.manifest.json",
    "build": "build.report.json",
    "test": "test.report.json",
    "deploy": "deploy.manifest.json",
    "operate": "operate.snapshot.json",
    "decision": "decision.json",
}


def _client() -> TestClient:
    app = create_app()
    return TestClient(app)


def _post_stage(client: TestClient, stage: str, file_path: Path | None) -> dict[str, str]:
    files = {}
    if file_path is not None:
        files["payload"] = (file_path.name, file_path.read_bytes())
    response = client.post(
        "/api/v1/artefacts",
        data={"type": stage, "app_name": APP_ID},
        files=files,
        headers={"Authorization": "Bearer local-dev-key"},
    )
    assert response.status_code == 201, response.text
    payload = response.json()
    outputs_dir = Path(payload["outputs_dir"])
    assert outputs_dir.exists()
    expected = outputs_dir / EXPECTED_OUTPUTS[stage]
    assert expected.exists()
    if stage == "decision":
        decision_payload = json.loads(expected.read_text())
        assert decision_payload.get("marketplace_recommendations") is not None
    return payload


def test_ingest_all_stages_via_api(signing_env: None) -> None:
    artefact_root = Path("artefacts") / APP_ID
    if artefact_root.exists():
        for child in artefact_root.rglob("*"):
            if child.is_file():
                child.unlink()
        for child in sorted(artefact_root.rglob("*"), reverse=True):
            if child.is_dir():
                child.rmdir()
        artefact_root.rmdir()

    with _client() as client:
        run_ids: list[str] = []
        for stage, path in (
            ("requirements", SIM_DIR / "requirements-input.csv"),
            ("design", SIM_DIR / "design-input.json"),
            ("build", SIM_DIR / "sbom.json"),
            ("test", SIM_DIR / "scanner.sarif"),
            ("deploy", SIM_DIR / "tfplan.json"),
            ("operate", SIM_DIR / "ops-telemetry.json"),
            ("decision", None),
        ):
            payload = _post_stage(client, stage, path)
            run_ids.append(payload["run_id"])
        # Ensure each stage created its own run folder
        assert len(set(run_ids)) == len(run_ids)
