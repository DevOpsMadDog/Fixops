"""Run the demo ingestion pipeline using the unified artefact endpoint."""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BLENDED_ROOT = ROOT / "fixops-blended-enterprise"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
if str(BLENDED_ROOT) not in sys.path:
    sys.path.insert(0, str(BLENDED_ROOT))

import argparse
import json
from typing import Any, Dict

from fastapi.testclient import TestClient

from src.main import create_app
from src.services import signing

DEMO_ROOT = Path(__file__).resolve().parents[1] / "simulations" / "demo_pack"

STAGES = [
    ("requirements", "requirements-input.csv"),
    ("design", "design-input.json"),
    ("sbom", "sbom.json"),
    ("sarif", "scanner.sarif"),
    ("provenance", "provenance.slsa.json"),
    ("tests", "tests-input.json"),
    ("tfplan", "tfplan.json"),
    ("ops", "ops-telemetry.json"),
    ("decision", "decision-input.json"),
]


def _load_payload(path: Path) -> Any:
    if not path.exists():
        return {}
    if path.suffix == ".csv":
        return path.read_text()
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return path.read_text()


def _submit(client: TestClient, artefact_type: str, payload: Any, app_id: str, run_id: str | None) -> Dict[str, Any]:
    body: Dict[str, Any] = {"type": artefact_type, "payload": payload, "app_id": app_id}
    if run_id:
        body["run_id"] = run_id
    response = client.post(
        "/api/v1/artefacts",
        json=body,
        headers={"Authorization": "Bearer local-dev-key"},
    )
    response.raise_for_status()
    return response.json()


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the FixOps demo pipeline")
    parser.add_argument("--app", default="demo-app", help="Application name for the run")
    args = parser.parse_args()

    client = TestClient(create_app())

    run_id = None
    app_id = args.app
    run_path: Path | None = None

    for artefact_type, filename in STAGES:
        payload = _load_payload(DEMO_ROOT / filename)
        result = _submit(client, artefact_type, payload, app_id, run_id)
        app_id = result["app_id"]
        run_id = result["run_id"]
        run_path = Path("artefacts") / app_id / run_id
        print(f"[{artefact_type.upper()}] stored {result['stored_as']}")

    if not run_path:
        raise SystemExit("Run did not produce any artefacts")

    outputs_dir = run_path / "outputs"
    print(f"\nRun outputs in: {outputs_dir}")
    for path in sorted(outputs_dir.glob("*.json")):
        print(f" - {path.relative_to(run_path)}")

    signed_dir = outputs_dir / "signed"
    signatures = sorted(signed_dir.glob("*.manifest.json"))
    if signatures:
        print("\nSignature envelopes:")
        for signature_file in signatures:
            manifest_name = signature_file.name.replace(".manifest.json", "")
            manifest_path = outputs_dir / manifest_name
            if manifest_path.exists():
                try:
                    manifest = json.loads(manifest_path.read_text())
                    envelope = json.loads(signature_file.read_text())
                    verified = signing.verify_manifest(manifest, envelope)
                except Exception as exc:  # pragma: no cover - defensive
                    verified = False
                    print(f" - {signature_file.name}: verification error {exc}")
                    continue
                status = "verified" if verified else "failed"
                print(f" - {signature_file.name}: {status}")
    else:
        print("\nSigning disabled; no signature envelopes produced.")

    bundle = outputs_dir / "evidence_bundle.zip"
    if bundle.exists():
        print(f"\nEvidence bundle created at: {bundle.relative_to(run_path)}")


if __name__ == "__main__":
    main()
