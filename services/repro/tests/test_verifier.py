import json
from pathlib import Path

import yaml

from services.repro.verifier import run_verification


def _write_plan(path: Path, payload: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(payload), encoding="utf-8")
    return path


def test_run_verification_match(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    reference = repo / "artifacts" / "reference.txt"
    reference.parent.mkdir(parents=True, exist_ok=True)
    reference.write_text("hello world", encoding="utf-8")

    plan_data = {
        "artifact": "dist/output.txt",
        "steps": [
            {
                "run": [
                    "python",
                    "-c",
                    "from pathlib import Path; Path('dist').mkdir(exist_ok=True); Path('dist/output.txt').write_text('hello world', encoding='utf-8')",
                ]
            }
        ],
        "reference_artifact": str(reference.relative_to(repo)),
    }
    plan_path = _write_plan(repo / "build" / "plan.yaml", plan_data)

    result = run_verification(
        plan_path, "v1.0.0", output_dir=repo / "artifacts" / "repro", repo_root=repo
    )
    assert result.match is True
    assert result.attestation_path is not None
    payload = json.loads(Path(result.attestation_path).read_text(encoding="utf-8"))
    assert payload["match"] is True
    assert (
        payload["reference_digest"]["sha256"] == payload["generated_digest"]["sha256"]
    )


def test_verify_plan_mismatch(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    repo.mkdir()

    reference = repo / "artifacts" / "reference.txt"
    reference.parent.mkdir(parents=True, exist_ok=True)
    reference.write_text("hello world", encoding="utf-8")

    plan_data = {
        "artifact": "dist/output.txt",
        "steps": [
            {
                "run": [
                    "python",
                    "-c",
                    "from pathlib import Path; Path('dist').mkdir(exist_ok=True); Path('dist/output.txt').write_text('different', encoding='utf-8')",
                ]
            }
        ],
        "reference_artifact": str(reference.relative_to(repo)),
    }
    plan_path = _write_plan(repo / "plan.yaml", plan_data)
    plan = run_verification(
        plan_path, "v1.0.0", output_dir=repo / "artifacts" / "repro", repo_root=repo
    )
    assert plan.match is False
    assert plan.reference_digest is not None
    assert plan.generated_digest["sha256"] != plan.reference_digest["sha256"]
