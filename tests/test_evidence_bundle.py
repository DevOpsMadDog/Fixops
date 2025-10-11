import json
from pathlib import Path
from zipfile import ZipFile

import yaml

from cli.fixops_ci import main as ci_main
from evidence.packager import (
    BundleInputs,
    _collect_files,
    create_bundle,
    evaluate_policy,
    load_policy,
)


def _write_json(path: Path, payload: dict) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_create_bundle(tmp_path: Path) -> None:
    tag = "v1.0.0"
    normalized = _write_json(
        tmp_path / "artifacts/sbom/normalized.json", {"components": []}
    )
    quality_json = _write_json(
        tmp_path / "analysis/sbom_quality_report.json",
        {"metrics": {"coverage_percent": 95.0, "license_coverage_percent": 90.0}},
    )
    quality_html = tmp_path / "reports/sbom_quality_report.html"
    quality_html.parent.mkdir(parents=True, exist_ok=True)
    quality_html.write_text("<html>quality</html>", encoding="utf-8")
    risk_report = _write_json(
        tmp_path / "artifacts/risk.json",
        {"summary": {"component_count": 2, "cve_count": 1, "max_risk_score": 60.0}},
    )
    provenance_dir = tmp_path / "artifacts/attestations"
    provenance_dir.mkdir(parents=True, exist_ok=True)
    (provenance_dir / "build.json").write_text("{}", encoding="utf-8")
    repro_attestation = _write_json(
        tmp_path / "artifacts/repro/attestations" / f"{tag}.json",
        {"match": True},
    )
    policy_path = tmp_path / "config/policy.yml"
    policy_path.parent.mkdir(parents=True, exist_ok=True)
    policy_path.write_text(
        yaml.safe_dump(
            {
                "risk": {"max_risk_score": {"warn_above": 80, "fail_above": 90}},
                "sbom_quality": {
                    "coverage_percent": {"warn_below": 80, "fail_below": 60},
                    "license_coverage_percent": {"warn_below": 80, "fail_below": 60},
                },
                "repro": {"require_match": True},
                "provenance": {"require_attestations": True},
            }
        ),
        encoding="utf-8",
    )

    inputs = BundleInputs(
        tag=tag,
        normalized_sbom=normalized,
        sbom_quality_json=quality_json,
        sbom_quality_html=quality_html,
        risk_report=risk_report,
        provenance_dir=provenance_dir,
        repro_attestation=repro_attestation,
        policy_path=policy_path,
        output_dir=tmp_path / "evidence",
    )
    manifest = create_bundle(inputs)
    bundle_path = Path(manifest["bundle_path"])
    assert bundle_path.is_file()
    with ZipFile(bundle_path, "r") as archive:
        names = archive.namelist()
        assert "MANIFEST.yaml" in names
        assert f"repro/{repro_attestation.name}" in names
    assert manifest["evaluations"]["overall"] == "pass"


def test_fixops_ci_evidence_bundle(tmp_path: Path) -> None:
    tag = "v2.0.0"
    normalized = _write_json(
        tmp_path / "artifacts/sbom/normalized.json", {"components": []}
    )
    quality_json = _write_json(
        tmp_path / "analysis/sbom_quality_report.json",
        {"metrics": {"coverage_percent": 85.0, "license_coverage_percent": 80.0}},
    )
    quality_html = tmp_path / "reports/sbom_quality_report.html"
    quality_html.parent.mkdir(parents=True, exist_ok=True)
    quality_html.write_text("<html>quality</html>", encoding="utf-8")
    risk_report = _write_json(
        tmp_path / "artifacts/risk.json",
        {"summary": {"component_count": 2, "cve_count": 1, "max_risk_score": 65.0}},
    )
    provenance_dir = tmp_path / "artifacts/attestations"
    provenance_dir.mkdir(parents=True, exist_ok=True)
    (provenance_dir / "build.json").write_text("{}", encoding="utf-8")
    repro_dir = tmp_path / "artifacts/repro/attestations"
    repro_attestation = _write_json(repro_dir / f"{tag}.json", {"match": True})
    policy_path = tmp_path / "config/policy.yml"
    policy_path.parent.mkdir(parents=True, exist_ok=True)
    policy_path.write_text(
        yaml.safe_dump(
            {
                "risk": {"max_risk_score": {"warn_above": 80, "fail_above": 90}},
                "sbom_quality": {
                    "coverage_percent": {"warn_below": 70, "fail_below": 50},
                    "license_coverage_percent": {"warn_below": 70, "fail_below": 50},
                },
                "repro": {"require_match": True},
                "provenance": {"require_attestations": True},
            }
        ),
        encoding="utf-8",
    )

    exit_code = ci_main(
        [
            "evidence",
            "bundle",
            "--tag",
            tag,
            "--normalized",
            str(normalized),
            "--quality-json",
            str(quality_json),
            "--quality-html",
            str(quality_html),
            "--risk",
            str(risk_report),
            "--provenance-dir",
            str(provenance_dir),
            "--repro-dir",
            str(repro_dir),
            "--policy",
            str(policy_path),
            "--out",
            str(tmp_path / "evidence"),
        ]
    )
    assert exit_code == 0
    bundle_path = tmp_path / "evidence/bundles" / f"{tag}.zip"
    assert bundle_path.is_file()
    manifest_path = tmp_path / "evidence/manifests" / f"{tag}.yaml"
    assert manifest_path.is_file()
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    assert manifest["evaluations"]["overall"] == "pass"


def test_load_policy_merges_overrides(tmp_path: Path) -> None:
    default_policy = load_policy(None)
    assert default_policy["risk"]["max_risk_score"]["fail_above"] == 85.0

    custom_policy = {
        "risk": {"max_risk_score": {"fail_above": 75.0}},
        "provenance": {"require_attestations": False},
    }
    policy_path = tmp_path / "policy.yml"
    policy_path.write_text(yaml.safe_dump(custom_policy), encoding="utf-8")

    merged = load_policy(policy_path)
    assert merged["risk"]["max_risk_score"]["fail_above"] == 75.0
    assert merged["provenance"]["require_attestations"] is False


def test_evaluate_policy_warn_and_fail() -> None:
    policy = load_policy(None)
    metrics = {
        "sbom": {"coverage_percent": 55.0, "license_coverage_percent": 95.0},
        "risk": {"max_risk_score": 82.0},
        "repro": {"match": False},
        "provenance": {"count": 0},
    }

    evaluations = evaluate_policy(policy, metrics=metrics)
    assert evaluations["overall"] == "fail"
    assert evaluations["checks"]["sbom_coverage_percent"]["status"] == "fail"
    assert evaluations["checks"]["risk_max_risk_score"]["status"] == "warn"
    assert evaluations["checks"]["repro_match"]["status"] == "fail"
    assert evaluations["checks"]["provenance_attestations"]["status"] == "fail"


def test_collect_files_handles_nested_directories(tmp_path: Path) -> None:
    extras = tmp_path / "extras"
    extras.mkdir()
    nested = extras / "nested"
    nested.mkdir()
    file_a = extras / "a.txt"
    file_a.write_text("a", encoding="utf-8")
    file_b = nested / "b.txt"
    file_b.write_text("b", encoding="utf-8")

    files = _collect_files([extras, tmp_path / "missing"])
    names = sorted(path.relative_to(extras).as_posix() for path in files)
    assert names == ["a.txt", "nested/b.txt"]
