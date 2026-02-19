"""Evidence bundle creation helpers."""

from __future__ import annotations

import copy
import json
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable, Mapping
from zipfile import ZipFile

import yaml

DEFAULT_POLICY: dict[str, Any] = {
    "sbom_quality": {
        "coverage_percent": {"warn_below": 80.0, "fail_below": 60.0},
        "license_coverage_percent": {"warn_below": 80.0, "fail_below": 50.0},
    },
    "risk": {"max_risk_score": {"warn_above": 70.0, "fail_above": 85.0}},
    "repro": {"require_match": True},
    "provenance": {"require_attestations": True},
}


@dataclass(slots=True)
class BundleInputs:
    """Paths and metadata needed to construct an evidence bundle."""

    tag: str
    normalized_sbom: Path
    sbom_quality_json: Path
    sbom_quality_html: Path | None
    risk_report: Path
    provenance_dir: Path
    repro_attestation: Path
    policy_path: Path | None = None
    output_dir: Path = Path("evidence")
    extra_paths: Iterable[Path] = field(default_factory=tuple)
    sign_key: Path | None = None


def load_policy(policy_path: Path | None) -> dict[str, Any]:
    if policy_path is None or not policy_path.is_file():
        return DEFAULT_POLICY
    with policy_path.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}
    if not isinstance(loaded, Mapping):
        raise ValueError("Policy document must be a mapping at the root level")
    merged = copy.deepcopy(DEFAULT_POLICY)
    for section, rules in loaded.items():
        if isinstance(rules, Mapping):
            existing = merged.setdefault(section, {})
            if isinstance(existing, Mapping):
                existing.update(
                    rules
                )  # shallow merge is sufficient for numeric thresholds
            else:
                merged[section] = rules
    return merged


def _digest_file(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _evaluate_rules(value: float, rules: Mapping[str, Any]) -> str:
    status = "pass"
    fail_above = rules.get("fail_above")
    fail_below = rules.get("fail_below")
    warn_above = rules.get("warn_above")
    warn_below = rules.get("warn_below")
    if fail_above is not None and value > float(fail_above):
        return "fail"
    if fail_below is not None and value < float(fail_below):
        return "fail"
    if warn_above is not None and value > float(warn_above):
        status = "warn"
    if warn_below is not None and value < float(warn_below):
        status = "warn"
    return status


def evaluate_policy(
    policy: Mapping[str, Any], *, metrics: Mapping[str, Any]
) -> dict[str, Any]:
    evaluations: dict[str, Any] = {"checks": {}, "overall": "pass"}

    sbom_metrics = (
        metrics.get("sbom", {}) if isinstance(metrics.get("sbom"), Mapping) else {}
    )
    sbom_policy = (
        policy.get("sbom_quality", {})
        if isinstance(policy.get("sbom_quality"), Mapping)
        else {}
    )
    for metric in ("coverage_percent", "license_coverage_percent"):
        value = sbom_metrics.get(metric)
        if value is None:
            continue
        status = _evaluate_rules(float(value), sbom_policy.get(metric, {}))
        evaluations["checks"][f"sbom_{metric}"] = {
            "value": float(value),
            "status": status,
        }

    risk_metrics = (
        metrics.get("risk", {}) if isinstance(metrics.get("risk"), Mapping) else {}
    )
    risk_policy = (
        policy.get("risk", {}) if isinstance(policy.get("risk"), Mapping) else {}
    )
    max_risk = risk_metrics.get("max_risk_score")
    if max_risk is not None:
        status = _evaluate_rules(float(max_risk), risk_policy.get("max_risk_score", {}))
        evaluations["checks"]["risk_max_risk_score"] = {
            "value": float(max_risk),
            "status": status,
        }

    repro_match = (
        metrics.get("repro", {}).get("match")
        if isinstance(metrics.get("repro"), Mapping)
        else None
    )
    repro_policy = (
        policy.get("repro", {}) if isinstance(policy.get("repro"), Mapping) else {}
    )
    if repro_match is not None:
        required = bool(repro_policy.get("require_match", True))
        status = "pass" if (not required or repro_match) else "fail"
        evaluations["checks"]["repro_match"] = {
            "value": bool(repro_match),
            "status": status,
        }

    provenance_policy = (
        policy.get("provenance", {})
        if isinstance(policy.get("provenance"), Mapping)
        else {}
    )
    attestation_count = int(metrics.get("provenance", {}).get("count", 0))
    if provenance_policy.get("require_attestations"):
        status = "pass" if attestation_count > 0 else "fail"
        evaluations["checks"]["provenance_attestations"] = {
            "value": attestation_count,
            "status": status,
        }

    overall = "pass"
    for details in evaluations["checks"].values():
        if details.get("status") == "fail":
            overall = "fail"
            break
        if details.get("status") == "warn" and overall != "fail":
            overall = "warn"
    evaluations["overall"] = overall
    return evaluations


def _collect_files(paths: Iterable[Path]) -> list[Path]:
    files: list[Path] = []
    for path in paths:
        if not path:
            continue
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            for candidate in sorted(path.rglob("*")):
                if candidate.is_file():
                    files.append(candidate)
    return files


def _sign_manifest(manifest_path: Path, signature_path: Path, key_path: Path) -> None:
    command = [
        "cosign",
        "sign-blob",
        "--key",
        str(key_path),
        "--output-signature",
        str(signature_path),
        str(manifest_path),
    ]
    subprocess.run(command, check=True)


def create_bundle(inputs: BundleInputs) -> dict[str, Any]:
    tag = inputs.tag
    output_root = inputs.output_dir
    bundle_dir = output_root / "bundles"
    manifest_dir = output_root / "manifests"
    bundle_dir.mkdir(parents=True, exist_ok=True)
    manifest_dir.mkdir(parents=True, exist_ok=True)

    required_files = [
        inputs.normalized_sbom,
        inputs.sbom_quality_json,
        inputs.risk_report,
        inputs.repro_attestation,
    ]
    for path in required_files:
        if not Path(path).is_file():
            raise FileNotFoundError(f"Required evidence file missing: {path}")
    if inputs.provenance_dir and not inputs.provenance_dir.exists():
        raise FileNotFoundError(
            f"Provenance directory '{inputs.provenance_dir}' not found"
        )

    quality_payload = json.loads(inputs.sbom_quality_json.read_text(encoding="utf-8"))
    risk_payload = json.loads(inputs.risk_report.read_text(encoding="utf-8"))
    repro_payload = json.loads(inputs.repro_attestation.read_text(encoding="utf-8"))

    provenance_files = (
        _collect_files([inputs.provenance_dir]) if inputs.provenance_dir else []
    )
    extra_files = _collect_files(inputs.extra_paths)
    bundle_files: list[tuple[Path, str]] = []
    artefact_descriptors: list[dict[str, Any]] = []

    mapping = [
        (inputs.normalized_sbom, f"sbom/{inputs.normalized_sbom.name}"),
        (inputs.sbom_quality_json, "sbom/quality.json"),
    ]
    if inputs.sbom_quality_html and inputs.sbom_quality_html.is_file():
        mapping.append((inputs.sbom_quality_html, "sbom/quality.html"))
    mapping.extend(
        [
            (inputs.risk_report, "risk/risk.json"),
            (inputs.repro_attestation, f"repro/{inputs.repro_attestation.name}"),
        ]
    )

    for source, arcname in mapping:
        bundle_files.append((source, arcname))
        artefact_descriptors.append(
            {
                "name": arcname,
                "source": str(source),
                "sha256": _digest_file(source),
            }
        )

    prov_seen: set[str] = set()
    for prov_file in provenance_files:
        try:
            rel = prov_file.relative_to(inputs.provenance_dir)
        except ValueError:
            rel = Path(prov_file.name)
        arcname = f"provenance/{rel}"
        if arcname in prov_seen:
            arcname = f"provenance/{prov_file.parent.name}/{prov_file.name}"
        prov_seen.add(arcname)
        bundle_files.append((prov_file, arcname))
        artefact_descriptors.append(
            {
                "name": arcname,
                "source": str(prov_file),
                "sha256": _digest_file(prov_file),
            }
        )

    extra_seen: set[str] = set()
    for extra in extra_files:
        arcname = f"extra/{extra.name}"
        if arcname in extra_seen:
            arcname = f"extra/{extra.parent.name}/{extra.name}"
        extra_seen.add(arcname)
        bundle_files.append((extra, arcname))
        artefact_descriptors.append(
            {
                "name": arcname,
                "source": str(extra),
                "sha256": _digest_file(extra),
            }
        )

    metrics = {
        "sbom": quality_payload.get("metrics", {}),
        "risk": {
            "component_count": risk_payload.get("summary", {}).get("component_count"),
            "cve_count": risk_payload.get("summary", {}).get("cve_count"),
            "max_risk_score": risk_payload.get("summary", {}).get("max_risk_score"),
        },
        "repro": {"match": bool(repro_payload.get("match"))},
        "provenance": {"count": len(provenance_files)},
    }

    policy = load_policy(inputs.policy_path)
    evaluations = evaluate_policy(policy, metrics=metrics)

    manifest = {
        "tag": tag,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "artefacts": artefact_descriptors,
        "metrics": metrics,
        "policy": policy,
        "evaluations": evaluations,
    }

    manifest_path = manifest_dir / f"{tag}.yaml"
    with manifest_path.open("w", encoding="utf-8") as handle:
        yaml.safe_dump(manifest, handle, sort_keys=False)

    bundle_path = bundle_dir / f"{tag}.zip"
    with ZipFile(bundle_path, "w") as archive:
        for source, arcname in bundle_files:
            archive.write(source, arcname)
        archive.write(manifest_path, "MANIFEST.yaml")
        if inputs.sign_key:
            with tempfile.NamedTemporaryFile(
                suffix=".sig", delete=False
            ) as tmp_signature:
                tmp_path = Path(tmp_signature.name)
            try:
                _sign_manifest(manifest_path, tmp_path, inputs.sign_key)
                archive.write(tmp_path, "MANIFEST.yaml.sig")
            finally:
                if "tmp_path" in locals() and tmp_path.exists():
                    tmp_path.unlink()

    manifest["bundle_path"] = str(bundle_path)
    manifest["manifest_path"] = str(manifest_path)
    return manifest


__all__ = ["BundleInputs", "create_bundle", "load_policy", "evaluate_policy"]
