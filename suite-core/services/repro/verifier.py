"""Reproducible build verification helpers."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable, Mapping

import yaml

from services.provenance.attestation import load_attestation
from telemetry import get_meter, get_tracer


@dataclass(slots=True)
class VerificationResult:
    """Result of executing a reproducible build plan."""

    tag: str
    plan: str
    artifact: str
    artifact_path: str
    generated_digest: dict[str, str]
    reference_digest: dict[str, str] | None
    match: bool
    verified_at: str
    reference_source: str | None = None
    attestation_path: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tag": self.tag,
            "plan": self.plan,
            "artifact": self.artifact,
            "artifact_path": self.artifact_path,
            "generated_digest": self.generated_digest,
            "reference_digest": self.reference_digest,
            "match": self.match,
            "verified_at": self.verified_at,
            "reference_source": self.reference_source,
            "attestation_path": self.attestation_path,
        }


_TRACER = get_tracer("fixops.repro")
_METER = get_meter("fixops.repro")
_REPRO_COUNTER = _METER.create_counter(
    "fixops_repro_verifications",
    description="Number of reproducibility checks executed",
)


def _normalise_digest(value: str | None) -> str | None:
    if not value:
        return None
    value = value.strip()
    if ":" in value:
        _, digest = value.split(":", 1)
        return digest.strip()
    return value


def _substitute_tag(payload: Any, tag: str) -> Any:
    if isinstance(payload, str):
        return payload.replace("{tag}", tag)
    if isinstance(payload, Mapping):
        return {key: _substitute_tag(value, tag) for key, value in payload.items()}
    if isinstance(payload, list):
        return [_substitute_tag(item, tag) for item in payload]
    return payload


def load_plan(path: Path | str, *, tag: str | None = None) -> dict[str, Any]:
    """Load a YAML plan file and apply optional tag substitution."""

    plan_path = Path(path)
    with plan_path.open("r", encoding="utf-8") as handle:
        data = yaml.safe_load(handle) or {}
    if not isinstance(data, dict):
        raise ValueError("Plan must be a mapping")
    if tag:
        data = _substitute_tag(data, tag)
    data.setdefault("tag", tag or data.get("tag") or "unknown")
    data["__plan_path__"] = str(plan_path)
    return data


def _copy_source(source: Path, destination: Path) -> None:
    if source.is_dir():
        shutil.copytree(source, destination, dirs_exist_ok=True)
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)


def _materialise_sources(
    sources: Iterable[Any], repo_root: Path, workspace: Path
) -> None:
    for entry in sources or []:
        if isinstance(entry, str):
            source_path = (repo_root / entry).resolve()
            destination = workspace / Path(entry).name
        elif isinstance(entry, Mapping):
            path_value = entry.get("path")
            if not isinstance(path_value, str):
                continue
            source_path = (repo_root / path_value).resolve()
            destination_name = entry.get("destination") or Path(path_value).name
            destination = workspace / destination_name
        else:
            continue
        if not source_path.exists():
            raise FileNotFoundError(f"Source path '{source_path}' does not exist")
        _copy_source(source_path, destination)


def _run_steps(
    steps: Iterable[Any], workspace: Path, env: Mapping[str, Any] | None
) -> None:
    if not steps:
        raise ValueError("Plan must include at least one step")
    base_env = {"PATH": os.environ.get("PATH", "")}
    if env:
        base_env.update({key: str(value) for key, value in env.items()})
    for step in steps:
        command = None
        if isinstance(step, Mapping):
            command = step.get("run")
        elif isinstance(step, (list, tuple)):
            command = [str(part) for part in step]
        elif isinstance(step, str):
            command = step
        if command is None:
            continue
        if isinstance(command, str):
            subprocess.run(
                shlex.split(command),
                cwd=workspace,
                env=base_env,
                shell=False,
                check=True,
            )
        else:
            subprocess.run(
                [str(part) for part in command],
                cwd=workspace,
                env=base_env,
                check=True,
            )


def _compute_digest(path: Path) -> str:
    digest = sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _resolve_reference(
    plan: Mapping[str, Any], repo_root: Path, artifact_name: str
) -> tuple[str | None, str | None]:
    expected = _normalise_digest(plan.get("expected_digest"))
    if expected:
        return expected, "expected_digest"

    attestation_path_value = plan.get("reference_attestation") or plan.get(
        "attestation"
    )
    if isinstance(attestation_path_value, str):
        attestation_path = (repo_root / attestation_path_value).resolve()
        if not attestation_path.is_file():
            raise FileNotFoundError(f"Attestation '{attestation_path}' not found")
        attestation = load_attestation(attestation_path)
        for subject in attestation.subject:
            if (
                subject.name == artifact_name
                or subject.name == Path(artifact_name).name
            ):
                digest_value = subject.digest.get("sha256")
                if digest_value:
                    return digest_value, f"attestation:{attestation_path_value}"
        if attestation.subject:
            digest_value = attestation.subject[0].digest.get("sha256")
            if digest_value:
                return digest_value, f"attestation:{attestation_path_value}"

    reference_artifact = plan.get("reference_artifact") or plan.get(
        "artifact_reference"
    )
    if isinstance(reference_artifact, str):
        reference_path = (repo_root / reference_artifact).resolve()
        if not reference_path.is_file():
            raise FileNotFoundError(f"Reference artifact '{reference_path}' not found")
        return _compute_digest(reference_path), f"artifact:{reference_artifact}"

    return None, None


def verify_plan(
    plan: Mapping[str, Any], *, repo_root: Path | str = Path(".")
) -> VerificationResult:
    """Execute *plan* in a temporary workspace and return the verification result."""

    repo_path = Path(repo_root).resolve()
    artifact_rel = plan.get("artifact")
    if not isinstance(artifact_rel, str):
        raise ValueError("Plan is missing 'artifact' entry")
    tag = str(plan.get("tag") or "unknown")
    steps = plan.get("steps") or plan.get("build_steps")
    environment = plan.get("environment")

    with _TRACER.start_as_current_span("repro.verify_plan") as span:
        span.set_attribute("fixops.repro.tag", tag)
        with tempfile.TemporaryDirectory(prefix="fixops-repro-") as workspace_dir:
            workspace = Path(workspace_dir)
            _materialise_sources(plan.get("sources", []), repo_path, workspace)
            _run_steps(steps, workspace, environment)
            artefact_path = (workspace / artifact_rel).resolve()
            if not artefact_path.is_file():
                raise FileNotFoundError(
                    f"Expected artefact '{artifact_rel}' not produced"
                )
            generated_digest = _compute_digest(artefact_path)
            expected_digest, reference_source = _resolve_reference(
                plan, repo_path, Path(artifact_rel).name
            )
            result = VerificationResult(
                tag=tag,
                plan=str(plan.get("__plan_path__", "")),
                artifact=artifact_rel,
                artifact_path=str(artefact_path),
                generated_digest={"sha256": generated_digest},
                reference_digest=(
                    {"sha256": expected_digest} if expected_digest else None
                ),
                match=bool(expected_digest and generated_digest == expected_digest),
                verified_at=datetime.now(timezone.utc).isoformat(),
                reference_source=reference_source,
            )
            span.set_attribute("fixops.repro.match", result.match)
            if expected_digest:
                span.set_attribute(
                    "fixops.repro.reference", reference_source or "unknown"
                )
            return result


def run_verification(
    plan_path: Path | str,
    tag: str,
    *,
    output_dir: Path | str,
    repo_root: Path | str = Path("."),
) -> VerificationResult:
    """Load *plan_path*, execute verification, and persist the attestation JSON."""

    plan = load_plan(plan_path, tag=tag)
    result = verify_plan(plan, repo_root=repo_root)
    output_directory = Path(output_dir)
    output_directory.mkdir(parents=True, exist_ok=True)
    attestation_path = output_directory / f"{tag}.json"
    with attestation_path.open("w", encoding="utf-8") as handle:
        json.dump(result.to_dict(), handle, indent=2, sort_keys=True)
        handle.write("\n")
    result.attestation_path = str(attestation_path)
    _REPRO_COUNTER.add(1, {"match": str(result.match).lower()})
    return result


__all__ = [
    "VerificationResult",
    "load_plan",
    "verify_plan",
    "run_verification",
]
