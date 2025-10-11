"""Utilities for generating and verifying SLSA v1 provenance attestations."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone, timedelta
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping, MutableMapping, Sequence

SLSA_VERSION = "1.0"


class ProvenanceVerificationError(Exception):
    """Raised when provenance verification fails."""


@dataclass(slots=True)
class ProvenanceSubject:
    """Describes the subject of the attestation (i.e., produced artefact)."""

    name: str
    digest: MutableMapping[str, str]


@dataclass(slots=True)
class ProvenanceMaterial:
    """Describes a build material consumed during attestation."""

    uri: str
    digest: MutableMapping[str, str] | None = None


@dataclass(slots=True)
class ProvenanceAttestation:
    """Structured representation of a SLSA v1 provenance statement."""

    slsaVersion: str
    builder: MutableMapping[str, Any]
    buildType: str
    source: MutableMapping[str, Any]
    metadata: MutableMapping[str, Any]
    subject: list[ProvenanceSubject] = field(default_factory=list)
    materials: list[ProvenanceMaterial] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation of the attestation."""

        return asdict(self)

    def to_json(self, *, indent: int = 2) -> str:
        """Serialise the attestation to JSON text."""

        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> "ProvenanceAttestation":
        """Hydrate an attestation from a dictionary, validating basic structure."""

        try:
            version = payload["slsaVersion"]
            builder = payload["builder"]
            build_type = payload["buildType"]
            source = payload["source"]
            metadata = payload["metadata"]
            raw_subjects = payload.get("subject", [])
            raw_materials = payload.get("materials", [])
        except KeyError as exc:  # pragma: no cover - defensive guard
            raise ProvenanceVerificationError(
                f"Missing required attestation field: {exc.args[0]}"
            ) from exc

        if version != SLSA_VERSION:
            raise ProvenanceVerificationError(
                f"Unsupported SLSA version: {version!r}; expected {SLSA_VERSION!r}"
            )

        subjects = [
            ProvenanceSubject(name=item["name"], digest=dict(item["digest"]))
            for item in raw_subjects
        ]
        materials = [
            ProvenanceMaterial(
                uri=item["uri"],
                digest=dict(item.get("digest", {})) if item.get("digest") else None,
            )
            for item in raw_materials
        ]
        return cls(
            slsaVersion=version,
            builder=dict(builder),
            buildType=build_type,
            source=dict(source),
            metadata=dict(metadata),
            subject=subjects,
            materials=materials,
        )


def _ensure_metadata(metadata: Mapping[str, Any] | None) -> dict[str, Any]:
    """Return attestation metadata with timestamps ensured."""

    now = datetime.now(timezone.utc)
    formatted_now = now.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    defaults: dict[str, Any] = {
        "buildStartedOn": formatted_now,
        "buildFinishedOn": formatted_now,
        "reproducible": True,
    }
    if metadata:
        defaults.update(metadata)
    return defaults


def compute_sha256(path: Path | str) -> str:
    """Compute the SHA-256 digest for the file located at *path*."""

    resolved = Path(path)
    if not resolved.is_file():
        raise FileNotFoundError(f"Artefact '{resolved}' does not exist or is not a file")

    digest = sha256()
    with resolved.open("rb") as handle:
        for chunk in iter(lambda: handle.read(8192), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _normalise_materials(materials: Sequence[Mapping[str, Any]] | None) -> list[ProvenanceMaterial]:
    """Convert user-supplied material mappings to dataclass instances."""

    normalised: list[ProvenanceMaterial] = []
    if not materials:
        return normalised
    for item in materials:
        if "uri" not in item:
            raise ValueError("Each material must include a 'uri' field")
        digest_mapping = item.get("digest")
        normalised.append(
            ProvenanceMaterial(
                uri=str(item["uri"]),
                digest=dict(digest_mapping) if digest_mapping else None,
            )
        )
    return normalised


def generate_attestation(
    artefact_path: Path | str,
    *,
    builder_id: str,
    source_uri: str,
    build_type: str,
    materials: Sequence[Mapping[str, Any]] | None = None,
    metadata: Mapping[str, Any] | None = None,
) -> ProvenanceAttestation:
    """Create a provenance attestation for *artefact_path* following SLSA v1."""

    path = Path(artefact_path)
    digest = compute_sha256(path)
    metadata_block = _ensure_metadata(metadata)
    subject = ProvenanceSubject(
        name=path.name,
        digest={"sha256": digest},
    )
    attestation = ProvenanceAttestation(
        slsaVersion=SLSA_VERSION,
        builder={"id": builder_id},
        buildType=build_type,
        source={"uri": source_uri},
        metadata=metadata_block,
        subject=[subject],
        materials=_normalise_materials(materials),
    )
    return attestation


def load_attestation(source: Path | str | Mapping[str, Any] | ProvenanceAttestation) -> ProvenanceAttestation:
    """Load an attestation from a path, mapping or existing object."""

    if isinstance(source, ProvenanceAttestation):
        return source
    if isinstance(source, Mapping):
        return ProvenanceAttestation.from_dict(source)

    path = Path(source)
    with path.open("r", encoding="utf-8") as handle:
        payload = json.load(handle)
    return ProvenanceAttestation.from_dict(payload)


def write_attestation(attestation: ProvenanceAttestation, destination: Path | str) -> Path:
    """Persist *attestation* to *destination* as JSON."""

    path = Path(destination)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(attestation.to_json(indent=2), encoding="utf-8")
    return path


def _expect_field(value: Any, description: str) -> Any:
    if not value:
        raise ProvenanceVerificationError(f"Attestation missing required {description}")
    return value


def verify_attestation(
    attestation: ProvenanceAttestation | Mapping[str, Any] | Path | str,
    *,
    artefact_path: Path | str,
    builder_id: str | None = None,
    source_uri: str | None = None,
    build_type: str | None = None,
) -> None:
    """Validate that *attestation* matches the provided artefact and expectations."""

    statement = load_attestation(attestation)
    path = Path(artefact_path)
    expected_digest = compute_sha256(path)

    subjects = _expect_field(statement.subject, "subject entry")
    subject = next((item for item in subjects if item.name == path.name), subjects[0])
    attested_digest = subject.digest.get("sha256")
    if attested_digest != expected_digest:
        raise ProvenanceVerificationError(
            "Attestation digest does not match artefact contents"
        )

    if builder_id is not None and statement.builder.get("id") != builder_id:
        raise ProvenanceVerificationError(
            f"Builder ID mismatch: expected {builder_id!r} got {statement.builder.get('id')!r}"
        )
    if source_uri is not None and statement.source.get("uri") != source_uri:
        raise ProvenanceVerificationError(
            f"Source URI mismatch: expected {source_uri!r} got {statement.source.get('uri')!r}"
        )
    if build_type is not None and statement.buildType != build_type:
        raise ProvenanceVerificationError(
            f"Build type mismatch: expected {build_type!r} got {statement.buildType!r}"
        )

    _expect_field(statement.metadata, "metadata block")

    # Basic sanity check that timestamps are not in the future beyond a 5 minute tolerance.
    finished_on = statement.metadata.get("buildFinishedOn")
    if finished_on:
        try:
            parsed = datetime.fromisoformat(finished_on.replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            if parsed - now > timedelta(minutes=5):  # pragma: no cover - defensive
                raise ProvenanceVerificationError(
                    "Attestation completion time is unreasonably in the future"
                )
        except ValueError:  # pragma: no cover - defensive guard
            raise ProvenanceVerificationError("Invalid buildFinishedOn timestamp format")

    # No return value on success.


__all__ = [
    "ProvenanceAttestation",
    "ProvenanceMaterial",
    "ProvenanceSubject",
    "ProvenanceVerificationError",
    "SLSA_VERSION",
    "compute_sha256",
    "generate_attestation",
    "load_attestation",
    "verify_attestation",
    "write_attestation",
]
