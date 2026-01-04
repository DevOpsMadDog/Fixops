"""Utilities for generating and verifying SLSA v1 provenance attestations.

This module implements the in-toto attestation framework with SLSA v1 provenance
predicates. It supports RSA-SHA256 signing of attestations when the enterprise
crypto module is available.

References:
- in-toto attestation framework: https://github.com/in-toto/attestation
- SLSA v1 provenance: https://slsa.dev/provenance/v1
"""

from __future__ import annotations

import base64
import json
import logging
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Callable, Mapping, MutableMapping, Optional, Sequence, Tuple

from telemetry import get_meter, get_tracer

logger = logging.getLogger(__name__)

SLSA_VERSION = "1.0"
IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
SLSA_PROVENANCE_PREDICATE_TYPE = "https://slsa.dev/provenance/v1"

_rsa_sign: Optional[Callable[[bytes], Tuple[bytes, str]]] = None
_rsa_verify: Optional[Callable[[bytes, bytes, str], bool]] = None

try:
    from fixops_enterprise.src.utils.crypto import rsa_sign as _enterprise_rsa_sign
    from fixops_enterprise.src.utils.crypto import rsa_verify as _enterprise_rsa_verify

    _rsa_sign = _enterprise_rsa_sign
    _rsa_verify = _enterprise_rsa_verify
except ImportError:
    try:
        import sys

        # Use append instead of insert(0) to avoid shadowing repo root packages
        # like services.graph when the enterprise path is searched first
        sys.path.append(
            str(Path(__file__).parent.parent.parent / "fixops-enterprise" / "src")
        )
        from utils.crypto import rsa_sign as _alt_rsa_sign
        from utils.crypto import rsa_verify as _alt_rsa_verify

        _rsa_sign = _alt_rsa_sign
        _rsa_verify = _alt_rsa_verify
    except ImportError:
        pass

_TRACER = get_tracer("fixops.provenance")
_COUNTER = get_meter("fixops.provenance").create_counter(
    "fixops_provenance_operations",
    description="Count of provenance attestation operations",
)


def _now() -> datetime:
    seed = os.getenv("FIXOPS_TEST_SEED")
    if seed:
        normalized_seed = seed.replace("Z", "+00:00")
        seeded = datetime.fromisoformat(normalized_seed)
        if seeded.tzinfo is None:
            seeded = seeded.replace(tzinfo=timezone.utc)
        else:
            seeded = seeded.astimezone(timezone.utc)
        return seeded
    return datetime.now(timezone.utc)


class ProvenanceVerificationError(Exception):
    """Raised when provenance verification fails."""


def _normalise_subject_name(path: Path) -> str:
    resolved = path.resolve()
    try:
        relative = resolved.relative_to(Path.cwd())
    except ValueError:
        relative = resolved
    return relative.as_posix()


def _validate_schema(payload: Mapping[str, Any]) -> None:
    required_fields = {
        "slsaVersion",
        "builder",
        "buildType",
        "source",
        "metadata",
        "subject",
    }
    missing = [field for field in required_fields if field not in payload]
    if missing:
        raise ProvenanceVerificationError(
            f"Attestation missing required fields: {', '.join(sorted(missing))}"
        )

    if not isinstance(payload.get("subject"), Sequence) or not payload["subject"]:
        raise ProvenanceVerificationError(
            "Attestation must include at least one subject"
        )

    for index, subject in enumerate(payload["subject"]):
        if not isinstance(subject, Mapping):
            raise ProvenanceVerificationError(f"Subject entry {index} is not a mapping")
        name = subject.get("name")
        digest = subject.get("digest")
        if not isinstance(name, str) or not name:
            raise ProvenanceVerificationError(
                f"Subject entry {index} is missing a valid name"
            )
        if not isinstance(digest, Mapping) or "sha256" not in digest:
            raise ProvenanceVerificationError(
                f"Subject entry {index} must include a sha256 digest"
            )

    builder = payload.get("builder", {})
    if not isinstance(builder, Mapping) or "id" not in builder:
        raise ProvenanceVerificationError("Builder block must include an 'id'")

    source = payload.get("source", {})
    if not isinstance(source, Mapping) or "uri" not in source:
        raise ProvenanceVerificationError("Source block must include a 'uri'")

    metadata = payload.get("metadata")
    if not isinstance(metadata, Mapping):
        raise ProvenanceVerificationError("Metadata block must be a mapping")


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

        _validate_schema(payload)
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
            ProvenanceSubject(name=str(item["name"]), digest=dict(item["digest"]))
            for item in raw_subjects
        ]
        materials = [
            ProvenanceMaterial(
                uri=str(item["uri"]),
                digest=dict(item.get("digest", {})) if item.get("digest") else None,
            )
            for item in sorted(
                raw_materials, key=lambda entry: str(entry.get("uri", ""))
            )
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

    now = _now()
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

    with _TRACER.start_as_current_span("provenance.compute_sha256") as span:
        resolved = Path(path)
        span.set_attribute("fixops.artifact", str(resolved))
        if not resolved.is_file():
            raise FileNotFoundError(
                f"Artefact '{resolved}' does not exist or is not a file"
            )

        digest = sha256()
        with resolved.open("rb") as handle:
            for chunk in iter(lambda: handle.read(8192), b""):
                digest.update(chunk)
        hex_digest = digest.hexdigest()
        span.set_attribute("fixops.sha256", hex_digest)
        return hex_digest


def _normalise_materials(
    materials: Sequence[Mapping[str, Any]] | None,
) -> list[ProvenanceMaterial]:
    """Convert user-supplied material mappings to dataclass instances."""

    normalised: list[ProvenanceMaterial] = []
    if not materials:
        return normalised
    for item in sorted(materials, key=lambda entry: str(entry.get("uri", ""))):
        if "uri" not in item:
            raise ValueError("Each material must include a 'uri' field")
        digest_mapping = item.get("digest")
        raw_uri = item["uri"]
        if isinstance(raw_uri, str) and "://" not in raw_uri:
            uri = Path(raw_uri).resolve().as_posix()
        else:
            uri = str(raw_uri)
        normalised.append(
            ProvenanceMaterial(
                uri=uri,
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

    with _TRACER.start_as_current_span("provenance.generate_attestation") as span:
        path = Path(artefact_path)
        span.set_attribute("fixops.artifact", str(path))
        span.set_attribute("fixops.builder", builder_id)
        span.set_attribute("fixops.source_uri", source_uri)
        digest = compute_sha256(path)
        metadata_block = _ensure_metadata(metadata)
        subject_name = _normalise_subject_name(path)
        subject = ProvenanceSubject(
            name=subject_name,
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
        _COUNTER.add(1, {"action": "generate"})
        return attestation


def load_attestation(
    source: Path | str | Mapping[str, Any] | ProvenanceAttestation,
) -> ProvenanceAttestation:
    """Load an attestation from a path, mapping or existing object."""

    with _TRACER.start_as_current_span("provenance.load_attestation") as span:
        if isinstance(source, ProvenanceAttestation):
            span.set_attribute("fixops.source", "object")
            return source
        if isinstance(source, Mapping):
            span.set_attribute("fixops.source", "mapping")
            return ProvenanceAttestation.from_dict(source)

        path = Path(source)
        span.set_attribute("fixops.source", str(path))
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
        _COUNTER.add(1, {"action": "load"})
        return ProvenanceAttestation.from_dict(payload)


def write_attestation(
    attestation: ProvenanceAttestation, destination: Path | str
) -> Path:
    """Persist *attestation* to *destination* as JSON."""

    with _TRACER.start_as_current_span("provenance.write_attestation") as span:
        path = Path(destination)
        span.set_attribute("fixops.destination", str(path))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(attestation.to_json(indent=2), encoding="utf-8")
        _COUNTER.add(1, {"action": "write"})
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
    expected_names = {
        path.name,
        path.resolve().as_posix(),
        _normalise_subject_name(path),
    }

    subjects = _expect_field(statement.subject, "subject entry")
    subject = next(
        (item for item in subjects if item.name in expected_names),
        None,
    )
    if subject is None:
        raise ProvenanceVerificationError(
            "No attestation subject matched the provided artefact"
        )
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
            raise ProvenanceVerificationError(
                "Invalid buildFinishedOn timestamp format"
            )

    # No return value on success.


@dataclass
class InTotoStatement:
    """In-toto attestation statement following the v1 specification.

    This wraps a SLSA provenance predicate in the standard in-toto statement
    format, which includes:
    - _type: The statement type URI
    - subject: Array of ResourceDescriptors identifying the artifacts
    - predicateType: URI identifying the predicate schema
    - predicate: The actual predicate content (SLSA provenance)
    """

    _type: str
    subject: list[dict[str, Any]]
    predicateType: str
    predicate: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "_type": self._type,
            "subject": self.subject,
            "predicateType": self.predicateType,
            "predicate": self.predicate,
        }

    def to_json(self, *, indent: Optional[int] = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    @classmethod
    def from_provenance(cls, attestation: ProvenanceAttestation) -> "InTotoStatement":
        subjects = [
            {"name": s.name, "digest": dict(s.digest)} for s in attestation.subject
        ]

        predicate = {
            "buildDefinition": {
                "buildType": attestation.buildType,
                "externalParameters": {"source": attestation.source},
                "internalParameters": {},
                "resolvedDependencies": [
                    {"uri": m.uri, "digest": m.digest}
                    for m in attestation.materials
                    if m.digest
                ],
            },
            "runDetails": {
                "builder": attestation.builder,
                "metadata": attestation.metadata,
            },
        }

        return cls(
            _type=IN_TOTO_STATEMENT_TYPE,
            subject=subjects,
            predicateType=SLSA_PROVENANCE_PREDICATE_TYPE,
            predicate=predicate,
        )


@dataclass
class InTotoEnvelope:
    """DSSE (Dead Simple Signing Envelope) for in-toto attestations.

    This envelope wraps a signed in-toto statement with:
    - payloadType: Media type of the payload
    - payload: Base64-encoded statement JSON
    - signatures: Array of signature objects with sig and keyid
    """

    payloadType: str
    payload: str
    signatures: list[dict[str, str]]

    def to_dict(self) -> dict[str, Any]:
        return {
            "payloadType": self.payloadType,
            "payload": self.payload,
            "signatures": self.signatures,
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, sort_keys=True)

    @classmethod
    def from_statement(
        cls,
        statement: InTotoStatement,
        *,
        sign: bool = True,
        require_signature: bool = False,
    ) -> "InTotoEnvelope":
        """Create an envelope from an in-toto statement.

        Args:
            statement: The in-toto statement to wrap
            sign: Whether to attempt signing (default True)
            require_signature: If True, raise exception when signing fails (fail-closed)

        Returns:
            InTotoEnvelope containing the (optionally signed) statement

        Raises:
            RuntimeError: If require_signature=True and signing fails or is unavailable
        """
        payload_bytes = statement.to_json(indent=None).encode("utf-8")
        payload_b64 = base64.b64encode(payload_bytes).decode("utf-8")

        signatures: list[dict[str, str]] = []

        if sign:
            if _rsa_sign is None:
                if require_signature:
                    raise RuntimeError(
                        "Signing required but RSA signing module is not available. "
                        "Install fixops-enterprise package or configure core.crypto module."
                    )
                logger.warning(
                    "RSA signing module not available, envelope will be unsigned"
                )
            else:
                try:
                    signature_bytes, fingerprint = _rsa_sign(payload_bytes)
                    signature_b64 = base64.b64encode(signature_bytes).decode("utf-8")
                    signatures.append({"keyid": fingerprint, "sig": signature_b64})
                    logger.info(
                        "In-toto statement signed with RSA-SHA256",
                        extra={"fingerprint": fingerprint},
                    )
                except Exception as exc:
                    if require_signature:
                        raise RuntimeError(
                            f"Signing required but failed: {exc}"
                        ) from exc
                    logger.warning(f"Failed to sign in-toto statement: {exc}")

        return cls(
            payloadType="application/vnd.in-toto+json",
            payload=payload_b64,
            signatures=signatures,
        )


def generate_signed_attestation(
    artefact_path: Path | str,
    *,
    builder_id: str,
    source_uri: str,
    build_type: str,
    materials: Sequence[Mapping[str, Any]] | None = None,
    metadata: Mapping[str, Any] | None = None,
    sign: bool = True,
    require_signature: bool = False,
) -> InTotoEnvelope:
    """Generate a signed SLSA v1 provenance attestation in in-toto envelope format.

    This function creates a complete, signed attestation following the in-toto
    attestation framework with SLSA v1 provenance predicate.

    Args:
        artefact_path: Path to the artifact being attested
        builder_id: URI identifying the build system
        source_uri: URI of the source repository
        build_type: URI identifying the build type
        materials: Optional list of build materials/dependencies
        metadata: Optional additional metadata
        sign: Whether to sign the attestation (default True)
        require_signature: If True, raise exception when signing fails (fail-closed)

    Returns:
        InTotoEnvelope containing the signed attestation

    Raises:
        RuntimeError: If require_signature=True and signing fails or is unavailable
    """
    with _TRACER.start_as_current_span(
        "provenance.generate_signed_attestation"
    ) as span:
        attestation = generate_attestation(
            artefact_path,
            builder_id=builder_id,
            source_uri=source_uri,
            build_type=build_type,
            materials=materials,
            metadata=metadata,
        )

        statement = InTotoStatement.from_provenance(attestation)
        envelope = InTotoEnvelope.from_statement(
            statement, sign=sign, require_signature=require_signature
        )

        span.set_attribute("fixops.signed", len(envelope.signatures) > 0)
        _COUNTER.add(1, {"action": "generate_signed"})

        return envelope


def write_signed_attestation(envelope: InTotoEnvelope, destination: Path | str) -> Path:
    """Persist a signed attestation envelope to disk."""
    with _TRACER.start_as_current_span("provenance.write_signed_attestation") as span:
        path = Path(destination)
        span.set_attribute("fixops.destination", str(path))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(envelope.to_json(indent=2), encoding="utf-8")
        _COUNTER.add(1, {"action": "write_signed"})
        return path


def verify_envelope_signature(envelope: InTotoEnvelope) -> bool:
    """Verify the RSA signature on an in-toto envelope.

    Returns True if the signature is valid, False otherwise.
    """
    if _rsa_verify is None:
        logger.warning("RSA verification module not available")
        return False

    if not envelope.signatures:
        logger.warning("Envelope has no signatures to verify")
        return False

    try:
        payload_bytes = base64.b64decode(envelope.payload)
    except Exception as exc:
        logger.warning(f"Failed to decode envelope payload: {exc}")
        return False

    for sig_entry in envelope.signatures:
        keyid = sig_entry.get("keyid", "")
        sig_b64 = sig_entry.get("sig", "")

        if not keyid or not sig_b64:
            continue

        try:
            signature_bytes = base64.b64decode(sig_b64)
            if _rsa_verify(payload_bytes, signature_bytes, keyid):
                logger.info(
                    "Envelope signature verified",
                    extra={"fingerprint": keyid},
                )
                return True
        except Exception as exc:
            logger.warning(f"Signature verification failed for keyid {keyid}: {exc}")

    return False


__all__ = [
    "InTotoEnvelope",
    "InTotoStatement",
    "IN_TOTO_STATEMENT_TYPE",
    "ProvenanceAttestation",
    "ProvenanceMaterial",
    "ProvenanceSubject",
    "ProvenanceVerificationError",
    "SLSA_PROVENANCE_PREDICATE_TYPE",
    "SLSA_VERSION",
    "compute_sha256",
    "generate_attestation",
    "generate_signed_attestation",
    "load_attestation",
    "verify_attestation",
    "verify_envelope_signature",
    "write_attestation",
    "write_signed_attestation",
]
