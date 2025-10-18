from __future__ import annotations

import json
from pathlib import Path

import pytest

from cli.fixops_provenance import main as provenance_main
from services.provenance import (
    ProvenanceVerificationError,
    generate_attestation,
    verify_attestation,
    write_attestation,
)


@pytest.fixture()
def sample_artifact(tmp_path: Path) -> Path:
    path = tmp_path / "artifact.txt"
    path.write_text("fixops", encoding="utf-8")
    return path


def test_generate_attestation_contains_expected_fields(sample_artifact: Path) -> None:
    attestation = generate_attestation(
        sample_artifact,
        builder_id="urn:fixops:builder:test",
        source_uri="https://example.com/repo",
        build_type="https://example.com/build",
        materials=[{"uri": "https://example.com/material"}],
        metadata={"invocationId": "123"},
    )
    payload = attestation.to_dict()
    assert payload["slsaVersion"] == "1.0"
    assert payload["builder"]["id"] == "urn:fixops:builder:test"
    assert payload["source"]["uri"] == "https://example.com/repo"
    assert payload["buildType"] == "https://example.com/build"
    assert payload["subject"][0]["digest"]["sha256"]
    assert payload["materials"][0]["uri"] == "https://example.com/material"
    assert payload["metadata"]["invocationId"] == "123"


def test_verify_attestation_round_trip(sample_artifact: Path, tmp_path: Path) -> None:
    attestation = generate_attestation(
        sample_artifact,
        builder_id="urn:fixops:builder:test",
        source_uri="https://example.com/repo",
        build_type="https://example.com/build",
    )
    destination = tmp_path / "attestation.json"
    write_attestation(attestation, destination)
    verify_attestation(
        destination,
        artefact_path=sample_artifact,
        builder_id="urn:fixops:builder:test",
        source_uri="https://example.com/repo",
        build_type="https://example.com/build",
    )


def test_verify_attestation_detects_digest_mismatch(
    sample_artifact: Path, tmp_path: Path
) -> None:
    attestation = generate_attestation(
        sample_artifact,
        builder_id="urn:fixops:builder:test",
        source_uri="https://example.com/repo",
        build_type="https://example.com/build",
    ).to_dict()
    attestation["subject"][0]["digest"]["sha256"] = "00"
    destination = tmp_path / "attestation.json"
    destination.write_text(json.dumps(attestation), encoding="utf-8")

    with pytest.raises(ProvenanceVerificationError):
        verify_attestation(
            destination,
            artefact_path=sample_artifact,
            builder_id="urn:fixops:builder:test",
        )


def test_cli_attest_and_verify(tmp_path: Path) -> None:
    artifact = tmp_path / "artifact.bin"
    artifact.write_bytes(b"data")
    attestation_path = tmp_path / "attestation.json"

    exit_code = provenance_main(
        [
            "attest",
            "--artifact",
            str(artifact),
            "--out",
            str(attestation_path),
            "--builder-id",
            "urn:fixops:builder:test",
            "--source-uri",
            "https://example.com/repo",
        ]
    )
    assert exit_code == 0
    assert attestation_path.is_file()

    exit_code = provenance_main(
        [
            "verify",
            "--artifact",
            str(artifact),
            "--attestation",
            str(attestation_path),
            "--builder-id",
            "urn:fixops:builder:test",
            "--source-uri",
            "https://example.com/repo",
        ]
    )
    assert exit_code == 0
