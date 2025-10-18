"""CLI helpers for generating and verifying FixOps provenance."""

from __future__ import annotations

import argparse
import json
import os
import sys
from base64 import b64decode, b64encode
from pathlib import Path
from typing import Any, Iterable, Mapping

from services.provenance import (
    ProvenanceVerificationError,
    generate_attestation,
    verify_attestation,
    write_attestation,
)

DEFAULT_BUILDER_ID = os.getenv("FIXOPS_BUILDER_ID", "urn:fixops:builder:local")
DEFAULT_SOURCE_URI = os.getenv(
    "FIXOPS_SOURCE_URI", "https://github.com/DevOpsMadDog/Fixops"
)
DEFAULT_BUILD_TYPE = os.getenv("FIXOPS_BUILD_TYPE", "https://github.com/actions/run")


def _parse_json(value: str, *, description: str) -> Mapping[str, Any]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise argparse.ArgumentTypeError(
            f"Invalid JSON for {description}: {exc.msg}"
        ) from exc
    if not isinstance(parsed, Mapping):
        raise argparse.ArgumentTypeError(
            f"Expected {description} JSON object, received {type(parsed).__name__}"
        )
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fixops-provenance",
        description="Generate and verify SLSA v1 provenance attestations.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    attest_parser = subparsers.add_parser(
        "attest", help="Generate a provenance attestation for an artefact"
    )
    attest_parser.add_argument(
        "--artifact", required=True, help="Path to artefact file"
    )
    attest_parser.add_argument(
        "--out", required=True, help="Destination path for the generated attestation"
    )
    attest_parser.add_argument(
        "--builder-id",
        default=DEFAULT_BUILDER_ID,
        help="Builder identifier recorded in the attestation",
    )
    attest_parser.add_argument(
        "--source-uri",
        default=DEFAULT_SOURCE_URI,
        help="Source repository URI recorded in the attestation",
    )
    attest_parser.add_argument(
        "--build-type",
        default=DEFAULT_BUILD_TYPE,
        help="Build type URI for the attestation",
    )
    attest_parser.add_argument(
        "--metadata",
        help="Optional JSON metadata object to merge into the attestation",
        type=lambda value: _parse_json(value, description="metadata"),
    )
    attest_parser.add_argument(
        "--material",
        action="append",
        type=lambda value: _parse_json(value, description="material"),
        help=(
            "Optional JSON material descriptor (repeatable). Each must include a 'uri' "
            "and may provide a 'digest' mapping."
        ),
    )
    attest_parser.add_argument(
        "--signing-key",
        help="Optional path to a PEM-encoded Ed25519 private key for signing",
    )
    attest_parser.add_argument(
        "--signature-out",
        help="Optional path for the generated signature (defaults to attestation path + .sig)",
    )

    verify_parser = subparsers.add_parser(
        "verify", help="Verify a provenance attestation against an artefact"
    )
    verify_parser.add_argument(
        "--artifact", required=True, help="Path to artefact file to verify"
    )
    verify_parser.add_argument(
        "--attestation",
        required=True,
        help="Path to the attestation JSON file to verify",
    )
    verify_parser.add_argument(
        "--builder-id",
        help="Expected builder identifier; checked if provided",
    )
    verify_parser.add_argument(
        "--source-uri",
        help="Expected source URI; checked if provided",
    )
    verify_parser.add_argument(
        "--build-type",
        help="Expected build type URI; checked if provided",
    )
    verify_parser.add_argument(
        "--signature",
        help="Optional signature file to verify alongside the attestation",
    )
    verify_parser.add_argument(
        "--public-key",
        help="Optional PEM-encoded Ed25519 public key matching the signature",
    )

    return parser


def _load_private_key(path: str):
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError("cryptography is required for signing attestations") from exc

    data = Path(path).read_bytes()
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise RuntimeError("Signing key must be an Ed25519 private key")
    return key


def _load_public_key(path: str):
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise RuntimeError(
            "cryptography is required for signature verification"
        ) from exc

    data = Path(path).read_bytes()
    key = serialization.load_pem_public_key(data)
    if not isinstance(key, Ed25519PublicKey):
        raise RuntimeError("Public key must be an Ed25519 key")
    return key


def _sign_attestation(path: Path, signing_key: str, signature_out: str | None) -> Path:
    key = _load_private_key(signing_key)
    payload = path.read_bytes()
    signature = key.sign(payload)
    destination = (
        Path(signature_out) if signature_out else path.with_suffix(path.suffix + ".sig")
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(b64encode(signature).decode("ascii"), encoding="utf-8")
    return destination


def _verify_signature(attestation: Path, signature_path: str, public_key: str) -> None:
    key = _load_public_key(public_key)
    payload = attestation.read_bytes()
    signature_bytes = b64decode(Path(signature_path).read_text(encoding="utf-8"))
    try:
        key.verify(signature_bytes, payload)
    except Exception as exc:  # pragma: no cover - verification failure
        raise RuntimeError(f"Signature verification failed: {exc}") from exc


def _handle_attest(args: argparse.Namespace) -> int:
    materials = args.material if args.material else None
    attestation = generate_attestation(
        args.artifact,
        builder_id=args.builder_id,
        source_uri=args.source_uri,
        build_type=args.build_type,
        materials=materials,
        metadata=args.metadata,
    )
    destination = write_attestation(attestation, args.out)
    print(f"Wrote attestation to {destination}")
    if args.signing_key:
        try:
            signature_path = _sign_attestation(
                Path(destination), args.signing_key, args.signature_out
            )
        except Exception as exc:
            print(f"Failed to sign attestation: {exc}", file=sys.stderr)
            return 2
        print(f"Wrote attestation signature to {signature_path}")
    return 0


def _handle_verify(args: argparse.Namespace) -> int:
    if bool(args.signature) != bool(args.public_key):
        print(
            "Signature verification requires both --signature and --public-key",
            file=sys.stderr,
        )
        return 2
    try:
        attestation_path = Path(args.attestation)
        if args.signature and args.public_key:
            _verify_signature(attestation_path, args.signature, args.public_key)
        verify_attestation(
            args.attestation,
            artefact_path=args.artifact,
            builder_id=args.builder_id,
            source_uri=args.source_uri,
            build_type=args.build_type,
        )
    except (FileNotFoundError, ProvenanceVerificationError, RuntimeError) as exc:
        print(f"Verification failed: {exc}", file=sys.stderr)
        return 1
    print("Verification succeeded")
    return 0


def main(argv: Iterable[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.command == "attest":
        return _handle_attest(args)
    if args.command == "verify":
        return _handle_verify(args)

    parser.error("No command specified")
    return 2  # pragma: no cover - argparse will raise before


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    raise SystemExit(main())
