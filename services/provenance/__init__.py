"""SLSA v1 provenance attestation utilities with in-toto envelope support.

This module provides utilities for generating and verifying SLSA v1 provenance
attestations following the in-toto attestation framework. It supports RSA-SHA256
signing of attestations when the enterprise crypto module is available.

Key features:
- SLSA v1 provenance predicate generation
- In-toto attestation statement format
- DSSE (Dead Simple Signing Envelope) support
- RSA-SHA256 signature generation and verification
"""

from .attestation import (
    IN_TOTO_STATEMENT_TYPE,
    SLSA_PROVENANCE_PREDICATE_TYPE,
    SLSA_VERSION,
    InTotoEnvelope,
    InTotoStatement,
    ProvenanceAttestation,
    ProvenanceMaterial,
    ProvenanceSubject,
    ProvenanceVerificationError,
    compute_sha256,
    generate_attestation,
    generate_signed_attestation,
    load_attestation,
    verify_attestation,
    verify_envelope_signature,
    write_attestation,
    write_signed_attestation,
)

__all__ = [
    "IN_TOTO_STATEMENT_TYPE",
    "InTotoEnvelope",
    "InTotoStatement",
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
