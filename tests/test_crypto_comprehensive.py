"""Tests for the quantum-secure crypto module (suite-core/core/crypto.py).

Covers:
  - Module-level constants
  - CryptoError hierarchy
  - KeyMetadata dataclass
  - HybridSignature dataclass (to_dict / from_dict)
  - VerificationResult dataclass (to_dict / failure factory)
  - SignatureChainEntry dataclass (to_dict / from_dict)
  - RSAKeyManager (generate, load, fingerprint)
  - RSASigner / RSAVerifier (sign / verify round-trip)
"""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone

import pytest

from core.crypto import (
    CryptoError,
    DecryptionError,
    EncryptionError,
    HybridSignature,
    KeyMetadata,
    KeyNotFoundError,
    RSAKeyManager,
    RSASigner,
    RSAVerifier,
    SignatureChainEntry,
    SignatureVerificationError,
    VerificationResult,
    _CURRENT_FORMAT_VERSION,
    _FORMAT_VERSION_V1,
    _FORMAT_VERSION_V2,
    _HYBRID_ALGORITHM,
    _RSA_ALGORITHM,
    _MLDSA_ALGORITHM,
    _DEFAULT_RETENTION_YEARS,
)


# ──────────────────────────────────────────────────────
#  Constants
# ──────────────────────────────────────────────────────


class TestCryptoConstants:
    def test_format_versions(self):
        assert _FORMAT_VERSION_V1 == 1
        assert _FORMAT_VERSION_V2 == 2
        assert _CURRENT_FORMAT_VERSION == _FORMAT_VERSION_V2

    def test_algorithm_strings(self):
        assert _RSA_ALGORITHM == "RSA-SHA256"
        assert _MLDSA_ALGORITHM == "ML-DSA-65"
        assert _HYBRID_ALGORITHM == "hybrid-rsa-ml-dsa"

    def test_retention_years(self):
        assert _DEFAULT_RETENTION_YEARS == 7


# ──────────────────────────────────────────────────────
#  Exception hierarchy
# ──────────────────────────────────────────────────────


class TestCryptoExceptions:
    def test_crypto_error_is_exception(self):
        assert issubclass(CryptoError, Exception)

    def test_key_not_found_error(self):
        err = KeyNotFoundError("key missing")
        assert isinstance(err, CryptoError)

    def test_signature_verification_error(self):
        err = SignatureVerificationError("bad sig")
        assert isinstance(err, CryptoError)

    def test_encryption_error(self):
        err = EncryptionError("encrypt fail")
        assert isinstance(err, CryptoError)

    def test_decryption_error(self):
        err = DecryptionError("decrypt fail")
        assert isinstance(err, CryptoError)


# ──────────────────────────────────────────────────────
#  KeyMetadata dataclass
# ──────────────────────────────────────────────────────


class TestKeyMetadata:
    def test_creation(self):
        km = KeyMetadata(
            key_id="key-001",
            fingerprint="sha256:abc123",
            algorithm="RSA-4096",
            key_size=4096,
            created_at=datetime.now(timezone.utc).isoformat(),
            public_key_pem="-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
        )
        assert km.key_id == "key-001"
        assert km.algorithm == "RSA-4096"
        assert km.key_size == 4096
        assert km.pq_public_key is None

    def test_to_dict(self):
        km = KeyMetadata(
            key_id="key-002",
            fingerprint="sha256:def456",
            algorithm="ML-DSA-65",
            key_size=65,
            created_at="2024-01-01T00:00:00Z",
            public_key_pem="pem-data",
        )
        d = km.to_dict()
        assert isinstance(d, dict)
        assert d["key_id"] == "key-002"
        assert d["algorithm"] == "ML-DSA-65"
        assert d["key_size"] == 65
        assert "pq_public_key" not in d  # None is omitted

    def test_to_dict_with_pq_key(self):
        km = KeyMetadata(
            key_id="key-003",
            fingerprint="sha256:ghi789",
            algorithm="hybrid",
            key_size=4096,
            created_at="2024-01-01T00:00:00Z",
            public_key_pem="pem",
            pq_public_key="base64pqkey",
        )
        d = km.to_dict()
        assert d["pq_public_key"] == "base64pqkey"


# ──────────────────────────────────────────────────────
#  HybridSignature dataclass
# ──────────────────────────────────────────────────────


class TestHybridSignature:
    def test_creation(self):
        sig = HybridSignature(
            format_version=2,
            algorithm="hybrid-rsa-ml-dsa",
            classical_sig="base64rsasig==",
            pq_sig="base64mldsasig==",
            key_fingerprint="sha256:combined",
        )
        assert sig.format_version == 2
        assert sig.algorithm == "hybrid-rsa-ml-dsa"
        assert sig.classical_sig == "base64rsasig=="
        assert sig.pq_sig == "base64mldsasig=="
        assert sig.created_at  # auto-generated

    def test_to_dict(self):
        sig = HybridSignature(
            format_version=2,
            algorithm="hybrid-rsa-ml-dsa",
            classical_sig="sig1",
            pq_sig="sig2",
            key_fingerprint="fp1",
            created_at="2024-01-01T00:00:00Z",
        )
        d = sig.to_dict()
        assert d["format_version"] == 2
        assert d["classical_sig"] == "sig1"
        assert d["pq_sig"] == "sig2"
        assert d["key_fingerprint"] == "fp1"

    def test_from_dict(self):
        d = {
            "format_version": 2,
            "algorithm": "hybrid-rsa-ml-dsa",
            "classical_sig": "sig1",
            "pq_sig": "sig2",
            "key_fingerprint": "fp1",
            "created_at": "2024-01-01T00:00:00Z",
        }
        sig = HybridSignature.from_dict(d)
        assert sig.format_version == 2
        assert sig.classical_sig == "sig1"

    def test_from_dict_missing_fields(self):
        with pytest.raises(CryptoError, match="missing fields"):
            HybridSignature.from_dict({"format_version": 2})

    def test_roundtrip(self):
        original = HybridSignature(
            format_version=2,
            algorithm="hybrid-rsa-ml-dsa",
            classical_sig="abc",
            pq_sig="def",
            key_fingerprint="fp",
        )
        reconstructed = HybridSignature.from_dict(original.to_dict())
        assert reconstructed.classical_sig == original.classical_sig
        assert reconstructed.pq_sig == original.pq_sig


# ──────────────────────────────────────────────────────
#  VerificationResult dataclass
# ──────────────────────────────────────────────────────


class TestVerificationResult:
    def test_success(self):
        vr = VerificationResult(
            classical_valid=True,
            pq_valid=True,
            hybrid_valid=True,
            algorithm="hybrid-rsa-ml-dsa",
            key_fingerprint="sha256:test",
        )
        assert vr.hybrid_valid is True
        assert vr.error_detail is None

    def test_failure_factory(self):
        vr = VerificationResult.failure(
            algorithm="RSA-SHA256",
            fingerprint="sha256:bad",
            detail="Signature mismatch",
        )
        assert vr.classical_valid is False
        assert vr.pq_valid is False
        assert vr.hybrid_valid is False
        assert "mismatch" in vr.error_detail.lower()

    def test_to_dict(self):
        vr = VerificationResult(
            classical_valid=True,
            pq_valid=False,
            hybrid_valid=False,
            algorithm="ML-DSA-65",
            key_fingerprint="sha256:ok",
        )
        d = vr.to_dict()
        assert d["classical_valid"] is True
        assert d["pq_valid"] is False
        assert d["hybrid_valid"] is False
        assert d["algorithm"] == "ML-DSA-65"

    def test_to_dict_with_error(self):
        vr = VerificationResult.failure("RSA-SHA256", "fp", "bad sig")
        d = vr.to_dict()
        assert "error_detail" in d


# ──────────────────────────────────────────────────────
#  SignatureChainEntry dataclass
# ──────────────────────────────────────────────────────


class TestSignatureChainEntry:
    def test_creation(self):
        entry = SignatureChainEntry(
            entry_id=1,
            data_hash="sha256:abc",
            signature="sig123",
            previous_hash="genesis",
            algorithm="hybrid-rsa-ml-dsa",
        )
        assert entry.entry_id == 1
        assert entry.previous_hash == "genesis"

    def test_to_dict(self):
        entry = SignatureChainEntry(
            entry_id=2,
            data_hash="sha256:def",
            signature="sig456",
            previous_hash="sha256:abc",
            algorithm="RSA-SHA256",
            timestamp="2024-01-02T00:00:00Z",
        )
        d = entry.to_dict()
        assert d["entry_id"] == 2
        assert "data_hash" in d
        assert "signature" in d

    def test_from_dict(self):
        d = {
            "entry_id": 3,
            "data_hash": "sha256:ghi",
            "signature": "sig789",
            "previous_hash": "sha256:def",
            "algorithm": "RSA-SHA256",
            "timestamp": "2024-01-03T00:00:00Z",
        }
        entry = SignatureChainEntry.from_dict(d)
        assert entry.entry_id == 3

    def test_roundtrip(self):
        original = SignatureChainEntry(
            entry_id=10,
            data_hash="hash1",
            signature="sig1",
            previous_hash="hash0",
            algorithm="RSA-SHA256",
        )
        reconstructed = SignatureChainEntry.from_dict(original.to_dict())
        assert reconstructed.entry_id == original.entry_id
        assert reconstructed.data_hash == original.data_hash


# ──────────────────────────────────────────────────────
#  RSAKeyManager
# ──────────────────────────────────────────────────────


class TestRSAKeyManager:
    def test_init_default(self):
        km = RSAKeyManager()
        assert km.key_size == 4096
        assert km.key_id is not None

    def test_init_custom_key_size(self):
        km = RSAKeyManager(key_size=2048)
        assert km.key_size == 2048

    def test_init_invalid_key_size(self):
        with pytest.raises(Exception):
            RSAKeyManager(key_size=1024)

    def test_supported_key_sizes(self):
        assert 2048 in RSAKeyManager.SUPPORTED_KEY_SIZES
        assert 3072 in RSAKeyManager.SUPPORTED_KEY_SIZES
        assert 4096 in RSAKeyManager.SUPPORTED_KEY_SIZES

    def test_private_key_auto_generates(self):
        km = RSAKeyManager(key_size=2048)  # 2048 for speed
        pk = km.private_key
        assert pk is not None

    def test_public_key_auto_generates(self):
        km = RSAKeyManager(key_size=2048)
        pub = km.public_key
        assert pub is not None

    def test_metadata(self):
        km = RSAKeyManager(key_size=2048)
        meta = km.metadata
        assert isinstance(meta, KeyMetadata)
        assert meta.algorithm == "RSA-SHA256"
        assert meta.key_size == 2048


# ──────────────────────────────────────────────────────
#  RSASigner / RSAVerifier
# ──────────────────────────────────────────────────────


class TestRSASignerVerifier:
    @pytest.fixture
    def key_manager(self):
        return RSAKeyManager(key_size=2048)

    def test_sign(self, key_manager):
        signer = RSASigner(key_manager)
        sig_bytes, fingerprint = signer.sign(b"test data")
        assert isinstance(sig_bytes, bytes)
        assert len(sig_bytes) > 0
        assert isinstance(fingerprint, str)

    def test_sign_base64(self, key_manager):
        signer = RSASigner(key_manager)
        sig_b64, fingerprint = signer.sign_base64(b"test data")
        decoded = base64.b64decode(sig_b64)
        assert len(decoded) > 0

    def test_verify_valid(self, key_manager):
        signer = RSASigner(key_manager)
        verifier = RSAVerifier(key_manager)

        data = b"Hello, quantum world!"
        sig_bytes, _ = signer.sign(data)
        result = verifier.verify(data, sig_bytes)
        assert result is True

    def test_verify_tampered(self, key_manager):
        signer = RSASigner(key_manager)
        verifier = RSAVerifier(key_manager)

        data = b"Original data"
        sig_bytes, _ = signer.sign(data)

        result = verifier.verify(b"Tampered data", sig_bytes)
        assert result is False

    def test_verify_base64(self, key_manager):
        signer = RSASigner(key_manager)
        verifier = RSAVerifier(key_manager)

        data = b"test payload"
        sig_b64, _ = signer.sign_base64(data)
        result = verifier.verify_base64(data, sig_b64)
        assert result is True

    def test_verify_base64_invalid(self, key_manager):
        verifier = RSAVerifier(key_manager)
        result = verifier.verify_base64(b"data", "not-valid-base64!!!")
        assert result is False

    def test_verify_raises_on_failure(self, key_manager):
        signer = RSASigner(key_manager)
        verifier = RSAVerifier(key_manager)

        data = b"data"
        sig_bytes, _ = signer.sign(data)
        with pytest.raises(SignatureVerificationError):
            verifier.verify(b"wrong data", sig_bytes, raise_on_failure=True)
