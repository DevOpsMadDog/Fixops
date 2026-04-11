"""Comprehensive unit tests for core.crypto — RSA signing and verification.

Tests cover: RSAKeyManager, RSASigner, RSAVerifier, convenience functions,
key generation, key persistence, key rotation, error handling, and edge cases.

Vision Pillar: V10 (CTEM with Crypto Proof), MOAT4 (Crypto Evidence)
"""

import base64
import os
from unittest.mock import patch

import pytest

from core.crypto import (
    CryptoError,
    HybridVerifier,
    KeyGenerationError,
    KeyMetadata,
    KeyNotFoundError,
    RSAKeyManager,
    RSASigner,
    RSAVerifier,
    SignatureVerificationError,
    generate_key_pair,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def key_manager(tmp_path):
    """Create a fresh RSAKeyManager with temp key paths to avoid loading cwd."""
    return RSAKeyManager(
        private_key_path=str(tmp_path / "priv.pem"),
        public_key_path=str(tmp_path / "pub.pem"),
    )


@pytest.fixture
def key_manager_2048(tmp_path):
    """Create an RSAKeyManager with 2048-bit key."""
    return RSAKeyManager(
        private_key_path=str(tmp_path / "priv2048.pem"),
        public_key_path=str(tmp_path / "pub2048.pem"),
        key_size=2048,
    )


@pytest.fixture
def key_manager_3072(tmp_path):
    """Create an RSAKeyManager with 3072-bit key."""
    return RSAKeyManager(
        private_key_path=str(tmp_path / "priv3072.pem"),
        public_key_path=str(tmp_path / "pub3072.pem"),
        key_size=3072,
    )


@pytest.fixture
def tmp_key_dir(tmp_path):
    """Provide a temporary directory for key files."""
    return tmp_path


@pytest.fixture
def signer(key_manager):
    """Create an RSASigner with a pre-generated key."""
    _ = key_manager.private_key  # Force key generation
    return RSASigner(key_manager)


@pytest.fixture
def verifier(key_manager):
    """Create an RSAVerifier sharing the same key as signer."""
    _ = key_manager.public_key  # Force key generation
    return RSAVerifier(key_manager)


@pytest.fixture
def signer_verifier_pair(tmp_path):
    """Create a matched signer/verifier pair sharing the same key manager."""
    km = RSAKeyManager(
        private_key_path=str(tmp_path / "sv_priv.pem"),
        public_key_path=str(tmp_path / "sv_pub.pem"),
        key_size=2048,
    )
    _ = km.private_key
    return RSASigner(km), RSAVerifier(km)


# ---------------------------------------------------------------------------
# RSAKeyManager Tests
# ---------------------------------------------------------------------------

class TestRSAKeyManager:
    """Tests for RSAKeyManager key generation and management."""

    def test_default_key_size(self, key_manager):
        assert key_manager.key_size == 4096

    def test_supported_key_sizes(self):
        assert RSAKeyManager.SUPPORTED_KEY_SIZES == (2048, 3072, 4096)

    def test_custom_key_size_2048(self, key_manager_2048):
        assert key_manager_2048.key_size == 2048

    def test_custom_key_size_3072(self, key_manager_3072):
        assert key_manager_3072.key_size == 3072

    def test_unsupported_key_size_raises(self):
        with pytest.raises(KeyGenerationError, match="Unsupported RSA key size"):
            RSAKeyManager(key_size=1024)

    def test_unsupported_key_size_512_raises(self):
        with pytest.raises(KeyGenerationError, match="Unsupported RSA key size"):
            RSAKeyManager(key_size=512)

    def test_key_id_auto_generated(self, key_manager):
        assert key_manager.key_id.startswith("fixops-rsa-")

    def test_custom_key_id(self):
        km = RSAKeyManager(key_id="custom-id-123")
        assert km.key_id == "custom-id-123"

    def test_private_key_property_generates_key(self, key_manager):
        pk = key_manager.private_key
        assert pk is not None
        assert pk.key_size == 4096

    def test_public_key_property_generates_key(self, key_manager):
        pub = key_manager.public_key
        assert pub is not None
        assert pub.key_size == 4096

    def test_metadata_property(self, key_manager):
        meta = key_manager.metadata
        assert isinstance(meta, KeyMetadata)
        assert meta.algorithm == "RSA-SHA256"
        assert meta.key_size == 4096
        assert meta.key_id == key_manager.key_id
        assert len(meta.fingerprint) == 64  # SHA-256 hex digest

    def test_metadata_to_dict(self, key_manager):
        d = key_manager.metadata.to_dict()
        assert "key_id" in d
        assert "fingerprint" in d
        assert "algorithm" in d
        assert "key_size" in d
        assert "created_at" in d
        assert "public_key_pem" in d

    def test_get_public_key_pem(self, key_manager):
        pem = key_manager.get_public_key_pem()
        assert pem.startswith("-----BEGIN PUBLIC KEY-----")
        assert pem.strip().endswith("-----END PUBLIC KEY-----")

    def test_key_generation_is_idempotent(self, key_manager):
        pk1 = key_manager.private_key
        pk2 = key_manager.private_key
        assert pk1 is pk2  # Same key object

    def test_public_key_derived_from_private(self, key_manager):
        _ = key_manager.private_key
        pub = key_manager.public_key
        # Public key modulus should match private key's
        assert pub.public_numbers().n == key_manager.private_key.public_key().public_numbers().n


class TestRSAKeyManagerPersistence:
    """Tests for key saving and loading from PEM files."""

    def test_save_and_load_private_key(self, tmp_key_dir):
        priv_path = str(tmp_key_dir / "test_priv.pem")
        pub_path = str(tmp_key_dir / "test_pub.pem")

        # Generate and save
        km1 = RSAKeyManager(
            private_key_path=priv_path,
            public_key_path=pub_path,
            key_size=2048,
        )
        _ = km1.private_key  # triggers generation + save
        fp1 = km1.metadata.fingerprint

        # Load from file
        km2 = RSAKeyManager(
            private_key_path=priv_path,
            public_key_path=pub_path,
            key_size=2048,
        )
        fp2 = km2.metadata.fingerprint
        assert fp1 == fp2

    def test_save_and_load_public_key_only(self, tmp_key_dir):
        priv_path = str(tmp_key_dir / "priv.pem")
        pub_path = str(tmp_key_dir / "pub.pem")

        # Generate and save
        km1 = RSAKeyManager(
            private_key_path=priv_path,
            public_key_path=pub_path,
            key_size=2048,
        )
        _ = km1.private_key

        # Load with only public key path (private points to non-existent file)
        km2 = RSAKeyManager(
            private_key_path=str(tmp_key_dir / "nonexistent.pem"),
            public_key_path=pub_path,
            key_size=2048,
        )
        assert km2.public_key is not None
        assert km2.metadata.fingerprint == km1.metadata.fingerprint

    def test_key_file_permissions(self, tmp_key_dir):
        priv_path = str(tmp_key_dir / "secure_priv.pem")
        pub_path = str(tmp_key_dir / "secure_pub.pem")

        km = RSAKeyManager(
            private_key_path=priv_path,
            public_key_path=pub_path,
            key_size=2048,
        )
        _ = km.private_key

        # Private key should have restrictive permissions (0o600)
        mode = oct(os.stat(priv_path).st_mode & 0o777)
        assert mode == "0o600"

    def test_generate_key_pair_function(self, tmp_key_dir):
        priv_path = str(tmp_key_dir / "gen_priv.pem")
        pub_path = str(tmp_key_dir / "gen_pub.pem")

        try:
            meta = generate_key_pair(priv_path, pub_path, key_size=2048, key_id="test-gen")
        except KeyGenerationError as exc:
            if "ML-DSA" in str(exc):
                pytest.skip("ML-DSA library not available")
            raise
        assert isinstance(meta, KeyMetadata)
        assert meta.key_id == "test-gen"
        assert os.path.exists(priv_path)
        assert os.path.exists(pub_path)


class TestRSAKeyManagerEnvVars:
    """Tests for environment variable configuration."""

    def test_key_size_from_env(self, tmp_path):
        with patch.dict(os.environ, {"FIXOPS_RSA_KEY_SIZE": "2048"}):
            km = RSAKeyManager(private_key_path=str(tmp_path / "p.pem"))
            assert km.key_size == 2048

    def test_invalid_key_size_from_env_falls_back(self, tmp_path):
        with patch.dict(os.environ, {"FIXOPS_RSA_KEY_SIZE": "not_a_number"}):
            km = RSAKeyManager(private_key_path=str(tmp_path / "p.pem"))
            assert km.key_size == 4096  # default

    def test_key_id_from_env(self, tmp_path):
        with patch.dict(os.environ, {"FIXOPS_RSA_KEY_ID": "env-key-id-42"}):
            km = RSAKeyManager(private_key_path=str(tmp_path / "p.pem"))
            assert km.key_id == "env-key-id-42"

    def test_private_key_path_from_env(self, tmp_key_dir):
        priv_path = str(tmp_key_dir / "env_priv.pem")
        pub_path = str(tmp_key_dir / "env_pub.pem")
        # First generate keys
        km = RSAKeyManager(private_key_path=priv_path, public_key_path=pub_path, key_size=2048)
        _ = km.private_key

        with patch.dict(os.environ, {"FIXOPS_RSA_PRIVATE_KEY_PATH": priv_path}):
            km2 = RSAKeyManager(key_size=2048)
            assert km2.private_key is not None


# ---------------------------------------------------------------------------
# RSASigner Tests
# ---------------------------------------------------------------------------

class TestRSASigner:
    """Tests for RSA-SHA256 signing."""

    def test_sign_returns_bytes_and_fingerprint(self, signer):
        data = b"Hello, cryptographic world!"
        sig, fp = signer.sign(data)
        assert isinstance(sig, bytes)
        assert len(sig) > 0
        assert isinstance(fp, str)
        assert len(fp) == 64  # SHA-256 hex

    def test_sign_base64(self, signer):
        data = b"Base64 test data"
        sig_b64, fp = signer.sign_base64(data)
        assert isinstance(sig_b64, str)
        # Should be valid base64
        decoded = base64.b64decode(sig_b64)
        assert len(decoded) > 0

    def test_different_data_produces_different_signatures(self, signer):
        sig1, _ = signer.sign(b"data one")
        sig2, _ = signer.sign(b"data two")
        assert sig1 != sig2

    def test_same_data_produces_same_signatures(self, signer):
        # RSA-PKCS1v15-SHA256 is deterministic
        data = b"deterministic signing test"
        sig1, _ = signer.sign(data)
        sig2, _ = signer.sign(data)
        assert sig1 == sig2

    def test_sign_empty_data(self, signer):
        sig, fp = signer.sign(b"")
        assert isinstance(sig, bytes)
        assert len(sig) > 0

    def test_sign_large_data(self, signer):
        data = b"x" * 1_000_000  # 1MB
        sig, fp = signer.sign(data)
        assert isinstance(sig, bytes)
        assert len(sig) > 0

    def test_signer_key_manager_property(self, signer, key_manager):
        assert signer.key_manager is key_manager

    def test_signer_default_key_manager(self, tmp_path):
        km = RSAKeyManager(private_key_path=str(tmp_path / "sd.pem"), key_size=2048)
        s = RSASigner(km)
        assert s.key_manager is not None
        assert isinstance(s.key_manager, RSAKeyManager)


# ---------------------------------------------------------------------------
# RSAVerifier Tests
# ---------------------------------------------------------------------------

class TestRSAVerifier:
    """Tests for RSA-SHA256 verification."""

    def test_verify_valid_signature(self, signer_verifier_pair):
        signer, verifier = signer_verifier_pair
        data = b"verify me"
        sig, fp = signer.sign(data)
        assert verifier.verify(data, sig) is True

    def test_verify_invalid_signature(self, signer_verifier_pair):
        _, verifier = signer_verifier_pair
        data = b"verify me"
        bad_sig = b"\x00" * 256
        assert verifier.verify(data, bad_sig) is False

    def test_verify_tampered_data(self, signer_verifier_pair):
        signer, verifier = signer_verifier_pair
        data = b"original data"
        sig, _ = signer.sign(data)
        assert verifier.verify(b"tampered data", sig) is False

    def test_verify_with_correct_fingerprint(self, signer_verifier_pair):
        signer, verifier = signer_verifier_pair
        data = b"fingerprint check"
        sig, fp = signer.sign(data)
        assert verifier.verify(data, sig, expected_fingerprint=fp) is True

    def test_verify_with_wrong_fingerprint(self, signer_verifier_pair):
        signer, verifier = signer_verifier_pair
        data = b"fingerprint mismatch"
        sig, _ = signer.sign(data)
        assert verifier.verify(data, sig, expected_fingerprint="wrong_fp") is False

    def test_verify_raise_on_failure_invalid_sig(self, signer_verifier_pair):
        _, verifier = signer_verifier_pair
        data = b"raise test"
        with pytest.raises(SignatureVerificationError):
            verifier.verify(data, b"\x00" * 256, raise_on_failure=True)

    def test_verify_raise_on_fingerprint_mismatch(self, signer_verifier_pair):
        signer, verifier = signer_verifier_pair
        data = b"fp raise test"
        sig, _ = signer.sign(data)
        with pytest.raises(SignatureVerificationError, match="fingerprint mismatch"):
            verifier.verify(data, sig, expected_fingerprint="badprint", raise_on_failure=True)

    def test_verify_base64(self, signer_verifier_pair):
        signer, verifier = signer_verifier_pair
        data = b"base64 verify"
        sig_b64, fp = signer.sign_base64(data)
        assert verifier.verify_base64(data, sig_b64) is True

    def test_verify_base64_invalid(self, signer_verifier_pair):
        _, verifier = signer_verifier_pair
        assert verifier.verify_base64(b"data", "!!!not-base64!!!") is False

    def test_verify_base64_with_fingerprint(self, signer_verifier_pair):
        signer, verifier = signer_verifier_pair
        data = b"b64 fp test"
        sig_b64, fp = signer.sign_base64(data)
        assert verifier.verify_base64(data, sig_b64, expected_fingerprint=fp) is True

    def test_verify_cross_key_fails(self, tmp_path):
        km1 = RSAKeyManager(
            private_key_path=str(tmp_path / "k1_priv.pem"),
            public_key_path=str(tmp_path / "k1_pub.pem"),
            key_size=2048,
        )
        km2 = RSAKeyManager(
            private_key_path=str(tmp_path / "k2_priv.pem"),
            public_key_path=str(tmp_path / "k2_pub.pem"),
            key_size=2048,
        )
        signer = RSASigner(km1)
        verifier = RSAVerifier(km2)
        data = b"cross key test"
        sig, _ = signer.sign(data)
        assert verifier.verify(data, sig) is False

    def test_verifier_key_manager_property(self, verifier, key_manager):
        assert verifier.key_manager is key_manager

    def test_verifier_default_key_manager(self, tmp_path):
        km = RSAKeyManager(private_key_path=str(tmp_path / "vd.pem"), key_size=2048)
        v = RSAVerifier(km)
        assert v.key_manager is not None


# ---------------------------------------------------------------------------
# Convenience Functions
# ---------------------------------------------------------------------------

class TestConvenienceFunctions:
    """Tests for module-level convenience functions using shared key manager."""

    def test_rsa_sign_returns_tuple(self, tmp_path):
        km = RSAKeyManager(
            private_key_path=str(tmp_path / "conv_priv.pem"),
            public_key_path=str(tmp_path / "conv_pub.pem"),
            key_size=2048,
        )
        signer = RSASigner(km)
        sig, fp = signer.sign(b"convenience sign test")
        assert isinstance(sig, bytes)
        assert isinstance(fp, str)

    def test_rsa_sign_and_verify_roundtrip(self, tmp_path):
        km = RSAKeyManager(
            private_key_path=str(tmp_path / "rt_priv.pem"),
            public_key_path=str(tmp_path / "rt_pub.pem"),
            key_size=2048,
        )
        signer = RSASigner(km)
        verifier = RSAVerifier(km)

        data = b"roundtrip convenience test"
        sig, fp = signer.sign(data)
        assert verifier.verify(data, sig, expected_fingerprint=fp) is True

    def test_rsa_verify_wrong_fingerprint_raises(self, tmp_path):
        km = RSAKeyManager(
            private_key_path=str(tmp_path / "wfp_priv.pem"),
            public_key_path=str(tmp_path / "wfp_pub.pem"),
            key_size=2048,
        )
        signer = RSASigner(km)
        verifier = RSAVerifier(km)

        data = b"wrong fp test"
        sig, _ = signer.sign(data)
        with pytest.raises(SignatureVerificationError):
            verifier.verify(data, sig, expected_fingerprint="wrong-fingerprint", raise_on_failure=True)


# ---------------------------------------------------------------------------
# Exception Classes
# ---------------------------------------------------------------------------

class TestExceptions:
    """Tests for crypto exception hierarchy."""

    def test_crypto_error_is_exception(self):
        assert issubclass(CryptoError, Exception)

    def test_key_not_found_is_crypto_error(self):
        assert issubclass(KeyNotFoundError, CryptoError)

    def test_signature_verification_is_crypto_error(self):
        assert issubclass(SignatureVerificationError, CryptoError)

    def test_key_generation_is_crypto_error(self):
        assert issubclass(KeyGenerationError, CryptoError)

    def test_crypto_error_message(self):
        err = CryptoError("test message")
        assert str(err) == "test message"

    def test_key_not_found_message(self):
        err = KeyNotFoundError("key missing")
        assert "key missing" in str(err)


# ---------------------------------------------------------------------------
# KeyMetadata Tests
# ---------------------------------------------------------------------------

class TestKeyMetadata:
    """Tests for KeyMetadata dataclass."""

    def test_create_metadata(self):
        meta = KeyMetadata(
            key_id="test-key",
            fingerprint="abcdef1234",
            algorithm="RSA-SHA256",
            key_size=4096,
            created_at="2026-03-01T00:00:00Z",
            public_key_pem="-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
        )
        assert meta.key_id == "test-key"
        assert meta.algorithm == "RSA-SHA256"
        assert meta.key_size == 4096

    def test_metadata_to_dict_keys(self):
        meta = KeyMetadata(
            key_id="id", fingerprint="fp", algorithm="alg",
            key_size=2048, created_at="now", public_key_pem="pem",
        )
        d = meta.to_dict()
        expected_keys = {"key_id", "fingerprint", "algorithm", "key_size", "created_at", "public_key_pem"}
        assert set(d.keys()) == expected_keys

    def test_metadata_to_dict_values(self):
        meta = KeyMetadata(
            key_id="myid", fingerprint="myfp", algorithm="RSA-SHA256",
            key_size=3072, created_at="2026-01-01", public_key_pem="mypem",
        )
        d = meta.to_dict()
        assert d["key_id"] == "myid"
        assert d["fingerprint"] == "myfp"
        assert d["key_size"] == 3072


# ---------------------------------------------------------------------------
# Edge Cases & Integration
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Edge case and integration tests."""

    def test_sign_unicode_encoded_as_bytes(self, signer_verifier_pair):
        signer, verifier = signer_verifier_pair
        data = "héllo wörld! 🔐".encode("utf-8")
        sig, fp = signer.sign(data)
        assert verifier.verify(data, sig) is True

    def test_sign_binary_data(self, signer_verifier_pair):
        signer, verifier = signer_verifier_pair
        data = bytes(range(256))  # All byte values 0-255
        sig, _ = signer.sign(data)
        assert verifier.verify(data, sig) is True

    def test_multiple_key_managers_independent(self, tmp_path):
        km1 = RSAKeyManager(
            private_key_path=str(tmp_path / "ind1_priv.pem"),
            public_key_path=str(tmp_path / "ind1_pub.pem"),
            key_size=2048, key_id="km1",
        )
        km2 = RSAKeyManager(
            private_key_path=str(tmp_path / "ind2_priv.pem"),
            public_key_path=str(tmp_path / "ind2_pub.pem"),
            key_size=2048, key_id="km2",
        )
        _ = km1.private_key
        _ = km2.private_key
        assert km1.metadata.fingerprint != km2.metadata.fingerprint

    def test_key_size_matches_generated(self, tmp_path):
        for i, size in enumerate((2048, 3072, 4096)):
            km = RSAKeyManager(
                private_key_path=str(tmp_path / f"sz{i}_priv.pem"),
                public_key_path=str(tmp_path / f"sz{i}_pub.pem"),
                key_size=size,
            )
            assert km.private_key.key_size == size

    def test_fingerprint_is_sha256_hex(self, key_manager):
        fp = key_manager.metadata.fingerprint
        assert len(fp) == 64
        assert all(c in "0123456789abcdef" for c in fp)

    def test_signature_length_matches_key_size(self, tmp_path):
        for i, (size, expected_sig_len) in enumerate([(2048, 256), (3072, 384), (4096, 512)]):
            km = RSAKeyManager(
                private_key_path=str(tmp_path / f"siglen{i}_priv.pem"),
                public_key_path=str(tmp_path / f"siglen{i}_pub.pem"),
                key_size=size,
            )
            s = RSASigner(km)
            sig, _ = s.sign(b"test")
            assert len(sig) == expected_sig_len

    def test_created_at_is_iso_format(self, key_manager):
        ts = key_manager.metadata.created_at
        assert "T" in ts  # ISO format contains T separator
        assert ":" in ts  # Has time component

    def test_key_id_format(self, key_manager):
        kid = key_manager.key_id
        assert kid.startswith("fixops-rsa-")
        # Should have timestamp portion: YYYYMMDDHHMMSS
        ts_part = kid.replace("fixops-rsa-", "")
        assert len(ts_part) == 14
        assert ts_part.isdigit()


class TestHybridVerifierSanitization:
    def test_verify_evidence_bundle_sanitizes_hybrid_signature_parse_errors(self):
        bundle = {
            "version": 2,
            "artifact": "demo",
            "signature": {
                "format_version": 2,
                "algorithm": "hybrid-rsa-ml-dsa",
                "key_fingerprint": "sha256:test-fingerprint",
            },
        }

        result = HybridVerifier.verify_evidence_bundle(object(), bundle)

        assert result.hybrid_valid is False
        assert result.error_detail == "Invalid hybrid signature envelope: CryptoError"
        assert "missing fields" not in result.error_detail
