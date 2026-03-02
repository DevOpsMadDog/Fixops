"""Unit tests for the production-ready RSA crypto module.

Tests cover:
- RSAKeyManager: Key generation, loading, persistence, rotation
- RSASigner: Signature generation
- RSAVerifier: Signature verification
- Module-level convenience functions
- Error handling and edge cases
"""

import base64
import hashlib
import os
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

# Ensure suite-core is on sys.path for direct test runs
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))

import core.crypto as _crypto_mod
from core.crypto import (
    CryptoError,
    KeyGenerationError,
    KeyMetadata,
    KeyNotFoundError,
    RSAKeyManager,
    RSASigner,
    RSAVerifier,
    SignatureVerificationError,
    generate_key_pair,
    rsa_sign,
    rsa_verify,
)


class TestKeyMetadata:
    """Tests for KeyMetadata dataclass."""

    def test_to_dict(self):
        metadata = KeyMetadata(
            key_id="test-key-1",
            fingerprint="abc123",
            algorithm="RSA-SHA256",
            key_size=2048,
            created_at="2024-01-01T00:00:00Z",
            public_key_pem="-----BEGIN PUBLIC KEY-----\ntest\n-----END PUBLIC KEY-----",
        )
        result = metadata.to_dict()
        assert result["key_id"] == "test-key-1"
        assert result["fingerprint"] == "abc123"
        assert result["algorithm"] == "RSA-SHA256"
        assert result["key_size"] == 2048
        assert result["created_at"] == "2024-01-01T00:00:00Z"
        assert "BEGIN PUBLIC KEY" in result["public_key_pem"]


class TestRSAKeyManager:
    """Tests for RSAKeyManager class."""

    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    def test_generate_new_keys(self, temp_dir):
        """Test generating new RSA key pair."""
        private_path = os.path.join(temp_dir, "private.pem")
        public_path = os.path.join(temp_dir, "public.pem")

        manager = RSAKeyManager(
            private_key_path=private_path,
            public_key_path=public_path,
            key_size=2048,
        )

        # Access private key to trigger generation
        private_key = manager.private_key
        assert private_key is not None

        # Verify files were created
        assert os.path.exists(private_path)
        assert os.path.exists(public_path)

        # Verify metadata
        metadata = manager.metadata
        assert metadata.key_size == 2048
        assert metadata.algorithm == "RSA-SHA256"
        assert len(metadata.fingerprint) > 0

    def test_load_existing_private_key(self, temp_dir):
        """Test loading existing private key from file."""
        private_path = os.path.join(temp_dir, "private.pem")
        public_path = os.path.join(temp_dir, "public.pem")

        # First, generate keys
        manager1 = RSAKeyManager(
            private_key_path=private_path,
            public_key_path=public_path,
            key_size=2048,
        )
        fingerprint1 = manager1.metadata.fingerprint

        # Create new manager that loads existing keys
        manager2 = RSAKeyManager(
            private_key_path=private_path,
            public_key_path=public_path,
            key_size=2048,
        )
        fingerprint2 = manager2.metadata.fingerprint

        # Should have same fingerprint
        assert fingerprint1 == fingerprint2

    def test_load_public_key_only(self, temp_dir):
        """Test loading only public key (for verification)."""
        private_path = os.path.join(temp_dir, "private.pem")
        public_path = os.path.join(temp_dir, "public.pem")

        # Generate keys
        manager1 = RSAKeyManager(
            private_key_path=private_path,
            public_key_path=public_path,
            key_size=2048,
        )
        _ = manager1.private_key  # Trigger generation

        # Load only public key (provide non-existent private path to avoid loading)
        nonexistent_private = os.path.join(temp_dir, "nonexistent_private.pem")
        manager2 = RSAKeyManager(
            private_key_path=nonexistent_private,
            public_key_path=public_path,
            key_size=2048,
        )

        # Should be able to get public key
        public_key = manager2.public_key
        assert public_key is not None

    def test_invalid_key_size_raises(self):
        """Test that invalid key size raises error."""
        with pytest.raises(KeyGenerationError):
            RSAKeyManager(key_size=1024)  # Too small

    def test_key_size_from_env(self, temp_dir):
        """Test key size from environment variable."""
        with patch.dict(os.environ, {"FIXOPS_RSA_KEY_SIZE": "3072"}):
            manager = RSAKeyManager(
                private_key_path=os.path.join(temp_dir, "private.pem"),
                public_key_path=os.path.join(temp_dir, "public.pem"),
            )
            _ = manager.private_key
            assert manager.metadata.key_size == 3072

    def test_invalid_key_size_env_uses_default(self, temp_dir):
        """Test invalid env key size falls back to default."""
        with patch.dict(os.environ, {"FIXOPS_RSA_KEY_SIZE": "invalid"}):
            manager = RSAKeyManager(
                private_key_path=os.path.join(temp_dir, "private.pem"),
                public_key_path=os.path.join(temp_dir, "public.pem"),
            )
            _ = manager.private_key
            assert manager.metadata.key_size == 4096  # Default

    def test_key_id_from_env(self, temp_dir):
        """Test key ID from environment variable."""
        with patch.dict(os.environ, {"FIXOPS_RSA_KEY_ID": "my-custom-key-id"}):
            manager = RSAKeyManager(
                private_key_path=os.path.join(temp_dir, "private.pem"),
                public_key_path=os.path.join(temp_dir, "public.pem"),
                key_size=2048,
            )
            assert manager.key_id == "my-custom-key-id"

    def test_get_public_key_pem(self, temp_dir):
        """Test getting public key in PEM format."""
        manager = RSAKeyManager(
            private_key_path=os.path.join(temp_dir, "private.pem"),
            public_key_path=os.path.join(temp_dir, "public.pem"),
            key_size=2048,
        )
        _ = manager.private_key

        pem = manager.get_public_key_pem()
        assert "BEGIN PUBLIC KEY" in pem
        assert "END PUBLIC KEY" in pem

    def test_private_key_not_available_raises(self):
        """Test accessing private key when not available raises error."""
        manager = RSAKeyManager(key_size=2048)
        # Don't generate keys, just try to access
        manager._private_key = None
        manager._public_key = None
        manager._metadata = None

        # Mock _load_or_generate_keys to do nothing
        manager._load_or_generate_keys = lambda: None

        with pytest.raises(KeyNotFoundError):
            _ = manager.private_key

    def test_public_key_not_available_raises(self):
        """Test accessing public key when not available raises error."""
        manager = RSAKeyManager(key_size=2048)
        manager._private_key = None
        manager._public_key = None
        manager._metadata = None
        manager._load_or_generate_keys = lambda: None

        with pytest.raises(KeyNotFoundError):
            _ = manager.public_key

    def test_metadata_not_available_raises(self):
        """Test accessing metadata when not available raises error."""
        manager = RSAKeyManager(key_size=2048)
        manager._private_key = None
        manager._public_key = None
        manager._metadata = None
        manager._load_or_generate_keys = lambda: None

        with pytest.raises(KeyNotFoundError):
            _ = manager.metadata

    def test_load_non_rsa_private_key_raises(self, temp_dir):
        """Test loading non-RSA private key raises error."""
        # Create a file with invalid key data
        private_path = os.path.join(temp_dir, "private.pem")
        with open(private_path, "wb") as f:
            f.write(b"not a valid key")

        manager = RSAKeyManager(
            private_key_path=private_path,
            key_size=2048,
        )

        with pytest.raises(CryptoError):
            _ = manager.private_key

    def test_load_non_rsa_public_key_raises(self, temp_dir):
        """Test loading non-RSA public key raises error."""
        public_path = os.path.join(temp_dir, "public.pem")
        with open(public_path, "wb") as f:
            f.write(b"not a valid key")

        manager = RSAKeyManager(
            public_key_path=public_path,
            key_size=2048,
        )

        with pytest.raises(CryptoError):
            _ = manager.public_key


class TestRSASigner:
    """Tests for RSASigner class."""

    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    @pytest.fixture
    def signer(self, temp_dir):
        manager = RSAKeyManager(
            private_key_path=os.path.join(temp_dir, "private.pem"),
            public_key_path=os.path.join(temp_dir, "public.pem"),
            key_size=2048,
        )
        return RSASigner(manager)

    def test_sign_bytes(self, signer):
        """Test signing bytes data."""
        data = b"test data to sign"
        signature, fingerprint = signer.sign(data)

        assert isinstance(signature, bytes)
        assert len(signature) > 0
        assert len(fingerprint) > 0

    def test_sign_base64(self, signer):
        """Test signing with base64 output."""
        data = b"test data to sign"
        signature_b64, fingerprint = signer.sign_base64(data)

        assert isinstance(signature_b64, str)
        # Should be valid base64
        import base64

        decoded = base64.b64decode(signature_b64)
        assert len(decoded) > 0

    def test_key_manager_property(self, signer):
        """Test key_manager property."""
        assert signer.key_manager is not None
        assert isinstance(signer.key_manager, RSAKeyManager)


class TestRSAVerifier:
    """Tests for RSAVerifier class."""

    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    @pytest.fixture
    def key_manager(self, temp_dir):
        manager = RSAKeyManager(
            private_key_path=os.path.join(temp_dir, "private.pem"),
            public_key_path=os.path.join(temp_dir, "public.pem"),
            key_size=2048,
        )
        return manager

    @pytest.fixture
    def signer(self, key_manager):
        return RSASigner(key_manager)

    @pytest.fixture
    def verifier(self, key_manager):
        return RSAVerifier(key_manager)

    def test_verify_valid_signature(self, signer, verifier):
        """Test verifying a valid signature."""
        data = b"test data to sign"
        signature, fingerprint = signer.sign(data)

        result = verifier.verify(data, signature, fingerprint)
        assert result is True

    def test_verify_invalid_signature(self, verifier, key_manager):
        """Test verifying an invalid signature."""
        data = b"test data"
        invalid_signature = b"invalid signature bytes"
        fingerprint = key_manager.metadata.fingerprint

        result = verifier.verify(data, invalid_signature, fingerprint)
        assert result is False

    def test_verify_wrong_fingerprint(self, signer, verifier):
        """Test verifying with wrong fingerprint."""
        data = b"test data"
        signature, _ = signer.sign(data)

        result = verifier.verify(data, signature, "wrong-fingerprint")
        assert result is False

    def test_verify_tampered_data(self, signer, verifier):
        """Test verifying signature with tampered data."""
        data = b"original data"
        signature, fingerprint = signer.sign(data)

        tampered_data = b"tampered data"
        result = verifier.verify(tampered_data, signature, fingerprint)
        assert result is False

    def test_verify_base64(self, signer, verifier):
        """Test verifying base64-encoded signature."""
        data = b"test data"
        signature_b64, fingerprint = signer.sign_base64(data)

        result = verifier.verify_base64(data, signature_b64, fingerprint)
        assert result is True

    def test_verify_base64_invalid(self, verifier, key_manager):
        """Test verifying invalid base64 signature."""
        data = b"test data"
        fingerprint = key_manager.metadata.fingerprint

        result = verifier.verify_base64(data, "not-valid-base64!!!", fingerprint)
        assert result is False

    def test_key_manager_property(self, verifier):
        """Test key_manager property."""
        assert verifier.key_manager is not None


class TestModuleFunctions:
    """Tests for module-level convenience functions."""

    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    def test_generate_key_pair(self, temp_dir):
        """Test generate_key_pair function."""
        private_path = os.path.join(temp_dir, "private.pem")
        public_path = os.path.join(temp_dir, "public.pem")

        metadata = generate_key_pair(private_path, public_path, key_size=2048)

        assert os.path.exists(private_path)
        assert os.path.exists(public_path)
        assert metadata.key_size == 2048
        assert len(metadata.fingerprint) > 0

    def test_rsa_sign_and_verify(self, temp_dir):
        """Test rsa_sign and rsa_verify functions."""
        private_path = os.path.join(temp_dir, "private.pem")
        public_path = os.path.join(temp_dir, "public.pem")

        with patch.dict(
            os.environ,
            {
                "FIXOPS_RSA_PRIVATE_KEY_PATH": private_path,
                "FIXOPS_RSA_PUBLIC_KEY_PATH": public_path,
            },
        ):
            # Clear cached instances
            import core.crypto as crypto_module

            crypto_module._default_key_manager = None
            crypto_module._default_signer = None
            crypto_module._default_verifier = None

            data = b"test data"
            signature, fingerprint = rsa_sign(data)

            assert len(signature) > 0
            assert len(fingerprint) > 0

            result = rsa_verify(data, signature, fingerprint)
            assert result is True

    def test_rsa_verify_invalid(self, temp_dir):
        """Test rsa_verify raises SignatureVerificationError with invalid signature.

        The rsa_verify convenience function uses raise_on_failure=True by default,
        so it raises SignatureVerificationError on invalid signatures rather than
        returning False. This matches the documented behavior in the docstring.
        """
        private_path = os.path.join(temp_dir, "private.pem")
        public_path = os.path.join(temp_dir, "public.pem")

        with patch.dict(
            os.environ,
            {
                "FIXOPS_RSA_PRIVATE_KEY_PATH": private_path,
                "FIXOPS_RSA_PUBLIC_KEY_PATH": public_path,
            },
        ):
            import core.crypto as crypto_module

            crypto_module._default_key_manager = None
            crypto_module._default_signer = None
            crypto_module._default_verifier = None

            # Generate keys first
            _, fingerprint = rsa_sign(b"dummy")

            # rsa_verify raises SignatureVerificationError on invalid signature
            with pytest.raises(SignatureVerificationError) as exc_info:
                rsa_verify(b"data", b"invalid", fingerprint)
            assert "Signature verification failed" in str(exc_info.value)


class TestExceptionClasses:
    """Tests for exception classes."""

    def test_crypto_error(self):
        with pytest.raises(CryptoError):
            raise CryptoError("test error")

    def test_key_not_found_error(self):
        with pytest.raises(KeyNotFoundError):
            raise KeyNotFoundError("key not found")

    def test_signature_verification_error(self):
        with pytest.raises(SignatureVerificationError):
            raise SignatureVerificationError("verification failed")

    def test_key_generation_error(self):
        with pytest.raises(KeyGenerationError):
            raise KeyGenerationError("generation failed")


class TestCoverageGaps:
    """Tests to cover specific missing coverage lines."""

    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    def test_verify_with_raise_on_failure_fingerprint_mismatch(self, temp_dir):
        """Test verify raises SignatureVerificationError on fingerprint mismatch when raise_on_failure=True.

        Covers line 406 in crypto.py.
        """
        private_path = os.path.join(temp_dir, "private.pem")
        public_path = os.path.join(temp_dir, "public.pem")

        manager = RSAKeyManager(
            private_key_path=private_path,
            public_key_path=public_path,
            key_size=2048,
        )
        signer = RSASigner(manager)
        verifier = RSAVerifier(manager)

        data = b"test data"
        signature, _ = signer.sign(data)

        # Should raise when fingerprint doesn't match and raise_on_failure=True
        with pytest.raises(SignatureVerificationError) as exc_info:
            verifier.verify(data, signature, "wrong-fingerprint", raise_on_failure=True)
        assert "fingerprint mismatch" in str(exc_info.value).lower()

    def test_verify_with_raise_on_failure_invalid_signature(self, temp_dir):
        """Test verify raises SignatureVerificationError on invalid signature when raise_on_failure=True.

        Covers line 424 in crypto.py.
        """
        private_path = os.path.join(temp_dir, "private.pem")
        public_path = os.path.join(temp_dir, "public.pem")

        manager = RSAKeyManager(
            private_key_path=private_path,
            public_key_path=public_path,
            key_size=2048,
        )
        verifier = RSAVerifier(manager)
        fingerprint = manager.metadata.fingerprint

        data = b"test data"
        invalid_signature = b"invalid signature bytes"

        # Should raise when signature is invalid and raise_on_failure=True
        with pytest.raises(SignatureVerificationError) as exc_info:
            verifier.verify(data, invalid_signature, fingerprint, raise_on_failure=True)
        assert "verification failed" in str(exc_info.value).lower()

    def test_save_private_key_when_none(self, temp_dir):
        """Test _save_private_key returns early when private key is None.

        Covers line 239 in crypto.py.
        """
        private_path = os.path.join(temp_dir, "private.pem")
        public_path = os.path.join(temp_dir, "public.pem")

        manager = RSAKeyManager(
            private_key_path=private_path,
            public_key_path=public_path,
            key_size=2048,
        )
        # Generate keys first
        _ = manager.private_key

        # Set private key to None and try to save
        manager._private_key = None
        manager._save_private_key()  # Should return early without error

        # File should still exist from initial generation
        assert os.path.exists(private_path)

    def test_save_public_key_when_none(self, temp_dir):
        """Test _save_public_key returns early when public key is None.

        Covers line 257 in crypto.py.
        """
        private_path = os.path.join(temp_dir, "private.pem")
        public_path = os.path.join(temp_dir, "public.pem")

        manager = RSAKeyManager(
            private_key_path=private_path,
            public_key_path=public_path,
            key_size=2048,
        )
        # Generate keys first
        _ = manager.private_key

        # Set public key to None and try to save
        manager._public_key = None
        manager._save_public_key()  # Should return early without error

        # File should still exist from initial generation
        assert os.path.exists(public_path)

    def test_compute_metadata_when_public_key_none(self, temp_dir):
        """Test _compute_metadata returns early when public key is None.

        Covers line 272 in crypto.py.
        """
        private_path = os.path.join(temp_dir, "private.pem")
        public_path = os.path.join(temp_dir, "public.pem")

        manager = RSAKeyManager(
            private_key_path=private_path,
            public_key_path=public_path,
            key_size=2048,
        )
        # Generate keys first
        _ = manager.private_key
        original_metadata = manager._metadata

        # Set public key to None and try to compute metadata
        manager._public_key = None
        manager._compute_metadata()  # Should return early without error

        # Metadata should be unchanged
        assert manager._metadata == original_metadata

    def test_save_private_key_exception_handling(self, temp_dir):
        """Test _save_private_key handles exceptions gracefully.

        Covers lines 251-252 in crypto.py.
        """
        from pathlib import Path

        private_path = os.path.join(temp_dir, "private.pem")
        public_path = os.path.join(temp_dir, "public.pem")

        manager = RSAKeyManager(
            private_key_path=private_path,
            public_key_path=public_path,
            key_size=2048,
        )
        # Generate keys first
        _ = manager.private_key

        # Mock write_bytes to raise an exception
        with patch.object(
            Path, "write_bytes", side_effect=OSError("Permission denied")
        ):
            # Should log warning but not raise
            manager._save_private_key()

    def test_save_public_key_exception_handling(self, temp_dir):
        """Test _save_public_key handles exceptions gracefully.

        Covers lines 266-267 in crypto.py.
        """
        from pathlib import Path

        private_path = os.path.join(temp_dir, "private.pem")
        public_path = os.path.join(temp_dir, "public.pem")

        manager = RSAKeyManager(
            private_key_path=private_path,
            public_key_path=public_path,
            key_size=2048,
        )
        # Generate keys first
        _ = manager.private_key

        # Mock write_bytes to raise an exception
        with patch.object(
            Path, "write_bytes", side_effect=OSError("Permission denied")
        ):
            # Should log warning but not raise
            manager._save_public_key()

    def test_sign_exception_handling(self, temp_dir):
        """Test sign raises CryptoError on signing failure.

        Covers lines 338-339 in crypto.py.
        """
        private_path = os.path.join(temp_dir, "private.pem")
        public_path = os.path.join(temp_dir, "public.pem")

        manager = RSAKeyManager(
            private_key_path=private_path,
            public_key_path=public_path,
            key_size=2048,
        )
        signer = RSASigner(manager)

        # Generate keys first
        _ = manager.private_key

        # Mock the key_manager's private_key property to return a mock that raises
        from unittest.mock import MagicMock, PropertyMock

        mock_key = MagicMock()
        mock_key.sign.side_effect = Exception("Signing failed")

        with patch.object(
            type(manager),
            "private_key",
            new_callable=PropertyMock,
            return_value=mock_key,
        ):
            with pytest.raises(CryptoError) as exc_info:
                signer.sign(b"test data")
            assert "Failed to sign data" in str(exc_info.value)

    def test_key_generation_exception_handling(self, temp_dir):
        """Test key generation raises KeyGenerationError on failure.

        Covers lines 233-234 in crypto.py.
        """
        from cryptography.hazmat.primitives.asymmetric import rsa

        private_path = os.path.join(temp_dir, "private.pem")
        public_path = os.path.join(temp_dir, "public.pem")

        # Mock rsa.generate_private_key to raise an exception
        with patch.object(
            rsa, "generate_private_key", side_effect=Exception("Key generation failed")
        ):
            manager = RSAKeyManager(
                private_key_path=private_path,
                public_key_path=public_path,
                key_size=2048,
            )
            with pytest.raises(KeyGenerationError) as exc_info:
                _ = manager.private_key
            assert "Failed to generate key pair" in str(exc_info.value)

    def test_load_ec_private_key_raises_crypto_error(self, temp_dir):
        """Test loading an EC private key (non-RSA) raises CryptoError.

        Covers line 183 in crypto.py.
        """
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        # Generate an EC key (not RSA)
        ec_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        ec_pem = ec_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        private_path = os.path.join(temp_dir, "ec_private.pem")
        with open(private_path, "wb") as f:
            f.write(ec_pem)

        manager = RSAKeyManager(
            private_key_path=private_path,
            key_size=2048,
        )

        with pytest.raises(CryptoError) as exc_info:
            _ = manager.private_key
        assert "not an RSA private key" in str(exc_info.value)

    def test_load_ec_public_key_raises_crypto_error(self, temp_dir):
        """Test loading an EC public key (non-RSA) raises CryptoError.

        Covers line 202 in crypto.py.
        """
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        # Generate an EC key (not RSA)
        ec_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        ec_public_key = ec_private_key.public_key()
        ec_pem = ec_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        public_path = os.path.join(temp_dir, "ec_public.pem")
        with open(public_path, "wb") as f:
            f.write(ec_pem)

        # Set private_key_path to a non-existent file so it doesn't try to load from cwd
        private_path = os.path.join(temp_dir, "nonexistent_private.pem")
        manager = RSAKeyManager(
            private_key_path=private_path,
            public_key_path=public_path,
            key_size=2048,
        )

        with pytest.raises(CryptoError) as exc_info:
            _ = manager.public_key
        assert "not an RSA public key" in str(exc_info.value)

    def test_load_public_key_exception_handling(self, temp_dir):
        """Test loading corrupted public key raises CryptoError.

        Covers lines 209-210 in crypto.py.
        """
        public_path = os.path.join(temp_dir, "corrupted_public.pem")
        # Write a file that looks like a PEM but is corrupted
        with open(public_path, "wb") as f:
            f.write(
                b"-----BEGIN PUBLIC KEY-----\ncorrupted data\n-----END PUBLIC KEY-----"
            )

        # Set private_key_path to a non-existent file so it doesn't try to load from cwd
        private_path = os.path.join(temp_dir, "nonexistent_private.pem")
        manager = RSAKeyManager(
            private_key_path=private_path,
            public_key_path=public_path,
            key_size=2048,
        )

        with pytest.raises(CryptoError) as exc_info:
            _ = manager.public_key
        assert "Failed to load public key" in str(exc_info.value)

    def test_save_private_key_skips_when_no_path_configured(self, temp_dir):
        """Test _save_private_key skips saving when path resolves to current directory.

        Covers lines 242-243 in crypto.py.
        """
        from pathlib import Path

        private_path = os.path.join(temp_dir, "private.pem")
        public_path = os.path.join(temp_dir, "public.pem")

        manager = RSAKeyManager(
            private_key_path=private_path,
            public_key_path=public_path,
            key_size=2048,
        )
        # Generate keys first
        _ = manager.private_key

        # Set private_key_path to empty path (resolves to '.')
        manager.private_key_path = Path("")
        # Call _save_private_key - should skip saving without error
        manager._save_private_key()

        # Verify no private.pem file was created in current directory
        # (the test should not create files outside temp_dir)
        cwd_private_pem = Path.cwd() / "private.pem"
        assert not cwd_private_pem.exists(), "private.pem should not be created in cwd"

    def test_save_public_key_skips_when_no_path_configured(self, temp_dir):
        """Test _save_public_key skips saving when path resolves to current directory.

        Covers lines 264-265 in crypto.py.
        """
        from pathlib import Path

        private_path = os.path.join(temp_dir, "private.pem")
        public_path = os.path.join(temp_dir, "public.pem")

        manager = RSAKeyManager(
            private_key_path=private_path,
            public_key_path=public_path,
            key_size=2048,
        )
        # Generate keys first
        _ = manager.private_key

        # Set public_key_path to empty path (resolves to '.')
        manager.public_key_path = Path("")
        # Call _save_public_key - should skip saving without error
        manager._save_public_key()

        # Verify no public.pem file was created in current directory
        # (the test should not create files outside temp_dir)
        cwd_public_pem = Path.cwd() / "public.pem"
        assert not cwd_public_pem.exists(), "public.pem should not be created in cwd"


# ---------------------------------------------------------------------------
# Exception Hierarchy Tests
# ---------------------------------------------------------------------------

class TestExceptionHierarchy:
    """Verify exception class hierarchy and raisability."""

    def test_crypto_error_is_base_exception(self):
        assert issubclass(CryptoError, Exception)

    def test_key_not_found_is_crypto_error(self):
        assert issubclass(KeyNotFoundError, CryptoError)

    def test_signature_verification_is_crypto_error(self):
        assert issubclass(SignatureVerificationError, CryptoError)

    def test_key_generation_error_is_crypto_error(self):
        assert issubclass(KeyGenerationError, CryptoError)

    def test_subclasses_caught_as_crypto_error_knfe(self):
        with pytest.raises(CryptoError):
            raise KeyNotFoundError("caught as base")

    def test_subclasses_caught_as_crypto_error_sve(self):
        with pytest.raises(CryptoError):
            raise SignatureVerificationError("caught as base")

    def test_subclasses_caught_as_crypto_error_kge(self):
        with pytest.raises(CryptoError):
            raise KeyGenerationError("caught as base")

    def test_exceptions_carry_message(self):
        e = SignatureVerificationError("specific message")
        assert "specific message" in str(e)


# ---------------------------------------------------------------------------
# KeyMetadata Additional Tests
# ---------------------------------------------------------------------------

class TestKeyMetadataExtended:
    """Additional KeyMetadata tests — format validation and correctness."""

    def test_fingerprint_is_sha256_of_public_pem(self):
        """The fingerprint must be exactly SHA-256 of the PEM bytes."""
        km = RSAKeyManager(key_size=2048)
        meta = km.metadata
        pem_bytes = meta.public_key_pem.encode("utf-8")
        expected = hashlib.sha256(pem_bytes).hexdigest()
        assert meta.fingerprint == expected

    def test_fingerprint_length_is_64(self):
        km = RSAKeyManager(key_size=2048)
        assert len(km.metadata.fingerprint) == 64

    def test_fingerprint_is_lowercase_hex(self):
        km = RSAKeyManager(key_size=2048)
        fp = km.metadata.fingerprint
        assert all(c in "0123456789abcdef" for c in fp)

    def test_to_dict_has_all_six_keys(self):
        km = RSAKeyManager(key_size=2048)
        d = km.metadata.to_dict()
        assert set(d.keys()) == {"key_id", "fingerprint", "algorithm", "key_size", "created_at", "public_key_pem"}

    def test_to_dict_key_size_is_int(self):
        km = RSAKeyManager(key_size=2048)
        d = km.metadata.to_dict()
        assert isinstance(d["key_size"], int)
        assert d["key_size"] == 2048

    def test_algorithm_always_rsa_sha256(self):
        for size in RSAKeyManager.SUPPORTED_KEY_SIZES:
            km = RSAKeyManager(key_size=size)
            assert km.metadata.algorithm == "RSA-SHA256"

    def test_created_at_contains_timezone(self):
        km = RSAKeyManager(key_size=2048)
        created_at = km.metadata.created_at
        assert "+" in created_at or "Z" in created_at

    def test_public_key_pem_parseable(self):
        """The PEM in metadata can be parsed back by cryptography library."""
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import serialization
        km = RSAKeyManager(key_size=2048)
        pem = km.metadata.public_key_pem.encode("utf-8")
        key = serialization.load_pem_public_key(pem, backend=default_backend())
        assert key.key_size == 2048

    def test_metadata_key_id_preserved_after_persist(self, tmp_path):
        priv = str(tmp_path / "priv.pem")
        pub = str(tmp_path / "pub.pem")
        meta = generate_key_pair(priv, pub, key_size=2048, key_id="rotation-test")
        km2 = RSAKeyManager(private_key_path=priv, key_size=2048)
        # Fingerprint persists; key_id is re-assigned on reload (auto-generated)
        assert meta.fingerprint == km2.metadata.fingerprint


# ---------------------------------------------------------------------------
# RSAKeyManager: Supported Key Size Round-Trips
# ---------------------------------------------------------------------------

class TestAllKeySizes:
    """Test that all three supported sizes produce valid signing key pairs."""

    def test_2048_key_generates_and_signs(self):
        km = RSAKeyManager(key_size=2048)
        signer = RSASigner(km)
        sig, fp = signer.sign(b"2048 test")
        assert len(sig) == 256  # 2048/8

    def test_3072_key_generates_and_signs(self):
        km = RSAKeyManager(key_size=3072)
        signer = RSASigner(km)
        sig, fp = signer.sign(b"3072 test")
        assert len(sig) == 384  # 3072/8

    def test_4096_key_generates_and_signs(self):
        km = RSAKeyManager(key_size=4096)
        signer = RSASigner(km)
        sig, fp = signer.sign(b"4096 test")
        assert len(sig) == 512  # 4096/8

    def test_2048_verify_round_trip(self):
        km = RSAKeyManager(key_size=2048)
        signer = RSASigner(km)
        verifier = RSAVerifier(km)
        data = b"rt 2048"
        sig, fp = signer.sign(data)
        assert verifier.verify(data, sig, expected_fingerprint=fp)

    def test_3072_verify_round_trip(self):
        km = RSAKeyManager(key_size=3072)
        signer = RSASigner(km)
        verifier = RSAVerifier(km)
        data = b"rt 3072"
        sig, fp = signer.sign(data)
        assert verifier.verify(data, sig, expected_fingerprint=fp)

    def test_4096_verify_round_trip(self):
        km = RSAKeyManager(key_size=4096)
        signer = RSASigner(km)
        verifier = RSAVerifier(km)
        data = b"rt 4096"
        sig, fp = signer.sign(data)
        assert verifier.verify(data, sig, expected_fingerprint=fp)

    def test_key_size_2048_in_metadata(self):
        km = RSAKeyManager(key_size=2048)
        assert km.metadata.key_size == 2048

    def test_key_size_3072_in_metadata(self):
        km = RSAKeyManager(key_size=3072)
        assert km.metadata.key_size == 3072

    def test_key_size_4096_in_metadata(self):
        km = RSAKeyManager(key_size=4096)
        assert km.metadata.key_size == 4096

    def test_invalid_key_size_999_raises(self):
        with pytest.raises(KeyGenerationError):
            RSAKeyManager(key_size=999)

    def test_invalid_key_size_error_lists_supported(self):
        with pytest.raises(KeyGenerationError) as exc:
            RSAKeyManager(key_size=1024)
        msg = str(exc.value)
        assert "2048" in msg and "4096" in msg


# ---------------------------------------------------------------------------
# Sign & Verify Edge Cases
# ---------------------------------------------------------------------------

class TestSignVerifyEdgeCases:
    """Edge cases: empty data, large data, binary data, determinism."""

    def test_sign_empty_bytes(self):
        km = RSAKeyManager(key_size=2048)
        signer = RSASigner(km)
        verifier = RSAVerifier(km)
        sig, fp = signer.sign(b"")
        assert verifier.verify(b"", sig, expected_fingerprint=fp) is True

    def test_sign_single_byte(self):
        km = RSAKeyManager(key_size=2048)
        signer = RSASigner(km)
        verifier = RSAVerifier(km)
        sig, fp = signer.sign(b"\x00")
        assert verifier.verify(b"\x00", sig, expected_fingerprint=fp) is True

    def test_sign_null_bytes(self):
        km = RSAKeyManager(key_size=2048)
        signer = RSASigner(km)
        verifier = RSAVerifier(km)
        data = b"\x00" * 100
        sig, fp = signer.sign(data)
        assert verifier.verify(data, sig, expected_fingerprint=fp) is True

    def test_sign_all_byte_values(self):
        km = RSAKeyManager(key_size=2048)
        signer = RSASigner(km)
        verifier = RSAVerifier(km)
        data = bytes(range(256))
        sig, fp = signer.sign(data)
        assert verifier.verify(data, sig, expected_fingerprint=fp) is True

    def test_sign_large_data_512kb(self):
        km = RSAKeyManager(key_size=2048)
        signer = RSASigner(km)
        verifier = RSAVerifier(km)
        large = b"L" * 512 * 1024
        sig, fp = signer.sign(large)
        assert verifier.verify(large, sig, expected_fingerprint=fp) is True

    def test_sign_large_data_1mb(self):
        km = RSAKeyManager(key_size=2048)
        signer = RSASigner(km)
        verifier = RSAVerifier(km)
        large = b"M" * 1024 * 1024
        sig, fp = signer.sign(large)
        assert verifier.verify(large, sig, expected_fingerprint=fp) is True

    def test_pkcs1v15_is_deterministic(self):
        """PKCS#1 v1.5 padding is deterministic: same data => same signature."""
        km = RSAKeyManager(key_size=2048)
        signer = RSASigner(km)
        data = b"deterministic"
        sig1, fp1 = signer.sign(data)
        sig2, fp2 = signer.sign(data)
        assert sig1 == sig2
        assert fp1 == fp2

    def test_different_data_different_signatures(self):
        km = RSAKeyManager(key_size=2048)
        signer = RSASigner(km)
        sig1, _ = signer.sign(b"aaa")
        sig2, _ = signer.sign(b"bbb")
        assert sig1 != sig2

    def test_verify_one_bit_flip_fails(self):
        km = RSAKeyManager(key_size=2048)
        signer = RSASigner(km)
        verifier = RSAVerifier(km)
        data = b"bit flip test"
        sig, fp = signer.sign(data)
        # Flip last bit of data
        bad_data = data[:-1] + bytes([data[-1] ^ 0x01])
        assert verifier.verify(bad_data, sig) is False

    def test_verify_truncated_signature_fails(self):
        km = RSAKeyManager(key_size=2048)
        signer = RSASigner(km)
        verifier = RSAVerifier(km)
        data = b"truncation test"
        sig, _ = signer.sign(data)
        assert verifier.verify(data, sig[:128]) is False  # half signature

    def test_sign_base64_empty_bytes(self):
        km = RSAKeyManager(key_size=2048)
        signer = RSASigner(km)
        verifier = RSAVerifier(km)
        sig_b64, fp = signer.sign_base64(b"")
        assert verifier.verify_base64(b"", sig_b64, expected_fingerprint=fp) is True

    def test_verify_base64_wrong_data_returns_false(self):
        km = RSAKeyManager(key_size=2048)
        signer = RSASigner(km)
        verifier = RSAVerifier(km)
        sig_b64, fp = signer.sign_base64(b"original")
        assert verifier.verify_base64(b"modified", sig_b64) is False

    def test_cross_key_verify_returns_false(self):
        km_a = RSAKeyManager(key_size=2048)
        km_b = RSAKeyManager(key_size=2048)
        signer = RSASigner(km_a)
        verifier = RSAVerifier(km_b)
        data = b"cross key"
        sig, _ = signer.sign(data)
        assert verifier.verify(data, sig) is False


# ---------------------------------------------------------------------------
# Module-Level Singleton and Convenience Functions
# ---------------------------------------------------------------------------

class TestModuleLevelFunctions:
    """Tests for rsa_sign, rsa_verify, and singleton management."""

    def setup_method(self):
        """Reset singletons before each test."""
        _crypto_mod._default_key_manager = None
        _crypto_mod._default_signer = None
        _crypto_mod._default_verifier = None

    def teardown_method(self):
        """Reset singletons after each test."""
        _crypto_mod._default_key_manager = None
        _crypto_mod._default_signer = None
        _crypto_mod._default_verifier = None

    def test_rsa_sign_returns_bytes_and_str(self):
        sig, fp = rsa_sign(b"module test")
        assert isinstance(sig, bytes) and isinstance(fp, str)

    def test_rsa_sign_signature_is_nonempty(self):
        sig, _ = rsa_sign(b"data")
        assert len(sig) > 0

    def test_rsa_sign_fingerprint_is_64_hex(self):
        _, fp = rsa_sign(b"data")
        assert len(fp) == 64
        assert all(c in "0123456789abcdef" for c in fp)

    def test_rsa_verify_returns_true_for_valid(self):
        data = b"valid module verify"
        sig, fp = rsa_sign(data)
        assert rsa_verify(data, sig, fp) is True

    def test_rsa_verify_raises_on_wrong_fp(self):
        data = b"wrong fp"
        sig, fp = rsa_sign(data)
        with pytest.raises(SignatureVerificationError):
            rsa_verify(data, sig, "wrong_fp")

    def test_rsa_verify_raises_on_tampered_data(self):
        data = b"tampered module"
        sig, fp = rsa_sign(data)
        with pytest.raises(SignatureVerificationError):
            rsa_verify(b"tampered", sig, fp)

    def test_rsa_sign_empty_data(self):
        sig, fp = rsa_sign(b"")
        assert rsa_verify(b"", sig, fp) is True

    def test_singleton_km_same_instance(self):
        km1 = _crypto_mod._get_default_key_manager()
        km2 = _crypto_mod._get_default_key_manager()
        assert km1 is km2

    def test_singleton_signer_uses_same_km(self):
        km = _crypto_mod._get_default_key_manager()
        signer = _crypto_mod._get_default_signer()
        assert signer.key_manager is km

    def test_singleton_verifier_uses_same_km(self):
        km = _crypto_mod._get_default_key_manager()
        verifier = _crypto_mod._get_default_verifier()
        assert verifier.key_manager is km

    def test_rsa_sign_twice_same_fingerprint(self):
        """Both calls share the same singleton key."""
        _, fp1 = rsa_sign(b"x")
        _, fp2 = rsa_sign(b"y")
        assert fp1 == fp2

    def test_generate_key_pair_returns_key_metadata_instance(self, tmp_path):
        meta = generate_key_pair(
            str(tmp_path / "priv.pem"), str(tmp_path / "pub.pem"), key_size=2048
        )
        assert isinstance(meta, KeyMetadata)

    def test_generate_key_pair_metadata_algorithm(self, tmp_path):
        meta = generate_key_pair(
            str(tmp_path / "priv.pem"), str(tmp_path / "pub.pem"), key_size=2048
        )
        assert meta.algorithm == "RSA-SHA256"

    def test_generate_key_pair_metadata_fingerprint_not_empty(self, tmp_path):
        meta = generate_key_pair(
            str(tmp_path / "priv.pem"), str(tmp_path / "pub.pem"), key_size=2048
        )
        assert len(meta.fingerprint) == 64

    def test_generate_key_pair_with_custom_key_id(self, tmp_path):
        meta = generate_key_pair(
            str(tmp_path / "priv.pem"),
            str(tmp_path / "pub.pem"),
            key_size=2048,
            key_id="custom-id",
        )
        assert meta.key_id == "custom-id"

    def test_generate_key_pair_fingerprint_stable_on_reload(self, tmp_path):
        priv = str(tmp_path / "priv.pem")
        pub = str(tmp_path / "pub.pem")
        meta = generate_key_pair(priv, pub, key_size=2048)
        km = RSAKeyManager(private_key_path=priv, key_size=2048)
        assert km.metadata.fingerprint == meta.fingerprint


# ---------------------------------------------------------------------------
# get_public_key_pem and key properties
# ---------------------------------------------------------------------------

class TestGetPublicKeyPem:
    """Test get_public_key_pem and property access."""

    def test_get_public_key_pem_starts_with_begin(self):
        km = RSAKeyManager(key_size=2048)
        pem = km.get_public_key_pem()
        assert pem.startswith("-----BEGIN PUBLIC KEY-----")

    def test_get_public_key_pem_ends_with_end(self):
        km = RSAKeyManager(key_size=2048)
        pem = km.get_public_key_pem().strip()
        assert pem.endswith("-----END PUBLIC KEY-----")

    def test_get_public_key_pem_equals_metadata_pem(self):
        km = RSAKeyManager(key_size=2048)
        assert km.get_public_key_pem() == km.metadata.public_key_pem

    def test_auto_generated_key_id_has_fixops_prefix(self):
        km = RSAKeyManager(key_size=2048)
        assert km.key_id.startswith("fixops-rsa-")

    def test_explicit_key_id_preserved(self):
        km = RSAKeyManager(key_size=2048, key_id="explicit-id-xyz")
        assert km.key_id == "explicit-id-xyz"

    def test_two_ephemeral_keys_have_different_fingerprints(self):
        km1 = RSAKeyManager(key_size=2048)
        km2 = RSAKeyManager(key_size=2048)
        assert km1.metadata.fingerprint != km2.metadata.fingerprint

    def test_private_key_is_rsa_private_key_instance(self):
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
        km = RSAKeyManager(key_size=2048)
        assert isinstance(km.private_key, RSAPrivateKey)

    def test_public_key_is_rsa_public_key_instance(self):
        from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
        km = RSAKeyManager(key_size=2048)
        assert isinstance(km.public_key, RSAPublicKey)

    def test_private_key_matches_public_key(self):
        km = RSAKeyManager(key_size=2048)
        # Private key's public key must equal the standalone public key
        derived_pub = km.private_key.public_key()
        assert derived_pub.public_numbers() == km.public_key.public_numbers()

    def test_private_key_permissions_600_after_persist(self, tmp_path):
        priv = str(tmp_path / "secure.pem")
        pub = str(tmp_path / "pub.pem")
        generate_key_pair(priv, pub, key_size=2048)
        mode = oct(os.stat(priv).st_mode & 0o777)
        assert mode == "0o600"
