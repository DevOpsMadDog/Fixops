"""Unit tests for the production-ready RSA crypto module.

Tests cover:
- RSAKeyManager: Key generation, loading, persistence, rotation
- RSASigner: Signature generation
- RSAVerifier: Signature verification
- Module-level convenience functions
- Error handling and edge cases
"""

import os
import tempfile
from unittest.mock import patch

import pytest
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
