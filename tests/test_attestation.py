"""Unit tests for the provenance attestation module.

Tests cover:
- InTotoStatement: Statement creation and serialization
- InTotoEnvelope: Envelope creation with signing options
- require_signature parameter: Fail-closed behavior
- generate_signed_attestation: End-to-end attestation generation
- write_signed_attestation: Attestation persistence
- verify_envelope_signature: Signature verification
"""

import base64
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from services.provenance.attestation import (
    InTotoEnvelope,
    InTotoStatement,
    generate_attestation,
    generate_signed_attestation,
    verify_envelope_signature,
    write_signed_attestation,
)


class TestInTotoStatement:
    """Tests for InTotoStatement class."""

    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    @pytest.fixture
    def sample_attestation(self, temp_dir):
        """Create a sample attestation for testing."""
        # Create a test artifact
        artifact_path = os.path.join(temp_dir, "test_artifact.txt")
        with open(artifact_path, "w") as f:
            f.write("test content")

        return generate_attestation(
            artifact_path,
            builder_id="https://fixops.example.com/builder",
            source_uri="https://github.com/example/repo",
            build_type="https://fixops.example.com/build-type/v1",
        )

    def test_from_provenance(self, sample_attestation):
        """Test creating InTotoStatement from ProvenanceAttestation."""
        statement = InTotoStatement.from_provenance(sample_attestation)

        assert statement._type == "https://in-toto.io/Statement/v1"
        assert len(statement.subject) > 0
        assert statement.predicateType == "https://slsa.dev/provenance/v1"
        assert statement.predicate is not None

    def test_to_dict(self, sample_attestation):
        """Test InTotoStatement serialization to dict."""
        statement = InTotoStatement.from_provenance(sample_attestation)
        result = statement.to_dict()

        assert "_type" in result
        assert "subject" in result
        assert "predicateType" in result
        assert "predicate" in result

    def test_to_json(self, sample_attestation):
        """Test InTotoStatement serialization to JSON."""
        statement = InTotoStatement.from_provenance(sample_attestation)
        json_str = statement.to_json()

        # Should be valid JSON
        parsed = json.loads(json_str)
        assert "_type" in parsed


class TestInTotoEnvelope:
    """Tests for InTotoEnvelope class."""

    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    @pytest.fixture
    def sample_statement(self, temp_dir):
        """Create a sample statement for testing."""
        artifact_path = os.path.join(temp_dir, "test_artifact.txt")
        with open(artifact_path, "w") as f:
            f.write("test content")

        attestation = generate_attestation(
            artifact_path,
            builder_id="https://fixops.example.com/builder",
            source_uri="https://github.com/example/repo",
            build_type="https://fixops.example.com/build-type/v1",
        )
        return InTotoStatement.from_provenance(attestation)

    def test_from_statement_no_sign(self, sample_statement):
        """Test creating envelope without signing."""
        envelope = InTotoEnvelope.from_statement(sample_statement, sign=False)

        assert envelope.payloadType == "application/vnd.in-toto+json"
        assert envelope.payload is not None
        assert envelope.signatures == []

        # Verify payload is valid base64
        decoded = base64.b64decode(envelope.payload)
        parsed = json.loads(decoded)
        assert "_type" in parsed

    def test_from_statement_with_sign_no_module(self, sample_statement):
        """Test creating envelope with signing when module not available."""
        # Mock _rsa_sign as None to simulate module not available
        with patch("services.provenance.attestation._rsa_sign", None):
            envelope = InTotoEnvelope.from_statement(sample_statement, sign=True)

            # Should succeed but with no signatures
            assert envelope.signatures == []

    def test_from_statement_require_signature_no_module_raises(self, sample_statement):
        """Test require_signature=True raises when signing module unavailable.

        Covers lines 539-543 in attestation.py.
        """
        with patch("services.provenance.attestation._rsa_sign", None):
            with pytest.raises(RuntimeError) as exc_info:
                InTotoEnvelope.from_statement(
                    sample_statement, sign=True, require_signature=True
                )
            assert "Signing required but RSA signing module is not available" in str(
                exc_info.value
            )

    def test_from_statement_require_signature_signing_fails_raises(
        self, sample_statement
    ):
        """Test require_signature=True raises when signing fails.

        Covers lines 557-560 in attestation.py.
        """
        mock_sign = MagicMock(side_effect=Exception("Signing failed"))
        with patch("services.provenance.attestation._rsa_sign", mock_sign):
            with pytest.raises(RuntimeError) as exc_info:
                InTotoEnvelope.from_statement(
                    sample_statement, sign=True, require_signature=True
                )
            assert "Signing required but failed" in str(exc_info.value)

    def test_from_statement_signing_fails_without_require(self, sample_statement):
        """Test signing failure without require_signature returns unsigned envelope.

        Covers line 561 in attestation.py.
        """
        mock_sign = MagicMock(side_effect=Exception("Signing failed"))
        with patch("services.provenance.attestation._rsa_sign", mock_sign):
            envelope = InTotoEnvelope.from_statement(
                sample_statement, sign=True, require_signature=False
            )
            # Should succeed but with no signatures
            assert envelope.signatures == []

    def test_from_statement_successful_signing(self, sample_statement):
        """Test successful signing adds signature to envelope.

        Covers lines 548-555 in attestation.py.
        """
        mock_sign = MagicMock(return_value=(b"fake_signature", "fake_fingerprint"))
        with patch("services.provenance.attestation._rsa_sign", mock_sign):
            envelope = InTotoEnvelope.from_statement(sample_statement, sign=True)

            assert len(envelope.signatures) == 1
            assert envelope.signatures[0]["keyid"] == "fake_fingerprint"
            assert envelope.signatures[0]["sig"] == base64.b64encode(
                b"fake_signature"
            ).decode("utf-8")

    def test_to_dict(self, sample_statement):
        """Test InTotoEnvelope serialization to dict."""
        envelope = InTotoEnvelope.from_statement(sample_statement, sign=False)
        result = envelope.to_dict()

        assert "payloadType" in result
        assert "payload" in result
        assert "signatures" in result

    def test_to_json(self, sample_statement):
        """Test InTotoEnvelope serialization to JSON."""
        envelope = InTotoEnvelope.from_statement(sample_statement, sign=False)
        json_str = envelope.to_json()

        # Should be valid JSON
        parsed = json.loads(json_str)
        assert "payloadType" in parsed


class TestGenerateSignedAttestation:
    """Tests for generate_signed_attestation function."""

    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    def test_generate_signed_attestation_no_sign(self, temp_dir):
        """Test generating attestation without signing.

        Covers lines 602-622 in attestation.py.
        """
        artifact_path = os.path.join(temp_dir, "test_artifact.txt")
        with open(artifact_path, "w") as f:
            f.write("test content")

        envelope = generate_signed_attestation(
            artifact_path,
            builder_id="https://fixops.example.com/builder",
            source_uri="https://github.com/example/repo",
            build_type="https://fixops.example.com/build-type/v1",
            sign=False,
        )

        assert isinstance(envelope, InTotoEnvelope)
        assert envelope.payloadType == "application/vnd.in-toto+json"
        assert envelope.signatures == []

    def test_generate_signed_attestation_with_materials(self, temp_dir):
        """Test generating attestation with materials."""
        artifact_path = os.path.join(temp_dir, "test_artifact.txt")
        with open(artifact_path, "w") as f:
            f.write("test content")

        materials = [
            {"uri": "https://example.com/dep1", "digest": {"sha256": "abc123"}},
            {"uri": "https://example.com/dep2", "digest": {"sha256": "def456"}},
        ]

        envelope = generate_signed_attestation(
            artifact_path,
            builder_id="https://fixops.example.com/builder",
            source_uri="https://github.com/example/repo",
            build_type="https://fixops.example.com/build-type/v1",
            materials=materials,
            sign=False,
        )

        assert isinstance(envelope, InTotoEnvelope)

    def test_generate_signed_attestation_with_metadata(self, temp_dir):
        """Test generating attestation with metadata."""
        artifact_path = os.path.join(temp_dir, "test_artifact.txt")
        with open(artifact_path, "w") as f:
            f.write("test content")

        metadata = {"build_number": "123", "environment": "production"}

        envelope = generate_signed_attestation(
            artifact_path,
            builder_id="https://fixops.example.com/builder",
            source_uri="https://github.com/example/repo",
            build_type="https://fixops.example.com/build-type/v1",
            metadata=metadata,
            sign=False,
        )

        assert isinstance(envelope, InTotoEnvelope)

    def test_generate_signed_attestation_require_signature_raises(self, temp_dir):
        """Test require_signature=True raises when signing unavailable."""
        artifact_path = os.path.join(temp_dir, "test_artifact.txt")
        with open(artifact_path, "w") as f:
            f.write("test content")

        with patch("services.provenance.attestation._rsa_sign", None):
            with pytest.raises(RuntimeError) as exc_info:
                generate_signed_attestation(
                    artifact_path,
                    builder_id="https://fixops.example.com/builder",
                    source_uri="https://github.com/example/repo",
                    build_type="https://fixops.example.com/build-type/v1",
                    sign=True,
                    require_signature=True,
                )
            assert "Signing required" in str(exc_info.value)


class TestWriteSignedAttestation:
    """Tests for write_signed_attestation function."""

    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    def test_write_signed_attestation(self, temp_dir):
        """Test writing attestation to disk.

        Covers lines 625-633 in attestation.py.
        """
        artifact_path = os.path.join(temp_dir, "test_artifact.txt")
        with open(artifact_path, "w") as f:
            f.write("test content")

        envelope = generate_signed_attestation(
            artifact_path,
            builder_id="https://fixops.example.com/builder",
            source_uri="https://github.com/example/repo",
            build_type="https://fixops.example.com/build-type/v1",
            sign=False,
        )

        output_path = os.path.join(temp_dir, "attestation.json")
        result = write_signed_attestation(envelope, output_path)

        assert result == Path(output_path)
        assert os.path.exists(output_path)

        # Verify content
        with open(output_path) as f:
            content = json.load(f)
        assert "payloadType" in content
        assert "payload" in content
        assert "signatures" in content

    def test_write_signed_attestation_creates_parent_dirs(self, temp_dir):
        """Test writing attestation creates parent directories."""
        artifact_path = os.path.join(temp_dir, "test_artifact.txt")
        with open(artifact_path, "w") as f:
            f.write("test content")

        envelope = generate_signed_attestation(
            artifact_path,
            builder_id="https://fixops.example.com/builder",
            source_uri="https://github.com/example/repo",
            build_type="https://fixops.example.com/build-type/v1",
            sign=False,
        )

        output_path = os.path.join(temp_dir, "nested", "dir", "attestation.json")
        result = write_signed_attestation(envelope, output_path)

        assert result == Path(output_path)
        assert os.path.exists(output_path)


class TestVerifyEnvelopeSignature:
    """Tests for verify_envelope_signature function."""

    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir

    @pytest.fixture
    def unsigned_envelope(self, temp_dir):
        """Create an unsigned envelope for testing."""
        artifact_path = os.path.join(temp_dir, "test_artifact.txt")
        with open(artifact_path, "w") as f:
            f.write("test content")

        return generate_signed_attestation(
            artifact_path,
            builder_id="https://fixops.example.com/builder",
            source_uri="https://github.com/example/repo",
            build_type="https://fixops.example.com/build-type/v1",
            sign=False,
        )

    def test_verify_no_module_returns_false(self, unsigned_envelope):
        """Test verification returns False when module unavailable.

        Covers lines 641-643 in attestation.py.
        """
        with patch("services.provenance.attestation._rsa_verify", None):
            result = verify_envelope_signature(unsigned_envelope)
            assert result is False

    def test_verify_no_signatures_returns_false(self, unsigned_envelope):
        """Test verification returns False when no signatures.

        Covers lines 645-647 in attestation.py.
        """
        mock_verify = MagicMock(return_value=True)
        with patch("services.provenance.attestation._rsa_verify", mock_verify):
            result = verify_envelope_signature(unsigned_envelope)
            assert result is False

    def test_verify_invalid_payload_returns_false(self, unsigned_envelope):
        """Test verification returns False when payload is invalid base64.

        Covers lines 651-653 in attestation.py.
        """
        # Create envelope with invalid payload
        envelope = InTotoEnvelope(
            payloadType="application/vnd.in-toto+json",
            payload="not-valid-base64!!!",
            signatures=[{"keyid": "test", "sig": "test"}],
        )

        mock_verify = MagicMock(return_value=True)
        with patch("services.provenance.attestation._rsa_verify", mock_verify):
            result = verify_envelope_signature(envelope)
            assert result is False

    def test_verify_empty_keyid_or_sig_skipped(self, unsigned_envelope):
        """Test verification skips signatures with empty keyid or sig.

        Covers lines 659-660 in attestation.py.
        """
        # Create envelope with empty keyid/sig
        envelope = InTotoEnvelope(
            payloadType="application/vnd.in-toto+json",
            payload=base64.b64encode(b"test payload").decode("utf-8"),
            signatures=[{"keyid": "", "sig": "test"}, {"keyid": "test", "sig": ""}],
        )

        mock_verify = MagicMock(return_value=True)
        with patch("services.provenance.attestation._rsa_verify", mock_verify):
            result = verify_envelope_signature(envelope)
            # Should return False because all signatures were skipped
            assert result is False
            # Verify mock was never called
            mock_verify.assert_not_called()

    def test_verify_successful_signature(self, unsigned_envelope):
        """Test successful signature verification.

        Covers lines 662-669 in attestation.py.
        """
        # Create envelope with valid signature
        payload = base64.b64encode(b"test payload").decode("utf-8")
        sig = base64.b64encode(b"fake_signature").decode("utf-8")
        envelope = InTotoEnvelope(
            payloadType="application/vnd.in-toto+json",
            payload=payload,
            signatures=[{"keyid": "test_fingerprint", "sig": sig}],
        )

        mock_verify = MagicMock(return_value=True)
        with patch("services.provenance.attestation._rsa_verify", mock_verify):
            result = verify_envelope_signature(envelope)
            assert result is True
            mock_verify.assert_called_once()

    def test_verify_failed_signature(self, unsigned_envelope):
        """Test failed signature verification.

        Covers lines 670-671 in attestation.py.
        """
        # Create envelope with signature
        payload = base64.b64encode(b"test payload").decode("utf-8")
        sig = base64.b64encode(b"fake_signature").decode("utf-8")
        envelope = InTotoEnvelope(
            payloadType="application/vnd.in-toto+json",
            payload=payload,
            signatures=[{"keyid": "test_fingerprint", "sig": sig}],
        )

        mock_verify = MagicMock(side_effect=Exception("Verification failed"))
        with patch("services.provenance.attestation._rsa_verify", mock_verify):
            result = verify_envelope_signature(envelope)
            assert result is False

    def test_verify_returns_false_when_verify_returns_false(self, unsigned_envelope):
        """Test verification returns False when verifier returns False.

        Covers line 673 in attestation.py.
        """
        # Create envelope with signature
        payload = base64.b64encode(b"test payload").decode("utf-8")
        sig = base64.b64encode(b"fake_signature").decode("utf-8")
        envelope = InTotoEnvelope(
            payloadType="application/vnd.in-toto+json",
            payload=payload,
            signatures=[{"keyid": "test_fingerprint", "sig": sig}],
        )

        mock_verify = MagicMock(return_value=False)
        with patch("services.provenance.attestation._rsa_verify", mock_verify):
            result = verify_envelope_signature(envelope)
            assert result is False
