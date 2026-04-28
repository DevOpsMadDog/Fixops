"""Tests for real DSSE signing — SLSA, air-gap bundle, container runtime, k8s.

Covers:
  - DSSESigner: key generation/loading, sign/verify roundtrip, tamper detection
  - SLSAProvenanceEngine: real signatures in envelope, crypto verify passes
  - AirGapBundleEngine: real ed25519 bundle signature, not placeholder string
  - ImageSigningVerifier: cosign-not-found path returns structured result (not crash)
  - k8s ImageSecurityScanner: cosign-not-found path returns False (not crash)
"""

from __future__ import annotations

import base64
import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _import_dsse_signer():
    """Import DSSESigner; skip test if cryptography not available."""
    try:
        from core.dsse_signer import DSSESigner, get_signer
        return DSSESigner, get_signer
    except ImportError as exc:
        pytest.skip(f"dsse_signer not importable: {exc}")


# ---------------------------------------------------------------------------
# DSSESigner unit tests
# ---------------------------------------------------------------------------


class TestDSSESigner:
    def _make_signer(self, tmp_path: Path):
        DSSESigner, _ = _import_dsse_signer()
        return DSSESigner(key_dir=tmp_path)

    def test_generates_key_on_first_use(self, tmp_path):
        signer = self._make_signer(tmp_path)
        assert (tmp_path / "slsa_signing.pem").exists()
        assert (tmp_path / "slsa_signing_pub.pem").exists()

    def test_private_key_permissions_0600(self, tmp_path):
        self._make_signer(tmp_path)
        priv_path = tmp_path / "slsa_signing.pem"
        mode = oct(priv_path.stat().st_mode & 0o777)
        assert mode == oct(0o600), f"Expected 0600, got {mode}"

    def test_fingerprint_is_hex_sha256(self, tmp_path):
        signer = self._make_signer(tmp_path)
        fp = signer.fingerprint
        assert len(fp) == 64
        assert all(c in "0123456789abcdef" for c in fp)

    def test_public_key_pem_present(self, tmp_path):
        signer = self._make_signer(tmp_path)
        pem = signer.public_key_pem
        assert pem.startswith("-----BEGIN PUBLIC KEY-----")

    def test_sign_dsse_roundtrip(self, tmp_path):
        signer = self._make_signer(tmp_path)
        payload = {"foo": "bar", "n": 42}
        envelope = signer.sign_dsse("application/vnd.test+json", payload)

        assert envelope["payloadType"] == "application/vnd.test+json"
        assert len(envelope["signatures"]) == 1
        sig_block = envelope["signatures"][0]
        assert sig_block["keyid"] == signer.fingerprint
        # sig must be non-empty base64
        raw_sig = base64.b64decode(sig_block["sig"])
        assert len(raw_sig) == 64  # ed25519 signature is always 64 bytes

    def test_verify_dsse_passes_on_valid_envelope(self, tmp_path):
        signer = self._make_signer(tmp_path)
        payload = {"hello": "world"}
        envelope = signer.sign_dsse("application/vnd.test+json", payload)
        assert signer.verify_dsse(envelope) is True

    def test_verify_dsse_fails_on_tampered_payload(self, tmp_path):
        signer = self._make_signer(tmp_path)
        payload = {"hello": "world"}
        envelope = signer.sign_dsse("application/vnd.test+json", payload)

        # Tamper: replace payload with different content
        tampered_payload = json.dumps({"hello": "TAMPERED"}, sort_keys=True, separators=(",", ":")).encode()
        envelope["payload"] = base64.b64encode(tampered_payload).decode()

        assert signer.verify_dsse(envelope) is False

    def test_verify_dsse_fails_on_tampered_signature(self, tmp_path):
        signer = self._make_signer(tmp_path)
        envelope = signer.sign_dsse("application/vnd.test+json", {"x": 1})
        # Corrupt the signature
        envelope["signatures"][0]["sig"] = base64.b64encode(b"A" * 64).decode()
        assert signer.verify_dsse(envelope) is False

    def test_verify_dsse_fails_on_empty_envelope(self, tmp_path):
        signer = self._make_signer(tmp_path)
        assert signer.verify_dsse({}) is False

    def test_key_reloaded_on_second_instantiation(self, tmp_path):
        DSSESigner, _ = _import_dsse_signer()
        s1 = DSSESigner(key_dir=tmp_path)
        s2 = DSSESigner(key_dir=tmp_path)
        # Same key means same fingerprint
        assert s1.fingerprint == s2.fingerprint

    def test_sign_bytes_roundtrip(self, tmp_path):
        signer = self._make_signer(tmp_path)
        data = b"hello air-gap bundle"
        sig = signer.sign_bytes(data)
        assert signer.verify_bytes(data, sig) is True

    def test_verify_bytes_fails_on_tampered_data(self, tmp_path):
        signer = self._make_signer(tmp_path)
        data = b"original"
        sig = signer.sign_bytes(data)
        assert signer.verify_bytes(b"tampered", sig) is False


# ---------------------------------------------------------------------------
# SLSAProvenanceEngine — real envelope signing
# ---------------------------------------------------------------------------


class TestSLSAProvenanceEngineRealSigning:
    def _make_engine(self, tmp_path: Path):
        try:
            from core.slsa_provenance_engine import SLSAProvenanceEngine
        except ImportError as exc:
            pytest.skip(f"slsa_provenance_engine not importable: {exc}")

        db = str(tmp_path / "slsa.db")
        return SLSAProvenanceEngine(db_path=db)

    def test_generate_attestation_has_real_signature(self, tmp_path):
        engine = self._make_engine(tmp_path)

        with patch.dict(os.environ, {"ALDECI_SIGNING_KEY_PATH": str(tmp_path / "keys")}):
            result = engine.generate_attestation(
                org_id="org-test",
                subject_name="my-image",
                subject_sha256="a" * 64,
                builder_id="https://ci.example.com/builder",
                build_type="https://slsa.dev/buildtype/v1",
                materials=[{"uri": "git+https://github.com/example/repo", "digest": {"sha1": "abc123"}}],
            )

        envelope = result["envelope"]
        assert envelope["payloadType"] == "application/vnd.in-toto+json"
        sigs = envelope["signatures"]
        assert len(sigs) == 1
        sig_b64 = sigs[0]["sig"]
        # Must not be the old placeholder string
        assert "placeholder" not in sig_b64.lower()
        # Must be valid base64 of 64 bytes (ed25519) or fallback
        try:
            raw = base64.b64decode(sig_b64)
            assert len(raw) == 64, f"ed25519 sig should be 64 bytes, got {len(raw)}"
        except Exception:
            pytest.fail(f"signature is not valid base64: {sig_b64!r}")

    def test_verify_attestation_passes_crypto_check(self, tmp_path):
        engine = self._make_engine(tmp_path)

        with patch.dict(os.environ, {"ALDECI_SIGNING_KEY_PATH": str(tmp_path / "keys")}):
            att = engine.generate_attestation(
                org_id="org-test",
                subject_name="my-image",
                subject_sha256="b" * 64,
                builder_id="https://ci.example.com/builder",
                build_type="https://slsa.dev/buildtype/v1",
                materials=[{"uri": "git+https://github.com/example/repo", "digest": {"sha1": "def456"}}],
            )
            result = engine.verify_attestation(att["id"])

        assert result["verdict"] == "pass", f"Expected pass, got: {result}"
        checks = result.get("checks", {})
        # Real crypto check should be present and True
        if "signature_crypto_valid" in checks:
            assert checks["signature_crypto_valid"] is True

    def test_attestation_signature_not_placeholder(self, tmp_path):
        engine = self._make_engine(tmp_path)

        with patch.dict(os.environ, {"ALDECI_SIGNING_KEY_PATH": str(tmp_path / "keys")}):
            att = engine.generate_attestation(
                org_id="org-test",
                subject_name="artifact",
                subject_sha256="c" * 64,
                builder_id="https://ci.example.com/builder",
                build_type="https://slsa.dev/buildtype/v1",
                materials=[{"uri": "https://example.com/src", "digest": {"sha256": "d" * 64}}],
            )

        sig_field = att["envelope"]["signatures"][0]["sig"]
        assert sig_field != "placeholder-signature-v0-not-for-production-use"
        assert sig_field != "unsigned-fallback-signature-not-for-production-use"


# ---------------------------------------------------------------------------
# AirGapBundleEngine — real ed25519 bundle signature
# ---------------------------------------------------------------------------


class TestAirGapBundleEngineRealSigning:
    def _make_engine(self, tmp_path: Path):
        try:
            from core.air_gap_bundle_engine import AirGapBundleEngine
        except ImportError as exc:
            pytest.skip(f"air_gap_bundle_engine not importable: {exc}")

        db = str(tmp_path / "airgap.db")
        bundle_dir = tmp_path / "bundles"
        return AirGapBundleEngine(
            db_path=db,
            bundle_dir=bundle_dir,
        )

    def test_export_bundle_signature_not_placeholder(self, tmp_path):
        engine = self._make_engine(tmp_path)

        with patch.dict(os.environ, {"ALDECI_SIGNING_KEY_PATH": str(tmp_path / "keys")}):
            result = engine.export_bundle(
                org_id="org-test",
                extra_cve_rows=[{"cve_id": "CVE-2024-0001", "cvss_score": 9.8}],
                extra_ti_rows=[],
                extra_policy_rows=[],
            )

        sig = result["signature_placeholder"]
        assert "placeholder" not in sig.lower() or sig.startswith("sha256-fallback:"), (
            f"Signature still looks like old placeholder: {sig!r}"
        )
        # Real sig is base64 of 64 bytes
        if not sig.startswith("sha256-fallback:"):
            raw = base64.b64decode(sig)
            assert len(raw) == 64

    def test_verify_bundle_passes_after_export(self, tmp_path):
        engine = self._make_engine(tmp_path)

        with patch.dict(os.environ, {"ALDECI_SIGNING_KEY_PATH": str(tmp_path / "keys")}):
            exported = engine.export_bundle(
                org_id="org-test",
                extra_cve_rows=[{"cve_id": "CVE-2024-0002", "cvss_score": 7.5}],
            )
            verify_result = engine.verify_bundle(exported["bundle_id"])

        assert verify_result["ok"] is True, f"verify_bundle failed: {verify_result['errors']}"

    def test_verify_bundle_fails_on_tampered_archive(self, tmp_path):
        """A bundle whose MANIFEST signature has been tampered must fail verification."""
        import tarfile
        import io

        engine = self._make_engine(tmp_path)

        with patch.dict(os.environ, {"ALDECI_SIGNING_KEY_PATH": str(tmp_path / "keys")}):
            exported = engine.export_bundle(
                org_id="org-test",
                extra_cve_rows=[{"cve_id": "CVE-2024-0003", "cvss_score": 5.0}],
            )

        archive_path = Path(exported["archive_path"])

        # Re-pack with corrupted manifest signature
        members: Dict[str, bytes] = {}
        with tarfile.open(str(archive_path), "r:gz") as tar:
            for member in tar.getmembers():
                f = tar.extractfile(member)
                if f:
                    members[member.name] = f.read()

        # Corrupt the manifest signature field
        manifest = json.loads(members["MANIFEST.json"].decode())
        manifest["signature"] = "corrupted-signature-aaaa"
        members["MANIFEST.json"] = json.dumps(manifest, indent=2).encode()

        # Write corrupted archive back
        tampered_path = archive_path.parent / "tampered.tar.gz"
        with tarfile.open(str(tampered_path), "w:gz") as tar:
            for name, data in members.items():
                info = tarfile.TarInfo(name=name)
                info.size = len(data)
                tar.addfile(info, io.BytesIO(data))

        result = engine.verify_bundle(str(tampered_path))
        assert result["ok"] is False
        assert any("signature" in e.lower() for e in result["errors"])


# ---------------------------------------------------------------------------
# ImageSigningVerifier — cosign not-found path
# ---------------------------------------------------------------------------


class TestImageSigningVerifierCosignNotFound:
    def test_cosign_not_found_returns_structured_result_not_crash(self):
        try:
            from core.container_runtime import ImageSigningVerifier, SignatureScheme
        except ImportError as exc:
            pytest.skip(f"container_runtime not importable: {exc}")

        verifier = ImageSigningVerifier(require_signed=False)

        with patch("shutil.which", return_value=None):
            result = verifier.verify(
                image_ref="docker.io/library/nginx:latest",
                signature_data={
                    "signatures": [{"signer": "test", "digest": "sha256:abc"}],
                    "signer": "test",
                    "digest": "sha256:abc",
                },
                scheme=SignatureScheme.COSIGN,
            )

        # Must return a result, not raise
        assert result is not None
        assert hasattr(result, "verified")
        assert hasattr(result, "policy_compliant")

    def test_cosign_not_found_no_signature_data_returns_unverified(self):
        try:
            from core.container_runtime import ImageSigningVerifier, SignatureScheme
        except ImportError as exc:
            pytest.skip(f"container_runtime not importable: {exc}")

        verifier = ImageSigningVerifier(require_signed=False)
        result = verifier.verify(
            image_ref="docker.io/library/alpine:3.18",
            signature_data=None,
        )
        assert result.verified is False
        assert result.policy_compliant is True  # not require_signed → compliant


# ---------------------------------------------------------------------------
# K8s ImageSecurityScanner — cosign not-found path
# ---------------------------------------------------------------------------


class TestK8sImageSecurityScannerCosignNotFound:
    def _make_engine(self):
        try:
            from core.k8s_security import K8sSecurityEngine
        except ImportError as exc:
            pytest.skip(f"k8s_security not importable: {exc}")
        return K8sSecurityEngine()

    def test_is_image_signed_returns_false_not_crash_when_cosign_missing(self):
        engine = self._make_engine()
        with patch("shutil.which", return_value=None):
            result = engine._is_image_signed("docker.io/library/nginx:latest")
        assert result is False  # conservative: unsigned when cosign absent

    def test_is_image_signed_returns_false_on_cosign_nonzero(self):
        engine = self._make_engine()
        fake_cosign = "/usr/local/bin/cosign"
        with patch("shutil.which", return_value=fake_cosign):
            import subprocess as _sp
            completed = _sp.CompletedProcess(
                args=[fake_cosign, "verify", "nginx:latest"],
                returncode=1,
                stdout="",
                stderr="no signatures found",
            )
            with patch("subprocess.run", return_value=completed):
                result = engine._is_image_signed("nginx:latest")
        assert result is False

    def test_is_image_signed_returns_true_on_cosign_zero(self):
        engine = self._make_engine()
        fake_cosign = "/usr/local/bin/cosign"
        with patch("shutil.which", return_value=fake_cosign):
            import subprocess as _sp
            completed = _sp.CompletedProcess(
                args=[fake_cosign, "verify", "nginx:signed"],
                returncode=0,
                stdout='[{"critical": {}}]',
                stderr="",
            )
            with patch("subprocess.run", return_value=completed):
                result = engine._is_image_signed("nginx:signed")
        assert result is True

    def test_is_image_signed_returns_false_on_timeout(self):
        engine = self._make_engine()
        import subprocess as _sp
        fake_cosign = "/usr/local/bin/cosign"
        with patch("shutil.which", return_value=fake_cosign):
            with patch("subprocess.run", side_effect=_sp.TimeoutExpired(cmd="cosign", timeout=15)):
                result = engine._is_image_signed("nginx:latest")
        assert result is False
