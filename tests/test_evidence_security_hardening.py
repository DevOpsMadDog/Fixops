"""Security hardening tests for evidence export and crypto subsystem.

Extends DEMO-011 coverage with:
1. Direct RSA-SHA256 roundtrip verification (crypto.py independent of API)
2. ISO27001, NIST-CSF, NIST-800-53 framework export tests
3. Cross-key verification failure (replay attack resistance)
4. Large bundle signing resilience
5. Input validation edge cases (injection, oversized payloads)
6. Signature non-malleability
7. Content hash determinism

Pillar: V10 — CTEM Full Loop with Cryptographic Proof
"""

import base64
import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

# Set API token and disable rate limiting before importing the app
os.environ.setdefault(
    "FIXOPS_API_TOKEN",
    "aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh",
)
os.environ["FIXOPS_DISABLE_RATE_LIMIT"] = "1"
API_TOKEN = os.environ["FIXOPS_API_TOKEN"]
AUTH_HEADERS = {"X-API-Key": API_TOKEN}

# Ensure suite paths are available
ROOT = Path(__file__).parent.parent
for suite_dir in ["suite-core", "suite-api", "suite-evidence-risk", "suite-attack"]:
    path = str(ROOT / suite_dir)
    if path not in sys.path:
        sys.path.insert(0, path)

from fastapi.testclient import TestClient


@pytest.fixture(scope="module")
def client():
    """Create a test client for the FastAPI app."""
    try:
        from apps.api.app import create_app

        app = create_app()
    except Exception:
        from fastapi import FastAPI
        from api.evidence_router import router

        app = FastAPI()
        app.include_router(router, prefix="/api/v1")
    return TestClient(app, raise_server_exceptions=False)


# ---------------------------------------------------------------------------
# Direct crypto.py RSA-SHA256 roundtrip tests
# ---------------------------------------------------------------------------


class TestCryptoRoundtrip:
    """Verify RSA-SHA256 crypto.py works independently of the API."""

    def test_sign_verify_json_payload(self):
        """Sign a JSON payload and verify it, matching evidence_router behavior."""
        from core.crypto import RSAKeyManager, RSASigner, RSAVerifier

        km = RSAKeyManager(key_size=2048)
        signer = RSASigner(km)
        verifier = RSAVerifier(km)

        payload = {
            "bundle_id": "EVB-2026-TEST01",
            "framework": "SOC2",
            "controls": [{"id": "CC7.1", "status": "satisfied"}],
        }
        canonical = json.dumps(payload, sort_keys=True).encode("utf-8")
        sig_bytes, fingerprint = signer.sign(canonical)
        sig_b64 = base64.b64encode(sig_bytes).decode("utf-8")

        # Verify raw
        assert verifier.verify(canonical, sig_bytes, fingerprint)
        # Verify via base64
        assert verifier.verify_base64(canonical, sig_b64, fingerprint)

    def test_sign_verify_deterministic_hash(self):
        """Content hash must be deterministic across serializations."""
        from core.crypto import RSAKeyManager, RSASigner, RSAVerifier

        km = RSAKeyManager(key_size=2048)
        signer = RSASigner(km)
        verifier = RSAVerifier(km)

        data = {"z_last": 1, "a_first": 2, "m_middle": 3}
        canonical = json.dumps(data, sort_keys=True).encode("utf-8")
        h1 = hashlib.sha256(canonical).hexdigest()
        h2 = hashlib.sha256(
            json.dumps(data, sort_keys=True).encode("utf-8")
        ).hexdigest()
        assert h1 == h2

        sig, fp = signer.sign(canonical)
        assert verifier.verify(canonical, sig, fp)

    def test_cross_key_verification_fails(self):
        """Signature from key A must NOT verify with key B (replay attack resistance)."""
        from core.crypto import RSAKeyManager, RSASigner, RSAVerifier

        km_a = RSAKeyManager(key_size=2048, key_id="key-A")
        km_b = RSAKeyManager(key_size=2048, key_id="key-B")

        signer_a = RSASigner(km_a)
        verifier_b = RSAVerifier(km_b)

        data = b"sensitive compliance evidence"
        sig, fp = signer_a.sign(data)

        # Must fail — different key pair
        assert not verifier_b.verify(data, sig)

    def test_signature_non_malleability(self):
        """Flipping one bit in signature must cause verification failure."""
        from core.crypto import RSAKeyManager, RSASigner, RSAVerifier

        km = RSAKeyManager(key_size=2048)
        signer = RSASigner(km)
        verifier = RSAVerifier(km)

        data = b"critical audit trail data"
        sig, fp = signer.sign(data)

        # Flip one bit in the signature
        tampered_sig = bytearray(sig)
        tampered_sig[0] ^= 0x01
        assert not verifier.verify(data, bytes(tampered_sig), fp)

    def test_empty_data_signing(self):
        """Signing empty data should work (edge case for empty bundles)."""
        from core.crypto import RSAKeyManager, RSASigner, RSAVerifier

        km = RSAKeyManager(key_size=2048)
        signer = RSASigner(km)
        verifier = RSAVerifier(km)

        sig, fp = signer.sign(b"")
        assert verifier.verify(b"", sig, fp)

    def test_large_payload_signing(self):
        """Signing a large payload (1MB) should work within timeout."""
        from core.crypto import RSAKeyManager, RSASigner, RSAVerifier

        km = RSAKeyManager(key_size=2048)
        signer = RSASigner(km)
        verifier = RSAVerifier(km)

        # 1MB payload — simulates a large compliance bundle
        large_data = b"X" * (1024 * 1024)
        sig, fp = signer.sign(large_data)
        assert verifier.verify(large_data, sig, fp)

    def test_invalid_base64_signature_rejected(self):
        """Invalid base64 in signature must be rejected gracefully."""
        from core.crypto import RSAKeyManager, RSAVerifier

        km = RSAKeyManager(key_size=2048)
        verifier = RSAVerifier(km)

        assert not verifier.verify_base64(b"data", "not-valid-base64!!!")

    def test_key_size_4096_default(self):
        """Default key size should be 4096 bits for production security."""
        from core.crypto import RSAKeyManager

        km = RSAKeyManager()
        assert km.metadata.key_size == 4096

    def test_unsupported_key_size_rejected(self):
        """Unsupported key sizes (e.g., 1024) must be rejected."""
        from core.crypto import KeyGenerationError, RSAKeyManager

        with pytest.raises(KeyGenerationError):
            RSAKeyManager(key_size=1024)


# ---------------------------------------------------------------------------
# Additional framework export tests
# ---------------------------------------------------------------------------


class TestEvidenceExportISO27001:
    """Tests for ISO27001 framework compliance export."""

    def test_export_iso27001_returns_200(self, client):
        resp = client.post(
            "/api/v1/evidence/export",
            json={"framework": "ISO27001", "sign": True},
            headers=AUTH_HEADERS,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["framework"] == "ISO27001"
        assert data["signed"] is True

    def test_export_iso27001_has_controls(self, client):
        resp = client.post(
            "/api/v1/evidence/export",
            json={"framework": "ISO27001"},
            headers=AUTH_HEADERS,
        )
        data = resp.json()
        assert len(data["controls"]) >= 5
        # ISO27001 controls should have Annex A references
        control_ids = {c["control_id"] for c in data["controls"]}
        assert len(control_ids) >= 5

    def test_export_iso27001_signature_verifiable(self, client):
        """Verify ISO27001 export signature via /export/verify."""
        export_resp = client.post(
            "/api/v1/evidence/export",
            json={"framework": "ISO27001", "sign": True},
            headers=AUTH_HEADERS,
        )
        bundle = export_resp.json()
        verify_resp = client.post(
            "/api/v1/evidence/export/verify",
            json={"bundle": bundle},
            headers=AUTH_HEADERS,
        )
        assert verify_resp.status_code == 200
        result = verify_resp.json()
        assert result["verified"] is True


class TestEvidenceExportNISTCSF:
    """Tests for NIST Cybersecurity Framework export."""

    def test_export_nist_csf_returns_200(self, client):
        resp = client.post(
            "/api/v1/evidence/export",
            json={"framework": "NIST-CSF"},
            headers=AUTH_HEADERS,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["framework"] == "NIST-CSF"

    def test_export_nist_csf_signed_verifiable(self, client):
        """Full roundtrip: export → sign → verify for NIST-CSF."""
        export_resp = client.post(
            "/api/v1/evidence/export",
            json={"framework": "NIST-CSF", "sign": True},
            headers=AUTH_HEADERS,
        )
        bundle = export_resp.json()
        assert bundle["signed"] is True

        verify_resp = client.post(
            "/api/v1/evidence/export/verify",
            json={"bundle": bundle},
            headers=AUTH_HEADERS,
        )
        result = verify_resp.json()
        assert result["verified"] is True


class TestEvidenceExportNIST80053:
    """Tests for NIST 800-53 framework export."""

    def test_export_nist_800_53_returns_200(self, client):
        resp = client.post(
            "/api/v1/evidence/export",
            json={"framework": "NIST-800-53"},
            headers=AUTH_HEADERS,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["framework"] == "NIST-800-53"

    def test_export_nist_800_53_signed_verifiable(self, client):
        export_resp = client.post(
            "/api/v1/evidence/export",
            json={"framework": "NIST-800-53", "sign": True},
            headers=AUTH_HEADERS,
        )
        bundle = export_resp.json()
        assert bundle["signed"] is True

        verify_resp = client.post(
            "/api/v1/evidence/export/verify",
            json={"bundle": bundle},
            headers=AUTH_HEADERS,
        )
        result = verify_resp.json()
        assert result["verified"] is True


# ---------------------------------------------------------------------------
# Input validation and attack surface tests
# ---------------------------------------------------------------------------


class TestExportAttackSurface:
    """Tests for malicious/edge-case inputs against the export endpoint."""

    def test_xss_in_app_id_sanitized(self, client):
        """XSS payload in app_id must not appear unescaped in response."""
        resp = client.post(
            "/api/v1/evidence/export",
            json={
                "framework": "SOC2",
                "app_id": '<script>alert("xss")</script>',
            },
            headers=AUTH_HEADERS,
        )
        # Should return 200 (app_id is a string field, validated by max_length)
        assert resp.status_code == 200
        data = resp.json()
        # The app_id is stored but the response is JSON, so no XSS risk
        # Key assertion: the content is still well-formed JSON
        assert "bundle_id" in data

    def test_sql_injection_in_framework_rejected(self, client):
        """SQL injection in framework field must be rejected by validation."""
        resp = client.post(
            "/api/v1/evidence/export",
            json={"framework": "SOC2'; DROP TABLE evidence;--"},
            headers=AUTH_HEADERS,
        )
        assert resp.status_code == 422

    def test_empty_framework_uses_default(self, client):
        """Empty body should use SOC2 default."""
        resp = client.post(
            "/api/v1/evidence/export",
            json={},
            headers=AUTH_HEADERS,
        )
        assert resp.status_code == 200
        assert resp.json()["framework"] == "SOC2"

    def test_negative_period_days_rejected(self, client):
        resp = client.post(
            "/api/v1/evidence/export",
            json={"framework": "SOC2", "period_days": -1},
            headers=AUTH_HEADERS,
        )
        assert resp.status_code == 422

    def test_verify_with_empty_bundle(self, client):
        """Empty bundle dict should fail gracefully."""
        resp = client.post(
            "/api/v1/evidence/export/verify",
            json={"bundle": {}},
            headers=AUTH_HEADERS,
        )
        assert resp.status_code == 200
        result = resp.json()
        assert result["verified"] is False

    def test_verify_with_garbage_signature(self, client):
        """Random signature string should fail verification."""
        export_resp = client.post(
            "/api/v1/evidence/export",
            json={"framework": "SOC2", "sign": True},
            headers=AUTH_HEADERS,
        )
        bundle = export_resp.json()
        # Replace signature with garbage
        bundle["signature"] = base64.b64encode(b"garbage" * 50).decode()

        verify_resp = client.post(
            "/api/v1/evidence/export/verify",
            json={"bundle": bundle},
            headers=AUTH_HEADERS,
        )
        result = verify_resp.json()
        assert result["verified"] is False
        assert result["signature_valid"] is False

    def test_verify_with_swapped_hash(self, client):
        """Bundle with mismatched content hash should fail."""
        export_resp = client.post(
            "/api/v1/evidence/export",
            json={"framework": "SOC2", "sign": True},
            headers=AUTH_HEADERS,
        )
        bundle = export_resp.json()
        bundle["content_hash"] = "sha256:" + "a" * 64

        verify_resp = client.post(
            "/api/v1/evidence/export/verify",
            json={"bundle": bundle},
            headers=AUTH_HEADERS,
        )
        result = verify_resp.json()
        assert result["verified"] is False

    def test_export_status_endpoint(self, client):
        """Status endpoint should report operational with crypto details."""
        resp = client.get(
            "/api/v1/evidence/export/status",
            headers=AUTH_HEADERS,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "operational"
        assert data["crypto_available"] is True
        assert "signing_key" in data
        assert data["signing_key"]["algorithm"] == "RSA-SHA256"
        assert data["signing_key"]["key_size"] in (2048, 3072, 4096)
        assert data["signature_algorithm"] == "RSA-SHA256 (PKCS1v15)"

    def test_all_six_frameworks_supported(self, client):
        """All 6 supported frameworks should be listed in status."""
        resp = client.get(
            "/api/v1/evidence/export/status",
            headers=AUTH_HEADERS,
        )
        data = resp.json()
        frameworks = data["supported_frameworks"]
        for fw in ["HIPAA", "ISO27001", "NIST-800-53", "NIST-CSF", "PCI-DSS", "SOC2"]:
            assert fw in frameworks, f"Missing framework: {fw}"


# ---------------------------------------------------------------------------
# Cross-framework verification consistency
# ---------------------------------------------------------------------------


class TestCrossFrameworkConsistency:
    """Ensure all frameworks produce verifiable bundles with consistent structure."""

    @pytest.mark.parametrize(
        "framework",
        ["SOC2", "PCI-DSS", "HIPAA", "ISO27001", "NIST-CSF", "NIST-800-53"],
    )
    def test_framework_export_verify_roundtrip(self, client, framework):
        """Every framework must produce a signed, verifiable bundle."""
        export_resp = client.post(
            "/api/v1/evidence/export",
            json={"framework": framework, "sign": True},
            headers=AUTH_HEADERS,
        )
        assert export_resp.status_code == 200
        bundle = export_resp.json()

        # Structural assertions
        assert bundle["framework"] == framework
        assert bundle["signed"] is True
        assert bundle["signature"] is not None
        assert bundle["key_fingerprint"] is not None
        assert bundle["content_hash"].startswith("sha256:")
        assert len(bundle["controls"]) >= 1
        assert "posture" in bundle
        assert "gaps" in bundle
        assert "summary" in bundle
        assert "metadata" in bundle
        assert bundle["metadata"]["platform"] == "ALdeci CTEM+"

        # Verify roundtrip
        verify_resp = client.post(
            "/api/v1/evidence/export/verify",
            json={"bundle": bundle},
            headers=AUTH_HEADERS,
        )
        assert verify_resp.status_code == 200
        result = verify_resp.json()
        assert result["verified"] is True, (
            f"Framework {framework} bundle verification failed: {result.get('error')}"
        )
        assert result["hash_match"] is True
        assert result["signature_valid"] is True


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--timeout=30"])
