"""Tests for the signed compliance evidence export endpoint (DEMO-011).

Verifies:
1. /api/v1/evidence/export returns signed compliance bundles
2. RSA-SHA256 signature is generated and verifiable
3. SOC2, PCI-DSS, HIPAA control mappings are correct
4. /api/v1/evidence/export/verify validates signatures
5. /api/v1/evidence/export/status returns subsystem health
6. Content hash integrity is maintained

Pillar: V10 — CTEM Full Loop with Cryptographic Proof
"""

import base64
import os
import sys
from pathlib import Path

import pytest

# Set API token before importing the app
os.environ.setdefault(
    "FIXOPS_API_TOKEN",
    "aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh",
)
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
# /api/v1/evidence/export — SOC2 signed bundle
# ---------------------------------------------------------------------------


class TestEvidenceExportSOC2:
    """Tests for SOC2 compliance export."""

    def test_export_soc2_returns_200(self, client):
        resp = client.post(
            "/api/v1/evidence/export",
            json={"framework": "SOC2", "sign": True},
            headers=AUTH_HEADERS,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["framework"] == "SOC2"
        assert data["bundle_id"].startswith("EVB-")
        assert "posture" in data
        assert "controls" in data
        assert "gaps" in data
        assert "summary" in data

    def test_export_soc2_is_signed(self, client):
        resp = client.post(
            "/api/v1/evidence/export",
            json={"framework": "SOC2", "sign": True},
            headers=AUTH_HEADERS,
        )
        data = resp.json()
        assert data["signed"] is True
        assert data["signature"] is not None
        assert data["key_fingerprint"] is not None
        assert data["signature_algorithm"] == "RSA-SHA256 (PKCS1v15)"

    def test_export_soc2_has_controls(self, client):
        resp = client.post(
            "/api/v1/evidence/export",
            json={"framework": "SOC2", "sign": True},
            headers=AUTH_HEADERS,
        )
        data = resp.json()
        controls = data["controls"]
        assert len(controls) >= 10
        control_ids = {c["control_id"] for c in controls}
        assert any(c.startswith("CC6") for c in control_ids), "Missing CC6"
        assert any(c.startswith("CC7") for c in control_ids), "Missing CC7"

    def test_export_soc2_posture(self, client):
        resp = client.post(
            "/api/v1/evidence/export",
            json={"framework": "SOC2"},
            headers=AUTH_HEADERS,
        )
        data = resp.json()
        posture = data["posture"]
        assert "total_controls" in posture
        assert "overall_score" in posture
        assert posture["total_controls"] > 0

    def test_export_soc2_content_hash(self, client):
        resp = client.post(
            "/api/v1/evidence/export",
            json={"framework": "SOC2", "sign": True},
            headers=AUTH_HEADERS,
        )
        data = resp.json()
        assert data["content_hash"].startswith("sha256:")
        assert len(data["content_hash"]) > 10

    def test_export_soc2_metadata(self, client):
        resp = client.post(
            "/api/v1/evidence/export",
            json={"framework": "SOC2", "period_days": 30},
            headers=AUTH_HEADERS,
        )
        data = resp.json()
        metadata = data["metadata"]
        assert metadata["platform"] == "ALdeci CTEM+"
        assert metadata["retention_policy"] == "7-year WORM"
        assert metadata["assessment_period"]["days"] == 30


# ---------------------------------------------------------------------------
# /api/v1/evidence/export — PCI-DSS
# ---------------------------------------------------------------------------


class TestEvidenceExportPCIDSS:

    def test_export_pcidss_returns_200(self, client):
        resp = client.post(
            "/api/v1/evidence/export",
            json={"framework": "PCI-DSS"},
            headers=AUTH_HEADERS,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["framework"] == "PCI-DSS"

    def test_export_pcidss_has_requirements(self, client):
        resp = client.post(
            "/api/v1/evidence/export",
            json={"framework": "PCI-DSS", "sign": True},
            headers=AUTH_HEADERS,
        )
        data = resp.json()
        controls = data["controls"]
        assert len(controls) >= 10


# ---------------------------------------------------------------------------
# /api/v1/evidence/export — HIPAA
# ---------------------------------------------------------------------------


class TestEvidenceExportHIPAA:

    def test_export_hipaa_returns_200(self, client):
        resp = client.post(
            "/api/v1/evidence/export",
            json={"framework": "HIPAA"},
            headers=AUTH_HEADERS,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["framework"] == "HIPAA"

    def test_export_hipaa_has_controls(self, client):
        resp = client.post(
            "/api/v1/evidence/export",
            json={"framework": "HIPAA"},
            headers=AUTH_HEADERS,
        )
        data = resp.json()
        controls = data["controls"]
        assert len(controls) >= 5
        categories = {c.get("category") for c in controls}
        assert len(categories) >= 2


# ---------------------------------------------------------------------------
# /api/v1/evidence/export/verify — Signature verification
# ---------------------------------------------------------------------------


class TestEvidenceExportVerify:

    def test_verify_valid_bundle(self, client):
        """Verify a valid signed bundle returns verified=True."""
        export_resp = client.post(
            "/api/v1/evidence/export",
            json={"framework": "SOC2", "sign": True},
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
        assert result["hash_match"] is True
        assert result["signature_valid"] is True
        assert result["error"] is None

    def test_verify_unsigned_bundle_fails(self, client):
        export_resp = client.post(
            "/api/v1/evidence/export",
            json={"framework": "SOC2", "sign": False},
            headers=AUTH_HEADERS,
        )
        bundle = export_resp.json()

        verify_resp = client.post(
            "/api/v1/evidence/export/verify",
            json={"bundle": bundle},
            headers=AUTH_HEADERS,
        )
        result = verify_resp.json()
        assert result["verified"] is False
        assert "not signed" in result.get("error", "").lower()

    def test_verify_tampered_bundle_fails(self, client):
        export_resp = client.post(
            "/api/v1/evidence/export",
            json={"framework": "SOC2", "sign": True},
            headers=AUTH_HEADERS,
        )
        bundle = export_resp.json()
        bundle["posture"]["overall_score"] = 999.99

        verify_resp = client.post(
            "/api/v1/evidence/export/verify",
            json={"bundle": bundle},
            headers=AUTH_HEADERS,
        )
        result = verify_resp.json()
        assert result["verified"] is False


# ---------------------------------------------------------------------------
# /api/v1/evidence/export/status — Subsystem health
# ---------------------------------------------------------------------------


class TestEvidenceExportStatus:

    def test_export_status_returns_200(self, client):
        resp = client.get(
            "/api/v1/evidence/export/status",
            headers=AUTH_HEADERS,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "operational"
        assert "supported_frameworks" in data
        assert "SOC2" in data["supported_frameworks"]


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


class TestExportInputValidation:

    def test_invalid_framework_rejected(self, client):
        resp = client.post(
            "/api/v1/evidence/export",
            json={"framework": "INVALID_FRAMEWORK"},
            headers=AUTH_HEADERS,
        )
        assert resp.status_code == 422

    def test_default_framework_is_soc2(self, client):
        resp = client.post(
            "/api/v1/evidence/export",
            json={},
            headers=AUTH_HEADERS,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["framework"] == "SOC2"

    def test_period_days_too_low(self, client):
        resp = client.post(
            "/api/v1/evidence/export",
            json={"framework": "SOC2", "period_days": 0},
            headers=AUTH_HEADERS,
        )
        assert resp.status_code == 422

    def test_period_days_too_high(self, client):
        resp = client.post(
            "/api/v1/evidence/export",
            json={"framework": "SOC2", "period_days": 366},
            headers=AUTH_HEADERS,
        )
        # 422 for validation error, 429 if rate-limited (rapid test sequences)
        assert resp.status_code in (422, 429)


# ---------------------------------------------------------------------------
# Crypto module direct tests
# ---------------------------------------------------------------------------


class TestCryptoRSASHA256:
    """Direct tests for the crypto.py RSA-SHA256 implementation."""

    def test_key_generation(self):
        from core.crypto import RSAKeyManager
        km = RSAKeyManager(key_size=2048)
        assert km.private_key is not None
        assert km.public_key is not None
        assert km.metadata.algorithm == "RSA-SHA256"
        assert km.metadata.key_size == 2048

    def test_sign_and_verify(self):
        from core.crypto import RSAKeyManager, RSASigner, RSAVerifier
        km = RSAKeyManager(key_size=2048)
        signer = RSASigner(km)
        verifier = RSAVerifier(km)

        data = b"test evidence bundle content"
        signature, fingerprint = signer.sign(data)

        assert len(signature) > 0
        assert len(fingerprint) > 0
        assert verifier.verify(data, signature, fingerprint)

    def test_sign_base64(self):
        from core.crypto import RSAKeyManager, RSASigner
        km = RSAKeyManager(key_size=2048)
        signer = RSASigner(km)

        data = b"compliance evidence data"
        sig_b64, fingerprint = signer.sign_base64(data)

        decoded = base64.b64decode(sig_b64)
        assert len(decoded) > 0

    def test_verify_tampered_data_fails(self):
        from core.crypto import RSAKeyManager, RSASigner, RSAVerifier
        km = RSAKeyManager(key_size=2048)
        signer = RSASigner(km)
        verifier = RSAVerifier(km)

        data = b"original evidence"
        signature, fingerprint = signer.sign(data)

        tampered = b"tampered evidence"
        assert not verifier.verify(tampered, signature, fingerprint)

    def test_fingerprint_mismatch_fails(self):
        from core.crypto import RSAKeyManager, RSASigner, RSAVerifier
        km = RSAKeyManager(key_size=2048)
        signer = RSASigner(km)
        verifier = RSAVerifier(km)

        data = b"test data"
        signature, _fingerprint = signer.sign(data)

        assert not verifier.verify(data, signature, "wrong-fingerprint")

    def test_key_metadata(self):
        from core.crypto import RSAKeyManager
        km = RSAKeyManager(key_size=4096, key_id="test-key-001")
        meta = km.metadata

        assert meta.key_id == "test-key-001"
        assert meta.algorithm == "RSA-SHA256"
        assert meta.key_size == 4096
        assert len(meta.fingerprint) == 64  # SHA-256 hex
        assert meta.public_key_pem.startswith("-----BEGIN PUBLIC KEY-----")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--timeout=30"])
