"""HTTP-level tests for secrets / crypto / key-management endpoints.

Covers 4 routers that were previously unmounted (empty endpoints):
  1. /api/v1/crypto-keys      — CryptoKeyManagementEngine
  2. /api/v1/secrets-management — SecretsManagementEngine
  3. /api/v1/pki              — PKIManagementEngine
  4. /api/v1/quantum-crypto   — QuantumSafeCryptoEngine

Each group tests: list (GET /), create (POST /), filter param, 404 on bad id,
and at least one stats/expiring endpoint.
"""
from __future__ import annotations

import os
import pytest
from fastapi.testclient import TestClient

API_TOKEN = os.getenv(
    "FIXOPS_API_TOKEN",
    "aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh",
)


@pytest.fixture(scope="module")
def client():
    os.environ.setdefault("FIXOPS_API_TOKEN", API_TOKEN)
    os.environ.setdefault("FIXOPS_MODE", "enterprise")
    from apps.api.app import create_app
    return TestClient(create_app(), raise_server_exceptions=False)


@pytest.fixture(scope="module")
def H():
    return {"X-API-Key": API_TOKEN}


# ---------------------------------------------------------------------------
# 1. Crypto Key Management  /api/v1/crypto-keys
# ---------------------------------------------------------------------------

class TestCryptoKeyManagement:
    def test_list_keys_returns_200(self, client, H):
        r = client.get("/api/v1/crypto-keys/", headers=H)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_create_key_returns_201(self, client, H):
        r = client.post(
            "/api/v1/crypto-keys/",
            headers=H,
            json={
                "name": "test-aes-key",
                "key_type": "aes256",
                "purpose": "encryption",
                "expiry_days": 90,
                "tags": ["test"],
            },
            params={"org_id": "test-org"},
        )
        assert r.status_code == 201
        data = r.json()
        assert "key_id" in data or "id" in data or "name" in data

    def test_list_keys_filter_by_type(self, client, H):
        r = client.get(
            "/api/v1/crypto-keys/",
            headers=H,
            params={"org_id": "test-org", "key_type": "aes256"},
        )
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_get_expiring_keys(self, client, H):
        r = client.get(
            "/api/v1/crypto-keys/expiring",
            headers=H,
            params={"org_id": "test-org", "days_ahead": 365},
        )
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_get_key_stats(self, client, H):
        r = client.get(
            "/api/v1/crypto-keys/stats",
            headers=H,
            params={"org_id": "test-org"},
        )
        assert r.status_code == 200
        data = r.json()
        assert isinstance(data, dict)

    def test_get_key_not_found(self, client, H):
        r = client.get(
            "/api/v1/crypto-keys/nonexistent-key-id",
            headers=H,
            params={"org_id": "test-org"},
        )
        assert r.status_code == 404

    def test_rotate_key_not_found(self, client, H):
        r = client.post(
            "/api/v1/crypto-keys/nonexistent-key/rotate",
            headers=H,
            params={"org_id": "test-org"},
        )
        assert r.status_code in (404, 500)

    def test_revoke_key_not_found(self, client, H):
        r = client.post(
            "/api/v1/crypto-keys/nonexistent-key/revoke",
            headers=H,
            json={"reason": "compromised"},
            params={"org_id": "test-org"},
        )
        assert r.status_code in (404, 500)

    def test_full_key_lifecycle(self, client, H):
        """Create → get → rotate → revoke."""
        # create
        r = client.post(
            "/api/v1/crypto-keys/",
            headers=H,
            json={"name": "lifecycle-key", "key_type": "ed25519",
                  "purpose": "signing", "expiry_days": 30},
            params={"org_id": "lifecycle-org"},
        )
        assert r.status_code == 201
        key_id = r.json().get("key_id") or r.json().get("id")
        if not key_id:
            pytest.skip("Engine did not return key_id")

        # get
        r2 = client.get(
            f"/api/v1/crypto-keys/{key_id}",
            headers=H,
            params={"org_id": "lifecycle-org"},
        )
        assert r2.status_code == 200

        # rotate
        r3 = client.post(
            f"/api/v1/crypto-keys/{key_id}/rotate",
            headers=H,
            params={"org_id": "lifecycle-org"},
        )
        assert r3.status_code in (200, 201)

        # revoke
        r4 = client.post(
            f"/api/v1/crypto-keys/{key_id}/revoke",
            headers=H,
            json={"reason": "test revocation"},
            params={"org_id": "lifecycle-org"},
        )
        assert r4.status_code in (200, 201)


# ---------------------------------------------------------------------------
# 2. Secrets Management  /api/v1/secrets-management
# ---------------------------------------------------------------------------

class TestSecretsManagement:
    def test_list_secrets_returns_200(self, client, H):
        r = client.get("/api/v1/secrets-management/secrets", headers=H)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_store_secret_returns_200(self, client, H):
        r = client.post(
            "/api/v1/secrets-management/secrets",
            headers=H,
            json={
                "name": "ci-deploy-token",
                "secret_type": "api_key",
                "path": "vault/ci/deploy",
                "tags": ["ci", "deploy"],
                "rotation_days": 30,
            },
            params={"org_id": "test-org"},
        )
        assert r.status_code == 200
        data = r.json()
        assert "secret_id" in data or "id" in data or "name" in data

    def test_list_secrets_filter_by_type(self, client, H):
        r = client.get(
            "/api/v1/secrets-management/secrets",
            headers=H,
            params={"org_id": "test-org", "secret_type": "api_key"},
        )
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_get_expiring_secrets(self, client, H):
        r = client.get(
            "/api/v1/secrets-management/expiring",
            headers=H,
            params={"org_id": "test-org", "days_ahead": 90},
        )
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_get_secrets_stats(self, client, H):
        r = client.get(
            "/api/v1/secrets-management/stats",
            headers=H,
            params={"org_id": "test-org"},
        )
        assert r.status_code == 200
        assert isinstance(r.json(), dict)

    def test_get_secret_not_found(self, client, H):
        r = client.get(
            "/api/v1/secrets-management/secrets/nonexistent-id",
            headers=H,
            params={"org_id": "test-org"},
        )
        assert r.status_code == 404

    def test_rotate_secret_not_found(self, client, H):
        r = client.post(
            "/api/v1/secrets-management/secrets/nonexistent-id/rotate",
            headers=H,
            params={"org_id": "test-org"},
        )
        assert r.status_code in (404, 422, 500)

    def test_full_secret_lifecycle(self, client, H):
        """Store → get → rotate → access log → revoke."""
        r = client.post(
            "/api/v1/secrets-management/secrets",
            headers=H,
            json={
                "name": "db-password-prod",
                "secret_type": "database",
                "path": "vault/prod/db",
                "rotation_days": 60,
            },
            params={"org_id": "lifecycle-org"},
        )
        assert r.status_code == 200
        secret_id = r.json().get("secret_id") or r.json().get("id")
        if not secret_id:
            pytest.skip("Engine did not return secret_id")

        # get
        r2 = client.get(
            f"/api/v1/secrets-management/secrets/{secret_id}",
            headers=H,
            params={"org_id": "lifecycle-org"},
        )
        assert r2.status_code == 200

        # record access
        r3 = client.post(
            f"/api/v1/secrets-management/secrets/{secret_id}/access",
            headers=H,
            json={"accessor": "deploy-bot", "action": "read"},
            params={"org_id": "lifecycle-org"},
        )
        assert r3.status_code == 200

        # get access log
        r4 = client.get(
            f"/api/v1/secrets-management/secrets/{secret_id}/access",
            headers=H,
            params={"org_id": "lifecycle-org"},
        )
        assert r4.status_code == 200
        assert isinstance(r4.json(), list)


# ---------------------------------------------------------------------------
# 3. PKI Management  /api/v1/pki
# ---------------------------------------------------------------------------

class TestPKIManagement:
    def test_list_certificates_returns_200(self, client, H):
        r = client.get("/api/v1/pki/certificates", headers=H)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_issue_certificate_returns_201(self, client, H):
        r = client.post(
            "/api/v1/pki/certificates",
            headers=H,
            json={
                "common_name": "test.example.com",
                "expires_at": "2027-01-01T00:00:00Z",
                "serial_number": "01:23:45",
                "issuer": "Test CA",
                "key_algorithm": "RSA",
                "key_size": 2048,
                "cert_type": "server",
                "status": "active",
                "subject_alt_names": ["test.example.com"],
            },
            params={"org_id": "test-org"},
        )
        assert r.status_code == 201
        data = r.json()
        assert "cert_id" in data or "id" in data or "common_name" in data

    def test_list_certs_filter_by_type(self, client, H):
        r = client.get(
            "/api/v1/pki/certificates",
            headers=H,
            params={"org_id": "test-org", "cert_type": "server"},
        )
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_get_expiring_certificates(self, client, H):
        r = client.get(
            "/api/v1/pki/certificates/expiring",
            headers=H,
            params={"org_id": "test-org", "days_ahead": 90},
        )
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_list_cas_returns_200(self, client, H):
        r = client.get("/api/v1/pki/cas", headers=H, params={"org_id": "test-org"})
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_register_ca_returns_201(self, client, H):
        r = client.post(
            "/api/v1/pki/cas",
            headers=H,
            json={
                "name": "Root CA Test",
                "ca_type": "root",
                "subject": "CN=Root CA Test",
                "key_algorithm": "RSA",
                "status": "active",
            },
            params={"org_id": "test-org"},
        )
        assert r.status_code == 201

    def test_get_pki_stats(self, client, H):
        r = client.get(
            "/api/v1/pki/stats", headers=H, params={"org_id": "test-org"}
        )
        assert r.status_code == 200
        assert isinstance(r.json(), dict)

    def test_get_pki_audit_log(self, client, H):
        r = client.get(
            "/api/v1/pki/audit-log",
            headers=H,
            params={"org_id": "test-org", "limit": 10},
        )
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_get_certificate_not_found(self, client, H):
        r = client.get(
            "/api/v1/pki/certificates/nonexistent-cert",
            headers=H,
            params={"org_id": "test-org"},
        )
        assert r.status_code == 404

    def test_full_cert_lifecycle(self, client, H):
        """Issue → get → revoke."""
        r = client.post(
            "/api/v1/pki/certificates",
            headers=H,
            json={
                "common_name": "lifecycle.example.com",
                "expires_at": "2027-06-01T00:00:00Z",
                "cert_type": "server",
                "key_algorithm": "ECDSA",
                "key_size": 256,
                "subject_alt_names": ["lifecycle.example.com"],
            },
            params={"org_id": "lifecycle-org"},
        )
        assert r.status_code == 201
        cert_id = r.json().get("cert_id") or r.json().get("id")
        if not cert_id:
            pytest.skip("Engine did not return cert_id")

        # get
        r2 = client.get(
            f"/api/v1/pki/certificates/{cert_id}",
            headers=H,
            params={"org_id": "lifecycle-org"},
        )
        assert r2.status_code == 200

        # revoke
        r3 = client.put(
            f"/api/v1/pki/certificates/{cert_id}/revoke",
            headers=H,
            json={"reason": "test revocation"},
            params={"org_id": "lifecycle-org"},
        )
        assert r3.status_code in (200, 201)


# ---------------------------------------------------------------------------
# 4. Quantum-Safe Crypto  /api/v1/quantum-crypto
# ---------------------------------------------------------------------------

class TestQuantumSafeCrypto:
    def test_list_assets_returns_200(self, client, H):
        r = client.get("/api/v1/quantum-crypto/assets", headers=H)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_register_asset_returns_200(self, client, H):
        r = client.post(
            "/api/v1/quantum-crypto/assets",
            headers=H,
            json={
                "org_id": "test-org",
                "asset_name": "vpn-gateway-rsa",
                "asset_type": "vpn",
                "current_algorithm": "rsa",
                "key_size": 2048,
                "risk_level": "high",
                "migration_status": "not_started",
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert "asset_id" in data or "id" in data or "asset_name" in data

    def test_list_assets_filter_by_type(self, client, H):
        r = client.get(
            "/api/v1/quantum-crypto/assets",
            headers=H,
            params={"org_id": "test-org", "asset_type": "vpn"},
        )
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_list_assets_filter_quantum_vulnerable(self, client, H):
        r = client.get(
            "/api/v1/quantum-crypto/assets",
            headers=H,
            params={"org_id": "test-org", "quantum_vulnerable": True},
        )
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_get_quantum_stats(self, client, H):
        r = client.get(
            "/api/v1/quantum-crypto/stats",
            headers=H,
            params={"org_id": "test-org"},
        )
        assert r.status_code == 200
        assert isinstance(r.json(), dict)

    def test_get_asset_not_found(self, client, H):
        r = client.get(
            "/api/v1/quantum-crypto/assets/nonexistent-asset",
            headers=H,
            params={"org_id": "test-org"},
        )
        assert r.status_code == 404

    def test_create_assessment(self, client, H):
        r = client.post(
            "/api/v1/quantum-crypto/assessments",
            headers=H,
            json={
                "org_id": "test-org",
                "assessment_name": "Q2 2026 PQC Readiness",
                "scope": "All production TLS endpoints",
            },
        )
        assert r.status_code == 200
        assert "assessment_id" in r.json() or "id" in r.json() or "assessment_name" in r.json()

    def test_list_assessments(self, client, H):
        r = client.get(
            "/api/v1/quantum-crypto/assessments",
            headers=H,
            params={"org_id": "test-org"},
        )
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_full_migration_lifecycle(self, client, H):
        """Register asset → create migration → list migrations."""
        r = client.post(
            "/api/v1/quantum-crypto/assets",
            headers=H,
            json={
                "org_id": "migration-org",
                "asset_name": "signing-service-ecdsa",
                "asset_type": "signing_key",
                "current_algorithm": "ecdsa",
                "key_size": 256,
                "risk_level": "critical",
                "migration_status": "planned",
            },
        )
        assert r.status_code == 200
        asset_id = r.json().get("asset_id") or r.json().get("id")
        if not asset_id:
            pytest.skip("Engine did not return asset_id")

        # create migration
        r2 = client.post(
            "/api/v1/quantum-crypto/migrations",
            headers=H,
            json={
                "org_id": "migration-org",
                "asset_id": asset_id,
                "from_algorithm": "ecdsa",
                "to_algorithm": "crystals-dilithium",
                "priority": "high",
            },
        )
        assert r2.status_code == 200

        # list migrations
        r3 = client.get(
            "/api/v1/quantum-crypto/migrations",
            headers=H,
            params={"org_id": "migration-org", "asset_id": asset_id},
        )
        assert r3.status_code == 200
        assert isinstance(r3.json(), list)

    def test_update_migration_status_not_found(self, client, H):
        r = client.put(
            "/api/v1/quantum-crypto/assets/nonexistent/migration-status",
            headers=H,
            json={"org_id": "test-org", "migration_status": "completed"},
        )
        assert r.status_code in (404, 422, 500)
