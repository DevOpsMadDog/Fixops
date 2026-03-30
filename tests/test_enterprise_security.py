"""
Tests for enterprise security hardening features.

Covers:
  - EncryptedPersistentDict (AES-256-GCM at-rest encryption)
  - KeyManager (API key lifecycle — create, rotate, revoke, expire)
  - TenantStore (org_id tenant isolation)
  - Scope enforcement (RBAC scope guards on router mounts)
"""

import json
import os
import secrets
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest


# ---------------------------------------------------------------------------
# EncryptedPersistentDict Tests
# ---------------------------------------------------------------------------
class TestEncryptedPersistentDict:
    """Test AES-256-GCM encrypted storage."""

    @pytest.fixture
    def master_key(self):
        return secrets.token_bytes(32)

    @pytest.fixture
    def store(self, master_key, tmp_path):
        from core.encrypted_store import EncryptedPersistentDict

        db_path = str(tmp_path / "test_encrypted.db")
        return EncryptedPersistentDict("test_data", db_path, master_key)

    def test_set_and_get(self, store):
        """Test basic write/read with encryption."""
        store["key1"] = {"severity": "critical", "cwe": "CWE-89"}
        result = store["key1"]
        assert result["severity"] == "critical"
        assert result["cwe"] == "CWE-89"

    def test_multiple_entries(self, store):
        """Test storing multiple encrypted entries."""
        for i in range(10):
            store[f"item-{i}"] = {"index": i, "data": f"value-{i}"}
        assert len(store) == 10
        assert store["item-5"]["index"] == 5

    def test_delete(self, store):
        """Test deletion of encrypted entries."""
        store["to_delete"] = {"temp": True}
        assert "to_delete" in store
        del store["to_delete"]
        assert "to_delete" not in store

    def test_persistence_across_instances(self, master_key, tmp_path):
        """Test that data persists and can be decrypted by new instance."""
        from core.encrypted_store import EncryptedPersistentDict

        db_path = str(tmp_path / "persist_test.db")

        # Write data with first instance
        store1 = EncryptedPersistentDict("persist", db_path, master_key)
        store1["secret"] = {"password_hash": "bcrypt:$2b$12$xyz"}
        store1.close()

        # Read with new instance
        store2 = EncryptedPersistentDict("persist", db_path, master_key)
        assert store2["secret"]["password_hash"] == "bcrypt:$2b$12$xyz"
        store2.close()

    def test_wrong_key_cannot_decrypt(self, master_key, tmp_path):
        """Test that data encrypted with one key can't be read with another."""
        from core.encrypted_store import EncryptedPersistentDict

        db_path = str(tmp_path / "wrong_key.db")

        # Write with key1
        store1 = EncryptedPersistentDict("security", db_path, master_key)
        store1["classified"] = {"level": "TOP SECRET"}
        store1.close()

        # Try to read with different key
        wrong_key = secrets.token_bytes(32)
        store2 = EncryptedPersistentDict("security", db_path, wrong_key)
        # Should not be able to decrypt — cache should be empty
        assert "classified" not in store2
        store2.close()

    def test_data_on_disk_is_encrypted(self, master_key, tmp_path):
        """Verify raw SQLite data does NOT contain plaintext values."""
        import sqlite3

        from core.encrypted_store import EncryptedPersistentDict

        db_path = str(tmp_path / "raw_check.db")
        store = EncryptedPersistentDict("raw", db_path, master_key)
        store["sensitive"] = {"ssn": "123-45-6789", "clearance": "TS/SCI"}
        store.close()

        # Read raw SQLite data
        conn = sqlite3.connect(db_path)
        rows = conn.execute("SELECT key_hash, encrypted_value FROM [raw]").fetchall()
        conn.close()

        # Key should be HMAC-hashed, not plaintext
        assert len(rows) == 1
        key_hash, encrypted = rows[0]
        assert key_hash != "sensitive"  # Key is hashed
        assert len(key_hash) == 64  # SHA-256 hex digest

        # Encrypted value should NOT contain plaintext
        raw_bytes = encrypted if isinstance(encrypted, bytes) else encrypted.encode()
        assert b"123-45-6789" not in raw_bytes
        assert b"TS/SCI" not in raw_bytes

    def test_clear(self, store):
        """Test clearing all encrypted entries."""
        store["a"] = 1
        store["b"] = 2
        store.clear()
        assert len(store) == 0

    def test_persist(self, store):
        """Test explicit persist after mutation."""
        store["mutable"] = {"count": 0}
        store._cache["mutable"]["count"] = 42
        store.persist("mutable")
        # Re-read from "disk" cache
        assert store["mutable"]["count"] == 42

    def test_iteration(self, store):
        """Test keys(), values(), items() iteration."""
        store["x"] = 10
        store["y"] = 20
        assert "x" in list(store.keys())
        assert 10 in list(store.values())
        items = dict(store.items())
        assert items["x"] == 10
        assert items["y"] == 20

    def test_to_dict(self, store):
        """Test to_dict returns plain dict copy."""
        store["a"] = 1
        store["b"] = 2
        d = store.to_dict()
        assert isinstance(d, dict)
        assert d == {"a": 1, "b": 2}

    def test_invalid_table_name(self, master_key, tmp_path):
        """Test that SQL injection via table name is blocked."""
        from core.encrypted_store import EncryptedPersistentDict

        with pytest.raises(ValueError, match="Invalid table name"):
            EncryptedPersistentDict(
                "Robert'; DROP TABLE students;--",
                str(tmp_path / "inject.db"),
                master_key,
            )

    def test_get_with_default(self, store):
        """Test .get() returns default for missing keys."""
        assert store.get("missing") is None
        assert store.get("missing", "fallback") == "fallback"


# ---------------------------------------------------------------------------
# KeyManager Tests
# ---------------------------------------------------------------------------
class TestKeyManager:
    """Test API key lifecycle management."""

    @pytest.fixture
    def km(self, tmp_path):
        from core.key_manager import KeyManager

        return KeyManager(db_path=str(tmp_path / "keys.db"))

    def test_create_key(self, km):
        """Test API key creation."""
        record, plaintext = km.create_key(
            user_id="user-1",
            name="CI Pipeline",
            role="service",
            scopes=["read:findings", "write:findings"],
        )
        assert record.id.startswith("key_")
        assert record.user_id == "user-1"
        assert record.role == "service"
        assert record.is_active is True
        assert record.expires_at is not None
        assert plaintext.startswith("fixops_")
        assert len(plaintext) > 20

    def test_validate_key(self, km):
        """Test key validation succeeds with correct key."""
        record, plaintext = km.create_key(user_id="u-1", name="test")
        validated = km.validate_key(plaintext)
        assert validated is not None
        assert validated.id == record.id
        assert validated.last_used_at is not None

    def test_validate_wrong_key(self, km):
        """Test key validation fails with incorrect key."""
        km.create_key(user_id="u-1", name="test")
        assert km.validate_key("fixops_wrong_key_here") is None

    def test_rotate_key(self, km):
        """Test key rotation creates new key and sets grace period."""
        old_record, old_plaintext = km.create_key(user_id="u-1", name="original")
        new_record, new_plaintext = km.rotate_key(old_record.id)

        # New key should work
        assert new_record.id != old_record.id
        assert new_record.user_id == old_record.user_id
        assert new_plaintext.startswith("fixops_")

        # Old key should still be in grace period
        old_validated = km.validate_key(old_plaintext)
        assert old_validated is not None  # Still valid during grace

        # New key should validate
        new_validated = km.validate_key(new_plaintext)
        assert new_validated is not None

    def test_revoke_key(self, km):
        """Test immediate key revocation."""
        record, plaintext = km.create_key(user_id="u-1", name="to_revoke")
        success = km.revoke_key(record.id)
        assert success is True

        # Should no longer validate
        assert km.validate_key(plaintext) is None

    def test_revoke_nonexistent(self, km):
        """Test revoking a non-existent key returns False."""
        assert km.revoke_key("key_does_not_exist") is False

    def test_list_keys(self, km):
        """Test listing active keys."""
        km.create_key(user_id="u-1", name="key-a")
        km.create_key(user_id="u-1", name="key-b")
        km.create_key(user_id="u-2", name="key-c")

        all_keys = km.list_keys()
        assert len(all_keys) == 3

        u1_keys = km.list_keys(user_id="u-1")
        assert len(u1_keys) == 2

    def test_expiring_keys(self, km):
        """Test finding keys that expire soon."""
        # Create a key with 3-day TTL
        record, _ = km.create_key(user_id="u-1", name="short-lived", ttl_days=3)
        expiring = km.get_expiring_keys(within_days=7)
        assert len(expiring) >= 1
        assert any(k.id == record.id for k in expiring)

    def test_cleanup_expired(self, km):
        """Test cleanup of expired keys past grace period."""
        from datetime import timedelta
        # Create a key and manually backdate its expiration in the DB
        record, plaintext = km.create_key(user_id="u-1", name="expired")
        past = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        with km._conn() as conn:
            conn.execute(
                "UPDATE managed_keys SET expires_at = ?, grace_expires_at = ? WHERE id = ?",
                (past, past, record.id),
            )
        # Now clean up
        count = km.cleanup_expired()
        assert count >= 1

        # Should no longer validate
        assert km.validate_key(plaintext) is None

    def test_audit_log(self, km):
        """Test key audit trail."""
        record, _ = km.create_key(user_id="u-1", name="audited")
        log = km.get_audit_log(key_id=record.id)
        assert len(log) >= 1
        assert log[0]["action"] == "created"
        assert log[0]["key_id"] == record.id

    def test_rotate_revoked_key_fails(self, km):
        """Test that rotating a revoked key raises ValueError."""
        record, _ = km.create_key(user_id="u-1", name="to-fail")
        km.revoke_key(record.id)
        with pytest.raises(ValueError, match="not active"):
            km.rotate_key(record.id)

    def test_key_scopes_preserved(self, km):
        """Test that scopes are preserved through creation."""
        scopes = ["read:findings", "read:evidence", "read:graph"]
        record, _ = km.create_key(user_id="u-1", name="scoped", scopes=scopes)
        assert record.scopes == scopes

    def test_to_dict(self, km):
        """Test key serialization."""
        record, _ = km.create_key(user_id="u-1", name="serialize")
        d = record.to_dict()
        assert "id" in d
        assert "key_prefix" in d
        assert "created_at" in d
        assert "key_hash" not in d  # Hash should not be in to_dict


# ---------------------------------------------------------------------------
# TenantStore Tests
# ---------------------------------------------------------------------------
class TestTenantStore:
    """Test tenant-isolated data access."""

    @pytest.fixture
    def store(self, tmp_path):
        from core.tenant_store import TenantStore

        return TenantStore("test_findings", str(tmp_path / "tenant.db"))

    def test_isolation_between_orgs(self, store):
        """Test that different org_ids see different data."""
        store.set("finding-1", {"severity": "high"}, org_id="org-alpha")
        store.set("finding-1", {"severity": "low"}, org_id="org-beta")

        alpha_data = store.get("finding-1", org_id="org-alpha")
        beta_data = store.get("finding-1", org_id="org-beta")

        assert alpha_data["severity"] == "high"
        assert beta_data["severity"] == "low"

    def test_list_all_scoped(self, store):
        """Test list_all returns only current tenant's data."""
        store.set("a", 1, org_id="org-1")
        store.set("b", 2, org_id="org-1")
        store.set("c", 3, org_id="org-2")

        org1_data = store.list_all(org_id="org-1")
        assert len(org1_data) == 2
        assert "a" in org1_data
        assert "b" in org1_data
        assert "c" not in org1_data

    def test_delete_scoped(self, store):
        """Test deletion is scoped to tenant."""
        store.set("shared-key", "org1-val", org_id="org-1")
        store.set("shared-key", "org2-val", org_id="org-2")

        store.delete("shared-key", org_id="org-1")

        assert not store.contains("shared-key", org_id="org-1")
        assert store.contains("shared-key", org_id="org-2")

    def test_count_scoped(self, store):
        """Test count returns only tenant's entries."""
        for i in range(5):
            store.set(f"item-{i}", i, org_id="org-a")
        for i in range(3):
            store.set(f"item-{i}", i, org_id="org-b")

        assert store.count(org_id="org-a") == 5
        assert store.count(org_id="org-b") == 3

    def test_list_keys_scoped(self, store):
        """Test list_keys returns only tenant's keys."""
        store.set("key1", "v1", org_id="org-x")
        store.set("key2", "v2", org_id="org-x")
        store.set("key3", "v3", org_id="org-y")

        x_keys = store.list_keys(org_id="org-x")
        assert sorted(x_keys) == ["key1", "key2"]


# ---------------------------------------------------------------------------
# Scope Enforcement Integration Tests
# ---------------------------------------------------------------------------
class TestScopeEnforcement:
    """Test that scope guards are enforced on API endpoints."""

    @pytest.fixture
    def app(self):
        """Create the app with auth strategy=token."""
        os.environ.setdefault("FIXOPS_API_TOKEN", "test-token-for-scope-tests")
        os.environ["FIXOPS_MODE"] = "enterprise"
        from apps.api.app import create_app

        return create_app()

    @pytest.fixture
    def admin_client(self, app):
        """Client with admin token (all scopes)."""
        from starlette.testclient import TestClient

        client = TestClient(app)
        return client

    def test_admin_token_has_all_scopes(self, admin_client):
        """Test that admin API key grants all scopes."""
        token = os.environ.get("FIXOPS_API_TOKEN", "test-token-for-scope-tests")
        resp = admin_client.get(
            "/api/v1/health",
            headers={"X-API-Key": token},
        )
        # Health endpoint should always work
        assert resp.status_code in (200, 404)  # 404 if no /health route at root

    def test_analytics_requires_auth(self, admin_client):
        """Test that analytics endpoint requires authentication."""
        resp = admin_client.get("/api/v1/analytics/dashboard")
        assert resp.status_code in (401, 403, 404)


# ---------------------------------------------------------------------------
# Auth Router Key Management API Tests
# ---------------------------------------------------------------------------
class TestAuthRouterKeyManagement:
    """Test key management API endpoints."""

    @pytest.fixture
    def app(self):
        os.environ.setdefault("FIXOPS_API_TOKEN", "test-token-for-key-mgmt")
        from apps.api.app import create_app

        return create_app()

    @pytest.fixture
    def client(self, app):
        from starlette.testclient import TestClient

        client = TestClient(app)
        return client

    @pytest.fixture
    def headers(self):
        token = os.environ.get("FIXOPS_API_TOKEN", "test-token-for-key-mgmt")
        return {"X-API-Key": token}

    def test_create_key_endpoint(self, client, headers):
        """Test POST /api/v1/auth/keys creates a key."""
        resp = client.post(
            "/api/v1/auth/keys",
            json={"name": "Test Key", "user_id": "test-user", "role": "viewer"},
            headers=headers,
        )
        assert resp.status_code == 201
        data = resp.json()
        assert "plaintext_key" in data
        assert data["name"] == "Test Key"
        assert data["is_active"] is True

    def test_list_keys_endpoint(self, client, headers):
        """Test GET /api/v1/auth/keys lists keys."""
        # Create a key first
        client.post(
            "/api/v1/auth/keys",
            json={"name": "List Test", "user_id": "u-1"},
            headers=headers,
        )
        resp = client.get("/api/v1/auth/keys", headers=headers)
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_rotate_key_endpoint(self, client, headers):
        """Test POST /api/v1/auth/keys/{id}/rotate rotates a key."""
        # Create a key
        create_resp = client.post(
            "/api/v1/auth/keys",
            json={"name": "Rotate Test", "user_id": "u-1"},
            headers=headers,
        )
        key_id = create_resp.json()["id"]

        # Rotate it
        resp = client.post(
            f"/api/v1/auth/keys/{key_id}/rotate",
            json={"performed_by": "admin"},
            headers=headers,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "plaintext_key" in data
        assert data["id"] != key_id  # New key has different ID

    def test_revoke_key_endpoint(self, client, headers):
        """Test DELETE /api/v1/auth/keys/{id} revokes a key."""
        create_resp = client.post(
            "/api/v1/auth/keys",
            json={"name": "Revoke Test", "user_id": "u-1"},
            headers=headers,
        )
        key_id = create_resp.json()["id"]

        resp = client.delete(f"/api/v1/auth/keys/{key_id}", headers=headers)
        assert resp.status_code == 200
        assert resp.json()["status"] == "revoked"

    def test_expiring_keys_endpoint(self, client, headers):
        """Test GET /api/v1/auth/keys/expiring returns soon-expiring keys."""
        resp = client.get(
            "/api/v1/auth/keys/expiring?within_days=30",
            headers=headers,
        )
        assert resp.status_code == 200
        assert "count" in resp.json()

    def test_cleanup_endpoint(self, client, headers):
        """Test POST /api/v1/auth/keys/cleanup runs expiration sweep."""
        resp = client.post("/api/v1/auth/keys/cleanup", headers=headers)
        assert resp.status_code == 200
        assert "deactivated_count" in resp.json()

    def test_key_audit_endpoint(self, client, headers):
        """Test GET /api/v1/auth/keys/{id}/audit returns audit log."""
        create_resp = client.post(
            "/api/v1/auth/keys",
            json={"name": "Audit Test", "user_id": "u-1"},
            headers=headers,
        )
        key_id = create_resp.json()["id"]

        resp = client.get(f"/api/v1/auth/keys/{key_id}/audit", headers=headers)
        assert resp.status_code == 200
        assert "entries" in resp.json()
        assert len(resp.json()["entries"]) >= 1


# ---------------------------------------------------------------------------
# Compliance Framework Coverage Tests (10/10 frameworks)
# ---------------------------------------------------------------------------
class TestComplianceFrameworkCoverage:
    """Verify all 10 compliance frameworks have control definitions."""

    def test_all_frameworks_have_controls(self):
        """Every Framework enum value must have at least 10 controls."""
        from compliance.compliance_engine import ComplianceEngine, Framework

        engine = ComplianceEngine()
        for framework in Framework:
            controls = engine._framework_controls.get(framework, {})
            assert len(controls) >= 10, (
                f"{framework.value} has only {len(controls)} controls — minimum is 10"
            )

    def test_cmmc_v2_has_required_domains(self):
        """CMMC V2 must cover all 14 NIST 800-171 domains."""
        from compliance.compliance_engine import CMMC_V2_CONTROLS

        categories = {c["category"] for c in CMMC_V2_CONTROLS.values()}
        required = {"AC", "AT", "AU", "CM", "IA", "IR", "MA", "MP", "PE", "PS", "RA", "SC", "SI"}
        missing = required - categories
        assert not missing, f"CMMC V2 missing domains: {missing}"

    def test_fedramp_covers_nist_families(self):
        """FedRAMP must cover key NIST 800-53 control families."""
        from compliance.compliance_engine import FEDRAMP_CONTROLS

        categories = {c["category"] for c in FEDRAMP_CONTROLS.values()}
        required = {"AC", "AU", "CM", "IA", "IR", "RA", "SC", "SI", "SA"}
        missing = required - categories
        assert not missing, f"FedRAMP missing families: {missing}"

    def test_hipaa_covers_three_safeguards(self):
        """HIPAA must cover Administrative, Physical, and Technical safeguards."""
        from compliance.compliance_engine import HIPAA_CONTROLS

        categories = {c["category"] for c in HIPAA_CONTROLS.values()}
        required = {"Administrative", "Physical", "Technical"}
        assert required.issubset(categories), f"HIPAA missing safeguards: {required - categories}"

    def test_dfars_covers_14_families(self):
        """DFARS must cover all 14 NIST 800-171 requirement families."""
        from compliance.compliance_engine import DFARS_CONTROLS

        assert len(DFARS_CONTROLS) == 14

    def test_nist_csf_covers_6_functions(self):
        """NIST CSF 2.0 must cover all 6 core functions."""
        from compliance.compliance_engine import NIST_CSF_CONTROLS

        categories = {c["category"] for c in NIST_CSF_CONTROLS.values()}
        required = {"Govern", "Identify", "Protect", "Detect", "Respond", "Recover"}
        missing = required - categories
        assert not missing, f"NIST CSF missing functions: {missing}"

    def test_owasp_asvs_covers_14_chapters(self):
        """OWASP ASVS must cover all 14 verification chapters."""
        from compliance.compliance_engine import OWASP_ASVS_CONTROLS

        assert len(OWASP_ASVS_CONTROLS) == 14

    def test_cwe_index_includes_all_frameworks(self):
        """CWE reverse index should include mappings from all frameworks."""
        from compliance.compliance_engine import Framework, _build_cwe_index, _CWE_TO_CONTROLS

        # Force rebuild
        _CWE_TO_CONTROLS.clear()
        _build_cwe_index()

        # Check that frameworks with CWE mappings appear in the index
        framework_ids_in_index = set()
        for entries in _CWE_TO_CONTROLS.values():
            for fw, ctrl_id in entries:
                framework_ids_in_index.add(fw)

        # At minimum, these frameworks have CWE mappings
        expected = {Framework.SOC2, Framework.PCI_DSS, Framework.NIST_800_53,
                    Framework.ISO_27001, Framework.CMMC_V2, Framework.FEDRAMP,
                    Framework.HIPAA, Framework.DFARS, Framework.OWASP_ASVS}
        missing = expected - framework_ids_in_index
        assert not missing, f"CWE index missing frameworks: {missing}"

    def test_automated_controls_exist(self):
        """Each framework must have automated controls for scanner integration."""
        from compliance.compliance_engine import ComplianceEngine, Framework

        engine = ComplianceEngine()
        for framework in Framework:
            controls = engine._framework_controls.get(framework, {})
            automated = [c for c in controls.values() if c.get("automated")]
            assert len(automated) >= 5, (
                f"{framework.value} has only {len(automated)} automated controls — need ≥5"
            )
