"""
Comprehensive tests for QuantumSafeCryptoEngine.

Covers:
- register_asset: valid, invalid asset_type, invalid algorithm, quantum_vulnerable auto-set,
                  recommended_algorithm mapping, migration_status validation
- list_assets: all, filtered by type, quantum_vulnerable, migration_status, org isolation
- get_asset: found, not found, org isolation
- update_migration_status: valid, invalid status, completed sets migrated_at, org isolation
- create_assessment: valid, status defaults to planned
- complete_assessment: readiness score calculation, zero total, status=completed
- list_assessments: all, filtered by status, org isolation
- create_migration: valid, invalid priority, status defaults to planned
- list_migrations: all, filtered by asset_id, status, priority, org isolation
- get_quantum_stats: totals, progress_pct, critical_vulnerable, by_asset_type,
                     by_migration_status, by_current_algorithm
- Multi-tenant isolation throughout
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("FIXOPS_MODE", "dev")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")

from core.quantum_safe_crypto_engine import QuantumSafeCryptoEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "qsc.db")
    return QuantumSafeCryptoEngine(db_path=db)


ORG = "org-qsc-test"
ORG2 = "org-qsc-other"


def _asset(overrides=None):
    base = {
        "asset_name": "prod-tls-cert",
        "asset_type": "tls_certificate",
        "current_algorithm": "rsa",
        "key_size": 2048,
        "risk_level": "high",
    }
    if overrides:
        base.update(overrides)
    return base


def _assessment(overrides=None):
    base = {
        "assessment_name": "Q1 2026 Quantum Assessment",
        "scope": "All TLS certificates",
    }
    if overrides:
        base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# register_asset
# ---------------------------------------------------------------------------

class TestRegisterAsset:
    def test_returns_dict_with_id(self, engine):
        result = engine.register_asset(ORG, _asset())
        assert "id" in result
        assert len(result["id"]) == 36

    def test_rsa_is_quantum_vulnerable(self, engine):
        result = engine.register_asset(ORG, _asset({"current_algorithm": "rsa"}))
        assert result["quantum_vulnerable"] is True

    def test_ecdsa_is_quantum_vulnerable(self, engine):
        result = engine.register_asset(ORG, _asset({"current_algorithm": "ecdsa"}))
        assert result["quantum_vulnerable"] is True

    def test_dh_is_quantum_vulnerable(self, engine):
        result = engine.register_asset(ORG, _asset({"current_algorithm": "dh"}))
        assert result["quantum_vulnerable"] is True

    def test_aes_not_quantum_vulnerable(self, engine):
        result = engine.register_asset(ORG, _asset({"current_algorithm": "aes"}))
        assert result["quantum_vulnerable"] is False

    def test_sha256_not_quantum_vulnerable(self, engine):
        result = engine.register_asset(ORG, _asset({"current_algorithm": "sha256"}))
        assert result["quantum_vulnerable"] is False

    def test_recommended_algorithm_rsa(self, engine):
        result = engine.register_asset(ORG, _asset({"current_algorithm": "rsa"}))
        assert result["recommended_algorithm"] == "CRYSTALS-Dilithium"

    def test_recommended_algorithm_ecdsa(self, engine):
        result = engine.register_asset(ORG, _asset({"current_algorithm": "ecdsa"}))
        assert result["recommended_algorithm"] == "CRYSTALS-Dilithium"

    def test_recommended_algorithm_dh(self, engine):
        result = engine.register_asset(ORG, _asset({"current_algorithm": "dh"}))
        assert result["recommended_algorithm"] == "CRYSTALS-Kyber"

    def test_recommended_algorithm_3des(self, engine):
        result = engine.register_asset(ORG, _asset({"current_algorithm": "3des"}))
        assert result["recommended_algorithm"] == "AES-256"

    def test_recommended_algorithm_sha1(self, engine):
        result = engine.register_asset(ORG, _asset({"current_algorithm": "sha1"}))
        assert result["recommended_algorithm"] == "SHA-384"

    def test_migration_status_default_not_started(self, engine):
        result = engine.register_asset(ORG, _asset())
        assert result["migration_status"] == "not_started"

    def test_invalid_asset_type_raises(self, engine):
        with pytest.raises(ValueError, match="Invalid asset_type"):
            engine.register_asset(ORG, _asset({"asset_type": "unknown_type"}))

    def test_invalid_algorithm_raises(self, engine):
        with pytest.raises(ValueError, match="Invalid current_algorithm"):
            engine.register_asset(ORG, _asset({"current_algorithm": "quantum-rsa-9999"}))

    def test_invalid_migration_status_raises(self, engine):
        with pytest.raises(ValueError, match="Invalid migration_status"):
            engine.register_asset(ORG, _asset({"migration_status": "launched"}))

    def test_all_valid_asset_types(self, engine):
        for at in ("tls_certificate", "vpn", "signing_key", "encryption_key",
                   "code_signing", "database_encryption", "api_key", "ssh_key"):
            result = engine.register_asset(ORG, _asset({"asset_type": at,
                                                          "asset_name": f"asset-{at}"}))
            assert result["asset_type"] == at


# ---------------------------------------------------------------------------
# list_assets
# ---------------------------------------------------------------------------

class TestListAssets:
    def test_list_returns_registered(self, engine):
        engine.register_asset(ORG, _asset())
        results = engine.list_assets(ORG)
        assert len(results) >= 1

    def test_filter_by_asset_type(self, engine):
        engine.register_asset(ORG, _asset({"asset_type": "vpn"}))
        engine.register_asset(ORG, _asset({"asset_name": "k", "asset_type": "ssh_key"}))
        results = engine.list_assets(ORG, asset_type="vpn")
        assert all(r["asset_type"] == "vpn" for r in results)

    def test_filter_by_quantum_vulnerable_true(self, engine):
        engine.register_asset(ORG, _asset({"current_algorithm": "rsa"}))
        engine.register_asset(ORG, _asset({"asset_name": "a2", "current_algorithm": "aes"}))
        results = engine.list_assets(ORG, quantum_vulnerable=True)
        assert all(r["quantum_vulnerable"] is True for r in results)

    def test_filter_by_quantum_vulnerable_false(self, engine):
        engine.register_asset(ORG, _asset({"current_algorithm": "rsa"}))
        engine.register_asset(ORG, _asset({"asset_name": "a2", "current_algorithm": "aes"}))
        results = engine.list_assets(ORG, quantum_vulnerable=False)
        assert all(r["quantum_vulnerable"] is False for r in results)

    def test_filter_by_migration_status(self, engine):
        engine.register_asset(ORG, _asset({"migration_status": "planned"}))
        engine.register_asset(ORG, _asset({"asset_name": "a2", "migration_status": "completed"}))
        results = engine.list_assets(ORG, migration_status="planned")
        assert all(r["migration_status"] == "planned" for r in results)

    def test_org_isolation(self, engine):
        engine.register_asset(ORG, _asset())
        results = engine.list_assets(ORG2)
        assert results == []

    def test_quantum_vulnerable_returned_as_bool(self, engine):
        engine.register_asset(ORG, _asset())
        results = engine.list_assets(ORG)
        assert isinstance(results[0]["quantum_vulnerable"], bool)


# ---------------------------------------------------------------------------
# get_asset
# ---------------------------------------------------------------------------

class TestGetAsset:
    def test_found(self, engine):
        created = engine.register_asset(ORG, _asset())
        result = engine.get_asset(ORG, created["id"])
        assert result is not None
        assert result["id"] == created["id"]

    def test_not_found_returns_none(self, engine):
        result = engine.get_asset(ORG, "nonexistent-id")
        assert result is None

    def test_org_isolation(self, engine):
        created = engine.register_asset(ORG, _asset())
        result = engine.get_asset(ORG2, created["id"])
        assert result is None

    def test_quantum_vulnerable_as_bool(self, engine):
        created = engine.register_asset(ORG, _asset({"current_algorithm": "rsa"}))
        result = engine.get_asset(ORG, created["id"])
        assert result["quantum_vulnerable"] is True


# ---------------------------------------------------------------------------
# update_migration_status
# ---------------------------------------------------------------------------

class TestUpdateMigrationStatus:
    def test_updates_status(self, engine):
        asset = engine.register_asset(ORG, _asset())
        result = engine.update_migration_status(ORG, asset["id"], "planned")
        assert result["migration_status"] == "planned"

    def test_invalid_status_raises(self, engine):
        asset = engine.register_asset(ORG, _asset())
        with pytest.raises(ValueError, match="Invalid migration_status"):
            engine.update_migration_status(ORG, asset["id"], "launched")

    def test_completed_sets_migrated_at(self, engine):
        asset = engine.register_asset(ORG, _asset())
        result = engine.update_migration_status(ORG, asset["id"], "completed")
        assert result["migrated_at"] is not None

    def test_not_started_migrated_at_none(self, engine):
        asset = engine.register_asset(ORG, _asset())
        result = engine.update_migration_status(ORG, asset["id"], "not_started")
        assert result["migrated_at"] is None

    def test_org_isolation_returns_none(self, engine):
        asset = engine.register_asset(ORG, _asset())
        result = engine.update_migration_status(ORG2, asset["id"], "planned")
        assert result is None

    def test_all_valid_statuses(self, engine):
        for status in ("not_started", "planned", "in_progress", "completed", "exempt"):
            asset = engine.register_asset(ORG, _asset({"asset_name": f"a-{status}"}))
            result = engine.update_migration_status(ORG, asset["id"], status)
            assert result["migration_status"] == status


# ---------------------------------------------------------------------------
# create_assessment
# ---------------------------------------------------------------------------

class TestCreateAssessment:
    def test_returns_dict_with_id(self, engine):
        result = engine.create_assessment(ORG, _assessment())
        assert "id" in result
        assert len(result["id"]) == 36

    def test_status_defaults_to_planned(self, engine):
        result = engine.create_assessment(ORG, _assessment())
        assert result["status"] == "planned"

    def test_stores_name_and_scope(self, engine):
        result = engine.create_assessment(ORG, _assessment())
        assert result["assessment_name"] == "Q1 2026 Quantum Assessment"
        assert result["scope"] == "All TLS certificates"

    def test_initial_counts_zero(self, engine):
        result = engine.create_assessment(ORG, _assessment())
        assert result["total_assets"] == 0
        assert result["vulnerable_assets"] == 0
        assert result["migrated_assets"] == 0
        assert result["quantum_readiness_score"] == 0.0


# ---------------------------------------------------------------------------
# complete_assessment
# ---------------------------------------------------------------------------

class TestCompleteAssessment:
    def test_sets_status_completed(self, engine):
        assess = engine.create_assessment(ORG, _assessment())
        result = engine.complete_assessment(ORG, assess["id"], 10, 6, 4)
        assert result["status"] == "completed"

    def test_readiness_score_calculated(self, engine):
        assess = engine.create_assessment(ORG, _assessment())
        result = engine.complete_assessment(ORG, assess["id"], 10, 8, 5)
        assert abs(result["quantum_readiness_score"] - 50.0) < 0.01

    def test_readiness_score_100_when_all_migrated(self, engine):
        assess = engine.create_assessment(ORG, _assessment())
        result = engine.complete_assessment(ORG, assess["id"], 5, 5, 5)
        assert abs(result["quantum_readiness_score"] - 100.0) < 0.01

    def test_readiness_score_zero_when_total_zero(self, engine):
        assess = engine.create_assessment(ORG, _assessment())
        result = engine.complete_assessment(ORG, assess["id"], 0, 0, 0)
        assert result["quantum_readiness_score"] == 0.0

    def test_assessed_at_set(self, engine):
        assess = engine.create_assessment(ORG, _assessment())
        result = engine.complete_assessment(ORG, assess["id"], 10, 6, 4)
        assert result["assessed_at"] is not None

    def test_counts_stored(self, engine):
        assess = engine.create_assessment(ORG, _assessment())
        result = engine.complete_assessment(ORG, assess["id"], 20, 15, 10)
        assert result["total_assets"] == 20
        assert result["vulnerable_assets"] == 15
        assert result["migrated_assets"] == 10

    def test_not_found_returns_empty_dict(self, engine):
        result = engine.complete_assessment(ORG, "nonexistent-id", 5, 3, 2)
        assert result == {}

    def test_org_isolation(self, engine):
        assess = engine.create_assessment(ORG, _assessment())
        result = engine.complete_assessment(ORG2, assess["id"], 10, 5, 3)
        assert result == {}


# ---------------------------------------------------------------------------
# list_assessments
# ---------------------------------------------------------------------------

class TestListAssessments:
    def test_list_returns_created(self, engine):
        engine.create_assessment(ORG, _assessment())
        results = engine.list_assessments(ORG)
        assert len(results) >= 1

    def test_filter_by_status(self, engine):
        assess = engine.create_assessment(ORG, _assessment())
        engine.complete_assessment(ORG, assess["id"], 10, 5, 3)
        results = engine.list_assessments(ORG, status="completed")
        assert all(r["status"] == "completed" for r in results)

    def test_org_isolation(self, engine):
        engine.create_assessment(ORG, _assessment())
        results = engine.list_assessments(ORG2)
        assert results == []


# ---------------------------------------------------------------------------
# create_migration
# ---------------------------------------------------------------------------

class TestCreateMigration:
    def test_returns_dict_with_id(self, engine):
        asset = engine.register_asset(ORG, _asset())
        mig = engine.create_migration(ORG, {
            "asset_id": asset["id"],
            "from_algorithm": "rsa",
            "to_algorithm": "CRYSTALS-Dilithium",
            "priority": "high",
        })
        assert "id" in mig
        assert len(mig["id"]) == 36

    def test_status_defaults_to_planned(self, engine):
        asset = engine.register_asset(ORG, _asset())
        mig = engine.create_migration(ORG, {"asset_id": asset["id"], "priority": "medium"})
        assert mig["status"] == "planned"

    def test_invalid_priority_raises(self, engine):
        asset = engine.register_asset(ORG, _asset())
        with pytest.raises(ValueError, match="Invalid priority"):
            engine.create_migration(ORG, {"asset_id": asset["id"], "priority": "extreme"})

    def test_all_valid_priorities(self, engine):
        asset = engine.register_asset(ORG, _asset())
        for priority in ("immediate", "high", "medium", "low", "scheduled"):
            mig = engine.create_migration(ORG, {
                "asset_id": asset["id"],
                "priority": priority,
            })
            assert mig["priority"] == priority


# ---------------------------------------------------------------------------
# list_migrations
# ---------------------------------------------------------------------------

class TestListMigrations:
    def test_list_returns_created(self, engine):
        asset = engine.register_asset(ORG, _asset())
        engine.create_migration(ORG, {"asset_id": asset["id"], "priority": "high"})
        results = engine.list_migrations(ORG)
        assert len(results) >= 1

    def test_filter_by_asset_id(self, engine):
        asset1 = engine.register_asset(ORG, _asset())
        asset2 = engine.register_asset(ORG, _asset({"asset_name": "a2"}))
        engine.create_migration(ORG, {"asset_id": asset1["id"], "priority": "high"})
        engine.create_migration(ORG, {"asset_id": asset2["id"], "priority": "medium"})
        results = engine.list_migrations(ORG, asset_id=asset1["id"])
        assert all(r["asset_id"] == asset1["id"] for r in results)

    def test_filter_by_status(self, engine):
        asset = engine.register_asset(ORG, _asset())
        engine.create_migration(ORG, {"asset_id": asset["id"], "priority": "high"})
        results = engine.list_migrations(ORG, status="planned")
        assert all(r["status"] == "planned" for r in results)

    def test_filter_by_priority(self, engine):
        asset = engine.register_asset(ORG, _asset())
        engine.create_migration(ORG, {"asset_id": asset["id"], "priority": "immediate"})
        engine.create_migration(ORG, {"asset_id": asset["id"], "priority": "low"})
        results = engine.list_migrations(ORG, priority="immediate")
        assert all(r["priority"] == "immediate" for r in results)

    def test_org_isolation(self, engine):
        asset = engine.register_asset(ORG, _asset())
        engine.create_migration(ORG, {"asset_id": asset["id"], "priority": "high"})
        results = engine.list_migrations(ORG2)
        assert results == []


# ---------------------------------------------------------------------------
# get_quantum_stats
# ---------------------------------------------------------------------------

class TestGetQuantumStats:
    def test_total_assets(self, engine):
        engine.register_asset(ORG, _asset())
        engine.register_asset(ORG, _asset({"asset_name": "a2"}))
        stats = engine.get_quantum_stats(ORG)
        assert stats["total_assets"] == 2

    def test_quantum_vulnerable_count(self, engine):
        engine.register_asset(ORG, _asset({"current_algorithm": "rsa"}))
        engine.register_asset(ORG, _asset({"asset_name": "a2", "current_algorithm": "aes"}))
        stats = engine.get_quantum_stats(ORG)
        assert stats["quantum_vulnerable"] == 1

    def test_migrated_count(self, engine):
        engine.register_asset(ORG, _asset({"migration_status": "completed"}))
        engine.register_asset(ORG, _asset({"asset_name": "a2", "migration_status": "planned"}))
        stats = engine.get_quantum_stats(ORG)
        assert stats["migrated"] == 1

    def test_migration_progress_pct(self, engine):
        engine.register_asset(ORG, _asset({"migration_status": "completed"}))
        engine.register_asset(ORG, _asset({"asset_name": "a2", "migration_status": "completed"}))
        engine.register_asset(ORG, _asset({"asset_name": "a3", "migration_status": "planned"}))
        engine.register_asset(ORG, _asset({"asset_name": "a4", "migration_status": "not_started"}))
        stats = engine.get_quantum_stats(ORG)
        assert abs(stats["migration_progress_pct"] - 50.0) < 0.01

    def test_critical_vulnerable(self, engine):
        engine.register_asset(ORG, _asset({
            "current_algorithm": "rsa",
            "risk_level": "critical",
        }))
        engine.register_asset(ORG, _asset({
            "asset_name": "a2",
            "current_algorithm": "rsa",
            "risk_level": "high",
        }))
        stats = engine.get_quantum_stats(ORG)
        assert stats["critical_vulnerable"] == 1

    def test_by_asset_type(self, engine):
        engine.register_asset(ORG, _asset({"asset_type": "vpn"}))
        engine.register_asset(ORG, _asset({"asset_name": "a2", "asset_type": "vpn"}))
        engine.register_asset(ORG, _asset({"asset_name": "a3", "asset_type": "ssh_key"}))
        stats = engine.get_quantum_stats(ORG)
        assert stats["by_asset_type"].get("vpn", 0) == 2
        assert stats["by_asset_type"].get("ssh_key", 0) == 1

    def test_by_migration_status(self, engine):
        engine.register_asset(ORG, _asset({"migration_status": "planned"}))
        engine.register_asset(ORG, _asset({"asset_name": "a2", "migration_status": "completed"}))
        stats = engine.get_quantum_stats(ORG)
        assert stats["by_migration_status"].get("planned", 0) >= 1

    def test_by_current_algorithm(self, engine):
        engine.register_asset(ORG, _asset({"current_algorithm": "rsa"}))
        engine.register_asset(ORG, _asset({"asset_name": "a2", "current_algorithm": "rsa"}))
        engine.register_asset(ORG, _asset({"asset_name": "a3", "current_algorithm": "aes"}))
        stats = engine.get_quantum_stats(ORG)
        assert stats["by_current_algorithm"].get("rsa", 0) == 2
        assert stats["by_current_algorithm"].get("aes", 0) == 1

    def test_empty_org(self, engine):
        stats = engine.get_quantum_stats("empty-org-qsc")
        assert stats["total_assets"] == 0
        assert stats["quantum_vulnerable"] == 0
        assert stats["migration_progress_pct"] == 0.0

    def test_org_isolation(self, engine):
        engine.register_asset(ORG, _asset())
        engine.register_asset(ORG, _asset({"asset_name": "a2"}))
        engine.register_asset(ORG2, _asset())
        stats = engine.get_quantum_stats(ORG)
        stats2 = engine.get_quantum_stats(ORG2)
        assert stats["total_assets"] == 2
        assert stats2["total_assets"] == 1
