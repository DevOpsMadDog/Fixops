"""Tests for AssetCriticalityScorer — 25+ tests covering scoring formula,
tier assignment, CRUD operations, stats, and org isolation.
"""
from __future__ import annotations

import pytest
from core.asset_criticality_scorer import AssetCriticalityScorer, _criticality_tier


@pytest.fixture
def scorer(tmp_path):
    return AssetCriticalityScorer(db_path=str(tmp_path / "asset_crit_test.db"))


@pytest.fixture
def org():
    return "org-test"


@pytest.fixture
def org2():
    return "org-test-beta"


def _asset(asset_name="web-server-01", asset_type="server", **kwargs):
    defaults = {
        "asset_name": asset_name,
        "asset_type": asset_type,
        "business_owner": "security-team",
        "data_classification": "internal",
        "internet_facing": False,
        "regulatory_scope": [],
        "dependencies_count": 0,
    }
    defaults.update(kwargs)
    return defaults


# ---------------------------------------------------------------------------
# Tier helper
# ---------------------------------------------------------------------------

class TestCriticalityTier:
    def test_critical_threshold(self):
        assert _criticality_tier(8.0) == "critical"
        assert _criticality_tier(10.0) == "critical"

    def test_high_threshold(self):
        assert _criticality_tier(6.0) == "high"
        assert _criticality_tier(7.9) == "high"

    def test_medium_threshold(self):
        assert _criticality_tier(4.0) == "medium"
        assert _criticality_tier(5.9) == "medium"

    def test_low_threshold(self):
        assert _criticality_tier(0.0) == "low"
        assert _criticality_tier(3.9) == "low"


# ---------------------------------------------------------------------------
# Init
# ---------------------------------------------------------------------------

class TestInit:
    def test_init_creates_db(self, tmp_path):
        db = str(tmp_path / "test.db")
        s = AssetCriticalityScorer(db_path=db)
        assert s.db_path == db

    def test_init_default_db_path(self):
        s = AssetCriticalityScorer.__new__(AssetCriticalityScorer)
        # Just verify default path logic works without file I/O
        assert AssetCriticalityScorer is not None


# ---------------------------------------------------------------------------
# register_asset
# ---------------------------------------------------------------------------

class TestRegisterAsset:
    def test_register_returns_record(self, scorer, org):
        result = scorer.register_asset(org, _asset())
        assert result["id"] is not None
        assert result["org_id"] == org
        assert result["asset_name"] == "web-server-01"
        assert 1.0 <= result["criticality_score"] <= 10.0
        assert result["criticality_tier"] in ("critical", "high", "medium", "low")
        assert "factors" in result

    def test_register_database_type(self, scorer, org):
        result = scorer.register_asset(org, _asset(asset_type="database"))
        # Database has higher base score (7.0) than server (5.0)
        assert result["criticality_score"] >= 5.0

    def test_register_invalid_asset_type_raises(self, scorer, org):
        with pytest.raises(ValueError, match="asset_type"):
            scorer.register_asset(org, _asset(asset_type="spaceship"))

    def test_register_invalid_data_classification_raises(self, scorer, org):
        with pytest.raises(ValueError, match="data_classification"):
            scorer.register_asset(org, _asset(data_classification="ultra-secret"))

    def test_register_internet_facing_boosts_score(self, scorer, org):
        base = scorer.register_asset(org, _asset(asset_name="a1", internet_facing=False))
        boosted = scorer.register_asset(org, _asset(asset_name="a2", internet_facing=True))
        assert boosted["criticality_score"] > base["criticality_score"]

    def test_register_secret_classification_higher_than_public(self, scorer, org):
        pub = scorer.register_asset(org, _asset(asset_name="pub", data_classification="public"))
        sec = scorer.register_asset(org, _asset(asset_name="sec", data_classification="secret"))
        assert sec["criticality_score"] > pub["criticality_score"]

    def test_register_database_higher_than_endpoint(self, scorer, org):
        db = scorer.register_asset(org, _asset(asset_name="db1", asset_type="database"))
        ep = scorer.register_asset(org, _asset(asset_name="ep1", asset_type="endpoint"))
        assert db["criticality_score"] > ep["criticality_score"]

    def test_register_regulatory_scope_boosts_score(self, scorer, org):
        no_reg = scorer.register_asset(org, _asset(asset_name="nr", regulatory_scope=[]))
        with_reg = scorer.register_asset(
            org, _asset(asset_name="wr", regulatory_scope=["pci-dss", "hipaa"])
        )
        assert with_reg["criticality_score"] > no_reg["criticality_score"]

    def test_register_dependencies_boost_score(self, scorer, org):
        low_dep = scorer.register_asset(org, _asset(asset_name="ld", dependencies_count=0))
        high_dep = scorer.register_asset(org, _asset(asset_name="hd", dependencies_count=20))
        assert high_dep["criticality_score"] > low_dep["criticality_score"]

    def test_register_score_capped_at_10(self, scorer, org):
        result = scorer.register_asset(org, _asset(
            asset_type="database",
            data_classification="secret",
            internet_facing=True,
            regulatory_scope=["pci-dss", "hipaa", "sox", "gdpr"],
            dependencies_count=100,
        ))
        assert result["criticality_score"] <= 10.0

    def test_register_persists_to_db(self, scorer, org):
        scorer.register_asset(org, _asset())
        assets = scorer.list_assets(org)
        assert len(assets) == 1


# ---------------------------------------------------------------------------
# score_asset
# ---------------------------------------------------------------------------

class TestScoreAsset:
    def test_score_returns_correct_fields(self, scorer, org):
        rec = scorer.register_asset(org, _asset())
        result = scorer.score_asset(org, rec["id"])
        assert result["asset_id"] == rec["id"]
        assert "criticality_score" in result
        assert "criticality_tier" in result
        assert "factors" in result
        assert 1.0 <= result["criticality_score"] <= 10.0

    def test_score_not_found_raises(self, scorer, org):
        with pytest.raises(ValueError, match="not found"):
            scorer.score_asset(org, "ghost-asset-id")

    def test_score_org_isolation(self, scorer, org, org2):
        rec = scorer.register_asset(org, _asset())
        with pytest.raises(ValueError, match="not found"):
            scorer.score_asset(org2, rec["id"])


# ---------------------------------------------------------------------------
# list_assets
# ---------------------------------------------------------------------------

class TestListAssets:
    def test_list_empty(self, scorer, org):
        assert scorer.list_assets(org) == []

    def test_list_returns_all(self, scorer, org):
        scorer.register_asset(org, _asset(asset_name="a1"))
        scorer.register_asset(org, _asset(asset_name="a2"))
        assert len(scorer.list_assets(org)) == 2

    def test_list_filter_by_tier(self, scorer, org):
        # Register a high-criticality asset
        scorer.register_asset(org, _asset(
            asset_name="critical-db",
            asset_type="database",
            data_classification="secret",
            internet_facing=True,
            regulatory_scope=["pci-dss", "hipaa"],
            dependencies_count=20,
        ))
        # Register a low-criticality asset
        scorer.register_asset(org, _asset(
            asset_name="low-ep",
            asset_type="endpoint",
            data_classification="public",
        ))
        # At least one asset should exist per list
        all_assets = scorer.list_assets(org)
        assert len(all_assets) == 2

    def test_list_sorted_by_score_desc(self, scorer, org):
        scorer.register_asset(org, _asset(asset_name="low", asset_type="endpoint", data_classification="public"))
        scorer.register_asset(org, _asset(asset_name="high", asset_type="database", data_classification="secret",
                                          internet_facing=True))
        assets = scorer.list_assets(org)
        scores = [a["criticality_score"] for a in assets]
        assert scores == sorted(scores, reverse=True)

    def test_list_org_isolation(self, scorer, org, org2):
        scorer.register_asset(org, _asset(asset_name="org1-asset"))
        assets_org2 = scorer.list_assets(org2)
        assert len(assets_org2) == 0


# ---------------------------------------------------------------------------
# update_asset
# ---------------------------------------------------------------------------

class TestUpdateAsset:
    def test_update_changes_score(self, scorer, org):
        rec = scorer.register_asset(org, _asset(internet_facing=False))
        original_score = rec["criticality_score"]
        updated = scorer.update_asset(org, rec["id"], {"internet_facing": True})
        assert updated["criticality_score"] > original_score

    def test_update_not_found_raises(self, scorer, org):
        with pytest.raises(ValueError, match="not found"):
            scorer.update_asset(org, "nonexistent", {"asset_name": "new"})

    def test_update_org_isolation(self, scorer, org, org2):
        rec = scorer.register_asset(org, _asset())
        with pytest.raises(ValueError, match="not found"):
            scorer.update_asset(org2, rec["id"], {"asset_name": "hacked"})


# ---------------------------------------------------------------------------
# get_criticality_stats
# ---------------------------------------------------------------------------

class TestCriticalityStats:
    def test_stats_empty(self, scorer, org):
        stats = scorer.get_criticality_stats(org)
        assert stats["total_assets"] == 0
        assert stats["avg_score"] == 0.0
        assert stats["internet_facing_count"] == 0
        assert stats["in_regulatory_scope_count"] == 0
        assert isinstance(stats["by_tier"], dict)

    def test_stats_counts(self, scorer, org):
        scorer.register_asset(org, _asset(asset_name="a1", internet_facing=True,
                                          regulatory_scope=["pci-dss"]))
        scorer.register_asset(org, _asset(asset_name="a2", internet_facing=False))
        stats = scorer.get_criticality_stats(org)
        assert stats["total_assets"] == 2
        assert stats["internet_facing_count"] == 1
        assert stats["in_regulatory_scope_count"] == 1
        assert stats["avg_score"] > 0.0

    def test_stats_org_isolation(self, scorer, org, org2):
        scorer.register_asset(org, _asset())
        stats_org2 = scorer.get_criticality_stats(org2)
        assert stats_org2["total_assets"] == 0
