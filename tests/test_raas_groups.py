"""Tests for RaaS group tracking in RansomwareProtectionEngine — 6 tests."""

from __future__ import annotations

import pytest

from core.ransomware_protection_engine import RansomwareProtectionEngine

ORG = "org-raas"
ORG2 = "org-raas-b"


@pytest.fixture
def engine(tmp_path):
    return RansomwareProtectionEngine(db_path=str(tmp_path / "raas_test.db"))


class TestRaaSGroups:
    def test_register_raas_group_basic(self, engine):
        g = engine.register_raas_group(
            ORG,
            "LockBit",
            aliases=["LockBit 3.0", "LockBit Black"],
            active_since="2019-09",
            extortion_model="triple",
            avg_ransom_usd=850_000,
            known_sectors=["healthcare", "manufacturing"],
        )
        assert g["id"]
        assert g["group_name"] == "LockBit"
        assert "LockBit 3.0" in g["aliases"]
        assert g["extortion_model"] == "triple"
        assert g["avg_ransom_usd"] == 850_000
        assert "healthcare" in g["known_sectors"]
        assert g["active"] is True

    def test_invalid_extortion_model_raises(self, engine):
        with pytest.raises(ValueError, match="extortion_model"):
            engine.register_raas_group(ORG, "BadGroup", extortion_model="unknown_model")

    def test_list_raas_groups_active_only(self, engine):
        g1 = engine.register_raas_group(ORG, "BlackCat")
        g2 = engine.register_raas_group(ORG, "Clop")
        engine.deactivate_raas_group(g2["id"], ORG)

        active = engine.list_raas_groups(ORG, active_only=True)
        all_groups = engine.list_raas_groups(ORG, active_only=False)

        assert len(active) == 1
        assert active[0]["group_name"] == "BlackCat"
        assert len(all_groups) == 2

    def test_deactivate_raas_group(self, engine):
        g = engine.register_raas_group(ORG, "REvil")
        assert g["active"] is True
        deactivated = engine.deactivate_raas_group(g["id"], ORG)
        assert deactivated["active"] is False

    def test_deactivate_wrong_org_raises(self, engine):
        g = engine.register_raas_group(ORG, "Hive")
        with pytest.raises(ValueError):
            engine.deactivate_raas_group(g["id"], ORG2)

    def test_org_isolation(self, engine):
        engine.register_raas_group(ORG, "GroupA")
        engine.register_raas_group(ORG2, "GroupB")
        assert len(engine.list_raas_groups(ORG)) == 1
        assert len(engine.list_raas_groups(ORG2)) == 1
