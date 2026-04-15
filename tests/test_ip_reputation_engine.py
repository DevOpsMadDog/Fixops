"""
Comprehensive tests for IPReputationEngine.

Covers:
- submit_reputation: creation, update/upsert, score clamping, category filtering
- get_reputation: found, not found, risk_level mapping
- bulk_check: known IPs, unknown IPs default, risk thresholds
- add_to_blocklist: creation, idempotent upsert
- remove_from_blocklist: removes existing, handles missing gracefully
- is_blocked: true/false cases
- get_blocklist: org isolation, limit
- get_reputation_stats: totals, avg_score, by_category, org isolation
- Multi-tenant isolation throughout
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("FIXOPS_MODE", "dev")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")

from core.ip_reputation_engine import IPReputationEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "iprep.db")
    return IPReputationEngine(db_path=db)


ORG = "org-rep-test"
ORG2 = "org-rep-other"


def _rep(overrides=None):
    base = {
        "ip": "1.2.3.4",
        "reputation_score": 50,
        "categories": ["spam"],
        "source": "test-feed",
    }
    if overrides:
        base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# submit_reputation
# ---------------------------------------------------------------------------

class TestSubmitReputation:
    def test_returns_dict_with_id(self, engine):
        result = engine.submit_reputation(ORG, _rep())
        assert "id" in result
        assert len(result["id"]) == 36

    def test_stores_ip_and_score(self, engine):
        result = engine.submit_reputation(ORG, _rep({"ip": "10.0.0.1", "reputation_score": 30}))
        assert result["ip"] == "10.0.0.1"
        assert result["score"] == 30

    def test_report_count_starts_at_one(self, engine):
        result = engine.submit_reputation(ORG, _rep())
        assert result["report_count"] == 1

    def test_upsert_increments_report_count(self, engine):
        engine.submit_reputation(ORG, _rep({"ip": "5.5.5.5"}))
        result = engine.submit_reputation(ORG, _rep({"ip": "5.5.5.5", "reputation_score": 20}))
        assert result["report_count"] == 2

    def test_upsert_updates_score(self, engine):
        engine.submit_reputation(ORG, _rep({"ip": "5.5.5.5", "reputation_score": 80}))
        result = engine.submit_reputation(ORG, _rep({"ip": "5.5.5.5", "reputation_score": 10}))
        assert result["score"] == 10

    def test_score_clamped_to_100(self, engine):
        result = engine.submit_reputation(ORG, _rep({"reputation_score": 150}))
        assert result["score"] == 100

    def test_score_clamped_to_0(self, engine):
        result = engine.submit_reputation(ORG, _rep({"reputation_score": -50}))
        assert result["score"] == 0

    def test_invalid_categories_filtered(self, engine):
        result = engine.submit_reputation(ORG, _rep({"categories": ["spam", "unknown_cat", "botnet"]}))
        assert "unknown_cat" not in result["categories"]
        assert "spam" in result["categories"]
        assert "botnet" in result["categories"]

    def test_all_valid_categories_accepted(self, engine):
        cats = ["spam", "botnet", "proxy", "tor", "scanner", "malware"]
        result = engine.submit_reputation(ORG, _rep({"categories": cats}))
        assert set(result["categories"]) == set(cats)

    def test_risk_level_critical_for_low_score(self, engine):
        result = engine.submit_reputation(ORG, _rep({"reputation_score": 5}))
        assert result["risk_level"] == "critical"

    def test_risk_level_low_for_high_score(self, engine):
        result = engine.submit_reputation(ORG, _rep({"reputation_score": 90}))
        assert result["risk_level"] == "low"

    def test_org_isolation(self, engine):
        engine.submit_reputation(ORG, _rep({"ip": "6.6.6.6"}))
        result = engine.get_reputation(ORG2, "6.6.6.6")
        assert result == {}


# ---------------------------------------------------------------------------
# get_reputation
# ---------------------------------------------------------------------------

class TestGetReputation:
    def test_found_returns_data(self, engine):
        engine.submit_reputation(ORG, _rep({"ip": "7.7.7.7", "reputation_score": 25}))
        result = engine.get_reputation(ORG, "7.7.7.7")
        assert result["ip"] == "7.7.7.7"
        assert result["score"] == 25

    def test_not_found_returns_empty_dict(self, engine):
        result = engine.get_reputation(ORG, "0.0.0.0")
        assert result == {}

    def test_risk_level_thresholds(self, engine):
        cases = [
            (10, "critical"),
            (30, "high"),
            (50, "medium"),
            (80, "low"),
        ]
        for score, expected_risk in cases:
            ip = f"192.168.0.{score}"
            engine.submit_reputation(ORG, _rep({"ip": ip, "reputation_score": score}))
            result = engine.get_reputation(ORG, ip)
            assert result["risk_level"] == expected_risk, f"score={score}"

    def test_categories_returned_as_list(self, engine):
        engine.submit_reputation(ORG, _rep({"ip": "3.3.3.3", "categories": ["tor", "proxy"]}))
        result = engine.get_reputation(ORG, "3.3.3.3")
        assert isinstance(result["categories"], list)
        assert "tor" in result["categories"]

    def test_report_count_returned(self, engine):
        engine.submit_reputation(ORG, _rep({"ip": "4.4.4.4"}))
        engine.submit_reputation(ORG, _rep({"ip": "4.4.4.4"}))
        result = engine.get_reputation(ORG, "4.4.4.4")
        assert result["report_count"] == 2


# ---------------------------------------------------------------------------
# bulk_check
# ---------------------------------------------------------------------------

class TestBulkCheck:
    def test_returns_list_of_same_length(self, engine):
        ips = ["1.1.1.1", "2.2.2.2", "3.3.3.3"]
        results = engine.bulk_check(ORG, ips)
        assert len(results) == 3

    def test_known_ips_return_stored_score(self, engine):
        engine.submit_reputation(ORG, _rep({"ip": "10.10.10.10", "reputation_score": 15}))
        results = engine.bulk_check(ORG, ["10.10.10.10"])
        assert results[0]["score"] == 15

    def test_unknown_ips_return_score_100(self, engine):
        results = engine.bulk_check(ORG, ["99.99.99.99"])
        assert results[0]["score"] == 100
        assert results[0]["risk_level"] == "low"

    def test_risk_level_critical_threshold(self, engine):
        engine.submit_reputation(ORG, _rep({"ip": "11.11.11.11", "reputation_score": 15}))
        results = engine.bulk_check(ORG, ["11.11.11.11"])
        assert results[0]["risk_level"] == "critical"

    def test_risk_level_high_threshold(self, engine):
        engine.submit_reputation(ORG, _rep({"ip": "12.12.12.12", "reputation_score": 35}))
        results = engine.bulk_check(ORG, ["12.12.12.12"])
        assert results[0]["risk_level"] == "high"

    def test_risk_level_medium_threshold(self, engine):
        engine.submit_reputation(ORG, _rep({"ip": "13.13.13.13", "reputation_score": 55}))
        results = engine.bulk_check(ORG, ["13.13.13.13"])
        assert results[0]["risk_level"] == "medium"

    def test_empty_list_returns_empty(self, engine):
        assert engine.bulk_check(ORG, []) == []

    def test_each_result_has_ip_field(self, engine):
        ips = ["1.2.3.4", "5.6.7.8"]
        results = engine.bulk_check(ORG, ips)
        result_ips = {r["ip"] for r in results}
        assert result_ips == set(ips)


# ---------------------------------------------------------------------------
# add_to_blocklist / remove_from_blocklist / is_blocked / get_blocklist
# ---------------------------------------------------------------------------

class TestBlocklist:
    def test_add_returns_entry(self, engine):
        entry = engine.add_to_blocklist(ORG, "1.1.1.1", "Botnet C2")
        assert entry["ip"] == "1.1.1.1"
        assert entry["reason"] == "Botnet C2"
        assert "id" in entry

    def test_is_blocked_true_after_add(self, engine):
        engine.add_to_blocklist(ORG, "2.2.2.2", "spam")
        assert engine.is_blocked(ORG, "2.2.2.2") is True

    def test_is_blocked_false_for_unknown(self, engine):
        assert engine.is_blocked(ORG, "3.3.3.3") is False

    def test_remove_returns_removed_true(self, engine):
        engine.add_to_blocklist(ORG, "4.4.4.4", "test")
        result = engine.remove_from_blocklist(ORG, "4.4.4.4")
        assert result["removed"] is True
        assert result["ip"] == "4.4.4.4"

    def test_remove_then_is_blocked_false(self, engine):
        engine.add_to_blocklist(ORG, "5.5.5.5", "test")
        engine.remove_from_blocklist(ORG, "5.5.5.5")
        assert engine.is_blocked(ORG, "5.5.5.5") is False

    def test_remove_missing_returns_removed_false(self, engine):
        result = engine.remove_from_blocklist(ORG, "9.9.9.9")
        assert result["removed"] is False

    def test_add_idempotent(self, engine):
        engine.add_to_blocklist(ORG, "6.6.6.6", "initial")
        engine.add_to_blocklist(ORG, "6.6.6.6", "updated")
        entries = [e for e in engine.get_blocklist(ORG) if e["ip"] == "6.6.6.6"]
        assert len(entries) == 1

    def test_get_blocklist_returns_added(self, engine):
        engine.add_to_blocklist(ORG, "7.7.7.7", "reason")
        bl = engine.get_blocklist(ORG)
        ips = [e["ip"] for e in bl]
        assert "7.7.7.7" in ips

    def test_get_blocklist_limit(self, engine):
        for i in range(10):
            engine.add_to_blocklist(ORG, f"10.0.0.{i}", "test")
        bl = engine.get_blocklist(ORG, limit=5)
        assert len(bl) == 5

    def test_org_isolation_blocklist(self, engine):
        engine.add_to_blocklist(ORG, "8.8.8.8", "test")
        assert engine.is_blocked(ORG2, "8.8.8.8") is False
        assert engine.get_blocklist(ORG2) == []


# ---------------------------------------------------------------------------
# get_reputation_stats
# ---------------------------------------------------------------------------

class TestGetReputationStats:
    def test_total_ips_tracked(self, engine):
        engine.submit_reputation(ORG, _rep({"ip": "1.1.1.1"}))
        engine.submit_reputation(ORG, _rep({"ip": "2.2.2.2"}))
        stats = engine.get_reputation_stats(ORG)
        assert stats["total_ips_tracked"] == 2

    def test_blocked_ips_count(self, engine):
        engine.add_to_blocklist(ORG, "3.3.3.3", "test")
        engine.add_to_blocklist(ORG, "4.4.4.4", "test")
        stats = engine.get_reputation_stats(ORG)
        assert stats["blocked_ips"] >= 2

    def test_avg_score_correct(self, engine):
        engine.submit_reputation(ORG, _rep({"ip": "5.5.5.5", "reputation_score": 40}))
        engine.submit_reputation(ORG, _rep({"ip": "6.6.6.6", "reputation_score": 60}))
        stats = engine.get_reputation_stats(ORG)
        assert abs(stats["avg_score"] - 50.0) < 1.0

    def test_by_category_counts(self, engine):
        engine.submit_reputation(ORG, _rep({"ip": "7.7.7.7", "categories": ["spam", "botnet"]}))
        engine.submit_reputation(ORG, _rep({"ip": "8.8.8.8", "categories": ["spam"]}))
        stats = engine.get_reputation_stats(ORG)
        assert stats["by_category"]["spam"] == 2
        assert stats["by_category"]["botnet"] == 1

    def test_by_category_has_all_keys(self, engine):
        stats = engine.get_reputation_stats(ORG)
        for cat in ("spam", "botnet", "proxy", "tor", "scanner", "malware"):
            assert cat in stats["by_category"]

    def test_empty_org_stats(self, engine):
        stats = engine.get_reputation_stats("empty-org")
        assert stats["total_ips_tracked"] == 0
        assert stats["blocked_ips"] == 0
        assert stats["avg_score"] == 0.0

    def test_org_isolation_stats(self, engine):
        engine.submit_reputation(ORG, _rep({"ip": "9.9.9.9"}))
        engine.submit_reputation(ORG, _rep({"ip": "10.10.10.10"}))
        engine.submit_reputation(ORG2, _rep({"ip": "11.11.11.11"}))
        stats = engine.get_reputation_stats(ORG)
        stats2 = engine.get_reputation_stats(ORG2)
        assert stats["total_ips_tracked"] == 2
        assert stats2["total_ips_tracked"] == 1
