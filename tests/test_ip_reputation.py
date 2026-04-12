"""Tests for the IP Reputation Scoring Engine.

Covers:
- IPRecord and ReputationFactor models
- ReputationLevel enum and score-to-level mapping
- IPReputationEngine: record, score, get, list, malicious, history, bulk, stats
- Blocklist: built-in CIDR check, manual add/remove
- Enrichment (mock-safe)
- Multi-tenant isolation
- Score calculation (_calculate_score)
- Edge cases: unknown IP, duplicate record, empty org
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from core.ip_reputation import (
    IPRecord,
    IPReputationEngine,
    ReputationFactor,
    ReputationLevel,
    _level_from_score,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_engine(tmp_path):
    """IPReputationEngine backed by a temp SQLite database."""
    db_path = str(tmp_path / "test_ip_rep.db")
    return IPReputationEngine(db_path=db_path)


ORG_A = "org_alpha"
ORG_B = "org_beta"
TEST_IP = "1.2.3.4"
TEST_IP2 = "5.6.7.8"
TEST_IP3 = "200.201.202.203"


# ---------------------------------------------------------------------------
# Model tests
# ---------------------------------------------------------------------------


class TestIPRecord:
    def test_default_values(self):
        record = IPRecord(ip_address="1.1.1.1", org_id="org_x")
        assert record.score == 0.0
        assert record.level == ReputationLevel.CLEAN
        assert record.finding_count == 0
        assert record.tags == []
        assert record.id is not None

    def test_score_bounds(self):
        record = IPRecord(ip_address="1.1.1.1", org_id="org_x", score=100.0)
        assert record.score == 100.0

    def test_optional_fields_none(self):
        record = IPRecord(ip_address="1.1.1.1", org_id="org_x")
        assert record.country_code is None
        assert record.asn is None
        assert record.isp is None


class TestReputationFactor:
    def test_creation(self):
        factor = ReputationFactor(name="test", weight=0.5, value=50.0, source="scanner")
        assert factor.name == "test"
        assert factor.weight == 0.5
        assert factor.value == 50.0


class TestReputationLevel:
    def test_level_from_score_clean(self):
        assert _level_from_score(0.0) == ReputationLevel.CLEAN
        assert _level_from_score(24.9) == ReputationLevel.CLEAN

    def test_level_from_score_suspicious(self):
        assert _level_from_score(25.0) == ReputationLevel.SUSPICIOUS
        assert _level_from_score(49.9) == ReputationLevel.SUSPICIOUS

    def test_level_from_score_malicious(self):
        assert _level_from_score(50.0) == ReputationLevel.MALICIOUS
        assert _level_from_score(74.9) == ReputationLevel.MALICIOUS

    def test_level_from_score_blocklisted(self):
        assert _level_from_score(75.0) == ReputationLevel.BLOCKLISTED
        assert _level_from_score(100.0) == ReputationLevel.BLOCKLISTED

    def test_enum_values(self):
        assert ReputationLevel.CLEAN.value == "CLEAN"
        assert ReputationLevel.SUSPICIOUS.value == "SUSPICIOUS"
        assert ReputationLevel.MALICIOUS.value == "MALICIOUS"
        assert ReputationLevel.BLOCKLISTED.value == "BLOCKLISTED"


# ---------------------------------------------------------------------------
# Engine: record_ip
# ---------------------------------------------------------------------------


class TestRecordIP:
    def test_record_new_ip(self, tmp_engine):
        record = tmp_engine.record_ip(TEST_IP, source="scanner", org_id=ORG_A)
        assert isinstance(record, IPRecord)
        assert record.ip_address == TEST_IP
        assert record.org_id == ORG_A
        assert record.finding_count >= 1

    def test_record_increments_finding_count(self, tmp_engine):
        tmp_engine.record_ip(TEST_IP, source="scanner", org_id=ORG_A)
        record2 = tmp_engine.record_ip(TEST_IP, source="scanner", org_id=ORG_A)
        assert record2.finding_count >= 2

    def test_record_different_orgs_independent(self, tmp_engine):
        r_a = tmp_engine.record_ip(TEST_IP, source="scanner", org_id=ORG_A)
        r_b = tmp_engine.record_ip(TEST_IP, source="scanner", org_id=ORG_B)
        assert r_a.org_id == ORG_A
        assert r_b.org_id == ORG_B
        assert r_a.finding_count != r_b.finding_count or r_b.finding_count == 1

    def test_record_returns_ip_record_instance(self, tmp_engine):
        result = tmp_engine.record_ip(TEST_IP, source="test", org_id=ORG_A)
        assert isinstance(result, IPRecord)


# ---------------------------------------------------------------------------
# Engine: score_ip
# ---------------------------------------------------------------------------


class TestScoreIP:
    def test_score_new_ip_returns_record(self, tmp_engine):
        record = tmp_engine.score_ip(TEST_IP, ORG_A)
        assert isinstance(record, IPRecord)
        assert record.ip_address == TEST_IP

    def test_score_clean_ip_low_score(self, tmp_engine):
        record = tmp_engine.score_ip(TEST_IP, ORG_A)
        assert record.score < 25.0
        assert record.level == ReputationLevel.CLEAN

    def test_score_persists_to_db(self, tmp_engine):
        tmp_engine.score_ip(TEST_IP, ORG_A)
        fetched = tmp_engine.get_ip(TEST_IP, ORG_A)
        assert fetched is not None
        assert fetched.ip_address == TEST_IP

    def test_score_increases_with_findings(self, tmp_engine):
        # Record many sightings to inflate finding_count
        for _ in range(5):
            tmp_engine.record_ip(TEST_IP, source="scanner", org_id=ORG_A)
        record = tmp_engine.score_ip(TEST_IP, ORG_A)
        assert record.score > 0.0


# ---------------------------------------------------------------------------
# Engine: get_ip
# ---------------------------------------------------------------------------


class TestGetIP:
    def test_get_existing_ip(self, tmp_engine):
        tmp_engine.record_ip(TEST_IP, source="scanner", org_id=ORG_A)
        record = tmp_engine.get_ip(TEST_IP, ORG_A)
        assert record is not None
        assert record.ip_address == TEST_IP

    def test_get_nonexistent_returns_none(self, tmp_engine):
        result = tmp_engine.get_ip("99.88.77.66", ORG_A)
        assert result is None

    def test_get_wrong_org_returns_none(self, tmp_engine):
        tmp_engine.record_ip(TEST_IP, source="scanner", org_id=ORG_A)
        result = tmp_engine.get_ip(TEST_IP, ORG_B)
        assert result is None


# ---------------------------------------------------------------------------
# Engine: list_ips
# ---------------------------------------------------------------------------


class TestListIPs:
    def test_list_returns_all_org_ips(self, tmp_engine):
        tmp_engine.record_ip(TEST_IP, source="s", org_id=ORG_A)
        tmp_engine.record_ip(TEST_IP2, source="s", org_id=ORG_A)
        records = tmp_engine.list_ips(ORG_A)
        ips = [r.ip_address for r in records]
        assert TEST_IP in ips
        assert TEST_IP2 in ips

    def test_list_empty_org(self, tmp_engine):
        records = tmp_engine.list_ips("org_empty")
        assert records == []

    def test_list_level_filter(self, tmp_engine):
        tmp_engine.record_ip(TEST_IP, source="s", org_id=ORG_A)
        # Blocklist one to force BLOCKLISTED level
        tmp_engine.add_to_blocklist(TEST_IP2, reason="test", org_id=ORG_A)
        clean = tmp_engine.list_ips(ORG_A, level_filter=ReputationLevel.CLEAN)
        blocked = tmp_engine.list_ips(ORG_A, level_filter=ReputationLevel.BLOCKLISTED)
        assert all(r.level == ReputationLevel.CLEAN for r in clean)
        assert all(r.level == ReputationLevel.BLOCKLISTED for r in blocked)

    def test_list_limit(self, tmp_engine):
        for i in range(10):
            tmp_engine.record_ip(f"10.0.0.{i}", source="s", org_id=ORG_A)
        records = tmp_engine.list_ips(ORG_A, limit=5)
        assert len(records) <= 5

    def test_list_isolates_orgs(self, tmp_engine):
        tmp_engine.record_ip(TEST_IP, source="s", org_id=ORG_A)
        tmp_engine.record_ip(TEST_IP2, source="s", org_id=ORG_B)
        records_a = tmp_engine.list_ips(ORG_A)
        assert all(r.org_id == ORG_A for r in records_a)


# ---------------------------------------------------------------------------
# Engine: get_malicious
# ---------------------------------------------------------------------------


class TestGetMalicious:
    def test_get_malicious_empty(self, tmp_engine):
        result = tmp_engine.get_malicious(ORG_A)
        assert result == []

    def test_get_malicious_after_blocklist(self, tmp_engine):
        tmp_engine.add_to_blocklist(TEST_IP, reason="manual block", org_id=ORG_A)
        result = tmp_engine.get_malicious(ORG_A)
        ips = [r.ip_address for r in result]
        assert TEST_IP in ips

    def test_get_malicious_only_own_org(self, tmp_engine):
        tmp_engine.add_to_blocklist(TEST_IP, reason="block", org_id=ORG_A)
        result_b = tmp_engine.get_malicious(ORG_B)
        ips_b = [r.ip_address for r in result_b]
        assert TEST_IP not in ips_b


# ---------------------------------------------------------------------------
# Engine: check_blocklist
# ---------------------------------------------------------------------------


class TestCheckBlocklist:
    def test_known_malicious_range(self, tmp_engine):
        # 185.220.101.5 is in the Tor exit range
        assert tmp_engine.check_blocklist("185.220.101.5") is True

    def test_clean_public_ip(self, tmp_engine):
        # 8.8.8.8 is not in any built-in range
        assert tmp_engine.check_blocklist("8.8.8.8") is False

    def test_another_clean_ip(self, tmp_engine):
        assert tmp_engine.check_blocklist("93.184.216.34") is False

    def test_invalid_ip_returns_false(self, tmp_engine):
        assert tmp_engine.check_blocklist("not_an_ip") is False

    def test_bulletproof_hosting_range(self, tmp_engine):
        assert tmp_engine.check_blocklist("5.188.86.100") is True


# ---------------------------------------------------------------------------
# Engine: enrich_ip
# ---------------------------------------------------------------------------


class TestEnrichIP:
    def test_enrich_returns_dict(self, tmp_engine):
        result = tmp_engine.enrich_ip(TEST_IP)
        assert isinstance(result, dict)

    def test_enrich_has_required_keys(self, tmp_engine):
        result = tmp_engine.enrich_ip(TEST_IP)
        for key in ("ip", "country_code", "asn", "isp", "is_tor", "is_vpn", "is_datacenter", "enriched_at"):
            assert key in result

    def test_enrich_ip_field_matches(self, tmp_engine):
        result = tmp_engine.enrich_ip("50.60.70.80")
        assert result["ip"] == "50.60.70.80"

    def test_enrich_invalid_ip_does_not_raise(self, tmp_engine):
        result = tmp_engine.enrich_ip("not_an_ip")
        assert result["ip"] == "not_an_ip"
        assert result["country_code"] is None


# ---------------------------------------------------------------------------
# Engine: get_ip_history
# ---------------------------------------------------------------------------


class TestGetIPHistory:
    def test_history_empty_for_unknown_ip(self, tmp_engine):
        result = tmp_engine.get_ip_history("9.9.9.9", ORG_A)
        assert result == []

    def test_history_records_after_record_ip(self, tmp_engine):
        tmp_engine.record_ip(TEST_IP, source="scanner", org_id=ORG_A)
        history = tmp_engine.get_ip_history(TEST_IP, ORG_A)
        assert len(history) >= 1

    def test_history_has_event_type(self, tmp_engine):
        tmp_engine.record_ip(TEST_IP, source="scanner", org_id=ORG_A)
        history = tmp_engine.get_ip_history(TEST_IP, ORG_A)
        assert all("event_type" in h for h in history)

    def test_history_isolates_orgs(self, tmp_engine):
        tmp_engine.record_ip(TEST_IP, source="scanner", org_id=ORG_A)
        history_b = tmp_engine.get_ip_history(TEST_IP, ORG_B)
        assert history_b == []


# ---------------------------------------------------------------------------
# Engine: bulk_check
# ---------------------------------------------------------------------------


class TestBulkCheck:
    def test_bulk_check_returns_list(self, tmp_engine):
        result = tmp_engine.bulk_check([TEST_IP, TEST_IP2], ORG_A)
        assert isinstance(result, list)
        assert len(result) == 2

    def test_bulk_check_all_ip_records(self, tmp_engine):
        result = tmp_engine.bulk_check([TEST_IP, TEST_IP2, TEST_IP3], ORG_A)
        assert all(isinstance(r, IPRecord) for r in result)

    def test_bulk_check_single_ip(self, tmp_engine):
        result = tmp_engine.bulk_check([TEST_IP], ORG_A)
        assert len(result) == 1
        assert result[0].ip_address == TEST_IP


# ---------------------------------------------------------------------------
# Engine: blocklist management
# ---------------------------------------------------------------------------


class TestBlocklistManagement:
    def test_add_to_blocklist_forces_blocklisted_level(self, tmp_engine):
        tmp_engine.add_to_blocklist(TEST_IP, reason="known bad actor", org_id=ORG_A)
        record = tmp_engine.get_ip(TEST_IP, ORG_A)
        assert record is not None
        assert record.level == ReputationLevel.BLOCKLISTED
        assert record.score == 100.0

    def test_remove_from_blocklist_rescores(self, tmp_engine):
        tmp_engine.add_to_blocklist(TEST_IP, reason="test", org_id=ORG_A)
        tmp_engine.remove_from_blocklist(TEST_IP, ORG_A)
        record = tmp_engine.get_ip(TEST_IP, ORG_A)
        assert record is not None
        # After removal, score should drop below 100
        assert record.score < 100.0

    def test_remove_nonexistent_blocklist_entry_no_error(self, tmp_engine):
        # Should not raise even if IP was never blocked
        tmp_engine.remove_from_blocklist("9.9.9.9", ORG_A)

    def test_blocklist_is_org_scoped(self, tmp_engine):
        tmp_engine.add_to_blocklist(TEST_IP, reason="org A block", org_id=ORG_A)
        record_b = tmp_engine.score_ip(TEST_IP, ORG_B)
        # ORG_B should not be affected by ORG_A's manual block
        assert record_b.level != ReputationLevel.BLOCKLISTED


# ---------------------------------------------------------------------------
# Engine: get_reputation_stats
# ---------------------------------------------------------------------------


class TestGetReputationStats:
    def test_stats_empty_org(self, tmp_engine):
        stats = tmp_engine.get_reputation_stats("org_empty_stats")
        assert stats["total_tracked"] == 0
        assert stats["average_score"] == 0.0

    def test_stats_counts_ips(self, tmp_engine):
        tmp_engine.record_ip(TEST_IP, source="s", org_id=ORG_A)
        tmp_engine.record_ip(TEST_IP2, source="s", org_id=ORG_A)
        stats = tmp_engine.get_reputation_stats(ORG_A)
        assert stats["total_tracked"] >= 2

    def test_stats_has_required_keys(self, tmp_engine):
        stats = tmp_engine.get_reputation_stats(ORG_A)
        for key in ("total_tracked", "by_level", "average_score", "manual_blocklist_count", "top_malicious"):
            assert key in stats

    def test_stats_by_level_has_all_levels(self, tmp_engine):
        stats = tmp_engine.get_reputation_stats(ORG_A)
        for level in ReputationLevel:
            assert level.value in stats["by_level"]

    def test_stats_blocklist_count(self, tmp_engine):
        tmp_engine.add_to_blocklist(TEST_IP, reason="test", org_id=ORG_A)
        stats = tmp_engine.get_reputation_stats(ORG_A)
        assert stats["manual_blocklist_count"] >= 1


# ---------------------------------------------------------------------------
# Engine: _calculate_score
# ---------------------------------------------------------------------------


class TestCalculateScore:
    def test_empty_factors_returns_zero(self, tmp_engine):
        assert tmp_engine._calculate_score([]) == 0.0

    def test_single_factor_full_score(self, tmp_engine):
        factors = [ReputationFactor(name="x", weight=1.0, value=80.0, source="test")]
        assert tmp_engine._calculate_score(factors) == pytest.approx(80.0)

    def test_weighted_average(self, tmp_engine):
        factors = [
            ReputationFactor(name="a", weight=0.5, value=100.0, source="s"),
            ReputationFactor(name="b", weight=0.5, value=0.0, source="s"),
        ]
        assert tmp_engine._calculate_score(factors) == pytest.approx(50.0)

    def test_score_clamped_to_100(self, tmp_engine):
        factors = [ReputationFactor(name="x", weight=1.0, value=100.0, source="test")]
        assert tmp_engine._calculate_score(factors) <= 100.0

    def test_score_clamped_to_zero(self, tmp_engine):
        factors = [ReputationFactor(name="x", weight=1.0, value=0.0, source="test")]
        assert tmp_engine._calculate_score(factors) >= 0.0
