"""
Tests for PassiveDNSEngine — historical DNS tracking, fast-flux detection,
domain reputation, and org isolation.
30+ tests covering all public methods.
"""
from __future__ import annotations

import pytest
from typing import Any, Dict


@pytest.fixture
def engine(tmp_path):
    from core.passive_dns_engine import PassiveDNSEngine
    return PassiveDNSEngine(db_path=str(tmp_path / "test.db"))


ORG = "org-passive-dns-test"
OTHER_ORG = "org-other"


def make_resolution(**kwargs) -> Dict[str, Any]:
    base = {
        "domain": "example.com",
        "resolved_ip": "1.2.3.4",
        "record_type": "A",
        "ttl": 3600,
        "source": "query",
    }
    base.update(kwargs)
    return base


def make_threat(**kwargs) -> Dict[str, Any]:
    base = {
        "domain": "evil.com",
        "threat_type": "c2",
        "confidence": 0.9,
        "source": "feed",
        "iocs": ["1.2.3.4"],
    }
    base.update(kwargs)
    return base


# ---------------------------------------------------------------------------
# Init / schema
# ---------------------------------------------------------------------------

class TestInit:
    def test_creates_db_file(self, tmp_path):
        from core.passive_dns_engine import PassiveDNSEngine
        db = str(tmp_path / "sub" / "dns.db")
        eng = PassiveDNSEngine(db_path=db)
        import os
        assert os.path.exists(db)

    def test_default_db_path_contains_passive_dns(self):
        from core.passive_dns_engine import _DEFAULT_DB
        assert "passive_dns" in _DEFAULT_DB


# ---------------------------------------------------------------------------
# record_resolution
# ---------------------------------------------------------------------------

class TestRecordResolution:
    def test_records_new_resolution(self, engine):
        r = engine.record_resolution(ORG, make_resolution())
        assert r["domain"] == "example.com"
        assert r["resolved_ip"] == "1.2.3.4"
        assert r["org_id"] == ORG

    def test_normalises_domain_to_lowercase(self, engine):
        r = engine.record_resolution(ORG, make_resolution(domain="EXAMPLE.COM"))
        assert r["domain"] == "example.com"

    def test_upserts_existing_pair(self, engine):
        r1 = engine.record_resolution(ORG, make_resolution(ttl=300))
        r2 = engine.record_resolution(ORG, make_resolution(ttl=600))
        assert r1["resolution_id"] == r2["resolution_id"]
        assert r2["ttl"] == 600

    def test_different_ips_are_separate_records(self, engine):
        engine.record_resolution(ORG, make_resolution(resolved_ip="1.1.1.1"))
        engine.record_resolution(ORG, make_resolution(resolved_ip="2.2.2.2"))
        history = engine.get_domain_history(ORG, "example.com")
        assert len(history) == 2

    def test_missing_domain_raises(self, engine):
        with pytest.raises(ValueError, match="domain"):
            engine.record_resolution(ORG, {"resolved_ip": "1.2.3.4"})

    def test_missing_ip_raises(self, engine):
        with pytest.raises(ValueError, match="resolved_ip"):
            engine.record_resolution(ORG, {"domain": "example.com"})

    def test_invalid_record_type_raises(self, engine):
        with pytest.raises(ValueError, match="record_type"):
            engine.record_resolution(ORG, make_resolution(record_type="BOGUS"))

    def test_invalid_source_raises(self, engine):
        with pytest.raises(ValueError, match="source"):
            engine.record_resolution(ORG, make_resolution(source="unknown"))

    def test_all_valid_record_types(self, engine):
        for rtype in ["A", "AAAA", "MX", "NS", "CNAME", "TXT"]:
            r = engine.record_resolution(
                ORG, make_resolution(domain=f"test-{rtype}.com", record_type=rtype)
            )
            assert r["record_type"] == rtype

    def test_all_valid_sources(self, engine):
        for src in ["sensor", "feed", "query"]:
            r = engine.record_resolution(
                ORG, make_resolution(domain=f"test-{src}.com", source=src)
            )
            assert r["source"] == src


# ---------------------------------------------------------------------------
# list_resolutions
# ---------------------------------------------------------------------------

class TestListResolutions:
    def test_returns_all_for_org(self, engine):
        engine.record_resolution(ORG, make_resolution(domain="a.com", resolved_ip="1.1.1.1"))
        engine.record_resolution(ORG, make_resolution(domain="b.com", resolved_ip="2.2.2.2"))
        results = engine.list_resolutions(ORG)
        assert len(results) == 2

    def test_filters_by_domain(self, engine):
        engine.record_resolution(ORG, make_resolution(domain="a.com", resolved_ip="1.1.1.1"))
        engine.record_resolution(ORG, make_resolution(domain="b.com", resolved_ip="2.2.2.2"))
        results = engine.list_resolutions(ORG, domain="a.com")
        assert all(r["domain"] == "a.com" for r in results)

    def test_filters_by_ip(self, engine):
        engine.record_resolution(ORG, make_resolution(domain="a.com", resolved_ip="1.1.1.1"))
        engine.record_resolution(ORG, make_resolution(domain="b.com", resolved_ip="2.2.2.2"))
        results = engine.list_resolutions(ORG, resolved_ip="1.1.1.1")
        assert all(r["resolved_ip"] == "1.1.1.1" for r in results)

    def test_respects_limit(self, engine):
        for i in range(10):
            engine.record_resolution(ORG, make_resolution(domain=f"d{i}.com", resolved_ip="1.1.1.1"))
        results = engine.list_resolutions(ORG, limit=5)
        assert len(results) <= 5


# ---------------------------------------------------------------------------
# get_domain_history
# ---------------------------------------------------------------------------

class TestDomainHistory:
    def test_returns_all_ips_for_domain(self, engine):
        engine.record_resolution(ORG, make_resolution(resolved_ip="1.1.1.1"))
        engine.record_resolution(ORG, make_resolution(resolved_ip="2.2.2.2"))
        engine.record_resolution(ORG, make_resolution(resolved_ip="3.3.3.3"))
        history = engine.get_domain_history(ORG, "example.com")
        assert len(history) == 3

    def test_ordered_by_last_seen_desc(self, engine):
        engine.record_resolution(ORG, make_resolution(
            resolved_ip="1.1.1.1", last_seen="2024-01-01T00:00:00+00:00"
        ))
        engine.record_resolution(ORG, make_resolution(
            resolved_ip="2.2.2.2", last_seen="2024-06-01T00:00:00+00:00"
        ))
        history = engine.get_domain_history(ORG, "example.com")
        assert history[0]["resolved_ip"] == "2.2.2.2"

    def test_empty_for_unknown_domain(self, engine):
        assert engine.get_domain_history(ORG, "unknown.com") == []


# ---------------------------------------------------------------------------
# get_ip_history
# ---------------------------------------------------------------------------

class TestIPHistory:
    def test_returns_all_domains_for_ip(self, engine):
        engine.record_resolution(ORG, make_resolution(domain="a.com", resolved_ip="10.0.0.1"))
        engine.record_resolution(ORG, make_resolution(domain="b.com", resolved_ip="10.0.0.1"))
        history = engine.get_ip_history(ORG, "10.0.0.1")
        domains = {r["domain"] for r in history}
        assert {"a.com", "b.com"} == domains

    def test_empty_for_unknown_ip(self, engine):
        assert engine.get_ip_history(ORG, "99.99.99.99") == []


# ---------------------------------------------------------------------------
# detect_fast_flux
# ---------------------------------------------------------------------------

class TestDetectFastFlux:
    def test_returns_dict_with_expected_keys(self, engine):
        engine.record_resolution(ORG, make_resolution())
        result = engine.detect_fast_flux(ORG, "example.com")
        assert "is_fast_flux" in result
        assert "distinct_ips" in result
        assert "avg_ttl" in result
        assert "reason" in result

    def test_not_fast_flux_for_single_ip(self, engine):
        engine.record_resolution(ORG, make_resolution(ttl=3600))
        result = engine.detect_fast_flux(ORG, "example.com")
        assert result["is_fast_flux"] is False

    def test_fast_flux_detected_for_many_distinct_ips(self, engine):
        for i in range(6):
            engine.record_resolution(
                ORG, make_resolution(resolved_ip=f"10.0.0.{i+1}", ttl=3600)
            )
        result = engine.detect_fast_flux(ORG, "example.com")
        assert result["is_fast_flux"] is True
        assert result["distinct_ips"] == 6

    def test_fast_flux_detected_for_low_ttl(self, engine):
        engine.record_resolution(ORG, make_resolution(resolved_ip="1.1.1.1", ttl=60))
        result = engine.detect_fast_flux(ORG, "example.com")
        assert result["is_fast_flux"] is True

    def test_no_data_returns_false(self, engine):
        result = engine.detect_fast_flux(ORG, "nodata.com")
        assert result["is_fast_flux"] is False
        assert result["distinct_ips"] == 0


# ---------------------------------------------------------------------------
# add_domain_threat / list_domain_threats
# ---------------------------------------------------------------------------

class TestDomainThreats:
    def test_add_threat_returns_record(self, engine):
        r = engine.add_domain_threat(ORG, make_threat())
        assert r["domain"] == "evil.com"
        assert r["threat_type"] == "c2"
        assert r["confidence"] == 0.9
        assert isinstance(r["iocs"], list)

    def test_invalid_threat_type_raises(self, engine):
        with pytest.raises(ValueError, match="threat_type"):
            engine.add_domain_threat(ORG, make_threat(threat_type="unknown"))

    def test_confidence_out_of_range_raises(self, engine):
        with pytest.raises(ValueError, match="confidence"):
            engine.add_domain_threat(ORG, make_threat(confidence=1.5))

    def test_missing_domain_raises(self, engine):
        with pytest.raises(ValueError, match="domain"):
            engine.add_domain_threat(ORG, {"threat_type": "c2"})

    def test_list_all_threats(self, engine):
        engine.add_domain_threat(ORG, make_threat(domain="a.com", threat_type="c2"))
        engine.add_domain_threat(ORG, make_threat(domain="b.com", threat_type="phishing"))
        results = engine.list_domain_threats(ORG)
        assert len(results) == 2

    def test_filter_by_threat_type(self, engine):
        engine.add_domain_threat(ORG, make_threat(domain="a.com", threat_type="c2"))
        engine.add_domain_threat(ORG, make_threat(domain="b.com", threat_type="phishing"))
        results = engine.list_domain_threats(ORG, threat_type="c2")
        assert all(r["threat_type"] == "c2" for r in results)

    def test_filter_by_min_confidence(self, engine):
        engine.add_domain_threat(ORG, make_threat(domain="a.com", confidence=0.3))
        engine.add_domain_threat(ORG, make_threat(domain="b.com", confidence=0.8))
        results = engine.list_domain_threats(ORG, min_confidence=0.7)
        assert all(r["confidence"] >= 0.7 for r in results)

    def test_all_valid_threat_types(self, engine):
        for ttype in ["c2", "phishing", "malware", "spam", "botnet"]:
            r = engine.add_domain_threat(
                ORG, make_threat(domain=f"{ttype}.evil.com", threat_type=ttype)
            )
            assert r["threat_type"] == ttype


# ---------------------------------------------------------------------------
# check_domain_reputation
# ---------------------------------------------------------------------------

class TestDomainReputation:
    def test_clean_domain_not_malicious(self, engine):
        engine.record_resolution(ORG, make_resolution(domain="clean.com"))
        rep = engine.check_domain_reputation(ORG, "clean.com")
        assert rep["is_malicious"] is False
        assert rep["threat_types"] == []
        assert rep["confidence"] == 0.0

    def test_malicious_domain_detected(self, engine):
        engine.add_domain_threat(ORG, make_threat(domain="evil.com", threat_type="malware", confidence=0.95))
        rep = engine.check_domain_reputation(ORG, "evil.com")
        assert rep["is_malicious"] is True
        assert "malware" in rep["threat_types"]
        assert rep["confidence"] == 0.95

    def test_includes_resolution_count(self, engine):
        engine.record_resolution(ORG, make_resolution(domain="example.com", resolved_ip="1.1.1.1"))
        engine.record_resolution(ORG, make_resolution(domain="example.com", resolved_ip="2.2.2.2"))
        rep = engine.check_domain_reputation(ORG, "example.com")
        assert rep["resolutions_count"] == 2

    def test_unknown_domain_returns_safe(self, engine):
        rep = engine.check_domain_reputation(ORG, "unknown.example.com")
        assert rep["is_malicious"] is False
        assert rep["resolutions_count"] == 0


# ---------------------------------------------------------------------------
# get_dns_stats
# ---------------------------------------------------------------------------

class TestDNSStats:
    def test_stats_keys_present(self, engine):
        stats = engine.get_dns_stats(ORG)
        assert "total_resolutions" in stats
        assert "unique_domains" in stats
        assert "unique_ips" in stats
        assert "threat_domains" in stats
        assert "fast_flux_detected" in stats
        assert "queries_24h" in stats

    def test_stats_empty_org(self, engine):
        stats = engine.get_dns_stats(ORG)
        assert stats["total_resolutions"] == 0
        assert stats["unique_domains"] == 0

    def test_stats_counts_correctly(self, engine):
        engine.record_resolution(ORG, make_resolution(domain="a.com", resolved_ip="1.1.1.1"))
        engine.record_resolution(ORG, make_resolution(domain="b.com", resolved_ip="2.2.2.2"))
        engine.add_domain_threat(ORG, make_threat(domain="a.com"))
        stats = engine.get_dns_stats(ORG)
        assert stats["total_resolutions"] == 2
        assert stats["unique_domains"] == 2
        assert stats["threat_domains"] == 1

    def test_fast_flux_counted_in_stats(self, engine):
        for i in range(6):
            engine.record_resolution(
                ORG, make_resolution(resolved_ip=f"10.0.0.{i+1}", ttl=3600)
            )
        stats = engine.get_dns_stats(ORG)
        assert stats["fast_flux_detected"] >= 1


# ---------------------------------------------------------------------------
# Org isolation
# ---------------------------------------------------------------------------

class TestOrgIsolation:
    def test_resolutions_isolated_by_org(self, engine):
        engine.record_resolution(ORG, make_resolution(domain="a.com", resolved_ip="1.1.1.1"))
        engine.record_resolution(OTHER_ORG, make_resolution(domain="b.com", resolved_ip="2.2.2.2"))
        org_results = engine.list_resolutions(ORG)
        assert all(r["org_id"] == ORG for r in org_results)

    def test_threats_isolated_by_org(self, engine):
        engine.add_domain_threat(ORG, make_threat(domain="evil.com"))
        engine.add_domain_threat(OTHER_ORG, make_threat(domain="evil.com"))
        org_threats = engine.list_domain_threats(ORG)
        assert all(r["org_id"] == ORG for r in org_threats)

    def test_reputation_check_isolated(self, engine):
        engine.add_domain_threat(ORG, make_threat(domain="evil.com"))
        rep = engine.check_domain_reputation(OTHER_ORG, "evil.com")
        assert rep["is_malicious"] is False

    def test_stats_isolated_by_org(self, engine):
        engine.record_resolution(ORG, make_resolution(domain="a.com", resolved_ip="1.1.1.1"))
        stats_other = engine.get_dns_stats(OTHER_ORG)
        assert stats_other["total_resolutions"] == 0
