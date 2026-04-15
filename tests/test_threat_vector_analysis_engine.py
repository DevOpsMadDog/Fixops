"""Tests for ThreatVectorAnalysisEngine.

Covers vector recording, filtering, org isolation, indicator management,
mitigation lifecycle, counter increments, and aggregate stats.

Total: 35 tests.
"""

from __future__ import annotations

import os
import pytest
from core.threat_vector_analysis_engine import ThreatVectorAnalysisEngine


@pytest.fixture()
def engine(tmp_path):
    db = str(tmp_path / "tva_test.db")
    return ThreatVectorAnalysisEngine(db_path=db)


@pytest.fixture()
def network_vector(engine):
    return engine.record_vector("org1", {
        "name": "Lateral movement via RDP",
        "vector_type": "network",
        "severity": "high",
        "frequency_score": 70,
        "impact_score": 80,
    })


@pytest.fixture()
def email_vector(engine):
    return engine.record_vector("org1", {
        "name": "Spear phishing campaign",
        "vector_type": "email",
        "severity": "critical",
        "frequency_score": 90,
        "impact_score": 95,
    })


# ===========================================================================
# 1. Initialization
# ===========================================================================

def test_init_creates_db(tmp_path):
    db = str(tmp_path / "tva_init.db")
    ThreatVectorAnalysisEngine(db_path=db)
    assert os.path.exists(db)


def test_init_idempotent(tmp_path):
    db = str(tmp_path / "tva_idem.db")
    ThreatVectorAnalysisEngine(db_path=db)
    ThreatVectorAnalysisEngine(db_path=db)  # no error on second init


# ===========================================================================
# 2. record_vector — happy path
# ===========================================================================

def test_record_vector_returns_record(network_vector):
    assert network_vector["id"]
    assert network_vector["name"] == "Lateral movement via RDP"
    assert network_vector["vector_type"] == "network"
    assert network_vector["severity"] == "high"
    assert network_vector["status"] == "active"


def test_record_vector_risk_score_computed(network_vector):
    # risk_score = (70 + 80) / 2 = 75
    assert network_vector["risk_score"] == pytest.approx(75.0)


def test_record_vector_defaults_frequency_impact(engine):
    v = engine.record_vector("org1", {"name": "X", "vector_type": "insider", "severity": "low"})
    assert v["frequency_score"] == pytest.approx(50.0)
    assert v["impact_score"] == pytest.approx(50.0)
    assert v["risk_score"] == pytest.approx(50.0)


def test_record_vector_initial_counts_zero(network_vector):
    assert network_vector["indicator_count"] == 0
    assert network_vector["mitigation_count"] == 0


def test_record_vector_all_vector_types(engine):
    types = [
        "network", "email", "supply_chain", "insider",
        "physical", "social_engineering", "zero_day", "credential_stuffing",
    ]
    for vt in types:
        v = engine.record_vector("org1", {"name": f"vec_{vt}", "vector_type": vt, "severity": "low"})
        assert v["vector_type"] == vt


# ===========================================================================
# 3. record_vector — validation
# ===========================================================================

def test_record_vector_missing_name_raises(engine):
    with pytest.raises(ValueError, match="name"):
        engine.record_vector("org1", {"vector_type": "network", "severity": "low"})


def test_record_vector_invalid_vector_type_raises(engine):
    with pytest.raises(ValueError, match="vector_type"):
        engine.record_vector("org1", {"name": "X", "vector_type": "wifi", "severity": "low"})


def test_record_vector_invalid_severity_raises(engine):
    with pytest.raises(ValueError, match="severity"):
        engine.record_vector("org1", {"name": "X", "vector_type": "network", "severity": "extreme"})


# ===========================================================================
# 4. list_vectors / get_vector
# ===========================================================================

def test_list_vectors_returns_all(engine, network_vector, email_vector):
    vectors = engine.list_vectors("org1")
    assert len(vectors) == 2


def test_list_vectors_filter_by_type(engine, network_vector, email_vector):
    result = engine.list_vectors("org1", vector_type="email")
    assert len(result) == 1
    assert result[0]["vector_type"] == "email"


def test_list_vectors_filter_by_severity(engine, network_vector, email_vector):
    result = engine.list_vectors("org1", severity="critical")
    assert len(result) == 1
    assert result[0]["severity"] == "critical"


def test_get_vector_returns_record(engine, network_vector):
    fetched = engine.get_vector("org1", network_vector["id"])
    assert fetched["id"] == network_vector["id"]


def test_get_vector_returns_none_for_missing(engine):
    assert engine.get_vector("org1", "nonexistent-id") is None


# ===========================================================================
# 5. Org isolation
# ===========================================================================

def test_org_isolation_vectors(engine, network_vector):
    # org2 should not see org1's vector
    assert engine.list_vectors("org2") == []
    assert engine.get_vector("org2", network_vector["id"]) is None


def test_org_isolation_indicators(engine, network_vector):
    engine.add_indicator("org1", network_vector["id"], {
        "indicator_type": "ip", "value": "1.2.3.4"
    })
    assert engine.list_indicators("org2") == []


def test_org_isolation_mitigations(engine, network_vector):
    engine.create_mitigation("org1", network_vector["id"], {"title": "Patch RDP"})
    assert engine.list_mitigations("org2") == []


# ===========================================================================
# 6. add_indicator
# ===========================================================================

def test_add_indicator_returns_record(engine, network_vector):
    ind = engine.add_indicator("org1", network_vector["id"], {
        "indicator_type": "ip",
        "value": "192.168.1.100",
        "confidence": 85,
        "source": "threat_feed",
    })
    assert ind["id"]
    assert ind["indicator_type"] == "ip"
    assert ind["value"] == "192.168.1.100"
    assert ind["confidence"] == pytest.approx(85.0)


def test_add_indicator_increments_count(engine, network_vector):
    engine.add_indicator("org1", network_vector["id"], {"indicator_type": "ip", "value": "1.2.3.4"})
    engine.add_indicator("org1", network_vector["id"], {"indicator_type": "domain", "value": "evil.com"})
    updated = engine.get_vector("org1", network_vector["id"])
    assert updated["indicator_count"] == 2


def test_add_indicator_invalid_type_raises(engine, network_vector):
    with pytest.raises(ValueError, match="indicator_type"):
        engine.add_indicator("org1", network_vector["id"], {
            "indicator_type": "certificate", "value": "abc"
        })


def test_add_indicator_missing_value_raises(engine, network_vector):
    with pytest.raises(ValueError, match="value"):
        engine.add_indicator("org1", network_vector["id"], {"indicator_type": "ip"})


def test_add_indicator_all_types(engine, network_vector):
    for itype in ["ip", "domain", "url", "hash", "email", "file"]:
        ind = engine.add_indicator("org1", network_vector["id"], {
            "indicator_type": itype,
            "value": f"test_{itype}",
        })
        assert ind["indicator_type"] == itype


# ===========================================================================
# 7. list_indicators
# ===========================================================================

def test_list_indicators_filter_by_vector(engine, network_vector, email_vector):
    engine.add_indicator("org1", network_vector["id"], {"indicator_type": "ip", "value": "1.1.1.1"})
    engine.add_indicator("org1", email_vector["id"], {"indicator_type": "domain", "value": "bad.com"})
    result = engine.list_indicators("org1", vector_id=network_vector["id"])
    assert len(result) == 1
    assert result[0]["value"] == "1.1.1.1"


def test_list_indicators_filter_by_type(engine, network_vector):
    engine.add_indicator("org1", network_vector["id"], {"indicator_type": "ip", "value": "1.1.1.1"})
    engine.add_indicator("org1", network_vector["id"], {"indicator_type": "hash", "value": "abc123"})
    result = engine.list_indicators("org1", indicator_type="hash")
    assert all(r["indicator_type"] == "hash" for r in result)


# ===========================================================================
# 8. create_mitigation
# ===========================================================================

def test_create_mitigation_returns_record(engine, network_vector):
    mit = engine.create_mitigation("org1", network_vector["id"], {
        "title": "Apply network segmentation",
        "mitigation_status": "planned",
        "assigned_to": "alice",
    })
    assert mit["id"]
    assert mit["title"] == "Apply network segmentation"
    assert mit["mitigation_status"] == "planned"


def test_create_mitigation_increments_count(engine, network_vector):
    engine.create_mitigation("org1", network_vector["id"], {"title": "M1"})
    engine.create_mitigation("org1", network_vector["id"], {"title": "M2"})
    updated = engine.get_vector("org1", network_vector["id"])
    assert updated["mitigation_count"] == 2


def test_create_mitigation_missing_title_raises(engine, network_vector):
    with pytest.raises(ValueError, match="title"):
        engine.create_mitigation("org1", network_vector["id"], {})


def test_create_mitigation_invalid_status_raises(engine, network_vector):
    with pytest.raises(ValueError, match="mitigation_status"):
        engine.create_mitigation("org1", network_vector["id"], {
            "title": "X", "mitigation_status": "abandoned"
        })


def test_create_mitigation_all_statuses(engine, network_vector):
    for status in ["planned", "in_progress", "completed", "deferred"]:
        mit = engine.create_mitigation("org1", network_vector["id"], {
            "title": f"mit_{status}",
            "mitigation_status": status,
        })
        assert mit["mitigation_status"] == status


# ===========================================================================
# 9. list_mitigations
# ===========================================================================

def test_list_mitigations_filter_by_vector(engine, network_vector, email_vector):
    engine.create_mitigation("org1", network_vector["id"], {"title": "M-net"})
    engine.create_mitigation("org1", email_vector["id"], {"title": "M-email"})
    result = engine.list_mitigations("org1", vector_id=network_vector["id"])
    assert len(result) == 1
    assert result[0]["title"] == "M-net"


def test_list_mitigations_filter_by_status(engine, network_vector):
    engine.create_mitigation("org1", network_vector["id"], {
        "title": "M1", "mitigation_status": "completed"
    })
    engine.create_mitigation("org1", network_vector["id"], {
        "title": "M2", "mitigation_status": "planned"
    })
    result = engine.list_mitigations("org1", mitigation_status="completed")
    assert all(r["mitigation_status"] == "completed" for r in result)


# ===========================================================================
# 10. get_vector_stats
# ===========================================================================

def test_get_vector_stats_empty(engine):
    stats = engine.get_vector_stats("org1")
    assert stats["total_vectors"] == 0
    assert stats["active_vectors"] == 0
    assert stats["critical_vectors"] == 0
    assert stats["total_indicators"] == 0
    assert stats["open_mitigations"] == 0
    assert stats["avg_risk_score"] == pytest.approx(0.0)
    assert stats["by_vector_type"] == {}


def test_get_vector_stats_counts(engine, network_vector, email_vector):
    engine.add_indicator("org1", network_vector["id"], {"indicator_type": "ip", "value": "1.1.1.1"})
    engine.add_indicator("org1", email_vector["id"], {"indicator_type": "domain", "value": "bad.com"})
    engine.create_mitigation("org1", network_vector["id"], {
        "title": "M1", "mitigation_status": "planned"
    })
    engine.create_mitigation("org1", email_vector["id"], {
        "title": "M2", "mitigation_status": "in_progress"
    })
    engine.create_mitigation("org1", network_vector["id"], {
        "title": "M3", "mitigation_status": "completed"
    })

    stats = engine.get_vector_stats("org1")
    assert stats["total_vectors"] == 2
    assert stats["active_vectors"] == 2
    assert stats["critical_vectors"] == 1  # only email_vector is critical
    assert stats["total_indicators"] == 2
    assert stats["open_mitigations"] == 2  # planned + in_progress
    assert stats["by_vector_type"] == {"network": 1, "email": 1}


def test_get_vector_stats_avg_risk_score(engine):
    engine.record_vector("org1", {
        "name": "V1", "vector_type": "network", "severity": "high",
        "frequency_score": 40, "impact_score": 60,  # risk = 50
    })
    engine.record_vector("org1", {
        "name": "V2", "vector_type": "email", "severity": "low",
        "frequency_score": 20, "impact_score": 80,  # risk = 50
    })
    stats = engine.get_vector_stats("org1")
    assert stats["avg_risk_score"] == pytest.approx(50.0)


def test_get_vector_stats_org_isolation(engine, network_vector):
    stats = engine.get_vector_stats("org2")
    assert stats["total_vectors"] == 0
