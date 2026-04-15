"""Tests for ThirdPartyVendorEngine — 30+ tests covering all major paths."""

from __future__ import annotations

import pytest


@pytest.fixture
def engine(tmp_path):
    from core.third_party_vendor_engine import ThirdPartyVendorEngine
    return ThirdPartyVendorEngine(db_path=str(tmp_path / "tpv.db"))


ORG = "test-org-tpv"
ORG2 = "other-org-tpv"


# ---------------------------------------------------------------------------
# Vendor registration
# ---------------------------------------------------------------------------

def test_register_vendor_basic(engine):
    vendor = engine.register_vendor(ORG, {
        "name": "Acme Corp",
        "vendor_category": "software",
    })
    assert vendor["id"]
    assert vendor["name"] == "Acme Corp"
    assert vendor["vendor_category"] == "software"
    assert vendor["org_id"] == ORG
    assert vendor["risk_rating"] == "unrated"
    assert vendor["risk_score"] == 50.0
    assert vendor["last_assessed"] is None
    assert vendor["contract_status"] == "active"


def test_register_vendor_all_categories(engine):
    for cat in ("software", "hardware", "services", "cloud", "consulting", "staffing", "logistics"):
        v = engine.register_vendor(ORG, {"name": f"V-{cat}", "vendor_category": cat})
        assert v["vendor_category"] == cat


def test_register_vendor_missing_name(engine):
    with pytest.raises(ValueError, match="name"):
        engine.register_vendor(ORG, {"vendor_category": "software"})


def test_register_vendor_empty_name(engine):
    with pytest.raises(ValueError, match="name"):
        engine.register_vendor(ORG, {"name": "", "vendor_category": "software"})


def test_register_vendor_invalid_category(engine):
    with pytest.raises(ValueError):
        engine.register_vendor(ORG, {"name": "X", "vendor_category": "transportation"})


def test_register_vendor_with_all_fields(engine):
    vendor = engine.register_vendor(ORG, {
        "name": "Full Vendor",
        "vendor_category": "cloud",
        "website": "https://example.com",
        "primary_contact": "jane@example.com",
        "data_access_level": "confidential",
        "contract_status": "under_review",
    })
    assert vendor["website"] == "https://example.com"
    assert vendor["primary_contact"] == "jane@example.com"
    assert vendor["data_access_level"] == "confidential"
    assert vendor["contract_status"] == "under_review"


# ---------------------------------------------------------------------------
# Vendor list / get
# ---------------------------------------------------------------------------

def test_list_vendors_empty(engine):
    assert engine.list_vendors(ORG) == []


def test_list_vendors_multiple(engine):
    engine.register_vendor(ORG, {"name": "A", "vendor_category": "software"})
    engine.register_vendor(ORG, {"name": "B", "vendor_category": "cloud"})
    assert len(engine.list_vendors(ORG)) == 2


def test_list_vendors_filter_category(engine):
    engine.register_vendor(ORG, {"name": "Soft", "vendor_category": "software"})
    engine.register_vendor(ORG, {"name": "Cloud", "vendor_category": "cloud"})
    soft = engine.list_vendors(ORG, vendor_category="software")
    assert len(soft) == 1
    assert soft[0]["vendor_category"] == "software"


def test_list_vendors_filter_contract_status(engine):
    engine.register_vendor(ORG, {"name": "Active", "vendor_category": "software", "contract_status": "active"})
    engine.register_vendor(ORG, {"name": "Expired", "vendor_category": "software", "contract_status": "expired"})
    active = engine.list_vendors(ORG, contract_status="active")
    assert len(active) == 1
    assert active[0]["contract_status"] == "active"


def test_list_vendors_org_isolation(engine):
    engine.register_vendor(ORG, {"name": "A", "vendor_category": "software"})
    assert engine.list_vendors(ORG2) == []


def test_get_vendor_found(engine):
    vendor = engine.register_vendor(ORG, {"name": "Found", "vendor_category": "services"})
    result = engine.get_vendor(ORG, vendor["id"])
    assert result is not None
    assert result["id"] == vendor["id"]
    assert result["name"] == "Found"


def test_get_vendor_not_found(engine):
    assert engine.get_vendor(ORG, "nonexistent-id") is None


def test_get_vendor_wrong_org(engine):
    vendor = engine.register_vendor(ORG, {"name": "Secret", "vendor_category": "cloud"})
    assert engine.get_vendor(ORG2, vendor["id"]) is None


# ---------------------------------------------------------------------------
# Assessments — risk_score recalculation and risk_rating auto-update
# ---------------------------------------------------------------------------

def test_conduct_assessment_basic(engine):
    vendor = engine.register_vendor(ORG, {"name": "V", "vendor_category": "software"})
    assessment = engine.conduct_assessment(ORG, vendor["id"], {
        "assessment_type": "security_questionnaire",
        "assessor": "Alice",
        "score": 80.0,
        "findings_count": 3,
        "critical_findings": 0,
        "passed": True,
    })
    assert assessment["id"]
    assert assessment["vendor_id"] == vendor["id"]
    assert assessment["assessment_type"] == "security_questionnaire"
    assert assessment["score"] == 80.0
    assert assessment["assessor"] == "Alice"
    assert assessment["passed"] == 1


def test_conduct_assessment_updates_last_assessed(engine):
    vendor = engine.register_vendor(ORG, {"name": "V", "vendor_category": "software"})
    assert vendor["last_assessed"] is None
    engine.conduct_assessment(ORG, vendor["id"], {
        "assessment_type": "audit",
        "score": 70.0,
        "findings_count": 2,
        "critical_findings": 0,
        "passed": True,
    })
    updated = engine.get_vendor(ORG, vendor["id"])
    assert updated["last_assessed"] is not None


def test_conduct_assessment_risk_score_recalculation(engine):
    """risk_score = 100 - score + (critical_findings * 10), clamped 0-100."""
    vendor = engine.register_vendor(ORG, {"name": "V", "vendor_category": "software"})
    # score=80, critical_findings=1 → 100 - 80 + 10 = 30
    engine.conduct_assessment(ORG, vendor["id"], {
        "assessment_type": "penetration_test",
        "score": 80.0,
        "findings_count": 5,
        "critical_findings": 1,
        "passed": True,
    })
    updated = engine.get_vendor(ORG, vendor["id"])
    assert updated["risk_score"] == pytest.approx(30.0)


def test_conduct_assessment_risk_score_clamped_min(engine):
    """score=100, critical_findings=0 → raw=-0 → clamped to 0."""
    vendor = engine.register_vendor(ORG, {"name": "V", "vendor_category": "cloud"})
    engine.conduct_assessment(ORG, vendor["id"], {
        "assessment_type": "audit",
        "score": 100.0,
        "findings_count": 0,
        "critical_findings": 0,
        "passed": True,
    })
    updated = engine.get_vendor(ORG, vendor["id"])
    assert updated["risk_score"] == pytest.approx(0.0)


def test_conduct_assessment_risk_score_clamped_max(engine):
    """score=0, critical_findings=10 → 100 + 100 = 200 → clamped to 100."""
    vendor = engine.register_vendor(ORG, {"name": "V", "vendor_category": "cloud"})
    engine.conduct_assessment(ORG, vendor["id"], {
        "assessment_type": "security_questionnaire",
        "score": 0.0,
        "findings_count": 20,
        "critical_findings": 10,
        "passed": False,
    })
    updated = engine.get_vendor(ORG, vendor["id"])
    assert updated["risk_score"] == pytest.approx(100.0)


def test_conduct_assessment_risk_rating_low(engine):
    """risk_score <= 25 → low."""
    vendor = engine.register_vendor(ORG, {"name": "V", "vendor_category": "software"})
    engine.conduct_assessment(ORG, vendor["id"], {
        "assessment_type": "audit",
        "score": 90.0,  # 100 - 90 = 10 → low
        "findings_count": 1,
        "critical_findings": 0,
        "passed": True,
    })
    updated = engine.get_vendor(ORG, vendor["id"])
    assert updated["risk_rating"] == "low"
    assert updated["risk_score"] == pytest.approx(10.0)


def test_conduct_assessment_risk_rating_medium(engine):
    """26 <= risk_score <= 50 → medium."""
    vendor = engine.register_vendor(ORG, {"name": "V", "vendor_category": "software"})
    engine.conduct_assessment(ORG, vendor["id"], {
        "assessment_type": "self_attestation",
        "score": 70.0,  # 100 - 70 = 30 → medium
        "findings_count": 0,
        "critical_findings": 0,
        "passed": True,
    })
    updated = engine.get_vendor(ORG, vendor["id"])
    assert updated["risk_rating"] == "medium"
    assert updated["risk_score"] == pytest.approx(30.0)


def test_conduct_assessment_risk_rating_high(engine):
    """51 <= risk_score <= 75 → high."""
    vendor = engine.register_vendor(ORG, {"name": "V", "vendor_category": "software"})
    engine.conduct_assessment(ORG, vendor["id"], {
        "assessment_type": "third_party_audit",
        "score": 40.0,  # 100 - 40 = 60 → high
        "findings_count": 5,
        "critical_findings": 0,
        "passed": False,
    })
    updated = engine.get_vendor(ORG, vendor["id"])
    assert updated["risk_rating"] == "high"
    assert updated["risk_score"] == pytest.approx(60.0)


def test_conduct_assessment_risk_rating_critical(engine):
    """risk_score > 75 → critical."""
    vendor = engine.register_vendor(ORG, {"name": "V", "vendor_category": "software"})
    engine.conduct_assessment(ORG, vendor["id"], {
        "assessment_type": "penetration_test",
        "score": 10.0,  # 100 - 10 = 90 → critical
        "findings_count": 10,
        "critical_findings": 0,
        "passed": False,
    })
    updated = engine.get_vendor(ORG, vendor["id"])
    assert updated["risk_rating"] == "critical"
    assert updated["risk_score"] == pytest.approx(90.0)


def test_conduct_assessment_all_types(engine):
    vendor = engine.register_vendor(ORG, {"name": "V", "vendor_category": "services"})
    for atype in ("security_questionnaire", "penetration_test", "audit", "self_attestation", "third_party_audit"):
        a = engine.conduct_assessment(ORG, vendor["id"], {
            "assessment_type": atype,
            "score": 50.0,
            "findings_count": 0,
            "critical_findings": 0,
            "passed": True,
        })
        assert a["assessment_type"] == atype


def test_conduct_assessment_invalid_type(engine):
    vendor = engine.register_vendor(ORG, {"name": "V", "vendor_category": "software"})
    with pytest.raises(ValueError):
        engine.conduct_assessment(ORG, vendor["id"], {"assessment_type": "unknown_type"})


def test_list_assessments_filter(engine):
    v1 = engine.register_vendor(ORG, {"name": "V1", "vendor_category": "cloud"})
    v2 = engine.register_vendor(ORG, {"name": "V2", "vendor_category": "software"})
    engine.conduct_assessment(ORG, v1["id"], {"assessment_type": "audit", "score": 80.0})
    engine.conduct_assessment(ORG, v2["id"], {"assessment_type": "security_questionnaire", "score": 60.0})

    v1_assessments = engine.list_assessments(ORG, vendor_id=v1["id"])
    assert len(v1_assessments) == 1

    audits = engine.list_assessments(ORG, assessment_type="audit")
    assert len(audits) == 1
    assert audits[0]["assessment_type"] == "audit"


# ---------------------------------------------------------------------------
# Incidents
# ---------------------------------------------------------------------------

def test_add_incident_basic(engine):
    vendor = engine.register_vendor(ORG, {"name": "V", "vendor_category": "cloud"})
    incident = engine.add_incident(ORG, vendor["id"], {
        "title": "Data Breach",
        "severity": "critical",
        "description": "Vendor exposed customer data",
        "impact": "High impact on confidentiality",
    })
    assert incident["id"]
    assert incident["vendor_id"] == vendor["id"]
    assert incident["title"] == "Data Breach"
    assert incident["severity"] == "critical"
    assert incident["status"] == "open"
    assert incident["reported_at"] is not None
    assert incident["resolved_at"] is None


def test_list_incidents_filter_by_vendor(engine):
    v1 = engine.register_vendor(ORG, {"name": "V1", "vendor_category": "software"})
    v2 = engine.register_vendor(ORG, {"name": "V2", "vendor_category": "cloud"})
    engine.add_incident(ORG, v1["id"], {"title": "Incident 1", "severity": "high"})
    engine.add_incident(ORG, v2["id"], {"title": "Incident 2", "severity": "low"})

    v1_incidents = engine.list_incidents(ORG, vendor_id=v1["id"])
    assert len(v1_incidents) == 1
    assert v1_incidents[0]["vendor_id"] == v1["id"]


def test_list_incidents_filter_by_severity(engine):
    vendor = engine.register_vendor(ORG, {"name": "V", "vendor_category": "services"})
    engine.add_incident(ORG, vendor["id"], {"title": "Critical Issue", "severity": "critical"})
    engine.add_incident(ORG, vendor["id"], {"title": "Low Issue", "severity": "low"})

    crits = engine.list_incidents(ORG, severity="critical")
    assert len(crits) == 1
    assert crits[0]["severity"] == "critical"


def test_list_incidents_filter_by_status(engine):
    vendor = engine.register_vendor(ORG, {"name": "V", "vendor_category": "cloud"})
    engine.add_incident(ORG, vendor["id"], {"title": "Open Issue", "severity": "medium"})
    open_incidents = engine.list_incidents(ORG, status="open")
    assert len(open_incidents) == 1
    # Closed incidents should be empty
    closed = engine.list_incidents(ORG, status="closed")
    assert len(closed) == 0


# ---------------------------------------------------------------------------
# Stats — unassessed_vendors, critical_vendors, avg_risk_score
# ---------------------------------------------------------------------------

def test_get_vendor_stats_empty(engine):
    stats = engine.get_vendor_stats(ORG)
    assert stats["total_vendors"] == 0
    assert stats["critical_vendors"] == 0
    assert stats["unassessed_vendors"] == 0
    assert stats["avg_risk_score"] == 0.0
    assert stats["active_incidents"] == 0


def test_get_vendor_stats_unassessed_count(engine):
    """Vendors with last_assessed=NULL are unassessed."""
    engine.register_vendor(ORG, {"name": "V1", "vendor_category": "software"})
    engine.register_vendor(ORG, {"name": "V2", "vendor_category": "cloud"})
    v3 = engine.register_vendor(ORG, {"name": "V3", "vendor_category": "services"})

    # Assess only v3
    engine.conduct_assessment(ORG, v3["id"], {
        "assessment_type": "audit",
        "score": 75.0,
        "findings_count": 0,
        "critical_findings": 0,
        "passed": True,
    })

    stats = engine.get_vendor_stats(ORG)
    assert stats["total_vendors"] == 3
    assert stats["unassessed_vendors"] == 2


def test_get_vendor_stats_critical_vendors(engine):
    """Vendors with risk_rating=critical are counted."""
    v1 = engine.register_vendor(ORG, {"name": "V1", "vendor_category": "software"})
    v2 = engine.register_vendor(ORG, {"name": "V2", "vendor_category": "cloud"})

    # Make v1 critical: score=0, critical_findings=5 → 100 + 50 = 150 → clamped 100 → critical
    engine.conduct_assessment(ORG, v1["id"], {
        "assessment_type": "penetration_test",
        "score": 0.0,
        "findings_count": 10,
        "critical_findings": 5,
        "passed": False,
    })
    # v2 stays unrated (no assessment)
    stats = engine.get_vendor_stats(ORG)
    assert stats["critical_vendors"] == 1


def test_get_vendor_stats_avg_risk_score(engine):
    v1 = engine.register_vendor(ORG, {"name": "V1", "vendor_category": "software"})
    v2 = engine.register_vendor(ORG, {"name": "V2", "vendor_category": "cloud"})

    # v1: score=80 → risk_score=20
    engine.conduct_assessment(ORG, v1["id"], {"assessment_type": "audit", "score": 80.0, "critical_findings": 0})
    # v2: score=60 → risk_score=40
    engine.conduct_assessment(ORG, v2["id"], {"assessment_type": "audit", "score": 60.0, "critical_findings": 0})

    stats = engine.get_vendor_stats(ORG)
    # avg = (20 + 40) / 2 = 30
    assert stats["avg_risk_score"] == pytest.approx(30.0)


def test_get_vendor_stats_by_category(engine):
    engine.register_vendor(ORG, {"name": "S1", "vendor_category": "software"})
    engine.register_vendor(ORG, {"name": "S2", "vendor_category": "software"})
    engine.register_vendor(ORG, {"name": "C1", "vendor_category": "cloud"})
    stats = engine.get_vendor_stats(ORG)
    assert stats["by_category"]["software"] == 2
    assert stats["by_category"]["cloud"] == 1


def test_get_vendor_stats_by_risk_rating(engine):
    v1 = engine.register_vendor(ORG, {"name": "V1", "vendor_category": "software"})
    engine.conduct_assessment(ORG, v1["id"], {
        "assessment_type": "audit",
        "score": 90.0,  # risk_score=10 → low
        "critical_findings": 0,
    })
    v2 = engine.register_vendor(ORG, {"name": "V2", "vendor_category": "cloud"})
    # V2 still unrated

    stats = engine.get_vendor_stats(ORG)
    assert stats["by_risk_rating"].get("low", 0) == 1
    assert stats["by_risk_rating"].get("unrated", 0) == 1


def test_get_vendor_stats_active_incidents(engine):
    vendor = engine.register_vendor(ORG, {"name": "V", "vendor_category": "services"})
    engine.add_incident(ORG, vendor["id"], {"title": "Inc 1", "severity": "high"})
    engine.add_incident(ORG, vendor["id"], {"title": "Inc 2", "severity": "medium"})
    stats = engine.get_vendor_stats(ORG)
    assert stats["active_incidents"] == 2


def test_stats_org_isolation(engine):
    engine.register_vendor(ORG, {"name": "V", "vendor_category": "software"})
    stats = engine.get_vendor_stats(ORG2)
    assert stats["total_vendors"] == 0
    assert stats["unassessed_vendors"] == 0
