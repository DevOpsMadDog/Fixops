"""Tests for RedTeamManagementEngine — 30+ tests covering all methods and stats."""

from __future__ import annotations

import pytest

from core.red_team_mgmt_engine import RedTeamManagementEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "test_red_team_mgmt.db")


@pytest.fixture
def engine(db_path):
    return RedTeamManagementEngine(db_path=db_path)


ORG = "org-rt-test"


# ---------------------------------------------------------------------------
# create_engagement
# ---------------------------------------------------------------------------

def test_create_engagement_basic(engine):
    eng = engine.create_engagement(ORG, {"name": "Internal RT Q1"})
    assert eng["name"] == "Internal RT Q1"
    assert eng["status"] == "planned"
    assert eng["engagement_type"] == "internal"
    assert eng["methodology"] == "PTES"
    assert eng["classification"] == "confidential"
    assert "id" in eng


def test_create_engagement_all_fields(engine):
    eng = engine.create_engagement(ORG, {
        "name": "External APT Sim",
        "engagement_type": "external",
        "methodology": "OWASP",
        "scope_description": "Public-facing web apps",
        "start_date": "2026-05-01",
        "end_date": "2026-05-15",
        "lead_operator": "op-123",
        "classification": "secret",
    })
    assert eng["engagement_type"] == "external"
    assert eng["methodology"] == "OWASP"
    assert eng["classification"] == "secret"
    assert eng["lead_operator"] == "op-123"


def test_create_engagement_missing_name(engine):
    with pytest.raises(ValueError, match="name is required"):
        engine.create_engagement(ORG, {})


def test_create_engagement_invalid_type(engine):
    with pytest.raises(ValueError, match="Invalid engagement_type"):
        engine.create_engagement(ORG, {"name": "X", "engagement_type": "black_box"})


def test_create_engagement_invalid_methodology(engine):
    with pytest.raises(ValueError, match="Invalid methodology"):
        engine.create_engagement(ORG, {"name": "X", "methodology": "NIST"})


def test_create_engagement_invalid_classification(engine):
    with pytest.raises(ValueError, match="Invalid classification"):
        engine.create_engagement(ORG, {"name": "X", "classification": "top_secret"})


# ---------------------------------------------------------------------------
# list_engagements / get_engagement
# ---------------------------------------------------------------------------

def test_list_engagements_empty(engine):
    assert engine.list_engagements(ORG) == []


def test_list_engagements_multiple(engine):
    engine.create_engagement(ORG, {"name": "E1"})
    engine.create_engagement(ORG, {"name": "E2"})
    result = engine.list_engagements(ORG)
    assert len(result) == 2


def test_list_engagements_filter_status(engine):
    engine.create_engagement(ORG, {"name": "E1"})
    e2 = engine.create_engagement(ORG, {"name": "E2"})
    engine.update_engagement_status(ORG, e2["id"], "active")
    result = engine.list_engagements(ORG, status="active")
    assert len(result) == 1
    assert result[0]["name"] == "E2"


def test_get_engagement_with_findings_summary(engine):
    eng = engine.create_engagement(ORG, {"name": "E1"})
    engine.add_finding(ORG, eng["id"], {"title": "F1", "severity": "critical"})
    engine.add_finding(ORG, eng["id"], {"title": "F2", "severity": "high"})
    result = engine.get_engagement(ORG, eng["id"])
    assert result is not None
    assert result["total_findings"] == 2
    assert result["findings_by_severity"]["critical"] == 1
    assert result["findings_by_severity"]["high"] == 1


def test_get_engagement_not_found(engine):
    assert engine.get_engagement(ORG, "nonexistent") is None


def test_get_engagement_org_isolation(engine):
    eng = engine.create_engagement(ORG, {"name": "E1"})
    assert engine.get_engagement("other-org", eng["id"]) is None


# ---------------------------------------------------------------------------
# update_engagement_status
# ---------------------------------------------------------------------------

def test_update_engagement_status_valid(engine):
    eng = engine.create_engagement(ORG, {"name": "E1"})
    result = engine.update_engagement_status(ORG, eng["id"], "active")
    assert result["status"] == "active"
    assert result["updated"] is True


def test_update_engagement_status_all_transitions(engine):
    eng = engine.create_engagement(ORG, {"name": "E1"})
    for status in ["active", "completed", "cancelled", "planned"]:
        result = engine.update_engagement_status(ORG, eng["id"], status)
        assert result["status"] == status


def test_update_engagement_status_invalid(engine):
    eng = engine.create_engagement(ORG, {"name": "E1"})
    with pytest.raises(ValueError, match="Invalid status"):
        engine.update_engagement_status(ORG, eng["id"], "deleted")


def test_update_engagement_status_not_found(engine):
    with pytest.raises(ValueError, match="not found"):
        engine.update_engagement_status(ORG, "nonexistent-id", "active")


# ---------------------------------------------------------------------------
# add_finding / list_findings
# ---------------------------------------------------------------------------

def test_add_finding_basic(engine):
    eng = engine.create_engagement(ORG, {"name": "E1"})
    f = engine.add_finding(ORG, eng["id"], {"title": "SQLi in login"})
    assert f["title"] == "SQLi in login"
    assert f["severity"] == "medium"
    assert f["status"] == "open"
    assert f["engagement_id"] == eng["id"]
    assert "id" in f


def test_add_finding_all_fields(engine):
    eng = engine.create_engagement(ORG, {"name": "E1"})
    f = engine.add_finding(ORG, eng["id"], {
        "title": "Pass-the-Hash",
        "category": "credential_access",
        "severity": "critical",
        "mitre_technique_id": "T1550.002",
        "mitre_technique_name": "Pass the Hash",
        "description": "Attacker used PTH to move laterally",
        "evidence_path": "/evidence/pth.pcap",
        "remediation_recommendation": "Enable Credential Guard",
        "status": "open",
    })
    assert f["mitre_technique_id"] == "T1550.002"
    assert f["category"] == "credential_access"


def test_add_finding_missing_title(engine):
    eng = engine.create_engagement(ORG, {"name": "E1"})
    with pytest.raises(ValueError, match="title is required"):
        engine.add_finding(ORG, eng["id"], {})


def test_add_finding_invalid_severity(engine):
    eng = engine.create_engagement(ORG, {"name": "E1"})
    with pytest.raises(ValueError, match="Invalid severity"):
        engine.add_finding(ORG, eng["id"], {"title": "X", "severity": "info"})


def test_add_finding_invalid_category(engine):
    eng = engine.create_engagement(ORG, {"name": "E1"})
    with pytest.raises(ValueError, match="Invalid category"):
        engine.add_finding(ORG, eng["id"], {"title": "X", "category": "recon"})


def test_list_findings_by_engagement(engine):
    e1 = engine.create_engagement(ORG, {"name": "E1"})
    e2 = engine.create_engagement(ORG, {"name": "E2"})
    engine.add_finding(ORG, e1["id"], {"title": "F1"})
    engine.add_finding(ORG, e2["id"], {"title": "F2"})
    result = engine.list_findings(ORG, engagement_id=e1["id"])
    assert len(result) == 1
    assert result[0]["title"] == "F1"


def test_list_findings_filter_severity(engine):
    eng = engine.create_engagement(ORG, {"name": "E1"})
    engine.add_finding(ORG, eng["id"], {"title": "Critical F", "severity": "critical"})
    engine.add_finding(ORG, eng["id"], {"title": "Low F", "severity": "low"})
    result = engine.list_findings(ORG, severity="critical")
    assert len(result) == 1
    assert result[0]["title"] == "Critical F"


# ---------------------------------------------------------------------------
# add_ttp / list_ttps
# ---------------------------------------------------------------------------

def test_add_ttp_basic(engine):
    eng = engine.create_engagement(ORG, {"name": "E1"})
    ttp = engine.add_ttp(ORG, eng["id"], {
        "tactic": "Initial Access",
        "technique_id": "T1566.001",
        "technique_name": "Spearphishing Attachment",
        "outcome": "successful",
    })
    assert ttp["tactic"] == "Initial Access"
    assert ttp["outcome"] == "successful"
    assert ttp["engagement_id"] == eng["id"]


def test_add_ttp_with_detection_time(engine):
    eng = engine.create_engagement(ORG, {"name": "E1"})
    ttp = engine.add_ttp(ORG, eng["id"], {
        "technique_id": "T1059",
        "outcome": "detected",
        "detection_time_seconds": 3600,
    })
    assert ttp["detection_time_seconds"] == 3600
    assert ttp["outcome"] == "detected"


def test_add_ttp_invalid_outcome(engine):
    eng = engine.create_engagement(ORG, {"name": "E1"})
    with pytest.raises(ValueError, match="Invalid outcome"):
        engine.add_ttp(ORG, eng["id"], {"outcome": "unknown"})


def test_list_ttps(engine):
    eng = engine.create_engagement(ORG, {"name": "E1"})
    engine.add_ttp(ORG, eng["id"], {"technique_id": "T1566", "outcome": "successful"})
    engine.add_ttp(ORG, eng["id"], {"technique_id": "T1059", "outcome": "detected"})
    result = engine.list_ttps(ORG, eng["id"])
    assert len(result) == 2


def test_list_ttps_empty(engine):
    eng = engine.create_engagement(ORG, {"name": "E1"})
    assert engine.list_ttps(ORG, eng["id"]) == []


# ---------------------------------------------------------------------------
# add_operator / list_operators
# ---------------------------------------------------------------------------

def test_add_operator_basic(engine):
    op = engine.add_operator(ORG, {
        "name": "Red Ranger",
        "specialization": "network",
        "certifications": "OSCP,CRTO",
    })
    assert op["name"] == "Red Ranger"
    assert op["specialization"] == "network"
    assert "id" in op


def test_add_operator_missing_name(engine):
    with pytest.raises(ValueError, match="name is required"):
        engine.add_operator(ORG, {})


def test_add_operator_invalid_specialization(engine):
    with pytest.raises(ValueError, match="Invalid specialization"):
        engine.add_operator(ORG, {"name": "X", "specialization": "mobile"})


def test_list_operators_empty(engine):
    assert engine.list_operators(ORG) == []


def test_list_operators_multiple(engine):
    engine.add_operator(ORG, {"name": "Alice", "specialization": "web"})
    engine.add_operator(ORG, {"name": "Bob", "specialization": "cloud"})
    result = engine.list_operators(ORG)
    assert len(result) == 2


def test_list_operators_org_isolation(engine):
    engine.add_operator(ORG, {"name": "Alice"})
    assert engine.list_operators("other-org") == []


# ---------------------------------------------------------------------------
# get_stats
# ---------------------------------------------------------------------------

def test_get_stats_empty(engine):
    stats = engine.get_stats(ORG)
    assert stats["engagement_count"] == 0
    assert stats["open_findings_by_severity"] == {}
    assert stats["avg_dwell_time"] == 0.0
    assert stats["detection_rate"] == 0.0
    assert stats["top_techniques"] == []


def test_get_stats_with_data(engine):
    eng = engine.create_engagement(ORG, {"name": "E1"})
    engine.add_finding(ORG, eng["id"], {"title": "F1", "severity": "critical"})
    engine.add_finding(ORG, eng["id"], {"title": "F2", "severity": "high"})
    engine.add_ttp(ORG, eng["id"], {
        "technique_id": "T1566", "technique_name": "Phishing",
        "outcome": "detected", "detection_time_seconds": 7200,
    })
    engine.add_ttp(ORG, eng["id"], {
        "technique_id": "T1059", "technique_name": "Command Exec",
        "outcome": "successful",
    })

    stats = engine.get_stats(ORG)
    assert stats["engagement_count"] == 1
    assert stats["open_findings_by_severity"]["critical"] == 1
    assert stats["open_findings_by_severity"]["high"] == 1
    assert stats["avg_dwell_time"] == 7200.0
    assert stats["detection_rate"] == 50.0  # 1 detected out of 2 total
    assert len(stats["top_techniques"]) == 2


def test_get_stats_detection_rate_all_detected(engine):
    eng = engine.create_engagement(ORG, {"name": "E1"})
    for i in range(3):
        engine.add_ttp(ORG, eng["id"], {
            "technique_id": f"T10{i:02d}",
            "outcome": "detected",
            "detection_time_seconds": 1000 * (i + 1),
        })
    stats = engine.get_stats(ORG)
    assert stats["detection_rate"] == 100.0
    assert stats["avg_dwell_time"] == 2000.0  # (1000+2000+3000)/3


def test_get_stats_top_techniques_ordering(engine):
    eng = engine.create_engagement(ORG, {"name": "E1"})
    # T1566 appears 3 times, T1059 appears 1 time
    for _ in range(3):
        engine.add_ttp(ORG, eng["id"], {"technique_id": "T1566", "technique_name": "Phishing", "outcome": "successful"})
    engine.add_ttp(ORG, eng["id"], {"technique_id": "T1059", "technique_name": "Exec", "outcome": "successful"})

    stats = engine.get_stats(ORG)
    top = stats["top_techniques"]
    assert top[0]["technique_id"] == "T1566"
    assert top[0]["cnt"] == 3
