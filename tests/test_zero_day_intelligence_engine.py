"""Tests for ZeroDayIntelligenceEngine — wave 20."""

import pytest
from core.zero_day_intelligence_engine import ZeroDayIntelligenceEngine


@pytest.fixture
def engine(tmp_path):
    return ZeroDayIntelligenceEngine(db_path=str(tmp_path / "zdi.db"))


# ---------------------------------------------------------------------------
# register_vulnerability — basic
# ---------------------------------------------------------------------------

def test_register_vulnerability_minimal(engine):
    v = engine.register_vulnerability("org1", {"cve_id": "CVE-2024-0001"})
    assert v["cve_id"] == "CVE-2024-0001"
    assert v["cvss_score"] == 0.0
    assert v["patch_status"] == "unpatched"
    assert v["exploitation_status"] == "unconfirmed"
    assert v["severity"] == "medium"
    assert v["disclosure_type"] == "coordinated"
    assert isinstance(v["affected_products"], list)
    assert "id" in v
    assert "created_at" in v


def test_register_vulnerability_full(engine):
    v = engine.register_vulnerability("org1", {
        "cve_id": "CVE-2024-9999",
        "title": "Critical RCE",
        "description": "Remote code execution via buffer overflow",
        "cvss_score": 9.8,
        "exploitability_score": 3.9,
        "affected_products": ["product-a", "product-b"],
        "disclosure_type": "zero_day",
        "patch_status": "unpatched",
        "exploitation_status": "actively_exploited",
        "severity": "critical",
    })
    assert v["cvss_score"] == 9.8
    assert v["severity"] == "critical"
    assert v["disclosure_type"] == "zero_day"
    assert v["exploitation_status"] == "actively_exploited"
    assert "product-a" in v["affected_products"]


def test_register_vulnerability_missing_cve_id_raises(engine):
    with pytest.raises(ValueError, match="cve_id"):
        engine.register_vulnerability("org1", {"title": "No CVE"})


def test_register_vulnerability_invalid_disclosure_type_raises(engine):
    with pytest.raises(ValueError, match="Invalid disclosure_type"):
        engine.register_vulnerability("org1", {
            "cve_id": "CVE-2024-0002",
            "disclosure_type": "secret",
        })


def test_register_vulnerability_invalid_exploitation_status_raises(engine):
    with pytest.raises(ValueError, match="Invalid exploitation_status"):
        engine.register_vulnerability("org1", {
            "cve_id": "CVE-2024-0003",
            "exploitation_status": "in_the_wild",
        })


def test_register_vulnerability_invalid_patch_status_raises(engine):
    with pytest.raises(ValueError, match="Invalid patch_status"):
        engine.register_vulnerability("org1", {
            "cve_id": "CVE-2024-0004",
            "patch_status": "pending",
        })


def test_register_vulnerability_invalid_severity_raises(engine):
    with pytest.raises(ValueError, match="Invalid severity"):
        engine.register_vulnerability("org1", {
            "cve_id": "CVE-2024-0005",
            "severity": "extreme",
        })


def test_register_vulnerability_all_severities(engine):
    for sev in ["critical", "high", "medium", "low"]:
        v = engine.register_vulnerability("org1", {
            "cve_id": f"CVE-2024-{sev}",
            "severity": sev,
        })
        assert v["severity"] == sev


def test_register_vulnerability_all_disclosure_types(engine):
    for dt in ["full", "limited", "coordinated", "zero_day"]:
        v = engine.register_vulnerability("org1", {
            "cve_id": f"CVE-2024-dt-{dt}",
            "disclosure_type": dt,
        })
        assert v["disclosure_type"] == dt


def test_register_vulnerability_all_exploitation_statuses(engine):
    for es in ["unconfirmed", "poc_available", "actively_exploited", "weaponized"]:
        v = engine.register_vulnerability("org1", {
            "cve_id": f"CVE-2024-es-{es}",
            "exploitation_status": es,
        })
        assert v["exploitation_status"] == es


# ---------------------------------------------------------------------------
# list_vulnerabilities
# ---------------------------------------------------------------------------

def test_list_vulnerabilities_empty(engine):
    assert engine.list_vulnerabilities("org1") == []


def test_list_vulnerabilities_org_isolation(engine):
    engine.register_vulnerability("org1", {"cve_id": "CVE-2024-ORG1"})
    assert engine.list_vulnerabilities("org2") == []
    assert len(engine.list_vulnerabilities("org1")) == 1


def test_list_vulnerabilities_filter_severity(engine):
    engine.register_vulnerability("org1", {"cve_id": "CVE-A", "severity": "critical"})
    engine.register_vulnerability("org1", {"cve_id": "CVE-B", "severity": "low"})
    critical = engine.list_vulnerabilities("org1", severity="critical")
    assert len(critical) == 1
    assert critical[0]["cve_id"] == "CVE-A"


def test_list_vulnerabilities_filter_patch_status(engine):
    engine.register_vulnerability("org1", {"cve_id": "CVE-UNPATCH", "patch_status": "unpatched"})
    engine.register_vulnerability("org1", {"cve_id": "CVE-PATCH", "patch_status": "patched"})
    unpatched = engine.list_vulnerabilities("org1", patch_status="unpatched")
    assert len(unpatched) == 1
    assert unpatched[0]["cve_id"] == "CVE-UNPATCH"


def test_list_vulnerabilities_filter_exploitation_status(engine):
    engine.register_vulnerability("org1", {
        "cve_id": "CVE-EXPLOIT",
        "exploitation_status": "actively_exploited",
    })
    engine.register_vulnerability("org1", {
        "cve_id": "CVE-POC",
        "exploitation_status": "poc_available",
    })
    exploited = engine.list_vulnerabilities("org1", exploitation_status="actively_exploited")
    assert len(exploited) == 1
    assert exploited[0]["cve_id"] == "CVE-EXPLOIT"


# ---------------------------------------------------------------------------
# get_vulnerability
# ---------------------------------------------------------------------------

def test_get_vulnerability_returns_record(engine):
    v = engine.register_vulnerability("org1", {"cve_id": "CVE-GET"})
    found = engine.get_vulnerability("org1", v["id"])
    assert found is not None
    assert found["id"] == v["id"]
    assert found["cve_id"] == "CVE-GET"


def test_get_vulnerability_not_found_returns_none(engine):
    assert engine.get_vulnerability("org1", "nonexistent-id") is None


def test_get_vulnerability_org_isolation(engine):
    v = engine.register_vulnerability("org1", {"cve_id": "CVE-ORG"})
    assert engine.get_vulnerability("org2", v["id"]) is None


# ---------------------------------------------------------------------------
# update_patch_status
# ---------------------------------------------------------------------------

def test_update_patch_status_updates_db(engine):
    v = engine.register_vulnerability("org1", {"cve_id": "CVE-PATCH-ME", "patch_status": "unpatched"})
    updated = engine.update_patch_status("org1", v["id"], "patched", patched_at="2024-01-15T00:00:00Z")
    assert updated["patch_status"] == "patched"
    assert updated["patched_at"] == "2024-01-15T00:00:00Z"


def test_update_patch_status_partial(engine):
    v = engine.register_vulnerability("org1", {"cve_id": "CVE-PARTIAL"})
    updated = engine.update_patch_status("org1", v["id"], "partial")
    assert updated["patch_status"] == "partial"


def test_update_patch_status_invalid_raises(engine):
    v = engine.register_vulnerability("org1", {"cve_id": "CVE-INVALID"})
    with pytest.raises(ValueError, match="Invalid patch_status"):
        engine.update_patch_status("org1", v["id"], "pending")


def test_update_patch_status_not_found_raises(engine):
    with pytest.raises(KeyError):
        engine.update_patch_status("org1", "nonexistent", "patched")


# ---------------------------------------------------------------------------
# record_threat_actor
# ---------------------------------------------------------------------------

def test_record_threat_actor_returns_record(engine):
    v = engine.register_vulnerability("org1", {"cve_id": "CVE-ACTOR"})
    ta = engine.record_threat_actor("org1", {
        "vulnerability_id": v["id"],
        "actor_name": "APT29",
        "actor_type": "state_sponsored",
        "confidence_score": 90.0,
    })
    assert ta["actor_name"] == "APT29"
    assert ta["actor_type"] == "state_sponsored"
    assert ta["confidence_score"] == 90.0
    assert ta["vulnerability_id"] == v["id"]
    assert "id" in ta


def test_record_threat_actor_clamps_confidence(engine):
    v = engine.register_vulnerability("org1", {"cve_id": "CVE-CLAMP"})
    ta_high = engine.record_threat_actor("org1", {
        "vulnerability_id": v["id"],
        "actor_name": "OverconfidentActor",
        "confidence_score": 150.0,
    })
    assert ta_high["confidence_score"] == 100.0

    ta_low = engine.record_threat_actor("org1", {
        "vulnerability_id": v["id"],
        "actor_name": "UnderconfidentActor",
        "confidence_score": -10.0,
    })
    assert ta_low["confidence_score"] == 0.0


def test_record_threat_actor_invalid_actor_type_raises(engine):
    v = engine.register_vulnerability("org1", {"cve_id": "CVE-BADTYPE"})
    with pytest.raises(ValueError, match="Invalid actor_type"):
        engine.record_threat_actor("org1", {
            "vulnerability_id": v["id"],
            "actor_name": "BadActor",
            "actor_type": "robot",
        })


def test_record_threat_actor_all_types(engine):
    v = engine.register_vulnerability("org1", {"cve_id": "CVE-ALLTYPES"})
    for atype in ["apt", "criminal", "hacktivist", "state_sponsored", "unknown"]:
        ta = engine.record_threat_actor("org1", {
            "vulnerability_id": v["id"],
            "actor_name": f"Actor-{atype}",
            "actor_type": atype,
        })
        assert ta["actor_type"] == atype


# ---------------------------------------------------------------------------
# list_threat_actors
# ---------------------------------------------------------------------------

def test_list_threat_actors_filter_by_vulnerability_id(engine):
    v1 = engine.register_vulnerability("org1", {"cve_id": "CVE-V1"})
    v2 = engine.register_vulnerability("org1", {"cve_id": "CVE-V2"})
    engine.record_threat_actor("org1", {"vulnerability_id": v1["id"], "actor_name": "A1"})
    engine.record_threat_actor("org1", {"vulnerability_id": v2["id"], "actor_name": "A2"})
    actors_v1 = engine.list_threat_actors("org1", vulnerability_id=v1["id"])
    assert len(actors_v1) == 1
    assert actors_v1[0]["actor_name"] == "A1"


def test_list_threat_actors_org_isolation(engine):
    v = engine.register_vulnerability("org1", {"cve_id": "CVE-ORGISO"})
    engine.record_threat_actor("org1", {"vulnerability_id": v["id"], "actor_name": "OrgActor"})
    assert engine.list_threat_actors("org2") == []


# ---------------------------------------------------------------------------
# record_mitigation + list_mitigations
# ---------------------------------------------------------------------------

def test_record_mitigation_returns_record(engine):
    v = engine.register_vulnerability("org1", {"cve_id": "CVE-MIT"})
    m = engine.record_mitigation("org1", {
        "vulnerability_id": v["id"],
        "mitigation_type": "patch",
        "description": "Apply vendor patch",
        "status": "approved",
        "applied_by": "sysadmin",
    })
    assert m["mitigation_type"] == "patch"
    assert m["status"] == "approved"
    assert m["vulnerability_id"] == v["id"]
    assert "id" in m


def test_record_mitigation_all_types(engine):
    v = engine.register_vulnerability("org1", {"cve_id": "CVE-MTYPE"})
    for mtype in ["workaround", "patch", "configuration", "network_isolation", "disable_feature"]:
        m = engine.record_mitigation("org1", {
            "vulnerability_id": v["id"],
            "mitigation_type": mtype,
        })
        assert m["mitigation_type"] == mtype


def test_record_mitigation_invalid_type_raises(engine):
    v = engine.register_vulnerability("org1", {"cve_id": "CVE-BADMIT"})
    with pytest.raises(ValueError, match="Invalid mitigation_type"):
        engine.record_mitigation("org1", {
            "vulnerability_id": v["id"],
            "mitigation_type": "magic_fix",
        })


def test_record_mitigation_invalid_status_raises(engine):
    v = engine.register_vulnerability("org1", {"cve_id": "CVE-BADSTATUS"})
    with pytest.raises(ValueError, match="Invalid status"):
        engine.record_mitigation("org1", {
            "vulnerability_id": v["id"],
            "mitigation_type": "patch",
            "status": "done",
        })


def test_list_mitigations_filter_by_vulnerability_id(engine):
    v1 = engine.register_vulnerability("org1", {"cve_id": "CVE-M1"})
    v2 = engine.register_vulnerability("org1", {"cve_id": "CVE-M2"})
    engine.record_mitigation("org1", {"vulnerability_id": v1["id"], "mitigation_type": "patch"})
    engine.record_mitigation("org1", {"vulnerability_id": v2["id"], "mitigation_type": "workaround"})
    mits_v1 = engine.list_mitigations("org1", vulnerability_id=v1["id"])
    assert len(mits_v1) == 1
    assert mits_v1[0]["mitigation_type"] == "patch"


def test_list_mitigations_filter_by_status(engine):
    v = engine.register_vulnerability("org1", {"cve_id": "CVE-MSTATUS"})
    engine.record_mitigation("org1", {"vulnerability_id": v["id"], "mitigation_type": "patch", "status": "approved"})
    engine.record_mitigation("org1", {"vulnerability_id": v["id"], "mitigation_type": "workaround", "status": "proposed"})
    approved = engine.list_mitigations("org1", status="approved")
    assert len(approved) == 1
    assert approved[0]["status"] == "approved"


# ---------------------------------------------------------------------------
# get_zero_day_stats
# ---------------------------------------------------------------------------

def test_get_zero_day_stats_empty_org(engine):
    stats = engine.get_zero_day_stats("empty_org")
    assert stats["total_vulns"] == 0
    assert stats["unpatched_count"] == 0
    assert stats["actively_exploited"] == 0
    assert stats["critical_count"] == 0
    assert stats["avg_cvss"] == 0.0
    assert stats["by_severity"] == {}
    assert stats["by_patch_status"] == {}
    assert stats["by_exploitation_status"] == {}


def test_get_zero_day_stats_populated(engine):
    engine.register_vulnerability("org1", {
        "cve_id": "CVE-S1",
        "severity": "critical",
        "patch_status": "unpatched",
        "exploitation_status": "actively_exploited",
        "cvss_score": 9.8,
    })
    engine.register_vulnerability("org1", {
        "cve_id": "CVE-S2",
        "severity": "high",
        "patch_status": "patched",
        "exploitation_status": "poc_available",
        "cvss_score": 7.5,
    })
    engine.register_vulnerability("org1", {
        "cve_id": "CVE-S3",
        "severity": "medium",
        "patch_status": "unpatched",
        "exploitation_status": "unconfirmed",
        "cvss_score": 5.0,
    })

    stats = engine.get_zero_day_stats("org1")
    assert stats["total_vulns"] == 3
    assert stats["unpatched_count"] == 2
    assert stats["actively_exploited"] == 1
    assert stats["critical_count"] == 1
    assert stats["avg_cvss"] == pytest.approx((9.8 + 7.5 + 5.0) / 3, rel=1e-2)
    assert stats["by_severity"]["critical"] == 1
    assert stats["by_severity"]["high"] == 1
    assert stats["by_patch_status"]["unpatched"] == 2
    assert stats["by_patch_status"]["patched"] == 1
    assert stats["by_exploitation_status"]["actively_exploited"] == 1


def test_get_zero_day_stats_org_isolation(engine):
    engine.register_vulnerability("org1", {"cve_id": "CVE-ORG-ISO", "severity": "critical"})
    stats = engine.get_zero_day_stats("org2")
    assert stats["total_vulns"] == 0
    assert stats["critical_count"] == 0
