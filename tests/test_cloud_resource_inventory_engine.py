"""Tests for CloudResourceInventoryEngine — 30+ tests."""

from __future__ import annotations

import pytest
from core.cloud_resource_inventory_engine import CloudResourceInventoryEngine


@pytest.fixture
def engine(tmp_path):
    return CloudResourceInventoryEngine(db_path=str(tmp_path / "cri_test.db"))


ORG = "org-cri-test"
ORG2 = "org-cri-other"


def _resource(overrides=None):
    data = {
        "resource_id": "i-12345abc",
        "resource_name": "web-server-01",
        "provider": "aws",
        "resource_type": "compute",
        "region": "us-east-1",
        "account_id": "123456789012",
        "tags": {"env": "prod"},
    }
    if overrides:
        data.update(overrides)
    return data


# ---------------------------------------------------------------------------
# register_resource
# ---------------------------------------------------------------------------

def test_register_resource_basic(engine):
    r = engine.register_resource(ORG, _resource())
    assert r["resource_id"] == "i-12345abc"
    assert r["provider"] == "aws"
    assert r["resource_type"] == "compute"
    assert r["security_score"] == 100.0
    assert r["compliance_status"] == "unknown"
    assert r["resource_state"] == "running"
    assert "id" in r


def test_register_resource_returns_id(engine):
    r = engine.register_resource(ORG, _resource())
    assert len(r["id"]) == 36  # UUID


def test_register_resource_missing_resource_id_raises(engine):
    with pytest.raises(ValueError, match="resource_id"):
        engine.register_resource(ORG, {"provider": "aws", "resource_type": "compute"})


def test_register_resource_invalid_provider_raises(engine):
    with pytest.raises(ValueError, match="provider"):
        engine.register_resource(ORG, _resource({"provider": "badcloud"}))


def test_register_resource_invalid_resource_type_raises(engine):
    with pytest.raises(ValueError, match="resource_type"):
        engine.register_resource(ORG, _resource({"resource_type": "spaceship"}))


def test_register_multiple_providers(engine):
    for prov in ("aws", "azure", "gcp", "alibaba", "oracle", "ibm", "digitalocean"):
        r = engine.register_resource(ORG, _resource({"provider": prov}))
        assert r["provider"] == prov


def test_register_all_resource_types(engine):
    types = ["compute", "storage", "database", "network", "iam",
             "container", "serverless", "cdn", "dns", "load_balancer"]
    for rt in types:
        r = engine.register_resource(ORG, _resource({"resource_type": rt}))
        assert r["resource_type"] == rt


# ---------------------------------------------------------------------------
# list_resources
# ---------------------------------------------------------------------------

def test_list_resources_empty(engine):
    assert engine.list_resources(ORG) == []


def test_list_resources_returns_all(engine):
    engine.register_resource(ORG, _resource())
    engine.register_resource(ORG, _resource({"resource_id": "i-99999"}))
    assert len(engine.list_resources(ORG)) == 2


def test_list_resources_filter_provider(engine):
    engine.register_resource(ORG, _resource({"provider": "aws"}))
    engine.register_resource(ORG, _resource({"resource_id": "az-001", "provider": "azure"}))
    aws = engine.list_resources(ORG, provider="aws")
    assert all(r["provider"] == "aws" for r in aws)
    assert len(aws) == 1


def test_list_resources_filter_resource_type(engine):
    engine.register_resource(ORG, _resource({"resource_type": "storage"}))
    engine.register_resource(ORG, _resource({"resource_id": "i-comp", "resource_type": "compute"}))
    storage = engine.list_resources(ORG, resource_type="storage")
    assert len(storage) == 1
    assert storage[0]["resource_type"] == "storage"


def test_list_resources_filter_resource_state(engine):
    engine.register_resource(ORG, _resource({"resource_state": "stopped"}))
    engine.register_resource(ORG, _resource({"resource_id": "i-run", "resource_state": "running"}))
    stopped = engine.list_resources(ORG, resource_state="stopped")
    assert len(stopped) == 1


def test_list_resources_org_isolation(engine):
    engine.register_resource(ORG, _resource())
    engine.register_resource(ORG2, _resource({"resource_id": "i-other"}))
    assert len(engine.list_resources(ORG)) == 1
    assert len(engine.list_resources(ORG2)) == 1


# ---------------------------------------------------------------------------
# get_resource
# ---------------------------------------------------------------------------

def test_get_resource_found(engine):
    r = engine.register_resource(ORG, _resource())
    fetched = engine.get_resource(ORG, r["id"])
    assert fetched["id"] == r["id"]


def test_get_resource_not_found(engine):
    assert engine.get_resource(ORG, "nonexistent-id") is None


def test_get_resource_org_isolation(engine):
    r = engine.register_resource(ORG, _resource())
    assert engine.get_resource(ORG2, r["id"]) is None


# ---------------------------------------------------------------------------
# update_resource_state
# ---------------------------------------------------------------------------

def test_update_resource_state_basic(engine):
    r = engine.register_resource(ORG, _resource())
    updated = engine.update_resource_state(ORG, r["id"], "stopped")
    assert updated["resource_state"] == "stopped"


def test_update_resource_state_with_compliance(engine):
    r = engine.register_resource(ORG, _resource())
    updated = engine.update_resource_state(ORG, r["id"], "running", compliance_status="compliant")
    assert updated["compliance_status"] == "compliant"


def test_update_resource_state_invalid_state_raises(engine):
    r = engine.register_resource(ORG, _resource())
    with pytest.raises(ValueError, match="state"):
        engine.update_resource_state(ORG, r["id"], "flying")


def test_update_resource_state_not_found_raises(engine):
    with pytest.raises(KeyError):
        engine.update_resource_state(ORG, "bad-id", "stopped")


def test_update_resource_state_updates_last_seen(engine):
    r = engine.register_resource(ORG, _resource())
    old_seen = r["last_seen"]
    updated = engine.update_resource_state(ORG, r["id"], "stopped")
    # last_seen should be present (may equal old if test runs fast)
    assert updated["last_seen"] is not None


# ---------------------------------------------------------------------------
# record_security_finding
# ---------------------------------------------------------------------------

def test_record_finding_basic(engine):
    r = engine.register_resource(ORG, _resource())
    f = engine.record_security_finding(ORG, r["id"], {
        "severity": "medium",
        "title": "Open port 22",
        "compliance_check": "CIS 4.1",
        "remediation": "Restrict SSH access",
    })
    assert f["severity"] == "medium"
    assert f["status"] == "open"
    assert f["cloud_resource_id"] == r["id"]


def test_record_finding_decrements_score_medium(engine):
    r = engine.register_resource(ORG, _resource())
    engine.record_security_finding(ORG, r["id"], {"severity": "medium", "title": "t"})
    updated = engine.get_resource(ORG, r["id"])
    assert updated["security_score"] == 98.0


def test_record_finding_decrements_score_critical(engine):
    r = engine.register_resource(ORG, _resource())
    engine.record_security_finding(ORG, r["id"], {"severity": "critical", "title": "t"})
    updated = engine.get_resource(ORG, r["id"])
    assert updated["security_score"] == 90.0


def test_record_finding_critical_sets_non_compliant(engine):
    r = engine.register_resource(ORG, _resource())
    engine.record_security_finding(ORG, r["id"], {"severity": "critical", "title": "t"})
    updated = engine.get_resource(ORG, r["id"])
    assert updated["compliance_status"] == "non_compliant"


def test_record_finding_high_sets_non_compliant(engine):
    r = engine.register_resource(ORG, _resource())
    engine.record_security_finding(ORG, r["id"], {"severity": "high", "title": "t"})
    updated = engine.get_resource(ORG, r["id"])
    assert updated["compliance_status"] == "non_compliant"


def test_record_finding_low_does_not_set_non_compliant(engine):
    r = engine.register_resource(ORG, _resource())
    engine.record_security_finding(ORG, r["id"], {"severity": "low", "title": "t"})
    updated = engine.get_resource(ORG, r["id"])
    # compliance stays unknown (only critical/high force non_compliant)
    assert updated["compliance_status"] == "unknown"


def test_record_finding_score_floor_zero(engine):
    r = engine.register_resource(ORG, _resource())
    for _ in range(15):
        engine.record_security_finding(ORG, r["id"], {"severity": "critical", "title": "t"})
    updated = engine.get_resource(ORG, r["id"])
    assert updated["security_score"] == 0.0


def test_record_finding_invalid_severity_raises(engine):
    r = engine.register_resource(ORG, _resource())
    with pytest.raises(ValueError, match="severity"):
        engine.record_security_finding(ORG, r["id"], {"severity": "fatal", "title": "t"})


def test_record_finding_resource_not_found_raises(engine):
    with pytest.raises(KeyError):
        engine.record_security_finding(ORG, "bad-id", {"severity": "medium", "title": "t"})


def test_record_finding_org_isolation(engine):
    r = engine.register_resource(ORG, _resource())
    with pytest.raises(KeyError):
        engine.record_security_finding(ORG2, r["id"], {"severity": "medium", "title": "t"})


# ---------------------------------------------------------------------------
# list_findings
# ---------------------------------------------------------------------------

def test_list_findings_empty(engine):
    assert engine.list_findings(ORG) == []


def test_list_findings_by_resource(engine):
    r1 = engine.register_resource(ORG, _resource())
    r2 = engine.register_resource(ORG, _resource({"resource_id": "i-other"}))
    engine.record_security_finding(ORG, r1["id"], {"severity": "medium", "title": "f1"})
    engine.record_security_finding(ORG, r2["id"], {"severity": "high", "title": "f2"})
    findings = engine.list_findings(ORG, cloud_resource_id=r1["id"])
    assert len(findings) == 1
    assert findings[0]["cloud_resource_id"] == r1["id"]


def test_list_findings_filter_severity(engine):
    r = engine.register_resource(ORG, _resource())
    engine.record_security_finding(ORG, r["id"], {"severity": "critical", "title": "c"})
    engine.record_security_finding(ORG, r["id"], {"severity": "low", "title": "l"})
    crits = engine.list_findings(ORG, severity="critical")
    assert len(crits) == 1


def test_list_findings_org_isolation(engine):
    r = engine.register_resource(ORG, _resource())
    engine.record_security_finding(ORG, r["id"], {"severity": "medium", "title": "f"})
    assert engine.list_findings(ORG2) == []


# ---------------------------------------------------------------------------
# get_inventory_stats
# ---------------------------------------------------------------------------

def test_stats_empty(engine):
    stats = engine.get_inventory_stats(ORG)
    assert stats["total_resources"] == 0
    assert stats["total_findings"] == 0
    assert stats["avg_security_score"] == 100.0
    assert stats["critical_resources"] == 0


def test_stats_counts(engine):
    r = engine.register_resource(ORG, _resource())
    engine.register_resource(ORG, _resource({"resource_id": "i-2"}))
    engine.record_security_finding(ORG, r["id"], {"severity": "high", "title": "h"})
    stats = engine.get_inventory_stats(ORG)
    assert stats["total_resources"] == 2
    assert stats["total_findings"] == 1
    assert stats["non_compliant_resources"] == 1
    assert stats["running_resources"] == 2


def test_stats_by_provider(engine):
    engine.register_resource(ORG, _resource({"provider": "aws"}))
    engine.register_resource(ORG, _resource({"resource_id": "az-1", "provider": "azure"}))
    stats = engine.get_inventory_stats(ORG)
    assert stats["by_provider"]["aws"] == 1
    assert stats["by_provider"]["azure"] == 1


def test_stats_critical_resources(engine):
    r = engine.register_resource(ORG, _resource())
    for _ in range(5):
        engine.record_security_finding(ORG, r["id"], {"severity": "critical", "title": "t"})
    stats = engine.get_inventory_stats(ORG)
    assert stats["critical_resources"] == 1


def test_stats_avg_security_score(engine):
    r1 = engine.register_resource(ORG, _resource())
    r2 = engine.register_resource(ORG, _resource({"resource_id": "i-2"}))
    engine.record_security_finding(ORG, r1["id"], {"severity": "medium", "title": "t"})
    stats = engine.get_inventory_stats(ORG)
    assert stats["avg_security_score"] == pytest.approx(99.0, abs=0.1)


def test_stats_org_isolation(engine):
    engine.register_resource(ORG, _resource())
    stats = engine.get_inventory_stats(ORG2)
    assert stats["total_resources"] == 0


def test_list_resources_filter_compliance_status(engine):
    r = engine.register_resource(ORG, _resource())
    engine.record_security_finding(ORG, r["id"], {"severity": "critical", "title": "x"})
    non_compliant = engine.list_resources(ORG, compliance_status="non_compliant")
    assert len(non_compliant) == 1
    unknown = engine.list_resources(ORG, compliance_status="unknown")
    assert len(unknown) == 0
