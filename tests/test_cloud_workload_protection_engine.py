"""Tests for CloudWorkloadProtectionEngine.

Covers: init, workload CRUD, threat lifecycle, policy management,
        stats aggregation, validation errors, org isolation.
"""

from __future__ import annotations

import pytest

from core.cloud_workload_protection_engine import CloudWorkloadProtectionEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    return CloudWorkloadProtectionEngine(db_path=str(tmp_path / "cwp_test.db"))


def _wl_data(**kw) -> dict:
    base = {
        "workload_name": "web-server-01",
        "workload_type": "vm",
        "cloud_provider": "aws",
        "region": "us-east-1",
        "account_id": "123456789012",
        "risk_score": 40.0,
        "risk_level": "medium",
    }
    base.update(kw)
    return base


def _register(engine, org_id="org1", **kw) -> dict:
    return engine.register_workload(org_id, _wl_data(**kw))


def _threat(engine, org_id, workload_id, **kw) -> dict:
    data = {
        "workload_id": workload_id,
        "threat_type": "malware",
        "severity": "high",
        "detection_source": "runtime",
    }
    data.update(kw)
    return engine.record_threat(org_id, data)


# ---------------------------------------------------------------------------
# 1. Initialisation
# ---------------------------------------------------------------------------


def test_init_creates_db(tmp_path):
    db = tmp_path / "cwp.db"
    CloudWorkloadProtectionEngine(db_path=str(db))
    assert db.exists()


def test_init_idempotent(tmp_path):
    db = str(tmp_path / "cwp.db")
    CloudWorkloadProtectionEngine(db_path=db)
    CloudWorkloadProtectionEngine(db_path=db)  # should not raise


# ---------------------------------------------------------------------------
# 2. Workload registration
# ---------------------------------------------------------------------------


def test_register_workload_returns_record(engine):
    wl = _register(engine)
    assert wl["workload_name"] == "web-server-01"
    assert wl["workload_type"] == "vm"
    assert wl["cloud_provider"] == "aws"
    assert wl["protection_status"] == "unprotected"
    assert "id" in wl


def test_register_workload_uuid_unique(engine):
    w1 = _register(engine, workload_name="w1")
    w2 = _register(engine, workload_name="w2")
    assert w1["id"] != w2["id"]


def test_register_workload_invalid_type(engine):
    with pytest.raises(ValueError, match="workload_type"):
        engine.register_workload("org1", _wl_data(workload_type="mainframe"))


def test_register_workload_invalid_provider(engine):
    with pytest.raises(ValueError, match="cloud_provider"):
        engine.register_workload("org1", _wl_data(cloud_provider="digitalocean"))


def test_register_all_workload_types(engine):
    types = ["vm", "container", "serverless", "kubernetes_pod", "bare_metal", "managed_service"]
    for wt in types:
        wl = engine.register_workload("org1", _wl_data(workload_type=wt, workload_name=f"wl-{wt}"))
        assert wl["workload_type"] == wt


def test_register_all_cloud_providers(engine):
    providers = ["aws", "azure", "gcp", "alibaba", "oracle", "on_prem", "multi_cloud"]
    for p in providers:
        wl = engine.register_workload("org1", _wl_data(cloud_provider=p, workload_name=f"wl-{p}"))
        assert wl["cloud_provider"] == p


# ---------------------------------------------------------------------------
# 3. List and get workloads
# ---------------------------------------------------------------------------


def test_list_workloads_empty(engine):
    assert engine.list_workloads("org1") == []


def test_list_workloads_returns_all(engine):
    _register(engine, workload_name="a")
    _register(engine, workload_name="b")
    assert len(engine.list_workloads("org1")) == 2


def test_list_workloads_filter_type(engine):
    _register(engine, workload_type="vm", workload_name="vm1")
    _register(engine, workload_type="container", workload_name="c1")
    result = engine.list_workloads("org1", workload_type="vm")
    assert len(result) == 1
    assert result[0]["workload_type"] == "vm"


def test_list_workloads_filter_provider(engine):
    _register(engine, cloud_provider="aws", workload_name="aws1")
    _register(engine, cloud_provider="gcp", workload_name="gcp1")
    result = engine.list_workloads("org1", cloud_provider="gcp")
    assert len(result) == 1
    assert result[0]["cloud_provider"] == "gcp"


def test_list_workloads_filter_risk_level(engine):
    _register(engine, risk_level="critical", workload_name="risky")
    _register(engine, risk_level="low", workload_name="safe")
    result = engine.list_workloads("org1", risk_level="critical")
    assert len(result) == 1


def test_get_workload_returns_record(engine):
    wl = _register(engine)
    fetched = engine.get_workload("org1", wl["id"])
    assert fetched is not None
    assert fetched["id"] == wl["id"]


def test_get_workload_wrong_org_returns_none(engine):
    wl = _register(engine, org_id="org1")
    assert engine.get_workload("org2", wl["id"]) is None


def test_get_workload_missing_returns_none(engine):
    assert engine.get_workload("org1", "bad-id") is None


# ---------------------------------------------------------------------------
# 4. Update protection status
# ---------------------------------------------------------------------------


def test_update_protection_status_valid(engine):
    wl = _register(engine)
    updated = engine.update_protection_status("org1", wl["id"], "protected")
    assert updated["protection_status"] == "protected"


def test_update_protection_status_all_values(engine):
    for status in ["protected", "partial", "unprotected", "exempt"]:
        wl = _register(engine, workload_name=f"wl-{status}")
        updated = engine.update_protection_status("org1", wl["id"], status)
        assert updated["protection_status"] == status


def test_update_protection_status_invalid(engine):
    wl = _register(engine)
    with pytest.raises(ValueError, match="protection_status"):
        engine.update_protection_status("org1", wl["id"], "secured")


def test_update_protection_status_wrong_org_raises(engine):
    wl = _register(engine, org_id="org1")
    with pytest.raises(ValueError):
        engine.update_protection_status("org2", wl["id"], "protected")


# ---------------------------------------------------------------------------
# 5. Record threats
# ---------------------------------------------------------------------------


def test_record_threat_returns_record(engine):
    wl = _register(engine)
    thr = _threat(engine, "org1", wl["id"])
    assert thr["threat_type"] == "malware"
    assert thr["severity"] == "high"
    assert thr["status"] == "detected"
    assert "id" in thr


def test_record_threat_invalid_type(engine):
    wl = _register(engine)
    with pytest.raises(ValueError, match="threat_type"):
        engine.record_threat("org1", {
            "workload_id": wl["id"],
            "threat_type": "unknown_threat",
            "severity": "high",
            "detection_source": "runtime",
        })


def test_record_threat_invalid_severity(engine):
    wl = _register(engine)
    with pytest.raises(ValueError, match="severity"):
        engine.record_threat("org1", {
            "workload_id": wl["id"],
            "threat_type": "malware",
            "severity": "extreme",
            "detection_source": "runtime",
        })


def test_record_threat_invalid_detection_source(engine):
    wl = _register(engine)
    with pytest.raises(ValueError, match="detection_source"):
        engine.record_threat("org1", {
            "workload_id": wl["id"],
            "threat_type": "malware",
            "severity": "high",
            "detection_source": "unknown_source",
        })


def test_record_all_threat_types(engine):
    wl = _register(engine)
    threat_types = [
        "malware", "ransomware", "cryptomining", "lateral_movement",
        "privilege_escalation", "data_exfil", "backdoor", "supply_chain",
        "container_escape", "serverless_abuse",
    ]
    for tt in threat_types:
        thr = engine.record_threat("org1", {
            "workload_id": wl["id"],
            "threat_type": tt,
            "severity": "medium",
            "detection_source": "runtime",
        })
        assert thr["threat_type"] == tt


def test_record_all_detection_sources(engine):
    wl = _register(engine)
    sources = ["runtime", "network", "file_integrity", "process", "memory", "api_call"]
    for src in sources:
        thr = engine.record_threat("org1", {
            "workload_id": wl["id"],
            "threat_type": "malware",
            "severity": "low",
            "detection_source": src,
        })
        assert thr["detection_source"] == src


# ---------------------------------------------------------------------------
# 6. List threats
# ---------------------------------------------------------------------------


def test_list_threats_empty(engine):
    assert engine.list_threats("org1") == []


def test_list_threats_filter_severity(engine):
    wl = _register(engine)
    _threat(engine, "org1", wl["id"], severity="critical")
    _threat(engine, "org1", wl["id"], severity="low")
    result = engine.list_threats("org1", severity="critical")
    assert len(result) == 1
    assert result[0]["severity"] == "critical"


def test_list_threats_filter_workload(engine):
    w1 = _register(engine, workload_name="w1")
    w2 = _register(engine, workload_name="w2")
    _threat(engine, "org1", w1["id"])
    _threat(engine, "org1", w2["id"])
    result = engine.list_threats("org1", workload_id=w1["id"])
    assert len(result) == 1
    assert result[0]["workload_id"] == w1["id"]


def test_list_threats_filter_status(engine):
    wl = _register(engine)
    thr = _threat(engine, "org1", wl["id"])
    engine.update_threat_status("org1", thr["id"], "contained")
    detected = engine.list_threats("org1", status="detected")
    contained = engine.list_threats("org1", status="contained")
    assert len(detected) == 0
    assert len(contained) == 1


# ---------------------------------------------------------------------------
# 7. Update threat status
# ---------------------------------------------------------------------------


def test_update_threat_status_valid(engine):
    wl = _register(engine)
    thr = _threat(engine, "org1", wl["id"])
    updated = engine.update_threat_status("org1", thr["id"], "investigating")
    assert updated["status"] == "investigating"


def test_update_threat_status_all_values(engine):
    wl = _register(engine)
    for status in ["detected", "investigating", "contained", "remediated", "false_positive"]:
        thr = _threat(engine, "org1", wl["id"])
        updated = engine.update_threat_status("org1", thr["id"], status)
        assert updated["status"] == status


def test_update_threat_status_invalid(engine):
    wl = _register(engine)
    thr = _threat(engine, "org1", wl["id"])
    with pytest.raises(ValueError, match="status"):
        engine.update_threat_status("org1", thr["id"], "deleted")


def test_update_threat_status_wrong_org_raises(engine):
    wl = _register(engine, org_id="org1")
    thr = _threat(engine, "org1", wl["id"])
    with pytest.raises(ValueError):
        engine.update_threat_status("org2", thr["id"], "contained")


# ---------------------------------------------------------------------------
# 8. Policies
# ---------------------------------------------------------------------------


def test_create_policy_returns_record(engine):
    pol = engine.create_policy("org1", {
        "policy_name": "Runtime Protection",
        "workload_types": ["vm", "container"],
        "controls": ["runtime_protection", "file_integrity"],
        "enforcement": "block",
    })
    assert pol["policy_name"] == "Runtime Protection"
    assert pol["enforcement"] == "block"
    assert "vm" in pol["workload_types"]
    assert "runtime_protection" in pol["controls"]
    assert pol["enabled"] is True


def test_create_policy_invalid_enforcement(engine):
    with pytest.raises(ValueError, match="enforcement"):
        engine.create_policy("org1", {
            "policy_name": "Bad policy",
            "enforcement": "deny",
        })


def test_create_policy_all_enforcements(engine):
    for enforcement in ["block", "alert", "log"]:
        pol = engine.create_policy("org1", {
            "policy_name": f"Policy-{enforcement}",
            "enforcement": enforcement,
        })
        assert pol["enforcement"] == enforcement


def test_list_policies_empty(engine):
    assert engine.list_policies("org1") == []


def test_list_policies_filter_enabled(engine):
    engine.create_policy("org1", {"policy_name": "active", "enforcement": "alert", "enabled": True})
    engine.create_policy("org1", {"policy_name": "inactive", "enforcement": "log", "enabled": False})
    active = engine.list_policies("org1", enabled=True)
    inactive = engine.list_policies("org1", enabled=False)
    assert len(active) == 1
    assert len(inactive) == 1


def test_list_policies_json_deserialized(engine):
    engine.create_policy("org1", {
        "policy_name": "json-pol",
        "enforcement": "alert",
        "workload_types": ["serverless"],
        "controls": ["logging", "access_control"],
    })
    pols = engine.list_policies("org1")
    assert isinstance(pols[0]["workload_types"], list)
    assert isinstance(pols[0]["controls"], list)
    assert "serverless" in pols[0]["workload_types"]
    assert "logging" in pols[0]["controls"]


# ---------------------------------------------------------------------------
# 9. Stats
# ---------------------------------------------------------------------------


def test_get_cwp_stats_empty(engine):
    stats = engine.get_cwp_stats("org1")
    assert stats["total_workloads"] == 0
    assert stats["protected_workloads"] == 0
    assert stats["unprotected_workloads"] == 0
    assert stats["total_threats"] == 0
    assert stats["active_threats"] == 0
    assert stats["critical_threats"] == 0
    assert stats["by_workload_type"] == {}
    assert stats["by_cloud_provider"] == {}
    assert stats["by_threat_type"] == {}


def test_get_cwp_stats_aggregation(engine):
    w1 = _register(engine, workload_type="vm", cloud_provider="aws", workload_name="w1")
    w2 = _register(engine, workload_type="container", cloud_provider="gcp", workload_name="w2")
    engine.update_protection_status("org1", w1["id"], "protected")
    _threat(engine, "org1", w1["id"], threat_type="malware", severity="critical")
    _threat(engine, "org1", w2["id"], threat_type="ransomware", severity="high")
    t3 = _threat(engine, "org1", w2["id"], threat_type="cryptomining", severity="medium")
    engine.update_threat_status("org1", t3["id"], "remediated")

    stats = engine.get_cwp_stats("org1")
    assert stats["total_workloads"] == 2
    assert stats["protected_workloads"] == 1
    assert stats["unprotected_workloads"] == 1
    assert stats["total_threats"] == 3
    assert stats["active_threats"] == 2  # detected + investigating
    assert stats["critical_threats"] == 1
    assert stats["by_workload_type"]["vm"] == 1
    assert stats["by_workload_type"]["container"] == 1
    assert stats["by_cloud_provider"]["aws"] == 1
    assert stats["by_cloud_provider"]["gcp"] == 1
    assert "malware" in stats["by_threat_type"]
    assert "ransomware" in stats["by_threat_type"]


# ---------------------------------------------------------------------------
# 10. Org isolation
# ---------------------------------------------------------------------------


def test_org_isolation_workloads(engine):
    _register(engine, org_id="org1", workload_name="w1")
    _register(engine, org_id="org2", workload_name="w2")
    assert len(engine.list_workloads("org1")) == 1
    assert len(engine.list_workloads("org2")) == 1
    assert engine.list_workloads("org1")[0]["workload_name"] == "w1"
    assert engine.list_workloads("org2")[0]["workload_name"] == "w2"


def test_org_isolation_threats(engine):
    w1 = _register(engine, org_id="org1")
    w2 = _register(engine, org_id="org2")
    _threat(engine, "org1", w1["id"])
    _threat(engine, "org2", w2["id"])
    assert len(engine.list_threats("org1")) == 1
    assert len(engine.list_threats("org2")) == 1


def test_org_isolation_stats(engine):
    _register(engine, org_id="org1")
    _register(engine, org_id="org2")
    _register(engine, org_id="org2")
    assert engine.get_cwp_stats("org1")["total_workloads"] == 1
    assert engine.get_cwp_stats("org2")["total_workloads"] == 2


def test_org_isolation_policies(engine):
    engine.create_policy("org1", {"policy_name": "p1", "enforcement": "block"})
    engine.create_policy("org2", {"policy_name": "p2", "enforcement": "log"})
    assert len(engine.list_policies("org1")) == 1
    assert len(engine.list_policies("org2")) == 1
