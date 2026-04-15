"""Tests for SupplyChainAttackDetectionEngine.

Covers: init, package CRUD, detection lifecycle, policy management,
        stats aggregation, validation errors, org isolation.
"""

from __future__ import annotations

import pytest

from core.supply_chain_attack_detection_engine import SupplyChainAttackDetectionEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    return SupplyChainAttackDetectionEngine(db_path=str(tmp_path / "scad_test.db"))


def _pkg_data(**kw) -> dict:
    base = {
        "package_name": "requests",
        "ecosystem": "pypi",
        "version": "2.28.0",
        "source_url": "https://pypi.org/project/requests/",
        "risk_score": 10.0,
        "attack_type": "none",
    }
    base.update(kw)
    return base


def _register(engine, org_id="org1", **kw) -> dict:
    return engine.register_package(org_id, _pkg_data(**kw))


def _detect(engine, org_id, package_id, **kw) -> dict:
    data = {
        "package_id": package_id,
        "detection_type": "name_similarity",
        "confidence_score": 85.0,
        "evidence": "Edit distance 1 from popular package",
        "severity": "high",
    }
    data.update(kw)
    return engine.record_detection(org_id, data)


# ---------------------------------------------------------------------------
# 1. Initialisation
# ---------------------------------------------------------------------------


def test_init_creates_db(tmp_path):
    db = tmp_path / "scad.db"
    SupplyChainAttackDetectionEngine(db_path=str(db))
    assert db.exists()


def test_init_idempotent(tmp_path):
    db = str(tmp_path / "scad.db")
    SupplyChainAttackDetectionEngine(db_path=db)
    SupplyChainAttackDetectionEngine(db_path=db)  # should not raise


# ---------------------------------------------------------------------------
# 2. Package registration
# ---------------------------------------------------------------------------


def test_register_package_returns_record(engine):
    pkg = _register(engine)
    assert pkg["package_name"] == "requests"
    assert pkg["ecosystem"] == "pypi"
    assert pkg["status"] == "clean"
    assert pkg["attack_type"] == "none"
    assert "id" in pkg


def test_register_package_uuid_unique(engine):
    p1 = _register(engine, package_name="pkg-a")
    p2 = _register(engine, package_name="pkg-b")
    assert p1["id"] != p2["id"]


def test_register_package_invalid_ecosystem(engine):
    with pytest.raises(ValueError, match="ecosystem"):
        engine.register_package("org1", _pkg_data(ecosystem="invalid_eco"))


def test_register_package_invalid_attack_type(engine):
    with pytest.raises(ValueError, match="attack_type"):
        engine.register_package("org1", _pkg_data(attack_type="not_a_type"))


def test_register_package_all_ecosystems(engine):
    ecosystems = ["npm", "pypi", "maven", "nuget", "rubygems", "cargo", "go", "composer"]
    for eco in ecosystems:
        pkg = engine.register_package("org1", _pkg_data(ecosystem=eco, package_name=f"pkg-{eco}"))
        assert pkg["ecosystem"] == eco


# ---------------------------------------------------------------------------
# 3. List and get packages
# ---------------------------------------------------------------------------


def test_list_packages_empty(engine):
    assert engine.list_packages("org1") == []


def test_list_packages_returns_all(engine):
    _register(engine, package_name="a")
    _register(engine, package_name="b")
    assert len(engine.list_packages("org1")) == 2


def test_list_packages_filter_ecosystem(engine):
    _register(engine, ecosystem="pypi", package_name="pypkg")
    _register(engine, ecosystem="npm", package_name="nmpkg")
    result = engine.list_packages("org1", ecosystem="pypi")
    assert len(result) == 1
    assert result[0]["ecosystem"] == "pypi"


def test_list_packages_filter_status(engine):
    pkg = _register(engine)
    engine.update_package_status("org1", pkg["id"], "suspicious")
    result = engine.list_packages("org1", status="suspicious")
    assert len(result) == 1
    result_clean = engine.list_packages("org1", status="clean")
    assert len(result_clean) == 0


def test_get_package_returns_record(engine):
    pkg = _register(engine)
    fetched = engine.get_package("org1", pkg["id"])
    assert fetched is not None
    assert fetched["id"] == pkg["id"]


def test_get_package_wrong_org_returns_none(engine):
    pkg = _register(engine, org_id="org1")
    result = engine.get_package("org2", pkg["id"])
    assert result is None


def test_get_package_missing_returns_none(engine):
    assert engine.get_package("org1", "nonexistent-id") is None


# ---------------------------------------------------------------------------
# 4. Update package status
# ---------------------------------------------------------------------------


def test_update_package_status_valid(engine):
    pkg = _register(engine)
    updated = engine.update_package_status("org1", pkg["id"], "suspicious")
    assert updated["status"] == "suspicious"


def test_update_package_status_with_attack_type(engine):
    pkg = _register(engine)
    updated = engine.update_package_status("org1", pkg["id"], "malicious", attack_type="typosquatting")
    assert updated["status"] == "malicious"
    assert updated["attack_type"] == "typosquatting"


def test_update_package_status_invalid(engine):
    pkg = _register(engine)
    with pytest.raises(ValueError, match="status"):
        engine.update_package_status("org1", pkg["id"], "unknown_status")


def test_update_package_status_wrong_org_raises(engine):
    pkg = _register(engine, org_id="org1")
    with pytest.raises(ValueError):
        engine.update_package_status("org2", pkg["id"], "suspicious")


def test_update_package_all_statuses(engine):
    for status in ["clean", "suspicious", "malicious", "quarantined"]:
        pkg = _register(engine, package_name=f"pkg-{status}")
        updated = engine.update_package_status("org1", pkg["id"], status)
        assert updated["status"] == status


# ---------------------------------------------------------------------------
# 5. Record detections
# ---------------------------------------------------------------------------


def test_record_detection_returns_record(engine):
    pkg = _register(engine)
    det = _detect(engine, "org1", pkg["id"])
    assert det["detection_type"] == "name_similarity"
    assert det["status"] == "open"
    assert det["confidence_score"] == 85.0
    assert "id" in det


def test_record_detection_clamps_confidence(engine):
    pkg = _register(engine)
    det = engine.record_detection("org1", {
        "package_id": pkg["id"],
        "detection_type": "backdoor",
        "confidence_score": 150.0,  # over max
        "severity": "critical",
    })
    assert det["confidence_score"] == 100.0


def test_record_detection_clamps_confidence_low(engine):
    pkg = _register(engine)
    det = engine.record_detection("org1", {
        "package_id": pkg["id"],
        "detection_type": "crypto_mining",
        "confidence_score": -10.0,  # below min
        "severity": "low",
    })
    assert det["confidence_score"] == 0.0


def test_record_detection_invalid_type(engine):
    pkg = _register(engine)
    with pytest.raises(ValueError, match="detection_type"):
        engine.record_detection("org1", {
            "package_id": pkg["id"],
            "detection_type": "invalid_type",
            "severity": "high",
        })


def test_record_detection_invalid_severity(engine):
    pkg = _register(engine)
    with pytest.raises(ValueError, match="severity"):
        engine.record_detection("org1", {
            "package_id": pkg["id"],
            "detection_type": "backdoor",
            "severity": "catastrophic",
        })


def test_record_all_detection_types(engine):
    pkg = _register(engine)
    detection_types = [
        "name_similarity", "maintainer_change", "unusual_permission",
        "obfuscated_code", "network_callback", "env_harvesting",
        "crypto_mining", "backdoor",
    ]
    for dt in detection_types:
        det = engine.record_detection("org1", {
            "package_id": pkg["id"],
            "detection_type": dt,
            "severity": "medium",
        })
        assert det["detection_type"] == dt


# ---------------------------------------------------------------------------
# 6. List detections
# ---------------------------------------------------------------------------


def test_list_detections_empty(engine):
    assert engine.list_detections("org1") == []


def test_list_detections_filter_severity(engine):
    pkg = _register(engine)
    _detect(engine, "org1", pkg["id"], severity="critical")
    _detect(engine, "org1", pkg["id"], severity="low")
    result = engine.list_detections("org1", severity="critical")
    assert len(result) == 1
    assert result[0]["severity"] == "critical"


def test_list_detections_filter_package(engine):
    pkg1 = _register(engine, package_name="p1")
    pkg2 = _register(engine, package_name="p2")
    _detect(engine, "org1", pkg1["id"])
    _detect(engine, "org1", pkg2["id"])
    result = engine.list_detections("org1", package_id=pkg1["id"])
    assert len(result) == 1
    assert result[0]["package_id"] == pkg1["id"]


def test_list_detections_filter_status(engine):
    pkg = _register(engine)
    det = _detect(engine, "org1", pkg["id"])
    engine.confirm_detection("org1", det["id"], "confirmed")
    open_dets = engine.list_detections("org1", status="open")
    confirmed_dets = engine.list_detections("org1", status="confirmed")
    assert len(open_dets) == 0
    assert len(confirmed_dets) == 1


# ---------------------------------------------------------------------------
# 7. Confirm detection
# ---------------------------------------------------------------------------


def test_confirm_detection_confirmed(engine):
    pkg = _register(engine)
    det = _detect(engine, "org1", pkg["id"])
    updated = engine.confirm_detection("org1", det["id"], "confirmed")
    assert updated["status"] == "confirmed"


def test_confirm_detection_false_positive(engine):
    pkg = _register(engine)
    det = _detect(engine, "org1", pkg["id"])
    updated = engine.confirm_detection("org1", det["id"], "false_positive")
    assert updated["status"] == "false_positive"


def test_confirm_detection_invalid_status(engine):
    pkg = _register(engine)
    det = _detect(engine, "org1", pkg["id"])
    with pytest.raises(ValueError, match="status"):
        engine.confirm_detection("org1", det["id"], "deleted")


def test_confirm_detection_wrong_org_raises(engine):
    pkg = _register(engine, org_id="org1")
    det = _detect(engine, "org1", pkg["id"])
    with pytest.raises(ValueError):
        engine.confirm_detection("org2", det["id"], "confirmed")


# ---------------------------------------------------------------------------
# 8. Policies
# ---------------------------------------------------------------------------


def test_create_policy_returns_record(engine):
    pol = engine.create_policy("org1", {
        "policy_name": "Block typosquatting",
        "ecosystems": ["npm", "pypi"],
        "action": "block",
        "min_confidence": 80.0,
    })
    assert pol["policy_name"] == "Block typosquatting"
    assert pol["action"] == "block"
    assert "npm" in pol["ecosystems"]
    assert pol["enabled"] is True


def test_create_policy_invalid_action(engine):
    with pytest.raises(ValueError, match="action"):
        engine.create_policy("org1", {
            "policy_name": "Bad policy",
            "action": "destroy",
        })


def test_create_policy_all_actions(engine):
    for action in ["block", "quarantine", "alert", "log"]:
        pol = engine.create_policy("org1", {
            "policy_name": f"Policy-{action}",
            "action": action,
        })
        assert pol["action"] == action


def test_list_policies_empty(engine):
    assert engine.list_policies("org1") == []


def test_list_policies_filter_enabled(engine):
    engine.create_policy("org1", {"policy_name": "active", "action": "alert", "enabled": True})
    engine.create_policy("org1", {"policy_name": "inactive", "action": "log", "enabled": False})
    active = engine.list_policies("org1", enabled=True)
    inactive = engine.list_policies("org1", enabled=False)
    assert len(active) == 1
    assert len(inactive) == 1


def test_list_policies_ecosystems_deserialized(engine):
    engine.create_policy("org1", {
        "policy_name": "eco-policy",
        "action": "alert",
        "ecosystems": ["npm", "cargo"],
    })
    pols = engine.list_policies("org1")
    assert isinstance(pols[0]["ecosystems"], list)
    assert "npm" in pols[0]["ecosystems"]


# ---------------------------------------------------------------------------
# 9. Stats
# ---------------------------------------------------------------------------


def test_get_attack_stats_empty(engine):
    stats = engine.get_attack_stats("org1")
    assert stats["total_packages"] == 0
    assert stats["total_detections"] == 0
    assert stats["suspicious_packages"] == 0
    assert stats["malicious_packages"] == 0
    assert stats["open_detections"] == 0
    assert stats["critical_detections"] == 0
    assert stats["by_ecosystem"] == {}
    assert stats["by_attack_type"] == {}
    assert stats["by_detection_type"] == {}


def test_get_attack_stats_aggregation(engine):
    pkg1 = _register(engine, ecosystem="npm", package_name="pkg1")
    pkg2 = _register(engine, ecosystem="pypi", package_name="pkg2")
    engine.update_package_status("org1", pkg1["id"], "suspicious")
    engine.update_package_status("org1", pkg2["id"], "malicious", attack_type="typosquatting")
    _detect(engine, "org1", pkg1["id"], severity="critical", detection_type="backdoor")
    _detect(engine, "org1", pkg2["id"], severity="high", detection_type="name_similarity")

    stats = engine.get_attack_stats("org1")
    assert stats["total_packages"] == 2
    assert stats["suspicious_packages"] == 1
    assert stats["malicious_packages"] == 1
    assert stats["total_detections"] == 2
    assert stats["critical_detections"] == 1
    assert "npm" in stats["by_ecosystem"]
    assert "pypi" in stats["by_ecosystem"]
    assert "typosquatting" in stats["by_attack_type"]
    assert "backdoor" in stats["by_detection_type"]


# ---------------------------------------------------------------------------
# 10. Org isolation
# ---------------------------------------------------------------------------


def test_org_isolation_packages(engine):
    _register(engine, org_id="org1", package_name="pkg-a")
    _register(engine, org_id="org2", package_name="pkg-b")
    org1_pkgs = engine.list_packages("org1")
    org2_pkgs = engine.list_packages("org2")
    assert len(org1_pkgs) == 1
    assert len(org2_pkgs) == 1
    assert org1_pkgs[0]["package_name"] == "pkg-a"
    assert org2_pkgs[0]["package_name"] == "pkg-b"


def test_org_isolation_detections(engine):
    pkg1 = _register(engine, org_id="org1")
    pkg2 = _register(engine, org_id="org2")
    _detect(engine, "org1", pkg1["id"])
    _detect(engine, "org2", pkg2["id"])
    assert len(engine.list_detections("org1")) == 1
    assert len(engine.list_detections("org2")) == 1


def test_org_isolation_stats(engine):
    _register(engine, org_id="org1")
    _register(engine, org_id="org2")
    _register(engine, org_id="org2")
    assert engine.get_attack_stats("org1")["total_packages"] == 1
    assert engine.get_attack_stats("org2")["total_packages"] == 2


def test_org_isolation_policies(engine):
    engine.create_policy("org1", {"policy_name": "p1", "action": "block"})
    engine.create_policy("org2", {"policy_name": "p2", "action": "log"})
    assert len(engine.list_policies("org1")) == 1
    assert len(engine.list_policies("org2")) == 1
