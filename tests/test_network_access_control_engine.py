"""Tests for NetworkAccessControlEngine.

Covers:
- Endpoint registration: valid/invalid device types, required fields
- Posture assessment: score math (5 checks * 20 = 100 max), status derivation
- NAC status derivation: compliant=allowed, warning=restricted, non_compliant=quarantined
- Manual NAC status update with reason
- Policy creation and listing
- Stats: avg_posture_score, compliant_pct, by_device_type, by_nac_status, quarantined_count
- Multi-tenant org isolation
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("FIXOPS_MODE", "dev")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")

from core.network_access_control_engine import NetworkAccessControlEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    return NetworkAccessControlEngine(db_path=str(tmp_path / "nac.db"))


ORG = "org-nac-test"
ORG2 = "org-nac-other"


def _ep(overrides=None):
    base = {"name": "WS-001", "mac_address": "aa:bb:cc:dd:ee:01"}
    if overrides:
        base.update(overrides)
    return base


def _posture(overrides=None):
    base = {
        "antivirus": True,
        "firewall": True,
        "os_patched": True,
        "disk_encrypted": True,
        "compliant_software": True,
    }
    if overrides:
        base.update(overrides)
    return base


def _policy(overrides=None):
    base = {"name": "Default Policy", "required_posture_score": 80, "action": "allow", "applies_to": "all"}
    if overrides:
        base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Endpoint Registration
# ---------------------------------------------------------------------------

class TestRegisterEndpoint:
    def test_returns_dict_with_id(self, engine):
        result = engine.register_endpoint(ORG, _ep())
        assert "id" in result
        assert len(result["id"]) == 36

    def test_stores_name_and_mac(self, engine):
        result = engine.register_endpoint(ORG, _ep({"name": "Laptop-42", "mac_address": "de:ad:be:ef:00:01"}))
        assert result["name"] == "Laptop-42"
        assert result["mac_address"] == "de:ad:be:ef:00:01"

    def test_default_device_type_workstation(self, engine):
        result = engine.register_endpoint(ORG, _ep())
        assert result["device_type"] == "workstation"

    def test_default_posture_status_unknown(self, engine):
        result = engine.register_endpoint(ORG, _ep())
        assert result["posture_status"] == "unknown"

    def test_default_nac_status_pending(self, engine):
        result = engine.register_endpoint(ORG, _ep())
        assert result["nac_status"] == "pending"

    def test_default_posture_score_zero(self, engine):
        result = engine.register_endpoint(ORG, _ep())
        assert result["posture_score"] == 0

    def test_optional_ip_address(self, engine):
        result = engine.register_endpoint(ORG, _ep({"ip_address": "192.168.1.100"}))
        assert result["ip_address"] == "192.168.1.100"

    def test_valid_device_types(self, engine):
        for dt in ["workstation", "laptop", "server", "mobile", "iot", "printer", "other"]:
            result = engine.register_endpoint(ORG, _ep({"device_type": dt, "mac_address": f"aa:bb:cc:00:00:{dt[:2]}"}))
            assert result["device_type"] == dt

    def test_invalid_device_type_raises(self, engine):
        with pytest.raises(ValueError, match="device_type"):
            engine.register_endpoint(ORG, _ep({"device_type": "robot"}))

    def test_missing_name_raises(self, engine):
        with pytest.raises(ValueError, match="name"):
            engine.register_endpoint(ORG, {"mac_address": "aa:bb:cc:dd:ee:ff"})

    def test_missing_mac_raises(self, engine):
        with pytest.raises(ValueError, match="mac_address"):
            engine.register_endpoint(ORG, {"name": "PC-1"})


# ---------------------------------------------------------------------------
# List and Get Endpoints
# ---------------------------------------------------------------------------

class TestListAndGetEndpoint:
    def test_list_returns_all_for_org(self, engine):
        engine.register_endpoint(ORG, _ep({"mac_address": "aa:01:01:01:01:01"}))
        engine.register_endpoint(ORG, _ep({"mac_address": "aa:02:02:02:02:02"}))
        assert len(engine.list_endpoints(ORG)) == 2

    def test_list_filter_by_device_type(self, engine):
        engine.register_endpoint(ORG, _ep({"device_type": "laptop", "mac_address": "aa:01:00:00:00:01"}))
        engine.register_endpoint(ORG, _ep({"device_type": "server", "mac_address": "aa:02:00:00:00:02"}))
        results = engine.list_endpoints(ORG, device_type="laptop")
        assert len(results) == 1
        assert results[0]["device_type"] == "laptop"

    def test_list_filter_by_nac_status(self, engine):
        ep = engine.register_endpoint(ORG, _ep())
        engine.assess_posture(ORG, ep["id"], _posture())
        results = engine.list_endpoints(ORG, nac_status="allowed")
        assert len(results) == 1

    def test_get_endpoint_found(self, engine):
        ep = engine.register_endpoint(ORG, _ep())
        fetched = engine.get_endpoint(ORG, ep["id"])
        assert fetched["id"] == ep["id"]

    def test_get_endpoint_not_found_raises(self, engine):
        with pytest.raises(ValueError):
            engine.get_endpoint(ORG, "bad-id")


# ---------------------------------------------------------------------------
# Posture Assessment — Score Math
# ---------------------------------------------------------------------------

class TestAssessPosture:
    def test_all_true_score_100(self, engine):
        ep = engine.register_endpoint(ORG, _ep())
        result = engine.assess_posture(ORG, ep["id"], _posture())
        assert result["posture_score"] == 100

    def test_no_checks_score_0(self, engine):
        ep = engine.register_endpoint(ORG, _ep())
        result = engine.assess_posture(ORG, ep["id"], _posture({
            "antivirus": False, "firewall": False, "os_patched": False,
            "disk_encrypted": False, "compliant_software": False,
        }))
        assert result["posture_score"] == 0

    def test_one_check_score_20(self, engine):
        ep = engine.register_endpoint(ORG, _ep())
        result = engine.assess_posture(ORG, ep["id"], _posture({
            "antivirus": True, "firewall": False, "os_patched": False,
            "disk_encrypted": False, "compliant_software": False,
        }))
        assert result["posture_score"] == 20

    def test_two_checks_score_40(self, engine):
        ep = engine.register_endpoint(ORG, _ep())
        result = engine.assess_posture(ORG, ep["id"], _posture({
            "antivirus": True, "firewall": True, "os_patched": False,
            "disk_encrypted": False, "compliant_software": False,
        }))
        assert result["posture_score"] == 40

    def test_three_checks_score_60(self, engine):
        ep = engine.register_endpoint(ORG, _ep())
        result = engine.assess_posture(ORG, ep["id"], _posture({
            "antivirus": True, "firewall": True, "os_patched": True,
            "disk_encrypted": False, "compliant_software": False,
        }))
        assert result["posture_score"] == 60

    def test_four_checks_score_80(self, engine):
        ep = engine.register_endpoint(ORG, _ep())
        result = engine.assess_posture(ORG, ep["id"], _posture({
            "antivirus": True, "firewall": True, "os_patched": True,
            "disk_encrypted": True, "compliant_software": False,
        }))
        assert result["posture_score"] == 80

    def test_five_checks_score_100(self, engine):
        ep = engine.register_endpoint(ORG, _ep())
        result = engine.assess_posture(ORG, ep["id"], _posture())
        assert result["posture_score"] == 100

    # NAC status derivation

    def test_score_100_gives_compliant_allowed(self, engine):
        ep = engine.register_endpoint(ORG, _ep())
        result = engine.assess_posture(ORG, ep["id"], _posture())
        assert result["posture_status"] == "compliant"
        assert result["nac_status"] == "allowed"

    def test_score_80_gives_warning_restricted(self, engine):
        ep = engine.register_endpoint(ORG, _ep())
        result = engine.assess_posture(ORG, ep["id"], _posture({
            "antivirus": True, "firewall": True, "os_patched": True,
            "disk_encrypted": True, "compliant_software": False,
        }))
        assert result["posture_status"] == "warning"
        assert result["nac_status"] == "restricted"

    def test_score_60_gives_warning_restricted(self, engine):
        ep = engine.register_endpoint(ORG, _ep())
        result = engine.assess_posture(ORG, ep["id"], _posture({
            "antivirus": True, "firewall": True, "os_patched": True,
            "disk_encrypted": False, "compliant_software": False,
        }))
        assert result["posture_status"] == "warning"
        assert result["nac_status"] == "restricted"

    def test_score_40_gives_non_compliant_quarantined(self, engine):
        ep = engine.register_endpoint(ORG, _ep())
        result = engine.assess_posture(ORG, ep["id"], _posture({
            "antivirus": True, "firewall": True, "os_patched": False,
            "disk_encrypted": False, "compliant_software": False,
        }))
        assert result["posture_status"] == "non_compliant"
        assert result["nac_status"] == "quarantined"

    def test_score_0_gives_non_compliant_quarantined(self, engine):
        ep = engine.register_endpoint(ORG, _ep())
        result = engine.assess_posture(ORG, ep["id"], _posture({
            "antivirus": False, "firewall": False, "os_patched": False,
            "disk_encrypted": False, "compliant_software": False,
        }))
        assert result["posture_status"] == "non_compliant"
        assert result["nac_status"] == "quarantined"

    def test_assessed_at_set(self, engine):
        ep = engine.register_endpoint(ORG, _ep())
        result = engine.assess_posture(ORG, ep["id"], _posture())
        assert result["assessed_at"] is not None

    def test_wrong_org_raises(self, engine):
        ep = engine.register_endpoint(ORG, _ep())
        with pytest.raises(ValueError):
            engine.assess_posture(ORG2, ep["id"], _posture())


# ---------------------------------------------------------------------------
# NAC Status Update
# ---------------------------------------------------------------------------

class TestUpdateNacStatus:
    def test_valid_status_allowed(self, engine):
        ep = engine.register_endpoint(ORG, _ep())
        result = engine.update_nac_status(ORG, ep["id"], "allowed", "manual approval")
        assert result["nac_status"] == "allowed"

    def test_valid_status_quarantined(self, engine):
        ep = engine.register_endpoint(ORG, _ep())
        result = engine.update_nac_status(ORG, ep["id"], "quarantined", "threat detected")
        assert result["nac_status"] == "quarantined"
        assert result["status_reason"] == "threat detected"

    def test_valid_status_blocked(self, engine):
        ep = engine.register_endpoint(ORG, _ep())
        result = engine.update_nac_status(ORG, ep["id"], "blocked")
        assert result["nac_status"] == "blocked"

    def test_invalid_status_raises(self, engine):
        ep = engine.register_endpoint(ORG, _ep())
        with pytest.raises(ValueError, match="nac_status"):
            engine.update_nac_status(ORG, ep["id"], "unknown_status")

    def test_wrong_org_raises(self, engine):
        ep = engine.register_endpoint(ORG, _ep())
        with pytest.raises(ValueError):
            engine.update_nac_status(ORG2, ep["id"], "allowed")


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------

class TestNacPolicies:
    def test_create_policy_returns_record(self, engine):
        result = engine.create_nac_policy(ORG, _policy())
        assert "id" in result
        assert result["name"] == "Default Policy"
        assert result["status"] == "active"

    def test_create_policy_stores_fields(self, engine):
        result = engine.create_nac_policy(ORG, _policy({
            "required_posture_score": 60, "action": "quarantine", "applies_to": "laptop"
        }))
        assert result["required_posture_score"] == 60
        assert result["action"] == "quarantine"
        assert result["applies_to"] == "laptop"

    def test_invalid_action_raises(self, engine):
        with pytest.raises(ValueError, match="action"):
            engine.create_nac_policy(ORG, _policy({"action": "deny"}))

    def test_invalid_applies_to_raises(self, engine):
        with pytest.raises(ValueError, match="applies_to"):
            engine.create_nac_policy(ORG, _policy({"applies_to": "tablet"}))

    def test_score_out_of_range_raises(self, engine):
        with pytest.raises(ValueError, match="required_posture_score"):
            engine.create_nac_policy(ORG, _policy({"required_posture_score": 150}))

    def test_missing_name_raises(self, engine):
        with pytest.raises(ValueError, match="name"):
            engine.create_nac_policy(ORG, {"required_posture_score": 80, "action": "allow", "applies_to": "all"})

    def test_list_nac_policies(self, engine):
        engine.create_nac_policy(ORG, _policy({"name": "Policy A"}))
        engine.create_nac_policy(ORG, _policy({"name": "Policy B"}))
        results = engine.list_nac_policies(ORG)
        assert len(results) == 2


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

class TestNacStats:
    def test_total_endpoints(self, engine):
        engine.register_endpoint(ORG, _ep({"mac_address": "aa:01:00:00:00:01"}))
        engine.register_endpoint(ORG, _ep({"mac_address": "aa:02:00:00:00:02"}))
        stats = engine.get_nac_stats(ORG)
        assert stats["total_endpoints"] == 2

    def test_by_device_type(self, engine):
        engine.register_endpoint(ORG, _ep({"device_type": "laptop", "mac_address": "aa:01:00:00:00:01"}))
        engine.register_endpoint(ORG, _ep({"device_type": "laptop", "mac_address": "aa:02:00:00:00:02"}))
        engine.register_endpoint(ORG, _ep({"device_type": "server", "mac_address": "aa:03:00:00:00:03"}))
        stats = engine.get_nac_stats(ORG)
        assert stats["by_device_type"]["laptop"] == 2
        assert stats["by_device_type"]["server"] == 1

    def test_avg_posture_score(self, engine):
        ep1 = engine.register_endpoint(ORG, _ep({"mac_address": "aa:01:00:00:00:01"}))
        ep2 = engine.register_endpoint(ORG, _ep({"mac_address": "aa:02:00:00:00:02"}))
        engine.assess_posture(ORG, ep1["id"], _posture())  # score=100
        engine.assess_posture(ORG, ep2["id"], _posture({
            "antivirus": False, "firewall": False, "os_patched": False,
            "disk_encrypted": False, "compliant_software": False,
        }))  # score=0
        stats = engine.get_nac_stats(ORG)
        assert stats["avg_posture_score"] == 50.0

    def test_compliant_pct(self, engine):
        ep1 = engine.register_endpoint(ORG, _ep({"mac_address": "aa:01:00:00:00:01"}))
        ep2 = engine.register_endpoint(ORG, _ep({"mac_address": "aa:02:00:00:00:02"}))
        engine.assess_posture(ORG, ep1["id"], _posture())  # allowed
        engine.assess_posture(ORG, ep2["id"], _posture({
            "antivirus": False, "firewall": False, "os_patched": False,
            "disk_encrypted": False, "compliant_software": False,
        }))  # quarantined
        stats = engine.get_nac_stats(ORG)
        assert stats["compliant_pct"] == 50.0

    def test_quarantined_count(self, engine):
        ep1 = engine.register_endpoint(ORG, _ep({"mac_address": "aa:01:00:00:00:01"}))
        ep2 = engine.register_endpoint(ORG, _ep({"mac_address": "aa:02:00:00:00:02"}))
        engine.assess_posture(ORG, ep1["id"], _posture({
            "antivirus": False, "firewall": False, "os_patched": False,
            "disk_encrypted": False, "compliant_software": False,
        }))
        engine.assess_posture(ORG, ep2["id"], _posture({
            "antivirus": False, "firewall": False, "os_patched": False,
            "disk_encrypted": False, "compliant_software": False,
        }))
        stats = engine.get_nac_stats(ORG)
        assert stats["quarantined_count"] == 2

    def test_empty_org_stats(self, engine):
        stats = engine.get_nac_stats("empty-org")
        assert stats["total_endpoints"] == 0
        assert stats["avg_posture_score"] == 0.0
        assert stats["compliant_pct"] == 0.0
        assert stats["quarantined_count"] == 0


# ---------------------------------------------------------------------------
# Org Isolation
# ---------------------------------------------------------------------------

class TestOrgIsolation:
    def test_endpoints_isolated_by_org(self, engine):
        engine.register_endpoint(ORG, _ep({"name": "EP-Org1", "mac_address": "aa:01:00:00:00:01"}))
        engine.register_endpoint(ORG2, _ep({"name": "EP-Org2", "mac_address": "bb:01:00:00:00:01"}))
        org1_eps = engine.list_endpoints(ORG)
        org2_eps = engine.list_endpoints(ORG2)
        assert len(org1_eps) == 1
        assert org1_eps[0]["name"] == "EP-Org1"
        assert len(org2_eps) == 1
        assert org2_eps[0]["name"] == "EP-Org2"

    def test_get_endpoint_cross_org_raises(self, engine):
        ep = engine.register_endpoint(ORG, _ep())
        with pytest.raises(ValueError):
            engine.get_endpoint(ORG2, ep["id"])

    def test_policies_isolated_by_org(self, engine):
        engine.create_nac_policy(ORG, _policy({"name": "Pol-1"}))
        engine.create_nac_policy(ORG, _policy({"name": "Pol-2"}))
        engine.create_nac_policy(ORG2, _policy({"name": "Pol-3"}))
        assert len(engine.list_nac_policies(ORG)) == 2
        assert len(engine.list_nac_policies(ORG2)) == 1

    def test_stats_isolated_by_org(self, engine):
        engine.register_endpoint(ORG, _ep({"mac_address": "aa:01:00:00:00:01"}))
        engine.register_endpoint(ORG, _ep({"mac_address": "aa:02:00:00:00:02"}))
        stats1 = engine.get_nac_stats(ORG)
        stats2 = engine.get_nac_stats(ORG2)
        assert stats1["total_endpoints"] == 2
        assert stats2["total_endpoints"] == 0
