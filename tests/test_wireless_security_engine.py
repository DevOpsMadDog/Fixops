"""Tests for WirelessSecurityEngine.

Covers:
- AP registration: valid/invalid bands and protocols
- AP listing with filters, get by ID
- Threat recording: valid/invalid threat types and severities
- Threat listing with filters
- Threat resolution
- insecure_aps count (open/wep/wpa protocols)
- Stats correctness
- Multi-tenant org isolation
"""

from __future__ import annotations

import os

import pytest

os.environ.setdefault("FIXOPS_MODE", "dev")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")

from core.wireless_security_engine import WirelessSecurityEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    return WirelessSecurityEngine(db_path=str(tmp_path / "wireless.db"))


ORG = "org-wireless-test"
ORG2 = "org-wireless-other"


def _ap(overrides=None):
    base = {"name": "AP-Main", "band": "5ghz", "security_protocol": "wpa2"}
    if overrides:
        base.update(overrides)
    return base


def _threat(overrides=None):
    base = {"threat_type": "rogue_ap", "severity": "high"}
    if overrides:
        base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# AP Registration
# ---------------------------------------------------------------------------

class TestRegisterAccessPoint:
    def test_returns_dict_with_id(self, engine):
        result = engine.register_access_point(ORG, _ap())
        assert "id" in result
        assert len(result["id"]) == 36

    def test_stores_name_band_protocol(self, engine):
        result = engine.register_access_point(ORG, _ap({"name": "Office-AP", "band": "2.4ghz", "security_protocol": "wpa3"}))
        assert result["name"] == "Office-AP"
        assert result["band"] == "2.4ghz"
        assert result["security_protocol"] == "wpa3"

    def test_defaults_status_active(self, engine):
        result = engine.register_access_point(ORG, _ap())
        assert result["status"] == "active"

    def test_defaults_signal_strength_zero(self, engine):
        result = engine.register_access_point(ORG, _ap())
        assert result["signal_strength"] == 0

    def test_defaults_connected_clients_zero(self, engine):
        result = engine.register_access_point(ORG, _ap())
        assert result["connected_clients"] == 0

    def test_stores_optional_ssid_bssid_location(self, engine):
        result = engine.register_access_point(ORG, _ap({
            "ssid": "CorpNet", "bssid": "aa:bb:cc:dd:ee:ff", "location": "Floor 2"
        }))
        assert result["ssid"] == "CorpNet"
        assert result["bssid"] == "aa:bb:cc:dd:ee:ff"
        assert result["location"] == "Floor 2"

    def test_valid_band_2_4ghz(self, engine):
        result = engine.register_access_point(ORG, _ap({"band": "2.4ghz"}))
        assert result["band"] == "2.4ghz"

    def test_valid_band_6ghz(self, engine):
        result = engine.register_access_point(ORG, _ap({"band": "6ghz"}))
        assert result["band"] == "6ghz"

    def test_valid_band_dual_band(self, engine):
        result = engine.register_access_point(ORG, _ap({"band": "dual_band"}))
        assert result["band"] == "dual_band"

    def test_invalid_band_raises(self, engine):
        with pytest.raises(ValueError, match="band"):
            engine.register_access_point(ORG, _ap({"band": "3ghz"}))

    def test_missing_name_raises(self, engine):
        with pytest.raises(ValueError, match="name"):
            engine.register_access_point(ORG, {"band": "5ghz"})

    def test_valid_protocol_open(self, engine):
        result = engine.register_access_point(ORG, _ap({"security_protocol": "open"}))
        assert result["security_protocol"] == "open"

    def test_valid_protocol_wep(self, engine):
        result = engine.register_access_point(ORG, _ap({"security_protocol": "wep"}))
        assert result["security_protocol"] == "wep"

    def test_valid_protocol_wpa(self, engine):
        result = engine.register_access_point(ORG, _ap({"security_protocol": "wpa"}))
        assert result["security_protocol"] == "wpa"

    def test_valid_protocol_wpa3(self, engine):
        result = engine.register_access_point(ORG, _ap({"security_protocol": "wpa3"}))
        assert result["security_protocol"] == "wpa3"

    def test_invalid_protocol_raises(self, engine):
        with pytest.raises(ValueError, match="security_protocol"):
            engine.register_access_point(ORG, _ap({"security_protocol": "tkip"}))


# ---------------------------------------------------------------------------
# AP Listing and Get
# ---------------------------------------------------------------------------

class TestListAndGetAP:
    def test_list_returns_all_for_org(self, engine):
        engine.register_access_point(ORG, _ap({"name": "AP-1"}))
        engine.register_access_point(ORG, _ap({"name": "AP-2"}))
        results = engine.list_access_points(ORG)
        assert len(results) == 2

    def test_list_filter_by_band(self, engine):
        engine.register_access_point(ORG, _ap({"band": "2.4ghz"}))
        engine.register_access_point(ORG, _ap({"band": "5ghz"}))
        results = engine.list_access_points(ORG, band="2.4ghz")
        assert len(results) == 1
        assert results[0]["band"] == "2.4ghz"

    def test_list_filter_by_security_protocol(self, engine):
        engine.register_access_point(ORG, _ap({"security_protocol": "wpa2"}))
        engine.register_access_point(ORG, _ap({"security_protocol": "open"}))
        results = engine.list_access_points(ORG, security_protocol="open")
        assert len(results) == 1
        assert results[0]["security_protocol"] == "open"

    def test_get_access_point_found(self, engine):
        ap = engine.register_access_point(ORG, _ap())
        fetched = engine.get_access_point(ORG, ap["id"])
        assert fetched["id"] == ap["id"]

    def test_get_access_point_not_found_raises(self, engine):
        with pytest.raises(ValueError):
            engine.get_access_point(ORG, "nonexistent-id")


# ---------------------------------------------------------------------------
# Threat Recording
# ---------------------------------------------------------------------------

class TestRecordWirelessThreat:
    def test_returns_dict_with_id(self, engine):
        result = engine.record_wireless_threat(ORG, _threat())
        assert "id" in result
        assert len(result["id"]) == 36

    def test_defaults_status_detected(self, engine):
        result = engine.record_wireless_threat(ORG, _threat())
        assert result["status"] == "detected"

    def test_stores_threat_type_and_severity(self, engine):
        result = engine.record_wireless_threat(ORG, _threat({"threat_type": "evil_twin", "severity": "critical"}))
        assert result["threat_type"] == "evil_twin"
        assert result["severity"] == "critical"

    def test_all_valid_threat_types(self, engine):
        types = ["rogue_ap", "evil_twin", "deauth_attack", "krack", "pmkid", "wardriving", "eavesdropping"]
        for t in types:
            result = engine.record_wireless_threat(ORG, _threat({"threat_type": t}))
            assert result["threat_type"] == t

    def test_invalid_threat_type_raises(self, engine):
        with pytest.raises(ValueError, match="threat_type"):
            engine.record_wireless_threat(ORG, _threat({"threat_type": "unknown_attack"}))

    def test_invalid_severity_raises(self, engine):
        with pytest.raises(ValueError, match="severity"):
            engine.record_wireless_threat(ORG, _threat({"severity": "extreme"}))

    def test_optional_ap_id_wired(self, engine):
        ap = engine.register_access_point(ORG, _ap())
        result = engine.record_wireless_threat(ORG, _threat({"ap_id": ap["id"]}))
        assert result["ap_id"] == ap["id"]

    def test_ap_id_wrong_org_raises(self, engine):
        ap = engine.register_access_point(ORG, _ap())
        with pytest.raises(ValueError):
            engine.record_wireless_threat(ORG2, _threat({"ap_id": ap["id"]}))

    def test_optional_bssid_stored(self, engine):
        result = engine.record_wireless_threat(ORG, _threat({"bssid": "11:22:33:44:55:66"}))
        assert result["bssid"] == "11:22:33:44:55:66"


# ---------------------------------------------------------------------------
# Threat Listing and Resolution
# ---------------------------------------------------------------------------

class TestListAndResolve:
    def test_list_returns_all_threats(self, engine):
        engine.record_wireless_threat(ORG, _threat())
        engine.record_wireless_threat(ORG, _threat({"threat_type": "evil_twin"}))
        results = engine.list_wireless_threats(ORG)
        assert len(results) == 2

    def test_list_filter_by_threat_type(self, engine):
        engine.record_wireless_threat(ORG, _threat({"threat_type": "rogue_ap"}))
        engine.record_wireless_threat(ORG, _threat({"threat_type": "evil_twin"}))
        results = engine.list_wireless_threats(ORG, threat_type="rogue_ap")
        assert len(results) == 1
        assert results[0]["threat_type"] == "rogue_ap"

    def test_list_filter_by_status(self, engine):
        t = engine.record_wireless_threat(ORG, _threat())
        engine.resolve_threat(ORG, t["id"], "Mitigated")
        detected = engine.list_wireless_threats(ORG, status="detected")
        resolved = engine.list_wireless_threats(ORG, status="resolved")
        assert len(detected) == 0
        assert len(resolved) == 1

    def test_resolve_sets_status_resolved(self, engine):
        t = engine.record_wireless_threat(ORG, _threat())
        result = engine.resolve_threat(ORG, t["id"], "AP removed from network")
        assert result["status"] == "resolved"
        assert result["resolution"] == "AP removed from network"
        assert result["resolved_at"] is not None

    def test_resolve_nonexistent_raises(self, engine):
        with pytest.raises(ValueError):
            engine.resolve_threat(ORG, "bad-id", "resolution")


# ---------------------------------------------------------------------------
# Stats and Insecure APs
# ---------------------------------------------------------------------------

class TestWirelessStats:
    def test_total_aps_count(self, engine):
        engine.register_access_point(ORG, _ap())
        engine.register_access_point(ORG, _ap())
        stats = engine.get_wireless_stats(ORG)
        assert stats["total_aps"] == 2

    def test_by_band_dict(self, engine):
        engine.register_access_point(ORG, _ap({"band": "2.4ghz"}))
        engine.register_access_point(ORG, _ap({"band": "5ghz"}))
        engine.register_access_point(ORG, _ap({"band": "5ghz"}))
        stats = engine.get_wireless_stats(ORG)
        assert stats["by_band"]["2.4ghz"] == 1
        assert stats["by_band"]["5ghz"] == 2

    def test_insecure_aps_counts_open_wep_wpa(self, engine):
        engine.register_access_point(ORG, _ap({"security_protocol": "open"}))
        engine.register_access_point(ORG, _ap({"security_protocol": "wep"}))
        engine.register_access_point(ORG, _ap({"security_protocol": "wpa"}))
        engine.register_access_point(ORG, _ap({"security_protocol": "wpa2"}))
        engine.register_access_point(ORG, _ap({"security_protocol": "wpa3"}))
        stats = engine.get_wireless_stats(ORG)
        assert stats["insecure_aps"] == 3

    def test_total_threats_and_open_threats(self, engine):
        t1 = engine.record_wireless_threat(ORG, _threat())
        engine.record_wireless_threat(ORG, _threat({"threat_type": "evil_twin"}))
        engine.resolve_threat(ORG, t1["id"], "Resolved")
        stats = engine.get_wireless_stats(ORG)
        assert stats["total_threats"] == 2
        assert stats["open_threats"] == 1

    def test_by_threat_type_dict(self, engine):
        engine.record_wireless_threat(ORG, _threat({"threat_type": "rogue_ap"}))
        engine.record_wireless_threat(ORG, _threat({"threat_type": "rogue_ap"}))
        engine.record_wireless_threat(ORG, _threat({"threat_type": "krack"}))
        stats = engine.get_wireless_stats(ORG)
        assert stats["by_threat_type"]["rogue_ap"] == 2
        assert stats["by_threat_type"]["krack"] == 1

    def test_empty_org_stats(self, engine):
        stats = engine.get_wireless_stats("empty-org")
        assert stats["total_aps"] == 0
        assert stats["insecure_aps"] == 0
        assert stats["total_threats"] == 0


# ---------------------------------------------------------------------------
# Org Isolation
# ---------------------------------------------------------------------------

class TestOrgIsolation:
    def test_aps_isolated_by_org(self, engine):
        engine.register_access_point(ORG, _ap({"name": "AP-Org1"}))
        engine.register_access_point(ORG2, _ap({"name": "AP-Org2"}))
        org1_aps = engine.list_access_points(ORG)
        org2_aps = engine.list_access_points(ORG2)
        assert len(org1_aps) == 1
        assert org1_aps[0]["name"] == "AP-Org1"
        assert len(org2_aps) == 1
        assert org2_aps[0]["name"] == "AP-Org2"

    def test_threats_isolated_by_org(self, engine):
        engine.record_wireless_threat(ORG, _threat())
        engine.record_wireless_threat(ORG, _threat())
        engine.record_wireless_threat(ORG2, _threat())
        assert len(engine.list_wireless_threats(ORG)) == 2
        assert len(engine.list_wireless_threats(ORG2)) == 1

    def test_stats_isolated_by_org(self, engine):
        engine.register_access_point(ORG, _ap())
        engine.register_access_point(ORG, _ap())
        stats1 = engine.get_wireless_stats(ORG)
        stats2 = engine.get_wireless_stats(ORG2)
        assert stats1["total_aps"] == 2
        assert stats2["total_aps"] == 0

    def test_get_ap_cross_org_raises(self, engine):
        ap = engine.register_access_point(ORG, _ap())
        with pytest.raises(ValueError):
            engine.get_access_point(ORG2, ap["id"])
