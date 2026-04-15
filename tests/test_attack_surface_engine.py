"""Tests for AttackSurfaceEngine — 25+ tests covering all major paths."""

from __future__ import annotations

import pytest


@pytest.fixture
def asm_engine(tmp_path):
    from core.attack_surface_engine import AttackSurfaceEngine
    return AttackSurfaceEngine(db_dir=str(tmp_path))


ORG = "test-org-asm"
ORG2 = "other-org-asm"


# ---------------------------------------------------------------------------
# Assets
# ---------------------------------------------------------------------------

def test_add_asset_basic(asm_engine):
    asset = asm_engine.add_asset(ORG, {"asset_type": "domain", "value": "example.com"})
    assert asset["id"]
    assert asset["asset_type"] == "domain"
    assert asset["value"] == "example.com"
    assert asset["status"] == "active"


def test_add_asset_all_fields(asm_engine):
    asset = asm_engine.add_asset(ORG, {
        "asset_type": "ip",
        "value": "203.0.113.1",
        "status": "active",
        "risk_score": 5.0,
        "tags": ["external", "production"],
        "notes": "Main web server IP",
    })
    assert asset["risk_score"] == 5.0
    assert isinstance(asset["tags"], list)
    assert "external" in asset["tags"]


def test_add_asset_missing_value(asm_engine):
    with pytest.raises(ValueError, match="value"):
        asm_engine.add_asset(ORG, {"asset_type": "domain"})


def test_add_asset_invalid_type(asm_engine):
    with pytest.raises(ValueError):
        asm_engine.add_asset(ORG, {"asset_type": "unknown", "value": "x"})


def test_list_assets_empty(asm_engine):
    assert asm_engine.list_assets(ORG) == []


def test_list_assets_filtered_by_type(asm_engine):
    asm_engine.add_asset(ORG, {"asset_type": "domain", "value": "a.com"})
    asm_engine.add_asset(ORG, {"asset_type": "ip", "value": "1.2.3.4"})
    domains = asm_engine.list_assets(ORG, asset_type="domain")
    assert len(domains) == 1
    assert domains[0]["asset_type"] == "domain"


def test_list_assets_filtered_by_min_risk(asm_engine):
    asm_engine.add_asset(ORG, {"asset_type": "ip", "value": "1.1.1.1", "risk_score": 2.0})
    asm_engine.add_asset(ORG, {"asset_type": "ip", "value": "2.2.2.2", "risk_score": 8.0})
    high_risk = asm_engine.list_assets(ORG, min_risk=5.0)
    assert len(high_risk) == 1
    assert high_risk[0]["value"] == "2.2.2.2"


def test_get_asset(asm_engine):
    asset = asm_engine.add_asset(ORG, {"asset_type": "domain", "value": "test.example.com"})
    result = asm_engine.get_asset(ORG, asset["id"])
    assert result is not None
    assert result["id"] == asset["id"]
    assert "exposures" in result


def test_get_asset_not_found(asm_engine):
    assert asm_engine.get_asset(ORG, "nonexistent-id") is None


def test_get_asset_org_isolation(asm_engine):
    asset = asm_engine.add_asset(ORG, {"asset_type": "domain", "value": "org1.example.com"})
    assert asm_engine.get_asset(ORG2, asset["id"]) is None


def test_list_assets_org_isolation(asm_engine):
    asm_engine.add_asset(ORG, {"asset_type": "domain", "value": "org1domain.com"})
    assert len(asm_engine.list_assets(ORG2)) == 0


# ---------------------------------------------------------------------------
# Exposures
# ---------------------------------------------------------------------------

def test_add_exposure(asm_engine):
    asset = asm_engine.add_asset(ORG, {"asset_type": "ip", "value": "5.5.5.5"})
    exposure = asm_engine.add_exposure(ORG, asset["id"], {
        "exposure_type": "open_port",
        "severity": "high",
        "title": "RDP port 3389 exposed to internet",
        "description": "Port 3389 is accessible from the public internet.",
        "cvss_score": 7.5,
        "remediation": "Restrict access via firewall.",
    })
    assert exposure["id"]
    assert exposure["exposure_type"] == "open_port"
    assert exposure["status"] == "open"


def test_add_exposure_updates_risk_score(asm_engine):
    asset = asm_engine.add_asset(ORG, {"asset_type": "ip", "value": "6.6.6.6", "risk_score": 0.0})
    asm_engine.add_exposure(ORG, asset["id"], {
        "exposure_type": "weak_ssl",
        "severity": "critical",
        "title": "SSLv3 enabled",
    })
    updated = asm_engine.get_asset(ORG, asset["id"])
    assert updated["risk_score"] > 0  # critical adds 10


def test_add_exposure_invalid_type(asm_engine):
    asset = asm_engine.add_asset(ORG, {"asset_type": "domain", "value": "x.com"})
    with pytest.raises(ValueError):
        asm_engine.add_exposure(ORG, asset["id"], {
            "exposure_type": "magic_hack",
            "severity": "high",
            "title": "Bad exposure",
        })


def test_add_exposure_missing_title(asm_engine):
    asset = asm_engine.add_asset(ORG, {"asset_type": "domain", "value": "y.com"})
    with pytest.raises(ValueError, match="title"):
        asm_engine.add_exposure(ORG, asset["id"], {"exposure_type": "open_port", "severity": "low"})


def test_list_exposures(asm_engine):
    asset = asm_engine.add_asset(ORG, {"asset_type": "ip", "value": "7.7.7.7"})
    asm_engine.add_exposure(ORG, asset["id"], {"exposure_type": "open_port", "severity": "high", "title": "Port 22 open"})
    asm_engine.add_exposure(ORG, asset["id"], {"exposure_type": "weak_ssl", "severity": "medium", "title": "TLS 1.0"})
    all_exp = asm_engine.list_exposures(ORG)
    assert len(all_exp) >= 2


def test_list_exposures_filtered_by_severity(asm_engine):
    asset = asm_engine.add_asset(ORG, {"asset_type": "ip", "value": "8.8.8.8"})
    asm_engine.add_exposure(ORG, asset["id"], {"exposure_type": "open_port", "severity": "critical", "title": "Critical port"})
    asm_engine.add_exposure(ORG, asset["id"], {"exposure_type": "weak_ssl", "severity": "low", "title": "Minor TLS"})
    critical = asm_engine.list_exposures(ORG, severity="critical")
    assert all(e["severity"] == "critical" for e in critical)


def test_fix_exposure(asm_engine):
    asset = asm_engine.add_asset(ORG, {"asset_type": "domain", "value": "fixme.com"})
    exposure = asm_engine.add_exposure(ORG, asset["id"], {
        "exposure_type": "exposed_admin",
        "severity": "high",
        "title": "Admin panel exposed",
    })
    assert asm_engine.fix_exposure(ORG, exposure["id"]) is True
    # Verify it's now fixed
    fixed_exp = asm_engine.list_exposures(ORG, status="fixed")
    assert any(e["id"] == exposure["id"] for e in fixed_exp)


def test_fix_exposure_not_found(asm_engine):
    assert asm_engine.fix_exposure(ORG, "nonexistent-id") is False


def test_fix_exposure_org_isolation(asm_engine):
    asset = asm_engine.add_asset(ORG, {"asset_type": "domain", "value": "org1.com"})
    exposure = asm_engine.add_exposure(ORG, asset["id"], {
        "exposure_type": "open_port", "severity": "low", "title": "Low port"
    })
    assert asm_engine.fix_exposure(ORG2, exposure["id"]) is False


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------

def test_create_scan(asm_engine):
    scan = asm_engine.create_scan(ORG, {"scan_type": "full", "target_scope": ["example.com"]})
    assert scan["id"]
    assert scan["status"] == "pending"
    assert isinstance(scan["target_scope"], list)


def test_complete_scan(asm_engine):
    scan = asm_engine.create_scan(ORG, {"scan_type": "incremental"})
    result = asm_engine.complete_scan(ORG, scan["id"], {
        "assets_discovered": 10,
        "new_assets": 3,
        "new_exposures": 2,
        "critical_exposures": 1,
    })
    assert result is True
    scans = asm_engine.list_scans(ORG, status="completed")
    completed = [s for s in scans if s["id"] == scan["id"]]
    assert len(completed) == 1
    assert completed[0]["assets_discovered"] == 10


def test_complete_scan_not_found(asm_engine):
    assert asm_engine.complete_scan(ORG, "nonexistent-id", {}) is False


def test_list_scans_filtered(asm_engine):
    asm_engine.create_scan(ORG, {"scan_type": "full"})
    asm_engine.create_scan(ORG, {"scan_type": "targeted"})
    all_scans = asm_engine.list_scans(ORG)
    assert len(all_scans) >= 2
    pending = asm_engine.list_scans(ORG, status="pending")
    assert all(s["status"] == "pending" for s in pending)


def test_invalid_scan_type(asm_engine):
    with pytest.raises(ValueError):
        asm_engine.create_scan(ORG, {"scan_type": "mega-scan"})


# ---------------------------------------------------------------------------
# Changes
# ---------------------------------------------------------------------------

def test_list_changes(asm_engine):
    asm_engine.add_asset(ORG, {"asset_type": "domain", "value": "change-test.com"})
    changes = asm_engine.list_changes(ORG, days=7)
    assert len(changes) >= 1
    assert changes[0]["change_type"] == "new_asset"


def test_list_changes_org_isolation(asm_engine):
    asm_engine.add_asset(ORG, {"asset_type": "ip", "value": "10.0.0.100"})
    assert len(asm_engine.list_changes(ORG2, days=30)) == 0


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

def test_get_surface_stats_empty(asm_engine):
    stats = asm_engine.get_surface_stats(ORG)
    assert stats["total_assets"] == 0
    assert stats["total_exposures"] == 0
    assert stats["surface_score"] == 100


def test_get_surface_stats_with_data(asm_engine):
    asset = asm_engine.add_asset(ORG, {"asset_type": "domain", "value": "stats.example.com"})
    asm_engine.add_asset(ORG, {"asset_type": "ip", "value": "192.0.2.1"})
    asm_engine.add_exposure(ORG, asset["id"], {
        "exposure_type": "open_port", "severity": "critical", "title": "Port 22"
    })
    stats = asm_engine.get_surface_stats(ORG)
    assert stats["total_assets"] == 2
    assert stats["total_exposures"] == 1
    assert stats["open_critical"] == 1
    assert stats["surface_score"] < 100  # reduced by critical exposure
    assert "by_type" in stats
    assert "by_severity" in stats
    assert "by_exposure_type" in stats


def test_get_surface_stats_org_isolation(asm_engine):
    asm_engine.add_asset(ORG, {"asset_type": "domain", "value": "org1only.com"})
    stats = asm_engine.get_surface_stats(ORG2)
    assert stats["total_assets"] == 0
