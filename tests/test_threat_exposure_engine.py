"""Tests for ThreatExposureEngine — ALDECI Wave 18."""

from __future__ import annotations

import pytest

from core.threat_exposure_engine import ThreatExposureEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    return ThreatExposureEngine(db_path=str(tmp_path / "exposure.db"))


@pytest.fixture
def asset(engine):
    return engine.register_asset("org1", {
        "asset_id": "server-01",
        "asset_name": "Production Server",
        "asset_type": "host",
    })


# ---------------------------------------------------------------------------
# register_asset
# ---------------------------------------------------------------------------

def test_register_asset_basic(engine):
    result = engine.register_asset("org1", {
        "asset_id": "app-01",
        "asset_name": "Web App",
        "asset_type": "application",
    })
    assert result["asset_id"] == "app-01"
    assert result["asset_name"] == "Web App"
    assert result["asset_type"] == "application"
    assert result["exposure_score"] == 0.0
    assert result["exposure_level"] == "none"
    assert result["threat_count"] == 0


def test_register_asset_missing_asset_id_raises(engine):
    with pytest.raises(ValueError, match="asset_id"):
        engine.register_asset("org1", {"asset_name": "X", "asset_type": "host"})


def test_register_asset_missing_asset_name_raises(engine):
    with pytest.raises(ValueError, match="asset_name"):
        engine.register_asset("org1", {"asset_id": "x-01", "asset_type": "host"})


def test_register_asset_invalid_type_raises(engine):
    with pytest.raises(ValueError, match="asset_type"):
        engine.register_asset("org1", {
            "asset_id": "bad-01", "asset_name": "Bad", "asset_type": "invalid",
        })


def test_register_asset_all_valid_types(engine):
    for i, asset_type in enumerate(["host", "application", "network", "cloud", "user", "api"]):
        result = engine.register_asset("org1", {
            "asset_id": f"asset-{i}",
            "asset_name": f"Asset {asset_type}",
            "asset_type": asset_type,
        })
        assert result["asset_type"] == asset_type


# ---------------------------------------------------------------------------
# list_assets
# ---------------------------------------------------------------------------

def test_list_assets_all(engine, asset):
    engine.register_asset("org1", {"asset_id": "app-02", "asset_name": "App", "asset_type": "application"})
    results = engine.list_assets("org1")
    assert len(results) == 2


def test_list_assets_filter_by_type(engine):
    engine.register_asset("org1", {"asset_id": "h1", "asset_name": "Host1", "asset_type": "host"})
    engine.register_asset("org1", {"asset_id": "a1", "asset_name": "App1", "asset_type": "application"})
    hosts = engine.list_assets("org1", asset_type="host")
    assert all(a["asset_type"] == "host" for a in hosts)
    apps = engine.list_assets("org1", asset_type="application")
    assert all(a["asset_type"] == "application" for a in apps)


def test_list_assets_filter_by_exposure_level(engine, asset):
    # Add enough correlations to push score into critical (>=80)
    for _ in range(2):
        engine.correlate_threat("org1", {
            "asset_id": "server-01", "threat_type": "malware",
            "confidence": 100.0, "severity": "critical",
        })
    engine.calculate_exposure("org1", "server-01")
    critical = engine.list_assets("org1", exposure_level="critical")
    assert len(critical) >= 1


# ---------------------------------------------------------------------------
# get_asset
# ---------------------------------------------------------------------------

def test_get_asset_found(engine, asset):
    result = engine.get_asset("org1", "server-01")
    assert result["asset_id"] == "server-01"


def test_get_asset_wrong_org_returns_none(engine, asset):
    assert engine.get_asset("org_other", "server-01") is None


def test_get_asset_not_found_returns_none(engine):
    assert engine.get_asset("org1", "nonexistent") is None


# ---------------------------------------------------------------------------
# correlate_threat
# ---------------------------------------------------------------------------

def test_correlate_threat_basic(engine, asset):
    corr = engine.correlate_threat("org1", {
        "asset_id": "server-01",
        "threat_type": "malware",
        "confidence": 80.0,
        "severity": "high",
    })
    assert corr["asset_id"] == "server-01"
    assert corr["threat_type"] == "malware"
    assert corr["confidence"] == 80.0
    assert corr["severity"] == "high"


def test_correlate_threat_increments_threat_count(engine, asset):
    engine.correlate_threat("org1", {
        "asset_id": "server-01", "threat_type": "apt", "confidence": 50.0, "severity": "medium",
    })
    engine.correlate_threat("org1", {
        "asset_id": "server-01", "threat_type": "ransomware", "confidence": 50.0, "severity": "high",
    })
    updated = engine.get_asset("org1", "server-01")
    assert updated["threat_count"] == 2


def test_correlate_threat_all_types(engine, asset):
    for tt in ["malware", "apt", "ransomware", "phishing", "exploit", "insider"]:
        corr = engine.correlate_threat("org1", {
            "asset_id": "server-01", "threat_type": tt,
            "confidence": 50.0, "severity": "medium",
        })
        assert corr["threat_type"] == tt


def test_correlate_threat_invalid_type_raises(engine, asset):
    with pytest.raises(ValueError, match="threat_type"):
        engine.correlate_threat("org1", {
            "asset_id": "server-01", "threat_type": "unknown",
            "confidence": 50.0, "severity": "medium",
        })


def test_correlate_threat_invalid_severity_raises(engine, asset):
    with pytest.raises(ValueError, match="severity"):
        engine.correlate_threat("org1", {
            "asset_id": "server-01", "threat_type": "malware",
            "confidence": 50.0, "severity": "extreme",
        })


def test_correlate_threat_invalid_asset_raises(engine):
    with pytest.raises(KeyError):
        engine.correlate_threat("org1", {
            "asset_id": "nonexistent", "threat_type": "malware",
            "confidence": 50.0, "severity": "high",
        })


def test_correlate_threat_ioc_matched(engine, asset):
    corr = engine.correlate_threat("org1", {
        "asset_id": "server-01", "threat_type": "exploit",
        "confidence": 70.0, "severity": "high", "ioc_matched": True,
    })
    assert corr["ioc_matched"] == 1


# ---------------------------------------------------------------------------
# calculate_exposure
# ---------------------------------------------------------------------------

def test_calculate_exposure_no_correlations(engine, asset):
    result = engine.calculate_exposure("org1", "server-01")
    assert result["exposure_score"] == 0.0
    assert result["exposure_level"] == "none"


def test_calculate_exposure_critical_level(engine, asset):
    # 100% confidence * critical weight(40) = 40, two correlations = 80 -> critical
    for _ in range(2):
        engine.correlate_threat("org1", {
            "asset_id": "server-01", "threat_type": "apt",
            "confidence": 100.0, "severity": "critical",
        })
    result = engine.calculate_exposure("org1", "server-01")
    assert result["exposure_score"] == pytest.approx(80.0)
    assert result["exposure_level"] == "critical"


def test_calculate_exposure_high_level(engine, asset):
    # 100% confidence * high weight(30) = 30, two = 60 -> high
    for _ in range(2):
        engine.correlate_threat("org1", {
            "asset_id": "server-01", "threat_type": "malware",
            "confidence": 100.0, "severity": "high",
        })
    result = engine.calculate_exposure("org1", "server-01")
    assert result["exposure_score"] == pytest.approx(60.0)
    assert result["exposure_level"] == "high"


def test_calculate_exposure_medium_level(engine, asset):
    # 100% confidence * medium weight(20) = 20, two = 40 -> medium
    for _ in range(2):
        engine.correlate_threat("org1", {
            "asset_id": "server-01", "threat_type": "phishing",
            "confidence": 100.0, "severity": "medium",
        })
    result = engine.calculate_exposure("org1", "server-01")
    assert result["exposure_score"] == pytest.approx(40.0)
    assert result["exposure_level"] == "medium"


def test_calculate_exposure_low_level(engine, asset):
    # 100% confidence * low weight(10) = 10, two = 20 -> low
    for _ in range(2):
        engine.correlate_threat("org1", {
            "asset_id": "server-01", "threat_type": "insider",
            "confidence": 100.0, "severity": "low",
        })
    result = engine.calculate_exposure("org1", "server-01")
    assert result["exposure_score"] == pytest.approx(20.0)
    assert result["exposure_level"] == "low"


def test_calculate_exposure_clamped_to_100(engine, asset):
    # Many correlations — score should never exceed 100
    for _ in range(10):
        engine.correlate_threat("org1", {
            "asset_id": "server-01", "threat_type": "apt",
            "confidence": 100.0, "severity": "critical",
        })
    result = engine.calculate_exposure("org1", "server-01")
    assert result["exposure_score"] <= 100.0


def test_calculate_exposure_saves_history(engine, asset):
    engine.correlate_threat("org1", {
        "asset_id": "server-01", "threat_type": "malware",
        "confidence": 80.0, "severity": "high",
    })
    engine.calculate_exposure("org1", "server-01")
    history = engine.get_exposure_history("org1", "server-01")
    assert len(history) == 1
    assert history[0]["asset_id"] == "server-01"


def test_calculate_exposure_not_found_returns_none(engine):
    assert engine.calculate_exposure("org1", "nonexistent") is None


# ---------------------------------------------------------------------------
# get_exposure_history
# ---------------------------------------------------------------------------

def test_get_exposure_history_ordered_desc(engine, asset):
    engine.correlate_threat("org1", {
        "asset_id": "server-01", "threat_type": "malware",
        "confidence": 50.0, "severity": "medium",
    })
    engine.calculate_exposure("org1", "server-01")
    engine.correlate_threat("org1", {
        "asset_id": "server-01", "threat_type": "apt",
        "confidence": 80.0, "severity": "high",
    })
    engine.calculate_exposure("org1", "server-01")
    history = engine.get_exposure_history("org1", "server-01")
    assert len(history) == 2
    # Most recent first
    assert history[0]["recorded_at"] >= history[1]["recorded_at"]


def test_get_exposure_history_limit(engine, asset):
    for _ in range(5):
        engine.correlate_threat("org1", {
            "asset_id": "server-01", "threat_type": "exploit",
            "confidence": 30.0, "severity": "low",
        })
        engine.calculate_exposure("org1", "server-01")
    history = engine.get_exposure_history("org1", "server-01", limit=3)
    assert len(history) == 3


# ---------------------------------------------------------------------------
# get_top_exposed_assets
# ---------------------------------------------------------------------------

def test_get_top_exposed_assets_ordering(engine):
    for i, asset_id in enumerate(["a1", "a2", "a3"]):
        engine.register_asset("org1", {
            "asset_id": asset_id, "asset_name": f"Asset {i}", "asset_type": "host",
        })
        # Different exposure via correlations
        for _ in range(i + 1):
            engine.correlate_threat("org1", {
                "asset_id": asset_id, "threat_type": "malware",
                "confidence": 100.0, "severity": "high",
            })
        engine.calculate_exposure("org1", asset_id)

    top = engine.get_top_exposed_assets("org1", limit=3)
    assert top[0]["exposure_score"] >= top[1]["exposure_score"]
    assert top[1]["exposure_score"] >= top[2]["exposure_score"]


def test_get_top_exposed_assets_limit(engine):
    for i in range(5):
        engine.register_asset("org1", {
            "asset_id": f"asset-{i}", "asset_name": f"A{i}", "asset_type": "cloud",
        })
    top = engine.get_top_exposed_assets("org1", limit=3)
    assert len(top) == 3


# ---------------------------------------------------------------------------
# get_exposure_stats
# ---------------------------------------------------------------------------

def test_get_exposure_stats_empty(engine):
    stats = engine.get_exposure_stats("org1")
    assert stats["total_assets"] == 0
    assert stats["avg_exposure_score"] == 0.0
    assert stats["critical_assets"] == 0
    assert stats["total_correlations"] == 0


def test_get_exposure_stats_counts(engine, asset):
    engine.register_asset("org1", {
        "asset_id": "app-99", "asset_name": "App", "asset_type": "application",
    })
    engine.correlate_threat("org1", {
        "asset_id": "server-01", "threat_type": "apt",
        "confidence": 100.0, "severity": "critical",
    })
    engine.correlate_threat("org1", {
        "asset_id": "server-01", "threat_type": "apt",
        "confidence": 100.0, "severity": "critical",
    })
    engine.calculate_exposure("org1", "server-01")

    stats = engine.get_exposure_stats("org1")
    assert stats["total_assets"] == 2
    assert stats["total_correlations"] == 2
    assert stats["critical_assets"] >= 1
    assert "critical" in stats["by_level"]


def test_get_exposure_stats_assessed_today(engine, asset):
    engine.correlate_threat("org1", {
        "asset_id": "server-01", "threat_type": "malware",
        "confidence": 50.0, "severity": "medium",
    })
    engine.calculate_exposure("org1", "server-01")
    stats = engine.get_exposure_stats("org1")
    assert stats["assessed_today"] == 1


# ---------------------------------------------------------------------------
# list_correlations
# ---------------------------------------------------------------------------

def test_list_correlations_by_asset(engine, asset):
    engine.register_asset("org1", {"asset_id": "app-02", "asset_name": "App", "asset_type": "application"})
    engine.correlate_threat("org1", {
        "asset_id": "server-01", "threat_type": "malware",
        "confidence": 50.0, "severity": "medium",
    })
    engine.correlate_threat("org1", {
        "asset_id": "app-02", "threat_type": "phishing",
        "confidence": 60.0, "severity": "low",
    })
    corrs = engine.list_correlations("org1", asset_id="server-01")
    assert all(c["asset_id"] == "server-01" for c in corrs)


def test_list_correlations_by_threat_type(engine, asset):
    engine.correlate_threat("org1", {
        "asset_id": "server-01", "threat_type": "malware",
        "confidence": 50.0, "severity": "medium",
    })
    engine.correlate_threat("org1", {
        "asset_id": "server-01", "threat_type": "apt",
        "confidence": 60.0, "severity": "high",
    })
    malware = engine.list_correlations("org1", threat_type="malware")
    assert all(c["threat_type"] == "malware" for c in malware)


# ---------------------------------------------------------------------------
# Org isolation
# ---------------------------------------------------------------------------

def test_org_isolation(engine):
    engine.register_asset("org1", {"asset_id": "a1", "asset_name": "A1", "asset_type": "host"})
    engine.register_asset("org2", {"asset_id": "a1", "asset_name": "A1", "asset_type": "host"})

    engine.correlate_threat("org1", {
        "asset_id": "a1", "threat_type": "malware", "confidence": 80.0, "severity": "high",
    })
    engine.calculate_exposure("org1", "a1")

    org1_stats = engine.get_exposure_stats("org1")
    org2_stats = engine.get_exposure_stats("org2")

    assert org1_stats["total_correlations"] == 1
    assert org2_stats["total_correlations"] == 0

    # org2 asset should still be at 0 exposure
    org2_asset = engine.get_asset("org2", "a1")
    assert org2_asset["exposure_score"] == 0.0
