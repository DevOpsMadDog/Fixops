"""Tests for CloudAccessSecurityEngine — 32 tests."""

from __future__ import annotations

import pytest

from core.cloud_access_security_engine import CloudAccessSecurityEngine


@pytest.fixture()
def engine(tmp_path):
    return CloudAccessSecurityEngine(db_path=str(tmp_path / "cas.db"))


# ---------------------------------------------------------------------------
# register_cloud_app
# ---------------------------------------------------------------------------


def test_register_app_basic(engine):
    app = engine.register_cloud_app("org1", {"name": "Salesforce", "app_category": "saas"})
    assert app["id"]
    assert app["name"] == "Salesforce"
    assert app["app_category"] == "saas"
    assert app["org_id"] == "org1"
    assert app["users_count"] == 0
    assert app["sanctioned"] == 1


def test_register_app_all_fields(engine):
    app = engine.register_cloud_app("org1", {
        "name": "AWS S3",
        "app_category": "iaas",
        "vendor": "Amazon",
        "risk_level": "high",
        "data_exposure_level": "confidential",
        "sanctioned": False,
    })
    assert app["app_category"] == "iaas"
    assert app["risk_level"] == "high"
    assert app["data_exposure_level"] == "confidential"
    assert app["sanctioned"] == 0
    assert app["vendor"] == "Amazon"


def test_register_app_missing_name_raises(engine):
    with pytest.raises(ValueError, match="name"):
        engine.register_cloud_app("org1", {"app_category": "saas"})


def test_register_app_empty_name_raises(engine):
    with pytest.raises(ValueError, match="name"):
        engine.register_cloud_app("org1", {"name": "   ", "app_category": "saas"})


def test_register_app_invalid_category_raises(engine):
    with pytest.raises(ValueError, match="app_category"):
        engine.register_cloud_app("org1", {"name": "X", "app_category": "invalid"})


def test_register_app_invalid_risk_level_raises(engine):
    with pytest.raises(ValueError, match="risk_level"):
        engine.register_cloud_app("org1", {"name": "X", "risk_level": "extreme"})


def test_register_all_categories(engine):
    categories = ["saas", "paas", "iaas", "collaboration", "storage",
                  "communication", "productivity", "security"]
    for cat in categories:
        app = engine.register_cloud_app("org1", {"name": f"App-{cat}", "app_category": cat})
        assert app["app_category"] == cat


def test_register_all_risk_levels(engine):
    for lvl in ["critical", "high", "medium", "low"]:
        app = engine.register_cloud_app("org1", {"name": f"App-{lvl}", "risk_level": lvl})
        assert app["risk_level"] == lvl


# ---------------------------------------------------------------------------
# list_cloud_apps
# ---------------------------------------------------------------------------


def test_list_cloud_apps_empty(engine):
    assert engine.list_cloud_apps("org1") == []


def test_list_cloud_apps_all(engine):
    engine.register_cloud_app("org1", {"name": "A", "app_category": "saas"})
    engine.register_cloud_app("org1", {"name": "B", "app_category": "paas"})
    assert len(engine.list_cloud_apps("org1")) == 2


def test_list_cloud_apps_filter_category(engine):
    engine.register_cloud_app("org1", {"name": "A", "app_category": "saas"})
    engine.register_cloud_app("org1", {"name": "B", "app_category": "paas"})
    result = engine.list_cloud_apps("org1", app_category="saas")
    assert len(result) == 1
    assert result[0]["name"] == "A"


def test_list_cloud_apps_filter_risk_level(engine):
    engine.register_cloud_app("org1", {"name": "High", "risk_level": "high"})
    engine.register_cloud_app("org1", {"name": "Low", "risk_level": "low"})
    result = engine.list_cloud_apps("org1", risk_level="high")
    assert len(result) == 1
    assert result[0]["name"] == "High"


def test_list_cloud_apps_filter_sanctioned_true(engine):
    engine.register_cloud_app("org1", {"name": "S", "sanctioned": True})
    engine.register_cloud_app("org1", {"name": "U", "sanctioned": False})
    result = engine.list_cloud_apps("org1", sanctioned=True)
    assert all(r["sanctioned"] == 1 for r in result)
    assert len(result) == 1


def test_list_cloud_apps_filter_sanctioned_false(engine):
    engine.register_cloud_app("org1", {"name": "S", "sanctioned": True})
    engine.register_cloud_app("org1", {"name": "U", "sanctioned": False})
    result = engine.list_cloud_apps("org1", sanctioned=False)
    assert len(result) == 1
    assert result[0]["sanctioned"] == 0


def test_list_cloud_apps_org_isolation(engine):
    engine.register_cloud_app("org1", {"name": "A"})
    engine.register_cloud_app("org2", {"name": "B"})
    assert len(engine.list_cloud_apps("org1")) == 1
    assert len(engine.list_cloud_apps("org2")) == 1


# ---------------------------------------------------------------------------
# get_cloud_app
# ---------------------------------------------------------------------------


def test_get_cloud_app_found(engine):
    created = engine.register_cloud_app("org1", {"name": "Slack"})
    fetched = engine.get_cloud_app("org1", created["id"])
    assert fetched["name"] == "Slack"


def test_get_cloud_app_not_found(engine):
    assert engine.get_cloud_app("org1", "nonexistent") is None


def test_get_cloud_app_wrong_org(engine):
    created = engine.register_cloud_app("org1", {"name": "Zoom"})
    assert engine.get_cloud_app("org2", created["id"]) is None


# ---------------------------------------------------------------------------
# record_access_event
# ---------------------------------------------------------------------------


def test_record_access_event_basic(engine):
    app = engine.register_cloud_app("org1", {"name": "GitHub"})
    event = engine.record_access_event("org1", {
        "app_id": app["id"],
        "user_id": "u1",
        "access_type": "oauth",
    })
    assert event["id"]
    assert event["app_id"] == app["id"]
    assert event["access_type"] == "oauth"


def test_record_access_event_missing_app_id_raises(engine):
    with pytest.raises(ValueError, match="app_id"):
        engine.record_access_event("org1", {"user_id": "u1"})


def test_record_access_event_invalid_access_type_raises(engine):
    app = engine.register_cloud_app("org1", {"name": "App"})
    with pytest.raises(ValueError, match="access_type"):
        engine.record_access_event("org1", {"app_id": app["id"], "access_type": "magic"})


def test_record_access_event_updates_last_activity(engine):
    app = engine.register_cloud_app("org1", {"name": "App"})
    assert engine.get_cloud_app("org1", app["id"])["last_activity"] is None
    engine.record_access_event("org1", {"app_id": app["id"], "user_id": "u1"})
    assert engine.get_cloud_app("org1", app["id"])["last_activity"] is not None


def test_record_access_event_increments_users_count(engine):
    app = engine.register_cloud_app("org1", {"name": "App"})
    engine.record_access_event("org1", {"app_id": app["id"], "user_id": "u1"})
    engine.record_access_event("org1", {"app_id": app["id"], "user_id": "u2"})
    assert engine.get_cloud_app("org1", app["id"])["users_count"] == 2


def test_record_access_event_same_user_no_double_count(engine):
    app = engine.register_cloud_app("org1", {"name": "App"})
    engine.record_access_event("org1", {"app_id": app["id"], "user_id": "u1"})
    engine.record_access_event("org1", {"app_id": app["id"], "user_id": "u1"})
    assert engine.get_cloud_app("org1", app["id"])["users_count"] == 1


def test_record_access_event_all_access_types(engine):
    app = engine.register_cloud_app("org1", {"name": "App"})
    for at in ["oauth", "saml", "api_key", "password", "sso"]:
        ev = engine.record_access_event("org1", {"app_id": app["id"], "access_type": at, "user_id": at})
        assert ev["access_type"] == at


# ---------------------------------------------------------------------------
# create_policy / list_policies
# ---------------------------------------------------------------------------


def test_create_policy_basic(engine):
    policy = engine.create_policy("org1", {
        "name": "Block Dropbox",
        "app_category": "storage",
        "policy_action": "block",
    })
    assert policy["id"]
    assert policy["policy_action"] == "block"
    assert policy["enabled"] == 1


def test_create_policy_invalid_action_raises(engine):
    with pytest.raises(ValueError, match="policy_action"):
        engine.create_policy("org1", {"policy_action": "destroy"})


def test_list_policies_empty(engine):
    assert engine.list_policies("org1") == []


def test_list_policies_filter_enabled(engine):
    engine.create_policy("org1", {"policy_action": "allow", "enabled": True})
    engine.create_policy("org1", {"policy_action": "block", "enabled": False})
    result = engine.list_policies("org1", enabled=True)
    assert len(result) == 1


def test_list_policies_filter_category(engine):
    engine.create_policy("org1", {"policy_action": "monitor", "app_category": "saas"})
    engine.create_policy("org1", {"policy_action": "block", "app_category": "storage"})
    result = engine.list_policies("org1", app_category="storage")
    assert len(result) == 1
    assert result[0]["app_category"] == "storage"


def test_create_policy_all_actions(engine):
    for action in ["allow", "block", "monitor", "require_mfa", "limit_data"]:
        p = engine.create_policy("org1", {"policy_action": action})
        assert p["policy_action"] == action


# ---------------------------------------------------------------------------
# get_cloud_access_stats
# ---------------------------------------------------------------------------


def test_stats_empty(engine):
    stats = engine.get_cloud_access_stats("org1")
    assert stats["total_apps"] == 0
    assert stats["total_events"] == 0
    assert stats["unique_users"] == 0
    assert stats["by_category"] == {}


def test_stats_populated(engine):
    a1 = engine.register_cloud_app("org1", {"name": "A", "app_category": "saas", "risk_level": "high"})
    a2 = engine.register_cloud_app("org1", {"name": "B", "app_category": "paas", "risk_level": "low", "sanctioned": False})
    engine.register_cloud_app("org1", {"name": "C", "app_category": "saas", "risk_level": "critical"})
    engine.record_access_event("org1", {"app_id": a1["id"], "user_id": "u1"})
    engine.record_access_event("org1", {"app_id": a1["id"], "user_id": "u2"})
    engine.record_access_event("org1", {"app_id": a2["id"], "user_id": "u1"})

    stats = engine.get_cloud_access_stats("org1")
    assert stats["total_apps"] == 3
    assert stats["unsanctioned_apps"] == 1
    assert stats["high_risk_apps"] == 2  # high + critical
    assert stats["total_events"] == 3
    assert stats["unique_users"] == 2
    assert stats["by_category"]["saas"] == 2
    assert stats["by_category"]["paas"] == 1
