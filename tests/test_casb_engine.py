"""Tests for CASBEngine — Cloud Access Security Broker.

Covers: init, discover_app, sanction/unsanction, list_apps (filters),
record_data_activity, list_activities (filters), create_policy,
record_violation, shadow_it_report structure, stats structure, org isolation.
"""

from __future__ import annotations

import pytest

from core.casb_engine import CASBEngine


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    return CASBEngine(db_path=str(tmp_path / "test.db"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _app(name="Dropbox", category="storage", risk="high", users=50, sanctioned=False):
    return {
        "app_name": name,
        "app_category": category,
        "risk_level": risk,
        "users_count": users,
        "data_uploaded_gb": 1.5,
        "is_sanctioned": sanctioned,
        "oauth_scopes": ["read", "write"],
    }


def _activity(app="Dropbox", user="alice@example.com", atype="upload",
               classification="confidential", dest="external"):
    return {
        "app_name": app,
        "user": user,
        "activity_type": atype,
        "file_type": "application/pdf",
        "size_bytes": 1024 * 1024,
        "destination": dest,
        "data_classification": classification,
    }


def _policy(name="Block Secret Uploads", ptype="data_loss", action="block"):
    return {
        "name": name,
        "policy_type": ptype,
        "conditions": {"classification": "secret", "activity": "upload"},
        "action": action,
    }


# ---------------------------------------------------------------------------
# Init
# ---------------------------------------------------------------------------


def test_init_creates_db(tmp_path):
    db = str(tmp_path / "casb.db")
    eng = CASBEngine(db_path=db)
    import os
    assert os.path.exists(db)


def test_init_empty_lists(engine):
    assert engine.list_apps("org1") == []
    assert engine.list_data_activities("org1") == []
    assert engine.list_policies("org1") == []
    assert engine.list_violations("org1") == []


# ---------------------------------------------------------------------------
# discover_app
# ---------------------------------------------------------------------------


def test_discover_app_returns_record(engine):
    app = engine.discover_app("org1", _app())
    assert app["app_name"] == "Dropbox"
    assert app["app_category"] == "storage"
    assert app["risk_level"] == "high"
    assert app["users_count"] == 50
    assert app["is_sanctioned"] is False
    assert "read" in app["oauth_scopes"]
    assert "app_id" in app


def test_discover_app_idempotent_update(engine):
    engine.discover_app("org1", _app(users=10))
    app2 = engine.discover_app("org1", _app(users=99))
    apps = engine.list_apps("org1")
    assert len(apps) == 1
    assert apps[0]["users_count"] == 99


def test_discover_app_missing_name_raises(engine):
    with pytest.raises(ValueError, match="app_name"):
        engine.discover_app("org1", {})


def test_discover_app_invalid_category_defaults(engine):
    app = engine.discover_app("org1", {"app_name": "WeirdApp", "app_category": "INVALID"})
    assert app["app_category"] == "other"


def test_discover_app_invalid_risk_defaults(engine):
    app = engine.discover_app("org1", {"app_name": "WeirdApp", "risk_level": "super-critical"})
    assert app["risk_level"] == "medium"


def test_discover_multiple_apps(engine):
    engine.discover_app("org1", _app("Dropbox", "storage"))
    engine.discover_app("org1", _app("Slack", "collaboration"))
    engine.discover_app("org1", _app("Salesforce", "crm"))
    assert len(engine.list_apps("org1")) == 3


# ---------------------------------------------------------------------------
# sanction / unsanction
# ---------------------------------------------------------------------------


def test_sanction_app(engine):
    app = engine.discover_app("org1", _app())
    result = engine.sanction_app("org1", app["app_id"], "admin@example.com")
    assert result["is_sanctioned"] is True
    assert result["sanctioned_by"] == "admin@example.com"


def test_unsanction_app(engine):
    app = engine.discover_app("org1", _app(sanctioned=True))
    engine.sanction_app("org1", app["app_id"], "admin@example.com")
    result = engine.unsanction_app("org1", app["app_id"], "Violates data policy")
    assert result["is_sanctioned"] is False
    assert result["unsanction_reason"] == "Violates data policy"


def test_sanction_not_found_raises(engine):
    with pytest.raises(KeyError):
        engine.sanction_app("org1", "nonexistent-id", "admin")


def test_unsanction_not_found_raises(engine):
    with pytest.raises(KeyError):
        engine.unsanction_app("org1", "nonexistent-id", "reason")


# ---------------------------------------------------------------------------
# list_apps filters
# ---------------------------------------------------------------------------


def test_list_apps_filter_by_category(engine):
    engine.discover_app("org1", _app("Dropbox", "storage"))
    engine.discover_app("org1", _app("Slack", "collaboration"))
    storage_apps = engine.list_apps("org1", category="storage")
    assert len(storage_apps) == 1
    assert storage_apps[0]["app_name"] == "Dropbox"


def test_list_apps_filter_by_sanctioned(engine):
    app1 = engine.discover_app("org1", _app("Dropbox"))
    engine.discover_app("org1", _app("ShadowApp"))
    engine.sanction_app("org1", app1["app_id"], "admin")
    sanctioned = engine.list_apps("org1", is_sanctioned=True)
    assert len(sanctioned) == 1
    assert sanctioned[0]["app_name"] == "Dropbox"
    unsanctioned = engine.list_apps("org1", is_sanctioned=False)
    assert len(unsanctioned) == 1
    assert unsanctioned[0]["app_name"] == "ShadowApp"


def test_list_apps_filter_by_risk_level(engine):
    engine.discover_app("org1", _app("CriticalApp", risk="critical"))
    engine.discover_app("org1", _app("LowApp", risk="low"))
    critical = engine.list_apps("org1", risk_level="critical")
    assert len(critical) == 1
    assert critical[0]["app_name"] == "CriticalApp"


def test_list_apps_combined_filter(engine):
    engine.discover_app("org1", _app("GoodApp", category="storage", risk="low"))
    engine.discover_app("org1", _app("BadApp", category="storage", risk="high"))
    results = engine.list_apps("org1", category="storage", risk_level="high")
    assert len(results) == 1
    assert results[0]["app_name"] == "BadApp"


# ---------------------------------------------------------------------------
# record_data_activity
# ---------------------------------------------------------------------------


def test_record_data_activity(engine):
    act = engine.record_data_activity("org1", _activity())
    assert act["app_name"] == "Dropbox"
    assert act["user_id"] == "alice@example.com"
    assert act["activity_type"] == "upload"
    assert act["data_classification"] == "confidential"
    assert act["destination"] == "external"
    assert "activity_id" in act


def test_record_activity_missing_app_name_raises(engine):
    with pytest.raises(ValueError, match="app_name"):
        engine.record_data_activity("org1", {"user": "alice", "activity_type": "upload"})


def test_record_activity_missing_user_raises(engine):
    with pytest.raises(ValueError, match="user"):
        engine.record_data_activity("org1", {"app_name": "Dropbox", "activity_type": "upload"})


def test_record_activity_invalid_type_raises(engine):
    with pytest.raises(ValueError):
        engine.record_data_activity(
            "org1", {"app_name": "Dropbox", "user": "alice", "activity_type": "hack"}
        )


def test_record_activity_invalid_classification_defaults(engine):
    act = engine.record_data_activity(
        "org1",
        {"app_name": "Dropbox", "user": "alice", "activity_type": "download",
         "data_classification": "TOPSECRET"},
    )
    assert act["data_classification"] == "internal"


# ---------------------------------------------------------------------------
# list_data_activities filters
# ---------------------------------------------------------------------------


def test_list_activities_filter_by_app(engine):
    engine.record_data_activity("org1", _activity("Dropbox"))
    engine.record_data_activity("org1", _activity("GDrive"))
    results = engine.list_data_activities("org1", app_name="Dropbox")
    assert len(results) == 1
    assert results[0]["app_name"] == "Dropbox"


def test_list_activities_filter_by_classification(engine):
    engine.record_data_activity("org1", _activity(classification="secret"))
    engine.record_data_activity("org1", _activity(classification="public"))
    results = engine.list_data_activities("org1", data_classification="secret")
    assert len(results) == 1
    assert results[0]["data_classification"] == "secret"


def test_list_activities_limit(engine):
    for i in range(10):
        engine.record_data_activity(
            "org1", {"app_name": "App", "user": f"user{i}", "activity_type": "upload"}
        )
    results = engine.list_data_activities("org1", limit=5)
    assert len(results) == 5


# ---------------------------------------------------------------------------
# Policies
# ---------------------------------------------------------------------------


def test_create_policy(engine):
    pol = engine.create_policy("org1", _policy())
    assert pol["name"] == "Block Secret Uploads"
    assert pol["policy_type"] == "data_loss"
    assert pol["action"] == "block"
    assert pol["conditions"]["classification"] == "secret"
    assert "policy_id" in pol
    assert pol["is_active"] is True


def test_create_policy_missing_name_raises(engine):
    with pytest.raises(ValueError, match="name"):
        engine.create_policy("org1", {"policy_type": "data_loss"})


def test_create_policy_invalid_type_raises(engine):
    with pytest.raises(ValueError, match="policy_type"):
        engine.create_policy("org1", {"name": "Test", "policy_type": "invalid"})


def test_list_policies(engine):
    engine.create_policy("org1", _policy("P1", "data_loss"))
    engine.create_policy("org1", _policy("P2", "app_block"))
    engine.create_policy("org1", _policy("P3", "oauth_restrict"))
    policies = engine.list_policies("org1")
    assert len(policies) == 3


# ---------------------------------------------------------------------------
# Violations
# ---------------------------------------------------------------------------


def test_record_violation(engine):
    pol = engine.create_policy("org1", _policy())
    viol = engine.record_policy_violation(
        "org1",
        {
            "policy_id": pol["policy_id"],
            "user": "bob@example.com",
            "app_name": "Dropbox",
            "violation_detail": "Uploaded secret file externally",
            "severity": "high",
        },
    )
    assert viol["policy_id"] == pol["policy_id"]
    assert viol["user_id"] == "bob@example.com"
    assert viol["severity"] == "high"
    assert "violation_id" in viol


def test_record_violation_missing_fields_raises(engine):
    with pytest.raises(ValueError):
        engine.record_policy_violation("org1", {"user": "alice", "app_name": "Dropbox"})


def test_list_violations_filter_by_severity(engine):
    pol = engine.create_policy("org1", _policy())
    pid = pol["policy_id"]
    engine.record_policy_violation(
        "org1", {"policy_id": pid, "user": "u1", "app_name": "App", "severity": "high"}
    )
    engine.record_policy_violation(
        "org1", {"policy_id": pid, "user": "u2", "app_name": "App", "severity": "low"}
    )
    high = engine.list_violations("org1", severity="high")
    assert len(high) == 1
    assert high[0]["severity"] == "high"


def test_list_violations_limit(engine):
    pol = engine.create_policy("org1", _policy())
    pid = pol["policy_id"]
    for i in range(10):
        engine.record_policy_violation(
            "org1", {"policy_id": pid, "user": f"u{i}", "app_name": "App"}
        )
    results = engine.list_violations("org1", limit=3)
    assert len(results) == 3


# ---------------------------------------------------------------------------
# Shadow IT report
# ---------------------------------------------------------------------------


def test_shadow_it_report_structure(engine):
    app1 = engine.discover_app("org1", _app("GoodApp", risk="low"))
    engine.discover_app("org1", _app("ShadowApp1", risk="critical"))
    engine.discover_app("org1", _app("ShadowApp2", risk="high"))
    engine.sanction_app("org1", app1["app_id"], "admin")
    engine.record_data_activity("org1", _activity("ShadowApp1", atype="upload"))

    report = engine.get_shadow_it_report("org1")
    assert report["total_apps"] == 3
    assert report["sanctioned_count"] == 1
    assert report["unsanctioned_count"] == 2
    assert report["shadow_it_count"] == 2
    assert "by_category" in report
    assert isinstance(report["high_risk_apps"], list)
    assert len(report["high_risk_apps"]) >= 2
    assert isinstance(report["top_data_uploaders"], list)


def test_shadow_it_report_empty(engine):
    report = engine.get_shadow_it_report("org1")
    assert report["total_apps"] == 0
    assert report["sanctioned_count"] == 0
    assert report["shadow_it_count"] == 0
    assert report["high_risk_apps"] == []
    assert report["top_data_uploaders"] == []


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


def test_casb_stats_structure(engine):
    engine.discover_app("org1", _app("App1", risk="critical"))
    engine.discover_app("org1", _app("App2", risk="high"))
    engine.record_data_activity("org1", _activity())
    pol = engine.create_policy("org1", _policy())
    engine.record_policy_violation(
        "org1", {"policy_id": pol["policy_id"], "user": "u1", "app_name": "App1"}
    )

    stats = engine.get_casb_stats("org1")
    assert stats["total_apps"] == 2
    assert "shadow_it_pct" in stats
    assert "data_activities_24h" in stats
    assert stats["data_activities_24h"] >= 1
    assert "violations_24h" in stats
    assert stats["violations_24h"] >= 1
    assert "by_risk_level" in stats
    assert stats["policy_count"] == 1


def test_casb_stats_shadow_it_pct(engine):
    engine.discover_app("org1", _app("App1"))
    engine.discover_app("org1", _app("App2"))
    stats = engine.get_casb_stats("org1")
    assert stats["shadow_it_pct"] == 100.0


def test_casb_stats_empty_org(engine):
    stats = engine.get_casb_stats("empty_org")
    assert stats["total_apps"] == 0
    assert stats["shadow_it_pct"] == 0.0


# ---------------------------------------------------------------------------
# Org isolation
# ---------------------------------------------------------------------------


def test_org_isolation_apps(engine):
    engine.discover_app("org1", _app("OrgOneApp"))
    engine.discover_app("org2", _app("OrgTwoApp"))
    assert len(engine.list_apps("org1")) == 1
    assert engine.list_apps("org1")[0]["app_name"] == "OrgOneApp"
    assert len(engine.list_apps("org2")) == 1
    assert engine.list_apps("org2")[0]["app_name"] == "OrgTwoApp"


def test_org_isolation_activities(engine):
    engine.record_data_activity("org1", _activity("App", user="user1@org1.com"))
    engine.record_data_activity("org2", _activity("App", user="user2@org2.com"))
    assert len(engine.list_data_activities("org1")) == 1
    assert engine.list_data_activities("org1")[0]["user_id"] == "user1@org1.com"


def test_org_isolation_policies(engine):
    engine.create_policy("org1", _policy("Org1 Policy"))
    engine.create_policy("org2", _policy("Org2 Policy"))
    assert len(engine.list_policies("org1")) == 1
    assert engine.list_policies("org1")[0]["name"] == "Org1 Policy"


def test_org_isolation_violations(engine):
    pol1 = engine.create_policy("org1", _policy())
    pol2 = engine.create_policy("org2", _policy())
    engine.record_policy_violation(
        "org1", {"policy_id": pol1["policy_id"], "user": "u1", "app_name": "App"}
    )
    engine.record_policy_violation(
        "org2", {"policy_id": pol2["policy_id"], "user": "u2", "app_name": "App"}
    )
    assert len(engine.list_violations("org1")) == 1
    assert len(engine.list_violations("org2")) == 1


def test_org_isolation_shadow_report(engine):
    engine.discover_app("org1", _app("App1"))
    engine.discover_app("org2", _app("App2"))
    report1 = engine.get_shadow_it_report("org1")
    report2 = engine.get_shadow_it_report("org2")
    assert report1["total_apps"] == 1
    assert report2["total_apps"] == 1


def test_org_isolation_stats(engine):
    engine.discover_app("org1", _app("App"))
    stats1 = engine.get_casb_stats("org1")
    stats2 = engine.get_casb_stats("org2")
    assert stats1["total_apps"] == 1
    assert stats2["total_apps"] == 0
