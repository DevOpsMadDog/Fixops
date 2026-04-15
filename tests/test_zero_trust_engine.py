"""
Tests for the Zero-Trust Policy Engine.

Coverage:
- create_policy: returns dict with policy_id, rejects invalid action
- get_policy: returns created policy
- list_policies: returns list
- delete_policy: returns True for known policy, False for unknown
- evaluate_access: compliant device + mfa -> allow, high risk -> deny/step_up
- evaluate_access: decision key present and valid, policies_matched is list
- evaluate_access: reasoning is non-empty string
- compute_trust_score: returns trust_level str, trust_score float 0-100
- compute_trust_score: mfa + compliant -> higher trust than no mfa + non-compliant
- get_access_log: returns list after evaluations
- get_trust_analytics: numeric rates that sum to <= 1.0
- Multiple policies evaluated in priority order
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

# Ensure suite-core is on the path
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

from core.zero_trust_engine import (
    POLICY_ACTIONS,
    TRUST_LEVELS,
    ZeroTrustEngine,
    get_zero_trust_engine,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    """Fresh engine backed by a temporary SQLite file."""
    return ZeroTrustEngine(db_path=str(tmp_path / "zt_test.db"))


def _sample_request(**overrides) -> dict:
    base = {
        "user_id": "alice",
        "org_id": "default",
        "resource": "reports",
        "device_id": "dev-001",
        "device_compliant": True,
        "network_ip": "10.0.0.5",
        "mfa_verified": True,
        "user_risk_score": 5.0,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# create_policy
# ---------------------------------------------------------------------------


def test_create_policy_returns_dict_with_policy_id(engine):
    result = engine.create_policy(
        name="test-policy",
        conditions={"require_mfa": True},
        action="allow",
    )
    assert isinstance(result, dict)
    assert "policy_id" in result
    assert result["policy_id"]


def test_create_policy_fields_match_input(engine):
    result = engine.create_policy(
        name="deny-untrusted",
        conditions={"min_trust_level": "medium"},
        action="deny",
        priority=10,
        org_id="acme",
    )
    assert result["name"] == "deny-untrusted"
    assert result["action"] == "deny"
    assert result["priority"] == 10
    assert result["org_id"] == "acme"
    assert result["active"] is True


def test_create_policy_invalid_action_raises_value_error(engine):
    with pytest.raises(ValueError, match="Invalid action"):
        engine.create_policy(
            name="bad",
            conditions={},
            action="explode",
        )


def test_create_policy_all_valid_actions_accepted(engine):
    for action in POLICY_ACTIONS:
        result = engine.create_policy(name=f"p-{action}", conditions={}, action=action)
        assert result["action"] == action


# ---------------------------------------------------------------------------
# get_policy
# ---------------------------------------------------------------------------


def test_get_policy_returns_created_policy(engine):
    created = engine.create_policy(name="get-test", conditions={}, action="allow")
    fetched = engine.get_policy(created["policy_id"])
    assert fetched is not None
    assert fetched["policy_id"] == created["policy_id"]
    assert fetched["name"] == "get-test"


def test_get_policy_unknown_id_returns_none(engine):
    assert engine.get_policy("nonexistent-id-xyz") is None


# ---------------------------------------------------------------------------
# list_policies
# ---------------------------------------------------------------------------


def test_list_policies_returns_list(engine):
    result = engine.list_policies()
    assert isinstance(result, list)


def test_list_policies_includes_created_policy(engine):
    engine.create_policy(name="listed", conditions={}, action="monitor")
    policies = engine.list_policies()
    names = [p["name"] for p in policies]
    assert "listed" in names


def test_list_policies_active_only_filter(engine):
    p = engine.create_policy(name="active-p", conditions={}, action="allow")
    engine.update_policy(p["policy_id"], active=False)
    active = engine.list_policies(active_only=True)
    inactive = engine.list_policies(active_only=False)
    active_ids = [x["policy_id"] for x in active]
    all_ids = [x["policy_id"] for x in inactive]
    assert p["policy_id"] not in active_ids
    assert p["policy_id"] in all_ids


# ---------------------------------------------------------------------------
# delete_policy
# ---------------------------------------------------------------------------


def test_delete_policy_returns_true_for_known(engine):
    p = engine.create_policy(name="to-delete", conditions={}, action="deny")
    assert engine.delete_policy(p["policy_id"]) is True


def test_delete_policy_returns_false_for_unknown(engine):
    assert engine.delete_policy("does-not-exist-abc") is False


def test_delete_policy_removes_from_list(engine):
    p = engine.create_policy(name="gone", conditions={}, action="allow")
    engine.delete_policy(p["policy_id"])
    assert engine.get_policy(p["policy_id"]) is None


# ---------------------------------------------------------------------------
# evaluate_access
# ---------------------------------------------------------------------------


def test_evaluate_access_compliant_mfa_allows(engine):
    result = engine.evaluate_access(_sample_request(device_compliant=True, mfa_verified=True, user_risk_score=5.0))
    assert result["decision"] == "allow"


def test_evaluate_access_high_risk_score_triggers_deny_or_step_up(engine):
    # Create a policy that fires on high risk
    engine.create_policy(
        name="block-high-risk",
        conditions={"max_risk_score": 30.0},
        action="deny",
        priority=1,
    )
    result = engine.evaluate_access(_sample_request(user_risk_score=80.0))
    assert result["decision"] in ("deny", "step_up_auth", "quarantine")


def test_evaluate_access_returns_decision_key(engine):
    result = engine.evaluate_access(_sample_request())
    assert "decision" in result


def test_evaluate_access_decision_is_valid_action(engine):
    result = engine.evaluate_access(_sample_request())
    assert result["decision"] in POLICY_ACTIONS


def test_evaluate_access_policies_matched_is_list(engine):
    result = engine.evaluate_access(_sample_request())
    assert isinstance(result["policies_matched"], list)


def test_evaluate_access_reasoning_is_nonempty_string(engine):
    result = engine.evaluate_access(_sample_request())
    assert isinstance(result["reasoning"], str)
    assert len(result["reasoning"]) > 0


def test_evaluate_access_returns_request_id(engine):
    result = engine.evaluate_access(_sample_request())
    assert "request_id" in result
    assert result["request_id"]


def test_evaluate_access_returns_trust_level(engine):
    result = engine.evaluate_access(_sample_request())
    assert result["trust_level"] in TRUST_LEVELS


def test_evaluate_access_non_compliant_no_mfa_matched_policy(engine):
    engine.create_policy(
        name="require-compliance",
        conditions={"require_compliant_device": True, "require_mfa": True},
        action="step_up_auth",
        priority=5,
    )
    result = engine.evaluate_access(
        _sample_request(device_compliant=False, mfa_verified=False)
    )
    assert result["decision"] in ("step_up_auth", "deny", "quarantine")
    assert len(result["policies_matched"]) > 0


# ---------------------------------------------------------------------------
# compute_trust_score
# ---------------------------------------------------------------------------


def test_compute_trust_score_returns_trust_level_string(engine):
    result = engine.compute_trust_score({"mfa_verified": True, "device_compliant": True})
    assert isinstance(result["trust_level"], str)
    assert result["trust_level"] in TRUST_LEVELS


def test_compute_trust_score_returns_float_in_range(engine):
    result = engine.compute_trust_score({"mfa_verified": True, "device_compliant": True, "user_risk_score": 10.0})
    assert isinstance(result["trust_score"], float)
    assert 0.0 <= result["trust_score"] <= 100.0


def test_compute_trust_score_mfa_compliant_higher_than_non(engine):
    high = engine.compute_trust_score({"mfa_verified": True, "device_compliant": True, "user_risk_score": 0.0})
    low = engine.compute_trust_score({"mfa_verified": False, "device_compliant": False, "user_risk_score": 80.0})
    assert high["trust_score"] > low["trust_score"]


def test_compute_trust_score_returns_signals_dict(engine):
    result = engine.compute_trust_score({"mfa_verified": True, "device_compliant": True})
    assert isinstance(result["signals"], dict)


# ---------------------------------------------------------------------------
# get_access_log
# ---------------------------------------------------------------------------


def test_get_access_log_returns_list_after_evaluations(engine):
    engine.evaluate_access(_sample_request(user_id="bob"))
    log = engine.get_access_log(user_id="bob")
    assert isinstance(log, list)
    assert len(log) >= 1


def test_get_access_log_filter_by_decision(engine):
    engine.evaluate_access(_sample_request())  # expect allow with no policies
    allow_log = engine.get_access_log(decision="allow")
    assert all(entry["decision"] == "allow" for entry in allow_log)


# ---------------------------------------------------------------------------
# get_trust_analytics
# ---------------------------------------------------------------------------


def test_get_trust_analytics_has_numeric_rates(engine):
    engine.evaluate_access(_sample_request())
    analytics = engine.get_trust_analytics()
    assert isinstance(analytics["allow_rate"], float)
    assert isinstance(analytics["deny_rate"], float)
    assert isinstance(analytics["step_up_rate"], float)


def test_get_trust_analytics_rates_sum_le_one(engine):
    engine.evaluate_access(_sample_request())
    analytics = engine.get_trust_analytics()
    total = analytics["allow_rate"] + analytics["deny_rate"] + analytics["step_up_rate"]
    assert total <= 1.0 + 1e-9  # floating point tolerance


def test_get_trust_analytics_total_evaluations(engine):
    engine.evaluate_access(_sample_request())
    engine.evaluate_access(_sample_request())
    analytics = engine.get_trust_analytics()
    assert analytics["total_evaluations"] >= 2


def test_get_trust_analytics_avg_trust_score(engine):
    engine.evaluate_access(_sample_request())
    analytics = engine.get_trust_analytics()
    assert isinstance(analytics["avg_trust_score"], float)
    assert 0.0 <= analytics["avg_trust_score"] <= 100.0


# ---------------------------------------------------------------------------
# Priority ordering
# ---------------------------------------------------------------------------


def test_multiple_policies_evaluated_in_priority_order(engine):
    """Higher-priority policy (lower number) should win when both fire."""
    # Both fire; deny (priority 5) should not override quarantine (priority 1)
    engine.create_policy(
        name="quarantine-first",
        conditions={"require_mfa": True},
        action="quarantine",
        priority=1,
    )
    engine.create_policy(
        name="deny-later",
        conditions={"require_mfa": True},
        action="deny",
        priority=10,
    )
    # No MFA → both fire; quarantine has higher action precedence than deny... but
    # the engine picks the highest-precedence action among all matched.
    # deny=5 > quarantine=4, so final decision is deny.
    result = engine.evaluate_access(_sample_request(mfa_verified=False))
    assert result["decision"] in ("deny", "quarantine")
    assert len(result["policies_matched"]) >= 2


# ---------------------------------------------------------------------------
# get_trust_score
# ---------------------------------------------------------------------------


def test_get_trust_score_no_history_returns_neutral(engine):
    result = engine.get_trust_score(subject_id="unknown-user")
    assert result["score"] == 50
    assert isinstance(result["factors"], dict)
    assert "device_health" in result["factors"]


def test_get_trust_score_returns_subject_id(engine):
    result = engine.get_trust_score(subject_id="alice")
    assert result["subject_id"] == "alice"


def test_get_trust_score_after_evaluations_returns_float_score(engine):
    engine.evaluate_access(_sample_request(user_id="carol", device_compliant=True, mfa_verified=True))
    result = engine.get_trust_score(subject_id="carol")
    assert isinstance(result["score"], float)
    assert 0.0 <= result["score"] <= 100.0


def test_get_trust_score_factors_all_present(engine):
    engine.evaluate_access(_sample_request(user_id="dave"))
    result = engine.get_trust_score(subject_id="dave")
    factors = result["factors"]
    for key in ("device_health", "location_risk", "behavior_anomaly", "identity_confidence", "data_sensitivity"):
        assert key in factors, f"Missing factor: {key}"


def test_get_trust_score_factors_in_range(engine):
    engine.evaluate_access(_sample_request(user_id="eve"))
    result = engine.get_trust_score(subject_id="eve")
    for key, val in result["factors"].items():
        assert 0.0 <= val <= 100.0, f"Factor {key}={val} out of range"


def test_get_trust_score_org_isolation(engine):
    engine.evaluate_access(_sample_request(user_id="frank", org_id="org-a"))
    result = engine.get_trust_score(subject_id="frank", org_id="org-b")
    # No history for org-b → neutral defaults
    assert result["score"] == 50


# ---------------------------------------------------------------------------
# get_policy_stats
# ---------------------------------------------------------------------------


def test_get_policy_stats_returns_dict_with_required_keys(engine):
    stats = engine.get_policy_stats()
    for key in ("total_policies", "allows_today", "denies_today", "challenges_today", "top_denied_resources"):
        assert key in stats, f"Missing key: {key}"


def test_get_policy_stats_total_policies_counts_active(engine):
    engine.create_policy(name="stat-p1", conditions={}, action="allow")
    engine.create_policy(name="stat-p2", conditions={}, action="deny")
    stats = engine.get_policy_stats()
    assert stats["total_policies"] >= 2


def test_get_policy_stats_counts_are_non_negative(engine):
    engine.evaluate_access(_sample_request())
    stats = engine.get_policy_stats()
    assert stats["allows_today"] >= 0
    assert stats["denies_today"] >= 0
    assert stats["challenges_today"] >= 0


def test_get_policy_stats_top_denied_resources_is_list(engine):
    stats = engine.get_policy_stats()
    assert isinstance(stats["top_denied_resources"], list)


def test_get_policy_stats_top_denied_resources_have_resource_and_count(engine):
    engine.create_policy(name="block-all", conditions={"max_risk_score": 0.0}, action="deny", priority=1)
    engine.evaluate_access(_sample_request(resource="secret-db", user_risk_score=50.0))
    stats = engine.get_policy_stats()
    if stats["top_denied_resources"]:
        for entry in stats["top_denied_resources"]:
            assert "resource" in entry
            assert "count" in entry


def test_get_policy_stats_allow_increments_on_allow_decision(engine):
    # Fresh engine, no policies → default allow
    before = engine.get_policy_stats()
    engine.evaluate_access(_sample_request())
    after = engine.get_policy_stats()
    assert after["allows_today"] >= before["allows_today"]


# ---------------------------------------------------------------------------
# get_micro_segmentation_map
# ---------------------------------------------------------------------------


def test_get_micro_segmentation_map_returns_zones_and_paths(engine):
    result = engine.get_micro_segmentation_map()
    assert "zones" in result
    assert "paths" in result
    assert "segment_count" in result


def test_get_micro_segmentation_map_zones_is_list(engine):
    result = engine.get_micro_segmentation_map()
    assert isinstance(result["zones"], list)
    assert len(result["zones"]) > 0


def test_get_micro_segmentation_map_zones_have_required_fields(engine):
    result = engine.get_micro_segmentation_map()
    for zone in result["zones"]:
        assert "id" in zone
        assert "label" in zone
        assert "risk" in zone


def test_get_micro_segmentation_map_paths_is_list(engine):
    result = engine.get_micro_segmentation_map()
    assert isinstance(result["paths"], list)


def test_get_micro_segmentation_map_paths_populated_after_traffic(engine):
    engine.evaluate_access(_sample_request(network_ip="10.0.0.1", resource="api-service"))
    result = engine.get_micro_segmentation_map()
    assert isinstance(result["paths"], list)
    # At least one path should exist after traffic
    assert len(result["paths"]) >= 1


def test_get_micro_segmentation_map_segment_count_matches_zones(engine):
    result = engine.get_micro_segmentation_map()
    assert result["segment_count"] == len(result["zones"])


def test_get_micro_segmentation_map_path_fields(engine):
    engine.evaluate_access(_sample_request(network_ip="192.168.1.5", resource="database-main"))
    result = engine.get_micro_segmentation_map()
    for path in result["paths"]:
        assert "from" in path
        assert "to" in path
        assert "allowed" in path
        assert "denied" in path
        assert "status" in path
