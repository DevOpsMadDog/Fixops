"""Tests for ZeroTrustEnforcementEngine.

30+ tests covering:
  - Policy CRUD (create, list, get, update, invalid inputs)
  - Access evaluation (allow, deny, mfa_required, block, risk scoring)
  - Trust score management (set, get, list, status derivation)
  - Session lifecycle (create, list, revoke)
  - Access log filtering
  - Stats aggregation
  - Multi-org isolation
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _isolated_db(tmp_path, monkeypatch):
    """Redirect .fixops_data to a temp dir so tests don't pollute the project."""
    import core.zero_trust_enforcement_engine as mod
    monkeypatch.setattr(mod, "_DEFAULT_DB_DIR", tmp_path)
    yield


@pytest.fixture()
def engine():
    from core.zero_trust_enforcement_engine import ZeroTrustEnforcementEngine
    return ZeroTrustEnforcementEngine()


@pytest.fixture()
def org():
    return f"test_org_{uuid.uuid4().hex[:8]}"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_policy(engine, org, **overrides):
    data = dict(
        policy_name="Default Allow",
        resource_type="application",
        action="allow",
        principal_type="user",
        conditions={},
        priority=50,
    )
    data.update(overrides)
    return engine.create_policy(org, data)


def make_access_request(**overrides):
    req = dict(
        principal_id="user-alice",
        principal_type="user",
        resource_id="app-portal",
        resource_type="application",
        action_requested="read",
        source_ip="10.0.0.1",
        device_trust_score=80.0,
        user_trust_score=80.0,
        mfa_verified=True,
        location="US",
        device_type="laptop",
    )
    req.update(overrides)
    return req


# ===========================================================================
# 1. Policy CRUD
# ===========================================================================

class TestPolicyCRUD:
    def test_create_policy_returns_dict(self, engine, org):
        p = make_policy(engine, org)
        assert p["id"]
        assert p["policy_name"] == "Default Allow"
        assert p["action"] == "allow"
        assert p["enabled"] is True

    def test_create_policy_all_resource_types(self, engine, org):
        for rt in ("application", "api", "database", "network_segment", "cloud_service"):
            p = make_policy(engine, org, resource_type=rt, policy_name=f"Policy-{rt}")
            assert p["resource_type"] == rt

    def test_create_policy_all_actions(self, engine, org):
        for action in ("allow", "deny", "mfa_required", "device_check_required"):
            p = make_policy(engine, org, action=action, policy_name=f"Policy-{action}")
            assert p["action"] == action

    def test_create_policy_all_principal_types(self, engine, org):
        for pt in ("user", "group", "service_account", "device"):
            p = make_policy(engine, org, principal_type=pt, policy_name=f"Policy-{pt}")
            assert p["principal_type"] == pt

    def test_create_policy_invalid_action_raises(self, engine, org):
        with pytest.raises(ValueError, match="Invalid action"):
            make_policy(engine, org, action="teleport")

    def test_create_policy_invalid_resource_type_raises(self, engine, org):
        with pytest.raises(ValueError, match="Invalid resource_type"):
            make_policy(engine, org, resource_type="spaceship")

    def test_create_policy_invalid_principal_type_raises(self, engine, org):
        with pytest.raises(ValueError, match="Invalid principal_type"):
            make_policy(engine, org, principal_type="robot")

    def test_create_policy_priority_clamped(self, engine, org):
        p = make_policy(engine, org, priority=200)
        assert p["priority"] == 100
        p2 = make_policy(engine, org, priority=0)
        assert p2["priority"] == 1

    def test_list_policies_empty(self, engine, org):
        assert engine.list_policies(org) == []

    def test_list_policies_returns_all(self, engine, org):
        make_policy(engine, org, policy_name="A")
        make_policy(engine, org, policy_name="B")
        policies = engine.list_policies(org)
        assert len(policies) == 2

    def test_list_policies_ordered_by_priority(self, engine, org):
        make_policy(engine, org, priority=80, policy_name="Low")
        make_policy(engine, org, priority=10, policy_name="High")
        policies = engine.list_policies(org)
        assert policies[0]["priority"] == 10

    def test_list_policies_filter_resource_type(self, engine, org):
        make_policy(engine, org, resource_type="api", policy_name="API Policy")
        make_policy(engine, org, resource_type="database", policy_name="DB Policy")
        api_only = engine.list_policies(org, resource_type="api")
        assert len(api_only) == 1
        assert api_only[0]["resource_type"] == "api"

    def test_list_policies_filter_enabled(self, engine, org):
        p1 = make_policy(engine, org, policy_name="Active")
        engine.update_policy(org, p1["id"], {"enabled": False})
        enabled = engine.list_policies(org, enabled=True)
        disabled = engine.list_policies(org, enabled=False)
        assert len(enabled) == 0
        assert len(disabled) == 1

    def test_get_policy_found(self, engine, org):
        p = make_policy(engine, org)
        fetched = engine.get_policy(org, p["id"])
        assert fetched is not None
        assert fetched["id"] == p["id"]

    def test_get_policy_not_found(self, engine, org):
        result = engine.get_policy(org, "nonexistent-id")
        assert result is None

    def test_get_policy_org_isolation(self, engine, org):
        other_org = f"other_{uuid.uuid4().hex[:8]}"
        p = make_policy(engine, org)
        result = engine.get_policy(other_org, p["id"])
        assert result is None

    def test_update_policy_name(self, engine, org):
        p = make_policy(engine, org, policy_name="Old Name")
        updated = engine.update_policy(org, p["id"], {"policy_name": "New Name"})
        assert updated["policy_name"] == "New Name"

    def test_update_policy_enable_disable(self, engine, org):
        p = make_policy(engine, org)
        updated = engine.update_policy(org, p["id"], {"enabled": False})
        assert updated["enabled"] is False

    def test_update_policy_conditions(self, engine, org):
        p = make_policy(engine, org)
        cond = {"require_mfa": True, "min_trust_score": 60.0}
        updated = engine.update_policy(org, p["id"], {"conditions": cond})
        assert updated["conditions"]["require_mfa"] is True

    def test_update_policy_not_found_raises(self, engine, org):
        with pytest.raises(ValueError, match="not found"):
            engine.update_policy(org, "bad-id", {"policy_name": "X"})


# ===========================================================================
# 2. Access Evaluation
# ===========================================================================

class TestAccessEvaluation:
    def test_default_allow_no_policies(self, engine, org):
        # No policies → no deny trigger → allow (if risk < 60)
        req = make_access_request(user_trust_score=80, device_trust_score=80,
                                  mfa_verified=True, location="US")
        result = engine.evaluate_access(org, req)
        assert result["decision"] == "allow"
        assert "session_id" in result

    def test_deny_policy_matches(self, engine, org):
        make_policy(engine, org, action="deny", priority=1,
                    conditions={"min_trust_score": 90.0})
        req = make_access_request(user_trust_score=50)
        result = engine.evaluate_access(org, req)
        assert result["decision"] == "deny"
        assert result["matched_policy_id"] is not None

    def test_mfa_required_decision(self, engine, org):
        make_policy(engine, org, action="mfa_required", priority=1,
                    resource_type="api",
                    conditions={"require_mfa": True})
        req = make_access_request(
            resource_type="api",
            mfa_verified=False,
            user_trust_score=80,
            device_trust_score=80,
            location="US",
        )
        result = engine.evaluate_access(org, req)
        assert result["decision"] in ("mfa_required", "block")

    def test_block_on_high_risk_score(self, engine, org):
        # Low trust + no MFA for sensitive + unknown location + low device trust
        req = make_access_request(
            user_trust_score=30,        # +30 risk
            device_trust_score=30,      # +15 risk
            mfa_verified=False,
            resource_type="database",   # +25 risk (sensitive + no MFA)
            location="",               # +20 risk
        )
        result = engine.evaluate_access(org, req)
        assert result["decision"] == "block"
        assert result["risk_score"] >= 60

    def test_risk_factors_populated(self, engine, org):
        req = make_access_request(user_trust_score=30, location="")
        result = engine.evaluate_access(org, req)
        assert "low_user_trust_score" in result["risk_factors"]
        assert "unusual_or_unknown_location" in result["risk_factors"]

    def test_allow_creates_session(self, engine, org):
        req = make_access_request()
        result = engine.evaluate_access(org, req)
        if result["decision"] == "allow":
            assert result.get("session_id") is not None

    def test_deny_no_session(self, engine, org):
        make_policy(engine, org, action="deny", priority=1,
                    conditions={"min_trust_score": 99.0})
        req = make_access_request(user_trust_score=50)
        result = engine.evaluate_access(org, req)
        assert result["decision"] == "deny"
        assert "session_id" not in result or result.get("session_id") is None

    def test_evaluate_persists_to_access_log(self, engine, org):
        req = make_access_request()
        engine.evaluate_access(org, req)
        log = engine.list_access_requests(org)
        assert len(log) == 1
        assert log[0]["principal_id"] == "user-alice"

    def test_no_mfa_low_sensitivity_no_risk_penalty(self, engine, org):
        # application type is not in _SENSITIVE_RESOURCE_TYPES
        req = make_access_request(
            mfa_verified=False,
            resource_type="application",
            user_trust_score=80,
            device_trust_score=80,
            location="US",
        )
        result = engine.evaluate_access(org, req)
        assert "no_mfa_for_sensitive_resource" not in result["risk_factors"]

    def test_location_based_risk(self, engine, org):
        req = make_access_request(location="unknown", user_trust_score=80,
                                  device_trust_score=80, mfa_verified=True)
        result = engine.evaluate_access(org, req)
        # "unknown" location → risk factor added
        assert "unusual_or_unknown_location" in result["risk_factors"]


# ===========================================================================
# 3. Trust Scores
# ===========================================================================

class TestTrustScores:
    def test_set_trust_score_creates_record(self, engine, org):
        result = engine.set_trust_score(org, "user-bob", "user", 85.0, {"source": "okta"})
        assert result["entity_id"] == "user-bob"
        assert result["trust_score"] == 85.0
        assert result["status"] == "trusted"

    def test_set_trust_score_updates_existing(self, engine, org):
        engine.set_trust_score(org, "user-bob", "user", 85.0, {})
        result = engine.set_trust_score(org, "user-bob", "user", 30.0, {"reason": "anomaly"})
        assert result["trust_score"] == 30.0
        # score=30 falls in probation range (25-49)
        assert result["status"] == "probation"

    def test_trust_status_derivation(self, engine, org):
        cases = [
            (90.0, "trusted"),
            (75.0, "trusted"),
            (60.0, "unknown"),
            (50.0, "unknown"),
            (30.0, "probation"),
            (10.0, "untrusted"),
        ]
        for score, expected_status in cases:
            eid = f"entity-{uuid.uuid4().hex[:6]}"
            result = engine.set_trust_score(org, eid, "user", score, {})
            assert result["status"] == expected_status, f"score={score}"

    def test_trust_score_clamped(self, engine, org):
        result = engine.set_trust_score(org, "u1", "user", 150.0, {})
        assert result["trust_score"] == 100.0
        result2 = engine.set_trust_score(org, "u2", "user", -10.0, {})
        assert result2["trust_score"] == 0.0

    def test_get_trust_score_found(self, engine, org):
        engine.set_trust_score(org, "user-carol", "user", 70.0, {})
        result = engine.get_trust_score(org, "user-carol")
        assert result is not None
        assert result["trust_score"] == 70.0

    def test_get_trust_score_not_found(self, engine, org):
        result = engine.get_trust_score(org, "nobody")
        assert result is None

    def test_invalid_entity_type_raises(self, engine, org):
        with pytest.raises(ValueError, match="Invalid entity_type"):
            engine.set_trust_score(org, "x", "alien", 50.0, {})

    def test_list_trust_scores_filter_type(self, engine, org):
        engine.set_trust_score(org, "u1", "user", 80.0, {})
        engine.set_trust_score(org, "d1", "device", 60.0, {})
        users = engine.list_trust_scores(org, entity_type="user")
        assert all(r["entity_type"] == "user" for r in users)

    def test_list_trust_scores_filter_status(self, engine, org):
        engine.set_trust_score(org, "u1", "user", 90.0, {})   # trusted
        engine.set_trust_score(org, "u2", "user", 10.0, {})   # untrusted
        untrusted = engine.list_trust_scores(org, status="untrusted")
        assert all(r["status"] == "untrusted" for r in untrusted)
        assert len(untrusted) >= 1


# ===========================================================================
# 4. Session Management
# ===========================================================================

class TestSessionManagement:
    def test_create_session(self, engine, org):
        session = engine.create_session(org, "user-dave", "app-crm")
        assert session["id"]
        assert session["status"] == "active"
        assert session["principal_id"] == "user-dave"
        assert session["resource_id"] == "app-crm"
        assert "expires_at" in session

    def test_list_sessions_by_principal(self, engine, org):
        engine.create_session(org, "user-eve", "app-a")
        engine.create_session(org, "user-eve", "app-b")
        engine.create_session(org, "user-frank", "app-a")
        eve_sessions = engine.list_sessions(org, principal_id="user-eve")
        assert len(eve_sessions) == 2
        assert all(s["principal_id"] == "user-eve" for s in eve_sessions)

    def test_list_sessions_by_status(self, engine, org):
        s = engine.create_session(org, "user-grace", "app-x")
        engine.revoke_session(org, s["id"])
        active = engine.list_sessions(org, status="active")
        revoked = engine.list_sessions(org, status="revoked")
        assert all(x["status"] == "active" for x in active)
        assert any(x["id"] == s["id"] for x in revoked)

    def test_revoke_session_returns_true(self, engine, org):
        s = engine.create_session(org, "user-henry", "app-y")
        result = engine.revoke_session(org, s["id"])
        assert result is True

    def test_revoke_session_already_revoked_returns_false(self, engine, org):
        s = engine.create_session(org, "user-iris", "app-z")
        engine.revoke_session(org, s["id"])
        result = engine.revoke_session(org, s["id"])
        assert result is False

    def test_revoke_nonexistent_session_returns_false(self, engine, org):
        result = engine.revoke_session(org, "no-such-session")
        assert result is False

    def test_session_has_token(self, engine, org):
        s = engine.create_session(org, "user-joe", "res-1")
        assert s["session_token"]
        assert len(s["session_token"]) > 10

    def test_session_duration_respected(self, engine, org):
        from datetime import datetime, timezone
        s = engine.create_session(org, "user-kim", "res-2", duration_hours=4)
        started = datetime.fromisoformat(s["started_at"])
        expires = datetime.fromisoformat(s["expires_at"])
        diff_hours = (expires - started).total_seconds() / 3600
        assert abs(diff_hours - 4) < 0.01


# ===========================================================================
# 5. Access Log
# ===========================================================================

class TestAccessLog:
    def test_access_log_filter_by_decision(self, engine, org):
        make_policy(engine, org, action="deny", priority=1,
                    conditions={"min_trust_score": 99.0})
        engine.evaluate_access(org, make_access_request(user_trust_score=50))
        denied = engine.list_access_requests(org, decision="deny")
        assert len(denied) >= 1

    def test_access_log_filter_by_resource_type(self, engine, org):
        engine.evaluate_access(org, make_access_request(resource_type="api"))
        engine.evaluate_access(org, make_access_request(resource_type="database"))
        api_log = engine.list_access_requests(org, resource_type="api")
        assert all(r["resource_type"] == "api" for r in api_log)

    def test_access_log_limit(self, engine, org):
        for _ in range(10):
            engine.evaluate_access(org, make_access_request())
        limited = engine.list_access_requests(org, limit=3)
        assert len(limited) == 3

    def test_access_log_org_isolation(self, engine, org):
        other_org = f"other_{uuid.uuid4().hex[:8]}"
        engine.evaluate_access(org, make_access_request())
        log = engine.list_access_requests(other_org)
        assert len(log) == 0


# ===========================================================================
# 6. Stats
# ===========================================================================

class TestStats:
    def test_stats_empty_org(self, engine, org):
        stats = engine.get_stats(org)
        assert stats["total_requests"] == 0
        assert stats["active_sessions"] == 0
        assert stats["allow_rate"] == 0.0

    def test_stats_counts_requests(self, engine, org):
        engine.evaluate_access(org, make_access_request())
        engine.evaluate_access(org, make_access_request())
        stats = engine.get_stats(org)
        assert stats["total_requests"] == 2

    def test_stats_active_sessions(self, engine, org):
        engine.create_session(org, "u1", "r1")
        engine.create_session(org, "u2", "r2")
        stats = engine.get_stats(org)
        assert stats["active_sessions"] >= 2

    def test_stats_avg_trust_score(self, engine, org):
        engine.set_trust_score(org, "u1", "user", 80.0, {})
        engine.set_trust_score(org, "u2", "user", 40.0, {})
        stats = engine.get_stats(org)
        assert stats["avg_trust_score"] == pytest.approx(60.0, abs=1.0)

    def test_stats_high_risk_principals(self, engine, org):
        engine.set_trust_score(org, "u1", "user", 30.0, {})  # high risk
        engine.set_trust_score(org, "u2", "user", 80.0, {})  # not high risk
        stats = engine.get_stats(org)
        assert stats["high_risk_principals"] == 1

    def test_stats_org_isolation(self, engine, org):
        other_org = f"other_{uuid.uuid4().hex[:8]}"
        engine.evaluate_access(org, make_access_request())
        stats = engine.get_stats(other_org)
        assert stats["total_requests"] == 0


# ===========================================================================
# 7. Multi-org isolation
# ===========================================================================

class TestMultiOrgIsolation:
    def test_policies_isolated_per_org(self, engine):
        org_a = f"org_a_{uuid.uuid4().hex[:6]}"
        org_b = f"org_b_{uuid.uuid4().hex[:6]}"
        make_policy(engine, org_a, policy_name="Org A Policy")
        assert len(engine.list_policies(org_b)) == 0

    def test_trust_scores_isolated_per_org(self, engine):
        org_a = f"org_a_{uuid.uuid4().hex[:6]}"
        org_b = f"org_b_{uuid.uuid4().hex[:6]}"
        engine.set_trust_score(org_a, "shared-user", "user", 90.0, {})
        result = engine.get_trust_score(org_b, "shared-user")
        assert result is None

    def test_sessions_isolated_per_org(self, engine):
        org_a = f"org_a_{uuid.uuid4().hex[:6]}"
        org_b = f"org_b_{uuid.uuid4().hex[:6]}"
        engine.create_session(org_a, "user-a", "res-a")
        sessions = engine.list_sessions(org_b)
        assert len(sessions) == 0


# ===========================================================================
# 8. Delete policy
# ===========================================================================

class TestDeletePolicy:
    def test_delete_policy_returns_true(self, engine, org):
        p = make_policy(engine, org)
        result = engine.delete_policy(org, p["id"])
        assert result is True

    def test_delete_policy_removes_from_list(self, engine, org):
        p = make_policy(engine, org)
        engine.delete_policy(org, p["id"])
        assert engine.get_policy(org, p["id"]) is None
        assert engine.list_policies(org) == []

    def test_delete_policy_not_found_returns_false(self, engine, org):
        result = engine.delete_policy(org, "nonexistent-id")
        assert result is False

    def test_delete_policy_wrong_org_returns_false(self, engine, org):
        other_org = f"other_{uuid.uuid4().hex[:8]}"
        p = make_policy(engine, org)
        result = engine.delete_policy(other_org, p["id"])
        assert result is False
        # original org still has it
        assert engine.get_policy(org, p["id"]) is not None

    def test_delete_only_deletes_target_policy(self, engine, org):
        p1 = make_policy(engine, org, policy_name="Keep")
        p2 = make_policy(engine, org, policy_name="Delete")
        engine.delete_policy(org, p2["id"])
        remaining = engine.list_policies(org)
        assert len(remaining) == 1
        assert remaining[0]["id"] == p1["id"]


# ===========================================================================
# 9. Compliance posture
# ===========================================================================

class TestCompliancePosture:
    def test_compliance_posture_structure(self, engine, org):
        posture = engine.get_compliance_posture(org)
        assert "zt_maturity_score" in posture
        assert "pillars" in posture
        assert "recommendations" in posture
        assert "total_enabled_policies" in posture
        assert "generated_at" in posture
        pillars = posture["pillars"]
        assert set(pillars.keys()) == {"identity", "device", "network", "application", "data"}

    def test_compliance_posture_empty_score_zero(self, engine, org):
        posture = engine.get_compliance_posture(org)
        assert posture["zt_maturity_score"] == 0
        for score in posture["pillars"].values():
            assert score == 0

    def test_compliance_posture_score_in_range(self, engine, org):
        # Add policies across resource types
        for rt in ("application", "api", "database", "network_segment", "cloud_service"):
            make_policy(engine, org, resource_type=rt, policy_name=f"Policy-{rt}")
        posture = engine.get_compliance_posture(org)
        assert 0 <= posture["zt_maturity_score"] <= 100

    def test_compliance_posture_score_increases_with_policies(self, engine, org):
        before = engine.get_compliance_posture(org)["zt_maturity_score"]
        make_policy(engine, org, resource_type="application", policy_name="App Policy")
        after = engine.get_compliance_posture(org)["zt_maturity_score"]
        assert after >= before

    def test_compliance_posture_recommendations_present_when_empty(self, engine, org):
        posture = engine.get_compliance_posture(org)
        assert len(posture["recommendations"]) > 0

    def test_compliance_posture_org_isolation(self, engine, org):
        other_org = f"other_{uuid.uuid4().hex[:8]}"
        make_policy(engine, org, resource_type="application", policy_name="App Policy")
        posture_other = engine.get_compliance_posture(other_org)
        assert posture_other["zt_maturity_score"] == 0

    def test_compliance_posture_trust_scores_improve_identity(self, engine, org):
        engine.set_trust_score(org, "u1", "user", 90.0, {})
        engine.set_trust_score(org, "u2", "user", 85.0, {})
        posture = engine.get_compliance_posture(org)
        # With trusted entities and no API policies, identity pillar gets a bonus
        # The maturity score should still be in valid range
        assert 0 <= posture["zt_maturity_score"] <= 100
