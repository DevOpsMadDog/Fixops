"""
Tests for suite-core/core/zero_trust_engine.py

Coverage:
- Access evaluation: ALLOW / DENY / CHALLENGE decisions
- Micro-segmentation policy generation
- Lateral movement detection
- Trust score calculation
- Policy creation and listing
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path

import pytest

# Ensure suite-core is on the path
suite_core = str(Path(__file__).parent.parent / "suite-core")
if suite_core not in sys.path:
    sys.path.insert(0, suite_core)

from core.zero_trust_engine import (
    AccessRequest,
    Alert,
    AlertSeverity,
    Decision,
    NetworkPolicy,
    Policy,
    ZeroTrustEngine,
    create_zero_trust_engine,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    """Fresh engine backed by a temp SQLite file."""
    return ZeroTrustEngine(db_path=str(tmp_path / "zte_test.db"))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hours_ago(h: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(hours=h)).isoformat()


def _make_request(**kwargs) -> AccessRequest:
    defaults = dict(
        user_id="alice",
        device_id="dev-001",
        resource="reports",
        action="read",
        location="10.0.0.5",
        timestamp=_now(),
        mfa_verified=False,
        device_trust_score=0.80,
        behaviour_score=0.80,
    )
    defaults.update(kwargs)
    return AccessRequest(**defaults)


# ---------------------------------------------------------------------------
# Access evaluation — ALLOW
# ---------------------------------------------------------------------------


def test_allow_standard_resource_high_trust(engine):
    req = _make_request(
        resource="reports",
        device_trust_score=0.90,
        behaviour_score=0.90,
        location="10.0.0.1",
    )
    decision = engine.evaluate_access_request(req)
    assert decision.decision == Decision.ALLOW
    assert decision.trust_score > 0.0


def test_allow_private_network_boosts_trust(engine):
    req = _make_request(
        resource="dashboard",
        location="192.168.1.1",
        device_trust_score=0.75,
        behaviour_score=0.80,
    )
    decision = engine.evaluate_access_request(req)
    assert decision.decision == Decision.ALLOW
    assert any("private_network" in r for r in decision.reasons)


def test_allow_mfa_verified_on_sensitive_resource(engine):
    req = _make_request(
        resource="users",
        device_trust_score=0.85,
        behaviour_score=0.85,
        mfa_verified=True,
        location="10.0.0.1",
    )
    decision = engine.evaluate_access_request(req)
    assert decision.decision == Decision.ALLOW
    assert any("mfa_verified" in r for r in decision.reasons)


def test_allow_critical_resource_with_mfa(engine):
    req = _make_request(
        resource="admin",
        device_trust_score=0.90,
        behaviour_score=0.90,
        mfa_verified=True,
        location="10.0.0.1",
    )
    decision = engine.evaluate_access_request(req)
    assert decision.decision == Decision.ALLOW


# ---------------------------------------------------------------------------
# Access evaluation — DENY
# ---------------------------------------------------------------------------


def test_deny_low_device_trust(engine):
    # Public IP (no private-network bonus), very low device + behaviour scores
    req = _make_request(
        resource="reports",
        device_trust_score=0.05,
        behaviour_score=0.05,
        location="203.0.113.5",
    )
    decision = engine.evaluate_access_request(req)
    assert decision.decision == Decision.DENY


def test_deny_anomalous_behaviour(engine):
    req = _make_request(
        resource="reports",
        device_trust_score=0.20,
        behaviour_score=0.05,
        location="203.0.113.5",  # public IP
    )
    decision = engine.evaluate_access_request(req)
    assert decision.decision == Decision.DENY


def test_deny_critical_resource_no_mfa(engine):
    """Critical resource + high trust but MFA not verified → CHALLENGE, not ALLOW."""
    req = _make_request(
        resource="secrets",
        device_trust_score=0.95,
        behaviour_score=0.95,
        mfa_verified=False,
        location="10.0.0.1",
    )
    decision = engine.evaluate_access_request(req)
    # Must not be ALLOW; engine should CHALLENGE or DENY
    assert decision.decision in (Decision.DENY, Decision.CHALLENGE)
    assert decision.mfa_required is True


# ---------------------------------------------------------------------------
# Access evaluation — CHALLENGE
# ---------------------------------------------------------------------------


def test_challenge_sensitive_resource_medium_trust(engine):
    # Public IP (no private bonus), moderate scores → composite in CHALLENGE band
    req = _make_request(
        resource="users",
        device_trust_score=0.45,
        behaviour_score=0.45,
        mfa_verified=False,
        location="203.0.113.5",
    )
    decision = engine.evaluate_access_request(req)
    assert decision.decision == Decision.CHALLENGE
    assert decision.mfa_required is True


def test_challenge_critical_resource_unverified_mfa(engine):
    req = _make_request(
        resource="admin",
        device_trust_score=0.90,
        behaviour_score=0.90,
        mfa_verified=False,
        location="10.0.0.1",
    )
    decision = engine.evaluate_access_request(req)
    assert decision.decision == Decision.CHALLENGE
    assert decision.mfa_required is True


# ---------------------------------------------------------------------------
# Lateral movement detection
# ---------------------------------------------------------------------------


def test_detect_port_scan(engine):
    events = [
        {"source_ip": "203.0.113.42", "dest_port": p, "dest_ip": "10.0.0.5"}
        for p in [22, 23, 80, 443, 3306, 5432, 8080]
    ]
    alerts = engine.detect_lateral_movement(events)
    types = [a.alert_type for a in alerts]
    assert "port_scan" in types


def test_detect_host_enumeration(engine):
    events = [
        {
            "source_ip": "10.1.1.99",
            "dest_ip": f"10.0.0.{i}",
            "dest_port": 22,
        }
        for i in range(1, 8)
    ]
    alerts = engine.detect_lateral_movement(events)
    types = [a.alert_type for a in alerts]
    assert "host_enumeration" in types


def test_detect_off_hours_external_access(engine):
    # 03:00 UTC — off hours
    off_hours_ts = datetime.now(timezone.utc).replace(
        hour=3, minute=0, second=0, microsecond=0
    ).isoformat()
    events = [
        {
            "source_ip": "203.0.113.10",  # public IP
            "dest_ip": "10.0.0.5",
            "dest_port": 443,
            "timestamp": off_hours_ts,
        }
    ]
    alerts = engine.detect_lateral_movement(events)
    types = [a.alert_type for a in alerts]
    assert "off_hours_external_access" in types


def test_detect_brute_force(engine):
    events = [
        {
            "source_ip": "10.0.0.99",
            "user_id": "bob",
            "event_type": "auth_failure",
            "dest_port": 22,
        }
        for _ in range(12)
    ]
    alerts = engine.detect_lateral_movement(events)
    types = [a.alert_type for a in alerts]
    assert "brute_force" in types


def test_detect_unusual_protocol(engine):
    events = [
        {
            "source_ip": "10.0.0.5",
            "dest_ip": "10.0.0.20",
            "protocol": "telnet",
            "dest_port": 23,
        }
    ]
    alerts = engine.detect_lateral_movement(events)
    types = [a.alert_type for a in alerts]
    assert "unusual_protocol" in types


def test_no_alerts_for_clean_traffic(engine):
    events = [
        {
            "source_ip": "10.0.0.5",
            "dest_ip": "10.0.0.10",
            "dest_port": 443,
            "protocol": "tcp",
        }
    ]
    alerts = engine.detect_lateral_movement(events)
    assert alerts == []


def test_empty_events_returns_no_alerts(engine):
    assert engine.detect_lateral_movement([]) == []


# ---------------------------------------------------------------------------
# Trust score calculation
# ---------------------------------------------------------------------------


def test_trust_score_known_compliant_internal(engine):
    entity = {
        "id": "user-alice",
        "type": "user",
        "known": True,
        "compliant": True,
        "location": "10.0.0.1",
        "anomaly_score": 0.1,
        "auth_method": "mfa",
        "last_seen": _hours_ago(1),
    }
    score = engine.calculate_trust_score(entity)
    assert score >= 0.70


def test_trust_score_unknown_external_anomalous(engine):
    entity = {
        "id": "user-unknown",
        "type": "user",
        "known": False,
        "compliant": False,
        "location": "203.0.113.5",
        "anomaly_score": 0.9,
        "auth_method": "password",
    }
    score = engine.calculate_trust_score(entity)
    assert score < 0.50


def test_trust_score_certificate_auth_boost(engine):
    entity = {
        "id": "svc-backend",
        "type": "service",
        "known": True,
        "compliant": True,
        "location": "10.0.0.20",
        "anomaly_score": 0.0,
        "auth_method": "certificate",
    }
    score = engine.calculate_trust_score(entity)
    assert score >= 0.75


def test_trust_score_persisted(engine):
    entity = {"id": "user-persist-test", "type": "user", "known": True}
    score1 = engine.calculate_trust_score(entity)
    all_scores = engine.get_all_trust_scores()
    ids = [e["entity_id"] for e in all_scores]
    assert "user-persist-test" in ids


# ---------------------------------------------------------------------------
# Policy creation and listing
# ---------------------------------------------------------------------------


def test_create_and_list_policy(engine):
    rules = [
        {"user_id": "alice", "action": "read", "decision": "ALLOW"},
        {"action": "delete", "decision": "DENY"},
    ]
    policy = engine.create_access_policy(resource="reports", rules=rules)
    assert policy.resource == "reports"
    assert len(policy.rules) == 2

    policies = engine.list_policies()
    resources = [p["resource"] for p in policies]
    assert "reports" in resources


def test_policy_applied_in_evaluation(engine):
    """Policy that explicitly allows alice → should get ALLOW even for sensitive resource."""
    engine.create_access_policy(
        resource="billing",
        rules=[
            {
                "user_id": "alice",
                "action": "read",
                "min_trust_score": 0.5,
                "decision": "ALLOW",
            }
        ],
    )
    req = _make_request(
        user_id="alice",
        resource="billing",
        action="read",
        device_trust_score=0.85,
        mfa_verified=True,
        location="10.0.0.1",
    )
    decision = engine.evaluate_access_request(req)
    assert decision.decision == Decision.ALLOW
    assert decision.policy_applied != "default"


def test_micro_segmentation_generates_segments(engine):
    assets = [
        {"name": "web-server", "sensitivity": "standard"},
        {"name": "api-gateway", "sensitivity": "sensitive"},
        {"name": "secrets-vault", "sensitivity": "critical"},
    ]
    policy = engine.generate_micro_segmentation_policy(assets)
    assert isinstance(policy, NetworkPolicy)
    assert policy.deny_all is True
    segment_names = [s["segment"] for s in policy.segments]
    assert "critical" in segment_names
    assert len(policy.allow_rules) > 0


def test_factory_function():
    import tempfile, os
    with tempfile.TemporaryDirectory() as d:
        engine = create_zero_trust_engine(db_path=os.path.join(d, "test.db"))
        assert isinstance(engine, ZeroTrustEngine)
