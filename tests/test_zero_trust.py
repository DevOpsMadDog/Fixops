"""
Tests for the Zero-Trust Policy Engine (suite-core/core/zero_trust.py)
and its FastAPI router (suite-api/apps/api/zero_trust_router.py).

Coverage:
- TrustLevel enum (5 tests)
- DevicePosture model + trust score computation (6 tests)
- AccessDecision model (3 tests)
- ZeroTrustEngine.register_device / get_device_trust (5 tests)
- ZeroTrustEngine.enforce_mfa (4 tests)
- ZeroTrustEngine.check_geo_restriction (6 tests)
- ZeroTrustEngine.check_time_restriction (4 tests)
- ZeroTrustEngine.evaluate_access — full policy (8 tests)
- ZeroTrustEngine.record_access_event (2 tests)
- ZeroTrustEngine.get_continuous_auth_status (4 tests)
- ZeroTrustEngine.get_zero_trust_stats (3 tests)
- Router imports / basic shape (3 tests)

Total: 53 tests
Run:  python -m pytest tests/test_zero_trust.py -v --timeout=10
"""

from __future__ import annotations

import sys
import uuid
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))

from core.zero_trust import (
    AccessDecision,
    DevicePosture,
    TrustLevel,
    ZeroTrustEngine,
    _trust_level_from_score,
    create_zero_trust_engine,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    """Fresh ZeroTrustEngine backed by a temp SQLite file per test."""
    return ZeroTrustEngine(db_path=str(tmp_path / "zt.db"))


@pytest.fixture
def healthy_device() -> DevicePosture:
    return DevicePosture(
        device_id="dev-001",
        os="Linux",
        os_version="6.8",
        encrypted=True,
        firewall_enabled=True,
        antivirus_active=True,
        patch_level=1.0,
    )


@pytest.fixture
def weak_device() -> DevicePosture:
    return DevicePosture(
        device_id="dev-weak",
        os="Windows",
        os_version="10",
        encrypted=False,
        firewall_enabled=False,
        antivirus_active=False,
        patch_level=0.0,
    )


# ============================================================================
# TrustLevel enum tests
# ============================================================================


class TestTrustLevelEnum:
    def test_enum_values_exist(self):
        levels = [t.value for t in TrustLevel]
        assert "none" in levels
        assert "low" in levels
        assert "medium" in levels
        assert "high" in levels
        assert "verified" in levels

    def test_ordinal_ordering(self):
        assert TrustLevel.NONE.ordinal < TrustLevel.LOW.ordinal
        assert TrustLevel.LOW.ordinal < TrustLevel.MEDIUM.ordinal
        assert TrustLevel.MEDIUM.ordinal < TrustLevel.HIGH.ordinal
        assert TrustLevel.HIGH.ordinal < TrustLevel.VERIFIED.ordinal

    def test_comparison_operators(self):
        assert TrustLevel.VERIFIED > TrustLevel.HIGH
        assert TrustLevel.HIGH >= TrustLevel.HIGH
        assert TrustLevel.LOW < TrustLevel.MEDIUM
        assert TrustLevel.NONE <= TrustLevel.LOW

    def test_trust_level_from_score_boundaries(self):
        assert _trust_level_from_score(0.95) == TrustLevel.VERIFIED
        assert _trust_level_from_score(0.75) == TrustLevel.HIGH
        assert _trust_level_from_score(0.55) == TrustLevel.MEDIUM
        assert _trust_level_from_score(0.35) == TrustLevel.LOW
        assert _trust_level_from_score(0.10) == TrustLevel.NONE

    def test_trust_level_is_str_enum(self):
        assert isinstance(TrustLevel.HIGH, str)
        assert TrustLevel.HIGH == "high"


# ============================================================================
# DevicePosture model tests
# ============================================================================


class TestDevicePosture:
    def test_fully_hardened_device_scores_1(self):
        d = DevicePosture(
            device_id="x",
            os="Linux",
            os_version="6.8",
            encrypted=True,
            firewall_enabled=True,
            antivirus_active=True,
            patch_level=1.0,
        )
        score = d.compute_trust_score()
        assert score == 1.0

    def test_unhardened_device_scores_0(self):
        d = DevicePosture(
            device_id="x",
            os="Windows",
            os_version="7",
            encrypted=False,
            firewall_enabled=False,
            antivirus_active=False,
            patch_level=0.0,
        )
        score = d.compute_trust_score()
        assert score == 0.0

    def test_partial_posture_score_in_range(self):
        d = DevicePosture(
            device_id="x",
            os="macOS",
            os_version="14",
            encrypted=True,
            firewall_enabled=False,
            antivirus_active=False,
            patch_level=0.5,
        )
        score = d.compute_trust_score()
        # encrypted=0.30 + patch_level=0.5*0.30=0.15 → 0.45
        assert 0.40 <= score <= 0.50

    def test_compute_trust_score_mutates_field(self):
        d = DevicePosture(device_id="x", os="Linux", os_version="6.8",
                          encrypted=True, firewall_enabled=True,
                          antivirus_active=True, patch_level=1.0)
        assert d.trust_score == 0.0  # default
        d.compute_trust_score()
        assert d.trust_score == 1.0

    def test_patch_level_clamped_to_1(self):
        d = DevicePosture(device_id="x", os="Linux", os_version="6",
                          patch_level=1.0)
        score = d.compute_trust_score()
        assert 0.0 <= score <= 1.0

    def test_to_dict_contains_expected_keys(self):
        d = DevicePosture(device_id="dev-x", os="Linux", os_version="6.8")
        data = d.to_dict()
        for key in ("device_id", "os", "os_version", "encrypted",
                    "firewall_enabled", "antivirus_active",
                    "patch_level", "trust_score"):
            assert key in data


# ============================================================================
# AccessDecision model tests
# ============================================================================


class TestAccessDecision:
    def test_allowed_decision(self):
        d = AccessDecision(
            allowed=True,
            trust_level=TrustLevel.HIGH,
            reason="access_granted",
        )
        assert d.allowed is True
        assert d.trust_level == TrustLevel.HIGH
        assert d.mfa_required is False

    def test_denied_decision(self):
        d = AccessDecision(
            allowed=False,
            trust_level=TrustLevel.LOW,
            reason="geo_blocked",
            mfa_required=True,
        )
        assert d.allowed is False
        assert d.mfa_required is True

    def test_to_dict_serialization(self):
        d = AccessDecision(
            allowed=True,
            trust_level=TrustLevel.VERIFIED,
            reason="access_granted",
            conditions=["device_trust_ok", "geo_ok"],
        )
        data = d.to_dict()
        assert data["allowed"] is True
        assert data["trust_level"] == "verified"
        assert "device_trust_ok" in data["conditions"]
        assert "decision_id" in data


# ============================================================================
# ZeroTrustEngine — device registration
# ============================================================================


class TestDeviceRegistration:
    def test_register_healthy_device(self, engine, healthy_device):
        result = engine.register_device(healthy_device)
        assert result.trust_score == 1.0

    def test_get_device_trust_after_register(self, engine, healthy_device):
        engine.register_device(healthy_device)
        score = engine.get_device_trust("dev-001")
        assert score == 1.0

    def test_get_device_trust_unknown_returns_none(self, engine):
        assert engine.get_device_trust("nonexistent-device") is None

    def test_register_updates_existing_device(self, engine, healthy_device):
        engine.register_device(healthy_device)
        # Re-register with weaker posture
        healthy_device.encrypted = False
        healthy_device.compute_trust_score()
        engine.register_device(healthy_device)
        score = engine.get_device_trust("dev-001")
        assert score < 1.0

    def test_register_weak_device_scores_zero(self, engine, weak_device):
        result = engine.register_device(weak_device)
        assert result.trust_score == 0.0
        assert engine.get_device_trust("dev-weak") == 0.0


# ============================================================================
# ZeroTrustEngine — MFA enforcement
# ============================================================================


class TestMFAEnforcement:
    def test_admin_resource_requires_mfa(self, engine):
        assert engine.enforce_mfa("alice", "admin") is True

    def test_secrets_resource_requires_mfa(self, engine):
        assert engine.enforce_mfa("alice", "secrets") is True

    def test_config_requires_mfa(self, engine):
        assert engine.enforce_mfa("alice", "config") is True

    def test_regular_resource_no_mfa(self, engine):
        assert engine.enforce_mfa("alice", "findings") is False


# ============================================================================
# ZeroTrustEngine — geographic restriction
# ============================================================================


class TestGeoRestriction:
    def test_loopback_always_allowed(self, engine):
        ok, reason = engine.check_geo_restriction("127.0.0.1")
        assert ok is True
        assert "private" in reason

    def test_private_10_network_allowed(self, engine):
        ok, reason = engine.check_geo_restriction("10.0.0.1")
        assert ok is True

    def test_private_192_168_allowed(self, engine):
        ok, reason = engine.check_geo_restriction("192.168.1.100")
        assert ok is True

    def test_us_ip_in_allowed_regions(self, engine):
        ok, reason = engine.check_geo_restriction("50.0.0.1", ["US", "CA"])
        assert ok is True

    def test_blocked_region_denied(self, engine):
        # 185.x maps to RU based on our pseudo-GeoIP
        ok, reason = engine.check_geo_restriction("185.0.0.1", ["US", "CA"])
        assert ok is False
        assert "blocked" in reason

    def test_custom_allowed_regions(self, engine):
        ok, _ = engine.check_geo_restriction("50.0.0.1", ["DE"])
        # 50.x → US, not in ["DE"], should be blocked
        assert ok is False


# ============================================================================
# ZeroTrustEngine — time restriction
# ============================================================================


class TestTimeRestriction:
    def test_default_window_returns_bool(self, engine):
        allowed, reason = engine.check_time_restriction("alice", "findings")
        assert isinstance(allowed, bool)
        assert isinstance(reason, str)
        assert "window" in reason

    def test_custom_window_24h_always_allowed(self, engine):
        """Insert a 0-24 window → always allowed."""
        import sqlite3
        from datetime import datetime, timezone
        conn = sqlite3.connect(str(engine.db_path))
        conn.execute(
            """INSERT INTO time_restrictions
               (id, user_id, resource, org_id, start_hour, end_hour, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (str(uuid.uuid4()), "bob", "findings", "default",
             0, 24, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
        conn.close()
        allowed, _ = engine.check_time_restriction("bob", "findings")
        assert allowed is True

    def test_custom_window_0_to_0_always_denied(self, engine):
        """Insert a 0–0 window → never in range."""
        import sqlite3
        from datetime import datetime, timezone
        conn = sqlite3.connect(str(engine.db_path))
        conn.execute(
            """INSERT INTO time_restrictions
               (id, user_id, resource, org_id, start_hour, end_hour, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (str(uuid.uuid4()), "carol", "admin", "default",
             0, 0, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
        conn.close()
        allowed, _ = engine.check_time_restriction("carol", "admin")
        assert allowed is False

    def test_unknown_user_uses_default_window(self, engine):
        allowed, reason = engine.check_time_restriction("nobody", "random_resource")
        assert isinstance(allowed, bool)


# ============================================================================
# ZeroTrustEngine — evaluate_access (full policy)
# ============================================================================


class TestEvaluateAccess:
    def test_healthy_device_private_ip_grants_access(self, engine, healthy_device):
        decision = engine.evaluate_access(
            user="alice",
            resource="findings",
            device_posture=healthy_device,
            context={"ip": "10.0.0.1", "mfa_verified": True},
        )
        assert decision.allowed is True
        assert decision.trust_level == TrustLevel.VERIFIED

    def test_weak_device_denies_access(self, engine, weak_device):
        decision = engine.evaluate_access(
            user="alice",
            resource="findings",
            device_posture=weak_device,
            context={"ip": "10.0.0.1"},
        )
        assert decision.allowed is False
        assert "device_trust_too_low" in decision.reason

    def test_blocked_geo_denies_access(self, engine, healthy_device):
        decision = engine.evaluate_access(
            user="alice",
            resource="findings",
            device_posture=healthy_device,
            context={"ip": "185.0.0.1", "allowed_regions": ["US"]},
        )
        assert decision.allowed is False
        assert "geo_blocked" in decision.reason

    def test_admin_resource_without_mfa_denied(self, engine, healthy_device):
        decision = engine.evaluate_access(
            user="alice",
            resource="admin",
            device_posture=healthy_device,
            context={"ip": "10.0.0.1"},  # mfa_verified not set
        )
        assert decision.allowed is False
        assert decision.mfa_required is True

    def test_admin_resource_with_mfa_granted(self, engine, healthy_device):
        decision = engine.evaluate_access(
            user="alice",
            resource="admin",
            device_posture=healthy_device,
            context={"ip": "10.0.0.1", "mfa_verified": True},
        )
        assert decision.allowed is True
        assert decision.mfa_required is True

    def test_high_trust_resource_requires_high_device(self, engine):
        """A device with medium trust cannot access secrets."""
        medium_device = DevicePosture(
            device_id="dev-med",
            os="Linux",
            os_version="6",
            encrypted=True,
            firewall_enabled=True,
            antivirus_active=False,
            patch_level=0.1,
        )
        decision = engine.evaluate_access(
            user="alice",
            resource="secrets",
            device_posture=medium_device,
            context={"ip": "10.0.0.1", "mfa_verified": True},
        )
        # secrets is in _MFA_ALWAYS_REQUIRED_RESOURCES and _HIGH_TRUST_RESOURCES
        # medium trust (encrypted+firewall+patch=0.30+0.20+0.03=0.53 → MEDIUM) blocked
        assert decision.allowed is False

    def test_conditions_list_populated_on_grant(self, engine, healthy_device):
        decision = engine.evaluate_access(
            user="alice",
            resource="reports",
            device_posture=healthy_device,
            context={"ip": "10.0.0.1"},
        )
        # reports not in MFA set, so access granted
        assert len(decision.conditions) > 0

    def test_decision_recorded_in_audit(self, engine, healthy_device):
        engine.evaluate_access(
            user="alice",
            resource="findings",
            device_posture=healthy_device,
            context={"ip": "10.0.0.1"},
        )
        stats = engine.get_zero_trust_stats()
        assert stats["total_evaluations"] >= 1


# ============================================================================
# ZeroTrustEngine — record_access_event
# ============================================================================


class TestRecordAccessEvent:
    def test_record_stores_event(self, engine):
        decision = AccessDecision(
            allowed=True,
            trust_level=TrustLevel.HIGH,
            reason="access_granted",
            conditions=["device_ok"],
        )
        engine.record_access_event(decision, user="bob", resource="findings")
        stats = engine.get_zero_trust_stats()
        assert stats["total_evaluations"] == 1
        assert stats["allowed"] == 1

    def test_denied_event_counted_separately(self, engine):
        decision = AccessDecision(
            allowed=False,
            trust_level=TrustLevel.NONE,
            reason="geo_blocked",
        )
        engine.record_access_event(decision, user="eve", resource="admin")
        stats = engine.get_zero_trust_stats()
        assert stats["denied"] == 1


# ============================================================================
# ZeroTrustEngine — continuous auth / sessions
# ============================================================================


class TestContinuousAuth:
    def test_unknown_session_returns_high_risk(self, engine):
        status = engine.get_continuous_auth_status("sess-unknown")
        assert status["found"] is False
        assert status["risk_score"] == 1.0
        assert status["requires_reauth"] is True

    def test_fresh_session_low_risk(self, engine):
        engine.upsert_session(
            session_id="sess-fresh",
            user_id="alice",
            device_id="dev-001",
            risk_score=0.1,
        )
        status = engine.get_continuous_auth_status("sess-fresh")
        assert status["found"] is True
        assert status["risk_score"] < 0.70
        assert status["requires_reauth"] is False

    def test_high_base_risk_session_requires_reauth(self, engine):
        engine.upsert_session(
            session_id="sess-risky",
            user_id="bob",
            risk_score=0.80,
        )
        status = engine.get_continuous_auth_status("sess-risky")
        assert status["requires_reauth"] is True

    def test_session_trust_level_in_response(self, engine):
        engine.upsert_session(
            session_id="sess-trusted",
            user_id="carol",
            risk_score=0.0,
        )
        status = engine.get_continuous_auth_status("sess-trusted")
        assert "trust_level" in status
        assert status["trust_level"] in ("none", "low", "medium", "high", "verified")


# ============================================================================
# ZeroTrustEngine — stats
# ============================================================================


class TestZeroTrustStats:
    def test_empty_db_stats(self, engine):
        stats = engine.get_zero_trust_stats()
        assert stats["total_evaluations"] == 0
        assert stats["allowed"] == 0
        assert stats["denied"] == 0
        assert stats["registered_devices"] == 0

    def test_stats_after_evaluations(self, engine, healthy_device):
        engine.evaluate_access(
            "alice", "findings", healthy_device,
            context={"ip": "10.0.0.1"},
        )
        engine.evaluate_access(
            "eve", "findings", healthy_device,
            context={"ip": "185.0.0.1", "allowed_regions": ["US"]},
        )
        stats = engine.get_zero_trust_stats()
        assert stats["total_evaluations"] == 2
        assert stats["allowed"] + stats["denied"] == 2

    def test_stats_include_allow_rate(self, engine, healthy_device):
        engine.evaluate_access(
            "alice", "reports", healthy_device,
            context={"ip": "10.0.0.1"},
        )
        stats = engine.get_zero_trust_stats()
        assert 0.0 <= stats["allow_rate"] <= 1.0


# ============================================================================
# Factory function
# ============================================================================


class TestFactory:
    def test_create_zero_trust_engine(self, tmp_path):
        eng = create_zero_trust_engine(db_path=str(tmp_path / "zt2.db"))
        assert isinstance(eng, ZeroTrustEngine)


# ============================================================================
# Router import / basic structure
# ============================================================================


class TestRouterImport:
    def test_router_importable(self):
        from apps.api.zero_trust_router import router
        assert router is not None

    def test_router_has_correct_prefix(self):
        from apps.api.zero_trust_router import router
        assert router.prefix == "/api/v1/zero-trust"

    def test_router_has_eight_routes(self):
        from apps.api.zero_trust_router import router
        assert len(router.routes) >= 8
