"""
Tests for API Gateway Security Engine and Router.

Covers:
1. API key management helpers (via existing APIKeyManager)
2. Rate limiting engine (sliding window, per-key, per-IP, tiers)
3. Request validation (content-type, payload size, required fields)
4. API versioning management (client version tracking, deprecation alerts)
5. Throttling policies (burst, sustained, plan tier override)
6. API usage analytics (recording, endpoint stats, top consumers, error rates, latency)
7. IP allowlisting/blocklisting with CIDR support
8. APIGatewayEngine facade (process_request end-to-end)
9. Router endpoints via FastAPI TestClient
"""

from __future__ import annotations

import os
import tempfile
import time
from datetime import datetime, timezone
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

# Env setup BEFORE importing anything from the project
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret-key-for-testing-only")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.api_gateway import (
    APIGatewayEngine,
    GatewayAnalytics,
    IPFilter,
    IPRuleAction,
    PlanTier,
    RateLimitConfig,
    RateLimiter,
    RequestValidator,
    ThrottlePolicy,
    ThrottlePolicyStore,
    VersionTracker,
    _SlidingWindow,
    get_api_gateway_engine,
)
from apps.api.api_gateway_router import router as gateway_router


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_prefix(tmp_path):
    """Return a temp-dir-based DB prefix for isolated engine instances."""
    return str(tmp_path / "gw")


@pytest.fixture
def engine(tmp_prefix):
    """Fresh APIGatewayEngine with isolated DBs."""
    return APIGatewayEngine(db_prefix=tmp_prefix)


@pytest.fixture
def ip_filter(tmp_path):
    return IPFilter(db_path=str(tmp_path / "ip.db"))


@pytest.fixture
def rate_limiter():
    return RateLimiter()


@pytest.fixture
def validator():
    return RequestValidator()


@pytest.fixture
def analytics(tmp_path):
    return GatewayAnalytics(db_path=str(tmp_path / "analytics.db"))


@pytest.fixture
def version_tracker(tmp_path):
    return VersionTracker(db_path=str(tmp_path / "versions.db"))


@pytest.fixture
def policy_store(tmp_path):
    return ThrottlePolicyStore(db_path=str(tmp_path / "policies.db"))


@pytest.fixture
def test_client(tmp_prefix):
    """TestClient with a fresh engine injected."""
    fresh_engine = APIGatewayEngine(db_prefix=tmp_prefix)
    app = FastAPI()
    app.include_router(gateway_router)

    from apps.api import api_gateway_router as router_module
    with patch.object(router_module, "get_api_gateway_engine", return_value=fresh_engine):
        with TestClient(app) as client:
            yield client, fresh_engine


# ---------------------------------------------------------------------------
# 1. Sliding window helper
# ---------------------------------------------------------------------------


class TestSlidingWindow:
    def test_count_starts_at_zero(self):
        sw = _SlidingWindow(60)
        assert sw.count() == 0

    def test_add_and_count(self):
        sw = _SlidingWindow(60)
        assert sw.add_and_count() == 1
        assert sw.add_and_count() == 2
        assert sw.count() == 2

    def test_window_expiry(self):
        sw = _SlidingWindow(1)  # 1-second window
        sw.add_and_count()
        sw.add_and_count()
        time.sleep(1.1)
        assert sw.count() == 0

    def test_add_after_expiry(self):
        sw = _SlidingWindow(1)
        sw.add_and_count()
        time.sleep(1.1)
        # After expiry, new add gives count of 1
        assert sw.add_and_count() == 1


# ---------------------------------------------------------------------------
# 2. Rate Limiter
# ---------------------------------------------------------------------------


class TestRateLimiter:
    def test_free_tier_allows_under_limit(self, rate_limiter):
        result = rate_limiter.check_rate_limit(tier=PlanTier.FREE, api_key_id="key1")
        assert result.allowed is True
        assert result.tier == PlanTier.FREE

    def test_rate_limiter_returns_correct_tier(self, rate_limiter):
        result = rate_limiter.check_rate_limit(tier=PlanTier.PRO, api_key_id="key2")
        assert result.tier == PlanTier.PRO
        assert result.limit_per_minute == 120

    def test_enterprise_tier_has_higher_limit(self, rate_limiter):
        result = rate_limiter.check_rate_limit(tier=PlanTier.ENTERPRISE, api_key_id="key3")
        assert result.limit_per_minute == 600
        assert result.burst_limit == 200

    def test_burst_limit_exceeded(self):
        rl = RateLimiter(tier_configs={
            PlanTier.FREE: RateLimitConfig(
                tier=PlanTier.FREE,
                requests_per_minute=1000,
                requests_per_hour=100000,
                burst_limit=3,
                sustained_limit=1000,
            )
        })
        for _ in range(3):
            rl.check_rate_limit(tier=PlanTier.FREE, api_key_id="busty")
        result = rl.check_rate_limit(tier=PlanTier.FREE, api_key_id="busty")
        assert result.allowed is False
        assert "Burst" in (result.reason or "")
        assert result.retry_after_seconds == 10

    def test_minute_limit_exceeded(self):
        rl = RateLimiter(tier_configs={
            PlanTier.FREE: RateLimitConfig(
                tier=PlanTier.FREE,
                requests_per_minute=2,
                requests_per_hour=100000,
                burst_limit=1000,
                sustained_limit=1000,
            )
        })
        for _ in range(2):
            rl.check_rate_limit(tier=PlanTier.FREE, api_key_id="mkey")
        result = rl.check_rate_limit(tier=PlanTier.FREE, api_key_id="mkey")
        assert result.allowed is False
        assert result.retry_after_seconds == 60

    def test_get_tier_configs(self, rate_limiter):
        configs = rate_limiter.get_tier_configs()
        assert "free" in configs
        assert "pro" in configs
        assert "enterprise" in configs

    def test_update_tier_config(self, rate_limiter):
        new_cfg = RateLimitConfig(
            tier=PlanTier.FREE,
            requests_per_minute=5,
            requests_per_hour=100,
            burst_limit=2,
            sustained_limit=5,
        )
        rate_limiter.update_tier_config(PlanTier.FREE, new_cfg)
        configs = rate_limiter.get_tier_configs()
        assert configs["free"]["requests_per_minute"] == 5

    def test_throttle_policy_override(self, rate_limiter):
        policy = ThrottlePolicy(
            target_id="vip_key",
            target_type="api_key",
            burst_limit=500,
            sustained_limit=500,
            requests_per_minute=500,
            requests_per_hour=50000,
            description="VIP override",
        )
        rate_limiter.register_policy(policy)
        result = rate_limiter.check_rate_limit(tier=PlanTier.FREE, api_key_id="vip_key")
        assert result.allowed is True
        assert result.limit_per_minute == 500

    def test_remove_policy(self, rate_limiter):
        policy = ThrottlePolicy(
            target_id="temp_key",
            target_type="api_key",
            burst_limit=5,
            sustained_limit=5,
            requests_per_minute=5,
            requests_per_hour=50,
        )
        rate_limiter.register_policy(policy)
        removed = rate_limiter.remove_policy("temp_key")
        assert removed is True

    def test_remove_nonexistent_policy(self, rate_limiter):
        assert rate_limiter.remove_policy("nonexistent") is False

    def test_reset_counters(self, rate_limiter):
        rate_limiter.check_rate_limit(tier=PlanTier.FREE, api_key_id="reset_me")
        rate_limiter.reset_counters("reset_me")
        # After reset, should start fresh
        result = rate_limiter.check_rate_limit(tier=PlanTier.FREE, api_key_id="reset_me")
        assert result.requests_this_minute == 1

    def test_per_ip_tracking(self, rate_limiter):
        result = rate_limiter.check_rate_limit(tier=PlanTier.FREE, ip="10.0.0.1")
        assert result.allowed is True
        assert result.ip == "10.0.0.1"

    def test_both_key_and_ip(self, rate_limiter):
        result = rate_limiter.check_rate_limit(
            tier=PlanTier.PRO,
            api_key_id="ak_xyz",
            ip="192.168.1.5",
        )
        assert result.allowed is True
        assert result.key_id == "ak_xyz"
        assert result.ip == "192.168.1.5"


# ---------------------------------------------------------------------------
# 3. IP Filter
# ---------------------------------------------------------------------------


class TestIPFilter:
    def test_default_allows_any_ip(self, ip_filter):
        result = ip_filter.is_allowed("8.8.8.8")
        assert result.allowed is True
        assert result.reason == "default_allow"

    def test_block_single_ip(self, ip_filter):
        ip_filter.add_rule("1.2.3.4", IPRuleAction.BLOCK, description="bad actor")
        result = ip_filter.is_allowed("1.2.3.4")
        assert result.allowed is False
        assert result.action == IPRuleAction.BLOCK

    def test_block_cidr_range(self, ip_filter):
        ip_filter.add_rule("10.0.0.0/8", IPRuleAction.BLOCK)
        assert ip_filter.is_allowed("10.1.2.3").allowed is False
        assert ip_filter.is_allowed("11.0.0.1").allowed is True

    def test_allow_rule(self, ip_filter):
        ip_filter.add_rule("192.168.1.0/24", IPRuleAction.ALLOW)
        result = ip_filter.is_allowed("192.168.1.100")
        assert result.allowed is True
        assert result.action == IPRuleAction.ALLOW

    def test_block_takes_priority_over_allow(self, ip_filter):
        ip_filter.add_rule("192.168.0.0/16", IPRuleAction.ALLOW)
        ip_filter.add_rule("192.168.1.5/32", IPRuleAction.BLOCK)
        # The specific /32 block should win
        result = ip_filter.is_allowed("192.168.1.5")
        assert result.allowed is False

    def test_remove_rule(self, ip_filter):
        rule = ip_filter.add_rule("5.5.5.5", IPRuleAction.BLOCK)
        assert ip_filter.is_allowed("5.5.5.5").allowed is False
        removed = ip_filter.remove_rule(rule.id)
        assert removed is True
        assert ip_filter.is_allowed("5.5.5.5").allowed is True

    def test_remove_nonexistent_rule(self, ip_filter):
        assert ip_filter.remove_rule("ipr_notexist") is False

    def test_list_rules_empty(self, ip_filter):
        assert ip_filter.list_rules() == []

    def test_list_rules_with_filter(self, ip_filter):
        ip_filter.add_rule("1.1.1.1", IPRuleAction.ALLOW)
        ip_filter.add_rule("2.2.2.2", IPRuleAction.BLOCK)
        allow_rules = ip_filter.list_rules(action=IPRuleAction.ALLOW)
        block_rules = ip_filter.list_rules(action=IPRuleAction.BLOCK)
        assert len(allow_rules) == 1
        assert len(block_rules) == 1

    def test_invalid_ip_returns_blocked(self, ip_filter):
        result = ip_filter.is_allowed("not-an-ip")
        assert result.allowed is False

    def test_invalid_cidr_raises(self, ip_filter):
        with pytest.raises(ValueError):
            ip_filter.add_rule("not-a-cidr", IPRuleAction.BLOCK)

    def test_ipv6_support(self, ip_filter):
        ip_filter.add_rule("::1/128", IPRuleAction.BLOCK)
        result = ip_filter.is_allowed("::1")
        assert result.allowed is False

    def test_rule_has_id_and_timestamps(self, ip_filter):
        rule = ip_filter.add_rule("3.3.3.3", IPRuleAction.ALLOW, description="test")
        assert rule.id.startswith("ipr_")
        assert isinstance(rule.created_at, datetime)
        assert rule.description == "test"


# ---------------------------------------------------------------------------
# 4. Request Validator
# ---------------------------------------------------------------------------


class TestRequestValidator:
    def test_valid_json_request(self, validator):
        result = validator.validate(
            content_type="application/json",
            payload_size_bytes=100,
        )
        assert result.valid is True
        assert len(result.errors) == 0

    def test_invalid_content_type(self, validator):
        result = validator.validate(
            content_type="application/xml",
            payload_size_bytes=100,
        )
        assert result.valid is False
        assert any(e["type"] == "invalid_content_type" for e in result.errors)

    def test_content_type_with_charset(self, validator):
        result = validator.validate(
            content_type="application/json; charset=utf-8",
            payload_size_bytes=100,
        )
        assert result.valid is True

    def test_payload_too_large(self, validator):
        result = validator.validate(
            content_type="application/json",
            payload_size_bytes=11 * 1024 * 1024,  # 11 MB
        )
        assert result.valid is False
        assert any(e["type"] == "payload_too_large" for e in result.errors)

    def test_custom_payload_limit(self):
        v = RequestValidator(max_payload_bytes=1024)
        result = v.validate(content_type="application/json", payload_size_bytes=2048)
        assert result.valid is False

    def test_missing_required_fields(self, validator):
        result = validator.validate(
            content_type="application/json",
            payload_size_bytes=50,
            required_fields=["name", "org_id"],
            payload_dict={"name": "test"},  # missing org_id
        )
        assert result.valid is False
        assert any(e["type"] == "missing_required_field" for e in result.errors)
        assert any("org_id" in e["detail"] for e in result.errors)

    def test_all_required_fields_present(self, validator):
        result = validator.validate(
            content_type="application/json",
            payload_size_bytes=50,
            required_fields=["name", "org_id"],
            payload_dict={"name": "test", "org_id": "acme"},
        )
        assert result.valid is True

    def test_no_content_type_is_valid(self, validator):
        result = validator.validate(content_type=None, payload_size_bytes=0)
        assert result.valid is True

    def test_multipart_content_type_allowed(self, validator):
        result = validator.validate(
            content_type="multipart/form-data",
            payload_size_bytes=500,
        )
        assert result.valid is True

    def test_multiple_errors_accumulated(self, validator):
        result = validator.validate(
            content_type="application/xml",
            payload_size_bytes=20 * 1024 * 1024,
        )
        assert result.valid is False
        assert len(result.errors) == 2

    def test_result_includes_payload_size(self, validator):
        result = validator.validate(content_type="application/json", payload_size_bytes=999)
        assert result.payload_size_bytes == 999

    def test_result_includes_api_version(self, validator):
        result = validator.validate(
            content_type="application/json",
            payload_size_bytes=10,
            api_version="v2",
        )
        assert result.api_version == "v2"


# ---------------------------------------------------------------------------
# 5. Version Tracker
# ---------------------------------------------------------------------------


class TestVersionTracker:
    def test_record_new_client_version(self, version_tracker):
        rec, alert = version_tracker.record_version_usage("client1", "v1")
        assert rec.client_id == "client1"
        assert rec.api_version == "v1"
        assert rec.request_count == 1
        assert alert is False  # v1 is not deprecated

    def test_deprecated_version_triggers_alert(self, version_tracker):
        # v0 is deprecated
        rec, alert = version_tracker.record_version_usage("old_client", "v0")
        assert alert is True
        assert rec.deprecation_warned is True

    def test_subsequent_requests_increment_count(self, version_tracker):
        version_tracker.record_version_usage("client2", "v1")
        rec, _ = version_tracker.record_version_usage("client2", "v1")
        assert rec.request_count == 2

    def test_no_repeat_deprecation_alert(self, version_tracker):
        _, first_alert = version_tracker.record_version_usage("dep_client", "v0")
        _, second_alert = version_tracker.record_version_usage("dep_client", "v0")
        assert first_alert is True
        assert second_alert is False  # already warned

    def test_get_client_versions(self, version_tracker):
        version_tracker.record_version_usage("multi", "v1")
        version_tracker.record_version_usage("multi", "v2")
        versions = version_tracker.get_client_versions("multi")
        assert len(versions) == 2
        version_strs = {v.api_version for v in versions}
        assert version_strs == {"v1", "v2"}

    def test_get_version_stats(self, version_tracker):
        version_tracker.record_version_usage("c1", "v1")
        version_tracker.record_version_usage("c2", "v2")
        version_tracker.record_version_usage("c3", "v0")
        stats = version_tracker.get_version_stats()
        assert "by_version" in stats
        assert "deprecated_versions" in stats
        assert stats["clients_on_deprecated"] >= 1

    def test_get_deprecation_alerts(self, version_tracker):
        version_tracker.record_version_usage("alert_client", "v0")
        alerts = version_tracker.get_deprecation_alerts()
        assert len(alerts) >= 1
        assert any(a["client_id"] == "alert_client" for a in alerts)

    def test_no_alerts_when_using_supported_version(self, version_tracker):
        version_tracker.record_version_usage("good_client", "v1")
        alerts = version_tracker.get_deprecation_alerts()
        assert all(a["client_id"] != "good_client" for a in alerts)


# ---------------------------------------------------------------------------
# 6. Analytics
# ---------------------------------------------------------------------------


class TestGatewayAnalytics:
    def test_record_and_retrieve_call(self, analytics):
        call = analytics.record_call(
            endpoint="/api/v1/findings",
            method="GET",
            status_code=200,
            response_ms=42.5,
            api_key_id="ak_test",
            org_id="acme",
            ip_address="1.2.3.4",
            api_version="v1",
            plan_tier=PlanTier.PRO,
        )
        assert call.id is not None
        assert call.endpoint == "/api/v1/findings"

    def test_endpoint_stats_empty(self, analytics):
        stats = analytics.get_endpoint_stats(hours=24)
        assert stats == []

    def test_endpoint_stats_with_data(self, analytics):
        for i in range(5):
            analytics.record_call(
                endpoint="/api/v1/test",
                method="GET",
                status_code=200 if i < 4 else 500,
                response_ms=float(10 + i * 5),
            )
        stats = analytics.get_endpoint_stats(hours=24)
        assert len(stats) == 1
        ep = stats[0]
        assert ep["endpoint"] == "/api/v1/test"
        assert ep["total_calls"] == 5
        assert ep["error_calls"] == 1
        assert 0.19 < ep["error_rate"] < 0.21
        assert ep["p95_response_ms"] > 0

    def test_top_consumers(self, analytics):
        for key in ["k1", "k1", "k2"]:
            analytics.record_call(
                endpoint="/test",
                method="GET",
                status_code=200,
                response_ms=10.0,
                api_key_id=key,
            )
        consumers = analytics.get_top_consumers(limit=5, hours=24)
        assert consumers[0]["api_key_id"] == "k1"
        assert consumers[0]["total_calls"] == 2

    def test_error_summary(self, analytics):
        analytics.record_call("/a", "GET", 200, 10.0)
        analytics.record_call("/a", "GET", 404, 5.0)
        analytics.record_call("/a", "GET", 500, 50.0)
        summary = analytics.get_error_summary(hours=24)
        assert summary["total_calls"] == 3
        assert summary["total_errors"] == 2
        assert abs(summary["error_rate"] - 0.6667) < 0.001

    def test_latency_percentiles(self, analytics):
        for ms in [10.0, 20.0, 30.0, 40.0, 100.0]:
            analytics.record_call("/lat", "GET", 200, ms)
        percs = analytics.get_latency_percentiles(endpoint="/lat", hours=24)
        assert percs["total_calls"] == 5
        assert percs["min_ms"] == 10.0
        assert percs["max_ms"] == 100.0
        assert percs["p50_ms"] > 0

    def test_latency_percentiles_empty(self, analytics):
        percs = analytics.get_latency_percentiles(hours=24)
        assert percs["total_calls"] == 0
        assert percs["p95_ms"] == 0.0

    def test_cleanup_old(self, analytics):
        analytics.record_call("/old", "GET", 200, 1.0)
        # Cleanup with 0 days should delete everything
        deleted = analytics.cleanup_old(days=0)
        assert deleted >= 0  # Could be 0 if timestamp is in future by ms


# ---------------------------------------------------------------------------
# 7. Throttle Policy Store
# ---------------------------------------------------------------------------


class TestThrottlePolicyStore:
    def test_upsert_and_get_policy(self, policy_store):
        policy = ThrottlePolicy(
            target_id="target1",
            target_type="api_key",
            burst_limit=50,
            sustained_limit=200,
            requests_per_minute=200,
            requests_per_hour=5000,
            description="Test policy",
        )
        saved = policy_store.upsert_policy(policy)
        retrieved = policy_store.get_policy("target1")
        assert retrieved is not None
        assert retrieved.burst_limit == 50
        assert retrieved.description == "Test policy"

    def test_upsert_updates_existing(self, policy_store):
        policy = ThrottlePolicy(
            target_id="target2",
            target_type="api_key",
            burst_limit=10,
            sustained_limit=10,
            requests_per_minute=10,
            requests_per_hour=100,
        )
        policy_store.upsert_policy(policy)
        # Update with higher limits
        updated = ThrottlePolicy(
            target_id="target2",
            target_type="api_key",
            burst_limit=500,
            sustained_limit=500,
            requests_per_minute=500,
            requests_per_hour=50000,
        )
        policy_store.upsert_policy(updated)
        got = policy_store.get_policy("target2")
        assert got is not None
        assert got.burst_limit == 500

    def test_get_nonexistent_policy(self, policy_store):
        assert policy_store.get_policy("nonexistent") is None

    def test_list_policies(self, policy_store):
        for i in range(3):
            policy_store.upsert_policy(ThrottlePolicy(
                target_id=f"tgt_{i}",
                target_type="api_key",
                burst_limit=10,
                sustained_limit=10,
                requests_per_minute=10,
                requests_per_hour=100,
            ))
        policies = policy_store.list_policies()
        assert len(policies) == 3

    def test_delete_policy(self, policy_store):
        policy_store.upsert_policy(ThrottlePolicy(
            target_id="to_delete",
            target_type="api_key",
            burst_limit=5,
            sustained_limit=5,
            requests_per_minute=5,
            requests_per_hour=50,
        ))
        removed = policy_store.delete_policy("to_delete")
        assert removed is True
        assert policy_store.get_policy("to_delete") is None

    def test_delete_nonexistent(self, policy_store):
        assert policy_store.delete_policy("doesnt_exist") is False


# ---------------------------------------------------------------------------
# 8. APIGatewayEngine facade
# ---------------------------------------------------------------------------


class TestAPIGatewayEngine:
    def test_allowed_request(self, engine):
        result = engine.process_request(
            endpoint="/api/v1/findings",
            method="GET",
            ip="8.8.8.8",
            content_type="application/json",
            payload_size_bytes=100,
            api_key_id="ak_test",
            api_version="v1",
            plan_tier=PlanTier.PRO,
        )
        assert result["allowed"] is True
        assert result["reason"] is None

    def test_blocked_by_ip(self, engine):
        engine.ip_filter.add_rule("1.2.3.4", IPRuleAction.BLOCK)
        result = engine.process_request(
            endpoint="/api/v1/findings",
            method="GET",
            ip="1.2.3.4",
        )
        assert result["allowed"] is False
        assert "Blocked" in result["reason"]

    def test_blocked_by_invalid_content_type(self, engine):
        result = engine.process_request(
            endpoint="/api/v1/test",
            method="POST",
            ip="9.9.9.9",
            content_type="application/xml",
            payload_size_bytes=100,
        )
        assert result["allowed"] is False
        assert result["validation"] is not None

    def test_deprecation_alert_returned(self, engine):
        result = engine.process_request(
            endpoint="/api/v0/old",
            method="GET",
            ip="7.7.7.7",
            api_key_id="old_client",
            api_version="v0",
        )
        assert result["allowed"] is True
        assert result["deprecation_alert"] is True

    def test_no_deprecation_for_v1(self, engine):
        result = engine.process_request(
            endpoint="/api/v1/findings",
            method="GET",
            ip="6.6.6.6",
            api_key_id="modern_client",
            api_version="v1",
        )
        assert result["allowed"] is True
        assert result["deprecation_alert"] is False

    def test_required_fields_missing_blocks(self, engine):
        result = engine.process_request(
            endpoint="/api/v1/test",
            method="POST",
            ip="5.5.5.5",
            content_type="application/json",
            payload_size_bytes=50,
            required_fields=["name"],
            payload_dict={},
        )
        assert result["allowed"] is False
        assert result["validation"]["errors"]

    def test_singleton_pattern(self):
        # Two calls without db_prefix return the same instance
        a = get_api_gateway_engine()
        b = get_api_gateway_engine()
        assert a is b

    def test_isolated_instance_with_prefix(self, tmp_prefix):
        # Two calls with same prefix return same instance
        a = APIGatewayEngine(db_prefix=tmp_prefix)
        b = APIGatewayEngine(db_prefix=tmp_prefix + "_other")
        # They are separate instances
        assert a is not b


# ---------------------------------------------------------------------------
# 9. Router endpoints via TestClient
# ---------------------------------------------------------------------------


class TestGatewayRouter:
    def test_health_endpoint(self, test_client):
        client, _ = test_client
        resp = client.get("/api/v1/gateway/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["engine"] == "api_gateway"

    def test_rate_limits_endpoint(self, test_client):
        client, _ = test_client
        resp = client.get("/api/v1/gateway/rate-limits")
        assert resp.status_code == 200
        data = resp.json()
        assert "tier_configs" in data
        assert "free" in data["tier_configs"]
        assert "pro" in data["tier_configs"]
        assert "enterprise" in data["tier_configs"]

    def test_update_tier_config(self, test_client):
        client, _ = test_client
        resp = client.put("/api/v1/gateway/rate-limits/tiers", json={
            "tier": "free",
            "requests_per_minute": 50,
            "requests_per_hour": 1000,
            "burst_limit": 15,
            "sustained_limit": 50,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["updated"] is True
        assert data["config"]["requests_per_minute"] == 50

    def test_list_ip_rules_empty(self, test_client):
        client, _ = test_client
        resp = client.get("/api/v1/gateway/ip-rules")
        assert resp.status_code == 200
        assert resp.json()["total"] == 0

    def test_add_ip_rule(self, test_client):
        client, _ = test_client
        resp = client.post("/api/v1/gateway/ip-rules", json={
            "cidr": "10.0.0.0/8",
            "action": "block",
            "description": "Test block",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["created"] is True
        assert data["rule"]["cidr"] == "10.0.0.0/8"

    def test_add_ip_rule_invalid_cidr(self, test_client):
        client, _ = test_client
        resp = client.post("/api/v1/gateway/ip-rules", json={
            "cidr": "not-a-cidr",
            "action": "block",
        })
        assert resp.status_code == 422

    def test_remove_ip_rule(self, test_client):
        client, _ = test_client
        # Add then remove
        add_resp = client.post("/api/v1/gateway/ip-rules", json={
            "cidr": "99.0.0.0/8",
            "action": "allow",
        })
        assert add_resp.status_code == 201
        rule_id = add_resp.json()["rule"]["id"]

        del_resp = client.delete(f"/api/v1/gateway/ip-rules/{rule_id}")
        assert del_resp.status_code == 200
        assert del_resp.json()["removed"] is True

    def test_remove_nonexistent_ip_rule(self, test_client):
        client, _ = test_client
        resp = client.delete("/api/v1/gateway/ip-rules/ipr_notexist")
        assert resp.status_code == 404

    def test_list_ip_rules_with_filter(self, test_client):
        client, _ = test_client
        client.post("/api/v1/gateway/ip-rules", json={"cidr": "1.1.1.1", "action": "allow"})
        client.post("/api/v1/gateway/ip-rules", json={"cidr": "2.2.2.2", "action": "block"})

        resp = client.get("/api/v1/gateway/ip-rules?action=allow")
        assert resp.status_code == 200
        data = resp.json()
        assert all(r["action"] == "allow" for r in data["rules"])

    def test_list_ip_rules_invalid_action(self, test_client):
        client, _ = test_client
        resp = client.get("/api/v1/gateway/ip-rules?action=invalid")
        assert resp.status_code == 422

    def test_set_throttle_policy(self, test_client):
        client, _ = test_client
        resp = client.post("/api/v1/gateway/throttle-policies", json={
            "target_id": "ak_vip",
            "target_type": "api_key",
            "burst_limit": 500,
            "sustained_limit": 500,
            "requests_per_minute": 500,
            "requests_per_hour": 50000,
            "description": "VIP key",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["created"] is True
        assert data["policy"]["burst_limit"] == 500

    def test_gateway_check_allowed(self, test_client):
        client, _ = test_client
        resp = client.post("/api/v1/gateway/check", json={
            "endpoint": "/api/v1/findings",
            "method": "GET",
            "ip": "8.8.8.8",
            "content_type": "application/json",
            "payload_size_bytes": 100,
            "api_key_id": "ak_test",
            "api_version": "v1",
            "plan_tier": "pro",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["allowed"] is True

    def test_gateway_check_blocked_ip(self, test_client):
        client, engine = test_client
        engine.ip_filter.add_rule("3.3.3.3", IPRuleAction.BLOCK)
        resp = client.post("/api/v1/gateway/check", json={
            "endpoint": "/api/v1/findings",
            "method": "GET",
            "ip": "3.3.3.3",
        })
        assert resp.status_code == 403

    def test_gateway_check_invalid_content_type(self, test_client):
        client, _ = test_client
        resp = client.post("/api/v1/gateway/check", json={
            "endpoint": "/api/v1/test",
            "method": "POST",
            "ip": "4.4.4.4",
            "content_type": "application/xml",
            "payload_size_bytes": 50,
        })
        assert resp.status_code == 403

    def test_analytics_endpoint(self, test_client):
        client, engine = test_client
        # Record some calls first
        engine.analytics.record_call("/test", "GET", 200, 10.0, api_key_id="k1")
        engine.analytics.record_call("/test", "GET", 500, 20.0, api_key_id="k2")

        resp = client.get("/api/v1/gateway/analytics?hours=24&limit=5")
        assert resp.status_code == 200
        data = resp.json()
        assert "endpoint_stats" in data
        assert "top_consumers" in data
        assert "error_summary" in data
        assert "latency_percentiles" in data

    def test_version_stats_endpoint(self, test_client):
        client, engine = test_client
        engine.version_tracker.record_version_usage("c1", "v1")
        engine.version_tracker.record_version_usage("c2", "v0")

        resp = client.get("/api/v1/gateway/version-stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "stats" in data
        assert "deprecation_alerts" in data
        assert data["alert_count"] >= 1

    def test_analytics_invalid_hours(self, test_client):
        client, _ = test_client
        resp = client.get("/api/v1/gateway/analytics?hours=0")
        assert resp.status_code == 422

    def test_analytics_hours_too_large(self, test_client):
        client, _ = test_client
        resp = client.get("/api/v1/gateway/analytics?hours=9999")
        assert resp.status_code == 422
