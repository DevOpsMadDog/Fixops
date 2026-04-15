"""Tests for DeceptionEngine — 28 tests covering all public methods + org isolation."""

from __future__ import annotations

import pytest
from core.deception_engine import CanaryType, DeceptionEngine


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "deception_test.db")
    return DeceptionEngine(db_path=db)


@pytest.fixture
def org():
    return "org-alpha"


@pytest.fixture
def org2():
    return "org-beta"


# ---------------------------------------------------------------------------
# generate_canary_aws_key
# ---------------------------------------------------------------------------

def test_generate_canary_aws_key_prefix(engine):
    key = engine.generate_canary_aws_key()
    assert key.startswith("ALDECI")
    assert len(key) > 6


def test_generate_canary_aws_key_unique(engine):
    k1 = engine.generate_canary_aws_key()
    k2 = engine.generate_canary_aws_key()
    assert k1 != k2


# ---------------------------------------------------------------------------
# generate_canary_db_url
# ---------------------------------------------------------------------------

def test_generate_canary_db_url_format(engine):
    url = engine.generate_canary_db_url()
    assert url.startswith("postgresql://aldeci_canary:")
    assert "canary_db" in url
    assert "aldeci-canary-db-" in url


# ---------------------------------------------------------------------------
# create_canary
# ---------------------------------------------------------------------------

def test_create_canary_api_key(engine, org):
    token = engine.create_canary(CanaryType.api_key, "Test API canary", org)
    assert token.id is not None
    assert token.type == CanaryType.api_key
    assert token.org_id == org
    assert token.active is True
    assert "ALDECI_CANARY_KEY_" in token.token_value


def test_create_canary_aws_credential(engine, org):
    token = engine.create_canary(CanaryType.aws_credential, "Fake AWS key", org)
    assert token.type == CanaryType.aws_credential
    assert token.token_value.startswith("ALDECI")


def test_create_canary_database_url(engine, org):
    token = engine.create_canary(CanaryType.database_url, "Fake DB URL", org)
    assert token.type == CanaryType.database_url
    assert "postgresql://" in token.token_value


def test_create_canary_file(engine, org):
    token = engine.create_canary(CanaryType.file, "Fake file", org)
    assert "ALDECI_CANARY_FILE_" in token.token_value


def test_create_canary_endpoint(engine, org):
    token = engine.create_canary(CanaryType.endpoint, "Honeypot endpoint", org)
    assert "/api/v1/aldeci-canary-" in token.token_value


def test_create_canary_dns_subdomain(engine, org):
    token = engine.create_canary(CanaryType.dns_subdomain, "DNS canary", org)
    assert "aldeci-canary-" in token.token_value
    assert ".internal.example.com" in token.token_value


def test_create_canary_oauth_token(engine, org):
    token = engine.create_canary(CanaryType.oauth_token, "OAuth canary", org)
    assert "ALDECI_CANARY_TOKEN_" in token.token_value


# ---------------------------------------------------------------------------
# list_canaries
# ---------------------------------------------------------------------------

def test_list_canaries_empty(engine, org):
    assert engine.list_canaries(org) == []


def test_list_canaries_returns_own_org(engine, org, org2):
    engine.create_canary(CanaryType.api_key, "A", org)
    engine.create_canary(CanaryType.api_key, "B", org2)
    result = engine.list_canaries(org)
    assert len(result) == 1
    assert result[0].org_id == org


def test_list_canaries_multiple(engine, org):
    engine.create_canary(CanaryType.api_key, "A", org)
    engine.create_canary(CanaryType.aws_credential, "B", org)
    result = engine.list_canaries(org)
    assert len(result) == 2


# ---------------------------------------------------------------------------
# check_canary (trigger alert)
# ---------------------------------------------------------------------------

def test_check_canary_no_match_returns_none(engine, org):
    alert = engine.check_canary("not-a-real-token", "10.1.2.3")
    assert alert is None


def test_check_canary_match_returns_alert(engine, org):
    token = engine.create_canary(CanaryType.api_key, "Triggered canary", org)
    alert = engine.check_canary(token.token_value, "1.2.3.4")
    assert alert is not None
    assert alert.canary_id == token.id
    assert alert.source_ip == "1.2.3.4"
    assert alert.severity == "critical"
    assert alert.org_id == org


def test_check_canary_increments_alert_count(engine, org):
    token = engine.create_canary(CanaryType.api_key, "Counter test", org)
    engine.check_canary(token.token_value, "5.5.5.5")
    engine.check_canary(token.token_value, "6.6.6.6")
    canaries = engine.list_canaries(org)
    assert canaries[0].alert_count == 2


def test_check_canary_with_context(engine, org):
    token = engine.create_canary(CanaryType.api_key, "Context test", org)
    alert = engine.check_canary(
        token.token_value,
        "9.9.9.9",
        context={"user_agent": "Mozilla/5.0", "headers": {"X-Forwarded-For": "1.1.1.1"}},
    )
    assert alert is not None
    assert alert.user_agent == "Mozilla/5.0"
    assert alert.request_headers.get("X-Forwarded-For") == "1.1.1.1"


# ---------------------------------------------------------------------------
# deactivate_canary
# ---------------------------------------------------------------------------

def test_deactivate_canary_success(engine, org):
    token = engine.create_canary(CanaryType.api_key, "To deactivate", org)
    result = engine.deactivate_canary(token.id, org)
    assert result is True
    # Deactivated canary should not fire
    alert = engine.check_canary(token.token_value, "1.2.3.4")
    assert alert is None


def test_deactivate_canary_wrong_org_returns_false(engine, org, org2):
    token = engine.create_canary(CanaryType.api_key, "Isolation test", org)
    result = engine.deactivate_canary(token.id, org2)
    assert result is False


def test_deactivate_canary_not_found_returns_false(engine, org):
    result = engine.deactivate_canary("nonexistent-id", org)
    assert result is False


# ---------------------------------------------------------------------------
# get_alerts
# ---------------------------------------------------------------------------

def test_get_alerts_empty(engine, org):
    assert engine.get_alerts(org) == []


def test_get_alerts_returns_recent(engine, org):
    token = engine.create_canary(CanaryType.api_key, "Alert test", org)
    engine.check_canary(token.token_value, "2.2.2.2")
    alerts = engine.get_alerts(org, hours=24)
    assert len(alerts) == 1
    assert alerts[0].source_ip == "2.2.2.2"


def test_get_alerts_org_isolation(engine, org, org2):
    t1 = engine.create_canary(CanaryType.api_key, "Org1 canary", org)
    t2 = engine.create_canary(CanaryType.api_key, "Org2 canary", org2)
    engine.check_canary(t1.token_value, "3.3.3.3")
    engine.check_canary(t2.token_value, "4.4.4.4")
    assert len(engine.get_alerts(org)) == 1
    assert len(engine.get_alerts(org2)) == 1


# ---------------------------------------------------------------------------
# deploy_honeypot_endpoint
# ---------------------------------------------------------------------------

def test_deploy_honeypot_endpoint_returns_info(engine, org):
    result = engine.deploy_honeypot_endpoint("/api/v1/admin/users", org)
    assert result["id"] is not None
    assert result["path"] == "/api/v1/admin/users"
    assert result["org_id"] == org


def test_deploy_honeypot_endpoint_multiple(engine, org):
    engine.deploy_honeypot_endpoint("/api/v1/secret", org)
    engine.deploy_honeypot_endpoint("/api/v2/hidden", org)
    # Stats should reflect both
    stats = engine.get_stats(org)
    assert stats["honeypot_endpoints"] == 2


# ---------------------------------------------------------------------------
# get_stats
# ---------------------------------------------------------------------------

def test_get_stats_empty(engine, org):
    stats = engine.get_stats(org)
    assert stats["org_id"] == org
    assert stats["total_canaries"] == 0
    assert stats["active_canaries"] == 0
    assert stats["total_alerts"] == 0
    assert stats["alerts_last_24h"] == 0
    assert stats["honeypot_endpoints"] == 0
    assert stats["canaries_by_type"] == {}


def test_get_stats_populated(engine, org):
    token = engine.create_canary(CanaryType.api_key, "Stats test", org)
    engine.create_canary(CanaryType.aws_credential, "Stats test 2", org)
    engine.check_canary(token.token_value, "7.7.7.7")
    engine.deploy_honeypot_endpoint("/trap", org)
    stats = engine.get_stats(org)
    assert stats["total_canaries"] == 2
    assert stats["active_canaries"] == 2
    assert stats["total_alerts"] == 1
    assert stats["alerts_last_24h"] == 1
    assert stats["honeypot_endpoints"] == 1
    assert "api_key" in stats["canaries_by_type"]
    assert "aws_credential" in stats["canaries_by_type"]


def test_get_stats_org_isolation(engine, org, org2):
    engine.create_canary(CanaryType.api_key, "Org1 canary", org)
    engine.create_canary(CanaryType.api_key, "Org2 canary", org2)
    s1 = engine.get_stats(org)
    s2 = engine.get_stats(org2)
    assert s1["total_canaries"] == 1
    assert s2["total_canaries"] == 1


def test_get_stats_deactivated_not_counted_as_active(engine, org):
    token = engine.create_canary(CanaryType.api_key, "Deactivation stats", org)
    engine.deactivate_canary(token.id, org)
    stats = engine.get_stats(org)
    assert stats["total_canaries"] == 1
    assert stats["active_canaries"] == 0
