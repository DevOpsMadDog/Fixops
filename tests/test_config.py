"""
Tests for suite-core/core/config.py — ALdeci centralized configuration module.

Covers:
- Default value loading (no env vars set)
- Environment variable overrides
- Validator behaviour (mode, queue_mode, consensus_threshold)
- Singleton get_config() and _reset_config()
- Convenience helpers (is_production, has_llm, has_smtp, has_slack, cloud_providers_configured)

Run with:
    python -m pytest tests/test_config.py -v --timeout=10
"""

import os
import sys
from pathlib import Path

import pytest

# Ensure suite-core is importable
_suite_core = str(Path(__file__).parent.parent / "suite-core")
if _suite_core not in sys.path:
    sys.path.insert(0, _suite_core)

from core.config import ALDECIConfig, _reset_config, get_config


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_config(**env_overrides) -> ALDECIConfig:
    """Instantiate a fresh ALDECIConfig with specific env vars set, without
    touching the global singleton."""
    # Snapshot relevant env vars, apply overrides, construct, restore.
    # We clear FIXOPS_*/AWS_*/AZURE_*/AZURE_*/GCP_* so tests are hermetic.
    _CLEAR_PREFIXES = (
        "FIXOPS_", "ALDECI_", "OPENAI_API_KEY", "ANTHROPIC_API_KEY",
        "OPENROUTER_API_KEY", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
        "AWS_DEFAULT_REGION", "AZURE_TENANT_ID", "AZURE_CLIENT_ID",
        "AZURE_CLIENT_SECRET", "AZURE_SUBSCRIPTION_ID", "GCP_PROJECT_ID",
        "GOOGLE_APPLICATION_CREDENTIALS",
    )
    saved: dict = {}
    # Save and clear env vars that would bleed in from the shell
    for k in list(os.environ.keys()):
        if any(k == p or k.startswith(p) for p in _CLEAR_PREFIXES):
            saved[k] = os.environ.pop(k)
    # Apply requested overrides
    for k, v in env_overrides.items():
        os.environ[k] = str(v)
    try:
        return ALDECIConfig.from_env()
    finally:
        # Remove overrides
        for k in env_overrides:
            os.environ.pop(k, None)
        # Restore original env
        for k, v in saved.items():
            os.environ[k] = v


# ---------------------------------------------------------------------------
# Default values
# ---------------------------------------------------------------------------


class TestDefaults:
    def test_api_port_default(self):
        cfg = _make_config()
        assert cfg.api_port == 8000

    def test_api_host_default(self):
        cfg = _make_config()
        assert cfg.api_host == "0.0.0.0"

    def test_api_workers_default(self):
        cfg = _make_config()
        assert cfg.api_workers == 1

    def test_api_mode_default(self):
        cfg = _make_config()
        assert cfg.api_mode == "enterprise"

    def test_disable_rate_limit_default_false(self):
        cfg = _make_config()
        assert cfg.disable_rate_limit is False

    def test_data_dir_default(self):
        cfg = _make_config()
        assert cfg.data_dir == ".fixops_data"

    def test_queue_mode_default(self):
        cfg = _make_config()
        assert cfg.queue_mode == "local"

    def test_use_council_default_false(self):
        cfg = _make_config()
        assert cfg.use_council is False

    def test_consensus_threshold_default(self):
        cfg = _make_config()
        assert cfg.consensus_threshold == 0.6

    def test_feeds_refresh_interval_default(self):
        cfg = _make_config()
        assert cfg.feeds_refresh_interval == 3600

    def test_feeds_stale_threshold_default(self):
        cfg = _make_config()
        assert cfg.feeds_stale_threshold == 86400

    def test_smtp_port_default(self):
        cfg = _make_config()
        assert cfg.smtp_port == 587

    def test_smtp_tls_default_true(self):
        cfg = _make_config()
        assert cfg.smtp_tls is True

    def test_jwt_exp_minutes_default(self):
        cfg = _make_config()
        assert cfg.jwt_exp_minutes == 30

    def test_jwt_expire_hours_default(self):
        cfg = _make_config()
        assert cfg.jwt_expire_hours == 2

    def test_jwt_refresh_days_default(self):
        cfg = _make_config()
        assert cfg.jwt_refresh_days == 7

    def test_max_findings_default(self):
        cfg = _make_config()
        assert cfg.max_findings == 100_000

    def test_max_scans_default(self):
        cfg = _make_config()
        assert cfg.max_scans_per_day == 1_000

    def test_max_mpte_default(self):
        cfg = _make_config()
        assert cfg.max_concurrent_mpte == 10

    def test_retention_days_default(self):
        cfg = _make_config()
        assert cfg.retention_days == 365

    def test_aws_region_default(self):
        cfg = _make_config()
        assert cfg.aws_region == "us-east-1"

    def test_github_base_branch_default(self):
        cfg = _make_config()
        assert cfg.github_base_branch == "main"

    def test_default_org_default(self):
        cfg = _make_config()
        assert cfg.default_org == "default"

    def test_feature_trustgraph_default_true(self):
        cfg = _make_config()
        assert cfg.feature_trustgraph is True

    def test_feature_autofix_default_false(self):
        cfg = _make_config()
        assert cfg.feature_autofix is False

    def test_feature_cspm_default_true(self):
        cfg = _make_config()
        assert cfg.feature_cspm is True

    def test_feature_feeds_default_true(self):
        cfg = _make_config()
        assert cfg.feature_feeds is True


# ---------------------------------------------------------------------------
# Environment variable overrides
# ---------------------------------------------------------------------------


class TestEnvOverrides:
    def test_api_port_override(self):
        cfg = _make_config(ALDECI_PORT="9000")
        assert cfg.api_port == 9000

    def test_api_mode_override(self):
        cfg = _make_config(FIXOPS_MODE="demo")
        assert cfg.api_mode == "demo"

    def test_api_token_override(self):
        cfg = _make_config(FIXOPS_API_TOKEN="my-secret-token")
        assert cfg.api_token == "my-secret-token"

    def test_jwt_secret_override(self):
        cfg = _make_config(FIXOPS_JWT_SECRET="supersecret32charslong1234567890")
        assert cfg.jwt_secret == "supersecret32charslong1234567890"

    def test_data_dir_override(self):
        cfg = _make_config(FIXOPS_DATA_DIR="/data/aldeci")
        assert cfg.data_dir == "/data/aldeci"

    def test_queue_mode_redis(self):
        cfg = _make_config(FIXOPS_QUEUE_MODE="redis")
        assert cfg.queue_mode == "redis"

    def test_redis_url_override(self):
        cfg = _make_config(FIXOPS_REDIS_URL="redis://myhost:6380/1")
        assert cfg.redis_url == "redis://myhost:6380/1"

    def test_use_council_true(self):
        cfg = _make_config(FIXOPS_USE_COUNCIL="1")
        assert cfg.use_council is True

    def test_consensus_threshold_override(self):
        cfg = _make_config(FIXOPS_CONSENSUS_THRESHOLD="0.75")
        assert cfg.consensus_threshold == 0.75

    def test_openai_key_override(self):
        cfg = _make_config(OPENAI_API_KEY="sk-test123")
        assert cfg.openai_key == "sk-test123"

    def test_anthropic_key_override(self):
        cfg = _make_config(ANTHROPIC_API_KEY="sk-ant-test")
        assert cfg.anthropic_key == "sk-ant-test"

    def test_openrouter_key_override(self):
        cfg = _make_config(OPENROUTER_API_KEY="sk-or-test")
        assert cfg.openrouter_key == "sk-or-test"

    def test_ollama_url_override(self):
        cfg = _make_config(FIXOPS_OLLAMA_URL="http://ollama:11434")
        assert cfg.ollama_url == "http://ollama:11434"

    def test_smtp_host_override(self):
        cfg = _make_config(FIXOPS_SMTP_HOST="smtp.example.com")
        assert cfg.smtp_host == "smtp.example.com"

    def test_smtp_password_override(self):
        cfg = _make_config(FIXOPS_SMTP_PASSWORD="secret123")
        assert cfg.smtp_password == "secret123"

    def test_slack_webhook_override(self):
        cfg = _make_config(FIXOPS_SLACK_WEBHOOK_URL="https://hooks.slack.com/test")
        assert cfg.slack_webhook_url == "https://hooks.slack.com/test"

    def test_jira_url_override(self):
        cfg = _make_config(FIXOPS_JIRA_URL="https://myorg.atlassian.net")
        assert cfg.jira_url == "https://myorg.atlassian.net"

    def test_github_token_override(self):
        cfg = _make_config(FIXOPS_GITHUB_TOKEN="ghp_abc123")
        assert cfg.github_token == "ghp_abc123"

    def test_disable_rate_limit_override(self):
        cfg = _make_config(FIXOPS_DISABLE_RATE_LIMIT="1")
        assert cfg.disable_rate_limit is True

    def test_aws_access_key_override(self):
        cfg = _make_config(AWS_ACCESS_KEY_ID="AKIATEST", AWS_SECRET_ACCESS_KEY="secretkey")
        assert cfg.aws_access_key_id == "AKIATEST"
        assert cfg.aws_secret_access_key == "secretkey"

    def test_azure_tenant_override(self):
        cfg = _make_config(AZURE_TENANT_ID="tenant-uuid")
        assert cfg.azure_tenant_id == "tenant-uuid"

    def test_gcp_project_override(self):
        cfg = _make_config(GCP_PROJECT_ID="my-gcp-project")
        assert cfg.gcp_project_id == "my-gcp-project"

    def test_snyk_token_override(self):
        cfg = _make_config(FIXOPS_SNYK_TOKEN="snyk-token-123")
        assert cfg.snyk_token == "snyk-token-123"

    def test_feature_autofix_enabled(self):
        cfg = _make_config(FIXOPS_FEATURE_AUTOFIX="true")
        assert cfg.feature_autofix is True

    def test_feature_trustgraph_disabled(self):
        cfg = _make_config(FIXOPS_FEATURE_TRUSTGRAPH="false")
        assert cfg.feature_trustgraph is False

    def test_version_override(self):
        cfg = _make_config(FIXOPS_VERSION="2.0.0")
        assert cfg.version == "2.0.0"

    def test_max_findings_override(self):
        cfg = _make_config(FIXOPS_MAX_FINDINGS="500000")
        assert cfg.max_findings == 500_000


# ---------------------------------------------------------------------------
# Validator edge cases
# ---------------------------------------------------------------------------


class TestValidators:
    def test_invalid_mode_raises(self):
        with pytest.raises(Exception):
            _make_config(FIXOPS_MODE="unknown-mode")

    def test_valid_modes_accepted(self):
        for mode in ("enterprise", "demo", "development", "test"):
            cfg = _make_config(FIXOPS_MODE=mode)
            assert cfg.api_mode == mode

    def test_invalid_queue_mode_raises(self):
        with pytest.raises(Exception):
            _make_config(FIXOPS_QUEUE_MODE="kafka")

    def test_consensus_threshold_zero_raises(self):
        with pytest.raises(Exception):
            _make_config(FIXOPS_CONSENSUS_THRESHOLD="0.0")

    def test_consensus_threshold_above_one_raises(self):
        with pytest.raises(Exception):
            _make_config(FIXOPS_CONSENSUS_THRESHOLD="1.1")

    def test_consensus_threshold_one_accepted(self):
        cfg = _make_config(FIXOPS_CONSENSUS_THRESHOLD="1.0")
        assert cfg.consensus_threshold == 1.0

    def test_consensus_threshold_small_valid(self):
        cfg = _make_config(FIXOPS_CONSENSUS_THRESHOLD="0.1")
        assert cfg.consensus_threshold == 0.1


# ---------------------------------------------------------------------------
# Convenience helpers
# ---------------------------------------------------------------------------


class TestHelpers:
    def test_is_production_with_token(self):
        cfg = _make_config(FIXOPS_MODE="enterprise", FIXOPS_API_TOKEN="real-token")
        assert cfg.is_production() is True

    def test_is_production_enterprise_no_token(self):
        cfg = _make_config(FIXOPS_MODE="enterprise", FIXOPS_API_TOKEN="")
        assert cfg.is_production() is False

    def test_is_production_demo_mode(self):
        cfg = _make_config(FIXOPS_MODE="demo", FIXOPS_API_TOKEN="some-token")
        assert cfg.is_production() is False

    def test_has_llm_openai(self):
        cfg = _make_config(OPENAI_API_KEY="sk-test")
        assert cfg.has_llm() is True

    def test_has_llm_anthropic(self):
        cfg = _make_config(ANTHROPIC_API_KEY="sk-ant-test")
        assert cfg.has_llm() is True

    def test_has_llm_ollama(self):
        cfg = _make_config(FIXOPS_OLLAMA_URL="http://localhost:11434")
        assert cfg.has_llm() is True

    def test_has_llm_false_when_no_keys(self):
        cfg = _make_config()
        assert cfg.has_llm() is False

    def test_has_smtp_true(self):
        cfg = _make_config(
            FIXOPS_SMTP_HOST="smtp.example.com",
            FIXOPS_SMTP_USER="user@example.com",
            FIXOPS_SMTP_PASSWORD="pass",
        )
        assert cfg.has_smtp() is True

    def test_has_smtp_missing_password(self):
        cfg = _make_config(
            FIXOPS_SMTP_HOST="smtp.example.com",
            FIXOPS_SMTP_USER="user@example.com",
        )
        assert cfg.has_smtp() is False

    def test_has_smtp_false_when_empty(self):
        cfg = _make_config()
        assert cfg.has_smtp() is False

    def test_has_slack_via_webhook(self):
        cfg = _make_config(FIXOPS_SLACK_WEBHOOK_URL="https://hooks.slack.com/test")
        assert cfg.has_slack() is True

    def test_has_slack_via_token(self):
        cfg = _make_config(FIXOPS_SLACK_TOKEN="xoxb-test")
        assert cfg.has_slack() is True

    def test_has_slack_false_when_empty(self):
        cfg = _make_config()
        assert cfg.has_slack() is False

    def test_cloud_providers_aws(self):
        cfg = _make_config(AWS_ACCESS_KEY_ID="AKIA", AWS_SECRET_ACCESS_KEY="secret")
        assert "aws" in cfg.cloud_providers_configured()

    def test_cloud_providers_azure(self):
        cfg = _make_config(
            AZURE_TENANT_ID="tid",
            AZURE_CLIENT_ID="cid",
            AZURE_CLIENT_SECRET="csec",
        )
        assert "azure" in cfg.cloud_providers_configured()

    def test_cloud_providers_gcp_json(self):
        cfg = _make_config(
            GCP_PROJECT_ID="my-project",
            GOOGLE_APPLICATION_CREDENTIALS_JSON='{"type":"service_account"}',
        )
        assert "gcp" in cfg.cloud_providers_configured()

    def test_cloud_providers_empty_when_no_creds(self):
        cfg = _make_config()
        assert cfg.cloud_providers_configured() == []

    def test_cloud_providers_multiple(self):
        cfg = _make_config(
            AWS_ACCESS_KEY_ID="AKIA",
            AWS_SECRET_ACCESS_KEY="secret",
            AZURE_TENANT_ID="tid",
            AZURE_CLIENT_ID="cid",
            AZURE_CLIENT_SECRET="csec",
        )
        providers = cfg.cloud_providers_configured()
        assert "aws" in providers
        assert "azure" in providers


# ---------------------------------------------------------------------------
# Singleton behaviour
# ---------------------------------------------------------------------------


class TestSingleton:
    def setup_method(self):
        _reset_config()

    def teardown_method(self):
        _reset_config()

    def test_get_config_returns_instance(self):
        cfg = get_config()
        assert isinstance(cfg, ALDECIConfig)

    def test_get_config_same_object_on_repeat_calls(self):
        cfg1 = get_config()
        cfg2 = get_config()
        assert cfg1 is cfg2

    def test_reset_clears_singleton(self):
        cfg1 = get_config()
        _reset_config()
        cfg2 = get_config()
        # After reset a new object is created
        assert cfg1 is not cfg2

    def test_get_config_thread_safety(self):
        """Multiple threads calling get_config() should all receive the same instance."""
        import threading

        results = []

        def fetch():
            results.append(get_config())

        threads = [threading.Thread(target=fetch) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(results) == 10
        first = results[0]
        for r in results[1:]:
            assert r is first
