"""Tests for auth_bootstrap — env file generation and crypto helpers."""

from core.auth_bootstrap import (
    _generate_jwt_secret,
    _generate_example_env,
    DEFAULT_ORIGINS,
)


class TestGenerateJWTSecret:
    def test_default_length(self):
        secret = _generate_jwt_secret()
        assert len(secret) == 64  # 64 hex chars = 32 bytes

    def test_custom_length(self):
        secret = _generate_jwt_secret(length=32)
        assert len(secret) == 32

    def test_uniqueness(self):
        s1 = _generate_jwt_secret()
        s2 = _generate_jwt_secret()
        assert s1 != s2

    def test_hex_format(self):
        secret = _generate_jwt_secret()
        # Should be valid hex
        int(secret, 16)


class TestGenerateExampleEnv:
    def test_basic_generation(self):
        content = _generate_example_env(
            api_token="test_sk_abc123",
            jwt_secret="deadbeef" * 8,
        )
        assert "FIXOPS_API_TOKEN=test_sk_abc123" in content
        assert "FIXOPS_JWT_SECRET=" in content
        assert "FIXOPS_MODE=enterprise" in content

    def test_custom_origins(self):
        content = _generate_example_env(
            api_token="tok",
            jwt_secret="sec",
            allowed_origins="https://custom.example.com",
        )
        assert "https://custom.example.com" in content

    def test_custom_org_id(self):
        content = _generate_example_env(
            api_token="tok",
            jwt_secret="sec",
            org_id="acme-corp",
        )
        assert "FIXOPS_ORG_ID=acme-corp" in content

    def test_custom_db_params(self):
        content = _generate_example_env(
            api_token="tok",
            jwt_secret="sec",
            db_host="prod-db.internal",
            db_port=5433,
            db_name="fixops_production",
            db_user="admin",
            db_password="secure-pw",
        )
        assert "prod-db.internal" in content
        assert "5433" in content
        assert "fixops_production" in content

    def test_contains_all_sections(self):
        content = _generate_example_env(
            api_token="tok",
            jwt_secret="sec",
        )
        assert "Authentication" in content
        assert "Database" in content
        assert "Rate Limiting" in content
        assert "LLM / AI Providers" in content
        assert "Integrations" in content
        assert "Feature Flags" in content
        assert "Observability" in content

    def test_contains_security_warnings(self):
        content = _generate_example_env(
            api_token="tok",
            jwt_secret="sec",
        )
        assert "rotate before use" in content.lower()
        assert "Do NOT commit" in content

    def test_default_origins_constant(self):
        assert DEFAULT_ORIGINS == "https://app.aldeci.com"

    def test_jira_integration_section(self):
        content = _generate_example_env(
            api_token="tok",
            jwt_secret="sec",
        )
        assert "JIRA_URL" in content
        assert "JIRA_API_TOKEN" in content

    def test_slack_integration_section(self):
        content = _generate_example_env(
            api_token="tok",
            jwt_secret="sec",
        )
        assert "SLACK_BOT_TOKEN" in content

    def test_github_integration_section(self):
        content = _generate_example_env(
            api_token="tok",
            jwt_secret="sec",
        )
        assert "GITHUB_TOKEN" in content

    def test_feature_flags_section(self):
        content = _generate_example_env(
            api_token="tok",
            jwt_secret="sec",
        )
        assert "FIXOPS_ENABLE_GNN" in content
        assert "FIXOPS_ENABLE_CVE_FEED" in content
        assert "FIXOPS_ENABLE_MCP" in content
