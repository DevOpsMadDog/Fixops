"""
config.py — ALdeci Centralized Configuration Module
ALDECI Security Platform

Single source of truth for all environment-variable-driven configuration.
Replaces scattered os.getenv() calls across the codebase with a validated,
type-safe Pydantic model.

Usage:
    from core.config import get_config
    cfg = get_config()
    print(cfg.api_port, cfg.api_token)
"""

from __future__ import annotations

import os
import threading
from typing import List, Optional

from pydantic import BaseModel, Field, field_validator


def _env(key: str, default: str = "") -> str:
    """Read a string env var, stripping whitespace."""
    return os.environ.get(key, default).strip()


def _env_int(key: str, default: int) -> int:
    raw = os.environ.get(key, "").strip()
    if raw:
        try:
            return int(raw)
        except ValueError:
            pass
    return default


def _env_float(key: str, default: float) -> float:
    raw = os.environ.get(key, "").strip()
    if raw:
        try:
            return float(raw)
        except ValueError:
            pass
    return default


def _env_bool(key: str, default: bool) -> bool:
    raw = os.environ.get(key, "").strip().lower()
    if raw in ("1", "true", "yes", "on"):
        return True
    if raw in ("0", "false", "no", "off"):
        return False
    return default


class ALDECIConfig(BaseModel):
    """Centralized configuration for the ALDECI platform.

    All values are read from environment variables. Defaults are chosen to be
    safe for local development; production deployments must override critical
    values via environment or a .env file loaded before import.
    """

    # -------------------------------------------------------------------------
    # API — server runtime
    # -------------------------------------------------------------------------
    api_port: int = Field(description="API server port")
    api_host: str = Field(description="API bind host")
    api_workers: int = Field(description="Uvicorn worker count")
    api_mode: str = Field(description="Platform mode (enterprise|demo|development|test)")
    disable_rate_limit: bool = Field(description="Disable API rate limiting (CI/tests)")
    detailed_logging: bool = Field(description="Enable verbose request logging")
    allowed_origins: str = Field(description="Comma-separated CORS allowed origins")
    fail_fast: bool = Field(description="Exit on startup errors instead of continuing")
    version: str = Field(description="Platform version string")
    build_date: str = Field(description="Build date (injected by CI)")
    git_commit: str = Field(description="Git commit SHA (injected by CI)")

    # -------------------------------------------------------------------------
    # Auth
    # -------------------------------------------------------------------------
    api_token: str = Field(description="X-API-Key bearer token for API auth")
    jwt_secret: str = Field(description="HMAC-SHA256 secret for JWT signing (>=32 chars in production)")
    jwt_exp_minutes: int = Field(description="JWT access token expiry in minutes")
    jwt_expire_hours: int = Field(description="JWT access token expiry in hours (users_router compat)")
    jwt_refresh_days: int = Field(description="JWT refresh token expiry in days")
    sso_enabled: bool = Field(description="Enable SSO/OIDC authentication")
    sso_provider: str = Field(description="SSO provider name (okta|azure|google)")
    oidc_client_id: str = Field(description="OIDC client ID")
    oidc_client_secret: str = Field(description="OIDC client secret")
    oidc_issuer_url: str = Field(description="OIDC issuer discovery URL")

    # -------------------------------------------------------------------------
    # Database / storage
    # -------------------------------------------------------------------------
    data_dir: str = Field(description="Root directory for all SQLite databases and state files")
    db_path: str = Field(description="Override path for the primary app-config SQLite DB")
    sqlite_wal_mode: bool = Field(description="Enable WAL journal mode on all SQLite connections")
    reports_dir: str = Field(description="Directory for generated reports")
    retention_days: int = Field(description="Default finding retention in days")

    # -------------------------------------------------------------------------
    # Queue
    # -------------------------------------------------------------------------
    queue_mode: str = Field(description="Task queue backend (local|redis)")
    redis_url: str = Field(description="Redis connection URL for queue mode=redis")

    # -------------------------------------------------------------------------
    # LLM / AI
    # -------------------------------------------------------------------------
    openai_key: str = Field(description="OpenAI API key")
    anthropic_key: str = Field(description="Anthropic API key")
    openrouter_key: str = Field(description="OpenRouter API key (free models)")
    mulerouter_key: str = Field(default="", description="MuleRouter API key (Qwen3-6b-Max, primary free council model)")
    use_council: bool = Field(description="Enable Karpathy LLM Council for decisions")
    consensus_threshold: float = Field(description="Minimum council vote fraction to reach consensus")
    ollama_url: str = Field(description="Ollama local inference base URL")
    vllm_url: str = Field(description="vLLM self-hosted inference base URL")

    # -------------------------------------------------------------------------
    # Threat intel feeds
    # -------------------------------------------------------------------------
    feeds_refresh_interval: int = Field(description="Feed refresh interval in seconds")
    feeds_stale_threshold: int = Field(description="Age in seconds before a feed is considered stale")

    # -------------------------------------------------------------------------
    # Notifications — SMTP
    # -------------------------------------------------------------------------
    smtp_host: str = Field(description="SMTP server hostname")
    smtp_port: int = Field(description="SMTP server port")
    smtp_user: str = Field(description="SMTP username")
    smtp_password: str = Field(description="SMTP password")
    smtp_from: str = Field(description="SMTP sender address")
    smtp_tls: bool = Field(description="Use STARTTLS for SMTP")

    # -------------------------------------------------------------------------
    # Notifications — Slack
    # -------------------------------------------------------------------------
    slack_token: str = Field(description="Slack Bot OAuth token")
    slack_webhook_url: str = Field(description="Slack incoming webhook URL")

    # -------------------------------------------------------------------------
    # CSPM — Cloud credentials
    # -------------------------------------------------------------------------
    aws_access_key_id: str = Field(description="AWS access key ID")
    aws_secret_access_key: str = Field(description="AWS secret access key")
    aws_region: str = Field(description="Default AWS region")
    aws_role_arn: str = Field(description="AWS IAM role ARN for cross-account scanning")

    azure_tenant_id: str = Field(description="Azure AD tenant ID")
    azure_client_id: str = Field(description="Azure service principal client ID")
    azure_client_secret: str = Field(description="Azure service principal secret")
    azure_subscription_id: str = Field(description="Azure subscription ID for CSPM scanning")

    gcp_project_id: str = Field(description="GCP project ID")
    google_credentials_json: str = Field(description="GCP service account credentials JSON (inline)")
    google_credentials_file: str = Field(description="Path to GCP service account credentials file")

    # -------------------------------------------------------------------------
    # External integrations
    # -------------------------------------------------------------------------
    jira_url: str = Field(description="Jira base URL")
    jira_user: str = Field(description="Jira username or email")
    jira_token: str = Field(description="Jira API token")
    jira_project: str = Field(description="Default Jira project key for ticket creation")
    jira_findings_jql: str = Field(description="JQL filter for syncing Jira findings")

    github_token: str = Field(description="GitHub personal access token")
    github_owner: str = Field(description="GitHub organisation or user name")
    github_repo: str = Field(description="GitHub repository name")
    github_base_branch: str = Field(description="Default base branch for PR/diff operations")

    snyk_token: str = Field(description="Snyk API token")
    snyk_org_id: str = Field(description="Snyk organisation ID")

    sonarqube_url: str = Field(description="SonarQube base URL")
    sonarqube_token: str = Field(description="SonarQube authentication token")

    opa_url: str = Field(description="Open Policy Agent base URL for policy evaluation")
    default_org: str = Field(description="Default organisation ID for single-tenant deployments")

    # -------------------------------------------------------------------------
    # Limits / capacity
    # -------------------------------------------------------------------------
    max_findings: int = Field(description="Maximum findings stored per scan")
    max_scans_per_day: int = Field(description="Daily scan count limit")
    max_concurrent_mpte: int = Field(description="Max concurrent manual pentest evidence jobs")

    # -------------------------------------------------------------------------
    # Feature flags
    # -------------------------------------------------------------------------
    feature_trustgraph: bool = Field(description="Enable TrustGraph GraphRAG integration")
    feature_autofix: bool = Field(description="Enable automated remediation (autofix engine)")
    feature_attack_sim: bool = Field(description="Enable attack simulation module (MPTE)")
    feature_cspm: bool = Field(description="Enable CSPM cloud posture scanning")
    feature_feeds: bool = Field(description="Enable threat intelligence feed ingestion")
    feature_council: bool = Field(description="Feature flag alias for use_council")
    disable_telemetry: bool = Field(description="Disable anonymous telemetry / usage metrics")

    # -------------------------------------------------------------------------
    # Validators
    # -------------------------------------------------------------------------

    @field_validator("api_mode")
    @classmethod
    def validate_mode(cls, v: str) -> str:
        allowed = {"enterprise", "demo", "development", "test"}
        v = v.strip().lower()
        if v not in allowed:
            raise ValueError(f"FIXOPS_MODE must be one of {allowed}, got '{v}'")
        return v

    @field_validator("queue_mode")
    @classmethod
    def validate_queue_mode(cls, v: str) -> str:
        allowed = {"local", "redis"}
        v = v.strip().lower()
        if v not in allowed:
            raise ValueError(f"FIXOPS_QUEUE_MODE must be one of {allowed}, got '{v}'")
        return v

    @field_validator("consensus_threshold")
    @classmethod
    def validate_threshold(cls, v: float) -> float:
        if not (0.0 < v <= 1.0):
            raise ValueError(
                "FIXOPS_CONSENSUS_THRESHOLD must be between 0 (exclusive) and 1 (inclusive)"
            )
        return v

    # -------------------------------------------------------------------------
    # Convenience helpers
    # -------------------------------------------------------------------------

    def is_production(self) -> bool:
        """Return True when running in enterprise mode with a real API token."""
        return self.api_mode == "enterprise" and bool(self.api_token)

    def has_llm(self) -> bool:
        """Return True if at least one LLM API key or local endpoint is configured."""
        return bool(
            self.openai_key
            or self.anthropic_key
            or self.openrouter_key
            or self.mulerouter_key
            or self.ollama_url
            or self.vllm_url
        )

    def has_smtp(self) -> bool:
        """Return True if SMTP is configured for email notifications."""
        return bool(self.smtp_host and self.smtp_user and self.smtp_password)

    def has_slack(self) -> bool:
        """Return True if Slack notifications are configured."""
        return bool(self.slack_webhook_url or self.slack_token)

    def cloud_providers_configured(self) -> List[str]:
        """Return list of cloud providers that have credentials configured."""
        providers: List[str] = []
        if self.aws_access_key_id and self.aws_secret_access_key:
            providers.append("aws")
        if self.azure_tenant_id and self.azure_client_id and self.azure_client_secret:
            providers.append("azure")
        if self.gcp_project_id and (self.google_credentials_json or self.google_credentials_file):
            providers.append("gcp")
        return providers

    # -------------------------------------------------------------------------
    # Factory: read from environment
    # -------------------------------------------------------------------------

    @classmethod
    def from_env(cls) -> "ALDECIConfig":
        """Construct an ALDECIConfig by reading all values from environment variables."""
        return cls(
            # API
            api_port=_env_int("ALDECI_PORT", 8000),
            api_host=_env("FIXOPS_HOST", "0.0.0.0"),  # nosec B104 — intentional for container networking, overridable via FIXOPS_HOST env var
            api_workers=_env_int("FIXOPS_WORKERS", 1),
            api_mode=_env("FIXOPS_MODE", "enterprise"),
            disable_rate_limit=_env_bool("FIXOPS_DISABLE_RATE_LIMIT", False),
            detailed_logging=_env_bool("FIXOPS_DETAILED_LOGGING", False),
            allowed_origins=_env("FIXOPS_ALLOWED_ORIGINS", ""),
            fail_fast=_env_bool("FIXOPS_FAIL_FAST", False),
            version=_env("FIXOPS_VERSION", "0.1.0"),
            build_date=_env("FIXOPS_BUILD_DATE", "unknown"),
            git_commit=_env("FIXOPS_GIT_COMMIT", "unknown"),
            # Auth
            api_token=_env("FIXOPS_API_TOKEN", ""),
            jwt_secret=_env("FIXOPS_JWT_SECRET", ""),
            jwt_exp_minutes=_env_int("FIXOPS_JWT_EXP_MINUTES", 30),
            jwt_expire_hours=_env_int("FIXOPS_JWT_EXPIRE_HOURS", 2),
            jwt_refresh_days=_env_int("FIXOPS_JWT_REFRESH_DAYS", 7),
            sso_enabled=_env_bool("FIXOPS_SSO_ENABLED", False),
            sso_provider=_env("FIXOPS_SSO_PROVIDER", ""),
            oidc_client_id=_env("FIXOPS_OIDC_CLIENT_ID", ""),
            oidc_client_secret=_env("FIXOPS_OIDC_CLIENT_SECRET", ""),
            oidc_issuer_url=_env("FIXOPS_OIDC_ISSUER_URL", ""),
            # Database
            data_dir=_env("FIXOPS_DATA_DIR", ".fixops_data"),
            db_path=_env("FIXOPS_DB_PATH", ""),
            sqlite_wal_mode=_env_bool("FIXOPS_SQLITE_WAL", True),
            reports_dir=_env("FIXOPS_REPORTS_DIR", "/tmp/fixops_reports"),  # nosec B108
            retention_days=_env_int("FIXOPS_RETENTION_DAYS", 365),
            # Queue
            queue_mode=_env("FIXOPS_QUEUE_MODE", "local"),
            redis_url=_env("FIXOPS_REDIS_URL", "redis://localhost:6379/0"),
            # LLM
            openai_key=_env("OPENAI_API_KEY", ""),
            anthropic_key=_env("ANTHROPIC_API_KEY", ""),
            openrouter_key=_env("OPENROUTER_API_KEY", ""),
            mulerouter_key=_env("MULEROUTER_API_KEY", ""),
            use_council=_env_bool("FIXOPS_USE_COUNCIL", False),
            consensus_threshold=_env_float("FIXOPS_CONSENSUS_THRESHOLD", 0.6),
            ollama_url=_env("FIXOPS_OLLAMA_URL", ""),
            vllm_url=_env("FIXOPS_VLLM_URL", ""),
            # Feeds
            feeds_refresh_interval=_env_int("FIXOPS_FEEDS_REFRESH_INTERVAL", 3600),
            feeds_stale_threshold=_env_int("FIXOPS_FEEDS_STALE_THRESHOLD", 86400),
            # SMTP
            smtp_host=_env("FIXOPS_SMTP_HOST", ""),
            smtp_port=_env_int("FIXOPS_SMTP_PORT", 587),
            smtp_user=_env("FIXOPS_SMTP_USER", ""),
            smtp_password=_env("FIXOPS_SMTP_PASSWORD", ""),
            smtp_from=_env("FIXOPS_SMTP_FROM", "aldeci@localhost"),
            smtp_tls=_env_bool("FIXOPS_SMTP_TLS", True),
            # Slack
            slack_token=_env("FIXOPS_SLACK_TOKEN", ""),
            slack_webhook_url=_env("FIXOPS_SLACK_WEBHOOK_URL", ""),
            # AWS
            aws_access_key_id=_env("AWS_ACCESS_KEY_ID", ""),
            aws_secret_access_key=_env("AWS_SECRET_ACCESS_KEY", ""),
            aws_region=_env("AWS_DEFAULT_REGION", "us-east-1"),
            aws_role_arn=_env("FIXOPS_AWS_ROLE_ARN", ""),
            # Azure
            azure_tenant_id=_env("AZURE_TENANT_ID", ""),
            azure_client_id=_env("AZURE_CLIENT_ID", ""),
            azure_client_secret=_env("AZURE_CLIENT_SECRET", ""),
            azure_subscription_id=_env("AZURE_SUBSCRIPTION_ID", ""),
            # GCP
            gcp_project_id=_env("GCP_PROJECT_ID", ""),
            google_credentials_json=_env("GOOGLE_APPLICATION_CREDENTIALS_JSON", ""),
            google_credentials_file=_env("GOOGLE_APPLICATION_CREDENTIALS", ""),
            # Integrations
            jira_url=_env("FIXOPS_JIRA_URL", ""),
            jira_user=_env("FIXOPS_JIRA_USER", ""),
            jira_token=_env("FIXOPS_JIRA_TOKEN", ""),
            jira_project=_env("FIXOPS_JIRA_PROJECT", ""),
            jira_findings_jql=_env("FIXOPS_JIRA_FINDINGS_JQL", ""),
            github_token=_env("FIXOPS_GITHUB_TOKEN", ""),
            github_owner=_env("FIXOPS_GITHUB_OWNER", ""),
            github_repo=_env("FIXOPS_GITHUB_REPO", ""),
            github_base_branch=_env("FIXOPS_GITHUB_BASE_BRANCH", "main"),
            snyk_token=_env("FIXOPS_SNYK_TOKEN", ""),
            snyk_org_id=_env("FIXOPS_SNYK_ORG_ID", ""),
            sonarqube_url=_env("FIXOPS_SONARQUBE_URL", ""),
            sonarqube_token=_env("FIXOPS_SONARQUBE_TOKEN", ""),
            opa_url=_env("FIXOPS_OPA_URL", ""),
            default_org=_env("FIXOPS_DEFAULT_ORG", "default"),
            # Limits
            max_findings=_env_int("FIXOPS_MAX_FINDINGS", 100_000),
            max_scans_per_day=_env_int("FIXOPS_MAX_SCANS", 1_000),
            max_concurrent_mpte=_env_int("FIXOPS_MAX_MPTE", 10),
            # Feature flags
            feature_trustgraph=_env_bool("FIXOPS_FEATURE_TRUSTGRAPH", True),
            feature_autofix=_env_bool("FIXOPS_FEATURE_AUTOFIX", False),
            feature_attack_sim=_env_bool("FIXOPS_FEATURE_ATTACK_SIM", False),
            feature_cspm=_env_bool("FIXOPS_FEATURE_CSPM", True),
            feature_feeds=_env_bool("FIXOPS_FEATURE_FEEDS", True),
            feature_council=_env_bool("FIXOPS_FEATURE_COUNCIL", False),
            disable_telemetry=_env_bool("FIXOPS_DISABLE_TELEMETRY", False),
        )


# ---------------------------------------------------------------------------
# Thread-safe singleton
# ---------------------------------------------------------------------------

_config_lock = threading.Lock()
_config_instance: Optional[ALDECIConfig] = None


def get_config() -> ALDECIConfig:
    """Return the global ALDECIConfig singleton.

    The instance is created on first call (via ``ALDECIConfig.from_env()``) and
    cached for the lifetime of the process. Tests can reset it by calling
    ``_reset_config()``.
    """
    global _config_instance
    if _config_instance is None:
        with _config_lock:
            if _config_instance is None:
                _config_instance = ALDECIConfig.from_env()
    return _config_instance


def _reset_config() -> None:
    """Reset the singleton — intended for use in tests only."""
    global _config_instance
    with _config_lock:
        _config_instance = None
