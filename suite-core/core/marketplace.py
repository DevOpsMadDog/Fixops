"""
Integration Marketplace for ALDECI.

Provides a webhook/integration marketplace where organizations can browse,
install, configure, and manage integrations with external security tools,
ticketing systems, notification channels, cloud platforms, and more.

SQLite-backed with a built-in catalog of 20+ integrations.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class IntegrationCategory(str, Enum):
    """Category of a marketplace integration."""

    SCANNER = "scanner"
    TICKETING = "ticketing"
    NOTIFICATION = "notification"
    CLOUD = "cloud"
    CI_CD = "ci_cd"
    SIEM = "siem"
    COMPLIANCE = "compliance"
    CUSTOM = "custom"


class AppStatus(str, Enum):
    """Installation status of an app."""

    ACTIVE = "active"
    DISABLED = "disabled"


class HealthStatus(str, Enum):
    """Health check result for an installed app."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class MarketplaceApp(BaseModel):
    """Available integration in the marketplace catalog."""

    id: str = Field(..., description="Unique app identifier (slug)")
    name: str = Field(..., description="Human-readable name")
    description: str = Field(..., description="Brief description of what the integration does")
    category: IntegrationCategory
    version: str = Field(..., description="Latest available version")
    author: str = Field(..., description="Publisher / maintainer name")
    icon_url: Optional[str] = Field(None, description="URL to the app's logo or icon")
    config_schema: Dict[str, Any] = Field(
        default_factory=dict,
        description="JSON Schema describing required configuration fields",
    )
    required_scopes: List[str] = Field(
        default_factory=list,
        description="OAuth / permission scopes needed by this integration",
    )
    install_count: int = Field(default=0, ge=0, description="Total install count across all orgs")
    rating: float = Field(default=0.0, ge=0.0, le=5.0, description="Average user rating (0-5)")
    org_id: Optional[str] = Field(
        None,
        description="If set, this is a private/custom app visible only to this org",
    )


class InstalledApp(BaseModel):
    """An integration installed by an organization."""

    app_id: str = Field(..., description="References MarketplaceApp.id")
    org_id: str = Field(..., description="Organization that installed the app")
    config: Dict[str, Any] = Field(
        default_factory=dict, description="Runtime configuration (API keys, URLs, etc.)"
    )
    installed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the app was installed",
    )
    status: AppStatus = Field(default=AppStatus.ACTIVE)
    installed_by: str = Field(..., description="User ID or service account that installed the app")


class AppRating(BaseModel):
    """User rating submission."""

    app_id: str
    org_id: str
    user_id: str
    score: float = Field(..., ge=1.0, le=5.0)
    comment: Optional[str] = None


# ---------------------------------------------------------------------------
# Built-in catalog
# ---------------------------------------------------------------------------

_BUILTIN_CATALOG: List[Dict[str, Any]] = [
    # --- Scanners ---
    {
        "id": "trivy",
        "name": "Trivy",
        "description": "Comprehensive vulnerability scanner for containers, filesystems, and repos.",
        "category": IntegrationCategory.SCANNER,
        "version": "0.51.0",
        "author": "Aqua Security",
        "icon_url": "https://trivy.dev/logo.svg",
        "config_schema": {
            "type": "object",
            "properties": {
                "severity": {"type": "string", "default": "CRITICAL,HIGH"},
                "scan_target": {"type": "string", "description": "Image name or filesystem path"},
            },
        },
        "required_scopes": ["scanner:read"],
        "install_count": 4821,
        "rating": 4.7,
    },
    {
        "id": "snyk",
        "name": "Snyk",
        "description": "Developer-first security for code, open source, containers, and IaC.",
        "category": IntegrationCategory.SCANNER,
        "version": "1.1293.0",
        "author": "Snyk Ltd",
        "icon_url": "https://snyk.io/wp-content/uploads/snyk-logo.svg",
        "config_schema": {
            "type": "object",
            "required": ["api_token", "org_id"],
            "properties": {
                "api_token": {"type": "string", "description": "Snyk API token"},
                "org_id": {"type": "string", "description": "Snyk organization ID"},
                "severity_threshold": {"type": "string", "default": "high"},
            },
        },
        "required_scopes": ["scanner:read", "scanner:write"],
        "install_count": 3204,
        "rating": 4.5,
    },
    {
        "id": "semgrep",
        "name": "Semgrep",
        "description": "Static analysis engine for finding bugs and enforcing code standards.",
        "category": IntegrationCategory.SCANNER,
        "version": "1.75.0",
        "author": "Semgrep, Inc.",
        "icon_url": "https://semgrep.dev/favicon.ico",
        "config_schema": {
            "type": "object",
            "properties": {
                "api_token": {"type": "string", "description": "Semgrep Cloud API token"},
                "rules": {"type": "string", "default": "auto"},
            },
        },
        "required_scopes": ["scanner:read"],
        "install_count": 2891,
        "rating": 4.6,
    },
    {
        "id": "sonarqube",
        "name": "SonarQube",
        "description": "Continuous inspection of code quality and security.",
        "category": IntegrationCategory.SCANNER,
        "version": "10.5.0",
        "author": "SonarSource",
        "icon_url": "https://sonarqube.org/favicon.ico",
        "config_schema": {
            "type": "object",
            "required": ["server_url", "token"],
            "properties": {
                "server_url": {"type": "string", "description": "SonarQube server URL"},
                "token": {"type": "string", "description": "SonarQube API token"},
                "project_key": {"type": "string"},
            },
        },
        "required_scopes": ["scanner:read"],
        "install_count": 1543,
        "rating": 4.2,
    },
    # --- Ticketing ---
    {
        "id": "jira",
        "name": "Jira",
        "description": "Create and track Jira issues from security findings automatically.",
        "category": IntegrationCategory.TICKETING,
        "version": "3.0",
        "author": "Atlassian",
        "icon_url": "https://jira.atlassian.com/favicon.ico",
        "config_schema": {
            "type": "object",
            "required": ["server_url", "api_token", "email", "project_key"],
            "properties": {
                "server_url": {"type": "string"},
                "api_token": {"type": "string"},
                "email": {"type": "string"},
                "project_key": {"type": "string"},
                "issue_type": {"type": "string", "default": "Bug"},
            },
        },
        "required_scopes": ["ticketing:read", "ticketing:write"],
        "install_count": 5102,
        "rating": 4.4,
    },
    {
        "id": "servicenow",
        "name": "ServiceNow",
        "description": "Bi-directional ServiceNow ITSM integration for incident management.",
        "category": IntegrationCategory.TICKETING,
        "version": "2023.4",
        "author": "ServiceNow",
        "icon_url": "https://www.servicenow.com/favicon.ico",
        "config_schema": {
            "type": "object",
            "required": ["instance_url", "username", "password"],
            "properties": {
                "instance_url": {"type": "string"},
                "username": {"type": "string"},
                "password": {"type": "string"},
                "table": {"type": "string", "default": "incident"},
            },
        },
        "required_scopes": ["ticketing:read", "ticketing:write"],
        "install_count": 2341,
        "rating": 4.1,
    },
    {
        "id": "linear",
        "name": "Linear",
        "description": "Create Linear issues from findings for engineering teams.",
        "category": IntegrationCategory.TICKETING,
        "version": "2024.1",
        "author": "Linear",
        "icon_url": "https://linear.app/favicon.ico",
        "config_schema": {
            "type": "object",
            "required": ["api_key", "team_id"],
            "properties": {
                "api_key": {"type": "string"},
                "team_id": {"type": "string"},
                "project_id": {"type": "string"},
            },
        },
        "required_scopes": ["ticketing:write"],
        "install_count": 987,
        "rating": 4.3,
    },
    # --- Notifications ---
    {
        "id": "slack",
        "name": "Slack",
        "description": "Send real-time security alerts and reports to Slack channels.",
        "category": IntegrationCategory.NOTIFICATION,
        "version": "2.0",
        "author": "Slack Technologies",
        "icon_url": "https://slack.com/favicon.ico",
        "config_schema": {
            "type": "object",
            "required": ["webhook_url"],
            "properties": {
                "webhook_url": {"type": "string", "description": "Slack Incoming Webhook URL"},
                "channel": {"type": "string", "default": "#security"},
                "mention_on_critical": {"type": "boolean", "default": True},
            },
        },
        "required_scopes": ["notification:write"],
        "install_count": 6234,
        "rating": 4.8,
    },
    {
        "id": "pagerduty",
        "name": "PagerDuty",
        "description": "Trigger and resolve PagerDuty incidents based on finding severity.",
        "category": IntegrationCategory.NOTIFICATION,
        "version": "3.1",
        "author": "PagerDuty, Inc.",
        "icon_url": "https://www.pagerduty.com/favicon.ico",
        "config_schema": {
            "type": "object",
            "required": ["routing_key"],
            "properties": {
                "routing_key": {"type": "string", "description": "PagerDuty Events API v2 routing key"},
                "severity_threshold": {"type": "string", "default": "high"},
            },
        },
        "required_scopes": ["notification:write"],
        "install_count": 2108,
        "rating": 4.5,
    },
    {
        "id": "opsgenie",
        "name": "OpsGenie",
        "description": "Route critical security alerts to on-call teams via OpsGenie.",
        "category": IntegrationCategory.NOTIFICATION,
        "version": "2.5",
        "author": "Atlassian",
        "icon_url": "https://www.atlassian.com/favicon.ico",
        "config_schema": {
            "type": "object",
            "required": ["api_key"],
            "properties": {
                "api_key": {"type": "string"},
                "team": {"type": "string"},
            },
        },
        "required_scopes": ["notification:write"],
        "install_count": 891,
        "rating": 4.2,
    },
    # --- Cloud ---
    {
        "id": "aws",
        "name": "AWS Security Hub",
        "description": "Pull findings from AWS Security Hub and correlate with ALDECI.",
        "category": IntegrationCategory.CLOUD,
        "version": "2024.1",
        "author": "Amazon Web Services",
        "icon_url": "https://aws.amazon.com/favicon.ico",
        "config_schema": {
            "type": "object",
            "required": ["access_key_id", "secret_access_key", "region"],
            "properties": {
                "access_key_id": {"type": "string"},
                "secret_access_key": {"type": "string"},
                "region": {"type": "string", "default": "us-east-1"},
                "account_id": {"type": "string"},
            },
        },
        "required_scopes": ["cloud:read"],
        "install_count": 3891,
        "rating": 4.3,
    },
    {
        "id": "azure",
        "name": "Microsoft Defender for Cloud",
        "description": "Pull alerts and security score from Microsoft Defender for Cloud.",
        "category": IntegrationCategory.CLOUD,
        "version": "2024.1",
        "author": "Microsoft",
        "icon_url": "https://azure.microsoft.com/favicon.ico",
        "config_schema": {
            "type": "object",
            "required": ["tenant_id", "client_id", "client_secret", "subscription_id"],
            "properties": {
                "tenant_id": {"type": "string"},
                "client_id": {"type": "string"},
                "client_secret": {"type": "string"},
                "subscription_id": {"type": "string"},
            },
        },
        "required_scopes": ["cloud:read"],
        "install_count": 2541,
        "rating": 4.1,
    },
    {
        "id": "gcp",
        "name": "Google Cloud Security Command Center",
        "description": "Sync findings from GCP Security Command Center into ALDECI.",
        "category": IntegrationCategory.CLOUD,
        "version": "2024.1",
        "author": "Google Cloud",
        "icon_url": "https://cloud.google.com/favicon.ico",
        "config_schema": {
            "type": "object",
            "required": ["project_id", "service_account_json"],
            "properties": {
                "project_id": {"type": "string"},
                "service_account_json": {"type": "string", "description": "JSON key file contents"},
                "organization_id": {"type": "string"},
            },
        },
        "required_scopes": ["cloud:read"],
        "install_count": 1203,
        "rating": 4.0,
    },
    # --- CI/CD ---
    {
        "id": "github",
        "name": "GitHub",
        "description": "Integrate with GitHub Actions, pull requests, and security advisories.",
        "category": IntegrationCategory.CI_CD,
        "version": "2022-11-28",
        "author": "GitHub, Inc.",
        "icon_url": "https://github.com/favicon.ico",
        "config_schema": {
            "type": "object",
            "required": ["access_token"],
            "properties": {
                "access_token": {"type": "string"},
                "org": {"type": "string"},
                "repo": {"type": "string"},
                "check_runs": {"type": "boolean", "default": True},
            },
        },
        "required_scopes": ["ci_cd:read", "ci_cd:write"],
        "install_count": 7241,
        "rating": 4.9,
    },
    {
        "id": "gitlab",
        "name": "GitLab",
        "description": "Sync GitLab security scanner results and manage MR security gates.",
        "category": IntegrationCategory.CI_CD,
        "version": "v4",
        "author": "GitLab Inc.",
        "icon_url": "https://gitlab.com/favicon.ico",
        "config_schema": {
            "type": "object",
            "required": ["server_url", "access_token"],
            "properties": {
                "server_url": {"type": "string", "default": "https://gitlab.com"},
                "access_token": {"type": "string"},
                "project_id": {"type": "integer"},
            },
        },
        "required_scopes": ["ci_cd:read", "ci_cd:write"],
        "install_count": 2891,
        "rating": 4.4,
    },
    {
        "id": "jenkins",
        "name": "Jenkins",
        "description": "Trigger security scans from Jenkins pipelines and ingest results.",
        "category": IntegrationCategory.CI_CD,
        "version": "2.0",
        "author": "Jenkins Community",
        "icon_url": "https://www.jenkins.io/favicon.ico",
        "config_schema": {
            "type": "object",
            "required": ["server_url", "username", "api_token"],
            "properties": {
                "server_url": {"type": "string"},
                "username": {"type": "string"},
                "api_token": {"type": "string"},
            },
        },
        "required_scopes": ["ci_cd:read"],
        "install_count": 1102,
        "rating": 3.9,
    },
    # --- SIEM ---
    {
        "id": "splunk",
        "name": "Splunk",
        "description": "Forward findings and events to Splunk SIEM for correlation.",
        "category": IntegrationCategory.SIEM,
        "version": "9.2",
        "author": "Splunk Inc.",
        "icon_url": "https://www.splunk.com/favicon.ico",
        "config_schema": {
            "type": "object",
            "required": ["hec_url", "hec_token"],
            "properties": {
                "hec_url": {"type": "string", "description": "Splunk HEC endpoint URL"},
                "hec_token": {"type": "string"},
                "index": {"type": "string", "default": "security"},
            },
        },
        "required_scopes": ["siem:write"],
        "install_count": 1874,
        "rating": 4.3,
    },
    {
        "id": "elastic_siem",
        "name": "Elastic SIEM",
        "description": "Ingest security findings into Elasticsearch / Elastic SIEM.",
        "category": IntegrationCategory.SIEM,
        "version": "8.13",
        "author": "Elastic N.V.",
        "icon_url": "https://www.elastic.co/favicon.ico",
        "config_schema": {
            "type": "object",
            "required": ["elasticsearch_url", "api_key"],
            "properties": {
                "elasticsearch_url": {"type": "string"},
                "api_key": {"type": "string"},
                "index": {"type": "string", "default": "aldeci-findings"},
            },
        },
        "required_scopes": ["siem:write"],
        "install_count": 1342,
        "rating": 4.2,
    },
    # --- Compliance ---
    {
        "id": "vanta",
        "name": "Vanta",
        "description": "Push evidence and control status to Vanta for SOC 2 / ISO 27001 automation.",
        "category": IntegrationCategory.COMPLIANCE,
        "version": "2024.1",
        "author": "Vanta Inc.",
        "icon_url": "https://www.vanta.com/favicon.ico",
        "config_schema": {
            "type": "object",
            "required": ["api_token"],
            "properties": {
                "api_token": {"type": "string"},
                "frameworks": {
                    "type": "array",
                    "items": {"type": "string"},
                    "default": ["SOC2"],
                },
            },
        },
        "required_scopes": ["compliance:write"],
        "install_count": 891,
        "rating": 4.5,
    },
    {
        "id": "drata",
        "name": "Drata",
        "description": "Continuous compliance monitoring — sync evidence to Drata automatically.",
        "category": IntegrationCategory.COMPLIANCE,
        "version": "2024.1",
        "author": "Drata Inc.",
        "icon_url": "https://drata.com/favicon.ico",
        "config_schema": {
            "type": "object",
            "required": ["api_key"],
            "properties": {
                "api_key": {"type": "string"},
            },
        },
        "required_scopes": ["compliance:write"],
        "install_count": 562,
        "rating": 4.4,
    },
    {
        "id": "webhook_generic",
        "name": "Generic Webhook",
        "description": "Send finding events to any HTTP endpoint via configurable webhook.",
        "category": IntegrationCategory.CUSTOM,
        "version": "1.0",
        "author": "ALDECI",
        "icon_url": None,
        "config_schema": {
            "type": "object",
            "required": ["url"],
            "properties": {
                "url": {"type": "string", "description": "Target webhook URL"},
                "secret": {"type": "string", "description": "HMAC signing secret"},
                "headers": {"type": "object", "description": "Additional HTTP headers"},
                "retry_count": {"type": "integer", "default": 3},
            },
        },
        "required_scopes": ["custom:write"],
        "install_count": 2104,
        "rating": 4.0,
    },
]


# ---------------------------------------------------------------------------
# Marketplace class
# ---------------------------------------------------------------------------


class Marketplace:
    """SQLite-backed integration marketplace.

    Supports browsing the built-in catalog, installing/uninstalling apps,
    updating configuration, health checking, and user ratings.
    """

    def __init__(self, db_path: str = "data/marketplace.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()
        self._seed_catalog()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_tables(self) -> None:
        conn = self._get_conn()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS catalog (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    description TEXT NOT NULL,
                    category TEXT NOT NULL,
                    version TEXT NOT NULL,
                    author TEXT NOT NULL,
                    icon_url TEXT,
                    config_schema TEXT NOT NULL,
                    required_scopes TEXT NOT NULL,
                    install_count INTEGER NOT NULL DEFAULT 0,
                    rating REAL NOT NULL DEFAULT 0.0,
                    org_id TEXT
                );

                CREATE TABLE IF NOT EXISTS installed_apps (
                    app_id TEXT NOT NULL,
                    org_id TEXT NOT NULL,
                    config TEXT NOT NULL,
                    installed_at TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active',
                    installed_by TEXT NOT NULL,
                    PRIMARY KEY (app_id, org_id)
                );

                CREATE TABLE IF NOT EXISTS ratings (
                    id TEXT PRIMARY KEY,
                    app_id TEXT NOT NULL,
                    org_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    score REAL NOT NULL,
                    comment TEXT,
                    created_at TEXT NOT NULL,
                    UNIQUE (app_id, org_id, user_id)
                );
                """
            )
            conn.commit()
        finally:
            conn.close()

    def _seed_catalog(self) -> None:
        """Insert built-in apps into the catalog if not already present."""
        conn = self._get_conn()
        try:
            for app in _BUILTIN_CATALOG:
                existing = conn.execute(
                    "SELECT id FROM catalog WHERE id = ?", (app["id"],)
                ).fetchone()
                if not existing:
                    conn.execute(
                        """
                        INSERT INTO catalog
                            (id, name, description, category, version, author,
                             icon_url, config_schema, required_scopes, install_count, rating, org_id)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            app["id"],
                            app["name"],
                            app["description"],
                            app["category"].value
                            if isinstance(app["category"], IntegrationCategory)
                            else app["category"],
                            app["version"],
                            app["author"],
                            app.get("icon_url"),
                            json.dumps(app.get("config_schema", {})),
                            json.dumps(app.get("required_scopes", [])),
                            app.get("install_count", 0),
                            app.get("rating", 0.0),
                            app.get("org_id"),
                        ),
                    )
            conn.commit()
        finally:
            conn.close()

    def _row_to_app(self, row: sqlite3.Row) -> MarketplaceApp:
        return MarketplaceApp(
            id=row["id"],
            name=row["name"],
            description=row["description"],
            category=IntegrationCategory(row["category"]),
            version=row["version"],
            author=row["author"],
            icon_url=row["icon_url"],
            config_schema=json.loads(row["config_schema"]),
            required_scopes=json.loads(row["required_scopes"]),
            install_count=row["install_count"],
            rating=row["rating"],
            org_id=row["org_id"],
        )

    def _row_to_installed(self, row: sqlite3.Row) -> InstalledApp:
        return InstalledApp(
            app_id=row["app_id"],
            org_id=row["org_id"],
            config=json.loads(row["config"]),
            installed_at=datetime.fromisoformat(row["installed_at"]),
            status=AppStatus(row["status"]),
            installed_by=row["installed_by"],
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def list_apps(
        self,
        category: Optional[IntegrationCategory] = None,
        search: Optional[str] = None,
        org_id: Optional[str] = None,
    ) -> List[MarketplaceApp]:
        """Browse available integrations.

        Returns public catalog apps plus any private apps belonging to org_id.
        Optionally filter by category and/or a text search term (name + description).
        """
        conditions = ["(org_id IS NULL OR org_id = ?)"]
        params: List[Any] = [org_id or ""]

        if category:
            conditions.append("category = ?")
            params.append(category.value)

        if search:
            conditions.append("(LOWER(name) LIKE ? OR LOWER(description) LIKE ?)")
            term = f"%{search.lower()}%"
            params.extend([term, term])

        query = f"SELECT * FROM catalog WHERE {' AND '.join(conditions)} ORDER BY install_count DESC"  # nosec B608
        conn = self._get_conn()
        try:
            rows = conn.execute(query, params).fetchall()
            return [self._row_to_app(r) for r in rows]
        finally:
            conn.close()

    def get_app(self, app_id: str) -> Optional[MarketplaceApp]:
        """Return details for a specific app, or None if not found."""
        conn = self._get_conn()
        try:
            row = conn.execute("SELECT * FROM catalog WHERE id = ?", (app_id,)).fetchone()
            return self._row_to_app(row) if row else None
        finally:
            conn.close()

    def install_app(
        self,
        app_id: str,
        org_id: str,
        config: Dict[str, Any],
        installed_by: str,
    ) -> InstalledApp:
        """Install a marketplace app for an organization.

        Raises:
            ValueError: If the app_id does not exist in the catalog.
            ValueError: If the app is already installed for this org.
        """
        if not self.get_app(app_id):
            raise ValueError(f"App '{app_id}' not found in catalog")

        conn = self._get_conn()
        try:
            existing = conn.execute(
                "SELECT app_id FROM installed_apps WHERE app_id = ? AND org_id = ?",
                (app_id, org_id),
            ).fetchone()
            if existing:
                raise ValueError(f"App '{app_id}' is already installed for org '{org_id}'")

            now = datetime.now(timezone.utc).isoformat()
            conn.execute(
                """
                INSERT INTO installed_apps (app_id, org_id, config, installed_at, status, installed_by)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (app_id, org_id, json.dumps(config), now, AppStatus.ACTIVE.value, installed_by),
            )
            # Increment install_count
            conn.execute(
                "UPDATE catalog SET install_count = install_count + 1 WHERE id = ?", (app_id,)
            )
            conn.commit()

            row = conn.execute(
                "SELECT * FROM installed_apps WHERE app_id = ? AND org_id = ?",
                (app_id, org_id),
            ).fetchone()
            return self._row_to_installed(row)
        finally:
            conn.close()

    def uninstall_app(self, app_id: str, org_id: str) -> bool:
        """Remove an installed app for an organization.

        Returns True if removed, False if the app was not installed.
        """
        conn = self._get_conn()
        try:
            cursor = conn.execute(
                "DELETE FROM installed_apps WHERE app_id = ? AND org_id = ?",
                (app_id, org_id),
            )
            conn.commit()
            removed = cursor.rowcount > 0
            if removed:
                # Decrement install_count (floor at 0)
                conn.execute(
                    "UPDATE catalog SET install_count = MAX(0, install_count - 1) WHERE id = ?",
                    (app_id,),
                )
                conn.commit()
            return removed
        finally:
            conn.close()

    def update_config(
        self, app_id: str, org_id: str, config: Dict[str, Any]
    ) -> InstalledApp:
        """Update configuration for an installed app.

        Raises:
            ValueError: If the app is not installed for this org.
        """
        conn = self._get_conn()
        try:
            existing = conn.execute(
                "SELECT app_id FROM installed_apps WHERE app_id = ? AND org_id = ?",
                (app_id, org_id),
            ).fetchone()
            if not existing:
                raise ValueError(f"App '{app_id}' is not installed for org '{org_id}'")

            conn.execute(
                "UPDATE installed_apps SET config = ? WHERE app_id = ? AND org_id = ?",
                (json.dumps(config), app_id, org_id),
            )
            conn.commit()
            row = conn.execute(
                "SELECT * FROM installed_apps WHERE app_id = ? AND org_id = ?",
                (app_id, org_id),
            ).fetchone()
            return self._row_to_installed(row)
        finally:
            conn.close()

    def list_installed(self, org_id: str) -> List[InstalledApp]:
        """Return all apps installed by an organization."""
        conn = self._get_conn()
        try:
            rows = conn.execute(
                "SELECT * FROM installed_apps WHERE org_id = ? ORDER BY installed_at DESC",
                (org_id,),
            ).fetchall()
            return [self._row_to_installed(r) for r in rows]
        finally:
            conn.close()

    def get_app_health(self, app_id: str, org_id: str) -> Dict[str, Any]:
        """Check health of an installed app.

        Performs a lightweight config validation check. Returns a health
        dict with status, latency_ms, and details.

        Raises:
            ValueError: If the app is not installed for this org.
        """
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT * FROM installed_apps WHERE app_id = ? AND org_id = ?",
                (app_id, org_id),
            ).fetchone()
            if not row:
                raise ValueError(f"App '{app_id}' is not installed for org '{org_id}'")

            installed = self._row_to_installed(row)
            app = self.get_app(app_id)

            # Validate required config fields from schema
            schema = app.config_schema if app else {}
            required_fields: List[str] = schema.get("required", []) if schema else []
            config = installed.config
            missing = [f for f in required_fields if f not in config or not config[f]]

            if installed.status == AppStatus.DISABLED:
                status = HealthStatus.UNHEALTHY
                details = "App is disabled"
            elif missing:
                status = HealthStatus.DEGRADED
                details = f"Missing required config fields: {', '.join(missing)}"
            else:
                status = HealthStatus.HEALTHY
                details = "Configuration valid"

            return {
                "app_id": app_id,
                "org_id": org_id,
                "status": status.value,
                "details": details,
                "checked_at": datetime.now(timezone.utc).isoformat(),
                "config_fields_present": list(config.keys()),
                "missing_required_fields": missing,
            }
        finally:
            conn.close()

    def rate_app(
        self,
        app_id: str,
        org_id: str,
        user_id: str,
        score: float,
        comment: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Submit or update a user rating for an app.

        Raises:
            ValueError: If app_id is not in the catalog.
            ValueError: If score is not in range [1.0, 5.0].
        """
        if not self.get_app(app_id):
            raise ValueError(f"App '{app_id}' not found in catalog")
        if not (1.0 <= score <= 5.0):
            raise ValueError(f"Score must be between 1.0 and 5.0, got {score}")

        conn = self._get_conn()
        try:
            now = datetime.now(timezone.utc).isoformat()
            # Upsert rating
            conn.execute(
                """
                INSERT INTO ratings (id, app_id, org_id, user_id, score, comment, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(app_id, org_id, user_id) DO UPDATE SET
                    score = excluded.score,
                    comment = excluded.comment,
                    created_at = excluded.created_at
                """,
                (str(uuid.uuid4()), app_id, org_id, user_id, score, comment, now),
            )

            # Recompute average rating
            avg_row = conn.execute(
                "SELECT AVG(score) as avg_score, COUNT(*) as count FROM ratings WHERE app_id = ?",
                (app_id,),
            ).fetchone()
            new_avg = round(avg_row["avg_score"] or 0.0, 2)
            conn.execute(
                "UPDATE catalog SET rating = ? WHERE id = ?",
                (new_avg, app_id),
            )
            conn.commit()

            return {
                "app_id": app_id,
                "user_id": user_id,
                "score": score,
                "new_average_rating": new_avg,
                "total_ratings": avg_row["count"],
            }
        finally:
            conn.close()

    def get_catalog_stats(self, org_id: Optional[str] = None) -> Dict[str, Any]:
        """Return aggregate statistics for the integration catalog.

        Includes total app count, per-category breakdown, total installs,
        average rating across all public apps, and most-installed app.
        org_id is used to include private apps belonging to that org.
        """
        conn = self._get_conn()
        try:
            params: List[Any] = [org_id or ""]
            rows = conn.execute(
                "SELECT category, install_count, rating FROM catalog WHERE (org_id IS NULL OR org_id = ?)",
                params,
            ).fetchall()

            total_apps = len(rows)
            category_counts: Dict[str, int] = {}
            total_installs = 0
            rating_sum = 0.0
            rating_count = 0
            top_app_row = None
            top_app_count = -1

            for row in rows:
                cat = row["category"]
                category_counts[cat] = category_counts.get(cat, 0) + 1
                total_installs += row["install_count"]
                if row["rating"] and row["rating"] > 0:
                    rating_sum += row["rating"]
                    rating_count += 1
                if row["install_count"] > top_app_count:
                    top_app_count = row["install_count"]

            # Fetch top app id separately
            top_row = conn.execute(
                "SELECT id, install_count FROM catalog WHERE (org_id IS NULL OR org_id = ?) ORDER BY install_count DESC LIMIT 1",
                params,
            ).fetchone()

            avg_rating = round(rating_sum / rating_count, 2) if rating_count else 0.0

            return {
                "total_apps": total_apps,
                "category_breakdown": category_counts,
                "total_installs_across_catalog": total_installs,
                "average_rating": avg_rating,
                "most_installed_app": top_row["id"] if top_row else None,
                "most_installed_count": top_row["install_count"] if top_row else 0,
            }
        finally:
            conn.close()

    def register_custom_app(self, app: MarketplaceApp) -> MarketplaceApp:
        """Register a custom/private integration visible only to one org.

        Raises:
            ValueError: If an app with the same id already exists.
        """
        existing = self.get_app(app.id)
        if existing:
            raise ValueError(f"App with id '{app.id}' already exists in catalog")

        conn = self._get_conn()
        try:
            conn.execute(
                """
                INSERT INTO catalog
                    (id, name, description, category, version, author,
                     icon_url, config_schema, required_scopes, install_count, rating, org_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    app.id,
                    app.name,
                    app.description,
                    app.category.value,
                    app.version,
                    app.author,
                    app.icon_url,
                    json.dumps(app.config_schema),
                    json.dumps(app.required_scopes),
                    app.install_count,
                    app.rating,
                    app.org_id,
                ),
            )
            conn.commit()
        finally:
            conn.close()

        return app
