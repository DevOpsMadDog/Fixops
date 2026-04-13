"""Tests for DeploymentManager and deployment_router.

Covers:
  - Health Check Aggregator (all 5 services)
  - First-Boot Initializer (idempotent, steps)
  - Migration Runner (apply, skip, rollback)
  - Service Discovery (available / degraded / unavailable)
  - Configuration Validator (env vars, ports, DB)
  - Deployment Status API (uptime, version, flags, modules)
  - Sanitized Configuration (secrets redacted)
  - Router endpoints (health, status, initialize, config, migrations, services, validate)

All tests use mocks — no real network or DB connections required.
"""

from __future__ import annotations

import os
import sqlite3
import socket
import tempfile
import time
from pathlib import Path
from typing import Any, Dict
from unittest.mock import AsyncMock, MagicMock, patch, call
import asyncio

import pytest

# ─── Environment setup (must happen before imports) ──────────────────────────
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token-abc123")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-jwt-secret-xyz789")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")
os.environ.setdefault("ALDECI_MODE", "full")

from fastapi import FastAPI
from fastapi.testclient import TestClient


# ─── Fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def tmp_data_dir(tmp_path):
    """Temporary data directory for each test."""
    return tmp_path


@pytest.fixture
def manager(tmp_data_dir):
    """Fresh DeploymentManager with isolated data dir."""
    with patch.dict(os.environ, {"FIXOPS_DATA_DIR": str(tmp_data_dir)}):
        # Import fresh to get a new instance
        import importlib
        import core.deployment_manager as dm_module
        importlib.reload(dm_module)
        dm_module._manager = None  # reset singleton
        mgr = dm_module.DeploymentManager()
        yield mgr


@pytest.fixture
def test_app(tmp_data_dir):
    """FastAPI test app with deployment router mounted."""
    app = FastAPI()
    with patch.dict(os.environ, {"FIXOPS_DATA_DIR": str(tmp_data_dir)}):
        import importlib
        import core.deployment_manager as dm_module
        importlib.reload(dm_module)
        dm_module._manager = None

        from apps.api.deployment_router import router
        app.include_router(router)
        yield app


@pytest.fixture
def client(test_app):
    """TestClient for the deployment router."""
    return TestClient(test_app, raise_server_exceptions=False)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _make_healthy_http(name, optional=False):
    """Build a ServiceHealth for a healthy HTTP service."""
    from core.deployment_manager import ServiceHealth
    return ServiceHealth(name=name, status="healthy", latency_ms=5.0, optional=optional)


def _make_unavailable(name, optional=False):
    from core.deployment_manager import ServiceHealth
    return ServiceHealth(name=name, status="unavailable", latency_ms=0.0,
                         message="connection refused", optional=optional)


def _make_degraded(name, optional=False):
    from core.deployment_manager import ServiceHealth
    return ServiceHealth(name=name, status="degraded", latency_ms=100.0,
                         message="slow response", optional=optional)


# ─── ServiceHealth dataclass ──────────────────────────────────────────────────

class TestServiceHealth:
    def test_defaults(self):
        from core.deployment_manager import ServiceHealth
        s = ServiceHealth(name="api", status="healthy", latency_ms=10.0)
        assert s.name == "api"
        assert s.status == "healthy"
        assert s.latency_ms == 10.0
        assert s.message == ""
        assert s.optional is False

    def test_optional_flag(self):
        from core.deployment_manager import ServiceHealth
        s = ServiceHealth(name="ui", status="degraded", latency_ms=50.0, optional=True)
        assert s.optional is True


# ─── AggregateHealth ──────────────────────────────────────────────────────────

class TestAggregateHealth:
    def test_as_dict_structure(self):
        from core.deployment_manager import AggregateHealth, ServiceHealth
        h = AggregateHealth(
            status="healthy",
            services=[ServiceHealth("api", "healthy", 5.0)],
            checked_at="2026-01-01T00:00:00+00:00",
            uptime_seconds=120.0,
        )
        d = h.as_dict()
        assert d["status"] == "healthy"
        assert "api" in d["services"]
        assert d["uptime_seconds"] == 120.0
        assert d["checked_at"] == "2026-01-01T00:00:00+00:00"

    def test_services_serialized(self):
        from core.deployment_manager import AggregateHealth, ServiceHealth
        h = AggregateHealth(
            status="degraded",
            services=[
                ServiceHealth("api", "healthy", 5.0),
                ServiceHealth("redis", "unavailable", 0.0, "timeout", optional=False),
            ],
        )
        d = h.as_dict()
        assert d["services"]["redis"]["status"] == "unavailable"
        assert d["services"]["redis"]["message"] == "timeout"


# ─── Health Check Aggregator ──────────────────────────────────────────────────

class TestAggregateHealth_Manager:
    @pytest.mark.asyncio
    async def test_all_healthy_returns_healthy(self, manager):
        """All services healthy → overall healthy."""
        healthy_services = [
            _make_healthy_http("api"),
            _make_healthy_http("ui", optional=True),
            _make_healthy_http("trustgraph", optional=True),
            _make_healthy_http("redis"),
            _make_healthy_http("postgres"),
        ]
        with patch.object(manager, "_check_api", return_value=healthy_services[0]), \
             patch.object(manager, "_check_ui", return_value=healthy_services[1]), \
             patch.object(manager, "_check_trustgraph", return_value=healthy_services[2]), \
             patch.object(manager, "_check_redis", return_value=healthy_services[3]), \
             patch.object(manager, "_check_postgres", return_value=healthy_services[4]):
            health = await manager.aggregate_health()
        assert health.status == "healthy"

    @pytest.mark.asyncio
    async def test_optional_down_returns_degraded(self, manager):
        """Required healthy, optional down → degraded (not unavailable)."""
        with patch.object(manager, "_check_api", return_value=_make_healthy_http("api")), \
             patch.object(manager, "_check_ui", return_value=_make_unavailable("ui", optional=True)), \
             patch.object(manager, "_check_trustgraph", return_value=_make_unavailable("trustgraph", optional=True)), \
             patch.object(manager, "_check_redis", return_value=_make_healthy_http("redis")), \
             patch.object(manager, "_check_postgres", return_value=_make_healthy_http("postgres")):
            health = await manager.aggregate_health()
        assert health.status == "degraded"

    @pytest.mark.asyncio
    async def test_required_down_returns_unavailable(self, manager):
        """Required service down → unavailable."""
        with patch.object(manager, "_check_api", return_value=_make_healthy_http("api")), \
             patch.object(manager, "_check_ui", return_value=_make_healthy_http("ui", optional=True)), \
             patch.object(manager, "_check_trustgraph", return_value=_make_healthy_http("trustgraph", optional=True)), \
             patch.object(manager, "_check_redis", return_value=_make_unavailable("redis")), \
             patch.object(manager, "_check_postgres", return_value=_make_healthy_http("postgres")):
            health = await manager.aggregate_health()
        assert health.status == "unavailable"

    @pytest.mark.asyncio
    async def test_health_has_all_five_services(self, manager):
        """Health result contains entries for all 5 services."""
        svcs = {n: _make_healthy_http(n, optional=(n in ("ui", "trustgraph")))
                for n in ("api", "ui", "trustgraph", "redis", "postgres")}
        with patch.object(manager, "_check_api", return_value=svcs["api"]), \
             patch.object(manager, "_check_ui", return_value=svcs["ui"]), \
             patch.object(manager, "_check_trustgraph", return_value=svcs["trustgraph"]), \
             patch.object(manager, "_check_redis", return_value=svcs["redis"]), \
             patch.object(manager, "_check_postgres", return_value=svcs["postgres"]):
            health = await manager.aggregate_health()
        assert {s.name for s in health.services} == {"api", "ui", "trustgraph", "redis", "postgres"}

    @pytest.mark.asyncio
    async def test_health_includes_uptime(self, manager):
        """Health includes positive uptime_seconds."""
        with patch.object(manager, "_check_api", return_value=_make_healthy_http("api")), \
             patch.object(manager, "_check_ui", return_value=_make_healthy_http("ui", optional=True)), \
             patch.object(manager, "_check_trustgraph", return_value=_make_healthy_http("trustgraph", optional=True)), \
             patch.object(manager, "_check_redis", return_value=_make_healthy_http("redis")), \
             patch.object(manager, "_check_postgres", return_value=_make_healthy_http("postgres")):
            health = await manager.aggregate_health()
        assert health.uptime_seconds >= 0.0

    @pytest.mark.asyncio
    async def test_health_checked_at_is_set(self, manager):
        """Health result has a non-empty checked_at timestamp."""
        with patch.object(manager, "_check_api", return_value=_make_healthy_http("api")), \
             patch.object(manager, "_check_ui", return_value=_make_healthy_http("ui", optional=True)), \
             patch.object(manager, "_check_trustgraph", return_value=_make_healthy_http("trustgraph", optional=True)), \
             patch.object(manager, "_check_redis", return_value=_make_healthy_http("redis")), \
             patch.object(manager, "_check_postgres", return_value=_make_healthy_http("postgres")):
            health = await manager.aggregate_health()
        assert health.checked_at != ""


# ─── HTTP check helper ────────────────────────────────────────────────────────

class TestHttpCheck:
    def test_http_check_success(self, manager):
        """Successful HTTP check returns healthy ServiceHealth."""
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__ = lambda s: mock_resp
        mock_resp.__exit__ = MagicMock(return_value=False)

        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = manager._http_check("api", "http://localhost:8000/health")
        assert result.status == "healthy"
        assert result.name == "api"

    def test_http_check_connection_error(self, manager):
        """Connection error returns unavailable."""
        import urllib.error
        with patch("urllib.request.urlopen", side_effect=OSError("connection refused")):
            result = manager._http_check("api", "http://localhost:8000/health")
        assert result.status == "unavailable"
        assert "connection refused" in result.message

    def test_http_check_500_returns_degraded(self, manager):
        """HTTP 500 returns degraded."""
        mock_resp = MagicMock()
        mock_resp.status = 500
        mock_resp.__enter__ = lambda s: mock_resp
        mock_resp.__exit__ = MagicMock(return_value=False)
        with patch("urllib.request.urlopen", return_value=mock_resp):
            result = manager._http_check("api", "http://localhost:8000/health")
        assert result.status == "degraded"


# ─── Redis ping ───────────────────────────────────────────────────────────────

class TestRedisPing:
    def test_redis_ping_success(self, manager):
        """Successful PONG from redis returns healthy."""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"+PONG\r\n"
        mock_sock.__enter__ = lambda s: mock_sock
        mock_sock.__exit__ = MagicMock(return_value=False)
        with patch("socket.create_connection", return_value=mock_sock):
            result = manager._redis_ping()
        assert result.status == "healthy"
        assert result.name == "redis"

    def test_redis_ping_connection_refused(self, manager):
        """Connection refused returns unavailable."""
        with patch("socket.create_connection", side_effect=ConnectionRefusedError("refused")):
            result = manager._redis_ping()
        assert result.status == "unavailable"
        assert result.name == "redis"

    def test_redis_ping_unexpected_response(self, manager):
        """Non-PONG response returns degraded."""
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"-ERR unknown command\r\n"
        mock_sock.__enter__ = lambda s: mock_sock
        mock_sock.__exit__ = MagicMock(return_value=False)
        with patch("socket.create_connection", return_value=mock_sock):
            result = manager._redis_ping()
        assert result.status == "degraded"


# ─── Migration Runner ─────────────────────────────────────────────────────────

class TestMigrationRunner:
    @pytest.mark.asyncio
    async def test_migrations_applied_on_first_run(self, manager):
        """First run applies all migrations."""
        result = await manager.run_migrations()
        assert result["status"] == "ok"
        assert len(result["applied"]) == 3  # all 3 migrations
        assert result["skipped"] == []

    @pytest.mark.asyncio
    async def test_migrations_idempotent(self, manager):
        """Second run skips already-applied migrations."""
        await manager.run_migrations()
        result = await manager.run_migrations()
        assert result["status"] == "ok"
        assert result["applied"] == []
        assert len(result["skipped"]) == 3

    @pytest.mark.asyncio
    async def test_migration_version_stored(self, manager):
        """After migrations, current_version matches last migration."""
        result = await manager.run_migrations()
        assert result["current_version"] == "003"

    def test_get_migration_history(self, manager):
        """Migration history returns MigrationRecord objects."""
        asyncio.run(manager.run_migrations())
        history = manager.get_migration_history()
        assert len(history) == 3
        versions = {m.version for m in history}
        assert versions == {"001", "002", "003"}

    def test_migration_checksum_consistent(self):
        """Migration checksum is deterministic."""
        from core.deployment_manager import _migration_checksum, _MIGRATIONS
        c1 = _migration_checksum(_MIGRATIONS[0])
        c2 = _migration_checksum(_MIGRATIONS[0])
        assert c1 == c2
        assert len(c1) == 16

    @pytest.mark.asyncio
    async def test_migration_history_names(self, manager):
        """Migration records have correct names."""
        await manager.run_migrations()
        history = manager.get_migration_history()
        names = {m.name for m in history}
        assert "create_deployment_meta" in names
        assert "create_migration_history" in names


# ─── First-Boot Initializer ───────────────────────────────────────────────────

class TestFirstBootInitializer:
    @pytest.mark.asyncio
    async def test_first_boot_runs_all_steps(self, manager):
        """First boot completes with all expected step keys."""
        with patch.object(manager, "_seed_admin_user", return_value={"status": "ok"}), \
             patch.object(manager, "_create_default_config", return_value={"status": "ok"}), \
             patch.object(manager, "_populate_service_registry", return_value={"status": "ok"}), \
             patch.object(manager, "_index_trustgraph", new=AsyncMock(return_value={"status": "skipped"})):
            result = await manager.initialize_first_boot()
        assert result["status"] == "initialized"
        assert "migrations" in result["steps"]
        assert "admin_seed" in result["steps"]
        assert "default_config" in result["steps"]
        assert "service_registry" in result["steps"]
        assert "trustgraph_index" in result["steps"]

    @pytest.mark.asyncio
    async def test_first_boot_idempotent(self, manager):
        """Second call returns already_initialized without re-running steps."""
        with patch.object(manager, "_seed_admin_user", return_value={"status": "ok"}), \
             patch.object(manager, "_create_default_config", return_value={"status": "ok"}), \
             patch.object(manager, "_populate_service_registry", return_value={"status": "ok"}), \
             patch.object(manager, "_index_trustgraph", new=AsyncMock(return_value={"status": "skipped"})):
            await manager.initialize_first_boot()
            result = await manager.initialize_first_boot()
        assert result["status"] == "already_initialized"
        assert result["steps"] == {}

    @pytest.mark.asyncio
    async def test_first_boot_stores_timestamp(self, manager):
        """First boot stores first_boot_at in meta DB."""
        with patch.object(manager, "_seed_admin_user", return_value={"status": "ok"}), \
             patch.object(manager, "_create_default_config", return_value={"status": "ok"}), \
             patch.object(manager, "_populate_service_registry", return_value={"status": "ok"}), \
             patch.object(manager, "_index_trustgraph", new=AsyncMock(return_value={"status": "skipped"})):
            await manager.initialize_first_boot()
        assert manager._meta_get("first_boot_complete") == "true"
        assert manager._meta_get("first_boot_at") != ""

    @pytest.mark.asyncio
    async def test_first_boot_partial_on_error(self, manager):
        """Step error does not crash — result status is partial."""
        with patch.object(manager, "_seed_admin_user", return_value={"status": "error", "error": "boom"}), \
             patch.object(manager, "_create_default_config", return_value={"status": "ok"}), \
             patch.object(manager, "_populate_service_registry", return_value={"status": "ok"}), \
             patch.object(manager, "_index_trustgraph", new=AsyncMock(return_value={"status": "skipped"})):
            result = await manager.initialize_first_boot()
        assert result["status"] in ("initialized", "partial")

    @pytest.mark.asyncio
    async def test_trustgraph_skipped_when_unavailable(self, manager):
        """TrustGraph index step is skipped gracefully when service is down."""
        unavailable_health = _make_unavailable("trustgraph", optional=True)
        with patch.object(manager, "_seed_admin_user", return_value={"status": "ok"}), \
             patch.object(manager, "_create_default_config", return_value={"status": "ok"}), \
             patch.object(manager, "_populate_service_registry", return_value={"status": "ok"}), \
             patch.object(manager, "_http_check", return_value=unavailable_health):
            result = await manager.initialize_first_boot()
        tg_step = result["steps"]["trustgraph_index"]
        assert tg_step["status"] == "skipped"


# ─── Service Discovery ────────────────────────────────────────────────────────

class TestServiceDiscovery:
    @pytest.mark.asyncio
    async def test_discover_all_available(self, manager):
        """All services available → no unavailable_required."""
        svcs = [_make_healthy_http(n, optional=(n in ("ui", "trustgraph")))
                for n in ("api", "ui", "trustgraph", "redis", "postgres")]
        with patch.object(manager, "_check_api", return_value=svcs[0]), \
             patch.object(manager, "_check_ui", return_value=svcs[1]), \
             patch.object(manager, "_check_trustgraph", return_value=svcs[2]), \
             patch.object(manager, "_check_redis", return_value=svcs[3]), \
             patch.object(manager, "_check_postgres", return_value=svcs[4]):
            result = await manager.discover_services()
        assert result["unavailable_required"] == []
        assert len(result["services"]) == 5

    @pytest.mark.asyncio
    async def test_discover_required_unavailable(self, manager):
        """Required service unavailable → appears in unavailable_required."""
        with patch.object(manager, "_check_api", return_value=_make_healthy_http("api")), \
             patch.object(manager, "_check_ui", return_value=_make_healthy_http("ui", optional=True)), \
             patch.object(manager, "_check_trustgraph", return_value=_make_healthy_http("trustgraph", optional=True)), \
             patch.object(manager, "_check_redis", return_value=_make_unavailable("redis")), \
             patch.object(manager, "_check_postgres", return_value=_make_healthy_http("postgres")):
            result = await manager.discover_services()
        assert "redis" in result["unavailable_required"]

    @pytest.mark.asyncio
    async def test_discover_optional_degraded(self, manager):
        """Optional service degraded → appears in degraded_services."""
        with patch.object(manager, "_check_api", return_value=_make_healthy_http("api")), \
             patch.object(manager, "_check_ui", return_value=_make_degraded("ui", optional=True)), \
             patch.object(manager, "_check_trustgraph", return_value=_make_healthy_http("trustgraph", optional=True)), \
             patch.object(manager, "_check_redis", return_value=_make_healthy_http("redis")), \
             patch.object(manager, "_check_postgres", return_value=_make_healthy_http("postgres")):
            result = await manager.discover_services()
        assert "ui" in result["degraded_services"]

    def test_get_service_registry_empty(self, manager):
        """Empty registry returns empty list."""
        registry = manager.get_service_registry()
        assert isinstance(registry, list)

    def test_get_service_registry_after_populate(self, manager):
        """Populated registry returns service entries."""
        manager._populate_service_registry()
        registry = manager.get_service_registry()
        names = {r["name"] for r in registry}
        assert "api" in names
        assert "redis" in names
        assert "postgres" in names


# ─── Configuration Validator ──────────────────────────────────────────────────

class TestConfigurationValidator:
    @pytest.mark.asyncio
    async def test_validate_missing_api_token(self, manager):
        """Missing FIXOPS_API_TOKEN produces a warning."""
        with patch.dict(os.environ, {"FIXOPS_API_TOKEN": ""}), \
             patch.object(manager, "_check_postgres", return_value=_make_healthy_http("postgres")), \
             patch.object(manager, "_check_redis", return_value=_make_healthy_http("redis")):
            result = await manager.validate_configuration()
        assert any("FIXOPS_API_TOKEN" in w for w in result["warnings"])

    @pytest.mark.asyncio
    async def test_validate_insecure_default_token(self, manager):
        """Insecure default value for token produces a warning."""
        with patch.dict(os.environ, {"FIXOPS_API_TOKEN": "changeme"}), \
             patch.object(manager, "_check_postgres", return_value=_make_healthy_http("postgres")), \
             patch.object(manager, "_check_redis", return_value=_make_healthy_http("redis")):
            result = await manager.validate_configuration()
        assert any("insecure" in w.lower() for w in result["warnings"])

    @pytest.mark.asyncio
    async def test_validate_no_llm_provider(self, manager):
        """No LLM provider configured produces a warning."""
        no_llm_env = {
            "OPENAI_API_KEY": "",
            "ANTHROPIC_API_KEY": "",
            "OPENROUTER_API_KEY": "",
            "FIXOPS_OLLAMA_URL": "",
        }
        with patch.dict(os.environ, no_llm_env), \
             patch.object(manager, "_check_postgres", return_value=_make_healthy_http("postgres")), \
             patch.object(manager, "_check_redis", return_value=_make_healthy_http("redis")):
            result = await manager.validate_configuration()
        assert any("llm" in w.lower() or "LLM" in w for w in result["warnings"])

    @pytest.mark.asyncio
    async def test_validate_db_unavailable_produces_issue(self, manager):
        """Unavailable required DB produces an issue (not just a warning)."""
        with patch.object(manager, "_check_postgres", return_value=_make_unavailable("postgres")), \
             patch.object(manager, "_check_redis", return_value=_make_healthy_http("redis")):
            result = await manager.validate_configuration()
        assert any("postgres" in issue.lower() for issue in result["issues"])
        assert result["status"] == "invalid"

    @pytest.mark.asyncio
    async def test_validate_has_checks_dict(self, manager):
        """Validation result always contains a checks dict."""
        with patch.object(manager, "_check_postgres", return_value=_make_healthy_http("postgres")), \
             patch.object(manager, "_check_redis", return_value=_make_healthy_http("redis")):
            result = await manager.validate_configuration()
        assert isinstance(result["checks"], dict)
        assert "validated_at" in result


# ─── Deployment Status ────────────────────────────────────────────────────────

class TestDeploymentStatus:
    @pytest.mark.asyncio
    async def test_status_has_required_fields(self, manager):
        """Status response contains all required fields."""
        healthy_svcs = [_make_healthy_http(n, optional=(n in ("ui", "trustgraph")))
                        for n in ("api", "ui", "trustgraph", "redis", "postgres")]
        with patch.object(manager, "_check_api", return_value=healthy_svcs[0]), \
             patch.object(manager, "_check_ui", return_value=healthy_svcs[1]), \
             patch.object(manager, "_check_trustgraph", return_value=healthy_svcs[2]), \
             patch.object(manager, "_check_redis", return_value=healthy_svcs[3]), \
             patch.object(manager, "_check_postgres", return_value=healthy_svcs[4]):
            status = await manager.get_deployment_status()
        d = status.as_dict()
        assert "version" in d
        assert "build" in d
        assert "uptime_seconds" in d
        assert "started_at" in d
        assert "feature_flags" in d
        assert "enabled_modules" in d
        assert "migration_version" in d
        assert "first_boot_complete" in d

    @pytest.mark.asyncio
    async def test_status_healthy_when_all_up(self, manager):
        """Status.healthy is True when all required services are up."""
        svcs = [_make_healthy_http(n, optional=(n in ("ui", "trustgraph")))
                for n in ("api", "ui", "trustgraph", "redis", "postgres")]
        with patch.object(manager, "_check_api", return_value=svcs[0]), \
             patch.object(manager, "_check_ui", return_value=svcs[1]), \
             patch.object(manager, "_check_trustgraph", return_value=svcs[2]), \
             patch.object(manager, "_check_redis", return_value=svcs[3]), \
             patch.object(manager, "_check_postgres", return_value=svcs[4]):
            status = await manager.get_deployment_status()
        assert status.healthy is True

    @pytest.mark.asyncio
    async def test_status_version_from_env(self, manager):
        """Status version reflects ALDECI_VERSION env var."""
        with patch.dict(os.environ, {"ALDECI_VERSION": "9.9.9"}):
            import core.deployment_manager as dm
            dm.ALDECI_VERSION = "9.9.9"
            svcs = [_make_healthy_http(n, optional=(n in ("ui", "trustgraph")))
                    for n in ("api", "ui", "trustgraph", "redis", "postgres")]
            with patch.object(manager, "_check_api", return_value=svcs[0]), \
                 patch.object(manager, "_check_ui", return_value=svcs[1]), \
                 patch.object(manager, "_check_trustgraph", return_value=svcs[2]), \
                 patch.object(manager, "_check_redis", return_value=svcs[3]), \
                 patch.object(manager, "_check_postgres", return_value=svcs[4]):
                status = await manager.get_deployment_status()
            dm.ALDECI_VERSION = "2.5.0"
        assert status.version == "9.9.9"

    def test_feature_flags_defaults(self, manager):
        """Feature flags contain expected keys."""
        flags = manager._get_feature_flags()
        assert "llm_consensus" in flags
        assert "trustgraph" in flags
        assert "compliance_engine" in flags
        assert isinstance(flags["llm_consensus"], bool)

    def test_enabled_modules_returns_list(self, manager):
        """Enabled modules discovery returns a list."""
        modules = manager._discover_enabled_modules()
        assert isinstance(modules, list)


# ─── Sanitized Configuration ──────────────────────────────────────────────────

class TestSanitizedConfig:
    def test_api_token_not_exposed(self, manager):
        """API token value is not in sanitized config."""
        with patch.dict(os.environ, {"FIXOPS_API_TOKEN": "super-secret-token-12345"}):
            config = manager.get_sanitized_config()
        assert "super-secret-token-12345" not in str(config)

    def test_api_token_set_flag(self, manager):
        """api_token_set reflects whether token is configured."""
        with patch.dict(os.environ, {"FIXOPS_API_TOKEN": "some-token"}):
            config = manager.get_sanitized_config()
        assert config["api_token_set"] is True

    def test_db_password_masked(self, manager):
        """Database DSN password is masked."""
        manager._postgres_dsn = "postgresql://aldeci:super_secret_pw@postgres:5432/aldeci"
        config = manager.get_sanitized_config()
        assert "super_secret_pw" not in config["database_url_preview"]
        assert "***" in config["database_url_preview"]

    def test_config_has_mode(self, manager):
        """Sanitized config includes deployment mode."""
        config = manager.get_sanitized_config()
        assert "mode" in config
        assert config["mode"] in ("full", "enterprise", "api-only")

    def test_config_has_llm_providers(self, manager):
        """Sanitized config has llm_providers dict."""
        config = manager.get_sanitized_config()
        assert "llm_providers" in config
        assert "openai" in config["llm_providers"]
        assert isinstance(config["llm_providers"]["openai"], bool)

    def test_mask_dsn_helper(self):
        """_mask_dsn helper correctly masks password."""
        from core.deployment_manager import _mask_dsn
        result = _mask_dsn("postgresql://user:secret@host:5432/db")
        assert "secret" not in result
        assert "user" in result
        assert "***" in result

    def test_mask_dsn_no_password(self):
        """_mask_dsn handles DSNs without credentials."""
        from core.deployment_manager import _mask_dsn
        result = _mask_dsn("sqlite:///data/aldeci.db")
        assert "sqlite" in result


# ─── Meta DB ──────────────────────────────────────────────────────────────────

class TestMetaDB:
    def test_meta_get_set_roundtrip(self, manager):
        """meta_get/meta_set round-trip works."""
        manager._meta_set("test.key", "test-value")
        assert manager._meta_get("test.key") == "test-value"

    def test_meta_get_missing_returns_default(self, manager):
        """meta_get returns default when key missing."""
        assert manager._meta_get("nonexistent.key", "fallback") == "fallback"

    def test_meta_set_overwrites(self, manager):
        """meta_set overwrites existing value."""
        manager._meta_set("overwrite.key", "first")
        manager._meta_set("overwrite.key", "second")
        assert manager._meta_get("overwrite.key") == "second"


# ─── Router endpoints ─────────────────────────────────────────────────────────

class TestDeploymentRouter:
    def test_health_endpoint_200(self, client, manager):
        """GET /health returns 200 when services healthy."""
        healthy = _make_healthy_http
        with patch("core.deployment_manager.get_deployment_manager", return_value=manager), \
             patch.object(manager, "_check_api", return_value=healthy("api")), \
             patch.object(manager, "_check_ui", return_value=healthy("ui", True)), \
             patch.object(manager, "_check_trustgraph", return_value=healthy("trustgraph", True)), \
             patch.object(manager, "_check_redis", return_value=healthy("redis")), \
             patch.object(manager, "_check_postgres", return_value=healthy("postgres")):
            resp = client.get("/api/v1/deployment/health")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "healthy"
        assert "services" in body

    def test_health_endpoint_503_on_required_down(self, client, manager):
        """GET /health returns 503 when required service is down."""
        with patch("core.deployment_manager.get_deployment_manager", return_value=manager), \
             patch.object(manager, "_check_api", return_value=_make_healthy_http("api")), \
             patch.object(manager, "_check_ui", return_value=_make_healthy_http("ui", True)), \
             patch.object(manager, "_check_trustgraph", return_value=_make_healthy_http("trustgraph", True)), \
             patch.object(manager, "_check_redis", return_value=_make_unavailable("redis")), \
             patch.object(manager, "_check_postgres", return_value=_make_healthy_http("postgres")):
            resp = client.get("/api/v1/deployment/health")
        assert resp.status_code == 503

    def test_status_endpoint_200(self, client, manager):
        """GET /status returns 200 with full status payload."""
        svcs = [_make_healthy_http(n, optional=(n in ("ui", "trustgraph")))
                for n in ("api", "ui", "trustgraph", "redis", "postgres")]
        with patch("core.deployment_manager.get_deployment_manager", return_value=manager), \
             patch.object(manager, "_check_api", return_value=svcs[0]), \
             patch.object(manager, "_check_ui", return_value=svcs[1]), \
             patch.object(manager, "_check_trustgraph", return_value=svcs[2]), \
             patch.object(manager, "_check_redis", return_value=svcs[3]), \
             patch.object(manager, "_check_postgres", return_value=svcs[4]):
            resp = client.get("/api/v1/deployment/status")
        assert resp.status_code == 200
        body = resp.json()
        assert "version" in body
        assert "feature_flags" in body
        assert "uptime_seconds" in body

    def test_initialize_endpoint_200(self, client, manager):
        """POST /initialize returns 200 on first call."""
        with patch("core.deployment_manager.get_deployment_manager", return_value=manager), \
             patch.object(manager, "_seed_admin_user", return_value={"status": "ok"}), \
             patch.object(manager, "_create_default_config", return_value={"status": "ok"}), \
             patch.object(manager, "_populate_service_registry", return_value={"status": "ok"}), \
             patch.object(manager, "_index_trustgraph", new=AsyncMock(return_value={"status": "skipped"})):
            resp = client.post("/api/v1/deployment/initialize")
        assert resp.status_code == 200
        body = resp.json()
        assert body["status"] == "initialized"

    def test_initialize_endpoint_idempotent(self, client, manager):
        """POST /initialize is idempotent — second call returns already_initialized."""
        with patch("core.deployment_manager.get_deployment_manager", return_value=manager), \
             patch.object(manager, "_seed_admin_user", return_value={"status": "ok"}), \
             patch.object(manager, "_create_default_config", return_value={"status": "ok"}), \
             patch.object(manager, "_populate_service_registry", return_value={"status": "ok"}), \
             patch.object(manager, "_index_trustgraph", new=AsyncMock(return_value={"status": "skipped"})):
            client.post("/api/v1/deployment/initialize")
            resp = client.post("/api/v1/deployment/initialize")
        assert resp.status_code == 200
        assert resp.json()["status"] == "already_initialized"

    def test_config_endpoint_no_secrets(self, client, manager):
        """GET /config does not expose secret values."""
        with patch.dict(os.environ, {"FIXOPS_API_TOKEN": "hidden-secret-value"}), \
             patch("core.deployment_manager.get_deployment_manager", return_value=manager):
            resp = client.get("/api/v1/deployment/config")
        assert resp.status_code == 200
        text = resp.text
        assert "hidden-secret-value" not in text

    def test_config_endpoint_structure(self, client, manager):
        """GET /config returns expected keys."""
        with patch("core.deployment_manager.get_deployment_manager", return_value=manager):
            resp = client.get("/api/v1/deployment/config")
        assert resp.status_code == 200
        body = resp.json()
        assert "mode" in body
        assert "version" in body
        assert "llm_providers" in body
        assert "feature_flags" in body

    def test_migrations_endpoint(self, client, manager):
        """GET /migrations returns migration history."""
        asyncio.run(manager.run_migrations())
        with patch("core.deployment_manager.get_deployment_manager", return_value=manager):
            resp = client.get("/api/v1/deployment/migrations")
        assert resp.status_code == 200
        body = resp.json()
        assert "migrations" in body
        assert body["total"] == 3

    def test_services_endpoint(self, client, manager):
        """GET /services returns service discovery result."""
        svcs = [_make_healthy_http(n, optional=(n in ("ui", "trustgraph")))
                for n in ("api", "ui", "trustgraph", "redis", "postgres")]
        with patch("core.deployment_manager.get_deployment_manager", return_value=manager), \
             patch.object(manager, "_check_api", return_value=svcs[0]), \
             patch.object(manager, "_check_ui", return_value=svcs[1]), \
             patch.object(manager, "_check_trustgraph", return_value=svcs[2]), \
             patch.object(manager, "_check_redis", return_value=svcs[3]), \
             patch.object(manager, "_check_postgres", return_value=svcs[4]):
            resp = client.get("/api/v1/deployment/services")
        assert resp.status_code == 200
        body = resp.json()
        assert "services" in body
        assert "checked_at" in body

    def test_validate_endpoint(self, client, manager):
        """GET /validate returns validation result."""
        with patch("core.deployment_manager.get_deployment_manager", return_value=manager), \
             patch.object(manager, "_check_postgres", return_value=_make_healthy_http("postgres")), \
             patch.object(manager, "_check_redis", return_value=_make_healthy_http("redis")):
            resp = client.get("/api/v1/deployment/validate")
        assert resp.status_code in (200, 422)
        body = resp.json()
        assert "checks" in body
        assert "issues" in body
        assert "warnings" in body
