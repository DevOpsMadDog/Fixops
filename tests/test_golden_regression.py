# ruff: noqa: E402
"""Golden regression validation tests.

These tests exercise ``DecisionEngine._real_golden_regression_validation``
and ``GoldenRegressionStore``.  Lightweight in-process stubs replace the
real database / cache / settings modules so the tests run without Redis,
PostgreSQL, or external config.
"""

import asyncio
import sys
import types

import pytest

# ---------------------------------------------------------------------------
# Lightweight stubs for heavy infrastructure modules
# ---------------------------------------------------------------------------

if "structlog" not in sys.modules:
    _structlog = types.ModuleType("structlog")

    class _Logger:
        def __getattr__(self, _name):
            def _noop(*_a, **_kw):
                return None

            return _noop

    def _get_logger(*_a, **_kw):
        return _Logger()

    _structlog.get_logger = _get_logger
    sys.modules["structlog"] = _structlog

# config.enterprise.settings — pydantic-free stub
if "config.enterprise.settings" not in sys.modules:
    _cfg_pkg = sys.modules.setdefault("config", types.ModuleType("config"))
    _cfg_ent = types.ModuleType("config.enterprise")
    _cfg_pkg.enterprise = _cfg_ent
    sys.modules["config.enterprise"] = _cfg_ent

    _settings_mod = types.ModuleType("config.enterprise.settings")

    class _Settings:
        DEMO_MODE = False
        EMERGENT_LLM_KEY = None
        VECTOR_DB_URL = None
        SECURITY_PATTERNS_DB_URL = None
        JIRA_URL = None
        JIRA_USERNAME = None
        JIRA_API_TOKEN = None
        CONFLUENCE_URL = None
        CONFLUENCE_USERNAME = None
        CONFLUENCE_API_TOKEN = None
        THREAT_INTEL_API_KEY = None
        DEMO_VECTOR_DB_PATTERNS = 0
        DEMO_GOLDEN_REGRESSION_CASES = 0
        DEMO_BUSINESS_CONTEXTS = 0

    def _get_settings():
        return _Settings()

    _settings_mod.get_settings = _get_settings
    _settings_mod.Settings = _Settings
    _cfg_ent.settings = _settings_mod
    sys.modules["config.enterprise.settings"] = _settings_mod

# core.services.enterprise.cache_service — in-memory no-op
if "core.services.enterprise.cache_service" not in sys.modules:
    _cache_mod = types.ModuleType("core.services.enterprise.cache_service")

    class _CacheService:
        _instance = None

        @classmethod
        def get_instance(cls):
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

        async def get(self, *_a, **_kw):
            return None

        async def set(self, *_a, **_kw):
            return None

    _cache_mod.CacheService = _CacheService
    sys.modules["core.services.enterprise.cache_service"] = _cache_mod

# core.db.enterprise.session — no-op database manager
if "core.db.enterprise.session" not in sys.modules:
    _db_pkg = sys.modules.setdefault("core.db", types.ModuleType("core.db"))
    _db_ent = types.ModuleType("core.db.enterprise")
    _db_pkg.enterprise = _db_ent
    sys.modules["core.db.enterprise"] = _db_ent

    _session_mod = types.ModuleType("core.db.enterprise.session")

    class _AsyncSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_a):
            return False

        async def commit(self):
            return None

        async def rollback(self):
            return None

        async def close(self):
            return None

    class _DatabaseManager:
        @classmethod
        async def get_session(cls):
            return _AsyncSession()

        @classmethod
        async def get_session_context(cls):
            return _AsyncSession()

    _session_mod.DatabaseManager = _DatabaseManager
    sys.modules["core.db.enterprise.session"] = _session_mod

# ---------------------------------------------------------------------------
from core.services.enterprise.decision_engine import DecisionContext, DecisionEngine
from core.services.enterprise.golden_regression_store import GoldenRegressionStore


@pytest.fixture(autouse=True)
def reset_golden_regression_store():
    GoldenRegressionStore.reset_instance()
    yield
    GoldenRegressionStore.reset_instance()


def test_store_lookup_matches_service_and_cve():
    store = GoldenRegressionStore.get_instance()

    lookup = store.lookup_cases(
        service_name="payment-service", cve_ids=["CVE-2024-1111"]
    )

    assert lookup["service_matches"] == 2
    assert lookup["cve_matches"] == {"CVE-2024-1111": 1}

    case_ids = {case["case_id"] for case in lookup["cases"]}
    assert case_ids == {"payment-2024-01", "payment-2024-02"}

    context_map = {case["case_id"]: case["match_context"] for case in lookup["cases"]}
    assert {entry["type"] for entry in context_map["payment-2024-01"]} == {
        "service",
        "cve",
    }
    assert {entry["type"] for entry in context_map["payment-2024-02"]} == {"service"}


def test_regression_validation_passes_with_historical_support():
    engine = DecisionEngine()
    context = DecisionContext(
        service_name="payment-service",
        environment="production",
        business_context={},
        security_findings=[{"cve": "CVE-2024-1111"}],
    )

    result = asyncio.run(engine._real_golden_regression_validation(context))

    assert result["status"] == "validated"
    assert result["validation_passed"] is True
    assert result["counts"]["total_matches"] == 2
    assert result["counts"]["passes"] == 2
    assert result["coverage"]["service"] is True
    assert result["coverage"]["cves"]["CVE-2024-1111"] is True


def test_regression_validation_surfaces_failures():
    engine = DecisionEngine()
    context = DecisionContext(
        service_name="inventory-service",
        environment="production",
        business_context={},
        security_findings=[{"cve_id": "CVE-2024-3333"}],
    )

    result = asyncio.run(engine._real_golden_regression_validation(context))

    assert result["status"] == "regression_failed"
    assert result["validation_passed"] is False
    assert result["counts"]["failures"] == 1
    assert result["failures"][0]["case_id"] == "inventory-2023-05"
    assert result["coverage"]["service"] is True
    assert result["coverage"]["cves"]["CVE-2024-3333"] is True


def test_regression_validation_handles_missing_coverage():
    engine = DecisionEngine()
    context = DecisionContext(
        service_name="unknown-service",
        environment="production",
        business_context={},
        security_findings=[{"cve": "CVE-0000-0000"}],
    )

    result = asyncio.run(engine._real_golden_regression_validation(context))

    assert result["status"] == "no_coverage"
    assert result["validation_passed"] is False
    assert result["counts"]["total_matches"] == 0
    assert result["coverage"]["service"] is False
    assert result["coverage"]["cves"]["CVE-0000-0000"] is False
