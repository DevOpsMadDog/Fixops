# ruff: noqa: E402

import asyncio
import sys
from pathlib import Path

import types

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1] / "fixops-blended-enterprise"
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

if "structlog" not in sys.modules:
    structlog_stub = types.ModuleType("structlog")

    class _Logger:
        def __getattr__(self, _name):
            def _noop(*_args, **_kwargs):
                return None

            return _noop

    def get_logger(*_args, **_kwargs):
        return _Logger()

    structlog_stub.get_logger = get_logger
    sys.modules["structlog"] = structlog_stub

if "src.config.settings" not in sys.modules:
    settings_module = types.ModuleType("src.config.settings")

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

    def get_settings():
        return _Settings()

    settings_module.get_settings = get_settings
    sys.modules["src.config.settings"] = settings_module
    config_package = sys.modules.setdefault("src.config", types.ModuleType("src.config"))
    config_package.settings = settings_module

if "src.services.cache_service" not in sys.modules:
    cache_module = types.ModuleType("src.services.cache_service")

    class CacheService:
        _instance = None

        @classmethod
        def get_instance(cls):
            if cls._instance is None:
                cls._instance = cls()
            return cls._instance

        async def get(self, *_args, **_kwargs):
            return None

        async def set(self, *_args, **_kwargs):
            return None

    cache_module.CacheService = CacheService
    sys.modules["src.services.cache_service"] = cache_module

if "src.db.session" not in sys.modules:
    session_module = types.ModuleType("src.db.session")

    class _AsyncSession:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def commit(self):
            return None

        async def rollback(self):
            return None

        async def close(self):
            return None

    class DatabaseManager:
        @classmethod
        async def get_session(cls):
            return _AsyncSession()

        @classmethod
        async def get_session_context(cls):
            return _AsyncSession()

    session_module.DatabaseManager = DatabaseManager
    sys.modules["src.db.session"] = session_module

from src.services.decision_engine import DecisionContext, DecisionEngine
from src.services.golden_regression_store import GoldenRegressionStore


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
    assert {entry["type"] for entry in context_map["payment-2024-01"]} == {"service", "cve"}
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
