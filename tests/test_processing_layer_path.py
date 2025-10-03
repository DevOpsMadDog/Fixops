"""Integration coverage ensuring the processing layer executes in production mode."""

from __future__ import annotations

import asyncio
import os
import importlib
import sys
import types
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "fixops-blended-enterprise"))


def _ensure_structlog_stub() -> None:
    if "structlog" in sys.modules:
        return

    structlog_stub = types.ModuleType("structlog")

    class _Logger:
        def bind(self, **kwargs):  # pragma: no cover - simple stub
            return self

        def info(self, *args, **kwargs):  # pragma: no cover - simple stub
            return None

        def warning(self, *args, **kwargs):  # pragma: no cover - simple stub
            return None

        def error(self, *args, **kwargs):  # pragma: no cover - simple stub
            return None

    structlog_stub.get_logger = lambda *args, **kwargs: _Logger()
    sys.modules["structlog"] = structlog_stub


def _ensure_redis_stub() -> None:
    try:
        import redis.asyncio  # type: ignore  # noqa: F401
    except ModuleNotFoundError:  # pragma: no cover - executed in minimal envs
        redis_pkg = types.ModuleType("redis")
        redis_async = types.ModuleType("redis.asyncio")
        redis_connection = types.ModuleType("redis.asyncio.connection")

        class _ConnectionPool:
            @classmethod
            def from_url(cls, *args, **kwargs):  # pragma: no cover - simple stub
                return cls()

            async def disconnect(self):  # pragma: no cover - simple stub
                return None

        class _Redis:
            def __init__(self, *args, **kwargs):
                self._store: dict[str, object] = {}

            async def ping(self):  # pragma: no cover - simple stub
                raise ConnectionError("redis library not available; using in-memory cache")

            async def set(self, key, value, ex=None, nx=False):  # pragma: no cover
                if nx and key in self._store:
                    return False
                self._store[key] = value
                return True

            async def get(self, key):  # pragma: no cover - simple stub
                return self._store.get(key)

            async def delete(self, key):  # pragma: no cover - simple stub
                return 1 if self._store.pop(key, None) is not None else 0

            async def close(self):  # pragma: no cover - simple stub
                self._store.clear()
                return None

        redis_connection.ConnectionPool = _ConnectionPool
        redis_async.Redis = _Redis
        redis_async.ConnectionPool = _ConnectionPool
        redis_async.connection = redis_connection
        redis_pkg.asyncio = redis_async

        sys.modules["redis"] = redis_pkg
        sys.modules["redis.asyncio"] = redis_async
        sys.modules["redis.asyncio.connection"] = redis_connection


def _ensure_orjson_stub() -> None:
    try:
        import orjson  # type: ignore  # noqa: F401
    except ModuleNotFoundError:  # pragma: no cover - executed in minimal envs
        import json as _json

        orjson_stub = types.ModuleType("orjson")
        orjson_stub.loads = _json.loads
        orjson_stub.dumps = lambda value: _json.dumps(value).encode("utf-8")
        orjson_stub.JSONDecodeError = _json.JSONDecodeError
        sys.modules["orjson"] = orjson_stub


def _ensure_sqlalchemy_stub() -> None:
    try:
        import sqlalchemy  # type: ignore  # noqa: F401
        from sqlalchemy.ext.asyncio import AsyncSession  # type: ignore  # noqa: F401
    except ModuleNotFoundError:  # pragma: no cover - executed in minimal envs
        sqlalchemy_pkg = types.ModuleType("sqlalchemy")
        sqlalchemy_ext = types.ModuleType("sqlalchemy.ext")
        sqlalchemy_asyncio = types.ModuleType("sqlalchemy.ext.asyncio")
        sqlalchemy_pool = types.ModuleType("sqlalchemy.pool")

        class _AsyncSession:
            async def execute(self, query):  # pragma: no cover - simple stub
                class _Result:
                    def scalar(self):
                        return 1

                return _Result()

            async def commit(self):  # pragma: no cover - simple stub
                return None

            async def rollback(self):  # pragma: no cover - simple stub
                return None

            async def close(self):  # pragma: no cover - simple stub
                return None

        class _SessionFactory:
            def __call__(self, *args, **kwargs):  # pragma: no cover - simple stub
                return _AsyncSession()

        def async_sessionmaker(*args, **kwargs):  # pragma: no cover - simple stub
            return _SessionFactory()

        class _DummyEngine:
            def __init__(self):
                self.sync_engine = self

            async def dispose(self):  # pragma: no cover - simple stub
                return None

        def create_async_engine(*args, **kwargs):  # pragma: no cover - simple stub
            return _DummyEngine()

        class _QueuePool:  # pragma: no cover - simple stub
            pass

        def text(value):  # pragma: no cover - simple stub
            return value

        def listens_for(target, identifier):  # pragma: no cover - simple stub
            def decorator(func):
                return func

            return decorator

        event_module = types.ModuleType("sqlalchemy.event")
        event_module.listens_for = listens_for

        sqlalchemy_pkg.event = event_module
        sqlalchemy_pkg.text = text
        sqlalchemy_ext.asyncio = sqlalchemy_asyncio
        sqlalchemy_pkg.ext = sqlalchemy_ext
        sqlalchemy_asyncio.AsyncSession = _AsyncSession
        sqlalchemy_asyncio.async_sessionmaker = async_sessionmaker
        sqlalchemy_asyncio.create_async_engine = create_async_engine
        sqlalchemy_pool.QueuePool = _QueuePool

        sys.modules["sqlalchemy"] = sqlalchemy_pkg
        sys.modules["sqlalchemy.ext"] = sqlalchemy_ext
        sys.modules["sqlalchemy.ext.asyncio"] = sqlalchemy_asyncio
        sys.modules["sqlalchemy.pool"] = sqlalchemy_pool
        sys.modules["sqlalchemy.event"] = event_module


def _ensure_pydantic_stubs() -> None:
    try:
        import pydantic_settings  # type: ignore  # noqa: F401
    except ModuleNotFoundError:  # pragma: no cover - executed in minimal envs
        settings_module = types.ModuleType("pydantic_settings")

        class BaseSettings:
            def __init__(self, **overrides):  # pragma: no cover - simple stub
                for name, value in self.__class__.__dict__.items():
                    if name.startswith("_") or callable(value):
                        continue
                    env_value = os.getenv(name)
                    if env_value is not None and isinstance(value, bool):
                        parsed = env_value.lower() in {"1", "true", "yes", "on"}
                        setattr(self, name, parsed)
                    elif env_value is not None:
                        setattr(self, name, env_value)
                    else:
                        setattr(self, name, value)

                for key, val in overrides.items():
                    setattr(self, key, val)

        settings_module.BaseSettings = BaseSettings
        sys.modules["pydantic_settings"] = settings_module

    try:
        import pydantic  # type: ignore  # noqa: F401
    except ModuleNotFoundError:  # pragma: no cover - executed in minimal envs
        pydantic_module = types.ModuleType("pydantic")

        def Field(default=None, **kwargs):  # pragma: no cover - simple stub
            return default

        def field_validator(*args, **kwargs):  # pragma: no cover - simple stub
            def decorator(func):
                return func

            return decorator

        pydantic_module.Field = Field
        pydantic_module.field_validator = field_validator
        sys.modules["pydantic"] = pydantic_module


def _ensure_prometheus_stub() -> None:
    try:
        import prometheus_client  # type: ignore  # noqa: F401
    except ModuleNotFoundError:  # pragma: no cover - executed in minimal envs
        prometheus_stub = types.ModuleType("prometheus_client")

        class _Metric:
            def __init__(self, *args, **kwargs):  # pragma: no cover - simple stub
                pass

            def labels(self, *args, **kwargs):  # pragma: no cover - simple stub
                return self

            def set(self, *args, **kwargs):  # pragma: no cover - simple stub
                return None

            def inc(self, *args, **kwargs):  # pragma: no cover - simple stub
                return None

            def observe(self, *args, **kwargs):  # pragma: no cover - simple stub
                return None

        prometheus_stub.Counter = _Metric
        prometheus_stub.Gauge = _Metric
        prometheus_stub.Histogram = _Metric
        prometheus_stub.Summary = _Metric
        prometheus_stub.start_http_server = lambda *args, **kwargs: None
        prometheus_stub.CollectorRegistry = type("CollectorRegistry", (), {"__init__": lambda self, *args, **kwargs: None})

        def generate_latest(registry):  # pragma: no cover - simple stub
            return b""

        prometheus_stub.generate_latest = generate_latest

        sys.modules["prometheus_client"] = prometheus_stub


_ensure_structlog_stub()
_ensure_redis_stub()
_ensure_orjson_stub()
_ensure_sqlalchemy_stub()
_ensure_pydantic_stubs()
_ensure_prometheus_stub()


def test_processing_layer_executes_with_optional_dependencies(monkeypatch):
    monkeypatch.setenv("DEMO_MODE", "false")

    from src.config import settings as settings_module

    settings_module.get_settings.cache_clear()

    decision_engine_module = importlib.import_module("src.services.decision_engine")
    decision_engine_module = importlib.reload(decision_engine_module)

    async def _run() -> None:
        engine = decision_engine_module.DecisionEngine()
        engine.demo_mode = False
        await engine.initialize()

        assert engine.processing_layer is not None

        context = decision_engine_module.DecisionContext(
            service_name="payment-api",
            environment="production",
            business_context={
                "service_owner": "platform-security",
                "customer_impact": "high",
                "data_classification": "restricted",
                "compliance_requirements": ["PCI-DSS", "SOC2"],
            },
            security_findings=[
                {
                    "cve": "CVE-2024-3094",
                    "severity": "CRITICAL",
                    "kev_flag": True,
                    "epss_score": 0.98,
                    "fix_available": True,
                }
            ],
            threat_model={"scenarios": ["remote exploitation"]},
            sbom_data=None,
            runtime_data=None,
        )

        result = await engine.make_decision(context)

        assert result.validation_results.get("processing_layer") is True
        assert isinstance(result.validation_results.get("processing_metadata"), dict)
        assert result.validation_results["processing_metadata"].get("status") == "executed"
        assert result.validation_results["bayesian_results"]
        assert result.validation_results["markov_results"]["predictions"]
        assert "golden_regression" in result.validation_results
        assert "compliance" in result.validation_results

    asyncio.run(_run())

