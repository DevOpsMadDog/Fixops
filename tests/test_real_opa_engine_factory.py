from __future__ import annotations

import pytest
from src.services import real_opa_engine
from src.services.real_opa_engine import (
    DemoOPAEngine,
    OPAEngineFactory,
    ProductionOPAEngine,
)


class _Settings:
    DEMO_MODE = False
    OPA_SERVER_URL = "http://opa:8181"
    OPA_POLICY_PACKAGE = "fixops"
    OPA_HEALTH_PATH = "/health"
    OPA_BUNDLE_STATUS_PATH = None
    OPA_AUTH_TOKEN = None
    OPA_REQUEST_TIMEOUT = 5


def test_factory_uses_production_engine(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(real_opa_engine, "get_settings", lambda: _Settings())
    engine = OPAEngineFactory.create()
    assert isinstance(engine, ProductionOPAEngine)


def test_factory_returns_demo_when_flag_enabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class DemoSettings(_Settings):
        DEMO_MODE = True

    monkeypatch.setattr(real_opa_engine, "get_settings", lambda: DemoSettings())
    engine = OPAEngineFactory.create()
    assert isinstance(engine, DemoOPAEngine)
