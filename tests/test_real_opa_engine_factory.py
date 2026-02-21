from __future__ import annotations

import pytest
from core.services.enterprise import real_opa_engine
from core.services.enterprise.real_opa_engine import (
    LocalOPAEngine,
    OPAEngineFactory,
    ProductionOPAEngine,
)


class _Settings:
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


def test_factory_returns_local_when_no_opa_url(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class NoOPASettings(_Settings):
        OPA_SERVER_URL = None

    monkeypatch.setattr(real_opa_engine, "get_settings", lambda: NoOPASettings())
    engine = OPAEngineFactory.create()
    assert isinstance(engine, LocalOPAEngine)
