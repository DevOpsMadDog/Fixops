from __future__ import annotations

import pytest


def test_production_requires_allowed_origins(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ENVIRONMENT", "production")
    monkeypatch.delenv("FIXOPS_ALLOWED_ORIGINS", raising=False)
    monkeypatch.setenv("ALLOWED_HOSTS", "fixops.local")
    monkeypatch.setenv("CORS_ORIGINS", "https://demo.fixops.local")

    from config.enterprise import settings as settings_module

    settings_module.get_settings.cache_clear()
    config = settings_module.get_settings()

    with pytest.raises(RuntimeError):
        settings_module.resolve_allowed_origins(config)

    monkeypatch.setenv("FIXOPS_ALLOWED_ORIGINS", "https://prod.fixops.local")
    settings_module.get_settings.cache_clear()
    config = settings_module.get_settings()

    allowed = settings_module.resolve_allowed_origins(config)
    assert allowed == ["https://prod.fixops.local"]
