"""Smoke tests for suite-core/core OWASP hardening fixes.

Verifies:
1. aldeci_client — no hardcoded API key in docstring example
2. webhook_notifier — no hardcoded secret; os import present
3. deployment_manager — no hardcoded password in live code path
"""
from __future__ import annotations

import importlib
import inspect
import os


def test_aldeci_client_no_hardcoded_key():
    """Hardcoded key 'fixops_ent_...' must not appear in aldeci_client source."""
    import core.aldeci_client as mod  # noqa: PLC0415

    src = inspect.getsource(mod)
    assert "fixops_ent_38wJA8mb7CsbJ3PaLvKNz7lFnLWvFWXti" not in src, (
        "Hardcoded API key still present in aldeci_client.py"
    )


def test_aldeci_client_imports():
    """ALDECIClient must be importable and instantiable without crashing."""
    from core.aldeci_client import ALDECIClient  # noqa: PLC0415

    client = ALDECIClient(base_url="http://localhost:9999", api_key="test-key")
    assert client.base_url == "http://localhost:9999"


def test_webhook_notifier_no_hardcoded_secret():
    """Literal 'super-secret' must not appear in webhook_notifier source."""
    import core.webhook_notifier as mod  # noqa: PLC0415

    src = inspect.getsource(mod)
    assert 'secret="super-secret"' not in src, (
        "Hardcoded webhook secret still present in webhook_notifier.py"
    )


def test_webhook_notifier_has_os_import():
    """webhook_notifier must import os (required for os.getenv)."""
    import core.webhook_notifier as mod  # noqa: PLC0415

    src = inspect.getsource(mod)
    assert "import os" in src, "os not imported in webhook_notifier.py"


def test_deployment_manager_no_hardcoded_password():
    """Literal 'change-me-on-first-login' must not appear in deployment_manager source."""
    import core.deployment_manager as mod  # noqa: PLC0415

    src = inspect.getsource(mod)
    assert 'password="change-me-on-first-login"' not in src, (
        "Hardcoded admin password still present in deployment_manager.py"
    )
