"""Tests: simulated engines emit warnings and API responses carry _simulation_warning.

Covers:
- Importing devsecops_engine / cloud_drift_engine logs the SIMULATION warning
- devsecops_router endpoints return _simulation_warning.is_simulated=True
- cloud_drift_router endpoints return _simulation_warning.is_simulated=True
- Warning includes the connector path for the real integration
"""

from __future__ import annotations

import importlib
import logging
import sys
import types
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reimport(module_name: str):
    """Force a fresh module import (removes cached entry first)."""
    sys.modules.pop(module_name, None)
    # Also remove sub-dependency that may cache it
    for key in list(sys.modules):
        if key.startswith(module_name):
            sys.modules.pop(key, None)
    return importlib.import_module(module_name)


# ---------------------------------------------------------------------------
# 1. Module-level startup warning logs
# ---------------------------------------------------------------------------

class TestStartupWarningLogs:
    def test_devsecops_engine_logs_simulation_warning(self, caplog):
        """Importing devsecops_engine must emit a SIMULATION warning."""
        # Stub trustgraph to avoid real DB/import chains
        fake_tg = types.ModuleType("core.trustgraph_event_bus")
        fake_tg.get_event_bus = lambda: None
        sys.modules.setdefault("core.trustgraph_event_bus", fake_tg)

        with caplog.at_level(logging.WARNING, logger="core.devsecops_engine"):
            _reimport("core.devsecops_engine")

        assert any(
            "SIMULATION mode" in r.message for r in caplog.records
        ), "Expected SIMULATION mode warning when devsecops_engine is imported"

    def test_cloud_drift_engine_logs_simulation_warning(self, caplog):
        """Importing cloud_drift_engine must emit a SIMULATION warning."""
        fake_tg = types.ModuleType("core.trustgraph_event_bus")
        fake_tg.get_event_bus = lambda: None
        sys.modules.setdefault("core.trustgraph_event_bus", fake_tg)

        with caplog.at_level(logging.WARNING, logger="core.cloud_drift_engine"):
            _reimport("core.cloud_drift_engine")

        assert any(
            "SIMULATION mode" in r.message for r in caplog.records
        ), "Expected SIMULATION mode warning when cloud_drift_engine is imported"

    def test_devsecops_warning_mentions_connectors(self, caplog):
        """Startup warning must reference the real connector path."""
        fake_tg = types.ModuleType("core.trustgraph_event_bus")
        fake_tg.get_event_bus = lambda: None
        sys.modules.setdefault("core.trustgraph_event_bus", fake_tg)

        with caplog.at_level(logging.WARNING, logger="core.devsecops_engine"):
            _reimport("core.devsecops_engine")

        combined = " ".join(r.message for r in caplog.records)
        assert "/api/v1/connectors/" in combined

    def test_cloud_drift_warning_mentions_connectors(self, caplog):
        """Startup warning must reference the real connector path."""
        fake_tg = types.ModuleType("core.trustgraph_event_bus")
        fake_tg.get_event_bus = lambda: None
        sys.modules.setdefault("core.trustgraph_event_bus", fake_tg)

        with caplog.at_level(logging.WARNING, logger="core.cloud_drift_engine"):
            _reimport("core.cloud_drift_engine")

        combined = " ".join(r.message for r in caplog.records)
        assert "/api/v1/connectors/" in combined


# ---------------------------------------------------------------------------
# 2. Router _wrap helper — unit tests (no HTTP layer needed)
# ---------------------------------------------------------------------------

class TestDevsecopsRouterWrap:
    def _get_wrap(self):
        """Import _wrap from devsecops_router without triggering engine load."""
        import importlib
        # Ensure the router module is importable (auth_deps mock if needed)
        sys.modules.setdefault("apps.api.auth_deps", types.ModuleType("apps.api.auth_deps"))
        sys.modules["apps.api.auth_deps"].api_key_auth = lambda: None  # type: ignore
        mod = importlib.import_module("apps.api.devsecops_router")
        return mod._wrap

    def test_wrap_sets_is_simulated_true(self):
        wrap = self._get_wrap()
        result = wrap({"foo": "bar"})
        assert result["_simulation_warning"]["is_simulated"] is True

    def test_wrap_engine_name(self):
        wrap = self._get_wrap()
        result = wrap([])
        assert result["_simulation_warning"]["engine"] == "devsecops_engine"

    def test_wrap_do_not_use_in_demo(self):
        wrap = self._get_wrap()
        result = wrap({})
        assert result["_simulation_warning"]["do_not_use_in_demo"] is True

    def test_wrap_real_integration_required_contains_connectors(self):
        wrap = self._get_wrap()
        result = wrap({})
        assert "/api/v1/connectors/" in result["_simulation_warning"]["real_integration_required"]

    def test_wrap_preserves_data(self):
        wrap = self._get_wrap()
        payload = {"runs": [1, 2, 3], "total": 3}
        result = wrap(payload)
        assert result["data"] == payload


class TestCloudDriftRouterWrap:
    def _get_wrap(self):
        sys.modules.setdefault("apps.api.auth_deps", types.ModuleType("apps.api.auth_deps"))
        sys.modules["apps.api.auth_deps"].api_key_auth = lambda: None  # type: ignore
        import importlib
        mod = importlib.import_module("apps.api.cloud_drift_router")
        return mod._wrap

    def test_wrap_sets_is_simulated_true(self):
        wrap = self._get_wrap()
        result = wrap({"drifts": []})
        assert result["_simulation_warning"]["is_simulated"] is True

    def test_wrap_engine_name(self):
        wrap = self._get_wrap()
        result = wrap({})
        assert result["_simulation_warning"]["engine"] == "cloud_drift_engine"

    def test_wrap_do_not_use_in_demo(self):
        wrap = self._get_wrap()
        result = wrap({})
        assert result["_simulation_warning"]["do_not_use_in_demo"] is True

    def test_wrap_real_integration_required_contains_cspm(self):
        wrap = self._get_wrap()
        result = wrap({})
        assert "cspm" in result["_simulation_warning"]["real_integration_required"]

    def test_wrap_preserves_data(self):
        wrap = self._get_wrap()
        payload = {"baselines": [], "total": 0}
        result = wrap(payload)
        assert result["data"] == payload


# ---------------------------------------------------------------------------
# 3. Docstring header present in engine files
# ---------------------------------------------------------------------------

class TestEngineDocstringWarning:
    def test_devsecops_engine_docstring_has_simulated_marker(self):
        import core.devsecops_engine as mod
        doc = mod.__doc__ or ""
        assert "SIMULATED DATA" in doc

    def test_cloud_drift_engine_docstring_has_simulated_marker(self):
        import core.cloud_drift_engine as mod
        doc = mod.__doc__ or ""
        assert "SIMULATED DATA" in doc

    def test_devsecops_engine_docstring_has_connector_path(self):
        import core.devsecops_engine as mod
        doc = mod.__doc__ or ""
        assert "/api/v1/connectors/" in doc

    def test_cloud_drift_engine_docstring_has_connector_path(self):
        import core.cloud_drift_engine as mod
        doc = mod.__doc__ or ""
        assert "/api/v1/connectors/" in doc
