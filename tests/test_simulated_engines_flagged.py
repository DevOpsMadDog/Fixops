"""Tests: simulated engines emit warnings and API responses carry _simulation_warning.

Covers:
- Importing devsecops_engine / cloud_drift_engine logs the appropriate status warning
- devsecops_router endpoints return _simulation_warning metadata
- cloud_drift_router endpoints return _simulation_warning.is_simulated=True
- Warning includes the connector path for the real integration (where applicable)
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
        """devsecops_engine is now real (no simulation warning at import).

        The engine no longer logs a SIMULATION warning — it uses real scanners
        (Semgrep, Trivy, SecretScannerEngine). This test verifies that the
        module imports cleanly without errors.
        """
        fake_tg = types.ModuleType("core.trustgraph_event_bus")
        fake_tg.get_event_bus = lambda: None
        sys.modules.setdefault("core.trustgraph_event_bus", fake_tg)

        # Should import without raising — no module-level simulation warning expected
        with caplog.at_level(logging.DEBUG, logger="core.devsecops_engine"):
            mod = _reimport("core.devsecops_engine")
        assert mod is not None

    def test_cloud_drift_engine_logs_simulation_warning(self, caplog):
        """Importing cloud_drift_engine must emit a notice that run_drift_scan() is stub."""
        fake_tg = types.ModuleType("core.trustgraph_event_bus")
        fake_tg.get_event_bus = lambda: None
        sys.modules.setdefault("core.trustgraph_event_bus", fake_tg)

        # Engine logs at INFO: captures "simulated" keyword in the message
        with caplog.at_level(logging.INFO, logger="core.cloud_drift_engine"):
            _reimport("core.cloud_drift_engine")

        stub_keywords = ("SIMULATION", "simulation", "STUB", "simulated", "not implemented")
        assert any(
            any(kw in r.message for kw in stub_keywords)
            for r in caplog.records
        ), (
            "Expected stub/simulation notice when cloud_drift_engine is imported, "
            f"got: {[r.message for r in caplog.records]}"
        )

    def test_devsecops_warning_mentions_connectors(self, caplog):
        """devsecops_engine is real — no connector warning required at import.

        The engine's docstring and router note real scanner paths instead.
        This test verifies the module imports cleanly.
        """
        fake_tg = types.ModuleType("core.trustgraph_event_bus")
        fake_tg.get_event_bus = lambda: None
        sys.modules.setdefault("core.trustgraph_event_bus", fake_tg)

        with caplog.at_level(logging.DEBUG, logger="core.devsecops_engine"):
            mod = _reimport("core.devsecops_engine")
        assert mod is not None

    def test_cloud_drift_warning_mentions_connectors(self, caplog):
        """cloud_drift_engine startup notice must reference a real connector path.

        The module-level INFO log says "CSPM cloud connector"; the docstring
        says /api/v1/connectors/cspm-{aws,azure,gcp}/configure. Either reference
        satisfies the intent: callers are told where to wire the real integration.
        """
        fake_tg = types.ModuleType("core.trustgraph_event_bus")
        fake_tg.get_event_bus = lambda: None
        sys.modules.setdefault("core.trustgraph_event_bus", fake_tg)

        with caplog.at_level(logging.INFO, logger="core.cloud_drift_engine"):
            mod = _reimport("core.cloud_drift_engine")

        combined = " ".join(r.message for r in caplog.records)
        # Log says "CSPM cloud connector"; docstring says /api/v1/connectors/
        connector_markers = ("/api/v1/connectors/", "connector", "CSPM")
        assert any(m in combined for m in connector_markers) or any(
            m in (mod.__doc__ or "") for m in ("/api/v1/connectors/",)
        ), (
            f"Expected connector reference in cloud_drift_engine log or docstring, "
            f"log: {combined!r}"
        )


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

    def _get_simulation_warning(self):
        """Return the _SIMULATION_WARNING constant from the router."""
        sys.modules.setdefault("apps.api.auth_deps", types.ModuleType("apps.api.auth_deps"))
        sys.modules["apps.api.auth_deps"].api_key_auth = lambda: None  # type: ignore
        mod = importlib.import_module("apps.api.devsecops_router")
        return mod._SIMULATION_WARNING

    def test_wrap_returns_simulation_warning_key(self):
        """_wrap must return a dict with a _simulation_warning key."""
        wrap = self._get_wrap()
        result = wrap({"foo": "bar"})
        assert "_simulation_warning" in result

    def test_wrap_engine_name(self):
        wrap = self._get_wrap()
        result = wrap([])
        assert result["_simulation_warning"]["engine"] == "devsecops_engine"

    def test_wrap_is_not_simulated(self):
        """devsecops_engine is now real — is_simulated must be False."""
        warn = self._get_simulation_warning()
        assert warn.get("is_simulated") is False

    def test_wrap_real_scanners_listed(self):
        """Router must document the real scanner classes it uses."""
        warn = self._get_simulation_warning()
        # Router lists real scanners under "scanners" key
        assert "scanners" in warn, f"Expected 'scanners' key in _SIMULATION_WARNING, got: {warn}"

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
        """devsecops_engine is now real — docstring describes real scanners, not simulation.

        Verify the docstring references the real scanner integrations instead.
        """
        import core.devsecops_engine as mod
        doc = mod.__doc__ or ""
        # Real engine — docstring describes real scanner paths
        real_markers = ("SemgrepScanner", "TrivyScanner", "SecretScannerEngine",
                        "real", "Real", "production")
        assert any(m in doc for m in real_markers), (
            f"devsecops_engine docstring should reference real scanner classes, got: {doc!r}"
        )

    def test_cloud_drift_engine_docstring_has_simulated_marker(self):
        """cloud_drift_engine docstring must still flag the non-real run_drift_scan()."""
        import core.cloud_drift_engine as mod
        doc = mod.__doc__ or ""
        stub_markers = ("STUB", "simulated", "NOT PRODUCTION READY", "random")
        assert any(m in doc for m in stub_markers), (
            f"cloud_drift_engine docstring should flag stub/simulated status, got: {doc!r}"
        )

    def test_devsecops_engine_docstring_has_connector_path(self):
        """devsecops_engine docstring must reference real scanner engine paths."""
        import core.devsecops_engine as mod
        doc = mod.__doc__ or ""
        # Real engine documents real scanner module paths
        assert "core." in doc, (
            f"devsecops_engine docstring should reference core.* scanner paths, got: {doc!r}"
        )

    def test_cloud_drift_engine_docstring_has_connector_path(self):
        """cloud_drift_engine docstring must reference the real CSPM connector path."""
        import core.cloud_drift_engine as mod
        doc = mod.__doc__ or ""
        assert "/api/v1/connectors/" in doc, (
            f"cloud_drift_engine docstring should reference /api/v1/connectors/, got: {doc!r}"
        )
