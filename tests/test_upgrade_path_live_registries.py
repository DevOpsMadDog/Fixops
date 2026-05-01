"""Tests for live registry adapters + offline registry on UpgradePathResolverEngine.

Covers npm/pypi/maven live HTTP adapters (mocked), offline JSON registry
(env-driven), and the dispatch chain (live → static → offline).
"""

from __future__ import annotations

import json
import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from core import upgrade_path_resolver_engine as upr


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _clear_live_cache() -> None:
    with upr._LIVE_CACHE_LOCK:
        upr._LIVE_CACHE.clear()


@pytest.fixture(autouse=True)
def _reset_state(monkeypatch):
    """Reset module-level cache and offline env var between tests."""
    _clear_live_cache()
    monkeypatch.delenv("ALDECI_OFFLINE_REGISTRY_PATH", raising=False)
    yield
    _clear_live_cache()


# ---------------------------------------------------------------------------
# Live adapter tests
# ---------------------------------------------------------------------------


def test_npm_live_returns_versions():
    adapter = upr.NpmLiveAdapter()
    fake_resp = MagicMock()
    fake_resp.json.return_value = {
        "name": "lodash",
        "versions": {"4.17.20": {}, "4.17.21": {}, "5.0.0": {}},
    }
    with patch("requests.get", return_value=fake_resp) as mock_get:
        versions = adapter.get_versions("lodash")
    assert sorted(versions) == ["4.17.20", "4.17.21", "5.0.0"]
    args, kwargs = mock_get.call_args
    assert kwargs.get("timeout") == 10
    assert "registry.npmjs.org" in args[0]


def test_pypi_live_returns_versions():
    adapter = upr.PyPILiveAdapter()
    fake_resp = MagicMock()
    fake_resp.json.return_value = {
        "info": {"name": "requests"},
        "releases": {"2.31.0": [], "2.32.0": [], "2.32.3": []},
    }
    with patch("requests.get", return_value=fake_resp) as mock_get:
        versions = adapter.get_versions("requests")
    assert sorted(versions) == ["2.31.0", "2.32.0", "2.32.3"]
    args, kwargs = mock_get.call_args
    assert kwargs.get("timeout") == 10
    assert "pypi.org/pypi/requests/json" in args[0]


def test_maven_live_handles_group_artifact_split():
    adapter = upr.MavenLiveAdapter()
    fake_resp = MagicMock()
    fake_resp.json.return_value = {
        "response": {
            "docs": [
                {"id": "com.fasterxml:jackson-core", "latestVersion": "2.17.0"},
                {"id": "com.fasterxml:jackson-core", "latestVersion": "2.16.0"},
            ]
        }
    }
    with patch("requests.get", return_value=fake_resp) as mock_get:
        versions = adapter.get_versions("com.fasterxml:jackson-core")
    assert "2.17.0" in versions and "2.16.0" in versions
    _, kwargs = mock_get.call_args
    params = kwargs.get("params", {})
    assert params.get("q") == "g:com.fasterxml AND a:jackson-core"
    assert kwargs.get("timeout") == 10


def test_live_failure_falls_back_to_static():
    """When live adapter raises/returns empty, dispatcher falls back to static."""
    adapter = upr.NpmAdapter()

    # Make the live adapter return [] (network failure path)
    with patch.object(adapter._live, "get_versions", side_effect=Exception("boom")):
        rows = adapter.list_versions("lodash")

    # Static catalog has lodash entries
    versions = [r[0] for r in rows]
    assert "4.17.21" in versions, f"expected static catalog hit, got {versions}"


def test_offline_adapter_reads_json():
    """OfflineRegistryAdapter reads versions from JSON file at env path."""
    payload = {
        "npm": {"my-internal-pkg": ["1.0.0", "1.1.0", "2.0.0"]},
        "pypi": {"corp-lib": ["0.1.0"]},
    }
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False
    ) as f:
        json.dump(payload, f)
        path = f.name
    try:
        os.environ["ALDECI_OFFLINE_REGISTRY_PATH"] = path
        offline = upr.OfflineRegistryAdapter()
        assert offline.get_versions("npm", "my-internal-pkg") == [
            "1.0.0",
            "1.1.0",
            "2.0.0",
        ]
        assert offline.get_versions("pypi", "corp-lib") == ["0.1.0"]
        assert offline.get_versions("npm", "missing-pkg") == []
    finally:
        os.environ.pop("ALDECI_OFFLINE_REGISTRY_PATH", None)
        os.unlink(path)


def test_chain_static_when_no_live_no_offline():
    """No live, no offline → static catalog wins."""
    adapter = upr.NpmAdapter()
    # Force live to empty AND ensure no offline env path
    with patch.object(adapter._live, "get_versions", return_value=[]):
        # Replace offline cache to be empty
        adapter._offline._cache = None
        rows = adapter.list_versions("express")
    versions = [r[0] for r in rows]
    assert "4.19.0" in versions, f"expected static express versions, got {versions}"
