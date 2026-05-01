"""Tests for the Tor exit-node list importer and API router.

Test plan:
  1. parse_exit_list: 50-IP fixture text parsed correctly
  2. list_exit_ips endpoint returns stored IPs
  3. check_ip endpoint: known IP returns is_tor_exit=True, unknown returns False
  4. Replace semantics: second import removes IPs not in new list
"""

from __future__ import annotations

import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Path bootstrap
# ---------------------------------------------------------------------------

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
_SUITE_FEEDS = str(_PROJECT_ROOT / "suite-feeds")
_SUITE_API = str(_PROJECT_ROOT / "suite-api")
_SUITE_CORE = str(_PROJECT_ROOT / "suite-core")

for p in [_SUITE_FEEDS, _SUITE_API, _SUITE_CORE]:
    if p not in sys.path:
        sys.path.insert(0, p)

# ---------------------------------------------------------------------------
# Stub PersistentDict with a plain in-memory dict so tests need no SQLite file
# ---------------------------------------------------------------------------

class _InMemoryStore(dict):
    """Minimal PersistentDict stand-in for tests."""
    def __init__(self, name: str, db_path: str = ""):
        super().__init__()


def _make_persistent_store_module():
    mod = types.ModuleType("core.persistent_store")
    mod.PersistentDict = _InMemoryStore  # type: ignore[attr-defined]
    return mod


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

FIXTURE_TEXT_50 = "\n".join(
    [f"10.0.0.{i}" for i in range(1, 51)]
    + ["# this is a comment", "", "   "]  # blanks and comments must be skipped
)

FIXTURE_TEXT_30 = "\n".join(f"10.0.0.{i}" for i in range(1, 31))


# ---------------------------------------------------------------------------
# 1. Parse 50-IP fixture text
# ---------------------------------------------------------------------------

def test_parse_exit_list_50_ips():
    from feeds.tor_exit_nodes.importer import parse_exit_list

    ips = parse_exit_list(FIXTURE_TEXT_50)
    assert len(ips) == 50, f"Expected 50 IPs, got {len(ips)}"
    assert "10.0.0.1" in ips
    assert "10.0.0.50" in ips


def test_parse_exit_list_skips_comments_and_blanks():
    from feeds.tor_exit_nodes.importer import parse_exit_list

    text = "# comment\n\n1.2.3.4\n  \n5.6.7.8\n"
    ips = parse_exit_list(text)
    assert ips == ["1.2.3.4", "5.6.7.8"]


def test_parse_exit_list_deduplication():
    from feeds.tor_exit_nodes.importer import parse_exit_list

    text = "1.2.3.4\n1.2.3.4\n5.6.7.8\n"
    ips = parse_exit_list(text)
    assert len(ips) == 2


# ---------------------------------------------------------------------------
# 2. List endpoint returns IPs
# ---------------------------------------------------------------------------

def test_list_ips_endpoint_returns_ips():
    """After import, GET /ips must return the stored IPs."""
    ps_mod = _make_persistent_store_module()

    with patch.dict(sys.modules, {"core.persistent_store": ps_mod}):
        import importlib
        import feeds.tor_exit_nodes.importer as imp_mod
        importlib.reload(imp_mod)
        # Reset lazy store
        imp_mod._store = None

        # Seed the store directly
        store = imp_mod._get_store()
        store["1.1.1.1"] = {"ip": "1.1.1.1", "imported_at": "2026-04-27T00:00:00+00:00"}
        store["2.2.2.2"] = {"ip": "2.2.2.2", "imported_at": "2026-04-27T00:00:00+00:00"}

        ips = imp_mod.list_exit_ips(limit=100, offset=0)
        assert "1.1.1.1" in ips
        assert "2.2.2.2" in ips
        assert imp_mod.total_count() == 2

        imp_mod._store = None  # cleanup


# ---------------------------------------------------------------------------
# 3. Single-IP check endpoint
# ---------------------------------------------------------------------------

def test_check_ip_known():
    """check_ip returns a dict for a known exit node."""
    ps_mod = _make_persistent_store_module()

    with patch.dict(sys.modules, {"core.persistent_store": ps_mod}):
        import importlib
        import feeds.tor_exit_nodes.importer as imp_mod
        importlib.reload(imp_mod)
        imp_mod._store = None

        store = imp_mod._get_store()
        store["3.3.3.3"] = {"ip": "3.3.3.3", "imported_at": "2026-04-27T00:00:00+00:00"}

        entry = imp_mod.check_ip("3.3.3.3")
        assert entry is not None
        assert entry["ip"] == "3.3.3.3"

        imp_mod._store = None


def test_check_ip_unknown():
    """check_ip returns None for an IP not in the store."""
    ps_mod = _make_persistent_store_module()

    with patch.dict(sys.modules, {"core.persistent_store": ps_mod}):
        import importlib
        import feeds.tor_exit_nodes.importer as imp_mod
        importlib.reload(imp_mod)
        imp_mod._store = None

        # Empty store
        _store = imp_mod._get_store()  # noqa: F841

        result = imp_mod.check_ip("9.9.9.9")
        assert result is None

        imp_mod._store = None


# ---------------------------------------------------------------------------
# 4. Replace semantics on second import
# ---------------------------------------------------------------------------

def test_replace_semantics():
    """Second import with a smaller list removes IPs that dropped off."""
    ps_mod = _make_persistent_store_module()

    with patch.dict(sys.modules, {"core.persistent_store": ps_mod}):
        import importlib
        import feeds.tor_exit_nodes.importer as imp_mod
        importlib.reload(imp_mod)
        imp_mod._store = None

        # First import: 50 IPs
        with patch.object(imp_mod, "_get_store", wraps=imp_mod._get_store):
            # Seed 50 IPs directly via _replace_all
            first_ips = [f"10.0.0.{i}" for i in range(1, 51)]
            count1 = imp_mod._replace_all(first_ips)
            assert count1 == 50

            store = imp_mod._get_store()
            assert "10.0.0.50" in store

            # Second import: 30 IPs (IPs 31–50 should be gone)
            second_ips = [f"10.0.0.{i}" for i in range(1, 31)]
            count2 = imp_mod._replace_all(second_ips)
            assert count2 == 30

            store = imp_mod._get_store()
            assert "10.0.0.1" in store
            assert "10.0.0.30" in store
            assert "10.0.0.31" not in store
            assert "10.0.0.50" not in store
            assert imp_mod.total_count() == 30

        imp_mod._store = None


# ---------------------------------------------------------------------------
# 5. run_import integration (httpx mocked)
# ---------------------------------------------------------------------------

def test_run_import_httpx_mocked():
    """run_import correctly calls parse + replace via mocked HTTP response."""
    ps_mod = _make_persistent_store_module()

    with patch.dict(sys.modules, {"core.persistent_store": ps_mod}):
        import importlib
        import feeds.tor_exit_nodes.importer as imp_mod
        importlib.reload(imp_mod)
        imp_mod._store = None

        mock_response = MagicMock()
        mock_response.text = FIXTURE_TEXT_50
        mock_response.raise_for_status = MagicMock()

        mock_client = MagicMock()
        mock_client.__enter__ = MagicMock(return_value=mock_client)
        mock_client.__exit__ = MagicMock(return_value=False)
        mock_client.get = MagicMock(return_value=mock_response)

        with patch("httpx.Client", return_value=mock_client):
            result = imp_mod.run_import()

        assert result["ips"] == 50
        assert "imported_at" in result
        assert imp_mod.total_count() == 50

        imp_mod._store = None
