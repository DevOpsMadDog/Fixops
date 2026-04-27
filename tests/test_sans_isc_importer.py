"""Tests for SANS ISC importer.

Test plan:
  1. parse_top_sources — fixture JSON (list form)
  2. parse_top_sources — fixture JSON (dict/envelope form)
  3. parse_top_ports   — fixture JSON (list form)
  4. parse_top_ports   — fixture JSON (dict/envelope form)
  5. get_top_sources   — sorted by attack_count desc after import
  6. get_top_ports     — endpoint returns ports after import
  7. Replace semantics — second run wipes first snapshot
"""

from __future__ import annotations

import sys
import types
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Path setup — ensure suite-feeds + suite-core are importable
# ---------------------------------------------------------------------------

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
for _p in [
    str(_PROJECT_ROOT / "suite-feeds"),
    str(_PROJECT_ROOT / "suite-core"),
]:
    if _p not in sys.path:
        sys.path.insert(0, _p)


# ---------------------------------------------------------------------------
# Stub out PersistentDict with an in-memory dict so tests need no SQLite
# ---------------------------------------------------------------------------

class _InMemoryStore(dict):
    """Minimal PersistentDict stand-in."""
    def __init__(self, namespace: str, db_path: str = "") -> None:
        super().__init__()
        self._ns = namespace


def _patch_persistent_dict():
    """Return a context-manager that replaces PersistentDict in the importer."""
    # We need the module to load fresh each time with our store
    return patch(
        "feeds.sans_isc.importer.PersistentDict",
        new=_InMemoryStore,
        create=True,
    )


# Fixture data ---------------------------------------------------------------

SOURCES_LIST_FIXTURE: List[Dict[str, Any]] = [
    {"ip": "1.2.3.4",   "country": "CN", "attacks": 500,  "mindate": "2024-01-01", "maxdate": "2024-04-01"},
    {"ip": "5.6.7.8",   "country": "RU", "attacks": 1200, "mindate": "2024-02-01", "maxdate": "2024-04-20"},
    {"ip": "9.10.11.12","country": "US", "attacks": 300,  "mindate": "2024-03-01", "maxdate": "2024-04-27"},
]

SOURCES_DICT_FIXTURE: Dict[str, Any] = {
    "sources": [
        {"ip": "10.0.0.1", "country": "DE", "attacks": 800,  "mindate": "2024-01-10", "maxdate": "2024-04-10"},
        {"ip": "10.0.0.2", "country": "BR", "attacks": 2000, "mindate": "2024-01-15", "maxdate": "2024-04-25"},
    ]
}

PORTS_LIST_FIXTURE: List[Dict[str, Any]] = [
    {"targetPort": 22,   "records": 9000, "service": "ssh"},
    {"targetPort": 443,  "records": 3500, "service": "https"},
    {"targetPort": 3389, "records": 7800, "service": "rdp"},
]

PORTS_DICT_FIXTURE: Dict[str, Any] = {
    "ports": [
        {"targetPort": 80,  "records": 2000, "service": "http"},
        {"targetPort": 8080,"records": 1100, "service": "http-alt"},
    ]
}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestParseTopSources:
    """Test 1 & 2 — parse_top_sources from list and dict payloads."""

    def setup_method(self):
        # Reimport fresh to avoid cached module state
        import importlib
        import feeds.sans_isc.importer as mod
        importlib.reload(mod)
        self.mod = mod

    def test_parse_list_form(self):
        result = self.mod.parse_top_sources(SOURCES_LIST_FIXTURE)
        assert len(result) == 3
        ips = [r["ip"] for r in result]
        assert "1.2.3.4" in ips
        assert "5.6.7.8" in ips
        # attack_count extracted from "attacks" key
        by_ip = {r["ip"]: r for r in result}
        assert by_ip["5.6.7.8"]["attack_count"] == 1200
        assert by_ip["1.2.3.4"]["country"] == "CN"
        assert by_ip["1.2.3.4"]["first_seen"] == "2024-01-01"
        assert by_ip["1.2.3.4"]["last_seen"] == "2024-04-01"

    def test_parse_dict_envelope_form(self):
        result = self.mod.parse_top_sources(SOURCES_DICT_FIXTURE)
        assert len(result) == 2
        by_ip = {r["ip"]: r for r in result}
        assert by_ip["10.0.0.2"]["attack_count"] == 2000
        assert by_ip["10.0.0.1"]["country"] == "DE"

    def test_skips_non_dict_entries(self):
        result = self.mod.parse_top_sources(["not-a-dict", None, 42])
        assert result == []

    def test_skips_missing_ip(self):
        result = self.mod.parse_top_sources([{"country": "XX", "attacks": 100}])
        assert result == []


class TestParseTopPorts:
    """Test 3 & 4 — parse_top_ports from list and dict payloads."""

    def setup_method(self):
        import importlib
        import feeds.sans_isc.importer as mod
        importlib.reload(mod)
        self.mod = mod

    def test_parse_list_form(self):
        result = self.mod.parse_top_ports(PORTS_LIST_FIXTURE)
        assert len(result) == 3
        ports = [r["port"] for r in result]
        assert 22 in ports
        assert 3389 in ports
        by_port = {r["port"]: r for r in result}
        assert by_port[22]["service"] == "ssh"
        assert by_port[22]["attack_count"] == 9000

    def test_parse_dict_envelope_form(self):
        result = self.mod.parse_top_ports(PORTS_DICT_FIXTURE)
        assert len(result) == 2
        by_port = {r["port"]: r for r in result}
        assert by_port[80]["attack_count"] == 2000
        assert by_port[8080]["service"] == "http-alt"

    def test_skips_non_dict_entries(self):
        result = self.mod.parse_top_ports(["x", None])
        assert result == []

    def test_skips_missing_port(self):
        result = self.mod.parse_top_ports([{"service": "ssh", "records": 100}])
        assert result == []


class TestGetTopSourcesSortedDesc:
    """Test 5 — get_top_sources returns entries sorted by attack_count desc."""

    def setup_method(self):
        import importlib
        import feeds.sans_isc.importer as mod
        importlib.reload(mod)
        self.mod = mod

    def test_sources_sorted_by_attack_count_desc(self, tmp_path):
        # Patch stores to in-memory
        stores: Dict[str, _InMemoryStore] = {}

        def _make_store(namespace, db_path=""):
            if namespace not in stores:
                stores[namespace] = _InMemoryStore(namespace, db_path)
            return stores[namespace]

        with patch.object(self.mod, "_get_sources_store", lambda: _make_store("sans_isc_sources")):
            with patch.object(self.mod, "_get_ports_store", lambda: _make_store("sans_isc_ports")):
                # Inject data via _replace_sources directly
                records = self.mod.parse_top_sources(SOURCES_LIST_FIXTURE)
                self.mod._replace_sources(records, "2024-04-27T00:00:00+00:00")

                result = self.mod.get_top_sources(limit=10)

        assert len(result) == 3
        counts = [r["attack_count"] for r in result]
        assert counts == sorted(counts, reverse=True), "Must be sorted desc"
        assert result[0]["ip"] == "5.6.7.8"  # highest at 1200


class TestGetTopPortsEndpoint:
    """Test 6 — get_top_ports returns all stored ports."""

    def setup_method(self):
        import importlib
        import feeds.sans_isc.importer as mod
        importlib.reload(mod)
        self.mod = mod

    def test_get_top_ports_returns_ports(self):
        stores: Dict[str, _InMemoryStore] = {}

        def _make_store(namespace, db_path=""):
            if namespace not in stores:
                stores[namespace] = _InMemoryStore(namespace, db_path)
            return stores[namespace]

        with patch.object(self.mod, "_get_sources_store", lambda: _make_store("sans_isc_sources")):
            with patch.object(self.mod, "_get_ports_store", lambda: _make_store("sans_isc_ports")):
                records = self.mod.parse_top_ports(PORTS_LIST_FIXTURE)
                self.mod._replace_ports(records, "2024-04-27T00:00:00+00:00")

                result = self.mod.get_top_ports(limit=10)

        assert len(result) == 3
        ports = {r["port"] for r in result}
        assert ports == {22, 443, 3389}


class TestReplaceSemantics:
    """Test 7 — second run completely wipes the first snapshot."""

    def setup_method(self):
        import importlib
        import feeds.sans_isc.importer as mod
        importlib.reload(mod)
        self.mod = mod

    def test_replace_wipes_previous_snapshot(self):
        store = _InMemoryStore("test_sources")

        with patch.object(self.mod, "_get_sources_store", lambda: store):
            # First import — 3 sources
            records_1 = self.mod.parse_top_sources(SOURCES_LIST_FIXTURE)
            self.mod._replace_sources(records_1, "2024-04-26T00:00:00+00:00")
            assert len(store) == 3

            # Second import — 2 different sources (dict envelope form)
            records_2 = self.mod.parse_top_sources(SOURCES_DICT_FIXTURE)
            self.mod._replace_sources(records_2, "2024-04-27T00:00:00+00:00")

            # Must be exactly 2 — old IPs gone
            assert len(store) == 2
            assert "1.2.3.4" not in store, "Old IP must be wiped by replace"
            assert "10.0.0.1" in store
            assert "10.0.0.2" in store

    def test_replace_ports_wipes_previous_snapshot(self):
        store = _InMemoryStore("test_ports")

        with patch.object(self.mod, "_get_ports_store", lambda: store):
            records_1 = self.mod.parse_top_ports(PORTS_LIST_FIXTURE)
            self.mod._replace_ports(records_1, "2024-04-26T00:00:00+00:00")
            assert len(store) == 3

            records_2 = self.mod.parse_top_ports(PORTS_DICT_FIXTURE)
            self.mod._replace_ports(records_2, "2024-04-27T00:00:00+00:00")

            assert len(store) == 2
            assert "22" not in store, "Old port must be wiped"
            assert "80" in store
            assert "8080" in store
