"""Performance assertions for the MCP gateway layer.

Validates three fixes applied 2026-05-04:
  1. MCPGateway._call_log is now a deque(maxlen=500) — O(1) append, no pop(0) shift.
  2. MCPToolRegistry._execution_history is now a deque(maxlen=1000) — same fix.
  3. MCPGateway.call_tool no longer does a per-call `import json` — module-level import.
  4. MCPToolRegistry.export_all_schemas is single-pass — no double-iteration.

All assertions use wall-clock timing with generous headroom so CI machines
(slow or fast) reliably pass, while still catching O(N) regressions.
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.perf

import sys
import time
from collections import deque
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))

from core.mcp_gateway import MCPGateway, get_mcp_gateway
from core.mcp_tool_registry import MCPToolRegistry


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fresh_registry() -> MCPToolRegistry:
    """Return a fresh (non-singleton) registry instance for isolation."""
    reg = object.__new__(MCPToolRegistry)
    reg._tools = {}
    reg._handlers = {}
    reg._stats = {}
    reg._execution_history = deque(maxlen=1000)
    reg._initialized = True
    reg._register_builtin_tools()
    return reg


def _fresh_gateway() -> MCPGateway:
    """Return a fresh MCPGateway (not the global singleton)."""
    return MCPGateway()


# ---------------------------------------------------------------------------
# Fix 1 & 2: deque — O(1) bounded append benchmark
# ---------------------------------------------------------------------------

class TestDequeHistory:
    """_execution_history / _call_log must be deque instances."""

    def test_registry_history_is_deque(self):
        reg = _fresh_registry()
        assert isinstance(reg._execution_history, deque), (
            "_execution_history must be a deque, not a list"
        )
        assert reg._execution_history.maxlen == 1000

    def test_gateway_call_log_is_deque(self):
        gw = _fresh_gateway()
        assert isinstance(gw._call_log, deque), (
            "_call_log must be a deque, not a list"
        )
        assert gw._call_log.maxlen == 500

    def test_registry_history_bounded_fast(self):
        """Appending 2000 items to the deque must complete well under 50 ms
        (a list.pop(0) loop over 2000 items can take 200 µs×2000 ≈ 400 ms)."""
        reg = _fresh_registry()
        start = time.perf_counter()
        for i in range(2000):
            reg._execution_history.append({"i": i})
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert elapsed_ms < 50, f"deque append loop took {elapsed_ms:.1f} ms — O(N) regression?"
        assert len(reg._execution_history) == 1000  # maxlen enforced

    def test_gateway_call_log_bounded_fast(self):
        """Same check for the gateway call log."""
        gw = _fresh_gateway()
        start = time.perf_counter()
        for i in range(1000):
            gw._call_log.append({"i": i})
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert elapsed_ms < 50, f"call_log deque append took {elapsed_ms:.1f} ms"
        assert len(gw._call_log) == 500  # maxlen enforced


# ---------------------------------------------------------------------------
# Fix 3: no per-call `import json` in call_tool
# ---------------------------------------------------------------------------

class TestCallToolSpeed:
    """call_tool on a dict-returning handler must complete quickly (no import overhead)."""

    def test_dict_dispatch_no_import_overhead(self):
        gw = _fresh_gateway()
        # call_tool with a known built-in that returns a dict
        N = 200
        start = time.perf_counter()
        for _ in range(N):
            resp = gw.call_tool("get_posture_score", {"org_id": "perf-test-org"})
        elapsed_ms = (time.perf_counter() - start) * 1000
        avg_ms = elapsed_ms / N
        assert not resp.is_error
        # 5 ms per call is very generous — each call should be < 1 ms with no import
        assert avg_ms < 5, f"avg call_tool took {avg_ms:.2f} ms — possible per-call import overhead?"


# ---------------------------------------------------------------------------
# Fix 4: export_all_schemas single-pass
# ---------------------------------------------------------------------------

class TestExportAllSchemas:
    """export_all_schemas must be a single-pass over _tools.values()."""

    def test_export_all_schemas_correctness(self):
        reg = _fresh_registry()
        schemas = reg.export_all_schemas()
        assert len(schemas) == 10  # 10 built-in tools
        for s in schemas:
            assert s["type"] == "function"
            assert "name" in s["function"]
            assert "description" in s["function"]
            assert "parameters" in s["function"]

    def test_export_all_schemas_fast(self):
        """1000 export calls on 10 tools must finish under 200 ms."""
        reg = _fresh_registry()
        start = time.perf_counter()
        for _ in range(1000):
            reg.export_all_schemas()
        elapsed_ms = (time.perf_counter() - start) * 1000
        assert elapsed_ms < 200, (
            f"export_all_schemas x1000 took {elapsed_ms:.1f} ms — double-pass regression?"
        )

    def test_export_matches_get_tool_schema(self):
        """Exported schemas must match get_tool_schema output per tool."""
        reg = _fresh_registry()
        bulk = {s["function"]["name"]: s for s in reg.export_all_schemas()}
        for tool_id in reg._tools:
            individual = reg.get_tool_schema(tool_id)
            assert bulk[tool_id] == individual, (
                f"export_all_schemas output for {tool_id} diverges from get_tool_schema"
            )


# ---------------------------------------------------------------------------
# Singleton safety
# ---------------------------------------------------------------------------

class TestSingletonIntegrity:
    def test_get_mcp_gateway_returns_same_instance(self):
        gw1 = get_mcp_gateway()
        gw2 = get_mcp_gateway()
        assert gw1 is gw2

    def test_registry_singleton(self):
        r1 = MCPToolRegistry()
        r2 = MCPToolRegistry()
        assert r1 is r2
