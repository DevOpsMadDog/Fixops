"""SAST engine performance regression tests.

Validates that the three hotspot fixes introduced in beast-mode(perf):
  1. Per-file language pre-filtering in scan_code (no per-line rule filter)
  2. Pre-compiled taint patterns (no re.compile in hot loop)
  3. Parallel scan_files via ThreadPoolExecutor

Assertions are intentionally generous (wall-clock, GIL-constrained CI) but
will catch catastrophic regressions (e.g. accidentally reverting to N×M
re.compile calls on every scan).
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.perf

import time
from typing import Dict

import pytest

from core.sast_engine import SASTEngine as SastEngine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_file_contents(n: int, template: str = "") -> Dict[str, str]:
    """Build a dict of n synthetic Python source files."""
    base = template or (
        "import os\n"
        "password = 'hardcoded_secret_abc123'\n"
        "result = os.system('ls ' + user_input)\n"
        "cursor.execute('SELECT * FROM users WHERE id=' + user_id)\n"
        "x = 1 + 1\n" * 40  # ~45 lines of mostly-clean code
    )
    return {f"file_{i:04d}.py": base for i in range(n)}


# ---------------------------------------------------------------------------
# Smoke: engine instantiation pre-compiles patterns
# ---------------------------------------------------------------------------

class TestEngineInit:
    def test_compiled_taint_sources_populated(self):
        engine = SastEngine()
        assert len(engine._compiled_taint_sources) > 0, (
            "Pre-compiled taint sources must be populated at init"
        )

    def test_compiled_taint_sinks_populated(self):
        engine = SastEngine()
        assert len(engine._compiled_taint_sinks) > 0, (
            "Pre-compiled taint sinks must be populated at init"
        )

    def test_compiled_rules_populated(self):
        engine = SastEngine()
        assert len(engine._compiled_rules) >= 50, (
            "Engine should have at least 50 compiled built-in rules"
        )


# ---------------------------------------------------------------------------
# Correctness: fixes must not change output
# ---------------------------------------------------------------------------

class TestScanCorrectnessAfterFixes:
    def test_scan_code_finds_hardcoded_secret(self):
        engine = SastEngine()
        result = engine.scan_code(
            "api_key = 'AKIAIOSFODNN7EXAMPLE'\n", filename="config.py"
        )
        assert result.total_findings >= 1
        rule_ids = [f.rule_id for f in result.findings]
        assert any("SAST-006" in r or "SAST-031" in r for r in rule_ids), (
            f"Expected hardcoded-secret rule, got: {rule_ids}"
        )

    def test_scan_code_finds_sql_injection(self):
        engine = SastEngine()
        result = engine.scan_code(
            'cursor.execute("SELECT * FROM u WHERE id=" + uid)\n',
            filename="db.py",
        )
        assert result.total_findings >= 1

    def test_scan_code_js_xss(self):
        engine = SastEngine()
        result = engine.scan_code(
            'el.innerHTML = userInput;\n', filename="app.js"
        )
        assert result.total_findings >= 1

    def test_scan_files_aggregates_findings(self):
        engine = SastEngine()
        files = _make_file_contents(10)
        result = engine.scan_files(files)
        assert result.files_scanned == 10
        assert result.total_findings > 0

    def test_scan_files_parallel_matches_serial(self):
        """Parallel and serial must produce identical finding counts."""
        engine = SastEngine()
        files = _make_file_contents(20)

        # Force serial by using scan_code directly
        serial_count = 0
        for fname, code in files.items():
            r = engine.scan_code(code, fname)
            serial_count += r.total_findings

        # scan_files uses ThreadPoolExecutor internally
        parallel_result = engine.scan_files(files)
        assert parallel_result.total_findings == serial_count, (
            f"Parallel ({parallel_result.total_findings}) != serial ({serial_count})"
        )


# ---------------------------------------------------------------------------
# Performance: 100-file scan must complete within 5 s
# ---------------------------------------------------------------------------

class TestScanPerformance:
    WALL_CLOCK_LIMIT_S = 5.0   # generous for CI/GIL-constrained environments
    FILE_COUNT = 100

    def test_100_file_scan_under_5s(self):
        engine = SastEngine()
        files = _make_file_contents(self.FILE_COUNT)

        t0 = time.perf_counter()
        result = engine.scan_files(files)
        elapsed = time.perf_counter() - t0

        assert result.files_scanned == self.FILE_COUNT, (
            f"Expected {self.FILE_COUNT} files scanned, got {result.files_scanned}"
        )
        assert elapsed < self.WALL_CLOCK_LIMIT_S, (
            f"100-file SAST scan took {elapsed:.2f}s — exceeds {self.WALL_CLOCK_LIMIT_S}s limit"
        )

    def test_scan_files_duration_ms_recorded(self):
        engine = SastEngine()
        files = _make_file_contents(10)
        result = engine.scan_files(files)
        assert result.duration_ms > 0, "duration_ms must be positive"

    def test_repeated_scan_incremental_faster(self):
        """Incremental scan of unchanged files should be materially faster."""
        engine = SastEngine()
        files = _make_file_contents(50)

        # Cold run
        t0 = time.perf_counter()
        engine.scan_files(files, incremental=True)
        cold_s = time.perf_counter() - t0

        # Warm run (all files cached by hash)
        t0 = time.perf_counter()
        engine.scan_files(files, incremental=True)
        warm_s = time.perf_counter() - t0

        assert warm_s < cold_s, (
            f"Incremental warm scan ({warm_s:.3f}s) should be faster than cold ({cold_s:.3f}s)"
        )
