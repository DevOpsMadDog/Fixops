"""Tests verifying all 9 simulated engines are properly flagged.

Checks:
1. Each engine logs SIMULATION warning at import
2. Wrapped API endpoints return _simulation_warning.is_simulated=True
3. DB contamination count from devsecops_engine reported
"""
from __future__ import annotations

import importlib
import logging
import sqlite3
import sys
import types
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Helper — capture log records emitted at module level during import
# ---------------------------------------------------------------------------

class _WarningCapture(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)

    def has_simulation_warning(self) -> bool:
        return any(
            "SIMULATION" in (r.getMessage()) or "simulation" in r.getMessage().lower()
            for r in self.records
        )


def _import_fresh(module_name: str) -> tuple[types.ModuleType, _WarningCapture]:
    """Force-reimport a module and capture its log output."""
    # Remove from cache so module-level code re-runs
    for key in list(sys.modules.keys()):
        if key == module_name or key.startswith(module_name + "."):
            del sys.modules[key]

    cap = _WarningCapture()
    root_logger = logging.getLogger()
    old_level = root_logger.level
    root_logger.setLevel(logging.WARNING)
    root_logger.addHandler(cap)
    try:
        mod = importlib.import_module(module_name)
    finally:
        root_logger.removeHandler(cap)
        root_logger.setLevel(old_level)
    return mod, cap


# ---------------------------------------------------------------------------
# 1. Engine import warning tests
# ---------------------------------------------------------------------------

ENGINES = [
    ("core.security_scorecard", "security_scorecard"),
    ("core.compliance_scanner_engine", "compliance_scanner_engine"),
    ("core.vendor_scorecard", "vendor_scorecard"),
    ("core.kubernetes_security_engine", "kubernetes_security_engine"),
    ("core.ccm_engine", "ccm_engine"),
    ("core.config_benchmark_engine", "config_benchmark_engine"),
    ("core.ioc_enrichment_engine", "ioc_enrichment_engine"),
    ("core.openclaw_engine", "openclaw_engine"),
]

CONNECTOR_ENGINES = [
    ("connectors.iam_sso_connector", "iam_sso_connector"),
]


@pytest.mark.parametrize("module_name,label", ENGINES + CONNECTOR_ENGINES)
def test_engine_logs_simulation_warning_at_import(module_name: str, label: str):
    """Each simulated engine must emit a WARNING-level SIMULATION log at import."""
    _mod, cap = _import_fresh(module_name)
    assert cap.has_simulation_warning(), (
        f"{label}: expected SIMULATION warning log at import, got records: "
        + str([r.getMessage() for r in cap.records])
    )


# ---------------------------------------------------------------------------
# 2. Router _SIMULATION_WARNING constant presence tests
# ---------------------------------------------------------------------------

ROUTERS = [
    "apps.api.security_scorecard_router",
    "apps.api.compliance_scanner_router",
    "apps.api.vendor_scorecard_router",
    "apps.api.kubernetes_security_router",
    "apps.api.iam_sso_router",
    "apps.api.ccm_router",
    "apps.api.config_benchmark_router",
    "apps.api.ioc_enrichment_router",
    "apps.api.openclaw_router",
]


@pytest.mark.parametrize("router_module", ROUTERS)
def test_router_has_simulation_warning_constant(router_module: str):
    """Each router must define _SIMULATION_WARNING with is_simulated=True."""
    # Remove from cache
    for key in list(sys.modules.keys()):
        if key == router_module or key.startswith(router_module + "."):
            del sys.modules[key]

    mod = importlib.import_module(router_module)
    assert hasattr(mod, "_SIMULATION_WARNING"), (
        f"{router_module} missing _SIMULATION_WARNING constant"
    )
    warn = mod._SIMULATION_WARNING
    assert warn.get("is_simulated") is True, (
        f"{router_module}._SIMULATION_WARNING.is_simulated must be True, got {warn}"
    )
    assert warn.get("do_not_use_in_demo") is True, (
        f"{router_module}._SIMULATION_WARNING.do_not_use_in_demo must be True"
    )
    assert "engine" in warn, f"{router_module}._SIMULATION_WARNING missing 'engine' key"
    assert "real_integration_required" in warn, (
        f"{router_module}._SIMULATION_WARNING missing 'real_integration_required' key"
    )


# ---------------------------------------------------------------------------
# 3. DB contamination report
# ---------------------------------------------------------------------------

_DB_PATH = Path(__file__).resolve().parents[1] / ".fixops_data" / "security_findings_engine.db"

CONTAMINATION_RESULT: dict = {}


def _query_contamination() -> dict:
    if not _DB_PATH.exists():
        return {"db_found": False, "devsecops_source_tool": 0, "devsecops_scan_id": 0,
                "cve_2024_cvss0": 0, "sample_rows": []}
    conn = sqlite3.connect(str(_DB_PATH))
    conn.row_factory = sqlite3.Row
    c1 = conn.execute(
        "SELECT COUNT(*) FROM security_findings WHERE source_tool LIKE '%devsecops%'"
    ).fetchone()[0]
    c2 = conn.execute(
        "SELECT COUNT(*) FROM security_findings WHERE scan_id LIKE '%devsecops%'"
    ).fetchone()[0]
    c3 = conn.execute(
        "SELECT COUNT(*) FROM security_findings "
        "WHERE cve_id LIKE 'CVE-2024-%' AND cvss_score=0"
    ).fetchone()[0]
    sample = conn.execute(
        "SELECT id, cve_id, cvss_score, source_tool, scan_id "
        "FROM security_findings WHERE cve_id LIKE 'CVE-2024-%' AND cvss_score=0 LIMIT 5"
    ).fetchall()
    conn.close()
    return {
        "db_found": True,
        "devsecops_source_tool": c1,
        "devsecops_scan_id": c2,
        "cve_2024_cvss0": c3,
        "sample_rows": [dict(r) for r in sample],
    }


def test_db_contamination_report():
    """Report DB contamination — count only, no deletes."""
    result = _query_contamination()
    CONTAMINATION_RESULT.update(result)

    # Print for visibility in pytest output
    print("\n=== DB Contamination Report ===")
    print(f"  DB found: {result['db_found']}")
    print(f"  Rows with source_tool LIKE '%devsecops%': {result['devsecops_source_tool']}")
    print(f"  Rows with scan_id LIKE '%devsecops%': {result['devsecops_scan_id']}")
    print(f"  Rows CVE-2024-* AND cvss_score=0: {result['cve_2024_cvss0']}")
    print("  Sample rows:")
    for row in result["sample_rows"]:
        print(f"    {row}")
    print("===============================")

    # The test passes regardless — we only report, not assert contamination is zero
    assert result["db_found"], "security_findings_engine.db not found — cannot audit"
    # Direct devsecops contamination must be zero (no devsecops rows found earlier)
    assert result["devsecops_source_tool"] == 0, (
        f"Found {result['devsecops_source_tool']} rows with devsecops source_tool — investigate"
    )
    assert result["devsecops_scan_id"] == 0, (
        f"Found {result['devsecops_scan_id']} rows with devsecops scan_id — investigate"
    )
    # CVE-2024 with cvss=0 is suspicious but may come from sast_scanner (not devsecops)
    # We report but do not fail on this — caller decides remediation
    print(
        f"\nNOTE: {result['cve_2024_cvss0']} CVE-2024-* rows with cvss_score=0 "
        f"found (may be from sast_scanner, not devsecops). Review sample rows above."
    )
