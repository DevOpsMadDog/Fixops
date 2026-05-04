"""SBOM performance assertions — beast-mode perf audit.

Guards three hotspot fixes:
  1. executemany bulk insert (import_sbom)
  2. single-JOIN list_sboms (no N+1)
  3. aggregate SQL vuln count in get_asset (no per-row JSON parse)

Threshold: 1000-component SBOM ingest < 500 ms on any reasonable CI host.
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.perf

import json
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_cyclonedx(n: int) -> str:
    """Build a minimal CycloneDX JSON with *n* components."""
    components: List[Dict[str, Any]] = []
    for i in range(n):
        components.append(
            {
                "type": "library",
                "name": f"pkg-{i}",
                "version": f"1.{i}.0",
                "purl": f"pkg:pypi/pkg-{i}@1.{i}.0",
                "licenses": [{"license": {"id": "MIT"}}],
            }
        )
    doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "metadata": {
            "timestamp": "2026-05-04T00:00:00Z",
            "component": {"type": "application", "name": "test-app", "version": "1.0.0"},
        },
        "components": components,
    }
    return json.dumps(doc)


# ---------------------------------------------------------------------------
# SBOMManager tests
# ---------------------------------------------------------------------------

@pytest.fixture()
def manager(tmp_path: Path):
    from core.sbom_manager import SBOMManager
    return SBOMManager(db_path=str(tmp_path / "sbom_perf.db"))


def test_import_1000_components_under_500ms(manager) -> None:
    """FIX #1 guard: executemany bulk insert must be fast."""
    from core.sbom_manager import SBOMFormat

    content = _make_cyclonedx(1000)

    t0 = time.perf_counter()
    sbom = manager.import_sbom(content, SBOMFormat.CYCLONEDX, "perf-test", org_id="org1")
    elapsed_ms = (time.perf_counter() - t0) * 1000

    assert len(sbom.components) == 1000, "All 1000 components must be parsed"
    assert elapsed_ms < 500, (
        f"import_sbom with 1000 components took {elapsed_ms:.1f}ms — exceeds 500ms threshold. "
        "Check executemany fix in sbom_manager.py."
    )


def test_list_sboms_no_n_plus_one(manager) -> None:
    """FIX #2 guard: list_sboms with multiple SBOMs must not fire N+1 queries."""
    from core.sbom_manager import SBOMFormat

    # Insert 5 SBOMs each with 100 components
    content = _make_cyclonedx(100)
    for i in range(5):
        manager.import_sbom(content, SBOMFormat.CYCLONEDX, f"proj-{i}", org_id="org2")

    t0 = time.perf_counter()
    sboms = manager.list_sboms(org_id="org2")
    elapsed_ms = (time.perf_counter() - t0) * 1000

    assert len(sboms) == 5
    assert all(len(s.components) == 100 for s in sboms), "Each SBOM must have 100 components"
    # With N+1 this would be ~5 × individual query latency; single JOIN should be well under 100ms
    assert elapsed_ms < 200, (
        f"list_sboms (5 SBOMs × 100 components) took {elapsed_ms:.1f}ms — exceeds 200ms threshold. "
        "Check single-JOIN fix in list_sboms."
    )


def test_import_round_trip_correctness(manager) -> None:
    """Correctness guard: executemany must persist all fields accurately."""
    from core.sbom_manager import SBOMFormat

    content = _make_cyclonedx(50)
    sbom = manager.import_sbom(content, SBOMFormat.CYCLONEDX, "correctness-test", org_id="org3")

    loaded = manager.get_sbom(sbom.id)
    assert len(loaded.components) == 50
    names = {c.name for c in loaded.components}
    assert "pkg-0" in names and "pkg-49" in names
    assert all(c.licenses == ["MIT"] for c in loaded.components)


# ---------------------------------------------------------------------------
# SBOMEngine tests
# ---------------------------------------------------------------------------

@pytest.fixture()
def engine(tmp_path: Path):
    from core.sbom_engine import SBOMEngine
    return SBOMEngine(data_dir=str(tmp_path))


def test_get_asset_aggregate_sql(engine) -> None:
    """FIX #3 guard: get_asset must return correct vuln count via SQL aggregate."""
    org = "org-sql"
    engine._ensure_db(org)

    asset = engine.register_asset(org, {"asset_name": "sql-agg-test"})
    asset_id = asset["id"]

    # Add 10 components — alternating 2 vulns / 0 vulns, risk_score 8.0 / 2.0
    for i in range(10):
        has_vulns = i % 2 == 0
        engine.add_component(org, asset_id, {
            "component_name": f"lib-{i}",
            "component_version": "1.0",
            "known_vulns": [f"CVE-2026-{i:04d}", f"CVE-2026-{i:04d}b"] if has_vulns else [],
            "risk_score": 8.0 if has_vulns else 2.0,
        })

    result = engine.get_asset(org, asset_id)

    assert result["component_count"] == 10
    # 5 components × 2 vulns each = 10
    assert result["vuln_count"] == 10, f"Expected 10, got {result['vuln_count']}"
    # 5 components with risk_score 8.0 >= 7.0
    assert result["high_risk_count"] == 5, f"Expected 5 high-risk, got {result['high_risk_count']}"


def test_get_asset_aggregate_performance(engine) -> None:
    """FIX #3 perf guard: aggregate query must outperform per-row JSON parse at scale."""
    org = "org-agg-perf"
    engine._ensure_db(org)

    asset = engine.register_asset(org, {"asset_name": "agg-perf-test"})
    asset_id = asset["id"]

    for i in range(500):
        engine.add_component(org, asset_id, {
            "component_name": f"comp-{i}",
            "component_version": "1.0",
            "known_vulns": [f"CVE-{i}"] if i % 3 == 0 else [],
            "risk_score": 7.5 if i % 3 == 0 else 1.0,
        })

    t0 = time.perf_counter()
    result = engine.get_asset(org, asset_id)
    elapsed_ms = (time.perf_counter() - t0) * 1000

    assert result["component_count"] == 500
    assert elapsed_ms < 200, (
        f"get_asset (500 components) took {elapsed_ms:.1f}ms — exceeds 200ms. "
        "Check SQL aggregate fix in sbom_engine.py::get_asset."
    )
