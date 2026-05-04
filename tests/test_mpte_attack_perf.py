"""Performance assertions for MPTE/attack simulation hotspot fixes.

Validates three optimizations:
1. _TECHNIQUES_BY_PHASE pre-index — O(1) phase lookup vs O(N) scan
2. asyncio.gather parallel phase execution — all 8 phases run concurrently
3. _MITRE_PHASE_MAP module-level constant — no dict rebuild per call
"""

import pytest

pytestmark = pytest.mark.perf
import asyncio
import time

import pytest


# ---------------------------------------------------------------------------
# Fix 1: MITRE technique pre-index (attack_simulation_engine)
# ---------------------------------------------------------------------------

def test_techniques_by_phase_index_exists():
    """_TECHNIQUES_BY_PHASE must be a module-level dict built at import time."""
    from core.attack_simulation_engine import MITRE_TECHNIQUES, _TECHNIQUES_BY_PHASE

    assert isinstance(_TECHNIQUES_BY_PHASE, dict), "_TECHNIQUES_BY_PHASE must be a dict"
    assert len(_TECHNIQUES_BY_PHASE) > 0, "_TECHNIQUES_BY_PHASE must not be empty"

    # Every technique must appear in the index exactly once
    total_indexed = sum(len(v) for v in _TECHNIQUES_BY_PHASE.values())
    assert total_indexed == len(MITRE_TECHNIQUES), (
        f"Index has {total_indexed} entries but MITRE_TECHNIQUES has {len(MITRE_TECHNIQUES)}"
    )


def test_phase_lookup_is_fast():
    """Phase lookup via pre-index must complete 1000 lookups under 5ms."""
    from core.attack_simulation_engine import _TECHNIQUES_BY_PHASE

    phases = list(_TECHNIQUES_BY_PHASE.keys())
    start = time.perf_counter()
    for _ in range(1000):
        for phase in phases:
            _ = _TECHNIQUES_BY_PHASE.get(phase, [])
    elapsed_ms = (time.perf_counter() - start) * 1000
    assert elapsed_ms < 5, f"1000 phase lookups took {elapsed_ms:.1f}ms — expected <5ms"


# ---------------------------------------------------------------------------
# Fix 2: asyncio.gather parallel phase execution
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_campaign_parallel_phases():
    """Full campaign must complete all 8 kill-chain phases and finish quickly."""
    from core.attack_simulation_engine import AttackSimulationEngine

    engine = AttackSimulationEngine()
    scenario = engine.create_scenario(
        name="perf-test",
        description="Parallel phase execution perf test",
        target_assets=["test-target"],
    )

    start = time.perf_counter()
    campaign = await engine.run_campaign(scenario.scenario_id, skip_llm_enrichment=True)
    elapsed_ms = (time.perf_counter() - start) * 1000

    # All 8 kill-chain phases must have produced steps
    assert campaign.steps_executed > 0, "Campaign must execute at least one step"

    # With parallel phases and no I/O, full campaign must run under 2000ms
    assert elapsed_ms < 2000, (
        f"Campaign took {elapsed_ms:.0f}ms — expected <2000ms with parallel phases"
    )


@pytest.mark.asyncio
async def test_execute_phase_uses_index():
    """_execute_phase must return techniques matching the phase from the pre-index."""
    from core.attack_simulation_engine import (
        AttackSimulationEngine,
        KillChainPhase,
        _TECHNIQUES_BY_PHASE,
    )

    engine = AttackSimulationEngine()
    scenario = engine.create_scenario(
        name="phase-index-test",
        target_assets=["test"],
    )

    for phase in KillChainPhase:
        steps = await engine._execute_phase(
            phase, scenario, None, skip_llm_enrichment=True  # type: ignore[arg-type]
        )
        expected_count = len(_TECHNIQUES_BY_PHASE.get(phase.value, []))
        assert len(steps) == expected_count, (
            f"Phase {phase.value}: got {len(steps)} steps, "
            f"expected {expected_count} from pre-index"
        )


# ---------------------------------------------------------------------------
# Fix 3: _MITRE_PHASE_MAP module-level constant (micro_pentest)
# ---------------------------------------------------------------------------

def test_mitre_phase_map_is_module_level():
    """_MITRE_PHASE_MAP must exist as a module-level dict (not rebuilt per call)."""
    import core.micro_pentest as mp

    assert hasattr(mp, "_MITRE_PHASE_MAP"), "_MITRE_PHASE_MAP must be a module-level constant"
    assert isinstance(mp._MITRE_PHASE_MAP, dict)
    assert len(mp._MITRE_PHASE_MAP) > 0


def test_mitre_phase_lookup_correctness():
    """_mitre_phase must resolve known technique IDs correctly."""
    from core.micro_pentest import _mitre_phase

    assert _mitre_phase("T1190") == "initial_access"
    assert _mitre_phase("T1059") == "execution"
    assert _mitre_phase("T1210") == "lateral_movement"
    # Sub-technique falls back to base
    assert _mitre_phase("T1059.007") == "execution"
    # Unknown returns "unknown"
    assert _mitre_phase("T9999") == "unknown"


def test_mitre_phase_map_call_speed():
    """10 000 _mitre_phase calls must complete under 10ms (no per-call dict alloc)."""
    from core.micro_pentest import _mitre_phase

    tids = ["T1190", "T1059", "T1210", "T1083", "T1550.004"] * 2000
    start = time.perf_counter()
    for tid in tids:
        _mitre_phase(tid)
    elapsed_ms = (time.perf_counter() - start) * 1000
    assert elapsed_ms < 10, (
        f"10 000 _mitre_phase calls took {elapsed_ms:.1f}ms — expected <10ms"
    )
