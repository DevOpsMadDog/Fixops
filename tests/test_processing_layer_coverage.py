"""Tests for enterprise processing layer — Bayesian priors, Markov transitions, SSVC fusion.

Note: pgmpy/networkx may not be compatible with the runtime Python version.
We mock the problematic import to test the heuristic fallback paths.
"""
import asyncio
import sys
import types
import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock


def _make_processing_layer_importable():
    """Ensure processing_layer can be imported even if pgmpy/networkx fails."""
    try:
        import core.services.enterprise.processing_layer as pl
        return pl
    except (ImportError, AttributeError):
        pass

    # pgmpy or networkx broken — stub the failing modules
    mock_modules = {}
    for mod_name in [
        "pgmpy", "pgmpy.factors", "pgmpy.factors.discrete",
        "pgmpy.inference", "pgmpy.models", "mchmm",
    ]:
        mock_modules[mod_name] = types.ModuleType(mod_name)

    mock_modules["pgmpy.factors.discrete"].TabularCPD = MagicMock
    mock_modules["pgmpy.inference"].VariableElimination = MagicMock
    mock_modules["pgmpy.models"].BayesianNetwork = MagicMock

    saved = {}
    for mod_name, mock_mod in mock_modules.items():
        saved[mod_name] = sys.modules.get(mod_name)
        sys.modules[mod_name] = mock_mod

    try:
        import importlib
        if "core.services.enterprise.processing_layer" in sys.modules:
            importlib.reload(sys.modules["core.services.enterprise.processing_layer"])
        else:
            pass
        return sys.modules["core.services.enterprise.processing_layer"]
    except Exception:
        pytest.skip("Cannot import processing_layer even with mocks", allow_module_level=True)
    finally:
        for mod_name, original in saved.items():
            if original is None:
                sys.modules.pop(mod_name, None)
            else:
                sys.modules[mod_name] = original


pl = _make_processing_layer_importable()

SSVCContext = pl.SSVCContext
MarkovState = pl.MarkovState
SARIFVulnerability = pl.SARIFVulnerability
BayesianPriorMapping = pl.BayesianPriorMapping
_mean = pl._mean
_variance = pl._variance


class TestMeanHelper:
    def test_empty_list(self):
        assert _mean([]) == 0.0

    def test_single_value(self):
        assert _mean([5.0]) == 5.0

    def test_multiple_values(self):
        assert _mean([2.0, 4.0, 6.0]) == pytest.approx(4.0)

    def test_negative_values(self):
        assert _mean([-1.0, 1.0]) == pytest.approx(0.0)

    def test_large_list(self):
        vals = [float(i) for i in range(100)]
        assert _mean(vals) == pytest.approx(49.5)


class TestVarianceHelper:
    def test_empty_list(self):
        assert _variance([]) == 0.0

    def test_single_value(self):
        assert _variance([7.0]) == 0.0

    def test_identical_values(self):
        assert _variance([3.0, 3.0, 3.0]) == pytest.approx(0.0)

    def test_known_variance(self):
        assert _variance([1.0, 2.0, 3.0, 4.0, 5.0]) == pytest.approx(2.0)

    def test_two_values(self):
        assert _variance([0.0, 10.0]) == pytest.approx(25.0)


class TestSSVCContext:
    def test_create_basic(self):
        ctx = SSVCContext(
            exploitation="active", exposure="open", utility="efficient",
            safety_impact="major", mission_impact="crippled",
        )
        assert ctx.exploitation == "active"
        assert ctx.exposure == "open"

    def test_all_exploitation_values(self):
        for val in ["none", "poc", "active"]:
            ctx = SSVCContext(exploitation=val, exposure="small", utility="laborious",
                             safety_impact="negligible", mission_impact="degraded")
            assert ctx.exploitation == val

    def test_all_exposure_values(self):
        for val in ["small", "controlled", "open"]:
            ctx = SSVCContext(exploitation="none", exposure=val, utility="laborious",
                             safety_impact="negligible", mission_impact="degraded")
            assert ctx.exposure == val

    def test_all_safety_impacts(self):
        for val in ["negligible", "marginal", "major", "hazardous"]:
            ctx = SSVCContext(exploitation="none", exposure="small", utility="laborious",
                             safety_impact=val, mission_impact="degraded")
            assert ctx.safety_impact == val


class TestMarkovState:
    def test_create_basic(self):
        state = MarkovState(
            current_state="vulnerable", cve_id="CVE-2024-1234", epss_score=0.85,
            kev_flag=True, disclosure_date=datetime(2024, 1, 15, tzinfo=timezone.utc),
        )
        assert state.current_state == "vulnerable"
        assert state.kev_flag is True

    def test_all_states(self):
        for s in ["secure", "vulnerable", "exploited", "patched"]:
            state = MarkovState(current_state=s, cve_id=None, epss_score=0.0,
                                kev_flag=False, disclosure_date=datetime.now(timezone.utc))
            assert state.current_state == s


class TestSARIFVulnerability:
    def test_create(self):
        vuln = SARIFVulnerability(
            rule_id="SAST-001", message="SQL injection", severity="high",
            cwe_id="CWE-89", owasp_category="A03:2021",
            file_location="src/api/users.py", confidence=0.95,
        )
        assert vuln.rule_id == "SAST-001"

    def test_none_cwe(self):
        vuln = SARIFVulnerability(
            rule_id="CUSTOM-001", message="Custom", severity="low",
            cwe_id=None, owasp_category=None,
            file_location="src/main.py", confidence=0.5,
        )
        assert vuln.cwe_id is None


class TestBayesianPriorMapping:
    def test_init(self):
        bpm = BayesianPriorMapping()
        assert bpm is not None

    def test_heuristic_priors_active_open_mev(self):
        bpm = BayesianPriorMapping()
        ctx = SSVCContext(exploitation="active", exposure="open",
                          utility="super_effective", safety_impact="hazardous",
                          mission_impact="mev")
        priors = bpm._heuristic_priors(ctx)
        assert isinstance(priors, dict)
        assert "critical" in priors
        total = sum(priors.values())
        assert total == pytest.approx(1.0, abs=0.01)
        assert priors["critical"] >= priors["low"]

    def test_heuristic_priors_none_small_degraded(self):
        bpm = BayesianPriorMapping()
        ctx = SSVCContext(exploitation="none", exposure="small",
                          utility="laborious", safety_impact="negligible",
                          mission_impact="degraded")
        priors = bpm._heuristic_priors(ctx)
        total = sum(priors.values())
        assert total == pytest.approx(1.0, abs=0.01)
        assert priors["low"] >= priors["critical"]

    def test_heuristic_priors_medium_risk(self):
        bpm = BayesianPriorMapping()
        ctx = SSVCContext(exploitation="poc", exposure="controlled",
                          utility="efficient", safety_impact="marginal",
                          mission_impact="degraded")
        priors = bpm._heuristic_priors(ctx)
        total = sum(priors.values())
        assert total == pytest.approx(1.0, abs=0.01)

    def test_compute_priors_async(self):
        bpm = BayesianPriorMapping()
        ctx = SSVCContext(exploitation="active", exposure="open",
                          utility="super_effective", safety_impact="hazardous",
                          mission_impact="mev")
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(bpm.compute_priors(ctx))
        finally:
            loop.close()
        assert isinstance(result, dict)
        assert len(result) == 4

    def test_unknown_values_heuristic(self):
        bpm = BayesianPriorMapping()
        ctx = SSVCContext(exploitation="unknown", exposure="unknown",
                          utility="unknown", safety_impact="unknown",
                          mission_impact="unknown")
        priors = bpm._heuristic_priors(ctx)
        assert isinstance(priors, dict)
        total = sum(priors.values())
        assert total == pytest.approx(1.0, abs=0.01)
