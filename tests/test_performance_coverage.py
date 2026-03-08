"""Coverage tests for core.performance — PerformanceSimulator."""
import os
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.performance import PerformanceSimulator


class TestPerformanceSimulator:
    def test_instantiation(self):
        sim = PerformanceSimulator(settings={})
        assert sim is not None

    def test_simulate_basic(self):
        sim = PerformanceSimulator(settings={})
        pipeline_result = {
            "status": "completed",
            "findings_count": 50,
            "duration_ms": 1200,
        }
        result = sim.simulate(pipeline_result)
        assert isinstance(result, dict)

    def test_simulate_empty_result(self):
        sim = PerformanceSimulator(settings={})
        result = sim.simulate({})
        assert isinstance(result, dict)

    def test_simulate_large_findings(self):
        sim = PerformanceSimulator(settings={"max_findings": 1000})
        pipeline_result = {
            "status": "completed",
            "findings_count": 5000,
            "duration_ms": 30000,
        }
        result = sim.simulate(pipeline_result)
        assert isinstance(result, dict)
