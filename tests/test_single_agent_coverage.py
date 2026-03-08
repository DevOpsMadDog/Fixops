"""Coverage tests for core.single_agent."""
import os
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

import pytest

try:
    from core.single_agent import SingleAgent
    HAS_AGENT = True
except ImportError:
    HAS_AGENT = False
    SingleAgent = None


@pytest.mark.skipif(not HAS_AGENT, reason="single_agent not available")
class TestSingleAgent:
    def test_instantiation(self):
        agent = SingleAgent()
        assert agent is not None
