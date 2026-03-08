"""Coverage tests for core.onboarding — OnboardingGuide."""
import os
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

import pytest
from unittest.mock import MagicMock
from core.onboarding import OnboardingGuide


@pytest.fixture
def overlay():
    ov = MagicMock()
    ov.overrides = {}
    return ov


class TestOnboardingGuide:
    def test_instantiation(self, overlay):
        guide = OnboardingGuide(overlay=overlay)
        assert guide is not None

    def test_build_with_inputs(self, overlay):
        guide = OnboardingGuide(overlay=overlay)
        result = guide.build(required_inputs=["app_id", "scan_type"])
        assert result is not None
        assert isinstance(result, dict)

    def test_build_empty_inputs(self, overlay):
        guide = OnboardingGuide(overlay=overlay)
        result = guide.build(required_inputs=[])
        assert result is not None
        assert isinstance(result, dict)

    def test_build_many_inputs(self, overlay):
        guide = OnboardingGuide(overlay=overlay)
        inputs = ["app_id", "scan_type", "target_url", "auth_token", "policy_id"]
        result = guide.build(required_inputs=inputs)
        assert isinstance(result, dict)
