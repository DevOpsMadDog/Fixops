"""Coverage tests for core.vllm_autofix_adapter."""
import os
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

import pytest

try:
    from core.vllm_autofix_adapter import VLLMAutoFixAdapter
    HAS_ADAPTER = True
except ImportError:
    HAS_ADAPTER = False
    VLLMAutoFixAdapter = None


@pytest.mark.skipif(not HAS_ADAPTER, reason="vllm_autofix_adapter not available")
class TestVLLMAutoFixAdapter:
    def test_instantiation(self):
        adapter = VLLMAutoFixAdapter()
        assert adapter is not None
