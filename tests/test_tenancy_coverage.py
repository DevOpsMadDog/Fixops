"""Coverage tests for core.tenancy — TenantLifecycleManager."""
import os
import sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.tenancy import TenantLifecycleManager


class TestTenantLifecycleManager:
    def test_instantiation(self):
        mgr = TenantLifecycleManager(settings={})
        assert mgr is not None

    def test_evaluate_basic(self):
        mgr = TenantLifecycleManager(settings={})
        pipeline_result = {
            "status": "completed",
            "org_id": "ORG-001",
            "findings": [{"id": "F1", "severity": "high"}],
        }
        result = mgr.evaluate(pipeline_result)
        assert isinstance(result, dict)

    def test_evaluate_empty(self):
        mgr = TenantLifecycleManager(settings={})
        result = mgr.evaluate({})
        assert isinstance(result, dict)

    def test_evaluate_with_settings(self):
        mgr = TenantLifecycleManager(settings={"max_tenants": 100, "isolation": "strict"})
        result = mgr.evaluate({"org_id": "ORG-002"})
        assert isinstance(result, dict)
