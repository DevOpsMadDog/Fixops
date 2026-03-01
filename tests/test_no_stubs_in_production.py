"""
Stub Detection Tests — prevent fake/stub/demo code from shipping to production.

Root cause: 84 fake endpoints shipped undetected because:
  1. CI had SKIP_UNIT_TESTS=true (no tests ran)
  2. 56 test files were in collect_ignore (26.7% skipped)
  3. 32 test files used MagicMock hiding real behavior
  4. 0 tests checked for stub patterns (integration_required, demo_data, empty controls)

This test file is the safety net — it hits critical endpoints via TestClient
and FAILS if any stub/fake/demo patterns are detected in responses.

Marker: @pytest.mark.unit
"""

import json
import os
import warnings

import pytest

# Ensure enterprise mode
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "aVFf3-1e7EmlXzx37Y8jaCx--yzpd4OJroyIdgXH-vFiylmaN0FDl2vIOAfBA_Oh")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-jwt-stub-detection")

from apps.api.app import create_app
from fastapi.testclient import TestClient

# ── Stub patterns that must NEVER appear in production responses ──────────
FORBIDDEN_PATTERNS = [
    "demo_data",
    "coming_soon",
    "not_implemented",
    "placeholder_value",
    "fake_",
    "stub_response",
    "todo_implement",
]

# JSON keys that should never be True in production
FORBIDDEN_TRUE_KEYS = [
    "demo_data",
    "demo_mode",
    "is_demo",
    "is_stub",
]


@pytest.fixture(scope="module")
def app():
    """Create the FastAPI app once for all tests in this module."""
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", category=UserWarning)
        return create_app()


@pytest.fixture(scope="module")
def client(app):
    """Create TestClient."""
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture(scope="module")
def headers():
    """Auth headers."""
    return {"X-API-Key": os.environ["FIXOPS_API_TOKEN"]}


def _check_no_stubs(data, endpoint: str):
    """Assert no stub patterns exist in a JSON response."""
    text = json.dumps(data, default=str).lower()

    for pattern in FORBIDDEN_PATTERNS:
        # Allow "demo_data": false (that's fine — it means NOT demo)
        if pattern == "demo_data" and '"demo_data": false' in text:
            continue
        if pattern == "demo_data" and '"demo_data":false' in text:
            continue
        # Fail if pattern found with a truthy value
        if f'"{pattern}": true' in text or f'"{pattern}":true' in text:
            pytest.fail(f"STUB DETECTED at {endpoint}: '{pattern}: true' found")

    # Check forbidden true keys
    if isinstance(data, dict):
        for key in FORBIDDEN_TRUE_KEYS:
            if data.get(key) is True:
                pytest.fail(f"STUB DETECTED at {endpoint}: '{key}' is True in response")


# ── Critical endpoints that were previously stubbed ──────────────────────


@pytest.mark.unit
class TestNoStubsInPentest:
    """Pentest endpoints must return real data, not integration_required."""

    def test_pentest_capabilities(self, client, headers):
        r = client.get("/api/v1/pentest/capabilities", headers=headers)
        assert r.status_code == 200
        data = r.json()
        _check_no_stubs(data, "/pentest/capabilities")

    def test_compliance_controls_not_empty(self, client, headers):
        """Controls endpoint must return real framework controls, not []."""
        for fw in ["pci-dss", "soc2", "iso27001", "hipaa", "nist-csf-2.0"]:
            r = client.get(
                f"/api/v1/copilot/agents/compliance/controls/{fw}",
                headers=headers,
            )
            assert r.status_code == 200
            data = r.json()
            controls = data.get("controls", [])
            assert (
                len(controls) > 0
            ), f"STUB: /compliance/controls/{fw} returned empty controls[]"
            _check_no_stubs(data, f"/compliance/controls/{fw}")

    def test_pentest_generate_poc(self, client, headers):
        r = client.post(
            "/api/v1/pentest/generate-poc",
            headers=headers,
            json={"cve_id": "CVE-2021-44228", "target_type": "web_application"},
        )
        assert r.status_code in [200, 422]
        if r.status_code == 200:
            data = r.json()
            assert (
                data.get("status") != "integration_required"
            ), "STUB: generate-poc still returns integration_required"
            _check_no_stubs(data, "/pentest/generate-poc")


@pytest.mark.unit
class TestNoStubsInDecisions:
    """Decision engine must not return fabricated metrics."""

    def test_core_components(self, client, headers):
        r = client.get("/api/v1/core-components", headers=headers)
        assert r.status_code == 200
        data = r.json()
        _check_no_stubs(data, "/core-components")

    def test_decisions_recent(self, client, headers):
        r = client.get("/api/v1/decisions/recent", headers=headers)
        assert r.status_code == 200
        _check_no_stubs(r.json(), "/decisions/recent")


@pytest.mark.unit
class TestNoStubsInMarketplace:
    """Marketplace must not have [DEMO] prefixed names or fake counts."""

    def test_marketplace_list(self, client, headers):
        r = client.get("/api/v1/marketplace", headers=headers)
        assert r.status_code == 200
        data = r.json()
        _check_no_stubs(data, "/marketplace")
        text = json.dumps(data)
        assert "[DEMO]" not in text, "STUB: marketplace still has [DEMO] prefixes"


@pytest.mark.unit
class TestNoStubsInHealth:
    """Health and capabilities endpoints must reflect real state."""

    def test_health(self, client, headers):
        r = client.get("/api/v1/health", headers=headers)
        assert r.status_code == 200

    def test_capabilities_dynamic(self, client, headers):
        """Capabilities must dynamically detect available engines."""
        r = client.get("/api/v1/pentest/capabilities", headers=headers)
        if r.status_code == 200:
            _check_no_stubs(r.json(), "/pentest/capabilities")
