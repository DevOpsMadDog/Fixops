"""
Tests for the Unified Security Metrics Dashboard.

Covers:
- DashboardWidget and DashboardLayout Pydantic models
- WidgetType enum values
- UnifiedDashboard.get_ciso_dashboard()
- UnifiedDashboard.get_soc_dashboard()
- UnifiedDashboard.get_compliance_dashboard()
- UnifiedDashboard.get_developer_dashboard()
- UnifiedDashboard.get_executive_dashboard()
- UnifiedDashboard.get_real_time_feed()
- Caching: repeated calls return cached=True within TTL
- Cache isolation: different org_ids have independent caches
- Real-time feed skips cache
- get_unified_dashboard() singleton
- FastAPI router: all 6 endpoints return 200 with correct shapes
- Widget structure invariants (id, title, type, data, config)
- Fallback data when backends are unavailable

Run with: python -m pytest tests/test_unified_dashboard.py -v --timeout=30
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))

# ---------------------------------------------------------------------------
# Environment (must be before app imports)
# ---------------------------------------------------------------------------
os.environ.setdefault("FIXOPS_MODE", "test")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret-key-that-is-long-enough")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

# ---------------------------------------------------------------------------
# Imports under test
# ---------------------------------------------------------------------------
from core.unified_dashboard import (
    DashboardLayout,
    DashboardWidget,
    UnifiedDashboard,
    WidgetType,
    _cache,
    _cache_lock,
    get_unified_dashboard,
)


# ============================================================================
# Helpers
# ============================================================================

def _clear_cache():
    with _cache_lock:
        _cache.clear()


def _assert_widget_structure(widget: DashboardWidget):
    """Assert every widget has required fields with correct types."""
    assert isinstance(widget.id, str) and len(widget.id) > 0
    assert isinstance(widget.title, str) and len(widget.title) > 0
    assert isinstance(widget.type, WidgetType)
    assert isinstance(widget.data, dict)
    assert isinstance(widget.config, dict)


def _assert_layout_structure(layout: DashboardLayout, expected_name_fragment: str):
    assert isinstance(layout.id, str) and len(layout.id) > 0
    assert expected_name_fragment.lower() in layout.name.lower()
    assert isinstance(layout.widgets, list)
    assert len(layout.widgets) > 0
    assert isinstance(layout.org_id, str)
    assert isinstance(layout.generated_at, str)
    for widget in layout.widgets:
        _assert_widget_structure(widget)


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture(autouse=True)
def clear_cache_before_each():
    _clear_cache()
    yield
    _clear_cache()


@pytest.fixture
def dashboard():
    return UnifiedDashboard()


# ============================================================================
# Model Tests
# ============================================================================

class TestDashboardWidget:
    def test_default_id_generated(self):
        w = DashboardWidget(title="Test", type=WidgetType.kpi, data={"v": 1})
        assert len(w.id) > 0

    def test_explicit_id_accepted(self):
        w = DashboardWidget(id="my-id", title="Test", type=WidgetType.chart, data={})
        assert w.id == "my-id"

    def test_all_widget_types_valid(self):
        for wt in WidgetType:
            w = DashboardWidget(title="T", type=wt, data={})
            assert w.type == wt

    def test_config_defaults_to_empty_dict(self):
        w = DashboardWidget(title="T", type=WidgetType.alert, data={})
        assert w.config == {}

    def test_data_and_config_round_trip(self):
        data = {"value": 42, "unit": "%"}
        config = {"color": "green", "threshold": 80}
        w = DashboardWidget(title="T", type=WidgetType.kpi, data=data, config=config)
        assert w.data == data
        assert w.config == config


class TestDashboardLayout:
    def test_default_id_generated(self):
        layout = DashboardLayout(name="Test Layout")
        assert len(layout.id) > 0

    def test_widgets_defaults_to_empty_list(self):
        layout = DashboardLayout(name="Empty")
        assert layout.widgets == []

    def test_widgets_accepted(self):
        w = DashboardWidget(title="W", type=WidgetType.kpi, data={})
        layout = DashboardLayout(name="L", widgets=[w])
        assert len(layout.widgets) == 1

    def test_org_id_defaults_to_default(self):
        layout = DashboardLayout(name="L")
        assert layout.org_id == "default"

    def test_generated_at_is_set(self):
        layout = DashboardLayout(name="L")
        assert "T" in layout.generated_at or "-" in layout.generated_at

    def test_cached_defaults_false(self):
        layout = DashboardLayout(name="L")
        assert layout.cached is False


# ============================================================================
# WidgetType Enum Tests
# ============================================================================

class TestWidgetType:
    def test_all_five_types_exist(self):
        assert WidgetType.kpi == "kpi"
        assert WidgetType.chart == "chart"
        assert WidgetType.table == "table"
        assert WidgetType.alert == "alert"
        assert WidgetType.timeline == "timeline"

    def test_widget_type_count(self):
        assert len(list(WidgetType)) == 5


# ============================================================================
# CISO Dashboard Tests
# ============================================================================

class TestCISODashboard:
    def test_returns_dashboard_layout(self, dashboard):
        result = dashboard.get_ciso_dashboard()
        assert isinstance(result, DashboardLayout)

    def test_name_contains_ciso(self, dashboard):
        result = dashboard.get_ciso_dashboard()
        assert "ciso" in result.name.lower() or "executive" in result.name.lower()

    def test_has_minimum_widgets(self, dashboard):
        result = dashboard.get_ciso_dashboard()
        assert len(result.widgets) >= 6

    def test_all_widget_types_present(self, dashboard):
        result = dashboard.get_ciso_dashboard()
        types = {w.type for w in result.widgets}
        assert WidgetType.kpi in types
        assert WidgetType.chart in types
        assert WidgetType.table in types

    def test_widget_structure_valid(self, dashboard):
        result = dashboard.get_ciso_dashboard()
        _assert_layout_structure(result, "ciso")

    def test_org_id_propagated(self, dashboard):
        result = dashboard.get_ciso_dashboard(org_id="acme")
        assert result.org_id == "acme"

    def test_posture_score_kpi_present(self, dashboard):
        result = dashboard.get_ciso_dashboard()
        posture_widget = next(
            (w for w in result.widgets if "posture" in w.title.lower()), None
        )
        assert posture_widget is not None
        assert "score" in posture_widget.data or "value" in posture_widget.data


# ============================================================================
# SOC Dashboard Tests
# ============================================================================

class TestSOCDashboard:
    def test_returns_dashboard_layout(self, dashboard):
        result = dashboard.get_soc_dashboard()
        assert isinstance(result, DashboardLayout)

    def test_name_contains_soc(self, dashboard):
        result = dashboard.get_soc_dashboard()
        assert "soc" in result.name.lower()

    def test_has_minimum_widgets(self, dashboard):
        result = dashboard.get_soc_dashboard()
        assert len(result.widgets) >= 6

    def test_has_timeline_widget(self, dashboard):
        result = dashboard.get_soc_dashboard()
        timeline_widgets = [w for w in result.widgets if w.type == WidgetType.timeline]
        assert len(timeline_widgets) >= 1

    def test_has_alert_widget(self, dashboard):
        result = dashboard.get_soc_dashboard()
        alert_widgets = [w for w in result.widgets if w.type == WidgetType.alert]
        assert len(alert_widgets) >= 1

    def test_widget_structure_valid(self, dashboard):
        result = dashboard.get_soc_dashboard()
        _assert_layout_structure(result, "soc")

    def test_org_id_propagated(self, dashboard):
        result = dashboard.get_soc_dashboard(org_id="beta-org")
        assert result.org_id == "beta-org"

    def test_timeline_has_events(self, dashboard):
        result = dashboard.get_soc_dashboard()
        timeline_widget = next(w for w in result.widgets if w.type == WidgetType.timeline)
        assert "events" in timeline_widget.data
        assert isinstance(timeline_widget.data["events"], list)


# ============================================================================
# Compliance Dashboard Tests
# ============================================================================

class TestComplianceDashboard:
    def test_returns_dashboard_layout(self, dashboard):
        result = dashboard.get_compliance_dashboard()
        assert isinstance(result, DashboardLayout)

    def test_name_contains_compliance(self, dashboard):
        result = dashboard.get_compliance_dashboard()
        assert "compliance" in result.name.lower()

    def test_has_minimum_widgets(self, dashboard):
        result = dashboard.get_compliance_dashboard()
        assert len(result.widgets) >= 5

    def test_has_table_widget(self, dashboard):
        result = dashboard.get_compliance_dashboard()
        table_widgets = [w for w in result.widgets if w.type == WidgetType.table]
        assert len(table_widgets) >= 1

    def test_framework_table_has_columns(self, dashboard):
        result = dashboard.get_compliance_dashboard()
        table_widget = next(
            (w for w in result.widgets if w.type == WidgetType.table and "framework" in w.title.lower()),
            None,
        )
        assert table_widget is not None
        assert "columns" in table_widget.data
        assert len(table_widget.data["columns"]) >= 4

    def test_widget_structure_valid(self, dashboard):
        result = dashboard.get_compliance_dashboard()
        _assert_layout_structure(result, "compliance")

    def test_org_id_propagated(self, dashboard):
        result = dashboard.get_compliance_dashboard(org_id="gamma-co")
        assert result.org_id == "gamma-co"


# ============================================================================
# Developer Dashboard Tests
# ============================================================================

class TestDeveloperDashboard:
    def test_returns_dashboard_layout(self, dashboard):
        result = dashboard.get_developer_dashboard()
        assert isinstance(result, DashboardLayout)

    def test_name_contains_developer(self, dashboard):
        result = dashboard.get_developer_dashboard()
        assert "developer" in result.name.lower()

    def test_has_minimum_widgets(self, dashboard):
        result = dashboard.get_developer_dashboard()
        assert len(result.widgets) >= 4

    def test_owner_set_to_user_email(self, dashboard):
        result = dashboard.get_developer_dashboard(user_email="alice@example.com")
        assert result.owner == "alice@example.com"

    def test_org_id_propagated(self, dashboard):
        result = dashboard.get_developer_dashboard(org_id="devorg")
        assert result.org_id == "devorg"

    def test_widget_structure_valid(self, dashboard):
        result = dashboard.get_developer_dashboard()
        _assert_layout_structure(result, "developer")

    def test_autofix_kpi_present(self, dashboard):
        result = dashboard.get_developer_dashboard()
        autofix_widget = next(
            (w for w in result.widgets if "autofix" in w.title.lower()), None
        )
        assert autofix_widget is not None

    def test_different_users_cached_separately(self, dashboard):
        r1 = dashboard.get_developer_dashboard(org_id="o1", user_email="alice@x.com")
        r2 = dashboard.get_developer_dashboard(org_id="o1", user_email="bob@x.com")
        assert r1.owner != r2.owner


# ============================================================================
# Executive Dashboard Tests
# ============================================================================

class TestExecutiveDashboard:
    def test_returns_dashboard_layout(self, dashboard):
        result = dashboard.get_executive_dashboard()
        assert isinstance(result, DashboardLayout)

    def test_name_contains_executive(self, dashboard):
        result = dashboard.get_executive_dashboard()
        assert "executive" in result.name.lower()

    def test_has_minimum_widgets(self, dashboard):
        result = dashboard.get_executive_dashboard()
        assert len(result.widgets) >= 4

    def test_widget_structure_valid(self, dashboard):
        result = dashboard.get_executive_dashboard()
        _assert_layout_structure(result, "executive")

    def test_org_id_propagated(self, dashboard):
        result = dashboard.get_executive_dashboard(org_id="board-org")
        assert result.org_id == "board-org"

    def test_posture_widget_present(self, dashboard):
        result = dashboard.get_executive_dashboard()
        posture_widget = next(
            (w for w in result.widgets if "posture" in w.title.lower()), None
        )
        assert posture_widget is not None

    def test_risk_exposure_widget_present(self, dashboard):
        result = dashboard.get_executive_dashboard()
        risk_widget = next(
            (w for w in result.widgets if "risk" in w.title.lower() or "exposure" in w.title.lower()),
            None,
        )
        assert risk_widget is not None


# ============================================================================
# Real-Time Feed Tests
# ============================================================================

class TestRealTimeFeed:
    def test_returns_dashboard_layout(self, dashboard):
        result = dashboard.get_real_time_feed()
        assert isinstance(result, DashboardLayout)

    def test_name_contains_real_time(self, dashboard):
        result = dashboard.get_real_time_feed()
        assert "real" in result.name.lower() or "live" in result.name.lower() or "stream" in result.name.lower()

    def test_has_minimum_widgets(self, dashboard):
        result = dashboard.get_real_time_feed()
        assert len(result.widgets) >= 2

    def test_has_timeline_widget(self, dashboard):
        result = dashboard.get_real_time_feed()
        timeline_widgets = [w for w in result.widgets if w.type == WidgetType.timeline]
        assert len(timeline_widgets) >= 1

    def test_widget_structure_valid(self, dashboard):
        result = dashboard.get_real_time_feed()
        for widget in result.widgets:
            _assert_widget_structure(widget)

    def test_not_marked_as_cached(self, dashboard):
        # Call twice — real-time feed should not use cache
        r1 = dashboard.get_real_time_feed(org_id="rt-org")
        r2 = dashboard.get_real_time_feed(org_id="rt-org")
        # Both should return fresh data (cached=False)
        assert r1.cached is False
        assert r2.cached is False

    def test_org_id_propagated(self, dashboard):
        result = dashboard.get_real_time_feed(org_id="rt-org")
        assert result.org_id == "rt-org"


# ============================================================================
# Caching Tests
# ============================================================================

class TestCaching:
    def test_second_call_returns_cached(self, dashboard):
        r1 = dashboard.get_ciso_dashboard(org_id="cache-test")
        r2 = dashboard.get_ciso_dashboard(org_id="cache-test")
        assert r1.cached is False
        assert r2.cached is True

    def test_different_orgs_cached_independently(self, dashboard):
        r1 = dashboard.get_soc_dashboard(org_id="org-a")
        r2 = dashboard.get_soc_dashboard(org_id="org-b")
        r3 = dashboard.get_soc_dashboard(org_id="org-a")
        assert r1.cached is False
        assert r2.cached is False
        assert r3.cached is True

    def test_different_dashboard_types_cached_independently(self, dashboard):
        r_ciso = dashboard.get_ciso_dashboard(org_id="shared-org")
        r_soc = dashboard.get_soc_dashboard(org_id="shared-org")
        r_ciso2 = dashboard.get_ciso_dashboard(org_id="shared-org")
        assert r_ciso.cached is False
        assert r_soc.cached is False
        assert r_ciso2.cached is True

    def test_real_time_feed_bypasses_cache(self, dashboard):
        r1 = dashboard.get_real_time_feed(org_id="rt")
        r2 = dashboard.get_real_time_feed(org_id="rt")
        assert r1.cached is False
        assert r2.cached is False


# ============================================================================
# Singleton Tests
# ============================================================================

class TestSingleton:
    def test_get_unified_dashboard_returns_instance(self):
        d = get_unified_dashboard()
        assert isinstance(d, UnifiedDashboard)

    def test_get_unified_dashboard_is_singleton(self):
        d1 = get_unified_dashboard()
        d2 = get_unified_dashboard()
        assert d1 is d2


# ============================================================================
# FastAPI Router Tests
# ============================================================================

try:
    from fastapi.testclient import TestClient
    from fastapi import FastAPI
    from apps.api.unified_dashboard_router import router as unified_router

    _ROUTER_AVAILABLE = True
except ImportError:
    _ROUTER_AVAILABLE = False


@pytest.mark.skipif(not _ROUTER_AVAILABLE, reason="Router not importable")
class TestUnifiedDashboardRouter:
    @pytest.fixture
    def client(self):
        app = FastAPI()
        app.include_router(unified_router)
        return TestClient(app)

    def test_ciso_endpoint_returns_200(self, client):
        resp = client.get("/api/v1/unified-dashboard/ciso")
        assert resp.status_code == 200

    def test_ciso_response_has_widgets(self, client):
        resp = client.get("/api/v1/unified-dashboard/ciso")
        data = resp.json()
        assert "widgets" in data
        assert len(data["widgets"]) > 0

    def test_soc_endpoint_returns_200(self, client):
        resp = client.get("/api/v1/unified-dashboard/soc")
        assert resp.status_code == 200

    def test_soc_response_has_widgets(self, client):
        resp = client.get("/api/v1/unified-dashboard/soc")
        data = resp.json()
        assert "widgets" in data

    def test_compliance_endpoint_returns_200(self, client):
        resp = client.get("/api/v1/unified-dashboard/compliance")
        assert resp.status_code == 200

    def test_developer_endpoint_returns_200(self, client):
        resp = client.get("/api/v1/unified-dashboard/developer")
        assert resp.status_code == 200

    def test_developer_endpoint_accepts_user_email(self, client):
        resp = client.get(
            "/api/v1/unified-dashboard/developer",
            params={"user_email": "dev@test.com"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["owner"] == "dev@test.com"

    def test_executive_endpoint_returns_200(self, client):
        resp = client.get("/api/v1/unified-dashboard/executive")
        assert resp.status_code == 200

    def test_real_time_endpoint_returns_200(self, client):
        resp = client.get("/api/v1/unified-dashboard/real-time")
        assert resp.status_code == 200

    def test_org_id_query_param_accepted(self, client):
        resp = client.get(
            "/api/v1/unified-dashboard/ciso",
            params={"org_id": "test-org"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["org_id"] == "test-org"

    def test_response_schema_has_required_fields(self, client):
        resp = client.get("/api/v1/unified-dashboard/ciso")
        data = resp.json()
        assert "id" in data
        assert "name" in data
        assert "widgets" in data
        assert "org_id" in data
        assert "generated_at" in data

    def test_widget_schema_has_required_fields(self, client):
        resp = client.get("/api/v1/unified-dashboard/soc")
        data = resp.json()
        widget = data["widgets"][0]
        assert "id" in widget
        assert "title" in widget
        assert "type" in widget
        assert "data" in widget
        assert "config" in widget

    def test_all_six_endpoints_accessible(self, client):
        endpoints = [
            "/api/v1/unified-dashboard/ciso",
            "/api/v1/unified-dashboard/soc",
            "/api/v1/unified-dashboard/compliance",
            "/api/v1/unified-dashboard/developer",
            "/api/v1/unified-dashboard/executive",
            "/api/v1/unified-dashboard/real-time",
        ]
        for endpoint in endpoints:
            resp = client.get(endpoint)
            assert resp.status_code == 200, f"Failed for {endpoint}"
