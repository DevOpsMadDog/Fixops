"""
Tests for DashboardBuilder core module and dashboard_builder_router API.

Covers:
- Dashboard CRUD (create, get, list, update, delete)
- Widget management (add, update, remove, reorder)
- Sharing and visibility changes
- Cloning dashboards
- Built-in templates (5 templates)
- Create from template
- Widget library catalog
- Dashboard stats
- API router endpoints (FastAPI TestClient)
- Error handling (404, 422)
"""

from __future__ import annotations

import os
import json
import tempfile
import pytest
from pathlib import Path
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Environment setup (must precede any app imports)
# ---------------------------------------------------------------------------
os.environ.setdefault("FIXOPS_MODE", "test")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret-key-that-is-long-enough")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

# ---------------------------------------------------------------------------
# Imports
# ---------------------------------------------------------------------------
from core.dashboard_builder import (
    Dashboard,
    DashboardBuilder,
    DashboardTemplate,
    DashboardVisibility,
    Widget,
    WidgetType,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def tmp_db(tmp_path):
    """Temporary SQLite database path."""
    return tmp_path / "test_dashboards.db"


@pytest.fixture
def builder(tmp_db):
    """Fresh DashboardBuilder instance backed by a temp DB."""
    return DashboardBuilder(db_path=tmp_db)


@pytest.fixture
def sample_dashboard(builder):
    """A dashboard created for testing."""
    return builder.create_dashboard(
        name="Test Dashboard",
        description="A dashboard for testing",
        owner="alice@example.com",
        org_id="org_test",
    )


@pytest.fixture
def sample_widget():
    return Widget(
        type=WidgetType.KPI_CARD,
        title="Critical Findings",
        data_source="metrics/critical_findings_count",
        config={"color": "#ef4444", "size": {"w": 3, "h": 2}},
        order=0,
    )


# ============================================================================
# Dashboard CRUD
# ============================================================================


class TestDashboardCRUD:
    def test_create_dashboard_returns_dashboard(self, builder):
        dash = builder.create_dashboard(
            name="My Dashboard",
            description="desc",
            owner="bob@example.com",
            org_id="org_a",
        )
        assert isinstance(dash, Dashboard)
        assert dash.name == "My Dashboard"
        assert dash.owner_email == "bob@example.com"
        assert dash.org_id == "org_a"
        assert dash.visibility == DashboardVisibility.PRIVATE
        assert dash.widgets == []

    def test_create_dashboard_assigns_uuid(self, builder):
        d1 = builder.create_dashboard("A", owner="a@a.com")
        d2 = builder.create_dashboard("B", owner="b@b.com")
        assert d1.id != d2.id
        assert len(d1.id) == 36  # UUID format

    def test_create_dashboard_timestamps(self, builder):
        dash = builder.create_dashboard("X", owner="x@x.com")
        assert isinstance(dash.created_at, datetime)
        assert isinstance(dash.updated_at, datetime)

    def test_get_dashboard_returns_correct(self, builder, sample_dashboard):
        fetched = builder.get_dashboard(sample_dashboard.id)
        assert fetched.id == sample_dashboard.id
        assert fetched.name == sample_dashboard.name

    def test_get_dashboard_not_found_raises(self, builder):
        with pytest.raises(KeyError):
            builder.get_dashboard("nonexistent-id")

    def test_list_dashboards_by_org(self, builder):
        builder.create_dashboard("D1", owner="u@u.com", org_id="org_x")
        builder.create_dashboard("D2", owner="u@u.com", org_id="org_x")
        builder.create_dashboard("D3", owner="u@u.com", org_id="org_y")
        result = builder.list_dashboards(org_id="org_x")
        assert len(result) == 2
        assert all(d.org_id == "org_x" for d in result)

    def test_list_dashboards_by_owner(self, builder):
        builder.create_dashboard("D1", owner="alice@a.com", org_id="org_z")
        builder.create_dashboard("D2", owner="bob@b.com", org_id="org_z")
        result = builder.list_dashboards(owner="alice@a.com")
        assert len(result) == 1
        assert result[0].owner_email == "alice@a.com"

    def test_list_dashboards_empty(self, builder):
        result = builder.list_dashboards(org_id="org_empty")
        assert result == []

    def test_update_dashboard_name(self, builder, sample_dashboard):
        updated = builder.update_dashboard(sample_dashboard.id, {"name": "Updated Name"})
        assert updated.name == "Updated Name"
        # Persisted
        fetched = builder.get_dashboard(sample_dashboard.id)
        assert fetched.name == "Updated Name"

    def test_update_dashboard_visibility(self, builder, sample_dashboard):
        updated = builder.update_dashboard(
            sample_dashboard.id, {"visibility": "org"}
        )
        assert updated.visibility == DashboardVisibility.ORG

    def test_update_dashboard_not_found_raises(self, builder):
        with pytest.raises(KeyError):
            builder.update_dashboard("bad-id", {"name": "x"})

    def test_update_dashboard_updated_at_changes(self, builder, sample_dashboard):
        original_ts = sample_dashboard.updated_at
        updated = builder.update_dashboard(sample_dashboard.id, {"name": "New"})
        assert updated.updated_at >= original_ts

    def test_delete_dashboard(self, builder, sample_dashboard):
        builder.delete_dashboard(sample_dashboard.id)
        with pytest.raises(KeyError):
            builder.get_dashboard(sample_dashboard.id)

    def test_delete_dashboard_not_found_raises(self, builder):
        with pytest.raises(KeyError):
            builder.delete_dashboard("ghost-id")


# ============================================================================
# Widget management
# ============================================================================


class TestWidgetManagement:
    def test_add_widget_returns_widget(self, builder, sample_dashboard, sample_widget):
        added = builder.add_widget(sample_dashboard.id, sample_widget)
        assert isinstance(added, Widget)
        assert added.title == sample_widget.title
        assert added.type == WidgetType.KPI_CARD

    def test_add_widget_persisted(self, builder, sample_dashboard, sample_widget):
        builder.add_widget(sample_dashboard.id, sample_widget)
        fetched = builder.get_dashboard(sample_dashboard.id)
        assert len(fetched.widgets) == 1
        assert fetched.widgets[0].title == sample_widget.title

    def test_add_multiple_widgets(self, builder, sample_dashboard):
        for i in range(3):
            w = Widget(
                type=WidgetType.CHART_BAR,
                title=f"Widget {i}",
                data_source=f"metrics/metric_{i}",
            )
            builder.add_widget(sample_dashboard.id, w)
        fetched = builder.get_dashboard(sample_dashboard.id)
        assert len(fetched.widgets) == 3

    def test_update_widget_title(self, builder, sample_dashboard, sample_widget):
        added = builder.add_widget(sample_dashboard.id, sample_widget)
        updated = builder.update_widget(
            sample_dashboard.id, added.id, {"title": "New Title"}
        )
        assert updated.title == "New Title"
        fetched = builder.get_dashboard(sample_dashboard.id)
        assert fetched.widgets[0].title == "New Title"

    def test_update_widget_not_found_raises(self, builder, sample_dashboard):
        with pytest.raises(KeyError):
            builder.update_widget(sample_dashboard.id, "bad-widget-id", {"title": "X"})

    def test_remove_widget(self, builder, sample_dashboard, sample_widget):
        added = builder.add_widget(sample_dashboard.id, sample_widget)
        builder.remove_widget(sample_dashboard.id, added.id)
        fetched = builder.get_dashboard(sample_dashboard.id)
        assert len(fetched.widgets) == 0

    def test_remove_widget_not_found_raises(self, builder, sample_dashboard):
        with pytest.raises(KeyError):
            builder.remove_widget(sample_dashboard.id, "ghost-widget")

    def test_reorder_widgets(self, builder, sample_dashboard):
        ids = []
        for i in range(3):
            w = Widget(
                type=WidgetType.TABLE,
                title=f"W{i}",
                data_source=f"ds_{i}",
                order=i,
            )
            added = builder.add_widget(sample_dashboard.id, w)
            ids.append(added.id)

        # Reverse the order
        builder.reorder_widgets(sample_dashboard.id, list(reversed(ids)))
        fetched = builder.get_dashboard(sample_dashboard.id)
        ordered = sorted(fetched.widgets, key=lambda w: w.order)
        assert ordered[0].id == ids[2]
        assert ordered[1].id == ids[1]
        assert ordered[2].id == ids[0]

    def test_reorder_widgets_unknown_id_raises(self, builder, sample_dashboard, sample_widget):
        added = builder.add_widget(sample_dashboard.id, sample_widget)
        with pytest.raises(KeyError):
            builder.reorder_widgets(sample_dashboard.id, [added.id, "unknown-id"])


# ============================================================================
# Sharing & cloning
# ============================================================================


class TestSharingAndCloning:
    def test_share_dashboard_adds_emails(self, builder, sample_dashboard):
        updated = builder.share_dashboard(
            sample_dashboard.id, ["bob@b.com", "carol@c.com"]
        )
        assert "bob@b.com" in updated.shared_with
        assert "carol@c.com" in updated.shared_with

    def test_share_dashboard_deduplicates_emails(self, builder, sample_dashboard):
        builder.share_dashboard(sample_dashboard.id, ["eve@e.com"])
        updated = builder.share_dashboard(sample_dashboard.id, ["eve@e.com", "frank@f.com"])
        assert updated.shared_with.count("eve@e.com") == 1

    def test_share_dashboard_changes_visibility(self, builder, sample_dashboard):
        updated = builder.share_dashboard(
            sample_dashboard.id, [], DashboardVisibility.ORG
        )
        assert updated.visibility == DashboardVisibility.ORG

    def test_share_dashboard_not_found_raises(self, builder):
        with pytest.raises(KeyError):
            builder.share_dashboard("bad-id", ["x@x.com"])

    def test_clone_dashboard_creates_new(self, builder, sample_dashboard, sample_widget):
        builder.add_widget(sample_dashboard.id, sample_widget)
        cloned = builder.clone_dashboard(
            sample_dashboard.id, "Cloned Dashboard", "new_owner@x.com"
        )
        assert cloned.id != sample_dashboard.id
        assert cloned.name == "Cloned Dashboard"
        assert cloned.owner_email == "new_owner@x.com"
        assert cloned.visibility == DashboardVisibility.PRIVATE

    def test_clone_dashboard_copies_widgets(self, builder, sample_dashboard, sample_widget):
        builder.add_widget(sample_dashboard.id, sample_widget)
        cloned = builder.clone_dashboard(sample_dashboard.id, "Clone", "owner@x.com")
        assert len(cloned.widgets) == 1
        # Widget IDs should be different (new UUIDs)
        assert cloned.widgets[0].id != sample_widget.id

    def test_clone_dashboard_not_found_raises(self, builder):
        with pytest.raises(KeyError):
            builder.clone_dashboard("bad-id", "X", "y@y.com")


# ============================================================================
# Templates
# ============================================================================


class TestTemplates:
    def test_get_templates_returns_five(self, builder):
        templates = builder.get_templates()
        assert len(templates) >= 5

    def test_template_categories(self, builder):
        templates = builder.get_templates()
        ids = [t.id for t in templates]
        assert "tpl_ciso" in ids
        assert "tpl_soc" in ids
        assert "tpl_compliance" in ids
        assert "tpl_devsecops" in ids
        assert "tpl_executive" in ids

    def test_templates_have_widgets(self, builder):
        templates = builder.get_templates()
        for t in templates:
            assert isinstance(t, DashboardTemplate)
            assert len(t.widgets) > 0

    def test_create_from_template(self, builder):
        dash = builder.create_from_template(
            template_id="tpl_ciso",
            name="My CISO Dashboard",
            owner="ciso@company.com",
            org_id="org_a",
        )
        assert isinstance(dash, Dashboard)
        assert dash.name == "My CISO Dashboard"
        assert dash.owner_email == "ciso@company.com"
        assert len(dash.widgets) > 0

    def test_create_from_template_widgets_have_new_ids(self, builder):
        templates = builder.get_templates()
        template = next(t for t in templates if t.id == "tpl_soc")
        dash = builder.create_from_template(
            template_id="tpl_soc",
            name="SOC Dashboard",
            owner="analyst@company.com",
        )
        template_widget_ids = {w.id for w in template.widgets}
        dash_widget_ids = {w.id for w in dash.widgets}
        assert template_widget_ids.isdisjoint(dash_widget_ids)

    def test_create_from_template_not_found_raises(self, builder):
        with pytest.raises(KeyError):
            builder.create_from_template("tpl_nonexistent", "X", "y@y.com")

    def test_create_from_different_templates(self, builder):
        d1 = builder.create_from_template("tpl_compliance", "Compliance", "u@u.com")
        d2 = builder.create_from_template("tpl_devsecops", "DevSecOps", "u@u.com")
        assert d1.id != d2.id
        assert len(d1.widgets) > 0
        assert len(d2.widgets) > 0


# ============================================================================
# Widget library
# ============================================================================


class TestWidgetLibrary:
    def test_widget_library_returns_all_types(self, builder):
        library = builder.get_widget_library()
        widget_types = {entry["type"] for entry in library}
        for wt in WidgetType:
            assert wt in widget_types or wt.value in widget_types

    def test_widget_library_entries_have_schema(self, builder):
        library = builder.get_widget_library()
        for entry in library:
            assert "type" in entry
            assert "label" in entry
            assert "description" in entry
            assert "config_schema" in entry

    def test_widget_library_count(self, builder):
        library = builder.get_widget_library()
        assert len(library) == len(list(WidgetType))


# ============================================================================
# Dashboard stats
# ============================================================================


class TestDashboardStats:
    def test_stats_empty_org(self, builder):
        stats = builder.get_dashboard_stats("org_empty")
        assert stats["total_dashboards"] == 0
        assert stats["org_id"] == "org_empty"
        assert "template_count" in stats
        assert "widget_types_available" in stats

    def test_stats_counts_dashboards(self, builder):
        for i in range(3):
            builder.create_dashboard(f"D{i}", owner="u@u.com", org_id="org_stats")
        stats = builder.get_dashboard_stats("org_stats")
        assert stats["total_dashboards"] == 3

    def test_stats_by_visibility(self, builder):
        builder.create_dashboard("D1", owner="u@u.com", org_id="org_vis")
        d2 = builder.create_dashboard("D2", owner="u@u.com", org_id="org_vis")
        builder.update_dashboard(d2.id, {"visibility": "org"})
        stats = builder.get_dashboard_stats("org_vis")
        assert stats["by_visibility"].get("private", 0) >= 1
        assert stats["by_visibility"].get("org", 0) >= 1

    def test_stats_template_count(self, builder):
        stats = builder.get_dashboard_stats("default")
        assert stats["template_count"] >= 5


# ============================================================================
# API Router tests
# ============================================================================


@pytest.fixture
def api_client(tmp_db):
    """FastAPI TestClient with dashboard_builder_router mounted."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    # Patch auth so tests don't need a real token
    import apps.api.dashboard_builder_router as router_module
    async def _no_auth():
        return None
    router_module._verify_api_key = _no_auth

    # Inject tmp builder
    from core.dashboard_builder import DashboardBuilder
    router_module._builder = DashboardBuilder(db_path=tmp_db)

    from apps.api.dashboard_builder_router import router
    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


class TestAPIRouter:
    def test_create_dashboard(self, api_client):
        resp = api_client.post(
            "/api/v1/dashboards",
            json={"name": "API Dashboard", "owner_email": "api@test.com"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "API Dashboard"
        assert "id" in data

    def test_list_dashboards(self, api_client):
        api_client.post(
            "/api/v1/dashboards",
            json={"name": "D1", "owner_email": "u@u.com", "org_id": "org_list"},
        )
        api_client.post(
            "/api/v1/dashboards",
            json={"name": "D2", "owner_email": "u@u.com", "org_id": "org_list"},
        )
        resp = api_client.get("/api/v1/dashboards", params={"org_id": "org_list"})
        assert resp.status_code == 200
        assert len(resp.json()) == 2

    def test_get_dashboard(self, api_client):
        created = api_client.post(
            "/api/v1/dashboards",
            json={"name": "Fetch Me", "owner_email": "u@u.com"},
        ).json()
        resp = api_client.get(f"/api/v1/dashboards/{created['id']}")
        assert resp.status_code == 200
        assert resp.json()["id"] == created["id"]

    def test_get_dashboard_not_found(self, api_client):
        resp = api_client.get("/api/v1/dashboards/no-such-id")
        assert resp.status_code == 404

    def test_update_dashboard(self, api_client):
        created = api_client.post(
            "/api/v1/dashboards",
            json={"name": "Old Name", "owner_email": "u@u.com"},
        ).json()
        resp = api_client.put(
            f"/api/v1/dashboards/{created['id']}",
            json={"name": "New Name"},
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "New Name"

    def test_delete_dashboard(self, api_client):
        created = api_client.post(
            "/api/v1/dashboards",
            json={"name": "To Delete", "owner_email": "u@u.com"},
        ).json()
        resp = api_client.delete(f"/api/v1/dashboards/{created['id']}")
        assert resp.status_code == 200
        # Confirm gone
        get_resp = api_client.get(f"/api/v1/dashboards/{created['id']}")
        assert get_resp.status_code == 404

    def test_add_widget(self, api_client):
        created = api_client.post(
            "/api/v1/dashboards",
            json={"name": "Widget Test", "owner_email": "u@u.com"},
        ).json()
        resp = api_client.post(
            f"/api/v1/dashboards/{created['id']}/widgets",
            json={
                "type": "kpi_card",
                "title": "Score",
                "data_source": "metrics/score",
            },
        )
        assert resp.status_code == 200
        assert resp.json()["title"] == "Score"

    def test_update_widget(self, api_client):
        dash = api_client.post(
            "/api/v1/dashboards",
            json={"name": "W Update", "owner_email": "u@u.com"},
        ).json()
        widget = api_client.post(
            f"/api/v1/dashboards/{dash['id']}/widgets",
            json={"type": "table", "title": "Old", "data_source": "ds"},
        ).json()
        resp = api_client.put(
            f"/api/v1/dashboards/{dash['id']}/widgets/{widget['id']}",
            json={"title": "Updated"},
        )
        assert resp.status_code == 200
        assert resp.json()["title"] == "Updated"

    def test_remove_widget(self, api_client):
        dash = api_client.post(
            "/api/v1/dashboards",
            json={"name": "W Remove", "owner_email": "u@u.com"},
        ).json()
        widget = api_client.post(
            f"/api/v1/dashboards/{dash['id']}/widgets",
            json={"type": "timeline", "title": "Events", "data_source": "events"},
        ).json()
        resp = api_client.delete(
            f"/api/v1/dashboards/{dash['id']}/widgets/{widget['id']}"
        )
        assert resp.status_code == 200
        # Confirm widget gone
        dash_data = api_client.get(f"/api/v1/dashboards/{dash['id']}").json()
        assert len(dash_data["widgets"]) == 0

    def test_share_dashboard(self, api_client):
        dash = api_client.post(
            "/api/v1/dashboards",
            json={"name": "Share Me", "owner_email": "u@u.com"},
        ).json()
        resp = api_client.post(
            f"/api/v1/dashboards/{dash['id']}/share",
            json={"emails": ["peer@p.com"], "visibility": "team"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "peer@p.com" in data["shared_with"]
        assert data["visibility"] == "team"

    def test_clone_dashboard(self, api_client):
        dash = api_client.post(
            "/api/v1/dashboards",
            json={"name": "Original", "owner_email": "u@u.com"},
        ).json()
        resp = api_client.post(
            f"/api/v1/dashboards/{dash['id']}/clone",
            json={"new_name": "Cloned", "new_owner": "new@n.com"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "Cloned"
        assert data["owner_email"] == "new@n.com"
        assert data["id"] != dash["id"]

    def test_list_templates(self, api_client):
        resp = api_client.get("/api/v1/dashboards/templates")
        assert resp.status_code == 200
        templates = resp.json()
        assert len(templates) >= 5

    def test_create_from_template(self, api_client):
        resp = api_client.post(
            "/api/v1/dashboards/from-template",
            json={
                "template_id": "tpl_executive",
                "name": "Exec Dashboard",
                "owner_email": "exec@company.com",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "Exec Dashboard"
        assert len(data["widgets"]) > 0

    def test_create_from_template_not_found(self, api_client):
        resp = api_client.post(
            "/api/v1/dashboards/from-template",
            json={"template_id": "tpl_unknown", "name": "X", "owner_email": "u@u.com"},
        )
        assert resp.status_code == 404

    def test_widget_library_endpoint(self, api_client):
        resp = api_client.get("/api/v1/dashboards/widget-library")
        assert resp.status_code == 200
        library = resp.json()
        assert len(library) == len(list(WidgetType))
        for entry in library:
            assert "type" in entry
            assert "label" in entry
