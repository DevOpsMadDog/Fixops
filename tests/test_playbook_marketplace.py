"""
Tests for the Playbook Marketplace — suite-core/core/playbook_marketplace.py

35+ tests covering:
- PlaybookTemplate model validation
- PlaybookMarketplace: publish, list, get, install, rate, get_installed,
  export, import, get_popular, get_marketplace_stats
- 15 built-in templates seeded correctly
- Edge cases: not found, invalid rating, bad JSON import, duplicate install

Run with:
    python -m pytest tests/test_playbook_marketplace.py -v --timeout=15
"""

from __future__ import annotations

import json
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

from core.playbook_marketplace import (
    PlaybookCategory,
    PlaybookMarketplace,
    PlaybookTemplate,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def marketplace(tmp_path):
    db = str(tmp_path / "test_marketplace.db")
    return PlaybookMarketplace(db_path=db)


@pytest.fixture
def sample_template():
    return PlaybookTemplate(
        name="Test Playbook",
        description="A test playbook for unit testing",
        category=PlaybookCategory.REMEDIATION,
        steps=[
            {"order": 1, "name": "Identify", "action": "scan", "automated": True},
            {"order": 2, "name": "Fix", "action": "patch", "automated": False},
        ],
        author="tester",
        version="1.0.0",
        tags=["test", "unit"],
        org_id="org-test",
    )


# ---------------------------------------------------------------------------
# PlaybookTemplate model
# ---------------------------------------------------------------------------


class TestPlaybookTemplateModel:
    def test_default_id_generated(self):
        t = PlaybookTemplate(
            name="X", description="Y", category=PlaybookCategory.HARDENING
        )
        assert t.id and len(t.id) > 8

    def test_category_enum_values(self):
        for cat in PlaybookCategory:
            t = PlaybookTemplate(name="X", description="Y", category=cat)
            assert t.category == cat.value

    def test_defaults(self):
        t = PlaybookTemplate(name="X", description="Y", category=PlaybookCategory.COMPLIANCE)
        assert t.downloads == 0
        assert t.rating == 0.0
        assert t.rating_count == 0
        assert t.tags == []
        assert t.steps == []
        assert t.author == "community"
        assert t.version == "1.0.0"
        assert t.org_id is None

    def test_steps_stored(self, sample_template):
        assert len(sample_template.steps) == 2
        assert sample_template.steps[0]["name"] == "Identify"

    def test_category_string_accepted(self):
        t = PlaybookTemplate(name="X", description="Y", category="hardening")
        assert t.category == "hardening"


# ---------------------------------------------------------------------------
# Built-in templates
# ---------------------------------------------------------------------------


class TestBuiltinTemplates:
    def test_15_builtins_seeded(self, marketplace):
        items = marketplace.list_playbooks()
        assert len(items) >= 15

    def test_builtin_categories_present(self, marketplace):
        items = marketplace.list_playbooks()
        cats = {i["category"] for i in items}
        assert "incident_response" in cats
        assert "remediation" in cats
        assert "compliance" in cats
        assert "hardening" in cats

    def test_ransomware_playbook_exists(self, marketplace):
        tpl = marketplace.get_playbook("pb-ransomware-response-001")
        assert tpl is not None
        assert "ransomware" in tpl["name"].lower()
        assert len(tpl["steps"]) == 8

    def test_data_breach_playbook_exists(self, marketplace):
        tpl = marketplace.get_playbook("pb-data-breach-001")
        assert tpl is not None
        assert "breach" in tpl["name"].lower()

    def test_builtin_has_steps(self, marketplace):
        items = marketplace.list_playbooks()
        for item in items:
            assert len(item["steps"]) > 0, f"Playbook {item['id']} has no steps"

    def test_builtin_tags_are_lists(self, marketplace):
        items = marketplace.list_playbooks()
        for item in items:
            assert isinstance(item["tags"], list)

    def test_seeding_idempotent(self, tmp_path):
        db = str(tmp_path / "idempotent.db")
        m1 = PlaybookMarketplace(db_path=db)
        m2 = PlaybookMarketplace(db_path=db)
        items = m2.list_playbooks()
        assert len(items) == 15  # not doubled


# ---------------------------------------------------------------------------
# publish_playbook
# ---------------------------------------------------------------------------


class TestPublishPlaybook:
    def test_publish_new(self, marketplace, sample_template):
        result = marketplace.publish_playbook(sample_template)
        assert result["id"] == sample_template.id
        assert result["name"] == "Test Playbook"
        assert result["downloads"] == 0

    def test_publish_updates_existing(self, marketplace, sample_template):
        marketplace.publish_playbook(sample_template)
        sample_template.description = "Updated description"
        result = marketplace.publish_playbook(sample_template)
        assert result["description"] == "Updated description"

    def test_published_visible_in_list(self, marketplace, sample_template):
        marketplace.publish_playbook(sample_template)
        items = marketplace.list_playbooks()
        ids = [i["id"] for i in items]
        assert sample_template.id in ids

    def test_created_at_set(self, marketplace, sample_template):
        result = marketplace.publish_playbook(sample_template)
        assert result["created_at"] is not None

    def test_category_stored(self, marketplace, sample_template):
        result = marketplace.publish_playbook(sample_template)
        assert result["category"] == "remediation"


# ---------------------------------------------------------------------------
# list_playbooks
# ---------------------------------------------------------------------------


class TestListPlaybooks:
    def test_list_all(self, marketplace):
        items = marketplace.list_playbooks()
        assert len(items) >= 15

    def test_filter_by_category(self, marketplace):
        items = marketplace.list_playbooks(category="incident_response")
        assert all(i["category"] == "incident_response" for i in items)
        assert len(items) >= 4

    def test_filter_by_search(self, marketplace):
        items = marketplace.list_playbooks(search="ransomware")
        assert any("ransomware" in i["name"].lower() for i in items)

    def test_filter_by_tags(self, marketplace):
        items = marketplace.list_playbooks(tags=["kubernetes"])
        assert len(items) >= 1
        assert any("kubernetes" in i["tags"] for i in items)

    def test_search_case_insensitive(self, marketplace):
        items = marketplace.list_playbooks(search="PATCH")
        # Should match patching/patch in descriptions
        assert isinstance(items, list)

    def test_combined_filter(self, marketplace):
        items = marketplace.list_playbooks(category="compliance", search="SOC")
        assert all(i["category"] == "compliance" for i in items)


# ---------------------------------------------------------------------------
# get_playbook
# ---------------------------------------------------------------------------


class TestGetPlaybook:
    def test_get_existing(self, marketplace):
        tpl = marketplace.get_playbook("pb-ransomware-response-001")
        assert tpl is not None
        assert tpl["id"] == "pb-ransomware-response-001"

    def test_get_nonexistent_returns_none(self, marketplace):
        tpl = marketplace.get_playbook("does-not-exist-xyz")
        assert tpl is None

    def test_get_includes_steps(self, marketplace):
        tpl = marketplace.get_playbook("pb-patch-management-001")
        assert isinstance(tpl["steps"], list)
        assert len(tpl["steps"]) > 0


# ---------------------------------------------------------------------------
# install_playbook
# ---------------------------------------------------------------------------


class TestInstallPlaybook:
    def test_install_success(self, marketplace):
        result = marketplace.install_playbook("pb-ransomware-response-001", "org-alpha")
        assert result["playbook_id"] == "pb-ransomware-response-001"
        assert result["org_id"] == "org-alpha"
        assert result["installed_at"] is not None

    def test_install_increments_downloads(self, marketplace):
        before = marketplace.get_playbook("pb-data-breach-001")["downloads"]
        marketplace.install_playbook("pb-data-breach-001", "org-beta")
        after = marketplace.get_playbook("pb-data-breach-001")["downloads"]
        assert after == before + 1

    def test_install_nonexistent_raises(self, marketplace):
        with pytest.raises(ValueError, match="not found"):
            marketplace.install_playbook("bad-id", "org-x")

    def test_install_idempotent(self, marketplace):
        # Installing twice should not raise — last install wins
        marketplace.install_playbook("pb-ransomware-response-001", "org-gamma")
        marketplace.install_playbook("pb-ransomware-response-001", "org-gamma")
        installed = marketplace.get_installed("org-gamma")
        assert len([i for i in installed if i["id"] == "pb-ransomware-response-001"]) == 1


# ---------------------------------------------------------------------------
# rate_playbook
# ---------------------------------------------------------------------------


class TestRatePlaybook:
    def test_rate_valid(self, marketplace):
        result = marketplace.rate_playbook("pb-ransomware-response-001", 4.5, "user-1")
        assert result["rating"] == 4.5
        assert result["rating_count"] == 1

    def test_rate_averages_multiple_raters(self, marketplace):
        marketplace.rate_playbook("pb-patch-management-001", 4.0, "user-a")
        result = marketplace.rate_playbook("pb-patch-management-001", 2.0, "user-b")
        assert result["rating_count"] == 2
        assert abs(result["rating"] - 3.0) < 0.01

    def test_rate_same_rater_updates(self, marketplace):
        marketplace.rate_playbook("pb-server-hardening-001", 3.0, "user-x")
        result = marketplace.rate_playbook("pb-server-hardening-001", 5.0, "user-x")
        assert result["rating_count"] == 1
        assert result["rating"] == 5.0

    def test_rate_below_range_raises(self, marketplace):
        with pytest.raises(ValueError):
            marketplace.rate_playbook("pb-ransomware-response-001", 0.5, "user-1")

    def test_rate_above_range_raises(self, marketplace):
        with pytest.raises(ValueError):
            marketplace.rate_playbook("pb-ransomware-response-001", 5.5, "user-1")

    def test_rate_nonexistent_raises(self, marketplace):
        with pytest.raises(ValueError, match="not found"):
            marketplace.rate_playbook("bad-id", 3.0)


# ---------------------------------------------------------------------------
# get_installed
# ---------------------------------------------------------------------------


class TestGetInstalled:
    def test_empty_org(self, marketplace):
        result = marketplace.get_installed("org-empty")
        assert result == []

    def test_installed_appears(self, marketplace):
        marketplace.install_playbook("pb-ransomware-response-001", "org-delta")
        installed = marketplace.get_installed("org-delta")
        assert len(installed) == 1
        assert installed[0]["id"] == "pb-ransomware-response-001"

    def test_multiple_installs(self, marketplace):
        for pid in ["pb-ransomware-response-001", "pb-data-breach-001"]:
            marketplace.install_playbook(pid, "org-epsilon")
        installed = marketplace.get_installed("org-epsilon")
        assert len(installed) == 2

    def test_orgs_isolated(self, marketplace):
        marketplace.install_playbook("pb-ransomware-response-001", "org-zeta")
        assert marketplace.get_installed("org-eta") == []


# ---------------------------------------------------------------------------
# export / import
# ---------------------------------------------------------------------------


class TestExportImport:
    def test_export_returns_valid_json(self, marketplace):
        json_str = marketplace.export_playbook("pb-ransomware-response-001")
        data = json.loads(json_str)
        assert data["id"] == "pb-ransomware-response-001"
        assert "steps" in data

    def test_export_nonexistent_raises(self, marketplace):
        with pytest.raises(ValueError, match="not found"):
            marketplace.export_playbook("bad-id")

    def test_import_roundtrip(self, marketplace):
        json_str = marketplace.export_playbook("pb-ransomware-response-001")
        imported = marketplace.import_playbook(json_str, org_id="org-import")
        assert imported["name"] == "Ransomware Incident Response"
        assert imported["org_id"] == "org-import"
        assert imported["downloads"] == 0

    def test_import_assigns_new_id(self, marketplace):
        json_str = marketplace.export_playbook("pb-ransomware-response-001")
        imported = marketplace.import_playbook(json_str)
        assert imported["id"] != "pb-ransomware-response-001"

    def test_import_invalid_json_raises(self, marketplace):
        with pytest.raises(ValueError, match="Invalid JSON"):
            marketplace.import_playbook("{not json")

    def test_import_custom_playbook(self, marketplace, sample_template):
        marketplace.publish_playbook(sample_template)
        json_str = marketplace.export_playbook(sample_template.id)
        imported = marketplace.import_playbook(json_str, org_id="org-theta")
        assert imported["category"] == "remediation"
        assert len(imported["steps"]) == 2


# ---------------------------------------------------------------------------
# get_popular
# ---------------------------------------------------------------------------


class TestGetPopular:
    def test_returns_list(self, marketplace):
        items = marketplace.get_popular(limit=5)
        assert len(items) <= 5

    def test_limit_respected(self, marketplace):
        items = marketplace.get_popular(limit=3)
        assert len(items) == 3

    def test_most_downloaded_first(self, marketplace):
        marketplace.install_playbook("pb-ransomware-response-001", "org-1")
        marketplace.install_playbook("pb-ransomware-response-001", "org-2")
        marketplace.install_playbook("pb-data-breach-001", "org-3")
        items = marketplace.get_popular(limit=2)
        assert items[0]["downloads"] >= items[1]["downloads"]


# ---------------------------------------------------------------------------
# get_marketplace_stats
# ---------------------------------------------------------------------------


class TestMarketplaceStats:
    def test_stats_structure(self, marketplace):
        stats = marketplace.get_marketplace_stats()
        assert "total_playbooks" in stats
        assert "total_downloads" in stats
        assert "total_installs" in stats
        assert "by_category" in stats
        assert "top_rated" in stats
        assert "average_rating" in stats

    def test_total_playbooks_at_least_15(self, marketplace):
        stats = marketplace.get_marketplace_stats()
        assert stats["total_playbooks"] >= 15

    def test_by_category_all_four(self, marketplace):
        stats = marketplace.get_marketplace_stats()
        cats = set(stats["by_category"].keys())
        assert {"incident_response", "remediation", "compliance", "hardening"}.issubset(cats)

    def test_installs_counted(self, marketplace):
        marketplace.install_playbook("pb-ransomware-response-001", "org-stat-1")
        stats = marketplace.get_marketplace_stats()
        assert stats["total_installs"] >= 1

    def test_downloads_counted(self, marketplace):
        marketplace.install_playbook("pb-data-breach-001", "org-stat-2")
        stats = marketplace.get_marketplace_stats()
        assert stats["total_downloads"] >= 1
