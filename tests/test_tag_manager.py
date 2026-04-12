"""Tests for the unified Tag Management system.

Covers:
- Tag CRUD (create, get, list, update, delete)
- Tag hierarchy (parent/child, get_tag_hierarchy)
- Entity apply/remove/get
- Bulk apply
- Find entities by tag
- Auto-tag rules (create, list, evaluate)
- Search
- Analytics
- Merge
- Cascade delete

Usage:
    pytest tests/test_tag_manager.py -v --timeout=10
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict

import pytest

# Ensure suite-core is on the path
suite_core_path = str(Path(__file__).parent.parent / "suite-core")
if suite_core_path not in sys.path:
    sys.path.insert(0, suite_core_path)

from core.tag_manager import AutoTagRule, EntityType, Tag, TagManager


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mgr(tmp_path):
    """Fresh TagManager backed by a temp SQLite DB."""
    db_path = str(tmp_path / "tags_test.db")
    return TagManager(db_path=db_path)


@pytest.fixture
def org():
    return "test-org"


@pytest.fixture
def red_tag(mgr, org):
    return mgr.create_tag("critical", "#FF0000", "Critical priority", org_id=org)


@pytest.fixture
def blue_tag(mgr, org):
    return mgr.create_tag("info", "#0000FF", "Informational", org_id=org)


# ---------------------------------------------------------------------------
# Tag CRUD
# ---------------------------------------------------------------------------


class TestTagCRUD:
    def test_create_tag_returns_tag(self, mgr, org):
        tag = mgr.create_tag("vuln", "#FF6600", "Vulnerability", org_id=org)
        assert isinstance(tag, Tag)
        assert tag.name == "vuln"
        assert tag.color == "#FF6600"
        assert tag.description == "Vulnerability"
        assert tag.org_id == org
        assert tag.id.startswith("tag-")

    def test_create_tag_defaults(self, mgr, org):
        tag = mgr.create_tag("simple", org_id=org)
        assert tag.color == "#6B7280"
        assert tag.description == ""
        assert tag.parent_id is None

    def test_get_tag_by_id(self, mgr, org, red_tag):
        fetched = mgr.get_tag(red_tag.id)
        assert fetched is not None
        assert fetched.id == red_tag.id
        assert fetched.name == "critical"

    def test_get_tag_missing_returns_none(self, mgr):
        assert mgr.get_tag("tag-nonexistent") is None

    def test_list_tags_returns_all_for_org(self, mgr, org, red_tag, blue_tag):
        tags = mgr.list_tags(org_id=org)
        ids = [t.id for t in tags]
        assert red_tag.id in ids
        assert blue_tag.id in ids

    def test_list_tags_isolated_by_org(self, mgr, org, red_tag):
        other_tags = mgr.list_tags(org_id="other-org")
        assert all(t.id != red_tag.id for t in other_tags)

    def test_update_tag_name(self, mgr, org, red_tag):
        updated = mgr.update_tag(red_tag.id, {"name": "CRITICAL"})
        assert updated is not None
        assert updated.name == "CRITICAL"

    def test_update_tag_color(self, mgr, org, red_tag):
        updated = mgr.update_tag(red_tag.id, {"color": "#123456"})
        assert updated.color == "#123456"

    def test_update_tag_description(self, mgr, org, red_tag):
        updated = mgr.update_tag(red_tag.id, {"description": "Updated desc"})
        assert updated.description == "Updated desc"

    def test_update_tag_missing_returns_none(self, mgr):
        result = mgr.update_tag("tag-missing", {"name": "x"})
        assert result is None

    def test_delete_tag(self, mgr, org, red_tag):
        assert mgr.delete_tag(red_tag.id) is True
        assert mgr.get_tag(red_tag.id) is None

    def test_delete_tag_missing_returns_false(self, mgr):
        assert mgr.delete_tag("tag-missing") is False

    def test_delete_cascades_from_entities(self, mgr, org, red_tag):
        mgr.apply_tag(EntityType.FINDING, "f-001", red_tag.id)
        mgr.delete_tag(red_tag.id)
        remaining = mgr.get_entity_tags(EntityType.FINDING, "f-001")
        assert all(t.id != red_tag.id for t in remaining)


# ---------------------------------------------------------------------------
# Tag Hierarchy
# ---------------------------------------------------------------------------


class TestTagHierarchy:
    def test_create_child_tag(self, mgr, org, red_tag):
        child = mgr.create_tag("rce", "#FF0000", "Remote code exec", parent_id=red_tag.id, org_id=org)
        assert child.parent_id == red_tag.id

    def test_list_tags_with_parent_filter(self, mgr, org, red_tag):
        child = mgr.create_tag("rce", "#FF0000", parent_id=red_tag.id, org_id=org)
        mgr.create_tag("other", "#000000", org_id=org)
        children = mgr.list_tags(org_id=org, parent_id=red_tag.id)
        assert any(t.id == child.id for t in children)
        assert all(t.parent_id == red_tag.id for t in children)

    def test_list_root_tags(self, mgr, org, red_tag, blue_tag):
        child = mgr.create_tag("child", "#000000", parent_id=red_tag.id, org_id=org)
        roots = mgr.list_tags(org_id=org, parent_id="__root__")
        root_ids = [t.id for t in roots]
        assert red_tag.id in root_ids
        assert blue_tag.id in root_ids
        assert child.id not in root_ids

    def test_get_tag_hierarchy_tree(self, mgr, org, red_tag, blue_tag):
        child = mgr.create_tag("rce", "#FF0000", parent_id=red_tag.id, org_id=org)
        tree = mgr.get_tag_hierarchy(org_id=org)
        assert isinstance(tree, list)
        # Find the red_tag node
        red_node = next((n for n in tree if n["id"] == red_tag.id), None)
        assert red_node is not None
        assert any(c["id"] == child.id for c in red_node["children"])

    def test_get_tag_hierarchy_no_tags(self, mgr, org):
        tree = mgr.get_tag_hierarchy(org_id=org)
        assert tree == []


# ---------------------------------------------------------------------------
# Apply / Remove / Get entity tags
# ---------------------------------------------------------------------------


class TestEntityTagOperations:
    def test_apply_tag_to_finding(self, mgr, org, red_tag):
        mgr.apply_tag(EntityType.FINDING, "f-001", red_tag.id)
        tags = mgr.get_entity_tags(EntityType.FINDING, "f-001")
        assert any(t.id == red_tag.id for t in tags)

    def test_apply_tag_idempotent(self, mgr, org, red_tag):
        mgr.apply_tag(EntityType.FINDING, "f-001", red_tag.id)
        mgr.apply_tag(EntityType.FINDING, "f-001", red_tag.id)
        tags = mgr.get_entity_tags(EntityType.FINDING, "f-001")
        assert len([t for t in tags if t.id == red_tag.id]) == 1

    def test_remove_tag_from_entity(self, mgr, org, red_tag):
        mgr.apply_tag(EntityType.ASSET, "a-001", red_tag.id)
        mgr.remove_tag(EntityType.ASSET, "a-001", red_tag.id)
        tags = mgr.get_entity_tags(EntityType.ASSET, "a-001")
        assert all(t.id != red_tag.id for t in tags)

    def test_get_entity_tags_empty(self, mgr):
        tags = mgr.get_entity_tags(EntityType.VENDOR, "v-999")
        assert tags == []

    def test_apply_multiple_tags(self, mgr, org, red_tag, blue_tag):
        mgr.apply_tag(EntityType.INCIDENT, "i-001", red_tag.id)
        mgr.apply_tag(EntityType.INCIDENT, "i-001", blue_tag.id)
        tags = mgr.get_entity_tags(EntityType.INCIDENT, "i-001")
        assert len(tags) == 2

    def test_all_entity_types_supported(self, mgr, org, red_tag):
        for et in EntityType:
            mgr.apply_tag(et, f"entity-{et.value}", red_tag.id)
            tags = mgr.get_entity_tags(et, f"entity-{et.value}")
            assert any(t.id == red_tag.id for t in tags)


# ---------------------------------------------------------------------------
# Find entities by tag
# ---------------------------------------------------------------------------


class TestFindEntitiesByTag:
    def test_find_entities_by_tag(self, mgr, org, red_tag):
        mgr.apply_tag(EntityType.FINDING, "f-001", red_tag.id)
        mgr.apply_tag(EntityType.FINDING, "f-002", red_tag.id)
        ids = mgr.find_entities_by_tag(red_tag.id, EntityType.FINDING)
        assert "f-001" in ids
        assert "f-002" in ids

    def test_find_entities_by_tag_no_filter(self, mgr, org, red_tag):
        mgr.apply_tag(EntityType.FINDING, "f-001", red_tag.id)
        mgr.apply_tag(EntityType.ASSET, "a-001", red_tag.id)
        ids = mgr.find_entities_by_tag(red_tag.id)
        assert "f-001" in ids
        assert "a-001" in ids

    def test_find_entities_by_tag_empty(self, mgr, org, red_tag):
        ids = mgr.find_entities_by_tag(red_tag.id, EntityType.SBOM)
        assert ids == []


# ---------------------------------------------------------------------------
# Bulk apply
# ---------------------------------------------------------------------------


class TestBulkApply:
    def test_bulk_apply_tags(self, mgr, org, red_tag, blue_tag):
        entity_ids = ["f-001", "f-002", "f-003"]
        mgr.bulk_apply(EntityType.FINDING, entity_ids, [red_tag.id, blue_tag.id])
        for eid in entity_ids:
            tags = mgr.get_entity_tags(EntityType.FINDING, eid)
            tag_ids = [t.id for t in tags]
            assert red_tag.id in tag_ids
            assert blue_tag.id in tag_ids

    def test_bulk_apply_idempotent(self, mgr, org, red_tag):
        mgr.bulk_apply(EntityType.FINDING, ["f-001"], [red_tag.id])
        mgr.bulk_apply(EntityType.FINDING, ["f-001"], [red_tag.id])
        tags = mgr.get_entity_tags(EntityType.FINDING, "f-001")
        assert len([t for t in tags if t.id == red_tag.id]) == 1


# ---------------------------------------------------------------------------
# Auto-tag rules
# ---------------------------------------------------------------------------


class TestAutoTagRules:
    def test_create_auto_rule(self, mgr, org, red_tag):
        rule = AutoTagRule(
            name="Flag critical findings",
            conditions={"field": "severity", "op": "eq", "value": "critical"},
            tags_to_apply=[red_tag.id],
            entity_type=EntityType.FINDING,
            org_id=org,
        )
        created = mgr.create_auto_rule(rule)
        assert created.id == rule.id
        assert created.name == "Flag critical findings"

    def test_list_auto_rules(self, mgr, org, red_tag):
        rule = AutoTagRule(
            name="Rule A",
            conditions={},
            tags_to_apply=[red_tag.id],
            entity_type=EntityType.FINDING,
            org_id=org,
        )
        mgr.create_auto_rule(rule)
        rules = mgr.list_auto_rules(org_id=org)
        assert any(r.id == rule.id for r in rules)

    def test_evaluate_auto_rules_match(self, mgr, org, red_tag):
        rule = AutoTagRule(
            name="Critical rule",
            conditions={"field": "severity", "op": "eq", "value": "critical"},
            tags_to_apply=[red_tag.id],
            entity_type=EntityType.FINDING,
            enabled=True,
            org_id=org,
        )
        mgr.create_auto_rule(rule)
        entity = {"severity": "critical", "title": "SQL Injection"}
        tags = mgr.evaluate_auto_rules(EntityType.FINDING, entity, org_id=org)
        assert red_tag.id in tags

    def test_evaluate_auto_rules_no_match(self, mgr, org, red_tag):
        rule = AutoTagRule(
            name="Critical rule",
            conditions={"field": "severity", "op": "eq", "value": "critical"},
            tags_to_apply=[red_tag.id],
            entity_type=EntityType.FINDING,
            enabled=True,
            org_id=org,
        )
        mgr.create_auto_rule(rule)
        entity = {"severity": "low"}
        tags = mgr.evaluate_auto_rules(EntityType.FINDING, entity, org_id=org)
        assert red_tag.id not in tags

    def test_evaluate_auto_rules_disabled_skipped(self, mgr, org, red_tag):
        rule = AutoTagRule(
            name="Disabled rule",
            conditions={"field": "severity", "op": "eq", "value": "critical"},
            tags_to_apply=[red_tag.id],
            entity_type=EntityType.FINDING,
            enabled=False,
            org_id=org,
        )
        mgr.create_auto_rule(rule)
        entity = {"severity": "critical"}
        tags = mgr.evaluate_auto_rules(EntityType.FINDING, entity, org_id=org)
        assert red_tag.id not in tags

    def test_evaluate_auto_rules_contains_op(self, mgr, org, blue_tag):
        rule = AutoTagRule(
            name="Contains rule",
            conditions={"field": "title", "op": "contains", "value": "SQL"},
            tags_to_apply=[blue_tag.id],
            entity_type=EntityType.FINDING,
            enabled=True,
            org_id=org,
        )
        mgr.create_auto_rule(rule)
        entity = {"title": "SQL Injection"}
        tags = mgr.evaluate_auto_rules(EntityType.FINDING, entity, org_id=org)
        assert blue_tag.id in tags

    def test_evaluate_auto_rules_gt_op(self, mgr, org, red_tag):
        rule = AutoTagRule(
            name="High CVSS",
            conditions={"field": "cvss", "op": "gt", "value": 7.0},
            tags_to_apply=[red_tag.id],
            entity_type=EntityType.FINDING,
            enabled=True,
            org_id=org,
        )
        mgr.create_auto_rule(rule)
        assert red_tag.id in mgr.evaluate_auto_rules(EntityType.FINDING, {"cvss": 9.0}, org_id=org)
        assert red_tag.id not in mgr.evaluate_auto_rules(EntityType.FINDING, {"cvss": 5.0}, org_id=org)

    def test_evaluate_auto_rules_in_op(self, mgr, org, red_tag):
        rule = AutoTagRule(
            name="In list",
            conditions={"field": "status", "op": "in", "value": ["open", "reopened"]},
            tags_to_apply=[red_tag.id],
            entity_type=EntityType.FINDING,
            enabled=True,
            org_id=org,
        )
        mgr.create_auto_rule(rule)
        assert red_tag.id in mgr.evaluate_auto_rules(EntityType.FINDING, {"status": "open"}, org_id=org)
        assert red_tag.id not in mgr.evaluate_auto_rules(EntityType.FINDING, {"status": "closed"}, org_id=org)

    def test_evaluate_deduplicates_tags(self, mgr, org, red_tag):
        for i in range(3):
            rule = AutoTagRule(
                name=f"Rule {i}",
                conditions={},
                tags_to_apply=[red_tag.id],
                entity_type=EntityType.FINDING,
                enabled=True,
                org_id=org,
            )
            mgr.create_auto_rule(rule)
        tags = mgr.evaluate_auto_rules(EntityType.FINDING, {}, org_id=org)
        assert tags.count(red_tag.id) == 1


# ---------------------------------------------------------------------------
# Search
# ---------------------------------------------------------------------------


class TestSearch:
    def test_search_by_name(self, mgr, org):
        mgr.create_tag("authentication", "#000", org_id=org)
        mgr.create_tag("authorisation", "#111", org_id=org)
        mgr.create_tag("unrelated", "#222", org_id=org)
        results = mgr.search_tags("auth", org_id=org)
        names = [t.name for t in results]
        assert "authentication" in names
        assert "authorisation" in names
        assert "unrelated" not in names

    def test_search_by_description(self, mgr, org):
        mgr.create_tag("xss", "#000", description="Cross-site scripting", org_id=org)
        results = mgr.search_tags("cross-site", org_id=org)
        assert any(t.name == "xss" for t in results)

    def test_search_no_results(self, mgr, org):
        results = mgr.search_tags("zzznomatch", org_id=org)
        assert results == []

    def test_search_case_insensitive(self, mgr, org):
        mgr.create_tag("CRITICAL", "#FF0000", org_id=org)
        results = mgr.search_tags("critical", org_id=org)
        assert any(t.name == "CRITICAL" for t in results)


# ---------------------------------------------------------------------------
# Analytics
# ---------------------------------------------------------------------------


class TestAnalytics:
    def test_analytics_returns_dict(self, mgr, org):
        analytics = mgr.get_tag_analytics(org_id=org)
        assert isinstance(analytics, dict)
        assert "most_used" in analytics
        assert "trending" in analytics
        assert "by_entity_type" in analytics
        assert "total_tags" in analytics
        assert "total_applied" in analytics

    def test_analytics_most_used(self, mgr, org, red_tag, blue_tag):
        # Apply red_tag to 3 entities, blue_tag to 1
        for i in range(3):
            mgr.apply_tag(EntityType.FINDING, f"f-{i}", red_tag.id)
        mgr.apply_tag(EntityType.FINDING, "f-99", blue_tag.id)
        analytics = mgr.get_tag_analytics(org_id=org)
        most_used = analytics["most_used"]
        assert len(most_used) >= 1
        top_name = most_used[0]["name"]
        assert top_name == "critical"

    def test_analytics_by_entity_type(self, mgr, org, red_tag):
        mgr.apply_tag(EntityType.FINDING, "f-001", red_tag.id)
        mgr.apply_tag(EntityType.ASSET, "a-001", red_tag.id)
        analytics = mgr.get_tag_analytics(org_id=org)
        by_type = analytics["by_entity_type"]
        assert "finding" in by_type
        assert "asset" in by_type


# ---------------------------------------------------------------------------
# Merge
# ---------------------------------------------------------------------------


class TestMerge:
    def test_merge_reassigns_entities(self, mgr, org, red_tag, blue_tag):
        mgr.apply_tag(EntityType.FINDING, "f-001", red_tag.id)
        mgr.apply_tag(EntityType.FINDING, "f-002", red_tag.id)
        mgr.merge_tags(source_tag_id=red_tag.id, target_tag_id=blue_tag.id)
        # Both entities should now carry blue_tag
        for eid in ("f-001", "f-002"):
            tags = mgr.get_entity_tags(EntityType.FINDING, eid)
            assert any(t.id == blue_tag.id for t in tags)

    def test_merge_deletes_source(self, mgr, org, red_tag, blue_tag):
        mgr.merge_tags(source_tag_id=red_tag.id, target_tag_id=blue_tag.id)
        assert mgr.get_tag(red_tag.id) is None

    def test_merge_keeps_target(self, mgr, org, red_tag, blue_tag):
        mgr.merge_tags(source_tag_id=red_tag.id, target_tag_id=blue_tag.id)
        assert mgr.get_tag(blue_tag.id) is not None

    def test_merge_no_duplicate_on_overlap(self, mgr, org, red_tag, blue_tag):
        # Entity already has both tags — after merge should still have blue_tag once
        mgr.apply_tag(EntityType.FINDING, "f-001", red_tag.id)
        mgr.apply_tag(EntityType.FINDING, "f-001", blue_tag.id)
        mgr.merge_tags(source_tag_id=red_tag.id, target_tag_id=blue_tag.id)
        tags = mgr.get_entity_tags(EntityType.FINDING, "f-001")
        blue_count = sum(1 for t in tags if t.id == blue_tag.id)
        assert blue_count == 1
