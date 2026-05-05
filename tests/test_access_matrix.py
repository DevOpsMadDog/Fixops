"""
Tests for the AccessMatrix — core module + FastAPI router.

Covers:
- AccessLevel ordering
- AccessRule model validation
- AccessMatrix CRUD (grant, revoke, list)
- check_access: specific rule, wildcard rule, no rule
- get_effective_permissions
- get_resource_acl
- audit_access_check logging
- get_access_stats
- Default seeded rules for all 6 ALDECI roles
- Router endpoints via FastAPI TestClient
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Generator

import pytest

os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from core.access_matrix import (
    AccessLevel,
    AccessMatrix,
    AccessRule,
    ResourceType,
    get_access_matrix,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def tmp_db(tmp_path: Path) -> str:
    return str(tmp_path / "test_access.db")


@pytest.fixture
def matrix(tmp_db: str) -> AccessMatrix:
    return AccessMatrix(db_path=tmp_db)


# ============================================================================
# AccessLevel ordering tests
# ============================================================================


class TestAccessLevelOrdering:
    def test_none_is_lowest(self):
        assert AccessLevel.NONE < AccessLevel.READ

    def test_read_lt_write(self):
        assert AccessLevel.READ < AccessLevel.WRITE

    def test_write_lt_admin(self):
        assert AccessLevel.WRITE < AccessLevel.ADMIN

    def test_admin_lt_owner(self):
        assert AccessLevel.ADMIN < AccessLevel.OWNER

    def test_owner_ge_owner(self):
        assert AccessLevel.OWNER >= AccessLevel.OWNER

    def test_write_ge_read(self):
        assert AccessLevel.WRITE >= AccessLevel.READ

    def test_none_not_ge_read(self):
        assert not (AccessLevel.NONE >= AccessLevel.READ)

    def test_ordinal_values(self):
        levels = [AccessLevel.NONE, AccessLevel.READ, AccessLevel.WRITE,
                  AccessLevel.ADMIN, AccessLevel.OWNER]
        ordinals = [l.ordinal for l in levels]
        assert ordinals == sorted(ordinals)


# ============================================================================
# AccessRule model tests
# ============================================================================


class TestAccessRule:
    def test_default_id_generated(self):
        rule = AccessRule(
            role="viewer",
            resource_type=ResourceType.FINDING,
            access_level=AccessLevel.READ,
        )
        assert rule.id and len(rule.id) == 36  # UUID4

    def test_resource_id_optional(self):
        rule = AccessRule(
            role="admin",
            resource_type=ResourceType.CONFIG,
            access_level=AccessLevel.ADMIN,
        )
        assert rule.resource_id is None

    def test_to_dict_contains_expected_keys(self):
        rule = AccessRule(
            role="security_analyst",
            resource_type=ResourceType.INCIDENT,
            access_level=AccessLevel.WRITE,
            resource_id="inc-001",
        )
        d = rule.to_dict()
        assert d["role"] == "security_analyst"
        assert d["resource_type"] == "incident"
        assert d["resource_id"] == "inc-001"
        assert d["access_level"] == "write"
        assert "conditions" in d
        assert "org_id" in d
        assert "created_at" in d

    def test_conditions_default_empty(self):
        rule = AccessRule(
            role="viewer",
            resource_type=ResourceType.DASHBOARD,
            access_level=AccessLevel.READ,
        )
        assert rule.conditions == {}

    def test_org_id_default(self):
        rule = AccessRule(
            role="admin",
            resource_type=ResourceType.AUDIT_LOG,
            access_level=AccessLevel.ADMIN,
        )
        assert rule.org_id == "default"


# ============================================================================
# AccessMatrix — seeded defaults
# ============================================================================


class TestDefaultRules:
    def test_defaults_seeded(self, matrix: AccessMatrix):
        rules = matrix.list_rules()
        assert len(rules) >= 48  # 6 roles x 8 resource types

    def test_viewer_can_read_finding(self, matrix: AccessMatrix):
        level = matrix.check_access("viewer", ResourceType.FINDING, audit=False)
        assert level == AccessLevel.READ

    def test_viewer_cannot_access_config(self, matrix: AccessMatrix):
        level = matrix.check_access("viewer", ResourceType.CONFIG, audit=False)
        assert level == AccessLevel.NONE

    def test_admin_has_admin_on_all(self, matrix: AccessMatrix):
        for rt in ResourceType:
            level = matrix.check_access("admin", rt, audit=False)
            assert level >= AccessLevel.ADMIN, f"admin should have admin on {rt.value}"

    def test_super_admin_is_owner(self, matrix: AccessMatrix):
        for rt in ResourceType:
            level = matrix.check_access("super_admin", rt, audit=False)
            assert level == AccessLevel.OWNER

    def test_compliance_officer_admin_on_compliance(self, matrix: AccessMatrix):
        level = matrix.check_access("compliance_officer", ResourceType.COMPLIANCE, audit=False)
        assert level == AccessLevel.ADMIN

    def test_security_analyst_write_finding(self, matrix: AccessMatrix):
        level = matrix.check_access("security_analyst", ResourceType.FINDING, audit=False)
        assert level == AccessLevel.WRITE

    def test_developer_no_config(self, matrix: AccessMatrix):
        level = matrix.check_access("developer", ResourceType.CONFIG, audit=False)
        assert level == AccessLevel.NONE


# ============================================================================
# grant_access / revoke_access
# ============================================================================


class TestGrantRevoke:
    def test_grant_creates_rule(self, matrix: AccessMatrix):
        rule = matrix.grant_access(
            role="developer",
            resource_type=ResourceType.INCIDENT,
            access_level=AccessLevel.WRITE,
        )
        assert rule.id
        assert rule.access_level == AccessLevel.WRITE

    def test_grant_with_resource_id(self, matrix: AccessMatrix):
        rule = matrix.grant_access(
            role="viewer",
            resource_type=ResourceType.REPORT,
            access_level=AccessLevel.READ,
            resource_id="report-42",
        )
        assert rule.resource_id == "report-42"

    def test_grant_with_conditions(self, matrix: AccessMatrix):
        rule = matrix.grant_access(
            role="developer",
            resource_type=ResourceType.ASSET,
            access_level=AccessLevel.WRITE,
            conditions={"env": "staging"},
        )
        assert rule.conditions == {"env": "staging"}

    def test_revoke_existing_rule(self, matrix: AccessMatrix):
        rule = matrix.grant_access(
            role="viewer",
            resource_type=ResourceType.DASHBOARD,
            access_level=AccessLevel.READ,
            resource_id="dash-99",
        )
        deleted = matrix.revoke_access(rule.id)
        assert deleted is True

    def test_revoke_nonexistent_rule(self, matrix: AccessMatrix):
        deleted = matrix.revoke_access("nonexistent-id")
        assert deleted is False

    def test_revoked_rule_no_longer_applies(self, matrix: AccessMatrix):
        # Grant a specific override, then revoke it; wildcard should remain
        rule = matrix.grant_access(
            role="viewer",
            resource_type=ResourceType.FINDING,
            access_level=AccessLevel.WRITE,
            resource_id="finding-special",
        )
        level_before = matrix.check_access(
            "viewer", ResourceType.FINDING, "finding-special", audit=False
        )
        assert level_before == AccessLevel.WRITE

        matrix.revoke_access(rule.id)
        level_after = matrix.check_access(
            "viewer", ResourceType.FINDING, "finding-special", audit=False
        )
        # Falls back to wildcard READ
        assert level_after == AccessLevel.READ


# ============================================================================
# check_access logic
# ============================================================================


class TestCheckAccess:
    def test_specific_rule_beats_wildcard(self, matrix: AccessMatrix):
        # viewer has READ (wildcard). Grant WRITE for specific resource.
        matrix.grant_access(
            role="viewer",
            resource_type=ResourceType.REPORT,
            access_level=AccessLevel.WRITE,
            resource_id="report-vip",
        )
        level = matrix.check_access("viewer", ResourceType.REPORT, "report-vip", audit=False)
        assert level == AccessLevel.WRITE

    def test_wildcard_applies_to_any_resource_id(self, matrix: AccessMatrix):
        level = matrix.check_access("admin", ResourceType.ASSET, "some-asset-id", audit=False)
        assert level >= AccessLevel.ADMIN

    def test_unknown_role_returns_none(self, matrix: AccessMatrix):
        level = matrix.check_access("ghost_role", ResourceType.FINDING, audit=False)
        assert level == AccessLevel.NONE

    def test_org_id_scoping(self, matrix: AccessMatrix):
        matrix.grant_access(
            role="viewer",
            resource_type=ResourceType.CONFIG,
            access_level=AccessLevel.READ,
            org_id="org-x",
        )
        level_x = matrix.check_access("viewer", ResourceType.CONFIG, org_id="org-x", audit=False)
        assert level_x == AccessLevel.READ

        level_default = matrix.check_access("viewer", ResourceType.CONFIG, org_id="default", audit=False)
        assert level_default == AccessLevel.NONE

    def test_check_audit_flag_false_no_write(self, matrix: AccessMatrix, tmp_db: str):
        matrix.check_access("viewer", ResourceType.FINDING, audit=False)
        import sqlite3
        conn = sqlite3.connect(tmp_db)
        count = conn.execute("SELECT COUNT(*) FROM access_audit").fetchone()[0]
        conn.close()
        assert count == 0

    def test_check_audit_flag_true_writes(self, matrix: AccessMatrix, tmp_db: str):
        matrix.check_access("viewer", ResourceType.FINDING, audit=True)
        import sqlite3
        conn = sqlite3.connect(tmp_db)
        count = conn.execute("SELECT COUNT(*) FROM access_audit").fetchone()[0]
        conn.close()
        assert count == 1


# ============================================================================
# list_rules
# ============================================================================


class TestListRules:
    def test_filter_by_role(self, matrix: AccessMatrix):
        rules = matrix.list_rules(role="viewer")
        assert all(r.role == "viewer" for r in rules)
        assert len(rules) >= 5

    def test_filter_by_resource_type(self, matrix: AccessMatrix):
        rules = matrix.list_rules(resource_type=ResourceType.COMPLIANCE)
        assert all(r.resource_type == ResourceType.COMPLIANCE for r in rules)

    def test_filter_by_org_id(self, matrix: AccessMatrix):
        matrix.grant_access(
            role="viewer",
            resource_type=ResourceType.DASHBOARD,
            access_level=AccessLevel.READ,
            org_id="org-special",
        )
        rules = matrix.list_rules(org_id="org-special")
        assert len(rules) == 1
        assert rules[0].org_id == "org-special"

    def test_limit_offset(self, matrix: AccessMatrix):
        all_rules = matrix.list_rules()
        page = matrix.list_rules(limit=5, offset=0)
        assert len(page) <= 5


# ============================================================================
# get_effective_permissions
# ============================================================================


class TestEffectivePermissions:
    def test_viewer_permissions(self, matrix: AccessMatrix):
        perms = matrix.get_effective_permissions("viewer")
        assert perms.get("finding") == "read"
        assert perms.get("dashboard") == "read"
        # Config and audit_log are NONE for viewer — might not appear
        assert perms.get("config", "none") == "none"

    def test_admin_all_admin(self, matrix: AccessMatrix):
        perms = matrix.get_effective_permissions("admin")
        for rt in ResourceType:
            assert perms.get(rt.value) == "admin", f"admin missing {rt.value}"

    def test_super_admin_all_owner(self, matrix: AccessMatrix):
        perms = matrix.get_effective_permissions("super_admin")
        for rt in ResourceType:
            assert perms.get(rt.value) == "owner"

    def test_empty_role_returns_empty(self, matrix: AccessMatrix):
        perms = matrix.get_effective_permissions("nonexistent_role")
        assert perms == {}


# ============================================================================
# get_resource_acl
# ============================================================================


class TestResourceACL:
    def test_acl_for_finding_has_entries(self, matrix: AccessMatrix):
        acl = matrix.get_resource_acl(ResourceType.FINDING)
        assert len(acl) >= 6  # one per role

    def test_acl_includes_specific_resource(self, matrix: AccessMatrix):
        matrix.grant_access(
            role="viewer",
            resource_type=ResourceType.REPORT,
            access_level=AccessLevel.WRITE,
            resource_id="report-special",
        )
        acl = matrix.get_resource_acl(ResourceType.REPORT, resource_id="report-special")
        resource_ids = [entry["resource_id"] for entry in acl]
        assert "report-special" in resource_ids

    def test_acl_wildcard_only(self, matrix: AccessMatrix):
        acl = matrix.get_resource_acl(ResourceType.COMPLIANCE)
        # All entries should have resource_id = None (wildcard)
        assert all(entry["resource_id"] is None for entry in acl)


# ============================================================================
# get_access_stats
# ============================================================================


class TestAccessStats:
    def test_stats_empty_audit(self, matrix: AccessMatrix):
        stats = matrix.get_access_stats()
        assert stats["total_checks"] == 0
        assert stats["total_grants"] == 0
        assert stats["total_denials"] == 0

    def test_stats_after_checks(self, matrix: AccessMatrix):
        matrix.check_access("viewer", ResourceType.FINDING, audit=True)
        matrix.check_access("admin", ResourceType.CONFIG, audit=True)
        matrix.check_access("ghost_role", ResourceType.AUDIT_LOG, audit=True)
        stats = matrix.get_access_stats()
        assert stats["total_checks"] == 3
        assert stats["total_grants"] >= 2
        assert stats["total_denials"] >= 1

    def test_grants_by_role(self, matrix: AccessMatrix):
        matrix.check_access("viewer", ResourceType.FINDING, audit=True)
        matrix.check_access("viewer", ResourceType.DASHBOARD, audit=True)
        stats = matrix.get_access_stats()
        assert "viewer" in stats["grants_by_role"]
        assert stats["grants_by_role"]["viewer"] == 2

    def test_most_accessed_resources(self, matrix: AccessMatrix):
        matrix.check_access("viewer", ResourceType.FINDING, audit=True)
        matrix.check_access("admin", ResourceType.FINDING, audit=True)
        stats = matrix.get_access_stats()
        types = [e["resource_type"] for e in stats["most_accessed_resources"]]
        assert "finding" in types

    def test_rules_by_role_in_stats(self, matrix: AccessMatrix):
        stats = matrix.get_access_stats()
        assert "rules_by_role" in stats
        assert "viewer" in stats["rules_by_role"]


# ============================================================================
# Router tests (FastAPI TestClient)
# ============================================================================


@pytest.fixture
def app(tmp_db: str):
    """Create isolated FastAPI app with a test-scoped AccessMatrix."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    import core.access_matrix as _am_module

    # Swap the singleton for a test-scoped instance
    test_matrix = AccessMatrix(db_path=tmp_db)
    original = _am_module._matrix_instance
    _am_module._matrix_instance = test_matrix

    from apps.api.access_matrix_router import router as am_router

    _app = FastAPI()
    _app.include_router(am_router)

    yield TestClient(_app)

    _am_module._matrix_instance = original


class TestRouter:
    def test_list_rules_returns_defaults(self, app):
        resp = app.get("/api/v1/access-matrix/rules")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 48

    def test_grant_access_creates_rule(self, app):
        resp = app.post("/api/v1/access-matrix/rules", json={
            "role": "viewer",
            "resource_type": "incident",
            "access_level": "read",
        })
        assert resp.status_code == 201
        data = resp.json()
        assert data["role"] == "viewer"
        assert data["access_level"] == "read"

    def test_revoke_nonexistent_404(self, app):
        resp = app.delete("/api/v1/access-matrix/rules/not-a-real-id")
        assert resp.status_code == 404

    def test_revoke_existing_rule(self, app):
        create_resp = app.post("/api/v1/access-matrix/rules", json={
            "role": "developer",
            "resource_type": "asset",
            "access_level": "write",
            "resource_id": "asset-x",
        })
        rule_id = create_resp.json()["id"]
        del_resp = app.delete(f"/api/v1/access-matrix/rules/{rule_id}")
        assert del_resp.status_code == 200
        assert del_resp.json()["deleted"] is True

    def test_check_access_viewer_finding(self, app):
        resp = app.post("/api/v1/access-matrix/check", json={
            "user_role": "viewer",
            "resource_type": "finding",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["access_level"] == "read"
        assert data["granted"] is True

    def test_check_access_ghost_role(self, app):
        resp = app.post("/api/v1/access-matrix/check", json={
            "user_role": "ghost",
            "resource_type": "config",
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["access_level"] == "none"
        assert data["granted"] is False

    def test_effective_permissions_viewer(self, app):
        resp = app.get("/api/v1/access-matrix/permissions/viewer")
        assert resp.status_code == 200
        perms = resp.json()["permissions"]
        assert perms.get("finding") == "read"

    def test_effective_permissions_unknown_role_empty(self, app):
        resp = app.get("/api/v1/access-matrix/permissions/ghost_role")
        assert resp.status_code == 200
        assert resp.json()["permissions"] == {}

    def test_get_resource_acl(self, app):
        resp = app.get("/api/v1/access-matrix/acl/finding")
        assert resp.status_code == 200
        data = resp.json()
        assert data["resource_type"] == "finding"
        assert data["total"] >= 6

    def test_get_access_stats(self, app):
        resp = app.get("/api/v1/access-matrix/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_checks" in data
        assert "grants_by_role" in data
        assert "most_accessed_resources" in data

    def test_get_full_matrix(self, app):
        resp = app.get("/api/v1/access-matrix/matrix")
        assert resp.status_code == 200
        data = resp.json()
        assert "matrix" in data
        assert "viewer" in data["matrix"]
        assert "admin" in data["matrix"]
        assert len(data["resource_types"]) == 8

    def test_list_rules_filter_by_role(self, app):
        resp = app.get("/api/v1/access-matrix/rules?role=viewer")
        assert resp.status_code == 200
        items = resp.json()["items"]
        assert all(i["role"] == "viewer" for i in items)

    def test_grant_with_org_id(self, app):
        resp = app.post("/api/v1/access-matrix/rules", json={
            "role": "viewer",
            "resource_type": "dashboard",
            "access_level": "read",
            "org_id": "org-beta",
        })
        assert resp.status_code == 201
        assert resp.json()["org_id"] == "org-beta"

    def test_check_access_super_admin_is_owner(self, app):
        resp = app.post("/api/v1/access-matrix/check", json={
            "user_role": "super_admin",
            "resource_type": "audit_log",
        })
        assert resp.status_code == 200
        assert resp.json()["access_level"] == "owner"

    def test_index_returns_service_envelope(self, app):
        """GET / returns service name, org_id, resource_types, and stats."""
        resp = app.get("/api/v1/access-matrix/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["service"] == "access-matrix"
        assert "resource_types" in data
        assert len(data["resource_types"]) > 0
        assert "stats" in data

    def test_index_empty_org_returns_valid_envelope(self, app):
        """GET / for a fresh org with no rules still returns a valid envelope."""
        resp = app.get("/api/v1/access-matrix/?org_id=brand-new-org")
        assert resp.status_code == 200
        data = resp.json()
        assert data["org_id"] == "brand-new-org"
        assert isinstance(data["stats"], dict)
