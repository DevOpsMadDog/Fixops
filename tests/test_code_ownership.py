"""
Tests for the Code Ownership Mapper.

Covers:
- Owner CRUD (add, get, list, delete)
- Rule management (add, list, delete)
- Glob resolution (exact, wildcard, **, priority)
- Finding resolution (file_path field, fallback to owner_email)
- CODEOWNERS import (comments, @ prefixes, multiple owners per line)
- Coverage analytics (full coverage, partial, zero)
- Unowned files listing
- Owner workload
- Auto-assign findings (bulk, partial, none)
- Router endpoints (all 11 endpoints)
- Edge cases (empty inputs, missing owners, conflicting rules)
"""

import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# Path setup — ensure suite-core is importable
# ---------------------------------------------------------------------------
_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(_ROOT / "suite-core"))
sys.path.insert(0, str(_ROOT / "suite-api"))

# Disable telemetry / rate limiting for tests
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from core.code_ownership import (
    AssignedFinding,
    CodeOwnership,
    Owner,
    OwnershipRule,
    _glob_match,
    get_code_ownership,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_db(tmp_path):
    """Return a fresh CodeOwnership instance backed by a temp DB."""
    db = tmp_path / "test_ownership.db"
    return CodeOwnership(db_path=db)


@pytest.fixture
def alice():
    return Owner(
        email="alice@example.com",
        name="Alice Smith",
        team="platform",
        repos=["Fixops"],
        file_patterns=["suite-core/**"],
    )


@pytest.fixture
def bob():
    return Owner(
        email="bob@example.com",
        name="Bob Jones",
        team="security",
        repos=["Fixops"],
        file_patterns=["suite-api/**", "tests/**"],
    )


# ---------------------------------------------------------------------------
# 1. Glob matching helper
# ---------------------------------------------------------------------------


class TestGlobMatch:
    def test_exact_match(self):
        assert _glob_match("README.md", "README.md")

    def test_simple_wildcard(self):
        assert _glob_match("*.py", "brain_pipeline.py")

    def test_double_star(self):
        assert _glob_match("suite-core/**", "suite-core/core/brain_pipeline.py")

    def test_double_star_direct_child(self):
        assert _glob_match("suite-core/**", "suite-core/core/something.py")

    def test_no_match(self):
        assert not _glob_match("suite-api/**", "suite-core/core/brain_pipeline.py")

    def test_leading_slash_stripped(self):
        assert _glob_match("/src/**", "src/core/main.py")

    def test_nested_double_star(self):
        assert _glob_match("tests/**", "tests/unit/test_foo.py")

    def test_basename_match(self):
        assert _glob_match("*.py", "deeply/nested/file.py")


# ---------------------------------------------------------------------------
# 2. Owner CRUD
# ---------------------------------------------------------------------------


class TestOwnerCRUD:
    def test_add_and_get_owner(self, tmp_db, alice):
        returned = tmp_db.add_owner(alice)
        assert returned.email == alice.email
        fetched = tmp_db.get_owner(alice.email)
        assert fetched is not None
        assert fetched.name == "Alice Smith"
        assert fetched.team == "platform"

    def test_add_owner_upsert(self, tmp_db, alice):
        tmp_db.add_owner(alice)
        alice_v2 = alice.model_copy(update={"name": "Alice Smith II"})
        tmp_db.add_owner(alice_v2)
        fetched = tmp_db.get_owner(alice.email)
        assert fetched.name == "Alice Smith II"

    def test_list_owners_empty(self, tmp_db):
        assert tmp_db.list_owners() == []

    def test_list_owners(self, tmp_db, alice, bob):
        tmp_db.add_owner(alice)
        tmp_db.add_owner(bob)
        owners = tmp_db.list_owners()
        emails = {o.email for o in owners}
        assert "alice@example.com" in emails
        assert "bob@example.com" in emails

    def test_delete_owner(self, tmp_db, alice):
        tmp_db.add_owner(alice)
        assert tmp_db.delete_owner(alice.email) is True
        assert tmp_db.get_owner(alice.email) is None

    def test_delete_nonexistent_owner(self, tmp_db):
        assert tmp_db.delete_owner("nobody@example.com") is False

    def test_owner_repos_and_patterns_preserved(self, tmp_db, alice):
        tmp_db.add_owner(alice)
        fetched = tmp_db.get_owner(alice.email)
        assert fetched.repos == ["Fixops"]
        assert fetched.file_patterns == ["suite-core/**"]


# ---------------------------------------------------------------------------
# 3. Rule management
# ---------------------------------------------------------------------------


class TestRuleManagement:
    def test_add_rule(self, tmp_db, alice):
        tmp_db.add_owner(alice)
        rule = tmp_db.add_rule("suite-core/**", alice.email, priority=10)
        assert rule.pattern == "suite-core/**"
        assert rule.owner_email == alice.email
        assert rule.priority == 10
        assert rule.id  # UUID generated

    def test_list_rules_ordered_by_priority(self, tmp_db, alice, bob):
        tmp_db.add_owner(alice)
        tmp_db.add_owner(bob)
        tmp_db.add_rule("*.py", alice.email, priority=5)
        tmp_db.add_rule("suite-core/**", bob.email, priority=20)
        rules = tmp_db.list_rules()
        assert rules[0].priority == 20
        assert rules[1].priority == 5

    def test_delete_rule(self, tmp_db, alice):
        tmp_db.add_owner(alice)
        rule = tmp_db.add_rule("suite-core/**", alice.email)
        assert tmp_db.delete_rule(rule.id) is True
        assert all(r.id != rule.id for r in tmp_db.list_rules())

    def test_delete_nonexistent_rule(self, tmp_db):
        assert tmp_db.delete_rule("nonexistent-id") is False


# ---------------------------------------------------------------------------
# 4. Owner resolution
# ---------------------------------------------------------------------------


class TestResolveOwner:
    def test_resolve_direct_match(self, tmp_db, alice):
        tmp_db.add_owner(alice)
        tmp_db.add_rule("suite-core/**", alice.email, priority=10)
        owner = tmp_db.resolve_owner("suite-core/core/brain_pipeline.py")
        assert owner is not None
        assert owner.email == alice.email

    def test_resolve_no_match(self, tmp_db, alice):
        tmp_db.add_owner(alice)
        tmp_db.add_rule("suite-core/**", alice.email)
        assert tmp_db.resolve_owner("suite-api/app.py") is None

    def test_resolve_priority_wins(self, tmp_db, alice, bob):
        tmp_db.add_owner(alice)
        tmp_db.add_owner(bob)
        # Both patterns match; higher priority should win
        tmp_db.add_rule("*.py", alice.email, priority=5)
        tmp_db.add_rule("suite-core/**", bob.email, priority=20)
        owner = tmp_db.resolve_owner("suite-core/core/brain_pipeline.py")
        assert owner.email == bob.email

    def test_resolve_lower_priority_fallback(self, tmp_db, alice, bob):
        tmp_db.add_owner(alice)
        tmp_db.add_owner(bob)
        tmp_db.add_rule("*.py", alice.email, priority=5)
        tmp_db.add_rule("suite-core/**", bob.email, priority=20)
        # .js file only matches *.py → alice
        tmp_db.add_rule("*.js", alice.email, priority=1)
        owner = tmp_db.resolve_owner("app.py")
        assert owner.email == alice.email

    def test_resolve_rule_with_unknown_owner_skips(self, tmp_db, alice):
        tmp_db.add_owner(alice)
        # Rule referencing missing owner
        tmp_db.add_rule("suite-core/**", "ghost@example.com", priority=100)
        tmp_db.add_rule("suite-core/**", alice.email, priority=5)
        owner = tmp_db.resolve_owner("suite-core/core/brain_pipeline.py")
        # Should fall through to alice
        assert owner.email == alice.email

    def test_resolve_empty_rules(self, tmp_db):
        assert tmp_db.resolve_owner("any/path.py") is None


# ---------------------------------------------------------------------------
# 5. Finding resolution
# ---------------------------------------------------------------------------


class TestResolveFindingOwner:
    def test_resolve_by_file_path(self, tmp_db, alice):
        tmp_db.add_owner(alice)
        tmp_db.add_rule("suite-core/**", alice.email, priority=10)
        finding = {"id": "f1", "file_path": "suite-core/core/foo.py", "severity": "high"}
        owner = tmp_db.resolve_finding_owner(finding)
        assert owner.email == alice.email

    def test_resolve_by_file_field(self, tmp_db, alice):
        tmp_db.add_owner(alice)
        tmp_db.add_rule("suite-core/**", alice.email, priority=10)
        finding = {"id": "f2", "file": "suite-core/core/bar.py"}
        owner = tmp_db.resolve_finding_owner(finding)
        assert owner.email == alice.email

    def test_resolve_fallback_owner_email_field(self, tmp_db, alice):
        tmp_db.add_owner(alice)
        finding = {"id": "f3", "owner_email": alice.email}
        owner = tmp_db.resolve_finding_owner(finding)
        assert owner.email == alice.email

    def test_resolve_no_match_returns_none(self, tmp_db):
        finding = {"id": "f4", "file_path": "unmatched/path.py"}
        assert tmp_db.resolve_finding_owner(finding) is None

    def test_resolve_empty_finding(self, tmp_db):
        assert tmp_db.resolve_finding_owner({}) is None


# ---------------------------------------------------------------------------
# 6. CODEOWNERS import
# ---------------------------------------------------------------------------


class TestImportCodeowners:
    def test_basic_import(self, tmp_db, alice, bob):
        tmp_db.add_owner(alice)
        tmp_db.add_owner(bob)
        content = """
# Platform team owns core
suite-core/**   alice@example.com

# Security team owns API
suite-api/**    bob@example.com
"""
        count = tmp_db.import_codeowners(content)
        assert count == 2
        rules = tmp_db.list_rules()
        patterns = {r.pattern for r in rules}
        assert "suite-core/**" in patterns
        assert "suite-api/**" in patterns

    def test_import_github_at_prefix(self, tmp_db, alice):
        tmp_db.add_owner(alice)
        content = "suite-core/**   @alice@example.com\n"
        count = tmp_db.import_codeowners(content)
        assert count == 1
        rules = tmp_db.list_rules()
        assert rules[0].owner_email == "alice@example.com"

    def test_import_multiple_owners_per_line(self, tmp_db, alice, bob):
        tmp_db.add_owner(alice)
        tmp_db.add_owner(bob)
        content = "suite-core/**   alice@example.com   bob@example.com\n"
        count = tmp_db.import_codeowners(content)
        assert count == 1  # 1 line, but 2 rules created
        rules = tmp_db.list_rules()
        emails = {r.owner_email for r in rules}
        assert "alice@example.com" in emails
        assert "bob@example.com" in emails

    def test_import_skips_comments_and_blanks(self, tmp_db, alice):
        tmp_db.add_owner(alice)
        content = """
# This is a comment

# Another comment
suite-core/**   alice@example.com
"""
        count = tmp_db.import_codeowners(content)
        assert count == 1

    def test_import_priority_order(self, tmp_db, alice, bob):
        tmp_db.add_owner(alice)
        tmp_db.add_owner(bob)
        content = "*.py   alice@example.com\nsuite-core/**   bob@example.com\n"
        tmp_db.import_codeowners(content)
        rules = tmp_db.list_rules()
        # First line gets highest priority (later lines have lower priority)
        py_rule = next(r for r in rules if r.pattern == "*.py")
        core_rule = next(r for r in rules if r.pattern == "suite-core/**")
        assert py_rule.priority > core_rule.priority

    def test_import_empty_content(self, tmp_db):
        count = tmp_db.import_codeowners("")
        assert count == 0


# ---------------------------------------------------------------------------
# 7. Coverage analytics
# ---------------------------------------------------------------------------


class TestCoverage:
    def test_full_coverage(self, tmp_db, alice):
        tmp_db.add_owner(alice)
        tmp_db.add_rule("**", alice.email, priority=1)
        files = ["src/a.py", "src/b.py", "tests/test_a.py"]
        result = tmp_db.get_ownership_coverage("org1", files)
        assert result["coverage_pct"] == 100.0
        assert result["owned_files"] == 3
        assert result["unowned_files"] == 0

    def test_partial_coverage(self, tmp_db, alice):
        tmp_db.add_owner(alice)
        tmp_db.add_rule("suite-core/**", alice.email, priority=5)
        files = [
            "suite-core/core/brain.py",
            "suite-api/app.py",
            "tests/test_foo.py",
        ]
        result = tmp_db.get_ownership_coverage("org1", files)
        assert result["owned_files"] == 1
        assert result["unowned_files"] == 2
        assert result["coverage_pct"] == pytest.approx(33.33, abs=0.01)

    def test_zero_coverage(self, tmp_db):
        files = ["some/file.py"]
        result = tmp_db.get_ownership_coverage("org1", files)
        assert result["coverage_pct"] == 0.0

    def test_empty_file_list(self, tmp_db):
        result = tmp_db.get_ownership_coverage("org1", [])
        assert result["total_files"] == 0
        assert result["coverage_pct"] == 0.0


# ---------------------------------------------------------------------------
# 8. Unowned files
# ---------------------------------------------------------------------------


class TestUnownedFiles:
    def test_all_unowned(self, tmp_db):
        files = ["a.py", "b.py"]
        result = tmp_db.get_unowned_files("org1", files)
        assert result == files

    def test_some_unowned(self, tmp_db, alice):
        tmp_db.add_owner(alice)
        tmp_db.add_rule("suite-core/**", alice.email, priority=5)
        files = ["suite-core/core/brain.py", "suite-api/app.py"]
        result = tmp_db.get_unowned_files("org1", files)
        assert result == ["suite-api/app.py"]

    def test_none_unowned(self, tmp_db, alice):
        tmp_db.add_owner(alice)
        tmp_db.add_rule("**", alice.email, priority=1)
        files = ["a.py", "b.py"]
        result = tmp_db.get_unowned_files("org1", files)
        assert result == []

    def test_empty_file_list(self, tmp_db):
        result = tmp_db.get_unowned_files("org1", [])
        assert result == []


# ---------------------------------------------------------------------------
# 9. Owner workload
# ---------------------------------------------------------------------------


class TestOwnerWorkload:
    def test_workload_after_auto_assign(self, tmp_db, alice, bob):
        tmp_db.add_owner(alice)
        tmp_db.add_owner(bob)
        tmp_db.add_rule("suite-core/**", alice.email, priority=10)
        tmp_db.add_rule("suite-api/**", bob.email, priority=10)

        findings = [
            {"id": "f1", "file_path": "suite-core/core/a.py"},
            {"id": "f2", "file_path": "suite-core/core/b.py"},
            {"id": "f3", "file_path": "suite-api/app.py"},
        ]
        tmp_db.auto_assign_findings(findings, org_id="org1")

        workload = tmp_db.get_owner_workload("org1")
        counts = {w["owner_email"]: w["finding_count"] for w in workload}
        assert counts.get("alice@example.com") == 2
        assert counts.get("bob@example.com") == 1

    def test_workload_empty(self, tmp_db):
        assert tmp_db.get_owner_workload("org1") == []

    def test_workload_includes_owner_name_and_team(self, tmp_db, alice):
        tmp_db.add_owner(alice)
        tmp_db.add_rule("**", alice.email, priority=1)
        tmp_db.auto_assign_findings([{"id": "f1", "file_path": "a.py"}], org_id="org1")
        workload = tmp_db.get_owner_workload("org1")
        assert workload[0]["owner_name"] == "Alice Smith"
        assert workload[0]["owner_team"] == "platform"


# ---------------------------------------------------------------------------
# 10. Auto-assign findings
# ---------------------------------------------------------------------------


class TestAutoAssignFindings:
    def test_all_assigned(self, tmp_db, alice):
        tmp_db.add_owner(alice)
        tmp_db.add_rule("suite-core/**", alice.email, priority=5)
        findings = [
            {"id": "f1", "file_path": "suite-core/core/a.py"},
            {"id": "f2", "file_path": "suite-core/core/b.py"},
        ]
        result = tmp_db.auto_assign_findings(findings, org_id="org1")
        assert len(result) == 2
        assert all(a.owner_email == alice.email for a in result)

    def test_partial_assignment(self, tmp_db, alice):
        tmp_db.add_owner(alice)
        tmp_db.add_rule("suite-core/**", alice.email, priority=5)
        findings = [
            {"id": "f1", "file_path": "suite-core/core/a.py"},
            {"id": "f2", "file_path": "unmatched/file.py"},
        ]
        result = tmp_db.auto_assign_findings(findings, org_id="org1")
        emails = {a.owner_email for a in result}
        assert alice.email in emails
        assert None in emails

    def test_none_assigned(self, tmp_db):
        findings = [{"id": "f1", "file_path": "nobody/owns/this.py"}]
        result = tmp_db.auto_assign_findings(findings, org_id="org1")
        assert result[0].owner_email is None

    def test_empty_findings(self, tmp_db):
        result = tmp_db.auto_assign_findings([], org_id="org1")
        assert result == []

    def test_assignment_persisted(self, tmp_db, alice):
        tmp_db.add_owner(alice)
        tmp_db.add_rule("**", alice.email, priority=1)
        tmp_db.auto_assign_findings([{"id": "f1", "file_path": "a.py"}], org_id="org1")
        workload = tmp_db.get_owner_workload("org1")
        assert workload[0]["finding_count"] == 1

    def test_upsert_on_duplicate_finding_id(self, tmp_db, alice, bob):
        tmp_db.add_owner(alice)
        tmp_db.add_owner(bob)
        tmp_db.add_rule("suite-core/**", alice.email, priority=10)
        tmp_db.add_rule("suite-api/**", bob.email, priority=10)

        tmp_db.auto_assign_findings(
            [{"id": "f1", "file_path": "suite-core/core/a.py"}], org_id="org1"
        )
        # Re-assign the same finding to a different path
        tmp_db.auto_assign_findings(
            [{"id": "f1", "file_path": "suite-api/app.py"}], org_id="org1"
        )
        workload = tmp_db.get_owner_workload("org1")
        counts = {w["owner_email"]: w["finding_count"] for w in workload}
        # Should be reassigned to bob
        assert counts.get("bob@example.com") == 1
        assert counts.get("alice@example.com", 0) == 0

    def test_finding_id_generated_when_missing(self, tmp_db):
        findings = [{"file_path": "a.py"}]  # no 'id' field
        result = tmp_db.auto_assign_findings(findings, org_id="org1")
        assert result[0].finding_id  # UUID was generated


# ---------------------------------------------------------------------------
# 11. Router endpoints (FastAPI TestClient)
# ---------------------------------------------------------------------------


@pytest.fixture
def app_client(tmp_path):
    """Create a FastAPI TestClient with the ownership router mounted."""
    import importlib
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    # Override the singleton so tests use temp DB
    import core.code_ownership as co_module

    tmp_db_path = tmp_path / "router_test.db"
    fresh = CodeOwnership(db_path=tmp_db_path)
    co_module._instance = fresh

    from apps.api.code_ownership_router import router

    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


class TestRouter:
    def test_register_owner(self, app_client):
        resp = app_client.post(
            "/api/v1/ownership/owners",
            json={
                "email": "alice@example.com",
                "name": "Alice",
                "team": "platform",
                "repos": [],
                "file_patterns": [],
            },
        )
        assert resp.status_code == 201
        assert resp.json()["email"] == "alice@example.com"

    def test_list_owners(self, app_client):
        app_client.post(
            "/api/v1/ownership/owners",
            json={"email": "x@x.com", "name": "X", "team": "t", "repos": [], "file_patterns": []},
        )
        resp = app_client.get("/api/v1/ownership/owners")
        assert resp.status_code == 200
        assert any(o["email"] == "x@x.com" for o in resp.json())

    def test_delete_owner(self, app_client):
        app_client.post(
            "/api/v1/ownership/owners",
            json={"email": "del@del.com", "name": "Del", "team": "t", "repos": [], "file_patterns": []},
        )
        resp = app_client.delete("/api/v1/ownership/owners/del@del.com")
        assert resp.status_code == 200
        assert resp.json()["deleted"] is True

    def test_delete_owner_not_found(self, app_client):
        resp = app_client.delete("/api/v1/ownership/owners/nobody@example.com")
        assert resp.status_code == 404

    def test_add_rule(self, app_client):
        app_client.post(
            "/api/v1/ownership/owners",
            json={"email": "r@r.com", "name": "R", "team": "t", "repos": [], "file_patterns": []},
        )
        resp = app_client.post(
            "/api/v1/ownership/rules",
            json={"pattern": "src/**", "owner_email": "r@r.com", "priority": 5},
        )
        assert resp.status_code == 201
        assert resp.json()["pattern"] == "src/**"

    def test_list_rules(self, app_client):
        app_client.post(
            "/api/v1/ownership/owners",
            json={"email": "lr@lr.com", "name": "LR", "team": "t", "repos": [], "file_patterns": []},
        )
        app_client.post(
            "/api/v1/ownership/rules",
            json={"pattern": "*.py", "owner_email": "lr@lr.com", "priority": 1},
        )
        resp = app_client.get("/api/v1/ownership/rules")
        assert resp.status_code == 200
        assert any(r["pattern"] == "*.py" for r in resp.json())

    def test_resolve_owner(self, app_client):
        app_client.post(
            "/api/v1/ownership/owners",
            json={"email": "res@res.com", "name": "Res", "team": "t", "repos": [], "file_patterns": []},
        )
        app_client.post(
            "/api/v1/ownership/rules",
            json={"pattern": "suite-core/**", "owner_email": "res@res.com", "priority": 10},
        )
        resp = app_client.post(
            "/api/v1/ownership/resolve",
            json={"file_path": "suite-core/core/brain.py"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["resolved"] is True
        assert data["owner"]["email"] == "res@res.com"

    def test_resolve_owner_no_match(self, app_client):
        resp = app_client.post(
            "/api/v1/ownership/resolve",
            json={"file_path": "unmatched/file.py"},
        )
        assert resp.status_code == 200
        assert resp.json()["resolved"] is False

    def test_import_codeowners(self, app_client):
        content = "suite-core/**   import_owner@example.com\n"
        resp = app_client.post("/api/v1/ownership/import", json={"content": content})
        assert resp.status_code == 201
        assert resp.json()["imported_rules"] == 1

    def test_coverage_endpoint(self, app_client):
        resp = app_client.post(
            "/api/v1/ownership/coverage",
            json={"org_id": "org1", "file_paths": ["a.py", "b.py"]},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "coverage_pct" in data
        assert data["total_files"] == 2

    def test_unowned_endpoint(self, app_client):
        resp = app_client.post(
            "/api/v1/ownership/unowned",
            json={"org_id": "org1", "file_paths": ["x.py", "y.py"]},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["unowned_count"] == 2

    def test_workload_endpoint(self, app_client):
        resp = app_client.get("/api/v1/ownership/workload?org_id=org1")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_auto_assign_endpoint(self, app_client):
        app_client.post(
            "/api/v1/ownership/owners",
            json={
                "email": "aa@aa.com",
                "name": "AA",
                "team": "t",
                "repos": [],
                "file_patterns": [],
            },
        )
        app_client.post(
            "/api/v1/ownership/rules",
            json={"pattern": "src/**", "owner_email": "aa@aa.com", "priority": 5},
        )
        resp = app_client.post(
            "/api/v1/ownership/auto-assign",
            json={
                "findings": [
                    {"id": "f1", "file_path": "src/main.py"},
                    {"id": "f2", "file_path": "unmatched/file.py"},
                ],
                "org_id": "org1",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_findings"] == 2
        assert data["assigned_count"] == 1
        assert data["unassigned_count"] == 1
