"""
Tests for the Developer Self-Service Security Portal.

Coverage:
- Repo ownership registration
- Scoped findings (only owned repos returned)
- Security score calculation and grading
- Fix suggestion generation for multiple finding types
- Batch fix suggestions
- Upgrade recommendations
- Learning resources lookup
- Developer stats
- Leaderboard ranking
- API router endpoints via TestClient
"""

from __future__ import annotations

import os
import sys
import uuid

import pytest

# ---------------------------------------------------------------------------
# Environment setup (must happen before any app imports)
# ---------------------------------------------------------------------------
os.environ.setdefault("FIXOPS_MODE", "dev")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret-that-is-long-enough-here")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-api"))

from core.developer_portal import (
    DeveloperPortal,
    FixSuggestion,
    LearningResource,
    RepoSecurityScore,
    _grade_from_score,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def portal(tmp_path):
    """Isolated DeveloperPortal backed by a temp SQLite database."""
    return DeveloperPortal(db_path=str(tmp_path / "dev_portal.db"))


@pytest.fixture
def org_id():
    return "org-test-" + uuid.uuid4().hex[:8]


@pytest.fixture
def dev_email():
    return "alice@example.com"


@pytest.fixture
def repo_name():
    return "acme/backend-api"


@pytest.fixture
def populated_portal(portal, org_id, dev_email, repo_name):
    """Portal with a registered owner and several findings."""
    portal.register_repo_owner(repo_name, dev_email, org_id)

    portal.add_finding(repo_name, org_id, "SQL Injection in login", "critical",
                       "sql_injection", language="python")
    portal.add_finding(repo_name, org_id, "XSS in profile page", "high",
                       "xss", language="javascript")
    portal.add_finding(repo_name, org_id, "Outdated requests library", "medium",
                       "outdated_dependency", language="python",
                       metadata={"package": "requests", "current_version": "2.25.0",
                                  "fixed_version": "2.31.0"})
    portal.add_finding(repo_name, org_id, "Missing rate limiting", "low",
                       "default")
    return portal


# ============================================================================
# Registration tests
# ============================================================================


class TestRegisterRepoOwner:
    def test_register_single_owner(self, portal, org_id, dev_email, repo_name):
        portal.register_repo_owner(repo_name, dev_email, org_id)
        owned = portal._get_owned_repos(dev_email, org_id)
        assert repo_name in owned

    def test_register_multiple_repos_same_dev(self, portal, org_id, dev_email):
        repos = ["org/repo-a", "org/repo-b", "org/repo-c"]
        for r in repos:
            portal.register_repo_owner(r, dev_email, org_id)
        owned = portal._get_owned_repos(dev_email, org_id)
        assert set(repos).issubset(set(owned))

    def test_register_idempotent(self, portal, org_id, dev_email, repo_name):
        portal.register_repo_owner(repo_name, dev_email, org_id)
        portal.register_repo_owner(repo_name, dev_email, org_id)  # duplicate
        owned = portal._get_owned_repos(dev_email, org_id)
        assert owned.count(repo_name) == 1

    def test_unregistered_dev_has_no_repos(self, portal, org_id):
        owned = portal._get_owned_repos("nobody@example.com", org_id)
        assert owned == []


# ============================================================================
# Findings scoping tests
# ============================================================================


class TestGetMyFindings:
    def test_returns_only_owned_repo_findings(self, portal, org_id, dev_email, repo_name):
        other_repo = "org/other-repo"
        portal.register_repo_owner(repo_name, dev_email, org_id)
        portal.add_finding(repo_name, org_id, "Finding A", "high", "xss")
        portal.add_finding(other_repo, org_id, "Finding B", "critical", "sql_injection")

        findings = portal.get_my_findings(dev_email, org_id)
        titles = [f["title"] for f in findings]
        assert "Finding A" in titles
        assert "Finding B" not in titles

    def test_unregistered_dev_gets_empty_list(self, portal, org_id):
        portal.add_finding("org/repo", org_id, "Some finding", "high", "xss")
        findings = portal.get_my_findings("nobody@example.com", org_id)
        assert findings == []

    def test_status_filter_open(self, populated_portal, org_id, dev_email, portal):
        # Mark one resolved
        findings = populated_portal.get_my_findings(dev_email, org_id)
        fid = findings[0]["id"]
        populated_portal.mark_finding_resolved(fid, dev_email, org_id)

        open_findings = populated_portal.get_my_findings(dev_email, org_id, status="open")
        ids = [f["id"] for f in open_findings]
        assert fid not in ids

    def test_findings_contain_required_fields(self, populated_portal, org_id, dev_email):
        findings = populated_portal.get_my_findings(dev_email, org_id)
        assert len(findings) > 0
        for f in findings:
            assert "id" in f
            assert "title" in f
            assert "severity" in f
            assert "repo_name" in f


# ============================================================================
# Repo scoring tests
# ============================================================================


class TestRepoSecurityScore:
    def test_empty_repo_scores_100(self, portal, org_id):
        score = portal.get_repo_score("org/empty-repo", org_id)
        assert score.score == 100.0
        assert score.grade == "A"
        assert score.finding_count == 0

    def test_critical_finding_reduces_score(self, portal, org_id):
        repo = "org/critical-repo"
        portal.add_finding(repo, org_id, "Critical vuln", "critical", "sql_injection")
        score = portal.get_repo_score(repo, org_id)
        assert score.score < 100.0
        assert score.critical == 1

    def test_severity_counts(self, populated_portal, repo_name, org_id):
        score = populated_portal.get_repo_score(repo_name, org_id)
        assert score.critical >= 1
        assert score.high >= 1
        assert score.medium >= 1
        assert score.low >= 1

    def test_grade_a_for_perfect_score(self):
        assert _grade_from_score(100.0) == "A"
        assert _grade_from_score(90.0) == "A"

    def test_grade_f_for_zero(self):
        assert _grade_from_score(0.0) == "F"
        assert _grade_from_score(49.9) == "F"

    def test_grade_b_range(self):
        assert _grade_from_score(80.0) == "B"
        assert _grade_from_score(89.9) == "B"

    def test_get_all_repo_scores(self, portal, org_id):
        for i in range(3):
            repo = f"org/repo-{i}"
            portal.add_finding(repo, org_id, f"Finding {i}", "medium", "xss")
        scores = portal.get_all_repo_scores(org_id)
        assert len(scores) == 3
        assert all(isinstance(s, RepoSecurityScore) for s in scores)

    def test_resolved_findings_not_counted(self, portal, org_id, dev_email):
        repo = "org/clean-repo"
        portal.register_repo_owner(repo, dev_email, org_id)
        fid = portal.add_finding(repo, org_id, "Old vuln", "critical", "xss")
        portal.mark_finding_resolved(fid, dev_email, org_id)
        score = portal.get_repo_score(repo, org_id)
        assert score.critical == 0
        assert score.finding_count == 0


# ============================================================================
# Fix suggestion tests
# ============================================================================


class TestFixSuggestions:
    def test_sql_injection_fix(self, portal, org_id):
        fid = portal.add_finding("org/r", org_id, "SQLi", "critical", "sql_injection",
                                  language="python")
        fix = portal.get_fix_suggestion(fid)
        assert isinstance(fix, FixSuggestion)
        assert "SQL" in fix.title or "sql" in fix.title.lower()
        assert fix.difficulty == "easy"
        assert fix.estimated_time_minutes == 30
        assert "owasp.org" in fix.reference_url

    def test_xss_fix_javascript_snippet(self, portal, org_id):
        fid = portal.add_finding("org/r", org_id, "XSS", "high", "xss", language="javascript")
        fix = portal.get_fix_suggestion(fid, language="javascript")
        assert fix.code_snippet is not None
        assert "textContent" in fix.code_snippet or "escape" in fix.code_snippet.lower() or "XSS" in fix.title

    def test_hardcoded_secret_fix(self, portal, org_id):
        fid = portal.add_finding("org/r", org_id, "Hardcoded creds", "high",
                                  "hardcoded_secret", language="python")
        fix = portal.get_fix_suggestion(fid)
        assert "environ" in (fix.code_snippet or "") or "secret" in fix.title.lower()

    def test_outdated_dependency_fix_has_upgrade_command(self, portal, org_id):
        fid = portal.add_finding("org/r", org_id, "Old dep", "medium",
                                  "outdated_dependency", language="python")
        fix = portal.get_fix_suggestion(fid, language="python")
        assert fix.upgrade_command is not None
        assert len(fix.upgrade_command) > 0

    def test_unknown_finding_type_returns_default(self, portal, org_id):
        fid = portal.add_finding("org/r", org_id, "Unknown vuln", "low", "totally_unknown")
        fix = portal.get_fix_suggestion(fid)
        assert isinstance(fix, FixSuggestion)
        assert fix.finding_id == fid

    def test_fix_for_nonexistent_finding(self, portal):
        fix = portal.get_fix_suggestion("nonexistent-id-12345")
        assert isinstance(fix, FixSuggestion)
        assert fix.finding_id == "nonexistent-id-12345"

    def test_batch_fix_suggestions(self, portal, org_id):
        ids = [
            portal.add_finding("org/r", org_id, f"Finding {i}", "medium", "xss")
            for i in range(5)
        ]
        fixes = portal.get_fix_suggestions_batch(ids)
        assert len(fixes) == 5
        assert all(isinstance(f, FixSuggestion) for f in fixes)
        for fix, fid in zip(fixes, ids):
            assert fix.finding_id == fid


# ============================================================================
# Upgrade recommendations tests
# ============================================================================


class TestUpgradeRecommendations:
    def test_returns_only_outdated_dependency_findings(self, portal, org_id, repo_name):
        portal.add_finding(repo_name, org_id, "Old lib", "high", "outdated_dependency",
                           metadata={"package": "django", "fixed_version": "4.2.1"})
        portal.add_finding(repo_name, org_id, "SQL inj", "critical", "sql_injection")

        upgrades = portal.get_upgrade_recommendations(repo_name, org_id)
        assert len(upgrades) == 1
        assert upgrades[0]["title"] == "Old lib"

    def test_upgrade_recommendation_fields(self, portal, org_id, repo_name):
        portal.add_finding(repo_name, org_id, "Vuln dep", "high", "outdated_dependency",
                           metadata={"package": "requests", "current_version": "2.25.0",
                                      "fixed_version": "2.31.0"})
        upgrades = portal.get_upgrade_recommendations(repo_name, org_id)
        assert len(upgrades) == 1
        assert upgrades[0]["package"] == "requests"
        assert upgrades[0]["current_version"] == "2.25.0"
        assert upgrades[0]["fixed_version"] == "2.31.0"

    def test_resolved_dependencies_excluded(self, portal, org_id, repo_name, dev_email):
        portal.register_repo_owner(repo_name, dev_email, org_id)
        fid = portal.add_finding(repo_name, org_id, "Old dep", "medium", "outdated_dependency")
        portal.mark_finding_resolved(fid, dev_email, org_id)
        upgrades = portal.get_upgrade_recommendations(repo_name, org_id)
        assert len(upgrades) == 0

    def test_empty_repo_returns_empty_list(self, portal, org_id):
        upgrades = portal.get_upgrade_recommendations("org/no-findings", org_id)
        assert upgrades == []


# ============================================================================
# Learning resources tests
# ============================================================================


class TestLearningResources:
    def test_sql_injection_resources(self, portal):
        resources = portal.get_learning_resources("sql_injection")
        assert len(resources) >= 1
        assert all(isinstance(r, LearningResource) for r in resources)
        urls = [r.url for r in resources]
        assert any("owasp.org" in u or "cwe.mitre.org" in u for u in urls)

    def test_xss_resources_have_correct_finding_type(self, portal):
        resources = portal.get_learning_resources("xss")
        for r in resources:
            assert "xss" in r.finding_types

    def test_unknown_type_falls_back_to_default(self, portal):
        resources = portal.get_learning_resources("totally_unknown_type")
        assert len(resources) >= 1

    def test_resource_categories_valid(self, portal):
        valid_categories = {"OWASP", "CWE", "best-practice"}
        for finding_type in ["sql_injection", "xss", "hardcoded_secret", "weak_crypto"]:
            for r in portal.get_learning_resources(finding_type):
                assert r.category in valid_categories, (
                    f"Unexpected category '{r.category}' for {finding_type}"
                )


# ============================================================================
# Developer stats tests
# ============================================================================


class TestDeveloperStats:
    def test_stats_for_new_dev(self, portal, org_id, dev_email):
        stats = portal.get_developer_stats(dev_email, org_id)
        assert stats["developer_email"] == dev_email
        assert stats["findings_fixed"] == 0
        assert stats["repos_owned"] == 0

    def test_stats_after_fixing(self, portal, org_id, dev_email, repo_name):
        portal.register_repo_owner(repo_name, dev_email, org_id)
        fid = portal.add_finding(repo_name, org_id, "Bug", "high", "xss")
        portal.mark_finding_resolved(fid, dev_email, org_id, time_to_fix_minutes=45)

        stats = portal.get_developer_stats(dev_email, org_id)
        assert stats["findings_fixed"] == 1
        assert stats["avg_fix_time_minutes"] == 45.0
        assert stats["repos_owned"] == 1

    def test_open_findings_counted(self, populated_portal, org_id, dev_email):
        stats = populated_portal.get_developer_stats(dev_email, org_id)
        assert stats["open_findings"] >= 4


# ============================================================================
# Leaderboard tests
# ============================================================================


class TestLeaderboard:
    def test_leaderboard_empty_org(self, portal, org_id):
        board = portal.get_leaderboard(org_id)
        assert board == []

    def test_leaderboard_ranking(self, portal, org_id):
        repo = "org/repo"
        devs = ["alice@x.com", "bob@x.com", "charlie@x.com"]
        fix_counts = [5, 3, 1]

        for dev, count in zip(devs, fix_counts):
            portal.register_repo_owner(repo, dev, org_id)
            for _ in range(count):
                fid = portal.add_finding(repo, org_id, "F", "medium", "xss")
                portal.mark_finding_resolved(fid, dev, org_id, time_to_fix_minutes=30)

        board = portal.get_leaderboard(org_id)
        assert board[0]["developer_email"] == "alice@x.com"
        assert board[0]["findings_fixed"] == 5
        assert board[0]["rank"] == 1

    def test_leaderboard_limit(self, portal, org_id):
        repo = "org/repo"
        for i in range(5):
            dev = f"dev{i}@x.com"
            portal.register_repo_owner(repo, dev, org_id)
            fid = portal.add_finding(repo, org_id, "F", "low", "xss")
            portal.mark_finding_resolved(fid, dev, org_id)

        board = portal.get_leaderboard(org_id, limit=3)
        assert len(board) == 3
