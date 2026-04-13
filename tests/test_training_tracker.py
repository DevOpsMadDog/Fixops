"""
Security Awareness Training Tracker tests.

Covers:
- TrainingModule / TrainingCompletion Pydantic models
- TrainingTracker CRUD operations
- Completion rate, overdue, stats, compliance evidence
- Training router endpoints via TestClient
"""
from __future__ import annotations

import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, "suite-core")
sys.path.insert(0, "suite-api")

from core.training_tracker import (
    TrainingCategory,
    TrainingCompletion,
    TrainingModule,
    TrainingTracker,
    _BUILTIN_MODULES,
    _FRAMEWORK_MODULES,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture()
def tracker(tmp_path):
    """Fresh TrainingTracker backed by a temp SQLite file."""
    return TrainingTracker(db_path=str(tmp_path / "test_training.db"))


@pytest.fixture()
def sample_module():
    return TrainingModule(
        title="Test Phishing Module",
        description="Test description",
        category=TrainingCategory.PHISHING,
        duration_minutes=20,
        passing_score=80,
        content_url="https://example.com/training",
    )


@pytest.fixture()
def org_id():
    return f"test-org-{uuid.uuid4().hex[:8]}"


def _make_completion(module_id: str, email: str, score: int, org_id: str) -> TrainingCompletion:
    from core.training_tracker import TrainingModule
    # Determine passing based on a placeholder passing_score of 80 for custom modules
    return TrainingCompletion(
        user_email=email,
        module_id=module_id,
        score=score,
        passed=score >= 80,
        org_id=org_id,
    )


# ===========================================================================
# 1. Model tests
# ===========================================================================

class TestTrainingModuleModel:
    def test_model_fields_present(self, sample_module):
        assert sample_module.title == "Test Phishing Module"
        assert sample_module.category == TrainingCategory.PHISHING
        assert sample_module.duration_minutes == 20
        assert sample_module.passing_score == 80

    def test_model_auto_id(self, sample_module):
        assert isinstance(sample_module.id, str)
        assert len(sample_module.id) > 0

    def test_all_categories_valid(self):
        for cat in TrainingCategory:
            m = TrainingModule(
                title="T", description="D", category=cat,
                duration_minutes=10, passing_score=70, content_url="https://x.com"
            )
            assert m.category == cat

    def test_passing_score_bounds(self):
        with pytest.raises(Exception):
            TrainingModule(
                title="T", description="D", category=TrainingCategory.PHISHING,
                duration_minutes=10, passing_score=101, content_url="https://x.com"
            )

    def test_duration_positive(self):
        with pytest.raises(Exception):
            TrainingModule(
                title="T", description="D", category=TrainingCategory.PHISHING,
                duration_minutes=0, passing_score=80, content_url="https://x.com"
            )


class TestTrainingCompletionModel:
    def test_model_fields(self):
        c = TrainingCompletion(
            user_email="alice@example.com",
            module_id="mod-1",
            score=90,
            passed=True,
            org_id="org-1",
        )
        assert c.user_email == "alice@example.com"
        assert c.passed is True
        assert c.score == 90

    def test_auto_id_generated(self):
        c = TrainingCompletion(
            user_email="bob@example.com",
            module_id="mod-1",
            score=70,
            passed=False,
            org_id="org-1",
        )
        assert isinstance(c.id, str)
        assert len(c.id) > 0

    def test_completed_at_defaults_to_now(self):
        c = TrainingCompletion(
            user_email="carol@example.com",
            module_id="mod-1",
            score=85,
            passed=True,
            org_id="org-1",
        )
        assert isinstance(c.completed_at, datetime)

    def test_score_bounds(self):
        with pytest.raises(Exception):
            TrainingCompletion(
                user_email="x@x.com", module_id="m", score=101, passed=True, org_id="o"
            )


# ===========================================================================
# 2. Built-in module seeding
# ===========================================================================

class TestBuiltinModules:
    def test_ten_builtin_modules_seeded(self, tracker):
        modules = tracker.list_modules()
        builtin_ids = {m["id"] for m in _BUILTIN_MODULES}
        seeded_ids = {m.id for m in modules}
        assert builtin_ids.issubset(seeded_ids)

    def test_exactly_ten_builtin_modules(self):
        assert len(_BUILTIN_MODULES) == 10

    def test_all_categories_represented(self):
        categories = {m["category"] for m in _BUILTIN_MODULES}
        expected = {"phishing", "passwords", "data_handling", "incident_reporting", "social_engineering"}
        assert categories == expected

    def test_builtin_module_required_fields(self):
        for m in _BUILTIN_MODULES:
            assert "id" in m
            assert "title" in m
            assert "category" in m
            assert "duration_minutes" in m
            assert "passing_score" in m
            assert "content_url" in m


# ===========================================================================
# 3. add_module / list_modules / get_module
# ===========================================================================

class TestModuleCRUD:
    def test_add_module_returns_module(self, tracker, sample_module):
        result = tracker.add_module(sample_module)
        assert result.id == sample_module.id
        assert result.title == sample_module.title

    def test_list_modules_includes_added(self, tracker, sample_module):
        tracker.add_module(sample_module)
        modules = tracker.list_modules()
        ids = [m.id for m in modules]
        assert sample_module.id in ids

    def test_list_modules_filter_by_category(self, tracker, sample_module):
        tracker.add_module(sample_module)
        results = tracker.list_modules(category=TrainingCategory.PHISHING)
        assert all(m.category == TrainingCategory.PHISHING for m in results)
        assert any(m.id == sample_module.id for m in results)

    def test_list_modules_filter_excludes_other_categories(self, tracker, sample_module):
        tracker.add_module(sample_module)
        results = tracker.list_modules(category=TrainingCategory.PASSWORDS)
        ids = [m.id for m in results]
        assert sample_module.id not in ids

    def test_get_module_by_id(self, tracker, sample_module):
        tracker.add_module(sample_module)
        fetched = tracker.get_module(sample_module.id)
        assert fetched is not None
        assert fetched.id == sample_module.id
        assert fetched.title == sample_module.title

    def test_get_module_not_found_returns_none(self, tracker):
        result = tracker.get_module("nonexistent-id")
        assert result is None


# ===========================================================================
# 4. record_completion / get_user_training
# ===========================================================================

class TestCompletionRecording:
    def test_record_completion_returns_completion(self, tracker, org_id):
        module_id = "builtin-phishing-01"
        c = _make_completion(module_id, "alice@test.com", 90, org_id)
        result = tracker.record_completion(c)
        assert result.user_email == "alice@test.com"
        assert result.passed is True

    def test_get_user_training_history(self, tracker, org_id):
        module_id = "builtin-phishing-01"
        c = _make_completion(module_id, "alice@test.com", 90, org_id)
        tracker.record_completion(c)
        history = tracker.get_user_training("alice@test.com", org_id=org_id)
        assert len(history) == 1
        assert history[0].module_id == module_id

    def test_get_user_training_multiple_modules(self, tracker, org_id):
        email = "bob@test.com"
        for mid in ["builtin-phishing-01", "builtin-passwords-01", "builtin-incident-01"]:
            c = _make_completion(mid, email, 85, org_id)
            tracker.record_completion(c)
        history = tracker.get_user_training(email, org_id=org_id)
        assert len(history) == 3

    def test_get_user_training_no_history(self, tracker, org_id):
        history = tracker.get_user_training("nobody@test.com", org_id=org_id)
        assert history == []

    def test_get_user_training_filters_by_org(self, tracker):
        email = "carol@test.com"
        c1 = _make_completion("builtin-phishing-01", email, 90, "org-a")
        c2 = _make_completion("builtin-passwords-01", email, 85, "org-b")
        tracker.record_completion(c1)
        tracker.record_completion(c2)
        history_a = tracker.get_user_training(email, org_id="org-a")
        assert len(history_a) == 1
        assert history_a[0].org_id == "org-a"

    def test_failed_completion_recorded(self, tracker, org_id):
        c = TrainingCompletion(
            user_email="dave@test.com",
            module_id="builtin-phishing-01",
            score=50,
            passed=False,
            org_id=org_id,
        )
        result = tracker.record_completion(c)
        assert result.passed is False
        assert result.score == 50


# ===========================================================================
# 5. get_completion_rate
# ===========================================================================

class TestCompletionRate:
    def test_empty_org_returns_zero(self, tracker, org_id):
        result = tracker.get_completion_rate(org_id)
        assert result["total_users"] == 0
        assert result["overall_completion_rate"] == 0.0

    def test_completion_rate_with_one_user_all_passed(self, tracker, org_id):
        email = "alice@test.com"
        for m in _BUILTIN_MODULES:
            c = TrainingCompletion(
                user_email=email, module_id=m["id"], score=90, passed=True, org_id=org_id
            )
            tracker.record_completion(c)
        result = tracker.get_completion_rate(org_id)
        assert result["total_users"] == 1
        assert result["overall_completion_rate"] == 100.0

    def test_completion_rate_partial(self, tracker, org_id):
        email = "bob@test.com"
        # Pass only the first 5 modules
        for m in _BUILTIN_MODULES[:5]:
            c = TrainingCompletion(
                user_email=email, module_id=m["id"], score=90, passed=True, org_id=org_id
            )
            tracker.record_completion(c)
        result = tracker.get_completion_rate(org_id)
        assert result["total_users"] == 1
        assert result["overall_completion_rate"] < 100.0

    def test_completion_rate_structure(self, tracker, org_id):
        email = "carol@test.com"
        c = TrainingCompletion(
            user_email=email, module_id="builtin-phishing-01", score=90, passed=True, org_id=org_id
        )
        tracker.record_completion(c)
        result = tracker.get_completion_rate(org_id)
        assert "org_id" in result
        assert "total_users" in result
        assert "overall_completion_rate" in result
        assert "by_module" in result


# ===========================================================================
# 6. get_overdue_training
# ===========================================================================

class TestOverdueTraining:
    def test_no_overdue_when_all_passed(self, tracker, org_id):
        email = "alice@test.com"
        required = ["builtin-phishing-01", "builtin-passwords-01"]
        for mid in required:
            c = TrainingCompletion(
                user_email=email, module_id=mid, score=90, passed=True, org_id=org_id
            )
            tracker.record_completion(c)
        overdue = tracker.get_overdue_training(org_id, required_module_ids=required)
        assert len(overdue) == 0

    def test_overdue_user_listed(self, tracker, org_id):
        email = "bob@test.com"
        required = ["builtin-phishing-01", "builtin-passwords-01"]
        # Only complete first module
        c = TrainingCompletion(
            user_email=email, module_id="builtin-phishing-01", score=90, passed=True, org_id=org_id
        )
        tracker.record_completion(c)
        overdue = tracker.get_overdue_training(org_id, required_module_ids=required)
        assert len(overdue) == 1
        assert overdue[0]["user_email"] == email
        assert any(m["id"] == "builtin-passwords-01" for m in overdue[0]["missing_modules"])

    def test_overdue_failed_completion_counts_as_missing(self, tracker, org_id):
        email = "carol@test.com"
        required = ["builtin-phishing-01"]
        # Record a failed attempt
        c = TrainingCompletion(
            user_email=email, module_id="builtin-phishing-01", score=50, passed=False, org_id=org_id
        )
        tracker.record_completion(c)
        overdue = tracker.get_overdue_training(org_id, required_module_ids=required)
        assert len(overdue) == 1

    def test_overdue_uses_all_builtins_by_default(self, tracker, org_id):
        email = "dave@test.com"
        # Only pass one module
        c = TrainingCompletion(
            user_email=email, module_id="builtin-phishing-01", score=90, passed=True, org_id=org_id
        )
        tracker.record_completion(c)
        overdue = tracker.get_overdue_training(org_id)
        assert len(overdue) == 1
        assert overdue[0]["missing_count"] == 9  # 10 builtins minus 1 passed


# ===========================================================================
# 7. get_training_stats
# ===========================================================================

class TestTrainingStats:
    def test_stats_empty_org(self, tracker, org_id):
        stats = tracker.get_training_stats(org_id)
        assert stats["total_attempts"] == 0
        assert stats["total_passed"] == 0
        assert stats["overall_pass_rate"] == 0.0
        assert stats["total_users"] == 0

    def test_stats_pass_rate_calculation(self, tracker, org_id):
        email = "alice@test.com"
        # 2 passed, 1 failed
        for score, passed in [(90, True), (85, True), (60, False)]:
            c = TrainingCompletion(
                user_email=email, module_id="builtin-phishing-01", score=score, passed=passed, org_id=org_id
            )
            tracker.record_completion(c)
        stats = tracker.get_training_stats(org_id)
        assert stats["total_attempts"] == 3
        assert stats["total_passed"] == 2
        assert abs(stats["overall_pass_rate"] - 66.7) < 0.1

    def test_stats_structure(self, tracker, org_id):
        c = TrainingCompletion(
            user_email="bob@test.com", module_id="builtin-phishing-01",
            score=90, passed=True, org_id=org_id
        )
        tracker.record_completion(c)
        stats = tracker.get_training_stats(org_id)
        assert "by_module" in stats
        assert "by_user" in stats
        assert isinstance(stats["by_module"], list)
        assert isinstance(stats["by_user"], list)

    def test_stats_by_user(self, tracker, org_id):
        email = "carol@test.com"
        for mid in ["builtin-phishing-01", "builtin-passwords-01"]:
            c = TrainingCompletion(
                user_email=email, module_id=mid, score=90, passed=True, org_id=org_id
            )
            tracker.record_completion(c)
        stats = tracker.get_training_stats(org_id)
        user_stat = next((u for u in stats["by_user"] if u["user_email"] == email), None)
        assert user_stat is not None
        assert user_stat["modules_passed"] == 2


# ===========================================================================
# 8. get_compliance_training_status
# ===========================================================================

class TestComplianceTrainingStatus:
    def test_compliance_status_structure(self, tracker, org_id):
        result = tracker.get_compliance_training_status(org_id, "SOC2")
        assert result["framework"] == "SOC2"
        assert "required_module_count" in result
        assert "compliant_users" in result
        assert "compliance_rate" in result
        assert "required_modules" in result
        assert "evidence_generated_at" in result

    def test_compliance_empty_org(self, tracker, org_id):
        result = tracker.get_compliance_training_status(org_id, "HIPAA")
        assert result["total_users"] == 0
        assert result["compliance_rate"] == 0.0

    def test_compliance_fully_compliant_user(self, tracker, org_id):
        email = "alice@test.com"
        required_ids = _FRAMEWORK_MODULES["SOC2"]
        for mid in required_ids:
            c = TrainingCompletion(
                user_email=email, module_id=mid, score=90, passed=True, org_id=org_id
            )
            tracker.record_completion(c)
        result = tracker.get_compliance_training_status(org_id, "SOC2")
        assert result["compliant_users"] == 1
        assert result["compliance_rate"] == 100.0

    def test_compliance_partial_completion(self, tracker, org_id):
        email = "bob@test.com"
        required_ids = _FRAMEWORK_MODULES["HIPAA"]
        # Complete only half
        for mid in required_ids[:2]:
            c = TrainingCompletion(
                user_email=email, module_id=mid, score=90, passed=True, org_id=org_id
            )
            tracker.record_completion(c)
        result = tracker.get_compliance_training_status(org_id, "HIPAA")
        assert result["compliant_users"] == 0
        assert result["compliance_rate"] == 0.0
        assert email in result["non_compliant_users"]

    def test_all_frameworks_supported(self, tracker, org_id):
        for framework in ["SOC2", "HIPAA", "PCI-DSS", "ISO27001", "GDPR", "NIST"]:
            result = tracker.get_compliance_training_status(org_id, framework)
            assert result["framework"] == framework

    def test_framework_required_modules_not_empty(self):
        for framework, mids in _FRAMEWORK_MODULES.items():
            assert len(mids) > 0, f"{framework} has no required modules"


# ===========================================================================
# 9. Router endpoint tests via TestClient
# ===========================================================================

@pytest.fixture()
def client(tmp_path):
    """FastAPI TestClient with isolated SQLite DB and auth bypassed."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from apps.api.training_router import router
    import apps.api.training_router as tr_module
    from apps.api.auth_deps import api_key_auth
    from core.training_tracker import TrainingTracker

    test_tracker = TrainingTracker(db_path=str(tmp_path / "router_test.db"))
    tr_module._tracker = test_tracker

    app = FastAPI()
    # Override auth dependency so tests don't need credentials
    app.dependency_overrides[api_key_auth] = lambda: None
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=True)


class TestTrainingRouterEndpoints:
    def test_list_modules_returns_200(self, client):
        resp = client.get("/api/v1/training/modules")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 10  # at least the 10 built-ins

    def test_list_modules_filter_by_category(self, client):
        resp = client.get("/api/v1/training/modules?category=phishing")
        assert resp.status_code == 200
        data = resp.json()
        assert all(m["category"] == "phishing" for m in data)

    def test_get_module_builtin(self, client):
        resp = client.get("/api/v1/training/modules/builtin-phishing-01")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == "builtin-phishing-01"

    def test_get_module_not_found(self, client):
        resp = client.get("/api/v1/training/modules/does-not-exist")
        assert resp.status_code == 404

    def test_add_module_creates_module(self, client):
        payload = {
            "title": "Custom Module",
            "description": "A custom training module",
            "category": "phishing",
            "duration_minutes": 15,
            "passing_score": 75,
            "content_url": "https://example.com/custom",
        }
        resp = client.post("/api/v1/training/modules", json=payload)
        assert resp.status_code == 201
        data = resp.json()
        assert data["title"] == "Custom Module"
        assert "id" in data

    def test_record_completion_pass(self, client):
        payload = {
            "user_email": "alice@example.com",
            "module_id": "builtin-phishing-01",
            "score": 90,
            "org_id": "org-test",
        }
        resp = client.post("/api/v1/training/completions", json=payload)
        assert resp.status_code == 201
        data = resp.json()
        assert data["passed"] is True
        assert data["module_title"] == "Phishing Awareness Fundamentals"

    def test_record_completion_fail(self, client):
        payload = {
            "user_email": "bob@example.com",
            "module_id": "builtin-phishing-01",
            "score": 50,
            "org_id": "org-test",
        }
        resp = client.post("/api/v1/training/completions", json=payload)
        assert resp.status_code == 201
        data = resp.json()
        assert data["passed"] is False

    def test_record_completion_module_not_found(self, client):
        payload = {
            "user_email": "carol@example.com",
            "module_id": "nonexistent",
            "score": 90,
            "org_id": "org-test",
        }
        resp = client.post("/api/v1/training/completions", json=payload)
        assert resp.status_code == 404

    def test_get_user_training_history(self, client):
        # First record a completion
        client.post("/api/v1/training/completions", json={
            "user_email": "dave@example.com",
            "module_id": "builtin-passwords-01",
            "score": 85,
            "org_id": "org-test",
        })
        resp = client.get("/api/v1/training/users/dave@example.com")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 1

    def test_get_completion_rate(self, client):
        resp = client.get("/api/v1/training/orgs/org-test/completion-rate")
        assert resp.status_code == 200
        data = resp.json()
        assert "overall_completion_rate" in data
        assert "total_users" in data

    def test_get_overdue_training(self, client):
        resp = client.get("/api/v1/training/orgs/org-test/overdue")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_get_training_stats(self, client):
        resp = client.get("/api/v1/training/orgs/org-test/stats")
        assert resp.status_code == 200
        data = resp.json()
        assert "by_module" in data
        assert "by_user" in data
        assert "overall_pass_rate" in data

    def test_compliance_status_soc2(self, client):
        resp = client.get("/api/v1/training/orgs/org-test/compliance/SOC2")
        assert resp.status_code == 200
        data = resp.json()
        assert data["framework"] == "SOC2"
        assert "compliance_rate" in data

    def test_compliance_status_unsupported_framework(self, client):
        resp = client.get("/api/v1/training/orgs/org-test/compliance/MADE-UP")
        assert resp.status_code == 400

    def test_compliance_all_supported_frameworks(self, client):
        for fw in ["SOC2", "HIPAA", "PCI-DSS", "ISO27001", "GDPR", "NIST"]:
            resp = client.get(f"/api/v1/training/orgs/org-test/compliance/{fw}")
            assert resp.status_code == 200, f"Failed for framework {fw}"
