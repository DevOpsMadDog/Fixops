"""Tests for customer onboarding wizard.

Covers:
- Start onboarding, verify initial state
- Complete steps in order, verify progress percentage
- Skip steps
- Step validation (missing config)
- Reset onboarding
- Get step config after completion
- Checklist endpoint
- API router endpoints via FastAPI TestClient
- List onboardings with status filter
- 30 tests total
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any, Dict

import pytest

# ---------------------------------------------------------------------------
# Environment setup (must precede any app imports)
# ---------------------------------------------------------------------------
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from fastapi import FastAPI
from fastapi.testclient import TestClient

from core.onboarding import (
    OnboardingManager,
    OnboardingProgress,
    OnboardingStep,
    StepStatus,
    STEP_ORDER,
    VALID_FRAMEWORKS,
)
import apps.api.onboarding_router as onboarding_router_module
from apps.api.onboarding_router import router as onboarding_router


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def tmp_db(tmp_path: Path) -> Path:
    return tmp_path / "test_onboarding.db"


@pytest.fixture()
def manager(tmp_db: Path) -> OnboardingManager:
    return OnboardingManager(db_path=tmp_db)


@pytest.fixture()
def client(tmp_db: Path) -> TestClient:
    """TestClient with onboarding router mounted and fresh manager."""
    mgr = OnboardingManager(db_path=tmp_db)
    onboarding_router_module._manager = mgr

    app = FastAPI()
    app.include_router(onboarding_router)
    return TestClient(app)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _complete_welcome(manager: OnboardingManager, org: str) -> OnboardingProgress:
    return manager.complete_step(org, OnboardingStep.WELCOME, {})


def _complete_auth(manager: OnboardingManager, org: str) -> OnboardingProgress:
    return manager.complete_step(
        org, OnboardingStep.CONFIGURE_AUTH, {"api_key": "sk-test-123"}
    )


def _complete_scanners(manager: OnboardingManager, org: str) -> OnboardingProgress:
    return manager.complete_step(
        org, OnboardingStep.CONNECT_SCANNERS, {"scanners": ["snyk", "trivy"]}
    )


def _complete_frameworks(manager: OnboardingManager, org: str) -> OnboardingProgress:
    return manager.complete_step(
        org, OnboardingStep.SELECT_FRAMEWORKS, {"frameworks": ["SOC2", "HIPAA"]}
    )


def _complete_roles(manager: OnboardingManager, org: str) -> OnboardingProgress:
    return manager.complete_step(
        org,
        OnboardingStep.DEFINE_ROLES,
        {"users": [{"name": "Alice", "role": "admin"}]},
    )


# ===========================================================================
# OnboardingManager unit tests
# ===========================================================================


class TestStartOnboarding:
    def test_start_creates_progress(self, manager: OnboardingManager) -> None:
        prog = manager.start_onboarding("org-001")
        assert prog.org_id == "org-001"
        assert prog.current_step == OnboardingStep.WELCOME
        assert prog.completion_percentage == 0.0
        assert prog.completed_at is None

    def test_start_idempotent(self, manager: OnboardingManager) -> None:
        p1 = manager.start_onboarding("org-001")
        p2 = manager.start_onboarding("org-001")
        assert p1.started_at == p2.started_at

    def test_all_steps_pending_on_start(self, manager: OnboardingManager) -> None:
        prog = manager.start_onboarding("org-002")
        for step in STEP_ORDER:
            assert prog.steps[step.value] in (StepStatus.PENDING, "PENDING")


class TestGetProgress:
    def test_get_progress_after_start(self, manager: OnboardingManager) -> None:
        manager.start_onboarding("org-010")
        prog = manager.get_progress("org-010")
        assert prog.org_id == "org-010"

    def test_get_progress_missing_org_raises(self, manager: OnboardingManager) -> None:
        with pytest.raises(KeyError):
            manager.get_progress("nonexistent-org")


class TestCompleteStep:
    def test_complete_welcome_advances_step(self, manager: OnboardingManager) -> None:
        manager.start_onboarding("org-020")
        prog = _complete_welcome(manager, "org-020")
        assert prog.steps[OnboardingStep.WELCOME.value] in (
            StepStatus.COMPLETED,
            "COMPLETED",
        )
        assert prog.completion_percentage > 0

    def test_progress_percentage_increases_with_each_step(
        self, manager: OnboardingManager
    ) -> None:
        org = "org-021"
        manager.start_onboarding(org)
        p1 = _complete_welcome(manager, org)
        p2 = _complete_auth(manager, org)
        p3 = _complete_scanners(manager, org)
        assert p3.completion_percentage > p2.completion_percentage > p1.completion_percentage

    def test_complete_step_not_found_raises(self, manager: OnboardingManager) -> None:
        with pytest.raises(KeyError):
            manager.complete_step("no-org", OnboardingStep.WELCOME, {})

    def test_complete_stores_config(self, manager: OnboardingManager) -> None:
        org = "org-022"
        manager.start_onboarding(org)
        config = {"api_key": "mykey", "extra": "value"}
        manager.complete_step(org, OnboardingStep.CONFIGURE_AUTH, config)
        stored = manager.get_step_config(org, OnboardingStep.CONFIGURE_AUTH)
        assert stored["api_key"] == "mykey"
        assert stored["extra"] == "value"


class TestValidation:
    def test_configure_auth_requires_api_key_or_sso(
        self, manager: OnboardingManager
    ) -> None:
        manager.start_onboarding("org-030")
        with pytest.raises(ValueError, match="CONFIGURE_AUTH"):
            manager.complete_step(
                "org-030", OnboardingStep.CONFIGURE_AUTH, {}
            )

    def test_configure_auth_accepts_sso(self, manager: OnboardingManager) -> None:
        manager.start_onboarding("org-031")
        prog = manager.complete_step(
            "org-031",
            OnboardingStep.CONFIGURE_AUTH,
            {"sso_provider": "okta"},
        )
        assert prog.steps[OnboardingStep.CONFIGURE_AUTH.value] in (
            StepStatus.COMPLETED,
            "COMPLETED",
        )

    def test_connect_scanners_requires_at_least_one(
        self, manager: OnboardingManager
    ) -> None:
        manager.start_onboarding("org-032")
        with pytest.raises(ValueError, match="CONNECT_SCANNERS"):
            manager.complete_step(
                "org-032", OnboardingStep.CONNECT_SCANNERS, {"scanners": []}
            )

    def test_select_frameworks_requires_at_least_one(
        self, manager: OnboardingManager
    ) -> None:
        manager.start_onboarding("org-033")
        with pytest.raises(ValueError, match="SELECT_FRAMEWORKS"):
            manager.complete_step(
                "org-033", OnboardingStep.SELECT_FRAMEWORKS, {"frameworks": []}
            )

    def test_select_frameworks_rejects_unknown(
        self, manager: OnboardingManager
    ) -> None:
        manager.start_onboarding("org-034")
        with pytest.raises(ValueError, match="Unknown"):
            manager.complete_step(
                "org-034",
                OnboardingStep.SELECT_FRAMEWORKS,
                {"frameworks": ["MADE-UP-FRAMEWORK"]},
            )

    def test_define_roles_requires_admin(self, manager: OnboardingManager) -> None:
        manager.start_onboarding("org-035")
        with pytest.raises(ValueError, match="admin"):
            manager.complete_step(
                "org-035",
                OnboardingStep.DEFINE_ROLES,
                {"users": [{"name": "Bob", "role": "viewer"}]},
            )

    def test_run_first_scan_requires_trigger(self, manager: OnboardingManager) -> None:
        manager.start_onboarding("org-036")
        with pytest.raises(ValueError, match="scan_triggered"):
            manager.complete_step(
                "org-036", OnboardingStep.RUN_FIRST_SCAN, {}
            )

    def test_review_results_requires_scan_completed(
        self, manager: OnboardingManager
    ) -> None:
        manager.start_onboarding("org-037")
        with pytest.raises(ValueError, match="first_scan_completed"):
            manager.complete_step(
                "org-037", OnboardingStep.REVIEW_RESULTS, {}
            )

    def test_connect_ticketing_requires_connectors(
        self, manager: OnboardingManager
    ) -> None:
        """CONNECT_TICKETING rejects empty connectors list (use skip_step instead)."""
        manager.start_onboarding("org-038")
        with pytest.raises(ValueError, match="CONNECT_TICKETING"):
            manager.complete_step(
                "org-038", OnboardingStep.CONNECT_TICKETING, {"connectors": []}
            )


class TestSkipStep:
    def test_skip_marks_as_skipped(self, manager: OnboardingManager) -> None:
        manager.start_onboarding("org-040")
        prog = manager.skip_step("org-040", OnboardingStep.CONNECT_TICKETING)
        assert prog.steps[OnboardingStep.CONNECT_TICKETING.value] in (
            StepStatus.SKIPPED,
            "SKIPPED",
        )

    def test_skip_advances_percentage(self, manager: OnboardingManager) -> None:
        org = "org-041"
        manager.start_onboarding(org)
        prog = manager.skip_step(org, OnboardingStep.CONNECT_TICKETING)
        assert prog.completion_percentage > 0

    def test_skip_not_found_raises(self, manager: OnboardingManager) -> None:
        with pytest.raises(KeyError):
            manager.skip_step("no-org", OnboardingStep.CONNECT_TICKETING)


class TestResetOnboarding:
    def test_reset_clears_progress(self, manager: OnboardingManager) -> None:
        org = "org-050"
        manager.start_onboarding(org)
        _complete_welcome(manager, org)
        _complete_auth(manager, org)
        fresh = manager.reset_onboarding(org)
        assert fresh.completion_percentage == 0.0
        assert fresh.current_step == OnboardingStep.WELCOME

    def test_reset_clears_configs(self, manager: OnboardingManager) -> None:
        org = "org-051"
        manager.start_onboarding(org)
        manager.complete_step(
            org, OnboardingStep.CONFIGURE_AUTH, {"api_key": "old-key"}
        )
        manager.reset_onboarding(org)
        config = manager.get_step_config(org, OnboardingStep.CONFIGURE_AUTH)
        assert config == {}


class TestGetStepConfig:
    def test_get_config_returns_empty_before_completion(
        self, manager: OnboardingManager
    ) -> None:
        manager.start_onboarding("org-060")
        config = manager.get_step_config("org-060", OnboardingStep.WELCOME)
        assert config == {}

    def test_get_config_after_completion(self, manager: OnboardingManager) -> None:
        org = "org-061"
        manager.start_onboarding(org)
        manager.complete_step(
            org,
            OnboardingStep.SELECT_FRAMEWORKS,
            {"frameworks": ["SOC2", "GDPR"]},
        )
        config = manager.get_step_config(org, OnboardingStep.SELECT_FRAMEWORKS)
        assert "SOC2" in config["frameworks"]
        assert "GDPR" in config["frameworks"]


class TestListOnboardings:
    def test_list_all(self, manager: OnboardingManager) -> None:
        manager.start_onboarding("org-070")
        manager.start_onboarding("org-071")
        items = manager.list_onboardings()
        assert len(items) >= 2

    def test_list_completed_filter(self, manager: OnboardingManager) -> None:
        org = "org-072"
        manager.start_onboarding(org)
        # Complete all non-COMPLETE steps
        for step in STEP_ORDER[:-1]:
            try:
                if step == OnboardingStep.CONFIGURE_AUTH:
                    manager.complete_step(org, step, {"api_key": "k"})
                elif step == OnboardingStep.CONNECT_SCANNERS:
                    manager.complete_step(org, step, {"scanners": ["snyk"]})
                elif step == OnboardingStep.SELECT_FRAMEWORKS:
                    manager.complete_step(org, step, {"frameworks": ["SOC2"]})
                elif step == OnboardingStep.DEFINE_ROLES:
                    manager.complete_step(
                        org, step, {"users": [{"role": "admin"}]}
                    )
                elif step == OnboardingStep.RUN_FIRST_SCAN:
                    manager.complete_step(org, step, {"scan_triggered": True})
                elif step == OnboardingStep.REVIEW_RESULTS:
                    manager.complete_step(
                        org, step, {"first_scan_completed": True}
                    )
                else:
                    manager.complete_step(org, step, {})
            except ValueError:
                manager.skip_step(org, step)

        completed = manager.list_onboardings(status_filter="completed")
        org_ids = [p.org_id for p in completed]
        assert org in org_ids

    def test_list_not_started_filter(self, manager: OnboardingManager) -> None:
        """Orgs that were started but have 0% progress appear in not_started."""
        org = "org-073"
        manager.start_onboarding(org)
        not_started = manager.list_onboardings(status_filter="not_started")
        org_ids = [p.org_id for p in not_started]
        assert org in org_ids

    def test_list_in_progress_filter(self, manager: OnboardingManager) -> None:
        """Org with at least one step done but not fully complete is in_progress."""
        org = "org-074"
        manager.start_onboarding(org)
        manager.complete_step(org, OnboardingStep.WELCOME, {})
        in_progress = manager.list_onboardings(status_filter="in_progress")
        org_ids = [p.org_id for p in in_progress]
        assert org in org_ids

    def test_completion_percentage_100_on_full_completion(
        self, manager: OnboardingManager
    ) -> None:
        """Completing every step (plus skipping optional ones) yields 100%."""
        org = "org-075"
        manager.start_onboarding(org)
        for step in STEP_ORDER[:-1]:
            try:
                if step == OnboardingStep.CONFIGURE_AUTH:
                    manager.complete_step(org, step, {"api_key": "k"})
                elif step == OnboardingStep.CONNECT_SCANNERS:
                    manager.complete_step(org, step, {"scanners": ["trivy"]})
                elif step == OnboardingStep.SELECT_FRAMEWORKS:
                    manager.complete_step(org, step, {"frameworks": ["NIST-CSF"]})
                elif step == OnboardingStep.DEFINE_ROLES:
                    manager.complete_step(
                        org, step, {"users": [{"name": "CTO", "role": "admin"}]}
                    )
                elif step == OnboardingStep.RUN_FIRST_SCAN:
                    manager.complete_step(org, step, {"scan_triggered": True})
                elif step == OnboardingStep.REVIEW_RESULTS:
                    manager.complete_step(
                        org, step, {"first_scan_completed": True}
                    )
                else:
                    manager.complete_step(org, step, {})
            except ValueError:
                manager.skip_step(org, step)
        prog = manager.get_progress(org)
        assert prog.completion_percentage == 100.0
        assert prog.completed_at is not None


class TestChecklist:
    def test_checklist_no_onboarding(self, manager: OnboardingManager) -> None:
        result = manager.get_checklist("org-080")
        assert result["onboarding_started"] is False
        assert result["items"] == []

    def test_checklist_after_start(self, manager: OnboardingManager) -> None:
        manager.start_onboarding("org-081")
        result = manager.get_checklist("org-081")
        assert result["onboarding_started"] is True
        assert len(result["items"]) == len(STEP_ORDER)

    def test_checklist_shows_completed_step(self, manager: OnboardingManager) -> None:
        org = "org-082"
        manager.start_onboarding(org)
        _complete_welcome(manager, org)
        result = manager.get_checklist(org)
        welcome_item = next(i for i in result["items"] if i["step"] == "WELCOME")
        assert welcome_item["status"] == "COMPLETED"


# ===========================================================================
# API router tests (via FastAPI TestClient)
# ===========================================================================


class TestOnboardingAPI:
    def test_start_returns_201(self, client: TestClient) -> None:
        resp = client.post("/api/v1/onboarding/start", json={"org_id": "api-org-001"})
        assert resp.status_code == 201
        data = resp.json()
        assert data["org_id"] == "api-org-001"
        assert data["current_step"] == "WELCOME"
        assert data["completion_percentage"] == 0.0

    def test_get_progress_404_for_unknown(self, client: TestClient) -> None:
        resp = client.get("/api/v1/onboarding/progress?org_id=unknown-999")
        assert resp.status_code == 404

    def test_get_progress_after_start(self, client: TestClient) -> None:
        client.post("/api/v1/onboarding/start", json={"org_id": "api-org-002"})
        resp = client.get("/api/v1/onboarding/progress?org_id=api-org-002")
        assert resp.status_code == 200
        assert resp.json()["org_id"] == "api-org-002"

    def test_complete_step_via_api(self, client: TestClient) -> None:
        client.post("/api/v1/onboarding/start", json={"org_id": "api-org-003"})
        resp = client.post(
            "/api/v1/onboarding/steps/CONFIGURE_AUTH/complete",
            json={"org_id": "api-org-003", "config_data": {"api_key": "test-key"}},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["steps"]["CONFIGURE_AUTH"] == "COMPLETED"

    def test_complete_step_validation_error(self, client: TestClient) -> None:
        client.post("/api/v1/onboarding/start", json={"org_id": "api-org-004"})
        resp = client.post(
            "/api/v1/onboarding/steps/CONFIGURE_AUTH/complete",
            json={"org_id": "api-org-004", "config_data": {}},
        )
        assert resp.status_code == 422

    def test_skip_step_via_api(self, client: TestClient) -> None:
        client.post("/api/v1/onboarding/start", json={"org_id": "api-org-005"})
        resp = client.post(
            "/api/v1/onboarding/steps/CONNECT_TICKETING/skip",
            json={"org_id": "api-org-005"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["steps"]["CONNECT_TICKETING"] == "SKIPPED"

    def test_get_step_config_via_api(self, client: TestClient) -> None:
        client.post("/api/v1/onboarding/start", json={"org_id": "api-org-006"})
        client.post(
            "/api/v1/onboarding/steps/CONFIGURE_AUTH/complete",
            json={"org_id": "api-org-006", "config_data": {"api_key": "my-key"}},
        )
        resp = client.get(
            "/api/v1/onboarding/steps/CONFIGURE_AUTH/config?org_id=api-org-006"
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["config"]["api_key"] == "my-key"

    def test_reset_via_api(self, client: TestClient) -> None:
        client.post("/api/v1/onboarding/start", json={"org_id": "api-org-007"})
        client.post(
            "/api/v1/onboarding/steps/CONFIGURE_AUTH/complete",
            json={"org_id": "api-org-007", "config_data": {"api_key": "k"}},
        )
        resp = client.post(
            "/api/v1/onboarding/reset", json={"org_id": "api-org-007"}
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["completion_percentage"] == 0.0

    def test_checklist_via_api(self, client: TestClient) -> None:
        client.post("/api/v1/onboarding/start", json={"org_id": "api-org-008"})
        resp = client.get("/api/v1/onboarding/checklist?org_id=api-org-008")
        assert resp.status_code == 200
        data = resp.json()
        assert data["onboarding_started"] is True
        assert len(data["items"]) == len(STEP_ORDER)

    def test_checklist_not_started(self, client: TestClient) -> None:
        resp = client.get("/api/v1/onboarding/checklist?org_id=never-started")
        assert resp.status_code == 200
        data = resp.json()
        assert data["onboarding_started"] is False

    def test_invalid_step_name_returns_422(self, client: TestClient) -> None:
        client.post("/api/v1/onboarding/start", json={"org_id": "api-org-009"})
        resp = client.post(
            "/api/v1/onboarding/steps/INVALID_STEP/complete",
            json={"org_id": "api-org-009", "config_data": {}},
        )
        assert resp.status_code == 422

    def test_list_onboardings_via_api(self, client: TestClient) -> None:
        client.post("/api/v1/onboarding/start", json={"org_id": "api-org-010"})
        resp = client.get("/api/v1/onboarding/list")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] >= 1
        assert isinstance(data["onboardings"], list)

    def test_list_onboardings_not_started_filter_via_api(
        self, client: TestClient
    ) -> None:
        """GET /list?status=not_started returns newly created orgs at 0%."""
        client.post("/api/v1/onboarding/start", json={"org_id": "api-org-011"})
        resp = client.get("/api/v1/onboarding/list?status=not_started")
        assert resp.status_code == 200
        data = resp.json()
        org_ids = [o["org_id"] for o in data["onboardings"]]
        assert "api-org-011" in org_ids
