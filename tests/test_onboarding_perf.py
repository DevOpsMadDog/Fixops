"""Performance assertions for OnboardingManager.

Validates that the three hotfixes ship measurable improvements:
  - hotfix #1/#2: WAL + thread-local connection cache
  - hotfix #3: single connection for read+write in complete_step/skip_step
  - hotfix #4: batched step_configs fetch in get_checklist (was N+1)
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.perf

import time
from pathlib import Path

import pytest

from core.onboarding import OnboardingManager, OnboardingStep


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _manager(tmp_path: Path) -> OnboardingManager:
    return OnboardingManager(db_path=tmp_path / "onboarding_perf.db")


def _complete_through(mgr: OnboardingManager, org_id: str, steps_data: list) -> None:
    """Drive an org through a sequence of (step, config_data) pairs."""
    for step, config in steps_data:
        mgr.complete_step(org_id, step, config)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_start_onboarding_repeated_is_fast(tmp_path: Path) -> None:
    """Repeated idempotent start_onboarding must complete 100 calls under 500 ms."""
    mgr = _manager(tmp_path)
    mgr.start_onboarding("org-perf-1")

    start = time.perf_counter()
    for _ in range(100):
        mgr.start_onboarding("org-perf-1")
    elapsed_ms = (time.perf_counter() - start) * 1000

    assert elapsed_ms < 500, f"100 idempotent start calls took {elapsed_ms:.1f}ms (limit 500ms)"


def test_complete_step_single_connection(tmp_path: Path) -> None:
    """complete_step for a single step must finish under 50 ms (was two DB opens)."""
    mgr = _manager(tmp_path)
    mgr.start_onboarding("org-perf-2")

    start = time.perf_counter()
    mgr.complete_step(
        "org-perf-2",
        OnboardingStep.CONFIGURE_AUTH,
        {"api_key": "k1"},
    )
    elapsed_ms = (time.perf_counter() - start) * 1000

    assert elapsed_ms < 50, f"complete_step took {elapsed_ms:.1f}ms (limit 50ms)"


def test_get_checklist_batched(tmp_path: Path) -> None:
    """get_checklist must complete under 30 ms regardless of how many steps have configs.

    Before hotfix #4 this issued N separate _connect() calls inside the loop.
    """
    mgr = _manager(tmp_path)
    mgr.start_onboarding("org-perf-3")
    # Store configs for several steps so the batch query has real rows to return.
    mgr.complete_step("org-perf-3", OnboardingStep.CONFIGURE_AUTH, {"api_key": "k"})
    mgr.complete_step("org-perf-3", OnboardingStep.CONNECT_SCANNERS, {"scanners": ["snyk"]})

    start = time.perf_counter()
    checklist = mgr.get_checklist("org-perf-3")
    elapsed_ms = (time.perf_counter() - start) * 1000

    assert elapsed_ms < 30, f"get_checklist took {elapsed_ms:.1f}ms (limit 30ms)"
    assert checklist["onboarding_started"] is True
    assert len(checklist["items"]) == 9  # STEP_ORDER has 9 entries


def test_get_checklist_configs_batched_correctly(tmp_path: Path) -> None:
    """Verify the batched config fetch returns the same data as the old per-step path."""
    mgr = _manager(tmp_path)
    mgr.start_onboarding("org-perf-4")
    mgr.complete_step("org-perf-4", OnboardingStep.CONFIGURE_AUTH, {"api_key": "abc", "sso_enabled": True})
    mgr.complete_step("org-perf-4", OnboardingStep.CONNECT_SCANNERS, {"scanners": ["trivy", "snyk"]})

    checklist = mgr.get_checklist("org-perf-4")
    items_by_step = {i["step"]: i for i in checklist["items"]}

    auth_item = items_by_step[OnboardingStep.CONFIGURE_AUTH.value]
    assert auth_item["has_config"] is True
    assert set(auth_item["config_keys"]) == {"api_key", "sso_enabled"}

    scanner_item = items_by_step[OnboardingStep.CONNECT_SCANNERS.value]
    assert scanner_item["has_config"] is True
    assert "scanners" in scanner_item["config_keys"]

    pending_item = items_by_step[OnboardingStep.CONNECT_TICKETING.value]
    assert pending_item["has_config"] is False
    assert pending_item["config_keys"] == []


def test_full_onboarding_flow_perf(tmp_path: Path) -> None:
    """End-to-end wizard completion (all non-skipped steps) must finish under 200 ms."""
    mgr = _manager(tmp_path)
    mgr.start_onboarding("org-perf-5")

    # WELCOME has no validation — skip it to mark terminal, then complete the rest.
    mgr.skip_step("org-perf-5", OnboardingStep.WELCOME)

    steps_data = [
        (OnboardingStep.CONFIGURE_AUTH, {"api_key": "k"}),
        (OnboardingStep.CONNECT_SCANNERS, {"scanners": ["trivy"]}),
        (OnboardingStep.CONNECT_TICKETING, {"connectors": ["jira"]}),
        (OnboardingStep.SELECT_FRAMEWORKS, {"frameworks": ["SOC2"]}),
        (OnboardingStep.DEFINE_ROLES, {"users": [{"role": "admin", "email": "a@b.com"}]}),
        (OnboardingStep.RUN_FIRST_SCAN, {"scan_triggered": True}),
        (OnboardingStep.REVIEW_RESULTS, {"first_scan_completed": True}),
    ]

    start = time.perf_counter()
    _complete_through(mgr, "org-perf-5", steps_data)
    elapsed_ms = (time.perf_counter() - start) * 1000

    assert elapsed_ms < 200, f"Full onboarding flow took {elapsed_ms:.1f}ms (limit 200ms)"

    progress = mgr.get_progress("org-perf-5")
    assert progress.completion_percentage == 100.0
