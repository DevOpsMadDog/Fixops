"""Tests for the Risk Register engine.

Coverage (50+ tests):
- RiskCategory, RiskStatus, TreatmentAction, KRIStatus enums
- Pydantic models: Risk, RiskControl, RiskTreatmentPlan, KRIRecord, RiskAppetite
- RiskRegister: create, get, update, delete, list risks
- RiskRegister: control CRUD and mapping/unmapping
- RiskRegister: treatment plan lifecycle
- RiskRegister: KRI create, value update, status transitions
- RiskRegister: risk appetite set and list
- RiskRegister: heat map generation
- RiskRegister: board report generation
- Score computation helpers
- API router endpoints via FastAPI TestClient
"""
from __future__ import annotations

import sys
import os
from datetime import datetime, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-api"))

from core.risk_register import (
    KRIRecord,
    KRIStatus,
    Risk,
    RiskAppetite,
    RiskCategory,
    RiskControl,
    RiskRegister,
    RiskStatus,
    RiskTreatmentPlan,
    TreatmentAction,
    _evaluate_kri_status,
    _score_label,
    _trend_direction,
    get_risk_register,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_register() -> RiskRegister:
    """Fresh in-memory register per test."""
    return RiskRegister(db_path=":memory:")


def _make_risk(
    title: str = "Test Risk",
    category: RiskCategory = RiskCategory.TECHNICAL,
    likelihood: int = 3,
    impact: int = 3,
    org_id: str = "org-test",
) -> Risk:
    return Risk(
        title=title,
        category=category,
        likelihood=likelihood,
        impact=impact,
        org_id=org_id,
    )


def _make_control(
    name: str = "Test Control",
    effectiveness: float = 2.0,
    implemented: bool = True,
    org_id: str = "org-test",
) -> RiskControl:
    return RiskControl(
        name=name,
        effectiveness=effectiveness,
        implemented=implemented,
        org_id=org_id,
    )


# ---------------------------------------------------------------------------
# Enum tests
# ---------------------------------------------------------------------------

class TestEnums:
    def test_risk_categories(self):
        assert RiskCategory.OPERATIONAL.value == "operational"
        assert RiskCategory.COMPLIANCE.value == "compliance"
        assert RiskCategory.TECHNICAL.value == "technical"
        assert RiskCategory.STRATEGIC.value == "strategic"
        assert RiskCategory.REPUTATIONAL.value == "reputational"

    def test_risk_status(self):
        assert RiskStatus.OPEN.value == "open"
        assert RiskStatus.IN_TREATMENT.value == "in_treatment"
        assert RiskStatus.ACCEPTED.value == "accepted"
        assert RiskStatus.CLOSED.value == "closed"
        assert RiskStatus.TRANSFERRED.value == "transferred"

    def test_treatment_action(self):
        assert TreatmentAction.ACCEPT.value == "accept"
        assert TreatmentAction.MITIGATE.value == "mitigate"
        assert TreatmentAction.TRANSFER.value == "transfer"
        assert TreatmentAction.AVOID.value == "avoid"

    def test_kri_status(self):
        assert KRIStatus.NORMAL.value == "normal"
        assert KRIStatus.WARNING.value == "warning"
        assert KRIStatus.BREACH.value == "breach"


# ---------------------------------------------------------------------------
# Helper function tests
# ---------------------------------------------------------------------------

class TestHelpers:
    def test_score_label_critical(self):
        assert _score_label(20.0) == "critical"
        assert _score_label(25.0) == "critical"

    def test_score_label_high(self):
        assert _score_label(15.0) == "high"
        assert _score_label(19.9) == "high"

    def test_score_label_medium(self):
        assert _score_label(8.0) == "medium"
        assert _score_label(14.9) == "medium"

    def test_score_label_low(self):
        assert _score_label(4.0) == "low"
        assert _score_label(7.9) == "low"

    def test_score_label_very_low(self):
        assert _score_label(1.0) == "very_low"
        assert _score_label(3.9) == "very_low"

    def test_trend_direction_increasing(self):
        assert _trend_direction([3.0, 5.0, 8.0]) == "increasing"

    def test_trend_direction_decreasing(self):
        assert _trend_direction([10.0, 7.0, 4.0]) == "decreasing"

    def test_trend_direction_stable(self):
        assert _trend_direction([5.0, 5.5, 5.0]) == "stable"

    def test_trend_direction_single(self):
        assert _trend_direction([5.0]) == "stable"

    def test_trend_direction_empty(self):
        assert _trend_direction([]) == "stable"

    def test_evaluate_kri_status_higher_is_worse_normal(self):
        assert _evaluate_kri_status(5.0, 10.0, 20.0, "higher_is_worse") == KRIStatus.NORMAL

    def test_evaluate_kri_status_higher_is_worse_warning(self):
        assert _evaluate_kri_status(12.0, 10.0, 20.0, "higher_is_worse") == KRIStatus.WARNING

    def test_evaluate_kri_status_higher_is_worse_breach(self):
        assert _evaluate_kri_status(21.0, 10.0, 20.0, "higher_is_worse") == KRIStatus.BREACH

    def test_evaluate_kri_status_lower_is_worse_normal(self):
        assert _evaluate_kri_status(90.0, 50.0, 20.0, "lower_is_worse") == KRIStatus.NORMAL

    def test_evaluate_kri_status_lower_is_worse_warning(self):
        assert _evaluate_kri_status(40.0, 50.0, 20.0, "lower_is_worse") == KRIStatus.WARNING

    def test_evaluate_kri_status_lower_is_worse_breach(self):
        assert _evaluate_kri_status(10.0, 50.0, 20.0, "lower_is_worse") == KRIStatus.BREACH


# ---------------------------------------------------------------------------
# Risk model tests
# ---------------------------------------------------------------------------

class TestRiskModel:
    def test_inherent_score_computed(self):
        risk = _make_risk(likelihood=4, impact=5)
        assert risk.inherent_risk_score == 20.0

    def test_residual_defaults_to_inherent(self):
        risk = _make_risk(likelihood=3, impact=3)
        assert risk.residual_risk_score == 9.0

    def test_risk_id_auto_generated(self):
        risk = _make_risk()
        assert risk.id.startswith("risk-")

    def test_risk_default_status(self):
        risk = _make_risk()
        assert risk.status == RiskStatus.OPEN

    def test_risk_tags_default_empty(self):
        risk = _make_risk()
        assert risk.tags == []


# ---------------------------------------------------------------------------
# RiskRegister — CRUD tests
# ---------------------------------------------------------------------------

class TestRiskCRUD:
    def test_create_risk(self):
        reg = _make_register()
        risk = reg.create_risk(_make_risk())
        assert risk.id.startswith("risk-")
        assert risk.inherent_risk_score == 9.0

    def test_get_risk_exists(self):
        reg = _make_register()
        created = reg.create_risk(_make_risk())
        fetched = reg.get_risk(created.id)
        assert fetched is not None
        assert fetched.id == created.id

    def test_get_risk_not_found(self):
        reg = _make_register()
        assert reg.get_risk("nonexistent-id") is None

    def test_update_risk_title(self):
        reg = _make_register()
        risk = reg.create_risk(_make_risk())
        updated = reg.update_risk(risk.id, {"title": "Updated Title"})
        assert updated is not None
        assert updated.title == "Updated Title"

    def test_update_risk_scores_recomputed(self):
        reg = _make_register()
        risk = reg.create_risk(_make_risk(likelihood=2, impact=2))
        assert risk.inherent_risk_score == 4.0
        updated = reg.update_risk(risk.id, {"likelihood": 5, "impact": 5})
        assert updated.inherent_risk_score == 25.0

    def test_update_risk_history_tracked(self):
        reg = _make_register()
        risk = reg.create_risk(_make_risk(likelihood=2, impact=2))
        reg.update_risk(risk.id, {"likelihood": 3, "impact": 3})
        updated = reg.get_risk(risk.id)
        assert len(updated.score_history) >= 2

    def test_update_risk_not_found(self):
        reg = _make_register()
        assert reg.update_risk("bad-id", {"title": "X"}) is None

    def test_delete_risk_success(self):
        reg = _make_register()
        risk = reg.create_risk(_make_risk())
        assert reg.delete_risk(risk.id) is True
        assert reg.get_risk(risk.id) is None

    def test_delete_risk_not_found(self):
        reg = _make_register()
        assert reg.delete_risk("nonexistent") is False

    def test_list_risks_by_org(self):
        reg = _make_register()
        r1 = _make_risk(org_id="org-a")
        r2 = _make_risk(org_id="org-b")
        reg.create_risk(r1)
        reg.create_risk(r2)
        result = reg.list_risks("org-a")
        assert len(result) == 1
        assert result[0].org_id == "org-a"

    def test_list_risks_by_category(self):
        reg = _make_register()
        reg.create_risk(_make_risk(category=RiskCategory.TECHNICAL))
        reg.create_risk(_make_risk(category=RiskCategory.COMPLIANCE))
        result = reg.list_risks("org-test", category="technical")
        assert all(r.category == RiskCategory.TECHNICAL for r in result)

    def test_list_risks_by_status(self):
        reg = _make_register()
        risk = _make_risk()
        risk.status = RiskStatus.CLOSED
        reg.create_risk(risk)
        reg.create_risk(_make_risk())
        result = reg.list_risks("org-test", status="open")
        assert all(r.status == RiskStatus.OPEN for r in result)

    def test_list_risks_min_score(self):
        reg = _make_register()
        reg.create_risk(_make_risk(likelihood=1, impact=1))  # score=1
        reg.create_risk(_make_risk(likelihood=5, impact=5))  # score=25
        result = reg.list_risks("org-test", min_score=10.0)
        assert all(r.residual_risk_score >= 10.0 for r in result)


# ---------------------------------------------------------------------------
# Control CRUD and mapping tests
# ---------------------------------------------------------------------------

class TestControlMapping:
    def test_create_control(self):
        reg = _make_register()
        ctrl = reg.create_control(_make_control())
        assert ctrl.id.startswith("ctrl-")

    def test_get_control(self):
        reg = _make_register()
        ctrl = reg.create_control(_make_control())
        fetched = reg.get_control(ctrl.id)
        assert fetched is not None
        assert fetched.name == ctrl.name

    def test_list_controls_by_org(self):
        reg = _make_register()
        reg.create_control(_make_control(org_id="org-a"))
        reg.create_control(_make_control(org_id="org-b"))
        assert len(reg.list_controls("org-a")) == 1

    def test_delete_control(self):
        reg = _make_register()
        ctrl = reg.create_control(_make_control())
        assert reg.delete_control(ctrl.id) is True
        assert reg.get_control(ctrl.id) is None

    def test_map_control_reduces_residual(self):
        reg = _make_register()
        risk = reg.create_risk(_make_risk(likelihood=4, impact=4))  # inherent=16
        ctrl = reg.create_control(_make_control(effectiveness=3.0, implemented=True))
        updated = reg.map_control_to_risk(risk.id, ctrl.id)
        assert updated is not None
        assert updated.residual_risk_score == 13.0

    def test_map_control_not_implemented_no_reduction(self):
        reg = _make_register()
        risk = reg.create_risk(_make_risk(likelihood=3, impact=3))  # inherent=9
        ctrl = reg.create_control(_make_control(effectiveness=3.0, implemented=False))
        updated = reg.map_control_to_risk(risk.id, ctrl.id)
        assert updated.residual_risk_score == 9.0

    def test_map_control_twice_no_duplicate(self):
        reg = _make_register()
        risk = reg.create_risk(_make_risk(likelihood=4, impact=4))
        ctrl = reg.create_control(_make_control(effectiveness=3.0, implemented=True))
        reg.map_control_to_risk(risk.id, ctrl.id)
        updated = reg.map_control_to_risk(risk.id, ctrl.id)
        assert updated.control_ids.count(ctrl.id) == 1

    def test_unmap_control_restores_residual(self):
        reg = _make_register()
        risk = reg.create_risk(_make_risk(likelihood=4, impact=4))  # inherent=16
        ctrl = reg.create_control(_make_control(effectiveness=4.0, implemented=True))
        reg.map_control_to_risk(risk.id, ctrl.id)
        unmapped = reg.unmap_control_from_risk(risk.id, ctrl.id)
        assert unmapped.residual_risk_score == 16.0

    def test_residual_floor_zero(self):
        reg = _make_register()
        risk = reg.create_risk(_make_risk(likelihood=1, impact=1))  # inherent=1
        ctrl = reg.create_control(_make_control(effectiveness=5.0, implemented=True))
        updated = reg.map_control_to_risk(risk.id, ctrl.id)
        assert updated.residual_risk_score == 0.0


# ---------------------------------------------------------------------------
# Treatment plan tests
# ---------------------------------------------------------------------------

class TestTreatmentPlans:
    def test_create_treatment(self):
        reg = _make_register()
        risk = reg.create_risk(_make_risk())
        plan = RiskTreatmentPlan(
            risk_id=risk.id,
            action=TreatmentAction.MITIGATE,
            description="Deploy WAF",
        )
        created = reg.create_treatment(plan)
        assert created.id.startswith("treat-")

    def test_treatment_sets_risk_in_treatment(self):
        reg = _make_register()
        risk = reg.create_risk(_make_risk())
        plan = RiskTreatmentPlan(
            risk_id=risk.id,
            action=TreatmentAction.MITIGATE,
            description="Deploy WAF",
        )
        reg.create_treatment(plan)
        updated_risk = reg.get_risk(risk.id)
        assert updated_risk.status == RiskStatus.IN_TREATMENT

    def test_list_treatments(self):
        reg = _make_register()
        risk = reg.create_risk(_make_risk())
        for action in [TreatmentAction.MITIGATE, TreatmentAction.ACCEPT]:
            reg.create_treatment(RiskTreatmentPlan(
                risk_id=risk.id, action=action, description="test"
            ))
        assert len(reg.list_treatments(risk.id)) == 2

    def test_update_treatment_status(self):
        reg = _make_register()
        risk = reg.create_risk(_make_risk())
        plan = reg.create_treatment(RiskTreatmentPlan(
            risk_id=risk.id, action=TreatmentAction.AVOID, description="Decommission"
        ))
        updated = reg.update_treatment_status(plan.id, "completed")
        assert updated.status == "completed"
        assert updated.completion_date != ""

    def test_update_treatment_not_found(self):
        reg = _make_register()
        assert reg.update_treatment_status("bad-id", "completed") is None


# ---------------------------------------------------------------------------
# KRI tests
# ---------------------------------------------------------------------------

class TestKRITracking:
    def _make_kri(self, risk_id: str, value: float = 5.0) -> KRIRecord:
        return KRIRecord(
            risk_id=risk_id,
            name="Failed Login Rate",
            unit="%",
            current_value=value,
            warning_threshold=10.0,
            breach_threshold=25.0,
            direction="higher_is_worse",
            org_id="org-test",
        )

    def test_create_kri_normal(self):
        reg = _make_register()
        risk = reg.create_risk(_make_risk())
        kri = reg.create_kri(self._make_kri(risk.id, value=5.0))
        assert kri.status == KRIStatus.NORMAL

    def test_create_kri_warning(self):
        reg = _make_register()
        risk = reg.create_risk(_make_risk())
        kri = reg.create_kri(self._make_kri(risk.id, value=15.0))
        assert kri.status == KRIStatus.WARNING

    def test_create_kri_breach(self):
        reg = _make_register()
        risk = reg.create_risk(_make_risk())
        kri = reg.create_kri(self._make_kri(risk.id, value=30.0))
        assert kri.status == KRIStatus.BREACH

    def test_update_kri_value_to_warning(self):
        reg = _make_register()
        risk = reg.create_risk(_make_risk())
        kri = reg.create_kri(self._make_kri(risk.id, value=5.0))
        updated = reg.update_kri_value(kri.id, 15.0)
        assert updated.status == KRIStatus.WARNING
        assert updated.current_value == 15.0

    def test_update_kri_value_to_breach(self):
        reg = _make_register()
        risk = reg.create_risk(_make_risk())
        kri = reg.create_kri(self._make_kri(risk.id, value=5.0))
        updated = reg.update_kri_value(kri.id, 30.0)
        assert updated.status == KRIStatus.BREACH

    def test_update_kri_value_recovers_to_normal(self):
        reg = _make_register()
        risk = reg.create_risk(_make_risk())
        kri = reg.create_kri(self._make_kri(risk.id, value=30.0))
        updated = reg.update_kri_value(kri.id, 3.0)
        assert updated.status == KRIStatus.NORMAL

    def test_update_kri_not_found(self):
        reg = _make_register()
        assert reg.update_kri_value("bad-id", 99.0) is None

    def test_list_kris_by_status(self):
        reg = _make_register()
        risk = reg.create_risk(_make_risk())
        reg.create_kri(self._make_kri(risk.id, value=5.0))   # normal
        reg.create_kri(self._make_kri(risk.id, value=30.0))  # breach
        breaches = reg.list_kris("org-test", status="breach")
        assert len(breaches) == 1
        assert breaches[0].status == KRIStatus.BREACH


# ---------------------------------------------------------------------------
# Risk appetite tests
# ---------------------------------------------------------------------------

class TestRiskAppetite:
    def test_set_appetite(self):
        reg = _make_register()
        ap = RiskAppetite(
            org_id="org-test",
            category=RiskCategory.TECHNICAL,
            appetite_score=8.0,
            tolerance_score=15.0,
        )
        created = reg.set_appetite(ap)
        assert created.id.startswith("rapp-")

    def test_get_appetite(self):
        reg = _make_register()
        ap = RiskAppetite(
            org_id="org-test",
            category=RiskCategory.COMPLIANCE,
            appetite_score=5.0,
            tolerance_score=12.0,
        )
        reg.set_appetite(ap)
        fetched = reg.get_appetite("org-test", "compliance")
        assert fetched is not None
        assert fetched.appetite_score == 5.0

    def test_list_appetites(self):
        reg = _make_register()
        for cat in [RiskCategory.TECHNICAL, RiskCategory.COMPLIANCE]:
            reg.set_appetite(RiskAppetite(
                org_id="org-test", category=cat,
                appetite_score=8.0, tolerance_score=15.0,
            ))
        assert len(reg.list_appetites("org-test")) == 2

    def test_appetite_upsert_overwrites(self):
        reg = _make_register()
        ap = RiskAppetite(org_id="org-test", category=RiskCategory.STRATEGIC,
                          appetite_score=8.0, tolerance_score=15.0)
        reg.set_appetite(ap)
        ap2 = RiskAppetite(org_id="org-test", category=RiskCategory.STRATEGIC,
                           appetite_score=5.0, tolerance_score=10.0)
        reg.set_appetite(ap2)
        fetched = reg.get_appetite("org-test", "strategic")
        assert fetched.appetite_score == 5.0


# ---------------------------------------------------------------------------
# Heat map tests
# ---------------------------------------------------------------------------

class TestHeatMap:
    def test_heat_map_size(self):
        reg = _make_register()
        cells = reg.get_heat_map("org-test")
        assert len(cells) == 25  # 5×5 grid

    def test_heat_map_empty_register(self):
        reg = _make_register()
        cells = reg.get_heat_map("org-test")
        assert all(c.risk_count == 0 for c in cells)

    def test_heat_map_populated(self):
        reg = _make_register()
        risk = _make_risk(likelihood=4, impact=5)
        reg.create_risk(risk)
        cells = reg.get_heat_map("org-test")
        target = next(c for c in cells if c.likelihood == 4 and c.impact == 5)
        assert target.risk_count == 1
        assert target.score == 20

    def test_heat_map_scores(self):
        reg = _make_register()
        cells = reg.get_heat_map("org-test")
        for cell in cells:
            assert cell.score == cell.likelihood * cell.impact


# ---------------------------------------------------------------------------
# Board report tests
# ---------------------------------------------------------------------------

class TestBoardReport:
    def test_board_report_empty(self):
        reg = _make_register()
        report = reg.get_board_report("org-test")
        assert report.total_risks == 0
        assert report.open_risks == 0
        assert report.top_10_risks == []

    def test_board_report_counts(self):
        reg = _make_register()
        for _ in range(3):
            reg.create_risk(_make_risk())
        report = reg.get_board_report("org-test")
        assert report.total_risks == 3
        assert report.open_risks == 3

    def test_board_report_top10_limit(self):
        reg = _make_register()
        for i in range(12):
            reg.create_risk(_make_risk(likelihood=i % 5 + 1, impact=i % 5 + 1))
        report = reg.get_board_report("org-test")
        assert len(report.top_10_risks) <= 10

    def test_board_report_above_appetite(self):
        reg = _make_register()
        reg.set_appetite(RiskAppetite(
            org_id="org-test", category=RiskCategory.TECHNICAL,
            appetite_score=4.0, tolerance_score=12.0,
        ))
        # risk score 9 > appetite 4 but < tolerance 12 => above_appetite
        reg.create_risk(_make_risk(likelihood=3, impact=3))
        report = reg.get_board_report("org-test")
        assert report.risks_above_appetite == 1
        assert report.risks_above_tolerance == 0

    def test_board_report_above_tolerance(self):
        reg = _make_register()
        reg.set_appetite(RiskAppetite(
            org_id="org-test", category=RiskCategory.TECHNICAL,
            appetite_score=4.0, tolerance_score=8.0,
        ))
        # risk score 25 > tolerance 8
        reg.create_risk(_make_risk(likelihood=5, impact=5))
        report = reg.get_board_report("org-test")
        assert report.risks_above_tolerance == 1

    def test_board_report_kri_alerts(self):
        reg = _make_register()
        risk = reg.create_risk(_make_risk())
        kri = KRIRecord(
            risk_id=risk.id, name="Test KRI", unit="%",
            current_value=30.0, warning_threshold=10.0, breach_threshold=20.0,
            direction="higher_is_worse", org_id="org-test",
        )
        reg.create_kri(kri)
        report = reg.get_board_report("org-test")
        assert len(report.kri_alerts) == 1
        assert report.kri_alerts[0]["status"] == "breach"

    def test_board_report_category_summary(self):
        reg = _make_register()
        reg.create_risk(_make_risk(category=RiskCategory.TECHNICAL))
        reg.create_risk(_make_risk(category=RiskCategory.COMPLIANCE))
        report = reg.get_board_report("org-test")
        assert report.category_summary["technical"]["total"] == 1
        assert report.category_summary["compliance"]["total"] == 1

    def test_board_report_generated_at_format(self):
        reg = _make_register()
        report = reg.get_board_report("org-test")
        # Should parse as ISO datetime without error
        datetime.fromisoformat(report.generated_at)


# ---------------------------------------------------------------------------
# API router tests
# ---------------------------------------------------------------------------

class TestRiskRegisterRouter:
    @pytest.fixture(autouse=True)
    def _setup(self):
        """Patch the singleton so each test gets a clean in-memory register."""
        import core.risk_register as rr_mod
        original = rr_mod._instance
        rr_mod._instance = RiskRegister(db_path=":memory:")
        yield
        rr_mod._instance = original

    @pytest.fixture
    def client(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from apps.api.risk_register_router import router

        app = FastAPI()
        app.include_router(router)
        return TestClient(app)

    def test_create_risk_endpoint(self, client):
        resp = client.post("/api/v1/risks", json={
            "title": "API Test Risk",
            "category": "technical",
            "likelihood": 3,
            "impact": 4,
        })
        assert resp.status_code == 200
        data = resp.json()
        assert data["title"] == "API Test Risk"
        assert data["inherent_risk_score"] == 12.0

    def test_list_risks_endpoint(self, client):
        client.post("/api/v1/risks", json={"title": "R1", "category": "technical"})
        client.post("/api/v1/risks", json={"title": "R2", "category": "compliance"})
        resp = client.get("/api/v1/risks?org_id=default")
        assert resp.status_code == 200
        assert len(resp.json()) == 2

    def test_get_risk_endpoint(self, client):
        create_resp = client.post("/api/v1/risks", json={
            "title": "Fetch Me", "category": "strategic",
        })
        risk_id = create_resp.json()["id"]
        resp = client.get(f"/api/v1/risks/{risk_id}")
        assert resp.status_code == 200
        assert resp.json()["id"] == risk_id

    def test_get_risk_not_found(self, client):
        resp = client.get("/api/v1/risks/bad-id")
        assert resp.status_code == 404

    def test_update_risk_endpoint(self, client):
        create_resp = client.post("/api/v1/risks", json={
            "title": "Old Title", "category": "operational",
        })
        risk_id = create_resp.json()["id"]
        resp = client.patch(f"/api/v1/risks/{risk_id}", json={"title": "New Title"})
        assert resp.status_code == 200
        assert resp.json()["title"] == "New Title"

    def test_delete_risk_endpoint(self, client):
        create_resp = client.post("/api/v1/risks", json={
            "title": "Delete Me", "category": "technical",
        })
        risk_id = create_resp.json()["id"]
        resp = client.delete(f"/api/v1/risks/{risk_id}")
        assert resp.status_code == 200
        assert resp.json()["deleted"] is True

    def test_create_control_endpoint(self, client):
        resp = client.post("/api/v1/risks/controls", json={
            "name": "WAF Rule",
            "effectiveness": 3.0,
            "implemented": True,
        })
        assert resp.status_code == 200
        assert resp.json()["name"] == "WAF Rule"

    def test_list_controls_endpoint(self, client):
        client.post("/api/v1/risks/controls", json={"name": "C1", "effectiveness": 1.0})
        resp = client.get("/api/v1/risks/controls/list?org_id=default")
        assert resp.status_code == 200
        assert len(resp.json()) >= 1

    def test_map_control_endpoint(self, client):
        risk_resp = client.post("/api/v1/risks", json={
            "title": "Mappable Risk", "category": "technical",
            "likelihood": 4, "impact": 4,
        })
        ctrl_resp = client.post("/api/v1/risks/controls", json={
            "name": "IDS", "effectiveness": 3.0, "implemented": True,
        })
        risk_id = risk_resp.json()["id"]
        ctrl_id = ctrl_resp.json()["id"]
        resp = client.post(f"/api/v1/risks/{risk_id}/controls/map",
                           json={"ctrl_id": ctrl_id})
        assert resp.status_code == 200
        assert resp.json()["residual_risk_score"] == 13.0

    def test_create_treatment_endpoint(self, client):
        risk_resp = client.post("/api/v1/risks", json={
            "title": "Risk to Treat", "category": "compliance",
        })
        risk_id = risk_resp.json()["id"]
        resp = client.post("/api/v1/risks/treatments", json={
            "risk_id": risk_id,
            "action": "mitigate",
            "description": "Apply patches",
        })
        assert resp.status_code == 200
        assert resp.json()["action"] == "mitigate"

    def test_create_kri_endpoint(self, client):
        risk_resp = client.post("/api/v1/risks", json={
            "title": "KRI Risk", "category": "operational",
        })
        risk_id = risk_resp.json()["id"]
        resp = client.post("/api/v1/risks/kris", json={
            "risk_id": risk_id,
            "name": "Patch Lag",
            "current_value": 5.0,
            "warning_threshold": 10.0,
            "breach_threshold": 20.0,
        })
        assert resp.status_code == 200
        assert resp.json()["status"] == "normal"

    def test_update_kri_value_endpoint(self, client):
        risk_resp = client.post("/api/v1/risks", json={
            "title": "KRI Risk 2", "category": "operational",
        })
        risk_id = risk_resp.json()["id"]
        kri_resp = client.post("/api/v1/risks/kris", json={
            "risk_id": risk_id, "name": "KRI",
            "current_value": 5.0,
            "warning_threshold": 10.0,
            "breach_threshold": 20.0,
        })
        kri_id = kri_resp.json()["id"]
        resp = client.patch(f"/api/v1/risks/kris/{kri_id}/value",
                            json={"current_value": 25.0})
        assert resp.status_code == 200
        assert resp.json()["status"] == "breach"

    def test_set_appetite_endpoint(self, client):
        resp = client.post("/api/v1/risks/appetite", json={
            "category": "technical",
            "appetite_score": 8.0,
            "tolerance_score": 15.0,
        })
        assert resp.status_code == 200
        assert resp.json()["appetite_score"] == 8.0

    def test_heat_map_endpoint(self, client):
        resp = client.get("/api/v1/risks/heatmap?org_id=default")
        assert resp.status_code == 200
        assert len(resp.json()) == 25

    def test_board_report_endpoint(self, client):
        client.post("/api/v1/risks", json={"title": "R1", "category": "technical"})
        resp = client.get("/api/v1/risks/report/board?org_id=default")
        assert resp.status_code == 200
        data = resp.json()
        assert "total_risks" in data
        assert "top_10_risks" in data
        assert "kri_alerts" in data
