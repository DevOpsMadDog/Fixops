"""
Vendor Risk Management (VRM) Engine Tests — ALDECI.

Covers:
- Vendor Registry CRUD (5 tests)
- Vendor Tiering logic (8 tests)
- Questionnaire scoring (8 tests)
- Continuous monitoring (7 tests)
- Fourth-party risk propagation (6 tests)
- Contract risk detection (6 tests)
- Vendor Scorecard calculation (6 tests)
- SIG questionnaire completeness (4 tests)
- Router endpoint smoke tests (5 tests via FastAPI TestClient)

Total: 55 tests
"""

from __future__ import annotations

import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List

import pytest

sys.path.insert(0, "suite-core")
sys.path.insert(0, "suite-api")

from core.vendor_risk import (
    AssessmentQuestion,
    CertificationRecord,
    ComplianceCert,
    ContractRisk,
    ContractRiskType,
    DataAccessLevel,
    FourthPartyRisk,
    QuestionCategory,
    QuestionnaireResponse,
    RiskSignal,
    RiskSignalSeverity,
    RiskSignalType,
    ServiceCategory,
    SLATerms,
    Vendor,
    VendorAssessment,
    VendorContact,
    VendorRiskEngine,
    VendorTier,
    _build_questionnaire,
    _compute_tier,
    _QUESTIONNAIRE,
    _QUESTION_MAP,
    _compute_monitoring_score,
    _compute_contract_score,
    _analyze_contract_risks,
    _score_to_grade,
)


# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def temp_db():
    """Isolated SQLite DB for each test."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
        db_path = f.name
    yield db_path
    Path(db_path).unlink(missing_ok=True)


@pytest.fixture
def engine(temp_db):
    """Fresh VendorRiskEngine per test."""
    return VendorRiskEngine(db_path=temp_db)


def _make_vendor(
    name: str = "Acme Corp",
    data_access_level: DataAccessLevel = DataAccessLevel.CONFIDENTIAL,
    is_core_operations: bool = True,
    service_category: ServiceCategory = ServiceCategory.CLOUD_INFRASTRUCTURE,
    sla_terms: SLATerms | None = None,
    certifications: list | None = None,
    fourth_party_vendors: list | None = None,
) -> Vendor:
    return Vendor(
        name=name,
        service_category=service_category,
        data_access_level=data_access_level,
        is_core_operations=is_core_operations,
        contract_start="2024-01-01",
        contract_end="2025-12-31",
        sla_terms=sla_terms or SLATerms(),
        certifications=certifications or [],
        fourth_party_vendors=fourth_party_vendors or [],
    )


def _make_cert(
    cert: ComplianceCert = ComplianceCert.SOC2_TYPE2,
    expired: bool = False,
) -> CertificationRecord:
    now = datetime.now(timezone.utc)
    if expired:
        issued = (now - timedelta(days=400)).strftime("%Y-%m-%d")
        expiry = (now - timedelta(days=30)).strftime("%Y-%m-%d")
    else:
        issued = (now - timedelta(days=30)).strftime("%Y-%m-%d")
        expiry = (now + timedelta(days=335)).strftime("%Y-%m-%d")
    return CertificationRecord(cert=cert, issued_date=issued, expiry_date=expiry)


def _all_yes_responses() -> List[QuestionnaireResponse]:
    """Return 'Yes' to every question in the questionnaire."""
    return [QuestionnaireResponse(question_id=q.id, answer=True) for q in _QUESTIONNAIRE]


def _all_no_responses() -> List[QuestionnaireResponse]:
    """Return 'No' to every question."""
    return [QuestionnaireResponse(question_id=q.id, answer=False) for q in _QUESTIONNAIRE]


# ============================================================================
# VENDOR REGISTRY TESTS (5 tests)
# ============================================================================


class TestVendorRegistry:
    def test_register_vendor_assigns_id(self, engine):
        vendor = _make_vendor()
        registered = engine.register_vendor(vendor)
        assert registered.id.startswith("vnd-")
        assert len(registered.id) > 4

    def test_register_vendor_computes_tier(self, engine):
        vendor = _make_vendor(
            data_access_level=DataAccessLevel.RESTRICTED,
            is_core_operations=True,
        )
        registered = engine.register_vendor(vendor)
        assert registered.tier == VendorTier.CRITICAL

    def test_get_vendor_returns_registered(self, engine):
        vendor = _make_vendor(name="CloudProv Inc")
        registered = engine.register_vendor(vendor)
        fetched = engine.get_vendor(registered.id)
        assert fetched is not None
        assert fetched.name == "CloudProv Inc"

    def test_get_vendor_returns_none_for_unknown_id(self, engine):
        result = engine.get_vendor("vnd-doesnotexist")
        assert result is None

    def test_list_vendors_returns_all(self, engine):
        v1 = engine.register_vendor(_make_vendor(name="Vendor A"))
        v2 = engine.register_vendor(_make_vendor(name="Vendor B"))
        vendors = engine.list_vendors()
        names = [v.name for v in vendors]
        assert "Vendor A" in names
        assert "Vendor B" in names
        assert len(vendors) >= 2


# ============================================================================
# VENDOR TIERING TESTS (8 tests)
# ============================================================================


class TestVendorTiering:
    def test_tier_critical_sensitive_and_core(self):
        v = _make_vendor(data_access_level=DataAccessLevel.RESTRICTED, is_core_operations=True)
        assert _compute_tier(v) == VendorTier.CRITICAL

    def test_tier_critical_secret_and_core(self):
        v = _make_vendor(data_access_level=DataAccessLevel.SECRET, is_core_operations=True)
        assert _compute_tier(v) == VendorTier.CRITICAL

    def test_tier_high_sensitive_not_core(self):
        v = _make_vendor(data_access_level=DataAccessLevel.CONFIDENTIAL, is_core_operations=False)
        assert _compute_tier(v) == VendorTier.HIGH

    def test_tier_high_not_sensitive_but_core(self):
        v = _make_vendor(data_access_level=DataAccessLevel.INTERNAL, is_core_operations=True)
        assert _compute_tier(v) == VendorTier.HIGH

    def test_tier_medium_internal_not_core(self):
        v = _make_vendor(data_access_level=DataAccessLevel.INTERNAL, is_core_operations=False)
        assert _compute_tier(v) == VendorTier.MEDIUM

    def test_tier_medium_public(self):
        v = _make_vendor(data_access_level=DataAccessLevel.PUBLIC, is_core_operations=False)
        assert _compute_tier(v) == VendorTier.MEDIUM

    def test_tier_low_no_data_access(self):
        v = _make_vendor(data_access_level=DataAccessLevel.NONE, is_core_operations=False)
        assert _compute_tier(v) == VendorTier.LOW

    def test_tiering_overview_counts(self, engine):
        engine.register_vendor(_make_vendor(name="C1", data_access_level=DataAccessLevel.RESTRICTED, is_core_operations=True))
        engine.register_vendor(_make_vendor(name="H1", data_access_level=DataAccessLevel.CONFIDENTIAL, is_core_operations=False))
        engine.register_vendor(_make_vendor(name="M1", data_access_level=DataAccessLevel.INTERNAL, is_core_operations=False))
        engine.register_vendor(_make_vendor(name="L1", data_access_level=DataAccessLevel.NONE, is_core_operations=False))
        overview = engine.get_tiering_overview()
        assert overview.critical_count >= 1
        assert overview.high_count >= 1
        assert overview.medium_count >= 1
        assert overview.low_count >= 1


# ============================================================================
# QUESTIONNAIRE TESTS (8 tests)
# ============================================================================


class TestQuestionnaire:
    def test_questionnaire_has_100_plus_questions(self):
        assert len(_QUESTIONNAIRE) >= 100

    def test_questionnaire_all_categories_present(self):
        categories = {q.category for q in _QUESTIONNAIRE}
        for cat in QuestionCategory:
            assert cat in categories, f"Missing category: {cat}"

    def test_all_yes_answers_yield_near_perfect_score(self, engine):
        vendor = engine.register_vendor(_make_vendor())
        assessment = engine.submit_questionnaire(vendor.id, _all_yes_responses())
        assert assessment.questionnaire_score >= 95.0

    def test_all_no_answers_yield_zero_score(self, engine):
        vendor = engine.register_vendor(_make_vendor())
        assessment = engine.submit_questionnaire(vendor.id, _all_no_responses())
        assert assessment.questionnaire_score == 0.0

    def test_partial_answers_yield_partial_score(self, engine):
        vendor = engine.register_vendor(_make_vendor())
        half = _all_yes_responses()[: len(_QUESTIONNAIRE) // 2]
        rest = _all_no_responses()[len(_QUESTIONNAIRE) // 2 :]
        assessment = engine.submit_questionnaire(vendor.id, half + rest)
        assert 0.0 < assessment.questionnaire_score < 100.0

    def test_category_scores_populated(self, engine):
        vendor = engine.register_vendor(_make_vendor())
        assessment = engine.submit_questionnaire(vendor.id, _all_yes_responses())
        assert len(assessment.category_scores) > 0
        for score in assessment.category_scores.values():
            assert 0.0 <= score <= 100.0

    def test_assessment_id_format(self, engine):
        vendor = engine.register_vendor(_make_vendor())
        assessment = engine.submit_questionnaire(vendor.id, _all_yes_responses())
        assert assessment.id.startswith("asm-")

    def test_get_assessment_returns_latest(self, engine):
        vendor = engine.register_vendor(_make_vendor())
        engine.submit_questionnaire(vendor.id, _all_no_responses())
        engine.submit_questionnaire(vendor.id, _all_yes_responses())
        latest = engine.get_assessment(vendor.id)
        assert latest is not None
        assert latest.questionnaire_score >= 95.0


# ============================================================================
# CONTINUOUS MONITORING TESTS (7 tests)
# ============================================================================


class TestContinuousMonitoring:
    def _make_signal(
        self,
        vendor_id: str,
        severity: RiskSignalSeverity = RiskSignalSeverity.MEDIUM,
        signal_type: RiskSignalType = RiskSignalType.NEWS_ALERT,
    ) -> RiskSignal:
        return RiskSignal(
            vendor_id=vendor_id,
            signal_type=signal_type,
            severity=severity,
            title="Test signal",
            description="A test monitoring signal",
            source="test",
        )

    def test_record_signal_returns_id(self, engine):
        vendor = engine.register_vendor(_make_vendor())
        signal = self._make_signal(vendor.id)
        recorded = engine.record_risk_signal(signal)
        assert recorded.id.startswith("sig-")

    def test_monitoring_data_returns_vendor_id(self, engine):
        vendor = engine.register_vendor(_make_vendor())
        data = engine.get_monitoring_data(vendor.id)
        assert data["vendor_id"] == vendor.id

    def test_monitoring_signal_count_increases(self, engine):
        vendor = engine.register_vendor(_make_vendor())
        for _ in range(3):
            engine.record_risk_signal(self._make_signal(vendor.id))
        data = engine.get_monitoring_data(vendor.id)
        assert data["total_signals"] == 3

    def test_monitoring_severity_breakdown(self, engine):
        vendor = engine.register_vendor(_make_vendor())
        engine.record_risk_signal(self._make_signal(vendor.id, RiskSignalSeverity.HIGH))
        engine.record_risk_signal(self._make_signal(vendor.id, RiskSignalSeverity.LOW))
        data = engine.get_monitoring_data(vendor.id)
        assert "high" in data["severity_breakdown"]
        assert "low" in data["severity_breakdown"]

    def test_monitoring_score_100_with_no_signals(self):
        score = _compute_monitoring_score([])
        assert score == 100.0

    def test_monitoring_score_decreases_with_critical_signal(self):
        signal = RiskSignal(
            vendor_id="vnd-x",
            signal_type=RiskSignalType.BREACH_HISTORY,
            severity=RiskSignalSeverity.CRITICAL,
            title="Breach",
            description="Breach detected",
        )
        score = _compute_monitoring_score([signal])
        assert score < 100.0
        assert score >= 0.0

    def test_monitoring_score_floored_at_zero(self):
        signals = [
            RiskSignal(
                vendor_id="vnd-x",
                signal_type=RiskSignalType.BREACH_HISTORY,
                severity=RiskSignalSeverity.CRITICAL,
                title=f"Signal {i}",
                description="critical",
            )
            for i in range(10)
        ]
        score = _compute_monitoring_score(signals)
        assert score == 0.0


# ============================================================================
# FOURTH-PARTY RISK TESTS (6 tests)
# ============================================================================


class TestFourthPartyRisk:
    def test_fourth_party_map_empty_initially(self, engine):
        fp_map = engine.get_fourth_party_map()
        assert fp_map.direct_vendor_count == 0

    def test_fourth_party_count_tracks_dependencies(self, engine):
        # Vendor A depends on cloud provider (another vendor ID)
        engine.register_vendor(_make_vendor(name="Vendor A", fourth_party_vendors=["dep-001"]))
        fp_map = engine.get_fourth_party_map()
        assert fp_map.fourth_party_count >= 1

    def test_high_signal_propagates_to_dependent_vendor(self, engine):
        # Register the dependency vendor
        dep_vendor = engine.register_vendor(_make_vendor(name="Cloud Infra"))
        # Register a vendor that depends on it
        consumer_vendor = engine.register_vendor(
            _make_vendor(name="App Vendor", fourth_party_vendors=[dep_vendor.id])
        )
        # Record a HIGH signal on the dependency
        signal = RiskSignal(
            vendor_id=dep_vendor.id,
            signal_type=RiskSignalType.BREACH_HISTORY,
            severity=RiskSignalSeverity.HIGH,
            title="Breach at cloud provider",
            description="Data breach detected",
        )
        engine.record_risk_signal(signal)
        fp_map = engine.get_fourth_party_map()
        assert fp_map.active_transitive_risks >= 1

    def test_low_signal_does_not_propagate(self, engine):
        dep_vendor = engine.register_vendor(_make_vendor(name="Low Risk Dep"))
        engine.register_vendor(
            _make_vendor(name="Consumer", fourth_party_vendors=[dep_vendor.id])
        )
        signal = RiskSignal(
            vendor_id=dep_vendor.id,
            signal_type=RiskSignalType.NEWS_ALERT,
            severity=RiskSignalSeverity.LOW,
            title="Minor news",
            description="Low severity news",
        )
        engine.record_risk_signal(signal)
        fp_map = engine.get_fourth_party_map()
        assert fp_map.active_transitive_risks == 0

    def test_dependency_chains_populated(self, engine):
        engine.register_vendor(
            _make_vendor(name="Chained Vendor", fourth_party_vendors=["dep-A", "dep-B"])
        )
        fp_map = engine.get_fourth_party_map()
        chains = fp_map.dependency_chains
        assert any(c["vendor_name"] == "Chained Vendor" for c in chains)
        chained = next(c for c in chains if c["vendor_name"] == "Chained Vendor")
        assert chained["dependency_count"] == 2

    def test_high_risk_fourth_parties_listed(self, engine):
        dep = engine.register_vendor(_make_vendor(name="Risky Dep"))
        consumer = engine.register_vendor(
            _make_vendor(name="Consumer", fourth_party_vendors=[dep.id])
        )
        signal = RiskSignal(
            vendor_id=dep.id,
            signal_type=RiskSignalType.BREACH_HISTORY,
            severity=RiskSignalSeverity.CRITICAL,
            title="Critical breach",
            description="Critical breach at dep",
        )
        engine.record_risk_signal(signal)
        fp_map = engine.get_fourth_party_map()
        assert len(fp_map.high_risk_fourth_parties) >= 1


# ============================================================================
# CONTRACT RISK TESTS (6 tests)
# ============================================================================


class TestContractRisk:
    def test_expired_cert_triggers_contract_risk(self):
        vendor = _make_vendor(
            certifications=[_make_cert(ComplianceCert.SOC2_TYPE2, expired=True)]
        )
        vendor.tier = VendorTier.HIGH
        risks = _analyze_contract_risks(vendor)
        types = [r.risk_type for r in risks]
        assert ContractRiskType.EXPIRED_CERT in types

    def test_long_breach_notification_triggers_risk(self):
        sla = SLATerms(breach_notification_hours=168)  # 7 days — too long
        vendor = _make_vendor(sla_terms=sla)
        risks = _analyze_contract_risks(vendor)
        types = [r.risk_type for r in risks]
        assert ContractRiskType.MISSING_BREACH_NOTIFICATION in types

    def test_compliant_vendor_no_contract_risks(self):
        sla = SLATerms(
            breach_notification_hours=24,
            data_return_days=30,
            uptime_percent=99.9,
        )
        vendor = _make_vendor(sla_terms=sla, certifications=[_make_cert()])
        vendor.tier = VendorTier.HIGH
        risks = _analyze_contract_risks(vendor)
        assert len(risks) == 0

    def test_critical_vendor_missing_soc2_triggers_risk(self):
        vendor = _make_vendor(certifications=[])  # No certs
        vendor.tier = VendorTier.CRITICAL
        risks = _analyze_contract_risks(vendor)
        types = [r.risk_type for r in risks]
        assert ContractRiskType.MISSING_SECURITY_STANDARDS in types

    def test_low_uptime_sla_triggers_risk(self):
        sla = SLATerms(uptime_percent=98.0)  # Below 99.5%
        vendor = _make_vendor(sla_terms=sla)
        risks = _analyze_contract_risks(vendor)
        types = [r.risk_type for r in risks]
        assert ContractRiskType.UNLIMITED_LIABILITY_GAP in types

    def test_contract_score_100_no_risks(self):
        score = _compute_contract_score([])
        assert score == 100.0


# ============================================================================
# SCORECARD TESTS (6 tests)
# ============================================================================


class TestVendorScorecard:
    def test_scorecard_returns_none_for_unknown_vendor(self, engine):
        result = engine.compute_scorecard("vnd-doesnotexist")
        assert result is None

    def test_scorecard_has_all_components(self, engine):
        vendor = engine.register_vendor(_make_vendor())
        scorecard = engine.compute_scorecard(vendor.id)
        assert scorecard is not None
        assert 0.0 <= scorecard.overall_score <= 100.0
        assert 0.0 <= scorecard.questionnaire_score <= 100.0
        assert 0.0 <= scorecard.monitoring_score <= 100.0
        assert 0.0 <= scorecard.contract_score <= 100.0
        assert 0.0 <= scorecard.incident_score <= 100.0

    def test_scorecard_grade_reflects_score(self):
        assert _score_to_grade(95.0) == "A"
        assert _score_to_grade(85.0) == "B"
        assert _score_to_grade(75.0) == "C"
        assert _score_to_grade(65.0) == "D"
        assert _score_to_grade(55.0) == "F"

    def test_scorecard_improves_after_perfect_questionnaire(self, engine):
        vendor = engine.register_vendor(_make_vendor())
        before = engine.compute_scorecard(vendor.id)
        engine.submit_questionnaire(vendor.id, _all_yes_responses())
        after = engine.compute_scorecard(vendor.id)
        assert after.questionnaire_score > before.questionnaire_score

    def test_scorecard_trend_populated_after_multiple_calls(self, engine):
        vendor = engine.register_vendor(_make_vendor())
        for _ in range(3):
            engine.compute_scorecard(vendor.id)
        final = engine.compute_scorecard(vendor.id)
        assert len(final.score_trend) >= 3

    def test_scorecard_vendor_name_matches(self, engine):
        vendor = engine.register_vendor(_make_vendor(name="SpecificVendor"))
        scorecard = engine.compute_scorecard(vendor.id)
        assert scorecard.vendor_name == "SpecificVendor"


# ============================================================================
# SIG QUESTIONNAIRE COMPLETENESS TESTS (4 tests)
# ============================================================================


class TestSIGQuestionnaire:
    def test_all_questions_have_unique_ids(self):
        ids = [q.id for q in _QUESTIONNAIRE]
        assert len(ids) == len(set(ids)), "Duplicate question IDs detected"

    def test_all_questions_have_positive_weight(self):
        for q in _QUESTIONNAIRE:
            assert q.weight > 0.0, f"Question {q.id} has non-positive weight"

    def test_question_map_matches_questionnaire(self):
        assert len(_QUESTION_MAP) == len(_QUESTIONNAIRE)
        for q in _QUESTIONNAIRE:
            assert q.id in _QUESTION_MAP

    def test_questionnaire_covers_access_control_and_encryption(self):
        cats = {q.category for q in _QUESTIONNAIRE}
        assert QuestionCategory.ACCESS_CONTROL in cats
        assert QuestionCategory.ENCRYPTION in cats
        assert QuestionCategory.INCIDENT_RESPONSE in cats
        assert QuestionCategory.DATA_HANDLING in cats


# ============================================================================
# ROUTER SMOKE TESTS (5 tests via FastAPI TestClient)
# ============================================================================


class TestVendorRiskRouter:
    @pytest.fixture(autouse=True)
    def _setup_client(self, temp_db, monkeypatch):
        """Wire a test FastAPI app with the VRM router using isolated DB."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        import core.vendor_risk as vrm_mod

        # Patch the module-level engine to use isolated DB
        test_engine = VendorRiskEngine(db_path=temp_db)
        monkeypatch.setattr(vrm_mod, "_engine", test_engine)

        # Patch the router's engine reference and disable auth for tests
        import apps.api.vendor_risk_router as router_mod
        monkeypatch.setattr(router_mod, "_engine", test_engine)

        # Auth dep is baked into router.dependencies AND each route's dependencies
        # at module import time — clear both so TestClient gets 200s without a token.
        router_mod.router.dependencies.clear()
        for route in router_mod.router.routes:
            if hasattr(route, "dependencies"):
                route.dependencies.clear()

        app = FastAPI()
        app.include_router(router_mod.router)
        self.client = TestClient(app, raise_server_exceptions=True)
        self.engine = test_engine

    def test_list_vendors_empty(self):
        resp = self.client.get("/api/v1/vendors")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["vendors"] == []

    def test_create_vendor_returns_201(self):
        payload = {
            "name": "Test SaaS Co",
            "service_category": "saas_application",
            "data_access_level": "confidential",
            "is_core_operations": False,
            "contract_start": "2024-01-01",
            "contract_end": "2025-12-31",
        }
        resp = self.client.post("/api/v1/vendors", json=payload)
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "Test SaaS Co"
        assert data["tier"] == "high"  # confidential + not core = HIGH

    def test_get_vendor_not_found(self):
        resp = self.client.get("/api/v1/vendors/vnd-doesnotexist")
        assert resp.status_code == 404

    def test_tiering_endpoint_returns_assessment_requirements(self):
        resp = self.client.get("/api/v1/vendors/tiering")
        assert resp.status_code == 200
        data = resp.json()
        assert "assessment_requirements" in data
        assert "critical" in data["assessment_requirements"]

    def test_fourth_party_endpoint_returns_map(self):
        resp = self.client.get("/api/v1/vendors/fourth-party")
        assert resp.status_code == 200
        data = resp.json()
        assert "direct_vendor_count" in data
        assert "fourth_party_count" in data
