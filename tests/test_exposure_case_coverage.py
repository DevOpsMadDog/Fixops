"""Coverage tests for core.exposure_case — ExposureCaseManager."""
import os
import sys
import uuid
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

import pytest
from core.exposure_case import ExposureCaseManager, ExposureCase, CaseStatus, CasePriority, severity_to_priority


class TestSeverityToPriority:
    def test_critical(self):
        assert severity_to_priority("critical") == CasePriority.CRITICAL

    def test_high(self):
        assert severity_to_priority("high") == CasePriority.HIGH

    def test_medium(self):
        assert severity_to_priority("medium") == CasePriority.MEDIUM

    def test_low(self):
        assert severity_to_priority("low") == CasePriority.LOW

    def test_info(self):
        assert severity_to_priority("info") == CasePriority.INFO

    def test_unknown_defaults_medium(self):
        assert severity_to_priority("unknown") == CasePriority.MEDIUM


class TestCaseStatus:
    def test_open_value(self):
        assert CaseStatus.OPEN.value == "open"

    def test_triaging(self):
        assert CaseStatus.TRIAGING.value == "triaging"

    def test_fixing(self):
        assert CaseStatus.FIXING.value == "fixing"

    def test_resolved(self):
        assert CaseStatus.RESOLVED.value == "resolved"

    def test_closed(self):
        assert CaseStatus.CLOSED.value == "closed"

    def test_accepted_risk(self):
        assert CaseStatus.ACCEPTED_RISK.value == "accepted_risk"

    def test_false_positive(self):
        assert CaseStatus.FALSE_POSITIVE.value == "false_positive"


class TestCasePriority:
    def test_critical(self):
        assert CasePriority.CRITICAL.value == "critical"

    def test_high(self):
        assert CasePriority.HIGH.value == "high"

    def test_medium(self):
        assert CasePriority.MEDIUM.value == "medium"

    def test_low(self):
        assert CasePriority.LOW.value == "low"

    def test_info(self):
        assert CasePriority.INFO.value == "info"


class TestExposureCase:
    def test_create(self):
        case = ExposureCase(
            case_id=str(uuid.uuid4()),
            title="Test XSS Vulnerability",
            description="XSS in login form",
            priority=CasePriority.HIGH,
        )
        assert case.title == "Test XSS Vulnerability"
        assert case.priority == CasePriority.HIGH
        assert case.status == CaseStatus.OPEN

    def test_to_dict(self):
        case = ExposureCase(
            case_id="CASE-001",
            title="SQL Injection",
            description="SQLi in search endpoint",
            priority=CasePriority.CRITICAL,
            risk_score=9.5,
        )
        d = case.to_dict()
        assert isinstance(d, dict)
        assert d["title"] == "SQL Injection"
        assert d["case_id"] == "CASE-001"
        assert d["risk_score"] == 9.5

    def test_default_status(self):
        case = ExposureCase(case_id="C1", title="T1")
        assert case.status == CaseStatus.OPEN

    def test_default_priority(self):
        case = ExposureCase(case_id="C2", title="T2")
        assert case.priority == CasePriority.MEDIUM

    def test_affected_assets(self):
        case = ExposureCase(
            case_id="C3",
            title="T3",
            affected_assets=["web-app-1", "api-server-2"],
        )
        assert len(case.affected_assets) == 2

    def test_sla_fields(self):
        case = ExposureCase(
            case_id="C4",
            title="T4",
            sla_due="2026-03-15",
            sla_breached=False,
        )
        assert case.sla_breached is False


class TestExposureCaseManager:
    @pytest.fixture(autouse=True)
    def reset_manager(self):
        ExposureCaseManager.reset_instance()
        yield
        ExposureCaseManager.reset_instance()

    def test_singleton(self):
        m1 = ExposureCaseManager.get_instance()
        m2 = ExposureCaseManager.get_instance()
        assert m1 is m2

    def test_create_and_get_case(self):
        mgr = ExposureCaseManager.get_instance()
        case = ExposureCase(
            case_id=str(uuid.uuid4()),
            title="Test XSS",
            description="XSS in login form",
            priority=CasePriority.HIGH,
        )
        created = mgr.create_case(case)
        assert created is not None
        retrieved = mgr.get_case(case.case_id)
        assert retrieved is not None
        assert retrieved.case_id == case.case_id

    def test_get_case_not_found(self):
        mgr = ExposureCaseManager.get_instance()
        result = mgr.get_case("nonexistent-id")
        assert result is None

    def test_list_cases(self):
        mgr = ExposureCaseManager.get_instance()
        c1 = ExposureCase(case_id=str(uuid.uuid4()), title="Case1", priority=CasePriority.LOW)
        c2 = ExposureCase(case_id=str(uuid.uuid4()), title="Case2", priority=CasePriority.HIGH)
        mgr.create_case(c1)
        mgr.create_case(c2)
        result = mgr.list_cases()
        assert isinstance(result, dict)

    def test_list_cases_by_status(self):
        mgr = ExposureCaseManager.get_instance()
        c = ExposureCase(case_id=str(uuid.uuid4()), title="StatusCase")
        mgr.create_case(c)
        result = mgr.list_cases(status="open")
        assert isinstance(result, dict)
