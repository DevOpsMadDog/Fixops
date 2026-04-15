"""Tests for IncidentCostEngine — Beast Mode wave 34."""

from __future__ import annotations

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'suite-core'))

from core.incident_cost_engine import IncidentCostEngine


@pytest.fixture
def engine(tmp_path):
    return IncidentCostEngine(db_path=str(tmp_path / "test.db"))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _cost(engine, org_id="org1", incident_id="INC-001", **kwargs):
    defaults = dict(
        incident_name="Test Incident",
        incident_type="data-breach",
        cost_category="personnel",
        amount=1000.0,
        currency="USD",
        estimated=False,
        description="test cost",
        recorded_by="analyst1",
    )
    defaults.update(kwargs)
    return engine.record_cost(org_id=org_id, incident_id=incident_id, **defaults)


# ---------------------------------------------------------------------------
# record_cost
# ---------------------------------------------------------------------------

def test_record_cost_basic(engine):
    cost = _cost(engine)
    assert cost["id"]
    assert cost["org_id"] == "org1"
    assert cost["incident_id"] == "INC-001"
    assert cost["amount"] == 1000.0
    assert cost["currency"] == "USD"
    assert cost["estimated"] == 0
    assert cost["created_at"]


def test_record_cost_amount_zero_allowed(engine):
    cost = _cost(engine, amount=0)
    assert cost["amount"] == 0.0


def test_record_cost_negative_amount_rejected(engine):
    with pytest.raises(ValueError, match="amount must be >= 0"):
        _cost(engine, amount=-100)


def test_record_cost_estimated_flag(engine):
    cost = _cost(engine, estimated=True)
    assert cost["estimated"] == 1


def test_record_cost_all_categories(engine):
    categories = [
        "personnel", "tools", "forensics", "legal", "regulatory-fine",
        "customer-notification", "PR", "business-interruption", "recovery", "insurance",
    ]
    for i, cat in enumerate(categories):
        c = _cost(engine, incident_id=f"INC-CAT-{i}", cost_category=cat)
        assert c["cost_category"] == cat


def test_record_cost_all_incident_types(engine):
    types = [
        "ransomware", "data-breach", "ddos", "phishing",
        "insider", "supply-chain", "misconfiguration", "zero-day",
    ]
    for i, t in enumerate(types):
        c = _cost(engine, incident_id=f"INC-TYPE-{i}", incident_type=t)
        assert c["incident_type"] == t


def test_record_cost_all_currencies(engine):
    for i, cur in enumerate(["USD", "EUR", "GBP", "AUD", "CAD"]):
        c = _cost(engine, incident_id=f"INC-CUR-{i}", currency=cur)
        assert c["currency"] == cur


def test_record_cost_invalid_incident_type(engine):
    with pytest.raises(ValueError, match="Invalid incident_type"):
        _cost(engine, incident_type="unknown-type")


def test_record_cost_invalid_cost_category(engine):
    with pytest.raises(ValueError, match="Invalid cost_category"):
        _cost(engine, cost_category="salary")


def test_record_cost_invalid_currency(engine):
    with pytest.raises(ValueError, match="Invalid currency"):
        _cost(engine, currency="JPY")


def test_record_cost_org_isolation(engine):
    _cost(engine, org_id="org1", incident_id="INC-ISO-1")
    _cost(engine, org_id="org2", incident_id="INC-ISO-2")
    costs1 = engine.get_incident_costs("org1", "INC-ISO-1")
    costs2 = engine.get_incident_costs("org2", "INC-ISO-2")
    assert len(costs1) == 1
    assert len(costs2) == 1
    assert engine.get_incident_costs("org1", "INC-ISO-2") == []


# ---------------------------------------------------------------------------
# finalize_incident
# ---------------------------------------------------------------------------

def test_finalize_incident_totals(engine):
    _cost(engine, incident_id="INC-FIN-1", amount=5000.0, estimated=False, cost_category="personnel")
    _cost(engine, incident_id="INC-FIN-1", amount=3000.0, estimated=True, cost_category="legal")
    _cost(engine, incident_id="INC-FIN-1", amount=2000.0, estimated=False, cost_category="tools")

    summary = engine.finalize_incident("org1", "INC-FIN-1", duration_hours=72.0, severity="high")
    assert summary["total_cost"] == 10000.0
    assert summary["actual_total"] == 7000.0
    assert summary["estimated_total"] == 3000.0


def test_finalize_incident_category_breakdown(engine):
    _cost(engine, incident_id="INC-FIN-2", amount=1000.0, cost_category="personnel")
    _cost(engine, incident_id="INC-FIN-2", amount=500.0, cost_category="personnel")
    _cost(engine, incident_id="INC-FIN-2", amount=2000.0, cost_category="legal")

    summary = engine.finalize_incident("org1", "INC-FIN-2", duration_hours=24.0, severity="critical")
    cats = summary["cost_categories"]
    assert isinstance(cats, dict)
    assert cats["personnel"] == 1500.0
    assert cats["legal"] == 2000.0


def test_finalize_incident_severity_stored(engine):
    _cost(engine, incident_id="INC-FIN-3", amount=100.0)
    summary = engine.finalize_incident("org1", "INC-FIN-3", duration_hours=10.0, severity="low")
    assert summary["severity"] == "low"


def test_finalize_incident_invalid_severity(engine):
    with pytest.raises(ValueError, match="Invalid severity"):
        engine.finalize_incident("org1", "INC-BADSEV", duration_hours=1.0, severity="extreme")


def test_finalize_incident_idempotent(engine):
    _cost(engine, incident_id="INC-FIN-4", amount=1000.0)
    engine.finalize_incident("org1", "INC-FIN-4", duration_hours=10.0, severity="high")
    # Second finalize should update
    engine.finalize_incident("org1", "INC-FIN-4", duration_hours=20.0, severity="critical")
    summary = engine.get_incident_summary("org1", "INC-FIN-4")
    assert summary["duration_hours"] == 20.0
    assert summary["severity"] == "critical"


def test_finalize_incident_no_costs(engine):
    # Should work even with no costs recorded
    summary = engine.finalize_incident("org1", "INC-EMPTY", duration_hours=5.0, severity="medium")
    assert summary["total_cost"] == 0.0
    assert summary["estimated_total"] == 0.0
    assert summary["actual_total"] == 0.0


# ---------------------------------------------------------------------------
# get_incident_costs / get_incident_summary
# ---------------------------------------------------------------------------

def test_get_incident_costs_empty(engine):
    assert engine.get_incident_costs("org1", "NO-SUCH") == []


def test_get_incident_costs_multiple(engine):
    for i in range(3):
        _cost(engine, incident_id="INC-GC-1", amount=float(i * 100))
    costs = engine.get_incident_costs("org1", "INC-GC-1")
    assert len(costs) == 3


def test_get_incident_summary_not_finalized(engine):
    assert engine.get_incident_summary("org1", "NOT-FINALIZED") is None


def test_get_incident_summary_parsed_categories(engine):
    _cost(engine, incident_id="INC-SUM-1", amount=500.0, cost_category="forensics")
    engine.finalize_incident("org1", "INC-SUM-1", duration_hours=5.0, severity="medium")
    summary = engine.get_incident_summary("org1", "INC-SUM-1")
    assert isinstance(summary["cost_categories"], dict)
    assert summary["cost_categories"]["forensics"] == 500.0


# ---------------------------------------------------------------------------
# add_benchmark
# ---------------------------------------------------------------------------

def test_add_benchmark_basic(engine):
    bm = engine.add_benchmark(
        org_id="org1",
        incident_type="data-breach",
        avg_cost=4_000_000.0,
        median_cost=3_500_000.0,
        p90_cost=8_000_000.0,
        sample_size=500,
        source="IBM Cost of a Data Breach 2025",
        published_year=2025,
    )
    assert bm["id"]
    assert bm["incident_type"] == "data-breach"
    assert bm["avg_cost"] == 4_000_000.0


def test_add_benchmark_invalid_type(engine):
    with pytest.raises(ValueError, match="Invalid incident_type"):
        engine.add_benchmark("org1", "unknown", 1000, 900, 1500, 10, "src", 2025)


# ---------------------------------------------------------------------------
# compare_to_benchmark
# ---------------------------------------------------------------------------

def test_compare_to_benchmark_above(engine):
    _cost(engine, incident_id="INC-BM-1", amount=6_000_000.0, incident_type="data-breach")
    engine.add_benchmark("org1", "data-breach", 4_000_000.0, 3_500_000.0, 8_000_000.0, 100, "IBM", 2025)
    result = engine.compare_to_benchmark("org1", "INC-BM-1")
    assert result["determination"] == "above"
    assert result["total_cost"] == 6_000_000.0


def test_compare_to_benchmark_below(engine):
    _cost(engine, incident_id="INC-BM-2", amount=1_000_000.0, incident_type="data-breach")
    engine.add_benchmark("org1", "data-breach", 4_000_000.0, 3_500_000.0, 8_000_000.0, 100, "IBM", 2025)
    result = engine.compare_to_benchmark("org1", "INC-BM-2")
    assert result["determination"] == "below"


def test_compare_to_benchmark_within_range(engine):
    # Within 20% of 4M avg → 3.2M - 4.8M is within-range
    _cost(engine, incident_id="INC-BM-3", amount=4_200_000.0, incident_type="data-breach")
    engine.add_benchmark("org1", "data-breach", 4_000_000.0, 3_500_000.0, 8_000_000.0, 100, "IBM", 2025)
    result = engine.compare_to_benchmark("org1", "INC-BM-3")
    assert result["determination"] == "within-range"


def test_compare_to_benchmark_no_benchmark(engine):
    _cost(engine, incident_id="INC-BM-4", amount=1000.0, incident_type="ransomware")
    result = engine.compare_to_benchmark("org1", "INC-BM-4")
    assert result["determination"] == "no-benchmark"


def test_compare_to_benchmark_not_found(engine):
    with pytest.raises(KeyError):
        engine.compare_to_benchmark("org1", "NO-SUCH-INC")


def test_compare_to_benchmark_exact_upper_boundary(engine):
    # Exactly at upper boundary (4M * 1.20 = 4.8M) → within-range
    _cost(engine, incident_id="INC-BM-5", amount=4_800_000.0, incident_type="data-breach")
    engine.add_benchmark("org1", "data-breach", 4_000_000.0, 3_500_000.0, 8_000_000.0, 100, "IBM", 2025)
    result = engine.compare_to_benchmark("org1", "INC-BM-5")
    assert result["determination"] == "within-range"


# ---------------------------------------------------------------------------
# get_cost_analytics
# ---------------------------------------------------------------------------

def test_get_cost_analytics_empty(engine):
    analytics = engine.get_cost_analytics("org1")
    assert analytics["total_spent"] == 0.0
    assert analytics["by_incident_type"] == {}
    assert analytics["by_cost_category"] == {}
    assert analytics["avg_per_incident"] == 0.0
    assert analytics["most_expensive_incident"] is None


def test_get_cost_analytics_populated(engine):
    _cost(engine, incident_id="INC-AN-1", amount=5000.0, incident_type="ransomware", cost_category="personnel")
    _cost(engine, incident_id="INC-AN-1", amount=3000.0, incident_type="ransomware", cost_category="legal")
    _cost(engine, incident_id="INC-AN-2", amount=2000.0, incident_type="phishing", cost_category="tools")

    analytics = engine.get_cost_analytics("org1")
    assert analytics["total_spent"] == 10000.0
    assert analytics["by_incident_type"]["ransomware"] == 8000.0
    assert analytics["by_incident_type"]["phishing"] == 2000.0
    assert analytics["by_cost_category"]["personnel"] == 5000.0
    assert analytics["by_cost_category"]["legal"] == 3000.0
    assert analytics["by_cost_category"]["tools"] == 2000.0
    assert analytics["avg_per_incident"] == 5000.0  # (8000+2000)/2
    assert analytics["most_expensive_incident"] == "INC-AN-1"


# ---------------------------------------------------------------------------
# list_summaries
# ---------------------------------------------------------------------------

def test_list_summaries_empty(engine):
    assert engine.list_summaries("org1") == []


def test_list_summaries_all(engine):
    _cost(engine, incident_id="INC-LS-1", amount=1000.0)
    _cost(engine, incident_id="INC-LS-2", amount=2000.0)
    engine.finalize_incident("org1", "INC-LS-1", 10.0, "high")
    engine.finalize_incident("org1", "INC-LS-2", 20.0, "critical")
    summaries = engine.list_summaries("org1")
    assert len(summaries) == 2


def test_list_summaries_filter_severity(engine):
    _cost(engine, incident_id="INC-LS-3", amount=1000.0)
    _cost(engine, incident_id="INC-LS-4", amount=2000.0)
    engine.finalize_incident("org1", "INC-LS-3", 10.0, "high")
    engine.finalize_incident("org1", "INC-LS-4", 20.0, "low")
    high_summaries = engine.list_summaries("org1", severity="high")
    assert len(high_summaries) == 1
    assert high_summaries[0]["severity"] == "high"


def test_list_summaries_filter_incident_type(engine):
    _cost(engine, incident_id="INC-LS-5", amount=1000.0, incident_type="ransomware")
    _cost(engine, incident_id="INC-LS-6", amount=2000.0, incident_type="phishing")
    engine.finalize_incident("org1", "INC-LS-5", 10.0, "high")
    engine.finalize_incident("org1", "INC-LS-6", 20.0, "medium")
    ransomware_summaries = engine.list_summaries("org1", incident_type="ransomware")
    assert len(ransomware_summaries) == 1


def test_list_summaries_cost_categories_parsed(engine):
    _cost(engine, incident_id="INC-LS-7", amount=500.0, cost_category="forensics")
    engine.finalize_incident("org1", "INC-LS-7", 5.0, "low")
    summaries = engine.list_summaries("org1")
    assert isinstance(summaries[0]["cost_categories"], dict)
