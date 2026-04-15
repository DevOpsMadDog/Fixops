"""Tests for HuntingAutomationEngine.

Covers: init, hypothesis CRUD + validation, query CRUD, execute_query
(execution_count increment, avg_execution_secs rolling avg, findings_count
accumulation), fail_execution (no stat update), high_yield_queries filter,
get_hunt_summary, get_hypothesis_detail, get_recent_executions, org isolation.
"""

from __future__ import annotations

import json
import pytest

from core.hunting_automation_engine import HuntingAutomationEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    return HuntingAutomationEngine(db_path=str(tmp_path / "hunt_test.db"))


def _hyp(engine, org_id="org1", **overrides):
    defaults = {
        "hypothesis": "Attacker may use PtH for lateral movement",
        "threat_category": "lateral_movement",
        "mitre_technique": "T1550.002",
        "confidence": "high",
        "data_sources": ["siem", "edr"],
        "created_by": "analyst1",
    }
    defaults.update(overrides)
    return engine.create_hypothesis(org_id=org_id, **defaults)


def _query(engine, hypothesis_id, org_id="org1", **overrides):
    defaults = {
        "query_name": "PtH Detection KQL",
        "query_language": "KQL",
        "query_content": "SecurityEvent | where EventID == 4624",
        "data_source": "siem",
    }
    defaults.update(overrides)
    return engine.add_query(hypothesis_id=hypothesis_id, org_id=org_id, **defaults)


# ---------------------------------------------------------------------------
# 1. Initialisation
# ---------------------------------------------------------------------------


def test_init_creates_db(tmp_path):
    db = tmp_path / "hunt.db"
    HuntingAutomationEngine(db_path=str(db))
    assert db.exists()


def test_init_twice_idempotent(tmp_path):
    db = str(tmp_path / "hunt.db")
    HuntingAutomationEngine(db_path=db)
    HuntingAutomationEngine(db_path=db)


# ---------------------------------------------------------------------------
# 2. create_hypothesis
# ---------------------------------------------------------------------------


def test_create_hypothesis_basic(engine):
    hyp = _hyp(engine)
    assert hyp["id"] is not None
    assert hyp["validated"] == 0
    assert hyp["validation_result"] == ""
    assert hyp["threat_category"] == "lateral_movement"


def test_data_sources_returned_as_list(engine):
    hyp = _hyp(engine, data_sources=["siem", "edr", "network"])
    assert isinstance(hyp["data_sources"], list)
    assert "siem" in hyp["data_sources"]
    assert len(hyp["data_sources"]) == 3


def test_data_sources_empty_list(engine):
    hyp = _hyp(engine, data_sources=[])
    assert hyp["data_sources"] == []


def test_invalid_threat_category_raises(engine):
    with pytest.raises(ValueError, match="threat_category"):
        _hyp(engine, threat_category="ransomware")


def test_invalid_confidence_raises(engine):
    with pytest.raises(ValueError, match="confidence"):
        _hyp(engine, confidence="very_high")


# ---------------------------------------------------------------------------
# 3. validate_hypothesis
# ---------------------------------------------------------------------------


def test_validate_hypothesis_true(engine):
    hyp = _hyp(engine)
    updated = engine.validate_hypothesis(hyp["id"], "org1", True, "Confirmed via EDR logs")
    assert updated["validated"] == 1
    assert updated["validation_result"] == "Confirmed via EDR logs"


def test_validate_hypothesis_false(engine):
    hyp = _hyp(engine)
    updated = engine.validate_hypothesis(hyp["id"], "org1", False, "No evidence found")
    assert updated["validated"] == 0
    assert updated["validation_result"] == "No evidence found"


def test_validate_hypothesis_wrong_org_raises(engine):
    hyp = _hyp(engine, org_id="orgA")
    with pytest.raises(ValueError):
        engine.validate_hypothesis(hyp["id"], "orgB", True, "ok")


# ---------------------------------------------------------------------------
# 4. get_hypothesis / list_hypotheses
# ---------------------------------------------------------------------------


def test_get_hypothesis_returns_data_sources_as_list(engine):
    hyp = _hyp(engine, data_sources=["cloud", "identity"])
    fetched = engine.get_hypothesis(hyp["id"], "org1")
    assert isinstance(fetched["data_sources"], list)
    assert "cloud" in fetched["data_sources"]


def test_get_hypothesis_wrong_org_returns_none(engine):
    hyp = _hyp(engine, org_id="orgA")
    result = engine.get_hypothesis(hyp["id"], "orgB")
    assert result is None


def test_list_hypotheses(engine):
    _hyp(engine, threat_category="lateral_movement")
    _hyp(engine, threat_category="exfiltration", mitre_technique="T1041")
    hyps = engine.list_hypotheses("org1")
    assert len(hyps) == 2


# ---------------------------------------------------------------------------
# 5. add_query
# ---------------------------------------------------------------------------


def test_add_query_basic(engine):
    hyp = _hyp(engine)
    q = _query(engine, hyp["id"])
    assert q["hypothesis_id"] == hyp["id"]
    assert q["execution_count"] == 0
    assert q["findings_count"] == 0
    assert q["avg_execution_secs"] == 0.0


def test_invalid_query_language_raises(engine):
    hyp = _hyp(engine)
    with pytest.raises(ValueError, match="query_language"):
        _query(engine, hyp["id"], query_language="COBOL")


def test_invalid_data_source_raises(engine):
    hyp = _hyp(engine)
    with pytest.raises(ValueError, match="data_source"):
        _query(engine, hyp["id"], data_source="mainframe")


# ---------------------------------------------------------------------------
# 6. execute_query — execution_count, avg, findings_count
# ---------------------------------------------------------------------------


def test_execute_query_increments_count(engine):
    hyp = _hyp(engine)
    q = _query(engine, hyp["id"])
    engine.execute_query(q["id"], "org1", records_scanned=1000, findings=5, execution_secs=2.0)
    updated = engine.get_query(q["id"], "org1")
    assert updated["execution_count"] == 1


def test_execute_query_accumulates_findings(engine):
    hyp = _hyp(engine)
    q = _query(engine, hyp["id"])
    engine.execute_query(q["id"], "org1", records_scanned=500, findings=3, execution_secs=1.0)
    engine.execute_query(q["id"], "org1", records_scanned=500, findings=7, execution_secs=1.0)
    updated = engine.get_query(q["id"], "org1")
    assert updated["findings_count"] == 10


def test_execute_query_rolling_avg_single(engine):
    hyp = _hyp(engine)
    q = _query(engine, hyp["id"])
    engine.execute_query(q["id"], "org1", records_scanned=100, findings=1, execution_secs=4.0)
    updated = engine.get_query(q["id"], "org1")
    assert abs(updated["avg_execution_secs"] - 4.0) < 0.001


def test_execute_query_rolling_avg_two(engine):
    hyp = _hyp(engine)
    q = _query(engine, hyp["id"])
    engine.execute_query(q["id"], "org1", records_scanned=100, findings=0, execution_secs=2.0)
    engine.execute_query(q["id"], "org1", records_scanned=100, findings=0, execution_secs=4.0)
    updated = engine.get_query(q["id"], "org1")
    # avg = ((0*0 + 2) + 4) / 2 → (2+4)/2 = 3.0  or rolling: ((2.0*1)+4.0)/2=3.0
    assert abs(updated["avg_execution_secs"] - 3.0) < 0.001


def test_execute_query_rolling_avg_three(engine):
    hyp = _hyp(engine)
    q = _query(engine, hyp["id"])
    for secs in [3.0, 6.0, 9.0]:
        engine.execute_query(q["id"], "org1", records_scanned=10, findings=0, execution_secs=secs)
    updated = engine.get_query(q["id"], "org1")
    # rolling: ((((3)*1)+6)/2=4.5, ((4.5*2)+9)/3=6.0
    assert abs(updated["avg_execution_secs"] - 6.0) < 0.01


def test_execute_query_returns_execution_record(engine):
    hyp = _hyp(engine)
    q = _query(engine, hyp["id"])
    exec_rec = engine.execute_query(q["id"], "org1", records_scanned=200, findings=2, execution_secs=1.5)
    assert exec_rec["status"] == "completed"
    assert exec_rec["findings"] == 2
    assert exec_rec["records_scanned"] == 200


def test_execute_query_wrong_org_raises(engine):
    hyp = _hyp(engine, org_id="orgA")
    q = _query(engine, hyp["id"], org_id="orgA")
    with pytest.raises(ValueError):
        engine.execute_query(q["id"], "orgB", records_scanned=0, findings=0, execution_secs=1.0)


# ---------------------------------------------------------------------------
# 7. fail_execution — no stat update
# ---------------------------------------------------------------------------


def test_fail_execution_status_failed(engine):
    hyp = _hyp(engine)
    q = _query(engine, hyp["id"])
    exec_rec = engine.fail_execution(q["id"], "org1", notes="Timeout")
    assert exec_rec["status"] == "failed"
    assert exec_rec["findings"] == 0


def test_fail_execution_does_not_increment_count(engine):
    hyp = _hyp(engine)
    q = _query(engine, hyp["id"])
    engine.fail_execution(q["id"], "org1", notes="Connection refused")
    updated = engine.get_query(q["id"], "org1")
    assert updated["execution_count"] == 0


def test_fail_execution_does_not_change_avg(engine):
    hyp = _hyp(engine)
    q = _query(engine, hyp["id"])
    engine.execute_query(q["id"], "org1", records_scanned=100, findings=1, execution_secs=5.0)
    engine.fail_execution(q["id"], "org1", notes="Error")
    updated = engine.get_query(q["id"], "org1")
    # avg should remain 5.0, count should remain 1
    assert updated["execution_count"] == 1
    assert abs(updated["avg_execution_secs"] - 5.0) < 0.001


def test_fail_execution_does_not_change_findings(engine):
    hyp = _hyp(engine)
    q = _query(engine, hyp["id"])
    engine.execute_query(q["id"], "org1", records_scanned=100, findings=3, execution_secs=1.0)
    engine.fail_execution(q["id"], "org1", notes="Error")
    updated = engine.get_query(q["id"], "org1")
    assert updated["findings_count"] == 3


# ---------------------------------------------------------------------------
# 8. get_hunt_summary
# ---------------------------------------------------------------------------


def test_summary_empty_org(engine):
    s = engine.get_hunt_summary("empty_org")
    assert s["total_hypotheses"] == 0
    assert s["validated_count"] == 0
    assert s["total_queries"] == 0
    assert s["total_findings"] == 0
    assert s["by_threat_category"] == {}
    assert s["top_queries"] == []


def test_summary_counts(engine):
    h1 = _hyp(engine, threat_category="lateral_movement")
    h2 = _hyp(engine, threat_category="exfiltration", mitre_technique="T1041")
    engine.validate_hypothesis(h1["id"], "org1", True, "confirmed")
    q1 = _query(engine, h1["id"])
    q2 = _query(engine, h2["id"])
    engine.execute_query(q1["id"], "org1", records_scanned=100, findings=5, execution_secs=1.0)
    engine.execute_query(q2["id"], "org1", records_scanned=200, findings=3, execution_secs=2.0)
    s = engine.get_hunt_summary("org1")
    assert s["total_hypotheses"] == 2
    assert s["validated_count"] == 1
    assert s["total_queries"] == 2
    assert s["total_findings"] == 8


def test_summary_by_threat_category(engine):
    _hyp(engine, threat_category="lateral_movement")
    _hyp(engine, threat_category="lateral_movement", mitre_technique="T1078")
    _hyp(engine, threat_category="exfiltration", mitre_technique="T1041")
    s = engine.get_hunt_summary("org1")
    assert s["by_threat_category"]["lateral_movement"] == 2
    assert s["by_threat_category"]["exfiltration"] == 1


def test_summary_top_queries_ordered(engine):
    hyp = _hyp(engine)
    q1 = _query(engine, hyp["id"], query_name="Q1")
    q2 = _query(engine, hyp["id"], query_name="Q2", query_language="SPL", data_source="edr")
    engine.execute_query(q1["id"], "org1", records_scanned=100, findings=10, execution_secs=1.0)
    engine.execute_query(q2["id"], "org1", records_scanned=100, findings=2, execution_secs=1.0)
    s = engine.get_hunt_summary("org1")
    assert s["top_queries"][0]["findings_count"] >= s["top_queries"][1]["findings_count"]


# ---------------------------------------------------------------------------
# 9. get_hypothesis_detail
# ---------------------------------------------------------------------------


def test_hypothesis_detail_includes_queries(engine):
    hyp = _hyp(engine)
    _query(engine, hyp["id"], query_name="Q1")
    _query(engine, hyp["id"], query_name="Q2", query_language="SPL", data_source="edr")
    detail = engine.get_hypothesis_detail(hyp["id"], "org1")
    assert len(detail["queries"]) == 2


def test_hypothesis_detail_includes_executions(engine):
    hyp = _hyp(engine)
    q = _query(engine, hyp["id"])
    for i in range(3):
        engine.execute_query(q["id"], "org1", records_scanned=i*100, findings=i, execution_secs=float(i+1))
    detail = engine.get_hypothesis_detail(hyp["id"], "org1")
    assert len(detail["queries"][0]["recent_executions"]) == 3


def test_hypothesis_detail_max_5_executions(engine):
    hyp = _hyp(engine)
    q = _query(engine, hyp["id"])
    for i in range(7):
        engine.execute_query(q["id"], "org1", records_scanned=100, findings=1, execution_secs=1.0)
    detail = engine.get_hypothesis_detail(hyp["id"], "org1")
    assert len(detail["queries"][0]["recent_executions"]) == 5


def test_hypothesis_detail_wrong_org_returns_none(engine):
    hyp = _hyp(engine, org_id="orgA")
    result = engine.get_hypothesis_detail(hyp["id"], "orgB")
    assert result is None


# ---------------------------------------------------------------------------
# 10. get_recent_executions
# ---------------------------------------------------------------------------


def test_recent_executions_includes_query_name(engine):
    hyp = _hyp(engine)
    q = _query(engine, hyp["id"], query_name="MyQuery")
    engine.execute_query(q["id"], "org1", records_scanned=100, findings=1, execution_secs=1.0)
    execs = engine.get_recent_executions("org1")
    assert execs[0]["query_name"] == "MyQuery"


def test_recent_executions_limit(engine):
    hyp = _hyp(engine)
    q = _query(engine, hyp["id"])
    for _ in range(5):
        engine.execute_query(q["id"], "org1", records_scanned=10, findings=0, execution_secs=0.5)
    execs = engine.get_recent_executions("org1", limit=3)
    assert len(execs) <= 3


def test_recent_executions_includes_failures(engine):
    hyp = _hyp(engine)
    q = _query(engine, hyp["id"])
    engine.fail_execution(q["id"], "org1", notes="network error")
    execs = engine.get_recent_executions("org1")
    assert any(e["status"] == "failed" for e in execs)


# ---------------------------------------------------------------------------
# 11. get_high_yield_queries
# ---------------------------------------------------------------------------


def test_high_yield_filters_by_min_findings(engine):
    hyp = _hyp(engine)
    q1 = _query(engine, hyp["id"], query_name="HighYield")
    q2 = _query(engine, hyp["id"], query_name="NoYield", query_language="SPL", data_source="edr")
    engine.execute_query(q1["id"], "org1", records_scanned=100, findings=5, execution_secs=1.0)
    # q2 has 0 findings
    high = engine.get_high_yield_queries("org1", min_findings=1)
    assert len(high) == 1
    assert high[0]["query_name"] == "HighYield"


def test_high_yield_ordered_by_findings_desc(engine):
    hyp = _hyp(engine)
    q1 = _query(engine, hyp["id"], query_name="Q1")
    q2 = _query(engine, hyp["id"], query_name="Q2", query_language="SPL", data_source="edr")
    engine.execute_query(q1["id"], "org1", records_scanned=100, findings=2, execution_secs=1.0)
    engine.execute_query(q2["id"], "org1", records_scanned=100, findings=8, execution_secs=1.0)
    high = engine.get_high_yield_queries("org1", min_findings=1)
    assert high[0]["findings_count"] >= high[1]["findings_count"]


def test_high_yield_min_findings_zero_returns_all(engine):
    hyp = _hyp(engine)
    _query(engine, hyp["id"], query_name="Q1")
    _query(engine, hyp["id"], query_name="Q2", query_language="SPL", data_source="edr")
    all_q = engine.get_high_yield_queries("org1", min_findings=0)
    assert len(all_q) == 2


# ---------------------------------------------------------------------------
# 12. Org isolation
# ---------------------------------------------------------------------------


def test_org_isolation_hypotheses(engine):
    _hyp(engine, org_id="orgA")
    _hyp(engine, org_id="orgB")
    sa = engine.get_hunt_summary("orgA")
    sb = engine.get_hunt_summary("orgB")
    assert sa["total_hypotheses"] == 1
    assert sb["total_hypotheses"] == 1


def test_org_isolation_executions(engine):
    h_a = _hyp(engine, org_id="orgA")
    q_a = _query(engine, h_a["id"], org_id="orgA")
    engine.execute_query(q_a["id"], "orgA", records_scanned=100, findings=5, execution_secs=1.0)
    execs_b = engine.get_recent_executions("orgB")
    assert len(execs_b) == 0


def test_org_isolation_high_yield(engine):
    h_a = _hyp(engine, org_id="orgA")
    q_a = _query(engine, h_a["id"], org_id="orgA")
    engine.execute_query(q_a["id"], "orgA", records_scanned=100, findings=10, execution_secs=1.0)
    high_b = engine.get_high_yield_queries("orgB", min_findings=1)
    assert len(high_b) == 0
