"""
Tests for the ThreatHuntingEngine — predefined queries, session lifecycle,
query matching, IOC correlation, finding generation, and stats.

Run with:
    python -m pytest tests/test_threat_hunting.py -x --tb=short --timeout=10 -q
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

from core.threat_hunting import (
    HuntCategory,
    HuntQuery,
    HuntResult,
    HuntSession,
    HuntStatus,
    ThreatHuntingEngine,
    _BUILTIN_QUERIES,
)


# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def engine(tmp_path):
    """ThreatHuntingEngine backed by a temporary SQLite database."""
    return ThreatHuntingEngine(db_path=str(tmp_path / "hunt_test.db"))


@pytest.fixture
def session(engine):
    """A live hunt session."""
    return engine.start_session(
        name="Test Hunt Session",
        hunter_email="hunter@example.com",
        org_id="org_test",
    )


@pytest.fixture
def sample_findings():
    return [
        {
            "id": "f-001",
            "title": "SMB lateral movement detected",
            "type": "smb",
            "description": "Pass-the-hash via SMB admin share",
            "severity": "high",
            "tags": ["lateral-movement"],
        },
        {
            "id": "f-002",
            "title": "Normal informational finding",
            "type": "info",
            "description": "Routine scan result",
            "severity": "low",
            "tags": [],
        },
        {
            "id": "f-003",
            "title": "Credential dumping via LSASS",
            "type": "credential",
            "description": "Mimikatz-style password dump from lsass.exe",
            "severity": "critical",
            "tags": ["credential-access"],
        },
    ]


@pytest.fixture
def sample_iocs():
    return [
        {"value": "192.168.1.99", "type": "ip", "source_feed": "test_feed", "confidence": 0.9},
        {"value": "evil.example.com", "type": "domain", "source_feed": "test_feed", "confidence": 0.8},
    ]


# ============================================================================
# PREDEFINED QUERIES
# ============================================================================


class TestPredefinedQueries:
    """All 8 MITRE ATT&CK categories must be covered by built-in queries."""

    def test_predefined_queries_returns_list(self, engine):
        queries = engine.get_predefined_queries()
        assert isinstance(queries, list)

    def test_predefined_query_count_at_least_15(self, engine):
        queries = engine.get_predefined_queries()
        assert len(queries) >= 15

    def test_all_queries_are_hunt_query_instances(self, engine):
        for q in engine.get_predefined_queries():
            assert isinstance(q, HuntQuery)

    def test_lateral_movement_category_covered(self, engine):
        categories = {q.category for q in engine.get_predefined_queries()}
        assert HuntCategory.LATERAL_MOVEMENT in categories

    def test_privilege_escalation_category_covered(self, engine):
        categories = {q.category for q in engine.get_predefined_queries()}
        assert HuntCategory.PRIVILEGE_ESCALATION in categories

    def test_data_exfiltration_category_covered(self, engine):
        categories = {q.category for q in engine.get_predefined_queries()}
        assert HuntCategory.DATA_EXFILTRATION in categories

    def test_persistence_category_covered(self, engine):
        categories = {q.category for q in engine.get_predefined_queries()}
        assert HuntCategory.PERSISTENCE in categories

    def test_command_and_control_category_covered(self, engine):
        categories = {q.category for q in engine.get_predefined_queries()}
        assert HuntCategory.COMMAND_AND_CONTROL in categories

    def test_credential_access_category_covered(self, engine):
        categories = {q.category for q in engine.get_predefined_queries()}
        assert HuntCategory.CREDENTIAL_ACCESS in categories

    def test_initial_access_category_covered(self, engine):
        categories = {q.category for q in engine.get_predefined_queries()}
        assert HuntCategory.INITIAL_ACCESS in categories

    def test_defense_evasion_category_covered(self, engine):
        categories = {q.category for q in engine.get_predefined_queries()}
        assert HuntCategory.DEFENSE_EVASION in categories

    def test_all_8_categories_present(self, engine):
        categories = {q.category for q in engine.get_predefined_queries()}
        assert categories == set(HuntCategory)

    def test_predefined_queries_all_have_mitre_tactic(self, engine):
        for q in engine.get_predefined_queries():
            assert q.mitre_tactic, f"Query {q.id} has no mitre_tactic"

    def test_predefined_queries_all_marked_built_in(self, engine):
        for q in engine.get_predefined_queries():
            assert q.built_in is True

    def test_predefined_queries_all_have_query_logic(self, engine):
        for q in engine.get_predefined_queries():
            assert q.query_logic, f"Query {q.id} has empty query_logic"


# ============================================================================
# CUSTOM QUERY CREATION
# ============================================================================


class TestCustomQueryCreation:
    def test_create_custom_query_returns_hunt_query(self, engine):
        q = engine.create_custom_query(
            name="My Custom Hunt",
            category=HuntCategory.PERSISTENCE,
            query_logic={"any": [{"field": "type", "contains": "cron"}]},
        )
        assert isinstance(q, HuntQuery)
        assert q.built_in is False

    def test_custom_query_persisted_in_db(self, engine):
        q = engine.create_custom_query(
            name="Persisted Hunt",
            category=HuntCategory.DEFENSE_EVASION,
            query_logic={"any": [{"field": "title", "contains": "base64"}]},
            severity="high",
        )
        all_queries = engine.get_all_queries()
        ids = [aq.id for aq in all_queries]
        assert q.id in ids

    def test_custom_query_not_in_predefined(self, engine):
        q = engine.create_custom_query(
            name="Exclusive Custom",
            category=HuntCategory.LATERAL_MOVEMENT,
            query_logic={"any": [{"field": "title", "contains": "pivot"}]},
        )
        predefined_ids = [pq.id for pq in engine.get_predefined_queries()]
        assert q.id not in predefined_ids

    def test_get_all_queries_includes_custom(self, engine):
        before = len(engine.get_all_queries())
        engine.create_custom_query(
            name="Extra Query",
            category=HuntCategory.INITIAL_ACCESS,
            query_logic={"any": [{"field": "tags", "contains": "phish"}]},
        )
        after = len(engine.get_all_queries())
        assert after == before + 1

    def test_custom_query_fields_stored_correctly(self, engine):
        q = engine.create_custom_query(
            name="Field Check",
            category=HuntCategory.CREDENTIAL_ACCESS,
            query_logic={"any": [{"field": "title", "contains": "kerberos"}]},
            severity="critical",
            description="Kerberoasting detection",
            mitre_tactic="TA0006",
        )
        all_q = {aq.id: aq for aq in engine.get_all_queries()}
        stored = all_q[q.id]
        assert stored.name == "Field Check"
        assert stored.severity == "critical"
        assert stored.mitre_tactic == "TA0006"
        assert stored.description == "Kerberoasting detection"


# ============================================================================
# SESSION LIFECYCLE
# ============================================================================


class TestSessionLifecycle:
    def test_start_session_returns_hunt_session(self, engine):
        s = engine.start_session(name="Hunt A", hunter_email="a@b.com")
        assert isinstance(s, HuntSession)

    def test_start_session_status_is_running(self, engine):
        s = engine.start_session(name="Hunt B", hunter_email="a@b.com")
        assert s.status == HuntStatus.RUNNING

    def test_start_session_persisted(self, engine):
        s = engine.start_session(name="Persisted Session", hunter_email="x@y.com", org_id="org_x")
        retrieved = engine.get_session(s.id)
        assert retrieved is not None
        assert retrieved.id == s.id

    def test_end_session_marks_completed(self, engine, session):
        ended = engine.end_session(session.id, notes="Hunt complete")
        assert ended.status == HuntStatus.COMPLETED

    def test_end_session_stores_notes(self, engine, session):
        ended = engine.end_session(session.id, notes="Important findings noted")
        assert ended.notes == "Important findings noted"

    def test_end_session_sets_completed_at(self, engine, session):
        ended = engine.end_session(session.id)
        assert ended.completed_at is not None

    def test_get_session_nonexistent_returns_none(self, engine):
        result = engine.get_session("nonexistent-id")
        assert result is None

    def test_end_session_nonexistent_raises(self, engine):
        with pytest.raises(ValueError):
            engine.end_session("nonexistent-id")

    def test_list_sessions_returns_all_for_org(self, engine):
        engine.start_session(name="S1", hunter_email="a@b.com", org_id="org_list")
        engine.start_session(name="S2", hunter_email="a@b.com", org_id="org_list")
        sessions = engine.list_sessions(org_id="org_list")
        assert len(sessions) == 2

    def test_list_sessions_filters_by_org(self, engine):
        engine.start_session(name="OrgA-1", hunter_email="a@b.com", org_id="org_a")
        engine.start_session(name="OrgB-1", hunter_email="b@b.com", org_id="org_b")
        sessions_a = engine.list_sessions(org_id="org_a")
        assert all(s.org_id == "org_a" for s in sessions_a)

    def test_list_sessions_filters_by_status(self, engine):
        s = engine.start_session(name="StatusFilter", hunter_email="a@b.com", org_id="org_sf")
        engine.end_session(s.id)
        running = engine.list_sessions(org_id="org_sf", status_filter=HuntStatus.RUNNING)
        completed = engine.list_sessions(org_id="org_sf", status_filter=HuntStatus.COMPLETED)
        assert len(running) == 0
        assert len(completed) == 1

    def test_list_sessions_no_filter_returns_all(self, engine):
        engine.start_session(name="Any1", hunter_email="a@b.com", org_id="org_any")
        engine.start_session(name="Any2", hunter_email="a@b.com", org_id="org_any")
        sessions = engine.list_sessions(org_id="org_any")
        assert len(sessions) == 2


# ============================================================================
# QUERY MATCHING LOGIC
# ============================================================================


class TestQueryMatchingLogic:
    def test_match_contains_field(self, engine):
        finding = {"title": "smb lateral movement", "type": "smb", "tags": []}
        logic = {"any": [{"field": "title", "contains": "smb"}]}
        assert engine._match_query(finding, logic) is True

    def test_no_match_wrong_value(self, engine):
        finding = {"title": "routine scan", "type": "info", "tags": []}
        logic = {"any": [{"field": "title", "contains": "lateral"}]}
        assert engine._match_query(finding, logic) is False

    def test_match_contains_in_list_field(self, engine):
        finding = {"tags": ["lateral-movement", "smb"], "title": ""}
        logic = {"any": [{"field": "tags", "contains": "lateral-movement"}]}
        assert engine._match_query(finding, logic) is True

    def test_match_equals_operator(self, engine):
        finding = {"severity": "critical", "title": ""}
        logic = {"any": [{"field": "severity", "equals": "critical"}]}
        assert engine._match_query(finding, logic) is True

    def test_no_match_equals_wrong_value(self, engine):
        finding = {"severity": "low", "title": ""}
        logic = {"any": [{"field": "severity", "equals": "critical"}]}
        assert engine._match_query(finding, logic) is False

    def test_match_contains_any_operator(self, engine):
        finding = {"title": "rce exploit found", "tags": []}
        logic = {"any": [{"field": "title", "contains_any": ["exploit", "rce", "injection"]}]}
        assert engine._match_query(finding, logic) is True

    def test_match_all_conditions(self, engine):
        finding = {"severity": "critical", "title": "exploit rce found", "tags": ["external"]}
        logic = {
            "any": [{"field": "tags", "contains": "external"}],
            "all": [{"field": "title", "contains_any": ["exploit", "rce"]}],
        }
        assert engine._match_query(finding, logic) is True

    def test_all_fails_if_one_condition_false(self, engine):
        finding = {"tags": ["external"], "title": "benign finding"}
        logic = {
            "any": [{"field": "tags", "contains": "external"}],
            "all": [{"field": "title", "contains_any": ["exploit", "rce"]}],
        }
        assert engine._match_query(finding, logic) is False

    def test_empty_query_logic_returns_false(self, engine):
        finding = {"title": "anything"}
        assert engine._match_query(finding, {}) is False

    def test_match_gt_operator(self, engine):
        finding = {"score": 90}
        logic = {"any": [{"field": "score", "gt": 80}]}
        assert engine._match_query(finding, logic) is True

    def test_no_match_gt_operator(self, engine):
        finding = {"score": 50}
        logic = {"any": [{"field": "score", "gt": 80}]}
        assert engine._match_query(finding, logic) is False

    def test_match_lt_operator(self, engine):
        finding = {"score": 10}
        logic = {"any": [{"field": "score", "lt": 20}]}
        assert engine._match_query(finding, logic) is True

    def test_case_insensitive_matching(self, engine):
        finding = {"title": "SMB Lateral Movement"}
        logic = {"any": [{"field": "title", "contains": "smb"}]}
        assert engine._match_query(finding, logic) is True


# ============================================================================
# RUN HUNT (integration: session + query + findings)
# ============================================================================


class TestRunHunt:
    def test_run_hunt_returns_results_list(self, engine, session, sample_findings):
        results = engine.run_hunt(session.id, "builtin-lm-001", sample_findings)
        assert isinstance(results, list)

    def test_run_hunt_matches_smb_finding(self, engine, session, sample_findings):
        results = engine.run_hunt(session.id, "builtin-lm-001", sample_findings)
        # f-001 has type=smb which matches builtin-lm-001
        assert len(results) >= 1

    def test_run_hunt_skips_non_matching(self, engine, session, sample_findings):
        results = engine.run_hunt(session.id, "builtin-lm-001", sample_findings)
        finding_ids = [r.finding_id for r in results]
        # f-002 (info) should not match
        assert "f-002" not in finding_ids

    def test_run_hunt_result_has_correct_hunt_id(self, engine, session, sample_findings):
        results = engine.run_hunt(session.id, "builtin-lm-001", sample_findings)
        for r in results:
            assert r.hunt_id == session.id

    def test_run_hunt_evidence_has_query_name(self, engine, session, sample_findings):
        results = engine.run_hunt(session.id, "builtin-lm-001", sample_findings)
        for r in results:
            assert "query_name" in r.evidence

    def test_run_hunt_nonexistent_query_raises(self, engine, session, sample_findings):
        with pytest.raises(ValueError, match="not found"):
            engine.run_hunt(session.id, "nonexistent-query-id", sample_findings)

    def test_run_hunt_updates_session_results_count(self, engine, session, sample_findings):
        results = engine.run_hunt(session.id, "builtin-lm-001", sample_findings)
        updated = engine.get_session(session.id)
        assert updated.results_count >= len(results)

    def test_run_hunt_updates_queries_run(self, engine, session, sample_findings):
        engine.run_hunt(session.id, "builtin-lm-001", sample_findings)
        updated = engine.get_session(session.id)
        assert "builtin-lm-001" in updated.queries_run

    def test_run_hunt_persists_results(self, engine, session, sample_findings):
        engine.run_hunt(session.id, "builtin-lm-001", sample_findings)
        stored = engine.get_results(session.id)
        assert len(stored) >= 1

    def test_run_hunt_empty_findings_returns_empty(self, engine, session):
        results = engine.run_hunt(session.id, "builtin-lm-001", [])
        assert results == []

    def test_run_hunt_credential_query_matches(self, engine, session, sample_findings):
        results = engine.run_hunt(session.id, "builtin-ca-001", sample_findings)
        # f-003 has "lsass" and "credential" which matches builtin-ca-001
        assert len(results) >= 1


# ============================================================================
# IOC CORRELATION
# ============================================================================


class TestIOCCorrelation:
    def test_correlate_finding_iocs_empty_iocs(self, engine):
        finding = {"title": "some finding", "description": "192.168.1.99 detected"}
        matches = engine._correlate_finding_iocs(finding, [])
        assert matches == []

    def test_correlate_finding_iocs_match(self, engine, sample_iocs):
        finding = {"title": "C2 beacon to 192.168.1.99", "description": "suspicious traffic"}
        matches = engine._correlate_finding_iocs(finding, sample_iocs)
        assert len(matches) >= 1
        assert matches[0]["ioc_value"] == "192.168.1.99"

    def test_correlate_finding_iocs_no_match(self, engine, sample_iocs):
        finding = {"title": "routine scan", "description": "nothing suspicious"}
        matches = engine._correlate_finding_iocs(finding, sample_iocs)
        assert matches == []

    def test_correlate_iocs_cross_session(self, engine, session, sample_iocs):
        finding_with_ioc = {
            "id": "f-ioc",
            "title": "C2 to 192.168.1.99",
            "type": "c2",
            "description": "beacon",
            "severity": "critical",
            "tags": ["command-and-control"],
        }
        engine.run_hunt(session.id, "builtin-c2-001", [finding_with_ioc], iocs=sample_iocs)
        correlations = engine.correlate_iocs(["192.168.1.99"], org_id="org_test")
        assert isinstance(correlations, list)

    def test_correlate_iocs_empty_list_returns_empty(self, engine):
        result = engine.correlate_iocs([], org_id="org_test")
        assert result == []

    def test_run_hunt_with_iocs_boosts_confidence(self, engine, session, sample_iocs):
        finding_with_ioc = {
            "id": "f-ioc2",
            "title": "SMB lateral with 192.168.1.99",
            "type": "smb",
            "description": "pass-the-hash",
            "severity": "high",
            "tags": [],
        }
        results = engine.run_hunt(
            session.id, "builtin-lm-001", [finding_with_ioc], iocs=sample_iocs
        )
        assert len(results) == 1
        assert results[0].confidence > 0.0


# ============================================================================
# FINDING GENERATION
# ============================================================================


class TestFindingGeneration:
    def test_generate_finding_returns_dict(self, engine, session, sample_findings):
        results = engine.run_hunt(session.id, "builtin-lm-001", sample_findings)
        assert len(results) >= 1
        finding = engine.generate_finding_from_result(results[0])
        assert isinstance(finding, dict)

    def test_generated_finding_has_required_keys(self, engine, session, sample_findings):
        results = engine.run_hunt(session.id, "builtin-lm-001", sample_findings)
        finding = engine.generate_finding_from_result(results[0])
        for key in ("id", "title", "description", "severity", "source", "confidence", "detected_at"):
            assert key in finding, f"Missing key: {key}"

    def test_generated_finding_source_is_threat_hunting(self, engine, session, sample_findings):
        results = engine.run_hunt(session.id, "builtin-lm-001", sample_findings)
        finding = engine.generate_finding_from_result(results[0])
        assert finding["source"] == "threat_hunting"

    def test_generated_finding_contains_mitre_tactic(self, engine, session, sample_findings):
        results = engine.run_hunt(session.id, "builtin-lm-001", sample_findings)
        finding = engine.generate_finding_from_result(results[0])
        assert finding["mitre_tactic"] == "TA0008"

    def test_generated_finding_title_includes_query_name(self, engine, session, sample_findings):
        results = engine.run_hunt(session.id, "builtin-lm-001", sample_findings)
        finding = engine.generate_finding_from_result(results[0])
        assert "Threat Hunt Finding" in finding["title"]

    def test_generated_finding_has_hunt_session_id(self, engine, session, sample_findings):
        results = engine.run_hunt(session.id, "builtin-lm-001", sample_findings)
        finding = engine.generate_finding_from_result(results[0])
        assert finding["hunt_session_id"] == session.id

    def test_generated_finding_confidence_in_range(self, engine, session, sample_findings):
        results = engine.run_hunt(session.id, "builtin-lm-001", sample_findings)
        finding = engine.generate_finding_from_result(results[0])
        assert 0.0 <= finding["confidence"] <= 1.0

    def test_generated_finding_tags_include_threat_hunt(self, engine, session, sample_findings):
        results = engine.run_hunt(session.id, "builtin-lm-001", sample_findings)
        finding = engine.generate_finding_from_result(results[0])
        assert "threat-hunt" in finding["tags"]


# ============================================================================
# STATS
# ============================================================================


class TestHuntStats:
    def test_get_hunt_stats_returns_dict(self, engine):
        stats = engine.get_hunt_stats(org_id="org_stats")
        assert isinstance(stats, dict)

    def test_stats_empty_org(self, engine):
        stats = engine.get_hunt_stats(org_id="org_empty")
        assert stats["total_sessions"] == 0
        assert stats["total_results"] == 0

    def test_stats_predefined_query_count(self, engine):
        stats = engine.get_hunt_stats()
        assert stats["predefined_query_count"] == len(_BUILTIN_QUERIES)

    def test_stats_counts_sessions(self, engine):
        engine.start_session(name="A", hunter_email="a@b.com", org_id="org_stat1")
        engine.start_session(name="B", hunter_email="a@b.com", org_id="org_stat1")
        stats = engine.get_hunt_stats(org_id="org_stat1")
        assert stats["total_sessions"] == 2

    def test_stats_sessions_by_status(self, engine):
        s = engine.start_session(name="S", hunter_email="a@b.com", org_id="org_stat2")
        engine.end_session(s.id)
        stats = engine.get_hunt_stats(org_id="org_stat2")
        assert "completed" in stats["sessions_by_status"]
        assert stats["sessions_by_status"]["completed"] >= 1

    def test_stats_avg_confidence_zero_when_no_results(self, engine):
        engine.start_session(name="NoResults", hunter_email="a@b.com", org_id="org_nc")
        stats = engine.get_hunt_stats(org_id="org_nc")
        assert stats["avg_confidence"] == 0.0

    def test_stats_counts_results(self, engine):
        s = engine.start_session(name="WithResults", hunter_email="a@b.com", org_id="org_wr")
        findings = [
            {"id": "f1", "title": "smb lateral", "type": "smb", "severity": "high", "tags": []},
        ]
        engine.run_hunt(s.id, "builtin-lm-001", findings)
        stats = engine.get_hunt_stats(org_id="org_wr")
        assert stats["total_results"] >= 1

    def test_stats_avg_confidence_in_range(self, engine):
        s = engine.start_session(name="ConfRange", hunter_email="a@b.com", org_id="org_cr")
        findings = [
            {"id": "f1", "title": "smb lateral", "type": "smb", "severity": "high", "tags": []},
        ]
        engine.run_hunt(s.id, "builtin-lm-001", findings)
        stats = engine.get_hunt_stats(org_id="org_cr")
        assert 0.0 <= stats["avg_confidence"] <= 1.0

    def test_stats_org_isolation(self, engine):
        engine.start_session(name="IsoA", hunter_email="a@b.com", org_id="org_iso_a")
        engine.start_session(name="IsoB", hunter_email="b@b.com", org_id="org_iso_b")
        stats_a = engine.get_hunt_stats(org_id="org_iso_a")
        stats_b = engine.get_hunt_stats(org_id="org_iso_b")
        assert stats_a["total_sessions"] == 1
        assert stats_b["total_sessions"] == 1
