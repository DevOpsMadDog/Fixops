"""
Tests for the Purple Team Exercise Engine and REST API router.

Covers:
- Exercise lifecycle (create, start, pause, cancel, complete)
- 30+ scenario library (list, filter, get)
- Detection validation (record step results)
- Blue team response tracking
- Gap identification
- Scoring (detection rate, MTTD, coverage, red success rate)
- After-action report generation
- Router endpoints (via FastAPI TestClient)

Run with: python -m pytest tests/test_purple_team.py -v --timeout=15
"""

import os
import sys
import pytest

# Environment setup (mirrors other test files in this repo)
os.environ.setdefault("FIXOPS_MODE", "demo")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret-key-32-chars-minimum!!")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

sys.path.insert(0, str(os.path.join(os.path.dirname(__file__), "..", "suite-core")))
sys.path.insert(0, str(os.path.join(os.path.dirname(__file__), "..", "suite-api")))

# ---------------------------------------------------------------------------
# Engine imports
# ---------------------------------------------------------------------------

from core.purple_team import (
    AfterActionReport,
    ContainmentAction,
    DetectionEngine,
    DetectionGap,
    Exercise,
    ExerciseScores,
    ExerciseScope,
    ExerciseStatus,
    ExerciseStep,
    PurpleTeamEngine,
    ScenarioCategory,
    StepOutcome,
    MITRE_TECHNIQUES,
    SCENARIO_LIBRARY,
    get_purple_team_engine,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def engine():
    """Fresh engine instance for each test."""
    return PurpleTeamEngine()


@pytest.fixture()
def basic_exercise(engine):
    """A freshly created exercise using sc-001 (phishing to exfil)."""
    return engine.create_exercise(name="Test Exercise", scenario_id="sc-001")


@pytest.fixture()
def active_exercise(engine, basic_exercise):
    """Exercise in ACTIVE status."""
    return engine.start_exercise(basic_exercise.exercise_id)


@pytest.fixture()
def completed_exercise(engine, active_exercise):
    """Exercise with all steps recorded and then completed."""
    ex = active_exercise
    for step in ex.steps:
        detected = step.step_index % 2 == 0  # alternate detected/missed
        engine.record_step_result(
            ex.exercise_id,
            step.step_index,
            outcome=StepOutcome.DETECTED if detected else StepOutcome.EXECUTED,
            detected=detected,
            detection_engine=DetectionEngine.SIEM if detected else DetectionEngine.NONE,
            alert_fired=detected,
            time_to_detect_seconds=120.0 if detected else None,
        )
    return engine.complete_exercise(ex.exercise_id)


# ===========================================================================
# 1. MITRE Technique Registry
# ===========================================================================


class TestMitreTechniques:
    def test_registry_non_empty(self):
        assert len(MITRE_TECHNIQUES) >= 30

    def test_each_technique_has_required_fields(self):
        for tid, data in MITRE_TECHNIQUES.items():
            assert "name" in data, f"{tid} missing name"
            assert "tactic" in data, f"{tid} missing tactic"
            assert "severity" in data, f"{tid} missing severity"
            assert 0.0 <= data["severity"] <= 1.0, f"{tid} severity out of range"

    def test_known_techniques_present(self):
        for tid in ("T1566", "T1059", "T1021", "T1486", "T1195", "T1110"):
            assert tid in MITRE_TECHNIQUES


# ===========================================================================
# 2. Scenario Library
# ===========================================================================


class TestScenarioLibrary:
    def test_library_has_30_plus_scenarios(self):
        assert len(SCENARIO_LIBRARY) >= 30

    def test_each_scenario_has_required_fields(self):
        required = {"scenario_id", "name", "category", "description", "threat_actor",
                    "difficulty", "estimated_duration_minutes", "steps"}
        for s in SCENARIO_LIBRARY:
            missing = required - set(s.keys())
            assert not missing, f"{s['scenario_id']} missing: {missing}"

    def test_each_scenario_has_at_least_one_step(self):
        for s in SCENARIO_LIBRARY:
            assert len(s["steps"]) >= 1, f"{s['scenario_id']} has no steps"

    def test_scenario_ids_are_unique(self):
        ids = [s["scenario_id"] for s in SCENARIO_LIBRARY]
        assert len(ids) == len(set(ids))

    def test_categories_covered(self):
        categories = {
            s["category"].value if hasattr(s["category"], "value") else str(s["category"])
            for s in SCENARIO_LIBRARY
        }
        expected = {"ransomware", "supply_chain", "phishing_to_exfil",
                    "insider_threat", "cloud_breach"}
        assert expected.issubset(categories), f"Missing categories: {expected - categories}"

    def test_engine_list_scenarios_all(self, engine):
        result = engine.list_scenarios()
        assert len(result) >= 30

    def test_engine_list_scenarios_filter_category(self, engine):
        result = engine.list_scenarios(category="ransomware")
        assert all(s["category"] == "ransomware" for s in result)
        assert len(result) >= 2

    def test_engine_get_scenario_found(self, engine):
        s = engine.get_scenario("sc-001")
        assert s is not None
        assert s["scenario_id"] == "sc-001"

    def test_engine_get_scenario_not_found(self, engine):
        assert engine.get_scenario("sc-9999") is None

    def test_scenario_summary_has_techniques_list(self, engine):
        summaries = engine.list_scenarios()
        for s in summaries:
            assert "techniques" in s
            assert isinstance(s["techniques"], list)


# ===========================================================================
# 3. Exercise Lifecycle
# ===========================================================================


class TestExerciseLifecycle:
    def test_create_exercise_returns_exercise(self, engine):
        ex = engine.create_exercise(name="My Exercise", scenario_id="sc-005")
        assert isinstance(ex, Exercise)
        assert ex.exercise_id.startswith("ex-")
        assert ex.status == ExerciseStatus.DRAFT

    def test_create_exercise_populates_steps(self, engine):
        ex = engine.create_exercise(name="My Exercise", scenario_id="sc-001")
        assert len(ex.steps) > 0

    def test_create_exercise_steps_have_technique_info(self, engine):
        ex = engine.create_exercise(name="My Exercise", scenario_id="sc-001")
        for step in ex.steps:
            assert step.technique_id
            assert step.technique_name
            assert step.tactic
            assert 0.0 <= step.severity <= 1.0

    def test_create_exercise_invalid_scenario_raises(self, engine):
        with pytest.raises(ValueError, match="Scenario not found"):
            engine.create_exercise(name="Bad", scenario_id="sc-9999")

    def test_start_exercise_changes_status(self, engine, basic_exercise):
        ex = engine.start_exercise(basic_exercise.exercise_id)
        assert ex.status == ExerciseStatus.ACTIVE
        assert ex.started_at is not None

    def test_start_exercise_records_timestamp(self, engine, basic_exercise):
        ex = engine.start_exercise(basic_exercise.exercise_id)
        assert "T" in ex.started_at  # ISO-8601

    def test_cannot_start_already_active_exercise(self, engine, active_exercise):
        with pytest.raises(ValueError):
            engine.start_exercise(active_exercise.exercise_id)

    def test_pause_exercise(self, engine, active_exercise):
        ex = engine.pause_exercise(active_exercise.exercise_id)
        assert ex.status == ExerciseStatus.PAUSED

    def test_cannot_pause_non_active(self, engine, basic_exercise):
        with pytest.raises(ValueError):
            engine.pause_exercise(basic_exercise.exercise_id)

    def test_cancel_exercise(self, engine, basic_exercise):
        ex = engine.cancel_exercise(basic_exercise.exercise_id)
        assert ex.status == ExerciseStatus.CANCELLED

    def test_cannot_cancel_completed_exercise(self, engine, completed_exercise):
        with pytest.raises(ValueError):
            engine.cancel_exercise(completed_exercise.exercise_id)

    def test_exercise_not_found_raises_key_error(self, engine):
        with pytest.raises(KeyError):
            engine.start_exercise("ex-nonexistent")

    def test_list_exercises_empty_initially(self, engine):
        assert engine.list_exercises() == []

    def test_list_exercises_returns_created(self, engine):
        engine.create_exercise(name="A", scenario_id="sc-001")
        engine.create_exercise(name="B", scenario_id="sc-005")
        assert len(engine.list_exercises()) == 2

    def test_get_exercise_found(self, engine, basic_exercise):
        ex = engine.get_exercise(basic_exercise.exercise_id)
        assert ex is not None
        assert ex.exercise_id == basic_exercise.exercise_id

    def test_get_exercise_not_found(self, engine):
        assert engine.get_exercise("ex-missing") is None

    def test_complete_exercise_status(self, engine, active_exercise):
        ex = active_exercise
        for step in ex.steps:
            engine.record_step_result(
                ex.exercise_id, step.step_index,
                outcome=StepOutcome.EXECUTED, detected=False,
            )
        completed = engine.complete_exercise(ex.exercise_id)
        assert completed.status == ExerciseStatus.COMPLETED
        assert completed.completed_at is not None

    def test_exercise_scope_custom(self, engine):
        ex = engine.create_exercise(
            name="Cloud Exercise", scenario_id="sc-009", scope=ExerciseScope.CLOUD
        )
        assert ex.scope == ExerciseScope.CLOUD

    def test_exercise_tags_stored(self, engine):
        ex = engine.create_exercise(
            name="Tagged", scenario_id="sc-001", tags=["quarterly", "soc2"]
        )
        assert "quarterly" in ex.tags
        assert "soc2" in ex.tags


# ===========================================================================
# 4. Detection Validation
# ===========================================================================


class TestDetectionValidation:
    def test_record_step_detected(self, engine, active_exercise):
        ex = active_exercise
        step = engine.record_step_result(
            ex.exercise_id, 0,
            outcome=StepOutcome.DETECTED,
            detected=True,
            detection_engine=DetectionEngine.SIEM,
            alert_fired=True,
            time_to_detect_seconds=45.0,
            detection_notes="SIEM rule fired",
        )
        assert step.detected is True
        assert step.detection_engine == DetectionEngine.SIEM
        assert step.alert_fired is True
        assert step.time_to_detect_seconds == 45.0
        assert step.detection_notes == "SIEM rule fired"

    def test_record_step_missed(self, engine, active_exercise):
        ex = active_exercise
        step = engine.record_step_result(
            ex.exercise_id, 0,
            outcome=StepOutcome.EXECUTED,
            detected=False,
        )
        assert step.detected is False
        assert step.outcome == StepOutcome.EXECUTED

    def test_record_step_blocked(self, engine, active_exercise):
        ex = active_exercise
        step = engine.record_step_result(
            ex.exercise_id, 1,
            outcome=StepOutcome.BLOCKED,
            detected=True,
            detection_engine=DetectionEngine.EDR,
        )
        assert step.outcome == StepOutcome.BLOCKED
        assert step.detection_engine == DetectionEngine.EDR

    def test_record_step_sets_executed_at(self, engine, active_exercise):
        ex = active_exercise
        step = engine.record_step_result(
            ex.exercise_id, 0,
            outcome=StepOutcome.DETECTED,
            detected=True,
        )
        assert step.executed_at is not None

    def test_record_step_sets_detected_at_when_detected(self, engine, active_exercise):
        ex = active_exercise
        step = engine.record_step_result(
            ex.exercise_id, 0,
            outcome=StepOutcome.DETECTED,
            detected=True,
        )
        assert step.detected_at is not None

    def test_record_step_no_detected_at_when_missed(self, engine, active_exercise):
        ex = active_exercise
        step = engine.record_step_result(
            ex.exercise_id, 0,
            outcome=StepOutcome.EXECUTED,
            detected=False,
        )
        assert step.detected_at is None

    def test_record_step_invalid_step_index(self, engine, active_exercise):
        with pytest.raises(KeyError):
            engine.record_step_result(
                active_exercise.exercise_id, 999,
                outcome=StepOutcome.EXECUTED,
                detected=False,
            )

    def test_record_step_requires_active_exercise(self, engine, basic_exercise):
        with pytest.raises(ValueError, match="active"):
            engine.record_step_result(
                basic_exercise.exercise_id, 0,
                outcome=StepOutcome.EXECUTED,
                detected=False,
            )

    def test_multiple_detection_engines(self, engine, active_exercise):
        ex = active_exercise
        engines_to_test = [
            DetectionEngine.SIEM, DetectionEngine.EDR, DetectionEngine.NDR,
            DetectionEngine.ANOMALY, DetectionEngine.MANUAL,
        ]
        for i, det_engine in enumerate(engines_to_test[:len(ex.steps)]):
            step = engine.record_step_result(
                ex.exercise_id, i,
                outcome=StepOutcome.DETECTED,
                detected=True,
                detection_engine=det_engine,
            )
            assert step.detection_engine == det_engine


# ===========================================================================
# 5. Blue Team Response Tracking
# ===========================================================================


class TestBlueTeamResponse:
    def test_add_blue_team_action(self, engine, active_exercise):
        ex = active_exercise
        engine.record_step_result(
            ex.exercise_id, 0, outcome=StepOutcome.DETECTED, detected=True
        )
        bta = engine.add_blue_team_action(
            ex.exercise_id, 0,
            action=ContainmentAction.ISOLATE_HOST,
            actor="soc_analyst",
            description="Isolated endpoint after lateral movement detected",
            effective=True,
        )
        assert bta.action == ContainmentAction.ISOLATE_HOST
        assert bta.actor == "soc_analyst"
        assert bta.effective is True
        assert bta.action_id.startswith("act-")

    def test_blue_team_action_stored_on_step(self, engine, active_exercise):
        ex = active_exercise
        engine.record_step_result(ex.exercise_id, 0, outcome=StepOutcome.DETECTED, detected=True)
        engine.add_blue_team_action(ex.exercise_id, 0, action=ContainmentAction.BLOCK_IP)
        step = engine.get_exercise(ex.exercise_id).steps[0]
        assert len(step.blue_team_actions) == 1

    def test_blue_team_action_stored_on_exercise(self, engine, active_exercise):
        ex = active_exercise
        engine.record_step_result(ex.exercise_id, 0, outcome=StepOutcome.DETECTED, detected=True)
        engine.add_blue_team_action(ex.exercise_id, 0, action=ContainmentAction.DISABLE_ACCOUNT)
        ex_updated = engine.get_exercise(ex.exercise_id)
        assert len(ex_updated.blue_team_actions) == 1

    def test_multiple_actions_on_same_step(self, engine, active_exercise):
        ex = active_exercise
        engine.record_step_result(ex.exercise_id, 0, outcome=StepOutcome.DETECTED, detected=True)
        engine.add_blue_team_action(ex.exercise_id, 0, action=ContainmentAction.BLOCK_IP)
        engine.add_blue_team_action(ex.exercise_id, 0, action=ContainmentAction.FIREWALL_RULE)
        step = engine.get_exercise(ex.exercise_id).steps[0]
        assert len(step.blue_team_actions) == 2

    def test_blue_team_action_has_timestamp(self, engine, active_exercise):
        ex = active_exercise
        engine.record_step_result(ex.exercise_id, 0, outcome=StepOutcome.DETECTED, detected=True)
        bta = engine.add_blue_team_action(ex.exercise_id, 0, action=ContainmentAction.ESCALATE)
        assert bta.timestamp is not None
        assert "T" in bta.timestamp

    def test_all_containment_actions_accepted(self, engine, active_exercise):
        ex = active_exercise
        for i, action in enumerate(ContainmentAction):
            if i >= len(ex.steps):
                break
            engine.record_step_result(
                ex.exercise_id, i, outcome=StepOutcome.DETECTED, detected=True
            )
            bta = engine.add_blue_team_action(ex.exercise_id, i, action=action)
            assert bta.action == action


# ===========================================================================
# 6. Gap Identification
# ===========================================================================


class TestGapIdentification:
    def test_gaps_identified_for_missed_steps(self, engine, active_exercise):
        ex = active_exercise
        # Step 0: detected, Step 1: missed
        engine.record_step_result(ex.exercise_id, 0, outcome=StepOutcome.DETECTED, detected=True)
        engine.record_step_result(ex.exercise_id, 1, outcome=StepOutcome.EXECUTED, detected=False)
        gaps = engine.identify_gaps(ex.exercise_id)
        assert any(g.step_index == 1 for g in gaps)
        assert not any(g.step_index == 0 for g in gaps)

    def test_gap_has_priority(self, engine, active_exercise):
        ex = active_exercise
        engine.record_step_result(ex.exercise_id, 0, outcome=StepOutcome.EXECUTED, detected=False)
        gaps = engine.identify_gaps(ex.exercise_id)
        assert len(gaps) >= 1
        assert gaps[0].priority in ("critical", "high", "medium", "low")

    def test_gap_has_recommendation(self, engine, active_exercise):
        ex = active_exercise
        engine.record_step_result(ex.exercise_id, 0, outcome=StepOutcome.EXECUTED, detected=False)
        gaps = engine.identify_gaps(ex.exercise_id)
        assert len(gaps) >= 1
        assert len(gaps[0].recommended_detection) > 10

    def test_gap_has_affected_engine(self, engine, active_exercise):
        ex = active_exercise
        engine.record_step_result(ex.exercise_id, 0, outcome=StepOutcome.EXECUTED, detected=False)
        gaps = engine.identify_gaps(ex.exercise_id)
        assert gaps[0].affected_engine in ("siem", "edr", "ndr")

    def test_no_gaps_when_all_detected(self, engine, active_exercise):
        ex = active_exercise
        for step in ex.steps:
            engine.record_step_result(
                ex.exercise_id, step.step_index,
                outcome=StepOutcome.DETECTED, detected=True,
            )
        gaps = engine.identify_gaps(ex.exercise_id)
        assert gaps == []

    def test_gaps_stored_on_exercise_after_complete(self, engine, completed_exercise):
        # Some steps are missed in the completed_exercise fixture
        ex = engine.get_exercise(completed_exercise.exercise_id)
        assert isinstance(ex.detection_gaps, list)

    def test_gap_priority_critical_for_high_severity(self, engine):
        # Create engine and exercise using ransomware scenario (T1486 severity 0.95)
        ex = engine.create_exercise(name="Ransomware Test", scenario_id="sc-005")
        engine.start_exercise(ex.exercise_id)
        # Find T1486 step (encrypt files)
        for step in ex.steps:
            engine.record_step_result(
                ex.exercise_id, step.step_index,
                outcome=StepOutcome.EXECUTED, detected=False,
            )
        gaps = engine.identify_gaps(ex.exercise_id)
        critical_gaps = [g for g in gaps if g.priority == "critical"]
        # T1486 has severity 0.95 → critical
        assert len(critical_gaps) >= 1


# ===========================================================================
# 7. Scoring
# ===========================================================================


class TestScoring:
    def test_compute_scores_returns_exercise_scores(self, engine, active_exercise):
        ex = active_exercise
        for step in ex.steps:
            engine.record_step_result(
                ex.exercise_id, step.step_index,
                outcome=StepOutcome.EXECUTED, detected=False,
            )
        scores = engine.compute_scores(ex.exercise_id)
        assert isinstance(scores, ExerciseScores)

    def test_detection_rate_all_detected(self, engine, active_exercise):
        ex = active_exercise
        for step in ex.steps:
            engine.record_step_result(
                ex.exercise_id, step.step_index,
                outcome=StepOutcome.DETECTED, detected=True,
                time_to_detect_seconds=60.0,
            )
        scores = engine.compute_scores(ex.exercise_id)
        assert scores.blue_team_detection_rate == 1.0
        assert scores.red_team_success_rate == 0.0

    def test_detection_rate_none_detected(self, engine, active_exercise):
        ex = active_exercise
        for step in ex.steps:
            engine.record_step_result(
                ex.exercise_id, step.step_index,
                outcome=StepOutcome.EXECUTED, detected=False,
            )
        scores = engine.compute_scores(ex.exercise_id)
        assert scores.blue_team_detection_rate == 0.0
        assert scores.red_team_success_rate == 1.0

    def test_mttd_computed_correctly(self, engine, active_exercise):
        ex = active_exercise
        engine.record_step_result(
            ex.exercise_id, 0,
            outcome=StepOutcome.DETECTED, detected=True,
            time_to_detect_seconds=100.0,
        )
        engine.record_step_result(
            ex.exercise_id, 1,
            outcome=StepOutcome.DETECTED, detected=True,
            time_to_detect_seconds=200.0,
        )
        for step in ex.steps[2:]:
            engine.record_step_result(
                ex.exercise_id, step.step_index,
                outcome=StepOutcome.EXECUTED, detected=False,
            )
        scores = engine.compute_scores(ex.exercise_id)
        assert scores.mean_time_to_detect_seconds == 150.0

    def test_mttd_none_when_no_detections(self, engine, active_exercise):
        ex = active_exercise
        for step in ex.steps:
            engine.record_step_result(
                ex.exercise_id, step.step_index,
                outcome=StepOutcome.EXECUTED, detected=False,
            )
        scores = engine.compute_scores(ex.exercise_id)
        assert scores.mean_time_to_detect_seconds is None

    def test_block_rate_computed(self, engine, active_exercise):
        ex = active_exercise
        engine.record_step_result(
            ex.exercise_id, 0, outcome=StepOutcome.BLOCKED, detected=True,
        )
        for step in ex.steps[1:]:
            engine.record_step_result(
                ex.exercise_id, step.step_index,
                outcome=StepOutcome.EXECUTED, detected=False,
            )
        scores = engine.compute_scores(ex.exercise_id)
        assert scores.blue_team_block_rate > 0.0

    def test_scores_step_counts_accurate(self, engine, active_exercise):
        ex = active_exercise
        n = len(ex.steps)
        for i, step in enumerate(ex.steps):
            det = i < 2
            engine.record_step_result(
                ex.exercise_id, step.step_index,
                outcome=StepOutcome.DETECTED if det else StepOutcome.EXECUTED,
                detected=det,
            )
        scores = engine.compute_scores(ex.exercise_id)
        assert scores.steps_total == n
        assert scores.steps_executed == n
        assert scores.steps_detected == 2

    def test_technique_coverage_dict(self, engine, active_exercise):
        ex = active_exercise
        for step in ex.steps:
            engine.record_step_result(
                ex.exercise_id, step.step_index,
                outcome=StepOutcome.DETECTED, detected=True,
            )
        scores = engine.compute_scores(ex.exercise_id)
        assert isinstance(scores.technique_coverage, dict)
        assert len(scores.technique_coverage) == len(ex.steps)

    def test_coverage_score_between_0_and_1(self, engine, completed_exercise):
        scores = engine.compute_scores(completed_exercise.exercise_id)
        assert 0.0 <= scores.coverage_score <= 1.0


# ===========================================================================
# 8. After-Action Report
# ===========================================================================


class TestAfterActionReport:
    def test_generate_report_returns_report(self, engine, completed_exercise):
        report = engine.generate_report(completed_exercise.exercise_id)
        assert isinstance(report, AfterActionReport)

    def test_report_has_executive_summary(self, engine, completed_exercise):
        report = engine.generate_report(completed_exercise.exercise_id)
        assert len(report.executive_summary) > 50

    def test_report_references_exercise_name(self, engine, completed_exercise):
        report = engine.generate_report(completed_exercise.exercise_id)
        assert completed_exercise.name in report.executive_summary

    def test_report_has_scores(self, engine, completed_exercise):
        report = engine.generate_report(completed_exercise.exercise_id)
        assert isinstance(report.scores, ExerciseScores)

    def test_report_has_step_results(self, engine, completed_exercise):
        report = engine.generate_report(completed_exercise.exercise_id)
        assert len(report.step_results) > 0

    def test_report_has_detection_gaps(self, engine, completed_exercise):
        report = engine.generate_report(completed_exercise.exercise_id)
        assert isinstance(report.detection_gaps, list)

    def test_report_has_recommendations(self, engine, completed_exercise):
        report = engine.generate_report(completed_exercise.exercise_id)
        assert len(report.recommended_improvements) >= 1

    def test_report_has_tactic_coverage(self, engine, completed_exercise):
        report = engine.generate_report(completed_exercise.exercise_id)
        assert isinstance(report.tactic_coverage, dict)
        for tactic, data in report.tactic_coverage.items():
            assert "total" in data
            assert "detected" in data
            assert "detection_rate" in data

    def test_report_has_technique_results(self, engine, completed_exercise):
        report = engine.generate_report(completed_exercise.exercise_id)
        assert len(report.technique_results) > 0
        for tr in report.technique_results:
            assert "technique_id" in tr
            assert "outcome" in tr

    def test_report_has_unique_id(self, engine, completed_exercise):
        r1 = engine.generate_report(completed_exercise.exercise_id)
        assert r1.report_id.startswith("aar-")

    def test_report_requires_completed_exercise(self, engine, active_exercise):
        with pytest.raises(ValueError, match="completed"):
            engine.generate_report(active_exercise.exercise_id)

    def test_report_stored_and_retrievable(self, engine, completed_exercise):
        report = engine.generate_report(completed_exercise.exercise_id)
        fetched = engine.get_report(report.report_id)
        assert fetched is not None
        assert fetched.report_id == report.report_id

    def test_list_reports(self, engine, completed_exercise):
        engine.generate_report(completed_exercise.exercise_id)
        reports = engine.list_reports()
        assert len(reports) >= 1

    def test_low_detection_rate_triggers_recommendation(self, engine):
        # All steps missed → detection rate 0 → recommendation added
        ex = engine.create_exercise(name="Zero Detection", scenario_id="sc-001")
        engine.start_exercise(ex.exercise_id)
        for step in ex.steps:
            engine.record_step_result(
                ex.exercise_id, step.step_index,
                outcome=StepOutcome.EXECUTED, detected=False,
            )
        engine.complete_exercise(ex.exercise_id)
        report = engine.generate_report(ex.exercise_id)
        low_det_recs = [
            r for r in report.recommended_improvements if "50%" in r or "Detection rate" in r
        ]
        assert len(low_det_recs) >= 1


# ===========================================================================
# 9. Singleton Accessor
# ===========================================================================


class TestSingleton:
    def test_get_engine_returns_same_instance(self):
        e1 = get_purple_team_engine()
        e2 = get_purple_team_engine()
        assert e1 is e2

    def test_get_engine_returns_purple_team_engine(self):
        engine = get_purple_team_engine()
        assert isinstance(engine, PurpleTeamEngine)


# ===========================================================================
# 10. Router / API Endpoints
# ===========================================================================


class TestPurpleTeamRouter:
    @pytest.fixture(autouse=True)
    def _setup_client(self):
        """Build a minimal FastAPI app with the purple team router mounted."""
        from fastapi import FastAPI
        from fastapi.testclient import TestClient
        from apps.api import purple_team_router as ptr_module
        from apps.api.auth_deps import api_key_auth

        app = FastAPI()
        app.include_router(ptr_module.router)

        # Override auth to be a no-op for all tests
        app.dependency_overrides[api_key_auth] = lambda: None

        self.client = TestClient(app)
        self.engine = get_purple_team_engine()
        yield
        app.dependency_overrides.clear()

    def test_list_scenarios_returns_30_plus(self):
        resp = self.client.get("/api/v1/purple-team/scenarios")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) >= 30

    def test_list_scenarios_filter_by_category(self):
        resp = self.client.get("/api/v1/purple-team/scenarios?category=ransomware")
        assert resp.status_code == 200
        data = resp.json()
        assert all(s["category"] == "ransomware" for s in data)

    def test_create_exercise_endpoint(self):
        resp = self.client.post(
            "/api/v1/purple-team/exercises",
            json={"name": "API Test Exercise", "scenario_id": "sc-003"},
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "API Test Exercise"
        assert "exercise_id" in data
        assert len(data["steps"]) > 0

    def test_create_exercise_invalid_scenario(self):
        resp = self.client.post(
            "/api/v1/purple-team/exercises",
            json={"name": "Bad", "scenario_id": "sc-9999"},
        )
        assert resp.status_code == 404

    def test_list_exercises_endpoint(self):
        # Create one first
        self.client.post(
            "/api/v1/purple-team/exercises",
            json={"name": "List Test", "scenario_id": "sc-001"},
        )
        resp = self.client.get("/api/v1/purple-team/exercises")
        assert resp.status_code == 200
        assert isinstance(resp.json(), list)

    def test_get_exercise_endpoint(self):
        create_resp = self.client.post(
            "/api/v1/purple-team/exercises",
            json={"name": "Get Test", "scenario_id": "sc-005"},
        )
        ex_id = create_resp.json()["exercise_id"]
        resp = self.client.get(f"/api/v1/purple-team/exercises/{ex_id}")
        assert resp.status_code == 200
        assert resp.json()["exercise_id"] == ex_id

    def test_get_exercise_not_found(self):
        resp = self.client.get("/api/v1/purple-team/exercises/ex-nonexistent")
        assert resp.status_code == 404

    def test_run_exercise_endpoint(self):
        create_resp = self.client.post(
            "/api/v1/purple-team/exercises",
            json={"name": "Run Test", "scenario_id": "sc-009"},
        )
        ex_id = create_resp.json()["exercise_id"]
        resp = self.client.post(f"/api/v1/purple-team/exercises/{ex_id}/run")
        assert resp.status_code == 200
        assert resp.json()["status"] == "active"

    def test_run_exercise_conflict(self):
        create_resp = self.client.post(
            "/api/v1/purple-team/exercises",
            json={"name": "Conflict Test", "scenario_id": "sc-001"},
        )
        ex_id = create_resp.json()["exercise_id"]
        self.client.post(f"/api/v1/purple-team/exercises/{ex_id}/run")
        # Start again → should 409
        resp = self.client.post(f"/api/v1/purple-team/exercises/{ex_id}/run")
        assert resp.status_code == 409

    def test_record_step_endpoint(self):
        create_resp = self.client.post(
            "/api/v1/purple-team/exercises",
            json={"name": "Step Test", "scenario_id": "sc-001"},
        )
        ex_id = create_resp.json()["exercise_id"]
        self.client.post(f"/api/v1/purple-team/exercises/{ex_id}/run")

        resp = self.client.post(
            f"/api/v1/purple-team/exercises/{ex_id}/steps/0",
            json={
                "outcome": "detected",
                "detected": True,
                "detection_engine": "siem",
                "alert_fired": True,
                "time_to_detect_seconds": 90.0,
                "detection_notes": "SIEM rule matched",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["detected"] is True
        assert data["alert_fired"] is True

    def test_blue_team_response_endpoint(self):
        create_resp = self.client.post(
            "/api/v1/purple-team/exercises",
            json={"name": "BTA Test", "scenario_id": "sc-001"},
        )
        ex_id = create_resp.json()["exercise_id"]
        self.client.post(f"/api/v1/purple-team/exercises/{ex_id}/run")
        self.client.post(
            f"/api/v1/purple-team/exercises/{ex_id}/steps/0",
            json={"outcome": "detected", "detected": True},
        )
        resp = self.client.post(
            f"/api/v1/purple-team/exercises/{ex_id}/response",
            json={
                "step_index": 0,
                "action": "isolate_host",
                "actor": "soc_l1",
                "description": "Isolated the host immediately",
                "effective": True,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["action"] == "isolate_host"
        assert data["actor"] == "soc_l1"

    def test_complete_exercise_endpoint(self):
        create_resp = self.client.post(
            "/api/v1/purple-team/exercises",
            json={"name": "Complete Test", "scenario_id": "sc-002"},
        )
        ex_id = create_resp.json()["exercise_id"]
        ex_data = create_resp.json()
        self.client.post(f"/api/v1/purple-team/exercises/{ex_id}/run")
        # Record results for all steps
        for step in ex_data["steps"]:
            self.client.post(
                f"/api/v1/purple-team/exercises/{ex_id}/steps/{step['step_index']}",
                json={"outcome": "executed", "detected": False},
            )
        resp = self.client.post(f"/api/v1/purple-team/exercises/{ex_id}/complete")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "completed"
        assert data["scores"] is not None

    def test_get_report_endpoint(self):
        create_resp = self.client.post(
            "/api/v1/purple-team/exercises",
            json={"name": "Report Test", "scenario_id": "sc-007"},
        )
        ex_id = create_resp.json()["exercise_id"]
        ex_data = create_resp.json()
        self.client.post(f"/api/v1/purple-team/exercises/{ex_id}/run")
        for step in ex_data["steps"]:
            self.client.post(
                f"/api/v1/purple-team/exercises/{ex_id}/steps/{step['step_index']}",
                json={"outcome": "executed", "detected": False},
            )
        self.client.post(f"/api/v1/purple-team/exercises/{ex_id}/complete")
        resp = self.client.get(f"/api/v1/purple-team/exercises/{ex_id}/report")
        assert resp.status_code == 200
        data = resp.json()
        assert "executive_summary" in data
        assert "scores" in data
        assert "detection_gaps" in data
        assert "recommended_improvements" in data
        assert "tactic_coverage" in data

    def test_get_report_requires_completed_exercise(self):
        create_resp = self.client.post(
            "/api/v1/purple-team/exercises",
            json={"name": "Not Done", "scenario_id": "sc-001"},
        )
        ex_id = create_resp.json()["exercise_id"]
        resp = self.client.get(f"/api/v1/purple-team/exercises/{ex_id}/report")
        assert resp.status_code == 409

    def test_list_exercises_filter_by_status(self):
        create_resp = self.client.post(
            "/api/v1/purple-team/exercises",
            json={"name": "Filter Test", "scenario_id": "sc-001"},
        )
        ex_id = create_resp.json()["exercise_id"]
        self.client.post(f"/api/v1/purple-team/exercises/{ex_id}/run")

        resp = self.client.get("/api/v1/purple-team/exercises?status=active")
        assert resp.status_code == 200
        data = resp.json()
        assert all(e["status"] == "active" for e in data)

    def test_invalid_outcome_returns_422(self):
        create_resp = self.client.post(
            "/api/v1/purple-team/exercises",
            json={"name": "Invalid Test", "scenario_id": "sc-001"},
        )
        ex_id = create_resp.json()["exercise_id"]
        self.client.post(f"/api/v1/purple-team/exercises/{ex_id}/run")
        resp = self.client.post(
            f"/api/v1/purple-team/exercises/{ex_id}/steps/0",
            json={"outcome": "INVALID_OUTCOME", "detected": False},
        )
        assert resp.status_code == 422

    def test_invalid_action_returns_422(self):
        create_resp = self.client.post(
            "/api/v1/purple-team/exercises",
            json={"name": "Invalid Action Test", "scenario_id": "sc-001"},
        )
        ex_id = create_resp.json()["exercise_id"]
        resp = self.client.post(
            f"/api/v1/purple-team/exercises/{ex_id}/response",
            json={"step_index": 0, "action": "INVALID_ACTION"},
        )
        assert resp.status_code == 422
