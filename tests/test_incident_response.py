"""
Comprehensive tests for the Incident Response Playbook System.

Tests cover:
- Incident creation with auto-populated steps from all 8 playbook templates
- State machine status transitions (valid and invalid)
- Step assignment and completion
- Timeline event logging
- Finding and evidence linking
- Post-mortem creation and retrieval
- Incident statistics
- Active incident filtering
- Edge cases (not found, invalid transitions, duplicate links)

Run with: python -m pytest tests/test_incident_response.py -x --tb=short --timeout=10 -q
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

from core.incident_response import (
    IRStep,
    IRStepStatus,
    Incident,
    IncidentResponseManager,
    IncidentSeverity,
    IncidentStatus,
    IncidentType,
    PostMortem,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def manager(tmp_path):
    """Fresh IncidentResponseManager backed by a temporary SQLite database."""
    db_path = str(tmp_path / "ir_test.db")
    return IncidentResponseManager(db_path=db_path)


@pytest.fixture
def ransomware_incident(manager):
    """A RANSOMWARE / SEV1 incident for reuse across tests."""
    return manager.create_incident(
        title="Ransomware detected on prod-db-01",
        type=IncidentType.RANSOMWARE,
        severity=IncidentSeverity.SEV1,
        reported_by="alice@example.com",
        org_id="org-test",
    )


@pytest.fixture
def phishing_incident(manager):
    """A PHISHING / SEV2 incident."""
    return manager.create_incident(
        title="Phishing campaign targeting finance team",
        type=IncidentType.PHISHING,
        severity=IncidentSeverity.SEV2,
        reported_by="bob@example.com",
        org_id="org-test",
    )


# ============================================================================
# 1. Incident creation
# ============================================================================


class TestCreateIncident:
    def test_create_returns_incident_object(self, manager):
        inc = manager.create_incident(
            title="Test incident",
            type=IncidentType.MALWARE,
            severity=IncidentSeverity.SEV3,
            reported_by="analyst@example.com",
        )
        assert isinstance(inc, Incident)
        assert inc.id
        assert inc.title == "Test incident"
        assert inc.type == IncidentType.MALWARE
        assert inc.severity == IncidentSeverity.SEV3
        assert inc.status == IncidentStatus.DETECTED

    def test_create_auto_populates_steps(self, manager):
        inc = manager.create_incident(
            title="Breach",
            type=IncidentType.DATA_BREACH,
            severity=IncidentSeverity.SEV1,
            reported_by="soc@example.com",
        )
        assert len(inc.steps) == 7  # DATA_BREACH has 7 steps
        assert all(isinstance(s, IRStep) for s in inc.steps)
        assert all(s.status == IRStepStatus.PENDING for s in inc.steps)

    def test_create_initial_timeline_event(self, manager):
        inc = manager.create_incident(
            title="DDoS attack",
            type=IncidentType.DDOS,
            severity=IncidentSeverity.SEV2,
            reported_by="noc@example.com",
        )
        assert len(inc.timeline) == 1
        assert "created" in inc.timeline[0]["event"].lower()

    def test_create_persists_to_db(self, manager):
        inc = manager.create_incident(
            title="Stored incident",
            type=IncidentType.PHISHING,
            severity=IncidentSeverity.SEV3,
            reported_by="user@example.com",
        )
        fetched = manager.get_incident(inc.id)
        assert fetched is not None
        assert fetched.id == inc.id
        assert fetched.title == inc.title

    def test_create_sets_org_id(self, manager):
        inc = manager.create_incident(
            title="Org incident",
            type=IncidentType.MALWARE,
            severity=IncidentSeverity.SEV4,
            reported_by="user@example.com",
            org_id="org-xyz",
        )
        assert inc.org_id == "org-xyz"


# ============================================================================
# 2. Playbook templates
# ============================================================================


class TestPlaybookTemplates:
    @pytest.mark.parametrize("inc_type,expected_min_steps", [
        (IncidentType.DATA_BREACH, 7),
        (IncidentType.RANSOMWARE, 8),
        (IncidentType.CREDENTIAL_COMPROMISE, 6),
        (IncidentType.DDOS, 6),
        (IncidentType.MALWARE, 7),
        (IncidentType.INSIDER_THREAT, 7),
        (IncidentType.PHISHING, 6),
        (IncidentType.SUPPLY_CHAIN, 8),
    ])
    def test_all_templates_have_steps(self, manager, inc_type, expected_min_steps):
        steps = manager.get_playbook_template(inc_type)
        assert len(steps) >= expected_min_steps

    def test_template_steps_have_required_fields(self, manager):
        steps = manager.get_playbook_template(IncidentType.RANSOMWARE)
        for step in steps:
            assert step.name
            assert step.description
            assert step.order >= 1

    def test_template_steps_ordered_sequentially(self, manager):
        steps = manager.get_playbook_template(IncidentType.DATA_BREACH)
        orders = [s.order for s in steps]
        assert orders == sorted(orders)

    def test_all_8_incident_types_have_templates(self, manager):
        for inc_type in IncidentType:
            steps = manager.get_playbook_template(inc_type)
            assert len(steps) >= 5, f"{inc_type.value} template has fewer than 5 steps"


# ============================================================================
# 3. Get and list incidents
# ============================================================================


class TestGetListIncidents:
    def test_get_nonexistent_returns_none(self, manager):
        result = manager.get_incident("nonexistent-id")
        assert result is None

    def test_list_by_org_id(self, manager):
        manager.create_incident("A", IncidentType.MALWARE, IncidentSeverity.SEV2, "u", org_id="org-a")
        manager.create_incident("B", IncidentType.DDOS, IncidentSeverity.SEV3, "u", org_id="org-b")
        results = manager.list_incidents(org_id="org-a")
        assert len(results) == 1
        assert results[0].title == "A"

    def test_list_filter_by_status(self, manager, ransomware_incident):
        manager.update_status(ransomware_incident.id, IncidentStatus.TRIAGING)
        detected = manager.list_incidents(status_filter=IncidentStatus.DETECTED)
        triaging = manager.list_incidents(status_filter=IncidentStatus.TRIAGING)
        assert all(i.status == IncidentStatus.DETECTED for i in detected)
        assert any(i.id == ransomware_incident.id for i in triaging)

    def test_list_filter_by_severity(self, manager):
        manager.create_incident("S1", IncidentType.MALWARE, IncidentSeverity.SEV1, "u")
        manager.create_incident("S4", IncidentType.MALWARE, IncidentSeverity.SEV4, "u")
        sev1 = manager.list_incidents(severity_filter=IncidentSeverity.SEV1)
        assert all(i.severity == IncidentSeverity.SEV1 for i in sev1)


# ============================================================================
# 4. Status transitions (state machine)
# ============================================================================


class TestStatusTransitions:
    def test_valid_transition_detected_to_triaging(self, manager, ransomware_incident):
        updated = manager.update_status(ransomware_incident.id, IncidentStatus.TRIAGING)
        assert updated.status == IncidentStatus.TRIAGING

    def test_full_happy_path_transitions(self, manager, ransomware_incident):
        manager.update_status(ransomware_incident.id, IncidentStatus.TRIAGING)
        manager.update_status(ransomware_incident.id, IncidentStatus.CONTAINING)
        manager.update_status(ransomware_incident.id, IncidentStatus.ERADICATING)
        manager.update_status(ransomware_incident.id, IncidentStatus.RECOVERING)
        updated = manager.update_status(ransomware_incident.id, IncidentStatus.CLOSED)
        assert updated.status == IncidentStatus.CLOSED
        assert updated.closed_at is not None

    def test_invalid_transition_raises_value_error(self, manager, ransomware_incident):
        with pytest.raises(ValueError, match="Invalid transition"):
            manager.update_status(ransomware_incident.id, IncidentStatus.RECOVERING)

    def test_transition_adds_timeline_event(self, manager, ransomware_incident):
        initial_count = len(ransomware_incident.timeline)
        updated = manager.update_status(ransomware_incident.id, IncidentStatus.TRIAGING)
        assert len(updated.timeline) == initial_count + 1
        assert "triaging" in updated.timeline[-1]["event"].lower()

    def test_transition_nonexistent_incident_raises(self, manager):
        with pytest.raises(ValueError, match="not found"):
            manager.update_status("bad-id", IncidentStatus.TRIAGING)

    def test_closed_sets_closed_at(self, manager, phishing_incident):
        manager.update_status(phishing_incident.id, IncidentStatus.TRIAGING)
        manager.update_status(phishing_incident.id, IncidentStatus.CONTAINING)
        manager.update_status(phishing_incident.id, IncidentStatus.ERADICATING)
        manager.update_status(phishing_incident.id, IncidentStatus.RECOVERING)
        closed = manager.update_status(phishing_incident.id, IncidentStatus.CLOSED)
        assert closed.closed_at is not None

    def test_early_close_from_triaging(self, manager, ransomware_incident):
        manager.update_status(ransomware_incident.id, IncidentStatus.TRIAGING)
        closed = manager.update_status(ransomware_incident.id, IncidentStatus.CLOSED)
        assert closed.status == IncidentStatus.CLOSED


# ============================================================================
# 5. Step assignment and completion
# ============================================================================


class TestStepManagement:
    def test_assign_step_sets_assignee(self, manager, ransomware_incident):
        updated = manager.assign_step(ransomware_incident.id, 1, "alice@example.com")
        step = next(s for s in updated.steps if s.order == 1)
        assert step.assignee == "alice@example.com"

    def test_assign_step_sets_in_progress(self, manager, ransomware_incident):
        updated = manager.assign_step(ransomware_incident.id, 1, "responder@example.com")
        step = next(s for s in updated.steps if s.order == 1)
        assert step.status == IRStepStatus.IN_PROGRESS

    def test_assign_step_sets_started_at(self, manager, ransomware_incident):
        updated = manager.assign_step(ransomware_incident.id, 1, "responder@example.com")
        step = next(s for s in updated.steps if s.order == 1)
        assert step.started_at is not None

    def test_complete_step_marks_completed(self, manager, ransomware_incident):
        manager.assign_step(ransomware_incident.id, 1, "alice@example.com")
        updated = manager.complete_step(ransomware_incident.id, 1, notes="Done isolating")
        step = next(s for s in updated.steps if s.order == 1)
        assert step.status == IRStepStatus.COMPLETED
        assert step.completed_at is not None
        assert step.notes == "Done isolating"

    def test_complete_step_adds_timeline_event(self, manager, ransomware_incident):
        manager.assign_step(ransomware_incident.id, 2, "bob@example.com")
        initial_count = len(ransomware_incident.timeline)
        updated = manager.complete_step(ransomware_incident.id, 2)
        assert len(updated.timeline) > initial_count

    def test_assign_invalid_step_raises(self, manager, ransomware_incident):
        with pytest.raises(ValueError, match="Step 99 not found"):
            manager.assign_step(ransomware_incident.id, 99, "user@example.com")

    def test_complete_invalid_step_raises(self, manager, ransomware_incident):
        with pytest.raises(ValueError, match="Step 99 not found"):
            manager.complete_step(ransomware_incident.id, 99)

    def test_assign_nonexistent_incident_raises(self, manager):
        with pytest.raises(ValueError, match="not found"):
            manager.assign_step("bad-id", 1, "user@example.com")


# ============================================================================
# 6. Timeline events
# ============================================================================


class TestTimelineEvents:
    def test_add_timeline_event(self, manager, ransomware_incident):
        updated = manager.add_timeline_event(
            ransomware_incident.id,
            "Contacted FBI cyber division",
            "ciso@example.com",
        )
        last = updated.timeline[-1]
        assert last["event"] == "Contacted FBI cyber division"
        assert last["author"] == "ciso@example.com"
        assert "timestamp" in last

    def test_multiple_timeline_events_accumulate(self, manager, ransomware_incident):
        initial_count = len(ransomware_incident.timeline)
        manager.add_timeline_event(ransomware_incident.id, "Event 1", "user1")
        manager.add_timeline_event(ransomware_incident.id, "Event 2", "user2")
        updated = manager.get_incident(ransomware_incident.id)
        assert len(updated.timeline) == initial_count + 2

    def test_add_timeline_event_nonexistent_incident(self, manager):
        with pytest.raises(ValueError, match="not found"):
            manager.add_timeline_event("bad-id", "Some event", "user")


# ============================================================================
# 7. Finding and evidence linking
# ============================================================================


class TestLinking:
    def test_link_finding(self, manager, ransomware_incident):
        updated = manager.link_finding(ransomware_incident.id, "finding-001")
        assert "finding-001" in updated.findings_linked

    def test_link_finding_idempotent(self, manager, ransomware_incident):
        manager.link_finding(ransomware_incident.id, "finding-001")
        updated = manager.link_finding(ransomware_incident.id, "finding-001")
        assert updated.findings_linked.count("finding-001") == 1

    def test_link_multiple_findings(self, manager, ransomware_incident):
        manager.link_finding(ransomware_incident.id, "finding-001")
        updated = manager.link_finding(ransomware_incident.id, "finding-002")
        assert "finding-001" in updated.findings_linked
        assert "finding-002" in updated.findings_linked

    def test_link_evidence(self, manager, ransomware_incident):
        updated = manager.link_evidence(ransomware_incident.id, "evidence-abc")
        assert "evidence-abc" in updated.evidence_ids

    def test_link_evidence_idempotent(self, manager, ransomware_incident):
        manager.link_evidence(ransomware_incident.id, "evidence-abc")
        updated = manager.link_evidence(ransomware_incident.id, "evidence-abc")
        assert updated.evidence_ids.count("evidence-abc") == 1

    def test_link_finding_nonexistent_incident(self, manager):
        with pytest.raises(ValueError, match="not found"):
            manager.link_finding("bad-id", "finding-001")

    def test_link_evidence_nonexistent_incident(self, manager):
        with pytest.raises(ValueError, match="not found"):
            manager.link_evidence("bad-id", "evidence-001")


# ============================================================================
# 8. Post-mortem
# ============================================================================


def _close_incident(manager: IncidentResponseManager, incident: Incident) -> Incident:
    """Helper to advance an incident all the way to CLOSED."""
    manager.update_status(incident.id, IncidentStatus.TRIAGING)
    manager.update_status(incident.id, IncidentStatus.CONTAINING)
    manager.update_status(incident.id, IncidentStatus.ERADICATING)
    manager.update_status(incident.id, IncidentStatus.RECOVERING)
    return manager.update_status(incident.id, IncidentStatus.CLOSED)


class TestPostMortem:
    def test_create_post_mortem(self, manager, ransomware_incident):
        _close_incident(manager, ransomware_incident)
        pm = manager.create_post_mortem(
            incident_id=ransomware_incident.id,
            summary="Ransomware via phishing email",
            root_cause="Unpatched SMB vulnerability exploited after phishing",
            lessons=["Patch faster", "Improve phishing training"],
            action_items=[{"task": "Deploy EDR on all endpoints", "owner": "infra-team"}],
            author="ciso@example.com",
        )
        assert isinstance(pm, PostMortem)
        assert pm.incident_id == ransomware_incident.id
        assert len(pm.lessons_learned) == 2
        assert len(pm.action_items) == 1

    def test_get_post_mortem(self, manager, ransomware_incident):
        _close_incident(manager, ransomware_incident)
        manager.create_post_mortem(
            incident_id=ransomware_incident.id,
            summary="Summary",
            root_cause="Root cause",
            lessons=["Lesson 1"],
            action_items=[],
            author="author@example.com",
        )
        pm = manager.get_post_mortem(ransomware_incident.id)
        assert pm is not None
        assert pm.incident_id == ransomware_incident.id
        assert pm.summary == "Summary"

    def test_get_post_mortem_nonexistent_returns_none(self, manager):
        result = manager.get_post_mortem("nonexistent-id")
        assert result is None

    def test_post_mortem_advances_status(self, manager, ransomware_incident):
        _close_incident(manager, ransomware_incident)
        manager.create_post_mortem(
            incident_id=ransomware_incident.id,
            summary="S",
            root_cause="R",
            lessons=[],
            action_items=[],
            author="author@example.com",
        )
        updated = manager.get_incident(ransomware_incident.id)
        assert updated.status == IncidentStatus.POST_MORTEM

    def test_post_mortem_on_non_closed_incident_raises(self, manager, ransomware_incident):
        with pytest.raises(ValueError, match="CLOSED"):
            manager.create_post_mortem(
                incident_id=ransomware_incident.id,
                summary="Too early",
                root_cause="N/A",
                lessons=[],
                action_items=[],
                author="user@example.com",
            )

    def test_post_mortem_nonexistent_incident_raises(self, manager):
        with pytest.raises(ValueError, match="not found"):
            manager.create_post_mortem(
                incident_id="bad-id",
                summary="S",
                root_cause="R",
                lessons=[],
                action_items=[],
                author="user@example.com",
            )


# ============================================================================
# 9. Active incidents and statistics
# ============================================================================


class TestStatsAndActive:
    def test_get_active_incidents(self, manager):
        inc1 = manager.create_incident("A", IncidentType.MALWARE, IncidentSeverity.SEV1, "u", org_id="org-s")
        inc2 = manager.create_incident("B", IncidentType.DDOS, IncidentSeverity.SEV2, "u", org_id="org-s")
        _close_incident(manager, inc2)
        active = manager.get_active_incidents("org-s")
        ids = [i.id for i in active]
        assert inc1.id in ids
        assert inc2.id not in ids

    def test_stats_total_count(self, manager):
        for i in range(3):
            manager.create_incident(f"Inc {i}", IncidentType.PHISHING, IncidentSeverity.SEV3, "u", org_id="org-stat")
        stats = manager.get_incident_stats("org-stat")
        assert stats["total"] == 3

    def test_stats_by_type(self, manager):
        manager.create_incident("I1", IncidentType.MALWARE, IncidentSeverity.SEV2, "u", org_id="org-type")
        manager.create_incident("I2", IncidentType.MALWARE, IncidentSeverity.SEV2, "u", org_id="org-type")
        manager.create_incident("I3", IncidentType.DDOS, IncidentSeverity.SEV3, "u", org_id="org-type")
        stats = manager.get_incident_stats("org-type")
        assert stats["by_type"]["malware"] == 2
        assert stats["by_type"]["ddos"] == 1

    def test_stats_by_severity(self, manager):
        manager.create_incident("X", IncidentType.PHISHING, IncidentSeverity.SEV1, "u", org_id="org-sev")
        manager.create_incident("Y", IncidentType.PHISHING, IncidentSeverity.SEV1, "u", org_id="org-sev")
        manager.create_incident("Z", IncidentType.PHISHING, IncidentSeverity.SEV4, "u", org_id="org-sev")
        stats = manager.get_incident_stats("org-sev")
        assert stats["by_severity"]["sev1"] == 2
        assert stats["by_severity"]["sev4"] == 1

    def test_stats_avg_resolution_hours(self, manager):
        inc = manager.create_incident("R", IncidentType.RANSOMWARE, IncidentSeverity.SEV1, "u", org_id="org-res")
        _close_incident(manager, inc)
        stats = manager.get_incident_stats("org-res")
        assert stats["avg_resolution_hours"] is not None
        assert stats["avg_resolution_hours"] >= 0

    def test_stats_no_resolution_when_open(self, manager):
        manager.create_incident("O", IncidentType.MALWARE, IncidentSeverity.SEV2, "u", org_id="org-open")
        stats = manager.get_incident_stats("org-open")
        assert stats["avg_resolution_hours"] is None

    def test_stats_active_count(self, manager):
        inc = manager.create_incident("A", IncidentType.DDOS, IncidentSeverity.SEV2, "u", org_id="org-ac")
        _close_incident(manager, inc)
        manager.create_incident("B", IncidentType.DDOS, IncidentSeverity.SEV2, "u", org_id="org-ac")
        stats = manager.get_incident_stats("org-ac")
        assert stats["active_count"] == 1
