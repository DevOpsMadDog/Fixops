"""Tests for IRPlaybookEngine — 30 tests covering all public methods + org isolation."""

from __future__ import annotations

import pytest
from core.ir_playbook_engine import (
    EvidenceItem,
    IRIncident,
    IRPhase,
    IRPlaybookEngine,
    IncidentSeverity,
    IncidentStatus,
    IncidentType,
    RegulationFramework,
    TimelineEvent,
    _compute_evidence_hash,
)


@pytest.fixture
def engine(tmp_path):
    db = str(tmp_path / "ir_playbook_test.db")
    return IRPlaybookEngine(db_path=db)


@pytest.fixture
def org():
    return "org-alpha"


@pytest.fixture
def org2():
    return "org-beta"


def _make_incident(engine, org, incident_type=IncidentType.MALWARE_INFECTION,
                   severity=IncidentSeverity.HIGH, title="Test Incident"):
    return engine.create_incident(
        title=title,
        incident_type=incident_type,
        severity=severity,
        org_id=org,
        assigned_to="analyst@example.com",
        affected_systems=["server-01"],
        affected_users=["user@example.com"],
        tags=["test"],
    )


# ---------------------------------------------------------------------------
# list_playbooks / get_playbook / get_playbook_for_type
# ---------------------------------------------------------------------------

def test_list_playbooks_returns_15(engine):
    playbooks = engine.list_playbooks()
    assert len(playbooks) == 15


def test_get_playbook_by_id(engine):
    pb = engine.get_playbook("ir-malware-infection")
    assert pb is not None
    assert pb.incident_type == IncidentType.MALWARE_INFECTION


def test_get_playbook_not_found_returns_none(engine):
    assert engine.get_playbook("nonexistent-id") is None


def test_get_playbook_for_type_malware(engine):
    pb = engine.get_playbook_for_type(IncidentType.MALWARE_INFECTION)
    assert pb is not None
    assert pb.name == "Malware Infection Response"


def test_get_playbook_for_type_ransomware(engine):
    pb = engine.get_playbook_for_type(IncidentType.RANSOMWARE)
    assert pb is not None
    assert IncidentSeverity.CRITICAL == pb.severity_threshold


def test_get_playbook_for_type_data_breach_has_regulations(engine):
    pb = engine.get_playbook_for_type(IncidentType.DATA_BREACH)
    assert pb is not None
    assert RegulationFramework.GDPR in pb.applicable_regulations
    assert RegulationFramework.HIPAA in pb.applicable_regulations


# ---------------------------------------------------------------------------
# create_incident
# ---------------------------------------------------------------------------

def test_create_incident_returns_incident(engine, org):
    incident = _make_incident(engine, org)
    assert isinstance(incident, IRIncident)
    assert incident.id is not None
    assert incident.title == "Test Incident"
    assert incident.incident_type == IncidentType.MALWARE_INFECTION
    assert incident.severity == IncidentSeverity.HIGH
    assert incident.org_id == org
    assert incident.status == IncidentStatus.ACTIVE
    assert incident.current_phase == IRPhase.DETECTION_ANALYSIS


def test_create_incident_populates_playbook_id(engine, org):
    incident = _make_incident(engine, org)
    assert incident.playbook_id == "ir-malware-infection"


def test_create_incident_creates_regulatory_notifications_for_data_breach(engine, org):
    engine.create_incident(
        title="Data Breach",
        incident_type=IncidentType.DATA_BREACH,
        severity=IncidentSeverity.CRITICAL,
        org_id=org,
    )
    notifications = engine.get_notifications(org_id=org)
    assert len(notifications) > 0
    frameworks = {n.framework for n in notifications}
    assert RegulationFramework.GDPR in frameworks


def test_create_incident_creates_timeline_event(engine, org):
    incident = _make_incident(engine, org)
    timeline = engine.get_timeline(incident.id, org)
    assert len(timeline) >= 1
    types = {e.event_type for e in timeline}
    assert "detection" in types


def test_create_incident_all_types(engine, org):
    for inc_type in list(IncidentType)[:5]:
        inc = engine.create_incident(
            title=f"Test {inc_type.value}",
            incident_type=inc_type,
            severity=IncidentSeverity.MEDIUM,
            org_id=org,
        )
        assert inc.incident_type == inc_type


# ---------------------------------------------------------------------------
# get_incident / list_incidents
# ---------------------------------------------------------------------------

def test_get_incident_found(engine, org):
    incident = _make_incident(engine, org)
    fetched = engine.get_incident(incident.id, org)
    assert fetched is not None
    assert fetched.id == incident.id


def test_get_incident_not_found_returns_none(engine, org):
    assert engine.get_incident("nonexistent-id", org) is None


def test_get_incident_org_isolation(engine, org, org2):
    incident = _make_incident(engine, org)
    assert engine.get_incident(incident.id, org2) is None


def test_list_incidents_empty(engine, org):
    assert engine.list_incidents(org) == []


def test_list_incidents_returns_own_org(engine, org, org2):
    _make_incident(engine, org, title="Org1 incident")
    _make_incident(engine, org2, title="Org2 incident")
    org1_incidents = engine.list_incidents(org)
    assert len(org1_incidents) == 1
    assert org1_incidents[0].title == "Org1 incident"


def test_list_incidents_filter_by_type(engine, org):
    _make_incident(engine, org, incident_type=IncidentType.MALWARE_INFECTION)
    _make_incident(engine, org, incident_type=IncidentType.PHISHING_CAMPAIGN)
    malware = engine.list_incidents(org, incident_type=IncidentType.MALWARE_INFECTION)
    assert len(malware) == 1
    assert malware[0].incident_type == IncidentType.MALWARE_INFECTION


# ---------------------------------------------------------------------------
# advance_phase
# ---------------------------------------------------------------------------

def test_advance_phase_moves_to_containment(engine, org):
    incident = _make_incident(engine, org)
    updated = engine.advance_phase(incident.id, org, approved_by="manager", notes="Approved")
    assert updated.current_phase == IRPhase.CONTAINMENT
    # Status becomes CONTAINED only when advancing to ERADICATION phase
    assert updated.status == IncidentStatus.ACTIVE


def test_advance_phase_sequence(engine, org):
    incident = _make_incident(engine, org)
    expected_phases = [
        (IRPhase.CONTAINMENT, IncidentStatus.ACTIVE),
        (IRPhase.ERADICATION, IncidentStatus.CONTAINED),
        (IRPhase.RECOVERY, IncidentStatus.ERADICATED),
        (IRPhase.LESSONS_LEARNED, IncidentStatus.RECOVERING),
        (IRPhase.CLOSED, IncidentStatus.CLOSED),
    ]
    for expected_phase, expected_status in expected_phases:
        incident = engine.advance_phase(incident.id, org)
        assert incident.current_phase == expected_phase
        assert incident.status == expected_status


def test_advance_phase_closed_raises(engine, org):
    incident = _make_incident(engine, org)
    # Advance all the way to closed
    for _ in range(5):
        incident = engine.advance_phase(incident.id, org)
    with pytest.raises(ValueError, match="closed"):
        engine.advance_phase(incident.id, org)


def test_advance_phase_not_found_raises(engine, org):
    with pytest.raises(ValueError, match="not found"):
        engine.advance_phase("nonexistent-id", org)


def test_advance_phase_adds_timeline_event(engine, org):
    incident = _make_incident(engine, org)
    engine.advance_phase(incident.id, org)
    timeline = engine.get_timeline(incident.id, org)
    types = [e.event_type for e in timeline]
    assert "phase_transition" in types


# ---------------------------------------------------------------------------
# add_evidence / get_evidence_chain / verify_evidence_chain
# ---------------------------------------------------------------------------

def test_add_evidence_returns_evidence_item(engine, org):
    incident = _make_incident(engine, org)
    ev = engine.add_evidence(
        incident_id=incident.id,
        collector_id="analyst-01",
        evidence_type="network_logs",
        description="Captured network packets",
        raw_content="packet data here",
        org_id=org,
    )
    assert isinstance(ev, EvidenceItem)
    assert ev.incident_id == incident.id
    assert ev.sha256_hash is not None
    assert ev.chain_sequence == 0


def test_add_evidence_chain_sequence_increments(engine, org):
    incident = _make_incident(engine, org)
    ev1 = engine.add_evidence(incident.id, "analyst", "log", "First", "data1", org_id=org)
    ev2 = engine.add_evidence(incident.id, "analyst", "log", "Second", "data2", org_id=org)
    assert ev1.chain_sequence == 0
    assert ev2.chain_sequence == 1
    assert ev2.previous_hash == ev1.sha256_hash


def test_add_evidence_not_found_raises(engine, org):
    with pytest.raises(ValueError, match="not found"):
        engine.add_evidence("ghost-id", "analyst", "log", "test", "content", org_id=org)


def test_get_evidence_chain_ordered(engine, org):
    incident = _make_incident(engine, org)
    engine.add_evidence(incident.id, "a1", "log", "First", "content1", org_id=org)
    engine.add_evidence(incident.id, "a1", "log", "Second", "content2", org_id=org)
    engine.add_evidence(incident.id, "a1", "log", "Third", "content3", org_id=org)
    chain = engine.get_evidence_chain(incident.id, org)
    assert len(chain) == 3
    assert chain[0].chain_sequence == 0
    assert chain[1].chain_sequence == 1
    assert chain[2].chain_sequence == 2


def test_verify_evidence_chain_valid(engine, org):
    incident = _make_incident(engine, org)
    engine.add_evidence(incident.id, "a1", "log", "A", "content-a", org_id=org)
    engine.add_evidence(incident.id, "a1", "log", "B", "content-b", org_id=org)
    assert engine.verify_evidence_chain(incident.id, org) is True


def test_verify_evidence_chain_empty_returns_true(engine, org):
    incident = _make_incident(engine, org)
    assert engine.verify_evidence_chain(incident.id, org) is True


def test_compute_evidence_hash_deterministic():
    h1 = _compute_evidence_hash("same content")
    h2 = _compute_evidence_hash("same content")
    assert h1 == h2
    h3 = _compute_evidence_hash("different content")
    assert h1 != h3


# ---------------------------------------------------------------------------
# add_timeline_event / get_timeline
# ---------------------------------------------------------------------------

def test_add_timeline_event(engine, org):
    incident = _make_incident(engine, org)
    event = engine.add_timeline_event(
        incident_id=incident.id,
        event_type="alert",
        source="siem",
        description="IDS alert triggered",
        metadata={"rule": "SURICATA-1234"},
    )
    assert isinstance(event, TimelineEvent)
    assert event.incident_id == incident.id
    assert event.event_type == "alert"
    assert event.metadata["rule"] == "SURICATA-1234"


def test_get_timeline_chronological(engine, org):
    incident = _make_incident(engine, org)
    engine.add_timeline_event(incident.id, "alert", "siem", "Event A")
    engine.add_timeline_event(incident.id, "log", "server", "Event B")
    timeline = engine.get_timeline(incident.id, org)
    # Should include auto-created detection event + our 2 events
    assert len(timeline) >= 3
    # Verify chronological order
    timestamps = [e.timestamp for e in timeline]
    assert timestamps == sorted(timestamps)


def test_get_timeline_not_found_raises(engine, org):
    with pytest.raises(ValueError, match="not found"):
        engine.get_timeline("nonexistent-id", org)


# ---------------------------------------------------------------------------
# get_notifications / mark_notification_sent
# ---------------------------------------------------------------------------

def test_get_notifications_for_data_breach(engine, org):
    engine.create_incident(
        title="Data Breach Test",
        incident_type=IncidentType.DATA_BREACH,
        severity=IncidentSeverity.HIGH,
        org_id=org,
    )
    notifications = engine.get_notifications(org_id=org)
    assert len(notifications) > 0
    statuses = {n.status for n in notifications}
    # All should be pending or overdue (not yet sent)
    assert statuses <= {"pending", "overdue"}


def test_mark_notification_sent(engine, org):
    engine.create_incident(
        title="Breach for notification",
        incident_type=IncidentType.DATA_BREACH,
        severity=IncidentSeverity.CRITICAL,
        org_id=org,
    )
    notifications = engine.get_notifications(org_id=org)
    assert len(notifications) > 0
    n = notifications[0]
    updated = engine.mark_notification_sent(n.id, org)
    assert updated is not None
    assert updated.status == "sent"
    assert updated.notified_at is not None


def test_get_notifications_org_isolation(engine, org, org2):
    engine.create_incident(
        title="Org1 Breach",
        incident_type=IncidentType.DATA_BREACH,
        severity=IncidentSeverity.HIGH,
        org_id=org,
    )
    engine.create_incident(
        title="Org2 Breach",
        incident_type=IncidentType.DATA_BREACH,
        severity=IncidentSeverity.HIGH,
        org_id=org2,
    )
    n1 = engine.get_notifications(org_id=org)
    n2 = engine.get_notifications(org_id=org2)
    # Both orgs should have their own notifications
    assert len(n1) > 0
    assert len(n2) > 0
    # Notification incident_ids should not overlap
    ids1 = {n.incident_id for n in n1}
    ids2 = {n.incident_id for n in n2}
    assert ids1.isdisjoint(ids2)


# ---------------------------------------------------------------------------
# get_metrics
# ---------------------------------------------------------------------------

def test_get_metrics_empty(engine, org):
    metrics = engine.get_metrics(org)
    assert metrics.org_id == org
    assert metrics.total_incidents == 0
    assert metrics.active_incidents == 0
    assert metrics.closed_incidents == 0
    assert metrics.mean_time_to_detect_hours == 0.0
    assert metrics.incidents_by_type == {}


def test_get_metrics_with_incidents(engine, org):
    _make_incident(engine, org, incident_type=IncidentType.MALWARE_INFECTION, severity=IncidentSeverity.HIGH)
    _make_incident(engine, org, incident_type=IncidentType.PHISHING_CAMPAIGN, severity=IncidentSeverity.MEDIUM)
    metrics = engine.get_metrics(org)
    assert metrics.total_incidents == 2
    assert metrics.active_incidents == 2
    assert metrics.closed_incidents == 0
    assert "malware_infection" in metrics.incidents_by_type
    assert "phishing_campaign" in metrics.incidents_by_type
    assert "high" in metrics.incidents_by_severity


def test_get_metrics_org_isolation(engine, org, org2):
    _make_incident(engine, org)
    _make_incident(engine, org2)
    m1 = engine.get_metrics(org)
    m2 = engine.get_metrics(org2)
    assert m1.total_incidents == 1
    assert m2.total_incidents == 1
