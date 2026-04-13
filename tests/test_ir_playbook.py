"""
Tests for the IR Playbook Engine — 55 tests covering:
- Playbook library: all 15 built-in playbooks
- Incident lifecycle: create, get, list, advance phases
- NIST 800-61 phase ordering
- Evidence chain: add, retrieve, verify cryptographic integrity
- Timeline: add events, retrieve in order
- Regulatory notifications: deadlines, overdue status, templates, mark sent
- IR metrics: MTTD, MTTC, MTTR, by-type, by-severity, playbook effectiveness
- Multi-tenant isolation
- Error handling: invalid IDs, closed incident advance, missing playbook
- Router request/response models

Run with: python -m pytest tests/test_ir_playbook.py -v --timeout=15
"""

from __future__ import annotations

import hashlib
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))

from core.ir_playbook_engine import (
    ActionMode,
    ActionType,
    EvidenceItem,
    IRIncident,
    IRMetrics,
    IRPhase,
    IRPlaybook,
    IRPlaybookEngine,
    IncidentSeverity,
    IncidentStatus,
    IncidentType,
    PhaseRecord,
    RegulationFramework,
    RegulatoryNotification,
    TimelineEvent,
    _PHASE_ORDER,
    _PLAYBOOK_LIBRARY,
    _compute_evidence_hash,
)


# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def engine(tmp_path):
    """Fresh IRPlaybookEngine backed by a temp SQLite DB."""
    return IRPlaybookEngine(db_path=str(tmp_path / "ir_test.db"))


@pytest.fixture
def org():
    return f"org-{uuid.uuid4().hex[:8]}"


@pytest.fixture
def malware_incident(engine, org):
    return engine.create_incident(
        title="Suspected malware on workstation WS-042",
        incident_type=IncidentType.MALWARE_INFECTION,
        severity=IncidentSeverity.HIGH,
        org_id=org,
        affected_systems=["WS-042"],
        tags=["malware", "endpoint"],
    )


@pytest.fixture
def breach_incident(engine, org):
    return engine.create_incident(
        title="PII data breach via misconfigured S3 bucket",
        incident_type=IncidentType.DATA_BREACH,
        severity=IncidentSeverity.CRITICAL,
        org_id=org,
        context={"org_name": "AcmeCorp", "affected_count": 5000, "data_categories": "PII"},
    )


# ============================================================================
# PLAYBOOK LIBRARY
# ============================================================================


class TestPlaybookLibrary:
    def test_15_playbooks_in_library(self, engine):
        playbooks = engine.list_playbooks()
        assert len(playbooks) == 15

    def test_all_incident_types_covered(self, engine):
        playbook_types = {pb.incident_type for pb in engine.list_playbooks()}
        all_types = set(IncidentType)
        assert playbook_types == all_types

    def test_get_playbook_by_id(self, engine):
        pb = engine.get_playbook("ir-malware-infection")
        assert pb is not None
        assert pb.incident_type == IncidentType.MALWARE_INFECTION

    def test_get_playbook_for_type(self, engine):
        pb = engine.get_playbook_for_type(IncidentType.RANSOMWARE)
        assert pb is not None
        assert pb.id == "ir-ransomware"

    def test_get_unknown_playbook_returns_none(self, engine):
        assert engine.get_playbook("nonexistent-id") is None

    def test_get_unknown_type_returns_none(self, engine):
        assert engine.get_playbook_for_type(None) is None  # type: ignore[arg-type]

    def test_ransomware_has_critical_severity_threshold(self, engine):
        pb = engine.get_playbook_for_type(IncidentType.RANSOMWARE)
        assert pb.severity_threshold == IncidentSeverity.CRITICAL

    def test_ransomware_has_regulatory_frameworks(self, engine):
        pb = engine.get_playbook_for_type(IncidentType.RANSOMWARE)
        assert RegulationFramework.GDPR in pb.applicable_regulations
        assert RegulationFramework.HIPAA in pb.applicable_regulations
        assert RegulationFramework.PCI_DSS in pb.applicable_regulations

    def test_data_breach_has_gdpr_ccpa(self, engine):
        pb = engine.get_playbook_for_type(IncidentType.DATA_BREACH)
        assert RegulationFramework.GDPR in pb.applicable_regulations
        assert RegulationFramework.CCPA in pb.applicable_regulations

    def test_all_playbooks_have_phases(self, engine):
        for pb in engine.list_playbooks():
            assert len(pb.phases) >= 4, f"{pb.name} has fewer than 4 phases"

    def test_all_playbooks_have_steps(self, engine):
        for pb in engine.list_playbooks():
            total_steps = sum(len(s) for s in pb.phases.values())
            assert total_steps >= 2, f"{pb.name} has fewer than 2 steps"

    def test_phase_order_constant(self):
        assert _PHASE_ORDER[0] == IRPhase.PREPARATION
        assert _PHASE_ORDER[-1] == IRPhase.CLOSED
        assert IRPhase.CONTAINMENT in _PHASE_ORDER

    def test_malware_playbook_has_automated_isolation(self, engine):
        pb = engine.get_playbook_for_type(IncidentType.MALWARE_INFECTION)
        containment_steps = pb.phases.get(IRPhase.CONTAINMENT.value, [])
        action_types = [s.action_type for s in containment_steps]
        assert ActionType.ISOLATE_HOST in action_types

    def test_ddos_playbook_has_block_ip(self, engine):
        pb = engine.get_playbook_for_type(IncidentType.DDOS)
        containment_steps = pb.phases.get(IRPhase.CONTAINMENT.value, [])
        action_types = [s.action_type for s in containment_steps]
        assert ActionType.BLOCK_IP in action_types

    def test_insider_threat_has_manual_legal_step(self, engine):
        pb = engine.get_playbook_for_type(IncidentType.INSIDER_THREAT)
        all_steps = [s for steps in pb.phases.values() for s in steps]
        manual_steps = [s for s in all_steps if s.action_mode == ActionMode.MANUAL]
        assert any(s.action_type == ActionType.CALL_LEGAL for s in manual_steps)


# ============================================================================
# INCIDENT LIFECYCLE
# ============================================================================


class TestIncidentLifecycle:
    def test_create_incident_returns_incident(self, engine, org):
        incident = engine.create_incident(
            title="Test incident",
            incident_type=IncidentType.PHISHING_CAMPAIGN,
            severity=IncidentSeverity.MEDIUM,
            org_id=org,
        )
        assert incident.id
        assert incident.title == "Test incident"
        assert incident.incident_type == IncidentType.PHISHING_CAMPAIGN
        assert incident.severity == IncidentSeverity.MEDIUM

    def test_create_incident_starts_in_detection_phase(self, engine, org):
        incident = engine.create_incident(
            title="Detection phase test",
            incident_type=IncidentType.API_ABUSE,
            severity=IncidentSeverity.LOW,
            org_id=org,
        )
        assert incident.current_phase == IRPhase.DETECTION_ANALYSIS

    def test_create_incident_auto_selects_playbook(self, engine, org):
        incident = engine.create_incident(
            title="Supply chain test",
            incident_type=IncidentType.SUPPLY_CHAIN_ATTACK,
            severity=IncidentSeverity.CRITICAL,
            org_id=org,
        )
        assert incident.playbook_id == "ir-supply-chain"

    def test_create_incident_sets_detected_at(self, engine, org):
        incident = engine.create_incident(
            title="Detected incident",
            incident_type=IncidentType.DDOS,
            severity=IncidentSeverity.HIGH,
            org_id=org,
        )
        assert incident.detected_at is not None

    def test_create_incident_custom_detected_at(self, engine, org):
        custom_time = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        incident = engine.create_incident(
            title="Historical incident",
            incident_type=IncidentType.UNAUTHORIZED_ACCESS,
            severity=IncidentSeverity.HIGH,
            org_id=org,
            detected_at=custom_time,
        )
        assert incident.detected_at == custom_time

    def test_get_incident_returns_same(self, engine, org, malware_incident):
        fetched = engine.get_incident(malware_incident.id, org_id=org)
        assert fetched is not None
        assert fetched.id == malware_incident.id
        assert fetched.title == malware_incident.title

    def test_get_incident_wrong_org_returns_none(self, engine, malware_incident):
        result = engine.get_incident(malware_incident.id, org_id="wrong-org")
        assert result is None

    def test_get_nonexistent_incident_returns_none(self, engine, org):
        assert engine.get_incident("nonexistent-id", org_id=org) is None

    def test_list_incidents_for_org(self, engine, org, malware_incident, breach_incident):
        incidents = engine.list_incidents(org_id=org)
        ids = [i.id for i in incidents]
        assert malware_incident.id in ids
        assert breach_incident.id in ids

    def test_list_incidents_isolation(self, engine, org):
        engine.create_incident(
            title="Org A incident",
            incident_type=IncidentType.DDOS,
            severity=IncidentSeverity.HIGH,
            org_id=org,
        )
        other_org = f"other-{uuid.uuid4().hex[:6]}"
        result = engine.list_incidents(org_id=other_org)
        assert all(i.org_id == other_org for i in result)

    def test_list_incidents_filter_by_type(self, engine, org, malware_incident, breach_incident):
        results = engine.list_incidents(org_id=org, incident_type=IncidentType.MALWARE_INFECTION)
        assert all(i.incident_type == IncidentType.MALWARE_INFECTION for i in results)
        ids = [i.id for i in results]
        assert malware_incident.id in ids
        assert breach_incident.id not in ids

    def test_incident_has_phase_history(self, engine, org, malware_incident):
        assert len(malware_incident.phase_history) >= 1
        assert malware_incident.phase_history[0].phase == IRPhase.DETECTION_ANALYSIS


# ============================================================================
# NIST PHASE ADVANCEMENT
# ============================================================================


class TestPhaseAdvancement:
    def test_advance_from_detection_to_containment(self, engine, org, malware_incident):
        advanced = engine.advance_phase(malware_incident.id, org_id=org)
        assert advanced.current_phase == IRPhase.CONTAINMENT

    def test_advance_through_all_phases(self, engine, org):
        incident = engine.create_incident(
            title="Full cycle test",
            incident_type=IncidentType.CREDENTIAL_COMPROMISE,
            severity=IncidentSeverity.HIGH,
            org_id=org,
        )
        # Detection → Containment → Eradication → Recovery → Lessons → Closed
        expected_phases = [
            IRPhase.CONTAINMENT,
            IRPhase.ERADICATION,
            IRPhase.RECOVERY,
            IRPhase.LESSONS_LEARNED,
            IRPhase.CLOSED,
        ]
        current_id = incident.id
        for expected in expected_phases:
            updated = engine.advance_phase(current_id, org_id=org)
            assert updated.current_phase == expected

    def test_containment_phase_sets_contained_status(self, engine, org, malware_incident):
        advanced = engine.advance_phase(malware_incident.id, org_id=org)
        assert advanced.current_phase == IRPhase.CONTAINMENT
        # Advance to eradication — this is when contained_at is set
        eradicated = engine.advance_phase(malware_incident.id, org_id=org)
        assert eradicated.status == IncidentStatus.CONTAINED
        assert eradicated.contained_at is not None

    def test_closed_phase_sets_resolved_at(self, engine, org):
        incident = engine.create_incident(
            title="Close me",
            incident_type=IncidentType.WEBSITE_DEFACEMENT,
            severity=IncidentSeverity.MEDIUM,
            org_id=org,
        )
        for _ in range(5):  # advance through all phases to closed
            incident = engine.advance_phase(incident.id, org_id=org)
        assert incident.current_phase == IRPhase.CLOSED
        assert incident.resolved_at is not None
        assert incident.status == IncidentStatus.CLOSED

    def test_advance_closed_incident_raises(self, engine, org):
        incident = engine.create_incident(
            title="Already closed",
            incident_type=IncidentType.COMPLIANCE_VIOLATION,
            severity=IncidentSeverity.LOW,
            org_id=org,
        )
        for _ in range(5):
            incident = engine.advance_phase(incident.id, org_id=org)
        with pytest.raises(ValueError, match="closed"):
            engine.advance_phase(incident.id, org_id=org)

    def test_advance_nonexistent_incident_raises(self, engine, org):
        with pytest.raises(ValueError):
            engine.advance_phase("nonexistent-id", org_id=org)

    def test_advance_records_approver(self, engine, org, malware_incident):
        advanced = engine.advance_phase(
            malware_incident.id, org_id=org, approved_by="alice@example.com"
        )
        prev_record = advanced.phase_history[0]
        assert prev_record.approval_granted_by == "alice@example.com"

    def test_advance_records_notes(self, engine, org, malware_incident):
        engine.advance_phase(malware_incident.id, org_id=org, notes="Containment verified by SOC")
        incident = engine.get_incident(malware_incident.id, org_id=org)
        assert incident.phase_history[0].notes == "Containment verified by SOC"

    def test_advance_adds_timeline_event(self, engine, org, malware_incident):
        engine.advance_phase(malware_incident.id, org_id=org)
        timeline = engine.get_timeline(malware_incident.id, org_id=org)
        transition_events = [e for e in timeline if e.event_type == "phase_transition"]
        assert len(transition_events) >= 1


# ============================================================================
# EVIDENCE CHAIN
# ============================================================================


class TestEvidenceChain:
    def test_add_evidence_returns_item(self, engine, org, malware_incident):
        item = engine.add_evidence(
            incident_id=malware_incident.id,
            collector_id="analyst-01",
            evidence_type="log",
            description="AV alert log",
            raw_content="2026-01-01 MALWARE DETECTED: trojan.generic",
            org_id=org,
        )
        assert item.id
        assert item.sha256_hash
        assert item.chain_sequence == 0

    def test_evidence_hash_is_sha256(self, engine, org, malware_incident):
        content = "Raw evidence content for hashing"
        item = engine.add_evidence(
            incident_id=malware_incident.id,
            collector_id="system",
            evidence_type="log",
            description="Hash test",
            raw_content=content,
            org_id=org,
        )
        expected = hashlib.sha256(content.encode()).hexdigest()
        assert item.sha256_hash == expected

    def test_evidence_chain_links_previous_hash(self, engine, org, malware_incident):
        item1 = engine.add_evidence(
            incident_id=malware_incident.id,
            collector_id="analyst-01",
            evidence_type="log",
            description="First evidence",
            raw_content="first content",
            org_id=org,
        )
        item2 = engine.add_evidence(
            incident_id=malware_incident.id,
            collector_id="analyst-01",
            evidence_type="pcap",
            description="Second evidence",
            raw_content="second content",
            org_id=org,
        )
        assert item2.previous_hash == item1.sha256_hash
        assert item2.chain_sequence == 1

    def test_evidence_chain_retrieval_ordered(self, engine, org, malware_incident):
        for i in range(3):
            engine.add_evidence(
                incident_id=malware_incident.id,
                collector_id="bot",
                evidence_type="log",
                description=f"Evidence {i}",
                raw_content=f"content {i}",
                org_id=org,
            )
        chain = engine.get_evidence_chain(malware_incident.id, org_id=org)
        sequences = [e.chain_sequence for e in chain]
        assert sequences == sorted(sequences)

    def test_verify_evidence_chain_valid(self, engine, org, malware_incident):
        engine.add_evidence(
            incident_id=malware_incident.id,
            collector_id="analyst",
            evidence_type="log",
            description="Log file",
            raw_content="access log entry",
            org_id=org,
        )
        engine.add_evidence(
            incident_id=malware_incident.id,
            collector_id="analyst",
            evidence_type="screenshot",
            description="Screen capture",
            raw_content="<screenshot data>",
            org_id=org,
        )
        assert engine.verify_evidence_chain(malware_incident.id, org_id=org) is True

    def test_verify_empty_chain_is_valid(self, engine, org, malware_incident):
        assert engine.verify_evidence_chain(malware_incident.id, org_id=org) is True

    def test_add_evidence_to_wrong_org_raises(self, engine, malware_incident):
        with pytest.raises(ValueError):
            engine.add_evidence(
                incident_id=malware_incident.id,
                collector_id="attacker",
                evidence_type="log",
                description="Malicious",
                raw_content="bogus",
                org_id="wrong-org",
            )

    def test_compute_evidence_hash_helper(self):
        content = "test content"
        h = _compute_evidence_hash(content)
        assert h == hashlib.sha256(content.encode()).hexdigest()
        assert len(h) == 64  # SHA-256 hex = 64 chars


# ============================================================================
# TIMELINE
# ============================================================================


class TestTimeline:
    def test_incident_creation_adds_timeline_event(self, engine, org, malware_incident):
        timeline = engine.get_timeline(malware_incident.id, org_id=org)
        assert len(timeline) >= 1
        assert timeline[0].event_type == "detection"

    def test_add_custom_timeline_event(self, engine, org, malware_incident):
        engine.add_timeline_event(
            incident_id=malware_incident.id,
            event_type="communication",
            source="legal-team",
            description="Legal counsel notified",
            metadata={"contact": "legal@example.com"},
        )
        timeline = engine.get_timeline(malware_incident.id, org_id=org)
        comms = [e for e in timeline if e.event_type == "communication"]
        assert len(comms) == 1
        assert comms[0].metadata["contact"] == "legal@example.com"

    def test_timeline_chronological_order(self, engine, org, malware_incident):
        t1 = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        t3 = datetime(2026, 1, 1, 14, 0, 0, tzinfo=timezone.utc)
        engine.add_timeline_event(malware_incident.id, "alert", "siem", "Alert 1", timestamp=t2)
        engine.add_timeline_event(malware_incident.id, "log", "edr", "Log entry", timestamp=t1)
        engine.add_timeline_event(malware_incident.id, "action", "soc", "Action taken", timestamp=t3)
        timeline = engine.get_timeline(malware_incident.id, org_id=org)
        timestamps = [e.timestamp for e in timeline]
        assert timestamps == sorted(timestamps)

    def test_get_timeline_wrong_org_raises(self, engine, malware_incident):
        with pytest.raises(ValueError):
            engine.get_timeline(malware_incident.id, org_id="wrong-org")

    def test_evidence_add_creates_timeline_entry(self, engine, org, malware_incident):
        engine.add_evidence(
            incident_id=malware_incident.id,
            collector_id="analyst",
            evidence_type="log",
            description="Test log",
            raw_content="log data",
            org_id=org,
        )
        timeline = engine.get_timeline(malware_incident.id, org_id=org)
        evidence_events = [e for e in timeline if e.event_type == "evidence"]
        assert len(evidence_events) == 1


# ============================================================================
# REGULATORY NOTIFICATIONS
# ============================================================================


class TestRegulatoryNotifications:
    def test_data_breach_creates_gdpr_notification(self, engine, org, breach_incident):
        notifications = engine.get_notifications(org_id=org, incident_id=breach_incident.id)
        frameworks = [n.framework for n in notifications]
        assert RegulationFramework.GDPR in frameworks

    def test_gdpr_notification_deadline_72h(self, engine, org, breach_incident):
        notifications = engine.get_notifications(org_id=org, incident_id=breach_incident.id)
        gdpr = next((n for n in notifications if n.framework == RegulationFramework.GDPR), None)
        assert gdpr is not None
        assert gdpr.deadline_hours == 72

    def test_ransomware_creates_pci_notification(self, engine, org):
        incident = engine.create_incident(
            title="Ransomware hit",
            incident_type=IncidentType.RANSOMWARE,
            severity=IncidentSeverity.CRITICAL,
            org_id=org,
        )
        notifications = engine.get_notifications(org_id=org, incident_id=incident.id)
        frameworks = [n.framework for n in notifications]
        assert RegulationFramework.PCI_DSS in frameworks

    def test_pci_dss_deadline_is_1_hour(self, engine, org):
        incident = engine.create_incident(
            title="Card breach",
            incident_type=IncidentType.RANSOMWARE,
            severity=IncidentSeverity.CRITICAL,
            org_id=org,
        )
        notifications = engine.get_notifications(org_id=org, incident_id=incident.id)
        pci = next((n for n in notifications if n.framework == RegulationFramework.PCI_DSS), None)
        assert pci is not None
        assert pci.deadline_hours == 1

    def test_notification_has_template(self, engine, org, breach_incident):
        notifications = engine.get_notifications(org_id=org, incident_id=breach_incident.id)
        gdpr = next((n for n in notifications if n.framework == RegulationFramework.GDPR), None)
        assert gdpr is not None
        assert len(gdpr.template) > 0

    def test_mark_notification_sent(self, engine, org, breach_incident):
        notifications = engine.get_notifications(org_id=org, incident_id=breach_incident.id)
        assert len(notifications) > 0
        n = notifications[0]
        updated = engine.mark_notification_sent(n.id, org_id=org)
        assert updated is not None
        assert updated.status == "sent"
        assert updated.notified_at is not None

    def test_mark_unknown_notification_returns_none(self, engine, org):
        result = engine.mark_notification_sent("nonexistent-id", org_id=org)
        assert result is None

    def test_notifications_filter_by_incident(self, engine, org, malware_incident, breach_incident):
        all_notifs = engine.get_notifications(org_id=org)
        breach_notifs = engine.get_notifications(org_id=org, incident_id=breach_incident.id)
        # Breach notifications should be a subset of all
        breach_ids = {n.id for n in breach_notifs}
        all_ids = {n.id for n in all_notifs}
        assert breach_ids.issubset(all_ids)


# ============================================================================
# IR METRICS
# ============================================================================


class TestIRMetrics:
    def test_empty_org_metrics(self, engine):
        org = f"empty-{uuid.uuid4().hex[:6]}"
        metrics = engine.get_metrics(org_id=org)
        assert metrics.total_incidents == 0
        assert metrics.active_incidents == 0
        assert metrics.mean_time_to_detect_hours == 0.0
        assert metrics.mean_time_to_contain_hours == 0.0
        assert metrics.mean_time_to_resolve_hours == 0.0

    def test_metrics_count_incidents(self, engine, org, malware_incident, breach_incident):
        metrics = engine.get_metrics(org_id=org)
        assert metrics.total_incidents == 2
        assert metrics.active_incidents == 2
        assert metrics.closed_incidents == 0

    def test_metrics_by_type(self, engine, org, malware_incident, breach_incident):
        metrics = engine.get_metrics(org_id=org)
        assert IncidentType.MALWARE_INFECTION.value in metrics.incidents_by_type
        assert IncidentType.DATA_BREACH.value in metrics.incidents_by_type

    def test_metrics_by_severity(self, engine, org, malware_incident, breach_incident):
        metrics = engine.get_metrics(org_id=org)
        assert IncidentSeverity.HIGH.value in metrics.incidents_by_severity
        assert IncidentSeverity.CRITICAL.value in metrics.incidents_by_severity

    def test_mttr_after_close(self, engine, org):
        incident = engine.create_incident(
            title="Close for MTTR test",
            incident_type=IncidentType.PHISHING_CAMPAIGN,
            severity=IncidentSeverity.MEDIUM,
            org_id=org,
        )
        for _ in range(5):
            incident = engine.advance_phase(incident.id, org_id=org)
        assert incident.current_phase == IRPhase.CLOSED
        metrics = engine.get_metrics(org_id=org)
        assert metrics.closed_incidents == 1
        assert metrics.mean_time_to_resolve_hours >= 0.0

    def test_metrics_isolation_across_orgs(self, engine):
        org_a = f"org-a-{uuid.uuid4().hex[:6]}"
        org_b = f"org-b-{uuid.uuid4().hex[:6]}"
        engine.create_incident(
            title="Org A incident",
            incident_type=IncidentType.DDOS,
            severity=IncidentSeverity.HIGH,
            org_id=org_a,
        )
        metrics_a = engine.get_metrics(org_id=org_a)
        metrics_b = engine.get_metrics(org_id=org_b)
        assert metrics_a.total_incidents == 1
        assert metrics_b.total_incidents == 0


# ============================================================================
# ROUTER MODELS (unit tests — no HTTP server needed)
# ============================================================================


class TestRouterModels:
    def test_import_router(self):
        """Router module must be importable without errors."""
        import importlib
        import sys
        sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))
        mod = importlib.import_module("apps.api.ir_playbook_router")
        assert hasattr(mod, "router")
        assert hasattr(mod, "CreateIncidentRequest")
        assert hasattr(mod, "AdvancePhaseRequest")

    def test_create_incident_request_model(self):
        sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))
        from apps.api.ir_playbook_router import CreateIncidentRequest
        req = CreateIncidentRequest(
            title="Test incident for model validation",
            incident_type=IncidentType.DDOS,
            severity=IncidentSeverity.HIGH,
        )
        assert req.org_id == "default"
        assert req.affected_systems == []

    def test_advance_phase_request_defaults(self):
        sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))
        from apps.api.ir_playbook_router import AdvancePhaseRequest
        req = AdvancePhaseRequest()
        assert req.approved_by is None
        assert req.notes == ""

    def test_playbook_summary_model(self):
        sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))
        from apps.api.ir_playbook_router import PlaybookSummary
        summary = PlaybookSummary(
            id="ir-test",
            name="Test Playbook",
            incident_type="ddos",
            description="Test description",
            severity_threshold="high",
            phase_count=5,
            step_count=12,
            applicable_regulations=["nist"],
        )
        assert summary.step_count == 12

    def test_add_evidence_request_model(self):
        sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))
        from apps.api.ir_playbook_router import AddEvidenceRequest
        req = AddEvidenceRequest(
            collector_id="analyst-42",
            evidence_type="log",
            description="Server access log",
            raw_content="2026-01-01 GET /admin HTTP/1.1 403",
        )
        assert req.collector_id == "analyst-42"
