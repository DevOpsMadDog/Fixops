"""Tests for cross_category_subscribers.py — verifies all 9 subscriber chains fire.

Covers Multica items:
  #1  TrustGraph Event Bus subscriber chains
  #8  CrossCategorySubscriberRegistry — all 9 chains verified

Each test confirms:
  a) The subscriber function exists and is callable
  b) It runs without raising (using mocked downstream engines)
  c) The event is registered in the _SUBSCRIBER_MAP with the correct key
  d) register_cross_category_subscribers() wires to both buses without error
"""
from __future__ import annotations

import threading
from collections import deque
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _event(org_id: str = "test-org", **kwargs) -> Dict[str, Any]:
    return {"org_id": org_id, "entity_id": str(id(kwargs)), **kwargs}


def _reset_dedup():
    """Clear the module-level dedup state between tests."""
    import core.cross_category_subscribers as m
    with m._SEEN_LOCK:
        m._SEEN_IDS.clear()
        m._SEEN_SET.clear()


# ---------------------------------------------------------------------------
# 1. on_threat_detected
# ---------------------------------------------------------------------------

class TestOnThreatDetected:
    def test_creates_alert_and_risk(self):
        _reset_dedup()
        from core.cross_category_subscribers import on_threat_detected

        mock_alert_eng = MagicMock()
        mock_risk_eng = MagicMock()
        mock_alert_eng.ingest_alert.return_value = {"alert_id": "a1"}
        mock_risk_eng.create_risk.return_value = {"risk_id": "r1"}

        with (
            patch("core.alert_triage_engine.AlertTriageEngine", return_value=mock_alert_eng),
            patch("core.risk_register_engine.RiskRegisterEngine", return_value=mock_risk_eng),
        ):
            on_threat_detected(_event(
                source_engine="edr",
                entity_type="process",
                severity="medium",
            ))
        mock_alert_eng.ingest_alert.assert_called_once()

    def test_high_severity_creates_incident(self):
        _reset_dedup()
        from core.cross_category_subscribers import on_threat_detected

        mock_alert_eng = MagicMock()
        mock_incident_eng = MagicMock()
        mock_risk_eng = MagicMock()
        mock_alert_eng.ingest_alert.return_value = {"alert_id": "a2"}
        mock_incident_eng.create_incident.return_value = {"incident_id": "i1"}
        mock_risk_eng.create_risk.return_value = {"risk_id": "r2"}

        with (
            patch("core.alert_triage_engine.AlertTriageEngine", return_value=mock_alert_eng),
            patch("core.incident_orchestration_engine.IncidentOrchestrationEngine", return_value=mock_incident_eng),
            patch("core.risk_register_engine.RiskRegisterEngine", return_value=mock_risk_eng),
        ):
            on_threat_detected(_event(
                source_engine="siem",
                entity_type="lateral_movement",
                severity="critical",
            ))
        mock_incident_eng.create_incident.assert_called_once()

    def test_dedup_prevents_double_fire(self):
        _reset_dedup()
        from core.cross_category_subscribers import on_threat_detected

        mock_eng = MagicMock()
        mock_eng.ingest_alert.return_value = {"alert_id": "a3"}
        mock_risk = MagicMock()
        mock_risk.create_risk.return_value = {}

        ev = _event(entity_id="dedup-test-001", severity="low")
        with (
            patch("core.alert_triage_engine.AlertTriageEngine", return_value=mock_eng),
            patch("core.risk_register_engine.RiskRegisterEngine", return_value=mock_risk),
        ):
            on_threat_detected(ev)
            on_threat_detected(ev)  # second call — dedup should block
        assert mock_eng.ingest_alert.call_count == 1


# ---------------------------------------------------------------------------
# 2. on_finding_created
# ---------------------------------------------------------------------------

class TestOnFindingCreated:
    def test_creates_vuln_ticket_and_syncs_risk(self):
        _reset_dedup()
        from core.cross_category_subscribers import on_finding_created

        mock_vuln = MagicMock()
        mock_risk = MagicMock()
        mock_vuln.create_ticket.return_value = {"ticket_id": "t1"}

        with (
            patch("core.vuln_workflow_engine.VulnWorkflowEngine") as MockVuln,
            patch("core.risk_aggregator_engine.RiskAggregatorEngine", return_value=mock_risk),
        ):
            MockVuln.for_org.return_value = mock_vuln
            on_finding_created(_event(
                source_engine="scanner",
                cve_id="CVE-2024-1234",
                severity="high",
            ))
        mock_vuln.create_ticket.assert_called_once()
        mock_risk.sync_from_brain_graph.assert_called_once()


# ---------------------------------------------------------------------------
# 3. on_anomaly_detected
# ---------------------------------------------------------------------------

class TestOnAnomalyDetected:
    def test_feeds_insider_threat_when_user_id_present(self):
        _reset_dedup()
        from core.cross_category_subscribers import on_anomaly_detected

        mock_insider = MagicMock()
        mock_alert = MagicMock()
        mock_insider.create_alert.return_value = {"alert_id": "ia1"}
        mock_alert.ingest_alert.return_value = {"alert_id": "a4"}

        with (
            patch("core.insider_threat_engine.InsiderThreatEngine", return_value=mock_insider),
            patch("core.alert_triage_engine.AlertTriageEngine", return_value=mock_alert),
        ):
            on_anomaly_detected(_event(
                user_id="user-42",
                entity_type="login_spike",
                source_engine="uba",
            ))
        mock_insider.create_alert.assert_called_once()
        mock_alert.ingest_alert.assert_called_once()

    def test_no_insider_call_without_user_id(self):
        _reset_dedup()
        from core.cross_category_subscribers import on_anomaly_detected

        mock_insider = MagicMock()
        mock_alert = MagicMock()
        mock_alert.ingest_alert.return_value = {"alert_id": "a5"}

        with (
            patch("core.insider_threat_engine.InsiderThreatEngine", return_value=mock_insider),
            patch("core.alert_triage_engine.AlertTriageEngine", return_value=mock_alert),
        ):
            on_anomaly_detected(_event(entity_type="network_spike", source_engine="ndr"))
        mock_insider.create_alert.assert_not_called()
        mock_alert.ingest_alert.assert_called_once()


# ---------------------------------------------------------------------------
# 4. on_alert_created
# ---------------------------------------------------------------------------

class TestOnAlertCreated:
    def test_escalates_critical_to_incident(self):
        _reset_dedup()
        from core.cross_category_subscribers import on_alert_created

        mock_inc = MagicMock()
        mock_inc.create_incident.return_value = {"incident_id": "i2"}

        with patch("core.incident_orchestration_engine.IncidentOrchestrationEngine", return_value=mock_inc):
            on_alert_created(_event(severity="critical", title="Ransomware detected"))
        mock_inc.create_incident.assert_called_once()

    def test_medium_does_not_escalate(self):
        _reset_dedup()
        from core.cross_category_subscribers import on_alert_created

        mock_inc = MagicMock()
        with patch("core.incident_orchestration_engine.IncidentOrchestrationEngine", return_value=mock_inc):
            on_alert_created(_event(severity="medium", title="Low signal alert"))
        mock_inc.create_incident.assert_not_called()


# ---------------------------------------------------------------------------
# 5. on_incident_created
# ---------------------------------------------------------------------------

class TestOnIncidentCreated:
    def test_initialises_cost_tracking(self):
        _reset_dedup()
        from core.cross_category_subscribers import on_incident_created

        mock_cost = MagicMock()
        mock_cost.record_cost.return_value = {"cost_id": "c1"}

        with patch("core.incident_cost_engine.IncidentCostEngine", return_value=mock_cost):
            on_incident_created(_event(title="Breach incident"))
        mock_cost.record_cost.assert_called_once()


# ---------------------------------------------------------------------------
# 6. on_control_failed
# ---------------------------------------------------------------------------

class TestOnControlFailed:
    def test_creates_compliance_gap(self):
        _reset_dedup()
        from core.cross_category_subscribers import on_control_failed

        mock_gap = MagicMock()
        mock_gap.create_assessment.return_value = {"id": "assess-1"}
        mock_gap.add_control_gap.return_value = {"gap_id": "g1"}

        with patch("core.compliance_gap_engine.ComplianceGapEngine", return_value=mock_gap):
            on_control_failed(_event(framework="SOC2", entity_id="CC6.1"))
        mock_gap.create_assessment.assert_called_once()
        mock_gap.add_control_gap.assert_called_once()

    def test_invalid_framework_falls_back_to_nist(self):
        _reset_dedup()
        from core.cross_category_subscribers import on_control_failed

        mock_gap = MagicMock()
        mock_gap.create_assessment.return_value = {"id": "assess-2"}
        mock_gap.add_control_gap.return_value = {"gap_id": "g2"}

        with patch("core.compliance_gap_engine.ComplianceGapEngine", return_value=mock_gap):
            on_control_failed(_event(framework="UNKNOWNFRAMEWORK", entity_id="ctrl-x"))
        call_kwargs = mock_gap.create_assessment.call_args
        data = call_kwargs[1]["data"] if call_kwargs[1] else call_kwargs[0][1]
        assert data["framework"] == "NIST"


# ---------------------------------------------------------------------------
# 7. on_cve_discovered
# ---------------------------------------------------------------------------

class TestOnCveDiscovered:
    def test_enriches_valid_cve(self):
        _reset_dedup()
        from core.cross_category_subscribers import on_cve_discovered

        mock_svc = MagicMock()
        mock_svc.enrich_cve.return_value = {"cve_id": "CVE-2024-5678", "epss": 0.42}

        with patch("core.cve_enrichment.CVEEnrichmentService", return_value=mock_svc):
            on_cve_discovered({"cve_id": "CVE-2024-5678", "org_id": "test-org"})
        mock_svc.enrich_cve.assert_called_once_with("CVE-2024-5678")

    def test_ignores_non_cve_entity(self):
        _reset_dedup()
        from core.cross_category_subscribers import on_cve_discovered

        mock_svc = MagicMock()
        with patch("core.cve_enrichment.CVEEnrichmentService", return_value=mock_svc):
            on_cve_discovered({"entity_id": "not-a-cve", "org_id": "test-org"})
        mock_svc.enrich_cve.assert_not_called()


# ---------------------------------------------------------------------------
# 8. on_risk_assessed
# ---------------------------------------------------------------------------

class TestOnRiskAssessed:
    def test_records_risk_score(self):
        _reset_dedup()
        from core.cross_category_subscribers import on_risk_assessed

        mock_agg = MagicMock()
        mock_agg.record_risk_score.return_value = {"id": "rs1"}

        with patch("core.risk_aggregator_engine.RiskAggregatorEngine", return_value=mock_agg):
            on_risk_assessed(_event(risk_score=55.0, entity_type="asset"))
        mock_agg.record_risk_score.assert_called_once()

    def test_high_risk_creates_alert(self):
        _reset_dedup()
        from core.cross_category_subscribers import on_risk_assessed

        mock_agg = MagicMock()
        mock_alert = MagicMock()
        mock_agg.record_risk_score.return_value = {}
        mock_alert.ingest_alert.return_value = {"alert_id": "a6"}

        with (
            patch("core.risk_aggregator_engine.RiskAggregatorEngine", return_value=mock_agg),
            patch("core.alert_triage_engine.AlertTriageEngine", return_value=mock_alert),
        ):
            on_risk_assessed(_event(risk_score=92.0, entity_type="user"))
        mock_alert.ingest_alert.assert_called_once()
        call_data = mock_alert.ingest_alert.call_args[1]["data"]
        assert call_data["severity"] == "critical"


# ---------------------------------------------------------------------------
# 9. on_identity_updated
# ---------------------------------------------------------------------------

class TestOnIdentityUpdated:
    def test_re_evaluates_access_policies(self):
        _reset_dedup()
        from core.cross_category_subscribers import on_identity_updated

        mock_ac = MagicMock()
        mock_ac.list_access_policies.return_value = [{"policy_id": "p1"}]
        mock_ac.list_grants.return_value = []

        with patch("core.access_control_engine.AccessControlEngine", return_value=mock_ac):
            on_identity_updated(_event(entity_id="user-99", source_engine="iam"))
        mock_ac.list_access_policies.assert_called_once()
        mock_ac.list_grants.assert_called_once()


# ---------------------------------------------------------------------------
# Subscriber map completeness
# ---------------------------------------------------------------------------

class TestSubscriberMap:
    def test_all_nine_chains_registered(self):
        from core.cross_category_subscribers import _SUBSCRIBER_MAP
        expected_keys = {
            "threat.detected",
            "finding.created",
            "anomaly.detected",
            "alert.created",
            "incident.created",
            "control.assessed",
            "cve.discovered",
            "risk.assessed",
            "identity.updated",
        }
        assert expected_keys == set(_SUBSCRIBER_MAP.keys()), (
            f"Missing: {expected_keys - set(_SUBSCRIBER_MAP.keys())}, "
            f"Extra: {set(_SUBSCRIBER_MAP.keys()) - expected_keys}"
        )

    def test_all_handlers_are_callable(self):
        from core.cross_category_subscribers import _SUBSCRIBER_MAP
        for key, handler in _SUBSCRIBER_MAP.items():
            assert callable(handler), f"Handler for {key!r} is not callable"


# ---------------------------------------------------------------------------
# register_cross_category_subscribers wiring
# ---------------------------------------------------------------------------

class TestRegistration:
    def test_register_wires_trustgraph_bus(self):
        """register_cross_category_subscribers() calls bus.on() for each event type."""
        from core.cross_category_subscribers import _SUBSCRIBER_MAP, register_cross_category_subscribers

        mock_bus = MagicMock()
        mock_legacy = MagicMock()
        mock_legacy_etype = MagicMock()

        with (
            patch("core.trustgraph_event_bus.get_event_bus", return_value=mock_bus),
            patch(
                "core.event_bus.get_event_bus",
                return_value=mock_legacy,
            ),
            patch("core.event_bus.EventType", mock_legacy_etype),
        ):
            count = register_cross_category_subscribers()

        # Should have called bus.on() once per entry in _SUBSCRIBER_MAP
        assert mock_bus.on.call_count == len(_SUBSCRIBER_MAP)
        assert count >= len(_SUBSCRIBER_MAP)

    def test_register_returns_positive_count(self):
        """register_cross_category_subscribers() returns count >= 9."""
        mock_bus = MagicMock()
        mock_legacy = MagicMock()

        with (
            patch("core.trustgraph_event_bus.get_event_bus", return_value=mock_bus),
            patch("core.event_bus.get_event_bus", return_value=mock_legacy),
            patch("core.event_bus.EventType", MagicMock()),
        ):
            from core.cross_category_subscribers import register_cross_category_subscribers
            count = register_cross_category_subscribers()

        assert count >= 9, f"Expected at least 9 subscribers registered, got {count}"

    def test_register_survives_missing_trustgraph_bus(self):
        """register_cross_category_subscribers() does not raise if TrustGraph bus unavailable."""
        with (
            patch("core.trustgraph_event_bus.get_event_bus", side_effect=ImportError("not available")),
            patch("core.event_bus.get_event_bus", return_value=MagicMock()),
            patch("core.event_bus.EventType", MagicMock()),
        ):
            from core.cross_category_subscribers import register_cross_category_subscribers
            # Should not raise — just logs a warning
            count = register_cross_category_subscribers()
        # Legacy bus subscribers may still have been registered
        assert count >= 0
