"""Cross-Category Event Subscriber Registry.

When engine A emits an event, subscribers here trigger actions in engines B, C, D.
This is the intelligence layer that transforms 331 isolated CRUD databases
into a correlated security platform.

Example: EDR detects threat → subscriber auto-creates alert → auto-evaluates for incident
"""

import logging
from typing import Any, Dict

logger = logging.getLogger(__name__)


def _safe_call(func, *args, **kwargs):
    """Call a function, log and swallow any exception."""
    try:
        return func(*args, **kwargs)
    except Exception as e:
        logger.warning("Subscriber %s failed: %s", func.__name__, e)
        return None


# ── THREAT_DETECTED subscribers ──────────────────────────────────────

def on_threat_detected(event_data: Dict[str, Any]) -> None:
    """When any engine detects a threat, auto-create alert and evaluate for incident."""
    org_id = event_data.get("org_id", "default")
    entity_type = event_data.get("entity_type", "unknown")
    entity_id = event_data.get("entity_id", "")
    source = event_data.get("source_engine", "unknown")
    severity = event_data.get("severity", "medium")

    # Normalise severity to a value AlertTriageEngine accepts
    valid_severities = {"critical", "high", "medium", "low", "info"}
    safe_severity = severity if severity in valid_severities else "medium"

    # 1. Auto-create alert in alert_triage
    def _create_alert():
        from core.alert_triage_engine import AlertTriageEngine
        eng = AlertTriageEngine()
        return eng.ingest_alert(
            org_id=org_id,
            data={
                "title": f"Auto-alert: {entity_type} from {source}",
                "severity": safe_severity,
                "source_system": "custom",
                "raw_alert_json": {
                    "entity_id": entity_id,
                    "entity_type": entity_type,
                    "auto_generated": True,
                },
            },
        )

    alert = _safe_call(_create_alert)

    # 2. If severity is high/critical, auto-create incident
    if severity in ("critical", "high"):
        def _create_incident():
            from core.incident_orchestration_engine import IncidentOrchestrationEngine
            eng = IncidentOrchestrationEngine()
            return eng.create_incident(
                org_id=org_id,
                data={
                    "title": f"Auto-incident: {entity_type} from {source}",
                    "severity": safe_severity if safe_severity in {"critical", "high", "medium", "low"} else "high",
                    "type": "other",
                },
            )
        _safe_call(_create_incident)

    # 3. Create a risk entry for this threat (best-effort)
    def _update_risk():
        from core.risk_register_engine import RiskRegisterEngine
        eng = RiskRegisterEngine()
        likelihood = "likely" if severity == "critical" else "possible"
        impact = "major" if severity in ("critical", "high") else "moderate"
        return eng.create_risk(
            org_id=org_id,
            data={
                "name": f"Risk from {entity_type}: {source}",
                "risk_category": "operational",
                "likelihood": likelihood,
                "impact": impact,
            },
        )
    _safe_call(_update_risk)


# ── FINDING_CREATED subscribers ──────────────────────────────────────

def on_finding_created(event_data: Dict[str, Any]) -> None:
    """When a finding is created, auto-create a vuln workflow ticket."""
    org_id = event_data.get("org_id", "default")
    entity_id = event_data.get("entity_id", "")
    source = event_data.get("source_engine", "manual")
    cve_id = event_data.get("cve_id", "")
    severity = event_data.get("severity", "medium")

    valid_severities = {"critical", "high", "medium", "low"}
    safe_severity = severity if severity in valid_severities else "medium"

    def _create_ticket():
        from core.vuln_workflow_engine import VulnWorkflowEngine
        eng = VulnWorkflowEngine.for_org(org_id)
        return eng.create_ticket(
            org_id=org_id,
            data={
                "title": f"Finding from {source}: {entity_id}",
                "severity": safe_severity,
                "source_engine": source if source in {
                    "manual", "scanner", "pentest", "bug_bounty",
                    "threat_intel", "cloud", "sast", "dast",
                } else "manual",
                "cve_id": cve_id,
            },
        )
    _safe_call(_create_ticket)


# ── ANOMALY_DETECTED subscribers ─────────────────────────────────────

def on_anomaly_detected(event_data: Dict[str, Any]) -> None:
    """When an anomaly is detected, feed to insider threat and create alert."""
    org_id = event_data.get("org_id", "default")
    entity_type = event_data.get("entity_type", "unknown")
    source = event_data.get("source_engine", "unknown")
    user_id = event_data.get("user_id")

    # 1. Feed to insider threat engine as a behavioural signal
    if user_id:
        def _feed_insider():
            from core.insider_threat_engine import InsiderThreatEngine
            eng = InsiderThreatEngine()
            return eng.create_alert(
                user_id=user_id,
                indicator="anomaly_detected",
                evidence={"source": source, "entity_type": entity_type},
                severity="high",
                org_id=org_id,
            )
        _safe_call(_feed_insider)

    # 2. Create alert in alert triage
    def _create_alert():
        from core.alert_triage_engine import AlertTriageEngine
        eng = AlertTriageEngine()
        return eng.ingest_alert(
            org_id=org_id,
            data={
                "title": f"Anomaly: {entity_type} from {source}",
                "severity": "high",
                "source_system": "custom",
                "raw_alert_json": {
                    "entity_type": entity_type,
                    "user_id": user_id,
                    "auto_generated": True,
                },
            },
        )
    _safe_call(_create_alert)


# ── ALERT_CREATED subscribers ────────────────────────────────────────

def on_alert_created(event_data: Dict[str, Any]) -> None:
    """When an alert is created, escalate to incident if critical/high."""
    org_id = event_data.get("org_id", "default")
    severity = event_data.get("severity", "medium")
    title = event_data.get("title", "Auto-escalated alert")
    source = event_data.get("source_engine", "unknown")

    if severity in ("critical", "high"):
        def _create_incident():
            from core.incident_orchestration_engine import IncidentOrchestrationEngine
            eng = IncidentOrchestrationEngine()
            return eng.create_incident(
                org_id=org_id,
                data={
                    "title": f"Escalated: {title}",
                    "severity": severity if severity in {"critical", "high", "medium", "low"} else "high",
                    "type": "other",
                    "source": source,
                },
            )
        _safe_call(_create_incident)


# ── INCIDENT_CREATED subscribers ─────────────────────────────────────

def on_incident_created(event_data: Dict[str, Any]) -> None:
    """When an incident is created, start cost tracking."""
    org_id = event_data.get("org_id", "default")
    entity_id = event_data.get("entity_id", "")
    title = event_data.get("title", "Unknown incident")

    def _init_costs():
        from core.incident_cost_engine import IncidentCostEngine
        eng = IncidentCostEngine()
        return eng.record_cost(
            org_id=org_id,
            incident_id=entity_id,
            incident_name=title,
            incident_type="other",
            cost_category="investigation",
            amount=0.0,
            description="Auto-created cost tracking for incident",
        )
    _safe_call(_init_costs)


# ── CONTROL_ASSESSED subscribers ─────────────────────────────────────

def on_control_failed(event_data: Dict[str, Any]) -> None:
    """When a compliance control fails, create a gap assessment and gap entry."""
    org_id = event_data.get("org_id", "default")
    entity_id = event_data.get("entity_id", "unknown-control")
    framework = event_data.get("framework", "NIST")

    valid_frameworks = {"SOC2", "ISO27001", "NIST", "PCI-DSS", "HIPAA", "GDPR", "CIS"}
    safe_framework = framework if framework in valid_frameworks else "NIST"

    def _create_gap():
        from core.compliance_gap_engine import ComplianceGapEngine
        eng = ComplianceGapEngine()
        # Must create an assessment first, then attach the gap
        assessment = eng.create_assessment(
            org_id=org_id,
            data={
                "assessment_name": f"Auto-assessment for {entity_id}",
                "framework": safe_framework,
                "total_controls": 1,
            },
        )
        assessment_id = assessment["id"]
        return eng.add_control_gap(
            org_id=org_id,
            data={
                "assessment_id": assessment_id,
                "control_id": entity_id,
                "control_name": f"Control: {entity_id}",
                "severity": "medium",
                "gap_description": f"Auto-detected gap for control {entity_id}",
            },
        )
    _safe_call(_create_gap)


# ── CVE_DISCOVERED subscribers ───────────────────────────────────────

def on_cve_discovered(event_data: Dict[str, Any]) -> None:
    """When a CVE is discovered, auto-enrich with EPSS/KEV data."""
    cve_id = event_data.get("cve_id") or event_data.get("entity_id", "")

    if not cve_id or not cve_id.startswith("CVE-"):
        return

    def _enrich():
        from core.cve_enrichment import CVEEnrichmentService
        svc = CVEEnrichmentService()
        return svc.enrich_cve(cve_id)
    _safe_call(_enrich)


# ── RISK_ASSESSED subscribers ────────────────────────────────────────

def on_risk_assessed(event_data: Dict[str, Any]) -> None:
    """When risk is assessed, update posture snapshot (best-effort placeholder)."""
    # Placeholder: future implementation will trigger scorecard recalculation
    org_id = event_data.get("org_id", "default")
    logger.debug("on_risk_assessed: org=%s — scorecard recalculation queued", org_id)


# ── IDENTITY_UPDATED subscribers ─────────────────────────────────────

def on_identity_updated(event_data: Dict[str, Any]) -> None:
    """When identity changes, log SoD check signal (best-effort placeholder)."""
    # Placeholder: future implementation will check separation-of-duties violations
    org_id = event_data.get("org_id", "default")
    logger.debug("on_identity_updated: org=%s — SoD check queued", org_id)


# ═══════════════════════════════════════════════════════════════════════
# REGISTRATION — Wire subscribers to event buses
# ═══════════════════════════════════════════════════════════════════════

_SUBSCRIBER_MAP = {
    "THREAT_DETECTED": on_threat_detected,
    "threat.detected": on_threat_detected,
    "FINDING_CREATED": on_finding_created,
    "finding.created": on_finding_created,
    "ANOMALY_DETECTED": on_anomaly_detected,
    "anomaly.detected": on_anomaly_detected,
    "ALERT_CREATED": on_alert_created,
    "alert.created": on_alert_created,
    "INCIDENT_CREATED": on_incident_created,
    "incident.created": on_incident_created,
    "CONTROL_ASSESSED": on_control_failed,
    "control.assessed": on_control_failed,
    "CVE_DISCOVERED": on_cve_discovered,
    "cve.discovered": on_cve_discovered,
    "RISK_ASSESSED": on_risk_assessed,
    "risk.assessed": on_risk_assessed,
    "IDENTITY_UPDATED": on_identity_updated,
    "identity.updated": on_identity_updated,
}


def register_cross_category_subscribers() -> int:
    """Register all cross-category subscribers with both event buses.

    Returns the number of successfully registered subscriptions.
    """
    registered = 0

    # Wire into TrustGraph event bus
    try:
        from core.trustgraph_event_bus import get_event_bus
        bus = get_event_bus()
        if bus and hasattr(bus, "subscribe"):
            for event_type, handler in _SUBSCRIBER_MAP.items():
                bus.subscribe(event_type, handler)
                registered += 1
    except Exception as e:
        logger.warning("Failed to wire TrustGraph subscribers: %s", e)

    # Wire into legacy event bus
    try:
        from core.event_bus import get_event_bus as get_legacy_bus, EventType
        legacy = get_legacy_bus()
        if legacy:
            type_map = {
                EventType.THREAT_DETECTED: on_threat_detected,
                EventType.FINDING_CREATED: on_finding_created,
                EventType.CVE_DISCOVERED: on_cve_discovered,
            }
            for etype, handler in type_map.items():
                legacy.subscribe(etype, handler)
                registered += 1
    except Exception as e:
        logger.warning("Failed to wire legacy subscribers: %s", e)

    logger.info("Registered %d cross-category subscribers", registered)
    return registered
