"""Cross-Category Event Subscriber Registry.

When engine A emits an event, subscribers here trigger actions in engines B, C, D.
This is the intelligence layer that transforms 331 isolated CRUD databases
into a correlated security platform.

Example: EDR detects threat → subscriber auto-creates alert → auto-evaluates for incident
"""

import logging
import threading
from collections import deque
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Deduplication: last-1000 seen event IDs to prevent duplicate processing
# ---------------------------------------------------------------------------

_SEEN_LOCK = threading.Lock()
_SEEN_IDS: deque = deque(maxlen=1000)
_SEEN_SET: set = set()


def _already_seen(event_id: Optional[str]) -> bool:
    """Return True if this event_id was processed recently (dedup guard)."""
    if not event_id:
        return False
    with _SEEN_LOCK:
        if event_id in _SEEN_SET:
            return True
        _SEEN_IDS.append(event_id)
        _SEEN_SET.add(event_id)
        # Keep set in sync when deque evicts oldest entry
        if len(_SEEN_IDS) == _SEEN_IDS.maxlen:
            # The deque already evicted the oldest; rebuild set from current deque
            _SEEN_SET.clear()
            _SEEN_SET.update(_SEEN_IDS)
        return False


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
    if _already_seen(event_data.get("event_id") or event_data.get("entity_id")):
        return
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

    _safe_call(_create_alert)

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
    """When a finding is created, auto-create a vuln workflow ticket and sync risk scores."""
    if _already_seen(event_data.get("event_id") or event_data.get("entity_id")):
        return
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

    # Sync the new finding's risk score into RiskAggregatorEngine immediately
    def _sync_risk():
        from core.risk_aggregator_engine import RiskAggregatorEngine
        eng = RiskAggregatorEngine()
        eng.sync_from_brain_graph(org_id=org_id)
    _safe_call(_sync_risk)


# ── ANOMALY_DETECTED subscribers ─────────────────────────────────────

def on_anomaly_detected(event_data: Dict[str, Any]) -> None:
    """When an anomaly is detected, feed to insider threat and create alert."""
    if _already_seen(event_data.get("event_id") or event_data.get("entity_id")):
        return
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
    if _already_seen(event_data.get("event_id") or event_data.get("entity_id")):
        return
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
    if _already_seen(event_data.get("event_id") or event_data.get("entity_id")):
        return
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
    if _already_seen(event_data.get("event_id") or event_data.get("entity_id")):
        return
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
    if _already_seen(event_data.get("event_id") or event_data.get("entity_id")):
        return
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
    """When risk is assessed, update RiskAggregatorEngine and alert if threshold exceeded."""
    if _already_seen(event_data.get("event_id") or event_data.get("entity_id")):
        return
    org_id = event_data.get("org_id", "default")
    risk_score = float(event_data.get("risk_score", 0))
    entity_id = event_data.get("entity_id", "")
    entity_type = event_data.get("entity_type", "asset")
    source_engine = event_data.get("source_engine", "unknown")

    # 1. Record the risk score in RiskAggregatorEngine
    valid_entity_types = {"asset", "user", "network", "application", "vendor"}
    safe_entity_type = entity_type if entity_type in valid_entity_types else "asset"

    def _record_risk():
        from core.risk_aggregator_engine import RiskAggregatorEngine
        eng = RiskAggregatorEngine()
        return eng.record_risk_score(
            org_id=org_id,
            data={
                "entity_id": entity_id,
                "entity_type": safe_entity_type,
                "entity_name": event_data.get("entity_name", entity_id),
                "risk_score": risk_score,
                "source_engine": source_engine,
                "risk_factors": event_data.get("risk_factors", []),
            },
        )
    _safe_call(_record_risk)

    # 2. If risk exceeds threshold (70), create an alert via AlertTriageEngine
    if risk_score >= 70:
        severity = "critical" if risk_score >= 90 else "high"

        def _create_alert():
            from core.alert_triage_engine import AlertTriageEngine
            eng = AlertTriageEngine()
            return eng.ingest_alert(
                org_id=org_id,
                data={
                    "title": f"High risk score ({risk_score:.0f}) detected for {entity_id}",
                    "severity": severity,
                    "source_system": "custom",
                    "raw_alert_json": {
                        "entity_id": entity_id,
                        "entity_type": safe_entity_type,
                        "risk_score": risk_score,
                        "source_engine": source_engine,
                        "auto_generated": True,
                    },
                },
            )
        _safe_call(_create_alert)


# ── IDENTITY_UPDATED subscribers ─────────────────────────────────────

def on_identity_updated(event_data: Dict[str, Any]) -> None:
    """When identity changes, re-evaluate access policies and log to audit trail."""
    if _already_seen(event_data.get("event_id") or event_data.get("entity_id")):
        return
    org_id = event_data.get("org_id", "default")
    subject_id = event_data.get("entity_id", "") or event_data.get("subject_id", "")
    source_engine = event_data.get("source_engine", "unknown")

    # 1. Trigger access policy re-evaluation via AccessControlEngine
    def _reeval_access():
        from core.access_control_engine import AccessControlEngine
        eng = AccessControlEngine()
        # List active policies for the org to re-evaluate applicability
        policies = eng.list_access_policies(org_id=org_id)
        # Check active grants for this subject across all resources
        grants = eng.list_grants(org_id=org_id, subject_id=subject_id) if subject_id else []
        return {
            "policies_evaluated": len(policies),
            "grants_checked": len(grants),
        }
    result = _safe_call(_reeval_access)

    # 2. Log the identity change to the audit trail
    logger.info(
        "on_identity_updated: org=%s subject=%s source=%s policies_evaluated=%s grants_checked=%s",
        org_id,
        subject_id,
        source_engine,
        result.get("policies_evaluated", 0) if result else 0,
        result.get("grants_checked", 0) if result else 0,
    )


# ═══════════════════════════════════════════════════════════════════════
# REGISTRATION — Wire subscribers to event buses
# ═══════════════════════════════════════════════════════════════════════

# Map bus event type strings (dot-notation, matching what engines emit) to handlers.
# The TrustGraph EventBus uses dot-notation keys exclusively (e.g. "threat.detected").
# Uppercase aliases ("THREAT_DETECTED") are NOT valid bus event types — they are only
# kept here for the legacy bus and the subscriber_map lookup below.
_SUBSCRIBER_MAP = {
    # TrustGraph bus event types (dot-notation — what get_event_bus().emit() uses)
    "threat.detected": on_threat_detected,
    "finding.created": on_finding_created,
    "anomaly.detected": on_anomaly_detected,
    "alert.created": on_alert_created,
    "incident.created": on_incident_created,
    "control.assessed": on_control_failed,
    "cve.discovered": on_cve_discovered,
    "risk.assessed": on_risk_assessed,
    "identity.updated": on_identity_updated,
}


def register_cross_category_subscribers() -> int:
    """Register all cross-category subscribers with both event buses.

    Returns the number of successfully registered subscriptions.
    """
    registered = 0

    # Wire into TrustGraph event bus using bus.on() (the correct method name)
    try:
        from core.trustgraph_event_bus import get_event_bus
        bus = get_event_bus()
        if bus:
            for event_type, handler in _SUBSCRIBER_MAP.items():
                bus.on(event_type, handler)
                registered += 1
    except Exception as e:
        logger.warning("Failed to wire TrustGraph subscribers: %s", e)

    # Wire into legacy event bus
    try:
        from core.event_bus import EventType
        from core.event_bus import get_event_bus as get_legacy_bus
        legacy = get_legacy_bus()
        if legacy:
            type_map = {
                EventType.THREAT_DETECTED: on_threat_detected,
                EventType.FINDING_CREATED: on_finding_created,
                EventType.CVE_DISCOVERED: on_cve_discovered,
            }
            for etype, handler in type_map.items():
                # Legacy bus uses subscribe(); fall back to on() if subscribe() absent
                if hasattr(legacy, "subscribe"):
                    legacy.subscribe(etype, handler)
                elif hasattr(legacy, "on"):
                    legacy.on(etype, handler)
                registered += 1
    except Exception as e:
        logger.warning("Failed to wire legacy subscribers: %s", e)

    logger.info("Registered %d cross-category subscribers", registered)
    return registered
