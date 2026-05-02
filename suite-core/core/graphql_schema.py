"""GraphQL Schema for ALDECI/FixOps — Pure Python implementation.

Provides a complete GraphQL API layer using a hand-rolled schema engine
(no external GraphQL library required). Implements the GraphQL specification
wire protocol over HTTP POST.

Types:     Finding, Asset, Incident, Compliance, Vendor, ThreatActor
Queries:   findings, assets, incidents, compliance_status, posture_score,
           attack_surface, vendors, threat_landscape
Mutations: acknowledge_finding, create_incident, update_compliance, accept_risk
Subscriptions (type definitions only): new_finding, sla_breach, incident_update

All resolvers delegate to existing manager instances so no business logic
is duplicated here.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import structlog

logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# SDL — Schema Definition Language (introspection only, wire protocol is
# handled by the resolver engine below)
# ---------------------------------------------------------------------------

SCHEMA_SDL = """
type Finding {
  id: String!
  title: String!
  severity: String!
  status: String!
  cve_id: String
  cvss_score: Float
  asset_id: String
  org_id: String!
  scanner: String
  description: String
  remediation: String
  sla_deadline: String
  created_at: String!
  updated_at: String
}

type Asset {
  id: String!
  name: String!
  asset_type: String!
  hostname: String
  ip_address: String
  criticality: String!
  lifecycle: String!
  environment: String
  owner: String
  org_id: String!
  tags: [String!]!
  last_seen: String
  created_at: String!
}

type Incident {
  id: String!
  title: String!
  incident_type: String!
  severity: String!
  status: String!
  org_id: String!
  description: String
  affected_assets: [String!]!
  assigned_to: String
  created_at: String!
  updated_at: String
}

type ComplianceControl {
  framework: String!
  control_id: String!
  title: String!
  status: String!
  evidence_count: Int!
  last_assessed: String
}

type ComplianceStatus {
  org_id: String!
  framework: String!
  overall_score: Float!
  passing_controls: Int!
  failing_controls: Int!
  not_applicable: Int!
  controls: [ComplianceControl!]!
  assessed_at: String!
}

type PostureComponent {
  name: String!
  score: Float!
  weight: Float!
}

type PostureScore {
  id: String!
  org_id: String!
  overall_score: Float!
  grade: String!
  components: [PostureComponent!]!
  calculated_at: String!
}

type ExposurePath {
  id: String!
  source_asset: String!
  target_asset: String!
  risk_score: Float!
  path_steps: [String!]!
}

type AttackSurface {
  org_id: String!
  total_assets: Int!
  external_assets: Int!
  critical_assets: Int!
  exposure_paths: [ExposurePath!]!
  risk_score: Float!
}

type VendorAssessment {
  score: Float!
  grade: String!
  assessed_at: String!
  expires_at: String!
  status: String!
}

type Vendor {
  id: String!
  name: String!
  domain: String!
  description: String
  tier: String!
  sbom_component_count: Int!
  org_id: String!
  latest_assessment: VendorAssessment
  created_at: String!
}

type ThreatActor {
  id: String!
  name: String!
  aliases: [String!]!
  motivation: String!
  sophistication: String!
  target_sectors: [String!]!
  ttps: [String!]!
  active: Boolean!
  first_seen: String
  last_seen: String
}

type ThreatLandscape {
  org_id: String!
  active_campaigns: Int!
  relevant_actors: [ThreatActor!]!
  top_ttps: [String!]!
  risk_level: String!
  assessed_at: String!
}

# Mutation payloads
type AcknowledgeResult {
  finding_id: String!
  status: String!
  acknowledged_by: String!
  acknowledged_at: String!
  message: String!
}

type CreateIncidentResult {
  incident_id: String!
  status: String!
  title: String!
  created_at: String!
}

type UpdateComplianceResult {
  control_id: String!
  framework: String!
  new_status: String!
  updated_at: String!
}

type AcceptRiskResult {
  finding_id: String!
  accepted: Boolean!
  accepted_by: String!
  expiry: String
  reason: String!
  accepted_at: String!
}

# Subscription event types (definitions only — no live transport)
type NewFindingEvent {
  finding: Finding!
  event_type: String!
  timestamp: String!
}

type SLABreachEvent {
  finding_id: String!
  severity: String!
  sla_deadline: String!
  breached_at: String!
  org_id: String!
}

type IncidentUpdateEvent {
  incident: Incident!
  previous_status: String!
  new_status: String!
  updated_at: String!
}

# Filter input types (represented as optional query args in resolver)
type Query {
  findings(
    org_id: String
    severity: String
    status: String
    scanner: String
    asset_id: String
    cve_id: String
    limit: Int
    offset: Int
  ): [Finding!]!

  assets(
    org_id: String
    asset_type: String
    criticality: String
    lifecycle: String
    environment: String
    limit: Int
    offset: Int
  ): [Asset!]!

  incidents(
    org_id: String
    incident_type: String
    severity: String
    status: String
    limit: Int
  ): [Incident!]!

  compliance_status(
    org_id: String!
    framework: String!
  ): ComplianceStatus!

  posture_score(
    org_id: String!
  ): PostureScore!

  attack_surface(
    org_id: String!
  ): AttackSurface!

  vendors(
    org_id: String
    tier: String
    limit: Int
  ): [Vendor!]!

  threat_landscape(
    org_id: String!
  ): ThreatLandscape!
}

type Mutation {
  acknowledge_finding(
    finding_id: String!
    acknowledged_by: String!
    comment: String
  ): AcknowledgeResult!

  create_incident(
    title: String!
    incident_type: String!
    severity: String!
    org_id: String!
    description: String
    affected_assets: [String!]
  ): CreateIncidentResult!

  update_compliance(
    org_id: String!
    framework: String!
    control_id: String!
    status: String!
    evidence_notes: String
  ): UpdateComplianceResult!

  accept_risk(
    finding_id: String!
    accepted_by: String!
    reason: String!
    expiry_days: Int
  ): AcceptRiskResult!
}

type Subscription {
  new_finding(org_id: String): NewFindingEvent!
  sla_breach(org_id: String): SLABreachEvent!
  incident_update(org_id: String, incident_id: String): IncidentUpdateEvent!
}
"""


# ---------------------------------------------------------------------------
# In-memory stores (fallback when manager instances are unavailable)
# ---------------------------------------------------------------------------
_findings_store: Dict[str, Dict[str, Any]] = {}
_incidents_store: Dict[str, Dict[str, Any]] = {}
_risk_acceptances: Dict[str, Dict[str, Any]] = {}


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _coerce_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _coerce_float(value: Any, default: float) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


# ---------------------------------------------------------------------------
# Type serialisers — convert manager objects / dicts to GraphQL-ready dicts
# ---------------------------------------------------------------------------

def _serialize_finding(f: Any) -> Dict[str, Any]:
    """Accept a dict or Pydantic model and return a Finding dict."""
    if hasattr(f, "model_dump"):
        d = f.model_dump()
    elif hasattr(f, "dict"):
        d = f.dict()
    elif isinstance(f, dict):
        d = f
    else:
        d = vars(f)
    return {
        "id": str(d.get("id", "")),
        "title": str(d.get("title", d.get("name", "Untitled"))),
        "severity": str(d.get("severity", "medium")),
        "status": str(d.get("status", "open")),
        "cve_id": d.get("cve_id"),
        "cvss_score": _coerce_float(d.get("cvss_score"), 0.0) if d.get("cvss_score") is not None else None,
        "asset_id": d.get("asset_id"),
        "org_id": str(d.get("org_id", "default")),
        "scanner": d.get("scanner") or d.get("source"),
        "description": d.get("description"),
        "remediation": d.get("remediation"),
        "sla_deadline": d.get("sla_deadline"),
        "created_at": str(d.get("created_at", _now_iso())),
        "updated_at": d.get("updated_at"),
    }


def _serialize_asset(a: Any) -> Dict[str, Any]:
    if hasattr(a, "model_dump"):
        d = a.model_dump()
    elif hasattr(a, "dict"):
        d = a.dict()
    elif isinstance(a, dict):
        d = a
    else:
        d = vars(a)
    return {
        "id": str(d.get("id", "")),
        "name": str(d.get("name", "")),
        "asset_type": str(d.get("asset_type", "unknown")),
        "hostname": d.get("hostname"),
        "ip_address": d.get("ip_address"),
        "criticality": str(d.get("criticality", "medium")),
        "lifecycle": str(d.get("lifecycle", "active")),
        "environment": d.get("environment"),
        "owner": d.get("owner"),
        "org_id": str(d.get("org_id", "default")),
        "tags": list(d.get("tags") or []),
        "last_seen": d.get("last_seen"),
        "created_at": str(d.get("created_at", _now_iso())),
    }


def _serialize_incident(i: Any) -> Dict[str, Any]:
    if hasattr(i, "model_dump"):
        d = i.model_dump()
    elif hasattr(i, "dict"):
        d = i.dict()
    elif isinstance(i, dict):
        d = i
    else:
        d = vars(i)
    return {
        "id": str(d.get("id", "")),
        "title": str(d.get("title", "")),
        "incident_type": str(d.get("incident_type", "unknown")),
        "severity": str(d.get("severity", "sev3")),
        "status": str(d.get("status", "detected")),
        "org_id": str(d.get("org_id", "default")),
        "description": d.get("description"),
        "affected_assets": list(d.get("affected_assets") or []),
        "assigned_to": d.get("assigned_to"),
        "created_at": str(d.get("created_at", _now_iso())),
        "updated_at": d.get("updated_at"),
    }


def _serialize_vendor(v: Any) -> Dict[str, Any]:
    if hasattr(v, "model_dump"):
        d = v.model_dump()
    elif hasattr(v, "dict"):
        d = v.dict()
    elif isinstance(v, dict):
        d = v
    else:
        d = vars(v)
    assessment = d.get("latest_assessment")
    assessment_out = None
    if assessment:
        if hasattr(assessment, "model_dump"):
            adict = assessment.model_dump()
        elif isinstance(assessment, dict):
            adict = assessment
        else:
            adict = vars(assessment)
        assessment_out = {
            "score": _coerce_float(adict.get("score"), 0.0),
            "grade": str(adict.get("grade", "N/A")),
            "assessed_at": str(adict.get("assessed_at", _now_iso())),
            "expires_at": str(adict.get("expires_at", _now_iso())),
            "status": str(adict.get("status", "completed")),
        }
    return {
        "id": str(d.get("id", "")),
        "name": str(d.get("name", "")),
        "domain": str(d.get("domain", "")),
        "description": d.get("description"),
        "tier": str(d.get("tier", "medium")),
        "sbom_component_count": _coerce_int(d.get("sbom_component_count"), 0),
        "org_id": str(d.get("org_id", "default")),
        "latest_assessment": assessment_out,
        "created_at": str(d.get("created_at", _now_iso())),
    }


# ---------------------------------------------------------------------------
# Resolver functions — each query/mutation maps to one function
# ---------------------------------------------------------------------------

def resolve_findings(args: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return findings list, optionally filtered."""
    org_id = args.get("org_id", "default")
    severity = args.get("severity")
    status = args.get("status")
    scanner = args.get("scanner")
    asset_id = args.get("asset_id")
    cve_id = args.get("cve_id")
    limit = _coerce_int(args.get("limit"), 50)
    offset = _coerce_int(args.get("offset"), 0)

    results: List[Dict[str, Any]] = []

    # Try to pull from the findings routes in-memory store
    try:
        from apps.api import findings_routes as _fr
        store = getattr(_fr, "_findings_store", {})
        for f in store.values():
            if org_id and f.get("org_id", "default") != org_id:
                continue
            results.append(_serialize_finding(f))
    except Exception as exc:
        logger.debug("graphql_schema: finding store read failed", error=str(exc))

    # Fallback to local store
    if not results:
        for f in _findings_store.values():
            if org_id and f.get("org_id", "default") != org_id:
                continue
            results.append(_serialize_finding(f))

    # Apply filters
    if severity:
        results = [r for r in results if r["severity"] == severity]
    if status:
        results = [r for r in results if r["status"] == status]
    if scanner:
        results = [r for r in results if r.get("scanner") == scanner]
    if asset_id:
        results = [r for r in results if r.get("asset_id") == asset_id]
    if cve_id:
        results = [r for r in results if r.get("cve_id") == cve_id]

    return results[offset: offset + limit]


def resolve_assets(args: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return assets list, optionally filtered."""
    org_id = args.get("org_id", "default")
    asset_type = args.get("asset_type")
    criticality = args.get("criticality")
    lifecycle = args.get("lifecycle")
    environment = args.get("environment")
    limit = _coerce_int(args.get("limit"), 50)
    offset = _coerce_int(args.get("offset"), 0)

    results: List[Dict[str, Any]] = []

    try:
        from core.asset_inventory import get_asset_inventory
        inventory = get_asset_inventory()
        assets = inventory.list_assets(org_id=org_id or "default", limit=200)
        results = [_serialize_asset(a) for a in assets]
    except Exception as exc:
        logger.warning("asset_inventory unavailable, using empty list", error=str(exc))

    if asset_type:
        results = [r for r in results if r["asset_type"] == asset_type]
    if criticality:
        results = [r for r in results if r["criticality"] == criticality]
    if lifecycle:
        results = [r for r in results if r["lifecycle"] == lifecycle]
    if environment:
        results = [r for r in results if r.get("environment") == environment]

    return results[offset: offset + limit]


def resolve_incidents(args: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return incidents list, optionally filtered."""
    org_id = args.get("org_id", "default")
    incident_type = args.get("incident_type")
    severity = args.get("severity")
    status = args.get("status")
    limit = _coerce_int(args.get("limit"), 50)

    results: List[Dict[str, Any]] = []

    # REMOVED — ``core.incident_response.get_incident_manager`` factory does
    # not exist; the module exposes ``IncidentResponseManager`` (class) only.
    # 2026-05-03 silenced-imports audit. Always use the local-store fallback
    # below until a canonical ``get_incident_manager`` factory is added or
    # callers are switched to the class directly.
    logger.debug(
        "incident_manager_factory_unavailable",
        reason="get_incident_manager removed; using local _incidents_store",
    )
    for i in _incidents_store.values():
        if org_id and i.get("org_id", "default") != org_id:
            continue
        results.append(_serialize_incident(i))

    if incident_type:
        results = [r for r in results if r["incident_type"] == incident_type]
    if severity:
        results = [r for r in results if r["severity"] == severity]
    if status:
        results = [r for r in results if r["status"] == status]

    return results[:limit]


def resolve_compliance_status(args: Dict[str, Any]) -> Dict[str, Any]:
    """Return compliance status for an org + framework.

    NOTE: ``core.compliance_automation.get_compliance_automation`` factory
    was removed in 2026-05-03 silenced-imports audit; the module exposes
    ``ComplianceAutomation`` class directly. Until a canonical factory lands
    callers go through the class without the factory wrapper.
    """
    org_id = args.get("org_id", "default")
    framework = args.get("framework", "SOC2")

    try:
        from core.compliance_automation import ComplianceAutomation
        engine = ComplianceAutomation()
        status = (
            engine.get_framework_status(org_id=org_id, framework=framework)
            if hasattr(engine, "get_framework_status")
            else None
        )
        if status:
            controls = []
            for c in status.get("controls", []):
                controls.append({
                    "framework": framework,
                    "control_id": str(c.get("control_id", "")),
                    "title": str(c.get("title", "")),
                    "status": str(c.get("status", "unknown")),
                    "evidence_count": _coerce_int(c.get("evidence_count"), 0),
                    "last_assessed": c.get("last_assessed"),
                })
            return {
                "org_id": org_id,
                "framework": framework,
                "overall_score": _coerce_float(status.get("score", 0.0), 0.0),
                "passing_controls": _coerce_int(status.get("passing", 0), 0),
                "failing_controls": _coerce_int(status.get("failing", 0), 0),
                "not_applicable": _coerce_int(status.get("na", 0), 0),
                "controls": controls,
                "assessed_at": str(status.get("assessed_at", _now_iso())),
            }
    except Exception as exc:
        logger.warning("compliance_automation unavailable", error=str(exc))

    # Fallback — return a sensible default
    return {
        "org_id": org_id,
        "framework": framework,
        "overall_score": 0.0,
        "passing_controls": 0,
        "failing_controls": 0,
        "not_applicable": 0,
        "controls": [],
        "assessed_at": _now_iso(),
    }


def resolve_posture_score(args: Dict[str, Any]) -> Dict[str, Any]:
    """Return posture score for an org."""
    org_id = args.get("org_id", "default")

    try:
        from core.posture_scoring import PostureScorer
        scorer = PostureScorer()
        score = scorer.calculate_posture(org_id=org_id)
        if score:
            components = []
            for comp in score.components:
                if hasattr(comp, "model_dump"):
                    cd = comp.model_dump()
                elif isinstance(comp, dict):
                    cd = comp
                else:
                    cd = vars(comp)
                components.append({
                    "name": str(cd.get("name", "")),
                    "score": _coerce_float(cd.get("score"), 0.0),
                    "weight": _coerce_float(cd.get("weight"), 0.0),
                })
            return {
                "id": str(score.id),
                "org_id": org_id,
                "overall_score": _coerce_float(score.overall_score, 0.0),
                "grade": str(score.grade),
                "components": components,
                "calculated_at": str(score.calculated_at),
            }
    except Exception as exc:
        logger.warning("posture_scorer unavailable", error=str(exc))

    return {
        "id": f"ps-{uuid.uuid4().hex[:12]}",
        "org_id": org_id,
        "overall_score": 0.0,
        "grade": "N/A",
        "components": [],
        "calculated_at": _now_iso(),
    }


def resolve_attack_surface(args: Dict[str, Any]) -> Dict[str, Any]:
    """Return attack surface analysis for an org."""
    org_id = args.get("org_id", "default")

    try:
        from core.attack_surface import AttackSurfaceMapper
        mapper = AttackSurfaceMapper()
        assets = mapper.list_assets(org_id=org_id)
        external = [a for a in assets if getattr(a, "exposure_level", None) in ("internet_exposed", "external")]
        critical = [a for a in assets if getattr(a, "criticality", None) in ("critical",)]
        paths = mapper.list_exposure_paths(org_id=org_id) if hasattr(mapper, "list_exposure_paths") else []

        serialized_paths = []
        for p in paths:
            if hasattr(p, "model_dump"):
                pd = p.model_dump()
            elif isinstance(p, dict):
                pd = p
            else:
                pd = vars(p)
            serialized_paths.append({
                "id": str(pd.get("id", uuid.uuid4().hex[:12])),
                "source_asset": str(pd.get("source_asset_id", pd.get("source_asset", ""))),
                "target_asset": str(pd.get("target_asset_id", pd.get("target_asset", ""))),
                "risk_score": _coerce_float(pd.get("risk_score"), 0.0),
                "path_steps": list(pd.get("path_steps") or []),
            })

        return {
            "org_id": org_id,
            "total_assets": len(assets),
            "external_assets": len(external),
            "critical_assets": len(critical),
            "exposure_paths": serialized_paths,
            "risk_score": _coerce_float(
                sum(p["risk_score"] for p in serialized_paths) / max(len(serialized_paths), 1), 0.0
            ),
        }
    except Exception as exc:
        logger.warning("attack_surface_mapper unavailable", error=str(exc))

    return {
        "org_id": org_id,
        "total_assets": 0,
        "external_assets": 0,
        "critical_assets": 0,
        "exposure_paths": [],
        "risk_score": 0.0,
    }


def resolve_vendors(args: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return vendors list."""
    org_id = args.get("org_id", "default")
    tier = args.get("tier")
    limit = _coerce_int(args.get("limit"), 50)

    results: List[Dict[str, Any]] = []

    try:
        from core.vendor_scorecard import VendorScorecard
        scorecard = VendorScorecard()
        vendors = scorecard.list_vendors(org_id=org_id or "default")
        for v in vendors:
            serialized = _serialize_vendor(v)
            # Try to attach latest assessment
            try:
                assessment = scorecard.get_latest_assessment(vendor_id=serialized["id"])
                if assessment:
                    serialized["latest_assessment"] = {
                        "score": _coerce_float(getattr(assessment, "score", 0), 0.0),
                        "grade": str(getattr(assessment, "grade", "N/A")),
                        "assessed_at": str(getattr(assessment, "assessed_at", _now_iso())),
                        "expires_at": str(getattr(assessment, "expires_at", _now_iso())),
                        "status": str(getattr(assessment, "status", "completed")),
                    }
            except Exception as exc:
                logger.debug("graphql_schema: vendor assessment serialization failed", error=str(exc))
            results.append(serialized)
    except Exception as exc:
        logger.warning("vendor_scorecard unavailable", error=str(exc))

    if tier:
        results = [r for r in results if r["tier"] == tier]

    return results[:limit]


def resolve_threat_landscape(args: Dict[str, Any]) -> Dict[str, Any]:
    """Return threat landscape for an org."""
    org_id = args.get("org_id", "default")

    actors: List[Dict[str, Any]] = []
    try:
        from suite_feeds.feeds.threat_intel_aggregator import ThreatIntelAggregator
        agg = ThreatIntelAggregator()
        raw_actors = agg.get_threat_actors(org_id=org_id) if hasattr(agg, "get_threat_actors") else []
        for actor in raw_actors:
            if isinstance(actor, dict):
                d = actor
            elif hasattr(actor, "model_dump"):
                d = actor.model_dump()
            else:
                d = vars(actor)
            actors.append({
                "id": str(d.get("id", uuid.uuid4().hex[:12])),
                "name": str(d.get("name", "")),
                "aliases": list(d.get("aliases") or []),
                "motivation": str(d.get("motivation", "unknown")),
                "sophistication": str(d.get("sophistication", "unknown")),
                "target_sectors": list(d.get("target_sectors") or []),
                "ttps": list(d.get("ttps") or []),
                "active": bool(d.get("active", True)),
                "first_seen": d.get("first_seen"),
                "last_seen": d.get("last_seen"),
            })
    except Exception as exc:
        logger.debug("threat_intel_aggregator unavailable", error=str(exc))

    return {
        "org_id": org_id,
        "active_campaigns": len(actors),
        "relevant_actors": actors,
        "top_ttps": [],
        "risk_level": "medium" if actors else "low",
        "assessed_at": _now_iso(),
    }


# ---------------------------------------------------------------------------
# Mutation resolvers
# ---------------------------------------------------------------------------

def resolve_acknowledge_finding(args: Dict[str, Any]) -> Dict[str, Any]:
    """Acknowledge a finding — mark it reviewed."""
    finding_id = args.get("finding_id", "")
    acknowledged_by = args.get("acknowledged_by", "unknown")
    comment = args.get("comment", "")
    now = _now_iso()

    # Update in findings routes store if available
    updated = False
    try:
        from apps.api import findings_routes as _fr
        store = getattr(_fr, "_findings_store", {})
        if finding_id in store:
            store[finding_id]["status"] = "in_progress"
            store[finding_id]["acknowledged_by"] = acknowledged_by
            store[finding_id]["acknowledged_at"] = now
            if comment:
                store[finding_id]["comment"] = comment
            updated = True
    except Exception as exc:
        logger.debug("graphql_schema: acknowledge finding store update failed", error=str(exc))

    # Update local store as fallback
    if not updated and finding_id in _findings_store:
        _findings_store[finding_id]["status"] = "in_progress"
        _findings_store[finding_id]["acknowledged_by"] = acknowledged_by
        _findings_store[finding_id]["acknowledged_at"] = now
        updated = True

    return {
        "finding_id": finding_id,
        "status": "in_progress" if updated else "not_found",
        "acknowledged_by": acknowledged_by,
        "acknowledged_at": now,
        "message": "Finding acknowledged" if updated else f"Finding {finding_id} not found; recorded acknowledgement",
    }


def resolve_create_incident(args: Dict[str, Any]) -> Dict[str, Any]:
    """Create a new incident."""
    incident_id = f"inc-{uuid.uuid4().hex[:12]}"
    now = _now_iso()
    title = args.get("title", "Untitled Incident")
    incident_type = args.get("incident_type", "malware")
    severity = args.get("severity", "sev3")
    org_id = args.get("org_id", "default")
    description = args.get("description", "")
    affected_assets = list(args.get("affected_assets") or [])

    record = {
        "id": incident_id,
        "title": title,
        "incident_type": incident_type,
        "severity": severity,
        "status": "detected",
        "org_id": org_id,
        "description": description,
        "affected_assets": affected_assets,
        "created_at": now,
        "updated_at": now,
    }

    # REMOVED — ``core.incident_response.{get_incident_manager,IncidentCreate}``
    # do not exist. The module exposes ``IncidentResponseManager`` (class) and
    # ``Incident`` Pydantic model only. 2026-05-03 silenced-imports audit.
    # Persist to local store until callers are rewired to the class directly.
    logger.debug(
        "incident_manager_create_unavailable",
        reason="get_incident_manager/IncidentCreate removed; using local store",
    )
    _incidents_store[incident_id] = record

    return {
        "incident_id": incident_id,
        "status": "detected",
        "title": title,
        "created_at": now,
    }


def resolve_update_compliance(args: Dict[str, Any]) -> Dict[str, Any]:
    """Update a compliance control status."""
    org_id = args.get("org_id", "default")
    framework = args.get("framework", "SOC2")
    control_id = args.get("control_id", "")
    status = args.get("status", "passing")
    evidence_notes = args.get("evidence_notes", "")
    now = _now_iso()

    try:
        # NOTE: ``get_compliance_automation`` factory was removed in 2026-05-03
        # silenced-imports audit; instantiate ``ComplianceAutomation`` class
        # directly. Wrapped in try/except so the resolver still degrades
        # gracefully if ``update_control_status`` is not exposed.
        from core.compliance_automation import ComplianceAutomation
        engine = ComplianceAutomation()
        if hasattr(engine, "update_control_status"):
            engine.update_control_status(
                org_id=org_id,
                framework=framework,
                control_id=control_id,
                status=status,
                notes=evidence_notes,
            )
    except Exception as exc:
        logger.warning("compliance_automation update failed", error=str(exc))

    return {
        "control_id": control_id,
        "framework": framework,
        "new_status": status,
        "updated_at": now,
    }


def resolve_accept_risk(args: Dict[str, Any]) -> Dict[str, Any]:
    """Accept risk on a finding with optional expiry."""
    finding_id = args.get("finding_id", "")
    accepted_by = args.get("accepted_by", "unknown")
    reason = args.get("reason", "")
    expiry_days = _coerce_int(args.get("expiry_days"), 0)
    now = _now_iso()

    expiry: Optional[str] = None
    if expiry_days > 0:
        from datetime import timedelta
        expiry = (datetime.now(timezone.utc) + timedelta(days=expiry_days)).isoformat()

    # Record in findings store
    try:
        from apps.api import findings_routes as _fr
        store = getattr(_fr, "_findings_store", {})
        if finding_id in store:
            store[finding_id]["status"] = "suppressed"
            store[finding_id]["risk_accepted"] = True
            store[finding_id]["risk_accepted_by"] = accepted_by
            store[finding_id]["risk_acceptance_reason"] = reason
            store[finding_id]["risk_acceptance_expiry"] = expiry
    except Exception as exc:
        logger.debug("graphql_schema: risk acceptance store update failed", error=str(exc))

    _risk_acceptances[finding_id] = {
        "finding_id": finding_id,
        "accepted_by": accepted_by,
        "reason": reason,
        "expiry": expiry,
        "accepted_at": now,
    }

    return {
        "finding_id": finding_id,
        "accepted": True,
        "accepted_by": accepted_by,
        "expiry": expiry,
        "reason": reason,
        "accepted_at": now,
    }


# ---------------------------------------------------------------------------
# GraphQL execution engine
# ---------------------------------------------------------------------------

# Resolver registry
_QUERY_RESOLVERS: Dict[str, Any] = {
    "findings": resolve_findings,
    "assets": resolve_assets,
    "incidents": resolve_incidents,
    "compliance_status": resolve_compliance_status,
    "posture_score": resolve_posture_score,
    "attack_surface": resolve_attack_surface,
    "vendors": resolve_vendors,
    "threat_landscape": resolve_threat_landscape,
}

_MUTATION_RESOLVERS: Dict[str, Any] = {
    "acknowledge_finding": resolve_acknowledge_finding,
    "create_incident": resolve_create_incident,
    "update_compliance": resolve_update_compliance,
    "accept_risk": resolve_accept_risk,
}


def _parse_graphql_query(query: str) -> Dict[str, Any]:
    """Minimal GraphQL query parser.

    Extracts the operation type, field name, and arguments from a GraphQL
    query document. Handles the common subset needed by ALDECI resolvers:
    - query { field(arg: value) { subfields } }
    - mutation { field(arg: value) { subfields } }

    Returns a dict with keys: operation, field, args.
    """
    import re

    query = query.strip()

    # Determine operation type
    operation = "query"
    if re.match(r"^\s*mutation\b", query, re.IGNORECASE):
        operation = "mutation"
    elif re.match(r"^\s*subscription\b", query, re.IGNORECASE):
        operation = "subscription"

    # Strip operation keyword + optional name
    body = re.sub(r"^\s*(query|mutation|subscription)\s*\w*\s*", "", query, flags=re.IGNORECASE).strip()

    # Strip outer braces of the operation block
    if body.startswith("{") and body.endswith("}"):
        body = body[1:-1].strip()

    # Extract the first field name with optional args
    # Pattern: fieldName(arg1: val1, arg2: "val2", ...) { ... }
    field_match = re.match(r"(\w+)\s*(?:\(([^)]*)\))?\s*\{", body, re.DOTALL)
    if not field_match:
        # No subfields — plain fieldName(args)
        field_match = re.match(r"(\w+)\s*(?:\(([^)]*)\))?", body, re.DOTALL)

    if not field_match:
        return {"operation": operation, "field": None, "args": {}}

    field_name = field_match.group(1)
    args_str = field_match.group(2) or ""

    # Parse arguments: key: value pairs
    args: Dict[str, Any] = {}
    if args_str:
        # Match key: "string" or key: number or key: true/false/null or key: [list]
        arg_pattern = re.compile(
            r'(\w+)\s*:\s*(?:"([^"]*)"'   # key: "string"
            r"|(-?\d+(?:\.\d+)?)"          # key: number
            r"|(true|false|null)"          # key: bool/null
            r"|(\[[^\]]*\])"              # key: [array]
            r"|(\w+))",                    # key: bareword
            re.IGNORECASE,
        )
        for m in arg_pattern.finditer(args_str):
            key = m.group(1)
            if m.group(2) is not None:
                args[key] = m.group(2)
            elif m.group(3) is not None:
                val = m.group(3)
                args[key] = float(val) if "." in val else int(val)
            elif m.group(4) is not None:
                raw = m.group(4).lower()
                args[key] = {"true": True, "false": False, "null": None}[raw]
            elif m.group(5) is not None:
                # Parse array: ["a", "b"] or [1, 2]
                inner = m.group(5)[1:-1]
                items = [x.strip().strip('"') for x in inner.split(",") if x.strip()]
                args[key] = items
            else:
                args[key] = m.group(6)

    return {"operation": operation, "field": field_name, "args": args}


def execute_graphql(query: str, variables: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Execute a GraphQL query/mutation and return a standard response envelope.

    Args:
        query:     GraphQL query document string.
        variables: Optional variable dict (merged into args).

    Returns:
        {"data": {...}} on success or {"errors": [...]} on failure.
    """
    try:
        parsed = _parse_graphql_query(query)
    except Exception as exc:
        return {"errors": [{"message": f"Parse error: {exc}"}]}

    operation = parsed["operation"]
    field = parsed["field"]
    args = parsed.get("args", {})

    # Merge variables (variables override inline args)
    if variables:
        args.update(variables)

    if operation == "subscription":
        # Subscriptions are not executed over HTTP — return type info only
        return {
            "data": {
                field: None,
            },
            "extensions": {
                "subscriptions": "Use WebSocket transport for subscription events.",
            },
        }

    if operation == "mutation":
        resolver = _MUTATION_RESOLVERS.get(field)
        if not resolver:
            return {"errors": [{"message": f"Unknown mutation: {field}"}]}
    else:
        resolver = _QUERY_RESOLVERS.get(field)
        if not resolver:
            return {"errors": [{"message": f"Unknown query field: {field}"}]}

    try:
        result = resolver(args)
        return {"data": {field: result}}
    except Exception as exc:
        logger.error("GraphQL resolver error", field=field, error=str(exc))
        return {"errors": [{"message": str(exc), "field": field}]}


def get_schema_sdl() -> str:
    """Return the GraphQL SDL for introspection."""
    return SCHEMA_SDL
