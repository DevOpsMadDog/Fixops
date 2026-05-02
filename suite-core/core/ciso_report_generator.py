"""CISO Report Generator — ALDECI.

Aggregates data from all 50+ ALDECI engines to produce a weekly CISO briefing
package. Each engine is imported with try/except so the generator degrades
gracefully when individual engines are unavailable.

Classes:
    CISOReportGenerator  — main aggregator + export
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _safe(fn, default=None):
    """Call fn(), return default on any exception."""
    try:
        return fn()
    except Exception as exc:  # noqa: BLE001
        _logger.debug("Engine call failed: %s", exc)
        return default


# ---------------------------------------------------------------------------
# CISOReportGenerator
# ---------------------------------------------------------------------------

class CISOReportGenerator:
    """Aggregates data from all ALDECI engines into a weekly CISO briefing."""

    def __init__(self) -> None:
        self._vuln_prio = None
        self._attack_path = None
        self._insider_threat = None
        self._threat_feed = None
        self._soc_triage = None
        self._compliance_scanner = None
        self._posture_score = None
        self._security_health = None
        self._incident_timeline = None
        self._vuln_workflow = None
        self._vuln_trend = None

    # ------------------------------------------------------------------
    # Lazy engine loaders (each with graceful fallback)
    # ------------------------------------------------------------------

    def _get_vuln_prio(self, org_id: str):
        try:
            from core.vuln_prioritization_engine import (
                VulnerabilityPrioritizationEngine,
            )
            return VulnerabilityPrioritizationEngine(org_id=org_id)
        except Exception:
            return None

    def _get_attack_path(self):
        try:
            from core.attack_path_engine import AttackPathEngine
            return AttackPathEngine()
        except Exception:
            return None

    def _get_insider_threat(self, org_id: str):
        try:
            from core.insider_threat_engine import InsiderThreatEngine
            return InsiderThreatEngine(org_id=org_id)
        except Exception:
            return None

    def _get_threat_feed(self):
        try:
            from core.threat_feed_aggregator import ThreatFeedAggregator
            return ThreatFeedAggregator()
        except Exception:
            return None

    def _get_soc_triage(self, org_id: str):
        try:
            from core.soc_triage_engine import SOCTriageEngine
            return SOCTriageEngine.for_org(org_id)
        except Exception:
            return None

    def _get_compliance_scanner(self):
        try:
            from core.compliance_scanner_engine import ComplianceScannerEngine
            return ComplianceScannerEngine()
        except Exception:
            return None

    def _get_posture_score(self):
        try:
            from core.posture_score_engine import PostureScoreEngine
            return PostureScoreEngine()
        except Exception:
            return None

    def _get_security_health(self):
        try:
            from core.security_health_engine import SecurityHealthEngine
            return SecurityHealthEngine()
        except Exception:
            return None

    def _get_incident_timeline(self):
        try:
            from core.incident_timeline_engine import IncidentTimelineEngine
            return IncidentTimelineEngine()
        except Exception:
            return None

    def _get_vuln_workflow(self, org_id: str):
        try:
            from core.vuln_workflow_engine import VulnWorkflowEngine
            return VulnWorkflowEngine.for_org(org_id)
        except Exception:
            return None

    def _get_vuln_trend(self):
        try:
            from core.vuln_trend_engine import VulnTrendEngine
            return VulnTrendEngine()
        except Exception:
            return None

    # ------------------------------------------------------------------
    # Section collectors
    # ------------------------------------------------------------------

    def _collect_vulnerabilities(self, org_id: str) -> Dict[str, Any]:
        section: Dict[str, Any] = {
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "total_scored": 0,
            "top_critical": [],
            "sla_breaches": 0,
            "open_tickets": 0,
            "overdue_tickets": 0,
            "trend": "stable",
        }

        # Vuln prioritization stats
        vp = self._get_vuln_prio(org_id)
        if vp:
            stats = _safe(lambda: vp.get_stats(org_id), {})
            section["critical_count"] = stats.get("critical", 0)
            section["high_count"] = stats.get("high", 0)
            section["medium_count"] = stats.get("medium", 0)
            section["total_scored"] = stats.get("total", 0)
            top = _safe(lambda: vp.get_top_critical(org_id, limit=5), [])
            section["top_critical"] = top or []

        # Vuln workflow stats
        vw = self._get_vuln_workflow(org_id)
        if vw:
            ws = _safe(lambda: vw.get_workflow_stats(org_id), {})
            section["open_tickets"] = ws.get("open_tickets", 0)
            section["overdue_tickets"] = ws.get("overdue_tickets", 0)
            section["sla_breaches"] = ws.get("sla_breaches", 0)

        # Vuln trend
        vt = self._get_vuln_trend()
        if vt:
            ts = _safe(lambda: vt.get_trend_stats(org_id), {})
            section["trend"] = ts.get("trend", "stable")
            sla_breaches = _safe(lambda: vt.check_sla_breaches(org_id), [])
            if sla_breaches and section["sla_breaches"] == 0:
                section["sla_breaches"] = len(sla_breaches)

        return section

    def _collect_threats(self, org_id: str) -> Dict[str, Any]:
        section: Dict[str, Any] = {
            "active_attack_paths": 0,
            "crown_jewels_at_risk": 0,
            "insider_threat_alerts": 0,
            "high_risk_users": 0,
            "threat_feed_items": 0,
            "feed_sources": 0,
            "ioc_count": 0,
        }

        # Attack paths
        ap = self._get_attack_path()
        if ap:
            gs = _safe(lambda: ap.get_graph_stats(org_id=org_id), {})
            section["active_attack_paths"] = gs.get("path_count", gs.get("edge_count", 0))
            cj = _safe(lambda: ap.get_crown_jewels_at_risk(org_id=org_id), [])
            section["crown_jewels_at_risk"] = len(cj) if cj else 0

        # Insider threat
        it = self._get_insider_threat(org_id)
        if it:
            rs = _safe(lambda: it.get_org_risk_summary(org_id=org_id), {})
            section["insider_threat_alerts"] = rs.get("total_alerts", 0)
            section["high_risk_users"] = rs.get("high_risk_users", 0)

        # Threat feed
        tf = self._get_threat_feed()
        if tf:
            fs = _safe(lambda: tf.get_feed_stats(org_id), {})
            section["threat_feed_items"] = fs.get("total_items", 0)
            section["feed_sources"] = fs.get("total_sources", 0)
            section["ioc_count"] = fs.get("ioc_count", 0)

        return section

    def _collect_compliance(self, org_id: str) -> Dict[str, Any]:
        section: Dict[str, Any] = {
            "overall_score": 0,
            "passing_checks": 0,
            "failing_checks": 0,
            "total_checks": 0,
            "open_remediation_tasks": 0,
            "compliance_grade": "N/A",
        }

        cs = self._get_compliance_scanner()
        if cs:
            stats = _safe(lambda: cs.get_compliance_stats(org_id), {})
            section["overall_score"] = stats.get("avg_score", 0)
            section["passing_checks"] = stats.get("passing", 0)
            section["failing_checks"] = stats.get("failing", 0)
            section["total_checks"] = stats.get("total_checks", 0)
            section["open_remediation_tasks"] = stats.get("open_tasks", 0)
            score = section["overall_score"]
            if score >= 90:
                section["compliance_grade"] = "A"
            elif score >= 80:
                section["compliance_grade"] = "B"
            elif score >= 70:
                section["compliance_grade"] = "C"
            elif score >= 60:
                section["compliance_grade"] = "D"
            else:
                section["compliance_grade"] = "F"

        return section

    def _collect_incidents(self, org_id: str) -> Dict[str, Any]:
        section: Dict[str, Any] = {
            "open_incidents": 0,
            "resolved_this_week": 0,
            "avg_mttd_minutes": None,
            "avg_mttr_minutes": None,
            "health_score": 0,
            "health_trend": "stable",
        }

        # Incident timeline
        it = self._get_incident_timeline()
        if it:
            ts = _safe(lambda: it.get_timeline_stats(org_id), {})
            section["open_incidents"] = ts.get("open_timelines", ts.get("active_timelines", 0))
            section["resolved_this_week"] = ts.get("resolved_this_week", 0)
            section["avg_mttd_minutes"] = ts.get("avg_mttd_minutes")
            section["avg_mttr_minutes"] = ts.get("avg_mttr_minutes")

        # Security health
        sh = self._get_security_health()
        if sh:
            hs = _safe(lambda: sh.get_health_stats(org_id), {})
            section["health_score"] = hs.get("avg_score", hs.get("health_score", 0))
            section["health_trend"] = hs.get("trend", "stable")

        return section

    def _collect_operations(self, org_id: str) -> Dict[str, Any]:
        section: Dict[str, Any] = {
            "alerts_ingested": 0,
            "alerts_resolved": 0,
            "alerts_false_positive": 0,
            "avg_triage_seconds": None,
            "posture_score": 0,
            "posture_trend": "stable",
            "posture_grade": "N/A",
        }

        # SOC triage
        st = self._get_soc_triage(org_id)
        if st:
            ts = _safe(lambda: st.get_triage_stats(org_id), {})
            section["alerts_ingested"] = ts.get("total_alerts", 0)
            section["alerts_resolved"] = ts.get("resolved", 0)
            section["alerts_false_positive"] = ts.get("false_positive", 0)
            section["avg_triage_seconds"] = ts.get("avg_triage_seconds")

        # Posture score
        ps = self._get_posture_score()
        if ps:
            pstats = _safe(lambda: ps.get_posture_stats(org_id), {})
            section["posture_score"] = pstats.get("current_score", 0)
            section["posture_trend"] = pstats.get("trend", "stable")
            # Also try compute if no saved score
            if section["posture_score"] == 0:
                computed = _safe(lambda: ps.compute_posture_score(org_id), {})
                section["posture_score"] = computed.get("overall_score", 0)
                section["posture_trend"] = computed.get("trend", "stable")
            score = section["posture_score"]
            if score >= 90:
                section["posture_grade"] = "A"
            elif score >= 80:
                section["posture_grade"] = "B"
            elif score >= 70:
                section["posture_grade"] = "C"
            elif score >= 60:
                section["posture_grade"] = "D"
            else:
                section["posture_grade"] = "F"

        return section

    # ------------------------------------------------------------------
    # Core report assembly
    # ------------------------------------------------------------------

    def _assemble_report(self, org_id: str, days: int = 7) -> Dict[str, Any]:
        now = _utcnow()
        period_start = now - timedelta(days=days)

        vulns = self._collect_vulnerabilities(org_id)
        threats = self._collect_threats(org_id)
        compliance = self._collect_compliance(org_id)
        incidents = self._collect_incidents(org_id)
        operations = self._collect_operations(org_id)

        # Derive overall risk posture score (weighted composite)
        posture_score = self._compute_risk_posture(
            vulns=vulns,
            threats=threats,
            compliance=compliance,
            operations=operations,
        )

        top_risks = self._derive_top_risks(
            org_id=org_id,
            vulns=vulns,
            threats=threats,
            compliance=compliance,
            incidents=incidents,
            operations=operations,
        )

        exec_summary = self._derive_executive_summary(
            posture_score=posture_score,
            vulns=vulns,
            threats=threats,
            compliance=compliance,
            incidents=incidents,
        )

        recommended_actions = self._derive_recommended_actions(
            vulns=vulns,
            threats=threats,
            compliance=compliance,
            incidents=incidents,
            operations=operations,
        )

        return {
            "generated_at": _iso(now),
            "org_id": org_id,
            "report_period": {
                "start": _iso(period_start),
                "end": _iso(now),
                "days": days,
            },
            "executive_summary": exec_summary,
            "risk_posture": posture_score,
            "top_risks": top_risks,
            "sections": {
                "vulnerabilities": vulns,
                "threats": threats,
                "compliance": compliance,
                "incidents": incidents,
                "operations": operations,
            },
            "recommended_actions": recommended_actions,
        }

    def _compute_risk_posture(
        self,
        vulns: dict,
        threats: dict,
        compliance: dict,
        operations: dict,
    ) -> Dict[str, Any]:
        """Compute weighted risk posture score (0-100, higher = safer)."""
        # Weights: posture 30%, compliance 25%, vuln 25%, threats 20%
        posture_raw = operations.get("posture_score", 0)
        compliance_raw = compliance.get("overall_score", 0)

        # Vuln score: penalize for criticals/highs
        vuln_total = max(vulns.get("total_scored", 1), 1)
        vuln_critical = vulns.get("critical_count", 0)
        vuln_high = vulns.get("high_count", 0)
        vuln_penalty = min((vuln_critical * 10 + vuln_high * 3) / vuln_total, 50)
        vuln_score = max(100 - vuln_penalty, 0)

        # Threat score: penalize for attack paths and insider alerts
        attack_paths = threats.get("active_attack_paths", 0)
        insider_alerts = threats.get("insider_threat_alerts", 0)
        threat_penalty = min(attack_paths * 5 + insider_alerts * 2, 50)
        threat_score = max(100 - threat_penalty, 0)

        overall = (
            posture_raw * 0.30
            + compliance_raw * 0.25
            + vuln_score * 0.25
            + threat_score * 0.20
        )
        overall = round(overall, 1)

        # Simple delta: if posture improving, positive
        trend = operations.get("posture_trend", "stable")
        if trend in ("improving", "up"):
            delta = 3
        elif trend in ("declining", "down", "degrading"):
            delta = -3
        else:
            delta = 0

        return {
            "overall_score": overall,
            "delta": delta,
            "trend": trend,
            "components": {
                "posture": posture_raw,
                "compliance": compliance_raw,
                "vulnerability": round(vuln_score, 1),
                "threat": round(threat_score, 1),
            },
        }

    def _derive_top_risks(
        self,
        org_id: str,
        vulns: dict,
        threats: dict,
        compliance: dict,
        incidents: dict,
        operations: dict,
        limit: int = 5,
    ) -> List[Dict[str, Any]]:
        risks = []

        if vulns.get("critical_count", 0) > 0:
            risks.append({
                "rank": 1,
                "category": "vulnerability",
                "title": f"{vulns['critical_count']} Critical Vulnerabilities Unpatched",
                "severity": "critical",
                "description": (
                    f"{vulns['critical_count']} critical and {vulns.get('high_count', 0)} "
                    "high severity vulnerabilities require immediate remediation."
                ),
                "recommended_action": "Patch critical CVEs within 24h; high within 7 days.",
            })

        if threats.get("active_attack_paths", 0) > 0:
            risks.append({
                "rank": 2,
                "category": "threat",
                "title": f"{threats['active_attack_paths']} Active Attack Paths Detected",
                "severity": "high",
                "description": (
                    f"Attack path analysis identified {threats['active_attack_paths']} "
                    "exploitable paths to crown jewels."
                ),
                "recommended_action": "Segment network, close lateral movement vectors.",
            })

        if threats.get("insider_threat_alerts", 0) > 0:
            risks.append({
                "rank": 3,
                "category": "insider",
                "title": f"{threats['insider_threat_alerts']} Insider Threat Alerts",
                "severity": "high",
                "description": (
                    f"{threats['high_risk_users']} high-risk users flagged; "
                    f"{threats['insider_threat_alerts']} total alerts this week."
                ),
                "recommended_action": "Review high-risk user activity; engage HR for investigation.",
            })

        if compliance.get("failing_checks", 0) > 0:
            risks.append({
                "rank": 4,
                "category": "compliance",
                "title": f"{compliance['failing_checks']} Compliance Controls Failing",
                "severity": "medium",
                "description": (
                    f"Compliance score: {compliance.get('overall_score', 0):.1f}% "
                    f"(Grade: {compliance.get('compliance_grade', 'N/A')}). "
                    f"{compliance['failing_checks']} controls need remediation."
                ),
                "recommended_action": "Assign remediation tasks; prioritize by framework deadlines.",
            })

        if vulns.get("sla_breaches", 0) > 0:
            risks.append({
                "rank": 5,
                "category": "sla",
                "title": f"{vulns['sla_breaches']} SLA Breaches on Vulnerabilities",
                "severity": "medium",
                "description": (
                    f"{vulns['sla_breaches']} vulnerabilities exceeded SLA deadlines. "
                    f"{vulns.get('overdue_tickets', 0)} tickets overdue."
                ),
                "recommended_action": "Escalate overdue tickets; update SLA policies.",
            })

        # Backfill with generic low-severity items if needed
        if len(risks) < limit and incidents.get("open_incidents", 0) > 0:
            risks.append({
                "rank": len(risks) + 1,
                "category": "incident",
                "title": f"{incidents['open_incidents']} Open Security Incidents",
                "severity": "medium",
                "description": f"{incidents['open_incidents']} incidents currently open.",
                "recommended_action": "Review incident backlog; assign owners and target resolution.",
            })

        # Re-rank sequentially
        for i, r in enumerate(risks[:limit], start=1):
            r["rank"] = i

        return risks[:limit]

    def _derive_executive_summary(
        self,
        posture_score: dict,
        vulns: dict,
        threats: dict,
        compliance: dict,
        incidents: dict,
    ) -> List[str]:
        score = posture_score.get("overall_score", 0)
        trend = posture_score.get("trend", "stable")
        trend_word = "improving" if trend in ("improving", "up") else (
            "declining" if trend in ("declining", "down", "degrading") else "stable"
        )

        bullet1 = (
            f"Overall security posture score is {score:.1f}/100 ({trend_word}), "
            f"with {vulns.get('critical_count', 0)} critical and "
            f"{vulns.get('high_count', 0)} high severity vulnerabilities requiring immediate attention."
        )

        bullet2 = (
            f"Threat landscape: {threats.get('active_attack_paths', 0)} active attack paths detected, "
            f"{threats.get('insider_threat_alerts', 0)} insider threat alerts, and "
            f"{threats.get('threat_feed_items', 0)} threat intelligence items ingested this week."
        )

        comp_score = compliance.get("overall_score", 0)
        comp_grade = compliance.get("compliance_grade", "N/A")
        open_incidents = incidents.get("open_incidents", 0)
        bullet3 = (
            f"Compliance posture: {comp_score:.1f}% (Grade {comp_grade}) across active frameworks; "
            f"{open_incidents} open incidents with "
            f"avg MTTR {incidents.get('avg_mttr_minutes') or 'N/A'} minutes."
        )

        return [bullet1, bullet2, bullet3]

    def _derive_recommended_actions(
        self,
        vulns: dict,
        threats: dict,
        compliance: dict,
        incidents: dict,
        operations: dict,
    ) -> List[Dict[str, Any]]:
        actions = []
        priority = 1

        if vulns.get("critical_count", 0) > 0:
            actions.append({
                "priority": priority,
                "action": "Immediate patch cycle for critical vulnerabilities",
                "owner": "Vulnerability Management Team",
                "deadline": "24 hours",
                "impact": "Reduces critical attack surface",
            })
            priority += 1

        if threats.get("active_attack_paths", 0) > 0:
            actions.append({
                "priority": priority,
                "action": "Segment network to block lateral movement attack paths",
                "owner": "Network Security Team",
                "deadline": "48 hours",
                "impact": "Eliminates attack paths to crown jewels",
            })
            priority += 1

        if compliance.get("failing_checks", 0) > 0:
            actions.append({
                "priority": priority,
                "action": "Remediate failing compliance controls",
                "owner": "GRC Team",
                "deadline": "2 weeks",
                "impact": "Improves compliance grade and reduces audit risk",
            })
            priority += 1

        if vulns.get("sla_breaches", 0) > 0:
            actions.append({
                "priority": priority,
                "action": "Review and resolve SLA-breached vulnerability tickets",
                "owner": "Security Operations",
                "deadline": "48 hours",
                "impact": "Restores SLA compliance for vulnerability management",
            })
            priority += 1

        if threats.get("insider_threat_alerts", 0) > 0:
            actions.append({
                "priority": priority,
                "action": "Investigate flagged insider threat alerts and high-risk users",
                "owner": "Insider Threat Team / HR",
                "deadline": "72 hours",
                "impact": "Reduces insider risk exposure",
            })
            priority += 1

        return actions

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_weekly_brief(self, org_id: str) -> Dict[str, Any]:
        """Generate full CISO weekly brief pulling from all engines."""
        return self._assemble_report(org_id, days=7)

    def generate_executive_summary(self, org_id: str) -> Dict[str, Any]:
        """3-bullet point executive summary for board presentation."""
        report = self._assemble_report(org_id, days=7)
        return {
            "generated_at": report["generated_at"],
            "org_id": org_id,
            "period_start": report["report_period"]["start"],
            "period_end": report["report_period"]["end"],
            "executive_summary": report["executive_summary"],
            "risk_posture": report["risk_posture"],
        }

    def get_risk_posture_delta(self, org_id: str, days: int = 7) -> Dict[str, Any]:
        """Risk posture change over last N days."""
        report = self._assemble_report(org_id, days=days)
        posture = report["risk_posture"]
        return {
            "org_id": org_id,
            "period_days": days,
            "overall_score": posture["overall_score"],
            "delta": posture["delta"],
            "trend": posture["trend"],
            "components": posture["components"],
            "generated_at": report["generated_at"],
        }

    def get_top_risks(self, org_id: str, limit: int = 5) -> List[Dict[str, Any]]:
        """Top N risks requiring CISO attention this week."""
        report = self._assemble_report(org_id, days=7)
        return report["top_risks"][:limit]

    def get_trustgraph_context(self, org_id: str, entity_id: str) -> Dict[str, Any]:
        """Query TrustGraph for cross-domain context to enrich CISO reports.

        Returns related assets, findings, and incidents for a given entity.
        Degrades gracefully when TrustGraph is unavailable.
        """
        context: Dict[str, Any] = {
            "related_assets": [],
            "related_findings": [],
            "related_incidents": [],
            "trustgraph_available": False,
        }
        try:
            from trustgraph.knowledge_store import KnowledgeStore
            store = KnowledgeStore()
            context["trustgraph_available"] = True

            for core_id in (1, 2, 3):
                try:
                    results = store.search(core_id=core_id, query_text=entity_id, limit=10)
                    for entity in results:
                        if entity.org_id not in ("default", org_id):
                            continue
                        entry = {"id": entity.entity_id, "name": entity.name, "type": entity.entity_type}
                        etype = entity.entity_type.lower()
                        if etype in ("asset", "service", "host"):
                            context["related_assets"].append(entry)
                        elif etype in ("finding", "vulnerability", "cve"):
                            context["related_findings"].append(entry)
                        elif etype in ("incident", "breach", "alert"):
                            context["related_incidents"].append(entry)
                except Exception:
                    pass

            neighbors = store.get_neighbors(entity_id=entity_id, depth=1)
            for n in neighbors:
                if n.org_id not in ("default", org_id):
                    continue
                entry = {"id": n.entity_id, "name": n.name, "type": n.entity_type}
                etype = n.entity_type.lower()
                if etype in ("asset", "service", "host"):
                    if entry not in context["related_assets"]:
                        context["related_assets"].append(entry)
                elif etype in ("finding", "vulnerability", "cve"):
                    if entry not in context["related_findings"]:
                        context["related_findings"].append(entry)
                elif etype in ("incident", "breach", "alert"):
                    if entry not in context["related_incidents"]:
                        context["related_incidents"].append(entry)
        except Exception:
            pass
        return context

    def export_json(self, org_id: str) -> str:
        """Export full brief as JSON string."""
        report = self._assemble_report(org_id, days=7)
        return json.dumps(report, indent=2, default=str)

    def export_markdown(self, org_id: str) -> str:
        """Export as Markdown for Slack/email delivery."""
        report = self._assemble_report(org_id, days=7)
        now_str = report["generated_at"]
        posture = report["risk_posture"]
        sections = report["sections"]
        vulns = sections["vulnerabilities"]
        threats = sections["threats"]
        compliance = sections["compliance"]
        incidents = sections["incidents"]
        operations = sections["operations"]

        lines = [
            "# CISO Weekly Security Briefing",
            f"**Organization:** {org_id}  ",
            f"**Generated:** {now_str}  ",
            f"**Period:** {report['report_period']['start']} → {report['report_period']['end']}",
            "",
            "---",
            "",
            "## Executive Summary",
            "",
        ]
        for bullet in report["executive_summary"]:
            lines.append(f"- {bullet}")

        lines += [
            "",
            "---",
            "",
            "## Risk Posture",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Overall Score | **{posture['overall_score']}/100** |",
            f"| Delta (7d) | {'+' if posture['delta'] >= 0 else ''}{posture['delta']} |",
            f"| Trend | {posture['trend'].capitalize()} |",
            f"| Posture Component | {posture['components'].get('posture', 0)} |",
            f"| Compliance Component | {posture['components'].get('compliance', 0)} |",
            f"| Vulnerability Component | {posture['components'].get('vulnerability', 0)} |",
            f"| Threat Component | {posture['components'].get('threat', 0)} |",
            "",
            "---",
            "",
            "## Top Risks",
            "",
        ]
        for risk in report["top_risks"]:
            lines.append(
                f"### {risk['rank']}. [{risk['severity'].upper()}] {risk['title']}"
            )
            lines.append(f"{risk['description']}")
            lines.append(f"**Action:** {risk['recommended_action']}")
            lines.append("")

        lines += [
            "---",
            "",
            "## Vulnerability Summary",
            "",
            "| Metric | Count |",
            "|--------|-------|",
            f"| Critical | {vulns.get('critical_count', 0)} |",
            f"| High | {vulns.get('high_count', 0)} |",
            f"| Medium | {vulns.get('medium_count', 0)} |",
            f"| Total Scored | {vulns.get('total_scored', 0)} |",
            f"| Open Tickets | {vulns.get('open_tickets', 0)} |",
            f"| Overdue Tickets | {vulns.get('overdue_tickets', 0)} |",
            f"| SLA Breaches | {vulns.get('sla_breaches', 0)} |",
            f"| Trend | {vulns.get('trend', 'stable')} |",
            "",
            "---",
            "",
            "## Threat Intelligence",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Active Attack Paths | {threats.get('active_attack_paths', 0)} |",
            f"| Crown Jewels at Risk | {threats.get('crown_jewels_at_risk', 0)} |",
            f"| Insider Threat Alerts | {threats.get('insider_threat_alerts', 0)} |",
            f"| High-Risk Users | {threats.get('high_risk_users', 0)} |",
            f"| Threat Feed Items | {threats.get('threat_feed_items', 0)} |",
            f"| IOC Count | {threats.get('ioc_count', 0)} |",
            "",
            "---",
            "",
            "## Compliance",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Overall Score | {compliance.get('overall_score', 0):.1f}% |",
            f"| Grade | {compliance.get('compliance_grade', 'N/A')} |",
            f"| Passing Controls | {compliance.get('passing_checks', 0)} |",
            f"| Failing Controls | {compliance.get('failing_checks', 0)} |",
            f"| Open Remediation Tasks | {compliance.get('open_remediation_tasks', 0)} |",
            "",
            "---",
            "",
            "## Incidents & Health",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Open Incidents | {incidents.get('open_incidents', 0)} |",
            f"| Resolved This Week | {incidents.get('resolved_this_week', 0)} |",
            f"| Avg MTTD (min) | {incidents.get('avg_mttd_minutes') or 'N/A'} |",
            f"| Avg MTTR (min) | {incidents.get('avg_mttr_minutes') or 'N/A'} |",
            f"| Health Score | {incidents.get('health_score', 0)} |",
            "",
            "---",
            "",
            "## SOC Operations",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| Alerts Ingested | {operations.get('alerts_ingested', 0)} |",
            f"| Alerts Resolved | {operations.get('alerts_resolved', 0)} |",
            f"| False Positives | {operations.get('alerts_false_positive', 0)} |",
            f"| Posture Score | {operations.get('posture_score', 0)} |",
            f"| Posture Grade | {operations.get('posture_grade', 'N/A')} |",
            "",
            "---",
            "",
            "## Recommended Actions",
            "",
        ]
        for action in report["recommended_actions"]:
            lines.append(
                f"{action['priority']}. **{action['action']}**  "
            )
            lines.append(
                f"   Owner: {action['owner']} | Deadline: {action['deadline']} | "
                f"Impact: {action['impact']}"
            )
            lines.append("")

        lines += [
            "---",
            "",
            "*Generated by ALDECI CISO Report Generator*",
        ]

        return "\n".join(lines)
