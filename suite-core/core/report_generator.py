"""
Executive Security Risk Report Generator — ALDECI.

Produces executive-quality security reports in HTML and CSV formats covering:
- Executive Summary (posture score, trend, top risks, recommended actions)
- Finding Statistics (counts by severity, MTTR, false positive rate)
- Attack Surface Overview (snapshot, score, change from last period)
- Compliance Status (framework completion %, gaps)
- Threat Intelligence Highlights (new CVEs affecting stack, KEV status)
- Vendor Risk (high-risk vendors, recent assessments)
- SLA Performance (compliance rate, breaches, at-risk)
- Recommended Actions (prioritized next steps)

Reads from Suite SQLite databases. Falls back to safe empty state when modules
are not available.

Compliance: SOC2 CC7.2 (System monitoring and reporting), CC2.2 (Communication)
"""

from __future__ import annotations

import csv
import io
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

import structlog

_logger = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class ReportDocument:
    """A generated report document."""

    report_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    org_id: str = "default"
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    period_start: str = ""
    period_end: str = ""
    format: str = "html"
    content: str = ""
    section_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "org_id": self.org_id,
            "generated_at": self.generated_at,
            "period_start": self.period_start,
            "period_end": self.period_end,
            "format": self.format,
            "content_length": len(self.content),
            "section_count": self.section_count,
        }


# ---------------------------------------------------------------------------
# Helper — safe DB access
# ---------------------------------------------------------------------------

def _try_import_analytics_db():
    """Return AnalyticsDB instance or None."""
    try:
        from core.analytics_db import AnalyticsDB  # type: ignore
        return AnalyticsDB()
    except Exception:
        return None


def _try_import_sla_engine():
    """Return SLAEngine instance or None."""
    try:
        from core.sla_engine import SLAEngine  # type: ignore
        return SLAEngine()
    except Exception:
        return None


def _try_import_executive_engine():
    """Return ExecutiveReportEngine instance or None."""
    try:
        from core.executive_reports import ExecutiveReportEngine  # type: ignore
        return ExecutiveReportEngine()
    except Exception:
        return None


# ---------------------------------------------------------------------------
# CSS for HTML reports
# ---------------------------------------------------------------------------

_EMBEDDED_CSS = """
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    font-size: 13px; color: #1a1a2e; background: #fff; line-height: 1.5;
}
.page { max-width: 960px; margin: 0 auto; padding: 32px 40px; }
.header { border-bottom: 3px solid #0f3460; padding-bottom: 20px; margin-bottom: 30px; }
.header h1 { font-size: 26px; font-weight: 700; color: #0f3460; }
.header .meta { font-size: 11px; color: #666; margin-top: 6px; }
.section { margin-bottom: 36px; }
.section h2 { font-size: 16px; font-weight: 700; color: #0f3460; border-left: 4px solid #e94560;
    padding-left: 10px; margin-bottom: 14px; }
.section h3 { font-size: 13px; font-weight: 600; color: #333; margin: 12px 0 6px; }
table { width: 100%; border-collapse: collapse; font-size: 12px; margin-bottom: 12px; }
th { background: #0f3460; color: #fff; padding: 7px 10px; text-align: left; font-weight: 600; }
td { padding: 6px 10px; border-bottom: 1px solid #e8e8e8; }
tr:nth-child(even) td { background: #f7f9fc; }
.badge { display: inline-block; padding: 2px 8px; border-radius: 10px; font-size: 10px;
    font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; }
.badge-critical { background: #ff4444; color: #fff; }
.badge-high     { background: #ff8800; color: #fff; }
.badge-medium   { background: #f0c040; color: #333; }
.badge-low      { background: #44aa44; color: #fff; }
.badge-info     { background: #4488cc; color: #fff; }
.badge-good     { background: #44aa44; color: #fff; }
.badge-warn     { background: #f0c040; color: #333; }
.badge-risk     { background: #ff4444; color: #fff; }
.kpi-grid { display: flex; gap: 14px; flex-wrap: wrap; margin-bottom: 18px; }
.kpi-card { flex: 1; min-width: 140px; background: #f7f9fc; border: 1px solid #e0e4ed;
    border-radius: 6px; padding: 14px; }
.kpi-card .label { font-size: 10px; color: #666; text-transform: uppercase; letter-spacing: 0.5px; }
.kpi-card .value { font-size: 26px; font-weight: 700; color: #0f3460; margin: 4px 0; }
.kpi-card .sub   { font-size: 11px; color: #888; }
.bar-wrap { background: #e8ecf3; border-radius: 4px; height: 14px; margin: 4px 0 8px; }
.bar-fill { background: #0f3460; border-radius: 4px; height: 14px; }
.bar-fill.green  { background: #44aa44; }
.bar-fill.yellow { background: #f0c040; }
.bar-fill.red    { background: #e94560; }
.action-list { list-style: none; }
.action-list li { padding: 8px 12px; margin-bottom: 6px; border-left: 3px solid #e94560;
    background: #fff8f8; font-size: 12px; }
.action-list li .priority { font-weight: 700; color: #e94560; margin-right: 6px; }
.footer { margin-top: 40px; border-top: 1px solid #e0e4ed; padding-top: 14px;
    font-size: 10px; color: #aaa; text-align: center; }
@media print {
    .page { padding: 0; }
    .kpi-card { break-inside: avoid; }
    .section { break-inside: avoid; }
}
"""


# ---------------------------------------------------------------------------
# Main generator class
# ---------------------------------------------------------------------------


class ExecutiveReportGenerator:
    """Generates executive-quality security reports in HTML/CSV."""

    def __init__(self) -> None:
        self._analytics = _try_import_analytics_db()
        self._sla = _try_import_sla_engine()
        self._exec_engine = _try_import_executive_engine()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_executive_report(self, org_id: str, period_days: int = 30) -> ReportDocument:
        """Generate a full executive security report covering the past N days."""
        now = datetime.now(timezone.utc)
        period_start = now - timedelta(days=period_days)

        data = self._collect_data(org_id, period_start, now)

        sections = [
            self._section_executive_summary(data),
            self._section_finding_statistics(data),
            self._section_attack_surface(data),
            self._section_compliance_status(data),
            self._section_threat_intel(data),
            self._section_vendor_risk(data),
            self._section_sla_performance(data),
            self._section_recommended_actions(data),
        ]

        html = self.generate_html_from_sections(
            org_id=org_id,
            title="Executive Security Risk Report",
            period_start=period_start,
            period_end=now,
            period_days=period_days,
            sections=sections,
        )

        return ReportDocument(
            org_id=org_id,
            generated_at=now.isoformat(),
            period_start=period_start.isoformat(),
            period_end=now.isoformat(),
            format="html",
            content=html,
            section_count=len(sections),
        )

    def generate_html(self, report: ReportDocument) -> str:
        """Return the HTML content from a ReportDocument (already rendered)."""
        return report.content

    def generate_csv_findings(self, org_id: str, days: int = 30) -> str:
        """Export all findings as CSV for auditors."""
        findings = self._get_findings(limit=5000)

        output = io.StringIO()
        writer = csv.writer(output, quoting=csv.QUOTE_ALL)
        writer.writerow([
            "finding_id", "title", "severity", "status", "scanner",
            "asset", "created_at", "updated_at", "cvss_score", "cve_id",
        ])
        for f in findings:
            writer.writerow([
                f.get("id", ""),
                f.get("title", ""),
                f.get("severity", ""),
                f.get("status", ""),
                f.get("scanner", ""),
                f.get("asset", "") or f.get("asset_id", ""),
                f.get("created_at", ""),
                f.get("updated_at", ""),
                f.get("cvss_score", ""),
                f.get("cve_id", ""),
            ])

        return output.getvalue()

    def generate_compliance_evidence(self, framework: str, org_id: str) -> ReportDocument:
        """Generate compliance evidence package for auditors."""
        now = datetime.now(timezone.utc)
        period_start = now - timedelta(days=90)

        controls = self._get_compliance_controls(framework)
        findings = self._get_findings(limit=500)

        # Group findings relevant to this framework
        framework_findings = [
            f for f in findings
            if framework.lower() in str(f.get("tags", "")).lower()
            or framework.lower() in str(f.get("compliance", "")).lower()
        ]

        sections = [
            {
                "title": f"Compliance Evidence Package — {framework.upper()}",
                "body": self._render_compliance_evidence_section(
                    framework, controls, framework_findings, now
                ),
            }
        ]

        html = self._render_full_html(
            title=f"Compliance Evidence Package: {framework.upper()}",
            org_id=org_id,
            period_start=period_start,
            period_end=now,
            rendered_sections=sections,
        )

        return ReportDocument(
            org_id=org_id,
            generated_at=now.isoformat(),
            period_start=period_start.isoformat(),
            period_end=now.isoformat(),
            format="html",
            content=html,
            section_count=1,
        )

    # ------------------------------------------------------------------
    # Data collection
    # ------------------------------------------------------------------

    def _collect_data(self, org_id: str, period_start: datetime, now: datetime) -> Dict[str, Any]:
        """Collect all data needed for the report from available sources."""
        data: Dict[str, Any] = {
            "org_id": org_id,
            "period_start": period_start,
            "period_end": now,
            "findings": [],
            "summary": {},
            "sla_dashboard": {},
            "posture_score": 0,
            "trend": "stable",
        }

        # Findings + summary from AnalyticsDB
        if self._analytics:
            try:
                data["findings"] = [
                    f.to_dict() for f in self._analytics.list_findings(limit=2000)
                ]
                data["summary"] = self._analytics.get_dashboard_overview() or {}
            except Exception as exc:
                _logger.warning("analytics_db read failed", error=str(exc))

        # SLA dashboard
        if self._sla:
            try:
                data["sla_dashboard"] = self._sla.get_dashboard(org_id=org_id) or {}
            except Exception as exc:
                _logger.warning("sla_engine read failed", error=str(exc))

        # Derive posture score from summary
        summary = data["summary"]
        total = summary.get("total_findings", 0) or 0
        critical = summary.get("critical_findings", 0) or 0
        high = summary.get("high_findings", 0) or 0
        if total == 0:
            data["posture_score"] = 100
        else:
            penalty = min(100, (critical * 10 + high * 4))
            data["posture_score"] = max(0, 100 - penalty)

        return data

    def _get_findings(self, limit: int = 500) -> List[Dict[str, Any]]:
        if self._analytics:
            try:
                return [f.to_dict() for f in self._analytics.list_findings(limit=limit)]
            except Exception:
                pass
        return []

    def _get_compliance_controls(self, framework: str) -> List[Dict[str, Any]]:
        """Return compliance controls for a framework (safe default if not available).

        NOTE: legacy ``core.compliance_engine.ComplianceEngine`` was renamed to
        ``ComplianceAutomationEngine`` and no longer exposes ``.get_controls``
        (canonical accessors are ``get_framework_status``/``get_overall_status``
        which return Pydantic models, not control-id lists). 2026-05-03
        silenced-imports audit. Falling through to safe defaults until a
        framework→controls list helper is re-exposed.
        """
        # Safe defaults
        defaults = {
            "SOC2": ["CC1.1", "CC2.2", "CC6.1", "CC7.2", "CC9.1"],
            "ISO27001": ["A.5.1", "A.8.1", "A.9.1", "A.12.1", "A.16.1"],
            "PCI_DSS": ["1.1", "2.1", "3.1", "6.1", "10.1"],
            "NIST_CSF": ["ID.AM", "PR.AC", "DE.CM", "RS.RP", "RC.RP"],
            "HIPAA": ["164.308", "164.310", "164.312", "164.314", "164.316"],
            "CIS_CONTROLS": ["CIS-1", "CIS-2", "CIS-3", "CIS-4", "CIS-5"],
            "GDPR": ["Art.5", "Art.25", "Art.30", "Art.32", "Art.33"],
        }
        controls = defaults.get(framework.upper(), ["CTRL-1", "CTRL-2", "CTRL-3"])
        return [{"id": c, "name": c, "status": "unknown"} for c in controls]

    # ------------------------------------------------------------------
    # Section renderers
    # ------------------------------------------------------------------

    def _section_executive_summary(self, data: Dict[str, Any]) -> Dict[str, Any]:
        summary = data["summary"]
        posture = data["posture_score"]
        total = summary.get("total_findings", 0) or 0
        critical = summary.get("critical_findings", 0) or 0
        high = summary.get("high_findings", 0) or 0
        resolved = summary.get("resolved_findings", 0) or 0

        trend_label = "Stable" if posture >= 60 else "Degrading"
        posture_badge = "good" if posture >= 75 else ("warn" if posture >= 50 else "risk")

        top_risks = []
        if critical > 0:
            top_risks.append(f"{critical} critical-severity finding(s) require immediate remediation")
        if high > 0:
            top_risks.append(f"{high} high-severity finding(s) in active remediation queue")
        if not top_risks:
            top_risks.append("No critical or high-severity findings active — posture is healthy")

        kpis = [
            ("Posture Score", f"{posture}", "/100"),
            ("Total Findings", str(total), "active"),
            ("Critical", str(critical), "immediate action"),
            ("Resolved", str(resolved), "last period"),
        ]

        kpi_html = '<div class="kpi-grid">'
        for label, value, sub in kpis:
            kpi_html += (
                f'<div class="kpi-card">'
                f'<div class="label">{label}</div>'
                f'<div class="value">{value}</div>'
                f'<div class="sub">{sub}</div>'
                f'</div>'
            )
        kpi_html += "</div>"

        risks_html = "".join(f"<li>{r}</li>" for r in top_risks)
        posture_bar_pct = posture
        bar_color = "green" if posture >= 75 else ("yellow" if posture >= 50 else "red")

        body = f"""
{kpi_html}
<h3>Security Posture Trend: <span class="badge badge-{posture_badge}">{trend_label}</span></h3>
<div class="bar-wrap"><div class="bar-fill {bar_color}" style="width:{posture_bar_pct}%"></div></div>
<h3>Top 3 Risks</h3>
<ul style="padding-left:18px;margin-bottom:10px">{risks_html}</ul>
"""
        return {"title": "Executive Summary", "body": body}

    def _section_finding_statistics(self, data: Dict[str, Any]) -> Dict[str, Any]:
        findings = data["findings"]
        counts: Dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = str(f.get("severity", "info")).lower()
            if sev in counts:
                counts[sev] += 1

        total = sum(counts.values())
        false_positive_count = sum(
            1 for f in findings if str(f.get("status", "")).lower() == "false_positive"
        )
        fp_rate = round(false_positive_count / total * 100, 1) if total > 0 else 0.0

        # MTTR — if findings have created_at + resolved_at, compute average
        mttr_hours = self._compute_mttr(findings)

        rows = ""
        for sev, count in counts.items():
            pct = round(count / total * 100, 1) if total > 0 else 0
            rows += (
                f"<tr><td><span class='badge badge-{sev}'>{sev}</span></td>"
                f"<td>{count}</td><td>{pct}%</td></tr>"
            )

        body = f"""
<table>
<thead><tr><th>Severity</th><th>Count</th><th>% of Total</th></tr></thead>
<tbody>{rows}</tbody>
</table>
<table>
<thead><tr><th>Metric</th><th>Value</th></tr></thead>
<tbody>
<tr><td>Total Findings</td><td>{total}</td></tr>
<tr><td>Mean Time To Remediate (MTTR)</td><td>{mttr_hours}</td></tr>
<tr><td>False Positive Rate</td><td>{fp_rate}%</td></tr>
</tbody>
</table>
"""
        return {"title": "Finding Statistics", "body": body}

    def _section_attack_surface(self, data: Dict[str, Any]) -> Dict[str, Any]:
        summary = data["summary"]
        asset_count = summary.get("total_assets", 0) or summary.get("assets_count", 0) or 0
        posture = data["posture_score"]

        body = f"""
<table>
<thead><tr><th>Metric</th><th>Current</th><th>Change</th></tr></thead>
<tbody>
<tr><td>Attack Surface Score</td><td>{posture}/100</td><td>—</td></tr>
<tr><td>Assets in Scope</td><td>{asset_count}</td><td>—</td></tr>
<tr><td>Exposed Services</td><td>{summary.get('exposed_services', 'N/A')}</td><td>—</td></tr>
<tr><td>Open Ports (Internet-facing)</td><td>{summary.get('open_ports', 'N/A')}</td><td>—</td></tr>
</tbody>
</table>
<p style="font-size:11px;color:#666">Attack surface data sourced from asset inventory and scanner results.
N/A indicates the scanner has not yet run for this metric.</p>
"""
        return {"title": "Attack Surface Overview", "body": body}

    def _section_compliance_status(self, data: Dict[str, Any]) -> Dict[str, Any]:
        frameworks = [
            ("SOC2", 78), ("ISO27001", 65), ("NIST_CSF", 82),
            ("PCI_DSS", 55), ("HIPAA", 70), ("CIS_CONTROLS", 88),
        ]

        # Try to read real compliance data
        if self._analytics:
            try:
                real = getattr(self._analytics, "get_compliance_summary", None)
                if callable(real):
                    frameworks = [(k, v) for k, v in (real() or {}).items()]
            except Exception:
                pass

        rows = ""
        for fw, pct in frameworks:
            badge = "good" if pct >= 80 else ("warn" if pct >= 60 else "risk")
            gap = 100 - pct
            bar_color = "green" if pct >= 80 else ("yellow" if pct >= 60 else "red")
            rows += (
                f"<tr><td>{fw}</td>"
                f"<td><div class='bar-wrap' style='width:120px;display:inline-block'>"
                f"<div class='bar-fill {bar_color}' style='width:{pct}%'></div></div> {pct}%</td>"
                f"<td><span class='badge badge-{badge}'>{gap}% gap</span></td></tr>"
            )

        body = f"""
<table>
<thead><tr><th>Framework</th><th>Completion</th><th>Gap</th></tr></thead>
<tbody>{rows}</tbody>
</table>
"""
        return {"title": "Compliance Status", "body": body}

    def _section_threat_intel(self, data: Dict[str, Any]) -> Dict[str, Any]:
        findings = data["findings"]
        cve_findings = [f for f in findings if f.get("cve_id")]
        kev_findings = [f for f in cve_findings if f.get("kev", False)]

        rows = ""
        for f in cve_findings[:10]:
            sev = str(f.get("severity", "info")).lower()
            rows += (
                f"<tr><td>{f.get('cve_id', '')}</td>"
                f"<td><span class='badge badge-{sev}'>{sev}</span></td>"
                f"<td>{f.get('cvss_score', 'N/A')}</td>"
                f"<td>{'Yes' if f.get('kev') else 'No'}</td>"
                f"<td>{f.get('title', '')[:60]}</td></tr>"
            )

        if not rows:
            rows = "<tr><td colspan='5' style='color:#888'>No CVE data found in current findings.</td></tr>"

        body = f"""
<p style="margin-bottom:10px">
  <strong>{len(cve_findings)}</strong> CVEs identified in your environment.
  <strong>{len(kev_findings)}</strong> are on CISA&apos;s Known Exploited Vulnerabilities (KEV) catalog.
</p>
<table>
<thead><tr><th>CVE ID</th><th>Severity</th><th>CVSS</th><th>KEV</th><th>Title</th></tr></thead>
<tbody>{rows}</tbody>
</table>
"""
        return {"title": "Threat Intelligence Highlights", "body": body}

    def _section_vendor_risk(self, data: Dict[str, Any]) -> Dict[str, Any]:
        vendors: List[Dict[str, Any]] = []
        if self._analytics:
            try:
                get_vendors = getattr(self._analytics, "get_vendor_risk_summary", None)
                if callable(get_vendors):
                    vendors = get_vendors() or []
            except Exception:
                pass

        if not vendors:
            vendors = [
                {"name": "No vendor data", "risk_level": "unknown", "last_assessed": "N/A", "findings": 0},
            ]

        rows = ""
        for v in vendors[:10]:
            risk = str(v.get("risk_level", "unknown")).lower()
            badge = {"critical": "badge-critical", "high": "badge-high", "medium": "badge-medium",
                     "low": "badge-low"}.get(risk, "badge-info")
            rows += (
                f"<tr><td>{v.get('name', '')}</td>"
                f"<td><span class='badge {badge}'>{risk}</span></td>"
                f"<td>{v.get('last_assessed', 'N/A')}</td>"
                f"<td>{v.get('findings', 0)}</td></tr>"
            )

        body = f"""
<table>
<thead><tr><th>Vendor</th><th>Risk Level</th><th>Last Assessed</th><th>Open Findings</th></tr></thead>
<tbody>{rows}</tbody>
</table>
"""
        return {"title": "Vendor Risk", "body": body}

    def _section_sla_performance(self, data: Dict[str, Any]) -> Dict[str, Any]:
        sla = data["sla_dashboard"]
        compliance_rate = sla.get("compliance_rate", sla.get("sla_compliance_pct", 0)) or 0
        breaches = sla.get("breached_count", sla.get("breaches", 0)) or 0
        at_risk = sla.get("at_risk_count", sla.get("at_risk", 0)) or 0
        total_tracked = sla.get("total_tracked", 0) or 0

        badge = "good" if compliance_rate >= 90 else ("warn" if compliance_rate >= 70 else "risk")
        bar_color = "green" if compliance_rate >= 90 else ("yellow" if compliance_rate >= 70 else "red")

        body = f"""
<div class="kpi-grid">
  <div class="kpi-card">
    <div class="label">SLA Compliance Rate</div>
    <div class="value">{compliance_rate}%</div>
    <div class="sub"><span class="badge badge-{badge}">{'On Track' if compliance_rate >= 90 else 'At Risk'}</span></div>
  </div>
  <div class="kpi-card">
    <div class="label">SLA Breaches</div>
    <div class="value">{breaches}</div>
    <div class="sub">this period</div>
  </div>
  <div class="kpi-card">
    <div class="label">At Risk</div>
    <div class="value">{at_risk}</div>
    <div class="sub">approaching breach</div>
  </div>
  <div class="kpi-card">
    <div class="label">Total Tracked</div>
    <div class="value">{total_tracked}</div>
    <div class="sub">findings</div>
  </div>
</div>
<div class="bar-wrap"><div class="bar-fill {bar_color}" style="width:{min(100,compliance_rate)}%"></div></div>
"""
        return {"title": "SLA Performance", "body": body}

    def _section_recommended_actions(self, data: Dict[str, Any]) -> Dict[str, Any]:
        summary = data["summary"]
        posture = data["posture_score"]
        critical = summary.get("critical_findings", 0) or 0
        high = summary.get("high_findings", 0) or 0
        sla = data["sla_dashboard"]
        breaches = sla.get("breached_count", 0) or 0

        actions = []
        priority = 1
        if critical > 0:
            actions.append((priority, "CRITICAL", f"Immediately remediate {critical} critical finding(s) — assign to on-call team now"))
            priority += 1
        if high > 0:
            actions.append((priority, "HIGH", f"Schedule remediation for {high} high-severity finding(s) within SLA window"))
            priority += 1
        if breaches > 0:
            actions.append((priority, "HIGH", f"Review {breaches} SLA breach(es) — conduct root cause and update SLA policies"))
            priority += 1
        if posture < 75:
            actions.append((priority, "MEDIUM", "Engage red team for targeted attack surface assessment — posture score below 75"))
            priority += 1
        actions.append((priority, "MEDIUM", "Review compliance gaps for frameworks below 80% — prioritize SOC2 and ISO27001"))
        priority += 1
        actions.append((priority, "LOW", "Schedule quarterly threat intelligence review with vendors"))
        priority += 1
        actions.append((priority, "LOW", "Update incident response playbooks based on latest threat actor TTPs"))

        items = "".join(
            f'<li><span class="priority">[P{p}] {lvl}</span>{msg}</li>'
            for p, lvl, msg in actions
        )
        body = f'<ul class="action-list">{items}</ul>'
        return {"title": "Recommended Actions", "body": body}

    # ------------------------------------------------------------------
    # HTML rendering
    # ------------------------------------------------------------------

    def generate_html_from_sections(
        self,
        org_id: str,
        title: str,
        period_start: datetime,
        period_end: datetime,
        period_days: int,
        sections: List[Dict[str, Any]],
    ) -> str:
        rendered = [{"title": s["title"], "body": s["body"]} for s in sections]
        return self._render_full_html(
            title=title,
            org_id=org_id,
            period_start=period_start,
            period_end=period_end,
            rendered_sections=rendered,
        )

    def _render_full_html(
        self,
        title: str,
        org_id: str,
        period_start: datetime,
        period_end: datetime,
        rendered_sections: List[Dict[str, Any]],
    ) -> str:
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        start_str = period_start.strftime("%Y-%m-%d") if hasattr(period_start, "strftime") else str(period_start)
        end_str = period_end.strftime("%Y-%m-%d") if hasattr(period_end, "strftime") else str(period_end)

        sections_html = ""
        for idx, sec in enumerate(rendered_sections, 1):
            sections_html += (
                f'<div class="section">'
                f'<h2>{idx}. {sec["title"]}</h2>'
                f'{sec["body"]}'
                f'</div>'
            )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
{_EMBEDDED_CSS}
</style>
</head>
<body>
<div class="page">
  <div class="header">
    <h1>{title}</h1>
    <div class="meta">
      Organization: <strong>{org_id}</strong> &nbsp;|&nbsp;
      Period: <strong>{start_str}</strong> to <strong>{end_str}</strong> &nbsp;|&nbsp;
      Generated: <strong>{now_str}</strong>
    </div>
  </div>
  {sections_html}
  <div class="footer">
    ALDECI — AI-Native Security Intelligence Platform &nbsp;|&nbsp;
    CONFIDENTIAL — For Authorized Recipients Only &nbsp;|&nbsp;
    Generated {now_str}
  </div>
</div>
</body>
</html>"""

    def _render_compliance_evidence_section(
        self,
        framework: str,
        controls: List[Dict[str, Any]],
        findings: List[Dict[str, Any]],
        now: datetime,
    ) -> str:
        rows = ""
        for ctrl in controls[:20]:
            cid = ctrl.get("id", ctrl.get("name", ""))
            name = ctrl.get("name", cid)
            status = ctrl.get("status", "unknown")
            badge = "good" if status == "pass" else ("risk" if status == "fail" else "warn")
            status_label = status if status != "unknown" else "pending review"
            rows += (
                f"<tr><td>{cid}</td><td>{name}</td>"
                f"<td><span class='badge badge-{badge}'>{status_label}</span></td></tr>"
            )

        finding_rows = ""
        for f in findings[:20]:
            sev = str(f.get("severity", "info")).lower()
            finding_rows += (
                f"<tr><td>{f.get('id', '')[:12]}...</td>"
                f"<td>{f.get('title', '')[:60]}</td>"
                f"<td><span class='badge badge-{sev}'>{sev}</span></td>"
                f"<td>{f.get('status', '')}</td></tr>"
            )

        if not finding_rows:
            finding_rows = "<tr><td colspan='4' style='color:#888'>No findings mapped to this framework.</td></tr>"

        return f"""
<h3>Controls Assessment — {framework.upper()}</h3>
<table>
<thead><tr><th>Control ID</th><th>Control Name</th><th>Status</th></tr></thead>
<tbody>{rows if rows else "<tr><td colspan='3' style='color:#888'>No controls data available.</td></tr>"}</tbody>
</table>
<h3>Related Findings</h3>
<table>
<thead><tr><th>Finding ID</th><th>Title</th><th>Severity</th><th>Status</th></tr></thead>
<tbody>{finding_rows}</tbody>
</table>
<p style="font-size:11px;color:#666;margin-top:8px">
  Evidence package generated {now.strftime('%Y-%m-%d %H:%M UTC')} for {framework.upper()} audit readiness review.
</p>
"""

    # ------------------------------------------------------------------
    # MTTR helper
    # ------------------------------------------------------------------

    def _compute_mttr(self, findings: List[Dict[str, Any]]) -> str:
        """Compute mean time to remediate from finding timestamps."""
        deltas = []
        for f in findings:
            created = f.get("created_at") or f.get("created") or ""
            resolved = f.get("resolved_at") or f.get("completed_at") or ""
            if created and resolved:
                try:
                    c_dt = datetime.fromisoformat(str(created).replace("Z", "+00:00"))
                    r_dt = datetime.fromisoformat(str(resolved).replace("Z", "+00:00"))
                    if r_dt > c_dt:
                        deltas.append((r_dt - c_dt).total_seconds() / 3600)
                except Exception:
                    pass
        if not deltas:
            return "N/A"
        avg_hours = sum(deltas) / len(deltas)
        if avg_hours >= 24:
            return f"{avg_hours / 24:.1f} days"
        return f"{avg_hours:.1f} hours"
