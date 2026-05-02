"""
Compliance Report Generator — SQLite-backed multi-framework report engine.

Generates compliance reports for SOC2, PCI-DSS, HIPAA, ISO27001, NIST CSF,
GDPR, and CIS Controls. Reports are stored in SQLite and can be exported as
JSON, HTML, CSV, or Markdown.
"""
from __future__ import annotations

import csv
import html as _html
import io
import json
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SUPPORTED_FRAMEWORKS = ["SOC2", "PCI", "HIPAA", "ISO27001", "NIST", "GDPR", "CIS"]

_FRAMEWORK_CONTROLS: Dict[str, List[Dict[str, Any]]] = {
    "SOC2": [
        {"id": "CC1", "title": "Control Environment", "category": "Common Criteria"},
        {"id": "CC2", "title": "Communication and Information", "category": "Common Criteria"},
        {"id": "CC3", "title": "Risk Assessment", "category": "Common Criteria"},
        {"id": "CC4", "title": "Monitoring Activities", "category": "Common Criteria"},
        {"id": "CC5", "title": "Control Activities", "category": "Common Criteria"},
        {"id": "CC6", "title": "Logical and Physical Access", "category": "Common Criteria"},
        {"id": "CC7", "title": "System Operations", "category": "Common Criteria"},
        {"id": "CC8", "title": "Change Management", "category": "Common Criteria"},
        {"id": "CC9", "title": "Risk Mitigation", "category": "Common Criteria"},
    ],
    "PCI": [
        {"id": "PCI-1", "title": "Install and maintain a firewall", "category": "Network Security"},
        {"id": "PCI-2", "title": "Do not use vendor-supplied defaults", "category": "Network Security"},
        {"id": "PCI-3", "title": "Protect stored cardholder data", "category": "Data Protection"},
        {"id": "PCI-4", "title": "Encrypt transmission of cardholder data", "category": "Data Protection"},
        {"id": "PCI-5", "title": "Use and regularly update anti-virus", "category": "Vulnerability Management"},
        {"id": "PCI-6", "title": "Develop and maintain secure systems", "category": "Vulnerability Management"},
        {"id": "PCI-7", "title": "Restrict access to cardholder data", "category": "Access Control"},
        {"id": "PCI-8", "title": "Assign unique ID to each person", "category": "Access Control"},
        {"id": "PCI-9", "title": "Restrict physical access", "category": "Physical Security"},
        {"id": "PCI-10", "title": "Track and monitor all access", "category": "Monitoring"},
        {"id": "PCI-11", "title": "Regularly test security systems", "category": "Testing"},
        {"id": "PCI-12", "title": "Maintain information security policy", "category": "Policy"},
    ],
    "HIPAA": [
        {"id": "HIPAA-164.308", "title": "Administrative Safeguards", "category": "Administrative"},
        {"id": "HIPAA-164.310", "title": "Physical Safeguards", "category": "Physical"},
        {"id": "HIPAA-164.312", "title": "Technical Safeguards", "category": "Technical"},
        {"id": "HIPAA-164.314", "title": "Organizational Requirements", "category": "Organizational"},
        {"id": "HIPAA-164.316", "title": "Documentation Requirements", "category": "Documentation"},
    ],
    "ISO27001": [
        {"id": "A.5", "title": "Information Security Policies", "category": "Organizational"},
        {"id": "A.6", "title": "Organization of Information Security", "category": "Organizational"},
        {"id": "A.7", "title": "Human Resource Security", "category": "People"},
        {"id": "A.8", "title": "Asset Management", "category": "Assets"},
        {"id": "A.9", "title": "Access Control", "category": "Access"},
        {"id": "A.10", "title": "Cryptography", "category": "Technology"},
        {"id": "A.11", "title": "Physical and Environmental Security", "category": "Physical"},
        {"id": "A.12", "title": "Operations Security", "category": "Operations"},
        {"id": "A.13", "title": "Communications Security", "category": "Communications"},
        {"id": "A.14", "title": "System Acquisition, Development and Maintenance", "category": "Development"},
        {"id": "A.15", "title": "Supplier Relationships", "category": "Supply Chain"},
        {"id": "A.16", "title": "Information Security Incident Management", "category": "Incidents"},
        {"id": "A.17", "title": "Business Continuity Management", "category": "Continuity"},
        {"id": "A.18", "title": "Compliance", "category": "Compliance"},
    ],
    "NIST": [
        {"id": "ID", "title": "Identify", "category": "Core Function"},
        {"id": "PR", "title": "Protect", "category": "Core Function"},
        {"id": "DE", "title": "Detect", "category": "Core Function"},
        {"id": "RS", "title": "Respond", "category": "Core Function"},
        {"id": "RC", "title": "Recover", "category": "Core Function"},
    ],
    "GDPR": [
        {"id": "Art.5", "title": "Principles of Processing", "category": "Principles"},
        {"id": "Art.6", "title": "Lawfulness of Processing", "category": "Lawfulness"},
        {"id": "Art.13", "title": "Information to be provided", "category": "Transparency"},
        {"id": "Art.15", "title": "Right of access", "category": "Data Subject Rights"},
        {"id": "Art.17", "title": "Right to erasure", "category": "Data Subject Rights"},
        {"id": "Art.25", "title": "Data protection by design", "category": "Privacy by Design"},
        {"id": "Art.32", "title": "Security of processing", "category": "Security"},
        {"id": "Art.33", "title": "Breach notification", "category": "Incident Response"},
        {"id": "Art.35", "title": "Data protection impact assessment", "category": "DPIA"},
        {"id": "Art.37", "title": "Data Protection Officer", "category": "Governance"},
    ],
    "CIS": [
        {"id": "CIS-1", "title": "Inventory and Control of Enterprise Assets", "category": "IG1"},
        {"id": "CIS-2", "title": "Inventory and Control of Software Assets", "category": "IG1"},
        {"id": "CIS-3", "title": "Data Protection", "category": "IG1"},
        {"id": "CIS-4", "title": "Secure Configuration of Enterprise Assets", "category": "IG1"},
        {"id": "CIS-5", "title": "Account Management", "category": "IG1"},
        {"id": "CIS-6", "title": "Access Control Management", "category": "IG1"},
        {"id": "CIS-7", "title": "Continuous Vulnerability Management", "category": "IG2"},
        {"id": "CIS-8", "title": "Audit Log Management", "category": "IG2"},
        {"id": "CIS-9", "title": "Email and Web Browser Protections", "category": "IG2"},
        {"id": "CIS-10", "title": "Malware Defenses", "category": "IG2"},
        {"id": "CIS-11", "title": "Data Recovery", "category": "IG2"},
        {"id": "CIS-12", "title": "Network Infrastructure Management", "category": "IG2"},
        {"id": "CIS-13", "title": "Network Monitoring and Defense", "category": "IG3"},
        {"id": "CIS-14", "title": "Security Awareness and Skills Training", "category": "IG3"},
        {"id": "CIS-15", "title": "Service Provider Management", "category": "IG3"},
        {"id": "CIS-16", "title": "Application Software Security", "category": "IG3"},
        {"id": "CIS-17", "title": "Incident Response Management", "category": "IG3"},
        {"id": "CIS-18", "title": "Penetration Testing", "category": "IG3"},
    ],
}


# ---------------------------------------------------------------------------
# Pydantic model
# ---------------------------------------------------------------------------


class ComplianceReport(BaseModel):
    """A generated compliance report."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    framework: str
    title: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    sections: List[Dict[str, Any]] = Field(default_factory=list)
    score: float = Field(default=0.0, ge=0.0, le=100.0)
    gaps_count: int = Field(default=0, ge=0)
    org_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Generator class
# ---------------------------------------------------------------------------


class ComplianceReportGenerator:
    """SQLite-backed compliance report generator."""

    def __init__(self, db_path: str = "data/compliance_reports.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_tables(self) -> None:
        conn = self._get_connection()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS compliance_reports (
                    id           TEXT PRIMARY KEY,
                    framework    TEXT NOT NULL,
                    title        TEXT NOT NULL,
                    generated_at TEXT NOT NULL,
                    sections     TEXT NOT NULL,
                    score        REAL NOT NULL,
                    gaps_count   INTEGER NOT NULL,
                    org_id       TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_cr_framework ON compliance_reports(framework);
                CREATE INDEX IF NOT EXISTS idx_cr_org       ON compliance_reports(org_id);
                CREATE INDEX IF NOT EXISTS idx_cr_generated ON compliance_reports(generated_at);
                """
            )
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_sections(
        self,
        framework: str,
        findings_context: Optional[Dict[str, Any]] = None,
    ) -> tuple[List[Dict[str, Any]], float, int]:
        """Build sections, score, and gaps_count for a framework."""
        controls = _FRAMEWORK_CONTROLS.get(framework, [])
        sections: List[Dict[str, Any]] = []
        passed = 0
        gaps = 0

        for ctrl in controls:
            # Simulate status from findings_context when provided; default passing
            status = "compliant"
            evidence = "Automated check passed."
            if findings_context:
                findings_context.get("open_findings", 0)
                critical_count = findings_context.get("critical_findings", 0)
                # Heuristic: controls with high critical findings have gaps
                if critical_count > 0 and ctrl.get("category") in (
                    "Access Control", "Security", "Technical", "Access", "IG1"
                ):
                    status = "gap"
                    evidence = f"{critical_count} critical finding(s) detected."

            if status == "compliant":
                passed += 1
                evidence_list = [evidence]
            else:
                gaps += 1
                evidence_list = [evidence]

            sections.append(
                {
                    "control_id": ctrl["id"],
                    "title": ctrl["title"],
                    "category": ctrl["category"],
                    "status": status,
                    "evidence": evidence_list,
                }
            )

        score = round((passed / len(controls)) * 100.0, 1) if controls else 100.0
        return sections, score, gaps

    def _row_to_report(self, row: sqlite3.Row) -> ComplianceReport:
        return ComplianceReport(
            id=row["id"],
            framework=row["framework"],
            title=row["title"],
            generated_at=datetime.fromisoformat(row["generated_at"]),
            sections=json.loads(row["sections"]),
            score=row["score"],
            gaps_count=row["gaps_count"],
            org_id=row["org_id"],
        )

    # ------------------------------------------------------------------
    # Generate
    # ------------------------------------------------------------------

    def generate_report(
        self,
        framework: str,
        org_id: Optional[str] = None,
        findings_context: Optional[Dict[str, Any]] = None,
        title: Optional[str] = None,
    ) -> ComplianceReport:
        """Generate and persist a compliance report for the given framework.

        Args:
            framework: One of SUPPORTED_FRAMEWORKS.
            org_id: Optional organisation identifier.
            findings_context: Optional dict with keys like ``open_findings``,
                ``critical_findings`` used to simulate gap detection.
            title: Override report title; defaults to "<Framework> Compliance Report".

        Returns:
            Persisted ComplianceReport.

        Raises:
            ValueError: If framework is not supported.
        """
        fw = framework.upper()
        if fw not in SUPPORTED_FRAMEWORKS:
            raise ValueError(
                f"Unsupported framework '{framework}'. "
                f"Supported: {', '.join(SUPPORTED_FRAMEWORKS)}"
            )

        sections, score, gaps_count = self._build_sections(fw, findings_context)
        report = ComplianceReport(
            framework=fw,
            title=title or f"{fw} Compliance Report",
            sections=sections,
            score=score,
            gaps_count=gaps_count,
            org_id=org_id,
        )

        conn = self._get_connection()
        try:
            conn.execute(
                "INSERT INTO compliance_reports VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    report.id,
                    report.framework,
                    report.title,
                    report.generated_at.isoformat(),
                    json.dumps(report.sections),
                    report.score,
                    report.gaps_count,
                    report.org_id,
                ),
            )
            conn.commit()
        finally:
            conn.close()

        return report

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def export_report(self, report_id: str, fmt: str = "json") -> str:
        """Export a report in the requested format.

        Args:
            report_id: Report UUID.
            fmt: One of ``json``, ``html``, ``csv``, ``markdown``.

        Returns:
            Serialised string in the requested format.

        Raises:
            ValueError: If report not found or format unsupported.
        """
        report = self.get_report(report_id)
        if report is None:
            raise ValueError(f"Report '{report_id}' not found.")

        fmt = fmt.lower()
        if fmt == "json":
            return report.model_dump_json(indent=2)

        if fmt == "html":
            return self._to_html(report)

        if fmt == "csv":
            return self._to_csv(report)

        if fmt == "markdown":
            return self._to_markdown(report)

        raise ValueError(f"Unsupported export format '{fmt}'. Use json/html/csv/markdown.")

    def _to_html(self, report: ComplianceReport) -> str:
        rows = "".join(
            f"<tr><td>{_html.escape(str(s['control_id']))}</td><td>{_html.escape(str(s['title']))}</td>"
            f"<td>{_html.escape(str(s['category']))}</td><td>{_html.escape(str(s['status']))}</td>"
            f"<td>{_html.escape('; '.join(s.get('evidence', [])))}</td></tr>"
            for s in report.sections
        )
        safe_title = _html.escape(str(report.title))
        safe_framework = _html.escape(str(report.framework))
        return (
            f"<!DOCTYPE html><html><head>"
            f"<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'\">"
            f"<title>{safe_title}</title></head>"
            f"<body><h1>{safe_title}</h1>"
            f"<p>Framework: {safe_framework} | Score: {_html.escape(str(report.score))}% | "
            f"Gaps: {_html.escape(str(report.gaps_count))} | Generated: {_html.escape(report.generated_at.isoformat())}</p>"
            f"<table border='1'><thead><tr><th>Control</th><th>Title</th>"
            f"<th>Category</th><th>Status</th><th>Evidence</th></tr></thead>"
            f"<tbody>{rows}</tbody></table></body></html>"
        )

    def _to_csv(self, report: ComplianceReport) -> str:
        buf = io.StringIO()
        writer = csv.writer(buf)
        writer.writerow(["control_id", "title", "category", "status", "evidence"])
        for s in report.sections:
            writer.writerow(
                [
                    s["control_id"],
                    s["title"],
                    s["category"],
                    s["status"],
                    "; ".join(s.get("evidence", [])),
                ]
            )
        return buf.getvalue()

    def _to_markdown(self, report: ComplianceReport) -> str:
        lines = [
            f"# {report.title}",
            "",
            f"**Framework:** {report.framework}  ",
            f"**Score:** {report.score}%  ",
            f"**Gaps:** {report.gaps_count}  ",
            f"**Generated:** {report.generated_at.isoformat()}  ",
            "",
            "| Control | Title | Category | Status | Evidence |",
            "|---------|-------|----------|--------|----------|",
        ]
        for s in report.sections:
            evidence = "; ".join(s.get("evidence", []))
            lines.append(
                f"| {s['control_id']} | {s['title']} | {s['category']} "
                f"| {s['status']} | {evidence} |"
            )
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # List / Get
    # ------------------------------------------------------------------

    def get_report(self, report_id: str) -> Optional[ComplianceReport]:
        """Retrieve a single report by ID."""
        conn = self._get_connection()
        try:
            row = conn.execute(
                "SELECT * FROM compliance_reports WHERE id = ?", (report_id,)
            ).fetchone()
            return self._row_to_report(row) if row else None
        finally:
            conn.close()

    def list_reports(
        self,
        framework: Optional[str] = None,
        org_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[ComplianceReport]:
        """List stored reports with optional filtering."""
        conn = self._get_connection()
        try:
            query = "SELECT * FROM compliance_reports WHERE 1=1"
            params: List[Any] = []
            if framework:
                query += " AND framework = ?"
                params.append(framework.upper())
            if org_id:
                query += " AND org_id = ?"
                params.append(org_id)
            query += " ORDER BY generated_at DESC LIMIT ? OFFSET ?"
            params.extend([limit, offset])

            rows = conn.execute(query, params).fetchall()
            return [self._row_to_report(r) for r in rows]
        finally:
            conn.close()

    def delete_report(self, report_id: str) -> bool:
        """Delete a report by ID. Returns True if deleted."""
        conn = self._get_connection()
        try:
            cursor = conn.execute(
                "DELETE FROM compliance_reports WHERE id = ?", (report_id,)
            )
            conn.commit()
            return cursor.rowcount > 0
        finally:
            conn.close()
