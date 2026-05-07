"""
POST /api/v1/audit-evidence/export?framework=<name>

Returns a ZIP archive containing:
  - controls.csv  — control_id, status, evidence_count (one row per control)
  - evidence/<control_id>.txt — last 10 audit-log events per control

Supports frameworks: SOC2, PCI_DSS, HIPAA, ISO27001, FedRAMP, NIST-800-53, CMMC

Reuses:
  - AuditDB.list_audit_logs  (suite-core/core/audit_db.py)
  - ComplianceAutomationEngine._get_controls  (suite-core/core/compliance_engine.py)
"""
from __future__ import annotations

import csv
import io
import zipfile
from typing import Optional, Dict, List

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse

from core.audit_db import AuditDB
from core.compliance_engine import ComplianceAutomationEngine, FRAMEWORKS

router = APIRouter(prefix="/api/v1/audit-evidence", tags=["audit-evidence"])

# Control registry per framework (for reference & documentation)
FRAMEWORK_CONTROL_REGISTRY: Dict[str, List[str]] = {
    "SOC2": [
        "CC1.1", "CC1.2", "CC1.3", "CC1.4", "CC2.1", "CC2.2", "CC2.3",
        "CC3.1", "CC3.2", "CC3.3", "CC3.4", "CC4.1", "CC4.2", "CC5.1", "CC5.2",
        "CC6.1", "CC6.2", "CC7.1", "CC7.2", "CC7.3", "CC7.4", "CC7.5",
        "CC8.1", "CC9.1", "CC9.2", "SI1.1", "SI1.2"
    ],
    "PCI_DSS": [
        "REQ-1", "REQ-2", "REQ-3", "REQ-4", "REQ-5", "REQ-6", "REQ-7", "REQ-8",
        "REQ-9", "REQ-10", "REQ-11", "REQ-12"
    ],
    "HIPAA": [
        "ADMIN-001", "ADMIN-002", "ADMIN-003", "ADMIN-004", "ADMIN-005",
        "PHYS-001", "PHYS-002", "PHYS-003", "PHYS-004",
        "TECH-001", "TECH-002", "TECH-003", "TECH-004", "TECH-005", "TECH-006"
    ],
    "ISO27001": [
        "A.5.1", "A.5.2", "A.6.1", "A.6.2", "A.7.1", "A.7.2", "A.8.1", "A.8.2",
        "A.8.3", "A.9.1", "A.9.2", "A.10.1", "A.11.1", "A.12.1", "A.12.2",
        "A.13.1", "A.14.1", "A.14.2", "A.15.1", "A.16.1"
    ],
}
"""Map framework name → list of control IDs (for validation & reporting)."""

_audit_db = AuditDB()


def _get_engine() -> ComplianceAutomationEngine:
    """Return a fresh ComplianceAutomationEngine (holds its own sqlite conn)."""
    return ComplianceAutomationEngine()


@router.post("/export")
async def export_audit_evidence(
    framework: str = Query(..., description="Compliance framework: SOC2, PCI_DSS, HIPAA, ISO27001, FedRAMP, NIST-800-53, CMMC"),
) -> StreamingResponse:
    """
    Export a ZIP containing controls.csv + per-control audit-event text files.

    - controls.csv columns: control_id, status, evidence_count
    - evidence/{control_id}.txt: last 10 audit log entries for that control

    Supported frameworks: SOC2, PCI_DSS, HIPAA, ISO27001, FedRAMP, NIST-800-53, CMMC
    """
    # Normalize framework name: convert underscores to hyphens for FRAMEWORKS list
    framework_normalized = framework.upper().replace("_", "-")

    if framework_normalized not in FRAMEWORKS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported framework '{framework}'. Valid: {', '.join(FRAMEWORKS)}",
        )

    engine = _get_engine()
    controls = engine._get_controls(framework_normalized)  # List[ComplianceControl]

    # Fetch all audit logs once (up to 1000) — filter per control below
    all_logs = _audit_db.list_audit_logs(limit=1000)

    # Build ZIP in memory
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        # --- controls.csv ---
        csv_buf = io.StringIO()
        writer = csv.writer(csv_buf)
        writer.writerow(["control_id", "status", "evidence_count"])

        for ctrl in controls:
            ev_count = len(ctrl.evidence_ids)
            writer.writerow([ctrl.id, ctrl.status.value, ev_count])

            # --- evidence/<control_id>.txt ---
            # Match logs whose resource_id or action mentions the control id
            ctrl_id_lower = ctrl.id.lower()
            matched = [
                log for log in all_logs
                if ctrl_id_lower in (log.resource_id or "").lower()
                or ctrl_id_lower in (log.action or "").lower()
            ]
            last_10 = matched[:10]

            lines: list[str] = [
                f"Control: {ctrl.id}",
                f"Framework: {framework_normalized}",
                f"Status: {ctrl.status.value}",
                f"Evidence count: {ev_count}",
                "=" * 60,
            ]
            if last_10:
                for log in last_10:
                    lines.append(
                        f"[{log.timestamp}] {log.event_type} | {log.action} | "
                        f"user={log.user_id or 'n/a'} | severity={log.severity}"
                    )
            else:
                lines.append("(no audit events matched this control)")

            zf.writestr(f"evidence/{ctrl.id}.txt", "\n".join(lines) + "\n")

        zf.writestr("controls.csv", csv_buf.getvalue())

    buf.seek(0)
    filename = f"audit-evidence-{framework_normalized}.zip"
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/health")
@router.get("/status")
async def health() -> dict:
    return {"status": "ok", "router": "audit-evidence-export"}
