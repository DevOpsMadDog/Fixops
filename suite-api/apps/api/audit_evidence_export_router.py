"""
POST /api/v1/audit-evidence/export?framework=<name>

Returns a ZIP archive containing:
  - controls.csv  — control_id, status, evidence_count (one row per control)
  - evidence/<control_id>.txt — last 10 audit-log events per control

Reuses:
  - AuditDB.list_audit_logs  (suite-core/core/audit_db.py)
  - ComplianceAutomationEngine._get_controls  (suite-core/core/compliance_engine.py)
"""
from __future__ import annotations

import csv
import io
import zipfile
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import StreamingResponse

from core.audit_db import AuditDB
from core.compliance_engine import ComplianceAutomationEngine, FRAMEWORKS

router = APIRouter(prefix="/api/v1/audit-evidence", tags=["audit-evidence"])

_audit_db = AuditDB()


def _get_engine() -> ComplianceAutomationEngine:
    """Return a fresh ComplianceAutomationEngine (holds its own sqlite conn)."""
    return ComplianceAutomationEngine()


@router.post("/export")
async def export_audit_evidence(
    framework: str = Query(..., description="Compliance framework, e.g. SOC2"),
) -> StreamingResponse:
    """
    Export a ZIP containing controls.csv + per-control audit-event text files.

    - controls.csv columns: control_id, status, evidence_count
    - evidence/{control_id}.txt: last 10 audit log entries for that control
    """
    framework = framework.upper()
    if framework not in FRAMEWORKS:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported framework '{framework}'. Valid: {FRAMEWORKS}",
        )

    engine = _get_engine()
    controls = engine._get_controls(framework)  # List[ComplianceControl]

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
                f"Framework: {framework}",
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
    filename = f"audit-evidence-{framework}.zip"
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/health")
@router.get("/status")
async def health() -> dict:
    return {"status": "ok", "router": "audit-evidence-export"}
