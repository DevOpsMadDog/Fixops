"""Org GDPR Export Router — ALDECI right-to-portability.

Prefix: /api/v1/orgs/{org_id}/export
Auth:   api_key_auth

Routes:
  POST /api/v1/orgs/{org_id}/export
    Generates a ZIP containing:
      org.json           — org metadata
      users.csv          — org users
      findings.csv       — all security findings
      incidents.csv      — all incidents
      audit_events.csv   — audit events from last 365 days
    Saves to /tmp/aldeci-export-{org_id}-{timestamp}.zip
    Returns {"download_url": "...", "zip_path": "...", "file_size_bytes": N}
    Optional query param: email=<addr>  — sends download link via slack_notifier
"""

from __future__ import annotations

import csv
import io
import json
import logging
import os
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException, Query

_logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1/orgs",
    tags=["Organizations"],
)

# ---------------------------------------------------------------------------
# Lazy engine singletons
# ---------------------------------------------------------------------------

_findings_engine = None
_incident_engine = None
_org_engine = None
_user_db = None


def _get_findings_engine():
    global _findings_engine
    if _findings_engine is None:
        from core.security_findings_engine import SecurityFindingsEngine
        _findings_engine = SecurityFindingsEngine()
    return _findings_engine


def _get_incident_engine():
    global _incident_engine
    if _incident_engine is None:
        from core.incident_response_engine import IncidentResponseEngine
        _incident_engine = IncidentResponseEngine()
    return _incident_engine


def _get_org_engine():
    global _org_engine
    if _org_engine is None:
        from core.org_engine import OrgEngine
        _org_engine = OrgEngine()
    return _org_engine


def _get_user_db():
    global _user_db
    if _user_db is None:
        from core.user_db import UserDB
        _user_db = UserDB()
    return _user_db


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_DATA_ROOT = Path(os.environ.get("FIXOPS_DATA_DIR", "")) or (
    Path(__file__).resolve().parents[3] / ".fixops_data"
)

_AUDIT_DB_PATH = _DATA_ROOT / "audit_events.db"


def _audit_logger():
    """Return a persistent AuditLogger bound to the standard data-root DB."""
    from core.audit_logger import AuditLogger
    return AuditLogger(db_path=_AUDIT_DB_PATH)


def _dict_to_csv_bytes(rows: List[Dict[str, Any]]) -> bytes:
    """Serialise a list of flat dicts to UTF-8 CSV bytes."""
    if not rows:
        return b""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()), extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        # Flatten nested objects to JSON strings so CSV stays flat
        flat = {
            k: (json.dumps(v) if isinstance(v, (dict, list)) else v)
            for k, v in row.items()
        }
        writer.writerow(flat)
    return buf.getvalue().encode("utf-8")


def _user_to_dict(u: Any) -> Dict[str, Any]:
    d = u.to_dict() if hasattr(u, "to_dict") else dict(u)
    return {
        "id": d.get("id", ""),
        "email": d.get("email", ""),
        "first_name": d.get("first_name", ""),
        "last_name": d.get("last_name", ""),
        "role": d.get("role", "viewer"),
        "status": d.get("status", "active"),
        "created_at": d.get("created_at", ""),
    }


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@router.post("/{org_id}/export", dependencies=[Depends(api_key_auth)])
def export_org_data(
    org_id: str,
    email: Optional[str] = Query(
        default=None,
        description="If provided, send download link to this address via notification engine",
    ),
) -> Dict[str, Any]:
    """GDPR right-to-portability export for an org.

    Builds a ZIP archive with org.json, users.csv, findings.csv,
    incidents.csv, audit_events.csv (last 365 days).
    Saves to /tmp/aldeci-export-{org_id}-{timestamp}.zip.
    Returns the download URL and metadata.
    """
    if not org_id or not org_id.strip():
        raise HTTPException(status_code=400, detail="org_id is required")

    # Sanitise org_id to prevent path traversal
    safe_org_id = "".join(c for c in org_id if c.isalnum() or c in "-_")
    if not safe_org_id:
        raise HTTPException(status_code=400, detail="org_id contains invalid characters")

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    zip_filename = f"aldeci-export-{safe_org_id}-{timestamp}.zip"
    zip_path = Path("/tmp") / zip_filename

    try:
        # ── 1. Org metadata ──────────────────────────────────────────────
        org_data: Dict[str, Any] = {}
        try:
            engine = _get_org_engine()
            summary = engine.get_org_summary(safe_org_id)
            org_data = {
                "org_id": safe_org_id,
                "export_generated_at": datetime.now(timezone.utc).isoformat(),
                "summary": summary,
            }
        except Exception as exc:
            _logger.warning("Could not fetch org metadata for %s: %s", safe_org_id, exc)
            org_data = {"org_id": safe_org_id, "export_generated_at": datetime.now(timezone.utc).isoformat()}

        # ── 2. Users ─────────────────────────────────────────────────────
        users: List[Dict[str, Any]] = []
        try:
            udb = _get_user_db()
            raw_users = udb.list_users(limit=10000, offset=0)
            users = [_user_to_dict(u) for u in raw_users]
        except Exception as exc:
            _logger.warning("Could not fetch users for %s: %s", safe_org_id, exc)

        # ── 3. Findings ───────────────────────────────────────────────────
        findings: List[Dict[str, Any]] = []
        try:
            findings = _get_findings_engine().list_findings(org_id=safe_org_id)
        except Exception as exc:
            _logger.warning("Could not fetch findings for %s: %s", safe_org_id, exc)

        # ── 4. Incidents ──────────────────────────────────────────────────
        incidents: List[Dict[str, Any]] = []
        try:
            incidents = _get_incident_engine().list_incidents(org_id=safe_org_id)
        except Exception as exc:
            _logger.warning("Could not fetch incidents for %s: %s", safe_org_id, exc)

        # ── 5. Audit events (last 365 days) ───────────────────────────────
        audit_events: List[Dict[str, Any]] = []
        try:
            al = _audit_logger()
            since = datetime.now(timezone.utc) - timedelta(days=365)
            raw_events = al.get_security_events(
                org_id=safe_org_id,
                since=since,
                limit=50000,
            )
            audit_events = [
                e.to_dict() if hasattr(e, "to_dict") else (
                    e.__dict__ if hasattr(e, "__dict__") else dict(e)
                )
                for e in raw_events
            ]
        except Exception as exc:
            _logger.warning("Could not fetch audit events for %s: %s", safe_org_id, exc)

        # ── 6. Build ZIP ──────────────────────────────────────────────────
        with zipfile.ZipFile(str(zip_path), "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("org.json", json.dumps(org_data, indent=2, default=str))
            zf.writestr("users.csv", _dict_to_csv_bytes(users))
            zf.writestr("findings.csv", _dict_to_csv_bytes(findings))
            zf.writestr("incidents.csv", _dict_to_csv_bytes(incidents))
            zf.writestr("audit_events.csv", _dict_to_csv_bytes(audit_events))

        file_size = zip_path.stat().st_size

        # ── 7. Build download URL ─────────────────────────────────────────
        base_url = os.environ.get("ALDECI_BASE_URL", "http://localhost:8099")
        download_url = f"{base_url}/api/v1/orgs/{safe_org_id}/export/download/{zip_filename}"

        result: Dict[str, Any] = {
            "org_id": safe_org_id,
            "zip_path": str(zip_path),
            "zip_filename": zip_filename,
            "download_url": download_url,
            "file_size_bytes": file_size,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "contents": {
                "org_metadata": True,
                "users": len(users),
                "findings": len(findings),
                "incidents": len(incidents),
                "audit_events": len(audit_events),
            },
        }

        # ── 8. Optional email notification ────────────────────────────────
        if email:
            try:
                from core.slack_notifier import SlackNotifier
                notifier = SlackNotifier()
                msg = (
                    f"GDPR export for org `{safe_org_id}` is ready.\n"
                    f"Download: {download_url}\n"
                    f"Size: {file_size:,} bytes"
                )
                notifier.notify(msg)
                result["notification_sent"] = True
                result["notification_target"] = email
            except Exception as exc:
                _logger.warning("Notification failed for %s: %s", email, exc)
                result["notification_sent"] = False
                result["notification_error"] = str(exc)

        _logger.info(
            "GDPR export generated for org=%s zip=%s size=%d",
            safe_org_id, zip_filename, file_size,
        )
        return result

    except HTTPException:
        raise
    except Exception as exc:
        _logger.exception("GDPR export failed for org=%s", safe_org_id)
        raise HTTPException(status_code=500, detail=f"Export failed: {exc}") from exc
