"""Scheduled Report Delivery — generate and deliver security reports via n8n webhooks.

Supports 5 report types, multi-channel delivery (email + Slack via n8n), and
full delivery history. SQLite WAL at data/report_schedules.db.
"""
from __future__ import annotations

import json
import os
import sqlite3
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog

_logger = structlog.get_logger("core.report_scheduler")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

REPORT_TYPES = [
    "executive_summary",
    "vulnerability_digest",
    "compliance_status",
    "threat_intel_brief",
    "kpi_scorecard",
]

FREQUENCIES = ["daily", "weekly", "monthly"]

CHANNELS = ["email", "slack"]

FORMATS = ["json", "html", "pdf"]

N8N_WEBHOOK_PATH = "webhook/aldeci-report-delivery"


# ---------------------------------------------------------------------------
# ReportScheduler
# ---------------------------------------------------------------------------


class ReportScheduler:
    """SQLite-backed scheduler that generates and delivers security reports via n8n.

    Tables:
        schedules      — delivery schedules with frequency, recipients, channels
        delivery_log   — history of past deliveries with status
    WAL mode is enabled for safe concurrent access.
    """

    def __init__(
        self,
        db_path: str = "data/report_schedules.db",
        n8n_base_url: Optional[str] = None,
    ) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._n8n_base_url = (
            n8n_base_url
            or os.environ.get("N8N_BASE_URL", "http://localhost:5678")
        ).rstrip("/")
        self._init_db()

    # ------------------------------------------------------------------
    # DB bootstrap
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS schedules (
                    schedule_id  TEXT PRIMARY KEY,
                    org_id       TEXT NOT NULL DEFAULT 'default',
                    name         TEXT NOT NULL,
                    report_type  TEXT NOT NULL,
                    frequency    TEXT NOT NULL,
                    recipients   TEXT NOT NULL DEFAULT '[]',
                    channels     TEXT NOT NULL DEFAULT '["email"]',
                    format       TEXT NOT NULL DEFAULT 'json',
                    filters      TEXT NOT NULL DEFAULT '{}',
                    active       INTEGER NOT NULL DEFAULT 1,
                    created_at   TEXT NOT NULL,
                    updated_at   TEXT NOT NULL,
                    next_run_at  TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS delivery_log (
                    report_id          TEXT PRIMARY KEY,
                    schedule_id        TEXT NOT NULL,
                    org_id             TEXT NOT NULL DEFAULT 'default',
                    report_type        TEXT NOT NULL,
                    delivered_at       TEXT NOT NULL,
                    channels_notified  TEXT NOT NULL DEFAULT '[]',
                    status             TEXT NOT NULL,
                    error_message      TEXT,
                    FOREIGN KEY (schedule_id) REFERENCES schedules(schedule_id)
                );
                CREATE INDEX IF NOT EXISTS idx_sched_org_active
                    ON schedules (org_id, active);
                CREATE INDEX IF NOT EXISTS idx_sched_next_run
                    ON schedules (next_run_at);
                CREATE INDEX IF NOT EXISTS idx_dlog_org_delivered
                    ON delivery_log (org_id, delivered_at DESC);
                CREATE INDEX IF NOT EXISTS idx_dlog_schedule
                    ON delivery_log (schedule_id);
                """
            )

    # ------------------------------------------------------------------
    # Schedule CRUD
    # ------------------------------------------------------------------

    def create_schedule(self, org_id: str, schedule: Dict[str, Any]) -> str:
        """Create a new report delivery schedule.

        Args:
            org_id: Organisation identifier.
            schedule: Dict with keys:
                name (str), report_type (str), frequency (str),
                recipients (list[str]), channels (list[str]),
                format (str, optional), filters (dict, optional).

        Returns:
            schedule_id (str)

        Raises:
            ValueError: If required fields are missing or values are invalid.
        """
        name = schedule.get("name", "").strip()
        report_type = schedule.get("report_type", "")
        frequency = schedule.get("frequency", "")
        recipients = schedule.get("recipients", [])
        channels = schedule.get("channels", ["email"])
        fmt = schedule.get("format", "json")
        filters = schedule.get("filters", {})

        if not name:
            raise ValueError("schedule.name is required")
        if report_type not in REPORT_TYPES:
            raise ValueError(
                f"Invalid report_type '{report_type}'. Must be one of {REPORT_TYPES}"
            )
        if frequency not in FREQUENCIES:
            raise ValueError(
                f"Invalid frequency '{frequency}'. Must be one of {FREQUENCIES}"
            )
        for ch in channels:
            if ch not in CHANNELS:
                raise ValueError(
                    f"Invalid channel '{ch}'. Must be one of {CHANNELS}"
                )
        if fmt not in FORMATS:
            raise ValueError(
                f"Invalid format '{fmt}'. Must be one of {FORMATS}"
            )

        schedule_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        next_run_at = _calculate_next_run(frequency, from_time=now)

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO schedules
                    (schedule_id, org_id, name, report_type, frequency,
                     recipients, channels, format, filters, active,
                     created_at, updated_at, next_run_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?)
                """,
                (
                    schedule_id,
                    org_id,
                    name,
                    report_type,
                    frequency,
                    json.dumps(recipients),
                    json.dumps(channels),
                    fmt,
                    json.dumps(filters),
                    now.isoformat(),
                    now.isoformat(),
                    next_run_at.isoformat(),
                ),
            )

        _logger.info(
            "report_scheduler.create_schedule",
            schedule_id=schedule_id,
            org_id=org_id,
            report_type=report_type,
            frequency=frequency,
        )
        return schedule_id

    def list_schedules(self, org_id: str) -> List[Dict[str, Any]]:
        """List all active schedules for an org.

        Returns:
            List of schedule dicts.
        """
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM schedules WHERE org_id = ? AND active = 1 ORDER BY created_at DESC",
                (org_id,),
            ).fetchall()
        return [_row_to_schedule(r) for r in rows]

    def delete_schedule(self, schedule_id: str, org_id: str) -> bool:
        """Delete a schedule, scoped to org_id.

        Returns:
            True if found and deleted, False if not found or wrong org.
        """
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM schedules WHERE schedule_id = ? AND org_id = ?",
                (schedule_id, org_id),
            )
            deleted = cur.rowcount > 0

        if deleted:
            _logger.info(
                "report_scheduler.delete_schedule",
                schedule_id=schedule_id,
                org_id=org_id,
            )
        return deleted

    def _get_schedule(self, schedule_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM schedules WHERE schedule_id = ?",
                (schedule_id,),
            ).fetchone()
        return _row_to_schedule(row) if row else None

    # ------------------------------------------------------------------
    # Report generation
    # ------------------------------------------------------------------

    def generate_report_data(
        self, report_type: str, org_id: str, filters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Aggregate report data for the given report type.

        Attempts to pull live data from other engines; falls back to
        structured stub data when engines are unavailable (test/offline mode).

        Args:
            report_type: One of REPORT_TYPES.
            org_id: Organisation to scope data to.
            filters: Optional filters (e.g. {"severity": "critical"}).

        Returns:
            Dict with report_type, org_id, generated_at, and type-specific data.
        """
        if report_type not in REPORT_TYPES:
            raise ValueError(
                f"Invalid report_type '{report_type}'. Must be one of {REPORT_TYPES}"
            )

        generated_at = datetime.now(timezone.utc).isoformat()
        data: Dict[str, Any] = {}

        if report_type == "executive_summary":
            data = _generate_executive_summary(org_id, filters)
        elif report_type == "vulnerability_digest":
            data = _generate_vulnerability_digest(org_id, filters)
        elif report_type == "compliance_status":
            data = _generate_compliance_status(org_id, filters)
        elif report_type == "threat_intel_brief":
            data = _generate_threat_intel_brief(org_id, filters)
        elif report_type == "kpi_scorecard":
            data = _generate_kpi_scorecard(org_id, filters)

        return {
            "report_type": report_type,
            "org_id": org_id,
            "generated_at": generated_at,
            "filters": filters,
            "data": data,
        }

    def get_report_preview(self, report_type: str, org_id: str) -> Dict[str, Any]:
        """Return sample report data for preview before scheduling.

        Returns:
            Same structure as generate_report_data, with preview=True flag.
        """
        result = self.generate_report_data(report_type, org_id, filters={})
        result["preview"] = True
        return result

    # ------------------------------------------------------------------
    # Delivery
    # ------------------------------------------------------------------

    def trigger_report(self, schedule_id: str, org_id: str) -> Dict[str, Any]:
        """Generate and deliver a report immediately for the given schedule.

        Sends via n8n webhook. Falls back gracefully if n8n is unavailable.

        Returns:
            {status: "sent"|"queued"|"failed", report_id, channels_notified}
        """
        schedule = self._get_schedule(schedule_id)
        if schedule is None:
            raise ValueError(f"Schedule '{schedule_id}' not found")
        if schedule["org_id"] != org_id:
            raise ValueError(f"Schedule '{schedule_id}' not found")

        report_data = self.generate_report_data(
            schedule["report_type"],
            org_id,
            schedule.get("filters", {}),
        )
        channels = schedule.get("channels", ["email"])
        recipients = schedule.get("recipients", [])

        payload = {
            "report_id": str(uuid.uuid4()),
            "schedule_id": schedule_id,
            "org_id": org_id,
            "schedule_name": schedule["name"],
            "channels": channels,
            "recipients": recipients,
            "format": schedule.get("format", "json"),
            "report": report_data,
        }

        status, error_message = self._dispatch_via_n8n(payload)
        channels_notified = channels if status == "sent" else []

        report_id = payload["report_id"]
        delivered_at = datetime.now(timezone.utc).isoformat()

        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO delivery_log
                    (report_id, schedule_id, org_id, report_type, delivered_at,
                     channels_notified, status, error_message)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    report_id,
                    schedule_id,
                    org_id,
                    schedule["report_type"],
                    delivered_at,
                    json.dumps(channels_notified),
                    status,
                    error_message,
                ),
            )
            # Advance next_run_at
            next_run = _calculate_next_run(schedule["frequency"]).isoformat()
            conn.execute(
                "UPDATE schedules SET next_run_at = ?, updated_at = ? WHERE schedule_id = ?",
                (next_run, delivered_at, schedule_id),
            )

        _logger.info(
            "report_scheduler.trigger_report",
            schedule_id=schedule_id,
            org_id=org_id,
            status=status,
            channels_notified=channels_notified,
        )

        return {
            "status": status,
            "report_id": report_id,
            "channels_notified": channels_notified,
        }

    def get_delivery_history(self, org_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Return past deliveries for an org, newest first.

        Args:
            org_id: Organisation to filter by.
            limit: Maximum rows to return.

        Returns:
            List of delivery log entry dicts.
        """
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM delivery_log
                WHERE org_id = ?
                ORDER BY delivered_at DESC
                LIMIT ?
                """,
                (org_id, limit),
            ).fetchall()
        return [_row_to_log_entry(r) for r in rows]

    # ------------------------------------------------------------------
    # n8n dispatch
    # ------------------------------------------------------------------

    def _dispatch_via_n8n(
        self, payload: Dict[str, Any]
    ) -> tuple[str, Optional[str]]:
        """POST payload to n8n webhook.

        Returns:
            (status, error_message) where status is "sent", "queued", or "failed".
        """
        url = f"{self._n8n_base_url}/{N8N_WEBHOOK_PATH}"
        payload_bytes = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(  # nosemgrep: dynamic-urllib-use-detected
            url,
            data=payload_bytes,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:  # nosemgrep: dynamic-urllib-use-detected  # nosec
                _logger.debug(
                    "report_scheduler.n8n_dispatch",
                    status=resp.status,
                    url=url,
                )
            return "sent", None
        except (urllib.error.URLError, OSError) as exc:
            # n8n not available — queue or degrade gracefully
            _logger.warning(
                "report_scheduler.n8n_unavailable",
                url=url,
                error=str(exc),
            )
            return "queued", str(exc)
        except Exception as exc:
            _logger.error(
                "report_scheduler.n8n_dispatch_error",
                url=url,
                error=str(exc),
            )
            return "failed", str(exc)


# ---------------------------------------------------------------------------
# Report data generators (stub implementations — real data from engines)
# ---------------------------------------------------------------------------


def _generate_executive_summary(org_id: str, filters: Dict[str, Any]) -> Dict[str, Any]:
    """Top 5 critical vulns, compliance score, risk posture, open incidents."""
    top_vulns: List[Dict[str, Any]] = []
    compliance_score = 0.0
    risk_posture = "unknown"
    open_incidents = 0

    try:
        import sys
        sys.path.insert(0, "suite-core")
        from core.vuln_lifecycle_tracker import VulnLifecycleTracker
        tracker = VulnLifecycleTracker()
        vulns = tracker.list_vulnerabilities(
            org_id=org_id, filters={"severity": "critical", "limit": 5}
        )
        top_vulns = vulns[:5] if vulns else []
    except Exception:
        pass

    # NOTE: core.security_posture_advisor module was retired; posture rollup
    # is now sourced via the canonical compliance + posture engines wired
    # below. Until the executive-summary report is rewired to those, leave
    # the defaults (compliance_score=0.0, risk_posture="unknown") so the
    # report renders without surfacing an import error every schedule.
    pass

    return {
        "top_critical_vulnerabilities": top_vulns,
        "compliance_score": compliance_score,
        "risk_posture": risk_posture,
        "open_incidents": open_incidents,
        "summary": f"Executive security summary for org {org_id}",
    }


def _generate_vulnerability_digest(org_id: str, filters: Dict[str, Any]) -> Dict[str, Any]:
    """New CVEs this week, patched vs open, EPSS high-risk items."""
    new_cves: List[Dict[str, Any]] = []
    patched_count = 0
    open_count = 0
    high_epss_items: List[Dict[str, Any]] = []

    # REMOVED — ``core.cve_enrichment.CVEEnrichmentEngine`` was renamed to
    # ``CVEEnrichmentService`` and no longer exposes ``.get_recent_cves`` (the
    # service surface is ``get_severity``/``get_top_epss``/``get_cache_stats``,
    # none of which return per-org recent CVE lists). 2026-05-03 silenced-
    # imports audit. Returning empty lists honestly until a recent-CVEs
    # accessor lands on the canonical service.
    _ = org_id  # signature preserved
    return {
        "new_cves_this_week": new_cves,
        "patched_count": patched_count,
        "open_count": open_count,
        "high_epss_items": high_epss_items,
        "summary": f"Vulnerability digest for org {org_id}",
    }


def _generate_compliance_status(org_id: str, filters: Dict[str, Any]) -> Dict[str, Any]:
    """Compliance framework scores and control status."""
    frameworks: List[Dict[str, Any]] = []
    overall_score = 0.0

    # REMOVED — ``core.compliance_engine.ComplianceEngine`` was renamed to
    # ``ComplianceAutomationEngine`` and no longer exposes
    # ``.get_compliance_status`` (canonical is ``get_overall_status()`` which
    # takes no org_id and returns a Pydantic model). 2026-05-03 silenced-
    # imports audit. Returning empty envelope honestly until a per-org
    # compliance-status accessor lands on the canonical engine.
    _ = org_id  # signature preserved
    return {
        "frameworks": frameworks,
        "overall_score": overall_score,
        "summary": f"Compliance status for org {org_id}",
    }


def _generate_threat_intel_brief(org_id: str, filters: Dict[str, Any]) -> Dict[str, Any]:
    """Latest threat intel indicators, feed status, top IOCs."""
    top_iocs: List[Dict[str, Any]] = []
    feed_status: List[Dict[str, Any]] = []
    threat_count = 0

    # NOTE: core.threat_intel_aggregator module was retired; threat-intel
    # rollup is now sourced via suite-feeds importers. Until this report is
    # rewired to that surface, leave defaults (empty lists / zero count) so
    # the brief renders without an import error each schedule.
    pass

    return {
        "top_iocs": top_iocs,
        "feed_status": feed_status,
        "threat_count": threat_count,
        "summary": f"Threat intelligence brief for org {org_id}",
    }


def _generate_kpi_scorecard(org_id: str, filters: Dict[str, Any]) -> Dict[str, Any]:
    """MTTD/MTTR, SLA compliance, trend vs last period."""
    mttd_hours = 0.0
    mttr_hours = 0.0
    sla_compliance_pct = 0.0
    posture_score = 0.0
    trend: Dict[str, Any] = {}

    try:
        import sys
        sys.path.insert(0, "suite-core")
        from core.security_kpi_tracker import SecurityKPITracker
        tracker = SecurityKPITracker()
        scorecard = tracker.get_scorecard(org_id=org_id)
        mttd_hours = scorecard.get("mttd_hours", 0.0)
        mttr_hours = scorecard.get("mttr_hours", 0.0)
        sla_compliance_pct = scorecard.get("sla_compliance_pct", 0.0)
        posture_score = scorecard.get("posture_score", 0.0)
        trend = scorecard.get("trend", {})
    except Exception:
        pass

    return {
        "mttd_hours": mttd_hours,
        "mttr_hours": mttr_hours,
        "sla_compliance_pct": sla_compliance_pct,
        "posture_score": posture_score,
        "trend_vs_last_period": trend,
        "summary": f"KPI scorecard for org {org_id}",
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _calculate_next_run(
    frequency: str, from_time: Optional[datetime] = None
) -> datetime:
    """Calculate next run datetime from now (or from_time)."""
    base = from_time or datetime.now(timezone.utc)
    if frequency == "daily":
        return base + timedelta(days=1)
    if frequency == "weekly":
        return base + timedelta(weeks=1)
    if frequency == "monthly":
        return base + timedelta(days=30)
    raise ValueError(f"Unknown frequency '{frequency}'")


def _row_to_schedule(row: sqlite3.Row) -> Dict[str, Any]:
    d = dict(row)
    for field in ("recipients", "channels", "filters"):
        if field in d and isinstance(d[field], str):
            try:
                d[field] = json.loads(d[field])
            except (json.JSONDecodeError, TypeError):
                d[field] = []
    if "active" in d:
        d["active"] = bool(d["active"])
    return d


def _row_to_log_entry(row: sqlite3.Row) -> Dict[str, Any]:
    d = dict(row)
    if "channels_notified" in d and isinstance(d["channels_notified"], str):
        try:
            d["channels_notified"] = json.loads(d["channels_notified"])
        except (json.JSONDecodeError, TypeError):
            d["channels_notified"] = []
    return d
