"""Endpoint Detection & Response (EDR) Engine — ALDECI.

Tracks endpoints, process-level telemetry, detections, and isolation actions.

Capabilities:
  - Endpoint registry (multi-OS, risk scoring, status tracking)
  - Process event ingestion with auto-detection heuristics (MITRE ATT&CK)
  - Detection lifecycle management (new → investigating → contained → resolved)
  - Endpoint isolation and release workflow
  - Stats aggregation per org

Compliance: MITRE ATT&CK, CIS Controls v8 (Control 10), NIST SP 800-171 (3.14)
"""

from __future__ import annotations

import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None

_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "edr_engine.db"
)

_VALID_OS_TYPES = {"windows", "linux", "macos", "android", "ios"}
_VALID_ENDPOINT_STATUSES = {"online", "offline", "isolated", "compromised"}
_VALID_EVENT_TYPES = {
    "create", "terminate", "inject", "suspicious_api", "network_conn",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_VALID_DETECTION_TYPES = {
    "malware", "ransomware", "rootkit", "keylogger", "credential_dumper",
    "lateral_tool", "suspicious_script", "anomaly",
}
_VALID_DETECTION_STATUSES = {
    "new", "investigating", "contained", "resolved", "false_positive",
}

# ---------------------------------------------------------------------------
# Heuristic detection rules: (pattern_check_fn, detection_name, detection_type,
#                              severity, mitre_technique, auto_isolate)
# ---------------------------------------------------------------------------
def _is_encoded_powershell(data: Dict[str, Any]) -> bool:
    proc = (data.get("process_name") or "").lower()
    cmd = (data.get("cmdline") or "").lower()
    return "powershell" in proc and ("-enc" in cmd or "-encodedcommand" in cmd)


def _is_mimikatz(data: Dict[str, Any]) -> bool:
    proc = (data.get("process_name") or "").lower()
    cmd = (data.get("cmdline") or "").lower()
    return "mimikatz" in proc or "lsass" in proc or "sekurlsa" in cmd


def _is_psexec(data: Dict[str, Any]) -> bool:
    proc = (data.get("process_name") or "").lower()
    return "psexec" in proc or "psexesvc" in proc


def _is_regsvr32(data: Dict[str, Any]) -> bool:
    proc = (data.get("process_name") or "").lower()
    return "regsvr32" in proc


def _is_cscript(data: Dict[str, Any]) -> bool:
    proc = (data.get("process_name") or "").lower()
    return proc in ("cscript.exe", "wscript.exe", "cscript", "wscript")


_DETECTION_RULES = [
    (_is_encoded_powershell, "Encoded PowerShell Execution",
     "suspicious_script", "critical", "T1059.001", True),
    (_is_mimikatz, "Credential Dumping via LSASS/Mimikatz",
     "credential_dumper", "critical", "T1003.001", True),
    (_is_psexec, "PsExec Lateral Movement Tool",
     "lateral_tool", "high", "T1570", False),
    (_is_regsvr32, "Regsvr32 Proxy Execution",
     "suspicious_script", "high", "T1218.010", False),
    (_is_cscript, "Suspicious Script Host Execution",
     "suspicious_script", "medium", "T1059.005", False),
]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class EDREngine:
    """SQLite WAL-backed EDR engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS endpoints (
                    endpoint_id   TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    hostname      TEXT NOT NULL,
                    ip_address    TEXT NOT NULL DEFAULT '',
                    os_type       TEXT NOT NULL DEFAULT 'linux',
                    os_version    TEXT NOT NULL DEFAULT '',
                    agent_version TEXT NOT NULL DEFAULT '',
                    status        TEXT NOT NULL DEFAULT 'online',
                    last_seen     DATETIME NOT NULL,
                    risk_score    REAL NOT NULL DEFAULT 0.0,
                    created_at    DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ep_org_status
                    ON endpoints (org_id, status);

                CREATE TABLE IF NOT EXISTS process_events (
                    event_id      TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    endpoint_id   TEXT NOT NULL,
                    process_name  TEXT NOT NULL DEFAULT '',
                    process_hash  TEXT NOT NULL DEFAULT '',
                    parent_process TEXT NOT NULL DEFAULT '',
                    cmdline       TEXT NOT NULL DEFAULT '',
                    user          TEXT NOT NULL DEFAULT '',
                    pid           INTEGER NOT NULL DEFAULT 0,
                    event_type    TEXT NOT NULL DEFAULT 'create',
                    severity      TEXT NOT NULL DEFAULT 'info',
                    mitre_technique TEXT NOT NULL DEFAULT '',
                    observed_at   DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_pe_org_ep
                    ON process_events (org_id, endpoint_id, observed_at DESC);

                CREATE INDEX IF NOT EXISTS idx_pe_org_severity
                    ON process_events (org_id, severity);

                CREATE TABLE IF NOT EXISTS edr_detections (
                    detection_id   TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    endpoint_id    TEXT NOT NULL,
                    event_id       TEXT NOT NULL,
                    detection_name TEXT NOT NULL,
                    detection_type TEXT NOT NULL DEFAULT 'anomaly',
                    confidence     REAL NOT NULL DEFAULT 0.8,
                    severity       TEXT NOT NULL DEFAULT 'medium',
                    status         TEXT NOT NULL DEFAULT 'new',
                    auto_isolated  INTEGER NOT NULL DEFAULT 0,
                    detected_at    DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_det_org_status
                    ON edr_detections (org_id, status, detected_at DESC);

                CREATE TABLE IF NOT EXISTS endpoint_isolation (
                    isolation_id  TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    endpoint_id   TEXT NOT NULL,
                    reason        TEXT NOT NULL DEFAULT '',
                    isolated_at   DATETIME NOT NULL,
                    released_at   DATETIME,
                    isolated_by   TEXT NOT NULL DEFAULT ''
                );

                CREATE INDEX IF NOT EXISTS idx_iso_org_ep
                    ON endpoint_isolation (org_id, endpoint_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Endpoints
    # ------------------------------------------------------------------

    def register_endpoint(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new endpoint. Returns the created record."""
        hostname = (data.get("hostname") or "").strip()
        if not hostname:
            raise ValueError("hostname is required.")

        os_type = data.get("os_type", "linux")
        if os_type not in _VALID_OS_TYPES:
            raise ValueError(f"Invalid os_type: {os_type}. Must be one of {_VALID_OS_TYPES}")

        now = _now_iso()
        record = {
            "endpoint_id": str(uuid.uuid4()),
            "org_id": org_id,
            "hostname": hostname,
            "ip_address": data.get("ip_address", ""),
            "os_type": os_type,
            "os_version": data.get("os_version", ""),
            "agent_version": data.get("agent_version", ""),
            "status": "online",
            "last_seen": now,
            "risk_score": float(data.get("risk_score", 0.0)),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO endpoints
                       (endpoint_id, org_id, hostname, ip_address, os_type,
                        os_version, agent_version, status, last_seen, risk_score, created_at)
                       VALUES (:endpoint_id, :org_id, :hostname, :ip_address, :os_type,
                               :os_version, :agent_version, :status, :last_seen, :risk_score, :created_at)""",
                    record,
                )
        return record

    def list_endpoints(
        self,
        org_id: str,
        status: Optional[str] = None,
        os_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List endpoints, optionally filtered by status and/or os_type."""
        sql = "SELECT * FROM endpoints WHERE org_id = ?"
        params: list = [org_id]
        if status:
            sql += " AND status = ?"
            params.append(status)
        if os_type:
            sql += " AND os_type = ?"
            params.append(os_type)
        sql += " ORDER BY last_seen DESC"
        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    def get_endpoint(self, org_id: str, endpoint_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single endpoint by ID."""
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM endpoints WHERE org_id = ? AND endpoint_id = ?",
                (org_id, endpoint_id),
            ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Process events
    # ------------------------------------------------------------------

    def ingest_process_event(
        self,
        org_id: str,
        endpoint_id: str,
        data: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Ingest a process event and auto-detect suspicious patterns.

        Returns the created process_event record. If a detection rule fires,
        also creates an edr_detections record and optionally isolates the endpoint.
        """
        event_type = data.get("event_type", "create")
        if event_type not in _VALID_EVENT_TYPES:
            raise ValueError(f"Invalid event_type: {event_type}")

        # Determine severity from heuristics first
        severity = "info"
        mitre_technique = ""
        triggered_rule = None

        for check_fn, det_name, det_type, det_sev, mitre, auto_iso in _DETECTION_RULES:
            if check_fn(data):
                severity = det_sev
                mitre_technique = mitre
                triggered_rule = (det_name, det_type, det_sev, mitre, auto_iso)
                break

        # Allow explicit severity override
        explicit_sev = data.get("severity")
        if explicit_sev and explicit_sev in _VALID_SEVERITIES:
            severity = explicit_sev

        now = _now_iso()
        event = {
            "event_id": str(uuid.uuid4()),
            "org_id": org_id,
            "endpoint_id": endpoint_id,
            "process_name": data.get("process_name", ""),
            "process_hash": data.get("process_hash", ""),
            "parent_process": data.get("parent_process", ""),
            "cmdline": data.get("cmdline", ""),
            "user": data.get("user", ""),
            "pid": int(data.get("pid", 0)),
            "event_type": event_type,
            "severity": severity,
            "mitre_technique": mitre_technique or data.get("mitre_technique", ""),
            "observed_at": now,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO process_events
                       (event_id, org_id, endpoint_id, process_name, process_hash,
                        parent_process, cmdline, user, pid, event_type, severity,
                        mitre_technique, observed_at)
                       VALUES (:event_id, :org_id, :endpoint_id, :process_name, :process_hash,
                               :parent_process, :cmdline, :user, :pid, :event_type, :severity,
                               :mitre_technique, :observed_at)""",
                    event,
                )

            # Create detection if heuristic fired
            if triggered_rule:
                det_name, det_type, det_sev, mitre, auto_iso = triggered_rule
                detection = {
                    "detection_id": str(uuid.uuid4()),
                    "org_id": org_id,
                    "endpoint_id": endpoint_id,
                    "event_id": event["event_id"],
                    "detection_name": det_name,
                    "detection_type": det_type,
                    "confidence": 0.9,
                    "severity": det_sev,
                    "status": "new",
                    "auto_isolated": 1 if auto_iso else 0,
                    "detected_at": now,
                }
                with self._conn() as conn:
                    conn.execute(
                        """INSERT INTO edr_detections
                           (detection_id, org_id, endpoint_id, event_id, detection_name,
                            detection_type, confidence, severity, status, auto_isolated, detected_at)
                           VALUES (:detection_id, :org_id, :endpoint_id, :event_id, :detection_name,
                                   :detection_type, :confidence, :severity, :status, :auto_isolated,
                                   :detected_at)""",
                        detection,
                    )

                if auto_iso:
                    try:
                        self.isolate_endpoint(
                            org_id, endpoint_id,
                            reason=f"Auto-isolated: {det_name}",
                            isolated_by="edr_engine_auto",
                        )
                    except Exception:
                        pass  # endpoint may not exist in db yet

                if _get_tg_bus:
                    try:
                        bus = _get_tg_bus()
                        if bus:
                            bus.emit("THREAT_DETECTED", {"entity_type": "edr_detection", "entity_id": str(detection["detection_id"]), "org_id": org_id, "source_engine": "edr_engine"})
                    except Exception:
                        pass  # Event emission should never break the main operation

                event["_detection_created"] = detection["detection_id"]

        # Update last_seen on endpoint
        try:
            with self._lock:
                with self._conn() as conn:
                    conn.execute(
                        "UPDATE endpoints SET last_seen = ? WHERE org_id = ? AND endpoint_id = ?",
                        (now, org_id, endpoint_id),
                    )
        except Exception:
            pass

        return event

    def list_process_events(
        self,
        org_id: str,
        endpoint_id: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """List process events with optional filters."""
        sql = "SELECT * FROM process_events WHERE org_id = ?"
        params: list = [org_id]
        if endpoint_id:
            sql += " AND endpoint_id = ?"
            params.append(endpoint_id)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        sql += " ORDER BY observed_at DESC LIMIT ?"
        params.append(limit)
        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    # ------------------------------------------------------------------
    # Detections
    # ------------------------------------------------------------------

    def list_detections(
        self,
        org_id: str,
        detection_type: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List detections with optional filters."""
        sql = "SELECT * FROM edr_detections WHERE org_id = ?"
        params: list = [org_id]
        if detection_type:
            sql += " AND detection_type = ?"
            params.append(detection_type)
        if status:
            sql += " AND status = ?"
            params.append(status)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        sql += " ORDER BY detected_at DESC"
        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    def update_detection_status(
        self, org_id: str, detection_id: str, status: str
    ) -> bool:
        """Update detection status. Returns True if record was found and updated."""
        if status not in _VALID_DETECTION_STATUSES:
            raise ValueError(f"Invalid status: {status}. Must be one of {_VALID_DETECTION_STATUSES}")
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    "UPDATE edr_detections SET status = ? WHERE org_id = ? AND detection_id = ?",
                    (status, org_id, detection_id),
                )
                return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Isolation
    # ------------------------------------------------------------------

    def isolate_endpoint(
        self,
        org_id: str,
        endpoint_id: str,
        reason: str,
        isolated_by: str,
    ) -> Dict[str, Any]:
        """Isolate an endpoint. Sets status=isolated and creates isolation record."""
        now = _now_iso()
        isolation = {
            "isolation_id": str(uuid.uuid4()),
            "org_id": org_id,
            "endpoint_id": endpoint_id,
            "reason": reason,
            "isolated_at": now,
            "released_at": None,
            "isolated_by": isolated_by,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    "UPDATE endpoints SET status = 'isolated' WHERE org_id = ? AND endpoint_id = ?",
                    (org_id, endpoint_id),
                )
                conn.execute(
                    """INSERT INTO endpoint_isolation
                       (isolation_id, org_id, endpoint_id, reason, isolated_at, released_at, isolated_by)
                       VALUES (:isolation_id, :org_id, :endpoint_id, :reason, :isolated_at,
                               :released_at, :isolated_by)""",
                    isolation,
                )
        return isolation

    def release_endpoint(self, org_id: str, endpoint_id: str) -> bool:
        """Release an isolated endpoint. Returns True if found."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    "UPDATE endpoints SET status = 'online' WHERE org_id = ? AND endpoint_id = ?",
                    (org_id, endpoint_id),
                )
                conn.execute(
                    """UPDATE endpoint_isolation SET released_at = ?
                       WHERE org_id = ? AND endpoint_id = ? AND released_at IS NULL""",
                    (now, org_id, endpoint_id),
                )
                return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_edr_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated EDR stats for org."""
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        with self._conn() as conn:
            total_ep = conn.execute(
                "SELECT COUNT(*) FROM endpoints WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            online_ep = conn.execute(
                "SELECT COUNT(*) FROM endpoints WHERE org_id = ? AND status = 'online'", (org_id,)
            ).fetchone()[0]
            isolated_ep = conn.execute(
                "SELECT COUNT(*) FROM endpoints WHERE org_id = ? AND status = 'isolated'", (org_id,)
            ).fetchone()[0]
            compromised_ep = conn.execute(
                "SELECT COUNT(*) FROM endpoints WHERE org_id = ? AND status = 'compromised'", (org_id,)
            ).fetchone()[0]
            new_det = conn.execute(
                "SELECT COUNT(*) FROM edr_detections WHERE org_id = ? AND status = 'new'", (org_id,)
            ).fetchone()[0]
            crit_det = conn.execute(
                "SELECT COUNT(*) FROM edr_detections WHERE org_id = ? AND severity = 'critical'",
                (org_id,),
            ).fetchone()[0]
            events_today = conn.execute(
                "SELECT COUNT(*) FROM process_events WHERE org_id = ? AND observed_at >= ?",
                (org_id, today),
            ).fetchone()[0]

            # By detection type
            by_type_rows = conn.execute(
                """SELECT detection_type, COUNT(*) as cnt
                   FROM edr_detections WHERE org_id = ?
                   GROUP BY detection_type""",
                (org_id,),
            ).fetchall()
            by_detection_type = {r["detection_type"]: r["cnt"] for r in by_type_rows}

        return {
            "total_endpoints": total_ep,
            "online_endpoints": online_ep,
            "isolated_endpoints": isolated_ep,
            "compromised_endpoints": compromised_ep,
            "new_detections": new_det,
            "critical_detections": crit_det,
            "process_events_today": events_today,
            "by_detection_type": by_detection_type,
        }
