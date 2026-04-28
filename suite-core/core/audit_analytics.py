"""
Audit Log Analytics Engine — ALDECI.

Provides end-to-end audit log lifecycle management:
- Log ingestion from syslog, JSON, CEF, and LEEF wire formats
- Normalization to a unified AuditEntry schema
- Full-text and field-based search with SQLite FTS5
- Anomaly detection: off-hours access, privilege escalation, unusual patterns
- Compliance audit trails for SOC2/HIPAA (who did what when)
- Retention policy: auto-archive after 90d, delete after 1yr, legal hold
- Forensic timeline builder from correlated audit entries

SQLite-backed, thread-safe, multi-tenant (per org_id).

Compliance: SOC2 CC7.2 (continuous monitoring), HIPAA §164.312(b) (audit controls)
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(Path(__file__).resolve().parents[2] / "data" / "audit_analytics.db")

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:
    _get_tg_bus = None  # type: ignore[assignment]


def _tg_emit(event_type: str, payload: dict) -> None:
    try:
        if _get_tg_bus is None:
            return
        bus = _get_tg_bus()
        if bus is not None:
            bus.emit(event_type, payload)
    except Exception:
        pass

# Business hours for off-hours detection (UTC)
_BUSINESS_HOUR_START = 8   # 08:00 UTC
_BUSINESS_HOUR_END = 18    # 18:00 UTC
_BUSINESS_DAYS = {0, 1, 2, 3, 4}  # Mon–Fri

# Retention defaults (days)
_ARCHIVE_AFTER_DAYS = 90
_DELETE_AFTER_DAYS = 365


# ============================================================================
# ENUMS
# ============================================================================


class LogFormat(str, Enum):
    """Supported wire formats for log ingestion."""

    JSON = "json"
    SYSLOG = "syslog"
    CEF = "cef"
    LEEF = "leef"


class AuditSeverity(str, Enum):
    """Normalised severity levels."""

    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class EntryStatus(str, Enum):
    """Lifecycle status of an audit entry."""

    ACTIVE = "active"
    ARCHIVED = "archived"
    LEGAL_HOLD = "legal_hold"
    DELETED = "deleted"


class AnomalyKind(str, Enum):
    """Categories of detected audit anomalies."""

    OFF_HOURS_ACCESS = "off_hours_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    UNUSUAL_VOLUME = "unusual_volume"
    REPEATED_FAILURE = "repeated_failure"
    GEO_ANOMALY = "geo_anomaly"
    SENSITIVE_RESOURCE = "sensitive_resource"


class RetentionAction(str, Enum):
    """Actions that can be applied to entries under a retention policy."""

    ARCHIVE = "archive"
    DELETE = "delete"
    HOLD = "hold"


# ============================================================================
# PYDANTIC MODELS
# ============================================================================


class AuditEntry(BaseModel):
    """Unified normalised audit log entry."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    org_id: str = "default"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ingested_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    source_format: LogFormat = LogFormat.JSON
    severity: AuditSeverity = AuditSeverity.INFO
    actor: str = ""                    # user / service that performed the action
    actor_ip: str = ""
    action: str = ""                   # verb: login, read, write, delete, escalate …
    resource_type: str = ""            # findings, user, policy, secret …
    resource_id: str = ""
    outcome: str = "success"           # success | failure | partial
    details: Dict[str, Any] = Field(default_factory=dict)
    raw: str = ""                      # original unparsed line
    status: EntryStatus = EntryStatus.ACTIVE
    checksum: str = ""                 # SHA-256 of (id + timestamp.isoformat + raw)

    def compute_checksum(self) -> str:
        """Return SHA-256 over id + timestamp + raw fields."""
        payload = f"{self.id}{self.timestamp.isoformat()}{self.raw}"
        return hashlib.sha256(payload.encode()).hexdigest()

    def model_post_init(self, __context: Any) -> None:  # noqa: D401
        if not self.checksum:
            self.checksum = self.compute_checksum()


class AuditAnomaly(BaseModel):
    """A detected anomaly within audit logs."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    org_id: str = "default"
    kind: AnomalyKind
    severity: AuditSeverity
    actor: str
    description: str
    entry_ids: List[str] = Field(default_factory=list)
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    details: Dict[str, Any] = Field(default_factory=dict)


class RetentionPolicy(BaseModel):
    """Retention configuration for an org."""

    org_id: str = "default"
    archive_after_days: int = _ARCHIVE_AFTER_DAYS
    delete_after_days: int = _DELETE_AFTER_DAYS
    legal_hold_actor_ids: List[str] = Field(default_factory=list)


class TimelineEvent(BaseModel):
    """A single event in a forensic timeline."""

    timestamp: datetime
    actor: str
    action: str
    resource_type: str
    resource_id: str
    outcome: str
    severity: AuditSeverity
    entry_id: str
    details: Dict[str, Any] = Field(default_factory=dict)


class ForensicTimeline(BaseModel):
    """Ordered sequence of audit events for forensic analysis."""

    query: str
    start: datetime
    end: datetime
    events: List[TimelineEvent] = Field(default_factory=list)
    total: int = 0
    actors: List[str] = Field(default_factory=list)
    resources: List[str] = Field(default_factory=list)


class SearchResult(BaseModel):
    """Paginated search result."""

    items: List[AuditEntry] = Field(default_factory=list)
    total: int = 0
    limit: int = 100
    offset: int = 0
    query: str = ""


class RetentionReport(BaseModel):
    """Summary of a retention policy run."""

    org_id: str
    archived: int = 0
    deleted: int = 0
    held: int = 0
    skipped: int = 0
    run_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# ============================================================================
# LOG PARSERS
# ============================================================================


class LogParser:
    """Parse raw log lines in multiple wire formats into AuditEntry objects."""

    # Syslog RFC 3164 prefix: <PRI>Mon DD HH:MM:SS hostname tag[pid]: msg
    _SYSLOG_RE = re.compile(
        r"^(?:<(?P<pri>\d+)>)?"
        r"(?P<month>\w{3})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
        r"(?P<host>\S+)\s+"
        r"(?P<tag>[^\[:\s]+)(?:\[(?P<pid>\d+)\])?:\s+"
        r"(?P<msg>.*)$",
        re.DOTALL,
    )

    # CEF: CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    _CEF_RE = re.compile(
        r"CEF:(?P<version>\d+)\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|"
        r"(?P<dev_version>[^|]*)\|(?P<sig_id>[^|]*)\|(?P<name>[^|]*)\|"
        r"(?P<severity>[^|]*)\|(?P<ext>.*)",
        re.DOTALL,
    )

    # LEEF: LEEF:Version|Vendor|Product|Version|EventID|key=value pairs
    _LEEF_RE = re.compile(
        r"LEEF:(?P<version>[^|]*)\|(?P<vendor>[^|]*)\|(?P<product>[^|]*)\|"
        r"(?P<dev_version>[^|]*)\|(?P<event_id>[^|]*)\|(?P<attrs>.*)",
        re.DOTALL,
    )

    _CEF_SEVERITY_MAP: Dict[str, AuditSeverity] = {
        "0": AuditSeverity.DEBUG,
        "1": AuditSeverity.DEBUG,
        "2": AuditSeverity.DEBUG,
        "3": AuditSeverity.INFO,
        "4": AuditSeverity.INFO,
        "5": AuditSeverity.WARNING,
        "6": AuditSeverity.WARNING,
        "7": AuditSeverity.ERROR,
        "8": AuditSeverity.ERROR,
        "9": AuditSeverity.CRITICAL,
        "10": AuditSeverity.CRITICAL,
        "low": AuditSeverity.INFO,
        "medium": AuditSeverity.WARNING,
        "high": AuditSeverity.ERROR,
        "very-high": AuditSeverity.CRITICAL,
    }

    def parse(self, raw: str, fmt: LogFormat, org_id: str = "default") -> AuditEntry:
        """Parse *raw* text using *fmt* format and return a normalised AuditEntry."""
        raw = raw.strip()
        if fmt == LogFormat.JSON:
            return self._parse_json(raw, org_id)
        if fmt == LogFormat.SYSLOG:
            return self._parse_syslog(raw, org_id)
        if fmt == LogFormat.CEF:
            return self._parse_cef(raw, org_id)
        if fmt == LogFormat.LEEF:
            return self._parse_leef(raw, org_id)
        raise ValueError(f"Unknown log format: {fmt}")

    # ------------------------------------------------------------------
    # JSON
    # ------------------------------------------------------------------

    def _parse_json(self, raw: str, org_id: str) -> AuditEntry:
        try:
            data: Dict[str, Any] = json.loads(raw)
        except json.JSONDecodeError as exc:
            _logger.warning("JSON parse error: %s", exc)
            data = {}

        ts = self._parse_ts(data.get("timestamp") or data.get("time") or data.get("@timestamp"))
        severity = self._norm_severity(str(data.get("severity") or data.get("level") or "info"))

        return AuditEntry(
            org_id=org_id,
            timestamp=ts,
            source_format=LogFormat.JSON,
            severity=severity,
            actor=str(data.get("actor") or data.get("user") or data.get("username") or ""),
            actor_ip=str(data.get("actor_ip") or data.get("ip") or data.get("src_ip") or ""),
            action=str(data.get("action") or data.get("event") or data.get("message") or ""),
            resource_type=str(data.get("resource_type") or data.get("resource") or ""),
            resource_id=str(data.get("resource_id") or data.get("id") or ""),
            outcome=str(data.get("outcome") or data.get("result") or data.get("status") or "success"),
            details=data,
            raw=raw,
        )

    # ------------------------------------------------------------------
    # Syslog
    # ------------------------------------------------------------------

    def _parse_syslog(self, raw: str, org_id: str) -> AuditEntry:
        m = self._SYSLOG_RE.match(raw)
        if not m:
            return AuditEntry(org_id=org_id, action=raw[:200], raw=raw, source_format=LogFormat.SYSLOG)

        pri = int(m.group("pri") or 13)
        # RFC 3164 severity = PRI mod 8
        syslog_sev = pri % 8
        severity_map = [
            AuditSeverity.CRITICAL, AuditSeverity.CRITICAL, AuditSeverity.CRITICAL,
            AuditSeverity.ERROR, AuditSeverity.WARNING, AuditSeverity.WARNING,
            AuditSeverity.INFO, AuditSeverity.DEBUG,
        ]
        severity = severity_map[syslog_sev] if syslog_sev < len(severity_map) else AuditSeverity.INFO

        now = datetime.now(timezone.utc)
        try:
            ts_str = f"{now.year} {m.group('month')} {m.group('day')} {m.group('time')}"
            ts = datetime.strptime(ts_str, "%Y %b %d %H:%M:%S").replace(tzinfo=timezone.utc)
        except ValueError:
            ts = now

        msg = m.group("msg") or ""
        return AuditEntry(
            org_id=org_id,
            timestamp=ts,
            source_format=LogFormat.SYSLOG,
            severity=severity,
            actor=m.group("host") or "",
            action=msg[:500],
            details={"tag": m.group("tag"), "pid": m.group("pid"), "host": m.group("host")},
            raw=raw,
        )

    # ------------------------------------------------------------------
    # CEF
    # ------------------------------------------------------------------

    def _parse_cef(self, raw: str, org_id: str) -> AuditEntry:
        m = self._CEF_RE.match(raw)
        if not m:
            return AuditEntry(org_id=org_id, action=raw[:200], raw=raw, source_format=LogFormat.CEF)

        ext_str = m.group("ext") or ""
        ext = self._parse_kv(ext_str)

        severity = self._CEF_SEVERITY_MAP.get(m.group("severity").strip().lower(), AuditSeverity.INFO)
        ts = self._parse_ts(ext.get("rt") or ext.get("start"))
        actor = str(ext.get("suser") or ext.get("duser") or "")
        actor_ip = str(ext.get("src") or ext.get("sourceAddress") or "")
        outcome = "failure" if ext.get("outcome", "").lower() in {"0", "false", "fail", "failure"} else "success"

        return AuditEntry(
            org_id=org_id,
            timestamp=ts,
            source_format=LogFormat.CEF,
            severity=severity,
            actor=actor,
            actor_ip=actor_ip,
            action=m.group("name") or m.group("sig_id") or "",
            resource_type=str(ext.get("destinationServiceName") or ""),
            resource_id=str(ext.get("fileId") or ext.get("resourceId") or ""),
            outcome=outcome,
            details={
                "vendor": m.group("vendor"),
                "product": m.group("product"),
                "sig_id": m.group("sig_id"),
                **ext,
            },
            raw=raw,
        )

    # ------------------------------------------------------------------
    # LEEF
    # ------------------------------------------------------------------

    def _parse_leef(self, raw: str, org_id: str) -> AuditEntry:
        m = self._LEEF_RE.match(raw)
        if not m:
            return AuditEntry(org_id=org_id, action=raw[:200], raw=raw, source_format=LogFormat.LEEF)

        attrs_str = m.group("attrs") or ""
        # LEEF 2.0 uses tab; LEEF 1.0 uses tab too, but allow any whitespace delimiter
        attrs = self._parse_kv(attrs_str, delimiter="\t")
        if not attrs:
            attrs = self._parse_kv(attrs_str)

        ts = self._parse_ts(attrs.get("devTime") or attrs.get("receiptTime"))
        severity_raw = str(attrs.get("severity") or attrs.get("sev") or "info")
        severity = self._norm_severity(severity_raw)
        actor = str(attrs.get("usrName") or attrs.get("src") or "")
        actor_ip = str(attrs.get("src") or "")

        return AuditEntry(
            org_id=org_id,
            timestamp=ts,
            source_format=LogFormat.LEEF,
            severity=severity,
            actor=actor,
            actor_ip=actor_ip,
            action=m.group("event_id") or "",
            resource_type=str(attrs.get("resource") or ""),
            resource_id=str(attrs.get("resourceId") or ""),
            outcome=str(attrs.get("outcome") or "success"),
            details={"vendor": m.group("vendor"), "product": m.group("product"), **attrs},
            raw=raw,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_kv(text: str, delimiter: str = " ") -> Dict[str, str]:
        """Parse `key=value` pairs from *text*."""
        result: Dict[str, str] = {}
        # Tokenise on delimiter then split each token on first '='
        for token in text.split(delimiter):
            if "=" in token:
                k, _, v = token.partition("=")
                result[k.strip()] = v.strip()
        return result

    @staticmethod
    def _parse_ts(value: Any) -> datetime:
        """Best-effort timestamp parse; falls back to utcnow."""
        if value is None:
            return datetime.now(timezone.utc)
        if isinstance(value, datetime):
            return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        s = str(value)
        formats = [
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%d %H:%M:%S",
            "%b %d %Y %H:%M:%S",
        ]
        for fmt in formats:
            try:
                dt = datetime.strptime(s, fmt)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                continue
        # Try epoch millis
        try:
            epoch_ms = int(s)
            return datetime.fromtimestamp(epoch_ms / 1000.0, tz=timezone.utc)
        except (ValueError, OSError):
            pass
        return datetime.now(timezone.utc)

    @staticmethod
    def _norm_severity(raw: str) -> AuditSeverity:
        """Normalise a free-text severity string to AuditSeverity."""
        lw = raw.strip().lower()
        mapping = {
            "debug": AuditSeverity.DEBUG,
            "trace": AuditSeverity.DEBUG,
            "info": AuditSeverity.INFO,
            "information": AuditSeverity.INFO,
            "notice": AuditSeverity.INFO,
            "warn": AuditSeverity.WARNING,
            "warning": AuditSeverity.WARNING,
            "medium": AuditSeverity.WARNING,
            "error": AuditSeverity.ERROR,
            "err": AuditSeverity.ERROR,
            "high": AuditSeverity.ERROR,
            "crit": AuditSeverity.CRITICAL,
            "critical": AuditSeverity.CRITICAL,
            "alert": AuditSeverity.CRITICAL,
            "emerg": AuditSeverity.CRITICAL,
            "emergency": AuditSeverity.CRITICAL,
            "very-high": AuditSeverity.CRITICAL,
        }
        return mapping.get(lw, AuditSeverity.INFO)


# ============================================================================
# ANOMALY DETECTOR
# ============================================================================


class AuditAnomalyDetector:
    """
    Stateless anomaly detector that scores a batch of AuditEntry objects.

    Rules applied (in order):
    1. Off-hours access — events outside business hours
    2. Privilege escalation — action contains escalation keywords
    3. Repeated failures — >5 failure events by same actor within 10 minutes
    4. Unusual volume — actor triggers >50 events in any 60-minute window
    5. Sensitive resource access — action on sensitive resource types
    """

    _ESCALATION_KEYWORDS = frozenset({
        "escalat", "sudo", "su ", "root", "admin", "privilege", "elevat",
        "impersonat", "assume_role", "sts:AssumeRole", "setuid",
    })
    _SENSITIVE_RESOURCES = frozenset({
        "secret", "credential", "password", "key", "token", "certificate",
        "private_key", "api_key", "ssh_key",
    })

    def detect(self, entries: List[AuditEntry], org_id: str = "default") -> List[AuditAnomaly]:
        """Return anomalies found in *entries*."""
        anomalies: List[AuditAnomaly] = []
        anomalies.extend(self._off_hours(entries, org_id))
        anomalies.extend(self._privilege_escalation(entries, org_id))
        anomalies.extend(self._repeated_failures(entries, org_id))
        anomalies.extend(self._unusual_volume(entries, org_id))
        anomalies.extend(self._sensitive_resource(entries, org_id))
        return anomalies

    def _off_hours(self, entries: List[AuditEntry], org_id: str) -> List[AuditAnomaly]:
        hits: List[AuditEntry] = []
        for e in entries:
            ts = e.timestamp.astimezone(timezone.utc)
            if ts.weekday() not in _BUSINESS_DAYS or not (_BUSINESS_HOUR_START <= ts.hour < _BUSINESS_HOUR_END):
                if e.severity not in (AuditSeverity.DEBUG,):
                    hits.append(e)
        if not hits:
            return []
        actors = list({h.actor for h in hits if h.actor})
        return [
            AuditAnomaly(
                org_id=org_id,
                kind=AnomalyKind.OFF_HOURS_ACCESS,
                severity=AuditSeverity.WARNING,
                actor=", ".join(actors[:5]),
                description=f"{len(hits)} event(s) detected outside business hours (UTC {_BUSINESS_HOUR_START}:00-{_BUSINESS_HOUR_END}:00, Mon-Fri)",
                entry_ids=[h.id for h in hits[:50]],
                details={"count": len(hits), "actors": actors},
            )
        ]

    def _privilege_escalation(self, entries: List[AuditEntry], org_id: str) -> List[AuditAnomaly]:
        hits: List[AuditEntry] = []
        for e in entries:
            action_lower = e.action.lower()
            if any(kw in action_lower for kw in self._ESCALATION_KEYWORDS):
                hits.append(e)
        if not hits:
            return []
        actors = list({h.actor for h in hits if h.actor})
        return [
            AuditAnomaly(
                org_id=org_id,
                kind=AnomalyKind.PRIVILEGE_ESCALATION,
                severity=AuditSeverity.CRITICAL,
                actor=", ".join(actors[:5]),
                description=f"{len(hits)} potential privilege-escalation event(s) detected",
                entry_ids=[h.id for h in hits[:50]],
                details={"count": len(hits), "actors": actors},
            )
        ]

    def _repeated_failures(self, entries: List[AuditEntry], org_id: str) -> List[AuditAnomaly]:
        window = timedelta(minutes=10)
        failures: Dict[str, List[AuditEntry]] = {}
        for e in entries:
            if e.outcome.lower() in {"failure", "fail", "error", "denied", "0", "false"}:
                failures.setdefault(e.actor, []).append(e)

        anomalies: List[AuditAnomaly] = []
        for actor, actor_entries in failures.items():
            actor_entries_sorted = sorted(actor_entries, key=lambda x: x.timestamp)
            # Sliding window
            for i, base in enumerate(actor_entries_sorted):
                cluster = [
                    e for e in actor_entries_sorted[i:]
                    if e.timestamp - base.timestamp <= window
                ]
                if len(cluster) > 5:
                    anomalies.append(AuditAnomaly(
                        org_id=org_id,
                        kind=AnomalyKind.REPEATED_FAILURE,
                        severity=AuditSeverity.ERROR,
                        actor=actor,
                        description=f"Actor '{actor}' had {len(cluster)} failures within 10 minutes",
                        entry_ids=[e.id for e in cluster[:50]],
                        details={"failure_count": len(cluster), "window_minutes": 10},
                    ))
                    break  # one anomaly per actor is enough
        return anomalies

    def _unusual_volume(self, entries: List[AuditEntry], org_id: str) -> List[AuditAnomaly]:
        window = timedelta(hours=1)
        by_actor: Dict[str, List[AuditEntry]] = {}
        for e in entries:
            by_actor.setdefault(e.actor, []).append(e)

        anomalies: List[AuditAnomaly] = []
        for actor, actor_entries in by_actor.items():
            sorted_entries = sorted(actor_entries, key=lambda x: x.timestamp)
            for i, base in enumerate(sorted_entries):
                cluster = [
                    e for e in sorted_entries[i:]
                    if e.timestamp - base.timestamp <= window
                ]
                if len(cluster) > 50:
                    anomalies.append(AuditAnomaly(
                        org_id=org_id,
                        kind=AnomalyKind.UNUSUAL_VOLUME,
                        severity=AuditSeverity.WARNING,
                        actor=actor,
                        description=f"Actor '{actor}' generated {len(cluster)} events in 60 minutes",
                        entry_ids=[e.id for e in cluster[:50]],
                        details={"event_count": len(cluster), "window_hours": 1},
                    ))
                    break
        return anomalies

    def _sensitive_resource(self, entries: List[AuditEntry], org_id: str) -> List[AuditAnomaly]:
        hits: List[AuditEntry] = []
        for e in entries:
            rt_lower = e.resource_type.lower()
            if any(kw in rt_lower for kw in self._SENSITIVE_RESOURCES):
                hits.append(e)
        if not hits:
            return []
        actors = list({h.actor for h in hits if h.actor})
        return [
            AuditAnomaly(
                org_id=org_id,
                kind=AnomalyKind.SENSITIVE_RESOURCE,
                severity=AuditSeverity.WARNING,
                actor=", ".join(actors[:5]),
                description=f"{len(hits)} access event(s) on sensitive resources",
                entry_ids=[h.id for h in hits[:50]],
                details={"count": len(hits), "actors": actors},
            )
        ]


# ============================================================================
# DATABASE
# ============================================================================


class AuditAnalyticsDB:
    """Thread-safe SQLite persistence for audit analytics."""

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_schema(self) -> None:
        with self._lock, self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS audit_entries (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    timestamp      TEXT NOT NULL,
                    ingested_at    TEXT NOT NULL,
                    source_format  TEXT NOT NULL,
                    severity       TEXT NOT NULL,
                    actor          TEXT NOT NULL DEFAULT '',
                    actor_ip       TEXT NOT NULL DEFAULT '',
                    action         TEXT NOT NULL DEFAULT '',
                    resource_type  TEXT NOT NULL DEFAULT '',
                    resource_id    TEXT NOT NULL DEFAULT '',
                    outcome        TEXT NOT NULL DEFAULT 'success',
                    details        TEXT NOT NULL DEFAULT '{}',
                    raw            TEXT NOT NULL DEFAULT '',
                    status         TEXT NOT NULL DEFAULT 'active',
                    checksum       TEXT NOT NULL DEFAULT ''
                );

                CREATE TABLE IF NOT EXISTS audit_anomalies (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    kind        TEXT NOT NULL,
                    severity    TEXT NOT NULL,
                    actor       TEXT NOT NULL DEFAULT '',
                    description TEXT NOT NULL DEFAULT '',
                    entry_ids   TEXT NOT NULL DEFAULT '[]',
                    detected_at TEXT NOT NULL,
                    details     TEXT NOT NULL DEFAULT '{}'
                );

                CREATE TABLE IF NOT EXISTS retention_policies (
                    org_id               TEXT PRIMARY KEY,
                    archive_after_days   INTEGER NOT NULL DEFAULT 90,
                    delete_after_days    INTEGER NOT NULL DEFAULT 365,
                    legal_hold_actor_ids TEXT NOT NULL DEFAULT '[]'
                );

                CREATE INDEX IF NOT EXISTS idx_ae_org_ts
                    ON audit_entries(org_id, timestamp);
                CREATE INDEX IF NOT EXISTS idx_ae_actor
                    ON audit_entries(actor);
                CREATE INDEX IF NOT EXISTS idx_ae_status
                    ON audit_entries(status);
                CREATE INDEX IF NOT EXISTS idx_ae_severity
                    ON audit_entries(severity);
                CREATE INDEX IF NOT EXISTS idx_ae_action
                    ON audit_entries(action);
                CREATE INDEX IF NOT EXISTS idx_anomalies_org
                    ON audit_anomalies(org_id, detected_at);

                CREATE VIRTUAL TABLE IF NOT EXISTS audit_fts
                    USING fts5(
                        id UNINDEXED,
                        actor,
                        action,
                        resource_type,
                        resource_id,
                        raw,
                        content='audit_entries',
                        content_rowid='rowid'
                    );

                CREATE TRIGGER IF NOT EXISTS audit_entries_ai
                    AFTER INSERT ON audit_entries BEGIN
                        INSERT INTO audit_fts(rowid, id, actor, action, resource_type, resource_id, raw)
                        VALUES (new.rowid, new.id, new.actor, new.action, new.resource_type, new.resource_id, new.raw);
                    END;

                CREATE TRIGGER IF NOT EXISTS audit_entries_ad
                    AFTER DELETE ON audit_entries BEGIN
                        INSERT INTO audit_fts(audit_fts, rowid, id, actor, action, resource_type, resource_id, raw)
                        VALUES ('delete', old.rowid, old.id, old.actor, old.action, old.resource_type, old.resource_id, old.raw);
                    END;
            """)

    # ------------------------------------------------------------------
    # Entries
    # ------------------------------------------------------------------

    def insert_entry(self, entry: AuditEntry) -> AuditEntry:
        """Persist a single AuditEntry. Returns the entry with id set."""
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT OR IGNORE INTO audit_entries VALUES
                   (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    entry.id, entry.org_id,
                    entry.timestamp.isoformat(), entry.ingested_at.isoformat(),
                    entry.source_format.value, entry.severity.value,
                    entry.actor, entry.actor_ip,
                    entry.action, entry.resource_type, entry.resource_id,
                    entry.outcome, json.dumps(entry.details),
                    entry.raw, entry.status.value, entry.checksum,
                ),
            )
        _tg_emit("audit_analytics.insert_entry", {"org_id": entry.org_id, "actor": entry.actor, "action": entry.action, "severity": entry.severity.value})
        return entry

    def insert_entries_bulk(self, entries: List[AuditEntry]) -> int:
        """Bulk-insert entries. Returns count inserted."""
        rows = [
            (
                e.id, e.org_id,
                e.timestamp.isoformat(), e.ingested_at.isoformat(),
                e.source_format.value, e.severity.value,
                e.actor, e.actor_ip,
                e.action, e.resource_type, e.resource_id,
                e.outcome, json.dumps(e.details),
                e.raw, e.status.value, e.checksum,
            )
            for e in entries
        ]
        with self._lock, self._connect() as conn:
            conn.executemany(
                "INSERT OR IGNORE INTO audit_entries VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                rows,
            )
        return len(rows)

    def search(
        self,
        org_id: str,
        query: str = "",
        actor: Optional[str] = None,
        action: Optional[str] = None,
        resource_type: Optional[str] = None,
        severity: Optional[str] = None,
        outcome: Optional[str] = None,
        status: Optional[str] = None,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Tuple[List[AuditEntry], int]:
        """
        Search audit entries.

        If *query* is given, full-text search via FTS5 is applied first.
        Additional field filters narrow the result set.
        Returns (items, total_count).
        """
        with self._lock, self._connect() as conn:
            if query:
                # FTS match → get matching ids then filter
                fts_rows = conn.execute(
                    "SELECT id FROM audit_fts WHERE audit_fts MATCH ? LIMIT 10000",
                    (query,),
                ).fetchall()
                fts_ids = [r["id"] for r in fts_rows]
                if not fts_ids:
                    return [], 0
                placeholders = ",".join("?" * len(fts_ids))
                base_clause = f"id IN ({placeholders})"
                params: List[Any] = list(fts_ids)
            else:
                base_clause = "1=1"
                params = []

            # Always filter by org
            base_clause += " AND org_id = ?"
            params.append(org_id)

            if actor:
                base_clause += " AND actor LIKE ?"
                params.append(f"%{actor}%")
            if action:
                base_clause += " AND action LIKE ?"
                params.append(f"%{action}%")
            if resource_type:
                base_clause += " AND resource_type = ?"
                params.append(resource_type)
            if severity:
                base_clause += " AND severity = ?"
                params.append(severity)
            if outcome:
                base_clause += " AND outcome = ?"
                params.append(outcome)
            if status:
                base_clause += " AND status = ?"
                params.append(status)
            if start:
                base_clause += " AND timestamp >= ?"
                params.append(start.isoformat())
            if end:
                base_clause += " AND timestamp <= ?"
                params.append(end.isoformat())

            count_row = conn.execute(
                f"SELECT COUNT(*) AS cnt FROM audit_entries WHERE {base_clause}",  # nosec B608
                params,
            ).fetchone()
            total = count_row["cnt"] if count_row else 0

            rows = conn.execute(
                f"SELECT * FROM audit_entries WHERE {base_clause} "  # nosec B608
                f"ORDER BY timestamp DESC LIMIT ? OFFSET ?",
                params + [limit, offset],
            ).fetchall()

        return [self._row_to_entry(r) for r in rows], total

    def get_entry(self, entry_id: str, org_id: str) -> Optional[AuditEntry]:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM audit_entries WHERE id = ? AND org_id = ?",
                (entry_id, org_id),
            ).fetchone()
        return self._row_to_entry(row) if row else None

    def update_status(self, entry_id: str, status: EntryStatus) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "UPDATE audit_entries SET status = ? WHERE id = ?",
                (status.value, entry_id),
            )
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Anomalies
    # ------------------------------------------------------------------

    def insert_anomalies(self, anomalies: List[AuditAnomaly]) -> int:
        rows = [
            (
                a.id, a.org_id, a.kind.value, a.severity.value,
                a.actor, a.description,
                json.dumps(a.entry_ids), a.detected_at.isoformat(),
                json.dumps(a.details),
            )
            for a in anomalies
        ]
        with self._lock, self._connect() as conn:
            conn.executemany(
                "INSERT OR IGNORE INTO audit_anomalies VALUES (?,?,?,?,?,?,?,?,?)",
                rows,
            )
        return len(rows)

    def list_anomalies(
        self,
        org_id: str,
        kind: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> Tuple[List[AuditAnomaly], int]:
        with self._lock, self._connect() as conn:
            clause = "org_id = ?"
            params: List[Any] = [org_id]
            if kind:
                clause += " AND kind = ?"
                params.append(kind)
            if severity:
                clause += " AND severity = ?"
                params.append(severity)
            total = conn.execute(
                f"SELECT COUNT(*) AS cnt FROM audit_anomalies WHERE {clause}", params  # nosec B608
            ).fetchone()["cnt"]
            rows = conn.execute(
                f"SELECT * FROM audit_anomalies WHERE {clause} "  # nosec B608
                f"ORDER BY detected_at DESC LIMIT ? OFFSET ?",
                params + [limit, offset],
            ).fetchall()
        return [self._row_to_anomaly(r) for r in rows], total

    # ------------------------------------------------------------------
    # Retention
    # ------------------------------------------------------------------

    def upsert_retention_policy(self, policy: RetentionPolicy) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO retention_policies VALUES (?,?,?,?)
                   ON CONFLICT(org_id) DO UPDATE SET
                     archive_after_days=excluded.archive_after_days,
                     delete_after_days=excluded.delete_after_days,
                     legal_hold_actor_ids=excluded.legal_hold_actor_ids""",
                (
                    policy.org_id,
                    policy.archive_after_days,
                    policy.delete_after_days,
                    json.dumps(policy.legal_hold_actor_ids),
                ),
            )

    def get_retention_policy(self, org_id: str) -> RetentionPolicy:
        with self._lock, self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM retention_policies WHERE org_id = ?", (org_id,)
            ).fetchone()
        if row:
            return RetentionPolicy(
                org_id=row["org_id"],
                archive_after_days=row["archive_after_days"],
                delete_after_days=row["delete_after_days"],
                legal_hold_actor_ids=json.loads(row["legal_hold_actor_ids"]),
            )
        return RetentionPolicy(org_id=org_id)

    def apply_retention(self, org_id: str) -> RetentionReport:
        """
        Apply retention policy for *org_id*.

        - Entries older than delete_after_days → deleted (unless legal hold)
        - Entries older than archive_after_days → archived (unless legal hold)
        - Entries whose actor is in legal_hold_actor_ids → status=legal_hold
        """
        policy = self.get_retention_policy(org_id)
        now = datetime.now(timezone.utc)
        archive_cutoff = (now - timedelta(days=policy.archive_after_days)).isoformat()
        delete_cutoff = (now - timedelta(days=policy.delete_after_days)).isoformat()
        held_actors = policy.legal_hold_actor_ids
        report = RetentionReport(org_id=org_id)

        with self._lock, self._connect() as conn:
            # Mark legal hold first so subsequent queries respect it
            if held_actors:
                placeholders = ",".join("?" * len(held_actors))
                cur = conn.execute(
                    f"UPDATE audit_entries SET status='legal_hold' "  # nosec B608
                    f"WHERE org_id=? AND actor IN ({placeholders}) AND status='active'",
                    [org_id] + held_actors,
                )
                report.held = cur.rowcount

            # Delete entries past delete threshold (not on hold)
            cur = conn.execute(
                "DELETE FROM audit_entries WHERE org_id=? AND timestamp < ? "
                "AND status NOT IN ('legal_hold','deleted')",
                (org_id, delete_cutoff),
            )
            report.deleted = cur.rowcount

            # Archive entries past archive threshold (not on hold, not deleted)
            cur = conn.execute(
                "UPDATE audit_entries SET status='archived' "
                "WHERE org_id=? AND timestamp < ? AND status='active'",
                (org_id, archive_cutoff),
            )
            report.archived = cur.rowcount

        return report

    # ------------------------------------------------------------------
    # Forensic timeline
    # ------------------------------------------------------------------

    def build_timeline(
        self,
        org_id: str,
        query: str,
        start: datetime,
        end: datetime,
        limit: int = 500,
    ) -> ForensicTimeline:
        """Build a chronological forensic timeline for *query* within [start, end]."""
        entries, total = self.search(
            org_id=org_id,
            query=query,
            start=start,
            end=end,
            limit=limit,
            offset=0,
        )
        # Sort ascending for timeline
        entries_sorted = sorted(entries, key=lambda e: e.timestamp)
        events = [
            TimelineEvent(
                timestamp=e.timestamp,
                actor=e.actor,
                action=e.action,
                resource_type=e.resource_type,
                resource_id=e.resource_id,
                outcome=e.outcome,
                severity=e.severity,
                entry_id=e.id,
                details=e.details,
            )
            for e in entries_sorted
        ]
        actors = list({e.actor for e in entries_sorted if e.actor})
        resources = list({e.resource_type for e in entries_sorted if e.resource_type})
        return ForensicTimeline(
            query=query,
            start=start,
            end=end,
            events=events,
            total=total,
            actors=actors,
            resources=resources,
        )

    # ------------------------------------------------------------------
    # Converters
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_entry(row: sqlite3.Row) -> AuditEntry:
        return AuditEntry(
            id=row["id"],
            org_id=row["org_id"],
            timestamp=datetime.fromisoformat(row["timestamp"]),
            ingested_at=datetime.fromisoformat(row["ingested_at"]),
            source_format=LogFormat(row["source_format"]),
            severity=AuditSeverity(row["severity"]),
            actor=row["actor"],
            actor_ip=row["actor_ip"],
            action=row["action"],
            resource_type=row["resource_type"],
            resource_id=row["resource_id"],
            outcome=row["outcome"],
            details=json.loads(row["details"]) if row["details"] else {},
            raw=row["raw"],
            status=EntryStatus(row["status"]),
            checksum=row["checksum"],
        )

    @staticmethod
    def _row_to_anomaly(row: sqlite3.Row) -> AuditAnomaly:
        return AuditAnomaly(
            id=row["id"],
            org_id=row["org_id"],
            kind=AnomalyKind(row["kind"]),
            severity=AuditSeverity(row["severity"]),
            actor=row["actor"],
            description=row["description"],
            entry_ids=json.loads(row["entry_ids"]),
            detected_at=datetime.fromisoformat(row["detected_at"]),
            details=json.loads(row["details"]),
        )


# ============================================================================
# HIGH-LEVEL ENGINE (facade)
# ============================================================================


class AuditAnalyticsEngine:
    """
    High-level facade for the Audit Log Analytics system.

    Orchestrates parsing, persistence, anomaly detection, retention,
    and forensic timeline construction.
    """

    def __init__(self, db_path: str = _DEFAULT_DB, org_id: str = "default") -> None:
        self.org_id = org_id
        self._db = AuditAnalyticsDB(db_path=db_path)
        self._parser = LogParser()
        self._detector = AuditAnomalyDetector()

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------

    def ingest(self, raw: str, fmt: LogFormat, org_id: Optional[str] = None) -> AuditEntry:
        """Parse *raw* log line and persist it. Returns the stored entry."""
        oid = org_id or self.org_id
        entry = self._parser.parse(raw, fmt, org_id=oid)
        self._db.insert_entry(entry)
        _logger.debug("Ingested audit entry %s (format=%s)", entry.id, fmt.value)
        return entry

    def ingest_batch(
        self,
        lines: List[str],
        fmt: LogFormat,
        org_id: Optional[str] = None,
        run_anomaly_detection: bool = True,
    ) -> Tuple[List[AuditEntry], List[AuditAnomaly]]:
        """
        Parse and persist a batch of log lines.

        Optionally runs anomaly detection over the batch.
        Returns (entries, anomalies).
        """
        oid = org_id or self.org_id
        entries = [self._parser.parse(line, fmt, org_id=oid) for line in lines if line.strip()]
        self._db.insert_entries_bulk(entries)

        anomalies: List[AuditAnomaly] = []
        if run_anomaly_detection and entries:
            anomalies = self._detector.detect(entries, org_id=oid)
            if anomalies:
                self._db.insert_anomalies(anomalies)
                _logger.info("Detected %d anomalies from batch of %d", len(anomalies), len(entries))

        return entries, anomalies

    # ------------------------------------------------------------------
    # Search
    # ------------------------------------------------------------------

    def search(
        self,
        query: str = "",
        actor: Optional[str] = None,
        action: Optional[str] = None,
        resource_type: Optional[str] = None,
        severity: Optional[str] = None,
        outcome: Optional[str] = None,
        status: Optional[str] = None,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
        org_id: Optional[str] = None,
    ) -> SearchResult:
        oid = org_id or self.org_id
        items, total = self._db.search(
            org_id=oid, query=query, actor=actor, action=action,
            resource_type=resource_type, severity=severity,
            outcome=outcome, status=status, start=start, end=end,
            limit=limit, offset=offset,
        )
        return SearchResult(items=items, total=total, limit=limit, offset=offset, query=query)

    # ------------------------------------------------------------------
    # Anomaly detection (on-demand)
    # ------------------------------------------------------------------

    def detect_anomalies(
        self,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        org_id: Optional[str] = None,
    ) -> List[AuditAnomaly]:
        """Run anomaly detection over stored entries in the given time window."""
        oid = org_id or self.org_id
        entries, _ = self._db.search(
            org_id=oid, start=start, end=end, limit=10000, offset=0,
        )
        anomalies = self._detector.detect(entries, org_id=oid)
        if anomalies:
            self._db.insert_anomalies(anomalies)
        return anomalies

    def list_anomalies(
        self,
        kind: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
        org_id: Optional[str] = None,
    ) -> Tuple[List[AuditAnomaly], int]:
        oid = org_id or self.org_id
        return self._db.list_anomalies(oid, kind=kind, severity=severity, limit=limit, offset=offset)

    # ------------------------------------------------------------------
    # Compliance trail
    # ------------------------------------------------------------------

    def compliance_trail(
        self,
        actor: Optional[str] = None,
        resource_type: Optional[str] = None,
        start: Optional[datetime] = None,
        end: Optional[datetime] = None,
        limit: int = 1000,
        org_id: Optional[str] = None,
    ) -> SearchResult:
        """
        Return ordered compliance audit trail.

        Filters by actor and/or resource_type, sorted newest-first.
        Suitable for SOC2/HIPAA "who did what when" reporting.
        """
        return self.search(
            actor=actor,
            resource_type=resource_type,
            start=start,
            end=end,
            limit=limit,
            org_id=org_id,
        )

    # ------------------------------------------------------------------
    # Retention
    # ------------------------------------------------------------------

    def set_retention_policy(self, policy: RetentionPolicy) -> None:
        self._db.upsert_retention_policy(policy)

    def get_retention_policy(self, org_id: Optional[str] = None) -> RetentionPolicy:
        return self._db.get_retention_policy(org_id or self.org_id)

    def apply_retention(self, org_id: Optional[str] = None) -> RetentionReport:
        return self._db.apply_retention(org_id or self.org_id)

    # ------------------------------------------------------------------
    # Forensic timeline
    # ------------------------------------------------------------------

    def build_timeline(
        self,
        query: str,
        start: datetime,
        end: datetime,
        limit: int = 500,
        org_id: Optional[str] = None,
    ) -> ForensicTimeline:
        return self._db.build_timeline(
            org_id=org_id or self.org_id,
            query=query,
            start=start,
            end=end,
            limit=limit,
        )
