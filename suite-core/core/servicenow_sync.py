"""ServiceNow Bidirectional Sync Engine for ALDECI/FixOps.

Synchronises security findings with ServiceNow incidents in both directions:
  - Finding → ServiceNow: create or update an incident from a finding
  - ServiceNow → Finding: update finding status when the linked incident changes
  - Status sync: propagate status transitions in both directions
  - Conflict resolution: last-write-wins with configurable override policy
  - Sync history: SQLite-backed audit trail of every sync event

Supported ServiceNow versions:
  - ServiceNow REST API v1 (Table API: /api/now/table/)
  - Works with Tokyo, Utah, Vancouver, Washington DC releases

Typical usage
-------------
    engine = ServiceNowSyncEngine(db_path="servicenow_sync.db")
    engine.configure(ServiceNowSyncConfig(
        instance_url="https://mycompany.service-now.com",
        username="sync_user",
        password="...",
        assignment_group="Security Operations",
    ))
    result = engine.sync_finding(finding_id="F-001", finding_data={...})
"""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from threading import Lock
from typing import Any, Dict, Generator, List, Optional
from urllib.parse import urljoin

import requests
from requests import RequestException
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

logger = logging.getLogger(__name__)

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:
    _get_tg_bus = None  # type: ignore


def _tg_emit(event_type: str, payload: dict) -> None:
    try:
        if _get_tg_bus is None:
            return
        bus = _get_tg_bus()
        if bus:
            bus.emit(event_type, payload)
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_DB = "servicenow_sync.db"
_TABLE_API = "api/now/table"
_INCIDENT_TABLE = "incident"

# ServiceNow incident state → ALDECI finding status mapping (default)
# ServiceNow state codes: 1=New, 2=In Progress, 3=On Hold, 6=Resolved, 7=Closed
_DEFAULT_SN_STATE_TO_FINDING_STATUS: Dict[str, str] = {
    "1": "open",
    "New": "open",
    "2": "in_progress",
    "In Progress": "in_progress",
    "3": "on_hold",
    "On Hold": "on_hold",
    "6": "resolved",
    "Resolved": "resolved",
    "7": "closed",
    "Closed": "closed",
    "8": "wont_fix",
    "Canceled": "wont_fix",
}

# ALDECI finding severity → ServiceNow urgency mapping (1=High, 2=Medium, 3=Low)
_DEFAULT_SEVERITY_TO_URGENCY: Dict[str, str] = {
    "critical": "1",
    "high": "1",
    "medium": "2",
    "low": "3",
    "info": "3",
    "informational": "3",
}

# ALDECI finding severity → ServiceNow impact mapping (1=High, 2=Medium, 3=Low)
_DEFAULT_SEVERITY_TO_IMPACT: Dict[str, str] = {
    "critical": "1",
    "high": "1",
    "medium": "2",
    "low": "3",
    "info": "3",
    "informational": "3",
}

# ALDECI finding status → ServiceNow incident state code mapping
_DEFAULT_FINDING_TO_SN_STATE: Dict[str, str] = {
    "open": "1",
    "in_progress": "2",
    "on_hold": "3",
    "resolved": "6",
    "closed": "7",
    "wont_fix": "8",
    "duplicate": "7",
    "in_review": "2",
}


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class SyncDirection(str, Enum):
    FINDING_TO_SN = "finding_to_servicenow"
    SN_TO_FINDING = "servicenow_to_finding"
    BIDIRECTIONAL = "bidirectional"


class SyncStatus(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    CONFLICT = "conflict"


class ConflictResolution(str, Enum):
    """Policy when both sides have changed since last sync."""
    SN_WINS = "servicenow_wins"
    FINDING_WINS = "finding_wins"
    NEWEST_WINS = "newest_wins"
    MANUAL = "manual"


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class FieldMapping:
    """Single field mapping between finding and ServiceNow incident."""
    finding_field: str
    sn_field: str
    transform: Optional[str] = None  # "severity_to_urgency" | "severity_to_impact" | "status_to_state"


@dataclass
class ServiceNowSyncConfig:
    """Full configuration for the ServiceNow sync engine."""
    instance_url: str = ""
    username: str = ""
    password: str = ""
    assignment_group: str = ""
    category: str = "Security"
    subcategory: str = "Vulnerability"
    sync_direction: SyncDirection = SyncDirection.BIDIRECTIONAL
    conflict_resolution: ConflictResolution = ConflictResolution.NEWEST_WINS
    field_mappings: List[FieldMapping] = field(default_factory=list)
    # Status/field maps
    sn_state_to_finding_status: Dict[str, str] = field(
        default_factory=lambda: dict(_DEFAULT_SN_STATE_TO_FINDING_STATUS)
    )
    finding_to_sn_state: Dict[str, str] = field(
        default_factory=lambda: dict(_DEFAULT_FINDING_TO_SN_STATE)
    )
    severity_to_urgency: Dict[str, str] = field(
        default_factory=lambda: dict(_DEFAULT_SEVERITY_TO_URGENCY)
    )
    severity_to_impact: Dict[str, str] = field(
        default_factory=lambda: dict(_DEFAULT_SEVERITY_TO_IMPACT)
    )
    # Optional tags/labels applied to every incident
    tags: List[str] = field(default_factory=lambda: ["aldeci", "security"])
    # Webhook secret for incoming ServiceNow webhooks
    webhook_secret: Optional[str] = None

    @property
    def configured(self) -> bool:
        return bool(self.instance_url and self.username and self.password)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "instance_url": self.instance_url,
            "username": self.username,
            "password": "***" if self.password else "",
            "assignment_group": self.assignment_group,
            "category": self.category,
            "subcategory": self.subcategory,
            "sync_direction": self.sync_direction.value,
            "conflict_resolution": self.conflict_resolution.value,
            "field_mappings": [
                {"finding_field": fm.finding_field, "sn_field": fm.sn_field}
                for fm in self.field_mappings
            ],
            "tags": self.tags,
            "configured": self.configured,
        }


# ---------------------------------------------------------------------------
# Sync history record
# ---------------------------------------------------------------------------


@dataclass
class SyncRecord:
    """One entry in the sync history audit trail."""
    record_id: str
    finding_id: str
    sn_incident_number: Optional[str]
    sn_sys_id: Optional[str]
    direction: SyncDirection
    status: SyncStatus
    detail: Dict[str, Any]
    synced_at: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_id": self.record_id,
            "finding_id": self.finding_id,
            "sn_incident_number": self.sn_incident_number,
            "sn_sys_id": self.sn_sys_id,
            "direction": self.direction.value,
            "status": self.status.value,
            "detail": self.detail,
            "synced_at": self.synced_at,
        }


# ---------------------------------------------------------------------------
# SQLite store
# ---------------------------------------------------------------------------


class ServiceNowSyncStore:
    """SQLite-backed store for sync state and history.

    Tables
    ------
    sync_links      — maps finding_id ↔ sn_sys_id + incident_number with timestamps
    sync_history    — append-only audit log of every sync event
    config          — serialised ServiceNowSyncConfig
    """

    _DDL = """
    CREATE TABLE IF NOT EXISTS sync_links (
        finding_id              TEXT PRIMARY KEY,
        sn_sys_id               TEXT NOT NULL,
        sn_incident_number      TEXT NOT NULL,
        created_at              TEXT NOT NULL,
        updated_at              TEXT NOT NULL,
        last_finding_updated_at TEXT,
        last_sn_updated_at      TEXT
    );

    CREATE TABLE IF NOT EXISTS sync_history (
        record_id           TEXT PRIMARY KEY,
        finding_id          TEXT NOT NULL,
        sn_incident_number  TEXT,
        sn_sys_id           TEXT,
        direction           TEXT NOT NULL,
        status              TEXT NOT NULL,
        detail              TEXT NOT NULL,
        synced_at           TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_sn_history_finding
        ON sync_history (finding_id);

    CREATE INDEX IF NOT EXISTS idx_sn_history_synced_at
        ON sync_history (synced_at);

    CREATE INDEX IF NOT EXISTS idx_sn_links_sys_id
        ON sync_links (sn_sys_id);

    CREATE TABLE IF NOT EXISTS config (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = Lock()
        self._init_db()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(self._DDL)

    @contextmanager
    def _connect(self) -> Generator[sqlite3.Connection, None, None]:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # -- links --

    def get_link(self, finding_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM sync_links WHERE finding_id = ?", (finding_id,)
            ).fetchone()
        return dict(row) if row else None

    def get_link_by_sys_id(self, sn_sys_id: str) -> Optional[Dict[str, Any]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM sync_links WHERE sn_sys_id = ?", (sn_sys_id,)
            ).fetchone()
        return dict(row) if row else None

    def upsert_link(
        self,
        finding_id: str,
        sn_sys_id: str,
        sn_incident_number: str,
        finding_updated_at: Optional[str] = None,
        sn_updated_at: Optional[str] = None,
    ) -> None:
        now = _now_iso()
        with self._lock, self._connect() as conn:
            existing = conn.execute(
                "SELECT created_at FROM sync_links WHERE finding_id = ?",
                (finding_id,),
            ).fetchone()
            if existing:
                conn.execute(
                    """UPDATE sync_links
                       SET sn_sys_id = ?, sn_incident_number = ?, updated_at = ?,
                           last_finding_updated_at = COALESCE(?, last_finding_updated_at),
                           last_sn_updated_at      = COALESCE(?, last_sn_updated_at)
                       WHERE finding_id = ?""",
                    (
                        sn_sys_id,
                        sn_incident_number,
                        now,
                        finding_updated_at,
                        sn_updated_at,
                        finding_id,
                    ),
                )
            else:
                conn.execute(
                    """INSERT INTO sync_links
                       (finding_id, sn_sys_id, sn_incident_number, created_at, updated_at,
                        last_finding_updated_at, last_sn_updated_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (
                        finding_id,
                        sn_sys_id,
                        sn_incident_number,
                        now,
                        now,
                        finding_updated_at,
                        sn_updated_at,
                    ),
                )

    def delete_link(self, finding_id: str) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM sync_links WHERE finding_id = ?", (finding_id,)
            )
            return cur.rowcount > 0

    def list_links(self) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM sync_links ORDER BY updated_at DESC"
            ).fetchall()
        return [dict(r) for r in rows]

    # -- history --

    def append_history(self, record: SyncRecord) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO sync_history
                   (record_id, finding_id, sn_incident_number, sn_sys_id,
                    direction, status, detail, synced_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    record.record_id,
                    record.finding_id,
                    record.sn_incident_number,
                    record.sn_sys_id,
                    record.direction.value,
                    record.status.value,
                    json.dumps(record.detail),
                    record.synced_at,
                ),
            )

    def get_history(
        self,
        finding_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        with self._connect() as conn:
            if finding_id:
                rows = conn.execute(
                    """SELECT * FROM sync_history WHERE finding_id = ?
                       ORDER BY synced_at DESC LIMIT ? OFFSET ?""",
                    (finding_id, limit, offset),
                ).fetchall()
            else:
                rows = conn.execute(
                    """SELECT * FROM sync_history
                       ORDER BY synced_at DESC LIMIT ? OFFSET ?""",
                    (limit, offset),
                ).fetchall()
        result = []
        for r in rows:
            d = dict(r)
            d["detail"] = json.loads(d["detail"])
            result.append(d)
        return result

    def get_stats(self) -> Dict[str, Any]:
        with self._connect() as conn:
            total_links = conn.execute("SELECT COUNT(*) FROM sync_links").fetchone()[0]
            total_history = conn.execute("SELECT COUNT(*) FROM sync_history").fetchone()[0]
            by_status = conn.execute(
                "SELECT status, COUNT(*) as cnt FROM sync_history GROUP BY status"
            ).fetchall()
            by_direction = conn.execute(
                "SELECT direction, COUNT(*) as cnt FROM sync_history GROUP BY direction"
            ).fetchall()
        return {
            "total_links": total_links,
            "total_sync_events": total_history,
            "by_status": {r["status"]: r["cnt"] for r in by_status},
            "by_direction": {r["direction"]: r["cnt"] for r in by_direction},
        }

    # -- config --

    def save_config(self, config: ServiceNowSyncConfig) -> None:
        data = json.dumps(
            {
                "instance_url": config.instance_url,
                "username": config.username,
                "password": config.password,
                "assignment_group": config.assignment_group,
                "category": config.category,
                "subcategory": config.subcategory,
                "sync_direction": config.sync_direction.value,
                "conflict_resolution": config.conflict_resolution.value,
                "tags": config.tags,
                "webhook_secret": config.webhook_secret,
                "sn_state_to_finding_status": config.sn_state_to_finding_status,
                "finding_to_sn_state": config.finding_to_sn_state,
                "severity_to_urgency": config.severity_to_urgency,
                "severity_to_impact": config.severity_to_impact,
                "field_mappings": [
                    {
                        "finding_field": fm.finding_field,
                        "sn_field": fm.sn_field,
                        "transform": fm.transform,
                    }
                    for fm in config.field_mappings
                ],
            }
        )
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO config (key, value) VALUES ('main', ?)", (data,)
            )

    def load_config(self) -> Optional[ServiceNowSyncConfig]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT value FROM config WHERE key = 'main'"
            ).fetchone()
        if not row:
            return None
        data = json.loads(row[0])
        cfg = ServiceNowSyncConfig(
            instance_url=data.get("instance_url", ""),
            username=data.get("username", ""),
            password=data.get("password", ""),
            assignment_group=data.get("assignment_group", ""),
            category=data.get("category", "Security"),
            subcategory=data.get("subcategory", "Vulnerability"),
            sync_direction=SyncDirection(
                data.get("sync_direction", SyncDirection.BIDIRECTIONAL.value)
            ),
            conflict_resolution=ConflictResolution(
                data.get("conflict_resolution", ConflictResolution.NEWEST_WINS.value)
            ),
            tags=data.get("tags", ["aldeci", "security"]),
            webhook_secret=data.get("webhook_secret"),
            sn_state_to_finding_status=data.get(
                "sn_state_to_finding_status", dict(_DEFAULT_SN_STATE_TO_FINDING_STATUS)
            ),
            finding_to_sn_state=data.get(
                "finding_to_sn_state", dict(_DEFAULT_FINDING_TO_SN_STATE)
            ),
            severity_to_urgency=data.get(
                "severity_to_urgency", dict(_DEFAULT_SEVERITY_TO_URGENCY)
            ),
            severity_to_impact=data.get(
                "severity_to_impact", dict(_DEFAULT_SEVERITY_TO_IMPACT)
            ),
            field_mappings=[
                FieldMapping(
                    finding_field=m["finding_field"],
                    sn_field=m["sn_field"],
                    transform=m.get("transform"),
                )
                for m in data.get("field_mappings", [])
            ],
        )
        return cfg


# ---------------------------------------------------------------------------
# ServiceNow HTTP client (Table API)
# ---------------------------------------------------------------------------


class _ServiceNowClient:
    """Minimal ServiceNow Table API REST client."""

    def __init__(self, config: ServiceNowSyncConfig, timeout: float = 15.0) -> None:
        self._cfg = config
        self._timeout = timeout
        self._session = requests.Session()
        retry = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=5, pool_maxsize=10)
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)

    def _url(self, table: str, sys_id: Optional[str] = None) -> str:
        base = self._cfg.instance_url.rstrip("/") + "/"
        path = f"{_TABLE_API}/{table}"
        if sys_id:
            path = f"{path}/{sys_id}"
        return urljoin(base, path)

    def _auth(self):  # type: ignore[return]
        return (self._cfg.username, self._cfg.password)

    def _headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        h = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if extra:
            h.update(extra)
        return h

    def create_incident(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        resp = self._session.post(
            self._url(_INCIDENT_TABLE),
            json=payload,
            auth=self._auth(),
            headers=self._headers(),
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json().get("result", {})

    def get_incident(self, sys_id: str) -> Dict[str, Any]:
        resp = self._session.get(
            self._url(_INCIDENT_TABLE, sys_id),
            auth=self._auth(),
            headers=self._headers(),
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json().get("result", {})

    def update_incident(self, sys_id: str, fields: Dict[str, Any]) -> Dict[str, Any]:
        resp = self._session.patch(
            self._url(_INCIDENT_TABLE, sys_id),
            json=fields,
            auth=self._auth(),
            headers=self._headers(),
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json().get("result", {})

    def query_incidents(
        self, sysparm_query: str, limit: int = 50
    ) -> List[Dict[str, Any]]:
        resp = self._session.get(
            self._url(_INCIDENT_TABLE),
            params={
                "sysparm_query": sysparm_query,
                "sysparm_limit": limit,
                "sysparm_fields": "sys_id,number,state,urgency,impact,short_description,sys_updated_on",
            },
            auth=self._auth(),
            headers=self._headers(),
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json().get("result", [])

    def add_work_note(self, sys_id: str, note: str) -> Dict[str, Any]:
        resp = self._session.patch(
            self._url(_INCIDENT_TABLE, sys_id),
            json={"work_notes": note},
            auth=self._auth(),
            headers=self._headers(),
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json().get("result", {})


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Sync result
# ---------------------------------------------------------------------------


@dataclass
class SyncResult:
    """Result from a single sync operation."""
    finding_id: str
    sn_incident_number: Optional[str]
    sn_sys_id: Optional[str]
    status: SyncStatus
    direction: SyncDirection
    detail: Dict[str, Any]
    synced_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "sn_incident_number": self.sn_incident_number,
            "sn_sys_id": self.sn_sys_id,
            "status": self.status.value,
            "direction": self.direction.value,
            "detail": self.detail,
            "synced_at": self.synced_at,
        }


# ---------------------------------------------------------------------------
# Core engine
# ---------------------------------------------------------------------------


class ServiceNowSyncEngine:
    """Bidirectional sync engine between ALDECI findings and ServiceNow incidents.

    Usage
    -----
        engine = ServiceNowSyncEngine()
        engine.configure(ServiceNowSyncConfig(
            instance_url="https://mycompany.service-now.com",
            username="sync_user",
            password="...",
        ))
        result = engine.sync_finding("F-001", {"title": "...", "severity": "high"})
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._store = ServiceNowSyncStore(db_path=db_path)
        self._config: Optional[ServiceNowSyncConfig] = self._store.load_config()
        self._client: Optional[_ServiceNowClient] = None
        if self._config and self._config.configured:
            self._client = _ServiceNowClient(self._config)

    # -- configuration --

    def configure(self, config: ServiceNowSyncConfig) -> None:
        """Set (and persist) the sync configuration."""
        self._config = config
        self._store.save_config(config)
        self._client = _ServiceNowClient(config) if config.configured else None
        logger.info(
            "ServiceNowSyncEngine configured (instance=%s)", config.instance_url
        )

    def get_config(self) -> Optional[ServiceNowSyncConfig]:
        return self._config

    # -- field mapping helpers --

    def _build_sn_fields(self, finding_data: Dict[str, Any]) -> Dict[str, Any]:
        """Map finding fields to ServiceNow incident fields."""
        cfg = self._config
        assert cfg is not None

        severity = str(finding_data.get("severity", "medium")).lower()
        urgency = cfg.severity_to_urgency.get(severity, "2")
        impact = cfg.severity_to_impact.get(severity, "2")

        short_description = (
            finding_data.get("title")
            or finding_data.get("summary")
            or f"Security Finding {finding_data.get('finding_id', '')}"
        )
        description = self._build_description(finding_data)

        fields: Dict[str, Any] = {
            "short_description": str(short_description)[:160],
            "description": description,
            "urgency": urgency,
            "impact": impact,
            "category": cfg.category,
            "subcategory": cfg.subcategory,
        }

        if cfg.assignment_group:
            fields["assignment_group"] = cfg.assignment_group

        # Apply custom field mappings
        for fm in cfg.field_mappings:
            val = finding_data.get(fm.finding_field)
            if val is not None:
                if fm.transform == "severity_to_urgency":
                    fields[fm.sn_field] = cfg.severity_to_urgency.get(
                        str(val).lower(), val
                    )
                elif fm.transform == "severity_to_impact":
                    fields[fm.sn_field] = cfg.severity_to_impact.get(
                        str(val).lower(), val
                    )
                else:
                    fields[fm.sn_field] = val

        return fields

    def _build_description(self, finding_data: Dict[str, Any]) -> str:
        lines = [
            f"Finding ID: {finding_data.get('finding_id', 'N/A')}",
            f"Severity: {finding_data.get('severity', 'N/A')}",
            f"Source: {finding_data.get('source', 'N/A')}",
            f"CVE: {finding_data.get('cve_id', 'N/A')}",
            "",
            "Description:",
            finding_data.get("description")
            or finding_data.get("detail")
            or "No description provided.",
            "",
            "Synced automatically by ALDECI/FixOps",
        ]
        return "\n".join(lines)

    # -- sync operations --

    def sync_finding(
        self,
        finding_id: str,
        finding_data: Dict[str, Any],
    ) -> SyncResult:
        """Create or update a ServiceNow incident from a finding (finding → SN)."""
        if not self._config or not self._config.configured:
            return self._skip(finding_id, SyncDirection.FINDING_TO_SN, "not configured")

        if self._config.sync_direction == SyncDirection.SN_TO_FINDING:
            return self._skip(
                finding_id,
                SyncDirection.FINDING_TO_SN,
                "direction is servicenow_to_finding only",
            )

        client = self._client
        assert client is not None

        link = self._store.get_link(finding_id)
        finding_updated_at = finding_data.get("updated_at") or _now_iso()

        try:
            if link:
                sys_id = link["sn_sys_id"]
                incident_number = link["sn_incident_number"]

                # Conflict resolution check
                if self._config.conflict_resolution == ConflictResolution.SN_WINS:
                    return self._record_and_return(
                        finding_id,
                        incident_number,
                        sys_id,
                        SyncDirection.FINDING_TO_SN,
                        SyncStatus.SKIPPED,
                        {
                            "reason": "conflict_resolution=servicenow_wins, skipping finding→sn push"
                        },
                    )

                # Update existing incident
                fields = self._build_sn_fields(finding_data)
                client.update_incident(sys_id, fields)
                self._store.upsert_link(
                    finding_id,
                    sys_id,
                    incident_number,
                    finding_updated_at=finding_updated_at,
                )
                return self._record_and_return(
                    finding_id,
                    incident_number,
                    sys_id,
                    SyncDirection.FINDING_TO_SN,
                    SyncStatus.SUCCESS,
                    {"operation": "updated", "sys_id": sys_id, "incident_number": incident_number},
                )
            else:
                # Create new incident
                fields = self._build_sn_fields(finding_data)
                result = client.create_incident(fields)
                sys_id = result.get("sys_id", "")
                incident_number = result.get("number", "")
                self._store.upsert_link(
                    finding_id,
                    sys_id,
                    incident_number,
                    finding_updated_at=finding_updated_at,
                )
                return self._record_and_return(
                    finding_id,
                    incident_number,
                    sys_id,
                    SyncDirection.FINDING_TO_SN,
                    SyncStatus.SUCCESS,
                    {"operation": "created", "sys_id": sys_id, "incident_number": incident_number},
                )
        except RequestException as exc:
            logger.error(
                "sync_finding failed for %s: %s", finding_id, type(exc).__name__
            )
            return self._record_and_return(
                finding_id,
                None,
                None,
                SyncDirection.FINDING_TO_SN,
                SyncStatus.FAILED,
                {"error": type(exc).__name__, "finding_id": finding_id},
            )

    def sync_from_servicenow(
        self,
        sn_sys_id: str,
        sn_data: Optional[Dict[str, Any]] = None,
    ) -> SyncResult:
        """Update ALDECI finding status from a ServiceNow incident (SN → finding).

        Returns the translated finding status in detail["new_finding_status"].
        Callers are responsible for applying the status to the finding store.
        """
        if not self._config or not self._config.configured:
            return self._skip(sn_sys_id, SyncDirection.SN_TO_FINDING, "not configured")

        if self._config.sync_direction == SyncDirection.FINDING_TO_SN:
            return self._skip(
                sn_sys_id,
                SyncDirection.SN_TO_FINDING,
                "direction is finding_to_servicenow only",
            )

        client = self._client
        assert client is not None

        try:
            if sn_data is None:
                sn_data = client.get_incident(sn_sys_id)

            # State can be a dict with "value" key (display value) or a plain string
            state_raw = sn_data.get("state", "")
            if isinstance(state_raw, dict):
                state_val = str(state_raw.get("value", ""))
                state_display = str(state_raw.get("display_value", ""))
            else:
                state_val = str(state_raw)
                state_display = state_val

            new_finding_status = (
                self._config.sn_state_to_finding_status.get(state_val)
                or self._config.sn_state_to_finding_status.get(state_display)
                or "unknown"
            )
            sn_updated = sn_data.get("sys_updated_on") or _now_iso()
            incident_number = sn_data.get("number", "")

            # Find linked finding
            link = self._store.get_link_by_sys_id(sn_sys_id)
            finding_id = link["finding_id"] if link else sn_sys_id

            self._store.upsert_link(
                finding_id,
                sn_sys_id,
                incident_number,
                sn_updated_at=str(sn_updated),
            )
            return self._record_and_return(
                finding_id,
                incident_number,
                sn_sys_id,
                SyncDirection.SN_TO_FINDING,
                SyncStatus.SUCCESS,
                {
                    "sn_state": state_val,
                    "new_finding_status": new_finding_status,
                    "sn_updated": str(sn_updated),
                },
            )
        except RequestException as exc:
            logger.error(
                "sync_from_servicenow failed for %s: %s", sn_sys_id, type(exc).__name__
            )
            return self._record_and_return(
                sn_sys_id,
                None,
                sn_sys_id,
                SyncDirection.SN_TO_FINDING,
                SyncStatus.FAILED,
                {"error": type(exc).__name__},
            )

    def sync_status(
        self,
        finding_id: str,
        new_status: str,
    ) -> SyncResult:
        """Propagate a finding status change to ServiceNow by updating the state field."""
        if not self._config or not self._config.configured:
            return self._skip(finding_id, SyncDirection.FINDING_TO_SN, "not configured")

        link = self._store.get_link(finding_id)
        if not link:
            return self._skip(
                finding_id,
                SyncDirection.FINDING_TO_SN,
                "no servicenow link for finding",
            )

        client = self._client
        assert client is not None
        sys_id = link["sn_sys_id"]
        incident_number = link["sn_incident_number"]

        target_state = self._config.finding_to_sn_state.get(new_status.lower())
        if not target_state:
            return self._record_and_return(
                finding_id,
                incident_number,
                sys_id,
                SyncDirection.FINDING_TO_SN,
                SyncStatus.SKIPPED,
                {"reason": f"no state mapping for status '{new_status}'"},
            )

        try:
            client.update_incident(sys_id, {"state": target_state})
            self._store.upsert_link(
                finding_id,
                sys_id,
                incident_number,
                finding_updated_at=_now_iso(),
            )
            return self._record_and_return(
                finding_id,
                incident_number,
                sys_id,
                SyncDirection.FINDING_TO_SN,
                SyncStatus.SUCCESS,
                {
                    "new_state": target_state,
                    "new_status": new_status,
                    "incident_number": incident_number,
                },
            )
        except RequestException as exc:
            logger.error(
                "sync_status failed for %s → %s: %s",
                finding_id,
                new_status,
                type(exc).__name__,
            )
            return self._record_and_return(
                finding_id,
                incident_number,
                sys_id,
                SyncDirection.FINDING_TO_SN,
                SyncStatus.FAILED,
                {"error": type(exc).__name__},
            )

    def sync_all(self, findings: List[Dict[str, Any]]) -> List[SyncResult]:
        """Sync a batch of findings to ServiceNow. Returns one result per finding."""
        results = []
        for f in findings:
            finding_id = f.get("finding_id") or f.get("id", "")
            result = self.sync_finding(finding_id, f)
            results.append(result)
        return results

    # -- history / stats --

    def get_history(
        self,
        finding_id: Optional[str] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Dict[str, Any]]:
        return self._store.get_history(
            finding_id=finding_id, limit=limit, offset=offset
        )

    def get_stats(self) -> Dict[str, Any]:
        return self._store.get_stats()

    def get_field_mapping(self) -> List[Dict[str, Any]]:
        if not self._config:
            return []
        return [
            {
                "finding_field": fm.finding_field,
                "sn_field": fm.sn_field,
                "transform": fm.transform,
            }
            for fm in self._config.field_mappings
        ]

    def set_field_mapping(self, mappings: List[Dict[str, Any]]) -> None:
        if not self._config:
            raise RuntimeError("Engine not configured")
        self._config.field_mappings = [
            FieldMapping(
                finding_field=m["finding_field"],
                sn_field=m["sn_field"],
                transform=m.get("transform"),
            )
            for m in mappings
        ]
        self._store.save_config(self._config)

    # -- webhook support --

    def handle_webhook(self, payload: Dict[str, Any]) -> SyncResult:
        """Process an incoming ServiceNow webhook event and sync back to finding.

        ServiceNow Business Rules or Flow Designer can POST to this endpoint
        when an incident is created, updated, or closed.
        Expected payload keys: sys_id, number, state, table_name, action
        """
        sys_id = payload.get("sys_id", "")
        table_name = payload.get("table_name", _INCIDENT_TABLE)
        action = payload.get("action", "")

        if not sys_id:
            return SyncResult(
                finding_id="",
                sn_incident_number=None,
                sn_sys_id=None,
                status=SyncStatus.SKIPPED,
                direction=SyncDirection.SN_TO_FINDING,
                detail={"reason": "no sys_id in webhook payload"},
                synced_at=_now_iso(),
            )

        if table_name != _INCIDENT_TABLE:
            return SyncResult(
                finding_id=sys_id,
                sn_incident_number=payload.get("number"),
                sn_sys_id=sys_id,
                status=SyncStatus.SKIPPED,
                direction=SyncDirection.SN_TO_FINDING,
                detail={"reason": f"unsupported table: {table_name}"},
                synced_at=_now_iso(),
            )

        if action in ("insert", "update", "delete", ""):
            # Pass the payload fields directly to avoid an extra API call
            sn_data = {
                "sys_id": sys_id,
                "number": payload.get("number", ""),
                "state": payload.get("state", ""),
                "sys_updated_on": payload.get("sys_updated_on", _now_iso()),
            }
            return self.sync_from_servicenow(sys_id, sn_data=sn_data)

        return SyncResult(
            finding_id=sys_id,
            sn_incident_number=payload.get("number"),
            sn_sys_id=sys_id,
            status=SyncStatus.SKIPPED,
            direction=SyncDirection.SN_TO_FINDING,
            detail={"reason": f"unhandled action: {action}"},
            synced_at=_now_iso(),
        )

    # -- internal helpers --

    def _skip(
        self, finding_id: str, direction: SyncDirection, reason: str
    ) -> SyncResult:
        result = SyncResult(
            finding_id=finding_id,
            sn_incident_number=None,
            sn_sys_id=None,
            status=SyncStatus.SKIPPED,
            direction=direction,
            detail={"reason": reason},
            synced_at=_now_iso(),
        )
        self._store.append_history(
            SyncRecord(
                record_id=str(uuid.uuid4()),
                finding_id=finding_id,
                sn_incident_number=None,
                sn_sys_id=None,
                direction=direction,
                status=SyncStatus.SKIPPED,
                detail={"reason": reason},
                synced_at=result.synced_at,
            )
        )
        return result

    def _record_and_return(
        self,
        finding_id: str,
        sn_incident_number: Optional[str],
        sn_sys_id: Optional[str],
        direction: SyncDirection,
        status: SyncStatus,
        detail: Dict[str, Any],
    ) -> SyncResult:
        synced_at = _now_iso()
        self._store.append_history(
            SyncRecord(
                record_id=str(uuid.uuid4()),
                finding_id=finding_id,
                sn_incident_number=sn_incident_number,
                sn_sys_id=sn_sys_id,
                direction=direction,
                status=status,
                detail=detail,
                synced_at=synced_at,
            )
        )
        _tg_emit("servicenow_sync.synced", {
            "finding_id": finding_id,
            "direction": direction.value,
            "status": status.value,
            "sn_incident_number": sn_incident_number,
        })
        return SyncResult(
            finding_id=finding_id,
            sn_incident_number=sn_incident_number,
            sn_sys_id=sn_sys_id,
            status=status,
            direction=direction,
            detail=detail,
            synced_at=synced_at,
        )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_engine: Optional[ServiceNowSyncEngine] = None
_engine_lock = Lock()


def get_servicenow_sync_engine(
    db_path: str = _DEFAULT_DB,
) -> ServiceNowSyncEngine:
    """Return (or create) the module-level ServiceNowSyncEngine singleton."""
    global _engine
    with _engine_lock:
        if _engine is None:
            _engine = ServiceNowSyncEngine(db_path=db_path)
    return _engine
