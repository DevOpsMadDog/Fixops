"""Jira Bidirectional Sync Engine for ALDECI/FixOps.

Synchronises security findings with Jira tickets in both directions:
  - Finding → Jira: create or update a Jira issue from a finding
  - Jira → Finding: update finding status when the linked Jira ticket changes
  - Status sync: propagate status transitions in both directions
  - Conflict resolution: last-write-wins with configurable override policy
  - Sync history: SQLite-backed audit trail of every sync event

Supported Jira endpoints:
  - Jira Cloud (REST API v3 / /rest/api/3/)
  - Jira Data Center 9.x+ / Jira Server 8.x+ (same URL scheme)

Typical usage
-------------
    engine = JiraSyncEngine(db_path="jira_sync.db")
    engine.configure(JiraSyncConfig(
        jira_url="https://example.atlassian.net",
        user_email="bot@example.com",
        api_token="...",
        project_key="SEC",
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

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_DB = "jira_sync.db"
_API_BASE = "rest/api/3"

# Jira status → ALDECI finding status mapping (default)
_DEFAULT_JIRA_TO_FINDING_STATUS: Dict[str, str] = {
    "To Do": "open",
    "In Progress": "in_progress",
    "In Review": "in_review",
    "Done": "resolved",
    "Resolved": "resolved",
    "Closed": "closed",
    "Won't Do": "wont_fix",
    "Duplicate": "duplicate",
}

# ALDECI finding severity → Jira priority mapping (default)
_DEFAULT_SEVERITY_TO_PRIORITY: Dict[str, str] = {
    "critical": "Highest",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Lowest",
    "informational": "Lowest",
}

# ALDECI finding status → Jira transition name mapping (default)
_DEFAULT_FINDING_TO_JIRA_TRANSITION: Dict[str, str] = {
    "resolved": "Done",
    "closed": "Done",
    "wont_fix": "Won't Do",
    "in_progress": "In Progress",
    "open": "To Do",
}


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class SyncDirection(str, Enum):
    FINDING_TO_JIRA = "finding_to_jira"
    JIRA_TO_FINDING = "jira_to_finding"
    BIDIRECTIONAL = "bidirectional"


class SyncStatus(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    CONFLICT = "conflict"


class ConflictResolution(str, Enum):
    """Policy when both sides have changed since last sync."""
    JIRA_WINS = "jira_wins"
    FINDING_WINS = "finding_wins"
    NEWEST_WINS = "newest_wins"
    MANUAL = "manual"


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------


@dataclass
class FieldMapping:
    """Single field mapping between finding and Jira."""
    finding_field: str
    jira_field: str
    transform: Optional[str] = None  # "severity_to_priority" | "status_to_transition"


@dataclass
class JiraSyncConfig:
    """Full configuration for the Jira sync engine."""
    jira_url: str = ""
    user_email: str = ""
    api_token: str = ""
    project_key: str = ""
    default_issue_type: str = "Bug"
    sync_direction: SyncDirection = SyncDirection.BIDIRECTIONAL
    conflict_resolution: ConflictResolution = ConflictResolution.NEWEST_WINS
    field_mappings: List[FieldMapping] = field(default_factory=list)
    # Status maps
    jira_to_finding_status: Dict[str, str] = field(
        default_factory=lambda: dict(_DEFAULT_JIRA_TO_FINDING_STATUS)
    )
    finding_to_jira_transition: Dict[str, str] = field(
        default_factory=lambda: dict(_DEFAULT_FINDING_TO_JIRA_TRANSITION)
    )
    severity_to_priority: Dict[str, str] = field(
        default_factory=lambda: dict(_DEFAULT_SEVERITY_TO_PRIORITY)
    )
    # Optional label/component settings
    labels: List[str] = field(default_factory=lambda: ["aldeci", "security"])
    component_name: Optional[str] = None
    # Webhook secret for incoming Jira webhooks
    webhook_secret: Optional[str] = None

    @property
    def configured(self) -> bool:
        return bool(
            self.jira_url and self.user_email and self.api_token and self.project_key
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "jira_url": self.jira_url,
            "user_email": self.user_email,
            "api_token": "***" if self.api_token else "",
            "project_key": self.project_key,
            "default_issue_type": self.default_issue_type,
            "sync_direction": self.sync_direction.value,
            "conflict_resolution": self.conflict_resolution.value,
            "field_mappings": [
                {"finding_field": fm.finding_field, "jira_field": fm.jira_field}
                for fm in self.field_mappings
            ],
            "labels": self.labels,
            "component_name": self.component_name,
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
    jira_issue_key: Optional[str]
    direction: SyncDirection
    status: SyncStatus
    detail: Dict[str, Any]
    synced_at: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "record_id": self.record_id,
            "finding_id": self.finding_id,
            "jira_issue_key": self.jira_issue_key,
            "direction": self.direction.value,
            "status": self.status.value,
            "detail": self.detail,
            "synced_at": self.synced_at,
        }


# ---------------------------------------------------------------------------
# SQLite store
# ---------------------------------------------------------------------------


class JiraSyncStore:
    """SQLite-backed store for sync state and history.

    Tables
    ------
    sync_links      — maps finding_id ↔ jira_issue_key with timestamps
    sync_history    — append-only audit log of every sync event
    config          — serialised JiraSyncConfig
    """

    _DDL = """
    CREATE TABLE IF NOT EXISTS sync_links (
        finding_id      TEXT PRIMARY KEY,
        jira_issue_key  TEXT NOT NULL,
        created_at      TEXT NOT NULL,
        updated_at      TEXT NOT NULL,
        last_finding_updated_at TEXT,
        last_jira_updated_at    TEXT
    );

    CREATE TABLE IF NOT EXISTS sync_history (
        record_id       TEXT PRIMARY KEY,
        finding_id      TEXT NOT NULL,
        jira_issue_key  TEXT,
        direction       TEXT NOT NULL,
        status          TEXT NOT NULL,
        detail          TEXT NOT NULL,
        synced_at       TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_history_finding
        ON sync_history (finding_id);

    CREATE INDEX IF NOT EXISTS idx_history_synced_at
        ON sync_history (synced_at);

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

    def upsert_link(
        self,
        finding_id: str,
        jira_issue_key: str,
        finding_updated_at: Optional[str] = None,
        jira_updated_at: Optional[str] = None,
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
                       SET jira_issue_key = ?, updated_at = ?,
                           last_finding_updated_at = COALESCE(?, last_finding_updated_at),
                           last_jira_updated_at    = COALESCE(?, last_jira_updated_at)
                       WHERE finding_id = ?""",
                    (
                        jira_issue_key,
                        now,
                        finding_updated_at,
                        jira_updated_at,
                        finding_id,
                    ),
                )
            else:
                conn.execute(
                    """INSERT INTO sync_links
                       (finding_id, jira_issue_key, created_at, updated_at,
                        last_finding_updated_at, last_jira_updated_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (
                        finding_id,
                        jira_issue_key,
                        now,
                        now,
                        finding_updated_at,
                        jira_updated_at,
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
            rows = conn.execute("SELECT * FROM sync_links ORDER BY updated_at DESC").fetchall()
        return [dict(r) for r in rows]

    # -- history --

    def append_history(self, record: SyncRecord) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO sync_history
                   (record_id, finding_id, jira_issue_key, direction, status, detail, synced_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    record.record_id,
                    record.finding_id,
                    record.jira_issue_key,
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

    def save_config(self, config: JiraSyncConfig) -> None:
        data = json.dumps(
            {
                "jira_url": config.jira_url,
                "user_email": config.user_email,
                "api_token": config.api_token,
                "project_key": config.project_key,
                "default_issue_type": config.default_issue_type,
                "sync_direction": config.sync_direction.value,
                "conflict_resolution": config.conflict_resolution.value,
                "labels": config.labels,
                "component_name": config.component_name,
                "webhook_secret": config.webhook_secret,
                "jira_to_finding_status": config.jira_to_finding_status,
                "finding_to_jira_transition": config.finding_to_jira_transition,
                "severity_to_priority": config.severity_to_priority,
            }
        )
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO config (key, value) VALUES ('main', ?)", (data,)
            )

    def load_config(self) -> Optional[JiraSyncConfig]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT value FROM config WHERE key = 'main'"
            ).fetchone()
        if not row:
            return None
        data = json.loads(row[0])
        cfg = JiraSyncConfig(
            jira_url=data.get("jira_url", ""),
            user_email=data.get("user_email", ""),
            api_token=data.get("api_token", ""),
            project_key=data.get("project_key", ""),
            default_issue_type=data.get("default_issue_type", "Bug"),
            sync_direction=SyncDirection(data.get("sync_direction", SyncDirection.BIDIRECTIONAL.value)),
            conflict_resolution=ConflictResolution(
                data.get("conflict_resolution", ConflictResolution.NEWEST_WINS.value)
            ),
            labels=data.get("labels", ["aldeci", "security"]),
            component_name=data.get("component_name"),
            webhook_secret=data.get("webhook_secret"),
            jira_to_finding_status=data.get("jira_to_finding_status", dict(_DEFAULT_JIRA_TO_FINDING_STATUS)),
            finding_to_jira_transition=data.get("finding_to_jira_transition", dict(_DEFAULT_FINDING_TO_JIRA_TRANSITION)),
            severity_to_priority=data.get("severity_to_priority", dict(_DEFAULT_SEVERITY_TO_PRIORITY)),
        )
        return cfg


# ---------------------------------------------------------------------------
# Jira HTTP client (thin wrapper, re-uses patterns from connectors.py)
# ---------------------------------------------------------------------------


class _JiraClient:
    """Minimal Jira Cloud/Server REST client."""

    def __init__(self, config: JiraSyncConfig, timeout: float = 15.0) -> None:
        self._cfg = config
        self._timeout = timeout
        self._session = requests.Session()
        retry = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "POST", "PUT", "DELETE"],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry, pool_connections=5, pool_maxsize=10)
        self._session.mount("http://", adapter)
        self._session.mount("https://", adapter)

    def _url(self, path: str) -> str:
        base = self._cfg.jira_url.rstrip("/") + "/"
        return urljoin(base, f"{_API_BASE}/{path.lstrip('/')}")

    def _auth(self):  # type: ignore[return]
        return (self._cfg.user_email, self._cfg.api_token)

    def _headers(self, extra: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        h = {"Accept": "application/json", "Content-Type": "application/json"}
        if extra:
            h.update(extra)
        return h

    def create_issue(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        resp = self._session.post(
            self._url("issue"),
            json=payload,
            auth=self._auth(),
            headers=self._headers(),
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def get_issue(self, issue_key: str) -> Dict[str, Any]:
        resp = self._session.get(
            self._url(f"issue/{issue_key}"),
            auth=self._auth(),
            headers=self._headers(),
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def update_issue(self, issue_key: str, fields: Dict[str, Any]) -> None:
        resp = self._session.put(
            self._url(f"issue/{issue_key}"),
            json={"fields": fields},
            auth=self._auth(),
            headers=self._headers(),
            timeout=self._timeout,
        )
        resp.raise_for_status()

    def add_comment(self, issue_key: str, body: str) -> Dict[str, Any]:
        resp = self._session.post(
            self._url(f"issue/{issue_key}/comment"),
            json={"body": body},
            auth=self._auth(),
            headers=self._headers(),
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json()

    def get_transitions(self, issue_key: str) -> List[Dict[str, Any]]:
        resp = self._session.get(
            self._url(f"issue/{issue_key}/transitions"),
            auth=self._auth(),
            headers=self._headers(),
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json().get("transitions", [])

    def transition_issue(self, issue_key: str, transition_id: str) -> None:
        resp = self._session.post(
            self._url(f"issue/{issue_key}/transitions"),
            json={"transition": {"id": str(transition_id)}},
            auth=self._auth(),
            headers=self._headers(),
            timeout=self._timeout,
        )
        resp.raise_for_status()

    def search_issues(self, jql: str, max_results: int = 50) -> List[Dict[str, Any]]:
        resp = self._session.post(
            self._url("search"),
            json={"jql": jql, "maxResults": max_results, "fields": ["*all"]},
            auth=self._auth(),
            headers=self._headers(),
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json().get("issues", [])


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
    jira_issue_key: Optional[str]
    status: SyncStatus
    direction: SyncDirection
    detail: Dict[str, Any]
    synced_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "jira_issue_key": self.jira_issue_key,
            "status": self.status.value,
            "direction": self.direction.value,
            "detail": self.detail,
            "synced_at": self.synced_at,
        }


# ---------------------------------------------------------------------------
# Core engine
# ---------------------------------------------------------------------------


class JiraSyncEngine:
    """Bidirectional sync engine between ALDECI findings and Jira tickets.

    Usage
    -----
        engine = JiraSyncEngine()
        engine.configure(JiraSyncConfig(...))
        result = engine.sync_finding("F-001", {"title": "...", "severity": "high"})
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._store = JiraSyncStore(db_path=db_path)
        self._config: Optional[JiraSyncConfig] = self._store.load_config()
        self._client: Optional[_JiraClient] = None
        if self._config and self._config.configured:
            self._client = _JiraClient(self._config)

    # -- configuration --

    def configure(self, config: JiraSyncConfig) -> None:
        """Set (and persist) the sync configuration."""
        self._config = config
        self._store.save_config(config)
        self._client = _JiraClient(config) if config.configured else None
        logger.info("JiraSyncEngine configured (project=%s)", config.project_key)

    def get_config(self) -> Optional[JiraSyncConfig]:
        return self._config

    # -- field mapping helpers --

    def _build_jira_fields(self, finding_data: Dict[str, Any]) -> Dict[str, Any]:
        """Map finding fields to Jira issue fields."""
        cfg = self._config
        assert cfg is not None

        severity = str(finding_data.get("severity", "medium")).lower()
        priority = cfg.severity_to_priority.get(severity, "Medium")

        summary = (
            finding_data.get("title")
            or finding_data.get("summary")
            or f"Security Finding {finding_data.get('finding_id', '')}"
        )
        description = self._build_description(finding_data)

        fields: Dict[str, Any] = {
            "project": {"key": cfg.project_key},
            "summary": str(summary)[:255],
            "description": description,
            "issuetype": {"name": cfg.default_issue_type},
            "priority": {"name": priority},
            "labels": cfg.labels,
        }

        if cfg.component_name:
            fields["components"] = [{"name": cfg.component_name}]

        # Apply custom field mappings
        for fm in cfg.field_mappings:
            val = finding_data.get(fm.finding_field)
            if val is not None:
                fields[fm.jira_field] = val

        return fields

    def _build_description(self, finding_data: Dict[str, Any]) -> str:
        lines = [
            f"*Finding ID*: {finding_data.get('finding_id', 'N/A')}",
            f"*Severity*: {finding_data.get('severity', 'N/A')}",
            f"*Source*: {finding_data.get('source', 'N/A')}",
            f"*CVE*: {finding_data.get('cve_id', 'N/A')}",
            "",
            "*Description*:",
            finding_data.get("description") or finding_data.get("detail") or "_No description provided._",
            "",
            "_Synced automatically by ALDECI/FixOps_",
        ]
        return "\n".join(lines)

    def _resolve_transition_id(self, client: _JiraClient, issue_key: str, target_name: str) -> Optional[str]:
        try:
            transitions = client.get_transitions(issue_key)
            for t in transitions:
                if t.get("name", "").lower() == target_name.lower():
                    return str(t["id"])
        except RequestException as exc:
            logger.warning("Could not fetch transitions for %s: %s", issue_key, type(exc).__name__)
        return None

    # -- sync operations --

    def sync_finding(
        self,
        finding_id: str,
        finding_data: Dict[str, Any],
    ) -> SyncResult:
        """Create or update a Jira ticket from a finding (finding → Jira)."""
        if not self._config or not self._config.configured:
            return self._skip(finding_id, SyncDirection.FINDING_TO_JIRA, "not configured")

        if self._config.sync_direction == SyncDirection.JIRA_TO_FINDING:
            return self._skip(finding_id, SyncDirection.FINDING_TO_JIRA, "direction is jira_to_finding only")

        client = self._client
        assert client is not None

        link = self._store.get_link(finding_id)
        finding_updated_at = finding_data.get("updated_at") or _now_iso()

        try:
            if link:
                issue_key = link["jira_issue_key"]
                # Conflict resolution check
                if self._config.conflict_resolution == ConflictResolution.JIRA_WINS:
                    return self._record_and_return(
                        finding_id, issue_key, SyncDirection.FINDING_TO_JIRA,
                        SyncStatus.SKIPPED, {"reason": "conflict_resolution=jira_wins, skipping finding→jira push"}
                    )
                # Update existing issue
                fields = self._build_jira_fields(finding_data)
                # Remove immutable creation-only fields
                for k in ("project", "issuetype"):
                    fields.pop(k, None)
                client.update_issue(issue_key, fields)
                self._store.upsert_link(
                    finding_id, issue_key,
                    finding_updated_at=finding_updated_at,
                )
                return self._record_and_return(
                    finding_id, issue_key, SyncDirection.FINDING_TO_JIRA,
                    SyncStatus.SUCCESS, {"operation": "updated", "issue_key": issue_key}
                )
            else:
                # Create new issue
                fields = self._build_jira_fields(finding_data)
                body = client.create_issue({"fields": fields})
                issue_key = body.get("key", "")
                self._store.upsert_link(
                    finding_id, issue_key,
                    finding_updated_at=finding_updated_at,
                )
                return self._record_and_return(
                    finding_id, issue_key, SyncDirection.FINDING_TO_JIRA,
                    SyncStatus.SUCCESS, {"operation": "created", "issue_key": issue_key}
                )
        except RequestException as exc:
            logger.error("sync_finding failed for %s: %s", finding_id, type(exc).__name__)
            return self._record_and_return(
                finding_id, None, SyncDirection.FINDING_TO_JIRA,
                SyncStatus.FAILED, {"error": type(exc).__name__, "finding_id": finding_id}
            )

    def sync_from_jira(
        self,
        jira_issue_key: str,
        jira_data: Optional[Dict[str, Any]] = None,
    ) -> SyncResult:
        """Update ALDECI finding status from a Jira ticket (Jira → finding).

        Returns the translated finding status in detail["new_finding_status"].
        Callers are responsible for applying the status to the finding store.
        """
        if not self._config or not self._config.configured:
            return self._skip(jira_issue_key, SyncDirection.JIRA_TO_FINDING, "not configured")

        if self._config.sync_direction == SyncDirection.FINDING_TO_JIRA:
            return self._skip(jira_issue_key, SyncDirection.JIRA_TO_FINDING, "direction is finding_to_jira only")

        client = self._client
        assert client is not None

        try:
            if jira_data is None:
                jira_data = client.get_issue(jira_issue_key)

            jira_status = (
                jira_data.get("fields", {})
                .get("status", {})
                .get("name", "")
            )
            new_finding_status = self._config.jira_to_finding_status.get(
                jira_status, "unknown"
            )
            jira_updated = (
                jira_data.get("fields", {}).get("updated")
                or _now_iso()
            )

            # Find linked finding
            links = self._store.list_links()
            linked = next(
                (l for l in links if l["jira_issue_key"] == jira_issue_key), None
            )
            finding_id = linked["finding_id"] if linked else jira_issue_key

            self._store.upsert_link(
                finding_id, jira_issue_key, jira_updated_at=jira_updated
            )
            return self._record_and_return(
                finding_id, jira_issue_key, SyncDirection.JIRA_TO_FINDING,
                SyncStatus.SUCCESS,
                {
                    "jira_status": jira_status,
                    "new_finding_status": new_finding_status,
                    "jira_updated": jira_updated,
                },
            )
        except RequestException as exc:
            logger.error("sync_from_jira failed for %s: %s", jira_issue_key, type(exc).__name__)
            return self._record_and_return(
                jira_issue_key, jira_issue_key, SyncDirection.JIRA_TO_FINDING,
                SyncStatus.FAILED, {"error": type(exc).__name__}
            )

    def sync_status(
        self,
        finding_id: str,
        new_status: str,
    ) -> SyncResult:
        """Propagate a finding status change to Jira via a workflow transition."""
        if not self._config or not self._config.configured:
            return self._skip(finding_id, SyncDirection.FINDING_TO_JIRA, "not configured")

        link = self._store.get_link(finding_id)
        if not link:
            return self._skip(finding_id, SyncDirection.FINDING_TO_JIRA, "no jira link for finding")

        client = self._client
        assert client is not None
        issue_key = link["jira_issue_key"]

        target_transition = self._config.finding_to_jira_transition.get(new_status.lower())
        if not target_transition:
            return self._record_and_return(
                finding_id, issue_key, SyncDirection.FINDING_TO_JIRA,
                SyncStatus.SKIPPED,
                {"reason": f"no transition mapping for status '{new_status}'"}
            )

        try:
            transition_id = self._resolve_transition_id(client, issue_key, target_transition)
            if not transition_id:
                return self._record_and_return(
                    finding_id, issue_key, SyncDirection.FINDING_TO_JIRA,
                    SyncStatus.FAILED,
                    {"reason": f"transition '{target_transition}' not available on {issue_key}"}
                )
            client.transition_issue(issue_key, transition_id)
            self._store.upsert_link(finding_id, issue_key, finding_updated_at=_now_iso())
            return self._record_and_return(
                finding_id, issue_key, SyncDirection.FINDING_TO_JIRA,
                SyncStatus.SUCCESS,
                {"transition": target_transition, "transition_id": transition_id, "new_status": new_status}
            )
        except RequestException as exc:
            logger.error("sync_status failed for %s → %s: %s", finding_id, new_status, type(exc).__name__)
            return self._record_and_return(
                finding_id, issue_key, SyncDirection.FINDING_TO_JIRA,
                SyncStatus.FAILED, {"error": type(exc).__name__}
            )

    def sync_all(self, findings: List[Dict[str, Any]]) -> List[SyncResult]:
        """Sync a batch of findings to Jira. Returns one result per finding."""
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
        return self._store.get_history(finding_id=finding_id, limit=limit, offset=offset)

    def get_stats(self) -> Dict[str, Any]:
        return self._store.get_stats()

    def get_field_mapping(self) -> List[Dict[str, Any]]:
        if not self._config:
            return []
        return [
            {"finding_field": fm.finding_field, "jira_field": fm.jira_field, "transform": fm.transform}
            for fm in self._config.field_mappings
        ]

    def set_field_mapping(self, mappings: List[Dict[str, Any]]) -> None:
        if not self._config:
            raise RuntimeError("Engine not configured")
        self._config.field_mappings = [
            FieldMapping(
                finding_field=m["finding_field"],
                jira_field=m["jira_field"],
                transform=m.get("transform"),
            )
            for m in mappings
        ]
        self._store.save_config(self._config)

    # -- webhook support --

    def handle_webhook(self, payload: Dict[str, Any]) -> SyncResult:
        """Process an incoming Jira webhook event and sync back to finding."""
        event_type = payload.get("webhookEvent", "")
        issue = payload.get("issue", {})
        issue_key = issue.get("key", "")

        if not issue_key:
            return SyncResult(
                finding_id="",
                jira_issue_key=None,
                status=SyncStatus.SKIPPED,
                direction=SyncDirection.JIRA_TO_FINDING,
                detail={"reason": "no issue key in webhook payload"},
                synced_at=_now_iso(),
            )

        if event_type in ("jira:issue_updated", "jira:issue_created", "jira:issue_deleted"):
            return self.sync_from_jira(issue_key, jira_data={"fields": issue.get("fields", {}), "key": issue_key})

        return SyncResult(
            finding_id=issue_key,
            jira_issue_key=issue_key,
            status=SyncStatus.SKIPPED,
            direction=SyncDirection.JIRA_TO_FINDING,
            detail={"reason": f"unhandled event type: {event_type}"},
            synced_at=_now_iso(),
        )

    # -- internal helpers --

    def _skip(self, finding_id: str, direction: SyncDirection, reason: str) -> SyncResult:
        result = SyncResult(
            finding_id=finding_id,
            jira_issue_key=None,
            status=SyncStatus.SKIPPED,
            direction=direction,
            detail={"reason": reason},
            synced_at=_now_iso(),
        )
        self._store.append_history(
            SyncRecord(
                record_id=str(uuid.uuid4()),
                finding_id=finding_id,
                jira_issue_key=None,
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
        jira_issue_key: Optional[str],
        direction: SyncDirection,
        status: SyncStatus,
        detail: Dict[str, Any],
    ) -> SyncResult:
        synced_at = _now_iso()
        self._store.append_history(
            SyncRecord(
                record_id=str(uuid.uuid4()),
                finding_id=finding_id,
                jira_issue_key=jira_issue_key,
                direction=direction,
                status=status,
                detail=detail,
                synced_at=synced_at,
            )
        )
        return SyncResult(
            finding_id=finding_id,
            jira_issue_key=jira_issue_key,
            status=status,
            direction=direction,
            detail=detail,
            synced_at=synced_at,
        )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_engine: Optional[JiraSyncEngine] = None
_engine_lock = Lock()


def get_jira_sync_engine(db_path: str = _DEFAULT_DB) -> JiraSyncEngine:
    """Return (or create) the module-level JiraSyncEngine singleton."""
    global _engine
    with _engine_lock:
        if _engine is None:
            _engine = JiraSyncEngine(db_path=db_path)
    return _engine
