"""Network Forensics Engine — ALDECI. SQLite WAL + RLock + org_id isolation."""
from __future__ import annotations

import json
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "network_forensics.db"
)

_VALID_ARTIFACT_TYPES = {"pcap", "flow", "dns_log", "http_log"}
_VALID_STATUSES = {"running", "completed", "failed", "cancelled"}


class NetworkForensicsEngine:
    """SQLite WAL-backed Network Forensics engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        return conn

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS nf_captures (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    interface   TEXT NOT NULL DEFAULT '',
                    filter_bpf  TEXT NOT NULL DEFAULT '',
                    duration_sec INTEGER NOT NULL DEFAULT 60,
                    status      TEXT NOT NULL DEFAULT 'running',
                    started_at  DATETIME,
                    ended_at    DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_nfc_org ON nf_captures (org_id);

                CREATE TABLE IF NOT EXISTS nf_artifacts (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    capture_id      TEXT NOT NULL,
                    artifact_type   TEXT NOT NULL DEFAULT 'pcap',
                    size_bytes      INTEGER NOT NULL DEFAULT 0,
                    findings_count  INTEGER NOT NULL DEFAULT 0,
                    analysis_json   TEXT NOT NULL DEFAULT '',
                    created_at      DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_nfa_org ON nf_artifacts (org_id);
                CREATE INDEX IF NOT EXISTS idx_nfa_cap ON nf_artifacts (capture_id);
                """
            )

    # ------------------------------------------------------------------
    # Captures
    # ------------------------------------------------------------------

    def create_capture(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new packet capture record. Requires 'interface' in data."""
        interface = data.get("interface", "").strip()
        if not interface:
            raise ValueError("interface is required")

        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "interface": interface,
            "filter_bpf": data.get("filter_bpf", ""),
            "duration_sec": int(data.get("duration_sec", 60)),
            "status": "running",
            "started_at": self._now(),
            "ended_at": None,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO nf_captures
                       (id, org_id, interface, filter_bpf, duration_sec, status, started_at, ended_at)
                       VALUES (:id, :org_id, :interface, :filter_bpf, :duration_sec, :status, :started_at, :ended_at)""",
                    record,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ASSET_DISCOVERED", {"entity_type": "network_forensics", "org_id": org_id, "source_engine": "network_forensics"})
            except Exception:
                pass

        return record

    def list_captures(self, org_id: str, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """List captures for org. Optionally filter by status."""
        with self._lock:
            with self._conn() as conn:
                if status:
                    rows = conn.execute(
                        "SELECT * FROM nf_captures WHERE org_id=? AND status=? ORDER BY started_at DESC",
                        (org_id, status),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM nf_captures WHERE org_id=? ORDER BY started_at DESC",
                        (org_id,),
                    ).fetchall()
        return [dict(r) for r in rows]

    def get_capture(self, org_id: str, capture_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single capture by id, scoped to org_id."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM nf_captures WHERE id=? AND org_id=?",
                    (capture_id, org_id),
                ).fetchone()
        return dict(row) if row else None

    def update_capture_status(self, org_id: str, capture_id: str, status: str) -> bool:
        """Update capture status. Returns True if updated."""
        if status not in _VALID_STATUSES:
            raise ValueError(f"Invalid status: {status}. Must be one of {_VALID_STATUSES}")
        ended_at = self._now() if status in {"completed", "failed", "cancelled"} else None
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    "UPDATE nf_captures SET status=?, ended_at=? WHERE id=? AND org_id=?",
                    (status, ended_at, capture_id, org_id),
                )
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Artifacts
    # ------------------------------------------------------------------

    def add_artifact(self, org_id: str, capture_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add an artifact to a capture. artifact_type must be in _VALID_ARTIFACT_TYPES."""
        artifact_type = data.get("artifact_type", "pcap")
        if artifact_type not in _VALID_ARTIFACT_TYPES:
            raise ValueError(
                f"Invalid artifact_type: {artifact_type!r}. Must be one of {_VALID_ARTIFACT_TYPES}"
            )

        record: Dict[str, Any] = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "capture_id": capture_id,
            "artifact_type": artifact_type,
            "size_bytes": int(data.get("size_bytes", 0)),
            "findings_count": int(data.get("findings_count", 0)),
            "analysis_json": data.get("analysis_json", ""),
            "created_at": self._now(),
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO nf_artifacts
                       (id, org_id, capture_id, artifact_type, size_bytes, findings_count, analysis_json, created_at)
                       VALUES (:id, :org_id, :capture_id, :artifact_type, :size_bytes, :findings_count, :analysis_json, :created_at)""",
                    record,
                )
        return record

    def analyze_capture(self, org_id: str, capture_id: str, analysis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Store analysis result on the first artifact of a capture (or create a note).

        Returns a summary dict with suspicious_ips, protocols_seen, anomalies.
        """
        suspicious_ips: List[str] = analysis_data.get("suspicious_ips", [])
        protocols_seen: List[str] = analysis_data.get("protocols_seen", [])
        anomalies: List[str] = analysis_data.get("anomalies", [])

        analysis_json = json.dumps({
            "suspicious_ips": suspicious_ips,
            "protocols_seen": protocols_seen,
            "anomalies": anomalies,
            "raw": analysis_data,
        })

        with self._lock:
            with self._conn() as conn:
                # Try to update the first artifact's analysis_json
                first_art = conn.execute(
                    "SELECT id FROM nf_artifacts WHERE capture_id=? AND org_id=? ORDER BY created_at LIMIT 1",
                    (capture_id, org_id),
                ).fetchone()
                if first_art:
                    conn.execute(
                        "UPDATE nf_artifacts SET analysis_json=?, findings_count=? WHERE id=?",
                        (analysis_json, len(anomalies) + len(suspicious_ips), first_art["id"]),
                    )

        return {
            "capture_id": capture_id,
            "suspicious_ips": suspicious_ips,
            "protocols_seen": protocols_seen,
            "anomalies": anomalies,
        }

    def list_artifacts(self, org_id: str, capture_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """List all artifacts for org, optionally filtered by capture_id."""
        with self._lock:
            with self._conn() as conn:
                if capture_id:
                    rows = conn.execute(
                        "SELECT * FROM nf_artifacts WHERE org_id=? AND capture_id=? ORDER BY created_at DESC",
                        (org_id, capture_id),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM nf_artifacts WHERE org_id=? ORDER BY created_at DESC",
                        (org_id,),
                    ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_forensics_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate stats for org."""
        with self._lock:
            with self._conn() as conn:
                total_captures = conn.execute(
                    "SELECT COUNT(*) FROM nf_captures WHERE org_id=?", (org_id,)
                ).fetchone()[0]
                active_captures = conn.execute(
                    "SELECT COUNT(*) FROM nf_captures WHERE org_id=? AND status='running'", (org_id,)
                ).fetchone()[0]
                total_artifacts = conn.execute(
                    "SELECT COUNT(*) FROM nf_artifacts WHERE org_id=?", (org_id,)
                ).fetchone()[0]
                suspicious_captures = conn.execute(
                    "SELECT COUNT(*) FROM nf_artifacts WHERE org_id=? AND findings_count>0", (org_id,)
                ).fetchone()[0]

        return {
            "org_id": org_id,
            "total_captures": total_captures,
            "active_captures": active_captures,
            "total_artifacts": total_artifacts,
            "suspicious_captures": suspicious_captures,
        }
