"""Code-to-Runtime Matcher Engine — ALDECI (GAP-013).

Maps live runtime traffic/error events back to repo + commit + owner for
triage. Supports three matching strategies with tiered confidence:

  1) stack-trace file path match   — highest confidence (0.9)
  2) service_name → repo mapping   — medium confidence (0.6)
  3) path-based heuristic match    — low confidence (0.3)

Stack-trace parsing uses a naive synthetic format `File "<path>", line N`.
The engine is stdlib-only; no external dependencies.

Compliance / use cases: runtime-to-code triage (incident response),
owner routing for production errors, CTEM decision loop enrichment.
"""

from __future__ import annotations

import logging
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:  # pragma: no cover - bus optional
    _get_tg_bus = None

_logger = logging.getLogger(__name__)

_DEFAULT_DB_DIR = str(Path(__file__).resolve().parents[2] / ".fixops_data")

_STRATEGY_STACK_TRACE = "stack_trace"
_STRATEGY_SERVICE_MAP = "service_mapping"
_STRATEGY_PATH_HEURISTIC = "path_heuristic"

_CONFIDENCE = {
    _STRATEGY_STACK_TRACE: 0.9,
    _STRATEGY_SERVICE_MAP: 0.6,
    _STRATEGY_PATH_HEURISTIC: 0.3,
}

_STACK_LINE_RE = re.compile(r'File\s+"([^"]+)",\s*line\s+(\d+)')


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class CodeToRuntimeMatcherEngine:
    """SQLite WAL-backed runtime-to-code matcher.

    Thread-safe via RLock. Multi-tenant via org_id.
    DB path: .fixops_data/code_to_runtime_matcher.db
    """

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = str(Path(_DEFAULT_DB_DIR) / "code_to_runtime_matcher.db")
        self._db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS runtime_events (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    event_ref       TEXT NOT NULL,
                    event_type      TEXT NOT NULL,
                    service_name    TEXT NOT NULL DEFAULT '',
                    path            TEXT NOT NULL DEFAULT '',
                    method          TEXT NOT NULL DEFAULT '',
                    status_code     INTEGER NOT NULL DEFAULT 0,
                    error_message   TEXT NOT NULL DEFAULT '',
                    stack_trace     TEXT NOT NULL DEFAULT '',
                    captured_at     TEXT NOT NULL,
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_re_org_service
                    ON runtime_events (org_id, service_name, captured_at DESC);

                CREATE TABLE IF NOT EXISTS runtime_to_code_matches (
                    id                TEXT PRIMARY KEY,
                    runtime_event_id  TEXT NOT NULL,
                    repo_ref          TEXT NOT NULL DEFAULT '',
                    commit_sha        TEXT NOT NULL DEFAULT '',
                    file_ref          TEXT NOT NULL DEFAULT '',
                    line_number       INTEGER NOT NULL DEFAULT 0,
                    match_confidence  REAL NOT NULL DEFAULT 0.0,
                    match_strategy    TEXT NOT NULL DEFAULT '',
                    matched_at        TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_rtcm_event
                    ON runtime_to_code_matches (runtime_event_id, matched_at DESC);

                CREATE TABLE IF NOT EXISTS service_code_mappings (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    service_name  TEXT NOT NULL,
                    repo_ref      TEXT NOT NULL DEFAULT '',
                    deploy_ref    TEXT NOT NULL DEFAULT '',
                    registered_at TEXT NOT NULL,
                    UNIQUE(org_id, service_name)
                );

                CREATE INDEX IF NOT EXISTS idx_scm_org
                    ON service_code_mappings (org_id, service_name);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Service mappings
    # ------------------------------------------------------------------

    def register_service_mapping(
        self,
        org_id: str,
        service_name: str,
        repo_ref: str,
        deploy_ref: str = "",
    ) -> Dict[str, Any]:
        """Register or update a service→repo mapping (UNIQUE org_id+service_name)."""
        if not org_id or not service_name:
            raise ValueError("org_id and service_name are required")
        mapping_id = str(uuid.uuid4())
        now = _now_iso()
        with self._lock, self._conn() as conn:
            # Upsert on (org_id, service_name)
            row = conn.execute(
                "SELECT id FROM service_code_mappings WHERE org_id=? AND service_name=?",
                (org_id, service_name),
            ).fetchone()
            if row is not None:
                conn.execute(
                    """
                    UPDATE service_code_mappings
                       SET repo_ref=?, deploy_ref=?, registered_at=?
                     WHERE id=?
                    """,
                    (repo_ref, deploy_ref, now, row["id"]),
                )
                mapping_id = row["id"]
            else:
                conn.execute(
                    """
                    INSERT INTO service_code_mappings
                      (id, org_id, service_name, repo_ref, deploy_ref, registered_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (mapping_id, org_id, service_name, repo_ref, deploy_ref, now),
                )
            conn.commit()
        return {
            "id": mapping_id,
            "org_id": org_id,
            "service_name": service_name,
            "repo_ref": repo_ref,
            "deploy_ref": deploy_ref,
            "registered_at": now,
        }

    def list_service_mappings(self, org_id: str) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM service_code_mappings WHERE org_id=? ORDER BY registered_at DESC",
                (org_id,),
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Event ingestion
    # ------------------------------------------------------------------

    def ingest_runtime_event(
        self,
        org_id: str,
        event_ref: str,
        event_type: str,
        service_name: str = "",
        path: str = "",
        method: str = "",
        status_code: int = 0,
        error_message: str = "",
        stack_trace: str = "",
    ) -> Dict[str, Any]:
        if not org_id or not event_ref or not event_type:
            raise ValueError("org_id, event_ref, and event_type are required")
        event_id = str(uuid.uuid4())
        now = _now_iso()
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO runtime_events
                  (id, org_id, event_ref, event_type, service_name, path, method,
                   status_code, error_message, stack_trace, captured_at, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event_id,
                    org_id,
                    event_ref,
                    event_type,
                    service_name,
                    path,
                    method,
                    int(status_code or 0),
                    error_message,
                    stack_trace,
                    now,
                    now,
                ),
            )
            conn.commit()
        self._emit_event(
            "RUNTIME_EVENT_INGESTED",
            {"event_id": event_id, "org_id": org_id, "event_type": event_type},
        )
        return {
            "id": event_id,
            "org_id": org_id,
            "event_ref": event_ref,
            "event_type": event_type,
            "service_name": service_name,
            "path": path,
            "method": method,
            "status_code": int(status_code or 0),
            "error_message": error_message,
            "stack_trace": stack_trace,
            "captured_at": now,
            "created_at": now,
        }

    # ------------------------------------------------------------------
    # Matching
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_stack_trace(stack_trace: str) -> Optional[Dict[str, Any]]:
        """Naive parser for synthetic format: File "<path>", line N."""
        if not stack_trace:
            return None
        match = _STACK_LINE_RE.search(stack_trace)
        if match is None:
            return None
        return {"file_ref": match.group(1), "line_number": int(match.group(2))}

    def _lookup_service_mapping(
        self, org_id: str, service_name: str
    ) -> Optional[Dict[str, Any]]:
        if not service_name:
            return None
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM service_code_mappings WHERE org_id=? AND service_name=?",
                (org_id, service_name),
            ).fetchone()
        return dict(row) if row else None

    @staticmethod
    def _path_heuristic_file_ref(path: str) -> str:
        """Convert /users/{id}/profile → routes/users_profile.py (fake heuristic)."""
        if not path:
            return ""
        parts = [p for p in path.split("/") if p and not p.startswith("{")]
        slug = "_".join(parts) or "root"
        return f"routes/{slug}.py"

    def match_event_to_code(self, runtime_event_id: str) -> Dict[str, Any]:
        """Run three strategies; persist the best (highest-confidence) result."""
        with self._conn() as conn:
            ev = conn.execute(
                "SELECT * FROM runtime_events WHERE id=?", (runtime_event_id,)
            ).fetchone()
        if ev is None:
            raise LookupError(f"runtime_event {runtime_event_id} not found")
        ev = dict(ev)
        org_id = ev["org_id"]

        # Attempt strategies in priority order (highest confidence first)
        result: Optional[Dict[str, Any]] = None
        strategy = ""

        # 1) stack-trace file/line match
        parsed = self._parse_stack_trace(ev.get("stack_trace") or "")
        mapping = self._lookup_service_mapping(org_id, ev.get("service_name") or "")
        if parsed is not None:
            repo_ref = mapping["repo_ref"] if mapping else ""
            commit_sha = mapping["deploy_ref"] if mapping else ""
            result = {
                "repo_ref": repo_ref,
                "commit_sha": commit_sha,
                "file_ref": parsed["file_ref"],
                "line_number": parsed["line_number"],
                "confidence": _CONFIDENCE[_STRATEGY_STACK_TRACE],
                "strategy": _STRATEGY_STACK_TRACE,
            }
            strategy = _STRATEGY_STACK_TRACE

        # 2) service_name → repo mapping
        elif mapping is not None:
            result = {
                "repo_ref": mapping["repo_ref"],
                "commit_sha": mapping["deploy_ref"],
                "file_ref": "",
                "line_number": 0,
                "confidence": _CONFIDENCE[_STRATEGY_SERVICE_MAP],
                "strategy": _STRATEGY_SERVICE_MAP,
            }
            strategy = _STRATEGY_SERVICE_MAP

        # 3) path-based heuristic
        elif ev.get("path"):
            result = {
                "repo_ref": "",
                "commit_sha": "",
                "file_ref": self._path_heuristic_file_ref(ev["path"]),
                "line_number": 0,
                "confidence": _CONFIDENCE[_STRATEGY_PATH_HEURISTIC],
                "strategy": _STRATEGY_PATH_HEURISTIC,
            }
            strategy = _STRATEGY_PATH_HEURISTIC

        if result is None:
            return {
                "runtime_event_id": runtime_event_id,
                "matched": False,
                "reason": "no_strategy_applicable",
            }

        match_id = str(uuid.uuid4())
        now = _now_iso()
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO runtime_to_code_matches
                  (id, runtime_event_id, repo_ref, commit_sha, file_ref,
                   line_number, match_confidence, match_strategy, matched_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    match_id,
                    runtime_event_id,
                    result["repo_ref"],
                    result["commit_sha"],
                    result["file_ref"],
                    int(result["line_number"]),
                    float(result["confidence"]),
                    strategy,
                    now,
                ),
            )
            conn.commit()
        self._emit_event(
            "RUNTIME_CODE_MATCH",
            {
                "match_id": match_id,
                "runtime_event_id": runtime_event_id,
                "strategy": strategy,
                "confidence": float(result["confidence"]),
            },
        )
        result.update({"match_id": match_id, "matched": True, "matched_at": now})
        return result

    def bulk_match(self, org_id: str, since_minutes: int = 60) -> Dict[str, Any]:
        """Match all events captured within last N minutes for an org."""
        if since_minutes < 0:
            since_minutes = 0
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=since_minutes)).isoformat()
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT id FROM runtime_events
                 WHERE org_id=? AND captured_at >= ?
                 ORDER BY captured_at DESC
                """,
                (org_id, cutoff),
            ).fetchall()
        matched = 0
        failed = 0
        strategies: Dict[str, int] = {}
        for row in rows:
            try:
                result = self.match_event_to_code(row["id"])
                if result.get("matched"):
                    matched += 1
                    strat = result.get("strategy", "")
                    strategies[strat] = strategies.get(strat, 0) + 1
                else:
                    failed += 1
            except Exception:  # noqa: BLE001
                _logger.exception("bulk_match: failed on event %s", row["id"])
                failed += 1
        return {
            "org_id": org_id,
            "since_minutes": since_minutes,
            "candidates": len(rows),
            "matched": matched,
            "failed": failed,
            "by_strategy": strategies,
        }

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_match_for_event(self, runtime_event_id: str) -> Optional[Dict[str, Any]]:
        with self._conn() as conn:
            row = conn.execute(
                """
                SELECT * FROM runtime_to_code_matches
                 WHERE runtime_event_id=?
                 ORDER BY match_confidence DESC, matched_at DESC
                 LIMIT 1
                """,
                (runtime_event_id,),
            ).fetchone()
        return dict(row) if row else None

    def list_events(
        self,
        org_id: str,
        service_name: Optional[str] = None,
        limit: int = 200,
    ) -> List[Dict[str, Any]]:
        if limit <= 0:
            limit = 200
        with self._conn() as conn:
            if service_name:
                rows = conn.execute(
                    """
                    SELECT * FROM runtime_events
                     WHERE org_id=? AND service_name=?
                     ORDER BY captured_at DESC LIMIT ?
                    """,
                    (org_id, service_name, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT * FROM runtime_events
                     WHERE org_id=?
                     ORDER BY captured_at DESC LIMIT ?
                    """,
                    (org_id, limit),
                ).fetchall()
        return [dict(r) for r in rows]

    def list_matches(
        self,
        org_id: str,
        runtime_event_id: Optional[str] = None,
        limit: int = 200,
    ) -> List[Dict[str, Any]]:
        if limit <= 0:
            limit = 200
        with self._conn() as conn:
            if runtime_event_id:
                rows = conn.execute(
                    """
                    SELECT m.* FROM runtime_to_code_matches m
                     JOIN runtime_events e ON e.id = m.runtime_event_id
                     WHERE e.org_id=? AND m.runtime_event_id=?
                     ORDER BY m.matched_at DESC LIMIT ?
                    """,
                    (org_id, runtime_event_id, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT m.* FROM runtime_to_code_matches m
                     JOIN runtime_events e ON e.id = m.runtime_event_id
                     WHERE e.org_id=?
                     ORDER BY m.matched_at DESC LIMIT ?
                    """,
                    (org_id, limit),
                ).fetchall()
        return [dict(r) for r in rows]

    def stats(self, org_id: str) -> Dict[str, Any]:
        with self._conn() as conn:
            total_events = conn.execute(
                "SELECT COUNT(*) AS c FROM runtime_events WHERE org_id=?",
                (org_id,),
            ).fetchone()["c"]
            total_mappings = conn.execute(
                "SELECT COUNT(*) AS c FROM service_code_mappings WHERE org_id=?",
                (org_id,),
            ).fetchone()["c"]
            match_rows = conn.execute(
                """
                SELECT m.match_strategy AS strat, COUNT(*) AS c, AVG(m.match_confidence) AS avg_conf
                  FROM runtime_to_code_matches m
                  JOIN runtime_events e ON e.id = m.runtime_event_id
                 WHERE e.org_id=?
                 GROUP BY m.match_strategy
                """,
                (org_id,),
            ).fetchall()
            total_matches = conn.execute(
                """
                SELECT COUNT(*) AS c FROM runtime_to_code_matches m
                 JOIN runtime_events e ON e.id = m.runtime_event_id
                 WHERE e.org_id=?
                """,
                (org_id,),
            ).fetchone()["c"]
        by_strategy: Dict[str, Dict[str, float]] = {}
        for row in match_rows:
            by_strategy[row["strat"]] = {
                "count": int(row["c"] or 0),
                "avg_confidence": float(row["avg_conf"] or 0.0),
            }
        coverage = 0.0
        if total_events:
            coverage = round(total_matches / total_events, 4)
        return {
            "org_id": org_id,
            "total_events": int(total_events or 0),
            "total_matches": int(total_matches or 0),
            "total_service_mappings": int(total_mappings or 0),
            "match_coverage": coverage,
            "by_strategy": by_strategy,
        }

    # ------------------------------------------------------------------
    # Event bus
    # ------------------------------------------------------------------

    def _emit_event(self, event_type: str, payload: Dict[str, Any]) -> None:
        if _get_tg_bus is None:
            return
        try:
            bus = _get_tg_bus()
            if bus is not None and hasattr(bus, "emit"):
                bus.emit(event_type, payload)
        except Exception:  # noqa: BLE001
            _logger.debug("trustgraph bus emit failed for %s", event_type)
