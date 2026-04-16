"""API abuse detection engine — detect brute force, scraping, DDoS, credential stuffing."""
from __future__ import annotations

import json
import sqlite3
import threading
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import structlog

_logger = structlog.get_logger()

_DEFAULT_DB = str(Path(__file__).resolve().parents[2] / "data" / "api_abuse.db")

ABUSE_PATTERNS = [
    "brute_force",
    "credential_stuffing",
    "scraping",
    "ddos",
    "bot_traffic",
    "anomalous_spike",
    "suspicious_user_agent",
]
SEVERITY_LEVELS = ["low", "medium", "high", "critical"]

# Detection thresholds
_BRUTE_FORCE_RPM = 100          # >100 requests/min from same IP
_CRED_STUFF_FAILS = 10          # >10 failed auth in 5 min
_CRED_STUFF_WINDOW_MIN = 5
_SCRAPING_RPH = 500             # >500 req/hour to same endpoint
_DDOS_RPM = 1000                # >1000 req/min
_BOT_AGENTS = ("bot", "crawler", "spider", "scraper", "wget", "curl/")
_SPIKE_MULTIPLIER = 3.0         # response time >3x avg


class APIAbuseDetector:
    """SQLite-backed API abuse detection engine. Thread-safe via RLock."""

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
            conn.executescript(
                """
                PRAGMA journal_mode=WAL;

                CREATE TABLE IF NOT EXISTS request_log (
                    id          TEXT PRIMARY KEY,
                    ip          TEXT NOT NULL,
                    endpoint    TEXT NOT NULL DEFAULT '',
                    user_agent  TEXT NOT NULL DEFAULT '',
                    status_code INTEGER NOT NULL DEFAULT 200,
                    api_key     TEXT NOT NULL DEFAULT '',
                    response_ms INTEGER NOT NULL DEFAULT 0,
                    org_id      TEXT NOT NULL DEFAULT 'default',
                    recorded_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_rl_ip       ON request_log(ip, recorded_at);
                CREATE INDEX IF NOT EXISTS idx_rl_ak       ON request_log(api_key, recorded_at);
                CREATE INDEX IF NOT EXISTS idx_rl_ep       ON request_log(endpoint, recorded_at);
                CREATE INDEX IF NOT EXISTS idx_rl_org      ON request_log(org_id, recorded_at);

                CREATE TABLE IF NOT EXISTS abuse_events (
                    event_id    TEXT PRIMARY KEY,
                    pattern     TEXT NOT NULL,
                    severity    TEXT NOT NULL,
                    ip          TEXT NOT NULL DEFAULT '',
                    api_key     TEXT NOT NULL DEFAULT '',
                    evidence    TEXT NOT NULL DEFAULT '{}',
                    org_id      TEXT NOT NULL DEFAULT 'default',
                    detected_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ae_ip  ON abuse_events(ip);
                CREATE INDEX IF NOT EXISTS idx_ae_ak  ON abuse_events(api_key);
                CREATE INDEX IF NOT EXISTS idx_ae_org ON abuse_events(org_id);

                CREATE TABLE IF NOT EXISTS block_list (
                    ip          TEXT NOT NULL,
                    org_id      TEXT NOT NULL DEFAULT 'default',
                    reason      TEXT NOT NULL DEFAULT '',
                    blocked_at  TEXT NOT NULL,
                    blocked_until TEXT NOT NULL,
                    PRIMARY KEY (ip, org_id)
                );
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Request recording
    # ------------------------------------------------------------------

    def record_request(
        self,
        ip: str,
        endpoint: str,
        user_agent: str = "",
        status_code: int = 200,
        api_key: str = "",
        response_time_ms: int = 0,
        org_id: str = "default",
    ) -> str:
        """Log an API request. Returns request_id."""
        request_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO request_log
                        (id, ip, endpoint, user_agent, status_code, api_key,
                         response_ms, org_id, recorded_at)
                    VALUES (?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        request_id,
                        ip,
                        endpoint,
                        user_agent,
                        status_code,
                        api_key,
                        response_time_ms,
                        org_id,
                        now,
                    ),
                )
        _logger.debug("api_abuse.request_recorded", request_id=request_id, ip=ip)
        return request_id

    # ------------------------------------------------------------------
    # Abuse detection
    # ------------------------------------------------------------------

    def detect_abuse(
        self,
        ip: Optional[str] = None,
        api_key: Optional[str] = None,
        window_minutes: int = 60,
        org_id: str = "default",
    ) -> List[Dict[str, Any]]:
        """Run abuse detection for an IP or API key over a time window.

        Returns list of detected abuse events:
        [{event_id, pattern, severity, ip, evidence: dict, detected_at}]

        Detection rules:
        - >100 requests/min from same IP → brute_force (high)
        - >10 failed auth (401/403) in 5 min → credential_stuffing (critical)
        - >500 requests/hour to same endpoint → scraping (medium)
        - >1000 requests/min → ddos (critical)
        - User agent contains "bot", "crawler", "spider" → bot_traffic (low)
        - Response time spike >3x avg → anomalous_spike (medium)
        """
        events: List[Dict[str, Any]] = []
        since = (
            datetime.now(timezone.utc) - timedelta(minutes=window_minutes)
        ).isoformat()

        with self._lock:
            with self._conn() as conn:
                # Build WHERE clause based on filters
                clauses = ["org_id = ?", "recorded_at >= ?"]
                params: List[Any] = [org_id, since]
                if ip:
                    clauses.append("ip = ?")
                    params.append(ip)
                if api_key:
                    clauses.append("api_key = ?")
                    params.append(api_key)
                where = " AND ".join(clauses)

                rows = conn.execute(
                    f"SELECT * FROM request_log WHERE {where} ORDER BY recorded_at",  # nosec B608
                    params,
                ).fetchall()

        if not rows:
            return []

        events.extend(self._check_brute_force(rows, org_id))
        events.extend(self._check_credential_stuffing(rows, org_id))
        events.extend(self._check_scraping(rows, org_id))
        events.extend(self._check_ddos(rows, org_id))
        events.extend(self._check_bot_traffic(rows, org_id))
        events.extend(self._check_anomalous_spike(rows, org_id))

        # Persist detected events
        if events:
            with self._lock:
                with self._conn() as conn:
                    for ev in events:
                        conn.execute(
                            """
                            INSERT OR IGNORE INTO abuse_events
                                (event_id, pattern, severity, ip, api_key,
                                 evidence, org_id, detected_at)
                            VALUES (?,?,?,?,?,?,?,?)
                            """,
                            (
                                ev["event_id"],
                                ev["pattern"],
                                ev["severity"],
                                ev.get("ip", ""),
                                ev.get("api_key", ""),
                                json.dumps(ev.get("evidence", {})),
                                org_id,
                                ev["detected_at"],
                            ),
                        )

        return events

    # ------------------------------------------------------------------
    # Detection helpers
    # ------------------------------------------------------------------

    def _check_brute_force(
        self, rows: List[sqlite3.Row], org_id: str
    ) -> List[Dict[str, Any]]:
        """More than _BRUTE_FORCE_RPM requests per minute from the same IP."""
        events = []
        # Group by ip + minute bucket
        ip_minute: Dict[str, int] = {}
        for r in rows:
            # truncate to minute: first 16 chars of ISO timestamp
            bucket = f"{r['ip']}|{r['recorded_at'][:16]}"
            ip_minute[bucket] = ip_minute.get(bucket, 0) + 1

        for bucket, count in ip_minute.items():
            if count > _BRUTE_FORCE_RPM:
                ip_part = bucket.split("|")[0]
                events.append(
                    self._make_event(
                        "brute_force",
                        "high",
                        ip=ip_part,
                        evidence={"requests_per_minute": count, "threshold": _BRUTE_FORCE_RPM},
                    )
                )
        return events

    def _check_credential_stuffing(
        self, rows: List[sqlite3.Row], org_id: str
    ) -> List[Dict[str, Any]]:
        """More than _CRED_STUFF_FAILS 401/403 responses in 5-minute window from same IP."""
        events = []
        # Bucket by ip + 5-min window (minutes truncated to nearest 5)
        ip_fails: Dict[str, int] = {}
        for r in rows:
            if r["status_code"] in (401, 403):
                # 5-minute bucket: group by floor(minute / 5)
                dt_str = r["recorded_at"][:16]  # "YYYY-MM-DDTHH:MM"
                minute = int(dt_str[-2:])
                bucket_min = (minute // _CRED_STUFF_WINDOW_MIN) * _CRED_STUFF_WINDOW_MIN
                bucket = f"{r['ip']}|{dt_str[:-2]}{bucket_min:02d}"
                ip_fails[bucket] = ip_fails.get(bucket, 0) + 1

        for bucket, count in ip_fails.items():
            if count > _CRED_STUFF_FAILS:
                ip_part = bucket.split("|")[0]
                events.append(
                    self._make_event(
                        "credential_stuffing",
                        "critical",
                        ip=ip_part,
                        evidence={
                            "failed_auth_count": count,
                            "threshold": _CRED_STUFF_FAILS,
                            "window_minutes": _CRED_STUFF_WINDOW_MIN,
                        },
                    )
                )
        return events

    def _check_scraping(
        self, rows: List[sqlite3.Row], org_id: str
    ) -> List[Dict[str, Any]]:
        """More than _SCRAPING_RPH requests/hour to same endpoint (by any IP)."""
        events = []
        # Bucket by endpoint + hour
        ep_hour: Dict[str, int] = {}
        for r in rows:
            bucket = f"{r['endpoint']}|{r['recorded_at'][:13]}"  # YYYY-MM-DDTHH
            ep_hour[bucket] = ep_hour.get(bucket, 0) + 1

        for bucket, count in ep_hour.items():
            if count > _SCRAPING_RPH:
                ep_part = bucket.split("|")[0]
                events.append(
                    self._make_event(
                        "scraping",
                        "medium",
                        evidence={
                            "endpoint": ep_part,
                            "requests_per_hour": count,
                            "threshold": _SCRAPING_RPH,
                        },
                    )
                )
        return events

    def _check_ddos(
        self, rows: List[sqlite3.Row], org_id: str
    ) -> List[Dict[str, Any]]:
        """More than _DDOS_RPM total requests per minute (any IP)."""
        events = []
        minute_counts: Dict[str, int] = {}
        for r in rows:
            bucket = r["recorded_at"][:16]
            minute_counts[bucket] = minute_counts.get(bucket, 0) + 1

        for bucket, count in minute_counts.items():
            if count > _DDOS_RPM:
                events.append(
                    self._make_event(
                        "ddos",
                        "critical",
                        evidence={
                            "requests_per_minute": count,
                            "threshold": _DDOS_RPM,
                            "time_bucket": bucket,
                        },
                    )
                )
        return events

    def _check_bot_traffic(
        self, rows: List[sqlite3.Row], org_id: str
    ) -> List[Dict[str, Any]]:
        """User agent contains known bot strings."""
        events = []
        seen_ips: set = set()
        for r in rows:
            ua = (r["user_agent"] or "").lower()
            if any(bot in ua for bot in _BOT_AGENTS) and r["ip"] not in seen_ips:
                seen_ips.add(r["ip"])
                events.append(
                    self._make_event(
                        "bot_traffic",
                        "low",
                        ip=r["ip"],
                        evidence={"user_agent": r["user_agent"]},
                    )
                )
        return events

    def _check_anomalous_spike(
        self, rows: List[sqlite3.Row], org_id: str
    ) -> List[Dict[str, Any]]:
        """Response time >3x average for an IP."""
        events = []
        # Compute per-IP avg response time
        ip_times: Dict[str, List[int]] = {}
        for r in rows:
            ip_times.setdefault(r["ip"], []).append(r["response_ms"])

        for ip_addr, times in ip_times.items():
            if len(times) < 2:
                continue
            avg = sum(times) / len(times)
            if avg == 0:
                continue
            max_time = max(times)
            if max_time > _SPIKE_MULTIPLIER * avg:
                events.append(
                    self._make_event(
                        "anomalous_spike",
                        "medium",
                        ip=ip_addr,
                        evidence={
                            "avg_response_ms": round(avg, 1),
                            "max_response_ms": max_time,
                            "spike_multiplier": round(max_time / avg, 2),
                            "threshold_multiplier": _SPIKE_MULTIPLIER,
                        },
                    )
                )
        return events

    def _make_event(
        self,
        pattern: str,
        severity: str,
        ip: str = "",
        api_key: str = "",
        evidence: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        return {
            "event_id": str(uuid.uuid4()),
            "pattern": pattern,
            "severity": severity,
            "ip": ip,
            "api_key": api_key,
            "evidence": evidence or {},
            "detected_at": datetime.now(timezone.utc).isoformat(),
        }

    # ------------------------------------------------------------------
    # Query abuse events
    # ------------------------------------------------------------------

    def get_abuse_events(
        self,
        ip: Optional[str] = None,
        api_key: Optional[str] = None,
        pattern: Optional[str] = None,
        org_id: str = "default",
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        clauses = ["org_id = ?"]
        params: List[Any] = [org_id]
        if ip:
            clauses.append("ip = ?")
            params.append(ip)
        if api_key:
            clauses.append("api_key = ?")
            params.append(api_key)
        if pattern:
            clauses.append("pattern = ?")
            params.append(pattern)
        where = " AND ".join(clauses)
        params.append(limit)

        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    f"""SELECT * FROM abuse_eventsWHERE {where}
                    ORDER BY detected_at DESC
                    LIMIT ?
                    """,  # nosec B608
                    params,
                ).fetchall()

        return [self._row_to_event(r) for r in rows]

    def _row_to_event(self, r: sqlite3.Row) -> Dict[str, Any]:
        return {
            "event_id": r["event_id"],
            "pattern": r["pattern"],
            "severity": r["severity"],
            "ip": r["ip"],
            "api_key": r["api_key"],
            "evidence": json.loads(r["evidence"]),
            "org_id": r["org_id"],
            "detected_at": r["detected_at"],
        }

    # ------------------------------------------------------------------
    # Block list
    # ------------------------------------------------------------------

    def block_ip(
        self,
        ip: str,
        reason: str,
        duration_hours: int = 24,
        org_id: str = "default",
    ) -> Dict[str, Any]:
        """Add IP to block list. Returns block record."""
        now = datetime.now(timezone.utc)
        until = now + timedelta(hours=duration_hours)
        record = {
            "ip": ip,
            "org_id": org_id,
            "reason": reason,
            "blocked_at": now.isoformat(),
            "blocked_until": until.isoformat(),
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT OR REPLACE INTO block_list
                        (ip, org_id, reason, blocked_at, blocked_until)
                    VALUES (?,?,?,?,?)
                    """,
                    (ip, org_id, reason, record["blocked_at"], record["blocked_until"]),
                )
        _logger.info("api_abuse.ip_blocked", ip=ip, until=record["blocked_until"])
        return record

    def is_blocked(self, ip: str, org_id: str = "default") -> Dict[str, Any]:
        """Check if IP is currently blocked. Returns {blocked, reason, until}."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    """
                    SELECT reason, blocked_until FROM block_list
                    WHERE ip = ? AND org_id = ? AND blocked_until > ?
                    """,
                    (ip, org_id, now),
                ).fetchone()

        if row:
            return {"blocked": True, "reason": row["reason"], "until": row["blocked_until"]}
        return {"blocked": False, "reason": "", "until": ""}

    def unblock_ip(self, ip: str, org_id: str = "default") -> bool:
        """Remove IP from block list. Returns True if it was blocked."""
        with self._lock:
            with self._conn() as conn:
                result = conn.execute(
                    "DELETE FROM block_list WHERE ip = ? AND org_id = ?",
                    (ip, org_id),
                )
        unblocked = result.rowcount > 0
        if unblocked:
            _logger.info("api_abuse.ip_unblocked", ip=ip)
        return unblocked

    def get_block_list(self, org_id: str = "default") -> List[Dict[str, Any]]:
        """Return all currently active (not expired) blocked IPs."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    """
                    SELECT ip, org_id, reason, blocked_at, blocked_until
                    FROM block_list
                    WHERE org_id = ? AND blocked_until > ?
                    ORDER BY blocked_at DESC
                    """,
                    (org_id, now),
                ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def get_stats(self, org_id: str = "default") -> Dict[str, Any]:
        """Return summary statistics for the org."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._conn() as conn:
                total_requests = conn.execute(
                    "SELECT COUNT(*) FROM request_log WHERE org_id = ?", (org_id,)
                ).fetchone()[0]

                total_abuse = conn.execute(
                    "SELECT COUNT(*) FROM abuse_events WHERE org_id = ?", (org_id,)
                ).fetchone()[0]

                blocked_ips = conn.execute(
                    "SELECT COUNT(*) FROM block_list WHERE org_id = ? AND blocked_until > ?",
                    (org_id, now),
                ).fetchone()[0]

                pattern_rows = conn.execute(
                    """
                    SELECT pattern, COUNT(*) as cnt FROM abuse_events
                    WHERE org_id = ? GROUP BY pattern
                    """,
                    (org_id,),
                ).fetchall()

                top_ip_rows = conn.execute(
                    """
                    SELECT ip, COUNT(*) as cnt FROM abuse_events
                    WHERE org_id = ? AND ip != ''
                    GROUP BY ip ORDER BY cnt DESC LIMIT 10
                    """,
                    (org_id,),
                ).fetchall()

        return {
            "total_requests": total_requests,
            "total_abuse_events": total_abuse,
            "blocked_ips": blocked_ips,
            "abuse_by_pattern": {r["pattern"]: r["cnt"] for r in pattern_rows},
            "top_abusing_ips": [{"ip": r["ip"], "count": r["cnt"]} for r in top_ip_rows],
        }
