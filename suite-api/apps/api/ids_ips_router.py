"""IDS/IPS Rules and Verdicts Router — ALDECI (Multica #3757, 2026-05-31).

Feed and rules management surface for Suricata/Snort rule sets plus a verdict
ingest endpoint. Rules are parsed from raw Suricata/Snort rule text via a
lightweight regex; verdicts are alerts fired by the IDS/IPS sensor layer.

Prefix: /api/v1/ids-ips
Auth:   api_key_auth dependency (read:scans scope at registration)
Storage: SQLite at data/ids_ips.db (thread-safe RLock pattern)

Routes:
  GET  /api/v1/ids-ips/                              router info (rule counts by ruleset, verdicts last 24h)
  POST /api/v1/ids-ips/rules/import                  import multi-line Snort/Suricata rule text
  GET  /api/v1/ids-ips/rules                         list rules (filter by org_id and/or ruleset)
  POST /api/v1/ids-ips/verdicts                      ingest a single verdict (alert event)
  GET  /api/v1/ids-ips/verdicts                      list recent verdicts (filter by org_id, hours, severity)
  DELETE /api/v1/ids-ips/rules/{rule_id}             delete a rule

NO MOCKS rule: all data is read from / written to the live SQLite database.
Bad rule-text lines are skipped with a warning (never 500). When a rule_id is
not found DELETE returns HTTP 404.

Rule parser
-----------
  Regex: ``alert\s+\S+\s+.*?sid\s*:\s*(\d+)\s*;.*?msg\s*:\s*"([^"]+)"``
  One rule per non-empty, non-comment line. Unparseable lines are logged and
  skipped — import still succeeds and returns the count of parsed rows.

Schema
------
  ids_rules    (id, org_id, ruleset, rule_name, sid, rule_text, enabled, imported_at)
  ids_verdicts (id, org_id, rule_id, src_ip, dst_ip, dst_port, protocol,
                ja3, sni, severity, message, detected_at)

  Indexes:
    idx_ids_org_ruleset        ON ids_rules(org_id, ruleset)
    idx_ids_verdict_org_time   ON ids_verdicts(org_id, detected_at DESC)
"""

from __future__ import annotations

import logging
import os
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from apps.api.dependencies import get_org_id
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SQLite DB path — override via env var for tests
# ---------------------------------------------------------------------------

_DEFAULT_DB_PATH = Path("data/ids_ips.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS ids_rules (
  id          TEXT PRIMARY KEY,
  org_id      TEXT NOT NULL,
  ruleset     TEXT NOT NULL,
  rule_name   TEXT NOT NULL,
  sid         INTEGER,
  rule_text   TEXT NOT NULL,
  enabled     INTEGER NOT NULL DEFAULT 1,
  imported_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ids_org_ruleset ON ids_rules(org_id, ruleset);

CREATE TABLE IF NOT EXISTS ids_verdicts (
  id           TEXT PRIMARY KEY,
  org_id       TEXT NOT NULL,
  rule_id      TEXT,
  src_ip       TEXT,
  dst_ip       TEXT,
  dst_port     INTEGER,
  protocol     TEXT,
  ja3          TEXT,
  sni          TEXT,
  severity     TEXT NOT NULL,
  message      TEXT NOT NULL,
  detected_at  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ids_verdict_org_time ON ids_verdicts(org_id, detected_at DESC);
"""

_VALID_RULESETS = {"suricata", "snort", "custom"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}

# Separate regexes to extract sid and msg from a rule line independently.
# Real Snort/Suricata rules have msg before sid in the options list, so we
# cannot rely on ordering. We require both fields to be present for a valid
# parse, but match them independently within the line.
_ALERT_RE = re.compile(r'^alert\s+', re.IGNORECASE)
_SID_RE = re.compile(r'sid\s*:\s*(\d+)\s*;', re.IGNORECASE)
_MSG_RE = re.compile(r'msg\s*:\s*"([^"]+)"', re.IGNORECASE)


# ---------------------------------------------------------------------------
# Thread-safe DB manager
# ---------------------------------------------------------------------------


class _IdsIpsDB:
    """Thread-safe SQLite wrapper for IDS/IPS rules and verdicts."""

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = Path(db_path)
        self._lock = threading.RLock()
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    def _init_schema(self) -> None:
        with self._lock:
            conn = self._connect()
            try:
                conn.executescript(_SCHEMA)
                conn.commit()
            finally:
                conn.close()

    # ------------------------------------------------------------------
    # Rule operations
    # ------------------------------------------------------------------

    def rule_counts_by_ruleset(self, org_id: Optional[str] = None) -> Dict[str, int]:
        """Return {ruleset: count} mapping."""
        with self._lock:
            conn = self._connect()
            try:
                if org_id:
                    rows = conn.execute(
                        "SELECT ruleset, COUNT(*) as cnt FROM ids_rules WHERE org_id=? GROUP BY ruleset",
                        (org_id,),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT ruleset, COUNT(*) as cnt FROM ids_rules GROUP BY ruleset"
                    ).fetchall()
                return {r["ruleset"]: r["cnt"] for r in rows}
            finally:
                conn.close()

    def verdict_count_last_hours(self, hours: int = 24, org_id: Optional[str] = None) -> int:
        cutoff = datetime.now(timezone.utc)
        from datetime import timedelta
        cutoff -= timedelta(hours=hours)
        cutoff_str = cutoff.isoformat()
        with self._lock:
            conn = self._connect()
            try:
                if org_id:
                    count = conn.execute(
                        "SELECT COUNT(*) FROM ids_verdicts WHERE org_id=? AND detected_at >= ?",
                        (org_id, cutoff_str),
                    ).fetchone()[0]
                else:
                    count = conn.execute(
                        "SELECT COUNT(*) FROM ids_verdicts WHERE detected_at >= ?",
                        (cutoff_str,),
                    ).fetchone()[0]
                return count
            finally:
                conn.close()

    def import_rules(self, org_id: str, ruleset: str, rule_text: str) -> int:
        """Parse rule_text line-by-line, insert valid rules, return imported count."""
        now = datetime.now(timezone.utc).isoformat()
        imported = 0
        rows_to_insert = []
        for line in rule_text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if not _ALERT_RE.match(line):
                _logger.warning(
                    "ids_ips_rule_parse_skip ruleset=%s line=%.80r reason=not_alert_rule",
                    ruleset, line,
                )
                continue
            sid_m = _SID_RE.search(line)
            msg_m = _MSG_RE.search(line)
            if not sid_m or not msg_m:
                _logger.warning(
                    "ids_ips_rule_parse_skip ruleset=%s line=%.80r reason=no_sid_msg_match",
                    ruleset, line,
                )
                continue
            rule_name = msg_m.group(1)
            try:
                sid = int(sid_m.group(1))
            except ValueError:
                sid = None
            rows_to_insert.append({
                "id": str(uuid.uuid4()),
                "org_id": org_id,
                "ruleset": ruleset,
                "rule_name": rule_name,
                "sid": sid,
                "rule_text": line,
                "enabled": 1,
                "imported_at": now,
            })

        if rows_to_insert:
            with self._lock:
                conn = self._connect()
                try:
                    conn.executemany(
                        """INSERT INTO ids_rules
                           (id, org_id, ruleset, rule_name, sid, rule_text, enabled, imported_at)
                           VALUES (:id, :org_id, :ruleset, :rule_name, :sid, :rule_text, :enabled, :imported_at)""",
                        rows_to_insert,
                    )
                    conn.commit()
                    imported = len(rows_to_insert)
                finally:
                    conn.close()

        _logger.info(
            "ids_ips_rules_imported org_id=%s ruleset=%s count=%d",
            org_id, ruleset, imported,
        )
        return imported

    def list_rules(self, org_id: str, ruleset: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._connect()
            try:
                if ruleset:
                    rows = conn.execute(
                        "SELECT * FROM ids_rules WHERE org_id=? AND ruleset=? ORDER BY imported_at DESC",
                        (org_id, ruleset),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        "SELECT * FROM ids_rules WHERE org_id=? ORDER BY imported_at DESC",
                        (org_id,),
                    ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()

    def delete_rule(self, rule_id: str) -> bool:
        with self._lock:
            conn = self._connect()
            try:
                result = conn.execute(
                    "DELETE FROM ids_rules WHERE id=?", (rule_id,)
                )
                conn.commit()
                deleted = result.rowcount > 0
            finally:
                conn.close()
        if deleted:
            _logger.info("ids_ips_rule_deleted id=%s", rule_id)
        return deleted

    # ------------------------------------------------------------------
    # Verdict operations
    # ------------------------------------------------------------------

    def create_verdict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        now = datetime.now(timezone.utc).isoformat()
        verdict_id = str(uuid.uuid4())
        row = {
            "id": verdict_id,
            "org_id": data.get("org_id", "default"),
            "rule_id": data.get("rule_id"),
            "src_ip": data.get("src_ip"),
            "dst_ip": data.get("dst_ip"),
            "dst_port": data.get("dst_port"),
            "protocol": data.get("protocol"),
            "ja3": data.get("ja3"),
            "sni": data.get("sni"),
            "severity": data["severity"],
            "message": data["message"],
            "detected_at": now,
        }
        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """INSERT INTO ids_verdicts
                       (id, org_id, rule_id, src_ip, dst_ip, dst_port, protocol,
                        ja3, sni, severity, message, detected_at)
                       VALUES (:id, :org_id, :rule_id, :src_ip, :dst_ip, :dst_port,
                               :protocol, :ja3, :sni, :severity, :message, :detected_at)""",
                    row,
                )
                conn.commit()
            finally:
                conn.close()
        _logger.info(
            "ids_ips_verdict_created id=%s org_id=%s severity=%s",
            verdict_id, row["org_id"], row["severity"],
        )
        return row

    def list_verdicts(
        self,
        org_id: str,
        hours: int = 24,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        from datetime import timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        with self._lock:
            conn = self._connect()
            try:
                if severity:
                    rows = conn.execute(
                        """SELECT * FROM ids_verdicts
                           WHERE org_id=? AND detected_at >= ? AND severity=?
                           ORDER BY detected_at DESC""",
                        (org_id, cutoff, severity),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        """SELECT * FROM ids_verdicts
                           WHERE org_id=? AND detected_at >= ?
                           ORDER BY detected_at DESC""",
                        (org_id, cutoff),
                    ).fetchall()
                return [dict(r) for r in rows]
            finally:
                conn.close()


# Module-level DB instance — lazily initialized
_db: Optional[_IdsIpsDB] = None
_db_lock = threading.Lock()


def _get_db() -> _IdsIpsDB:
    global _db
    with _db_lock:
        if _db is None:
            db_path = os.environ.get("IDS_IPS_DB_PATH", str(_DEFAULT_DB_PATH))
            _db = _IdsIpsDB(db_path)
    return _db


# ---------------------------------------------------------------------------
# FastAPI router
# ---------------------------------------------------------------------------

router = APIRouter(
    prefix="/api/v1/ids-ips",
    tags=["IDS/IPS"],
    dependencies=[Depends(api_key_auth)],
)


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class RouterInfoResponse(BaseModel):
    service: str = "IDS/IPS Rules and Verdicts"
    prefix: str = "/api/v1/ids-ips"
    endpoints: List[str]
    rule_counts_by_ruleset: Dict[str, int]
    verdicts_last_24h: int
    status: str  # ok | empty


class ImportRulesRequest(BaseModel):
    org_id: str = Field(default="default", min_length=1, max_length=256)
    ruleset: str = Field(..., description="'suricata' | 'snort' | 'custom'")
    rule_text: str = Field(..., min_length=1, description="Raw rule text (one or more lines)")


class ImportRulesResponse(BaseModel):
    imported: int
    ruleset: str
    org_id: str


class IdsRuleResponse(BaseModel):
    id: str
    org_id: str
    ruleset: str
    rule_name: str
    sid: Optional[int] = None
    rule_text: str
    enabled: int
    imported_at: str


class RulesListResponse(BaseModel):
    rules: List[IdsRuleResponse]
    count: int


class CreateVerdictRequest(BaseModel):
    org_id: str = Field(default="default", min_length=1, max_length=256)
    rule_id: Optional[str] = Field(None, max_length=36, description="FK to ids_rules.id if known")
    src_ip: Optional[str] = Field(None, max_length=45)
    dst_ip: Optional[str] = Field(None, max_length=45)
    dst_port: Optional[int] = Field(None, ge=1, le=65535)
    protocol: Optional[str] = Field(None, max_length=16)
    ja3: Optional[str] = Field(None, max_length=32, description="JA3 TLS fingerprint")
    sni: Optional[str] = Field(None, max_length=253, description="TLS SNI hostname")
    severity: str = Field(..., description="critical | high | medium | low")
    message: str = Field(..., min_length=1, max_length=1024)


class VerdictResponse(BaseModel):
    id: str
    org_id: str
    rule_id: Optional[str] = None
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    protocol: Optional[str] = None
    ja3: Optional[str] = None
    sni: Optional[str] = None
    severity: str
    message: str
    detected_at: str


class VerdictListResponse(BaseModel):
    verdicts: List[VerdictResponse]
    count: int


# ---------------------------------------------------------------------------
# GET / — router info
# ---------------------------------------------------------------------------


@router.get("/", response_model=RouterInfoResponse)
async def router_info() -> RouterInfoResponse:
    """Return info about the IDS/IPS surface.

    Always returns 200. Reports rule counts per ruleset and verdicts in the
    last 24 hours across all orgs.
    """
    db = _get_db()
    rule_counts = db.rule_counts_by_ruleset()
    verdict_count = db.verdict_count_last_hours(24)
    total_rules = sum(rule_counts.values())
    status = "ok" if total_rules > 0 else "empty"
    _logger.info(
        "ids_ips_info total_rules=%d verdicts_24h=%d",
        total_rules, verdict_count,
    )
    return RouterInfoResponse(
        endpoints=[
            "POST   /rules/import",
            "GET    /rules?org_id=&ruleset=",
            "DELETE /rules/{rule_id}",
            "POST   /verdicts",
            "GET    /verdicts?org_id=&hours=24&severity=",
        ],
        rule_counts_by_ruleset=rule_counts,
        verdicts_last_24h=verdict_count,
        status=status,
    )


# ---------------------------------------------------------------------------
# POST /rules/import — parse and bulk-import rules
# ---------------------------------------------------------------------------


@router.post("/rules/import", response_model=ImportRulesResponse)
async def import_rules(body: ImportRulesRequest) -> ImportRulesResponse:
    """Import one or more Snort/Suricata rules from raw rule text.

    Parses each non-empty, non-comment line for ``sid`` and ``msg`` fields.
    Lines that do not match are skipped with a warning (never 500).
    Returns the count of successfully imported rows.

    Accepted ruleset values: 'suricata', 'snort', 'custom'.
    """
    if body.ruleset not in _VALID_RULESETS:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "invalid_ruleset",
                "allowed": sorted(_VALID_RULESETS),
                "received": body.ruleset,
            },
        )
    db = _get_db()
    imported = db.import_rules(body.org_id, body.ruleset, body.rule_text)
    return ImportRulesResponse(imported=imported, ruleset=body.ruleset, org_id=body.org_id)


# ---------------------------------------------------------------------------
# GET /rules — list rules
# ---------------------------------------------------------------------------


@router.get("/rules", response_model=RulesListResponse)
async def list_rules(
    org_id: str = Depends(get_org_id),
    ruleset: Optional[str] = Query(None, description="Filter by ruleset: suricata | snort | custom"),
) -> RulesListResponse:
    """List IDS/IPS rules, optionally filtered by ruleset."""
    if ruleset is not None and ruleset not in _VALID_RULESETS:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "invalid_ruleset",
                "allowed": sorted(_VALID_RULESETS),
                "received": ruleset,
            },
        )
    db = _get_db()
    rows = db.list_rules(org_id, ruleset)
    _logger.info(
        "ids_ips_list_rules org_id=%s ruleset=%s count=%d",
        org_id, ruleset, len(rows),
    )
    return RulesListResponse(
        rules=[IdsRuleResponse(**r) for r in rows],
        count=len(rows),
    )


# ---------------------------------------------------------------------------
# POST /verdicts — ingest a verdict
# ---------------------------------------------------------------------------


@router.post("/verdicts", response_model=VerdictResponse, status_code=201)
async def create_verdict(body: CreateVerdictRequest) -> VerdictResponse:
    """Ingest a single IDS/IPS verdict (alert event).

    HTTP 422 when severity is not one of 'critical', 'high', 'medium', 'low'.
    """
    if body.severity not in _VALID_SEVERITIES:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "invalid_severity",
                "allowed": sorted(_VALID_SEVERITIES),
                "received": body.severity,
            },
        )
    db = _get_db()
    created = db.create_verdict(body.model_dump())
    return VerdictResponse(**created)


# ---------------------------------------------------------------------------
# GET /verdicts — list recent verdicts
# ---------------------------------------------------------------------------


@router.get("/verdicts", response_model=VerdictListResponse)
async def list_verdicts(
    org_id: str = Depends(get_org_id),
    hours: int = Query(default=24, ge=1, le=8760, description="Look-back window in hours (max 365d)"),
    severity: Optional[str] = Query(None, description="Filter by severity: critical | high | medium | low"),
) -> VerdictListResponse:
    """List recent verdicts within the specified time window."""
    if severity is not None and severity not in _VALID_SEVERITIES:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "invalid_severity",
                "allowed": sorted(_VALID_SEVERITIES),
                "received": severity,
            },
        )
    db = _get_db()
    rows = db.list_verdicts(org_id, hours, severity)
    _logger.info(
        "ids_ips_list_verdicts org_id=%s hours=%d severity=%s count=%d",
        org_id, hours, severity, len(rows),
    )
    return VerdictListResponse(
        verdicts=[VerdictResponse(**r) for r in rows],
        count=len(rows),
    )


# ---------------------------------------------------------------------------
# DELETE /rules/{rule_id} — delete a rule
# ---------------------------------------------------------------------------


@router.delete("/rules/{rule_id}", status_code=204)
async def delete_rule(rule_id: str) -> None:
    """Hard-delete an IDS/IPS rule by its UUID.

    Returns HTTP 204 on success, HTTP 404 when rule_id does not exist.
    """
    db = _get_db()
    deleted = db.delete_rule(rule_id)
    if not deleted:
        raise HTTPException(
            status_code=404,
            detail={"error": "rule_not_found", "rule_id": rule_id},
        )


__all__ = ["router"]
