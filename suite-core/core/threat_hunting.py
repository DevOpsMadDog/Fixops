"""Threat Hunting Engine — predefined hunt queries, session tracking, and IOC correlation.

Provides:
- 15+ built-in MITRE ATT&CK-mapped hunt queries
- Custom query creation
- Hunt session lifecycle (start, run, end)
- Query matching against findings and IOCs
- IOC cross-correlation
- Finding promotion from hunt results
- Per-org statistics

Storage: SQLite (same pattern as feed_manager.py).
"""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

_DEFAULT_DB = "data/threat_hunting.db"


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class HuntCategory(str, Enum):
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    PERSISTENCE = "persistence"
    COMMAND_AND_CONTROL = "command_and_control"
    CREDENTIAL_ACCESS = "credential_access"
    INITIAL_ACCESS = "initial_access"
    DEFENSE_EVASION = "defense_evasion"


class HuntStatus(str, Enum):
    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class HuntQuery(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    category: HuntCategory
    mitre_tactic: str
    query_logic: Dict[str, Any] = Field(default_factory=dict)
    severity: str = "medium"
    built_in: bool = False


class HuntResult(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    hunt_id: str
    finding_id: Optional[str] = None
    ioc_matches: List[Dict[str, Any]] = Field(default_factory=list)
    evidence: Dict[str, Any] = Field(default_factory=dict)
    confidence: float = Field(0.5, ge=0.0, le=1.0)
    detected_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class HuntSession(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    hunter_email: str
    status: HuntStatus = HuntStatus.CREATED
    queries_run: List[str] = Field(default_factory=list)
    results_count: int = 0
    started_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    completed_at: Optional[str] = None
    notes: str = ""
    org_id: str = "default"


# ---------------------------------------------------------------------------
# Built-in hunt queries (15 queries covering all 8 MITRE ATT&CK tactics)
# ---------------------------------------------------------------------------

_BUILTIN_QUERIES: List[Dict[str, Any]] = [
    # LATERAL_MOVEMENT
    {
        "id": "builtin-lm-001",
        "name": "Suspicious SMB Lateral Movement",
        "description": "Detects SMB-based lateral movement via pass-the-hash or admin share access",
        "category": HuntCategory.LATERAL_MOVEMENT,
        "mitre_tactic": "TA0008",
        "query_logic": {
            "any": [
                {"field": "type", "contains": "smb"},
                {"field": "title", "contains": "lateral"},
                {"field": "tags", "contains": "lateral-movement"},
            ]
        },
        "severity": "high",
        "built_in": True,
    },
    {
        "id": "builtin-lm-002",
        "name": "RDP Brute Force Lateral Movement",
        "description": "Detects RDP-based lateral movement patterns via repeated authentication attempts",
        "category": HuntCategory.LATERAL_MOVEMENT,
        "mitre_tactic": "TA0008",
        "query_logic": {
            "any": [
                {"field": "type", "contains": "rdp"},
                {"field": "title", "contains": "brute"},
                {"field": "description", "contains": "lateral movement"},
            ]
        },
        "severity": "high",
        "built_in": True,
    },
    # PRIVILEGE_ESCALATION
    {
        "id": "builtin-pe-001",
        "name": "Sudo Abuse / Privilege Escalation",
        "description": "Detects sudo misuse and SUID binary abuse for privilege escalation",
        "category": HuntCategory.PRIVILEGE_ESCALATION,
        "mitre_tactic": "TA0004",
        "query_logic": {
            "any": [
                {"field": "type", "contains": "privilege"},
                {"field": "title", "contains": "escalation"},
                {"field": "tags", "contains": "privilege-escalation"},
                {"field": "title", "contains": "sudo"},
            ]
        },
        "severity": "critical",
        "built_in": True,
    },
    {
        "id": "builtin-pe-002",
        "name": "Token Impersonation",
        "description": "Detects Windows token impersonation and process injection for privilege escalation",
        "category": HuntCategory.PRIVILEGE_ESCALATION,
        "mitre_tactic": "TA0004",
        "query_logic": {
            "any": [
                {"field": "title", "contains": "impersonat"},
                {"field": "description", "contains": "token"},
                {"field": "type", "contains": "injection"},
            ]
        },
        "severity": "critical",
        "built_in": True,
    },
    # DATA_EXFILTRATION
    {
        "id": "builtin-de-001",
        "name": "Large Data Transfer / Exfiltration",
        "description": "Detects abnormally large outbound data transfers indicative of exfiltration",
        "category": HuntCategory.DATA_EXFILTRATION,
        "mitre_tactic": "TA0010",
        "query_logic": {
            "any": [
                {"field": "type", "contains": "exfil"},
                {"field": "title", "contains": "exfiltration"},
                {"field": "tags", "contains": "data-exfiltration"},
                {"field": "description", "contains": "data transfer"},
            ]
        },
        "severity": "critical",
        "built_in": True,
    },
    # PERSISTENCE
    {
        "id": "builtin-ps-001",
        "name": "Scheduled Task / Cron Persistence",
        "description": "Detects persistence via scheduled tasks, cron jobs, or startup scripts",
        "category": HuntCategory.PERSISTENCE,
        "mitre_tactic": "TA0003",
        "query_logic": {
            "any": [
                {"field": "title", "contains": "cron"},
                {"field": "title", "contains": "scheduled task"},
                {"field": "tags", "contains": "persistence"},
                {"field": "description", "contains": "startup"},
            ]
        },
        "severity": "high",
        "built_in": True,
    },
    {
        "id": "builtin-ps-002",
        "name": "Registry Run Key Persistence",
        "description": "Detects Windows registry run key manipulation for persistence",
        "category": HuntCategory.PERSISTENCE,
        "mitre_tactic": "TA0003",
        "query_logic": {
            "any": [
                {"field": "title", "contains": "registry"},
                {"field": "description", "contains": "run key"},
                {"field": "type", "contains": "registry"},
            ]
        },
        "severity": "high",
        "built_in": True,
    },
    # COMMAND_AND_CONTROL
    {
        "id": "builtin-c2-001",
        "name": "Beaconing / C2 Communication",
        "description": "Detects periodic beaconing patterns and known C2 communication channels",
        "category": HuntCategory.COMMAND_AND_CONTROL,
        "mitre_tactic": "TA0011",
        "query_logic": {
            "any": [
                {"field": "type", "contains": "c2"},
                {"field": "title", "contains": "beacon"},
                {"field": "tags", "contains": "command-and-control"},
                {"field": "description", "contains": "c2"},
            ]
        },
        "severity": "critical",
        "built_in": True,
    },
    {
        "id": "builtin-c2-002",
        "name": "DNS Tunneling",
        "description": "Detects DNS tunneling used for covert C2 communication or data exfiltration",
        "category": HuntCategory.COMMAND_AND_CONTROL,
        "mitre_tactic": "TA0011",
        "query_logic": {
            "any": [
                {"field": "title", "contains": "dns tunnel"},
                {"field": "description", "contains": "dns tunneling"},
                {"field": "type", "contains": "dns"},
            ]
        },
        "severity": "high",
        "built_in": True,
    },
    # CREDENTIAL_ACCESS
    {
        "id": "builtin-ca-001",
        "name": "Credential Dumping",
        "description": "Detects credential dumping via LSASS, SAM database, or memory scraping",
        "category": HuntCategory.CREDENTIAL_ACCESS,
        "mitre_tactic": "TA0006",
        "query_logic": {
            "any": [
                {"field": "title", "contains": "credential"},
                {"field": "title", "contains": "lsass"},
                {"field": "tags", "contains": "credential-access"},
                {"field": "description", "contains": "password dump"},
            ]
        },
        "severity": "critical",
        "built_in": True,
    },
    {
        "id": "builtin-ca-002",
        "name": "Kerberoasting",
        "description": "Detects Kerberos ticket-granting ticket abuse for offline password cracking",
        "category": HuntCategory.CREDENTIAL_ACCESS,
        "mitre_tactic": "TA0006",
        "query_logic": {
            "any": [
                {"field": "title", "contains": "kerberos"},
                {"field": "description", "contains": "kerberoast"},
                {"field": "type", "contains": "kerberos"},
            ]
        },
        "severity": "high",
        "built_in": True,
    },
    # INITIAL_ACCESS
    {
        "id": "builtin-ia-001",
        "name": "Phishing / Spearphishing Indicators",
        "description": "Detects phishing-related indicators including malicious attachments and links",
        "category": HuntCategory.INITIAL_ACCESS,
        "mitre_tactic": "TA0001",
        "query_logic": {
            "any": [
                {"field": "type", "contains": "phishing"},
                {"field": "title", "contains": "phish"},
                {"field": "tags", "contains": "initial-access"},
                {"field": "description", "contains": "spearphish"},
            ]
        },
        "severity": "high",
        "built_in": True,
    },
    {
        "id": "builtin-ia-002",
        "name": "Exposed Public-Facing Service Exploitation",
        "description": "Detects exploitation of internet-facing services as initial access vector",
        "category": HuntCategory.INITIAL_ACCESS,
        "mitre_tactic": "TA0001",
        "query_logic": {
            "any": [
                {"field": "tags", "contains": "internet-facing"},
                {"field": "tags", "contains": "external"},
                {"field": "severity", "equals": "critical"},
            ],
            "all": [
                {"field": "title", "contains_any": ["exploit", "rce", "injection", "overflow"]}
            ],
        },
        "severity": "critical",
        "built_in": True,
    },
    # DEFENSE_EVASION
    {
        "id": "builtin-dv-001",
        "name": "Log Clearing / Audit Log Tampering",
        "description": "Detects clearing of security event logs and audit log tampering",
        "category": HuntCategory.DEFENSE_EVASION,
        "mitre_tactic": "TA0005",
        "query_logic": {
            "any": [
                {"field": "title", "contains": "log clear"},
                {"field": "title", "contains": "audit"},
                {"field": "tags", "contains": "defense-evasion"},
                {"field": "description", "contains": "log tamper"},
            ]
        },
        "severity": "high",
        "built_in": True,
    },
    {
        "id": "builtin-dv-002",
        "name": "Obfuscated Malicious Code",
        "description": "Detects obfuscation techniques used to evade detection (base64, encoding, packing)",
        "category": HuntCategory.DEFENSE_EVASION,
        "mitre_tactic": "TA0005",
        "query_logic": {
            "any": [
                {"field": "title", "contains": "obfuscat"},
                {"field": "description", "contains": "base64"},
                {"field": "type", "contains": "obfuscat"},
                {"field": "description", "contains": "encoded payload"},
            ]
        },
        "severity": "high",
        "built_in": True,
    },
]


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------


class ThreatHuntingEngine:
    """SQLite-backed threat hunting engine with predefined MITRE ATT&CK queries."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        self._db_path = db_path or _DEFAULT_DB
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ------------------------------------------------------------------
    # DB helpers
    # ------------------------------------------------------------------

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._get_conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS hunt_queries (
                    id          TEXT PRIMARY KEY,
                    name        TEXT NOT NULL,
                    description TEXT NOT NULL DEFAULT '',
                    category    TEXT NOT NULL,
                    mitre_tactic TEXT NOT NULL DEFAULT '',
                    query_logic TEXT NOT NULL DEFAULT '{}',
                    severity    TEXT NOT NULL DEFAULT 'medium',
                    built_in    INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS hunt_sessions (
                    id           TEXT PRIMARY KEY,
                    name         TEXT NOT NULL,
                    hunter_email TEXT NOT NULL,
                    status       TEXT NOT NULL DEFAULT 'created',
                    queries_run  TEXT NOT NULL DEFAULT '[]',
                    results_count INTEGER NOT NULL DEFAULT 0,
                    started_at   TEXT NOT NULL,
                    completed_at TEXT,
                    notes        TEXT NOT NULL DEFAULT '',
                    org_id       TEXT NOT NULL DEFAULT 'default'
                );
                CREATE INDEX IF NOT EXISTS idx_sessions_org ON hunt_sessions(org_id);
                CREATE INDEX IF NOT EXISTS idx_sessions_status ON hunt_sessions(status);

                CREATE TABLE IF NOT EXISTS hunt_results (
                    id          TEXT PRIMARY KEY,
                    hunt_id     TEXT NOT NULL,
                    finding_id  TEXT,
                    ioc_matches TEXT NOT NULL DEFAULT '[]',
                    evidence    TEXT NOT NULL DEFAULT '{}',
                    confidence  REAL NOT NULL DEFAULT 0.5,
                    detected_at TEXT NOT NULL,
                    FOREIGN KEY (hunt_id) REFERENCES hunt_sessions(id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS idx_results_hunt ON hunt_results(hunt_id);
                """
            )

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    def get_predefined_queries(self) -> List[HuntQuery]:
        """Return all 15 built-in MITRE ATT&CK hunt queries."""
        return [HuntQuery(**q) for q in _BUILTIN_QUERIES]

    def get_all_queries(self) -> List[HuntQuery]:
        """Return built-in queries plus any custom queries from DB."""
        queries = self.get_predefined_queries()
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM hunt_queries WHERE built_in = 0"
            ).fetchall()
        for row in rows:
            queries.append(
                HuntQuery(
                    id=row["id"],
                    name=row["name"],
                    description=row["description"],
                    category=HuntCategory(row["category"]),
                    mitre_tactic=row["mitre_tactic"],
                    query_logic=json.loads(row["query_logic"]),
                    severity=row["severity"],
                    built_in=False,
                )
            )
        return queries

    def create_custom_query(
        self,
        name: str,
        category: HuntCategory,
        query_logic: Dict[str, Any],
        severity: str = "medium",
        description: str = "",
        mitre_tactic: str = "",
    ) -> HuntQuery:
        """Create and persist a custom hunt query."""
        query = HuntQuery(
            name=name,
            description=description,
            category=category,
            mitre_tactic=mitre_tactic,
            query_logic=query_logic,
            severity=severity,
            built_in=False,
        )
        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO hunt_queries
                    (id, name, description, category, mitre_tactic, query_logic, severity, built_in)
                VALUES (?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (
                    query.id,
                    query.name,
                    query.description,
                    query.category.value,
                    query.mitre_tactic,
                    json.dumps(query.query_logic),
                    query.severity,
                ),
            )
        return query

    # ------------------------------------------------------------------
    # Sessions
    # ------------------------------------------------------------------

    def start_session(
        self, name: str, hunter_email: str, org_id: str = "default"
    ) -> HuntSession:
        """Create and persist a new hunt session."""
        session = HuntSession(
            name=name,
            hunter_email=hunter_email,
            status=HuntStatus.RUNNING,
            org_id=org_id,
        )
        with self._get_conn() as conn:
            conn.execute(
                """
                INSERT INTO hunt_sessions
                    (id, name, hunter_email, status, queries_run, results_count,
                     started_at, completed_at, notes, org_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session.id,
                    session.name,
                    session.hunter_email,
                    session.status.value,
                    json.dumps(session.queries_run),
                    session.results_count,
                    session.started_at,
                    session.completed_at,
                    session.notes,
                    session.org_id,
                ),
            )
        return session

    def end_session(self, session_id: str, notes: str = "") -> HuntSession:
        """Mark a session as completed."""
        completed_at = datetime.now(timezone.utc).isoformat()
        with self._get_conn() as conn:
            conn.execute(
                """
                UPDATE hunt_sessions
                SET status = ?, completed_at = ?, notes = ?
                WHERE id = ?
                """,
                (HuntStatus.COMPLETED.value, completed_at, notes, session_id),
            )
        session = self.get_session(session_id)
        if session is None:
            raise ValueError(f"Session {session_id} not found")
        return session

    def get_session(self, session_id: str) -> Optional[HuntSession]:
        """Retrieve a session by id."""
        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM hunt_sessions WHERE id = ?", (session_id,)
            ).fetchone()
        if row is None:
            return None
        return self._row_to_session(row)

    def list_sessions(
        self,
        org_id: Optional[str] = None,
        status_filter: Optional[HuntStatus] = None,
    ) -> List[HuntSession]:
        """List sessions, optionally filtered by org and/or status."""
        query = "SELECT * FROM hunt_sessions WHERE 1=1"
        params: List[Any] = []
        if org_id:
            query += " AND org_id = ?"
            params.append(org_id)
        if status_filter:
            query += " AND status = ?"
            params.append(status_filter.value)
        query += " ORDER BY started_at DESC"
        with self._get_conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row_to_session(r) for r in rows]

    def _row_to_session(self, row: sqlite3.Row) -> HuntSession:
        return HuntSession(
            id=row["id"],
            name=row["name"],
            hunter_email=row["hunter_email"],
            status=HuntStatus(row["status"]),
            queries_run=json.loads(row["queries_run"]),
            results_count=row["results_count"],
            started_at=row["started_at"],
            completed_at=row["completed_at"],
            notes=row["notes"],
            org_id=row["org_id"],
        )

    # ------------------------------------------------------------------
    # Running hunts
    # ------------------------------------------------------------------

    def run_hunt(
        self,
        session_id: str,
        query_id: str,
        findings: List[Dict[str, Any]],
        iocs: Optional[List[Dict[str, Any]]] = None,
    ) -> List[HuntResult]:
        """Execute a hunt query against findings and IOCs, persist results."""
        iocs = iocs or []

        # Resolve query
        query = self._resolve_query(query_id)
        if query is None:
            raise ValueError(f"Query {query_id} not found")

        results: List[HuntResult] = []
        for finding in findings:
            if not self._match_query(finding, query.query_logic):
                continue

            # IOC correlation within hunt
            matched_iocs = self._correlate_finding_iocs(finding, iocs)
            confidence = self._compute_confidence(finding, matched_iocs, query)

            result = HuntResult(
                hunt_id=session_id,
                finding_id=str(finding.get("id", finding.get("finding_id", ""))),
                ioc_matches=matched_iocs,
                evidence={
                    "finding_title": finding.get("title", ""),
                    "finding_severity": finding.get("severity", ""),
                    "query_name": query.name,
                    "query_id": query.id,
                    "mitre_tactic": query.mitre_tactic,
                },
                confidence=confidence,
            )
            results.append(result)

        # Persist results and update session
        with self._get_conn() as conn:
            for r in results:
                conn.execute(
                    """
                    INSERT INTO hunt_results
                        (id, hunt_id, finding_id, ioc_matches, evidence, confidence, detected_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        r.id,
                        r.hunt_id,
                        r.finding_id,
                        json.dumps(r.ioc_matches),
                        json.dumps(r.evidence),
                        r.confidence,
                        r.detected_at,
                    ),
                )
            # Update session: append query_id and increment results_count
            conn.execute(
                """
                UPDATE hunt_sessions
                SET results_count = results_count + ?,
                    queries_run = (
                        SELECT json(
                            CASE WHEN queries_run = '[]'
                            THEN json_array(?)
                            ELSE json_insert(queries_run, '$[#]', ?)
                            END
                        ) FROM hunt_sessions WHERE id = ?
                    )
                WHERE id = ?
                """,
                (len(results), query_id, query_id, session_id, session_id),
            )

        return results

    def get_results(self, session_id: str) -> List[HuntResult]:
        """Retrieve all results for a session."""
        with self._get_conn() as conn:
            rows = conn.execute(
                "SELECT * FROM hunt_results WHERE hunt_id = ? ORDER BY detected_at",
                (session_id,),
            ).fetchall()
        return [self._row_to_result(r) for r in rows]

    def _row_to_result(self, row: sqlite3.Row) -> HuntResult:
        return HuntResult(
            id=row["id"],
            hunt_id=row["hunt_id"],
            finding_id=row["finding_id"],
            ioc_matches=json.loads(row["ioc_matches"]),
            evidence=json.loads(row["evidence"]),
            confidence=row["confidence"],
            detected_at=row["detected_at"],
        )

    # ------------------------------------------------------------------
    # Query matching
    # ------------------------------------------------------------------

    def _match_query(self, finding: Dict[str, Any], query_logic: Dict[str, Any]) -> bool:
        """Evaluate query logic conditions against a finding.

        Supports:
          - ``any``: at least one condition must match (OR)
          - ``all``: all conditions must match (AND)
          - condition operators: contains, equals, contains_any, gt, lt
        """
        if not query_logic:
            return False

        results: List[bool] = []

        if "any" in query_logic:
            results.append(
                any(self._eval_condition(finding, c) for c in query_logic["any"])
            )

        if "all" in query_logic:
            results.append(
                all(self._eval_condition(finding, c) for c in query_logic["all"])
            )

        if not results:
            return False

        return all(results)

    def _eval_condition(self, finding: Dict[str, Any], condition: Dict[str, Any]) -> bool:
        """Evaluate a single condition against a finding field."""
        field = condition.get("field", "")
        raw_value = finding.get(field, "")

        # Normalise to string for text operators; keep original for numeric
        if isinstance(raw_value, list):
            str_value = " ".join(str(v) for v in raw_value).lower()
        else:
            str_value = str(raw_value).lower()

        if "contains" in condition:
            needle = str(condition["contains"]).lower()
            return needle in str_value

        if "contains_any" in condition:
            needles = [str(n).lower() for n in condition["contains_any"]]
            return any(n in str_value for n in needles)

        if "equals" in condition:
            return str_value == str(condition["equals"]).lower()

        if "gt" in condition:
            try:
                return float(raw_value) > float(condition["gt"])
            except (TypeError, ValueError):
                return False

        if "lt" in condition:
            try:
                return float(raw_value) < float(condition["lt"])
            except (TypeError, ValueError):
                return False

        return False

    # ------------------------------------------------------------------
    # IOC correlation
    # ------------------------------------------------------------------

    def _correlate_finding_iocs(
        self, finding: Dict[str, Any], iocs: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Match IOC values against finding fields."""
        matched: List[Dict[str, Any]] = []
        finding_text = json.dumps(finding).lower()
        for ioc in iocs:
            value = str(ioc.get("value", "")).lower()
            if value and value in finding_text:
                matched.append(
                    {
                        "ioc_value": ioc.get("value"),
                        "ioc_type": ioc.get("type"),
                        "source_feed": ioc.get("source_feed", ""),
                        "confidence": ioc.get("confidence", 0.5),
                    }
                )
        return matched

    def correlate_iocs(
        self, ioc_values: List[str], org_id: str = "default"
    ) -> List[Dict[str, Any]]:
        """Cross-reference IOC values against all persisted hunt results for the org."""
        if not ioc_values:
            return []

        with self._get_conn() as conn:
            # Get all results for sessions in org
            rows = conn.execute(
                """
                SELECT r.* FROM hunt_results r
                JOIN hunt_sessions s ON r.hunt_id = s.id
                WHERE s.org_id = ?
                """,
                (org_id,),
            ).fetchall()

        correlations: List[Dict[str, Any]] = []
        for row in rows:
            evidence = json.loads(row["evidence"])
            ioc_matches = json.loads(row["ioc_matches"])
            evidence_text = json.dumps(evidence).lower()

            matched_values = [v for v in ioc_values if v.lower() in evidence_text]
            ioc_hit_values = [
                m["ioc_value"] for m in ioc_matches if m.get("ioc_value") in ioc_values
            ]
            all_hits = list(set(matched_values + ioc_hit_values))

            if all_hits:
                correlations.append(
                    {
                        "result_id": row["id"],
                        "hunt_id": row["hunt_id"],
                        "finding_id": row["finding_id"],
                        "matched_iocs": all_hits,
                        "confidence": row["confidence"],
                        "detected_at": row["detected_at"],
                    }
                )

        return correlations

    # ------------------------------------------------------------------
    # Finding promotion
    # ------------------------------------------------------------------

    def generate_finding_from_result(self, result: HuntResult) -> Dict[str, Any]:
        """Promote a hunt result to a finding dict."""
        return {
            "id": str(uuid.uuid4()),
            "title": f"Threat Hunt Finding — {result.evidence.get('query_name', 'Unknown Hunt')}",
            "description": (
                f"Threat hunt query '{result.evidence.get('query_name', '')}' "
                f"detected suspicious activity. MITRE Tactic: {result.evidence.get('mitre_tactic', 'N/A')}. "
                f"Confidence: {result.confidence:.0%}."
            ),
            "severity": result.evidence.get("finding_severity", "medium"),
            "source": "threat_hunting",
            "hunt_session_id": result.hunt_id,
            "original_finding_id": result.finding_id,
            "ioc_matches": result.ioc_matches,
            "mitre_tactic": result.evidence.get("mitre_tactic", ""),
            "confidence": result.confidence,
            "detected_at": result.detected_at,
            "tags": ["threat-hunt", result.evidence.get("mitre_tactic", "").lower()],
        }

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_hunt_stats(self, org_id: str = "default") -> Dict[str, Any]:
        """Return aggregate statistics for an org."""
        with self._get_conn() as conn:
            session_rows = conn.execute(
                "SELECT status FROM hunt_sessions WHERE org_id = ?", (org_id,)
            ).fetchall()

            result_rows = conn.execute(
                """
                SELECT r.confidence, r.evidence
                FROM hunt_results r
                JOIN hunt_sessions s ON r.hunt_id = s.id
                WHERE s.org_id = ?
                """,
                (org_id,),
            ).fetchall()

        total_sessions = len(session_rows)
        status_counts: Dict[str, int] = {}
        for row in session_rows:
            status_counts[row["status"]] = status_counts.get(row["status"], 0) + 1

        total_results = len(result_rows)
        by_category: Dict[str, int] = {}
        confidences: List[float] = []

        for row in result_rows:
            confidences.append(row["confidence"])
            evidence = json.loads(row["evidence"])
            # Try to derive category from mitre_tactic stored in evidence
            tactic = evidence.get("mitre_tactic", "")
            by_category[tactic] = by_category.get(tactic, 0) + 1

        avg_confidence = (sum(confidences) / len(confidences)) if confidences else 0.0

        return {
            "org_id": org_id,
            "total_sessions": total_sessions,
            "sessions_by_status": status_counts,
            "total_results": total_results,
            "results_by_mitre_tactic": by_category,
            "avg_confidence": round(avg_confidence, 3),
            "predefined_query_count": len(_BUILTIN_QUERIES),
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _resolve_query(self, query_id: str) -> Optional[HuntQuery]:
        """Return a built-in or custom query by id."""
        for q in _BUILTIN_QUERIES:
            if q["id"] == query_id:
                return HuntQuery(**q)

        with self._get_conn() as conn:
            row = conn.execute(
                "SELECT * FROM hunt_queries WHERE id = ?", (query_id,)
            ).fetchone()
        if row is None:
            return None
        return HuntQuery(
            id=row["id"],
            name=row["name"],
            description=row["description"],
            category=HuntCategory(row["category"]),
            mitre_tactic=row["mitre_tactic"],
            query_logic=json.loads(row["query_logic"]),
            severity=row["severity"],
            built_in=False,
        )

    def _compute_confidence(
        self,
        finding: Dict[str, Any],
        matched_iocs: List[Dict[str, Any]],
        query: HuntQuery,
    ) -> float:
        """Derive result confidence from finding severity and IOC matches."""
        severity_map = {"critical": 0.9, "high": 0.75, "medium": 0.55, "low": 0.35, "info": 0.2}
        base = severity_map.get(str(finding.get("severity", "medium")).lower(), 0.5)
        ioc_boost = min(0.1 * len(matched_iocs), 0.3)
        return min(round(base + ioc_boost, 3), 1.0)
