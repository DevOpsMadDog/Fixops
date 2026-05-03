"""MITRE ATT&CK Coverage Engine — ALDECI.

Maps ALDECI security detections to MITRE ATT&CK TTPs, tracks coverage across
the 14 Enterprise tactics, surfaces gap analysis, and generates heatmap data.

Multi-tenant via org_id.  SQLite WAL + threading.RLock for concurrency safety.
Per-org DB: .fixops_data/{org_id}_mitre_attack.db
"""

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

_DATA_DIR = Path(__file__).resolve().parents[2] / ".fixops_data"

# ---------------------------------------------------------------------------
# Real MITRE ATT&CK data (v14 Enterprise)
# ---------------------------------------------------------------------------

MITRE_TACTICS: List[tuple] = [
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"),
    ("TA0005", "Defense Evasion"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0010", "Exfiltration"),
    ("TA0011", "Command and Control"),
    ("TA0040", "Impact"),
    ("TA0042", "Resource Development"),
    ("TA0043", "Reconnaissance"),
]

# (technique_id, name, tactic_id, description, severity)
MITRE_TECHNIQUES: List[tuple] = [
    # Initial Access
    ("T1190", "Exploit Public-Facing Application", "TA0001",
     "Adversaries exploit weaknesses in internet-facing systems.", "critical"),
    ("T1078", "Valid Accounts", "TA0001",
     "Adversaries use compromised credentials to access systems.", "high"),
    ("T1566", "Phishing", "TA0001",
     "Adversaries send phishing messages to gain access.", "high"),
    ("T1133", "External Remote Services", "TA0001",
     "Adversaries leverage external remote services for initial access.", "high"),
    ("T1199", "Trusted Relationship", "TA0001",
     "Adversaries exploit trusted third-party connections.", "medium"),
    # Execution
    ("T1059", "Command and Scripting Interpreter", "TA0002",
     "Adversaries abuse command interpreters to execute commands.", "critical"),
    ("T1053", "Scheduled Task/Job", "TA0002",
     "Adversaries abuse task schedulers to execute malicious code.", "high"),
    ("T1204", "User Execution", "TA0002",
     "Adversaries rely on user actions to execute malicious code.", "medium"),
    ("T1203", "Exploitation for Client Execution", "TA0002",
     "Adversaries exploit client-side software for code execution.", "critical"),
    # Persistence
    ("T1547", "Boot or Logon Autostart Execution", "TA0003",
     "Adversaries configure autostart entries for persistence.", "high"),
    ("T1505", "Server Software Component", "TA0003",
     "Adversaries install web shells or malicious server components.", "critical"),
    ("T1136", "Create Account", "TA0003",
     "Adversaries create accounts for persistent access.", "medium"),
    ("T1098", "Account Manipulation", "TA0003",
     "Adversaries manipulate accounts to maintain persistence.", "high"),
    # Privilege Escalation
    ("T1548", "Abuse Elevation Control Mechanism", "TA0004",
     "Adversaries abuse elevation mechanisms to gain higher privileges.", "high"),
    ("T1055", "Process Injection", "TA0004",
     "Adversaries inject code into processes to escalate privileges.", "critical"),
    ("T1068", "Exploitation for Privilege Escalation", "TA0004",
     "Adversaries exploit vulnerabilities to gain elevated privileges.", "critical"),
    # Defense Evasion
    ("T1070", "Indicator Removal", "TA0005",
     "Adversaries delete or modify artifacts to evade detection.", "high"),
    ("T1027", "Obfuscated Files or Information", "TA0005",
     "Adversaries obfuscate files or information to hide malicious activity.", "high"),
    ("T1562", "Impair Defenses", "TA0005",
     "Adversaries disable or modify security tools.", "critical"),
    ("T1036", "Masquerading", "TA0005",
     "Adversaries disguise malicious artifacts as legitimate.", "medium"),
    # Credential Access
    ("T1003", "OS Credential Dumping", "TA0006",
     "Adversaries dump credentials from OS memory.", "critical"),
    ("T1110", "Brute Force", "TA0006",
     "Adversaries attempt to guess credentials through brute force.", "high"),
    ("T1552", "Unsecured Credentials", "TA0006",
     "Adversaries search for credentials stored insecurely.", "high"),
    ("T1555", "Credentials from Password Stores", "TA0006",
     "Adversaries steal credentials from password managers.", "high"),
    # Discovery
    ("T1082", "System Information Discovery", "TA0007",
     "Adversaries enumerate system information.", "medium"),
    ("T1046", "Network Service Discovery", "TA0007",
     "Adversaries scan to enumerate services on remote hosts.", "medium"),
    ("T1083", "File and Directory Discovery", "TA0007",
     "Adversaries enumerate files and directories.", "low"),
    ("T1033", "System Owner/User Discovery", "TA0007",
     "Adversaries attempt to find the primary user of a system.", "low"),
    # Lateral Movement
    ("T1021", "Remote Services", "TA0008",
     "Adversaries use valid accounts to log into remote services.", "high"),
    ("T1210", "Exploitation of Remote Services", "TA0008",
     "Adversaries exploit remote services to gain access.", "critical"),
    ("T1563", "Remote Service Session Hijacking", "TA0008",
     "Adversaries take over existing remote sessions.", "high"),
    # Collection
    ("T1056", "Input Capture", "TA0009",
     "Adversaries capture user input such as keystrokes.", "high"),
    ("T1005", "Data from Local System", "TA0009",
     "Adversaries search local file systems for sensitive data.", "medium"),
    ("T1213", "Data from Information Repositories", "TA0009",
     "Adversaries collect data from wikis, SharePoint, etc.", "medium"),
    # Exfiltration
    ("T1041", "Exfiltration Over C2 Channel", "TA0010",
     "Adversaries exfiltrate data over the existing C2 channel.", "high"),
    ("T1048", "Exfiltration Over Alternative Protocol", "TA0010",
     "Adversaries use alternate protocols to exfiltrate data.", "high"),
    ("T1567", "Exfiltration Over Web Service", "TA0010",
     "Adversaries exfiltrate data to cloud services.", "medium"),
    # Command and Control
    ("T1071", "Application Layer Protocol", "TA0011",
     "Adversaries communicate using application layer protocols.", "high"),
    ("T1571", "Non-Standard Port", "TA0011",
     "Adversaries use non-standard ports for C2.", "medium"),
    ("T1105", "Ingress Tool Transfer", "TA0011",
     "Adversaries transfer tools from external systems.", "high"),
    # Impact
    ("T1486", "Data Encrypted for Impact", "TA0040",
     "Adversaries encrypt data to render it inaccessible (ransomware).", "critical"),
    ("T1499", "Endpoint Denial of Service", "TA0040",
     "Adversaries perform DoS attacks against endpoints.", "high"),
    ("T1485", "Data Destruction", "TA0040",
     "Adversaries destroy data to impact availability.", "critical"),
    # Resource Development
    ("T1583", "Acquire Infrastructure", "TA0042",
     "Adversaries acquire infrastructure for operations.", "medium"),
    ("T1588", "Obtain Capabilities", "TA0042",
     "Adversaries obtain capabilities such as malware or exploits.", "medium"),
    # Reconnaissance
    ("T1595", "Active Scanning", "TA0043",
     "Adversaries actively scan victim infrastructure.", "medium"),
    ("T1589", "Gather Victim Identity Information", "TA0043",
     "Adversaries gather identity info about potential targets.", "medium"),
    ("T1590", "Gather Victim Network Information", "TA0043",
     "Adversaries gather network info about the target.", "low"),
]

# Coverage thresholds
_WELL_DETECTED_THRESHOLD = 3   # detections needed to be "well covered"
_LOW_COVERAGE_THRESHOLD = 1    # detections for "low coverage"


class MITREAttackCoverageEngine:
    """Maps ALDECI detections to MITRE ATT&CK TTPs and reports coverage.

    Multi-tenant via org_id.  Each org gets its own SQLite database at:
        .fixops_data/{org_id}_mitre_attack.db

    Thread-safe via RLock.
    """

    def __init__(self, data_dir: Optional[str] = None) -> None:
        self._data_dir = Path(data_dir) if data_dir else _DATA_DIR
        self._lock = threading.RLock()
        self._db_cache: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _db_path(self, org_id: str) -> str:
        safe = org_id.replace("/", "_").replace("..", "_")
        return str(self._data_dir / f"{safe}_mitre_attack.db")

    def _conn(self, org_id: str) -> sqlite3.Connection:
        path = self._db_path(org_id)
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self, org_id: str) -> None:
        with self._lock:
            with self._conn(org_id) as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.executescript("""
                    CREATE TABLE IF NOT EXISTS tactics (
                        tactic_id   TEXT PRIMARY KEY,
                        name        TEXT NOT NULL,
                        org_id      TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS techniques (
                        technique_id TEXT NOT NULL,
                        org_id       TEXT NOT NULL,
                        name         TEXT NOT NULL,
                        tactic_id    TEXT NOT NULL,
                        description  TEXT NOT NULL DEFAULT '',
                        severity     TEXT NOT NULL DEFAULT 'medium',
                        created_at   TEXT NOT NULL,
                        PRIMARY KEY (technique_id, org_id)
                    );

                    CREATE TABLE IF NOT EXISTS detections (
                        detection_id TEXT PRIMARY KEY,
                        org_id       TEXT NOT NULL,
                        technique_id TEXT NOT NULL,
                        source       TEXT NOT NULL DEFAULT '',
                        confidence   REAL NOT NULL DEFAULT 0.5,
                        metadata     TEXT NOT NULL DEFAULT '{}',
                        detected_at  TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_det_org_tech
                        ON detections (org_id, technique_id);

                    CREATE TABLE IF NOT EXISTS coverage_assessments (
                        assessment_id   TEXT PRIMARY KEY,
                        org_id          TEXT NOT NULL,
                        total_techniques INTEGER NOT NULL DEFAULT 0,
                        covered_count   INTEGER NOT NULL DEFAULT 0,
                        coverage_pct    REAL NOT NULL DEFAULT 0.0,
                        assessed_at     TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_ca_org
                        ON coverage_assessments (org_id, assessed_at DESC);

                    CREATE TABLE IF NOT EXISTS gaps (
                        gap_id       TEXT PRIMARY KEY,
                        org_id       TEXT NOT NULL,
                        technique_id TEXT NOT NULL,
                        tactic_id    TEXT NOT NULL,
                        severity     TEXT NOT NULL DEFAULT 'medium',
                        identified_at TEXT NOT NULL
                    );
                    CREATE INDEX IF NOT EXISTS idx_gap_org
                        ON gaps (org_id, severity);
                """)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def seed_att_ck_techniques(self, org_id: str) -> int:
        """Seed the 14 MITRE ATT&CK tactics and all known techniques.

        Returns count of techniques seeded.  Safe to call multiple times
        (uses INSERT OR IGNORE).
        """
        self._init_db(org_id)
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._conn(org_id) as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                # Seed tactics
                for tactic_id, tactic_name in MITRE_TACTICS:
                    conn.execute(
                        "INSERT OR IGNORE INTO tactics (tactic_id, name, org_id) VALUES (?, ?, ?)",
                        (tactic_id, tactic_name, org_id),
                    )
                # Seed techniques
                count = 0
                for tid, name, tactic_id, description, severity in MITRE_TECHNIQUES:
                    cur = conn.execute(
                        """INSERT OR IGNORE INTO techniques
                           (technique_id, org_id, name, tactic_id, description, severity, created_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        (tid, org_id, name, tactic_id, description, severity, now),
                    )
                    count += cur.rowcount
        _logger.info("mitre_coverage.seed org_id=%s seeded=%d", org_id, count)
        return count

    def add_technique(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a custom MITRE ATT&CK technique.

        Args:
            org_id: Tenant identifier.
            data: dict with keys: technique_id, name, tactic_id,
                  description (opt), severity (opt).

        Returns:
            The technique record as a dict.
        """
        self._init_db(org_id)
        technique_id = str(data.get("technique_id", "")).strip().upper()
        name = str(data.get("name", "")).strip()
        tactic_id = str(data.get("tactic_id", "")).strip().upper()
        description = str(data.get("description", "")).strip()
        severity = str(data.get("severity", "medium")).lower()

        if not technique_id or not name or not tactic_id:
            raise ValueError("technique_id, name, and tactic_id are required")

        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            with self._conn(org_id) as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute(
                    """INSERT OR REPLACE INTO techniques
                       (technique_id, org_id, name, tactic_id, description, severity, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (technique_id, org_id, name, tactic_id, description, severity, now),
                )

        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("THREAT_DETECTED", {"entity_type": "mitre_attack_coverage", "org_id": org_id, "source_engine": "mitre_attack_coverage"})
            except Exception:
                pass

        return {
            "technique_id": technique_id,
            "org_id": org_id,
            "name": name,
            "tactic_id": tactic_id,
            "description": description,
            "severity": severity,
            "created_at": now,
        }

    def log_detection(
        self,
        org_id: str,
        technique_id: str,
        source: str,
        confidence: float,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Log a detection event for a MITRE ATT&CK technique.

        Args:
            org_id: Tenant identifier.
            technique_id: ATT&CK technique ID (e.g. 'T1190').
            source: Detection source (e.g. 'ids', 'siem', 'edr').
            confidence: Detection confidence 0.0–1.0.
            metadata: Optional extra context.

        Returns:
            The detection record as a dict.
        """
        self._init_db(org_id)
        confidence = max(0.0, min(1.0, float(confidence)))
        detection_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        meta_str = json.dumps(metadata or {})
        tid = technique_id.strip().upper()

        with self._lock:
            with self._conn(org_id) as conn:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute(
                    """INSERT INTO detections
                       (detection_id, org_id, technique_id, source, confidence, metadata, detected_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (detection_id, org_id, tid, source, confidence, meta_str, now),
                )

        return {
            "detection_id": detection_id,
            "org_id": org_id,
            "technique_id": tid,
            "source": source,
            "confidence": confidence,
            "metadata": metadata or {},
            "detected_at": now,
        }

    def get_coverage(self, org_id: str) -> Dict[str, Any]:
        """Get overall ATT&CK coverage percentage and per-tactic breakdown.

        Returns:
            dict with overall_pct, covered_count, total_count, tactic_breakdown,
            and an assessment_id written to coverage_assessments table.
        """
        self._init_db(org_id)
        with self._lock:
            with self._conn(org_id) as conn:
                # Total techniques registered for this org
                total_row = conn.execute(
                    "SELECT COUNT(*) as cnt FROM techniques WHERE org_id = ?", (org_id,)
                ).fetchone()
                total = total_row["cnt"] if total_row else 0

                if total == 0:
                    return {
                        "org_id": org_id,
                        "overall_pct": 0.0,
                        "covered_count": 0,
                        "total_count": 0,
                        "tactic_breakdown": {},
                        "assessment_id": None,
                    }

                # Techniques with at least one detection
                covered_rows = conn.execute(
                    """SELECT DISTINCT technique_id FROM detections WHERE org_id = ?""",
                    (org_id,),
                ).fetchall()
                covered_ids = {r["technique_id"] for r in covered_rows}
                covered = len(covered_ids)

                # Per-tactic breakdown
                tactic_rows = conn.execute(
                    """SELECT t.tactic_id, ta.name as tactic_name,
                              COUNT(DISTINCT t.technique_id) as total_techs
                       FROM techniques t
                       LEFT JOIN tactics ta ON ta.tactic_id = t.tactic_id AND ta.org_id = t.org_id
                       WHERE t.org_id = ?
                       GROUP BY t.tactic_id""",
                    (org_id,),
                ).fetchall()

                tactic_breakdown: Dict[str, Any] = {}
                for row in tactic_rows:
                    # Count covered techs in this tactic
                    covered_in_tactic = conn.execute(
                        """SELECT COUNT(DISTINCT d.technique_id) as cnt
                           FROM detections d
                           JOIN techniques t ON t.technique_id = d.technique_id AND t.org_id = d.org_id
                           WHERE d.org_id = ? AND t.tactic_id = ?""",
                        (org_id, row["tactic_id"]),
                    ).fetchone()
                    c_count = covered_in_tactic["cnt"] if covered_in_tactic else 0
                    t_count = row["total_techs"]
                    pct = round(c_count / t_count * 100, 1) if t_count else 0.0
                    tactic_name = row["tactic_name"] or row["tactic_id"]
                    tactic_breakdown[tactic_name] = {
                        "tactic_id": row["tactic_id"],
                        "covered": c_count,
                        "total": t_count,
                        "coverage_pct": pct,
                    }

                overall_pct = round(covered / total * 100, 2)

                # Record assessment
                assessment_id = str(uuid.uuid4())
                now = datetime.now(timezone.utc).isoformat()
                conn.execute(
                    """INSERT INTO coverage_assessments
                       (assessment_id, org_id, total_techniques, covered_count, coverage_pct, assessed_at)
                       VALUES (?, ?, ?, ?, ?, ?)""",
                    (assessment_id, org_id, total, covered, overall_pct, now),
                )

        return {
            "org_id": org_id,
            "overall_pct": overall_pct,
            "covered_count": covered,
            "total_count": total,
            "tactic_breakdown": tactic_breakdown,
            "assessment_id": assessment_id,
            "assessed_at": now,
        }

    def get_gaps(self, org_id: str) -> List[Dict[str, Any]]:
        """Get undetected or low-coverage techniques (critical gaps).

        A technique is a gap if it has zero detections.
        Returns list sorted by severity (critical first), then technique_id.
        """
        self._init_db(org_id)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

        with self._lock:
            with self._conn(org_id) as conn:
                # Techniques with zero detections
                rows = conn.execute(
                    """SELECT t.technique_id, t.name, t.tactic_id, t.description, t.severity,
                              ta.name as tactic_name
                       FROM techniques t
                       LEFT JOIN tactics ta ON ta.tactic_id = t.tactic_id AND ta.org_id = t.org_id
                       LEFT JOIN detections d ON d.technique_id = t.technique_id AND d.org_id = t.org_id
                       WHERE t.org_id = ?
                       GROUP BY t.technique_id
                       HAVING COUNT(d.detection_id) = 0""",
                    (org_id,),
                ).fetchall()

                gaps = []
                for row in rows:
                    # Also write gap record
                    gap_id = str(uuid.uuid4())
                    now = datetime.now(timezone.utc).isoformat()
                    try:
                        conn.execute(
                            """INSERT OR IGNORE INTO gaps
                               (gap_id, org_id, technique_id, tactic_id, severity, identified_at)
                               VALUES (?, ?, ?, ?, ?, ?)""",
                            (gap_id, org_id, row["technique_id"], row["tactic_id"],
                             row["severity"], now),
                        )
                    except Exception:
                        pass

                    gaps.append({
                        "technique_id": row["technique_id"],
                        "name": row["name"],
                        "tactic_id": row["tactic_id"],
                        "tactic_name": row["tactic_name"] or row["tactic_id"],
                        "description": row["description"],
                        "severity": row["severity"],
                    })

        gaps.sort(
            key=lambda g: (severity_order.get(g["severity"], 99), g["technique_id"])
        )
        return gaps

    def get_heatmap(self, org_id: str) -> Dict[str, Any]:
        """Get heatmap data: technique → detection count per tactic.

        Returns ATT&CK Navigator-compatible layer structure with per-tactic
        grouping for UI rendering.
        """
        self._init_db(org_id)
        with self._lock:
            with self._conn(org_id) as conn:
                # Detection counts per technique
                det_rows = conn.execute(
                    """SELECT technique_id, COUNT(*) as cnt
                       FROM detections WHERE org_id = ?
                       GROUP BY technique_id""",
                    (org_id,),
                ).fetchall()
                freq: Dict[str, int] = {r["technique_id"]: r["cnt"] for r in det_rows}

                # All techniques with tactic info
                tech_rows = conn.execute(
                    """SELECT t.technique_id, t.name, t.tactic_id, t.severity,
                              ta.name as tactic_name
                       FROM techniques t
                       LEFT JOIN tactics ta ON ta.tactic_id = t.tactic_id AND ta.org_id = t.org_id
                       WHERE t.org_id = ?""",
                    (org_id,),
                ).fetchall()

        # Build per-tactic heat buckets
        tactic_map: Dict[str, Dict[str, Any]] = {}
        techniques_layer = []

        for row in tech_rows:
            tid = row["technique_id"]
            count = freq.get(tid, 0)
            score = min(count * 25, 100)
            tactic_name = row["tactic_name"] or row["tactic_id"]
            tactic_id = row["tactic_id"]

            if tactic_id not in tactic_map:
                tactic_map[tactic_id] = {
                    "tactic_id": tactic_id,
                    "tactic_name": tactic_name,
                    "techniques": [],
                    "total_detections": 0,
                    "covered_count": 0,
                    "total_count": 0,
                }
            tactic_map[tactic_id]["techniques"].append({
                "technique_id": tid,
                "name": row["name"],
                "detection_count": count,
                "score": score,
                "severity": row["severity"],
            })
            tactic_map[tactic_id]["total_detections"] += count
            tactic_map[tactic_id]["total_count"] += 1
            if count > 0:
                tactic_map[tactic_id]["covered_count"] += 1

            if count > 0:
                techniques_layer.append({
                    "techniqueID": tid,
                    "score": score,
                    "comment": f"Detected {count} time(s)",
                    "enabled": True,
                })

        return {
            "name": "ALDECI ATT&CK Coverage Heatmap",
            "domain": "enterprise-attack",
            "attack_version": "14",
            "navigator_version": "4.9",
            "org_id": org_id,
            "by_tactic": list(tactic_map.values()),
            "techniques": techniques_layer,
            "total_detections": sum(freq.values()),
        }

    def get_techniques(self, org_id: str) -> List[Dict[str, Any]]:
        """List all techniques registered for the org."""
        self._init_db(org_id)
        with self._lock:
            with self._conn(org_id) as conn:
                rows = conn.execute(
                    """SELECT t.technique_id, t.name, t.tactic_id, t.description,
                              t.severity, t.created_at, ta.name as tactic_name,
                              COUNT(d.detection_id) as detection_count
                       FROM techniques t
                       LEFT JOIN tactics ta ON ta.tactic_id = t.tactic_id AND ta.org_id = t.org_id
                       LEFT JOIN detections d ON d.technique_id = t.technique_id AND d.org_id = t.org_id
                       WHERE t.org_id = ?
                       GROUP BY t.technique_id
                       ORDER BY t.tactic_id, t.technique_id""",
                    (org_id,),
                ).fetchall()

        return [dict(r) for r in rows]

    def get_technique_by_id(self, org_id: str, technique_id: str) -> Optional[Dict[str, Any]]:
        """Return a single technique record by ID, or None if not found."""
        self._init_db(org_id)
        tid = technique_id.upper()
        with self._lock:
            with self._conn(org_id) as conn:
                row = conn.execute(
                    """SELECT t.technique_id, t.name, t.tactic_id, t.description,
                              t.severity, t.created_at, ta.name as tactic_name,
                              COUNT(d.detection_id) as detection_count
                       FROM techniques t
                       LEFT JOIN tactics ta ON ta.tactic_id = t.tactic_id AND ta.org_id = t.org_id
                       LEFT JOIN detections d ON d.technique_id = t.technique_id AND d.org_id = t.org_id
                       WHERE t.org_id = ? AND t.technique_id = ?
                       GROUP BY t.technique_id""",
                    (org_id, tid),
                ).fetchone()
        return dict(row) if row else None

    def get_detections(
        self,
        org_id: str,
        technique_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """List detection events for the org, optionally filtered by technique."""
        self._init_db(org_id)
        with self._lock:
            with self._conn(org_id) as conn:
                if technique_id:
                    rows = conn.execute(
                        """SELECT * FROM detections
                           WHERE org_id = ? AND technique_id = ?
                           ORDER BY detected_at DESC LIMIT ?""",
                        (org_id, technique_id.upper(), limit),
                    ).fetchall()
                else:
                    rows = conn.execute(
                        """SELECT * FROM detections
                           WHERE org_id = ?
                           ORDER BY detected_at DESC LIMIT ?""",
                        (org_id, limit),
                    ).fetchall()

        result = []
        for r in rows:
            rec = dict(r)
            try:
                rec["metadata"] = json.loads(rec.get("metadata", "{}"))
            except (json.JSONDecodeError, TypeError):
                rec["metadata"] = {}
            result.append(rec)
        return result


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_engine_instance: Optional[MITREAttackCoverageEngine] = None


def get_mitre_coverage_engine() -> MITREAttackCoverageEngine:
    """Return the shared MITREAttackCoverageEngine singleton."""
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = MITREAttackCoverageEngine()
    return _engine_instance
