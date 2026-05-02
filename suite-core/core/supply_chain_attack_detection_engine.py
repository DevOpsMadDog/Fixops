"""Supply Chain Attack Detection Engine — ALDECI.

Detects typosquatting, dependency confusion, malicious updates, compromised
maintainers, hidden code, and other software supply chain attack vectors.

Features:
- Package registration with ecosystem + attack_type classification
- Detection recording with confidence scoring and evidence
- Policy enforcement (block/quarantine/alert/log) per ecosystem
- Multi-tenant org_id isolation
- Attack stats aggregated by ecosystem, attack_type, detection_type

Compliance: CISA Supply Chain Risk Management, NIST SP 800-161,
            SLSA framework, CIS Software Supply Chain Security Guide
"""

from __future__ import annotations

import json
import logging

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "supply_chain_attack_detection.db"
)

_VALID_ECOSYSTEMS = {
    "npm", "pypi", "maven", "nuget", "rubygems", "cargo", "go", "composer",
}
_VALID_ATTACK_TYPES = {
    "typosquatting", "dependency_confusion", "malicious_update",
    "compromised_maintainer", "hidden_code", "none",
}
_VALID_STATUSES = {"clean", "suspicious", "malicious", "quarantined"}
_VALID_DETECTION_TYPES = {
    "name_similarity", "maintainer_change", "unusual_permission",
    "obfuscated_code", "network_callback", "env_harvesting",
    "crypto_mining", "backdoor",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_DETECTION_STATUSES = {"open", "investigating", "confirmed", "false_positive"}
_VALID_ACTIONS = {"block", "quarantine", "alert", "log"}


class SupplyChainAttackDetectionEngine:
    """Detect and manage software supply chain attacks."""

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self._db_path = db_path
        self._lock = threading.RLock()
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ------------------------------------------------------------------
    # DB INIT
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS scad_packages (
                    id            TEXT PRIMARY KEY,
                    org_id        TEXT NOT NULL,
                    package_name  TEXT NOT NULL,
                    ecosystem     TEXT NOT NULL,
                    version       TEXT,
                    source_url    TEXT,
                    risk_score    REAL NOT NULL DEFAULT 0.0,
                    attack_type   TEXT NOT NULL DEFAULT 'none',
                    status        TEXT NOT NULL DEFAULT 'clean',
                    last_scanned  TEXT,
                    created_at    TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS quarantined_packages (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    package_purl     TEXT NOT NULL,
                    reason           TEXT NOT NULL,
                    quarantined_by   TEXT NOT NULL,
                    quarantined_at   TEXT NOT NULL,
                    released_at      TEXT,
                    released_by      TEXT,
                    release_reason   TEXT
                );

                CREATE UNIQUE INDEX IF NOT EXISTS idx_quarantine_active_unique
                    ON quarantined_packages(org_id, package_purl)
                    WHERE released_at IS NULL;

                CREATE INDEX IF NOT EXISTS idx_quarantine_org
                    ON quarantined_packages(org_id);

                CREATE TABLE IF NOT EXISTS scad_detections (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    package_id       TEXT NOT NULL,
                    detection_type   TEXT NOT NULL,
                    confidence_score REAL NOT NULL DEFAULT 0.0,
                    evidence         TEXT,
                    severity         TEXT NOT NULL,
                    status           TEXT NOT NULL DEFAULT 'open',
                    detected_at      TEXT NOT NULL,
                    created_at       TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS scad_policies (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    policy_name     TEXT NOT NULL,
                    ecosystems      TEXT NOT NULL DEFAULT '[]',
                    action          TEXT NOT NULL,
                    min_confidence  REAL NOT NULL DEFAULT 70.0,
                    enabled         INTEGER NOT NULL DEFAULT 1,
                    created_at      TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_scad_packages_org
                    ON scad_packages(org_id);
                CREATE INDEX IF NOT EXISTS idx_scad_detections_org
                    ON scad_detections(org_id);
                CREATE INDEX IF NOT EXISTS idx_scad_policies_org
                    ON scad_policies(org_id);
            """)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    # ------------------------------------------------------------------
    # PACKAGES
    # ------------------------------------------------------------------

    def register_package(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a package for supply chain tracking. Returns the package record."""
        ecosystem = data.get("ecosystem", "npm")
        if ecosystem not in _VALID_ECOSYSTEMS:
            raise ValueError(f"Invalid ecosystem '{ecosystem}'. Must be one of {_VALID_ECOSYSTEMS}")

        attack_type = data.get("attack_type", "none")
        if attack_type not in _VALID_ATTACK_TYPES:
            raise ValueError(f"Invalid attack_type '{attack_type}'. Must be one of {_VALID_ATTACK_TYPES}")

        pkg_id = str(uuid.uuid4())
        now = self._now()
        risk_score = float(data.get("risk_score", 0.0))

        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO scad_packages
                   (id, org_id, package_name, ecosystem, version, source_url,
                    risk_score, attack_type, status, last_scanned, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    pkg_id, org_id, data["package_name"], ecosystem,
                    data.get("version"), data.get("source_url"),
                    risk_score, attack_type, "clean",
                    data.get("last_scanned"), now,
                ),
            )
        _logger.info("scad.package_registered org=%s id=%s pkg=%s", org_id, pkg_id, data["package_name"])
        return self.get_package(org_id, pkg_id)

    def list_packages(
        self,
        org_id: str,
        ecosystem: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List packages for org, optionally filtered by ecosystem or status."""
        query = "SELECT * FROM scad_packages WHERE org_id=?"
        params: List[Any] = [org_id]
        if ecosystem:
            query += " AND ecosystem=?"
            params.append(ecosystem)
        if status:
            query += " AND status=?"
            params.append(status)
        query += " ORDER BY created_at DESC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def get_package(self, org_id: str, package_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single package scoped to org_id, or None if not found."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM scad_packages WHERE org_id=? AND id=?",
                (org_id, package_id),
            ).fetchone()
        return dict(row) if row else None

    def update_package_status(
        self,
        org_id: str,
        package_id: str,
        status: str,
        attack_type: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update package status (and optionally attack_type)."""
        if status not in _VALID_STATUSES:
            raise ValueError(f"Invalid status '{status}'. Must be one of {_VALID_STATUSES}")
        if attack_type is not None and attack_type not in _VALID_ATTACK_TYPES:
            raise ValueError(f"Invalid attack_type '{attack_type}'.")

        pkg = self.get_package(org_id, package_id)
        if pkg is None:
            raise ValueError(f"Package {package_id} not found for org {org_id}")

        now = self._now()
        with self._lock, self._connect() as conn:
            if attack_type is not None:
                conn.execute(
                    "UPDATE scad_packages SET status=?, attack_type=?, last_scanned=? WHERE org_id=? AND id=?",
                    (status, attack_type, now, org_id, package_id),
                )
            else:
                conn.execute(
                    "UPDATE scad_packages SET status=?, last_scanned=? WHERE org_id=? AND id=?",
                    (status, now, org_id, package_id),
                )
        _logger.info("scad.package_status_updated org=%s id=%s status=%s", org_id, package_id, status)
        return self.get_package(org_id, package_id)

    # ------------------------------------------------------------------
    # DETECTIONS
    # ------------------------------------------------------------------

    def record_detection(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a supply chain attack detection. Returns the detection record."""
        detection_type = data.get("detection_type")
        if detection_type not in _VALID_DETECTION_TYPES:
            raise ValueError(f"Invalid detection_type '{detection_type}'. Must be one of {_VALID_DETECTION_TYPES}")

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid severity '{severity}'. Must be one of {_VALID_SEVERITIES}")

        confidence = float(data.get("confidence_score", 0.0))
        confidence = max(0.0, min(100.0, confidence))

        detection_id = str(uuid.uuid4())
        now = self._now()

        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO scad_detections
                   (id, org_id, package_id, detection_type, confidence_score,
                    evidence, severity, status, detected_at, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    detection_id, org_id, data["package_id"], detection_type,
                    confidence, data.get("evidence"), severity, "open",
                    data.get("detected_at", now), now,
                ),
            )
        _logger.info(
            "scad.detection_recorded org=%s id=%s type=%s severity=%s",
            org_id, detection_id, detection_type, severity,
        )
        if _get_tg_bus is not None:
            try:
                _get_tg_bus().emit("THREAT_DETECTED", {
                    "org_id": org_id,
                    "entity": "supply_chain_detection",
                    "detection_id": detection_id,
                    "detection_type": detection_type,
                    "severity": severity,
                    "confidence_score": confidence,
                })
            except Exception:
                pass
        return self._get_detection(org_id, detection_id)

    def list_detections(
        self,
        org_id: str,
        package_id: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List detections for org, optionally filtered."""
        query = "SELECT * FROM scad_detections WHERE org_id=?"
        params: List[Any] = [org_id]
        if package_id:
            query += " AND package_id=?"
            params.append(package_id)
        if severity:
            query += " AND severity=?"
            params.append(severity)
        if status:
            query += " AND status=?"
            params.append(status)
        query += " ORDER BY detected_at DESC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def _get_detection(self, org_id: str, detection_id: str) -> Dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM scad_detections WHERE org_id=? AND id=?",
                (org_id, detection_id),
            ).fetchone()
        if not row:
            raise ValueError(f"Detection {detection_id} not found for org {org_id}")
        return dict(row)

    def confirm_detection(
        self,
        org_id: str,
        detection_id: str,
        confirmed_status: str,
    ) -> Dict[str, Any]:
        """Update detection status to confirmed or false_positive."""
        valid = {"confirmed", "false_positive"}
        if confirmed_status not in valid:
            raise ValueError(f"Invalid status '{confirmed_status}'. Must be one of {valid}")

        self._get_detection(org_id, detection_id)  # raises if not found / wrong org
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE scad_detections SET status=? WHERE org_id=? AND id=?",
                (confirmed_status, org_id, detection_id),
            )
        _logger.info("scad.detection_confirmed org=%s id=%s status=%s", org_id, detection_id, confirmed_status)
        return self._get_detection(org_id, detection_id)

    # ------------------------------------------------------------------
    # POLICIES
    # ------------------------------------------------------------------

    def create_policy(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a supply chain attack policy."""
        action = data.get("action", "alert")
        if action not in _VALID_ACTIONS:
            raise ValueError(f"Invalid action '{action}'. Must be one of {_VALID_ACTIONS}")

        ecosystems = data.get("ecosystems", [])
        policy_id = str(uuid.uuid4())
        now = self._now()

        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO scad_policies
                   (id, org_id, policy_name, ecosystems, action, min_confidence, enabled, created_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    policy_id, org_id, data["policy_name"],
                    json.dumps(ecosystems),
                    action,
                    float(data.get("min_confidence", 70.0)),
                    1 if data.get("enabled", True) else 0,
                    now,
                ),
            )
        _logger.info("scad.policy_created org=%s id=%s name=%s", org_id, policy_id, data["policy_name"])
        return self._get_policy(org_id, policy_id)

    def list_policies(
        self,
        org_id: str,
        enabled: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        """List policies for org, optionally filtered by enabled flag."""
        query = "SELECT * FROM scad_policies WHERE org_id=?"
        params: List[Any] = [org_id]
        if enabled is not None:
            query += " AND enabled=?"
            params.append(1 if enabled else 0)
        query += " ORDER BY created_at DESC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._deserialize_policy(dict(r)) for r in rows]

    def _get_policy(self, org_id: str, policy_id: str) -> Dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM scad_policies WHERE org_id=? AND id=?",
                (org_id, policy_id),
            ).fetchone()
        if not row:
            raise ValueError(f"Policy {policy_id} not found for org {org_id}")
        return self._deserialize_policy(dict(row))

    @staticmethod
    def _deserialize_policy(row: Dict[str, Any]) -> Dict[str, Any]:
        if isinstance(row.get("ecosystems"), str):
            try:
                row["ecosystems"] = json.loads(row["ecosystems"])
            except (json.JSONDecodeError, TypeError):
                row["ecosystems"] = []
        row["enabled"] = bool(row.get("enabled", 1))
        return row

    # ------------------------------------------------------------------
    # STATS
    # ------------------------------------------------------------------

    def get_attack_stats(self, org_id: str) -> Dict[str, Any]:
        """Return supply chain attack overview stats for org_id."""
        with self._connect() as conn:
            total_packages = conn.execute(
                "SELECT COUNT(*) FROM scad_packages WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            suspicious = conn.execute(
                "SELECT COUNT(*) FROM scad_packages WHERE org_id=? AND status='suspicious'", (org_id,)
            ).fetchone()[0]

            malicious = conn.execute(
                "SELECT COUNT(*) FROM scad_packages WHERE org_id=? AND status='malicious'", (org_id,)
            ).fetchone()[0]

            total_detections = conn.execute(
                "SELECT COUNT(*) FROM scad_detections WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            open_detections = conn.execute(
                "SELECT COUNT(*) FROM scad_detections WHERE org_id=? AND status='open'", (org_id,)
            ).fetchone()[0]

            critical_detections = conn.execute(
                "SELECT COUNT(*) FROM scad_detections WHERE org_id=? AND severity='critical'", (org_id,)
            ).fetchone()[0]

            eco_rows = conn.execute(
                "SELECT ecosystem, COUNT(*) as cnt FROM scad_packages WHERE org_id=? GROUP BY ecosystem",
                (org_id,),
            ).fetchall()

            attack_rows = conn.execute(
                "SELECT attack_type, COUNT(*) as cnt FROM scad_packages WHERE org_id=? GROUP BY attack_type",
                (org_id,),
            ).fetchall()

            det_type_rows = conn.execute(
                "SELECT detection_type, COUNT(*) as cnt FROM scad_detections WHERE org_id=? GROUP BY detection_type",
                (org_id,),
            ).fetchall()

        return {
            "total_packages": total_packages,
            "suspicious_packages": suspicious,
            "malicious_packages": malicious,
            "total_detections": total_detections,
            "open_detections": open_detections,
            "critical_detections": critical_detections,
            "by_ecosystem": {r["ecosystem"]: r["cnt"] for r in eco_rows},
            "by_attack_type": {r["attack_type"]: r["cnt"] for r in attack_rows},
            "by_detection_type": {r["detection_type"]: r["cnt"] for r in det_type_rows},
        }

    # ------------------------------------------------------------------
    # BEHAVIORAL RISK SCORING (GAP-009)
    # ------------------------------------------------------------------
    # Weighted-signal scorer. Each known signal has a weight; contributing
    # signals are accumulated to a 0-100 risk score, bucketed into
    # low/medium/high/critical. Unknown signals are ignored.

    _SIGNAL_WEIGHTS: Dict[str, float] = {
        "postinstall_script": 18.0,
        "typosquat_score": 22.0,       # value in 0.0-1.0 scales weight
        "author_change_recent": 15.0,
        "deps_expanded_recently": 12.0,
        "obfuscated_code_detected": 20.0,
        "ioc_matches": 25.0,           # value in 0.0-1.0 scales weight
    }

    def score_package_behavior(
        self,
        org_id: str,
        package_purl: str,
        signals: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Compute a weighted-signal risk score for a package's behavior.

        Args:
            org_id: Tenant identifier (for audit / downstream emission).
            package_purl: Package URL (pkg:npm/.., pkg:pypi/..).
            signals: Dict of signal_name -> value. Booleans contribute full
                weight; numeric values in [0,1] scale the weight linearly.

        Returns:
            {risk_score, risk_level, contributing: [{signal, weight}]}
        """
        if not package_purl:
            raise ValueError("package_purl is required")
        if not isinstance(signals, dict):
            raise ValueError("signals must be a dict")

        score = 0.0
        contributing: List[Dict[str, Any]] = []

        for name, weight in self._SIGNAL_WEIGHTS.items():
            raw = signals.get(name)
            if raw is None or raw is False:
                continue
            if isinstance(raw, bool):
                factor = 1.0 if raw else 0.0
            else:
                try:
                    factor = float(raw)
                except (TypeError, ValueError):
                    continue
                if factor <= 0:
                    continue
                # Clamp 0..1 for continuous signals
                factor = max(0.0, min(1.0, factor))
            contribution = weight * factor
            if contribution <= 0:
                continue
            score += contribution
            contributing.append({
                "signal": name,
                "value": raw,
                "weight": weight,
                "contribution": round(contribution, 2),
            })

        score = max(0.0, min(100.0, score))
        if score >= 80.0:
            level = "critical"
        elif score >= 55.0:
            level = "high"
        elif score >= 25.0:
            level = "medium"
        else:
            level = "low"

        result = {
            "org_id": org_id,
            "package_purl": package_purl,
            "risk_score": round(score, 2),
            "risk_level": level,
            "contributing": contributing,
            "scored_at": self._now(),
        }

        _logger.info(
            "scad.score_package_behavior org=%s purl=%s score=%.2f level=%s signals=%d",
            org_id, package_purl, score, level, len(contributing),
        )

        if _get_tg_bus is not None and level in {"high", "critical"}:
            try:
                _get_tg_bus().emit("THREAT_DETECTED", {
                    "org_id": org_id,
                    "entity": "malicious_package_score",
                    "package_purl": package_purl,
                    "risk_score": round(score, 2),
                    "risk_level": level,
                    "signals": [c["signal"] for c in contributing],
                })
            except Exception:
                pass

        return result

    # ------------------------------------------------------------------
    # QUARANTINE QUEUE (GAP-009)
    # ------------------------------------------------------------------

    def quarantine_package(
        self,
        org_id: str,
        package_purl: str,
        reason: str,
        quarantined_by: str,
    ) -> Dict[str, Any]:
        """Quarantine a package (purl) for an org. Unique on (org_id, purl)
        while active (released_at IS NULL). Raises ValueError if already
        actively quarantined.
        """
        if not package_purl:
            raise ValueError("package_purl is required")
        if not reason:
            raise ValueError("reason is required")
        if not quarantined_by:
            raise ValueError("quarantined_by is required")

        qid = str(uuid.uuid4())
        now = self._now()
        with self._lock, self._connect() as conn:
            existing = conn.execute(
                """SELECT id FROM quarantined_packages
                   WHERE org_id=? AND package_purl=? AND released_at IS NULL""",
                (org_id, package_purl),
            ).fetchone()
            if existing is not None:
                raise ValueError(
                    f"Package {package_purl} already actively quarantined for org {org_id}"
                )
            conn.execute(
                """INSERT INTO quarantined_packages
                   (id, org_id, package_purl, reason, quarantined_by,
                    quarantined_at, released_at, released_by, release_reason)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (qid, org_id, package_purl, reason, quarantined_by,
                 now, None, None, None),
            )

        _logger.info(
            "scad.quarantine org=%s purl=%s by=%s", org_id, package_purl, quarantined_by
        )
        if _get_tg_bus is not None:
            try:
                _get_tg_bus().emit("POLICY_ENFORCED", {
                    "org_id": org_id,
                    "entity": "malicious_package_quarantine",
                    "package_purl": package_purl,
                    "action": "quarantine",
                    "reason": reason,
                })
            except Exception:
                pass

        return self._get_quarantine_row(qid)

    def release_quarantine(
        self,
        org_id: str,
        package_purl: str,
        released_by: str,
        reason: str,
    ) -> Dict[str, Any]:
        """Release an active quarantine for (org_id, package_purl)."""
        if not released_by:
            raise ValueError("released_by is required")
        if not reason:
            raise ValueError("reason is required")

        now = self._now()
        with self._lock, self._connect() as conn:
            row = conn.execute(
                """SELECT id FROM quarantined_packages
                   WHERE org_id=? AND package_purl=? AND released_at IS NULL""",
                (org_id, package_purl),
            ).fetchone()
            if row is None:
                raise ValueError(
                    f"No active quarantine for {package_purl} in org {org_id}"
                )
            qid = row["id"]
            conn.execute(
                """UPDATE quarantined_packages
                   SET released_at=?, released_by=?, release_reason=?
                   WHERE id=?""",
                (now, released_by, reason, qid),
            )

        _logger.info(
            "scad.release_quarantine org=%s purl=%s by=%s", org_id, package_purl, released_by
        )
        if _get_tg_bus is not None:
            try:
                _get_tg_bus().emit("POLICY_ENFORCED", {
                    "org_id": org_id,
                    "entity": "malicious_package_release",
                    "package_purl": package_purl,
                    "action": "release",
                    "reason": reason,
                })
            except Exception:
                pass
        return self._get_quarantine_row(qid)

    def list_quarantine(
        self,
        org_id: str,
        active_only: bool = True,
    ) -> List[Dict[str, Any]]:
        """List quarantined packages for org. active_only excludes released."""
        query = "SELECT * FROM quarantined_packages WHERE org_id=?"
        params: List[Any] = [org_id]
        if active_only:
            query += " AND released_at IS NULL"
        query += " ORDER BY quarantined_at DESC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    def _get_quarantine_row(self, qid: str) -> Dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM quarantined_packages WHERE id=?", (qid,)
            ).fetchone()
        if not row:
            raise ValueError(f"Quarantine record {qid} not found")
        return dict(row)
