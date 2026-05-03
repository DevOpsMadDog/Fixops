"""
CNAPP Engine (Cloud Native Application Protection Platform) — ALDECI.

Aggregates CSPM + CWPP + CIEM scores into a unified cloud risk posture.
Tracks cloud workloads, findings, policies, and composite scores.

Multi-tenant via org_id.  Thread-safe via RLock.  SQLite WAL for concurrency.
"""
from __future__ import annotations

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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "cnapp_engine.db"
)

_VALID_WORKLOAD_TYPES = {"vm", "container", "serverless", "kubernetes_pod", "cloud_function"}
_VALID_CLOUD_PROVIDERS = {"aws", "azure", "gcp", "oci", "alibaba", "ibm", "on_prem"}
_VALID_CATEGORIES = {
    "misconfiguration", "vulnerability", "secret_exposure", "excessive_permission",
    "network_exposure", "malware", "compliance_violation",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_VALID_FINDING_STATUSES = {"open", "suppressed", "resolved"}
_VALID_POLICY_TYPES = {"network", "iam", "encryption", "logging", "backup", "patch", "image"}
_VALID_POLICY_ACTIONS = {"block", "alert", "audit"}

# Score deltas per finding severity when updating workload risk_score
_SEVERITY_DELTA = {"critical": 0.4, "high": 0.2, "medium": 0.1, "low": 0.0, "info": 0.0}

# Score penalties per finding (for CNAPP scoring: per-finding occurrence)
_SCORE_PENALTY_CRITICAL = 15
_SCORE_PENALTY_HIGH = 5


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _grade(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


class CNAPPEngine:
    """SQLite WAL-backed CNAPP engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    Tables: cloud_workloads, cnapp_findings, cloud_policies, cnapp_scores.
    """

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
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS cloud_workloads (
                    workload_id     TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    name            TEXT NOT NULL,
                    workload_type   TEXT NOT NULL DEFAULT 'vm',
                    cloud_provider  TEXT NOT NULL DEFAULT 'aws',
                    region          TEXT NOT NULL DEFAULT '',
                    image_name      TEXT NOT NULL DEFAULT '',
                    image_hash      TEXT NOT NULL DEFAULT '',
                    running         INTEGER NOT NULL DEFAULT 1,
                    privileged      INTEGER NOT NULL DEFAULT 0,
                    risk_score      REAL NOT NULL DEFAULT 0.0,
                    last_scanned    DATETIME,
                    created_at      DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_cw_org
                    ON cloud_workloads (org_id, workload_type, cloud_provider, running);

                CREATE TABLE IF NOT EXISTS cnapp_findings (
                    finding_id      TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    workload_id     TEXT NOT NULL
                        REFERENCES cloud_workloads(workload_id) ON DELETE CASCADE,
                    category        TEXT NOT NULL DEFAULT 'misconfiguration',
                    severity        TEXT NOT NULL DEFAULT 'medium',
                    title           TEXT NOT NULL DEFAULT '',
                    description     TEXT NOT NULL DEFAULT '',
                    remediation     TEXT NOT NULL DEFAULT '',
                    cve_id          TEXT NOT NULL DEFAULT '',
                    status          TEXT NOT NULL DEFAULT 'open',
                    detected_at     DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_cf_org
                    ON cnapp_findings (org_id, workload_id, category, severity, status);

                CREATE TABLE IF NOT EXISTS cloud_policies (
                    policy_id       TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    name            TEXT NOT NULL,
                    policy_type     TEXT NOT NULL DEFAULT 'network',
                    action          TEXT NOT NULL DEFAULT 'alert',
                    severity        TEXT NOT NULL DEFAULT 'medium',
                    cloud_provider  TEXT NOT NULL DEFAULT 'aws',
                    enabled         INTEGER NOT NULL DEFAULT 1,
                    violation_count INTEGER NOT NULL DEFAULT 0,
                    created_at      DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_cp_org
                    ON cloud_policies (org_id, cloud_provider, enabled);

                CREATE TABLE IF NOT EXISTS cnapp_scores (
                    score_id            TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    calculated_at       DATETIME NOT NULL,
                    cspm_score          REAL NOT NULL DEFAULT 100.0,
                    cwpp_score          REAL NOT NULL DEFAULT 100.0,
                    ciem_score          REAL NOT NULL DEFAULT 100.0,
                    composite_score     REAL NOT NULL DEFAULT 100.0,
                    critical_findings   INTEGER NOT NULL DEFAULT 0,
                    high_findings       INTEGER NOT NULL DEFAULT 0,
                    workloads_at_risk   INTEGER NOT NULL DEFAULT 0,
                    grade               TEXT NOT NULL DEFAULT 'A'
                );

                CREATE INDEX IF NOT EXISTS idx_cs_org
                    ON cnapp_scores (org_id, calculated_at);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Cloud Workloads
    # ------------------------------------------------------------------

    def register_workload(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a new cloud workload."""
        workload_id = str(uuid.uuid4())
        now = _now()
        workload_type = data.get("workload_type", "vm")
        if workload_type not in _VALID_WORKLOAD_TYPES:
            workload_type = "vm"
        cloud_provider = data.get("cloud_provider", "aws")
        if cloud_provider not in _VALID_CLOUD_PROVIDERS:
            cloud_provider = "aws"

        record = {
            "workload_id": workload_id,
            "org_id": org_id,
            "name": data.get("name", ""),
            "workload_type": workload_type,
            "cloud_provider": cloud_provider,
            "region": data.get("region", ""),
            "image_name": data.get("image_name", ""),
            "image_hash": data.get("image_hash", ""),
            "running": int(bool(data.get("running", True))),
            "privileged": int(bool(data.get("privileged", False))),
            "risk_score": float(data.get("risk_score", 0.0)),
            "last_scanned": data.get("last_scanned"),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO cloud_workloads
                       (workload_id, org_id, name, workload_type, cloud_provider,
                        region, image_name, image_hash, running, privileged,
                        risk_score, last_scanned, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        record["workload_id"], record["org_id"], record["name"],
                        record["workload_type"], record["cloud_provider"], record["region"],
                        record["image_name"], record["image_hash"], record["running"],
                        record["privileged"], record["risk_score"],
                        record["last_scanned"], record["created_at"],
                    ),
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ENTITY_UPDATED", {"entity_type": "cnapp", "org_id": org_id, "source_engine": "cnapp"})
            except Exception:
                pass

        return record

    def list_workloads(
        self,
        org_id: str,
        workload_type: Optional[str] = None,
        cloud_provider: Optional[str] = None,
        running_only: bool = True,
    ) -> List[Dict[str, Any]]:
        """List cloud workloads with optional filters."""
        query = "SELECT * FROM cloud_workloads WHERE org_id=?"
        params: List[Any] = [org_id]
        if workload_type:
            query += " AND workload_type=?"
            params.append(workload_type)
        if cloud_provider:
            query += " AND cloud_provider=?"
            params.append(cloud_provider)
        if running_only:
            query += " AND running=1"
        query += " ORDER BY risk_score DESC"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def add_finding(
        self, org_id: str, workload_id: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add a CNAPP finding and update the workload's risk_score."""
        finding_id = str(uuid.uuid4())
        detected_at = data.get("detected_at", _now())
        category = data.get("category", "misconfiguration")
        if category not in _VALID_CATEGORIES:
            category = "misconfiguration"
        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            severity = "medium"
        status = data.get("status", "open")
        if status not in _VALID_FINDING_STATUSES:
            status = "open"

        record = {
            "finding_id": finding_id,
            "org_id": org_id,
            "workload_id": workload_id,
            "category": category,
            "severity": severity,
            "title": data.get("title", ""),
            "description": data.get("description", ""),
            "remediation": data.get("remediation", ""),
            "cve_id": data.get("cve_id", ""),
            "status": status,
            "detected_at": detected_at,
        }

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO cnapp_findings
                       (finding_id, org_id, workload_id, category, severity,
                        title, description, remediation, cve_id, status, detected_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        record["finding_id"], record["org_id"], record["workload_id"],
                        record["category"], record["severity"], record["title"],
                        record["description"], record["remediation"],
                        record["cve_id"], record["status"], record["detected_at"],
                    ),
                )
                # Auto-update workload risk_score (capped at 1.0)
                delta = _SEVERITY_DELTA.get(severity, 0.0)
                if delta > 0:
                    conn.execute(
                        """UPDATE cloud_workloads
                           SET risk_score = MIN(1.0, risk_score + ?),
                               last_scanned = ?
                           WHERE workload_id=? AND org_id=?""",
                        (delta, _now(), workload_id, org_id),
                    )

        return record

    def list_findings(
        self,
        org_id: str,
        category: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List CNAPP findings with optional filters."""
        query = "SELECT * FROM cnapp_findings WHERE org_id=?"
        params: List[Any] = [org_id]
        if category:
            query += " AND category=?"
            params.append(category)
        if severity:
            query += " AND severity=?"
            params.append(severity)
        if status:
            query += " AND status=?"
            params.append(status)
        query += " ORDER BY detected_at DESC"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    def suppress_finding(
        self, org_id: str, finding_id: str, reason: str = ""
    ) -> bool:
        """Suppress a finding. Returns True if a row was updated."""
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    """UPDATE cnapp_findings SET status='suppressed'
                       WHERE finding_id=? AND org_id=? AND status='open'""",
                    (finding_id, org_id),
                )
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Policies
    # ------------------------------------------------------------------

    def create_policy(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a cloud security policy."""
        policy_id = str(uuid.uuid4())
        now = _now()
        policy_type = data.get("policy_type", "network")
        if policy_type not in _VALID_POLICY_TYPES:
            policy_type = "network"
        action = data.get("action", "alert")
        if action not in _VALID_POLICY_ACTIONS:
            action = "alert"
        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            severity = "medium"
        cloud_provider = data.get("cloud_provider", "aws")
        if cloud_provider not in _VALID_CLOUD_PROVIDERS:
            cloud_provider = "aws"

        record = {
            "policy_id": policy_id,
            "org_id": org_id,
            "name": data.get("name", ""),
            "policy_type": policy_type,
            "action": action,
            "severity": severity,
            "cloud_provider": cloud_provider,
            "enabled": int(bool(data.get("enabled", True))),
            "violation_count": int(data.get("violation_count", 0)),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO cloud_policies
                       (policy_id, org_id, name, policy_type, action, severity,
                        cloud_provider, enabled, violation_count, created_at)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        record["policy_id"], record["org_id"], record["name"],
                        record["policy_type"], record["action"], record["severity"],
                        record["cloud_provider"], record["enabled"],
                        record["violation_count"], record["created_at"],
                    ),
                )
        return record

    def list_policies(
        self,
        org_id: str,
        cloud_provider: Optional[str] = None,
        enabled_only: bool = True,
    ) -> List[Dict[str, Any]]:
        """List cloud policies with optional filters."""
        query = "SELECT * FROM cloud_policies WHERE org_id=?"
        params: List[Any] = [org_id]
        if cloud_provider:
            query += " AND cloud_provider=?"
            params.append(cloud_provider)
        if enabled_only:
            query += " AND enabled=1"
        query += " ORDER BY created_at DESC"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # CNAPP Scoring
    # ------------------------------------------------------------------

    def calculate_cnapp_score(self, org_id: str) -> Dict[str, Any]:
        """Calculate composite CNAPP score (CSPM + CWPP + CIEM) and persist it.

        Scoring formula per pillar:
          score = 100 - (critical_count * 15) - (high_count * 5), floored at 0.
        CSPM: misconfiguration findings
        CWPP: vulnerability + malware findings
        CIEM: excessive_permission + network_exposure findings
        Composite: (cspm + cwpp + ciem) / 3
        """
        with self._lock:
            with self._conn() as conn:
                def _pillar_score(categories: tuple) -> tuple:
                    placeholders = ",".join("?" * len(categories))
                    critical_count = conn.execute(
                        f"""SELECT COUNT(*) FROM cnapp_findings WHERE org_id=? AND category IN ({placeholders})
                            AND severity='critical' AND status='open'""",  # nosec B608
                        (org_id, *categories),
                    ).fetchone()[0]
                    high_count = conn.execute(
                        f"""SELECT COUNT(*) FROM cnapp_findings WHERE org_id=? AND category IN ({placeholders})
                            AND severity='high' AND status='open'""",  # nosec B608
                        (org_id, *categories),
                    ).fetchone()[0]
                    score = max(0.0, 100.0 - critical_count * _SCORE_PENALTY_CRITICAL
                                - high_count * _SCORE_PENALTY_HIGH)
                    return score, critical_count, high_count

                cspm_score, cspm_crit, cspm_high = _pillar_score(("misconfiguration",))
                cwpp_score, cwpp_crit, cwpp_high = _pillar_score(("vulnerability", "malware"))
                ciem_score, ciem_crit, ciem_high = _pillar_score(
                    ("excessive_permission", "network_exposure")
                )

                composite_score = round((cspm_score + cwpp_score + ciem_score) / 3, 2)
                total_critical = cspm_crit + cwpp_crit + ciem_crit
                total_high = cspm_high + cwpp_high + ciem_high

                # Workloads with risk_score > 0.5
                workloads_at_risk = conn.execute(
                    "SELECT COUNT(*) FROM cloud_workloads WHERE org_id=? AND risk_score > 0.5",
                    (org_id,),
                ).fetchone()[0]

                score_id = str(uuid.uuid4())
                calculated_at = _now()
                grade = _grade(composite_score)

                conn.execute(
                    """INSERT INTO cnapp_scores
                       (score_id, org_id, calculated_at, cspm_score, cwpp_score,
                        ciem_score, composite_score, critical_findings, high_findings,
                        workloads_at_risk, grade)
                       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        score_id, org_id, calculated_at,
                        round(cspm_score, 2), round(cwpp_score, 2), round(ciem_score, 2),
                        composite_score, total_critical, total_high,
                        workloads_at_risk, grade,
                    ),
                )

        return {
            "score_id": score_id,
            "org_id": org_id,
            "calculated_at": calculated_at,
            "cspm_score": round(cspm_score, 2),
            "cwpp_score": round(cwpp_score, 2),
            "ciem_score": round(ciem_score, 2),
            "composite_score": composite_score,
            "critical_findings": total_critical,
            "high_findings": total_high,
            "workloads_at_risk": workloads_at_risk,
            "grade": grade,
        }

    def list_scores(self, org_id: str, limit: int = 10) -> List[Dict[str, Any]]:
        """List CNAPP scores ordered by calculated_at descending."""
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    """SELECT * FROM cnapp_scores WHERE org_id=?
                       ORDER BY calculated_at DESC LIMIT ?""",
                    (org_id, limit),
                ).fetchall()
        return [self._row_to_dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_policy_recommendations(self, org_id: str) -> List[Dict[str, Any]]:
        """Derive actionable policy recommendations from open findings.

        Logic:
        - Group open findings by category + severity.
        - For each group with >=1 finding, emit a recommendation with priority,
          suggested action, and affected workload count.
        - Suppress duplicates when a matching enabled policy already exists.
        Priority: critical > high > medium > low.
        """
        _PRIORITY_ORDER = {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}
        _CATEGORY_POLICY_TYPE = {
            "misconfiguration": "image",
            "vulnerability": "patch",
            "secret_exposure": "encryption",
            "excessive_permission": "iam",
            "network_exposure": "network",
            "malware": "patch",
            "compliance_violation": "logging",
        }
        _CATEGORY_ACTION = {
            "misconfiguration": "alert",
            "vulnerability": "block",
            "secret_exposure": "block",
            "excessive_permission": "alert",
            "network_exposure": "block",
            "malware": "block",
            "compliance_violation": "audit",
        }

        with self._lock:
            with self._conn() as conn:
                # Aggregate open findings by category + severity + workload count
                rows = conn.execute(
                    """SELECT category, severity, COUNT(DISTINCT workload_id) AS wl_count,
                              COUNT(*) AS finding_count
                       FROM cnapp_findings
                       WHERE org_id=? AND status='open'
                       GROUP BY category, severity
                       ORDER BY category, severity""",
                    (org_id,),
                ).fetchall()

                # Fetch already-enabled policies to suppress redundant recs
                existing_policy_rows = conn.execute(
                    "SELECT policy_type, action FROM cloud_policies WHERE org_id=? AND enabled=1",
                    (org_id,),
                ).fetchall()

        existing_policies = {
            (r["policy_type"], r["action"]) for r in existing_policy_rows
        }

        recommendations: List[Dict[str, Any]] = []
        seen: set = set()
        for row in rows:
            category = row["category"]
            severity = row["severity"]
            key = (category, severity)
            if key in seen:
                continue
            seen.add(key)

            policy_type = _CATEGORY_POLICY_TYPE.get(category, "network")
            action = _CATEGORY_ACTION.get(category, "alert")
            already_covered = (policy_type, action) in existing_policies

            recommendations.append({
                "category": category,
                "severity": severity,
                "priority": _PRIORITY_ORDER.get(severity, 5),
                "finding_count": row["finding_count"],
                "affected_workloads": row["wl_count"],
                "suggested_policy_type": policy_type,
                "suggested_action": action,
                "already_covered": already_covered,
                "title": f"Remediate {severity} {category.replace('_', ' ')} findings",
                "description": (
                    f"{row['finding_count']} open {severity}-severity {category} finding(s) "
                    f"across {row['wl_count']} workload(s). "
                    f"Suggested policy: {policy_type}/{action}."
                ),
            })

        # Sort by priority asc, then finding_count desc
        recommendations.sort(key=lambda r: (r["priority"], -r["finding_count"]))
        return recommendations

    def get_cnapp_stats(self, org_id: str) -> Dict[str, Any]:
        """Aggregate CNAPP stats for an org."""
        with self._lock:
            with self._conn() as conn:
                total_workloads = conn.execute(
                    "SELECT COUNT(*) FROM cloud_workloads WHERE org_id=?", (org_id,)
                ).fetchone()[0]
                running_workloads = conn.execute(
                    "SELECT COUNT(*) FROM cloud_workloads WHERE org_id=? AND running=1",
                    (org_id,),
                ).fetchone()[0]
                privileged_workloads = conn.execute(
                    "SELECT COUNT(*) FROM cloud_workloads WHERE org_id=? AND privileged=1",
                    (org_id,),
                ).fetchone()[0]
                open_findings = conn.execute(
                    "SELECT COUNT(*) FROM cnapp_findings WHERE org_id=? AND status='open'",
                    (org_id,),
                ).fetchone()[0]
                critical_findings = conn.execute(
                    "SELECT COUNT(*) FROM cnapp_findings WHERE org_id=? AND severity='critical' AND status='open'",
                    (org_id,),
                ).fetchone()[0]

                # By category
                cat_rows = conn.execute(
                    """SELECT category, COUNT(*) as cnt FROM cnapp_findings
                       WHERE org_id=? AND status='open'
                       GROUP BY category""",
                    (org_id,),
                ).fetchall()
                by_category = {r["category"]: r["cnt"] for r in cat_rows}

                # By cloud provider
                prov_rows = conn.execute(
                    """SELECT cloud_provider, COUNT(*) as cnt FROM cloud_workloads
                       WHERE org_id=?
                       GROUP BY cloud_provider""",
                    (org_id,),
                ).fetchall()
                by_provider = {r["cloud_provider"]: r["cnt"] for r in prov_rows}

                # Latest composite score
                latest_score_row = conn.execute(
                    """SELECT composite_score FROM cnapp_scores WHERE org_id=?
                       ORDER BY calculated_at DESC LIMIT 1""",
                    (org_id,),
                ).fetchone()
                latest_composite_score = latest_score_row["composite_score"] if latest_score_row else None

        return {
            "total_workloads": total_workloads,
            "running_workloads": running_workloads,
            "privileged_workloads": privileged_workloads,
            "open_findings": open_findings,
            "critical_findings": critical_findings,
            "by_category": by_category,
            "by_provider": by_provider,
            "latest_composite_score": latest_composite_score,
        }


# ---------------------------------------------------------------------------
# GAP-025: Multi-CSP workload adapters (OCI, Alibaba, IBM)
# ---------------------------------------------------------------------------

class _BaseWorkloadAdapter:
    provider_name: str = "base"

    _SEED_WORKLOADS: List[Dict[str, Any]] = []
    _SEED_FINDINGS: List[Tuple[str, str, str, str, str]] = []

    def list_resources(self, account_id: str) -> List[Dict[str, Any]]:
        """Return seeded workloads belonging to the given account_id."""
        out: List[Dict[str, Any]] = []
        for i, w in enumerate(self._SEED_WORKLOADS):
            out.append(
                {
                    "workload_id": f"{self.provider_name}-{account_id}-wl-{i:03d}",
                    "account_id": account_id,
                    "name": w["name"],
                    "workload_type": w.get("workload_type", "vm"),
                    "cloud_provider": self.provider_name,
                    "region": w.get("region", "global"),
                    "image_name": w.get("image_name", ""),
                    "running": True,
                    "privileged": w.get("privileged", False),
                }
            )
        return out

    def scan_resource(self, resource: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Synthesize 2-3 findings per workload."""
        findings: List[Dict[str, Any]] = []
        wid = resource.get("workload_id", "unknown")
        provider = resource.get("cloud_provider", self.provider_name)
        for i, rule in enumerate(self._SEED_FINDINGS[:3]):
            title, severity, category, description, remediation = rule
            findings.append(
                {
                    "finding_id": f"CNAPP-{self.provider_name.upper()}-{uuid.uuid4().hex[:8]}",
                    "workload_id": wid,
                    "cloud_provider": provider,
                    "category": category,
                    "severity": severity,
                    "title": title,
                    "description": description,
                    "remediation": remediation,
                    "detected_at": _now(),
                }
            )
        return findings


class OCIWorkloadAdapter(_BaseWorkloadAdapter):
    provider_name = "oci"
    _SEED_WORKLOADS = [
        {"name": "oci-vm-prod-01", "workload_type": "vm", "region": "us-ashburn-1", "image_name": "Oracle-Linux-8.6"},
        {"name": "oci-k8s-pod-01", "workload_type": "kubernetes_pod", "region": "us-ashburn-1", "image_name": "nginx:1.21"},
        {"name": "oci-function-01", "workload_type": "serverless", "region": "us-phoenix-1"},
        {"name": "oci-container-01", "workload_type": "container", "region": "us-ashburn-1", "image_name": "alpine:3.15", "privileged": True},
    ]
    _SEED_FINDINGS = [
        ("OCI Workload Running Privileged Container", "high", "misconfiguration",
         "Container is running in privileged mode.", "Remove --privileged flag."),
        ("OCI Workload Image Has Critical CVE", "critical", "vulnerability",
         "Workload image contains known critical CVEs.", "Upgrade base image to latest patched version."),
        ("OCI Workload Has Excessive IAM Permissions", "high", "excessive_permission",
         "Workload service account has overly broad permissions.", "Apply least-privilege IAM policy."),
    ]


class AlibabaWorkloadAdapter(_BaseWorkloadAdapter):
    provider_name = "alibaba"
    _SEED_WORKLOADS = [
        {"name": "ali-ecs-prod-01", "workload_type": "vm", "region": "cn-hangzhou", "image_name": "centos-7"},
        {"name": "ali-ack-pod-01", "workload_type": "kubernetes_pod", "region": "cn-shanghai", "image_name": "mysql:8.0"},
        {"name": "ali-fc-function-01", "workload_type": "serverless", "region": "cn-beijing"},
        {"name": "ali-container-01", "workload_type": "container", "region": "cn-hangzhou", "image_name": "redis:6.2"},
    ]
    _SEED_FINDINGS = [
        ("Alibaba ECS Instance Exposed To Internet", "high", "network_exposure",
         "ECS instance has public IP and open ports.", "Put instance behind SLB and close direct public IP."),
        ("Alibaba ACK Pod Runs As Root", "medium", "misconfiguration",
         "Kubernetes pod runs as root user.", "Set runAsNonRoot: true in pod securityContext."),
        ("Alibaba Function Compute Uses Deprecated Runtime", "medium", "vulnerability",
         "Function Compute uses an end-of-life runtime.", "Upgrade to a supported runtime version."),
    ]


class IBMWorkloadAdapter(_BaseWorkloadAdapter):
    provider_name = "ibm"
    _SEED_WORKLOADS = [
        {"name": "ibm-vs-prod-01", "workload_type": "vm", "region": "us-south", "image_name": "Ubuntu-20.04"},
        {"name": "ibm-iks-pod-01", "workload_type": "kubernetes_pod", "region": "us-south", "image_name": "python:3.9"},
        {"name": "ibm-function-01", "workload_type": "serverless", "region": "us-east"},
        {"name": "ibm-container-01", "workload_type": "container", "region": "us-south", "image_name": "busybox"},
    ]
    _SEED_FINDINGS = [
        ("IBM VS Instance Has Public IP", "medium", "network_exposure",
         "IBM virtual server has a public IP address.", "Use a load balancer or VPN gateway."),
        ("IBM IKS Pod Missing Security Context", "medium", "misconfiguration",
         "Pod has no securityContext defined.", "Add securityContext with runAsNonRoot and readOnlyRootFilesystem."),
        ("IBM Function Uses Hardcoded Secret", "high", "secret_exposure",
         "IBM Cloud Function contains hardcoded secrets in env vars.", "Move secrets to IBM Secrets Manager."),
    ]


# CNAPP provider registry — 6 providers
PROVIDERS: Dict[str, Any] = {
    "aws": None,
    "azure": None,
    "gcp": None,
    "oci": OCIWorkloadAdapter(),
    "alibaba": AlibabaWorkloadAdapter(),
    "ibm": IBMWorkloadAdapter(),
}


def get_workload_adapter(provider: str):
    if not provider:
        return None
    return PROVIDERS.get(provider.lower())


def list_supported_cnapp_providers() -> List[str]:
    return ["aws", "azure", "gcp", "oci", "alibaba", "ibm"]


# Need Tuple for type hints above
from typing import Tuple  # noqa: E402

# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_engine: Optional[CNAPPEngine] = None
_engine_lock = threading.Lock()


def get_engine(db_path: str = _DEFAULT_DB) -> CNAPPEngine:
    global _engine
    with _engine_lock:
        if _engine is None:
            _engine = CNAPPEngine(db_path)
    return _engine
