"""Cloud Security Engine — ALDECI.

CSPM + cloud misconfiguration tracking across AWS, Azure, GCP, and Alibaba Cloud.

Capabilities:
  - Cloud account registry (multi-provider, risk scoring, status tracking)
  - Security finding lifecycle management (open → suppressed → resolved)
  - Cloud resource inventory with public exposure and encryption tracking
  - CIS/NIST/PCI-DSS benchmark results per account
  - Stats aggregation per org

Compliance: CIS Benchmarks, NIST 800-53, PCI-DSS, SOC 2
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

_DEFAULT_DB_DIR = Path(__file__).resolve().parents[2] / ".fixops_data"

_VALID_PROVIDERS = {"aws", "azure", "gcp", "alibaba"}
_VALID_ACCOUNT_STATUSES = {"healthy", "warning", "critical"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_VALID_CATEGORIES = {"iam", "network", "storage", "compute", "logging", "encryption", "compliance"}
_VALID_FINDING_STATUSES = {"open", "suppressed", "resolved"}
_VALID_BENCHMARKS = {"cis_aws_v1.5", "azure_cis", "gcp_cis", "nist_800_53", "pci_dss"}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class CloudSecurityEngine:
    """SQLite WAL-backed CSPM engine.

    Thread-safe via RLock. Multi-tenant via org_id.
    Each org gets its own database file.
    """

    def __init__(self, org_id: str, db_dir: str = str(_DEFAULT_DB_DIR)) -> None:
        self.org_id = org_id
        db_path = Path(db_dir) / f"{org_id}_cloud_security.db"
        self.db_path = str(db_path)
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
                CREATE TABLE IF NOT EXISTS cloud_accounts (
                    id              TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    account_id      TEXT NOT NULL,
                    account_name    TEXT NOT NULL DEFAULT '',
                    provider        TEXT NOT NULL DEFAULT 'aws',
                    region          TEXT NOT NULL DEFAULT '',
                    status          TEXT NOT NULL DEFAULT 'healthy',
                    resource_count  INTEGER NOT NULL DEFAULT 0,
                    finding_count   INTEGER NOT NULL DEFAULT 0,
                    risk_score      REAL NOT NULL DEFAULT 0.0,
                    last_scanned    DATETIME,
                    created_at      DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ca_org_provider
                    ON cloud_accounts (org_id, provider);

                CREATE TABLE IF NOT EXISTS cloud_findings (
                    id                    TEXT PRIMARY KEY,
                    org_id                TEXT NOT NULL,
                    account_id            TEXT NOT NULL,
                    resource_id           TEXT NOT NULL DEFAULT '',
                    resource_type         TEXT NOT NULL DEFAULT '',
                    resource_name         TEXT NOT NULL DEFAULT '',
                    region                TEXT NOT NULL DEFAULT '',
                    severity              TEXT NOT NULL DEFAULT 'medium',
                    category              TEXT NOT NULL DEFAULT 'compliance',
                    title                 TEXT NOT NULL DEFAULT '',
                    description           TEXT NOT NULL DEFAULT '',
                    remediation           TEXT NOT NULL DEFAULT '',
                    status                TEXT NOT NULL DEFAULT 'open',
                    cis_control           TEXT NOT NULL DEFAULT '',
                    compliance_frameworks TEXT NOT NULL DEFAULT '[]',
                    risk_score            REAL NOT NULL DEFAULT 0.0,
                    created_at            DATETIME NOT NULL,
                    resolved_at           DATETIME
                );

                CREATE INDEX IF NOT EXISTS idx_cf_org_account
                    ON cloud_findings (org_id, account_id, created_at DESC);

                CREATE INDEX IF NOT EXISTS idx_cf_org_severity
                    ON cloud_findings (org_id, severity, status);

                CREATE TABLE IF NOT EXISTS cloud_resources (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    account_id     TEXT NOT NULL,
                    resource_id    TEXT NOT NULL DEFAULT '',
                    resource_type  TEXT NOT NULL DEFAULT '',
                    resource_name  TEXT NOT NULL DEFAULT '',
                    region         TEXT NOT NULL DEFAULT '',
                    tags           TEXT NOT NULL DEFAULT '{}',
                    security_score REAL NOT NULL DEFAULT 100.0,
                    finding_count  INTEGER NOT NULL DEFAULT 0,
                    is_public      INTEGER NOT NULL DEFAULT 0,
                    is_encrypted   INTEGER NOT NULL DEFAULT 1,
                    created_at     DATETIME NOT NULL,
                    updated_at     DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_cr_org_account
                    ON cloud_resources (org_id, account_id);

                CREATE INDEX IF NOT EXISTS idx_cr_org_public
                    ON cloud_resources (org_id, is_public);

                CREATE TABLE IF NOT EXISTS cloud_benchmarks (
                    id          TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    account_id  TEXT NOT NULL,
                    benchmark   TEXT NOT NULL,
                    pass_count  INTEGER NOT NULL DEFAULT 0,
                    fail_count  INTEGER NOT NULL DEFAULT 0,
                    score       REAL NOT NULL DEFAULT 0.0,
                    last_run    DATETIME NOT NULL,
                    created_at  DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_cb_org_account
                    ON cloud_benchmarks (org_id, account_id, last_run DESC);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    # ------------------------------------------------------------------
    # Cloud Accounts
    # ------------------------------------------------------------------

    def add_account(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a cloud account. Returns the created record."""
        account_id = (data.get("account_id") or "").strip()
        if not account_id:
            raise ValueError("account_id is required.")

        provider = data.get("provider", "aws")
        if provider not in _VALID_PROVIDERS:
            raise ValueError(f"Invalid provider: {provider}. Must be one of {_VALID_PROVIDERS}")

        status = data.get("status", "healthy")
        if status not in _VALID_ACCOUNT_STATUSES:
            raise ValueError(f"Invalid status: {status}.")

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "account_id": account_id,
            "account_name": data.get("account_name", ""),
            "provider": provider,
            "region": data.get("region", ""),
            "status": status,
            "resource_count": int(data.get("resource_count", 0)),
            "finding_count": int(data.get("finding_count", 0)),
            "risk_score": float(data.get("risk_score", 0.0)),
            "last_scanned": data.get("last_scanned"),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO cloud_accounts
                       (id, org_id, account_id, account_name, provider, region, status,
                        resource_count, finding_count, risk_score, last_scanned, created_at)
                       VALUES (:id, :org_id, :account_id, :account_name, :provider, :region, :status,
                               :resource_count, :finding_count, :risk_score, :last_scanned, :created_at)""",
                    record,
                )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ASSET_DISCOVERED", {"entity_type": "cloud_security", "org_id": org_id, "source_engine": "cloud_security"})
            except Exception:
                pass

        return record

    def list_accounts(self, org_id: str, provider: Optional[str] = None) -> List[Dict[str, Any]]:
        """List cloud accounts, optionally filtered by provider."""
        sql = "SELECT * FROM cloud_accounts WHERE org_id = ?"
        params: list = [org_id]
        if provider:
            sql += " AND provider = ?"
            params.append(provider)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    # ------------------------------------------------------------------
    # Cloud Findings
    # ------------------------------------------------------------------

    def add_finding(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a cloud security finding. Returns the created record."""
        account_id = (data.get("account_id") or "").strip()
        if not account_id:
            raise ValueError("account_id is required.")

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid severity: {severity}.")

        category = data.get("category", "compliance")
        if category not in _VALID_CATEGORIES:
            raise ValueError(f"Invalid category: {category}.")

        status = data.get("status", "open")
        if status not in _VALID_FINDING_STATUSES:
            raise ValueError(f"Invalid status: {status}.")

        frameworks = data.get("compliance_frameworks", [])
        if isinstance(frameworks, list):
            frameworks_json = json.dumps(frameworks)
        else:
            frameworks_json = str(frameworks)

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "account_id": account_id,
            "resource_id": data.get("resource_id", ""),
            "resource_type": data.get("resource_type", ""),
            "resource_name": data.get("resource_name", ""),
            "region": data.get("region", ""),
            "severity": severity,
            "category": category,
            "title": data.get("title", ""),
            "description": data.get("description", ""),
            "remediation": data.get("remediation", ""),
            "status": status,
            "cis_control": data.get("cis_control", ""),
            "compliance_frameworks": frameworks_json,
            "risk_score": float(data.get("risk_score", 0.0)),
            "created_at": now,
            "resolved_at": None,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO cloud_findings
                       (id, org_id, account_id, resource_id, resource_type, resource_name,
                        region, severity, category, title, description, remediation, status,
                        cis_control, compliance_frameworks, risk_score, created_at, resolved_at)
                       VALUES (:id, :org_id, :account_id, :resource_id, :resource_type, :resource_name,
                               :region, :severity, :category, :title, :description, :remediation, :status,
                               :cis_control, :compliance_frameworks, :risk_score, :created_at, :resolved_at)""",
                    record,
                )
        # Deserialize for return
        record["compliance_frameworks"] = frameworks
        return record

    def list_findings(
        self,
        org_id: str,
        account_id: Optional[str] = None,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """List cloud findings with optional filters."""
        sql = "SELECT * FROM cloud_findings WHERE org_id = ?"
        params: list = [org_id]
        if account_id:
            sql += " AND account_id = ?"
            params.append(account_id)
        if severity:
            sql += " AND severity = ?"
            params.append(severity)
        if category:
            sql += " AND category = ?"
            params.append(category)
        if status:
            sql += " AND status = ?"
            params.append(status)
        sql += " ORDER BY created_at DESC LIMIT ?"
        params.append(limit)
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        results = []
        for row in rows:
            d = self._row(row)
            try:
                d["compliance_frameworks"] = json.loads(d["compliance_frameworks"])
            except Exception:
                d["compliance_frameworks"] = []
            results.append(d)
        return results

    def resolve_finding(self, org_id: str, finding_id: str) -> bool:
        """Mark a finding as resolved. Returns True if found and updated."""
        now = _now_iso()
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    """UPDATE cloud_findings SET status = 'resolved', resolved_at = ?
                       WHERE org_id = ? AND id = ?""",
                    (now, org_id, finding_id),
                )
                return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Cloud Resources
    # ------------------------------------------------------------------

    def add_resource(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a cloud resource. Returns the created record."""
        account_id = (data.get("account_id") or "").strip()
        if not account_id:
            raise ValueError("account_id is required.")

        tags = data.get("tags", {})
        if isinstance(tags, dict):
            tags_json = json.dumps(tags)
        else:
            tags_json = str(tags)

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "account_id": account_id,
            "resource_id": data.get("resource_id", ""),
            "resource_type": data.get("resource_type", ""),
            "resource_name": data.get("resource_name", ""),
            "region": data.get("region", ""),
            "tags": tags_json,
            "security_score": float(data.get("security_score", 100.0)),
            "finding_count": int(data.get("finding_count", 0)),
            "is_public": 1 if data.get("is_public", False) else 0,
            "is_encrypted": 1 if data.get("is_encrypted", True) else 0,
            "created_at": now,
            "updated_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO cloud_resources
                       (id, org_id, account_id, resource_id, resource_type, resource_name,
                        region, tags, security_score, finding_count, is_public, is_encrypted,
                        created_at, updated_at)
                       VALUES (:id, :org_id, :account_id, :resource_id, :resource_type, :resource_name,
                               :region, :tags, :security_score, :finding_count, :is_public, :is_encrypted,
                               :created_at, :updated_at)""",
                    record,
                )
        record["tags"] = tags
        record["is_public"] = bool(record["is_public"])
        record["is_encrypted"] = bool(record["is_encrypted"])
        return record

    def list_resources(
        self,
        org_id: str,
        account_id: Optional[str] = None,
        is_public: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        """List cloud resources with optional filters."""
        sql = "SELECT * FROM cloud_resources WHERE org_id = ?"
        params: list = [org_id]
        if account_id:
            sql += " AND account_id = ?"
            params.append(account_id)
        if is_public is not None:
            sql += " AND is_public = ?"
            params.append(1 if is_public else 0)
        sql += " ORDER BY created_at DESC"
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        results = []
        for row in rows:
            d = self._row(row)
            try:
                d["tags"] = json.loads(d["tags"])
            except Exception:
                d["tags"] = {}
            d["is_public"] = bool(d["is_public"])
            d["is_encrypted"] = bool(d["is_encrypted"])
            results.append(d)
        return results

    # ------------------------------------------------------------------
    # Benchmarks
    # ------------------------------------------------------------------

    def add_benchmark_result(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Save a benchmark run result. Returns the created record."""
        account_id = (data.get("account_id") or "").strip()
        if not account_id:
            raise ValueError("account_id is required.")

        benchmark = data.get("benchmark", "cis_aws_v1.5")
        if benchmark not in _VALID_BENCHMARKS:
            raise ValueError(f"Invalid benchmark: {benchmark}. Must be one of {_VALID_BENCHMARKS}")

        pass_count = int(data.get("pass_count", 0))
        fail_count = int(data.get("fail_count", 0))
        total = pass_count + fail_count
        score = float(data.get("score", (pass_count / total * 100) if total > 0 else 0.0))

        now = _now_iso()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "account_id": account_id,
            "benchmark": benchmark,
            "pass_count": pass_count,
            "fail_count": fail_count,
            "score": score,
            "last_run": data.get("last_run", now),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO cloud_benchmarks
                       (id, org_id, account_id, benchmark, pass_count, fail_count, score, last_run, created_at)
                       VALUES (:id, :org_id, :account_id, :benchmark, :pass_count, :fail_count,
                               :score, :last_run, :created_at)""",
                    record,
                )
        return record

    def list_benchmarks(
        self, org_id: str, account_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List benchmark results, optionally filtered by account."""
        sql = "SELECT * FROM cloud_benchmarks WHERE org_id = ?"
        params: list = [org_id]
        if account_id:
            sql += " AND account_id = ?"
            params.append(account_id)
        sql += " ORDER BY last_run DESC"
        with self._conn() as conn:
            return [self._row(r) for r in conn.execute(sql, params).fetchall()]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_cloud_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated cloud security stats for org."""
        with self._conn() as conn:
            total_accounts = conn.execute(
                "SELECT COUNT(*) FROM cloud_accounts WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            by_provider_rows = conn.execute(
                """SELECT provider, COUNT(*) as cnt FROM cloud_accounts WHERE org_id = ?
                   GROUP BY provider""",
                (org_id,),
            ).fetchall()
            by_provider = {r["provider"]: r["cnt"] for r in by_provider_rows}

            total_findings = conn.execute(
                "SELECT COUNT(*) FROM cloud_findings WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            by_severity_rows = conn.execute(
                """SELECT severity, COUNT(*) as cnt FROM cloud_findings WHERE org_id = ? AND status = 'open'
                   GROUP BY severity""",
                (org_id,),
            ).fetchall()
            by_severity = {r["severity"]: r["cnt"] for r in by_severity_rows}

            by_category_rows = conn.execute(
                """SELECT category, COUNT(*) as cnt FROM cloud_findings WHERE org_id = ? AND status = 'open'
                   GROUP BY category""",
                (org_id,),
            ).fetchall()
            by_category = {r["category"]: r["cnt"] for r in by_category_rows}

            critical_resources = conn.execute(
                "SELECT COUNT(*) FROM cloud_resources WHERE org_id = ? AND is_public = 1",
                (org_id,),
            ).fetchone()[0]

            avg_risk_row = conn.execute(
                "SELECT AVG(risk_score) FROM cloud_accounts WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            avg_risk_score = round(float(avg_risk_row or 0.0), 2)

            bench_rows = conn.execute(
                "SELECT pass_count, fail_count FROM cloud_benchmarks WHERE org_id = ?", (org_id,)
            ).fetchall()
            total_pass = sum(r["pass_count"] for r in bench_rows)
            total_fail = sum(r["fail_count"] for r in bench_rows)
            total_bench = total_pass + total_fail
            benchmark_pass_rate = round(
                (total_pass / total_bench * 100) if total_bench > 0 else 0.0, 2
            )

        return {
            "total_accounts": total_accounts,
            "by_provider": by_provider,
            "total_findings": total_findings,
            "by_severity": by_severity,
            "by_category": by_category,
            "critical_resources": critical_resources,
            "avg_risk_score": avg_risk_score,
            "benchmark_pass_rate": benchmark_pass_rate,
        }


# ---------------------------------------------------------------------------
# Module-level singleton registry (one engine per org_id)
# ---------------------------------------------------------------------------
_engines: Dict[str, CloudSecurityEngine] = {}
_engines_lock = threading.Lock()


def get_engine(org_id: str, db_dir: str = str(_DEFAULT_DB_DIR)) -> CloudSecurityEngine:
    """Return (or create) the CloudSecurityEngine for the given org."""
    with _engines_lock:
        if org_id not in _engines:
            _engines[org_id] = CloudSecurityEngine(org_id=org_id, db_dir=db_dir)
        return _engines[org_id]
