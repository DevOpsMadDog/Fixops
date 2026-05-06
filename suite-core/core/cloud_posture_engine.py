"""Cloud Posture Engine — ALDECI. SQLite WAL + RLock + org_id isolation."""
from __future__ import annotations

import logging
import sqlite3

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "cloud_posture.db"
)

VALID_PROVIDERS = frozenset({"aws", "azure", "gcp", "alibaba", "oracle", "ibm"})
VALID_RESOURCE_TYPES = frozenset(
    {"iam", "storage", "compute", "network", "database", "serverless", "container"}
)
VALID_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
VALID_FINDING_STATUSES = frozenset({"open", "suppressed", "resolved", "false_positive"})

_SEVERITY_SCORE_IMPACT = {
    "critical": 10,
    "high": 5,
    "medium": 2,
    "low": 1,
    "info": 0,
}


class CloudPostureEngine:
    """SQLite-backed Cloud Security Posture Management engine.

    All public methods are thread-safe via RLock.
    Multi-tenant via org_id isolation.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS cp_accounts (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    account_id TEXT NOT NULL DEFAULT '',
                    account_name TEXT NOT NULL DEFAULT '',
                    provider TEXT NOT NULL DEFAULT 'aws',
                    region TEXT NOT NULL DEFAULT '',
                    resource_count INTEGER NOT NULL DEFAULT 0,
                    posture_score REAL NOT NULL DEFAULT 100.0,
                    last_scanned DATETIME,
                    status TEXT NOT NULL DEFAULT 'active',
                    created_at DATETIME
                );
                CREATE TABLE IF NOT EXISTS cp_findings (
                    id TEXT PRIMARY KEY,
                    org_id TEXT NOT NULL,
                    cloud_account_id TEXT NOT NULL DEFAULT '',
                    resource_id TEXT NOT NULL DEFAULT '',
                    resource_type TEXT NOT NULL DEFAULT 'compute',
                    provider TEXT NOT NULL DEFAULT 'aws',
                    severity TEXT NOT NULL DEFAULT 'medium',
                    title TEXT NOT NULL DEFAULT '',
                    description TEXT NOT NULL DEFAULT '',
                    remediation TEXT NOT NULL DEFAULT '',
                    status TEXT NOT NULL DEFAULT 'open',
                    detected_at DATETIME,
                    resolved_at DATETIME,
                    notes TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_cp_findings_org_status_sev
                    ON cp_findings(org_id, status, severity);
                CREATE INDEX IF NOT EXISTS idx_cp_accounts_org_provider
                    ON cp_accounts(org_id, provider);
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
    # Accounts
    # ------------------------------------------------------------------

    def register_account(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a cloud account for posture tracking."""
        account_id = data.get("account_id", "").strip()
        if not account_id:
            raise ValueError("account_id is required")
        provider = data.get("provider", "aws")
        if provider not in VALID_PROVIDERS:
            raise ValueError(f"provider must be one of {sorted(VALID_PROVIDERS)}")

        now = datetime.now(timezone.utc).isoformat()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "account_id": account_id,
            "account_name": data.get("account_name", ""),
            "provider": provider,
            "region": data.get("region", ""),
            "resource_count": int(data.get("resource_count", 0)),
            "posture_score": float(data.get("posture_score", 100.0)),
            "last_scanned": data.get("last_scanned"),
            "status": data.get("status", "active"),
            "created_at": now,
        }
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO cp_accounts
                       (id, org_id, account_id, account_name, provider, region,
                        resource_count, posture_score, last_scanned, status, created_at)
                       VALUES (:id, :org_id, :account_id, :account_name, :provider, :region,
                               :resource_count, :posture_score, :last_scanned, :status, :created_at)""",
                    record,
                )
        if _get_tg_bus is not None:
            try:
                _get_tg_bus().emit("ASSET_DISCOVERED", {
                    "org_id": org_id,
                    "entity": "cloud_account",
                    "asset_id": record["id"],
                    "account_id": account_id,
                    "provider": provider,
                })
            except Exception:
                pass
        return record

    def list_accounts(
        self, org_id: str, provider: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List cloud accounts for the org, optionally filtered by provider."""
        query = "SELECT * FROM cp_accounts WHERE org_id = ?"
        params: List[Any] = [org_id]
        if provider:
            query += " AND provider = ?"
            params.append(provider)
        query += " ORDER BY created_at DESC"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    def get_account(self, org_id: str, account_id_param: str) -> Optional[Dict[str, Any]]:
        """Get a single cloud account by internal id, org-isolated."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM cp_accounts WHERE id = ? AND org_id = ?",
                    (account_id_param, org_id),
                ).fetchone()
        return self._row(row) if row else None

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def record_finding(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a cloud posture finding and adjust account posture score."""
        cloud_account_id = data.get("cloud_account_id", data.get("account_id", "")).strip()
        if not cloud_account_id:
            raise ValueError("cloud_account_id is required")
        resource_type = data.get("resource_type", "compute")
        if resource_type not in VALID_RESOURCE_TYPES:
            raise ValueError(f"resource_type must be one of {sorted(VALID_RESOURCE_TYPES)}")
        severity = data.get("severity", "medium")
        if severity not in VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(VALID_SEVERITIES)}")

        now = datetime.now(timezone.utc).isoformat()
        record = {
            "id": str(uuid.uuid4()),
            "org_id": org_id,
            "cloud_account_id": cloud_account_id,
            "resource_id": data.get("resource_id", ""),
            "resource_type": resource_type,
            "provider": data.get("provider", "aws"),
            "severity": severity,
            "title": data.get("title", ""),
            "description": data.get("description", ""),
            "remediation": data.get("remediation", ""),
            "status": "open",
            "detected_at": now,
            "resolved_at": None,
            "notes": data.get("notes", ""),
        }
        impact = _SEVERITY_SCORE_IMPACT.get(severity, 0)
        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """INSERT INTO cp_findings
                       (id, org_id, cloud_account_id, resource_id, resource_type, provider,
                        severity, title, description, remediation, status, detected_at, resolved_at, notes)
                       VALUES (:id, :org_id, :cloud_account_id, :resource_id, :resource_type, :provider,
                               :severity, :title, :description, :remediation, :status, :detected_at,
                               :resolved_at, :notes)""",
                    record,
                )
                # Decrement posture score for the matching account (by internal id or account_id field)
                if impact > 0:
                    conn.execute(
                        """UPDATE cp_accounts
                           SET posture_score = MAX(0.0, posture_score - ?)
                           WHERE org_id = ? AND (id = ? OR account_id = ?)""",
                        (impact, org_id, cloud_account_id, cloud_account_id),
                    )
        return record

    def list_findings(
        self,
        org_id: str,
        provider: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        resource_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List findings with optional filters."""
        query = "SELECT * FROM cp_findings WHERE org_id = ?"
        params: List[Any] = [org_id]
        if provider:
            query += " AND provider = ?"
            params.append(provider)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if status:
            query += " AND status = ?"
            params.append(status)
        if resource_type:
            query += " AND resource_type = ?"
            params.append(resource_type)
        query += " ORDER BY detected_at DESC"
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Connector fallback — CSPMConnector → projects scanner findings
    # ------------------------------------------------------------------

    def list_findings_with_cspm_fallback(
        self,
        org_id: str,
        provider: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        resource_type: Optional[str] = None,
        cspm_connector: Any = None,
        findings_engine: Any = None,
    ) -> Dict[str, Any]:
        """List cp_findings; when org has zero rows AND a CSPM tool was
        previously executed (Prowler / Checkov / Trivy / CloudSploit /
        agentless), project the resulting SecurityFindingsEngine rows whose
        ``source_tool`` starts with ``cspm_via_`` into the cp_findings shape.

        Behaviour:
            - Org-recorded rows always take precedence (returns
              ``source="org_recorded"``).
            - When org has none AND the connector has produced findings in
              ``SecurityFindingsEngine`` (because someone POSTed to
              /api/v1/cspm/scan), those rows are projected one-per-finding,
              tagged ``source="cspm_connector"`` plus ``cspm_tool`` for
              provenance.
            - When neither org rows nor connector rows exist, returns
              ``{"findings": [], "source": "needs_credentials", "hint": ...}``.
            - Filters (provider/severity/status/resource_type) apply to the
              projected rows too.

        Args:
            org_id:           Tenant identifier.
            provider/severity/status/resource_type:  Optional filters.
            cspm_connector:   Override for testing (unused here; reserved for
                              future is_configured() gates).
            findings_engine:  Override for testing — must expose
                              ``.list_findings(org_id=..., source_tool=...)``.

        Returns:
            ``{findings, total, source, hint?, projected_from?}``.
        """
        rows = self.list_findings(
            org_id,
            provider=provider,
            severity=severity,
            status=status,
            resource_type=resource_type,
        )
        if rows:
            return {
                "findings": rows,
                "total": len(rows),
                "source": "org_recorded",
            }

        # Lazy-resolve SecurityFindingsEngine (where CSPMConnector mirrors
        # everything it scrapes from Prowler / Checkov / Trivy / CloudSploit).
        if findings_engine is None:
            try:
                from core.security_findings_engine import SecurityFindingsEngine
                findings_engine = SecurityFindingsEngine()
            except (ImportError, Exception) as exc:  # noqa: BLE001
                _logger.warning(
                    "cloud_posture: SecurityFindingsEngine unavailable: %s",
                    exc,
                )
                return {
                    "findings": [],
                    "total": 0,
                    "source": "needs_credentials",
                    "hint": (
                        "Configure cloud account credentials and run "
                        "POST /api/v1/cspm/scan (Prowler/Checkov/Trivy/"
                        "CloudSploit/agentless) to populate findings, "
                        "or POST /api/v1/cloud-posture/findings to record "
                        "manually."
                    ),
                }

        # Pull every CSPM-tagged finding for the org. We can't scope by
        # source_tool exact match because CSPMConnector emits 5 distinct tags
        # (cspm_via_prowler, cspm_via_checkov, cspm_via_trivy,
        # cspm_via_cloudsploit, cspm_via_agentless), so we list all and
        # filter in Python.
        try:
            all_findings = findings_engine.list_findings(org_id=org_id) or []
        except (ValueError, RuntimeError, OSError) as exc:
            _logger.warning(
                "cloud_posture: SecurityFindingsEngine.list_findings failed "
                "for org=%s: %s", org_id, exc,
            )
            return {
                "findings": [],
                "total": 0,
                "source": "needs_credentials",
                "hint": (
                    "Configure cloud account credentials and run "
                    "POST /api/v1/cspm/scan to populate findings."
                ),
            }

        cspm_findings = [
            f for f in all_findings
            if str(f.get("source_tool") or "").startswith("cspm_via_")
        ]
        if not cspm_findings:
            return {
                "findings": [],
                "total": 0,
                "source": "needs_credentials",
                "hint": (
                    "No CSPM scanner findings recorded for this org. "
                    "Configure cloud account credentials (AWS, Azure, GCP) "
                    "and run POST /api/v1/cspm/scan to invoke "
                    "Prowler/Checkov/Trivy/CloudSploit/agentless. Or POST "
                    "/api/v1/cloud-posture/findings to record manually."
                ),
            }

        derived: List[Dict[str, Any]] = []
        # Map asset_type → cp resource_type vocabulary
        _RTYPE_MAP = {
            "cloud_resource": "compute",
            "iac_resource": "compute",
            "container_image": "container",
            "kubernetes_cluster": "container",
            "snapshot": "storage",
        }
        # Map SecurityFindings severity vocabulary back to cp_findings vocab.
        # SF uses "informational"; cp_findings uses "info".
        _SEV_MAP = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "informational": "info",
            "info": "info",
        }
        for f in cspm_findings:
            sf_sev = str(f.get("severity") or "medium").lower()
            cp_sev = _SEV_MAP.get(sf_sev, "medium")
            asset_type = str(f.get("asset_type") or "cloud_resource").lower()
            rtype = _RTYPE_MAP.get(asset_type, "compute")
            cspm_tool = str(f.get("source_tool") or "").replace("cspm_via_", "")
            # Apply filters against derived shape
            if provider is not None and provider != "aws":
                # CSPMConnector currently supports aws/azure/gcp; we don't
                # store provider on SF row, default to aws (matches
                # ProwlerNormalizer + cspm_connector default).
                continue
            if severity is not None and severity != cp_sev:
                continue
            if status is not None and status != "open":
                continue
            if resource_type is not None and resource_type != rtype:
                continue
            derived.append({
                "id": f"cspm:{f.get('id', '')}",
                "org_id": org_id,
                "cloud_account_id": str(f.get("asset_id", ""))[:255],
                "resource_id": str(f.get("asset_id", ""))[:255],
                "resource_type": rtype,
                "provider": "aws",  # CSPMConnector default; future: parse cor_key
                "severity": cp_sev,
                "title": str(f.get("title", ""))[:500],
                "description": str(f.get("description", ""))[:4000],
                "remediation": str(f.get("remediation", ""))[:2000],
                "status": "open",
                "detected_at": f.get("first_seen") or f.get("created_at"),
                "resolved_at": None,
                "notes": "",
                # Provenance fields — not in cp_findings columns but UI badges.
                "source": "cspm_connector",
                "cspm_tool": cspm_tool,
                "correlation_key": f.get("correlation_key", ""),
            })

        return {
            "findings": derived,
            "total": len(derived),
            "source": "cspm_connector",
            "projected_from": "SecurityFindingsEngine",
            "hint": (
                "Findings projected from CSPMConnector scanner output "
                "(Prowler/Checkov/Trivy/CloudSploit/agentless). "
                "Org-recorded rows take precedence — POST "
                "/api/v1/cloud-posture/findings to override."
            ),
        }

    def update_finding_status(
        self, org_id: str, finding_id: str, status: str, notes: str = ""
    ) -> Dict[str, Any]:
        """Update a finding's status. Restores posture score when resolved."""
        if status not in VALID_FINDING_STATUSES:
            raise ValueError(f"status must be one of {sorted(VALID_FINDING_STATUSES)}")
        now = datetime.now(timezone.utc).isoformat()
        resolved_at = now if status == "resolved" else None
        with self._lock:
            with self._conn() as conn:
                # Fetch current finding
                row = conn.execute(
                    "SELECT * FROM cp_findings WHERE id = ? AND org_id = ?",
                    (finding_id, org_id),
                ).fetchone()
                if not row:
                    raise ValueError(f"Finding {finding_id} not found")
                finding = self._row(row)
                old_status = finding["status"]

                conn.execute(
                    """UPDATE cp_findings
                       SET status = ?, resolved_at = ?, notes = ?
                       WHERE id = ? AND org_id = ?""",
                    (status, resolved_at, notes, finding_id, org_id),
                )

                # Restore posture score when transitioning to resolved
                if status == "resolved" and old_status != "resolved":
                    impact = _SEVERITY_SCORE_IMPACT.get(finding["severity"], 0)
                    if impact > 0:
                        cloud_account_id = finding["cloud_account_id"]
                        conn.execute(
                            """UPDATE cp_accounts
                               SET posture_score = MIN(100.0, posture_score + ?)
                               WHERE org_id = ? AND (id = ? OR account_id = ?)""",
                            (impact, org_id, cloud_account_id, cloud_account_id),
                        )

        finding["status"] = status
        finding["resolved_at"] = resolved_at
        finding["notes"] = notes
        return finding

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_posture_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregate posture statistics for the org.

        Perf: collapsed from 6 round-trips to 2 (one scalar CTE + one GROUP BY
        per dimension) to eliminate repeated SQLite connection overhead.
        """
        with self._lock:
            with self._conn() as conn:
                # Query 1: all scalar aggregates in one pass via CTE.
                scalar = conn.execute(
                    """
                    WITH accts AS (
                        SELECT COUNT(*) AS cnt, AVG(posture_score) AS avg_score
                        FROM cp_accounts WHERE org_id = ?
                    ),
                    finds AS (
                        SELECT
                            COUNT(*) AS total,
                            SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) AS open_cnt,
                            SUM(CASE WHEN severity = 'critical' THEN 1 ELSE 0 END) AS crit_cnt
                        FROM cp_findings WHERE org_id = ?
                    )
                    SELECT
                        accts.cnt        AS total_accounts,
                        accts.avg_score  AS avg_score,
                        finds.total      AS total_findings,
                        finds.open_cnt   AS open_findings,
                        finds.crit_cnt   AS critical_findings
                    FROM accts, finds
                    """,
                    (org_id, org_id),
                ).fetchone()

                total_accounts = scalar["total_accounts"] or 0
                avg_posture_score = round(scalar["avg_score"] or 100.0, 2)
                total_findings = scalar["total_findings"] or 0
                open_findings = scalar["open_findings"] or 0
                critical_findings = scalar["critical_findings"] or 0

                # Query 2: both GROUP BY breakdowns in a single UNION ALL pass.
                breakdown_rows = conn.execute(
                    """
                    SELECT 'provider' AS dim, provider AS val, COUNT(*) AS cnt
                    FROM cp_accounts WHERE org_id = ? GROUP BY provider
                    UNION ALL
                    SELECT 'severity' AS dim, severity AS val, COUNT(*) AS cnt
                    FROM cp_findings WHERE org_id = ? GROUP BY severity
                    """,
                    (org_id, org_id),
                ).fetchall()

        by_provider: Dict[str, int] = {}
        by_severity: Dict[str, int] = {}
        for r in breakdown_rows:
            if r["dim"] == "provider":
                by_provider[r["val"]] = r["cnt"]
            else:
                by_severity[r["val"]] = r["cnt"]

        return {
            "total_accounts": total_accounts,
            "avg_posture_score": avg_posture_score,
            "total_findings": total_findings,
            "open_findings": open_findings,
            "critical_findings": critical_findings,
            "by_provider": by_provider,
            "by_severity": by_severity,
        }
