"""Cloud Workload Protection (CWPP) Engine — ALDECI.

Protects cloud workloads (VMs, containers, serverless, Kubernetes pods,
bare metal, managed services) from runtime threats across all major clouds.

Features:
- Workload registration with risk scoring and protection status tracking
- Threat detection (malware, ransomware, container escape, etc.)
- Policy enforcement (block/alert/log) with per-workload-type controls
- Multi-tenant org_id isolation
- CWP stats aggregated by workload_type, cloud_provider, threat_type

Compliance: CIS Benchmarks (AWS/Azure/GCP), NIST SP 800-190 (Container Security),
            CSA CCM, PCI-DSS 6.3, SOC 2 CC6.8
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

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "cloud_workload_protection.db"
)

_VALID_WORKLOAD_TYPES = {
    "vm", "container", "serverless", "kubernetes_pod", "bare_metal", "managed_service",
}
_VALID_CLOUD_PROVIDERS = {
    "aws", "azure", "gcp", "alibaba", "oracle", "on_prem", "multi_cloud",
}
_VALID_RISK_LEVELS = {"critical", "high", "medium", "low"}
_VALID_PROTECTION_STATUSES = {"protected", "partial", "unprotected", "exempt"}
_VALID_THREAT_TYPES = {
    "malware", "ransomware", "cryptomining", "lateral_movement",
    "privilege_escalation", "data_exfil", "backdoor", "supply_chain",
    "container_escape", "serverless_abuse",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_DETECTION_SOURCES = {
    "runtime", "network", "file_integrity", "process", "memory", "api_call",
}
_VALID_THREAT_STATUSES = {
    "detected", "investigating", "contained", "remediated", "false_positive",
}
_VALID_CONTROLS = {
    "file_integrity", "network_segmentation", "runtime_protection",
    "vuln_scanning", "access_control", "logging",
}
_VALID_ENFORCEMENTS = {"block", "alert", "log"}


class CloudWorkloadProtectionEngine:
    """Cloud Workload Protection engine — threat detection, policy, risk scoring."""

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
                CREATE TABLE IF NOT EXISTS cwp_workloads (
                    id                TEXT PRIMARY KEY,
                    org_id            TEXT NOT NULL,
                    workload_name     TEXT NOT NULL,
                    workload_type     TEXT NOT NULL,
                    cloud_provider    TEXT NOT NULL,
                    region            TEXT,
                    account_id        TEXT,
                    risk_score        REAL NOT NULL DEFAULT 50.0,
                    risk_level        TEXT NOT NULL DEFAULT 'medium',
                    protection_status TEXT NOT NULL DEFAULT 'unprotected',
                    last_assessed     TEXT,
                    created_at        TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS cwp_threats (
                    id               TEXT PRIMARY KEY,
                    org_id           TEXT NOT NULL,
                    workload_id      TEXT NOT NULL,
                    threat_type      TEXT NOT NULL,
                    severity         TEXT NOT NULL,
                    detection_source TEXT NOT NULL,
                    status           TEXT NOT NULL DEFAULT 'detected',
                    detected_at      TEXT NOT NULL,
                    created_at       TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS cwp_policies (
                    id             TEXT PRIMARY KEY,
                    org_id         TEXT NOT NULL,
                    policy_name    TEXT NOT NULL,
                    workload_types TEXT NOT NULL DEFAULT '[]',
                    controls       TEXT NOT NULL DEFAULT '[]',
                    enforcement    TEXT NOT NULL DEFAULT 'alert',
                    enabled        INTEGER NOT NULL DEFAULT 1,
                    created_at     TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_cwp_workloads_org
                    ON cwp_workloads(org_id);
                CREATE INDEX IF NOT EXISTS idx_cwp_threats_org
                    ON cwp_threats(org_id);
                CREATE INDEX IF NOT EXISTS idx_cwp_policies_org
                    ON cwp_policies(org_id);
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
    # WORKLOADS
    # ------------------------------------------------------------------

    def register_workload(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register a cloud workload. Returns the workload record."""
        workload_type = data.get("workload_type", "vm")
        if workload_type not in _VALID_WORKLOAD_TYPES:
            raise ValueError(
                f"Invalid workload_type '{workload_type}'. Must be one of {_VALID_WORKLOAD_TYPES}"
            )

        cloud_provider = data.get("cloud_provider", "aws")
        if cloud_provider not in _VALID_CLOUD_PROVIDERS:
            raise ValueError(
                f"Invalid cloud_provider '{cloud_provider}'. Must be one of {_VALID_CLOUD_PROVIDERS}"
            )

        risk_score = float(data.get("risk_score", 50.0))
        risk_level = data.get("risk_level", "medium")
        if risk_level not in _VALID_RISK_LEVELS:
            raise ValueError(f"Invalid risk_level '{risk_level}'.")

        workload_id = str(uuid.uuid4())
        now = self._now()

        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO cwp_workloads
                   (id, org_id, workload_name, workload_type, cloud_provider,
                    region, account_id, risk_score, risk_level, protection_status,
                    last_assessed, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    workload_id, org_id, data["workload_name"], workload_type,
                    cloud_provider, data.get("region"), data.get("account_id"),
                    risk_score, risk_level, "unprotected",
                    data.get("last_assessed"), now,
                ),
            )
        _logger.info(
            "cwp.workload_registered org=%s id=%s name=%s",
            org_id, workload_id, data["workload_name"],
        )
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("ASSET_DISCOVERED", {"entity_type": "cloud_workload_protection", "org_id": org_id, "source_engine": "cloud_workload_protection"})
            except Exception:
                pass

        return self.get_workload(org_id, workload_id)

    def list_workloads(
        self,
        org_id: str,
        workload_type: Optional[str] = None,
        cloud_provider: Optional[str] = None,
        risk_level: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List workloads for org, optionally filtered."""
        query = "SELECT * FROM cwp_workloads WHERE org_id=?"
        params: List[Any] = [org_id]
        if workload_type:
            query += " AND workload_type=?"
            params.append(workload_type)
        if cloud_provider:
            query += " AND cloud_provider=?"
            params.append(cloud_provider)
        if risk_level:
            query += " AND risk_level=?"
            params.append(risk_level)
        query += " ORDER BY created_at DESC"
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Connector fallback — ContainerSecurityConnector → derived workloads
    # ------------------------------------------------------------------

    def list_workloads_with_container_fallback(
        self,
        org_id: str,
        workload_type: Optional[str] = None,
        cloud_provider: Optional[str] = None,
        risk_level: Optional[str] = None,
        container_connector: Any = None,
    ) -> Dict[str, Any]:
        """List CWP workloads; when org has zero rows AND the
        ``ContainerSecurityConnector`` has produced scan history (Trivy +
        Grype + Dockle results per tenant image), project each scanned
        image as a derived ``container`` workload.

        Behaviour:
            - Org-registered rows always take precedence (returns
              ``source="org_registered"``).
            - When org has none AND the container connector exposes scan
              history for ``org_id``, each ``TenantScanResult`` produces one
              derived workload row (workload_type=container,
              cloud_provider=on_prem). Risk score derives from severity
              breakdown: critical/high counts dominate.
            - Each derived row carries provenance: ``source="container_oss"``,
              ``scan_id``, ``image``, ``tenant``.
            - When the connector has no scan history AND its toolchain is
              not configured (no docker/trivy/grype/dockle binaries on PATH
              AND no tenant repos under ``tenants_root``), returns
              ``{"workloads": [], "source": "needs_credentials", "hint": ...}``.
            - Filters apply against derived rows.

        Args:
            org_id:               Tenant identifier.
            workload_type:        Optional filter (vm|container|...).
            cloud_provider:       Optional filter (aws|azure|gcp|on_prem|...).
            risk_level:           Optional filter (critical|high|medium|low).
            container_connector:  Override for testing — must expose
                                  ``get_scan_history(org_id)`` (module-level
                                  helper from container_security_connector)
                                  and optionally ``tool_status()``.

        Returns:
            ``{workloads, total, source, hint?, scans_seen?}``.
        """
        rows = self.list_workloads(
            org_id,
            workload_type=workload_type,
            cloud_provider=cloud_provider,
            risk_level=risk_level,
        )
        if rows:
            return {
                "workloads": rows,
                "total": len(rows),
                "source": "org_registered",
            }

        # Lazy-import container connector helpers.
        scan_history: List[Dict[str, Any]] = []
        connector_obj: Any = None
        if container_connector is None:
            try:
                from connectors.container_security_connector import (
                    get_container_security_connector as _get_connector,
                )
                from connectors.container_security_connector import (
                    get_scan_history as _get_scan_history,
                )
                connector_obj = _get_connector()
                scan_history = _get_scan_history(org_id, limit=200) or []
            except (ImportError, Exception) as exc:  # noqa: BLE001
                _logger.warning(
                    "cwp: ContainerSecurityConnector unavailable: %s", exc,
                )
                return {
                    "workloads": [],
                    "total": 0,
                    "source": "needs_credentials",
                    "hint": (
                        "Install docker + trivy/grype/dockle on the host, "
                        "place tenant repos under FIXOPS_CONTAINER_TENANTS_ROOT "
                        "(default /tmp/aspm-repos), then POST "
                        "/api/v1/container-security/scan to populate scan "
                        "history; or POST /api/v1/cwp/workloads to register "
                        "manually."
                    ),
                }
        else:
            connector_obj = container_connector
            try:
                if hasattr(container_connector, "get_scan_history"):
                    scan_history = container_connector.get_scan_history(
                        org_id, limit=200
                    ) or []
            except (ValueError, RuntimeError, OSError) as exc:
                _logger.warning(
                    "cwp: container_connector.get_scan_history failed: %s",
                    exc,
                )
                scan_history = []

        if not scan_history:
            # Distinguish "configured but no scans yet" vs "not configured".
            tool_state: Dict[str, bool] = {}
            try:
                if connector_obj is not None and hasattr(
                    connector_obj, "tool_status"
                ):
                    tool_state = connector_obj.tool_status() or {}
            except (ValueError, RuntimeError, OSError):
                tool_state = {}
            any_tool = any(tool_state.values())
            tenants_present = False
            try:
                if connector_obj is not None and hasattr(
                    connector_obj, "list_tenants"
                ):
                    tenants_present = bool(connector_obj.list_tenants())
            except (ValueError, RuntimeError, OSError):
                tenants_present = False
            if not any_tool or not tenants_present:
                return {
                    "workloads": [],
                    "total": 0,
                    "source": "needs_credentials",
                    "hint": (
                        f"Container scanner toolchain present={tool_state}; "
                        f"tenant repos detected={tenants_present}. Install "
                        "docker + trivy/grype/dockle, place tenant repos "
                        "under FIXOPS_CONTAINER_TENANTS_ROOT, then POST "
                        "/api/v1/container-security/scan. Or POST "
                        "/api/v1/cwp/workloads to register manually."
                    ),
                    "tool_status": tool_state,
                    "tenants_present": tenants_present,
                }
            return {
                "workloads": [],
                "total": 0,
                "source": "needs_scan",
                "hint": (
                    "Container scanner is configured but no scans have run "
                    "for this org yet. POST /api/v1/container-security/scan "
                    "to populate workloads."
                ),
                "tool_status": tool_state,
            }

        # Collapse history by image — keep most recent scan per image.
        seen_images: set = set()
        ordered = sorted(
            scan_history,
            key=lambda r: r.get("started_at") or "",
            reverse=True,
        )
        derived: List[Dict[str, Any]] = []
        scans_projected = 0
        for scan in ordered:
            image = scan.get("image") or ""
            if not image or image in seen_images:
                continue
            seen_images.add(image)
            sev = scan.get("severity_breakdown") or {}
            critical = int(sev.get("critical") or 0)
            high = int(sev.get("high") or 0)
            medium = int(sev.get("medium") or 0)
            # Risk scoring: critical=10pt, high=5pt, medium=2pt, capped 0..100
            raw_score = critical * 10 + high * 5 + medium * 2
            risk_score_v = float(min(100, raw_score))
            if critical > 0 or risk_score_v >= 80:
                derived_risk = "critical"
            elif high > 0 or risk_score_v >= 50:
                derived_risk = "high"
            elif medium > 0 or risk_score_v >= 20:
                derived_risk = "medium"
            else:
                derived_risk = "low"

            # Build canonical workload values
            derived_workload_type = "container"
            derived_provider = "on_prem"
            findings_recorded = int(scan.get("findings_recorded") or 0)
            protection_status = "protected" if findings_recorded == 0 else (
                "partial" if (high + critical) == 0 else "unprotected"
            )

            # Apply filters against derived shape
            if workload_type is not None and workload_type != derived_workload_type:
                continue
            if cloud_provider is not None and cloud_provider != derived_provider:
                continue
            if risk_level is not None and risk_level != derived_risk:
                continue

            derived.append({
                "id": f"container:{scan.get('scan_id', '')}",
                "org_id": org_id,
                "workload_name": image,
                "workload_type": derived_workload_type,
                "cloud_provider": derived_provider,
                "region": "",
                "account_id": scan.get("tenant", ""),
                "risk_score": risk_score_v,
                "risk_level": derived_risk,
                "protection_status": protection_status,
                "last_assessed": scan.get("completed_at")
                or scan.get("started_at"),
                "created_at": scan.get("started_at"),
                # Provenance fields
                "source": "container_oss",
                "scan_id": scan.get("scan_id", ""),
                "image": image,
                "tenant": scan.get("tenant", ""),
                "findings_recorded": findings_recorded,
                "severity_breakdown": sev,
            })
            scans_projected += 1

        return {
            "workloads": derived,
            "total": len(derived),
            "source": "container_oss",
            "scans_seen": scans_projected,
            "hint": (
                "Workloads projected from ContainerSecurityConnector scan "
                "history (trivy/grype/dockle). Org-registered rows take "
                "precedence — POST /api/v1/cwp/workloads to override."
            ),
        }

    def get_workload(self, org_id: str, workload_id: str) -> Optional[Dict[str, Any]]:
        """Fetch a single workload scoped to org_id, or None if not found."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM cwp_workloads WHERE org_id=? AND id=?",
                (org_id, workload_id),
            ).fetchone()
        return dict(row) if row else None

    def update_protection_status(
        self,
        org_id: str,
        workload_id: str,
        protection_status: str,
    ) -> Dict[str, Any]:
        """Update the protection status of a workload."""
        if protection_status not in _VALID_PROTECTION_STATUSES:
            raise ValueError(
                f"Invalid protection_status '{protection_status}'. "
                f"Must be one of {_VALID_PROTECTION_STATUSES}"
            )
        wl = self.get_workload(org_id, workload_id)
        if wl is None:
            raise ValueError(f"Workload {workload_id} not found for org {org_id}")

        now = self._now()
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE cwp_workloads SET protection_status=?, last_assessed=? WHERE org_id=? AND id=?",
                (protection_status, now, org_id, workload_id),
            )
        _logger.info(
            "cwp.protection_updated org=%s id=%s status=%s",
            org_id, workload_id, protection_status,
        )
        return self.get_workload(org_id, workload_id)

    # ------------------------------------------------------------------
    # THREATS
    # ------------------------------------------------------------------

    def record_threat(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a threat detection against a workload."""
        threat_type = data.get("threat_type")
        if threat_type not in _VALID_THREAT_TYPES:
            raise ValueError(
                f"Invalid threat_type '{threat_type}'. Must be one of {_VALID_THREAT_TYPES}"
            )

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"Invalid severity '{severity}'. Must be one of {_VALID_SEVERITIES}")

        detection_source = data.get("detection_source", "runtime")
        if detection_source not in _VALID_DETECTION_SOURCES:
            raise ValueError(
                f"Invalid detection_source '{detection_source}'. "
                f"Must be one of {_VALID_DETECTION_SOURCES}"
            )

        threat_id = str(uuid.uuid4())
        now = self._now()

        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO cwp_threats
                   (id, org_id, workload_id, threat_type, severity,
                    detection_source, status, detected_at, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?)""",
                (
                    threat_id, org_id, data["workload_id"], threat_type,
                    severity, detection_source, "detected",
                    data.get("detected_at", now), now,
                ),
            )
        _logger.info(
            "cwp.threat_recorded org=%s id=%s type=%s severity=%s",
            org_id, threat_id, threat_type, severity,
        )
        return self._get_threat(org_id, threat_id)

    def list_threats(
        self,
        org_id: str,
        workload_id: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List threats for org, optionally filtered."""
        query = "SELECT * FROM cwp_threats WHERE org_id=?"
        params: List[Any] = [org_id]
        if workload_id:
            query += " AND workload_id=?"
            params.append(workload_id)
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

    def _get_threat(self, org_id: str, threat_id: str) -> Dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM cwp_threats WHERE org_id=? AND id=?",
                (org_id, threat_id),
            ).fetchone()
        if not row:
            raise ValueError(f"Threat {threat_id} not found for org {org_id}")
        return dict(row)

    def update_threat_status(
        self,
        org_id: str,
        threat_id: str,
        status: str,
    ) -> Dict[str, Any]:
        """Update the status of a threat."""
        if status not in _VALID_THREAT_STATUSES:
            raise ValueError(
                f"Invalid status '{status}'. Must be one of {_VALID_THREAT_STATUSES}"
            )
        self._get_threat(org_id, threat_id)  # raises if not found / wrong org
        with self._lock, self._connect() as conn:
            conn.execute(
                "UPDATE cwp_threats SET status=? WHERE org_id=? AND id=?",
                (status, org_id, threat_id),
            )
        _logger.info("cwp.threat_status_updated org=%s id=%s status=%s", org_id, threat_id, status)
        return self._get_threat(org_id, threat_id)

    # ------------------------------------------------------------------
    # POLICIES
    # ------------------------------------------------------------------

    def create_policy(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a CWP policy."""
        enforcement = data.get("enforcement", "alert")
        if enforcement not in _VALID_ENFORCEMENTS:
            raise ValueError(
                f"Invalid enforcement '{enforcement}'. Must be one of {_VALID_ENFORCEMENTS}"
            )

        workload_types = data.get("workload_types", [])
        controls = data.get("controls", [])

        policy_id = str(uuid.uuid4())
        now = self._now()

        with self._lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO cwp_policies
                   (id, org_id, policy_name, workload_types, controls, enforcement, enabled, created_at)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    policy_id, org_id, data["policy_name"],
                    json.dumps(workload_types),
                    json.dumps(controls),
                    enforcement,
                    1 if data.get("enabled", True) else 0,
                    now,
                ),
            )
        _logger.info("cwp.policy_created org=%s id=%s name=%s", org_id, policy_id, data["policy_name"])
        return self._get_policy(org_id, policy_id)

    def list_policies(
        self,
        org_id: str,
        enabled: Optional[bool] = None,
    ) -> List[Dict[str, Any]]:
        """List policies for org, optionally filtered by enabled flag."""
        query = "SELECT * FROM cwp_policies WHERE org_id=?"
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
                "SELECT * FROM cwp_policies WHERE org_id=? AND id=?",
                (org_id, policy_id),
            ).fetchone()
        if not row:
            raise ValueError(f"Policy {policy_id} not found for org {org_id}")
        return self._deserialize_policy(dict(row))

    @staticmethod
    def _deserialize_policy(row: Dict[str, Any]) -> Dict[str, Any]:
        for field in ("workload_types", "controls"):
            if isinstance(row.get(field), str):
                try:
                    row[field] = json.loads(row[field])
                except (json.JSONDecodeError, TypeError):
                    row[field] = []
        row["enabled"] = bool(row.get("enabled", 1))
        return row

    # ------------------------------------------------------------------
    # STATS
    # ------------------------------------------------------------------

    def get_cwp_stats(self, org_id: str) -> Dict[str, Any]:
        """Return CWP overview stats for org_id."""
        with self._connect() as conn:
            total_workloads = conn.execute(
                "SELECT COUNT(*) FROM cwp_workloads WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            protected = conn.execute(
                "SELECT COUNT(*) FROM cwp_workloads WHERE org_id=? AND protection_status='protected'",
                (org_id,),
            ).fetchone()[0]

            unprotected = conn.execute(
                "SELECT COUNT(*) FROM cwp_workloads WHERE org_id=? AND protection_status='unprotected'",
                (org_id,),
            ).fetchone()[0]

            total_threats = conn.execute(
                "SELECT COUNT(*) FROM cwp_threats WHERE org_id=?", (org_id,)
            ).fetchone()[0]

            active_threats = conn.execute(
                "SELECT COUNT(*) FROM cwp_threats WHERE org_id=? AND status IN ('detected','investigating')",
                (org_id,),
            ).fetchone()[0]

            critical_threats = conn.execute(
                "SELECT COUNT(*) FROM cwp_threats WHERE org_id=? AND severity='critical'", (org_id,)
            ).fetchone()[0]

            wtype_rows = conn.execute(
                "SELECT workload_type, COUNT(*) as cnt FROM cwp_workloads WHERE org_id=? GROUP BY workload_type",
                (org_id,),
            ).fetchall()

            provider_rows = conn.execute(
                "SELECT cloud_provider, COUNT(*) as cnt FROM cwp_workloads WHERE org_id=? GROUP BY cloud_provider",
                (org_id,),
            ).fetchall()

            threat_type_rows = conn.execute(
                "SELECT threat_type, COUNT(*) as cnt FROM cwp_threats WHERE org_id=? GROUP BY threat_type",
                (org_id,),
            ).fetchall()

        return {
            "total_workloads": total_workloads,
            "protected_workloads": protected,
            "unprotected_workloads": unprotected,
            "total_threats": total_threats,
            "active_threats": active_threats,
            "critical_threats": critical_threats,
            "by_workload_type": {r["workload_type"]: r["cnt"] for r in wtype_rows},
            "by_cloud_provider": {r["cloud_provider"]: r["cnt"] for r in provider_rows},
            "by_threat_type": {r["threat_type"]: r["cnt"] for r in threat_type_rows},
        }
