"""AI-Powered SOC Engine — ALDECI.

ML-driven detection management with model registry, automation rules,
auto-triage, and SOC statistics.

Compliance: NIST CSF DE.AE, ISO/IEC 27001 A.16.1, SOC 2 CC7.2, MITRE ATT&CK
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
    Path(__file__).resolve().parents[2] / ".fixops_data" / "ai_powered_soc.db"
)

_VALID_MODEL_TYPES = {
    "anomaly_detection", "classification", "nlp", "graph_ml",
    "time_series", "rule_based", "ensemble",
}
_VALID_SEVERITIES = {"critical", "high", "medium", "low"}
_VALID_SOURCE_DATA_TYPES = {"logs", "network", "endpoint", "identity", "cloud", "email", "file"}
_VALID_DETECTION_STATUSES = {
    "new", "triaged", "investigating", "escalated", "resolved", "false_positive",
}
_VALID_MODEL_STATUSES = {"training", "active", "deprecated", "failed"}
_VALID_ACTION_TYPES = {"auto_close", "escalate", "enrich", "notify", "block", "isolate"}


class AIPoweredSOCEngine:
    """SQLite WAL-backed AI-Powered SOC engine.

    Thread-safe via RLock.  Multi-tenant via org_id.
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
                CREATE TABLE IF NOT EXISTS aisoc_detections (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    detection_name      TEXT NOT NULL DEFAULT '',
                    model_type          TEXT NOT NULL DEFAULT 'rule_based',
                    confidence_score    REAL NOT NULL DEFAULT 0.0,
                    severity            TEXT NOT NULL DEFAULT 'medium',
                    source_data_type    TEXT NOT NULL DEFAULT 'logs',
                    status              TEXT NOT NULL DEFAULT 'new',
                    auto_triaged        INTEGER NOT NULL DEFAULT 0,
                    triage_time_seconds INTEGER NOT NULL DEFAULT 0,
                    created_at          TEXT NOT NULL,
                    resolved_at         TEXT
                );

                CREATE INDEX IF NOT EXISTS idx_det_org
                    ON aisoc_detections (org_id, severity, status);

                CREATE TABLE IF NOT EXISTS aisoc_models (
                    id                  TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    model_name          TEXT NOT NULL DEFAULT '',
                    model_type          TEXT NOT NULL DEFAULT 'anomaly_detection',
                    accuracy_score      REAL NOT NULL DEFAULT 0.0,
                    false_positive_rate REAL NOT NULL DEFAULT 0.0,
                    version             TEXT NOT NULL DEFAULT '1.0',
                    training_data_size  INTEGER NOT NULL DEFAULT 0,
                    status              TEXT NOT NULL DEFAULT 'training',
                    deployed_at         TEXT,
                    last_retrained      TEXT,
                    created_at          TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_mdl_org
                    ON aisoc_models (org_id, model_type, status);

                CREATE TABLE IF NOT EXISTS aisoc_automation (
                    id                   TEXT PRIMARY KEY,
                    org_id               TEXT NOT NULL,
                    rule_name            TEXT NOT NULL DEFAULT '',
                    trigger_condition    TEXT NOT NULL DEFAULT '',
                    action_type          TEXT NOT NULL DEFAULT 'notify',
                    confidence_threshold REAL NOT NULL DEFAULT 80.0,
                    execution_count      INTEGER NOT NULL DEFAULT 0,
                    success_count        INTEGER NOT NULL DEFAULT 0,
                    enabled              INTEGER NOT NULL DEFAULT 1,
                    created_at           TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_auto_org
                    ON aisoc_automation (org_id, enabled);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _clamp(value: float, lo: float = 0.0, hi: float = 100.0) -> float:
        return max(lo, min(hi, float(value)))

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        d = dict(row)
        for bool_field in ("auto_triaged", "enabled"):
            if bool_field in d:
                d[bool_field] = bool(d[bool_field])
        return d

    # ------------------------------------------------------------------
    # Detections
    # ------------------------------------------------------------------

    def record_detection(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Record a new AI-driven detection.

        Required keys: detection_name
        Optional: model_type, confidence_score, severity, source_data_type, status
        """
        model_type = data.get("model_type", "rule_based")
        if model_type not in _VALID_MODEL_TYPES:
            raise ValueError(f"model_type must be one of {_VALID_MODEL_TYPES}")

        severity = data.get("severity", "medium")
        if severity not in _VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {_VALID_SEVERITIES}")

        source_data_type = data.get("source_data_type", "logs")
        if source_data_type not in _VALID_SOURCE_DATA_TYPES:
            raise ValueError(f"source_data_type must be one of {_VALID_SOURCE_DATA_TYPES}")

        rec_id = str(uuid.uuid4())
        now = self._now()
        row = {
            "id": rec_id,
            "org_id": org_id,
            "detection_name": data.get("detection_name", ""),
            "model_type": model_type,
            "confidence_score": self._clamp(data.get("confidence_score", 0.0)),
            "severity": severity,
            "source_data_type": source_data_type,
            "status": "new",
            "auto_triaged": 0,
            "triage_time_seconds": 0,
            "created_at": now,
            "resolved_at": None,
        }
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO aisoc_detections
                    (id, org_id, detection_name, model_type, confidence_score,
                     severity, source_data_type, status, auto_triaged,
                     triage_time_seconds, created_at, resolved_at)
                VALUES
                    (:id, :org_id, :detection_name, :model_type, :confidence_score,
                     :severity, :source_data_type, :status, :auto_triaged,
                     :triage_time_seconds, :created_at, :resolved_at)
                """,
                row,
            )
        result = dict(row)
        result["auto_triaged"] = False
        if _get_tg_bus is not None:
            try:
                _get_tg_bus().emit("FINDING_CREATED", {
                    "org_id": org_id,
                    "entity": "aisoc_detection",
                    "detection_id": rec_id,
                    "detection_name": row["detection_name"],
                    "severity": severity,
                    "model_type": model_type,
                })
            except Exception:
                pass
        return result

    def list_detections(
        self,
        org_id: str,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        source_data_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List detections with optional filters."""
        query = "SELECT * FROM aisoc_detections WHERE org_id = ?"
        params: list = [org_id]
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if status:
            query += " AND status = ?"
            params.append(status)
        if source_data_type:
            query += " AND source_data_type = ?"
            params.append(source_data_type)
        query += " ORDER BY created_at DESC"
        with self._lock, self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Type-a #27 — DefenderXDR (live Microsoft Graph) fallback
    # ------------------------------------------------------------------
    # Mapping from Defender XDR finding_type → ALDECI source_data_type
    _DEFENDER_TYPE_TO_SOURCE: Dict[str, str] = {
        "malware":          "endpoint",
        "secret-exposure":  "identity",
        "data-leak":        "cloud",
        "policy-violation": "logs",
        "vulnerability":    "endpoint",
        "anomaly":          "logs",
    }

    def _project_defender_alert_as_detection(
        self, alert: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Project a normalized Defender XDR alert into an aisoc_detection row.

        Returns None if the alert doesn't carry the required minimum (title +
        severity in our valid set).
        """
        if not isinstance(alert, dict):
            return None
        title = str(alert.get("title") or "").strip()
        if not title:
            return None
        severity = alert.get("severity")
        if severity not in _VALID_SEVERITIES:
            # Defender's "informational" or "info" → "low".
            severity = "low" if severity in ("informational", "info") else None
        if severity is None:
            return None
        finding_type = alert.get("finding_type") or "anomaly"
        source_data_type = self._DEFENDER_TYPE_TO_SOURCE.get(finding_type, "logs")
        # CVSS proxy 0..10 → confidence 0..100.
        try:
            cvss = float(alert.get("cvss_score") or 5.0)
        except (TypeError, ValueError):
            cvss = 5.0
        confidence = self._clamp(round(cvss * 10.0, 2))
        alert_id = str(alert.get("alert_id") or alert.get("correlation_key") or "").strip()
        return {
            "id":                  f"defender_xdr|{alert_id}" if alert_id else None,
            "detection_name":      title[:255],
            "model_type":          "rule_based",
            "confidence_score":    confidence,
            "severity":            severity,
            "source_data_type":    source_data_type,
            "status":              "new",
            "auto_triaged":        False,
            "triage_time_seconds": 0,
            "created_at":          alert.get("ingested_at") or self._now(),
            "resolved_at":         None,
            "source":              "defender_xdr",
            "alert_id":            alert_id,
            "asset_id":            alert.get("asset_id", ""),
            "asset_type":          alert.get("asset_type", ""),
            "correlation_key":     alert.get("correlation_key", ""),
        }

    def list_detections_with_xdr_fallback(
        self,
        org_id: str,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        source_data_type: Optional[str] = None,
        xdr_connector: Any = None,
    ) -> Dict[str, Any]:
        """List AI-SOC detections; fall back to Microsoft Defender XDR live alerts.

        Behavior (ranked):

        1. Org has registered detections → ``source="org_registered"``.
        2. Else, if a DefenderXDR live connector is available *and* its OAuth
           creds are present, call ``fetch_alerts()`` and project each alert
           into an ``aps_detection`` shape → ``source="defender_xdr"``.
        3. Else if creds *or* the SDK are missing → ``source="needs_credentials"``
           with a structured hint. NEVER mocks.
        4. Connector returned ``status != "ok"`` (e.g. ``api_error``) →
           ``source="connector_error"``.
        5. Connector OK but returned zero alerts → ``source="needs_data"``.

        Filters apply against the projected rows in modes 2/4/5 too.
        """
        if not isinstance(org_id, str) or not org_id.strip():
            raise ValueError("org_id is required")

        org_rows = self.list_detections(
            org_id,
            severity=severity,
            status=status,
            source_data_type=source_data_type,
        )
        if org_rows:
            return {
                "detections": org_rows,
                "total":      len(org_rows),
                "source":     "org_registered",
            }

        # Resolve connector lazily if not injected (test seam).
        creds_present = False
        connector_unavailable_reason: Optional[str] = None
        if xdr_connector is None:
            try:
                from connectors.defender_xdr_live_connector import (  # type: ignore
                    _creds_present,
                    get_defender_xdr_live_connector,
                )
                creds_present = bool(_creds_present())
                if creds_present:
                    xdr_connector = get_defender_xdr_live_connector()
            except (ImportError, RuntimeError) as exc:
                connector_unavailable_reason = f"connector_import_failed: {exc}"
        else:
            # When injected, treat creds as present so callers can drive the
            # full path in tests.
            creds_present = True

        if not creds_present or xdr_connector is None:
            return {
                "detections": [],
                "total": 0,
                "source": "needs_credentials",
                "hint": (
                    "Set DEFENDER_TENANT_ID, DEFENDER_CLIENT_ID, "
                    "DEFENDER_CLIENT_SECRET to enable Microsoft Defender XDR "
                    "live alert ingestion, or POST /api/v1/ai-soc/detections "
                    "to record a detection manually."
                ),
                **({"reason": connector_unavailable_reason}
                   if connector_unavailable_reason else {}),
            }

        try:
            payload = xdr_connector.fetch_alerts(org_id)
        except Exception as exc:  # noqa: BLE001 - never let connector crash list view
            _logger.warning(
                "DefenderXDR fetch_alerts failed for org=%s: %s", org_id, exc
            )
            return {
                "detections": [],
                "total": 0,
                "source": "connector_error",
                "error": str(exc)[:500],
                "hint": "DefenderXDR API call failed; retry once token/network available.",
            }

        if not isinstance(payload, dict):
            return {
                "detections": [],
                "total": 0,
                "source": "connector_error",
                "error": "fetch_alerts returned non-dict payload",
            }

        connector_status = payload.get("status", "ok")
        if connector_status == "needs_credentials":
            return {
                "detections": [],
                "total": 0,
                "source": "needs_credentials",
                "hint": payload.get(
                    "hint",
                    "DefenderXDR connector reports missing credentials.",
                ),
            }
        if connector_status != "ok":
            return {
                "detections": [],
                "total": 0,
                "source": "connector_error",
                "error": str(payload.get("error", connector_status))[:500],
            }

        raw_alerts = payload.get("alerts") or []
        derived: List[Dict[str, Any]] = []
        seen_ids: set = set()
        for alert in raw_alerts:
            row = self._project_defender_alert_as_detection(alert)
            if row is None:
                continue
            # Dedup on alert_id when present (defender alert_ids are stable).
            ak = row.get("alert_id") or row.get("id") or row["detection_name"]
            if ak in seen_ids:
                continue
            seen_ids.add(ak)
            derived.append(row)

        if not derived:
            return {
                "detections": [],
                "total": 0,
                "source": "needs_data",
                "hint": (
                    "DefenderXDR connector returned no alerts. Trigger a fresh "
                    "pull or wait for new Microsoft Graph events."
                ),
            }

        # Apply filters against derived rows.
        if severity:
            derived = [r for r in derived if r["severity"] == severity]
        if status:
            derived = [r for r in derived if r["status"] == status]
        if source_data_type:
            derived = [r for r in derived if r["source_data_type"] == source_data_type]

        return {
            "detections": derived,
            "total":      len(derived),
            "source":     "defender_xdr",
            "ingested_at": payload.get("ingested_at"),
        }

    def triage_detection(
        self,
        org_id: str,
        detection_id: str,
        new_status: str,
        auto_triaged: bool = False,
        triage_time_seconds: int = 0,
    ) -> Dict[str, Any]:
        """Update the status of a detection (triage workflow).

        Raises KeyError if detection not found for org.
        """
        if new_status not in _VALID_DETECTION_STATUSES:
            raise ValueError(f"new_status must be one of {_VALID_DETECTION_STATUSES}")

        resolved_at = self._now() if new_status in ("resolved", "false_positive") else None

        with self._lock, self._conn() as conn:
            conn.execute(
                """
                UPDATE aisoc_detections
                SET status = ?, auto_triaged = ?, triage_time_seconds = ?,
                    resolved_at = COALESCE(?, resolved_at)
                WHERE id = ? AND org_id = ?
                """,
                (
                    new_status,
                    1 if auto_triaged else 0,
                    triage_time_seconds,
                    resolved_at,
                    detection_id,
                    org_id,
                ),
            )
            row = conn.execute(
                "SELECT * FROM aisoc_detections WHERE id = ? AND org_id = ?",
                (detection_id, org_id),
            ).fetchone()

        if not row:
            raise KeyError(f"Detection {detection_id} not found for org {org_id}")
        return self._row(row)

    # ------------------------------------------------------------------
    # Models
    # ------------------------------------------------------------------

    def register_model(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Register an AI/ML model for the SOC.

        Required keys: model_name
        Optional: model_type, accuracy_score, false_positive_rate, version,
                  training_data_size, status, deployed_at, last_retrained
        """
        model_type = data.get("model_type", "anomaly_detection")
        if model_type not in _VALID_MODEL_TYPES:
            raise ValueError(f"model_type must be one of {_VALID_MODEL_TYPES}")

        model_id = str(uuid.uuid4())
        now = self._now()
        row = {
            "id": model_id,
            "org_id": org_id,
            "model_name": data.get("model_name", ""),
            "model_type": model_type,
            "accuracy_score": self._clamp(data.get("accuracy_score", 0.0)),
            "false_positive_rate": self._clamp(data.get("false_positive_rate", 0.0)),
            "version": data.get("version", "1.0"),
            "training_data_size": int(data.get("training_data_size", 0)),
            "status": "training",
            "deployed_at": data.get("deployed_at"),
            "last_retrained": data.get("last_retrained"),
            "created_at": now,
        }
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO aisoc_models
                    (id, org_id, model_name, model_type, accuracy_score,
                     false_positive_rate, version, training_data_size, status,
                     deployed_at, last_retrained, created_at)
                VALUES
                    (:id, :org_id, :model_name, :model_type, :accuracy_score,
                     :false_positive_rate, :version, :training_data_size, :status,
                     :deployed_at, :last_retrained, :created_at)
                """,
                row,
            )
        return dict(row)

    def update_model_status(
        self,
        org_id: str,
        model_id: str,
        status: str,
        last_retrained: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Update a model's status (and optionally last_retrained timestamp)."""
        if status not in _VALID_MODEL_STATUSES:
            raise ValueError(f"status must be one of {_VALID_MODEL_STATUSES}")

        with self._lock, self._conn() as conn:
            conn.execute(
                """
                UPDATE aisoc_models
                SET status = ?,
                    last_retrained = COALESCE(?, last_retrained)
                WHERE id = ? AND org_id = ?
                """,
                (status, last_retrained, model_id, org_id),
            )
            row = conn.execute(
                "SELECT * FROM aisoc_models WHERE id = ? AND org_id = ?",
                (model_id, org_id),
            ).fetchone()

        if not row:
            raise KeyError(f"Model {model_id} not found for org {org_id}")
        return self._row(row)

    def list_models(
        self,
        org_id: str,
        model_type: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List models with optional filters."""
        query = "SELECT * FROM aisoc_models WHERE org_id = ?"
        params: list = [org_id]
        if model_type:
            query += " AND model_type = ?"
            params.append(model_type)
        if status:
            query += " AND status = ?"
            params.append(status)
        query += " ORDER BY created_at DESC"
        with self._lock, self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Automation Rules
    # ------------------------------------------------------------------

    def create_automation_rule(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create an automation rule.

        Required keys: rule_name
        Optional: trigger_condition, action_type, confidence_threshold, enabled
        """
        action_type = data.get("action_type", "notify")
        if action_type not in _VALID_ACTION_TYPES:
            raise ValueError(f"action_type must be one of {_VALID_ACTION_TYPES}")

        rule_id = str(uuid.uuid4())
        now = self._now()
        row = {
            "id": rule_id,
            "org_id": org_id,
            "rule_name": data.get("rule_name", ""),
            "trigger_condition": data.get("trigger_condition", ""),
            "action_type": action_type,
            "confidence_threshold": self._clamp(data.get("confidence_threshold", 80.0)),
            "execution_count": 0,
            "success_count": 0,
            "enabled": 1 if data.get("enabled", True) else 0,
            "created_at": now,
        }
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                INSERT INTO aisoc_automation
                    (id, org_id, rule_name, trigger_condition, action_type,
                     confidence_threshold, execution_count, success_count,
                     enabled, created_at)
                VALUES
                    (:id, :org_id, :rule_name, :trigger_condition, :action_type,
                     :confidence_threshold, :execution_count, :success_count,
                     :enabled, :created_at)
                """,
                row,
            )
        result = dict(row)
        result["enabled"] = bool(row["enabled"])
        return result

    def execute_automation(
        self, org_id: str, rule_id: str, success: bool = True
    ) -> Dict[str, Any]:
        """Increment execution counters for an automation rule.

        Raises KeyError if rule not found.
        """
        with self._lock, self._conn() as conn:
            conn.execute(
                """
                UPDATE aisoc_automation
                SET execution_count = execution_count + 1,
                    success_count   = success_count + ?
                WHERE id = ? AND org_id = ?
                """,
                (1 if success else 0, rule_id, org_id),
            )
            row = conn.execute(
                "SELECT * FROM aisoc_automation WHERE id = ? AND org_id = ?",
                (rule_id, org_id),
            ).fetchone()

        if not row:
            raise KeyError(f"Automation rule {rule_id} not found for org {org_id}")
        return self._row(row)

    def list_automation_rules(
        self, org_id: str, enabled: Optional[bool] = None
    ) -> List[Dict[str, Any]]:
        """List automation rules with optional enabled filter."""
        query = "SELECT * FROM aisoc_automation WHERE org_id = ?"
        params: list = [org_id]
        if enabled is not None:
            query += " AND enabled = ?"
            params.append(1 if enabled else 0)
        query += " ORDER BY created_at DESC"
        with self._lock, self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # GAP-044: Teammate-mode playbook drafter
    # ------------------------------------------------------------------

    _PLAYBOOK_TEMPLATES: Dict[str, List[str]] = {
        "ransomware": [
            "Isolate affected endpoints at network layer",
            "Disable lateral movement via domain credential reset",
            "Snapshot forensic disk images",
            "Activate crisis communications (legal, exec, PR)",
            "Engage backup recovery workflow",
            "Contact law enforcement if required",
        ],
        "phishing": [
            "Pull email from all inboxes via O365/Gmail admin",
            "Block sender domain at email gateway",
            "Reset credentials for any recipient who clicked",
            "Run endpoint scan on affected users' laptops",
            "Deliver targeted awareness training",
        ],
        "data_breach": [
            "Confirm exfiltration scope via DLP/network logs",
            "Freeze impacted accounts and rotate API keys",
            "Engage legal + privacy counsel for notification obligations",
            "Preserve forensic evidence (memory, disk, logs)",
            "Prepare regulatory notification (GDPR 72h, CCPA, etc)",
            "Internal and external comms after scope confirmed",
        ],
        "credential_theft": [
            "Revoke affected sessions/tokens immediately",
            "Force password reset on impacted identities",
            "Require MFA re-enrollment",
            "Review IAM entitlements for privilege escalation indicators",
            "Scan SIEM for anomalous logins (geolocation, impossible travel)",
        ],
        "insider_threat": [
            "Pause insider access pending investigation",
            "Preserve user activity audit logs (UEBA)",
            "Engage HR + legal in parallel",
            "Review data access history over last 90 days",
            "Plan controlled exit if employee separation is warranted",
        ],
    }

    def teammate_draft_playbook(
        self,
        org_id: str,
        incident_type: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Teammate-mode: return a draft playbook outline for an incident type.

        If ``incident_type`` matches a known template, returns that template
        enriched with context-aware notes. Otherwise returns a generic
        skeleton so the analyst can edit and save.
        """
        if not isinstance(org_id, str) or not org_id:
            raise ValueError("org_id must be a non-empty string")
        incident_type = (incident_type or "").strip().lower().replace(" ", "_")
        if not incident_type:
            raise ValueError("incident_type is required")
        context = context or {}

        template_steps = self._PLAYBOOK_TEMPLATES.get(incident_type)
        if template_steps is None:
            steps = [
                "Detect & validate the alert",
                "Contain the affected scope",
                "Eradicate the root cause",
                "Recover systems to baseline",
                "Conduct post-incident review",
            ]
            source = "generic_ir_skeleton"
            matched = False
        else:
            steps = list(template_steps)
            source = "template"
            matched = True

        severity_hint = context.get("severity", "medium")
        affected_assets = context.get("affected_assets", [])

        return {
            "incident_type": incident_type,
            "matched_template": matched,
            "source": source,
            "severity_hint": severity_hint,
            "affected_asset_count": len(affected_assets) if isinstance(affected_assets, list) else 0,
            "steps": [
                {"order": idx + 1, "action": step, "status": "pending"}
                for idx, step in enumerate(steps)
            ],
            "estimated_runtime_hours": max(2, len(steps)),
            "required_roles": [
                "ir_lead",
                "soc_analyst",
                "comms_lead",
                "exec_sponsor",
            ],
            "drafted_at": self._now(),
            "org_id": org_id,
        }

    def get_soc_stats(self, org_id: str) -> Dict[str, Any]:
        """Return aggregated SOC statistics for an org."""
        with self._lock, self._conn() as conn:
            total_detections = conn.execute(
                "SELECT COUNT(*) FROM aisoc_detections WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            auto_triaged_count = conn.execute(
                "SELECT COUNT(*) FROM aisoc_detections WHERE org_id = ? AND auto_triaged = 1",
                (org_id,),
            ).fetchone()[0]

            avg_triage_row = conn.execute(
                "SELECT AVG(triage_time_seconds) FROM aisoc_detections WHERE org_id = ?",
                (org_id,),
            ).fetchone()[0]
            avg_triage_time = round(avg_triage_row, 2) if avg_triage_row else 0.0

            fp_count = conn.execute(
                "SELECT COUNT(*) FROM aisoc_detections WHERE org_id = ? AND status = 'false_positive'",
                (org_id,),
            ).fetchone()[0]
            false_positive_rate = (
                round(fp_count / total_detections * 100, 2) if total_detections else 0.0
            )

            active_models = conn.execute(
                "SELECT COUNT(*) FROM aisoc_models WHERE org_id = ? AND status = 'active'",
                (org_id,),
            ).fetchone()[0]

            avg_acc_row = conn.execute(
                "SELECT AVG(accuracy_score) FROM aisoc_models WHERE org_id = ? AND status = 'active'",
                (org_id,),
            ).fetchone()[0]
            avg_model_accuracy = round(avg_acc_row, 2) if avg_acc_row else 0.0

            total_automation_rules = conn.execute(
                "SELECT COUNT(*) FROM aisoc_automation WHERE org_id = ?", (org_id,)
            ).fetchone()[0]

            sev_rows = conn.execute(
                """
                SELECT severity, COUNT(*) AS cnt
                FROM aisoc_detections WHERE org_id = ?
                GROUP BY severity
                """,
                (org_id,),
            ).fetchall()
            by_severity = {r["severity"]: r["cnt"] for r in sev_rows}

            mt_rows = conn.execute(
                """
                SELECT model_type, COUNT(*) AS cnt
                FROM aisoc_detections WHERE org_id = ?
                GROUP BY model_type
                """,
                (org_id,),
            ).fetchall()
            by_model_type = {r["model_type"]: r["cnt"] for r in mt_rows}

            st_rows = conn.execute(
                """
                SELECT status, COUNT(*) AS cnt
                FROM aisoc_detections WHERE org_id = ?
                GROUP BY status
                """,
                (org_id,),
            ).fetchall()
            by_status = {r["status"]: r["cnt"] for r in st_rows}

        return {
            "org_id": org_id,
            "total_detections": total_detections,
            "auto_triaged_count": auto_triaged_count,
            "avg_triage_time": avg_triage_time,
            "false_positive_rate": false_positive_rate,
            "active_models": active_models,
            "avg_model_accuracy": avg_model_accuracy,
            "total_automation_rules": total_automation_rules,
            "by_severity": by_severity,
            "by_model_type": by_model_type,
            "by_status": by_status,
        }
