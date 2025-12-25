"""Webhook receivers for bidirectional integration sync."""

import hashlib
import hmac
import json
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Header, HTTPException, Request
from pydantic import BaseModel

router = APIRouter(prefix="/api/v1/webhooks", tags=["webhooks"])

_DATA_DIR = Path("data/integrations")
_db_path: Optional[Path] = None


def _get_db_path() -> Path:
    global _db_path
    if _db_path is None:
        _db_path = _DATA_DIR / "webhooks.db"
        _db_path.parent.mkdir(parents=True, exist_ok=True)
    return _db_path


def _init_db():
    conn = sqlite3.connect(_get_db_path())
    cursor = conn.cursor()

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS integration_mappings (
            mapping_id TEXT PRIMARY KEY,
            cluster_id TEXT NOT NULL,
            integration_type TEXT NOT NULL,
            external_id TEXT NOT NULL,
            external_url TEXT,
            external_status TEXT,
            fixops_status TEXT,
            last_synced TEXT NOT NULL,
            sync_direction TEXT DEFAULT 'outbound',
            created_at TEXT NOT NULL,
            UNIQUE(cluster_id, integration_type)
        )
    """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS webhook_events (
            event_id TEXT PRIMARY KEY,
            integration_type TEXT NOT NULL,
            event_type TEXT NOT NULL,
            external_id TEXT,
            payload TEXT NOT NULL,
            processed BOOLEAN DEFAULT FALSE,
            processed_at TEXT,
            error TEXT,
            created_at TEXT NOT NULL
        )
    """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS sync_drift (
            drift_id TEXT PRIMARY KEY,
            mapping_id TEXT NOT NULL,
            fixops_status TEXT,
            external_status TEXT,
            detected_at TEXT NOT NULL,
            resolved BOOLEAN DEFAULT FALSE,
            resolved_at TEXT,
            resolution TEXT,
            FOREIGN KEY (mapping_id) REFERENCES integration_mappings(mapping_id)
        )
    """
    )

    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_mappings_cluster ON integration_mappings(cluster_id)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_mappings_external ON integration_mappings(integration_type, external_id)"
    )
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_events_processed ON webhook_events(processed)"
    )

    conn.commit()
    conn.close()


_init_db()


class JiraWebhookPayload(BaseModel):
    webhookEvent: str
    issue: Optional[Dict[str, Any]] = None
    changelog: Optional[Dict[str, Any]] = None
    user: Optional[Dict[str, Any]] = None


class ServiceNowWebhookPayload(BaseModel):
    event_type: str
    sys_id: str
    number: Optional[str] = None
    state: Optional[str] = None
    assignment_group: Optional[str] = None
    assigned_to: Optional[str] = None
    short_description: Optional[str] = None
    additional_info: Optional[Dict[str, Any]] = None


class CreateMappingRequest(BaseModel):
    cluster_id: str
    integration_type: str
    external_id: str
    external_url: Optional[str] = None
    external_status: Optional[str] = None


class DriftResolutionRequest(BaseModel):
    resolution: str
    apply_fixops_status: Optional[bool] = False
    apply_external_status: Optional[bool] = False


def _verify_jira_signature(payload: bytes, signature: str, secret: str) -> bool:
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)


def _map_jira_status_to_fixops(jira_status: str) -> str:
    status_map = {
        "To Do": "open",
        "Open": "open",
        "In Progress": "in_progress",
        "In Review": "in_progress",
        "Done": "resolved",
        "Closed": "resolved",
        "Won't Fix": "accepted_risk",
        "Won't Do": "accepted_risk",
        "Duplicate": "false_positive",
    }
    return status_map.get(jira_status, "open")


def _map_servicenow_state_to_fixops(state: str) -> str:
    state_map = {
        "1": "open",
        "2": "in_progress",
        "3": "in_progress",
        "4": "in_progress",
        "5": "in_progress",
        "6": "resolved",
        "7": "resolved",
        "8": "accepted_risk",
    }
    return state_map.get(state, "open")


def _detect_drift(
    mapping_id: str, fixops_status: str, external_status: str
) -> Optional[str]:
    if fixops_status != external_status:
        conn = sqlite3.connect(_get_db_path())
        try:
            cursor = conn.cursor()
            drift_id = str(uuid.uuid4())
            now = datetime.utcnow().isoformat()

            cursor.execute(
                """
                INSERT INTO sync_drift (
                    drift_id, mapping_id, fixops_status, external_status, detected_at
                ) VALUES (?, ?, ?, ?, ?)
            """,
                (drift_id, mapping_id, fixops_status, external_status, now),
            )
            conn.commit()
            return drift_id
        finally:
            conn.close()
    return None


@router.post("/jira")
async def receive_jira_webhook(
    request: Request,
    x_atlassian_webhook_identifier: Optional[str] = Header(None),
) -> Dict[str, Any]:
    """Receive webhook events from Jira for bidirectional sync."""
    body = await request.body()

    try:
        payload_dict = json.loads(body)
        payload = JiraWebhookPayload(**payload_dict)
    except (json.JSONDecodeError, ValueError) as e:
        raise HTTPException(status_code=400, detail=f"Invalid payload: {e}")

    event_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()

    conn = sqlite3.connect(_get_db_path())
    try:
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO webhook_events (
                event_id, integration_type, event_type, external_id, payload, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
        """,
            (
                event_id,
                "jira",
                payload.webhookEvent,
                payload.issue.get("key") if payload.issue else None,
                json.dumps(payload_dict),
                now,
            ),
        )

        result = {
            "event_id": event_id,
            "status": "received",
            "event_type": payload.webhookEvent,
        }

        if payload.issue and payload.webhookEvent in [
            "jira:issue_updated",
            "jira:issue_deleted",
        ]:
            issue_key = payload.issue.get("key")
            issue_status = None

            if payload.issue.get("fields", {}).get("status"):
                issue_status = payload.issue["fields"]["status"].get("name")

            cursor.execute(
                """
                SELECT mapping_id, cluster_id, fixops_status
                FROM integration_mappings
                WHERE integration_type = 'jira' AND external_id = ?
            """,
                (issue_key,),
            )
            mapping = cursor.fetchone()

            if mapping and issue_status:
                mapping_id, cluster_id, fixops_status = mapping
                external_status = _map_jira_status_to_fixops(issue_status)

                cursor.execute(
                    """
                    UPDATE integration_mappings
                    SET external_status = ?, last_synced = ?
                    WHERE mapping_id = ?
                """,
                    (external_status, now, mapping_id),
                )

                drift_id = _detect_drift(mapping_id, fixops_status, external_status)
                if drift_id:
                    result["drift_detected"] = True
                    result["drift_id"] = drift_id

                result["mapping_updated"] = True
                result["cluster_id"] = cluster_id

        cursor.execute(
            "UPDATE webhook_events SET processed = TRUE, processed_at = ? WHERE event_id = ?",
            (now, event_id),
        )
        conn.commit()

        return result
    except Exception as e:
        cursor.execute(
            "UPDATE webhook_events SET error = ? WHERE event_id = ?",
            (str(e), event_id),
        )
        conn.commit()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


@router.post("/servicenow")
async def receive_servicenow_webhook(request: Request) -> Dict[str, Any]:
    """Receive webhook events from ServiceNow for bidirectional sync."""
    body = await request.body()

    try:
        payload_dict = json.loads(body)
        payload = ServiceNowWebhookPayload(**payload_dict)
    except (json.JSONDecodeError, ValueError) as e:
        raise HTTPException(status_code=400, detail=f"Invalid payload: {e}")

    event_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()

    conn = sqlite3.connect(_get_db_path())
    try:
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO webhook_events (
                event_id, integration_type, event_type, external_id, payload, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
        """,
            (
                event_id,
                "servicenow",
                payload.event_type,
                payload.sys_id,
                json.dumps(payload_dict),
                now,
            ),
        )

        result = {
            "event_id": event_id,
            "status": "received",
            "event_type": payload.event_type,
        }

        if payload.event_type in ["update", "state_change"]:
            cursor.execute(
                """
                SELECT mapping_id, cluster_id, fixops_status
                FROM integration_mappings
                WHERE integration_type = 'servicenow' AND external_id = ?
            """,
                (payload.sys_id,),
            )
            mapping = cursor.fetchone()

            if mapping and payload.state:
                mapping_id, cluster_id, fixops_status = mapping
                external_status = _map_servicenow_state_to_fixops(payload.state)

                cursor.execute(
                    """
                    UPDATE integration_mappings
                    SET external_status = ?, last_synced = ?
                    WHERE mapping_id = ?
                """,
                    (external_status, now, mapping_id),
                )

                drift_id = _detect_drift(mapping_id, fixops_status, external_status)
                if drift_id:
                    result["drift_detected"] = True
                    result["drift_id"] = drift_id

                result["mapping_updated"] = True
                result["cluster_id"] = cluster_id

        cursor.execute(
            "UPDATE webhook_events SET processed = TRUE, processed_at = ? WHERE event_id = ?",
            (now, event_id),
        )
        conn.commit()

        return result
    except Exception as e:
        cursor.execute(
            "UPDATE webhook_events SET error = ? WHERE event_id = ?",
            (str(e), event_id),
        )
        conn.commit()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        conn.close()


@router.post("/mappings")
def create_integration_mapping(request: CreateMappingRequest) -> Dict[str, Any]:
    """Create a mapping between a FixOps cluster and an external ticket."""
    conn = sqlite3.connect(_get_db_path())
    try:
        cursor = conn.cursor()

        mapping_id = str(uuid.uuid4())
        now = datetime.utcnow().isoformat()

        cursor.execute(
            """
            INSERT INTO integration_mappings (
                mapping_id, cluster_id, integration_type, external_id,
                external_url, external_status, fixops_status, last_synced, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                mapping_id,
                request.cluster_id,
                request.integration_type,
                request.external_id,
                request.external_url,
                request.external_status,
                "open",
                now,
                now,
            ),
        )
        conn.commit()

        return {
            "mapping_id": mapping_id,
            "cluster_id": request.cluster_id,
            "integration_type": request.integration_type,
            "external_id": request.external_id,
            "status": "created",
        }
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=409,
            detail="Mapping already exists for this cluster and integration type",
        )
    finally:
        conn.close()


@router.get("/mappings")
def list_integration_mappings(
    cluster_id: Optional[str] = None,
    integration_type: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> Dict[str, Any]:
    """List integration mappings with optional filters."""
    conn = sqlite3.connect(_get_db_path())
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()

        query = "SELECT * FROM integration_mappings WHERE 1=1"
        params: List[Any] = []

        if cluster_id:
            query += " AND cluster_id = ?"
            params.append(cluster_id)
        if integration_type:
            query += " AND integration_type = ?"
            params.append(integration_type)

        query += " ORDER BY last_synced DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(query, params)
        mappings = [dict(row) for row in cursor.fetchall()]

        return {"mappings": mappings, "count": len(mappings)}
    finally:
        conn.close()


@router.get("/mappings/{mapping_id}")
def get_integration_mapping(mapping_id: str) -> Dict[str, Any]:
    """Get a specific integration mapping."""
    conn = sqlite3.connect(_get_db_path())
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM integration_mappings WHERE mapping_id = ?",
            (mapping_id,),
        )
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Mapping not found")
        return dict(row)
    finally:
        conn.close()


@router.put("/mappings/{mapping_id}/sync")
def sync_mapping_status(mapping_id: str, fixops_status: str) -> Dict[str, Any]:
    """Update the FixOps status for a mapping and check for drift."""
    conn = sqlite3.connect(_get_db_path())
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM integration_mappings WHERE mapping_id = ?",
            (mapping_id,),
        )
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Mapping not found")

        mapping = dict(row)
        now = datetime.utcnow().isoformat()

        cursor.execute(
            """
            UPDATE integration_mappings
            SET fixops_status = ?, last_synced = ?
            WHERE mapping_id = ?
        """,
            (fixops_status, now, mapping_id),
        )

        result = {
            "mapping_id": mapping_id,
            "fixops_status": fixops_status,
            "external_status": mapping["external_status"],
            "synced_at": now,
        }

        if mapping["external_status"] and fixops_status != mapping["external_status"]:
            drift_id = _detect_drift(
                mapping_id, fixops_status, mapping["external_status"]
            )
            if drift_id:
                result["drift_detected"] = True
                result["drift_id"] = drift_id

        conn.commit()
        return result
    finally:
        conn.close()


@router.get("/drift")
def list_drift_events(
    resolved: Optional[bool] = None,
    limit: int = 100,
    offset: int = 0,
) -> Dict[str, Any]:
    """List drift events between FixOps and external systems."""
    conn = sqlite3.connect(_get_db_path())
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()

        query = """
            SELECT d.*, m.cluster_id, m.integration_type, m.external_id
            FROM sync_drift d
            JOIN integration_mappings m ON d.mapping_id = m.mapping_id
            WHERE 1=1
        """
        params: List[Any] = []

        if resolved is not None:
            query += " AND d.resolved = ?"
            params.append(resolved)

        query += " ORDER BY d.detected_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(query, params)
        drifts = [dict(row) for row in cursor.fetchall()]

        return {"drifts": drifts, "count": len(drifts)}
    finally:
        conn.close()


@router.put("/drift/{drift_id}/resolve")
def resolve_drift(drift_id: str, request: DriftResolutionRequest) -> Dict[str, Any]:
    """Resolve a drift event by choosing which status to apply."""
    conn = sqlite3.connect(_get_db_path())
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT d.*, m.mapping_id, m.cluster_id
            FROM sync_drift d
            JOIN integration_mappings m ON d.mapping_id = m.mapping_id
            WHERE d.drift_id = ?
        """,
            (drift_id,),
        )
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Drift event not found")

        drift = dict(row)
        now = datetime.utcnow().isoformat()

        cursor.execute(
            """
            UPDATE sync_drift
            SET resolved = TRUE, resolved_at = ?, resolution = ?
            WHERE drift_id = ?
        """,
            (now, request.resolution, drift_id),
        )

        result = {
            "drift_id": drift_id,
            "resolved": True,
            "resolution": request.resolution,
            "resolved_at": now,
        }

        if request.apply_fixops_status:
            cursor.execute(
                """
                UPDATE integration_mappings
                SET external_status = fixops_status, last_synced = ?
                WHERE mapping_id = ?
            """,
                (now, drift["mapping_id"]),
            )
            result["applied"] = "fixops_status"
        elif request.apply_external_status:
            cursor.execute(
                """
                UPDATE integration_mappings
                SET fixops_status = external_status, last_synced = ?
                WHERE mapping_id = ?
            """,
                (now, drift["mapping_id"]),
            )
            result["applied"] = "external_status"

        conn.commit()
        return result
    finally:
        conn.close()


@router.get("/events")
def list_webhook_events(
    integration_type: Optional[str] = None,
    processed: Optional[bool] = None,
    limit: int = 100,
    offset: int = 0,
) -> Dict[str, Any]:
    """List received webhook events."""
    conn = sqlite3.connect(_get_db_path())
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()

        query = "SELECT * FROM webhook_events WHERE 1=1"
        params: List[Any] = []

        if integration_type:
            query += " AND integration_type = ?"
            params.append(integration_type)
        if processed is not None:
            query += " AND processed = ?"
            params.append(processed)

        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(query, params)
        events = [dict(row) for row in cursor.fetchall()]

        return {"events": events, "count": len(events)}
    finally:
        conn.close()
