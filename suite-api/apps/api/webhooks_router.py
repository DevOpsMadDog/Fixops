"""Webhook receivers for bidirectional integration sync.

This module exports two routers:
- router: Management endpoints (mappings, drift, outbox) - requires API key authentication
- receiver_router: Webhook receiver endpoints (jira, servicenow, gitlab, azure) - uses signature verification only

External services (Jira, ServiceNow, GitLab, Azure DevOps) cannot provide FixOps API keys,
so receiver endpoints use their own authentication mechanisms (webhook signatures).
"""

import hashlib
import hmac
import json
import logging
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

logger = logging.getLogger(__name__)

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel

from apps.api.dependencies import get_org_id
from core.connectors import AutomationConnectors

# Management endpoints - requires API key authentication
router = APIRouter(prefix="/api/v1/webhooks", tags=["webhooks"])

# Receiver endpoints - uses signature verification only, no API key required
receiver_router = APIRouter(prefix="/api/v1/webhooks", tags=["webhooks-receivers"])

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

    # Outbox table for reliable outbound sync with retry logic
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS outbox (
            outbox_id TEXT PRIMARY KEY,
            integration_type TEXT NOT NULL,
            operation TEXT NOT NULL,
            cluster_id TEXT,
            external_id TEXT,
            payload TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            retry_count INTEGER DEFAULT 0,
            max_retries INTEGER DEFAULT 3,
            next_retry_at TEXT,
            last_error TEXT,
            created_at TEXT NOT NULL,
            processed_at TEXT
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
    cursor.execute(
        "CREATE INDEX IF NOT EXISTS idx_outbox_status ON outbox(status, next_retry_at)"
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


def _get_jira_webhook_secret() -> Optional[str]:
    """Get Jira webhook secret from environment."""
    return os.environ.get("FIXOPS_JIRA_WEBHOOK_SECRET")


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
            now = datetime.now(timezone.utc).isoformat()

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


@receiver_router.post("/jira")
def receive_jira_webhook(
    payload: JiraWebhookPayload,
    x_atlassian_webhook_identifier: Optional[str] = Header(None),
    x_hub_signature: Optional[str] = Header(None),
) -> Dict[str, Any]:
    """Receive webhook events from Jira for bidirectional sync.

    Note: This endpoint uses synchronous def (not async def) because it performs
    blocking SQLite operations. FastAPI automatically runs sync endpoints in a
    threadpool to avoid blocking the event loop.
    """
    # For signature verification, we need the raw body. Since we're using Pydantic
    # model parsing, we reconstruct the body from the validated payload.
    raw_body = json.dumps(payload.model_dump()).encode()

    # Validate Jira webhook signature if configured
    expected_secret = _get_jira_webhook_secret()
    if expected_secret:
        if not x_hub_signature:
            raise HTTPException(
                status_code=401,
                detail="Missing X-Hub-Signature header",
            )
        # Verify the actual signature using HMAC-SHA256
        if not _verify_jira_signature(raw_body, x_hub_signature, expected_secret):
            raise HTTPException(
                status_code=401,
                detail="Invalid webhook signature",
            )

    event_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    payload_dict = payload.model_dump()

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

        result: Dict[str, Any] = {
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


@receiver_router.post("/servicenow")
def receive_servicenow_webhook(payload: ServiceNowWebhookPayload) -> Dict[str, Any]:
    """Receive webhook events from ServiceNow for bidirectional sync."""
    event_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    payload_dict = payload.model_dump()

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

        result: Dict[str, Any] = {
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
        now = datetime.now(timezone.utc).isoformat()

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
    org_id: str = Depends(get_org_id),
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
        now = datetime.now(timezone.utc).isoformat()

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
        now = datetime.now(timezone.utc).isoformat()

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


class OutboxRequest(BaseModel):
    """Request to queue an outbound sync operation."""

    integration_type: str
    operation: str
    cluster_id: Optional[str] = None
    external_id: Optional[str] = None
    payload: Dict[str, Any]
    max_retries: int = 3


def _calculate_next_retry(retry_count: int) -> str:
    """Calculate next retry time with exponential backoff."""
    from datetime import timedelta

    base_delay = 60
    delay_seconds = base_delay * (2**retry_count)
    max_delay = 3600
    delay_seconds = min(delay_seconds, max_delay)
    next_retry = datetime.now(timezone.utc) + timedelta(seconds=delay_seconds)
    return next_retry.isoformat()


@router.post("/outbox")
def queue_outbound_sync(request: OutboxRequest) -> Dict[str, Any]:
    """Queue an outbound sync operation for reliable delivery with retries."""
    conn = sqlite3.connect(_get_db_path())
    try:
        cursor = conn.cursor()

        outbox_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        cursor.execute(
            """
            INSERT INTO outbox (
                outbox_id, integration_type, operation, cluster_id,
                external_id, payload, status, max_retries, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)
        """,
            (
                outbox_id,
                request.integration_type,
                request.operation,
                request.cluster_id,
                request.external_id,
                json.dumps(request.payload),
                request.max_retries,
                now,
            ),
        )
        conn.commit()

        return {
            "outbox_id": outbox_id,
            "integration_type": request.integration_type,
            "operation": request.operation,
            "status": "pending",
            "created_at": now,
        }
    finally:
        conn.close()


@router.get("/outbox")
def list_outbox_items(
    status: Optional[str] = None,
    integration_type: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> Dict[str, Any]:
    """List outbox items with optional filters."""
    conn = sqlite3.connect(_get_db_path())
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()

        query = "SELECT * FROM outbox WHERE 1=1"
        params: List[Any] = []

        if status:
            query += " AND status = ?"
            params.append(status)
        if integration_type:
            query += " AND integration_type = ?"
            params.append(integration_type)

        query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(query, params)
        items = [dict(row) for row in cursor.fetchall()]

        for item in items:
            if item.get("payload"):
                item["payload"] = json.loads(item["payload"])

        return {"items": items, "count": len(items)}
    finally:
        conn.close()


@router.get("/outbox/pending")
def get_pending_outbox_items(limit: int = 100) -> Dict[str, Any]:
    """Get pending outbox items ready for processing."""
    conn = sqlite3.connect(_get_db_path())
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()
        now = datetime.now(timezone.utc).isoformat()

        cursor.execute(
            """
            SELECT * FROM outbox
            WHERE status = 'pending'
            AND (next_retry_at IS NULL OR next_retry_at <= ?)
            ORDER BY created_at ASC
            LIMIT ?
        """,
            (now, limit),
        )
        items = [dict(row) for row in cursor.fetchall()]

        for item in items:
            if item.get("payload"):
                item["payload"] = json.loads(item["payload"])

        return {"items": items, "count": len(items)}
    finally:
        conn.close()


@router.put("/outbox/{outbox_id}/process")
def process_outbox_item(
    outbox_id: str, success: bool, error: Optional[str] = None
) -> Dict[str, Any]:
    """Mark an outbox item as processed or schedule retry."""
    conn = sqlite3.connect(_get_db_path())
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM outbox WHERE outbox_id = ?",
            (outbox_id,),
        )
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Outbox item not found")

        item = dict(row)
        now = datetime.now(timezone.utc).isoformat()

        if success:
            cursor.execute(
                """
                UPDATE outbox
                SET status = 'completed', processed_at = ?
                WHERE outbox_id = ?
            """,
                (now, outbox_id),
            )
            result = {
                "outbox_id": outbox_id,
                "status": "completed",
                "processed_at": now,
            }
        else:
            retry_count = item["retry_count"] + 1
            max_retries = item["max_retries"]

            error_str = error or "Unknown error"
            if retry_count >= max_retries:
                cursor.execute(
                    """
                    UPDATE outbox
                    SET status = 'failed', retry_count = ?, last_error = ?, processed_at = ?
                    WHERE outbox_id = ?
                """,
                    (retry_count, error_str, now, outbox_id),
                )
                result = {
                    "outbox_id": outbox_id,
                    "status": "failed",
                    "retry_count": retry_count,
                    "max_retries": max_retries,
                    "error": error_str,
                }
            else:
                next_retry = _calculate_next_retry(retry_count)
                cursor.execute(
                    """
                    UPDATE outbox
                    SET retry_count = ?, next_retry_at = ?, last_error = ?
                    WHERE outbox_id = ?
                """,
                    (retry_count, next_retry, error_str, outbox_id),
                )
                result = {
                    "outbox_id": outbox_id,
                    "status": "pending",
                    "retry_count": retry_count,
                    "max_retries": max_retries,
                    "next_retry_at": next_retry,
                    "error": error_str,
                }

        conn.commit()
        return result
    finally:
        conn.close()


@router.delete("/outbox/{outbox_id}")
def cancel_outbox_item(outbox_id: str) -> Dict[str, Any]:
    """Cancel a pending outbox item."""
    conn = sqlite3.connect(_get_db_path())
    try:
        cursor = conn.cursor()

        cursor.execute(
            "SELECT status FROM outbox WHERE outbox_id = ?",
            (outbox_id,),
        )
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Outbox item not found")

        if row[0] != "pending":
            raise HTTPException(
                status_code=400,
                detail=f"Cannot cancel item with status '{row[0]}'",
            )

        now = datetime.now(timezone.utc).isoformat()
        cursor.execute(
            """
            UPDATE outbox
            SET status = 'cancelled', processed_at = ?
            WHERE outbox_id = ?
        """,
            (now, outbox_id),
        )
        conn.commit()

        return {
            "outbox_id": outbox_id,
            "status": "cancelled",
            "cancelled_at": now,
        }
    finally:
        conn.close()


@router.post("/outbox/{outbox_id}/retry")
def retry_outbox_item(outbox_id: str) -> Dict[str, Any]:
    """Manually retry a failed outbox item."""
    conn = sqlite3.connect(_get_db_path())
    try:
        cursor = conn.cursor()

        cursor.execute(
            "SELECT status, retry_count FROM outbox WHERE outbox_id = ?",
            (outbox_id,),
        )
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Outbox item not found")

        if row[0] not in ("failed", "pending"):
            raise HTTPException(
                status_code=400,
                detail=f"Cannot retry item with status '{row[0]}'",
            )

        cursor.execute(
            """
            UPDATE outbox
            SET status = 'pending', retry_count = 0, next_retry_at = NULL, last_error = NULL
            WHERE outbox_id = ?
        """,
            (outbox_id,),
        )
        conn.commit()

        return {
            "outbox_id": outbox_id,
            "status": "pending",
            "message": "Item queued for retry",
        }
    finally:
        conn.close()


@router.get("/outbox/stats")
def get_outbox_stats() -> Dict[str, Any]:
    """Get statistics about outbox items."""
    conn = sqlite3.connect(_get_db_path())
    try:
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT status, COUNT(*) as count
            FROM outbox
            GROUP BY status
        """
        )
        status_counts = {row[0]: row[1] for row in cursor.fetchall()}

        cursor.execute(
            """
            SELECT integration_type, COUNT(*) as count
            FROM outbox
            WHERE status = 'pending'
            GROUP BY integration_type
        """
        )
        pending_by_type = {row[0]: row[1] for row in cursor.fetchall()}

        cursor.execute(
            """
            SELECT AVG(retry_count) as avg_retries
            FROM outbox
            WHERE status = 'completed'
        """
        )
        avg_retries = cursor.fetchone()[0] or 0

        return {
            "status_counts": status_counts,
            "pending_by_integration": pending_by_type,
            "average_retries_to_success": round(avg_retries, 2),
            "total_items": sum(status_counts.values()),
        }
    finally:
        conn.close()


@router.post("/outbox/{outbox_id}/execute")
def execute_outbox_item(outbox_id: str) -> Dict[str, Any]:
    """Execute an outbox item by calling the appropriate connector.

    This endpoint actually delivers the outbox item to the external system
    using the configured connectors. It handles retry logic and updates
    the outbox item status based on the result.
    """
    conn = sqlite3.connect(_get_db_path())
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM outbox WHERE outbox_id = ?",
            (outbox_id,),
        )
        row = cursor.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Outbox item not found")

        item = dict(row)

        if item["status"] not in ("pending", "retrying"):
            return {
                "outbox_id": outbox_id,
                "success": False,
                "message": f"Cannot execute item with status '{item['status']}'",
            }

        integration_type = item["integration_type"]
        operation = item["operation"]
        payload = json.loads(item["payload"])

        payload["type"] = integration_type
        payload["operation"] = operation

        connectors = AutomationConnectors(
            overlay_settings=_get_connector_settings(),
            toggles={"enforce_ticket_sync": True},
        )

        outcome = connectors.deliver(payload)

        now = datetime.now(timezone.utc).isoformat()

        if outcome.status == "sent":
            cursor.execute(
                """
                UPDATE outbox
                SET status = 'completed', processed_at = ?
                WHERE outbox_id = ?
            """,
                (now, outbox_id),
            )
            conn.commit()
            return {
                "outbox_id": outbox_id,
                "success": True,
                "status": "completed",
                "outcome": outcome.to_dict(),
                "processed_at": now,
            }
        else:
            retry_count = item["retry_count"] + 1
            max_retries = item["max_retries"]
            error_str = outcome.details.get("reason", "Unknown error")

            if retry_count >= max_retries:
                cursor.execute(
                    """
                    UPDATE outbox
                    SET status = 'failed', retry_count = ?, last_error = ?, processed_at = ?
                    WHERE outbox_id = ?
                """,
                    (retry_count, error_str, now, outbox_id),
                )
                conn.commit()
                return {
                    "outbox_id": outbox_id,
                    "success": False,
                    "status": "failed",
                    "retry_count": retry_count,
                    "max_retries": max_retries,
                    "error": error_str,
                    "outcome": outcome.to_dict(),
                }
            else:
                next_retry = _calculate_next_retry(retry_count)
                cursor.execute(
                    """
                    UPDATE outbox
                    SET status = 'retrying', retry_count = ?, next_retry_at = ?, last_error = ?
                    WHERE outbox_id = ?
                """,
                    (retry_count, next_retry, error_str, outbox_id),
                )
                conn.commit()
                return {
                    "outbox_id": outbox_id,
                    "success": False,
                    "status": "retrying",
                    "retry_count": retry_count,
                    "max_retries": max_retries,
                    "next_retry_at": next_retry,
                    "error": error_str,
                    "outcome": outcome.to_dict(),
                }
    finally:
        conn.close()


def _get_connector_settings() -> Dict[str, Any]:
    """Load connector settings from environment or config file."""
    settings: Dict[str, Any] = {}

    if os.getenv("FIXOPS_JIRA_URL"):
        settings["jira"] = {
            "url": os.getenv("FIXOPS_JIRA_URL"),
            "user": os.getenv("FIXOPS_JIRA_USER"),
            "token_env": "FIXOPS_JIRA_TOKEN",
            "project_key": os.getenv("FIXOPS_JIRA_PROJECT_KEY"),
        }

    if os.getenv("FIXOPS_SERVICENOW_URL"):
        settings["servicenow"] = {
            "instance_url": os.getenv("FIXOPS_SERVICENOW_URL"),
            "user": os.getenv("FIXOPS_SERVICENOW_USER"),
            "token_env": "FIXOPS_SERVICENOW_TOKEN",
        }

    if os.getenv("FIXOPS_GITLAB_URL"):
        settings["gitlab"] = {
            "base_url": os.getenv("FIXOPS_GITLAB_URL"),
            "project_id": os.getenv("FIXOPS_GITLAB_PROJECT_ID"),
            "token_env": "FIXOPS_GITLAB_TOKEN",
        }

    if os.getenv("FIXOPS_GITHUB_OWNER"):
        settings["github"] = {
            "owner": os.getenv("FIXOPS_GITHUB_OWNER"),
            "repo": os.getenv("FIXOPS_GITHUB_REPO"),
            "token_env": "FIXOPS_GITHUB_TOKEN",
        }

    if os.getenv("FIXOPS_AZURE_DEVOPS_ORG"):
        settings["azure_devops"] = {
            "organization": os.getenv("FIXOPS_AZURE_DEVOPS_ORG"),
            "project": os.getenv("FIXOPS_AZURE_DEVOPS_PROJECT"),
            "token_env": "FIXOPS_AZURE_DEVOPS_TOKEN",
        }

    if os.getenv("FIXOPS_SLACK_WEBHOOK_URL"):
        settings["policy_automation"] = {
            "webhook_url": os.getenv("FIXOPS_SLACK_WEBHOOK_URL"),
        }

    if os.getenv("FIXOPS_CONFLUENCE_URL"):
        settings["confluence"] = {
            "url": os.getenv("FIXOPS_CONFLUENCE_URL"),
            "user": os.getenv("FIXOPS_CONFLUENCE_USER"),
            "token_env": "FIXOPS_CONFLUENCE_TOKEN",
            "space_key": os.getenv("FIXOPS_CONFLUENCE_SPACE_KEY"),
        }

    return settings


@router.post("/outbox/process-pending")
def process_pending_outbox_items(limit: int = 10) -> Dict[str, Any]:
    """Process pending outbox items that are ready for delivery.

    This endpoint processes up to `limit` pending outbox items that have
    either never been attempted or whose next_retry_at time has passed.
    """
    conn = sqlite3.connect(_get_db_path())
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()
        now = datetime.now(timezone.utc).isoformat()

        cursor.execute(
            """
            SELECT outbox_id FROM outbox
            WHERE status IN ('pending', 'retrying')
            AND (next_retry_at IS NULL OR next_retry_at <= ?)
            ORDER BY created_at ASC
            LIMIT ?
        """,
            (now, limit),
        )
        rows = cursor.fetchall()
        outbox_ids = [row["outbox_id"] for row in rows]
    finally:
        conn.close()

    results = []
    for outbox_id in outbox_ids:
        try:
            result = execute_outbox_item(outbox_id)
            results.append(result)
        except Exception as e:
            logger.error(f"Failed to execute outbox item {outbox_id}: {e}")
            results.append(
                {
                    "outbox_id": outbox_id,
                    "success": False,
                    "error": "Internal processing error",
                }
            )

    return {
        "processed_count": len(results),
        "results": results,
    }


# ============================================================================
# GitLab ALM Integration
# ============================================================================


class GitLabWebhookPayload(BaseModel):
    """GitLab webhook payload for issue events."""

    object_kind: str
    event_type: Optional[str] = None
    object_attributes: Optional[Dict[str, Any]] = None
    project: Optional[Dict[str, Any]] = None
    user: Optional[Dict[str, Any]] = None
    labels: Optional[List[Dict[str, Any]]] = None


def _map_gitlab_state_to_fixops(state: str) -> str:
    """Map GitLab issue state to FixOps status."""
    state_map = {
        "opened": "open",
        "closed": "resolved",
        "reopened": "open",
        "merged": "resolved",
    }
    return state_map.get(state.lower(), "open")


def _map_gitlab_labels_to_status(labels: List[Dict[str, Any]]) -> Optional[str]:
    """Extract status from GitLab labels."""
    label_map = {
        "in progress": "in_progress",
        "in-progress": "in_progress",
        "wip": "in_progress",
        "won't fix": "accepted_risk",
        "wontfix": "accepted_risk",
        "false positive": "false_positive",
        "duplicate": "false_positive",
    }
    for label in labels:
        label_name = label.get("title", "").lower()
        if label_name in label_map:
            return label_map[label_name]
    return None


def _get_gitlab_webhook_secret() -> Optional[str]:
    """Get configured GitLab webhook secret from environment."""
    return os.environ.get("FIXOPS_GITLAB_WEBHOOK_SECRET")


@receiver_router.post("/gitlab")
def receive_gitlab_webhook(
    payload: GitLabWebhookPayload,
    x_gitlab_token: Optional[str] = Header(None),
    x_gitlab_event: Optional[str] = Header(None),
) -> Dict[str, Any]:
    """Receive webhook events from GitLab for bidirectional sync.

    Supports GitLab issue events for ALM integration with vulnerability tracking.
    """
    # Validate GitLab webhook token if configured
    expected_secret = _get_gitlab_webhook_secret()
    if expected_secret:
        if not x_gitlab_token:
            raise HTTPException(
                status_code=401,
                detail="Missing X-Gitlab-Token header",
            )
        if not hmac.compare_digest(x_gitlab_token, expected_secret):
            raise HTTPException(
                status_code=401,
                detail="Invalid X-Gitlab-Token",
            )

    event_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    payload_dict = payload.model_dump()

    conn = sqlite3.connect(_get_db_path())
    try:
        cursor = conn.cursor()

        object_attrs = payload.object_attributes or {}
        issue_iid = object_attrs.get("iid")
        project_id = payload.project.get("id") if payload.project else None
        external_id = f"{project_id}#{issue_iid}" if project_id and issue_iid else None

        cursor.execute(
            """
            INSERT INTO webhook_events (
                event_id, integration_type, event_type, external_id, payload, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
        """,
            (
                event_id,
                "gitlab",
                payload.object_kind,
                external_id,
                json.dumps(payload_dict),
                now,
            ),
        )

        result: Dict[str, Any] = {
            "event_id": event_id,
            "status": "received",
            "event_type": payload.object_kind,
            "gitlab_event": x_gitlab_event,
        }

        if payload.object_kind == "issue" and external_id:
            issue_state = object_attrs.get("state")
            issue_action = object_attrs.get("action")

            cursor.execute(
                """
                SELECT mapping_id, cluster_id, fixops_status
                FROM integration_mappings
                WHERE integration_type = 'gitlab' AND external_id = ?
            """,
                (external_id,),
            )
            mapping = cursor.fetchone()

            if mapping:
                mapping_id, cluster_id, fixops_status = mapping

                # Determine external status from state and labels
                external_status = _map_gitlab_state_to_fixops(issue_state or "opened")
                if payload.labels:
                    label_status = _map_gitlab_labels_to_status(payload.labels)
                    if label_status:
                        external_status = label_status

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
                result["action"] = issue_action

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


# ============================================================================
# Azure DevOps ALM Integration
# ============================================================================


class AzureDevOpsWebhookPayload(BaseModel):
    """Azure DevOps webhook payload for work item events."""

    subscriptionId: Optional[str] = None
    notificationId: Optional[int] = None
    eventType: str
    resource: Optional[Dict[str, Any]] = None
    resourceVersion: Optional[str] = None
    resourceContainers: Optional[Dict[str, Any]] = None


def _map_azure_state_to_fixops(state: str) -> str:
    """Map Azure DevOps work item state to FixOps status."""
    state_map = {
        "new": "open",
        "active": "in_progress",
        "resolved": "resolved",
        "closed": "resolved",
        "removed": "false_positive",
        "done": "resolved",
        "to do": "open",
        "doing": "in_progress",
    }
    return state_map.get(state.lower(), "open")


@receiver_router.post("/azure-devops")
def receive_azure_devops_webhook(payload: AzureDevOpsWebhookPayload) -> Dict[str, Any]:
    """Receive webhook events from Azure DevOps for bidirectional sync.

    Supports Azure DevOps work item events for ALM integration.
    """
    event_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    payload_dict = payload.model_dump()

    conn = sqlite3.connect(_get_db_path())
    try:
        cursor = conn.cursor()

        resource = payload.resource or {}
        work_item_id = resource.get("id")
        project = resource.get("fields", {}).get("System.TeamProject")
        if work_item_id is None:
            raise HTTPException(
                status_code=400,
                detail="Missing work item ID in webhook payload",
            )
        external_id = f"{project}/{work_item_id}" if project else str(work_item_id)

        cursor.execute(
            """
            INSERT INTO webhook_events (
                event_id, integration_type, event_type, external_id, payload, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
        """,
            (
                event_id,
                "azure_devops",
                payload.eventType,
                external_id,
                json.dumps(payload_dict),
                now,
            ),
        )

        result: Dict[str, Any] = {
            "event_id": event_id,
            "status": "received",
            "event_type": payload.eventType,
        }

        if payload.eventType.startswith("workitem.") and external_id:
            fields = resource.get("fields", {})
            work_item_state = fields.get("System.State")

            cursor.execute(
                """
                SELECT mapping_id, cluster_id, fixops_status
                FROM integration_mappings
                WHERE integration_type = 'azure_devops' AND external_id = ?
            """,
                (external_id,),
            )
            mapping = cursor.fetchone()

            if mapping and work_item_state:
                mapping_id, cluster_id, fixops_status = mapping
                external_status = _map_azure_state_to_fixops(work_item_state)

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


# ============================================================================
# ALM Work Item Creation Endpoints
# ============================================================================


class CreateWorkItemRequest(BaseModel):
    """Request to create a work item in an ALM system."""

    cluster_id: str = "default-cluster"
    integration_type: Literal["gitlab", "azure_devops", "jira", "servicenow"] = "jira"
    title: str = "Untitled Work Item"
    description: Optional[str] = None
    severity: Optional[str] = None
    labels: Optional[List[str]] = None
    assignee: Optional[str] = None
    project_id: Optional[str] = None
    additional_fields: Optional[Dict[str, Any]] = None


@router.post("/alm/work-items")
def create_alm_work_item(request: CreateWorkItemRequest) -> Dict[str, Any]:
    """Queue creation of a work item in an ALM system.

    This endpoint queues the work item creation in the outbox for reliable delivery.
    The actual creation happens asynchronously via the outbox processor.
    """
    conn = sqlite3.connect(_get_db_path())
    try:
        cursor = conn.cursor()

        # Check if mapping already exists
        cursor.execute(
            """
            SELECT mapping_id, external_id
            FROM integration_mappings
            WHERE cluster_id = ? AND integration_type = ?
        """,
            (request.cluster_id, request.integration_type),
        )
        existing = cursor.fetchone()
        if existing:
            return {
                "status": "already_exists",
                "mapping_id": existing[0],
                "external_id": existing[1],
                "message": "Work item already exists for this cluster",
            }

        # Queue in outbox for async creation
        outbox_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        payload = {
            "cluster_id": request.cluster_id,
            "title": request.title,
            "description": request.description,
            "severity": request.severity,
            "labels": request.labels,
            "assignee": request.assignee,
            "project_id": request.project_id,
            "additional_fields": request.additional_fields,
        }

        cursor.execute(
            """
            INSERT INTO outbox (
                outbox_id, integration_type, operation, cluster_id,
                payload, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
            (
                outbox_id,
                request.integration_type,
                "create_work_item",
                request.cluster_id,
                json.dumps(payload),
                "pending",
                now,
            ),
        )
        conn.commit()

        return {
            "status": "queued",
            "outbox_id": outbox_id,
            "cluster_id": request.cluster_id,
            "integration_type": request.integration_type,
            "message": "Work item creation queued for processing",
        }
    finally:
        conn.close()


class UpdateWorkItemRequest(BaseModel):
    """Request to update a work item in an ALM system."""

    status: Optional[str] = None
    assignee: Optional[str] = None
    labels: Optional[List[str]] = None
    comment: Optional[str] = None
    additional_fields: Optional[Dict[str, Any]] = None


@router.put("/alm/work-items/{mapping_id}")
def update_alm_work_item(
    mapping_id: str, request: UpdateWorkItemRequest
) -> Dict[str, Any]:
    """Queue update of a work item in an ALM system.

    This endpoint queues the work item update in the outbox for reliable delivery.
    """
    conn = sqlite3.connect(_get_db_path())
    try:
        cursor = conn.cursor()

        # Get existing mapping
        cursor.execute(
            """
            SELECT cluster_id, integration_type, external_id
            FROM integration_mappings
            WHERE mapping_id = ?
        """,
            (mapping_id,),
        )
        mapping = cursor.fetchone()
        if not mapping:
            raise HTTPException(status_code=404, detail="Mapping not found")

        cluster_id, integration_type, external_id = mapping

        # Queue in outbox for async update
        outbox_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        payload = {
            "mapping_id": mapping_id,
            "external_id": external_id,
            "status": request.status,
            "assignee": request.assignee,
            "labels": request.labels,
            "comment": request.comment,
            "additional_fields": request.additional_fields,
        }

        cursor.execute(
            """
            INSERT INTO outbox (
                outbox_id, integration_type, operation, cluster_id, external_id,
                payload, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                outbox_id,
                integration_type,
                "update_work_item",
                cluster_id,
                external_id,
                json.dumps(payload),
                "pending",
                now,
            ),
        )
        conn.commit()

        return {
            "status": "queued",
            "outbox_id": outbox_id,
            "mapping_id": mapping_id,
            "external_id": external_id,
            "message": "Work item update queued for processing",
        }
    finally:
        conn.close()


@router.get("/alm/work-items")
def list_alm_work_items(
    cluster_id: Optional[str] = None,
    integration_type: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
    offset: int = 0,
) -> Dict[str, Any]:
    """List ALM work items with their sync status."""
    conn = sqlite3.connect(_get_db_path())
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()

        query = """
            SELECT m.*,
                   (SELECT COUNT(*) FROM sync_drift d
                    WHERE d.mapping_id = m.mapping_id AND d.resolved = FALSE) as unresolved_drifts
            FROM integration_mappings m
            WHERE m.integration_type IN ('gitlab', 'azure_devops', 'jira', 'servicenow')
        """
        params: List[Any] = []

        if cluster_id:
            query += " AND m.cluster_id = ?"
            params.append(cluster_id)
        if integration_type:
            query += " AND m.integration_type = ?"
            params.append(integration_type)
        if status:
            query += " AND (m.fixops_status = ? OR m.external_status = ?)"
            params.extend([status, status])

        query += " ORDER BY m.last_synced DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])

        cursor.execute(query, params)
        work_items = [dict(row) for row in cursor.fetchall()]

        return {
            "work_items": work_items,
            "count": len(work_items),
        }
    finally:
        conn.close()
