"""n8n webhook connector — bidirectional bridge for workflow automation."""
from __future__ import annotations

import json
import sqlite3
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Optional

import structlog

from connectors._emit import emit_connector_event

_logger = structlog.get_logger("connectors.n8n_connector")

VALID_EVENT_TYPES = frozenset({
    "finding", "incident", "sla_breach", "scan_complete", "alert"
})

_DDL = """
CREATE TABLE IF NOT EXISTS webhooks (
    webhook_id  TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    event_type  TEXT NOT NULL,
    webhook_url TEXT NOT NULL,
    created_at  REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
    event_id    TEXT PRIMARY KEY,
    event_type  TEXT NOT NULL,
    webhook_id  TEXT,
    status      TEXT NOT NULL,
    response_code INTEGER,
    triggered_at REAL NOT NULL,
    payload     TEXT
);
"""


class N8nConnector:
    """Bidirectional n8n webhook bridge for ALDECI security events."""

    def __init__(
        self,
        base_url: str = "http://localhost:5678",
        db_path: str = "data/n8n_connector.db",
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._db_path = Path(db_path)
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._db_path))
        conn.execute("PRAGMA journal_mode=WAL")
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(_DDL)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register_webhook(
        self, name: str, event_type: str, webhook_url: str
    ) -> dict:
        """Register an n8n webhook URL for a specific event type.

        event_type: 'finding', 'incident', 'sla_breach', 'scan_complete', 'alert'
        Returns: {webhook_id, name, event_type, webhook_url, created_at}
        """
        if event_type not in VALID_EVENT_TYPES:
            raise ValueError(
                f"Invalid event_type '{event_type}'. "
                f"Allowed: {sorted(VALID_EVENT_TYPES)}"
            )
        webhook_id = str(uuid.uuid4())
        created_at = time.time()
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO webhooks (webhook_id, name, event_type, webhook_url, created_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (webhook_id, name, event_type, webhook_url, created_at),
            )
        _logger.info("webhook_registered", webhook_id=webhook_id, event_type=event_type)
        return {
            "webhook_id": webhook_id,
            "name": name,
            "event_type": event_type,
            "webhook_url": webhook_url,
            "created_at": created_at,
        }

    def unregister_webhook(self, webhook_id: str) -> bool:
        """Remove a webhook registration. Returns True if removed, False if not found."""
        with self._connect() as conn:
            cur = conn.execute(
                "DELETE FROM webhooks WHERE webhook_id = ?", (webhook_id,)
            )
            removed = cur.rowcount > 0
        if removed:
            _logger.info("webhook_unregistered", webhook_id=webhook_id)
        return removed

    def list_webhooks(self, event_type: Optional[str] = None) -> list[dict]:
        """List registered webhooks, optionally filtered by event_type."""
        with self._connect() as conn:
            if event_type is not None:
                rows = conn.execute(
                    "SELECT * FROM webhooks WHERE event_type = ? ORDER BY created_at",
                    (event_type,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM webhooks ORDER BY created_at"
                ).fetchall()
        return [dict(r) for r in rows]

    def trigger_webhook(self, event_type: str, payload: dict) -> list[dict]:
        """Fire all webhooks registered for event_type with payload.

        Returns list of {webhook_id, status: 'sent'|'failed'|'skipped', response_code}
        Gracefully handles unreachable URLs — returns 'failed' without raising.
        """
        webhooks = self.list_webhooks(event_type=event_type)
        results: list[dict] = []
        body = json.dumps({"event_type": event_type, "payload": payload}).encode()

        for wh in webhooks:
            webhook_id = wh["webhook_id"]
            status = "failed"
            response_code: Optional[int] = None
            try:
                req = urllib.request.Request(  # nosemgrep: dynamic-urllib-use-detected
                    wh["webhook_url"],
                    data=body,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=5) as resp:  # nosemgrep: dynamic-urllib-use-detected  # nosec
                    response_code = resp.status
                    status = "sent"
            except urllib.error.HTTPError as exc:
                response_code = exc.code
                _logger.warning(
                    "webhook_http_error",
                    webhook_id=webhook_id,
                    code=exc.code,
                )
            except Exception as exc:
                _logger.warning(
                    "webhook_delivery_failed",
                    webhook_id=webhook_id,
                    error=str(exc),
                )

            result = {
                "webhook_id": webhook_id,
                "status": status,
                "response_code": response_code,
            }
            results.append(result)
            self._record_event(event_type, webhook_id, status, response_code, payload)

        if not webhooks:
            _logger.debug("trigger_no_webhooks", event_type=event_type)

        sent = sum(1 for r in results if r.get("status") == "sent")
        emit_connector_event(
            connector="N8nConnector",
            org_id=str(payload.get("org_id") or "default"),
            source_kind="sync",
            finding_count=sent,
            extra={
                "event_type": event_type,
                "webhooks_targeted": len(webhooks),
                "delivered": sent,
                "failed": len(webhooks) - sent,
            },
        )
        return results

    def get_event_history(
        self, limit: int = 50, event_type: Optional[str] = None
    ) -> list[dict]:
        """Return list of past webhook trigger events from SQLite."""
        with self._connect() as conn:
            if event_type is not None:
                rows = conn.execute(
                    "SELECT * FROM events WHERE event_type = ? "
                    "ORDER BY triggered_at DESC LIMIT ?",
                    (event_type, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM events ORDER BY triggered_at DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        return [dict(r) for r in rows]

    def get_stats(self) -> dict:
        """Return {total_webhooks, total_events, success_rate, events_by_type}"""
        with self._connect() as conn:
            total_webhooks: int = conn.execute(
                "SELECT COUNT(*) FROM webhooks"
            ).fetchone()[0]
            total_events: int = conn.execute(
                "SELECT COUNT(*) FROM events"
            ).fetchone()[0]
            sent_count: int = conn.execute(
                "SELECT COUNT(*) FROM events WHERE status = 'sent'"
            ).fetchone()[0]
            by_type_rows = conn.execute(
                "SELECT event_type, COUNT(*) as cnt FROM events GROUP BY event_type"
            ).fetchall()

        success_rate = (sent_count / total_events) if total_events > 0 else 0.0
        events_by_type = {r["event_type"]: r["cnt"] for r in by_type_rows}

        return {
            "total_webhooks": total_webhooks,
            "total_events": total_events,
            "success_rate": float(success_rate),
            "events_by_type": events_by_type,
        }

    def test_connectivity(self) -> dict:
        """Test if n8n base_url is reachable. Returns {reachable: bool, latency_ms: float}"""
        url = self._base_url + "/healthz"
        start = time.monotonic()
        reachable = False
        latency_ms = 0.0
        try:
            req = urllib.request.Request(url, method="GET")  # nosemgrep: dynamic-urllib-use-detected
            with urllib.request.urlopen(req, timeout=5):  # nosemgrep: dynamic-urllib-use-detected  # nosec
                reachable = True
        except Exception:
            pass
        latency_ms = (time.monotonic() - start) * 1000.0
        return {"reachable": reachable, "latency_ms": latency_ms}

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _record_event(
        self,
        event_type: str,
        webhook_id: str,
        status: str,
        response_code: Optional[int],
        payload: dict,
    ) -> None:
        event_id = str(uuid.uuid4())
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO events "
                "(event_id, event_type, webhook_id, status, response_code, triggered_at, payload) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    event_id,
                    event_type,
                    webhook_id,
                    status,
                    response_code,
                    time.time(),
                    json.dumps(payload),
                ),
            )


# ---------------------------------------------------------------------------
# N8nAPIClient — manages n8n workflows via REST API
# ---------------------------------------------------------------------------

_INTEGRATION_NODE_TYPES = {
    "slack": "n8n-nodes-base.slack",
    "jira": "n8n-nodes-base.jira",
    "pagerduty": "n8n-nodes-base.pagerDuty",
}


class N8nAPIClient:
    """Manages n8n workflows via REST API (POST /api/v1/workflows etc.)"""

    def __init__(self, base_url: str = None, api_key: str = None):
        import os
        self._base = (base_url or os.environ.get("N8N_BASE_URL", "http://localhost:5678")).rstrip("/")
        self._key = api_key or os.environ.get("N8N_API_KEY", "")
        self._api = f"{self._base}/api/v1"

    def _headers(self) -> dict:
        h = {"Content-Type": "application/json"}
        if self._key:
            h["X-N8N-API-KEY"] = self._key
        return h

    def _request(self, method: str, url: str, body: Optional[dict] = None) -> dict | list:
        """Make an HTTP request. Returns parsed JSON or error dict on failure."""
        try:
            data = json.dumps(body).encode() if body is not None else None
            req = urllib.request.Request(url, data=data, headers=self._headers(), method=method)  # nosemgrep: dynamic-urllib-use-detected
            with urllib.request.urlopen(req, timeout=10) as resp:  # nosemgrep: dynamic-urllib-use-detected  # nosec
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            _logger.warning("n8n_api_http_error", method=method, url=url, code=exc.code)
            try:
                detail = json.loads(exc.read().decode())
            except Exception:
                detail = str(exc)
            return {"error": f"HTTP {exc.code}", "detail": detail}
        except Exception as exc:
            _logger.warning("n8n_api_unavailable", method=method, url=url, error=str(exc))
            return {"error": "n8n unavailable", "detail": str(exc)}

    def create_workflow(self, name: str, nodes: list, connections: dict, settings: dict = None) -> dict:
        """POST /api/v1/workflows — returns {id, name, active, ...}"""
        body: dict = {"name": name, "nodes": nodes, "connections": connections}
        if settings is not None:
            body["settings"] = settings
        return self._request("POST", f"{self._api}/workflows", body)

    def activate_workflow(self, workflow_id: str) -> dict:
        """POST /api/v1/workflows/{id}/activate"""
        return self._request("POST", f"{self._api}/workflows/{workflow_id}/activate")

    def deactivate_workflow(self, workflow_id: str) -> dict:
        """POST /api/v1/workflows/{id}/deactivate"""
        return self._request("POST", f"{self._api}/workflows/{workflow_id}/deactivate")

    def list_workflows(self) -> list:
        """GET /api/v1/workflows"""
        result = self._request("GET", f"{self._api}/workflows")
        if isinstance(result, list):
            return result
        # n8n wraps in {"data": [...]}
        if isinstance(result, dict) and "data" in result:
            return result["data"]
        return result  # may be an error dict; callers should check

    def get_workflow(self, workflow_id: str) -> dict:
        """GET /api/v1/workflows/{id}"""
        return self._request("GET", f"{self._api}/workflows/{workflow_id}")

    def delete_workflow(self, workflow_id: str) -> bool:
        """DELETE /api/v1/workflows/{id} — returns True on success."""
        result = self._request("DELETE", f"{self._api}/workflows/{workflow_id}")
        return "error" not in result

    def list_executions(self, workflow_id: str = None) -> list:
        """GET /api/v1/executions"""
        url = f"{self._api}/executions"
        if workflow_id:
            url = f"{url}?workflowId={workflow_id}"
        result = self._request("GET", url)
        if isinstance(result, list):
            return result
        if isinstance(result, dict) and "data" in result:
            return result["data"]
        return result

    def get_execution(self, execution_id: str) -> dict:
        """GET /api/v1/executions/{id}"""
        return self._request("GET", f"{self._api}/executions/{execution_id}")

    def get_webhook_url(self, path: str) -> str:
        """Returns http://{n8n_host}/webhook/{path}"""
        return f"{self._base}/webhook/{path}"

    def provision_security_workflow(self, event_type: str, integrations: list) -> dict:
        """
        Create + activate a workflow: Webhook trigger → configured output nodes.
        integrations: list of "slack", "jira", "pagerduty"
        Returns: {workflow_id, webhook_url, active}
        """
        webhook_path = f"aldeci-{event_type}"
        webhook_node = {
            "id": "webhook-trigger",
            "name": "ALDECI Webhook",
            "type": "n8n-nodes-base.webhook",
            "typeVersion": 1,
            "position": [200, 300],
            "parameters": {
                "path": webhook_path,
                "responseMode": "onReceived",
                "httpMethod": "POST",
            },
        }
        nodes = [webhook_node]
        connections: dict = {"ALDECI Webhook": {"main": [[]]}}

        for idx, integration in enumerate(integrations):
            node_type = _INTEGRATION_NODE_TYPES.get(integration, f"n8n-nodes-base.{integration}")
            node_id = f"{integration}-output-{idx}"
            node_name = f"{integration.title()} Output"
            output_node = {
                "id": node_id,
                "name": node_name,
                "type": node_type,
                "typeVersion": 1,
                "position": [500, 200 + idx * 150],
                "parameters": {},
            }
            nodes.append(output_node)
            connections["ALDECI Webhook"]["main"][0].append(
                {"node": node_name, "type": "main", "index": 0}
            )

        workflow_name = f"ALDECI {event_type} → {', '.join(integrations) or 'none'}"
        created = self.create_workflow(
            name=workflow_name,
            nodes=nodes,
            connections=connections,
            settings={"executionOrder": "v1"},
        )

        if "error" in created:
            return created

        workflow_id = created.get("id", "")
        activated = self.activate_workflow(workflow_id)
        active = activated.get("active", False) if "error" not in activated else False

        return {
            "workflow_id": workflow_id,
            "webhook_url": self.get_webhook_url(webhook_path),
            "active": active,
        }
