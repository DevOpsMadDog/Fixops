"""
Elastic ECS Forwarder — ALdeci webhook consumer.

Listens on HTTP port 9091 (configurable) for ALdeci webhook events,
transforms each event into Elastic Common Schema (ECS) format,
and indexes to Elasticsearch.

ECS spec:
  https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html

Environment variables:
  ALDECI_WEBHOOK_PORT       Listening port (default: 9091)
  ELASTIC_URL               Elasticsearch base URL (default: "mock")
  ELASTIC_INDEX             Index name (default: aldeci-security)
  ELASTIC_API_KEY           Elastic API key (base64, optional for real ES)
  ELASTIC_USERNAME          Basic auth username (alternative to API key)
  ELASTIC_PASSWORD          Basic auth password (alternative to API key)
  ALDECI_WEBHOOK_SECRET     Optional HMAC-SHA256 secret for signature verification

Mock-Elastic fallback:
  If ELASTIC_URL is not set or is "mock", events are printed to stdout
  instead of being indexed. Use for local demos without Elasticsearch.

Run:
  python elastic_forwarder.py

Register with ALdeci:
  curl -X POST http://localhost:8000/api/v1/webhook-subscriptions/ \\
    -H "Content-Type: application/json" \\
    -H "Authorization: Bearer $ALDECI_TOKEN" \\
    -d '{"url": "https://your-forwarder.example.com/webhook",
         "events": ["finding.created","finding.critical","sla.breach"]}'
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [elastic-forwarder] %(message)s",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

LISTEN_PORT: int = int(os.environ.get("ALDECI_WEBHOOK_PORT", "9091"))
ELASTIC_URL: str = os.environ.get("ELASTIC_URL", "mock")
ELASTIC_INDEX: str = os.environ.get("ELASTIC_INDEX", "aldeci-security")
ELASTIC_API_KEY: str = os.environ.get("ELASTIC_API_KEY", "")
ELASTIC_USERNAME: str = os.environ.get("ELASTIC_USERNAME", "")
ELASTIC_PASSWORD: str = os.environ.get("ELASTIC_PASSWORD", "")
ALDECI_WEBHOOK_SECRET: str = os.environ.get("ALDECI_WEBHOOK_SECRET", "")

# ECS severity mapping
# ECS uses numeric severity (0-100) and text labels per log.level convention
_ECS_SEVERITY_NUM: Dict[str, int] = {
    "critical": 100,
    "high": 75,
    "medium": 50,
    "low": 25,
    "info": 1,
}


# ---------------------------------------------------------------------------
# HMAC verification
# ---------------------------------------------------------------------------


def _verify_signature(body: bytes, sig_header: Optional[str]) -> bool:
    """Verify X-ALdeci-Signature HMAC-SHA256 header."""
    if not ALDECI_WEBHOOK_SECRET:
        return True
    if not sig_header:
        log.warning("Missing X-ALdeci-Signature — rejecting")
        return False
    expected = "sha256=" + hmac.new(
        ALDECI_WEBHOOK_SECRET.encode("utf-8"), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, sig_header)


# ---------------------------------------------------------------------------
# ALdeci → ECS transform
# ---------------------------------------------------------------------------


def transform_to_ecs(event_type: str, aldeci_payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Transform an ALdeci webhook payload to Elastic Common Schema (ECS).

    ECS top-level field sets used:
      @timestamp        — RFC3339 detection time
      event.*           — event categorisation
      vulnerability.*   — CVE/CVSS data
      file.*            — affected file/asset
      organization.*    — org_id
      tags              — aldeci, scanner source, severity
      labels.*          — arbitrary key-value metadata

    Ref: https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html
    """
    ts_str: Optional[str] = (
        aldeci_payload.get("detected_at")
        or aldeci_payload.get("timestamp")
        or aldeci_payload.get("created_at")
    )
    try:
        if ts_str:
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        else:
            dt = datetime.now(timezone.utc)
        timestamp_iso = dt.isoformat()
    except (ValueError, TypeError):
        timestamp_iso = datetime.now(timezone.utc).isoformat()

    severity_raw: str = str(aldeci_payload.get("severity", "info")).lower()
    severity_num: int = _ECS_SEVERITY_NUM.get(severity_raw, 1)

    # ECS event.category and event.type mapping
    ecs_category: List[str] = ["vulnerability"]
    ecs_type: List[str] = ["info"]
    ecs_outcome: str = "unknown"

    if event_type in ("finding.created", "finding.critical"):
        ecs_type = ["creation"]
        ecs_outcome = "failure"  # security finding = system failure
    elif event_type == "finding.resolved":
        ecs_type = ["deletion"]
        ecs_outcome = "success"
    elif event_type == "decision.made":
        ecs_category = ["process"]
        ecs_type = ["change"]
        ecs_outcome = "success"
    elif event_type == "alert.created":
        ecs_category = ["alert"]
        ecs_type = ["creation"]
        ecs_outcome = "failure"
    elif event_type == "threat.detected":
        ecs_category = ["threat"]
        ecs_type = ["indicator"]
        ecs_outcome = "failure"
    elif event_type == "sla.breach":
        ecs_category = ["vulnerability"]
        ecs_type = ["change"]
        ecs_outcome = "failure"
    elif event_type == "compliance.violation":
        ecs_category = ["compliance"]
        ecs_type = ["change"]
        ecs_outcome = "failure"
    elif event_type == "attack_path.discovered":
        ecs_category = ["threat"]
        ecs_type = ["indicator"]
        ecs_outcome = "failure"

    # Build ECS document
    doc: Dict[str, Any] = {
        "@timestamp": timestamp_iso,
        # ECS event fields
        "event": {
            "kind": "event",
            "category": ecs_category,
            "type": ecs_type,
            "outcome": ecs_outcome,
            "severity": severity_num,
            "provider": "aldeci",
            "dataset": "aldeci.finding",
            "module": "aldeci",
            "action": event_type,
            "reason": aldeci_payload.get("title", ""),
            "id": aldeci_payload.get("finding_id", ""),
            "created": timestamp_iso,
            "original": json.dumps(aldeci_payload, default=str)[:32000],
        },
        # ECS log fields
        "log": {
            "level": severity_raw,
            "logger": "aldeci.webhook",
        },
        # ECS vulnerability fields
        "vulnerability": {
            "id": aldeci_payload.get("cve_id", ""),
            "severity": severity_raw,
            "score": {
                "base": aldeci_payload.get("cvss_score"),
            },
            "description": aldeci_payload.get("description", "")[:4096],
            "reference": (
                f"https://nvd.nist.gov/vuln/detail/{aldeci_payload['cve_id']}"
                if aldeci_payload.get("cve_id") else None
            ),
        },
        # ECS file fields (affected asset)
        "file": {
            "path": aldeci_payload.get("affected_asset", ""),
            "name": (aldeci_payload.get("affected_asset", "") or "").split("/")[-1],
        },
        # ECS observer (scanner that produced the finding)
        "observer": {
            "name": aldeci_payload.get("source", "aldeci"),
            "type": "scanner",
            "vendor": "ALdeci",
            "product": "CTEM+",
        },
        # ECS organization
        "organization": {
            "id": aldeci_payload.get("org_id", ""),
        },
        # Tags for easy filtering
        "tags": [
            "aldeci",
            event_type,
            aldeci_payload.get("source", "aldeci"),
            severity_raw,
        ],
        # ALdeci-specific labels (ECS labels must be key-value strings)
        "labels": {
            "aldeci_event_type": event_type,
            "aldeci_org_id": str(aldeci_payload.get("org_id", "")),
            "aldeci_finding_id": str(aldeci_payload.get("finding_id", "")),
            "aldeci_scanner": str(aldeci_payload.get("source", "")),
        },
        # Decision fields (decision.made events)
        "aldeci": {
            "decision": aldeci_payload.get("decision"),
            "confidence": aldeci_payload.get("confidence"),
            "recommendation": aldeci_payload.get("recommendation"),
            "threat_actor": aldeci_payload.get("threat_actor"),
            "ioc": aldeci_payload.get("ioc"),
            "mitre_technique": aldeci_payload.get("mitre_technique"),
            "webhook_id": aldeci_payload.get("webhook_id"),
        },
    }

    # Clean None/empty nested values
    def _clean(d: Any) -> Any:
        if isinstance(d, dict):
            return {k: _clean(v) for k, v in d.items() if v is not None and v != ""}
        if isinstance(d, list):
            return [_clean(i) for i in d if i is not None and i != ""]
        return d

    return _clean(doc)


# ---------------------------------------------------------------------------
# Elasticsearch index
# ---------------------------------------------------------------------------


def _build_auth_header() -> Optional[str]:
    """Build Authorization header — prefer API key, fall back to basic auth."""
    if ELASTIC_API_KEY:
        return f"ApiKey {ELASTIC_API_KEY}"
    if ELASTIC_USERNAME and ELASTIC_PASSWORD:
        creds = base64.b64encode(
            f"{ELASTIC_USERNAME}:{ELASTIC_PASSWORD}".encode("utf-8")
        ).decode("ascii")
        return f"Basic {creds}"
    return None


def _index_to_elastic(doc: Dict[str, Any]) -> Tuple[int, Optional[str]]:
    """
    POST a document to Elasticsearch index API.
    Returns (status_code, error_or_None).

    If ELASTIC_URL is "mock" or empty, prints to stdout.
    """
    if not ELASTIC_URL or ELASTIC_URL == "mock":
        log.info("[MOCK-ELASTIC] ECS document:\n%s", json.dumps(doc, indent=2, default=str))
        return 200, None

    url = f"{ELASTIC_URL.rstrip('/')}/{ELASTIC_INDEX}/_doc"
    body = json.dumps(doc, default=str).encode("utf-8")
    headers: Dict[str, str] = {"Content-Type": "application/json"}
    auth = _build_auth_header()
    if auth:
        headers["Authorization"] = auth

    req = urllib.request.Request(url, data=body, headers=headers, method="POST")  # nosec B310
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # nosec B310
            return resp.status, None
    except urllib.error.HTTPError as exc:
        return exc.code, f"HTTP {exc.code}: {exc.reason}"
    except urllib.error.URLError as exc:
        return 0, f"URLError: {exc.reason}"
    except Exception as exc:  # noqa: BLE001
        return 0, str(exc)


# ---------------------------------------------------------------------------
# HTTP request handler
# ---------------------------------------------------------------------------


class ALdeciWebhookHandler(BaseHTTPRequestHandler):
    """Receives ALdeci webhooks, transforms to ECS, indexes to Elasticsearch."""

    server_version = "ALdeci-ElasticForwarder/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        pass

    def do_GET(self) -> None:  # noqa: N802
        if self.path in ("/health", "/status"):
            self._respond(200, {"status": "healthy", "forwarder": "elastic-ecs"})
        else:
            self._respond(404, {"error": "Not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path not in ("/webhook", "/webhook/"):
            self._respond(404, {"error": "Not found"})
            return

        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len)

        sig = self.headers.get("X-ALdeci-Signature") or self.headers.get("X-Aldeci-Signature")
        if not _verify_signature(body, sig):
            self._respond(401, {"error": "Invalid signature"})
            return

        try:
            payload: Dict[str, Any] = json.loads(body)
        except json.JSONDecodeError as exc:
            self._respond(400, {"error": f"Invalid JSON: {exc}"})
            return

        event_type: str = (
            self.headers.get("X-ALdeci-Event")
            or payload.get("event_type", "unknown")
        )

        log.info("Received event=%s finding_id=%s", event_type, payload.get("finding_id", "n/a"))

        ecs_doc = transform_to_ecs(event_type, payload)
        status_code, error = _index_to_elastic(ecs_doc)

        if error:
            log.error("Elasticsearch index failed: %s (HTTP %s)", error, status_code)
            self._respond(502, {"error": "Elasticsearch index failed", "detail": error})
        else:
            log.info("Indexed to Elasticsearch — HTTP %s", status_code)
            self._respond(200, {"status": "indexed", "elastic_status": status_code})

    def _respond(self, code: int, body: Dict[str, Any]) -> None:
        data = json.dumps(body).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def run(port: int = LISTEN_PORT, server_class: type = HTTPServer) -> None:
    server = server_class(("", port), ALdeciWebhookHandler)
    mode = "MOCK" if (not ELASTIC_URL or ELASTIC_URL == "mock") else ELASTIC_URL
    log.info("Elastic ECS forwarder listening on port %d (target=%s)", port, mode)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down")
    finally:
        server.server_close()


if __name__ == "__main__":
    run()
