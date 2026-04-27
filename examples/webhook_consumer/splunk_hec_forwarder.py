"""
Splunk HEC Forwarder — ALdeci webhook consumer.

Listens on HTTP port 9090 (configurable) for ALdeci webhook events,
transforms each event into Splunk HTTP Event Collector (HEC) format,
and POSTs to a configured Splunk HEC endpoint.

Splunk HEC spec:
  https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector

Environment variables:
  ALDECI_WEBHOOK_PORT   Listening port (default: 9090)
  SPLUNK_HEC_URL        Splunk HEC endpoint, e.g. https://splunk.example.com:8088/services/collector
  SPLUNK_HEC_TOKEN      Splunk HEC token (required for real Splunk)
  SPLUNK_INDEX          Splunk index to write to (default: aldeci_security)
  SPLUNK_SOURCETYPE     Sourcetype for events (default: aldeci:finding)
  SPLUNK_HOST           Source host label (default: aldeci-platform)
  ALDECI_WEBHOOK_SECRET Optional HMAC-SHA256 secret for signature verification

Mock-Splunk fallback:
  If SPLUNK_HEC_URL is not set or is the literal string "mock", the forwarder
  echoes transformed events to stdout instead of posting to Splunk.
  Use this for local demos without a real Splunk instance.

Run:
  python splunk_hec_forwarder.py

Register with ALdeci:
  curl -X POST http://localhost:8000/api/v1/webhook-subscriptions/ \\
    -H "Content-Type: application/json" \\
    -H "Authorization: Bearer $ALDECI_TOKEN" \\
    -d '{"url": "https://your-ngrok-url.ngrok.io/webhook",
         "events": ["finding.created","finding.critical","alert.created"]}'
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [splunk-hec-forwarder] %(message)s",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

LISTEN_PORT: int = int(os.environ.get("ALDECI_WEBHOOK_PORT", "9090"))
SPLUNK_HEC_URL: str = os.environ.get("SPLUNK_HEC_URL", "mock")
SPLUNK_HEC_TOKEN: str = os.environ.get("SPLUNK_HEC_TOKEN", "")
SPLUNK_INDEX: str = os.environ.get("SPLUNK_INDEX", "aldeci_security")
SPLUNK_SOURCETYPE: str = os.environ.get("SPLUNK_SOURCETYPE", "aldeci:finding")
SPLUNK_HOST: str = os.environ.get("SPLUNK_HOST", "aldeci-platform")
ALDECI_WEBHOOK_SECRET: str = os.environ.get("ALDECI_WEBHOOK_SECRET", "")

# Severity → Splunk severity label mapping
_SEVERITY_MAP: Dict[str, str] = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "informational",
}

# ---------------------------------------------------------------------------
# HMAC signature verification
# ---------------------------------------------------------------------------


def _verify_signature(body: bytes, sig_header: Optional[str]) -> bool:
    """Verify X-ALdeci-Signature header if a secret is configured."""
    if not ALDECI_WEBHOOK_SECRET:
        return True  # no secret configured — skip verification
    if not sig_header:
        log.warning("Missing X-ALdeci-Signature header — rejecting request")
        return False
    expected = "sha256=" + hmac.new(
        ALDECI_WEBHOOK_SECRET.encode("utf-8"), body, hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected, sig_header)


# ---------------------------------------------------------------------------
# ALdeci → Splunk HEC transform
# ---------------------------------------------------------------------------


def transform_to_hec(event_type: str, aldeci_payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Transform an ALdeci webhook payload into Splunk HEC JSON format.

    Splunk HEC envelope:
      {
        "time":       <epoch float>,
        "host":       <source host>,
        "source":     <scanner/source>,
        "sourcetype": <sourcetype>,
        "index":      <index>,
        "event": {
          ... normalised ALdeci fields ...
        }
      }

    Ref: https://docs.splunk.com/Documentation/Splunk/latest/Data/FormateventsforHTTPEventCollector
    """
    # Parse timestamp — prefer detected_at / timestamp in payload
    ts_str: Optional[str] = (
        aldeci_payload.get("detected_at")
        or aldeci_payload.get("timestamp")
        or aldeci_payload.get("created_at")
    )
    try:
        if ts_str:
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            epoch_time = dt.timestamp()
        else:
            epoch_time = time.time()
    except (ValueError, TypeError):
        epoch_time = time.time()

    severity_raw: str = str(aldeci_payload.get("severity", "info")).lower()
    severity: str = _SEVERITY_MAP.get(severity_raw, "informational")

    event_body: Dict[str, Any] = {
        # Core fields
        "aldeci_event_type": event_type,
        "finding_id": aldeci_payload.get("finding_id", ""),
        "title": aldeci_payload.get("title", ""),
        "severity": severity,
        "severity_raw": severity_raw,
        "affected_asset": aldeci_payload.get("affected_asset", ""),
        "source_scanner": aldeci_payload.get("source", ""),
        "org_id": aldeci_payload.get("org_id", ""),
        # Optional enrichment fields
        "cve_id": aldeci_payload.get("cve_id"),
        "cvss_score": aldeci_payload.get("cvss_score"),
        "description": aldeci_payload.get("description", "")[:1024],
        # Decision fields (present on decision.made events)
        "decision": aldeci_payload.get("decision"),
        "confidence": aldeci_payload.get("confidence"),
        "recommendation": aldeci_payload.get("recommendation"),
        # Threat fields (present on threat.detected events)
        "threat_actor": aldeci_payload.get("threat_actor"),
        "ioc": aldeci_payload.get("ioc"),
        "mitre_technique": aldeci_payload.get("mitre_technique"),
        # Delivery metadata
        "webhook_id": aldeci_payload.get("webhook_id", ""),
        "delivered_at": aldeci_payload.get("delivered_at", ""),
    }

    # Strip None values to keep Splunk events compact
    event_body = {k: v for k, v in event_body.items() if v is not None and v != ""}

    return {
        "time": epoch_time,
        "host": SPLUNK_HOST,
        "source": aldeci_payload.get("source", "aldeci"),
        "sourcetype": SPLUNK_SOURCETYPE,
        "index": SPLUNK_INDEX,
        "event": event_body,
    }


# ---------------------------------------------------------------------------
# HEC delivery
# ---------------------------------------------------------------------------


def _post_to_splunk(hec_event: Dict[str, Any]) -> Tuple[int, Optional[str]]:
    """
    POST a single HEC event to Splunk. Returns (status_code, error_or_None).

    If SPLUNK_HEC_URL is "mock" or empty, prints to stdout and returns (200, None).
    """
    if not SPLUNK_HEC_URL or SPLUNK_HEC_URL == "mock":
        log.info("[MOCK-SPLUNK] HEC event: %s", json.dumps(hec_event, indent=2))
        return 200, None

    body = json.dumps(hec_event).encode("utf-8")
    headers = {
        "Authorization": f"Splunk {SPLUNK_HEC_TOKEN}",
        "Content-Type": "application/json",
    }
    req = urllib.request.Request(  # nosec B310
        SPLUNK_HEC_URL, data=body, headers=headers, method="POST"
    )
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
    """Minimal HTTP handler — receives POST /webhook, transforms, forwards."""

    server_version = "ALdeci-SplunkHECForwarder/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:  # suppress default access log
        pass

    def do_GET(self) -> None:  # noqa: N802
        if self.path in ("/health", "/status"):
            self._respond(200, {"status": "healthy", "forwarder": "splunk-hec"})
        else:
            self._respond(404, {"error": "Not found"})

    def do_POST(self) -> None:  # noqa: N802
        if self.path not in ("/webhook", "/webhook/"):
            self._respond(404, {"error": "Not found"})
            return

        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len)

        # Signature verification
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

        hec_event = transform_to_hec(event_type, payload)
        status_code, error = _post_to_splunk(hec_event)

        if error:
            log.error("Splunk HEC delivery failed: %s (HTTP %s)", error, status_code)
            self._respond(502, {"error": "Splunk delivery failed", "detail": error})
        else:
            log.info("Forwarded to Splunk HEC — HTTP %s", status_code)
            self._respond(200, {"status": "forwarded", "splunk_status": status_code})

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
    mode = "MOCK" if (not SPLUNK_HEC_URL or SPLUNK_HEC_URL == "mock") else SPLUNK_HEC_URL
    log.info("Splunk HEC forwarder listening on port %d (target=%s)", port, mode)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down")
    finally:
        server.server_close()


if __name__ == "__main__":
    run()
