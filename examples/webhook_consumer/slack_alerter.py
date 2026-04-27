"""
Slack Alerter — ALdeci webhook consumer.

Listens on HTTP port 9092 (configurable) for ALdeci webhook events.
For `decision.made` events with severity HIGH or CRITICAL, posts a
rich Slack Block Kit message to a configured Slack Incoming Webhook URL.

Slack Incoming Webhooks spec:
  https://api.slack.com/messaging/webhooks
  https://api.slack.com/reference/block-kit/blocks

Environment variables:
  ALDECI_WEBHOOK_PORT      Listening port (default: 9092)
  SLACK_WEBHOOK_URL        Slack incoming webhook URL (required for real delivery)
                           Set to "mock" to echo to stdout instead.
  SLACK_CHANNEL            Optional channel override (e.g. #security-alerts)
  SLACK_ALERT_SEVERITIES   Comma-separated severities to alert on (default: high,critical)
  SLACK_ALERT_EVENTS       Comma-separated event types to alert on
                           (default: decision.made,finding.critical,alert.created,threat.detected)
  ALDECI_DASHBOARD_URL     Base URL for deep-links (default: http://localhost:8000)
  ALDECI_WEBHOOK_SECRET    Optional HMAC-SHA256 secret for signature verification

Run:
  python slack_alerter.py

Register with ALdeci:
  curl -X POST http://localhost:8000/api/v1/webhook-subscriptions/ \\
    -H "Content-Type: application/json" \\
    -H "Authorization: Bearer $ALDECI_TOKEN" \\
    -d '{"url": "https://your-forwarder.example.com/webhook",
         "events": ["decision.made","finding.critical","alert.created","threat.detected"]}'
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional, Set, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [slack-alerter] %(message)s",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

LISTEN_PORT: int = int(os.environ.get("ALDECI_WEBHOOK_PORT", "9092"))
SLACK_WEBHOOK_URL: str = os.environ.get("SLACK_WEBHOOK_URL", "mock")
SLACK_CHANNEL: str = os.environ.get("SLACK_CHANNEL", "")
ALDECI_DASHBOARD_URL: str = os.environ.get("ALDECI_DASHBOARD_URL", "http://localhost:8000")
ALDECI_WEBHOOK_SECRET: str = os.environ.get("ALDECI_WEBHOOK_SECRET", "")

_ALERT_SEVERITIES: Set[str] = {
    s.strip().lower()
    for s in os.environ.get("SLACK_ALERT_SEVERITIES", "high,critical").split(",")
    if s.strip()
}

_ALERT_EVENTS: Set[str] = {
    e.strip()
    for e in os.environ.get(
        "SLACK_ALERT_EVENTS",
        "decision.made,finding.critical,alert.created,threat.detected",
    ).split(",")
    if e.strip()
}

# Severity → Slack colour (attachment fallback for older clients)
_SEVERITY_COLOUR: Dict[str, str] = {
    "critical": "#FF0000",
    "high": "#FF6600",
    "medium": "#FFC000",
    "low": "#0080FF",
    "info": "#808080",
}

# Severity → Slack emoji prefix
_SEVERITY_EMOJI: Dict[str, str] = {
    "critical": ":rotating_light:",
    "high": ":warning:",
    "medium": ":large_orange_circle:",
    "low": ":large_blue_circle:",
    "info": ":information_source:",
}


# ---------------------------------------------------------------------------
# HMAC verification
# ---------------------------------------------------------------------------


def _verify_signature(body: bytes, sig_header: Optional[str]) -> bool:
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
# Slack Block Kit message builder
# ---------------------------------------------------------------------------


def _finding_url(finding_id: str) -> str:
    return f"{ALDECI_DASHBOARD_URL.rstrip('/')}/findings/{finding_id}"


def build_slack_message(event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a Slack Block Kit message payload for an ALdeci event.

    Uses Slack's Block Kit with:
      - Header block (coloured emoji + title)
      - Section with key fields
      - Actions block with deep-link button to ALdeci dashboard
      - Fallback text for notifications

    Ref: https://api.slack.com/reference/block-kit/blocks
    """
    severity: str = str(payload.get("severity", "info")).lower()
    emoji: str = _SEVERITY_EMOJI.get(severity, ":information_source:")
    colour: str = _SEVERITY_COLOUR.get(severity, "#808080")
    title: str = payload.get("title", event_type)
    finding_id: str = str(payload.get("finding_id", ""))
    org_id: str = str(payload.get("org_id", ""))
    asset: str = str(payload.get("affected_asset", ""))
    source: str = str(payload.get("source", "aldeci"))
    cve_id: Optional[str] = payload.get("cve_id")
    cvss: Optional[float] = payload.get("cvss_score")
    description: str = str(payload.get("description", ""))[:500]
    decision: Optional[str] = payload.get("decision")
    recommendation: Optional[str] = payload.get("recommendation")
    threat_actor: Optional[str] = payload.get("threat_actor")
    mitre: Optional[str] = payload.get("mitre_technique")
    ts_str: str = str(payload.get("detected_at") or datetime.now(timezone.utc).isoformat())

    # Fallback text (shown in notifications, search results)
    fallback = f"{emoji} [{severity.upper()}] {title} | org={org_id}"

    # --- Blocks ---
    blocks: List[Dict[str, Any]] = []

    # Header block
    blocks.append({
        "type": "header",
        "text": {
            "type": "plain_text",
            "text": f"{emoji} [{severity.upper()}] {title[:150]}",
            "emoji": True,
        },
    })

    # Main section with key fields
    fields: List[Dict[str, str]] = [
        {"type": "mrkdwn", "text": f"*Event*\n`{event_type}`"},
        {"type": "mrkdwn", "text": f"*Severity*\n`{severity.upper()}`"},
    ]
    if org_id:
        fields.append({"type": "mrkdwn", "text": f"*Org*\n{org_id}"})
    if asset:
        fields.append({"type": "mrkdwn", "text": f"*Asset*\n`{asset[:60]}`"})
    if source:
        fields.append({"type": "mrkdwn", "text": f"*Scanner*\n{source}"})
    if cve_id:
        fields.append({"type": "mrkdwn", "text": f"*CVE*\n<https://nvd.nist.gov/vuln/detail/{cve_id}|{cve_id}>"})
    if cvss is not None:
        fields.append({"type": "mrkdwn", "text": f"*CVSS*\n{cvss}"})
    if decision:
        fields.append({"type": "mrkdwn", "text": f"*Decision*\n{decision}"})
    if threat_actor:
        fields.append({"type": "mrkdwn", "text": f"*Threat Actor*\n{threat_actor}"})
    if mitre:
        fields.append({"type": "mrkdwn", "text": f"*MITRE*\n`{mitre}`"})

    # Split into chunks of 10 (Slack section field limit)
    for i in range(0, len(fields), 10):
        blocks.append({"type": "section", "fields": fields[i : i + 10]})

    # Description / recommendation text block
    body_lines: List[str] = []
    if description:
        body_lines.append(f"*Details:* {description}")
    if recommendation:
        body_lines.append(f"*Recommendation:* {recommendation}")
    if body_lines:
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": "\n".join(body_lines)},
        })

    # Context block — timestamp + finding ID
    context_elements: List[Dict[str, str]] = [
        {"type": "mrkdwn", "text": f"Detected: {ts_str}"},
    ]
    if finding_id:
        context_elements.append({"type": "mrkdwn", "text": f"Finding ID: `{finding_id}`"})
    blocks.append({"type": "context", "elements": context_elements})

    # Action button — deep-link to ALdeci dashboard
    if finding_id:
        blocks.append({
            "type": "actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "View in ALdeci", "emoji": True},
                    "url": _finding_url(finding_id),
                    "style": "danger" if severity in ("critical", "high") else "primary",
                    "action_id": "view_finding",
                }
            ],
        })

    # Divider
    blocks.append({"type": "divider"})

    message: Dict[str, Any] = {
        "text": fallback,
        "blocks": blocks,
        # Attachment for colour bar (legacy but widely rendered)
        "attachments": [
            {
                "color": colour,
                "fallback": fallback,
            }
        ],
    }
    if SLACK_CHANNEL:
        message["channel"] = SLACK_CHANNEL

    return message


# ---------------------------------------------------------------------------
# Slack delivery
# ---------------------------------------------------------------------------


def _post_to_slack(message: Dict[str, Any]) -> Tuple[int, Optional[str]]:
    """
    POST a Block Kit message to Slack. Returns (status_code, error_or_None).

    If SLACK_WEBHOOK_URL is "mock" or empty, prints to stdout.
    """
    if not SLACK_WEBHOOK_URL or SLACK_WEBHOOK_URL == "mock":
        log.info("[MOCK-SLACK] Block Kit message:\n%s", json.dumps(message, indent=2))
        return 200, None

    body = json.dumps(message).encode("utf-8")
    req = urllib.request.Request(  # nosec B310
        SLACK_WEBHOOK_URL,
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
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
    """Receives ALdeci webhooks, filters by severity/event, posts to Slack."""

    server_version = "ALdeci-SlackAlerter/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        pass

    def do_GET(self) -> None:  # noqa: N802
        if self.path in ("/health", "/status"):
            self._respond(200, {
                "status": "healthy",
                "forwarder": "slack-alerter",
                "alert_events": sorted(_ALERT_EVENTS),
                "alert_severities": sorted(_ALERT_SEVERITIES),
            })
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
        severity: str = str(payload.get("severity", "info")).lower()

        # Filter — only alert on configured event types AND severities
        if event_type not in _ALERT_EVENTS:
            log.debug("Skipping event=%s (not in alert events)", event_type)
            self._respond(200, {"status": "skipped", "reason": "event_type_not_configured"})
            return

        if severity not in _ALERT_SEVERITIES:
            log.debug("Skipping severity=%s (below threshold)", severity)
            self._respond(200, {"status": "skipped", "reason": "severity_below_threshold"})
            return

        log.info(
            "Alerting: event=%s severity=%s finding_id=%s",
            event_type, severity, payload.get("finding_id", "n/a"),
        )

        message = build_slack_message(event_type, payload)
        status_code, error = _post_to_slack(message)

        if error:
            log.error("Slack delivery failed: %s (HTTP %s)", error, status_code)
            self._respond(502, {"error": "Slack delivery failed", "detail": error})
        else:
            log.info("Slack alert sent — HTTP %s", status_code)
            self._respond(200, {"status": "alerted", "slack_status": status_code})

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
    mode = "MOCK" if (not SLACK_WEBHOOK_URL or SLACK_WEBHOOK_URL == "mock") else SLACK_WEBHOOK_URL
    log.info("Slack alerter listening on port %d (target=%s)", port, mode)
    log.info("Alerting on events=%s severities=%s", sorted(_ALERT_EVENTS), sorted(_ALERT_SEVERITIES))
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down")
    finally:
        server.server_close()


if __name__ == "__main__":
    run()
