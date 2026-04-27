# ALdeci Webhook Consumer Examples

Three production-ready external consumer examples that prove the ALdeci
TrustGraph EventBus is open for partner integrations (SIEM/SOC federation story).

## Forwarders

| File | Port | Target | Schema |
|------|------|--------|--------|
| `splunk_hec_forwarder.py` | 9090 | Splunk HEC | [Splunk HEC docs](https://docs.splunk.com/Documentation/Splunk/latest/Data/UsetheHTTPEventCollector) |
| `elastic_forwarder.py` | 9091 | Elasticsearch | [ECS spec](https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html) |
| `slack_alerter.py` | 9092 | Slack Block Kit | [Slack webhooks](https://api.slack.com/messaging/webhooks) |

All three run without external dependencies (stdlib only). Each has a
**mock-target fallback**: set the target URL to `"mock"` (or leave it unset)
and events are echoed to stdout — useful for local demos.

---

## Quick Start

### Step 1 — Start the forwarders

```bash
# Terminal 1 — Splunk (mock mode)
python examples/webhook_consumer/splunk_hec_forwarder.py

# Terminal 2 — Elastic (mock mode)
ALDECI_WEBHOOK_PORT=9091 python examples/webhook_consumer/elastic_forwarder.py

# Terminal 3 — Slack (mock mode, only HIGH/CRITICAL decision.made events)
ALDECI_WEBHOOK_PORT=9092 python examples/webhook_consumer/slack_alerter.py
```

### Step 2 — Register with ALdeci

```bash
export ALDECI_TOKEN="your-api-token"
export ALDECI_URL="http://localhost:8000"

# Register Splunk forwarder
curl -s -X POST "$ALDECI_URL/api/v1/webhook-subscriptions/" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ALDECI_TOKEN" \
  -d '{
    "url": "https://your-public-host:9090/webhook",
    "events": ["finding.created", "finding.critical", "sla.breach"],
    "description": "Splunk HEC forwarder"
  }'

# Register Elastic forwarder
curl -s -X POST "$ALDECI_URL/api/v1/webhook-subscriptions/" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ALDECI_TOKEN" \
  -d '{
    "url": "https://your-public-host:9091/webhook",
    "events": ["finding.created", "finding.critical", "alert.created"],
    "description": "Elastic ECS forwarder"
  }'

# Register Slack alerter
curl -s -X POST "$ALDECI_URL/api/v1/webhook-subscriptions/" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $ALDECI_TOKEN" \
  -d '{
    "url": "https://your-public-host:9092/webhook",
    "events": ["decision.made", "finding.critical", "alert.created", "threat.detected"],
    "description": "Slack HIGH/CRITICAL alerter"
  }'
```

### Step 3 — Fire a test event

```bash
# Emit a test finding via ALdeci scan-test endpoint
curl -s -X POST "$ALDECI_URL/api/v1/scans/test-emit" \
  -H "Authorization: Bearer $ALDECI_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "event_type": "finding.critical",
    "severity": "critical",
    "title": "SQL Injection in /api/v1/login",
    "affected_asset": "src/auth/login.py",
    "source": "semgrep",
    "org_id": "demo-org"
  }'
```

You should see the event appear in:
- **Splunk mock**: JSON printed to Terminal 1
- **Elastic mock**: ECS document printed to Terminal 2
- **Slack mock**: Block Kit message printed to Terminal 3 (only if severity=critical or high)

---

## Real Target Configuration

### Splunk HEC

```bash
export SPLUNK_HEC_URL="https://splunk.example.com:8088/services/collector"
export SPLUNK_HEC_TOKEN="your-hec-token"
export SPLUNK_INDEX="aldeci_security"
export SPLUNK_SOURCETYPE="aldeci:finding"
python examples/webhook_consumer/splunk_hec_forwarder.py
```

The forwarder maps ALdeci severities to Splunk severity labels per the HEC
`event.severity` field. Each event lands in `$SPLUNK_INDEX` with
`sourcetype=aldeci:finding`.

### Elasticsearch

```bash
export ELASTIC_URL="https://elastic.example.com:9200"
export ELASTIC_API_KEY="your-base64-api-key"
export ELASTIC_INDEX="aldeci-security"
python examples/webhook_consumer/elastic_forwarder.py
```

Or with basic auth:

```bash
export ELASTIC_USERNAME="elastic"
export ELASTIC_PASSWORD="changeme"
```

Documents are indexed as ECS with full `event.*`, `vulnerability.*`,
`file.*`, `observer.*`, and `organization.*` field sets.

### Slack

```bash
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/T.../B.../xxx"
export SLACK_CHANNEL="#security-alerts"          # optional override
export SLACK_ALERT_SEVERITIES="high,critical"    # comma-separated
export SLACK_ALERT_EVENTS="decision.made,finding.critical,threat.detected"
export ALDECI_DASHBOARD_URL="https://aldeci.example.com"
python examples/webhook_consumer/slack_alerter.py
```

Only events matching BOTH `SLACK_ALERT_EVENTS` and `SLACK_ALERT_SEVERITIES`
are forwarded. All other events receive `200 {"status": "skipped"}`.

---

## HMAC Signature Verification

ALdeci signs all webhook deliveries with `X-ALdeci-Signature: sha256=<hex>`.
To verify:

```bash
export ALDECI_WEBHOOK_SECRET="the-secret-from-subscription-create-response"
python examples/webhook_consumer/splunk_hec_forwarder.py
```

When `ALDECI_WEBHOOK_SECRET` is set, all three forwarders reject requests
with missing or invalid signatures with HTTP 401.

---

## Running the Integration Test

```bash
python -m pytest examples/webhook_consumer/test_consumer.py -v
```

The test boots all three forwarders on random free ports, fires 3 canonical
ALdeci events at each, and asserts correct transformation and delivery.

---

## Supported Event Types

Per `webhook_subscriptions_router.py`:

| Event | Description |
|-------|-------------|
| `finding.created` | New finding from any scanner |
| `finding.critical` | Finding with CRITICAL severity |
| `finding.resolved` | Finding closed/remediated |
| `sla.breach` | SLA deadline exceeded |
| `pipeline.completed` | Brain pipeline run finished |
| `autofix.applied` | AI AutoFix patch applied |
| `compliance.violation` | Compliance control failure |
| `attack_path.discovered` | New attack path found by MPTE |

---

## Schema References

- **Splunk HEC**: https://docs.splunk.com/Documentation/Splunk/latest/Data/FormateventsforHTTPEventCollector
- **ECS**: https://www.elastic.co/guide/en/ecs/current/ecs-field-reference.html
- **Slack Block Kit**: https://api.slack.com/reference/block-kit/blocks
