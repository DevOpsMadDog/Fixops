# n8n Workflow Import Instructions

## Status
- n8n container: RUNNING (`vigilant_solomon`, port 5678)
- n8n version: 2.16.1
- API access: BLOCKED (basic auth enabled, credentials not stored in env)
- Workflow files: READY for manual import

## How to Import

### Step 1 — Get n8n credentials
The container has `N8N_BASIC_AUTH_ACTIVE=true` but the username/password were set
at container creation time. Try one of:
- Check the docker-compose file that launched this container
- Default n8n first-run creates an owner account via browser setup wizard
- Open http://localhost:5678 in a browser — n8n will prompt for login

### Step 2 — Import workflows via UI
1. Open http://localhost:5678
2. Log in with your credentials
3. Click **"+"** → **"Import from File"**
4. Import each file in order:

| File | Workflow | Schedule |
|------|----------|----------|
| `01-aldeci-daily-posture-report.json` | ALDECI Daily Posture Report | 6:00 AM UTC daily |
| `02-critical-alert-escalation.json` | ALDECI Critical Alert Escalation | Webhook (on-demand) |
| `03-weekly-compliance-summary.json` | ALDECI Weekly Compliance Summary | Monday 8:00 AM UTC |

### Step 3 — Configure webhooks/Slack
Set environment variables in Docker or in each workflow node:

```bash
SLACK_SECURITY_WEBHOOK=https://hooks.slack.com/services/YOUR/REAL/WEBHOOK
SLACK_COMPLIANCE_WEBHOOK=https://hooks.slack.com/services/YOUR/REAL/WEBHOOK
ALDECI_REPORT_WEBHOOK=https://hooks.slack.com/services/YOUR/REAL/WEBHOOK
```

Or edit the webhook URLs directly in each "Send" node inside n8n.

### Step 4 — Activate workflows
After importing, toggle each workflow to **Active** in the n8n UI.

---

## Workflow Details

### 1. ALDECI Daily Posture Report
- **Trigger:** Cron `0 6 * * *` (6am UTC daily)
- **Flow:** Schedule → fetch `/api/v1/platform/health` + `/api/v1/kpi/summary` → format markdown → POST to Slack/webhook
- **ALDECI endpoint:** `http://host.docker.internal:8000` (Docker internal DNS)
- **Output:** Markdown report with posture score, open vulns, critical alerts, MTTD, MTTR

### 2. Critical Alert Escalation
- **Trigger:** Webhook POST to `http://localhost:5678/webhook/aldeci-critical-alert`
- **Flow:** Receive alert JSON → check severity==critical → format Slack blocks → POST to Slack + auto-triage in ALDECI → respond 200
- **Non-critical alerts:** Immediately respond 200 with `status: ignored`
- **How to trigger from ALDECI:**
  ```bash
  curl -X POST http://localhost:5678/webhook/aldeci-critical-alert \
    -H "Content-Type: application/json" \
    -d '{"id":"alert-001","severity":"critical","title":"Ransomware Detected","description":"File encryption activity on host-42","source":"ransomware_protection","org_id":"acme"}'
  ```

### 3. Weekly Compliance Summary
- **Trigger:** Cron `0 8 * * 1` (Monday 8am UTC)
- **Flow:** Schedule → fetch compliance/status + gaps + coverage → format report → POST to Slack + store in ALDECI regulatory-reporting
- **Frameworks covered:** SOC2, PCI-DSS, ISO27001, NIST, GDPR, HIPAA (whatever `/api/v1/compliance/status` returns)
- **ALDECI links in report:** `/compliance`, `/gap-analysis`, `/compliance-mapping`, `/compliance-calendar`

---

## If you want API access (skip browser login)

Re-launch the container with an API key enabled:
```bash
docker stop vigilant_solomon
docker run -d \
  --name n8n-aldeci \
  -p 5678:5678 \
  -e N8N_BASIC_AUTH_ACTIVE=false \
  -e N8N_API_KEY_ENABLED=true \
  -v n8n_data:/home/node/.n8n \
  n8nio/n8n:2.16.1
```
Then use: `curl -H "X-N8N-API-KEY: your-key" http://localhost:5678/api/v1/workflows`
