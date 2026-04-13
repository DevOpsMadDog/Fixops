# ALDECI Enterprise Security Simulation Design

## Overview

Full 8-stage lifecycle: **Code → Cloud → SIEM → SOAR → EDR → CMDB → ALM → Back to Code**

Each stage uses REAL ALDECI API endpoints with data flowing through TrustGraph Knowledge Cores.

## Architecture

```
Stage 1: CODE          Stage 2: CLOUD         Stage 3: SIEM
SAST scan → findings   IaC scan → misconfigs  Audit logs → anomalies
Secrets scan → exposed Container scan → CVEs   Threat hunt → IOC matches
    ↓                      ↓                       ↓
  [TrustGraph Core 2]   [TrustGraph Core 1+2]  [TrustGraph Core 2]
    ↓                      ↓                       ↓
Stage 8: FIX ←←←←←←  Stage 7: ALM          Stage 4: SOAR
Re-scan confirms fix   Jira ticket created    IR playbook triggers
Issue closed, SLA met  SLA assigned (24h)     SOAR containment
Posture improves       Compliance checked     WAF rule generated
    ↑                      ↑                       ↓
  [TrustGraph All]     [TrustGraph Core 3+4]  [TrustGraph Core 4]
    ↑                      ↑                       ↓
Stage 6: CMDB          Stage 5: EDR
Asset inventory updated RASP blocks exploit
Vendor risk assessed    Network lateral movement
Data classification     Container drift detected
```

## Stage API Calls

### Stage 1: CODE
- `POST /api/v1/scanner-ingest/webhook/semgrep` — SAST findings
- `POST /api/v1/secrets/scan` — Secret detection
- `POST /api/v1/graph/index` — Index into TrustGraph Core 2

### Stage 2: CLOUD
- `POST /api/v1/containers/scan` — Dockerfile analysis
- `POST /api/v1/cspm-engine/scan` — Cloud misconfigurations
- `POST /api/v1/drift/check` — Configuration drift
- `POST /api/v1/graph/index` — Index into TrustGraph Core 1+2

### Stage 3: SIEM
- `POST /api/v1/audit/logs/chain` — Audit log ingestion
- `POST /api/v1/anomalies/detect` — Anomaly detection
- `POST /api/v1/hunting/ioc-correlate` — IOC correlation
- `POST /api/v1/graph/index` — Index into TrustGraph Core 2

### Stage 4: SOAR
- `POST /api/v1/incidents` — Create IR incident
- `POST /api/v1/workflows/evaluate` — SOAR workflow
- `POST /api/v1/graph/index` — Index into TrustGraph Core 4

### Stage 5: EDR
- `GET /api/v1/rasp/threats` — RASP blocked threats
- `POST /api/v1/runtime/events/evaluate` — Runtime event analysis
- `POST /api/v1/network/analysis/detect-violations` — Lateral movement
- `POST /api/v1/drift/check` — Container drift
- `POST /api/v1/graph/index` — Index into TrustGraph Core 1+2

### Stage 6: CMDB
- `POST /api/v1/inventory/apps` — Update asset inventory
- `POST /api/v1/vendors/{id}/auto-assess` — Vendor risk
- `POST /api/v1/classification/assets/{id}/auto-classify` — Data classification
- `POST /api/v1/graph/index` — Index into TrustGraph Core 1

### Stage 7: ALM
- `POST /api/v1/jira-sync/sync-finding` — Create Jira ticket
- `POST /api/v1/sla/track` — Assign SLA
- `GET /api/v1/audit/compliance/frameworks/soc2/status` — Check compliance
- `POST /api/v1/posture/calculate` — Security posture score
- `POST /api/v1/graph/index` — Index into TrustGraph Core 3+4

### Stage 8: FIX
- `POST /api/v1/scanner-ingest/webhook/semgrep` — Re-scan (0 findings)
- `POST /api/v1/jira-sync/sync-status` — Close Jira issue
- `PUT /api/v1/incidents/{id}/status` — Close incident
- `GET /api/v1/sla/status/{finding_id}` — Verify SLA met
- `POST /api/v1/posture/calculate` — Score improves
- `POST /api/v1/graph/index` — Update all cores

## Gaps to Build

| Priority | Endpoint | Purpose |
|----------|---------|---------|
| HIGH | `POST /api/v1/simulation/run` | Orchestrator for all 8 stages |
| HIGH | TrustGraph Event Bus middleware | Auto-connect 3,036 endpoints |
| MEDIUM | `POST /api/v1/rasp/rules/auto-generate` | Auto WAF from CWEs |
| MEDIUM | `GET /api/v1/graph/lifecycle/{id}` | Full lifecycle traversal |

## TrustGraph Knowledge Core Mapping

| Core | Name | Receives From |
|------|------|--------------|
| 1 | Customer Environment | Assets, configs, repos, cloud resources |
| 2 | Threat Intelligence | Findings, CVEs, IOCs, vulnerabilities |
| 3 | Compliance & Regulatory | Controls, evidence, gaps, SLA |
| 4 | Decision Memory | Verdicts, triage, response actions |
| 5 | Competitive Intelligence | (not used in simulation) |

## Disconnection Stats

- **Total API endpoints:** 3,036
- **Connected to TrustGraph:** 52 (1.7%)
- **Disconnected:** 2,984 (98.3%)
- **Fix:** TrustGraph Event Bus middleware (building now)
