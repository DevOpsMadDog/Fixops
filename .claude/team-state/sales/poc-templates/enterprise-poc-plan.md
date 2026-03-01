# ALdeci POC Plan — Enterprise Customer Template

> **Duration**: 2 weeks
> **Version**: 1.0 (2026-03-01)
> **Pillars**: [V3] Decision Intelligence, [V5] MPTE Verification, [V7] MCP-Native

---

## POC Overview

| Field | Value |
|-------|-------|
| **Customer Name** | _{Fill in}_ |
| **Industry** | _{Healthcare / FinTech / Government / Defense / Other}_ |
| **Primary Use Case** | _{Noise reduction / Compliance / Exploit verification / AutoFix}_ |
| **Existing Tools** | _{List current scanners: Snyk, Wiz, Semgrep, etc.}_ |
| **Environment** | _{Cloud / On-prem / Air-gapped / Hybrid}_ |
| **Number of Apps** | _{Estimate}_ |
| **Compliance Frameworks** | _{SOC2 / PCI-DSS / HIPAA / ISO27001 / NIST}_ |
| **Decision Maker** | _{Name, Title}_ |
| **Technical Champion** | _{Name, Title}_ |

---

## Success Criteria (Agreed Before POC Start)

- [ ] **Ingest data** from customer's primary scanner (_{scanner name}_)
- [ ] **Correlate findings** across _{N}_ applications
- [ ] **Reduce noise** by 70%+ (raw findings → actionable exposure cases)
- [ ] **MPTE verification** on at least 10 critical findings (prove/disprove exploitability)
- [ ] **AutoFix generation** for at least 5 findings with confidence scores
- [ ] **Generate compliance report** for _{framework}_ with evidence bundle
- [ ] **Decision engine** recommends top 10 priority actions with reasoning

---

## Deployment Options

### Option A: Docker (Recommended for POC)

```bash
# Single command deployment
docker compose -f docker/docker-compose.yml up -d

# Verify health
curl http://localhost:8000/health

# Expected: {"status":"healthy","timestamp":"...","service":"aldeci-api"}
```

**Requirements**: Docker 20.10+, 4 GB RAM, 10 GB disk

### Option B: Air-Gapped Deployment

```bash
# Pre-load Docker image from USB/internal registry
docker load -i aldeci-enterprise.tar.gz
docker compose -f docker/docker-compose.yml up -d

# No internet required — all 8 scanners + self-hosted AI work offline
```

**Requirements**: Docker 20.10+, 8 GB RAM (for self-hosted LLM), 20 GB disk

### Option C: Kubernetes / Helm

```bash
helm install aldeci ./docker/helm/aldeci \
  --set api.replicas=2 \
  --set mode=enterprise
```

---

## Week 1: Setup + Data Ingestion

### Day 1-2: Environment Setup

| Task | API Endpoint | Verification |
|------|-------------|--------------|
| Deploy ALdeci | N/A (Docker) | `GET /health` → 200 |
| Configure API key | Environment variable | `GET /api/v1/system/health` → 200 |
| Health check all services | Pre-flight script | All 18 services green |
| Connect to customer's scanner | `POST /api/v1/connectors` | `GET /api/v1/connectors/{id}` → active |

```bash
# Connect to customer's scanner (example: Snyk)
curl -X POST http://localhost:8000/api/v1/connectors \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Customer Snyk",
    "type": "snyk",
    "config": {
      "api_token": "customer-snyk-token",
      "org_id": "customer-org-id"
    }
  }'
```

### Day 3-4: Data Ingestion

| Task | API Endpoint | Expected Result |
|------|-------------|-----------------|
| Upload scanner report | `POST /api/v1/scanner-ingest/upload` | Findings ingested |
| Verify normalization | `GET /api/v1/analytics/findings` | All findings in UFF format |
| Run native SAST scan | `POST /api/v1/sast/scan/files` | Additional findings |
| Run secrets scan | `POST /api/v1/secrets/scan` | Credential detections |

```bash
# Upload a scanner report (ZAP, Nessus, Burp, etc.)
curl -X POST http://localhost:8000/api/v1/scanner-ingest/upload \
  -H "X-API-Key: $API_KEY" \
  -F "file=@customer-scan-report.json" \
  -F "scanner_type=auto"
```

### Day 5: Brain Pipeline Processing

| Task | API Endpoint | Expected Result |
|------|-------------|-----------------|
| Trigger Brain Pipeline | `POST /api/v1/brain/ingest/scan` | 12-step processing |
| Check knowledge graph | `GET /api/v1/knowledge-graph/analytics` | Nodes + edges populated |
| View deduplication results | `GET /api/v1/brain/stats` | Dedup ratio visible |
| FAIL scoring | `POST /api/v1/fail/score/batch` | Priority rankings |

---

## Week 2: Analysis + Remediation + Review

### Day 6-7: MPTE Verification

| Task | API Endpoint | Expected Result |
|------|-------------|-----------------|
| Verify top 10 criticals | `POST /api/v1/mpte/verify` (×10) | Verdicts per finding |
| Review false positives | `GET /api/v1/mpte/verifications` | FP identification |
| Comprehensive scan | `POST /api/v1/mpte/scan/comprehensive` | Multi-vector results |

### Day 8-9: AutoFix + Compliance

| Task | API Endpoint | Expected Result |
|------|-------------|-----------------|
| Generate fixes for top 5 | `POST /api/v1/autofix/generate` (×5) | Code patches |
| Map to compliance framework | `POST /api/v1/compliance-engine/map-findings` | Control coverage |
| Generate evidence bundle | `GET /api/v1/compliance-engine/audit-bundle` | Signed bundle |
| Export audit logs | `GET /api/v1/audit/logs/export` | Complete trail |

### Day 10: Review Meeting

**Agenda**:
1. **Results walkthrough** (20 min)
   - Noise reduction ratio (target: 70%+)
   - MPTE verification results (exploitable vs false positive)
   - AutoFix accuracy and confidence scores
2. **Compliance readiness** (10 min)
   - Framework coverage percentage
   - Evidence bundle demonstration
3. **Decision engine demo** (10 min)
   - Top 10 priority actions with reasoning
   - Attack path visualization
4. **Pricing discussion** (10 min)
   - Tier selection based on environment size
   - Annual vs monthly

---

## Resources Required

| Resource | From Customer | From ALdeci |
|----------|--------------|-------------|
| Scanner API access | ✅ | — |
| Network access for MPTE | ✅ (staging only) | — |
| Compliance requirements | ✅ | — |
| Technical champion | ✅ (2 hrs/week) | — |
| Deployment support | — | ✅ (included) |
| Training session | — | ✅ (1 hour) |
| Postman collections | — | ✅ (7 collections, 380+ tests) |

---

## Pricing Reference

| Tier | Price | Best For |
|------|-------|----------|
| Professional | $3-5K/month | Mid-market, 50-200 developers |
| Enterprise | $8-15K/month | Large orgs, 200-2000 developers |
| Air-Gapped | $15-25K/month | Government, defense, critical infrastructure |

**ROI Calculator**: $4,200 cost/vuln (industry avg) → $890 with ALdeci = 79% reduction. With 340 actionable cases/year = **$110K annual savings**.

---

## POC Exit Criteria

| Outcome | Next Step |
|---------|-----------|
| **All criteria met** | Move to procurement — annual license |
| **Partial success** | Extend POC 1 week with focused re-test |
| **Not meeting criteria** | Honest debrief, identify blockers, schedule follow-up |

---

*Template version 1.0 — Updated 2026-03-01 by Sales Engineer Agent*
