# ALdeci POC Plan — Enterprise Customer Template

> **Duration**: 2 weeks
> **Version**: 4.0 (2026-03-03 15:48 UTC) — Full API validation (34/36 GET + 7/7 POST), 93% AutoFix confidence, 1,717 KG nodes
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
- [ ] **AutoFix confidence accuracy**: HIGH-confidence (>0.85) fixes achieve 90%+ code-review acceptance
- [ ] **Generate compliance report** for _{framework}_ with evidence bundle
- [ ] **Decision engine** recommends top 10 priority actions with reasoning

### Air-Gapped Evaluation Track (Government / Defense / Critical Infrastructure)

- [ ] **Deploy fully air-gapped** — Docker image loaded from USB, zero internet
- [ ] **Run native SAST** on customer code sample (no external scanner)
- [ ] **Run native secrets scan** on customer repository
- [ ] **Run native container scan** on customer Dockerfiles
- [ ] **Compare native scanner results** to customer's existing scanner (accuracy benchmark)
- [ ] **MPTE verification** without any cloud API dependency
- [ ] **Self-hosted AI inference** via Llama 3.1 70B ($0 token cost)
- [ ] **Evidence bundle** with RSA-SHA256 signatures (verify offline)

### AutoFix Accuracy Measurement

- [ ] **Generate fixes** for 10 verified findings
- [ ] **Measure accuracy**: % of fixes that pass code review without modification
- [ ] **Measure confidence calibration**: Do HIGH (>85%) fixes actually have higher accuracy?
- [ ] **Measure auto-apply safety**: Any HIGH-confidence fixes that caused regressions?
- [ ] **Compare to existing fix process**: Time-to-fix with ALdeci vs current workflow
- [ ] **Confidence score accuracy**: Track `confidence_score` field per fix — verify that HIGH-confidence fixes (>0.85) achieve 90%+ acceptance rate in code review; flag any HIGH fix that fails review as a calibration error

#### AutoFix Confidence Score Measurement Protocol

```bash
# 1. Generate a fix and capture the confidence score
curl -X POST http://localhost:8000/api/v1/autofix/generate \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "finding_id": "poc-finding-001",
    "vulnerability_type": "sql_injection",
    "source_code": "cursor.execute(\"SELECT * FROM users WHERE name = \" + user_input)",
    "language": "python",
    "fix_type": "code_patch"
  }' | jq '{fix_id: .fix_id, confidence_score: .confidence_score, fix_type: .fix_type, auto_apply_eligible: (.confidence_score > 0.85)}'

# 2. Review confidence level definitions before applying
curl -s http://localhost:8000/api/v1/autofix/confidence-levels -H "X-API-Key: $API_KEY" | jq .

# 3. Track overall accuracy statistics after 10 fixes
curl -s http://localhost:8000/api/v1/autofix/stats -H "X-API-Key: $API_KEY" | jq '{total_generated, auto_applied, human_reviewed, accuracy_rate}'
```

**Confidence Thresholds and Actions**:
| Score Range | Label | Auto-Action | POC Acceptance Target |
|-------------|-------|-------------|----------------------|
| >0.85 | HIGH | Auto-apply to PR | 90%+ accepted without modification |
| 0.60–0.85 | MEDIUM | Create PR for review | 70%+ accepted with minor edits |
| <0.60 | LOW | Suggestion only | Review for context gaps |

---

## Native Scanner Evaluation

ALdeci ships 8 native scanners that run entirely on-premises. During the POC, benchmark each against the customer's existing tools to quantify the "zero rip-and-replace" value proposition.

### 8 Native Scanners — Verified Endpoints

| Scanner | POC Endpoint | What It Detects | Air-Gapped? |
|---------|-------------|-----------------|-------------|
| **SAST** | `POST /api/v1/sast/scan/code` | SQL injection, XSS, command injection, path traversal | Yes |
| **DAST** | `POST /api/v1/dast/scan` | Live web app vulnerabilities via active probing | Yes |
| **Secrets** | `POST /api/v1/secrets/scan/content` | API keys, passwords, tokens, credentials in source | Yes |
| **Container** | `POST /api/v1/container/scan/dockerfile` | Dockerfile security, base image CVEs, USER directives | Yes |
| **CSPM/IaC** | `POST /api/v1/cspm/scan/terraform` or `/cloudformation` | Terraform / CloudFormation misconfigurations | Yes |
| **API Fuzzer** | `POST /api/v1/api-fuzzer/fuzz` | API endpoint auth bypasses, injection, mass assignment | Yes |
| **Malware** | `POST /api/v1/malware/scan/content` | Malicious code patterns, obfuscated payloads, backdoors | Yes |
| **LLM Monitor** | `POST /api/v1/llm-monitor/analyze` | Prompt injection, jailbreak, indirect injection attempts | Yes |

### Scanner Evaluation Checklist

- [ ] Run **SAST** on a representative code sample from customer's application
- [ ] Run **Secrets** scan on a snapshot of customer's repository (sanitized OK)
- [ ] Run **Container** scan on at least 3 Dockerfiles or image manifests
- [ ] Run **CSPM** on customer's Terraform or CloudFormation templates
- [ ] Run **DAST** against customer's staging application
- [ ] Run **API Fuzzer** against one of customer's internal APIs (with permission)
- [ ] Run **Malware** scan on a sample build artifact or uploaded package
- [ ] Run **LLM Monitor** on prompts from customer's AI-integrated application (if applicable)
- [ ] Compare native scanner findings to results from customer's existing tool for the same target
- [ ] Record false positive rate and unique findings per scanner

### Scanner Benchmarking Command Examples

```bash
# SAST — scan code snippet inline
curl -X POST http://localhost:8000/api/v1/sast/scan/code \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"code": "eval(user_input)", "language": "python", "filename": "handler.py"}'

# Container — scan a Dockerfile
curl -X POST http://localhost:8000/api/v1/container/scan/dockerfile \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"dockerfile_content": "FROM ubuntu:20.04\nRUN apt-get install -y curl\nUSER root", "image_name": "customer-app"}'

# Secrets — scan source content
curl -X POST http://localhost:8000/api/v1/secrets/scan/content \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"content": "GITHUB_TOKEN=ghp_abcdef123456", "filename": "config.env"}'

# CSPM — scan Terraform config
curl -X POST http://localhost:8000/api/v1/cspm/scan/terraform \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"terraform_content": "resource \"aws_s3_bucket\" \"b\" { acl = \"public-read\" }"}'

# API Fuzzer — discover and fuzz an OpenAPI spec
curl -X POST http://localhost:8000/api/v1/api-fuzzer/discover \
  -H "X-API-Key: $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"target_url": "http://staging-app:8080", "openapi_url": "http://staging-app:8080/openapi.json"}'
```

### 25 Third-Party Scanner Parsers (Zero Rip-and-Replace)

In addition to 8 native scanners, ALdeci ingests output from 25 external scanner formats:

```bash
# List all supported parser formats
curl -s http://localhost:8000/api/v1/scanner-ingest/supported \
  -H "X-API-Key: $API_KEY" | jq .
```

**Supported formats**: ZAP, Burp Suite, Nessus, OpenVAS, Bandit, Checkmarx, SonarQube, Fortify, Veracode, Nikto, Nuclei, Nmap, Snyk, Prowler, Checkov — plus SARIF (universal), CycloneDX, SPDX, Trivy, Grype, Semgrep, Dependabot, AWS SecurityHub, Wiz, Prisma Cloud.

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
| Run native SAST scan | `POST /api/v1/sast/scan/code` | Additional code findings |
| Run native SAST on files | `POST /api/v1/sast/scan/files` | File-level analysis |
| Run secrets scan | `POST /api/v1/secrets/scan/content` | Credential detections |
| Run container scan | `POST /api/v1/container/scan/dockerfile` | Dockerfile findings |

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
| Generate evidence bundle | `POST /api/v1/evidence/export` | RSA-SHA256 signed bundle |
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
| Postman collections | — | ✅ (7 collections, 475+ tests) |

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

---

## Air-Gapped Deployment Verification Checklist

For government/defense POCs, verify these capabilities work with ZERO internet:

| Capability | Verified Endpoint | Air-Gapped? |
|-----------|------------------|-------------|
| SAST Scan (inline) | `POST /api/v1/sast/scan/code` | Yes — native engine |
| SAST Scan (files) | `POST /api/v1/sast/scan/files` | Yes — native engine |
| DAST Scan | `POST /api/v1/dast/scan` | Yes — native engine |
| Secrets Scan | `POST /api/v1/secrets/scan/content` | Yes — native engine |
| Container Scan (Dockerfile) | `POST /api/v1/container/scan/dockerfile` | Yes — native engine |
| Container Scan (Image) | `POST /api/v1/container/scan/image` | Yes — native engine |
| CSPM/IaC (Terraform) | `POST /api/v1/cspm/scan/terraform` | Yes — native engine |
| CSPM/IaC (CloudFormation) | `POST /api/v1/cspm/scan/cloudformation` | Yes — native engine |
| API Fuzzer | `POST /api/v1/api-fuzzer/fuzz` | Yes — native engine |
| Malware Scan | `POST /api/v1/malware/scan/content` | Yes — native engine |
| LLM Monitor | `POST /api/v1/llm-monitor/analyze` | Yes — native engine |
| Brain Pipeline | `POST /api/v1/brain/ingest/finding` | Yes — synthetic enrichment |
| MPTE Verify | `POST /api/v1/mpte/verify` | Yes — deterministic phases |
| AutoFix | `POST /api/v1/autofix/generate` | Partial — requires self-hosted LLM (Llama 3.1 70B) |
| Evidence Export | `POST /api/v1/evidence/export` | Yes — local RSA-SHA256 |
| Evidence Verify | `POST /api/v1/evidence/export/verify` | Yes — local RSA-SHA256 |
| Compliance Map | `POST /api/v1/compliance-engine/map-findings` | Yes — local CWE database |
| Knowledge Graph | `GET /api/v1/knowledge-graph/analytics` | Yes — local SQLite |
| System Health | `GET /api/v1/system/health` | Yes — no external calls |

### Air-Gapped Test Command

```bash
# Disconnect network, then:
docker compose -f docker/docker-compose.air-gapped-test.yml up -d
# Run full CTEM loop without internet
bash scripts/demo-scripts/ctem-full-loop.sh
```

---

## Investor Demo Quick-POC (1 Day)

For investor meetings, a condensed 1-day POC that demonstrates the full CTEM loop:

```bash
# Morning: Deploy + scan
docker compose -f docker/docker-compose.yml up -d
curl -X POST http://localhost:8000/api/v1/sast/scan/code \
  -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"code": "cursor.execute(f\"SELECT * FROM users WHERE id = {uid}\")", "language": "python"}'

# Afternoon: Verify + Fix + Evidence
curl -X POST http://localhost:8000/api/v1/mpte/verify \
  -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"finding_id": "sast-001", "target_url": "http://target:8080", "vulnerability_type": "sqli", "evidence": "SQLi via f-string"}'

curl -X POST http://localhost:8000/api/v1/autofix/generate \
  -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"finding": {"id": "sast-001", "title": "SQL Injection", "severity": "HIGH", "cwe": "CWE-89", "code_snippet": "cursor.execute(f\"SELECT * FROM users WHERE id = {uid}\")"}}'

curl -X POST http://localhost:8000/api/v1/evidence/export \
  -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"framework": "SOC2", "findings": [{"id": "sast-001", "title": "SQLi", "severity": "HIGH"}]}'
```

**Key metrics to highlight**: scan <1ms, AutoFix 89% confidence, RSA-SHA256 signed evidence, 4 API calls = full CTEM loop.

---

*Template version 3.2 — 2026-03-02 08:02 UTC by Sales Engineer. Full API validation (33/33 GET + 9/11 POST). 475/475 Postman. Dashboard: 1,000 findings, Brain: 1,512 nodes, MPTE: 235 requests. 769 routes mounted. AutoFix timeout: 30s.*
