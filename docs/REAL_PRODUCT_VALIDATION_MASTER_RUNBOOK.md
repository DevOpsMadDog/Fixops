# ALdeci Real Product Validation - Master Runbook

## Purpose
Prove ALdeci as a real CTEM+ product in a single repeatable workflow across:
- Vulnerable training apps (ground-truth checks)
- Real open-source production codebases (scale and realism)
- Permissioned live internet targets (real-world credibility)

This runbook is designed for enterprise demos, investor diligence, and pre-sales technical validation.

## Vision Alignment
- V3 Decision Intelligence: prioritize what to do, not only what exists
- V5 MPTE Verification: prove exploitability
- V7 MCP-Native Platform: integrate and orchestrate tools
- V10 CTEM Full Loop: discover -> prioritize -> validate -> remediate -> measure with evidence

## Non-Negotiable Legal and Safety Rules
1. Only test assets with explicit authorization.
2. Respect platform scope and safe-harbor terms for bug bounty targets.
3. Start live targets with passive and low-impact checks.
4. Enforce strict allowlists for hosts, paths, and methods.
5. Stop immediately on scope ambiguity.

## Master Success Gates
1. Dedupe ratio >= 35% on mixed datasets.
2. Actionability score >= 60%.
3. MPTE confirmation rate >= 20% of High/Critical findings in controlled targets.
4. Noise ratio < 30% on sampled findings.
5. Scope compliance = 100% for live runs.
6. Signed evidence completeness >= 90% of runs.

## Scope of Targets (Recommended)

### A. Controlled vulnerable apps (self-hosted preferred)
- OWASP Juice Shop
- OWASP crAPI
- OWASP WebGoat
- DVWA
- bWAPP or OWASP Security Shepherd

### B. Real open-source production repos
- Grafana
- Argo CD
- Harbor
- Istio
- Kubernetes (subset first)

### C. Permissioned live targets
- HackerOne, Bugcrowd, Intigriti, YesWeHack programs with explicit scope

## Operating Model
Run the full flow per target batch (not per day):
1. Intake and scope lock
2. Baseline asset discovery
3. Multi-engine scanning
4. Normalization, dedupe, prioritization
5. Exploitability validation (MPTE)
6. Remediation and AutoFix workflow
7. Compliance and signed evidence
8. KPI scoring and executive output

## Prerequisites

### 1) Runtime
- Python environment active
- ALdeci backend reachable
- API token configured

### 2) Tooling
- curl
- jq
- git
- docker (for local target labs)

### 3) Environment variables
Export once per session:

```bash
export ALDECI_BASE_URL="http://localhost:8000"
export ALDECI_API_KEY="<your_api_key>"
export RUN_ID="rv-$(date +%Y%m%d-%H%M%S)"
export OUT_DIR="artifacts/${RUN_ID}"
mkdir -p "${OUT_DIR}"/{raw,normalized,evidence,reports,logs}
```

## Step 0 - Platform Health and Endpoint Discovery
Use OpenAPI to discover available endpoints in this deployment and avoid hardcoded assumptions.

```bash
curl -s "${ALDECI_BASE_URL}/openapi.json" > "${OUT_DIR}/raw/openapi.json"

jq -r '.paths | keys[]' "${OUT_DIR}/raw/openapi.json" \
  | grep -Ei 'health|findings|analytics|scan|scanner|mpte|pentest|autofix|evidence|compliance|risk' \
  > "${OUT_DIR}/raw/candidate-endpoints.txt"

wc -l "${OUT_DIR}/raw/candidate-endpoints.txt"
```

Health check (adjust if your deployment uses a different endpoint):

```bash
curl -s -H "X-API-Key: ${ALDECI_API_KEY}" \
  "${ALDECI_BASE_URL}/api/v1/health" | tee "${OUT_DIR}/raw/health.json"
```

## Step 1 - Build a Target Manifest (Single Source of Truth)
Create a manifest for all targets in this run.

```yaml
# targets-manifest.yaml
run_id: rv-20260329-000001
owner: security-team
mode: mixed

allowlist:
  hosts:
    - localhost
    - 127.0.0.1
    - demo.owasp-juice.shop
  methods:
    - GET
    - HEAD
  notes: "For live targets, expand only within written scope"

targets:
  - id: lab-juice-shop
    type: vulnerable-lab
    source: local-docker
    locator: http://localhost:3000
    auth: none
    scope: full-local

  - id: oss-grafana
    type: oss-repo
    source: github
    locator: https://github.com/grafana/grafana
    checkout_ref: main

  - id: live-program-1
    type: permissioned-live
    source: bug-bounty
    locator: https://example-program-scope.tld
    scope_reference: https://program.example/scope
    safe_harbor_reference: https://program.example/policy
```

## Step 2 - Controlled Asset Acquisition

### 2A) Vulnerable labs (local)
Example local deployment command patterns:

```bash
# Example only; use official project instructions per target.
# docker run -d --name juice-shop -p 3000:3000 bkimminich/juice-shop
# docker run -d --name webgoat -p 8080:8080 webgoat/webgoat
```

### 2B) OSS repos

```bash
mkdir -p targets && cd targets
git clone --depth 1 https://github.com/grafana/grafana.git
git clone --depth 1 https://github.com/argoproj/argo-cd.git
git clone --depth 1 https://github.com/goharbor/harbor.git
cd ..
```

## Step 3 - Scan Orchestration (Per Target)
Use ALdeci APIs for scanner ingestion and orchestration. Since endpoint shapes vary by deployment version, discover first from OpenAPI and then call.

### 3A) Find scan-related endpoints quickly

```bash
grep -Ei '/api/v1/.+(scan|scanner|ingest|findings|analytics)' \
  "${OUT_DIR}/raw/candidate-endpoints.txt" | sort -u \
  > "${OUT_DIR}/raw/scan-endpoints.txt"

cat "${OUT_DIR}/raw/scan-endpoints.txt"
```

### 3B) Generic POST runner template

```bash
# TEMPLATE: replace <ENDPOINT> and payload schema per openapi
curl -s -X POST "${ALDECI_BASE_URL}<ENDPOINT>" \
  -H "X-API-Key: ${ALDECI_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "run_id": "'"${RUN_ID}"'",
    "target_id": "lab-juice-shop",
    "target": "http://localhost:3000"
  }' | tee "${OUT_DIR}/raw/scan-lab-juice-shop.json"
```

## Step 4 - Normalize, Dedupe, Prioritize
Export findings and analytics for KPI calculation.

```bash
# TEMPLATE endpoint example: /api/v1/analytics/findings
curl -s -H "X-API-Key: ${ALDECI_API_KEY}" \
  "${ALDECI_BASE_URL}/api/v1/analytics/findings?run_id=${RUN_ID}" \
  | tee "${OUT_DIR}/normalized/findings.json"
```

Compute baseline KPIs from exported JSON (adapt keys as needed):

```bash
jq -r '
  def count(sev): [.findings[] | select(.severity==sev)] | length;
  {
    raw_total: (.raw_total // (.findings | length)),
    unique_total: (.unique_total // (.findings | length)),
    critical: count("CRITICAL"),
    high: count("HIGH"),
    medium: count("MEDIUM"),
    low: count("LOW")
  }
' "${OUT_DIR}/normalized/findings.json" \
  | tee "${OUT_DIR}/reports/finding-counts.json"
```

## Step 5 - MPTE Exploitability Validation
Identify MPTE endpoints from OpenAPI and run validation on prioritized findings.

```bash
grep -Ei '/api/v1/.+(mpte|micro-pentest|pentest)' \
  "${OUT_DIR}/raw/candidate-endpoints.txt" | sort -u \
  > "${OUT_DIR}/raw/mpte-endpoints.txt"

cat "${OUT_DIR}/raw/mpte-endpoints.txt"
```

Generic MPTE call template:

```bash
curl -s -X POST "${ALDECI_BASE_URL}<MPTE_ENDPOINT>" \
  -H "X-API-Key: ${ALDECI_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "run_id": "'"${RUN_ID}"'",
    "target_id": "lab-juice-shop",
    "finding_ids": ["<high_or_critical_finding_id>"]
  }' | tee "${OUT_DIR}/raw/mpte-lab-juice-shop.json"
```

## Step 6 - Remediation and AutoFix Validation
Discover and call AutoFix endpoints for prioritized findings.

```bash
grep -Ei '/api/v1/.+(autofix|remediation|fix)' \
  "${OUT_DIR}/raw/candidate-endpoints.txt" | sort -u \
  > "${OUT_DIR}/raw/autofix-endpoints.txt"

cat "${OUT_DIR}/raw/autofix-endpoints.txt"
```

Generic AutoFix template:

```bash
curl -s -X POST "${ALDECI_BASE_URL}<AUTOFIX_ENDPOINT>" \
  -H "X-API-Key: ${ALDECI_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "run_id": "'"${RUN_ID}"'",
    "finding_id": "<finding_id>",
    "mode": "recommend"
  }' | tee "${OUT_DIR}/raw/autofix.json"
```

## Step 7 - Compliance and Signed Evidence
Discover evidence/compliance endpoints and generate auditable artifacts.

```bash
grep -Ei '/api/v1/.+(evidence|compliance|audit|attest|signature|risk)' \
  "${OUT_DIR}/raw/candidate-endpoints.txt" | sort -u \
  > "${OUT_DIR}/raw/evidence-endpoints.txt"

cat "${OUT_DIR}/raw/evidence-endpoints.txt"
```

Generic evidence template:

```bash
curl -s -X POST "${ALDECI_BASE_URL}<EVIDENCE_ENDPOINT>" \
  -H "X-API-Key: ${ALDECI_API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{
    "run_id": "'"${RUN_ID}"'",
    "include": ["findings", "mpte", "autofix", "policy", "timeline"]
  }' | tee "${OUT_DIR}/evidence/evidence-bundle.json"
```

## Step 8 - KPI Scoring Sheet (Single Report)
Create one summary file for every run.

```json
{
  "run_id": "rv-YYYYMMDD-HHMMSS",
  "targets_total": 0,
  "raw_findings": 0,
  "unique_findings": 0,
  "dedupe_ratio": 0.0,
  "actionability_score": 0.0,
  "mpte_confirmation_rate": 0.0,
  "noise_ratio": 0.0,
  "time_to_first_signal_min": 0.0,
  "evidence_completeness": 0.0,
  "scope_compliance": 1.0,
  "notes": ""
}
```

Recommended formulas:
- dedupe_ratio = (raw_findings - unique_findings) / raw_findings
- actionability_score = actionable_findings / unique_findings
- mpte_confirmation_rate = mpte_confirmed / high_plus_critical
- noise_ratio = false_positives_sampled / sample_size
- evidence_completeness = workflows_with_signed_evidence / workflows_total

## Step 9 - Executive Output Pack
For each run, produce:
1. One-page executive summary
2. Top 10 prioritized findings with owner and ETA
3. MPTE validated findings list
4. AutoFix recommendation acceptance table
5. Compliance/evidence artifact index
6. Scope compliance log

## Continuous Run Cadence
Use the same master flow repeatedly:
- Batch 1: controlled vulnerable labs
- Batch 2: OSS production repos
- Batch 3: permissioned live targets

Do not change the KPI schema between batches. This preserves comparability and trust.

## Hardening Checks Against Fake Signal or Hardcoding
1. Verify findings are tied to real source location, request, or artifact path.
2. Reject findings with no reproducibility detail.
3. Flag repeated static CVE IDs that appear without contextual evidence.
4. Require at least one of: exploit path, reachable asset evidence, or policy mapping.
5. Sample manually and verify at least 20 findings per batch.

## Troubleshooting
1. Empty findings:
- Confirm endpoint path from OpenAPI
- Confirm auth header and token
- Confirm target availability and network path

2. High noise ratio:
- Increase confidence threshold for triage
- Use component ownership and reachability filters
- Re-run dedupe after normalization fixes

3. MPTE low confirmation rate:
- Re-check prioritization logic
- Validate preconditions for exploit simulation
- Limit to high-confidence reachable findings first

4. Evidence generation gaps:
- Ensure run_id is consistently passed
- Confirm evidence endpoint permissions
- Verify signing dependency availability

## Final Sign-Off Checklist
1. All targets are in manifest with scope references.
2. Scope compliance log shows zero violations.
3. KPI summary meets minimum success gates.
4. Evidence bundle exists and is auditable.
5. Executive pack is complete and reproducible.

---
Owner: Security Engineering + Product Security
Usage: Enterprise demo, pilot onboarding, investor technical diligence
