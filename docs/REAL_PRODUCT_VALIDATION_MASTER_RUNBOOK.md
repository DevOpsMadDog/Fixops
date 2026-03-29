# ALdeci CTEM+ — Technical Validation Runbook

> **Classification**: Company Confidential — Customer-Ready
> **Version**: 3.0 | **Effective**: Q1 2026
> **Audience**: Security Engineers, Platform Architects, Technical Evaluation Teams

---

## Purpose

This runbook provides the command-level technical validation procedures for ALdeci CTEM+ deployments. It enables security engineering teams to:

- Verify platform functionality across the complete CTEM lifecycle
- Validate scanning, triage, exploitation verification, remediation, and evidence generation
- Measure platform performance against quantitative success criteria
- Produce auditable validation artifacts for technical evaluation

This is the technical companion to the [Enterprise Pilot Deployment Guide](ORG_WIDE_PERSONA_TRIAL_RUNBOOK.md), which defines organizational governance and persona workflows.

---

## Vision Alignment

| Pillar | Validation Coverage |
|--------|-------------------|
| **V3 — Decision Intelligence** | Brain Pipeline end-to-end, risk scoring, policy enforcement |
| **V5 — MPTE Verification** | Exploit verification on prioritized findings |
| **V7 — MCP-Native Platform** | API surface validation, MCP gateway testing |
| **V10 — CTEM Full Loop** | Discover, Prioritize, Validate, Remediate, and Comply with evidence at each step |

---

## Legal and Safety Requirements

1. Only test applications with explicit written authorization from the application owner.
2. Respect all scope boundaries defined in the target manifest.
3. Begin with passive and low-impact checks; escalate only within authorized scope.
4. Enforce strict allowlists for hosts, paths, and HTTP methods.
5. Halt all testing immediately upon scope ambiguity or unexpected behavior.
6. Maintain a signed scope compliance log for every validation run.

---

## Success Gates

| # | Metric | Threshold | Category |
|---|--------|-----------|----------|
| 1 | Deduplication ratio | >= 35% on mixed-source datasets | Quality |
| 2 | Actionability score | >= 60% of unique findings are actionable | Quality |
| 3 | MPTE confirmation rate | >= 20% of High/Critical findings verified | Verification |
| 4 | Noise ratio | < 30% on sampled findings | Quality |
| 5 | Scope compliance | 100% — zero out-of-scope actions | Safety |
| 6 | Evidence completeness | >= 90% of workflows produce signed evidence | Compliance |

---

## Target Portfolio

Validation is performed against the customer\'s actual application portfolio, organized into three categories:

### Category A — Customer Applications

Production and pre-production applications from the customer\'s portfolio, registered in the ALdeci Application Registry with APP_ID, ownership, and compliance scope.

| Tier | Examples | Validation Focus |
|------|---------|-----------------|
| Critical | Payment services, identity platforms, API gateways | Full CTEM cycle with MPTE verification |
| Important | Internal dashboards, CI/CD systems, developer tools | Scanning, triage, and remediation workflow |
| Standard | Documentation sites, marketing assets | Scanner coverage and deduplication |

### Category B — Open-Source Repositories

Real-world production codebases for scale and realism testing:

- Large-scale infrastructure projects (100K+ LOC)
- Cloud-native applications with known CVE history
- Multi-language repositories for cross-scanner validation

### Category C — Authorized External Targets

Permissioned targets with explicit scope documentation:

- Bug bounty program targets with written scope and safe harbor references
- Customer-authorized penetration testing targets
- Compliance validation environments

---

## Prerequisites

### Runtime Requirements

| Requirement | Specification |
|-------------|---------------|
| ALdeci backend | Deployed and reachable (any deployment model) |
| API authentication | API key or JWT configured and tested |
| CLI tools | curl, jq, git (for repo-based validation) |
| Container runtime | Docker or equivalent (for container scanning validation) |
| Network access | To target applications within authorized scope |

### Environment Configuration

Configure environment variables for the validation session:

```bash
export ALDECI_BASE_URL="${ALDECI_BASE_URL:-https://aldeci.customer.internal}"
export ALDECI_API_KEY="${ALDECI_API_KEY}"
export RUN_ID="rv-$(date +%Y%m%d-%H%M%S)"
export OUT_DIR="artifacts/${RUN_ID}"
mkdir -p "${OUT_DIR}"/{raw,normalized,evidence,reports,logs}
```

> **Note**: Replace `ALDECI_BASE_URL` with the actual deployment URL for your environment. Never commit API keys to version control.

---

## Step 0 — Platform Health and Endpoint Discovery

Verify platform availability and discover the API surface for this deployment version.

### 0.1 — Retrieve API Schema

```bash
curl -s -H "X-API-Key: ${ALDECI_API_KEY}" \
  "${ALDECI_BASE_URL}/openapi.json" > "${OUT_DIR}/raw/openapi.json"

jq -r \'.paths | keys[]\' "${OUT_DIR}/raw/openapi.json" \
  | grep -Ei \'health|findings|analytics|scan|scanner|mpte|pentest|autofix|evidence|compliance|risk\' \
  > "${OUT_DIR}/raw/candidate-endpoints.txt"

echo "Discovered $(wc -l < \"${OUT_DIR}/raw/candidate-endpoints.txt\") relevant endpoints"
```

### 0.2 — Health Check

```bash
curl -s -H "X-API-Key: ${ALDECI_API_KEY}" \
  "${ALDECI_BASE_URL}/api/v1/health" | tee "${OUT_DIR}/raw/health.json" | jq .
```

Expected response: All subsystems report healthy status.

---

## Step 1 — Build Target Manifest

Create a structured manifest for all validation targets. This manifest is the single source of truth for scope compliance.

```yaml
# targets-manifest.yaml
run_id: "${RUN_ID}"
owner: security-engineering
mode: mixed
classification: confidential

allowlist:
  hosts: []       # Populate with authorized target hosts
  methods:
    - GET
    - HEAD
    - POST
  notes: "Expand scope only with written authorization"

targets:
  - id: app-001
    type: customer-application
    tier: critical
    app_id: "${APP_ID}"
    locator: "${TARGET_URL}"
    owner: "${BUSINESS_OWNER}"
    technical_owner: "${TECH_OWNER}"
    compliance_scope:
      - PCI-DSS
      - SOC2
    auth: api-key
    scope: authorized-full

  - id: oss-001
    type: open-source-repo
    source: github
    locator: "https://github.com/${ORG}/${REPO}"
    checkout_ref: main
    scope: source-analysis-only

  - id: ext-001
    type: authorized-external
    source: bug-bounty
    locator: "${PROGRAM_URL}"
    scope_reference: "${SCOPE_DOC_URL}"
    safe_harbor_reference: "${SAFE_HARBOR_URL}"
    scope: per-program-rules
```

---

## Step 2 — Asset Acquisition

### 2A — Customer Applications

Verify network connectivity and authentication to each target application:

```bash
# Verify connectivity to each target in the manifest
for target in $(yq -r \'.targets[] | select(.type == "customer-application") | .locator\' targets-manifest.yaml); do
  echo "Testing connectivity: ${target}"
  curl -s -o /dev/null -w "%{http_code}" "${target}"
  echo ""
done
```

### 2B — Open-Source Repositories

```bash
mkdir -p targets
for repo in $(yq -r \'.targets[] | select(.type == "open-source-repo") | .locator\' targets-manifest.yaml); do
  repo_name=$(basename "${repo}" .git)
  echo "Cloning ${repo_name}..."
  git clone --depth 1 "${repo}" "targets/${repo_name}"
done
```

---

## Step 3 — Scan Orchestration

### 3.1 — Discover Available Scan Endpoints

```bash
grep -Ei \'/api/v1/.+(scan|scanner|ingest|findings|analytics|sast|dast|secrets|container|cspm)\' \
  "${OUT_DIR}/raw/candidate-endpoints.txt" | sort -u \
  > "${OUT_DIR}/raw/scan-endpoints.txt"

echo "Available scan endpoints:"
cat "${OUT_DIR}/raw/scan-endpoints.txt"
```

### 3.2 — Execute Scans

Execute scans per target using the appropriate engine. Adapt the endpoint and payload to your deployment version (discovered in Step 0):

```bash
# Template — adapt endpoint path and payload per OpenAPI schema
TARGET_ID="app-001"

curl -s -X POST "${ALDECI_BASE_URL}/api/v1/sast/scan" \
  -H "X-API-Key: ${ALDECI_API_KEY}" \
  -H "Content-Type: application/json" \
  -d \'{
    "run_id": "\'"\"${RUN_ID}\""\'",
    "target_id": "\'"\"${TARGET_ID}\""\'",
    "target": "\'"\"${TARGET_URL}\""\'"
  }\' | tee "${OUT_DIR}/raw/scan-${TARGET_ID}-sast.json" | jq \'.summary // .\'
```

Repeat for each scanner engine (DAST, secrets, container, CSPM, API fuzzer) as applicable to the target type.

---

## Step 4 — Normalize, Deduplicate, Prioritize

### 4.1 — Export Findings

```bash
curl -s -H "X-API-Key: ${ALDECI_API_KEY}" \
  "${ALDECI_BASE_URL}/api/v1/analytics/findings?run_id=${RUN_ID}" \
  | tee "${OUT_DIR}/normalized/findings.json" | jq \'.summary // { total: (.findings | length) }\'
```

### 4.2 — Compute Baseline KPIs

```bash
jq -r \'
  def count(sev): [.findings[] | select(.severity==sev)] | length;
  {
    raw_total: (.raw_total // (.findings | length)),
    unique_total: (.unique_total // (.findings | length)),
    critical: count("CRITICAL"),
    high: count("HIGH"),
    medium: count("MEDIUM"),
    low: count("LOW")
  }
\' "${OUT_DIR}/normalized/findings.json" \
  | tee "${OUT_DIR}/reports/finding-counts.json" | jq .
```

---

## Step 5 — MPTE Exploitability Validation

### 5.1 — Discover MPTE Endpoints

```bash
grep -Ei \'/api/v1/.+(mpte|micro-pentest|pentest)\' \
  "${OUT_DIR}/raw/candidate-endpoints.txt" | sort -u \
  > "${OUT_DIR}/raw/mpte-endpoints.txt"

echo "Available MPTE endpoints:"
cat "${OUT_DIR}/raw/mpte-endpoints.txt"
```

### 5.2 — Execute MPTE Verification

Select High and Critical findings for exploit verification:

```bash
# Extract High/Critical finding IDs for MPTE
FINDING_IDS=$(jq -r \'[.findings[] | select(.severity == "CRITICAL" or .severity == "HIGH") | .id] | join(",")\' \
  "${OUT_DIR}/normalized/findings.json")

# Execute MPTE verification
curl -s -X POST "${ALDECI_BASE_URL}/api/v1/mpte/verify" \
  -H "X-API-Key: ${ALDECI_API_KEY}" \
  -H "Content-Type: application/json" \
  -d \'{
    "run_id": "\'"\"${RUN_ID}\""\'",
    "finding_ids": [\'"${FINDING_IDS}"\'"]
  }\' | tee "${OUT_DIR}/raw/mpte-results.json" | jq \'.summary // .\'
```

---

## Step 6 — Remediation and AutoFix Validation

### 6.1 — Discover AutoFix Endpoints

```bash
grep -Ei \'/api/v1/.+(autofix|remediation|fix)\' \
  "${OUT_DIR}/raw/candidate-endpoints.txt" | sort -u \
  > "${OUT_DIR}/raw/autofix-endpoints.txt"

echo "Available AutoFix endpoints:"
cat "${OUT_DIR}/raw/autofix-endpoints.txt"
```

### 6.2 — Generate AutoFix Recommendations

```bash
curl -s -X POST "${ALDECI_BASE_URL}/api/v1/autofix/generate" \
  -H "X-API-Key: ${ALDECI_API_KEY}" \
  -H "Content-Type: application/json" \
  -d \'{
    "run_id": "\'"\"${RUN_ID}\""\'",
    "finding_id": "\'"\"${FINDING_ID}\""\'",
    "mode": "recommend"
  }\' | tee "${OUT_DIR}/raw/autofix-result.json" | jq \'.fix_type, .confidence, .summary\'
```

---

## Step 7 — Compliance and Signed Evidence

### 7.1 — Discover Evidence Endpoints

```bash
grep -Ei \'/api/v1/.+(evidence|compliance|audit|attest|signature|risk)\' \
  "${OUT_DIR}/raw/candidate-endpoints.txt" | sort -u \
  > "${OUT_DIR}/raw/evidence-endpoints.txt"

echo "Available evidence endpoints:"
cat "${OUT_DIR}/raw/evidence-endpoints.txt"
```

### 7.2 — Generate Evidence Bundle

```bash
curl -s -X POST "${ALDECI_BASE_URL}/api/v1/evidence/generate" \
  -H "X-API-Key: ${ALDECI_API_KEY}" \
  -H "Content-Type: application/json" \
  -d \'{
    "run_id": "\'"\"${RUN_ID}\""\'",
    "include": ["findings", "mpte", "autofix", "policy", "timeline"]
  }\' | tee "${OUT_DIR}/evidence/evidence-bundle.json" | jq \'.bundle_id, .signature_status, .evidence_count\'
```

### 7.3 — Verify Evidence Integrity

```bash
curl -s -X POST "${ALDECI_BASE_URL}/api/v1/evidence/verify" \
  -H "X-API-Key: ${ALDECI_API_KEY}" \
  -H "Content-Type: application/json" \
  -d \'{
    "bundle_id": "\'"\"$(jq -r \'.bundle_id\' \"${OUT_DIR}/evidence/evidence-bundle.json\")\""\'"
  }\' | tee "${OUT_DIR}/evidence/verification-result.json" | jq .
```

---

## Step 8 — KPI Scoring

Produce the final KPI scorecard for the validation run:

```json
{
  "run_id": "rv-YYYYMMDD-HHMMSS",
  "timestamp": "ISO-8601",
  "targets_total": 0,
  "findings": {
    "raw_total": 0,
    "unique_total": 0,
    "critical": 0,
    "high": 0,
    "medium": 0,
    "low": 0
  },
  "kpis": {
    "dedupe_ratio": 0.0,
    "actionability_score": 0.0,
    "mpte_confirmation_rate": 0.0,
    "noise_ratio": 0.0,
    "time_to_first_signal_minutes": 0.0,
    "evidence_completeness": 0.0,
    "scope_compliance": 1.0
  },
  "gates": {
    "dedupe_ratio_pass": false,
    "actionability_pass": false,
    "mpte_rate_pass": false,
    "noise_ratio_pass": false,
    "scope_compliance_pass": true,
    "evidence_completeness_pass": false
  },
  "overall_result": "PASS | CONDITIONAL | FAIL",
  "notes": ""
}
```

### KPI Formulas

| KPI | Formula |
|-----|---------|
| Deduplication ratio | (raw_findings - unique_findings) / raw_findings |
| Actionability score | actionable_findings / unique_findings |
| MPTE confirmation rate | mpte_confirmed / (high_count + critical_count) |
| Noise ratio | false_positives_in_sample / sample_size |
| Evidence completeness | workflows_with_signed_evidence / total_workflows |

---

## Step 9 — Executive Output Pack

For each validation run, produce the following deliverables:

| # | Deliverable | Format | Audience |
|---|-------------|--------|----------|
| 1 | One-page executive summary | PDF | CISO, CTO, CFO |
| 2 | Top 10 prioritized findings with owner and ETA | Dashboard export | VP Eng, Security Architect |
| 3 | MPTE-verified findings list with evidence | JSON + PDF | AppSec, Compliance |
| 4 | AutoFix recommendation acceptance table | CSV | Tech Leads, Engineering |
| 5 | Compliance evidence artifact index | JSON manifest | GRC, Auditors |
| 6 | Scope compliance log | Signed log file | Legal, CISO |
| 7 | KPI scorecard against success gates | JSON + PDF | All stakeholders |

---

## Continuous Validation Cadence

Execute the same validation flow repeatedly across target categories:

| Cycle | Targets | Focus |
|-------|---------|-------|
| 1 | Customer Tier 1 applications | Full CTEM cycle, MPTE, evidence |
| 2 | Customer Tier 2/3 applications | Scanning, deduplication, triage |
| 3 | Open-source repositories | Scale testing, cross-language coverage |
| 4 | Authorized external targets | Real-world exploitability validation |

**Do not change the KPI schema between cycles.** Consistent measurement preserves comparability and builds trust over time.

---

## Data Integrity Checks

1. **Source binding**: Verify every finding is tied to a real source location — file path, endpoint URL, request/response, or artifact reference.
2. **Reproducibility**: Reject any finding without sufficient detail to reproduce independently.
3. **Template detection**: Flag findings with repeated static CVE IDs that appear without contextual evidence.
4. **Contextual anchoring**: Require at least one of: exploit path, reachable asset evidence, ownership mapping, or policy tie-in.
5. **Statistical sampling**: Manually verify at least 20 findings per validation cycle for accuracy.

---

## Operational Guidance

### Connectivity Issues

| Symptom | Resolution |
|---------|------------|
| Empty findings response | Verify endpoint path from OpenAPI schema; confirm auth header and token; confirm target network reachability |
| Authentication failure | Verify API key format and permissions; check token expiration for JWT |
| Timeout on scan | Increase timeout parameter; verify target application responsiveness; check firewall rules |

### Quality Tuning

| Symptom | Resolution |
|---------|------------|
| High noise ratio | Increase confidence threshold for triage; apply component ownership and reachability filters; re-run deduplication |
| Low MPTE confirmation rate | Review prioritization criteria; validate preconditions; limit MPTE to high-confidence reachable findings |
| Incomplete evidence | Verify run_id consistency across all steps; confirm evidence endpoint permissions; check signing key availability |

---

## Final Sign-Off Checklist

| # | Check | Status |
|---|-------|--------|
| 1 | All targets registered in manifest with scope references | [ ] |
| 2 | Scope compliance log shows zero violations | [ ] |
| 3 | KPI scorecard meets all success gates | [ ] |
| 4 | Evidence bundles exist and pass signature verification | [ ] |
| 5 | Executive output pack is complete and reproducible | [ ] |
| 6 | All artifacts stored in run-specific directory | [ ] |
| 7 | Sign-off from Security Engineering lead | [ ] |

---

## Related Documentation

| Document | Purpose |
|----------|---------|
| [Enterprise Pilot Deployment Guide](ORG_WIDE_PERSONA_TRIAL_RUNBOOK.md) | Organizational governance, persona workflows, and acceptance criteria |
| [CEO Vision](CEO_VISION.md) | Strategic platform direction and market positioning |
| [CTEM+ Platform Capabilities](CTEM_PLUS_IDENTITY.md) | Technical capability reference for evaluation teams |

---

*This runbook defines the technical validation procedures for ALdeci CTEM+ deployments. It is designed for use by security engineering teams during platform evaluation, pilot execution, and production readiness validation.*

*Version 3.0 — Q1 2026 — Company Confidential*
