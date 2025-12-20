# FixOps End-to-End Developer Workflow

## Overview

This document maps the complete developer workflow from design to release to monitoring, showing exactly where FixOps integrates, which CLI/API commands are used at each stage, and when evidence is created.

FixOps operates as an **evidence-producing decision pipeline** that runs at key points in your SDLC. The primary integration point is the **release gate**, but evidence can be collected throughout the development lifecycle.

---

## SDLC Stage Integration Map

| Stage | Trigger | Inputs | CLI Command | API Endpoint | Evidence Created |
|-------|---------|--------|-------------|--------------|------------------|
| **Design** | Architect review | design.csv, context.json | `stage-run --stage design` | `POST /inputs/design` | Design manifest, risk score |
| **Build** | CI build complete | sbom.json | `stage-run --stage build` | `POST /inputs/sbom` | SBOM summary, component inventory |
| **Test** | Scanners complete | scan.sarif, cve.json, vex.json | `stage-run --stage test` | `POST /inputs/sarif`, `/inputs/cve` | Findings summary, severity counts |
| **Deploy** | Pre-deployment | tfplan.json, k8s manifests | `stage-run --stage deploy` | `POST /inputs/cnapp` | Posture analysis, control evidence |
| **Release Gate** | Before production | All artifacts | `make-decision` or `run` | `GET /pipeline/run` | **Full evidence bundle** |
| **Monitor** | Scheduled/continuous | New scans, feeds | `run --offline` | `GET /pipeline/run` | Updated evidence, audit logs |

---

## Stage 1: Design Phase

**When:** Architecture review, threat modeling, before development begins

**Who triggers:** Security architect, tech lead

**Inputs produced:**
- `design.csv` - Architecture components (internet-facing, auth required, data classification)
- `context.json` - Business context (criticality, environment, data sensitivity)

**FixOps integration:**

```bash
# CLI: Run design stage
python -m core.cli stage-run --stage design \
  --input design.csv \
  --app-name "payments-api" \
  --sign

# API equivalent
curl -X POST -F "file=@design.csv" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  http://localhost:8000/inputs/design
```

**Evidence created:**
- `design.manifest.json` - Normalized design with component IDs
- Design risk score (0.0-1.0)
- Signed manifest (if `--sign` enabled)

**Output location:** `artefacts/{app_id}/{run_id}/outputs/design.manifest.json`

---

## Stage 2: Build Phase

**When:** CI/CD build completes, after dependency resolution

**Who triggers:** CI pipeline (automated)

**Inputs produced:**
- `sbom.json` - Software Bill of Materials (CycloneDX or SPDX format)
- `provenance.slsa.json` - Build provenance (optional)

**FixOps integration:**

```bash
# CLI: Run build stage
python -m core.cli stage-run --stage build \
  --input sbom.json \
  --app-id APP-1234 \
  --sign

# API equivalent
curl -X POST -F "file=@sbom.json" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  http://localhost:8000/inputs/sbom
```

**Evidence created:**
- `build.report.json` - Component inventory, risk flags
- Build risk score
- Links to SBOM and provenance artifacts

**Risk flags detected:**
- Known vulnerable packages (e.g., log4j)
- Historical RCE families
- Component count metrics

---

## Stage 3: Test Phase

**When:** Security scanners complete (SAST, DAST, SCA)

**Who triggers:** CI pipeline (automated)

**Inputs produced:**
- `scan.sarif` - SAST results (Semgrep, CodeQL, etc.)
- `cve.json` - Vulnerability scan results (Grype, Trivy)
- `vex.json` - Vulnerability Exploitability eXchange (known false positives)

**FixOps integration:**

```bash
# CLI: Run test stage
python -m core.cli stage-run --stage test \
  --input scan.sarif \
  --app-id APP-1234

# Or upload multiple artifacts via API
curl -X POST -F "file=@scan.sarif" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  http://localhost:8000/inputs/sarif

curl -X POST -F "file=@cve.json" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  http://localhost:8000/inputs/cve

curl -X POST -F "file=@vex.json" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  http://localhost:8000/inputs/vex
```

**Evidence created:**
- `test.report.json` - Severity summary, drift analysis, coverage metrics
- Test risk score
- Findings normalized and deduplicated

---

## Stage 4: Deploy Phase

**When:** Infrastructure changes ready for deployment

**Who triggers:** CI/CD pipeline or DevOps engineer

**Inputs produced:**
- `tfplan.json` - Terraform plan output
- Kubernetes manifests
- Cloud configuration (CNAPP findings)

**FixOps integration:**

```bash
# CLI: Run deploy stage
python -m core.cli stage-run --stage deploy \
  --input tfplan.json \
  --app-id APP-1234

# API equivalent
curl -X POST -F "file=@cnapp.json" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  http://localhost:8000/inputs/cnapp
```

**Evidence created:**
- `deploy.manifest.json` - Posture analysis, control evidence
- Deploy risk score
- Control compliance status (pass/fail/warn)

**Posture checks:**
- Public S3 buckets
- Open security groups
- Unpinned container images
- Privileged containers
- Encryption gaps
- TLS policy compliance

---

## Stage 5: Release Gate (Primary Integration Point)

**When:** Before production deployment - this is the critical decision point

**Who triggers:** CI/CD pipeline (blocking gate)

**This is where the full evidence bundle is created.**

**FixOps integration:**

```bash
# CLI: Full pipeline with exit code for CI/CD gating
python -m core.cli make-decision \
  --design design.csv \
  --sbom sbom.json \
  --sarif scan.sarif \
  --cve cve.json \
  --vex vex.json \
  --context context.json \
  --evidence-dir ./evidence \
  --output decision.json

# Exit codes:
# 0 = GO (allow deployment)
# 1 = NO-GO (block deployment)
# 2 = CONDITIONAL (defer to human review)

# Alternative: Full run command
python -m core.cli run \
  --overlay config/fixops.overlay.yml \
  --design design.csv \
  --sbom sbom.json \
  --sarif scan.sarif \
  --cve cve.json \
  --evidence-dir ./evidence \
  --output pipeline-result.json
```

**API equivalent:**

```bash
# Upload all artifacts
curl -X POST -F "file=@design.csv" -H "X-API-Key: $TOKEN" http://localhost:8000/inputs/design
curl -X POST -F "file=@sbom.json" -H "X-API-Key: $TOKEN" http://localhost:8000/inputs/sbom
curl -X POST -F "file=@scan.sarif" -H "X-API-Key: $TOKEN" http://localhost:8000/inputs/sarif
curl -X POST -F "file=@cve.json" -H "X-API-Key: $TOKEN" http://localhost:8000/inputs/cve
curl -X POST -F "file=@context.json" -H "X-API-Key: $TOKEN" http://localhost:8000/inputs/context

# Execute pipeline and get decision
curl -H "X-API-Key: $TOKEN" http://localhost:8000/pipeline/run | jq
```

**Evidence bundle created (core/evidence.py):**

The `EvidenceHub.persist()` method creates a comprehensive evidence bundle containing:

| Section | Description |
|---------|-------------|
| `design_summary` | Architecture components and risk |
| `sbom_summary` | Component inventory |
| `sarif_summary` | SAST findings |
| `cve_summary` | Vulnerability findings |
| `severity_overview` | Risk distribution |
| `context_summary` | Business context |
| `guardrail_evaluation` | Policy compliance |
| `compliance_status` | Framework mapping |
| `policy_automation` | Policy decisions |
| `analytics` | Metrics and trends |
| `ai_agent_analysis` | LLM consensus results |
| `probabilistic_forecast` | Risk predictions |
| `exploitability_insights` | Threat intelligence |
| `ssdlc_assessment` | SDLC maturity |

**Bundle characteristics:**
- SHA-256 hash for integrity
- Optional compression (gzip)
- Optional encryption (Fernet, requires `cryptography` package)
- Retention period (default: 2555 days / ~7 years)
- Audit log entry appended

**Output files:**
```
evidence/{mode}/{run_id}/
  ├── fixops-{mode}-run-bundle.json      # Main evidence bundle
  ├── fixops-{mode}-run-bundle.json.gz   # If compressed
  ├── fixops-{mode}-run-bundle.json.enc  # If encrypted
  └── manifest.json                       # Bundle metadata
```

---

## Stage 6: Monitor/Operate Phase

**When:** Continuous monitoring, nightly scans, incident response

**Who triggers:** Scheduled jobs, security operations

**FixOps integration:**

```bash
# Scheduled pipeline run (e.g., nightly)
python -m core.cli run \
  --overlay config/fixops.overlay.yml \
  --offline \
  --sbom current-sbom.json \
  --cve latest-scan.json \
  --evidence-dir ./evidence

# Check analytics
python -m core.cli analytics dashboard --period 30d

# Review audit trail
python -m core.cli audit logs --limit 100

# Export compliance report
python -m core.cli compliance report SOC2 --output soc2-report.json
```

**GitHub Actions integration (already configured in repo):**

The `fixops_pipeline.yml` workflow runs:
- On every PR
- On push to main/master
- Nightly at 2 AM UTC (scheduled)

**Evidence created:**
- New evidence bundles for each run
- Audit log entries
- Analytics data points
- Compliance status updates

---

## CI/CD Integration Example

### GitHub Actions

```yaml
name: FixOps Security Gate

on:
  pull_request:
  push:
    branches: [main]

jobs:
  security-gate:
    runs-on: ubuntu-latest
    container:
      image: devopsaico/fixops:latest
    
    steps:
      - uses: actions/checkout@v4
      
      # Generate SBOM
      - name: Generate SBOM
        run: syft . -o cyclonedx-json > sbom.json
      
      # Run security scanners
      - name: Run SAST
        run: semgrep --config auto --json > scan.sarif
      
      # FixOps decision gate
      - name: FixOps Release Gate
        run: |
          python -m core.cli make-decision \
            --sbom sbom.json \
            --sarif scan.sarif \
            --evidence-dir ./evidence \
            --output decision.json
        env:
          FIXOPS_API_TOKEN: ${{ secrets.FIXOPS_API_TOKEN }}
      
      # Upload evidence as artifact
      - name: Upload Evidence
        uses: actions/upload-artifact@v4
        with:
          name: fixops-evidence
          path: evidence/
          retention-days: 90
```

---

## Evidence Retrieval

After evidence is created, retrieve it for audits:

```bash
# Get evidence bundle
python -m core.cli get-evidence --run decision.json

# Copy evidence to handoff directory
python -m core.cli copy-evidence --run decision.json --target ./audit-handoff

# API: Download evidence bundle
curl -H "X-API-Key: $TOKEN" \
  http://localhost:8000/api/v1/evidence/bundles/{bundle_id}/download \
  -o evidence-bundle.zip
```

---

## Compliance Framework Mapping

Evidence bundles automatically map to compliance frameworks:

```bash
# Check compliance status
python -m core.cli compliance status SOC2

# View compliance gaps
python -m core.cli compliance gaps ISO27001

# Generate compliance report
python -m core.cli compliance report PCI_DSS --output pci-report.json
```

**Supported frameworks:**
- SOC 2 Type 2
- ISO 27001:2022 (including A.8.25 Secure SDLC)
- PCI DSS 4.0
- NIST SSDF (SP 800-218)
- HIPAA
- GDPR
- FedRAMP

---

## Summary: Where Evidence is Created

| Trigger | CLI Command | Evidence Type |
|---------|-------------|---------------|
| Design review | `stage-run --stage design` | Design manifest |
| Build complete | `stage-run --stage build` | Build report |
| Scanners complete | `stage-run --stage test` | Test report |
| Pre-deployment | `stage-run --stage deploy` | Deploy manifest |
| **Release gate** | `make-decision` or `run` | **Full evidence bundle** |
| Monitoring | `run` (scheduled) | Updated evidence |
| Audit request | `get-evidence`, `copy-evidence` | Evidence export |

The **release gate** is the primary evidence creation point. Individual stage runs create intermediate artifacts that feed into the final evidence bundle.

---

## Docker Image Note

The CI/CD workflows use `devopsaico/fixops:latest` as the base image. This image is built and pushed externally (not via a workflow in this repository). To build your own image:

```bash
docker build -t your-registry/fixops:latest -f Dockerfile .
docker push your-registry/fixops:latest
```

---

## Quick Reference

| Action | CLI | API |
|--------|-----|-----|
| Full pipeline | `run` | Upload inputs + `GET /pipeline/run` |
| Release gate | `make-decision` | Upload inputs + `GET /pipeline/run` |
| Single stage | `stage-run --stage {stage}` | `POST /inputs/{stage}` |
| Get evidence | `get-evidence` | `GET /api/v1/evidence/bundles/{id}` |
| Export evidence | `copy-evidence` | `GET /api/v1/evidence/bundles/{id}/download` |
| Compliance check | `compliance status {framework}` | `GET /api/v1/compliance/frameworks/{id}` |
| Analytics | `analytics dashboard` | `GET /api/v1/analytics/dashboard` |
| Audit logs | `audit logs` | `GET /api/v1/audit/logs` |
