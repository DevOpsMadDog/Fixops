# SPEC-013 — Cloud Security Posture Management (CSPM)

- **Status**: BACKFILL
- **Owner family**: CSPM / Cloud
- **Routers**:
  - `suite-api/apps/api/cloud_posture_router.py` (prefix `/api/v1/cloud-posture`)
  - `suite-api/apps/api/cspm_connector_router.py` (prefix `/api/v1/connectors/cspm`)
  - `suite-api/apps/api/cloud_connectors_router.py` (prefix `/api/v1/cloud-connectors`)
  - `suite-api/apps/api/cloud_compliance_router.py` (prefix `/api/v1/cloud-compliance`)
  - `suite-api/apps/api/compliance_router.py` (prefix `/api/v1/compliance`)
  - `suite-api/apps/api/checkov_router.py` (prefix `/api/v1/checkov`)
- **Engines**:
  - `suite-core/core/cloud_posture_engine.py` — `CloudPostureEngine` (primary CSPM store)
  - `suite-core/core/cspm_engine.py` — `CSPMEngine` (IaC pattern scanner: `scan_terraform`, `scan_cloudformation`)
  - `suite-core/core/iac_scanner.py` — `IaCScanner` (Checkov + tfsec subprocess wrappers)
  - `suite-core/core/cloud_connectors.py` — `CloudConnectorEngine` (AWS/Azure/GCP live cloud API abstraction)
  - `suite-core/connectors/cspm_connector.py` — `CSPMConnector` (Prowler + Checkov + CloudSploit + Trivy + Agentless)
  - `suite-core/core/cloud_compliance_engine.py` — `CloudComplianceEngine`
  - `suite-core/core/compliance_engine.py` — `ComplianceEngine` (NIST/PCI/SOC2/HIPAA/FedRAMP/ISO27001/CMMC)
- **Stores**:
  - `.fixops_data/cloud_posture.db` — `cp_accounts`, `cp_findings` (WAL, RLock, org_id-isolated)
  - per-org compliance SQLite via `CloudComplianceEngine`
- **Depends on**: SPEC-006 (honest compliance), SPEC-007 (tenancy), `SecurityFindingsEngine` (findings projection)
- **Last updated**: 2026-06-01

---

## 1. Intent

CSPM is the cloud-posture surface of ALDECI: it ingests, normalises, and surfaces cloud misconfigurations from three distinct input paths — (a) IaC template scanning (Terraform/CloudFormation pattern rules or Checkov/tfsec subprocesses), (b) live cloud-API scanning via the AWS/Azure/GCP connector framework (Prowler, CloudSploit, Trivy, Agentless snapshot), and (c) manual finding ingestion. The unified `CloudPostureEngine` stores findings per-org and projects connector findings when no org-recorded rows exist, returning an honest `needs_credentials` hint rather than empty silence. Compliance frameworks (NIST-800-53, PCI-DSS, SOC2, HIPAA, FedRAMP, ISO27001, CMMC) are evaluated against collected evidence by the `ComplianceEngine`; per SPEC-006 every uncollected control is reported `not_assessed`, never `passing`.

---

## 2. Scope — endpoints

### 2a. Cloud Posture (`/api/v1/cloud-posture`)

| Method | Path | Purpose | Auth | Tenant-scoped |
|--------|------|---------|------|---------------|
| POST | /api/v1/cloud-posture/accounts | Register a cloud account for posture tracking | api_key_auth | yes (org_id in body) |
| GET | /api/v1/cloud-posture/accounts | List registered cloud accounts | api_key_auth | yes (org_id query param) |
| GET | /api/v1/cloud-posture/accounts/{id} | Get single account by internal UUID | api_key_auth | yes (org_id query param) |
| POST | /api/v1/cloud-posture/findings | Record a manual posture finding | api_key_auth | yes (org_id in body) |
| GET | /api/v1/cloud-posture/findings | List findings (with CSPM connector fallback) | api_key_auth | yes (org_id query param) |
| PATCH | /api/v1/cloud-posture/findings/{id}/status | Update finding status | api_key_auth | yes (org_id in body) |
| GET | /api/v1/cloud-posture/stats | Aggregate posture statistics | api_key_auth | yes (org_id query param) |

### 2b. CSPM Connector (`/api/v1/connectors/cspm`)

| Method | Path | Purpose | Auth | Tenant-scoped |
|--------|------|---------|------|---------------|
| POST | /api/v1/connectors/cspm/scan | Run Prowler+Checkov+CloudSploit+Trivy+Agentless for one tenant | api_key_auth | yes (org_id in body) |
| POST | /api/v1/connectors/cspm/scan-bulk | Same, multi-tenant batch | api_key_auth | yes (per-tenant loop) |
| GET | /api/v1/connectors/cspm/status | Tool availability + connector health | api_key_auth | no |
| GET | /api/v1/connectors/cspm/health | Health alias | api_key_auth | no |

### 2c. Cloud Connectors — live cloud API (`/api/v1/cloud-connectors`)

| Method | Path | Purpose | Auth | Tenant-scoped |
|--------|------|---------|------|---------------|
| POST | /api/v1/cloud-connectors/accounts | Register AWS/Azure/GCP credentials | api_key_auth | yes |
| DELETE | /api/v1/cloud-connectors/accounts/{provider}/{id} | Remove credentials | api_key_auth | yes |
| GET | /api/v1/cloud-connectors/accounts | List registered accounts (masked) | api_key_auth | yes |
| GET | /api/v1/cloud-connectors/accounts/health | Connector health per account | api_key_auth | yes |
| POST | /api/v1/cloud-connectors/accounts/{provider}/{id}/validate | Test credential connectivity | api_key_auth | yes |
| GET | /api/v1/cloud-connectors/resources | List resources (provider+account required) | api_key_auth | yes |
| GET | /api/v1/cloud-connectors/findings | List live findings | api_key_auth | yes |
| GET | /api/v1/cloud-connectors/posture | Security posture report | api_key_auth | yes |
| POST | /api/v1/cloud-connectors/sync | Trigger full sync for one account | api_key_auth | yes |
| POST | /api/v1/cloud-connectors/sync/organization | Sync all accounts for a provider | api_key_auth | yes |

### 2d. Cloud Compliance (`/api/v1/cloud-compliance`)

| Method | Path | Purpose | Auth | Tenant-scoped |
|--------|------|---------|------|---------------|
| POST | /api/v1/cloud-compliance/assessments | Create compliance assessment | api_key_auth | yes (org_id query) |
| GET | /api/v1/cloud-compliance/assessments | List assessments | api_key_auth | yes |
| GET | /api/v1/cloud-compliance/assessments/{id} | Get assessment | api_key_auth | yes |
| POST | /api/v1/cloud-compliance/assessments/{id}/controls | Add control result | api_key_auth | yes |
| POST | /api/v1/cloud-compliance/assessments/{id}/complete | Complete assessment + compute score/drift | api_key_auth | yes |
| GET | /api/v1/cloud-compliance/controls | List control results | api_key_auth | yes |
| POST | /api/v1/cloud-compliance/remediation-plans | Create remediation plan | api_key_auth | yes |
| PATCH | /api/v1/cloud-compliance/remediation-plans/{id}/status | Update plan status | api_key_auth | yes |
| GET | /api/v1/cloud-compliance/remediation-plans | List remediation plans | api_key_auth | yes |
| GET | /api/v1/cloud-compliance/drift | List compliance drift history | api_key_auth | yes |
| GET | /api/v1/cloud-compliance/stats | Compliance statistics | api_key_auth | yes |

### 2e. Core Compliance (`/api/v1/compliance`) — cross-ref SPEC-006

| Method | Path | Purpose | Auth | Tenant-scoped |
|--------|------|---------|------|---------------|
| GET | /api/v1/compliance/status | Status across all 7 frameworks | api_key_auth | no (single-tenant engine) |
| GET | /api/v1/compliance/status/{framework} | Per-framework status | api_key_auth | no |
| POST | /api/v1/compliance/{framework}/collect-evidence | Collect evidence | api_key_auth | no |
| GET | /api/v1/compliance/evidence | Get collected evidence | api_key_auth | no |
| GET | /api/v1/compliance/gaps | Compliance gaps | api_key_auth | no |
| GET | /api/v1/compliance/cross-map | Cross-framework control mapping | api_key_auth | no |
| POST | /api/v1/compliance/poam | Create Plan of Action & Milestones | api_key_auth | no |
| PATCH | /api/v1/compliance/poam/{id}/status | Update POAM status | api_key_auth | no |
| GET | /api/v1/compliance/poam | List POAMs | api_key_auth | no |
| POST | /api/v1/compliance/{framework}/record-score | Record compliance score | api_key_auth | no |
| GET | /api/v1/compliance/{framework}/score-trend | Score trend over time | api_key_auth | no |
| GET | /api/v1/compliance/{framework}/report | Generate compliance report | api_key_auth | no |

Valid `{framework}` values: `SOC2`, `PCI-DSS`, `HIPAA`, `FedRAMP`, `ISO27001`, `NIST-800-53`, `CMMC`

### 2f. Checkov IaC scanner (`/api/v1/checkov`)

| Method | Path | Purpose | Auth | Tenant-scoped |
|--------|------|---------|------|---------------|
| GET | /api/v1/checkov/ | Checkov capability summary | api_key_auth | no |
| GET | /api/v1/checkov/frameworks | List supported frameworks | api_key_auth | no |
| POST | /api/v1/checkov/scan | Queue a new IaC scan | api_key_auth | yes |
| GET | /api/v1/checkov/scan/{scan_id} | Get scan detail | api_key_auth | yes |

**Out of scope**: Prowler standalone router (no dedicated router; Prowler is invoked only via `CSPMConnector.scan_tenant`). Container scanning (separate surface). SBOM/SCA (SPEC-009 territory).

---

## 3. Data contracts

### IaC scanning — CSPMEngine (pattern-based, no external tool required)

```
POST body → hcl_text (string) or cf_json_text (string)
  engine.scan_terraform(hcl_text) → {
    "scan_id": "<uuid>",
    "timestamp": "<iso8601>",
    "total_findings": N,
    "findings": [
      {
        "rule_id": "CSPM-AWS-001",
        "title": "S3 Bucket Publicly Accessible",
        "severity": "critical",           # critical|high|medium|low|info
        "cis_benchmark": "CIS-AWS-2.1.5",
        "category": "storage",
        "description": "...",
        "recommendation": "...",
        "compliance_frameworks": ["CIS-AWS-2.1.5", "SOC2-CC6.6", ...],
        "resource": "<matched resource block or line ref>"
      }, ...
    ]
  }
```

### Cloud Posture — org-recorded findings (cp_findings row)

```
GET /api/v1/cloud-posture/findings?org_id=<org>
  → 200 {
      "findings": [...],
      "total": N,
      "source": "org_recorded"            # when rows exist for org
    }
  | 200 {
      "findings": [...cspm_connector projected rows...],
      "total": N,
      "source": "cspm_connector",
      "projected_from": "SecurityFindingsEngine",
      "hint": "Findings projected from CSPMConnector scanner output ..."
    }
  | 200 {
      "findings": [],
      "total": 0,
      "source": "needs_credentials",
      "hint": "Configure cloud account credentials and run POST /api/v1/connectors/cspm/scan ..."
    }
```

Note: the endpoint never returns HTTP 503. It returns HTTP 200 with `source: "needs_credentials"` when no connector output or manual findings exist. This is the honest-unconfigured path for CSPM.

### CSPM Connector scan (CSPMConnector.scan_tenant)

```
POST /api/v1/connectors/cspm/scan
  body: { "org_id": "...", "provider": "aws|azure|gcp",
          "account_id": "...", "localstack_endpoint": "...",
          "iac_dir": null, "run_prowler": true,
          "run_checkov": true, "run_cloudsploit": true,
          "run_agentless": true, "run_trivy": true }
  → 200 {
      "prowler":      { "ingested": N, "errors": [...] },
      "checkov":      { "ingested": N, "errors": [...] },
      "cloudsploit":  { "ingested": N, "errors": [...] },
      "agentless":    { "ingested": N, "errors": [...] },
      "trivy":        { "ingested": N, "errors": [...] },
      "_summary":     { "ingested_total": N }
    }
  | 400 if provider not in {aws, azure, gcp}
  | 500 on unexpected scan_tenant exception (logged)
```

Tool availability: `CSPMConnector` probes for `prowler`, `checkov`, `cloudsploit`, `trivy` CLI binaries at construction time. Missing binaries cause that tool's section to report `errors: ["tool not found"]` but do NOT block the overall scan (graceful degradation per tool).

### CSPM status

```
GET /api/v1/connectors/cspm/status
  → 200 {
      "connector": "cspm_oss",
      "tools": {
        "prowler_cli": "<path or null>",
        "checkov_cli": "<path or null>",
        "cloudsploit_cli": "<path or null>",
        "trivy_cli": "<path or null>"
      },
      "fallback_available": true,
      "supported_providers": ["aws", "azure", "gcp"]
    }
```

### Cloud connector credential registration

```
POST /api/v1/cloud-connectors/accounts
  body: { "provider": "aws|azure|gcp", "account_id": "...",
          "aws_access_key_id": ..., "aws_secret_access_key": ...,
          "aws_role_arn": ..., ... (provider-specific fields) }
  → ConnectorStatus: healthy|degraded|error|unconfigured
```

The engine returns `ConnectorStatus.UNCONFIGURED` (not HTTP 503) when credentials are absent or invalid, consistent with the connector health model.

### Compliance honest-not-assessed path (SPEC-006)

```
GET /api/v1/compliance/status/{framework}
  → 200 {
      "framework": "NIST-800-53",
      "controls": [
        { "control_id": "SC-28", "is_passing": false,
          "source": "not_configured",
          "status": "not_assessed" },
        ...
      ],
      "score": <0-100, NOT_ASSESSED controls excluded from denominator>
    }
```

Per SPEC-006: no control returns `is_passing: true` with `source: "simulated"`. Uncollected controls → `not_assessed`.

---

## 4. Functional requirements

- **REQ-013-01**: `CSPMEngine.scan_terraform(hcl_text)` applies the AWS, Azure, and GCP rule catalogues via regex/string pattern matching and returns a structured findings list. No external binary is required for this path.
- **REQ-013-02**: `CSPMEngine.scan_cloudformation(cf_json_text)` applies the same rule catalogues to CF JSON/YAML template text.
- **REQ-013-03**: `IaCScanner` (checkov/tfsec) wraps the Checkov and tfsec CLI as async subprocesses. When the binary is absent, the scan result's `status` is `FAILED` with an `error_message`; it does not raise an unhandled exception to the caller.
- **REQ-013-04**: `CloudPostureEngine.list_findings_with_cspm_fallback` returns `source: "org_recorded"` when `cp_findings` rows exist; falls back to `SecurityFindingsEngine` rows with `source_tool` prefix `cspm_via_*` (tagged by CSPMConnector); returns `source: "needs_credentials"` with a descriptive `hint` when both are empty. Never returns an empty response with no `hint`.
- **REQ-013-05**: `CSPMConnector.scan_tenant` runs Prowler, Checkov, CloudSploit, Trivy, and Agentless as subprocesses and mirrors every normalised finding to `SecurityFindingsEngine` keyed by `org_id` with `source_tool = "cspm_via_{tool}"`. Individual tool failures do not abort the overall scan.
- **REQ-013-06**: Cloud connector credential registration (`CloudConnectorEngine`) supports AWS (access key + secret, or role ARN assume-role), Azure (service principal: tenant_id + client_id + client_secret + subscription_id), and GCP (service account JSON). Credential validation is run on `POST /accounts/{provider}/{id}/validate`.
- **REQ-013-07**: `ComplianceEngine` supports 7 frameworks: `SOC2`, `PCI-DSS`, `HIPAA`, `FedRAMP`, `ISO27001`, `NIST-800-53`, `CMMC`. Per SPEC-006, no control check returns `is_passing=True` with `source="simulated"` or `source="not_configured"`.
- **REQ-013-08**: `CloudPostureEngine` uses SQLite WAL + RLock; all public methods are thread-safe and org_id-isolated (every query includes `WHERE org_id = ?`). Findings affecting a cloud account decrement `cp_accounts.posture_score`; resolving a finding restores it.
- **REQ-013-09**: TrustGraph event bus is wired in both `CloudPostureEngine` (`ASSET_DISCOVERED` on account register) and `cloud_connectors.py` (module heartbeat `engine.loaded`); events are fire-and-forget and never block the API path.

---

## 5. Non-functional requirements

- **Latency**: GET endpoints (findings, stats, accounts) must return in < 2s for orgs with up to 10 000 findings; `get_posture_stats` uses a 2-query CTE plan (not 6 round-trips).
- **Tenancy**: `cp_accounts` and `cp_findings` include `org_id NOT NULL`; every query filters by `org_id`. Cross-org access returns empty list (not 404) for listing endpoints; `get_account` returns 404 for wrong-org lookups.
- **Honest-unconfigured path**: When no cloud credentials are configured and no CSPM scanner output exists, the API returns HTTP 200 with `source: "needs_credentials"` and a actionable `hint`. It does NOT return HTTP 503 (no cloud connector warrants 503; the feature is optional).
- **Compliance honest path**: Per SPEC-006. No simulated passes. Unconfigured controls → `not_assessed`. Score denominator excludes `NOT_ASSESSED` controls.
- **Subprocess safety**: `IaCScanner` paths are constrained to `TRUSTED_ROOT` (`/var/fixops`); path segments are not constructed from user input. `safe_path_ops` helpers enforce containment.
- **Tool availability graceful degradation**: Missing Prowler/Checkov/CloudSploit/Trivy binaries produce per-tool `errors` entries, not unhandled 500s.

---

## 6. Acceptance criteria (executable)

- **AC-013-01**: `pytest tests/test_cloud_posture_engine.py -q` passes (org isolation, finding CRUD, posture score arithmetic).
- **AC-013-02**: `pytest tests/test_cloud_posture_findings_real_data.py -q` passes.
- **AC-013-03**: `pytest tests/test_cloud_compliance_engine.py -q` passes.
- **AC-013-04**: `curl -X GET "http://localhost:8000/api/v1/cloud-posture/findings?org_id=fresh-org" -H "X-API-Key: $KEY"` → 200 `{"findings":[],"total":0,"source":"needs_credentials","hint":"..."}` (never empty without hint, never 503).
- **AC-013-05**: `curl -X GET "http://localhost:8000/api/v1/connectors/cspm/status" -H "X-API-Key: $KEY"` → 200 `{"connector":"cspm_oss","tools":{...},...}`.
- **AC-013-06**: `curl -X GET "http://localhost:8000/api/v1/compliance/status/NIST-800-53" -H "X-API-Key: $KEY"` for a fresh org → SC-28 `source: "not_configured"`, `is_passing: false` (per AC-006-02).
- **AC-013-07**: `pytest tests/test_honest_compliance.py -q` 21/21 pass (SPEC-006 gate, cross-ref here as the compliance surface is shared).
- **AC-013-08**: Two concurrent calls to `GET /api/v1/cloud-posture/findings` with different `org_id` values never return each other's findings.
- **AC-013-09**: `pytest tests/test_compliance_engine.py tests/test_compliance_engine_full.py tests/test_compliance_engine_unit.py -q` — 169+ existing tests pass without regression.

---

## 7. Debate log

| Date | Mode | Verdict / change |
|------|------|-----------------|
| 2026-06-01 | Backfill review | Honest-unconfigured path is HTTP 200 + `source: "needs_credentials"`, NOT HTTP 503 — the 503 pattern applies to services with a single mandatory external dep (e.g. DB); CSPM is optional and multi-tool so graceful degradation is the correct model. Documented as-is. |
| 2026-06-01 | Red-Team | IaC path (CSPMEngine pattern rules) is independent of binary availability — always returns findings from HCL/CF text analysis. This is a real, non-stub capability. Connector path (CSPMConnector) requires CLI tools on PATH; tool-absent graceful degradation is correct. |

---

## 8. Implementation notes

### Real vs. honest-503 assessment

| Component | Status | Notes |
|-----------|--------|-------|
| `CSPMEngine.scan_terraform` | REAL — pattern rules in `cspm_engine.py` AWS/Azure/GCP rule catalogues | No external tool required |
| `CSPMEngine.scan_cloudformation` | REAL — same pattern catalogues applied to CF JSON/YAML | No external tool required |
| `IaCScanner` (checkov/tfsec) | REAL when binary present; graceful FAILED status when absent | Subprocess wrapper with async + path-containment |
| `CSPMConnector` (Prowler) | REAL when `prowler` CLI on PATH; tool-absent = `errors: [...]` per tool | |
| `CSPMConnector` (Checkov) | REAL when `checkov` CLI on PATH | |
| `CSPMConnector` (CloudSploit) | REAL when `cloudsploit` CLI on PATH | |
| `CSPMConnector` (Trivy) | REAL when `trivy` CLI on PATH | |
| `CSPMConnector` (Agentless) | REAL — agentless snapshot logic in connector | |
| `CloudConnectorEngine` (AWS) | REAL credential acceptance; live API calls require valid AWS creds | |
| `CloudConnectorEngine` (Azure) | REAL credential acceptance; live API calls require valid Azure SP creds | |
| `CloudConnectorEngine` (GCP) | REAL credential acceptance; live API calls require valid GCP SA JSON | |
| `ComplianceEngine` (7 frameworks) | REAL engine with `NOT_ASSESSED` honest path per SPEC-006 | |

### Key files

- `suite-core/core/cloud_posture_engine.py` — primary store, 569 lines, WAL+RLock+TrustGraph wiring
- `suite-core/core/cspm_engine.py` — IaC pattern scanner, rule catalogues for AWS/Azure/GCP
- `suite-core/core/iac_scanner.py` — Checkov/tfsec subprocess wrappers with `safe_path_ops`
- `suite-core/core/cloud_connectors.py` — `CloudConnectorEngine`, rate limiter, credential management
- `suite-core/connectors/cspm_connector.py` — `CSPMConnector.scan_tenant` orchestrator
- `suite-api/apps/api/cloud_posture_router.py` — 7 routes, prefix `/api/v1/cloud-posture`
- `suite-api/apps/api/cspm_connector_router.py` — 4 routes, prefix `/api/v1/connectors/cspm`
- `suite-api/apps/api/cloud_connectors_router.py` — 10 routes, prefix `/api/v1/cloud-connectors`
- `suite-api/apps/api/cloud_compliance_router.py` — 11 routes, prefix `/api/v1/cloud-compliance`
- `suite-api/apps/api/compliance_router.py` — 12 routes, prefix `/api/v1/compliance`
- `suite-api/apps/api/checkov_router.py` — 4 routes, prefix `/api/v1/checkov`
- `suite-core/core/compliance_engine.py` — `ComplianceEngine`, SPEC-006 honest paths, 7 frameworks

### Tenancy gap (SPEC-007 debt)

`cloud_posture_router.py` passes `org_id` from query params / request body directly (pattern: `org_id: str = Query(default="default")`). This is a V1 violation tracked in the SPEC-007 tenancy allowlist (1724 V1 entries). It does not create a cross-tenant data leak at the engine layer because `CloudPostureEngine` enforces `WHERE org_id = ?` on every query — but the API layer does not enforce that the supplied `org_id` matches the authenticated caller's org. This is a known gap documented in the SPEC-007 allowlist.

### Cross-references

- SPEC-006: `ComplianceEngine` honest-not-assessed path — all 8 check functions fixed, `NOT_ASSESSED` excluded from score denominator.
- SPEC-007: Tenancy lint allowlist covers `Query(default="default")` org_id params in these routers.
