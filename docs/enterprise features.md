# FixOps Enterprise Features

## Status Legend
| Status | Description |
|--------|-------------|
| ✅ Implemented | Feature complete and tested |
| 🔄 In Progress | Active development |
| 📋 Planned | Designed, pending implementation |

---

## Feature 1: Deduplication & Correlation Engine

**Status:** ✅ Implemented

Cross-stage deduplication and correlation of security findings across the SDLC.

### Capabilities

| Capability | Stage Coverage | Source Types |
|------------|----------------|--------------|
| Fingerprint-based dedup | All | All |
| Location clustering | Build, Deploy | SARIF, Scanners |
| CVE/CWE correlation | All | CVE feeds, SBOM |
| Root cause grouping | All | All |
| Cross-stage linking | Design→Runtime | All |

### API Enhancements

| Endpoint | Method | Changes |
|----------|--------|---------|
| `/api/v1/enhanced/correlation` | POST | **New** - Batch correlation analysis |
| `/api/v1/enhanced/correlation/stats` | GET | **New** - Correlation statistics |
| `/api/v1/enhanced/analysis` | POST | **Enhanced** - Added `correlate: bool` flag |
| `/api/v1/artefacts` | POST | **Enhanced** - Auto-correlation on ingest |

#### Request/Response Schema

```yaml
# POST /api/v1/enhanced/correlation
Request:
  findings: list[Finding]        # Required
  stage: string                  # design|build|deploy|runtime
  window_hours: int              # Dedup time window (default: 24)
  strategies: list[string]       # fingerprint|location|pattern|root_cause|vulnerability

Response:
  correlated_groups: list[CorrelatedGroup]
  dedup_count: int
  noise_reduction_pct: float
  raw_preserved: bool
```

### CLI Changes

| Command | Flags | Description |
|---------|-------|-------------|
| `fixops correlate` | `--input`, `--stage`, `--window`, `--format` | Run correlation on findings |
| `fixops run` | `--correlate` | Enable correlation during pipeline |
| `fixops analyze` | `--correlate` | Enable correlation in analysis |

### YAML Overlay

```yaml
modules:
  correlation_engine:
    enabled: true                    # Enable/disable
    strategies:
      - fingerprint                  # Exact fingerprint match
      - location                     # File/line proximity
      - pattern                      # Rule/scanner pattern
      - root_cause                   # Root cause inference
      - vulnerability                # CVE/CWE taxonomy
    dedup_window_hours: 24           # Time window for deduplication
    noise_reduction_target: 0.35     # Target 35% reduction
    preserve_raw: true               # Keep original findings
    cross_stage:
      enabled: true
      link_attributes:
        - cve_id
        - component
        - asset_id
        - repo_path
```

---

## Feature 2: Integrations Framework

**Status:** ✅ Implemented

### Integration Inventory

| Integration | Type | Status | Config Key |
|-------------|------|--------|------------|
| GitHub | SCM/CI | ✅ Complete | `integrations.github` |
| GitLab | SCM/CI | ✅ Complete | `integrations.gitlab` |
| Jenkins | CI/CD | ✅ Complete | `integrations.jenkins` |
| Azure DevOps | CI/CD | ✅ Complete | `integrations.azure_devops` |
| SonarQube | Scanner | ✅ Complete | `integrations.sonarqube` |
| Snyk | Scanner | ✅ Complete | `integrations.snyk` |
| DefectDojo | Vuln Mgmt | ✅ Complete | `integrations.defectdojo` |
| Jira | Ticketing | ✅ Complete | `jira` |
| ServiceNow | Ticketing | ✅ Complete | `integrations.servicenow` |
| Confluence | Documentation | ✅ Complete | `confluence` |
| Slack | Notification | ✅ Complete | `policy_automation` |
| Splunk | SIEM | ✅ Complete | `integrations.splunk` |
| QRadar | SIEM | ✅ Complete | `integrations.qradar` |
| DataDog | Observability | ✅ Complete | `integrations.datadog` |
| PagerDuty | Alerting | ✅ Complete | `integrations.pagerduty` |
| PentAGI | Pentest | ✅ Complete | `integrations.pentagi` |

### API Enhancements

| Endpoint | Method | Changes |
|----------|--------|---------|
| `/api/v1/integrations` | GET | List all integrations with status |
| `/api/v1/integrations/{name}/test` | POST | Test integration connectivity |
| `/api/v1/integrations/{name}/sync` | POST | Sync findings bidirectionally |
| `/api/v1/cicd/gitlab/webhook` | POST | **New** - GitLab webhook handler |
| `/api/v1/cicd/azure-devops/webhook` | POST | **New** - Azure DevOps webhook |
| `/api/v1/cicd/snyk/ingest` | POST | **New** - Direct Snyk ingestion |
| `/api/v1/cicd/defectdojo/sync` | POST | **New** - DefectDojo sync |

### CLI Changes

| Command | Flags | Description |
|---------|-------|-------------|
| `fixops integrations list` | `--status`, `--type` | List integrations |
| `fixops integrations test` | `<name>` | Test connectivity |
| `fixops integrations sync` | `<name>`, `--direction` | Sync findings |
| `fixops integrations configure` | `<name>`, `--url`, `--token` | Configure integration |

### YAML Overlay

```yaml
integrations:
  gitlab:
    enabled: true
    url: https://gitlab.example.com
    token_env: FIXOPS_GITLAB_TOKEN
    webhook_secret_env: FIXOPS_GITLAB_WEBHOOK_SECRET
    
  azure_devops:
    enabled: true
    organization: my-org
    project: my-project
    token_env: FIXOPS_AZDO_TOKEN
    
  snyk:
    enabled: true
    org_id: my-snyk-org
    token_env: FIXOPS_SNYK_TOKEN
    sync_mode: pull  # pull|push|bidirectional
    
  defectdojo:
    enabled: true
    url: https://defectdojo.example.com
    token_env: FIXOPS_DEFECTDOJO_TOKEN
    product_id: 1
    engagement_id: auto
    
  datadog:
    enabled: true
    site: datadoghq.com
    api_key_env: FIXOPS_DD_API_KEY
    app_key_env: FIXOPS_DD_APP_KEY
    
  pagerduty:
    enabled: true
    routing_key_env: FIXOPS_PD_ROUTING_KEY
    severity_mapping:
      critical: critical
      high: error
      medium: warning
      low: info
```

---

## Canonical Finding Model

All integrations normalize findings to this schema:

```yaml
Finding:
  id: string                    # Unique identifier
  fingerprint: string           # Content-based hash
  correlation_key: string       # Cross-run matching key
  
  # Source
  source_tool: string           # Scanner/integration name
  source_stage: string          # design|build|deploy|runtime
  source_type: string           # sarif|sbom|cve|api|pentest
  
  # Classification
  title: string
  description: string
  severity: string              # critical|high|medium|low|info
  cve_id: string?
  cwe_id: string?
  rule_id: string?
  
  # Location
  file_path: string?
  line_number: int?
  component: string?
  asset_id: string?
  repo_path: string?
  
  # Context
  exploitability: string?       # none|poc|active
  kev_listed: bool
  epss_score: float?
  
  # Metadata
  discovered_at: datetime
  raw: object                   # Original finding preserved
```

---

## Configuration Reference

### Enable All Enterprise Features

```yaml
# fixops.overlay.yml
modules:
  correlation_engine:
    enabled: true
    strategies: [fingerprint, location, pattern, root_cause, vulnerability]
    cross_stage:
      enabled: true
      
integrations:
  gitlab:
    enabled: true
  azure_devops:
    enabled: true
  snyk:
    enabled: true
  defectdojo:
    enabled: true
  datadog:
    enabled: true
  pagerduty:
    enabled: true
```

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 2.1.0 | 2025-01 | Added cross-stage correlation, GitLab/Azure DevOps/Snyk/DefectDojo integrations |
| 2.0.0 | 2024-12 | Initial correlation engine, core integrations |
