# Overlay Configuration Guide

FixOps uses a single overlay file (`config/fixops.overlay.yml`) to switch between Demo and Enterprise
modes. The file is JSON-compatible YAML so it can be parsed without external dependencies. This guide
explains the schema, override mechanisms, and provides ready-to-use examples.

## File Location & Overrides

- Default path: `config/fixops.overlay.yml` (relative to repository root).
- Override: set `FIXOPS_OVERLAY_PATH=/path/to/overlay.yml` before starting the FastAPI service.
- Mode selection: set the top-level `mode` key (`"demo"` or `"enterprise"`). Profile-specific blocks
  under `profiles` provide overrides applied after base keys are loaded.
- Data roots: constrain provisioning directories by exporting
  `FIXOPS_DATA_ROOT_ALLOWLIST=/srv/fixops/data:/var/lib/fixops` (colon-separated paths).

## Schema Overview

```yaml
mode: demo | enterprise
jira:
  url: https://jira.example.com
  project_key: FIX
  default_issue_type: Task
confluence:
  base_url: https://confluence.example.com
  space_key: FIXOPS
  onboarding_page: /display/FIXOPS/Demo+Runbook
git:
  provider: github | gitlab
  host: https://github.com
  default_org: fixops-demo
ci:
  provider: github_actions | gitlab_ci | circleci
  pipeline_slug: org/project/pipeline
auth:
  strategy: token | oidc
  token_env: FIXOPS_API_TOKEN
  client_id: fixops-enterprise
data:
  design_context_dir: data/design_context/demo
  evidence_dir: data/evidence/demo
  feedback_dir: data/feedback/demo
  audit_export_dir: data/audit
toggles:
  require_design_input: false
  auto_attach_overlay_metadata: true
  include_overlay_metadata_in_bundles: true
  enforce_ticket_sync: false
  capture_feedback: false
limits:
  max_upload_bytes:
    default: 3145728
    sarif: 6291456
    cve: 6291456
guardrails:
  maturity: foundational | scaling | advanced
  fail_on: (optional) critical | high | medium | low
  warn_on: (optional) critical | high | medium | low
  profiles:
    scaling:
      fail_on: high
      warn_on: medium
context_engine:
  fields:
    criticality: customer_impact
    data: data_classification
    exposure: exposure
  criticality_weights:
    mission_critical: 4
    internal: 1
  playbooks:
    - name: Stabilise Customer Impact
      min_score: 9
evidence_hub:
  bundle_name: fixops-run
  include_sections:
    - design_summary
    - context_summary
onboarding:
  time_to_value_minutes: 30
  checklist:
    - step: Upload design context CSV
      modes: [demo, enterprise]
compliance:
  frameworks:
    - name: SOC 2
      controls:
        - id: CC8.1
          requires: [design, guardrails, evidence]
policy_automation:
  actions:
    - trigger: guardrail:fail
      type: jira_issue
ssdlc:
  stages:
    - id: plan
      requirements:
        - key: design
        - key: threat_model
ai_agents:
  watchlist_version: 2024-07
  framework_signatures:
    - name: LangChain
      keywords: [langchain, llmchain]
  controls:
    default:
      recommended_controls:
        - Document tool/API access scopes
        - Require prompt/response logging
pricing:
  plans:
    - name: Launch
      mode: demo
profiles:
  enterprise:
    mode: enterprise
    # Overrides merged on top of base keys
```

All keys are optional. Missing sections default to empty dictionaries. Toggle defaults are applied by
`load_overlay()` when absent.

## Demo Mode Example

```yaml
mode: demo
jira:
  url: https://jira.example.com
  project_key: FIX
  default_issue_type: Task
confluence:
  base_url: https://confluence.example.com
  space_key: FIXOPS
  onboarding_page: /display/FIXOPS/Demo+Runbook
git:
  provider: github
  host: https://github.com
  default_org: fixops-demo
ci:
  provider: github_actions
  pipeline_slug: fixops/demo-pipeline
auth:
  strategy: token
  token_env: FIXOPS_API_TOKEN
data:
  design_context_dir: data/design_context/demo
  evidence_dir: data/evidence/demo
  feedback_dir: data/feedback/demo
toggles:
  require_design_input: false
  auto_attach_overlay_metadata: true
  include_overlay_metadata_in_bundles: true
limits:
  max_upload_bytes:
    default: 3145728
guardrails:
  maturity: foundational
context_engine:
  fields:
    criticality: customer_impact
    data: data_classification
    exposure: exposure
  playbooks:
    - name: Stabilise Customer Impact
      min_score: 9
onboarding:
  time_to_value_minutes: 30
compliance:
  frameworks:
    - name: SOC 2
      controls:
        - id: CC8.1
          requires: [design, guardrails, evidence]
policy_automation:
  actions:
    - trigger: guardrail:fail
      type: jira_issue
ssdlc:
  stages:
    - id: plan
      requirements:
        - key: design
        - key: threat_model
ai_agents:
  watchlist_version: 2024-07
  framework_signatures:
    - name: LangChain
      keywords: [langchain]
pricing:
  plans:
    - name: Launch
      mode: demo
      included_scans: 50
```

## Enterprise Mode Example

```yaml
mode: enterprise
profiles:
  enterprise:
    jira:
      url: https://jira.example.com
      project_key: FIXOPS
      default_issue_type: Security Review
      workflow_scheme: Enterprise Risk
    confluence:
      base_url: https://confluence.example.com
      space_key: FIXOPS-ENT
      onboarding_page: /display/FIXOPS-ENT/Control+Runbook
    git:
      provider: gitlab
      host: https://gitlab.example.com
      default_group: fixops
    ci:
      provider: gitlab_ci
      pipeline_slug: fixops/enterprise/security
    auth:
      strategy: oidc
      client_id: fixops-enterprise
    data:
      design_context_dir: data/design_context/enterprise
      evidence_dir: data/evidence/enterprise
      audit_export_dir: data/audit
      feedback_dir: data/feedback/enterprise
    toggles:
      require_design_input: true
      auto_attach_overlay_metadata: true
      include_overlay_metadata_in_bundles: false
      enforce_ticket_sync: true
      capture_feedback: true
    limits:
      max_upload_bytes:
        default: 7340032
        sarif: 10485760
        cve: 10485760
    guardrails:
      maturity: advanced
    context_engine:
      playbooks:
        - name: Enterprise Stabilisation
          min_score: 8
    onboarding:
      time_to_value_minutes: 25
      checklist:
        - step: Connect Jira project
          modes: [enterprise]
    compliance:
      frameworks:
        - name: PCI DSS
          controls:
            - id: 6.5
              requires: [cve, context, guardrails]
    policy_automation:
      actions:
        - trigger: compliance:gap
          type: confluence_page
          space: FIXOPS-ENT
    ssdlc:
      stages:
        - id: deploy
          requirements:
            - key: compliance
            - key: deploy_approvals
    ai_agents:
      watchlist_version: 2024-07
      framework_signatures:
        - name: LangChain
          keywords: [langchain, llmchain]
        - name: AutoGPT
          keywords: [autogpt]
    pricing:
      plans:
        - name: Scale
          mode: enterprise
          included_scans: 500
```

> Tip: you can keep Demo defaults in the base document and only specify overrides inside the
> `enterprise` profile, as shown above.

## AI Agent Watchlist

- Configure `ai_agents.framework_signatures` with the LLM/agent stacks you use (LangChain, AutoGPT,
  CrewAI, etc.). Keywords are matched against design rows and SBOM components during pipeline runs.
- Populate `ai_agents.controls` to describe mandatory mitigations (prompt logging, tool allowlists).
- Use `ai_agents.playbooks` to map detected frameworks to response channels (e.g., `appsec-ai`). The
  pipeline emits an `ai_agent_analysis` section and evidence bundles include it when requested.

## SSDLC Assessment

- Define `ssdlc.stages` to map lifecycle checkpoints (Plan, Code, Build, Test, Deploy, Run, Audit) to
  concrete requirements such as `design`, `threat_model`, `dependency_pinning`, or
  `deploy_approvals`.
- Each requirement is evaluated during `/pipeline/run`; results are returned as
  `ssdlc_assessment` and persisted in the evidence bundle when `ssdlc_assessment` appears in
  `evidence_hub.include_sections`.
- Enterprise profiles can override stages to tighten expectations (e.g., requiring deployment
  approvals or feedback capture) without modifying the core application.

## Operational Checklist

1. **Create directories** referenced by `data.*` before first run (the FastAPI startup hook will also
   attempt to create them).
2. **Inject secrets** via environment variables referenced in `auth.token_env` or your OIDC provider,
   then distribute the matching header (default `X-API-Key`) to ingest clients.
3. **Restart the API** after modifying the overlay file to reload the configuration.
4. **Monitor responses** — the `/pipeline/run` payload includes an `overlay` block with masked values so
   you can confirm which profile is active.
5. **Review guardrails & context** — pipeline results include `guardrail_evaluation` and `context_summary`
   so you know which playbook to activate for each component.
6. **Pull compliance & policy outputs** — capture the `compliance_status`, `policy_automation`, and
   `evidence_bundle` manifest to keep Jira, Confluence, and auditors aligned.
