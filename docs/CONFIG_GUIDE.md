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
  user_email: bot@fixops.io
  token_env: FIXOPS_JIRA_TOKEN
confluence:
  base_url: https://confluence.example.com
  space_key: FIXOPS
  onboarding_page: /display/FIXOPS/Demo+Runbook
  user: fixops-bot
  token_env: FIXOPS_CONFLUENCE_TOKEN
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
  design_context_dir: design_context/demo
  evidence_dir: evidence/demo
  feedback_dir: feedback/demo
  automation_dir: automation/demo
  feeds_dir: feeds/demo
  automation_dir: automation/demo
  feeds_dir: feeds/demo
  audit_export_dir: audit
# (relative paths resolve against the first entry in `FIXOPS_DATA_ROOT_ALLOWLIST`, defaulting to `./data`)
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
  evidence:
    bundle_max_bytes: 1048576
    compress: true
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
  slack_webhook_env: FIXOPS_SLACK_WEBHOOK
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
exploit_signals:
  auto_refresh:
    enabled: true
    refresh_interval_hours: 12
    feeds:
      - id: kev
        destination: kev.json
      - id: epss
        destination: epss.json
  signals:
    kev:
      mode: boolean
      fields: [knownExploited, kev]
      escalate_to: critical
    epss:
      mode: probability
      fields: [epss]
      threshold: 0.5
probabilistic:
  bayesian_prior:
    low: 0.4
    medium: 0.9
    high: 1.2
    critical: 1.4
  markov_transitions:
    medium:
      medium: 0.6
      high: 0.3
      critical: 0.1
  component_limit: 5
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

### Module registry and feature toggles

- `modules.guardrails`, `modules.context_engine`, `modules.compliance`, `modules.probabilistic`, etc.
  in a Terraform-like module switch. Set `enabled: false` to disable a feature for a profile without
  editing code. Omitted modules default to `enabled: true`.
- `modules.custom` accepts a list of custom pipeline hooks. Each entry requires:
  - `name`: identifier for reporting.
  - `entrypoint`: Python import path (`package.module:function` or `package.module:function` syntax).
  - Optional `config` mapping passed to the callable.
- Executed module metadata is returned under `pipeline_result["modules"]` and bundled into evidence
  artefacts for troubleshooting.
- When `toggles.enforce_ticket_sync` is true, the policy automation module will call Jira, Confluence,
  and Slack connectors. Provide `jira.user_email`, `jira.token_env`, `confluence.user`,
  `confluence.token_env`, and `policy_automation.slack_webhook_env` so connectors authenticate.

Example:

```yaml
modules:
  context_engine:
    enabled: true
  ai_agents:
    enabled: false   # disable AI advisor for lightweight profiles
  custom:
    - name: notify-finops
      entrypoint: integrations.finops:emit_cost_report
      config:
        channel: finops-alerts
```

### Probabilistic risk forecasting module

- Configure Bayesian priors under `probabilistic.bayesian_prior`. The loader normalises the weights so
  relative emphasis matters more than the absolute numbers.
- Describe Markov state transitions with `probabilistic.markov_transitions`. Each severity row should
  sum to 1.0; the loader normalises rows if necessary.
- `component_limit` caps how many high-risk components the forecast returns. Increase it in
  enterprise overlays to surface broader blast-radius views.
- Set `escalate_from` to the minimum severity that should be treated as a candidate for transition
  analysis (defaults to `medium`).
- Per-mode overrides live under `probabilistic.profiles.<mode>` and can refine priors or transitions
  without touching the base profile.

### Infrastructure-as-code coverage

- Configure multi-cloud/on-prem posture evaluation via the `iac` section.
- Each target block accepts `id`, optional `display_name`, `match` keywords, `required_artifacts`,
  `recommended_controls`, and `environments` lists.
- Additional targets can be layered per profile under `iac.profiles.<mode>.targets`.
- The pipeline emits an `iac_posture` summary describing matched targets, missing artefacts,
  detected environments, and unmatched components.

Example:

```yaml
iac:
  targets:
    - id: aws
      match: [aws, lambda]
      required_artifacts: [policy_automation, evidence_bundle]
      recommended_controls: [iam-hardening, network-segmentation]
      environments: [prod]
    - id: on_prem
      match: [on-prem, vmware]
      recommended_controls: [patching-window]
      environments: [datacenter]
```


### Exploit signal auto-refresh

- Configure automatic KEV/EPSS ingestion with `exploit_signals.auto_refresh`.
- Each feed entry can define `url` or `path`, a `destination` filename relative to `data.feeds_dir`, and optional `score_field` / `mark_exploited` attributes.
- The pipeline refreshes feeds when the last download exceeds `refresh_interval_hours`, updates CVE records in-memory, and writes the raw feed for auditors to review.

### Analytics and ROI configuration

- Define ROI assumptions under `analytics.baseline` (`findings_per_interval`, `review_minutes_per_finding`, `mttr_hours`, `audit_hours`).
- Capture improvement goals in `analytics.targets` (e.g., `mttr_hours`, `audit_hours`) and monetary assumptions under `analytics.costs` (`currency`, `hourly_rate`).
- `analytics.module_weights` assigns proportional ROI value to each enabled module; weights auto-normalise when omitted.
- Optional `analytics.metrics` can store custom KPIs that downstream dashboards render alongside the computed ROI summary.
- Per-mode overrides under `analytics.profiles.<mode>` let enterprise deployments increase automation savings or change hourly rates without touching the base profile.

### Tenant lifecycle settings

- `tenancy.defaults` lists modules that every tenant should execute plus support/billing contacts surfaced in pipeline responses.
- `tenancy.tenants` enumerates known tenants with `id`, `name`, `status`, `stage`, `environments`, optional `modules` overrides, and free-form `notes` for contextualisation.
- `tenancy.lifecycle` defines lifecycle `stages`, optional `stage_defaults` module expectations, and allowed `transitions` between stages.
- Enterprise overlays can append tenants or adjust defaults via `tenancy.profiles.<mode>`. Entries are appended to the base list so demo and enterprise inventories can coexist.
- Pipeline runs emit `tenant_lifecycle` summaries highlighting stage counts, module gaps, and operational metadata for each tenant; evidence bundles include the same payload when the tenancy module is enabled.

### Performance simulation thresholds

- `performance.baseline.per_module_ms` sets the fallback duration applied when a module-specific latency is not provided.
- `performance.module_latency_ms` maps each module to a nominal execution time in milliseconds, enabling realistic per-module and cumulative timelines.
- Throughput and latency targets live under `performance.ingestion_throughput_per_minute` and `performance.near_real_time_threshold_ms`.
- `performance.capacity` declares expected `concurrent_runs` and optional `burst_runs` so the simulator can flag backlogs.
- Profiles can override any of the above via `performance.profiles.<mode>`—enterprise overlays typically increase throughput thresholds and adjust module timings for heavier automations.

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
  design_context_dir: design_context/demo
  evidence_dir: evidence/demo
  feedback_dir: feedback/demo
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
  slack_webhook_env: FIXOPS_SLACK_WEBHOOK
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
  exploit_signals:
    auto_refresh:
      enabled: true
      feeds:
        - id: kev
        - id: epss
    signals:
      kev:
        mode: boolean
        fields: [knownExploited]
        escalate_to: critical
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
      user_email: enterprise-bot@fixops.io
      token_env: FIXOPS_JIRA_TOKEN
    confluence:
      base_url: https://confluence.example.com
      space_key: FIXOPS-ENT
      onboarding_page: /display/FIXOPS-ENT/Control+Runbook
      user: fixops-enterprise
      token_env: FIXOPS_CONFLUENCE_TOKEN
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
      design_context_dir: design_context/enterprise
      evidence_dir: evidence/enterprise
      audit_export_dir: audit
      feedback_dir: feedback/enterprise
      automation_dir: automation/enterprise
      feeds_dir: feeds/enterprise
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
      evidence:
        bundle_max_bytes: 2097152
        compress: true
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
      exploit_signals:
        signals:
          kev:
            mode: boolean
            fields: [knownExploited, kev]
            escalate_to: critical
          epss:
            mode: probability
            fields: [epss]
            threshold: 0.3
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

## Exploitability Signals

- Configure `exploit_signals.signals` with identifiers such as `kev` (boolean truthy detection of CISA
  KEV catalogue fields) and `epss` (numeric probability from FIRST EPSS feeds).
- Specify `threshold` for probability modes and `escalate_to` or `severity_floor` for boolean
  detectors so guardrail and policy automation modules can react to high-risk CVEs automatically.
- Override `profiles.<mode>.signals` to enforce stricter Enterprise thresholds without copying the
  entire configuration; pipeline responses emit `exploitability_insights` and evidence bundles capture
  the summary whenever the section is allowed.

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
