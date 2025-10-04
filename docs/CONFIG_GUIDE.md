# Overlay Configuration Guide

FixOps uses a single overlay file (`config/fixops.overlay.yml`) to switch between Demo and Enterprise
modes. The file is JSON-compatible YAML so it can be parsed without external dependencies. This guide
explains the schema, override mechanisms, and provides ready-to-use examples.

## File Location & Overrides

- Default path: `config/fixops.overlay.yml` (relative to repository root).
- Override: set `FIXOPS_OVERLAY_PATH=/path/to/overlay.yml` before starting the FastAPI service.
- Mode selection: set the top-level `mode` key (`"demo"` or `"enterprise"`). Profile-specific blocks
  under `profiles` provide overrides applied after base keys are loaded.

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
  audit_export_dir: data/audit
toggles:
  require_design_input: false
  auto_attach_overlay_metadata: true
  enforce_ticket_sync: false
  capture_feedback: false
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
toggles:
  require_design_input: false
  auto_attach_overlay_metadata: true
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
    toggles:
      require_design_input: true
      auto_attach_overlay_metadata: true
      enforce_ticket_sync: true
      capture_feedback: true
```

> Tip: you can keep Demo defaults in the base document and only specify overrides inside the
> `enterprise` profile, as shown above.

## Operational Checklist

1. **Create directories** referenced by `data.*` before first run (the FastAPI startup hook will also
   attempt to create them).
2. **Inject secrets** via environment variables referenced in `auth.token_env` or your OIDC provider.
3. **Restart the API** after modifying the overlay file to reload the configuration.
4. **Monitor responses** — the `/pipeline/run` payload includes an `overlay` block with masked values so
   you can confirm which profile is active.
