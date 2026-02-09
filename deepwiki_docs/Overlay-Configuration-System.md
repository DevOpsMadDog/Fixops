# Overlay Configuration System

> **Relevant source files**
> * [.emergent/summary.txt](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/.emergent/summary.txt)
> * [backend_test.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/backend_test.py)
> * [config/fixops.overlay.yml](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/config/fixops.overlay.yml)
> * [core/analytics.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/analytics.py)
> * [core/compliance.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/compliance.py)
> * [core/configuration.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/configuration.py)
> * [core/decision_policy.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/decision_policy.py)
> * [core/enhanced_decision.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/enhanced_decision.py)
> * [core/llm_providers.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/llm_providers.py)
> * [demo_ssdlc_stages/03_code_development.json](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/demo_ssdlc_stages/03_code_development.json)
> * [demo_ssdlc_stages/04_build_ci.yaml](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/demo_ssdlc_stages/04_build_ci.yaml)
> * [demo_ssdlc_stages/06_deploy_production.yaml](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/demo_ssdlc_stages/06_deploy_production.yaml)
> * [docs/USAGE_GUIDE.html](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/docs/USAGE_GUIDE.html)
> * [simulations/cve_scenario/runner.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/simulations/cve_scenario/runner.py)
> * [tests/e2e/test_critical_decision_policy.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/e2e/test_critical_decision_policy.py)
> * [tests/test_comprehensive_e2e.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_comprehensive_e2e.py)
> * [tests/test_cve_simulation.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_cve_simulation.py)
> * [tests/test_data_generator.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_data_generator.py)
> * [tests/test_end_to_end.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_end_to_end.py)
> * [tests/test_enhanced_api.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_enhanced_api.py)
> * [tests/test_overlay_configuration.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_overlay_configuration.py)
> * [tests/test_pipeline_matching.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_pipeline_matching.py)

## Purpose and Scope

The Overlay Configuration System provides a centralized, profile-driven configuration mechanism for the FixOps platform. It controls operational behavior, feature enablement, integration settings, and compliance policies through a single YAML file (`fixops.overlay.yml`) that can adapt the platform from demo environments to enterprise deployments without code changes.

This document covers the configuration file structure, loading mechanisms, validation rules, and the profile system. For information about how the configuration is consumed during pipeline execution, see [Pipeline Orchestrator](/DevOpsMadDog/Fixops/6.2-pipeline-orchestrator). For module-specific configuration details, see [Processing Layer Internals](/DevOpsMadDog/Fixops/5.3-processing-layer-internals).

**Sources**: [config/fixops.overlay.yml L1-L582](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/config/fixops.overlay.yml#L1-L582)

 [core/configuration.py L1-L58](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/configuration.py#L1-L58)

---

## Configuration File Structure

The overlay configuration file is a YAML document located at `config/fixops.overlay.yml` by default. The file path can be overridden using the `FIXOPS_OVERLAY_PATH` environment variable.

### Top-Level Sections

```

```

**Sources**: [config/fixops.overlay.yml L1-L100](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/config/fixops.overlay.yml#L1-L100)

 [core/configuration.py L655-L698](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/configuration.py#L655-L698)

### Analysis Engines Configuration

The `analysis_engines` section controls the strategy for proprietary vs. open-source security scanners:

| Field | Type | Description |
| --- | --- | --- |
| `strategy` | string | Execution strategy: `proprietary_first`, `oss_first`, `proprietary_only`, `oss_only` |
| `result_combination` | string | How to merge results: `merge`, `replace`, `best_of` |
| `languages` | mapping | Per-language analyzer configuration with OSS fallback |
| `iac` | mapping | Infrastructure-as-Code scanner configuration |
| `container` | mapping | Container scanning configuration |
| `cloud` | mapping | Cloud security posture management configuration |

**Example configuration**:

```

```

**Sources**: [config/fixops.overlay.yml L3-L152](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/config/fixops.overlay.yml#L3-L152)

 [core/configuration.py L621-L623](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/configuration.py#L621-L623)

---

## Loading and Validation Process

### Configuration Loading Flow

```

```

**Sources**: [core/configuration.py L18-L88](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/configuration.py#L18-L88)

 [core/configuration.py L584-L626](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/configuration.py#L584-L626)

### Validation Rules

The configuration loader enforces strict validation at multiple levels:

**Schema Validation** (via `_OverlayDocument` Pydantic model):

* Only allowed top-level keys are accepted (see `_ALLOWED_OVERLAY_KEYS`)
* Unknown keys trigger `ValueError` with `extra="forbid"`
* Field types are validated according to the Pydantic schema

**Path Security Validation**:

* All data directory paths must be within allowed roots
* `FIXOPS_DATA_ROOT_ALLOWLIST` environment variable defines allowed roots
* Defaults to repository `data/` directory if not specified
* Path traversal attempts are rejected

**Business Logic Validation**:

* Compliance framework controls must have valid structure
* Policy automation actions must use recognized triggers
* Guardrail maturity levels must be valid
* Signing provider must be one of: `env`, `aws_kms`, `azure_key_vault`

**Sources**: [core/configuration.py L97-L135](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/configuration.py#L97-L135)

 [core/configuration.py L628-L653](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/configuration.py#L628-L653)

 [core/configuration.py L219-L308](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/configuration.py#L219-L308)

---

## Profile System

The profile system enables mode-specific configuration overrides without duplicating the entire configuration file. This allows a single `fixops.overlay.yml` to serve both demo and enterprise environments.

### Profile Hierarchy

```

```

### Profile Application Logic

The `_deep_merge()` function recursively merges profile overrides into base configuration:

| Merge Scenario | Behavior |
| --- | --- |
| Scalar values | Profile value replaces base value |
| Nested mappings | Recursive merge, profile values override base |
| Lists | Profile list replaces base list (no appending) |
| Missing in profile | Base value retained |

**Example configuration with profiles**:

```

```

**Sources**: [core/configuration.py L60-L87](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/configuration.py#L60-L87)

 [config/fixops.overlay.yml L341-L420](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/config/fixops.overlay.yml#L341-L420)

 [tests/test_overlay_configuration.py L28-L46](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_overlay_configuration.py#L28-L46)

---

## Module Configuration

The `modules` section controls feature enablement across the platform. Each module can be independently enabled or disabled, affecting both processing behavior and API endpoint availability.

### Module Matrix Structure

```

```

### Standard Modules

| Module Name | Purpose | Configuration Keys |
| --- | --- | --- |
| `guardrails` | Security policy enforcement | `enabled` |
| `context_engine` | Business context enrichment | `enabled`, `fields`, `weights`, `playbooks` |
| `compliance` | Compliance framework mapping | `enabled` |
| `probabilistic` | Risk forecasting models | `enabled`, `risk_models`, `ab_test` |
| `exploit_signals` | KEV/EPSS signal processing | `enabled`, `signals` |
| `correlation_engine` | Finding deduplication | `enabled`, `strategies`, `noise_reduction_target` |
| `vector_store` | Pattern-based matching | `enabled`, `provider`, `patterns_path`, `top_k` |
| `enhanced_decision` | Multi-LLM consensus | `enabled` |
| `iac_posture` | Infrastructure security | `enabled` |
| `analytics` | ROI computation | `enabled` |
| `tenancy` | Multi-tenant support | `enabled` |
| `performance` | Performance profiling | `enabled` |

**Sources**: [config/fixops.overlay.yml L200-L221](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/config/fixops.overlay.yml#L200-L221)

 [core/configuration.py L763-L792](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/configuration.py#L763-L792)

### Custom Module Specifications

Custom modules can be registered via the `modules.custom` array:

```

```

**Sources**: [core/configuration.py L834-L867](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/configuration.py#L834-L867)

---

## Integration Configuration

The overlay system provides centralized configuration for external system integrations, including credentials, endpoints, and synchronization policies.

### Integration Architecture

```

```

### Jira Integration Configuration

```

```

**Configuration fields**:

* `url` - Jira instance base URL
* `project_key` - Default project for ticket creation
* `default_issue_type` - Issue type for automated tickets
* `user_email` - Bot user email
* `token_env` - Environment variable containing API token

**Sources**: [config/fixops.overlay.yml L168-L173](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/config/fixops.overlay.yml#L168-L173)

 [core/configuration.py L798-L803](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/configuration.py#L798-L803)

### Confluence Integration Configuration

```

```

**Configuration fields**:

* `base_url` - Confluence instance URL
* `space_key` - Default space for page creation
* `user` - Bot username
* `token_env` - Environment variable containing API token

**Sources**: [config/fixops.overlay.yml L174-L178](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/config/fixops.overlay.yml#L174-L178)

 [core/configuration.py L804-L809](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/configuration.py#L804-L809)

### Authentication Configuration

The `auth` section controls API authentication strategy:

```

```

**Strategies**:

* `token` - Require API key in header (default)
* `jwt` - JSON Web Token authentication
* `none` - No authentication (demo mode only)

**Sources**: [config/fixops.overlay.yml L179-L182](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/config/fixops.overlay.yml#L179-L182)

 [core/configuration.py L810-L828](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/configuration.py#L810-L828)

---

## Data Directory Configuration

The `data` section specifies filesystem paths for storing artifacts, evidence bundles, and analytics data. All paths undergo strict validation to prevent directory traversal attacks.

### Path Validation Architecture

```

```

### Standard Data Directories

| Directory Key | Purpose | Default Path |
| --- | --- | --- |
| `design_context_dir` | Design CSV uploads | `data/design_context` |
| `evidence_dir` | Signed evidence bundles | `data/evidence` |
| `archive_dir` | SBOM/SARIF archives | `data/archive` |
| `analytics_dir` | Analytics persistence | `data/analytics` |
| `automation_dir` | Policy automation logs | `data/automation` |
| `feedback_dir` | User feedback capture | `data/feedback` |

**Path resolution rules**:

1. Relative paths are resolved against the first allowlisted root
2. Absolute paths must be within an allowlisted root
3. `~` is expanded before validation
4. Symlinks are resolved before validation

**Sources**: [config/fixops.overlay.yml L183-L189](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/config/fixops.overlay.yml#L183-L189)

 [core/configuration.py L628-L653](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/configuration.py#L628-L653)

 [core/configuration.py L717-L730](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/configuration.py#L717-L730)

---

## Guardrails and Compliance Configuration

The overlay system provides structured configuration for security guardrails and compliance frameworks, enabling policy-as-code enforcement.

### Guardrail Maturity Levels

```

```

**Maturity level definitions**:

```

```

**Sources**: [core/configuration.py L90-L95](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/configuration.py#L90-L95)

 [config/fixops.overlay.yml L386-L391](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/config/fixops.overlay.yml#L386-L391)

### Compliance Framework Configuration

Compliance frameworks are defined with control mappings:

```

```

**Control fields**:

* `id` - Control identifier (string, can be numeric)
* `title` - Human-readable description
* `requires` - Array of required pipeline inputs
* `description` - (optional) Extended description
* `tags` - (optional) Array of tags
* `metadata` - (optional) Additional metadata

**Validation rules**:

* Control `id` must be non-empty string
* `requires` must be array of recognized input types
* Unknown fields trigger validation error

**Sources**: [config/fixops.overlay.yml L289-L357](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/config/fixops.overlay.yml#L289-L357)

 [core/configuration.py L219-L308](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/configuration.py#L219-L308)

 [core/configuration.py L310-L345](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/configuration.py#L310-L345)

---

## Policy Automation Configuration

The `policy_automation` section defines automated actions triggered by pipeline events such as guardrail failures or compliance gaps.

### Action Configuration Structure

```

```

### Supported Triggers and Actions

| Trigger | Description | Supported Action Types |
| --- | --- | --- |
| `guardrail:fail` | Guardrail check failed | `jira_issue`, `confluence_page`, `slack` |
| `guardrail:warn` | Guardrail warning issued | `jira_issue`, `confluence_page`, `slack` |
| `context:high` | High-context score detected | `jira_issue`, `slack` |
| `compliance:gap` | Compliance control not met | `jira_issue`, `confluence_page` |

**Action type fields**:

**`jira_issue`**:

* `summary` (required)
* `description` (optional)
* `priority` (optional)
* `project_key` (optional, uses default from jira config)
* `issue_type` (optional)

**`confluence_page`**:

* `title` (required)
* `body` or `content` (optional)
* `space` (optional, uses default from confluence config)
* `parent_page_id` (optional)
* `representation` (optional, default: `storage`)

**`slack`**:

* `webhook_url` or use `webhook_env` (required)
* `channel` (optional)
* `text` (required)

**Sources**: [config/fixops.overlay.yml L276-L288](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/config/fixops.overlay.yml#L276-L288)

 [core/configuration.py L348-L445](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/configuration.py#L348-L445)

 [core/configuration.py L448-L510](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/configuration.py#L448-L510)

---

## Probabilistic Risk Model Configuration

The overlay system supports switchable risk scoring models with fallback chains and A/B testing capabilities.

### Risk Model Strategy

```

```

### Model Configuration

```

```

**Model priority interpretation**:

* Higher priority = more sophisticated model
* Fallback chain tries models in order
* If all models fail, uses deterministic heuristics

**A/B Testing Configuration** (optional):

```

```

**Sources**: [config/fixops.overlay.yml L421-L461](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/config/fixops.overlay.yml#L421-L461)

 [core/configuration.py L868-L906](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/configuration.py#L868-L906)

---

## Exploit Signal Configuration

The `exploit_signals` section configures how the platform escalates severity based on threat intelligence signals like CISA KEV and EPSS.

### Signal Types and Escalation Logic

```

```

**Signal modes**:

* `boolean` - Binary check (present/absent)
* `probability` - Threshold-based check (0.0 - 1.0)

**Escalation behaviors**:

* `escalate_to` - Force severity to specified level
* `severity_floor` - Ensure severity is at least this level

**Sources**: [config/fixops.overlay.yml L462-L493](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/config/fixops.overlay.yml#L462-L493)

 [core/configuration.py L907-L933](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/configuration.py#L907-L933)

---

## Usage Patterns

### Loading Configuration in Application Code

```

```

**Sources**: [core/configuration.py L951-L1002](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/configuration.py#L951-L1002)

### Environment Variable Overrides

The overlay path can be overridden via environment variable:

```

```

**Sources**: [core/configuration.py L18-L23](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/configuration.py#L18-L23)

 [tests/test_overlay_configuration.py L49-L57](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_overlay_configuration.py#L49-L57)

### Testing with Custom Overlays

```

```

**Sources**: [tests/test_overlay_configuration.py L90-L105](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_overlay_configuration.py#L90-L105)

 [tests/test_cve_simulation.py L10-L94](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_cve_simulation.py#L10-L94)

---

**Key Takeaways**:

1. The overlay system provides **centralized configuration** for all platform behavior
2. **Profile-based overrides** enable single-file configuration for multiple environments
3. **Strict validation** prevents configuration errors and security issues (path traversal)
4. **Module toggles** allow fine-grained feature control
5. **Integration credentials** are resolved from environment variables at runtime
6. **Risk models** can be switched and chained with fallback strategies
7. Configuration is **cached** for performance and accessed via `OverlayConfig` properties

**Sources**: [core/configuration.py L1-L1002](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/configuration.py#L1-L1002)

 [config/fixops.overlay.yml L1-L582](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/config/fixops.overlay.yml#L1-L582)

 [tests/test_overlay_configuration.py L1-L286](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_overlay_configuration.py#L1-L286)