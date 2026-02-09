# Pipeline Orchestrator

> **Relevant source files**
> * [.github/workflows/ci.yml](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/.github/workflows/ci.yml)
> * [.github/workflows/fixops-ci.yml](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/.github/workflows/fixops-ci.yml)
> * [.github/workflows/qa.yml](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/.github/workflows/qa.yml)
> * [apps/api/bulk_router.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/bulk_router.py)
> * [apps/api/collaboration_router.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/collaboration_router.py)
> * [apps/api/deduplication_router.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/deduplication_router.py)
> * [apps/api/integrations_router.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/integrations_router.py)
> * [apps/api/normalizers.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/normalizers.py)
> * [apps/api/pipeline.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py)
> * [apps/api/remediation_router.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/remediation_router.py)
> * [apps/api/webhooks_router.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/webhooks_router.py)
> * [core/adapters.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/adapters.py)
> * [core/connectors.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/connectors.py)
> * [core/paths.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/paths.py)
> * [core/policy.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/policy.py)
> * [core/processing_layer.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py)
> * [core/services/collaboration.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/services/collaboration.py)
> * [core/services/deduplication.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/services/deduplication.py)
> * [core/services/identity.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/services/identity.py)
> * [core/services/remediation.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/services/remediation.py)
> * [core/storage.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/storage.py)
> * [fixops-enterprise/src/services/feeds_service.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/fixops-enterprise/src/services/feeds_service.py)
> * [fixops-enterprise/src/services/vex_ingestion.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/fixops-enterprise/src/services/vex_ingestion.py)
> * [tests/test_file_size_limits.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_file_size_limits.py)
> * [tests/test_pipeline_integration.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_pipeline_integration.py)
> * [tests/test_round2_fresh_apps.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_round2_fresh_apps.py)

The `PipelineOrchestrator` is the central coordination engine that processes normalized security artifacts through a multi-stage pipeline, producing enriched findings, risk assessments, and actionable intelligence. It orchestrates the transformation of raw inputs (SBOM, SARIF, CVE feeds, VEX, CNAPP) into correlated crosswalks, severity analyses, risk profiles, and compliance assessments.

For information about input normalization that precedes orchestration, see [Input Normalization](/DevOpsMadDog/Fixops/3.4-input-normalization). For information about the processing layer's probabilistic models, see [Processing Layer Internals](/DevOpsMadDog/Fixops/5.3-processing-layer-internals). For configuration of feature modules, see [Overlay Configuration System](/DevOpsMadDog/Fixops/6.1-overlay-configuration-system).

---

## Architecture Overview

The `PipelineOrchestrator` class implements a sequential processing pipeline with conditional feature execution based on overlay configuration. The orchestrator accepts normalized inputs and coordinates multiple subsystems to produce a comprehensive output document.

```

```

**Sources**: [apps/api/pipeline.py L176-L1030](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L176-L1030)

---

## Core Processing Stages

### Stage 1: Crosswalk Correlation

The first stage builds a unified correlation structure that links design context, SBOM components, SARIF findings, and CVE records using multiple indexing strategies.

```

```

The `build_crosswalk()` function uses seven correlation strategies:

| Strategy | Description | Code Location |
| --- | --- | --- |
| CVE+PURL | Match CVE ID and package URL | [services/match/join.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/services/match/join.py) |
| CVE+ComponentName | Match CVE ID and component name | [services/match/join.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/services/match/join.py) |
| RuleID+FilePath | Match SARIF rule and file path | [services/match/join.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/services/match/join.py) |
| Fuzzy Component | Normalized component name matching | [services/match/join.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/services/match/join.py) |
| File Path Prefix | Hierarchical file path matching | [services/match/join.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/services/match/join.py) |
| CVE Weakref | Weak CVE reference matching | [services/match/join.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/services/match/join.py) |
| Exact Match | Direct identifier matching | [services/match/join.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/services/match/join.py) |

**Sources**: [apps/api/pipeline.py L656-L667](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L656-L667)

 [services/match/join.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/services/match/join.py)

 [services/match/indexes.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/services/match/indexes.py)

---

### Stage 2: Severity Aggregation

The orchestrator normalizes severity levels across different input formats and tracks the highest severity finding that triggered evaluation.

```

```

Severity ordering is defined by `_SEVERITY_ORDER = ("low", "medium", "high", "critical")` with corresponding index mapping for comparison. The `_determine_highest_severity()` method traverses this ordering in reverse to find the most severe level present.

**Sources**: [apps/api/pipeline.py L56-L82](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L56-L82)

 [apps/api/pipeline.py L196-L215](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L196-L215)

 [apps/api/pipeline.py L669-L706](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L669-L706)

---

### Stage 3: Business Context Enrichment

When `NormalizedBusinessContext` is provided, the orchestrator merges SSVC signals and business-critical metadata into crosswalk rows.

```

```

The context enrichment uses normalized component names (lowercased) as keys. For each crosswalk entry, the `extract_component_name()` utility derives a candidate component identifier from the design row, then looks up business context metadata in the `context_map`.

**Sources**: [apps/api/pipeline.py L708-L730](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L708-L730)

---

### Stage 4: VEX Noise Reduction

VEX (Vulnerability Exploitability eXchange) assertions suppress findings for components marked as `not_affected`. This achieves documented noise reduction of up to 35%.

```

```

The noise reduction statistics include:

* `initial`: Original severity counts before VEX
* `suppressed`: Counts of findings filtered by VEX
* `final`: Resulting severity counts after VEX
* `suppressed_total`: Total number of suppressed findings

**Sources**: [apps/api/pipeline.py L735-L780](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L735-L780)

---

### Stage 5: Processing Layer Evaluation

The `ProcessingLayer.evaluate()` method computes Bayesian priors, Markov projections, and knowledge graph metrics. This provides probabilistic insights that feed into risk scoring.

```

```

The Bayesian network uses a 5-factor CPD model with `pgmpy`, while Markov projection uses `mchmm` for state transition forecasting. Knowledge graph construction leverages `networkx` for centrality and density metrics.

**Sources**: [apps/api/pipeline.py L887-L894](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L887-L894)

 [core/processing_layer.py L75-L105](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L75-L105)

---

## Risk Scoring Methods

The `_compute_risk_profile()` method supports two computation strategies controlled by feature flags:

### Heuristic Risk Scoring

The default heuristic method combines EPSS scores, KEV status, Bayesian priors, and Markov projections:

```

```

**Formula**:

* `p_bayesian = 1 - (1 - p_epss) × (1 - risk_prior)`
* `p_combined = 1 - (1 - p_bayesian) × (1 - p_markov)`
* If KEV match: `p_combined = max(p_combined, 0.90)`

**Sources**: [apps/api/pipeline.py L351-L449](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L351-L449)

---

### BN-LR Hybrid Risk Scoring

The BN-LR (Bayesian Network + Logistic Regression) hybrid model is enabled when:

* `fixops.model.risk.bn_lr.enabled = true`
* `fixops.model.risk.default = "bn_lr"`
* `fixops.model.risk.bn_lr.model_path` points to trained model

```

```

The BN-LR model extracts CVSS scores from CVE records, derives EPSS/KEV from exploit summary, and uses conservative defaults for features not available in the pipeline (e.g., `exploit_complexity = 0.5`).

**Sources**: [apps/api/pipeline.py L451-L538](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L451-L538)

 [apps/api/pipeline.py L317-L349](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L317-L349)

---

## Feature Module Execution

The `execute_custom_modules()` function conditionally executes feature modules based on overlay configuration and CLI flags.

```

```

Each module receives a `PipelineContext` object containing:

* `crosswalk`: Correlated findings
* `overlay`: `OverlayConfig` instance
* `exploit_summary`: Threat intelligence
* `processing_result`: Bayesian/Markov insights
* `risk_profile`: Risk scoring output

Modules return dictionaries that are merged into `module_outputs` and included in the final pipeline result under their respective keys (e.g., `"exploit_signals"`, `"iac_posture"`).

**Sources**: [apps/api/pipeline.py L900-L1030](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L900-L1030)

 [core/modules.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/modules.py)

---

## Guardrail Evaluation

The `_evaluate_guardrails()` method implements threshold-based pass/fail logic using severity rankings.

```

```

**Example Configuration**:

```

```

With this policy, any `high` or `critical` finding results in `status: "fail"`, while `medium` findings result in `status: "warn"`.

**Sources**: [apps/api/pipeline.py L247-L286](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L247-L286)

---

## Compliance Mapping

The `evaluate_compliance()` function maps guardrail and policy results to compliance control coverage using control mappings from overlay configuration.

```

```

**Control Map Example**:

```

```

The resolver supports:

* Namespace prefixes: `guardrails:`, `policies:`, `policy.`
* Dot-separated paths: `execution.results.status`
* Status value normalization: `"pass"`, `"PASSED"`, `"ok"`, `"success"` → `True`

**Sources**: [apps/api/pipeline.py L85-L173](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L85-L173)

---

## Marketplace Recommendations

The `_derive_marketplace_recommendations()` method generates actionable recommendations based on compliance gaps and policy failures.

```

```

**Gap Extraction Patterns**:

* Compliance: `"{framework}:{control_id}"` for non-satisfied controls
* Policy: `"policy:{action_id}"` for failed actions
* Guardrail: `"guardrail:{status}"` and `"guardrail:{highest_severity}"`

**Sources**: [apps/api/pipeline.py L540-L638](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L540-L638)

---

## Pipeline Output Structure

The `PipelineOrchestrator.run()` method returns a comprehensive dictionary with the following top-level keys:

| Key | Type | Description |
| --- | --- | --- |
| `status` | `str` | Always `"ok"` for successful runs |
| `design_summary` | `dict` | Row count, unique components |
| `sbom_summary` | `dict` | Component count, licenses, suppliers |
| `sarif_summary` | `dict` | Tool names, findings by level |
| `cve_summary` | `dict` | Record count, exploited count |
| `crosswalk` | `list` | Correlated findings (each entry includes design_row, sbom_component, findings, cves, business_context, suppressed_findings) |
| `severity_overview` | `dict` | Highest severity, counts, sources, trigger, metadata |
| `processing_insights` | `dict` | Bayesian priors, Markov projection, non-CVE findings, knowledge graph, library status |
| `risk_profile` | `dict` | Score, method, components, exposure_applied, model_used |
| `guardrail_evaluation` | `dict` | Status, rationale, severity counts, policy |
| `compliance_status` | `dict` | Control coverage results |
| `policy_summary` | `dict` | Automated actions, execution results |
| `noise_reduction` | `dict` | Initial, suppressed, final counts |
| `cnapp_insights` | `dict` | Asset exposures, findings breakdown |
| Module outputs | `dict` | Keys: `exploit_signals`, `iac_posture`, `ssdlc_assessment`, etc. (conditional) |
| `marketplace_recommendations` | `list` | Actionable recommendations |

**Sources**: [apps/api/pipeline.py L896-L1030](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L896-L1030)

---

## Configuration Integration

The orchestrator respects overlay configuration for:

1. **Feature Enablement**: Modules execute only when enabled in overlay or CLI flags
2. **Guardrail Policy**: Threshold configuration for pass/fail logic
3. **Compliance Mappings**: Control-to-rule mappings for coverage calculation
4. **Risk Model Selection**: Heuristic vs BN-LR via feature flags
5. **Data Directories**: Secure storage paths for deduplication, automation artifacts

**Overlay Access**:

```

```

**Sources**: [apps/api/pipeline.py L640-L651](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L640-L651)

 [core/configuration.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/configuration.py)

---

## Deduplication Integration

When the deduplication module is enabled, the orchestrator uses `DeduplicationService` to cluster findings and track occurrences across runs.

```

```

The deduplication service uses:

* **Correlation key**: Stable identifier across runs (CVE+component, rule+path)
* **Fingerprint**: SHA256 hash of finding content for exact match
* **Cluster status**: Lifecycle state (open, in_progress, resolved, accepted_risk)

**Sources**: [apps/api/pipeline.py L187-L193](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L187-L193)

 [core/services/deduplication.py L24-L139](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/services/deduplication.py#L24-L139)

---

## Thread Safety and Instance Management

The `PipelineOrchestrator` maintains instance-level state for:

1. **Vector Matcher**: Lazy initialization with signature-based cache invalidation
2. **Deduplication Service**: Lazy initialization with shared DB connection
3. **Identity Resolver**: Instance-level for consistent correlation logic

```

```

The vector matcher uses configuration signature comparison to detect when the underlying configuration has changed, triggering re-initialization.

**Sources**: [apps/api/pipeline.py L179-L193](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L179-L193)

 [apps/api/pipeline.py L237-L245](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L237-L245)

---

## Error Handling and Validation

The orchestrator implements defensive validation at each stage:

1. **Input Type Checking**: All optional inputs are validated with `isinstance()` and `Mapping` checks
2. **Severity Fallbacks**: Default to `"medium"` when severity cannot be determined
3. **Empty Data Handling**: Graceful degradation when inputs contain no data
4. **Module Exceptions**: Feature modules are isolated; exceptions are logged but don't fail the pipeline
5. **Library Availability**: Processing layer reports library status and provides fallbacks

**Example Validation**:

```

```

**Sources**: [apps/api/pipeline.py L92-L107](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L92-L107)

 [apps/api/pipeline.py L218-L235](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L218-L235)