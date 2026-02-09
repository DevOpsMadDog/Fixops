# Pipeline Orchestration

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

## Purpose and Scope

The Pipeline Orchestration system coordinates all processing stages from ingested security artifacts to final decision outputs. The `PipelineOrchestrator` class serves as the central coordinator that sequentially executes 15+ processing stages, integrating vulnerability intelligence, deduplication, risk analysis, compliance evaluation, and policy automation.

This page covers the architecture and coordination logic of the pipeline. For details on the configuration system that controls pipeline behavior, see [Overlay Configuration System](/DevOpsMadDog/Fixops/6.1-overlay-configuration-system). For implementation details of the main `run` method, see [Pipeline Orchestrator](/DevOpsMadDog/Fixops/6.2-pipeline-orchestrator). For the processing layer internals (Bayesian/Markov/Graph), see [Processing Layer Internals](/DevOpsMadDog/Fixops/5.3-processing-layer-internals).

## Architecture Overview

The pipeline orchestrator acts as the central conductor, coordinating multiple specialized services to transform raw security artifacts into actionable intelligence with risk scores, deduplication clusters, compliance mappings, and policy-driven decisions.

```

```

**Sources:** [apps/api/pipeline.py L1-L1012](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L1-L1012)

## Core Components

### PipelineOrchestrator Class

The `PipelineOrchestrator` class is initialized with minimal dependencies and lazily instantiates services as needed during execution.

```

```

**Sources:** [apps/api/pipeline.py L176-L245](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L176-L245)

 [apps/api/pipeline.py L288-L638](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L288-L638)

### Service Dependencies

The orchestrator coordinates with specialized services through well-defined interfaces:

| Service | Class | Purpose | Source File |
| --- | --- | --- | --- |
| Identity Resolution | `IdentityResolver` | Normalize org/app/component IDs, CWE/control mapping | [core/services/identity.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/services/identity.py) |
| Deduplication | `DeduplicationService` | Cluster findings, correlation keys, fingerprints | [core/services/deduplication.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/services/deduplication.py) |
| Processing Layer | `ProcessingLayer` | Bayesian priors, Markov projections, knowledge graph | [core/processing_layer.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py) |
| Exploit Feeds | `ExploitFeedRefresher` | KEV (1,422 vulns) + EPSS (296,333 CVEs) | [core/exploit_signals.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/exploit_signals.py) |
| Exploit Signals | `ExploitSignalEvaluator` | Signal detection across 166 sources | [core/exploit_signals.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/exploit_signals.py) |
| Severity Promotion | `SeverityPromotionEngine` | Dynamic escalation based on KEV/EPSS | [core/severity_promotion.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/severity_promotion.py) |
| IaC Evaluation | `IaCPostureEvaluator` | Checkov/tfsec scanning | [core/iac.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/iac.py) |
| Compliance | `ComplianceEvaluator` | Framework mapping, control coverage | [core/compliance.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/compliance.py) |
| Policy Automation | `PolicyAutomation` | Action planning, connector dispatch | [core/policy.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/policy.py) |

**Sources:** [apps/api/pipeline.py L13-L43](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L13-L43)

## Pipeline Execution Stages

The `run` method executes a carefully sequenced pipeline of 15 major stages:

```

```

**Sources:** [apps/api/pipeline.py L640-L1012](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L640-L1012)

## Stage Details

### Stage 1: Crosswalk Correlation

The pipeline begins by correlating multiple input sources into unified crosswalk entries that link design context, SBOM components, SARIF findings, and CVE records.

```

```

**Sources:** [apps/api/pipeline.py L652-L667](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L652-L667)

 [services/match/indexes.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/services/match/indexes.py)

 [services/match/join.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/services/match/join.py)

### Stage 2-3: Severity Normalization and Context Enrichment

Findings are normalized to consistent severity levels (low/medium/high/critical) and enriched with business context signals (exploitation, exposure, safety impact, mission impact).

**Sources:** [apps/api/pipeline.py L669-L730](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L669-L730)

### Stage 4: VEX Suppression

VEX (Vulnerability Exploitability eXchange) assertions are applied to suppress findings marked as `not_affected`, reducing noise.

```

```

**Sources:** [apps/api/pipeline.py L735-L780](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L735-L780)

### Stage 5: CNAPP Integration

Cloud Native Application Protection Platform (CNAPP) findings are integrated, adding cloud posture and exposure data.

**Sources:** [apps/api/pipeline.py L785-L815](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L785-L815)

### Stage 6: Metadata Extraction

The highest severity SARIF finding is analyzed to extract metadata (file path, rule ID, CWE IDs, message) for the policy engine.

**Sources:** [apps/api/pipeline.py L827-L885](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L827-L885)

### Stage 7: Processing Layer Execution

The advanced processing layer computes Bayesian priors, Markov projections, non-CVE finding summaries, and knowledge graph metrics.

```

```

**Sources:** [apps/api/pipeline.py L887-L894](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L887-L894)

 [core/processing_layer.py L75-L105](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L75-L105)

### Stage 8-9: Exploit Intelligence

Exploit signals are evaluated across 166 sources and severity is dynamically promoted based on KEV listings and high EPSS scores.

**Sources:** [apps/api/pipeline.py L896-L930](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L896-L930)

### Stage 10: Risk Profile Computation

The orchestrator computes a comprehensive risk profile combining EPSS, KEV, Bayesian priors, and Markov projections. Feature flags control whether to use heuristic scoring or the BN-LR (Bayesian Network + Logistic Regression) hybrid model.

```

```

**Sources:** [apps/api/pipeline.py L288-L538](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L288-L538)

### Risk Profile Structure

The risk profile returned contains:

```

```

**Sources:** [apps/api/pipeline.py L437-L449](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L437-L449)

 [apps/api/pipeline.py L518-L530](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L518-L530)

### Stages 11-14: Security Scanning Services

Additional scanning services execute in parallel or sequence:

| Stage | Service | Configuration Key | Optional |
| --- | --- | --- | --- |
| 11 | Knowledge Graph | `knowledge_graph.enabled` | Yes |
| 12 | IaC Scanning | `iac.enabled` | Yes |
| 13 | Secrets Detection | `secrets.enabled` | Yes |
| 14 | Micro Pentest | `micro_pentest.enabled` | Yes |

**Sources:** [apps/api/pipeline.py L932-L975](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L932-L975)

### Stage 15: Deduplication

The deduplication service clusters findings using 7 correlation strategies, achieving 35% noise reduction.

```

```

**Sources:** [apps/api/pipeline.py L977-L988](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L977-L988)

### Stage 16: Guardrail Evaluation

Guardrails enforce severity thresholds (fail_on, warn_on) and return pass/warn/fail status.

**Sources:** [apps/api/pipeline.py L247-L286](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L247-L286)

 [apps/api/pipeline.py L990-L996](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L990-L996)

### Stage 17: Compliance Evaluation

The `evaluate_compliance` function maps guardrail and policy results to compliance control coverage using the control map from the overlay configuration.

```

```

**Sources:** [apps/api/pipeline.py L85-L173](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L85-L173)

 [apps/api/pipeline.py L998-L1001](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L998-L1001)

### Stage 18: Policy Automation and AI Analysis

Final stages execute policy automation (action planning, connector dispatch) and optional AI agent analysis.

**Sources:** [apps/api/pipeline.py L1003-L1012](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L1003-L1012)

## Output Assembly

The pipeline result is a comprehensive JSON structure containing all processed data:

```

```

**Sources:** [apps/api/pipeline.py L896-L1012](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L896-L1012)

## Configuration Control

The pipeline behavior is controlled by the `OverlayConfig` object, which loads from `fixops.overlay.yml`:

```

```

**Sources:** [core/configuration.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/configuration.py)

## Service Initialization

The orchestrator lazily initializes services to avoid unnecessary overhead:

```

```

**Sources:** [apps/api/pipeline.py L179-L193](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L179-L193)

 [apps/api/pipeline.py L237-L245](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L237-L245)

## Integration with FastAPI

The pipeline is invoked via the FastAPI endpoint `/pipeline/run`:

```

```

**Sources:** [apps/api/app.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/app.py)

 FastAPI application structure in CI workflows

## Error Handling and Resilience

The pipeline implements several resilience patterns:

1. **Optional Services**: Most services check `module_config` before execution
2. **Lazy Initialization**: Services only created when needed
3. **Graceful Degradation**: BN-LR falls back to heuristic on error
4. **Library Fallbacks**: Processing layer falls back when pgmpy/mchmm unavailable
5. **Null Checks**: All optional inputs (VEX, CNAPP, context) checked before use

**Sources:** [apps/api/pipeline.py L288-L538](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L288-L538)

 [core/processing_layer.py L57-L105](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L57-L105)

## Performance Characteristics

The pipeline is designed for batch processing with acceptable latency:

* **Typical Runtime**: 2-5 seconds for 200-500 findings
* **Bottlenecks**: * Deduplication cluster queries (SQLite) * External LLM calls (if enabled) * Processing layer graph analytics (NetworkX)
* **Optimization Strategies**: * Lazy service initialization * Batch processing in deduplication * In-memory crosswalk correlation * SQLite connection pooling (timeout=30.0)

**Sources:** [apps/api/pipeline.py L640-L1012](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L640-L1012)

 [core/services/deduplication.py L38-L138](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/services/deduplication.py#L38-L138)

---

**Sources:** [apps/api/pipeline.py L1-L1012](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L1-L1012)

 [core/configuration.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/configuration.py)

 [core/processing_layer.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py)

 [core/exploit_signals.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/exploit_signals.py)

 [core/services/deduplication.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/services/deduplication.py)

 [services/match/indexes.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/services/match/indexes.py)

 [services/match/join.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/services/match/join.py)