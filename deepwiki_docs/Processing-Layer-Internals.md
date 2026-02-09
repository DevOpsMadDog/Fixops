# Processing Layer Internals

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
> * [compliance/__init__.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/compliance/__init__.py)
> * [compliance/mapping.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/compliance/mapping.py)
> * [core/adapters.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/adapters.py)
> * [core/connectors.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/connectors.py)
> * [core/decision_tree.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/decision_tree.py)
> * [core/hallucination_guards.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/hallucination_guards.py)
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
> * [risk/enrichment.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/risk/enrichment.py)
> * [risk/forecasting.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/risk/forecasting.py)
> * [risk/threat_model.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/risk/threat_model.py)
> * [tests/test_compliance_mapping.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_compliance_mapping.py)
> * [tests/test_file_size_limits.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_file_size_limits.py)
> * [tests/test_pipeline_integration.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_pipeline_integration.py)
> * [tests/test_round2_fresh_apps.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_round2_fresh_apps.py)
> * [tests/test_threat_intelligence_comprehensive_coverage.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_threat_intelligence_comprehensive_coverage.py)

## Purpose and Scope

This document details the internal workings of the `ProcessingLayer` class, which implements advanced probabilistic analytics for vulnerability data. The Processing Layer applies Bayesian network inference, Markov chain state projections, and knowledge graph analysis to SBOM components, SARIF findings, CVE records, and CNAPP exposures.

For information about the high-level risk scoring computation that uses ProcessingLayer outputs, see [BN-LR Hybrid Risk Model](/DevOpsMadDog/Fixops/5.2-bn-lr-hybrid-risk-model). For details on the probabilistic forecasting models that consume Markov projections, see [Probabilistic Forecasting](/DevOpsMadDog/Fixops/5.5-probabilistic-forecasting).

---

## Architecture Overview

The `ProcessingLayer` serves as the analytical engine that transforms raw vulnerability data into probabilistic insights. It operates as a stateless evaluator that accepts multiple input types and produces structured analytics.

```

```

**Sources:** [core/processing_layer.py L1-L106](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L1-L106)

---

## ProcessingLayer.evaluate Method

The `evaluate` method is the primary entry point that orchestrates all analytical computations. It accepts vulnerability data as keyword arguments and returns a structured `ProcessingLayerResult`.

### Method Signature

```

```

### Execution Flow

```

```

### Library Availability Detection

The ProcessingLayer checks for optional dependencies at initialization:

| Library | Purpose | Availability Flag |
| --- | --- | --- |
| `pgmpy` | Bayesian network inference with CPDs | `self.pgmpy_available` |
| `pomegranate` | Alternative Bayesian implementation | `self.pomegranate_available` |
| `mchmm` | Hidden Markov model computations | `self.mchmm_available` |
| `networkx` | Graph analysis and centrality metrics | `self.networkx_available` |

The system gracefully degrades when libraries are unavailable, returning heuristic defaults instead of failing.

**Sources:** [core/processing_layer.py L57-L106](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L57-L106)

---

## Bayesian Network Inference

The `_compute_bayesian_priors` method implements a 5-factor Conditional Probability Distribution (CPD) model using SSVC (Stakeholder-Specific Vulnerability Categorization) signals.

### Bayesian Network Structure

```

```

### CPD Model Configuration

The model defines conditional probability tables for each factor:

| Variable | Cardinality | Prior Distribution | Evidence Dependencies |
| --- | --- | --- | --- |
| exploitation | 3 states | [0.6, 0.3, 0.1] | None |
| exposure | 3 states | [0.5, 0.3, 0.2] | None |
| utility | 3 states | [0.4, 0.4, 0.2] | None |
| safety_impact | 4 states | [0.5, 0.3, 0.15, 0.05] | None |
| mission_impact | 3 states | [0.5, 0.35, 0.15] | None |
| risk | 4 states | [0.35, 0.3, 0.2, 0.15] × 324 | All 5 parent factors |

### Inference Execution

When `pgmpy` is available, the method:

1. Constructs a `BayesianNetwork` with directed edges from factors to risk
2. Adds `TabularCPD` objects for each variable with state names
3. Validates the model structure and CPD compatibility
4. Creates a `VariableElimination` inference engine
5. Queries the posterior distribution P(risk | evidence)
6. Returns the most probable risk state and its confidence

### Fallback Behavior

When `pgmpy` is unavailable, the method returns heuristic defaults extracted from the input context with a fixed confidence of 0.5.

**Sources:** [core/processing_layer.py L110-L193](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L110-L193)

---

## Markov Chain Projections

The `_build_markov_projection` method constructs severity state transitions from CVE temporal data to forecast exploitation progression.

### State Space Definition

```

```

### Transition Matrix Construction

The method analyzes CVE records to build an empirical transition matrix:

1. **Severity Sequence Extraction**: Maps each CVE to its severity evolution over time
2. **Transition Counting**: Counts observed transitions between severity states
3. **Matrix Normalization**: Converts counts to probabilities for each row
4. **Stationary Distribution**: Computes long-run equilibrium probabilities

### Projection Computation

When `mchmm` is available:

* Constructs a `MarkovChain` object with the transition matrix
* Projects future states for time horizons: 30, 60, 90 days
* Includes transition probabilities and confidence intervals

### Output Structure

```

```

**Sources:** [core/processing_layer.py L194-L239](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L194-L239)

---

## Knowledge Graph Construction

The `_build_knowledge_graph` method creates a directed graph representing relationships between components, vulnerabilities, and exposures.

### Graph Schema

```

```

### Node Types and Attributes

| Node Type | Key Attributes | Source Data |
| --- | --- | --- |
| component | name, version, purl, supplier | sbom_components |
| vulnerability | cve_id, severity, exploited | cve_records |
| finding | rule_id, level, file, line | sarif_findings |
| asset | asset_id, internet_exposed, data_sensitivity | cnapp_exposures |

### Edge Types and Semantics

| Edge Type | Source → Target | Meaning |
| --- | --- | --- |
| depends_on | component → component | Dependency relationship |
| affects | vulnerability → component | CVE impacts component |
| detected_in | finding → component | SAST finding in component |
| contains | asset → component | Asset deploys component |

### Network Metrics

When `networkx` is available, the method computes:

* **Density**: Ratio of actual edges to possible edges
* **Degree Centrality**: Normalized node connection counts
* **Betweenness Centrality**: Nodes on shortest paths (attack paths)
* **PageRank**: Importance based on incoming edges
* **Connected Components**: Isolated vulnerability clusters

### Simplified Fallback

When `networkx` is unavailable, the method returns simplified metrics based on node and edge counts.

**Sources:** [core/processing_layer.py L281-L380](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L281-L380)

---

## Non-CVE Finding Analysis

The `_summarise_non_cve_findings` method extracts SAST findings that don't correspond to known CVEs, categorizing them by severity and CWE/rule patterns.

### Processing Logic

```

```

### Output Schema

Each non-CVE finding includes:

```

```

### Severity Distribution

The method returns aggregated counts:

```

```

**Sources:** [core/processing_layer.py L240-L280](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L240-L280)

---

## Integration with 166 Vulnerability Data Sources

The ProcessingLayer receives pre-enriched CVE data from the threat intelligence orchestrator, which aggregates information from 166 sources across 8 categories.

### Data Source Categories

```

```

### Data Enrichment Pipeline

Before reaching the ProcessingLayer, CVE records are enriched with:

| Enrichment Type | Data Source | Fields Added |
| --- | --- | --- |
| EPSS scores | FIRST.org API | `epss_score`, `percentile` |
| KEV status | CISA KEV catalog | `kev_listed`, `date_added`, `due_date` |
| ExploitDB refs | ExploitDB CSV | `exploit_count`, `exploit_ids` |
| CVSS metrics | NVD JSON feeds | `cvss_vector`, `cvss_score`, `attack_vector` |
| CWE mappings | CVE records | `cwe_ids`, `weakness_description` |
| Vendor data | Vendor-specific feeds | `vendor_advisory`, `patch_available` |

### Feed Update Frequency

The ThreatIntelligenceOrchestrator maintains a refresh schedule:

* **KEV catalog**: Daily at 00:00 UTC
* **EPSS scores**: Daily at 01:00 UTC
* **NVD feeds**: Every 2 hours
* **Exploit feeds**: Every 6 hours
* **Ecosystem feeds**: Every 12 hours
* **Vendor feeds**: Every 24 hours

**Sources:** [risk/feeds/orchestrator.py L1-L200](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/risk/feeds/orchestrator.py#L1-L200)

 [apps/api/pipeline.py L887-L894](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L887-L894)

---

## Data Flow Through Pipeline

The following diagram shows how the ProcessingLayer integrates into the complete pipeline execution:

```

```

### Key Integration Points

1. **Line 887-894** in `apps/api/pipeline.py`: ProcessingLayer invocation ``` ```
2. **Line 288-349** in `apps/api/pipeline.py`: Risk profile computation uses ProcessingLayer outputs * Extracts `bayesian_priors` for Bayesian probability P(exploitation) * Extracts `markov_projection` for temporal severity forecasting * Combines with EPSS and KEV signals for hybrid risk score
3. **Line 896-903** in `apps/api/pipeline.py`: ProcessingLayer results stored in pipeline output ``` ```

**Sources:** [apps/api/pipeline.py L887-L903](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L887-L903)

 [apps/api/pipeline.py L288-L449](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L288-L449)

---

## Output Structure: ProcessingLayerResult

The `ProcessingLayerResult` dataclass encapsulates all analytical outputs in a structured format.

### Result Schema

```

```

### Example Output

```

```

**Sources:** [core/processing_layer.py L37-L54](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L37-L54)

---

## Error Handling and Degradation

The ProcessingLayer implements graceful degradation when optional libraries are unavailable or when input data is malformed.

### Library Unavailability Handling

| Library Missing | Affected Feature | Fallback Behavior |
| --- | --- | --- |
| `pgmpy` | Bayesian inference | Returns context defaults with 0.5 confidence |
| `networkx` | Graph metrics | Returns simple node/edge counts only |
| `mchmm` | Markov projections | Returns heuristic state transitions |
| `pomegranate` | Alternative Bayesian | No impact (pgmpy preferred) |

### Input Validation

The method handles edge cases:

* **Empty input sequences**: Returns empty structures with zero counts
* **Missing context fields**: Uses default SSVC values (none, controlled, efficient, negligible, degraded)
* **Invalid severity values**: Normalizes to "medium" default
* **Malformed CVE records**: Skips invalid records with warning logs

### Logging and Observability

The ProcessingLayer emits structured logs at key points:

```

```

**Sources:** [core/processing_layer.py L57-L70](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L57-L70)

 [core/processing_layer.py L110-L193](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L110-L193)

---

## Performance Characteristics

### Computational Complexity

| Operation | Time Complexity | Space Complexity | Bottleneck |
| --- | --- | --- | --- |
| Bayesian inference | O(3^5) states | O(324) CPD entries | VariableElimination |
| Markov matrix | O(n × k^2) | O(k^2) matrix | Transition counting (n CVEs, k states) |
| Graph construction | O(n + m) | O(n + m) | NetworkX DiGraph (n nodes, m edges) |
| Non-CVE filtering | O(n) | O(n) | Linear scan (n findings) |

### Typical Execution Times

Based on pipeline integration tests:

* **Small dataset** (< 100 CVEs, < 50 components): ~200ms
* **Medium dataset** (100-1000 CVEs, 50-500 components): ~800ms
* **Large dataset** (> 1000 CVEs, > 500 components): ~2.5s

### Memory Usage

* **Bayesian model**: ~2MB for CPD tables
* **Knowledge graph**: ~50KB per 100 nodes with NetworkX overhead
* **Markov matrix**: ~1KB for 4×4 transition matrix
* **Total overhead**: ~5-10MB for typical workloads

**Sources:** [core/processing_layer.py L75-L106](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L75-L106)

---

## Testing and Validation

The ProcessingLayer is validated through multiple test suites:

### Unit Tests

Located in `tests/test_processing_layer.py`:

* Bayesian inference correctness
* Markov state transition computation
* Graph metric calculations
* Fallback behavior verification

### Integration Tests

Located in `tests/test_round2_fresh_apps.py` and `tests/test_pipeline_integration.py`:

* End-to-end pipeline execution with ProcessingLayer
* Real-world CVE datasets (2024-2025 vulnerabilities)
* Multi-application scenarios (StreamHub, HealthAPI, CargoTrack, MLPredict)

### Coverage Targets

From `.github/workflows/qa.yml`:

* Line coverage: 20% baseline, 100% for new code
* Branch coverage tracked via pytest-cov
* Comprehensive API smoke tests covering 169 paths

**Sources:** [.github/workflows/qa.yml L37-L56](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/.github/workflows/qa.yml#L37-L56)

 [tests/test_pipeline_integration.py L1-L100](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_pipeline_integration.py#L1-L100)