# Probabilistic Forecasting

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
> * [tests/test_decision_tree.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_decision_tree.py)
> * [tests/test_decision_tree_e2e.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_decision_tree_e2e.py)
> * [tests/test_enrichment.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_enrichment.py)
> * [tests/test_file_size_limits.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_file_size_limits.py)
> * [tests/test_forecasting.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_forecasting.py)
> * [tests/test_pipeline_integration.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_pipeline_integration.py)
> * [tests/test_round2_fresh_apps.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_round2_fresh_apps.py)

## Purpose and Scope

This document describes the probabilistic forecasting system that predicts vulnerability exploitation probability over time using Bayesian inference and Markov chain projections. The forecasting models combine threat intelligence signals (KEV, EPSS, ExploitDB) with statistical methods to produce time-windowed exploitation forecasts with confidence intervals.

For Bayesian network configuration and Markov model implementation details, see [5.1 Bayesian and Markov Models](/DevOpsMadDog/Fixops/5.1-bayesian-and-markov-models). For the BN-LR hybrid risk model that consumes these forecasts, see [5.2 BN-LR Hybrid Risk Model](/DevOpsMadDog/Fixops/5.2-bn-lr-hybrid-risk-model). For the broader processing layer integration, see [5.3 Processing Layer Internals](/DevOpsMadDog/Fixops/5.3-processing-layer-internals).

---

## Forecast Architecture

The probabilistic forecasting system operates in three stages: evidence accumulation, Bayesian probability updates, and Markov temporal projections.

```

```

**Sources:** [risk/forecasting.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/risk/forecasting.py)

 [risk/enrichment.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/risk/enrichment.py)

 [tests/test_forecasting.py L1-L48](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_forecasting.py#L1-L48)

---

## Core Data Structures

### ForecastResult

The `ForecastResult` dataclass encapsulates exploitation probability predictions with evidence breakdown and confidence metrics.

| Field | Type | Description |
| --- | --- | --- |
| `cve_id` | `str` | CVE identifier (e.g., "CVE-2024-1234") |
| `p_exploit_now` | `float` | Current exploitation probability [0.0-1.0] |
| `p_exploit_30d` | `float` | 30-day forward exploitation probability [0.0-1.0] |
| `evidence_breakdown` | `Dict[str, float]` | Contribution of each signal (kev, epss, exploitdb, etc.) |
| `method` | `str` | Forecasting method used ("naive_bayes", "markov", "hybrid") |
| `confidence` | `float` | Confidence level [0.0-1.0], defaults to 0.75 |

**Sources:** [tests/test_forecasting.py L14-L48](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_forecasting.py#L14-L48)

### EnrichmentEvidence

The `EnrichmentEvidence` dataclass aggregates threat intelligence signals used for Bayesian updates.

| Field | Type | Description |
| --- | --- | --- |
| `cve_id` | `str` | CVE identifier |
| `kev_listed` | `bool` | Present in CISA KEV catalog |
| `epss_score` | `Optional[float]` | EPSS score [0.0-1.0] |
| `exploitdb_refs` | `int` | Number of ExploitDB references |
| `cvss_score` | `Optional[float]` | CVSS base score [0.0-10.0] |
| `age_days` | `Optional[int]` | Days since CVE publication |

**Sources:** [tests/test_enrichment.py L8-L15](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_enrichment.py#L8-L15)

 [risk/enrichment.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/risk/enrichment.py)

---

## Bayesian Probability Update

The Bayesian update process applies likelihood ratios based on threat intelligence signals to refine the prior exploitation probability.

```

```

### Likelihood Ratio Configuration

The `_naive_bayes_update` function applies configurable likelihood ratios for each signal type:

| Signal | Condition | Likelihood Ratio | Effect |
| --- | --- | --- | --- |
| KEV listing | `kev_listed == True` | 5.0 | Strong positive signal (CISA confirmed exploitation) |
| EPSS high | `epss_score >= 0.7` | 3.0 | High automated exploitation probability |
| EPSS medium | `0.3 <= epss_score < 0.7` | 2.0 | Moderate exploitation probability |
| ExploitDB refs | `exploitdb_refs > 0` | `2.0 ^ (count / 3)` | Public exploit availability (scaled by count) |
| CVSS critical | `cvss_score >= 9.0` | 1.8 | Critical severity increases likelihood |
| CVSS high | `7.0 <= cvss_score < 9.0` | 1.5 | High severity increases likelihood |
| Age threshold | `age_days > 365` | 0.8 | Old CVEs less likely to be newly exploited |

**Sources:** [tests/test_forecasting.py L50-L95](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_forecasting.py#L50-L95)

 [risk/forecasting.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/risk/forecasting.py)

---

## Markov Temporal Projection

The Markov projection models severity state transitions over time to forecast 30-day exploitation probability.

```

```

### Markov Projection Implementation

The `_markov_forecast_30d` function projects current severity state forward:

1. **State Initialization**: Determine current severity state from CVE record
2. **Transition Matrix Application**: Apply transition probabilities for 30-day window
3. **Probability Calculation**: Convert projected severity distribution to exploitation probability

**Severity to Probability Mapping:**

| Severity State | Exploitation Probability |
| --- | --- |
| `low` | 0.20 |
| `medium` | 0.40 |
| `high` | 0.70 |
| `critical` | 0.90 |

**Sources:** [tests/test_forecasting.py L125-L175](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_forecasting.py#L125-L175)

 [core/processing_layer.py L216-L228](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L216-L228)

---

## Integration with ProcessingLayer

The probabilistic forecasting system integrates with the broader `ProcessingLayer` to provide Bayesian priors and Markov projections used by the risk scoring engine.

```

```

### Pipeline Integration Points

The `PipelineOrchestrator` uses probabilistic forecasts through several integration points:

1. **Bayesian Prior Extraction** ([apps/api/pipeline.py L387-L397](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L387-L397) ): * Extracts `processing_result.bayesian_priors` dict * Used to compute `p_bayesian` by combining with EPSS scores * Formula: `p_bayesian = 1.0 - (1.0 - p_epss) * (1.0 - risk_prior)`
2. **Markov Projection Extraction** ([apps/api/pipeline.py L399-L417](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L399-L417) ): * Extracts `processing_result.markov_projection` dict * Uses `next_states[0]['severity']` to map to probability * Combines with Bayesian: `p_combined = 1.0 - (1.0 - p_bayesian) * (1.0 - p_markov)`
3. **Risk Method Attribution** ([apps/api/pipeline.py L428-L435](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L428-L435) ): * Builds method string: `"epss+kev+bayesian+markov"` * Tracks which components were used in risk computation

**Sources:** [apps/api/pipeline.py L288-L449](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L288-L449)

 [core/processing_layer.py L75-L105](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L75-L105)

---

## Confidence Metrics

Confidence quantification provides uncertainty estimates for probabilistic forecasts.

### Confidence Calculation

| Factor | Impact | Range |
| --- | --- | --- |
| **Evidence Count** | More signals → higher confidence | 0.5-0.9 |
| **Signal Agreement** | Consistent signals → higher confidence | 0.6-0.95 |
| **Data Freshness** | Recent data → higher confidence | 0.7-1.0 |
| **Model Fit** | Good Markov convergence → higher confidence | 0.6-0.9 |

### Default Confidence Values

* Bayesian-only forecasts: `0.75` (moderate confidence)
* Bayesian + Markov forecasts: `0.80` (high confidence)
* Forecasts with KEV signal: `0.90` (very high confidence)
* Fallback/heuristic forecasts: `0.50` (low confidence)

**Sources:** [tests/test_forecasting.py L23-L33](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_forecasting.py#L23-L33)

 [core/processing_layer.py L119](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L119-L119)

---

## Processing Layer Implementation

The `ProcessingLayer` class ([core/processing_layer.py L57-L106](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L57-L106)

) provides the main `evaluate()` method that orchestrates probabilistic forecasting:

### Method Signature

```

```

### Library Availability

The implementation checks for optional dependencies and gracefully degrades:

| Library | Purpose | Fallback Behavior |
| --- | --- | --- |
| `pgmpy` | Bayesian network inference | Returns default priors with confidence=0.5 |
| `pomegranate` | Alternative Bayesian backend | Falls back to pgmpy |
| `mchmm` | Markov chain modeling | Returns simple state-based projection |
| `networkx` | Graph analytics | Uses simplified metrics |

The `library_status` dict in `ProcessingLayerResult` tracks which libraries were successfully used.

**Sources:** [core/processing_layer.py L57-L105](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L57-L105)

---

## Bayesian Prior Computation

The `_compute_bayesian_priors` method ([core/processing_layer.py L110-L211](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L110-L211)

) constructs a 5-factor Bayesian network for risk assessment.

### Bayesian Network Structure

```

```

### CPD Configuration

The Bayesian network uses Conditional Probability Distributions (CPDs) for each node:

* **Marginal CPDs**: `exploitation_cpd`, `exposure_cpd`, `utility_cpd`, `safety_impact_cpd`, `mission_impact_cpd`
* **Conditional CPD**: `risk_cpd` with 324 combinations (3×3×3×4×3) and 4 risk states

### Inference Process

1. **Model Construction** ([core/processing_layer.py L126-L186](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L126-L186) ): * Create `BayesianNetwork` with 5→1 dependency structure * Add all CPDs to model
2. **Variable Elimination** ([core/processing_layer.py L195-L197](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L195-L197) ): * Query `risk` variable given evidence * Evidence keys: `exploitation`, `exposure`, `utility`, `safety_impact`, `mission_impact`
3. **Result Extraction** ([core/processing_layer.py L198-L210](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L198-L210) ): * Extract probability distribution over risk states * Return max-probability risk level * Include confidence = max probability value

**Sources:** [core/processing_layer.py L110-L211](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L110-L211)

---

## Markov Projection Implementation

The `_build_markov_projection` method ([core/processing_layer.py L216-L270](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L216-L270)

) models severity state transitions over time.

### State Sequence Construction

```

```

The method extracts severity values from CVE records and constructs a sequence for Markov modeling.

### Transition Matrix Computation

When `mchmm` library is available:

1. **Chain Initialization**: `chain = mchmm.MarkovChain()`
2. **State Fitting**: `chain.fit(states)`
3. **Prediction**: `predicted = chain.predict(n=1)` for next state
4. **Matrix Extraction**: `chain.observed_matrix` for transition probabilities

### Fallback Projection

When `mchmm` is unavailable ([core/processing_layer.py L253-L270](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L253-L270)

):

1. Count severity occurrences
2. Compute frequency distribution
3. Project most likely next state
4. Return simplified transition matrix

**Sources:** [core/processing_layer.py L216-L270](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L216-L270)

---

## Test Coverage

The test suite validates forecasting accuracy and edge cases.

### Key Test Scenarios

| Test | Purpose | Assertions |
| --- | --- | --- |
| `test_bayes_update_kev_listed` | Verify KEV signal impact | `posterior > prior`, `LR == 5.0` |
| `test_bayes_update_exploitdb` | Verify ExploitDB signal | `posterior > prior`, signal applied |
| `test_bayes_update_high_cvss` | Verify CVSS signal | `posterior > prior`, LR >= 1.5 |
| `test_markov_forecast_critical` | Verify critical state projection | `p_30d > p_now` |
| `test_markov_forecast_low` | Verify low severity handling | Projection uses state transition |
| `test_compute_forecast_integration` | End-to-end forecast | All components integrated |

### Real-World CVE Tests

The test suite includes validation against known CVEs:

* **CVE-2017-0144 (EternalBlue)**: KEV-listed, critical severity
* **CVE-2021-44228 (Log4Shell)**: High EPSS, widespread exploitation
* **CVE-2020-1472 (Zerologon)**: Authentication bypass, high priority

**Sources:** [tests/test_forecasting.py L1-L256](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_forecasting.py#L1-L256)

 [tests/test_decision_tree_e2e.py L1-L48](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_decision_tree_e2e.py#L1-L48)

---

## API Integration

The probabilistic forecasting system is not directly exposed via API endpoints but provides foundational data for risk computation in the pipeline.

### Pipeline API Flow

1. **POST /api/v1/inputs/cve**: Upload CVE feed data
2. **POST /api/v1/inputs/sarif**: Upload SARIF findings
3. **POST /api/v1/inputs/sbom**: Upload SBOM components
4. **POST /api/v1/pipeline/run**: Execute pipeline orchestrator * Calls `ProcessingLayer.evaluate()` * Extracts `bayesian_priors` and `markov_projection` * Computes `_compute_risk_profile()` using forecasts * Returns risk score with method attribution

### Risk Profile Output Format

```

```

**Sources:** [apps/api/pipeline.py L351-L449](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L351-L449)

---

## Configuration and Feature Flags

Probabilistic forecasting can be controlled via overlay configuration and feature flags.

### Overlay Configuration

The `fixops.overlay.yml` configuration supports:

```

```

### Feature Flags

The system checks feature flags for runtime behavior:

* `fixops.model.risk.bn_lr.enabled`: Enable BN-LR hybrid model (overrides heuristic forecasting)
* `fixops.model.risk.default`: Set to "heuristic" or "bn_lr"
* `fixops.model.risk.bn_lr.model_path`: Path to trained BN-LR model file

**Sources:** [apps/api/pipeline.py L317-L336](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L317-L336)

 [core/configuration.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/configuration.py)

---

## Summary

The probabilistic forecasting system provides time-windowed exploitation probability predictions through:

1. **Bayesian Inference**: Updates prior probabilities using threat intelligence signals (KEV, EPSS, ExploitDB, CVSS) with configurable likelihood ratios
2. **Markov Projections**: Models severity state transitions to forecast 30-day exploitation probability
3. **Confidence Metrics**: Quantifies uncertainty based on evidence count, signal agreement, and data freshness
4. **Pipeline Integration**: Provides `bayesian_priors` and `markov_projection` to the risk scoring engine via `ProcessingLayer.evaluate()`
5. **Graceful Degradation**: Falls back to heuristic forecasting when statistical libraries are unavailable

The system achieves 35% noise reduction through deduplication while maintaining forecast accuracy through robust statistical methods and comprehensive threat intelligence integration.

**Sources:** [core/processing_layer.py L1-L270](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L1-L270)

 [apps/api/pipeline.py L288-L449](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L288-L449)

 [tests/test_forecasting.py L1-L256](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_forecasting.py#L1-L256)