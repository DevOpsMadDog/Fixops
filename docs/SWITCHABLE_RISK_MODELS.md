# Switchable Risk Models - Feature Toggle Architecture

## Overview

FixOps now supports **switchable risk assessment models** with feature toggles, allowing you to:

- **Toggle between different risk models** (weighted scoring, Bayesian Network, BN-LR hybrid, future models)
- **A/B test models** in production with consistent traffic routing
- **Gradually roll out new models** without breaking existing functionality
- **Compare model performance** side-by-side with detailed metrics
- **Fallback gracefully** when models fail or are unavailable

This architecture enables FixOps to evolve its risk assessment capabilities as new research emerges and better models are developed, without requiring code changes or redeployment.

## Architecture

### Components

1. **Model Registry** (`core/model_registry.py`)
   - Central registry for managing multiple risk models
   - Handles model registration, enablement/disablement, and fallback chains
   - Supports A/B testing with consistent hashing
   - Tracks model metadata, performance metrics, and versions

2. **Risk Model Interface** (`core/model_registry.RiskModel`)
   - Abstract base class for all risk models
   - Standardized `predict()` method signature
   - Availability checking via `is_available()`
   - Metadata management

3. **Concrete Model Implementations** (`core/models/`)
   - **WeightedScoringModel**: Traditional severity-based scoring (baseline)
   - **BayesianNetworkModel**: Causal dependency modeling with pgmpy
   - **BNLRHybridModel**: Research paper approach combining BN + Logistic Regression

4. **Model Factory** (`core/model_factory.py`)
   - Creates and configures models from overlay configuration
   - Initializes registry with enabled models
   - Sets up fallback chains and A/B tests

5. **Configuration** (`config/fixops.overlay.yml`)
   - Feature toggles for enabling/disabling models
   - Priority settings for fallback order
   - A/B test configuration
   - Model-specific parameters

## Configuration

### Basic Configuration

Add the following to your `config/fixops.overlay.yml`:

```yaml
probabilistic:
  enabled: true
  risk_models:
    enabled: true
    default_model: bn_lr_hybrid_v1  # Primary model to use
    fallback_chain:  # Try models in order if primary fails
      - bn_lr_hybrid_v1
      - bayesian_network_v1
      - weighted_scoring_v1
    models:
      weighted_scoring_v1:
        enabled: true
        priority: 10
        config:
          severity_weights:
            critical: 1.0
            high: 0.75
            medium: 0.5
            low: 0.25
          allow_threshold: 0.6
          block_threshold: 0.85
      bayesian_network_v1:
        enabled: true
        priority: 50
        config:
          allow_threshold: 0.6
          block_threshold: 0.85
      bn_lr_hybrid_v1:
        enabled: true
        priority: 100
        config:
          allow_threshold: 0.6
          block_threshold: 0.85
```

### A/B Testing Configuration

To A/B test a new model against the baseline:

```yaml
probabilistic:
  risk_models:
    # ... other config ...
    ab_test:
      enabled: true
      control_model: bayesian_network_v1
      treatment_model: bn_lr_hybrid_v1
      traffic_split: 0.5  # 50% to treatment
      hash_key: cve_id  # Use CVE ID for consistent assignment
```

## Usage

### Programmatic Usage

```python
from core.configuration import load_overlay
from core.model_factory import create_model_registry_from_config

# Load configuration
overlay = load_overlay("config/fixops.overlay.yml")

# Create model registry
registry = create_model_registry_from_config(overlay)

# Make a prediction (uses default model with fallback)
prediction = registry.predict(
    sbom_components=sbom_components,
    sarif_findings=sarif_findings,
    cve_records=cve_records,
    context=business_context,
    enrichment_map=enrichment_evidence,
)

print(f"Model: {prediction.model_id}")
print(f"Risk Score: {prediction.risk_score:.3f}")
print(f"Verdict: {prediction.verdict}")
print(f"Confidence: {prediction.confidence:.3f}")
print(f"Fallback Used: {prediction.fallback_used}")
```

### Using a Specific Model

```python
# Use a specific model (bypass default)
prediction = registry.predict(
    sbom_components=sbom_components,
    sarif_findings=sarif_findings,
    cve_records=cve_records,
    model_id="bayesian_network_v1",
    use_fallback=False,  # Don't fallback on failure
)
```

### A/B Testing

```python
# Get model assignment for A/B test
model_id, is_treatment = registry.get_ab_test_model("CVE-2024-1234")
print(f"Using model: {model_id} (treatment={is_treatment})")

# Make prediction with assigned model
prediction = registry.predict(
    sbom_components=sbom_components,
    sarif_findings=sarif_findings,
    cve_records=cve_records,
    model_id=model_id,
)
```

### Listing Available Models

```python
# List all registered models
models = registry.list_models()
for model in models:
    print(f"{model.model_id} (v{model.version}): {model.description}")
    print(f"  Type: {model.model_type.value}")
    print(f"  Enabled: {model.enabled}")
    print(f"  Priority: {model.priority}")
    print()

# List only enabled models
enabled_models = registry.list_models(enabled_only=True)
```

### Enabling/Disabling Models at Runtime

```python
# Disable a model
registry.disable_model("bn_lr_hybrid_v1")

# Enable a model
registry.enable_model("bn_lr_hybrid_v1")
```

## Model Types

### 1. Weighted Scoring Model

**Type**: `weighted_scoring`  
**Priority**: 10 (lowest - used as fallback)  
**Dependencies**: None (always available)

Traditional severity-based scoring using weighted averages:
- Critical: 1.0
- High: 0.75
- Medium: 0.5
- Low: 0.25

Applies KEV boost (+0.2 per KEV-listed CVE) for actively exploited vulnerabilities.

**Use Case**: Baseline model, guaranteed to work, simple and fast.

### 2. Bayesian Network Model

**Type**: `bayesian_network`  
**Priority**: 50 (medium)  
**Dependencies**: pgmpy

Models causal dependencies among vulnerability characteristics:
- Exploitation status (none/poc/active)
- Exposure level (controlled/limited/open)
- Utility (laborious/efficient/super_effective)
- Safety impact (negligible/marginal/major/hazardous)
- Mission impact (degraded/crippled/mev)

Uses probabilistic inference to compute risk distribution and expected risk score.

**Use Case**: More sophisticated than weighted scoring, captures causal relationships, provides probability distributions.

### 3. BN-LR Hybrid Model

**Type**: `bn_lr_hybrid`  
**Priority**: 100 (highest - try first)  
**Dependencies**: pgmpy, scikit-learn

Implements the research paper approach:
1. Run Bayesian Network inference to get posterior probabilities
2. Extract raw features (KEV, EPSS, CVSS, exploit complexity)
3. Combine BN posteriors + raw features as input to Logistic Regression
4. Output calibrated risk score with high accuracy

**Research**: "A hybrid approach combining Bayesian networks and logistic regression for enhancing risk assessment" (97% accuracy on CISA KEV data)

**Use Case**: Most accurate model, combines causal reasoning with discriminative classification, best for production.

## Model Prediction Output

All models return a `ModelPrediction` object with:

```python
@dataclass
class ModelPrediction:
    model_id: str              # Which model made the prediction
    model_version: str         # Model version
    risk_score: float          # 0.0 to 1.0
    verdict: str               # "allow", "review", or "block"
    confidence: float          # 0.0 to 1.0
    explanation: Dict          # Model-specific explanation
    features_used: List[str]   # Features used in prediction
    execution_time_ms: float   # Prediction latency
    fallback_used: bool        # Whether fallback was used
```

This metadata is included in evidence bundles for audit trails and explainability.

## Fallback Chain

When a model fails (exception, unavailable dependencies, etc.), the registry automatically tries the next model in the fallback chain:

```
bn_lr_hybrid_v1 (try first)
    ↓ (if fails)
bayesian_network_v1
    ↓ (if fails)
weighted_scoring_v1 (always works)
```

The fallback chain is configurable via `fallback_chain` in the overlay config.

## A/B Testing

A/B testing allows you to compare two models in production with consistent traffic routing:

1. **Configure A/B test** in overlay config with control/treatment models and traffic split
2. **Consistent hashing** ensures the same CVE always goes to the same model
3. **Track metrics** for both models to compare performance
4. **Gradually roll out** by adjusting traffic split (0% → 10% → 50% → 100%)

Example metrics to track:
- Accuracy (if ground truth available)
- Precision/Recall (for KEV-listed CVEs)
- Execution time
- Confidence scores
- Verdict distribution

## Adding New Models

To add a new risk model:

1. **Create model class** inheriting from `RiskModel`:

```python
from core.model_registry import RiskModel, ModelMetadata, ModelPrediction, ModelType

class MyNewModel(RiskModel):
    def __init__(self, config):
        metadata = ModelMetadata(
            model_id="my_new_model_v1",
            model_type=ModelType.ENSEMBLE,  # or other type
            version="1.0.0",
            description="My new risk model",
            enabled=True,
            priority=75,
            config=config,
        )
        super().__init__(metadata)
    
    def predict(self, *, sbom_components, sarif_findings, cve_records, 
                context=None, enrichment_map=None):
        # Your prediction logic here
        return ModelPrediction(...)
    
    def is_available(self):
        # Check if dependencies are available
        return True
```

2. **Register in factory** (`core/model_factory.py`):

```python
my_model_config = models_config.get("my_new_model_v1", {})
if my_model_config.get("enabled", True):
    model = MyNewModel(config=my_model_config.get("config", {}))
    registry.register(model, add_to_fallback=True)
```

3. **Add to overlay config**:

```yaml
probabilistic:
  risk_models:
    models:
      my_new_model_v1:
        enabled: true
        priority: 75
        config:
          # model-specific config
```

4. **Update fallback chain** if desired

## Performance Considerations

- **Weighted Scoring**: ~1-2ms (fastest)
- **Bayesian Network**: ~5-10ms (moderate)
- **BN-LR Hybrid**: ~10-20ms (slowest, most accurate)

All models are designed to complete within acceptable latency for CI/CD pipelines (<100ms).

## Testing

Run the test suite to verify model registry and models:

```bash
pytest tests/test_model_registry.py -v
```

Tests cover:
- Model registration and listing
- Prediction with default and specific models
- Fallback chain behavior
- A/B test configuration and assignment
- Model enablement/disablement
- Factory initialization from config

## Future Enhancements

Potential future additions:
- **Dynamic Bayesian Networks** (DBN) for temporal modeling
- **Ensemble models** combining multiple models
- **Online learning** to update models from production feedback
- **Model versioning** with automatic migration
- **Performance benchmarking** dashboard
- **Automated model selection** based on input characteristics

## References

- Research Paper: [A hybrid approach combining Bayesian networks and logistic regression for enhancing risk assessment](https://pmc.ncbi.nlm.nih.gov/articles/PMC12287328/#CR19)
- CISA KEV Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- EPSS: https://www.first.org/epss/
- SSVC Framework: https://www.cisa.gov/ssvc
