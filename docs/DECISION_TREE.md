# Decision Tree Framework

## Overview

The Decision Tree Framework implements a comprehensive 6-step analysis pipeline for CVE exploitation assessment. It combines enrichment data, probabilistic forecasting, threat modeling, compliance mapping, LLM analysis, and verdict determination to provide actionable security decisions.

## Architecture

### 6-Step Decision Tree

```
Step 1: Enrichment
    ↓ EPSS, KEV, ExploitDB, CVSS, CWE
Step 2: Forecasting
    ↓ Markov + Bayesian modeling
Step 3: Threat Modeling
    ↓ Match CVE to architecture + threat tree
Step 4: Compliance Mapping
    ↓ Map CVE to org-specific + standard controls
Step 5: LLM Explanation
    ↓ Natural language + math-backed + hallucination guard
Step 6: Final Verdict
    → Exploitable / Not Exploitable / Needs Review
```

## Components

### 1. Enrichment Module (`risk/enrichment.py`)

Extracts and aggregates exploit signals from multiple sources:

- **KEV (Known Exploited Vulnerabilities)**: CISA catalog of actively exploited CVEs
- **EPSS (Exploit Prediction Scoring System)**: Probability of exploitation in next 30 days
- **ExploitDB**: Public exploit code availability
- **CVSS**: Common Vulnerability Scoring System metrics
- **CWE**: Common Weakness Enumeration categories
- **Age**: Days since publication
- **Vendor Advisory**: Patch/mitigation availability

**Key Functions:**
- `compute_enrichment(cve_feed, exploit_signals)` → Dict[str, EnrichmentEvidence]
- `_extract_cvss_from_record(record)` → tuple[Optional[str], Optional[float]]
- `_extract_cwe_from_record(record)` → List[str]
- `_calculate_age_days(published_date)` → Optional[int]
- `_check_vendor_advisory(record)` → bool

**Example:**
```python
from risk.enrichment import compute_enrichment

cve_feed = [...]  # NVD CVE records
exploit_signals = {
    "kev": {"vulnerabilities": [{"cveID": "CVE-2023-1234"}]},
    "epss": {"CVE-2023-1234": 0.85}
}

enrichment_map = compute_enrichment(cve_feed, exploit_signals)
evidence = enrichment_map["CVE-2023-1234"]
print(f"KEV: {evidence.kev_listed}, EPSS: {evidence.epss_score}")
```

### 2. Forecasting Module (`risk/forecasting.py`)

Computes exploitation probability using Naive Bayes and Markov models:

**Naive Bayes Update:**
- Prior: 0.05 (5% base exploitation rate)
- Likelihood ratios:
  - KEV-listed: 5.0x
  - ExploitDB refs: 3.0x (scaled by count)
  - High CVSS (≥7.0): 2.0x
  - Vendor advisory: 0.7x (reduces probability)
  - Old vulnerability (>365 days): 1.5x

**Markov Forecasting:**
- Competing risks model with 3 states: Unexploited, Exploited, Mitigated
- Transition rates (per day):
  - λ(Unexploited→Exploited): 0.01 base, 0.05 if KEV-listed
  - λ(Unexploited→Mitigated): 0.03 base, 0.10 if patch available
  - λ(Exploited→Mitigated): 0.20 if active remediation, 0.05 otherwise

**Key Functions:**
- `compute_forecast(enrichment_map, config)` → Dict[str, ForecastResult]
- `_naive_bayes_update(prior, evidence, config)` → tuple[float, Dict[str, Any]]
- `_markov_forecast_30d(p_now, evidence, config)` → float

**Example:**
```python
from risk.forecasting import compute_forecast

forecast_map = compute_forecast(enrichment_map, config)
forecast = forecast_map["CVE-2023-1234"]
print(f"P(exploit now): {forecast.p_exploit_now:.2%}")
print(f"P(exploit 30d): {forecast.p_exploit_30d:.2%}")
```

### 3. Threat Modeling Module (`risk/threat_model.py`)

Analyzes attack paths and reachability:

**Reachability Score Calculation:**
- Attack Vector (AV): Network (0.4), Adjacent (0.2), Local (0.1), Physical (0.05)
- Attack Complexity (AC): Low (0.2), High (0.05)
- Privileges Required (PR): None (0.2), Low (0.1), High (0.05)
- User Interaction (UI): None (0.1), Required (0.05)
- Exposure multiplier: Internet (1.5x), Partner (1.2x), Internal (0.8x)
- Patch penalty: 0.7x if vendor advisory available

**Attack Path Detection:**
- Network accessible (AV:N)
- Low complexity (AC:L)
- Internet/partner exposure OR no privileges required (PR:N)

**Key Functions:**
- `compute_threat_model(enrichment_map, graph, cnapp_exposures)` → Dict[str, ThreatModelResult]
- `_parse_cvss_vector(cvss_vector)` → Dict[str, str]
- `_calculate_reachability_score(cvss_components, exposure_level, has_vendor_advisory)` → float
- `_find_affected_components(cve_id, graph)` → List[str]
- `_determine_exposure_level(cnapp_exposures, affected_components)` → str

**Example:**
```python
from risk.threat_model import compute_threat_model

threat_map = compute_threat_model(enrichment_map, graph, cnapp_exposures)
threat_model = threat_map["CVE-2023-1234"]
print(f"Attack path found: {threat_model.attack_path_found}")
print(f"Reachability: {threat_model.reachability_score:.2f}")
print(f"Exposure: {threat_model.exposure_level}")
```

### 4. Compliance Mapping Module (`compliance/mapping.py`)

Maps CVEs to compliance controls via CWE:

**Default Mappings:**
- CWE-89 (SQL Injection) → NIST 800-53: SI-10, SA-11 | PCI DSS: 6.5.1 | OWASP: A03:2021
- CWE-79 (XSS) → NIST 800-53: SI-10, SA-11 | PCI DSS: 6.5.7 | OWASP: A03:2021
- CWE-287 (Improper Auth) → NIST 800-53: IA-2, IA-5, AC-7 | PCI DSS: 8.2, 8.3 | OWASP: A07:2021
- CWE-327 (Broken Crypto) → NIST 800-53: SC-12, SC-13 | PCI DSS: 6.5.3, 4.1 | OWASP: A02:2021
- 10+ more CWE mappings included

**Key Functions:**
- `load_control_mappings(overlay)` → Dict[str, ControlMapping]
- `map_cve_to_controls(enrichment_map, control_mappings, required_frameworks)` → Dict[str, ComplianceMappingResult]

**Example:**
```python
from compliance.mapping import load_control_mappings, map_cve_to_controls

control_mappings = load_control_mappings(overlay)
compliance_map = map_cve_to_controls(
    enrichment_map,
    control_mappings,
    required_frameworks=["NIST 800-53", "PCI DSS"]
)
compliance = compliance_map["CVE-2023-1234"]
print(f"Frameworks affected: {compliance.frameworks_affected}")
print(f"Compliance gaps: {compliance.compliance_gaps}")
```

### 5. LLM Hallucination Guards (`core/hallucination_guards.py`)

Validates LLM outputs to prevent hallucinations:

**Three Guard Types:**

1. **Input Citation Guard**: Validates LLM cites input fields correctly
   - Checks required fields are mentioned
   - Detects numeric hallucinations (numbers not in input)
   - Allows common numbers (0, 1, 100)

2. **Cross-Model Agreement Guard**: Validates consensus across models
   - Measures action disagreement ratio
   - Detects high confidence spread (>0.3)
   - Default threshold: 30% disagreement

3. **Numeric Consistency Guard**: Validates computed values match LLM output
   - Compares quoted numbers to computed metrics
   - Default tolerance: 5%
   - Flags inconsistencies

**Confidence Adjustments:**
- Default penalty: 15% per failed guard
- Scaled by disagreement severity
- Clamped to [0.0, 1.0] range

**Key Functions:**
- `validate_input_citation(llm_response, input_context, required_fields)` → tuple[bool, List[str]]
- `validate_cross_model_agreement(analyses, disagreement_threshold)` → tuple[bool, float, List[str]]
- `validate_numeric_consistency(llm_response, computed_values, tolerance)` → tuple[bool, List[str]]
- `apply_hallucination_guards(llm_result, input_context, computed_metrics, config)` → Dict[str, Any]

**Example:**
```python
from core.hallucination_guards import apply_hallucination_guards

guard_result = apply_hallucination_guards(
    llm_result,
    input_context,
    computed_metrics={"CVSS score": 9.8},
    config={"disagreement_threshold": 0.3}
)
print(f"Validation passed: {guard_result['validation_passed']}")
print(f"Adjusted confidence: {guard_result['adjusted_confidence']:.2f}")
```

### 6. Decision Tree Orchestrator (`core/decision_tree.py`)

Orchestrates all 6 steps and computes final verdict:

**Verdict Logic:**
- **Exploitable** (p_exploit ≥ 0.70):
  - High exploitation probability
  - Attack path found (if required)
  - High reachability score
  - Maps to legacy "block" verdict

- **Not Exploitable** (p_exploit ≤ 0.15):
  - Low exploitation probability
  - Patch available
  - Low reachability score
  - Maps to legacy "allow" verdict

- **Needs Review** (0.15 < p_exploit < 0.70):
  - Moderate exploitation probability
  - Low confidence (<0.60)
  - No clear attack path
  - Maps to legacy "defer" verdict

**Key Functions:**
- `analyze(cve_feed, exploit_signals, graph, cnapp_exposures, llm_results)` → Dict[str, DecisionTreeResult]
- `_compute_verdict(enrichment, forecast, threat_model, compliance, llm_confidence)` → tuple[str, float, List[str]]
- `_map_to_legacy_verdict(verdict)` → str

**Example:**
```python
from core.decision_tree import DecisionTreeOrchestrator

orchestrator = DecisionTreeOrchestrator(config, overlay)
results = orchestrator.analyze(
    cve_feed,
    exploit_signals=exploit_signals,
    graph=graph,
    cnapp_exposures=cnapp_exposures,
    llm_results=llm_results
)

result = results["CVE-2023-1234"]
print(f"Verdict: {result.verdict}")
print(f"Confidence: {result.verdict_confidence:.2%}")
print(f"Reasoning: {result.verdict_reasoning}")
```

## Configuration

### Overlay Configuration (`config/fixops.overlay.yml`)

```yaml
decision_tree:
  enabled: true
  thresholds:
    not_exploitable_max: 0.15      # Max probability for "not exploitable"
    exploitable_min: 0.70           # Min probability for "exploitable"
    require_attack_path: true       # Require attack path for "exploitable"
    min_confidence: 0.60            # Min confidence for non-review verdict
  probabilistic:
    prior_exploit: 0.05             # Base exploitation probability
    markov:
      lambda_ux_to_ex: 0.01         # Unexploited→Exploited rate
      lambda_ux_to_mit: 0.03        # Unexploited→Mitigated rate
      lambda_ex_to_mit: 0.05        # Exploited→Mitigated rate
      kev_boost_factor: 5.0         # KEV boost multiplier
      patch_boost_factor: 3.33      # Patch boost multiplier
  required_frameworks:
    - NIST 800-53
    - PCI DSS

enhanced_decision:
  hallucination_guards:
    enabled: true
    disagreement_threshold: 0.3     # Max allowed disagreement
    numeric_tolerance: 0.05         # Numeric consistency tolerance
    confidence_penalty: 0.15        # Penalty per failed guard
```

## Usage Examples

### Basic Usage

```python
from core.decision_tree import DecisionTreeOrchestrator

# Initialize orchestrator
orchestrator = DecisionTreeOrchestrator()

# Prepare CVE feed (from NVD or other source)
cve_feed = [
    {
        "cve": {"id": "CVE-2023-1234", "published": "2023-01-01T00:00:00.000Z"},
        "metrics": {
            "cvssMetricV31": [{
                "cvssData": {
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "baseScore": 9.8
                }
            }]
        },
        "weaknesses": [{"description": [{"value": "CWE-89"}]}]
    }
]

# Run analysis
results = orchestrator.analyze(cve_feed)

# Get verdict
result = results["CVE-2023-1234"]
print(f"Verdict: {result.verdict}")
print(f"Confidence: {result.verdict_confidence:.2%}")
```

### Advanced Usage with All Features

```python
from core.decision_tree import DecisionTreeOrchestrator

# Load configuration
overlay = load_overlay("config/fixops.overlay.yml")
config = load_config()

# Initialize orchestrator
orchestrator = DecisionTreeOrchestrator(config, overlay)

# Prepare inputs
cve_feed = load_cve_feed()
exploit_signals = load_exploit_signals()  # KEV + EPSS
graph = load_knowledge_graph()
cnapp_exposures = load_cnapp_exposures()
llm_results = run_llm_analysis()  # Optional

# Run complete analysis
results = orchestrator.analyze(
    cve_feed,
    exploit_signals=exploit_signals,
    graph=graph,
    cnapp_exposures=cnapp_exposures,
    llm_results=llm_results
)

# Process results
for cve_id, result in results.items():
    print(f"\n{cve_id}:")
    print(f"  Verdict: {result.verdict} ({result.legacy_verdict})")
    print(f"  Confidence: {result.verdict_confidence:.2%}")
    print(f"  Reasoning:")
    for reason in result.verdict_reasoning:
        print(f"    - {reason}")
    
    # Step details
    print(f"  Enrichment: KEV={result.enrichment.kev_listed}, EPSS={result.enrichment.epss_score}")
    print(f"  Forecast: P(now)={result.forecast.p_exploit_now:.2%}, P(30d)={result.forecast.p_exploit_30d:.2%}")
    print(f"  Threat: Attack path={result.threat_model.attack_path_found}, Reachability={result.threat_model.reachability_score:.2f}")
    print(f"  Compliance: Frameworks={result.compliance.frameworks_affected}, Gaps={len(result.compliance.compliance_gaps)}")
```

## Testing

### Unit Tests

```bash
# Run all decision tree tests
pytest tests/test_enrichment.py -v
pytest tests/test_forecasting.py -v
pytest tests/test_threat_model.py -v
pytest tests/test_compliance_mapping.py -v
pytest tests/test_decision_tree.py -v
pytest tests/test_hallucination_guards.py -v

# Run end-to-end tests with real CVE data
pytest tests/test_decision_tree_e2e.py -v
```

### Test Coverage

- **Enrichment**: 15 tests covering CVSS/CWE extraction, age calculation, vendor advisory detection
- **Forecasting**: 15 tests covering Naive Bayes, Markov models, probability clamping
- **Threat Modeling**: 15 tests covering CVSS parsing, reachability scoring, attack path detection
- **Compliance Mapping**: 15 tests covering CWE-to-control mapping, framework gaps
- **Decision Tree**: 15 tests covering verdict computation, threshold logic, legacy mapping
- **Hallucination Guards**: 15 tests covering citation, agreement, numeric consistency
- **End-to-End**: 10 tests with real CVE data (EternalBlue, Spring4Shell, Looney Tunables)

## Performance

### Benchmarks

- **Enrichment**: ~2ms per CVE
- **Forecasting**: ~1ms per CVE
- **Threat Modeling**: ~1ms per CVE
- **Compliance Mapping**: ~0.5ms per CVE
- **Total Pipeline**: ~5ms per CVE (excluding LLM calls)

### Scalability

- Handles 1000+ CVEs in <5 seconds
- Memory efficient: ~1KB per CVE result
- Parallelizable: All steps are stateless

## Troubleshooting

### Common Issues

**Issue**: Low confidence scores
- **Cause**: Missing exploit signals (KEV/EPSS)
- **Solution**: Ensure exploit_signals parameter is provided

**Issue**: All verdicts are "needs_review"
- **Cause**: Thresholds too strict
- **Solution**: Adjust thresholds in overlay configuration

**Issue**: No attack paths found
- **Cause**: Missing knowledge graph or CNAPP data
- **Solution**: Provide graph and cnapp_exposures parameters

**Issue**: Compliance gaps reported
- **Cause**: CWE not in default mappings
- **Solution**: Add custom CWE mappings to overlay

## Future Enhancements

- [ ] Machine learning model for probability estimation
- [ ] Real-time exploit feed integration
- [ ] Automated remediation recommendations
- [ ] Custom CWE-to-control mapping UI
- [ ] Historical trend analysis
- [ ] Risk scoring aggregation across portfolios

## References

- CISA KEV Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- EPSS: https://www.first.org/epss/
- CVSS v3.1: https://www.first.org/cvss/v3.1/specification-document
- CWE: https://cwe.mitre.org/
- NIST 800-53: https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final
- PCI DSS: https://www.pcisecuritystandards.org/
