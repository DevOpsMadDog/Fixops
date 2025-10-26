# Correlation Engine Documentation

## Overview

The Correlation Engine is an intelligent system for reducing security alert fatigue by identifying and grouping related security findings. It can reduce security noise by approximately **35%** through multiple correlation strategies.

## Features

### 5 Correlation Strategies

1. **Fingerprint Matching** (95% confidence)
   - Exact fingerprint match between findings
   - Fastest correlation method
   - Identifies identical security patterns

2. **Location Proximity** (60-80% confidence)
   - Correlates findings in the same file
   - Considers line number proximity (±10 lines)
   - Groups findings in code location clusters

3. **Rule Pattern** (70% confidence)
   - Matches by rule ID, scanner type, and severity
   - Identifies common vulnerability patterns
   - Groups findings from same detection rule

4. **Root Cause Analysis** (60% confidence)
   - Categorizes by security domain:
     - Input validation (injection, XSS, traversal, overflow)
     - Authentication (auth, login, session, token)
     - Authorization (access, privilege, permission, ACL)
     - Cryptography (crypto, SSL, TLS, hash, encrypt)
     - Configuration (config, default, hardcoded, exposure)
   - Groups findings with similar root causes

5. **Vulnerability Taxonomy** (70-90% confidence)
   - Correlates by CVE ID (90% confidence)
   - Correlates by CWE ID (70% confidence)
   - Groups known vulnerabilities

## Configuration

### Enable/Disable

The correlation engine is **disabled by default** to preserve existing functionality. Enable it in `config/fixops.overlay.yml`:

```yaml
modules:
  correlation_engine:
    enabled: true  # Set to true to enable
    strategies:
      - fingerprint
      - location
      - pattern
      - root_cause
      - vulnerability
    noise_reduction_target: 0.35
```

### Environment Variable

Alternatively, set via environment variable:

```bash
export ENABLE_CORRELATION_ENGINE=true
```

## Usage

### Programmatic Usage

```python
from fixops_enterprise.src.services.correlation_engine import (
    get_correlation_engine,
    correlate_finding_async,
    batch_correlate_async
)

# Get engine instance
engine = get_correlation_engine(enabled=True)

# Correlate single finding
finding = {
    'id': 'finding-123',
    'title': 'SQL Injection vulnerability',
    'severity': 'high',
    'file_path': '/src/api/users.py',
    'line_number': 42,
    'rule_id': 'SAST-001',
    'scanner_type': 'semgrep'
}

all_findings = [...]  # List of all findings

result = await correlate_finding_async(finding, all_findings, enabled=True)

if result:
    print(f"Found {len(result.correlated_findings)} correlated findings")
    print(f"Correlation type: {result.correlation_type}")
    print(f"Confidence: {result.confidence_score}")
    print(f"Noise reduction: {result.noise_reduction_factor}")
    print(f"Root cause: {result.root_cause}")

# Batch correlate multiple findings
results = await batch_correlate_async(all_findings, enabled=True)
print(f"Correlated {len(results)} findings")
```

### API Integration

The correlation engine can be integrated into the decision pipeline:

```python
from fixops_enterprise.src.services.correlation_engine import get_correlation_engine

# In your decision engine or pipeline
async def process_findings(findings):
    # Enable correlation if configured
    correlation_enabled = config.get('modules.correlation_engine.enabled', False)
    
    if correlation_enabled:
        engine = get_correlation_engine(enabled=True)
        
        # Correlate all findings
        correlations = await engine.batch_correlate_findings(findings)
        
        # Group findings by correlation
        correlated_groups = {}
        for correlation in correlations:
            group_id = correlation.finding_id
            correlated_groups[group_id] = correlation.correlated_findings
        
        # Reduce noise by selecting representative findings
        unique_findings = []
        processed_ids = set()
        
        for finding in findings:
            finding_id = finding.get('id')
            if finding_id not in processed_ids:
                unique_findings.append(finding)
                # Mark correlated findings as processed
                if finding_id in correlated_groups:
                    processed_ids.update(correlated_groups[finding_id])
                processed_ids.add(finding_id)
        
        print(f"Reduced {len(findings)} findings to {len(unique_findings)} unique findings")
        print(f"Noise reduction: {(1 - len(unique_findings)/len(findings)) * 100:.1f}%")
        
        return unique_findings
    else:
        return findings
```

## Data Structures

### CorrelationResult

```python
@dataclass
class CorrelationResult:
    finding_id: str                    # ID of the primary finding
    correlated_findings: List[str]     # IDs of correlated findings
    correlation_type: str              # Type of correlation used
    confidence_score: float            # Confidence (0.0-1.0)
    noise_reduction_factor: float      # Noise reduction (0.0-1.0)
    root_cause: str                    # Root cause category
    timestamp: str                     # ISO timestamp
```

### Finding Format

The correlation engine expects findings in this format:

```python
{
    'id': str,                    # Unique finding ID
    'title': str,                 # Finding title
    'description': str,           # Finding description
    'severity': str,              # critical/high/medium/low
    'status': str,                # open/in_progress/closed
    'file_path': str,             # File path (optional)
    'line_number': int,           # Line number (optional)
    'rule_id': str,               # Rule ID (optional)
    'scanner_type': str,          # Scanner name (optional)
    'cve_id': str,                # CVE ID (optional)
    'cwe_id': str,                # CWE ID (optional)
    'fingerprint': str,           # Finding fingerprint (optional)
}
```

## Performance

### Benchmarks

- **Single finding correlation**: <1ms (sub-millisecond)
- **Batch correlation (100 findings)**: ~50ms
- **Memory overhead**: Minimal (no persistent storage)
- **Parallel processing**: Yes (asyncio-based)

### Optimization

The correlation engine is optimized for performance:

1. **Parallel strategy execution**: All 5 strategies run concurrently
2. **Early termination**: Stops when high-confidence correlation found
3. **Efficient scoring**: Weighted scoring (confidence 70%, noise reduction 30%)
4. **Batch processing**: Processes findings in batches of 10

## Integration Points

### 1. Decision Engine Integration

Add correlation to the decision pipeline:

```python
# In decision_engine.py
from .correlation_engine import get_correlation_engine

class DecisionEngine:
    def __init__(self, config):
        self.correlation_enabled = config.get('modules.correlation_engine.enabled', False)
        self.correlation_engine = get_correlation_engine(enabled=self.correlation_enabled)
    
    async def make_decision(self, findings):
        # Correlate findings if enabled
        if self.correlation_enabled:
            correlations = await self.correlation_engine.batch_correlate_findings(findings)
            # Use correlations to reduce noise
            findings = self._deduplicate_findings(findings, correlations)
        
        # Continue with decision logic
        ...
```

### 2. API Endpoint Integration

Add correlation endpoint:

```python
# In api/v1/correlation.py
from fastapi import APIRouter
from fixops_enterprise.src.services.correlation_engine import correlate_finding_async

router = APIRouter()

@router.post("/correlate")
async def correlate_finding(finding: dict, all_findings: list):
    """Correlate a finding with other findings"""
    result = await correlate_finding_async(finding, all_findings, enabled=True)
    if result:
        return {
            "finding_id": result.finding_id,
            "correlated_findings": result.correlated_findings,
            "correlation_type": result.correlation_type,
            "confidence_score": result.confidence_score,
            "noise_reduction_factor": result.noise_reduction_factor,
            "root_cause": result.root_cause
        }
    return {"message": "No correlations found"}
```

### 3. CLI Integration

Add correlation command:

```bash
# Correlate findings from a file
fixops correlate --findings findings.json --output correlations.json
```

## Monitoring

### Metrics

Track these metrics to monitor correlation effectiveness:

1. **Noise Reduction Rate**: `(correlated_findings / total_findings) * 100`
2. **Average Confidence**: Mean confidence score across all correlations
3. **Correlation Type Distribution**: Count by correlation type
4. **Processing Time**: Average time per finding

### Logging

The correlation engine logs key events:

```python
# Initialization
logger.info("Correlation engine initialized and enabled")

# Correlation completion
logger.info(
    "Correlation analysis completed",
    finding_id=finding_id,
    latency_us=latency_us,
    found_correlations=True
)

# Batch completion
logger.info(
    "Batch correlation completed",
    total_findings=100,
    correlated_findings=35,
    total_time_ms=50.2,
    avg_time_per_finding_us=502
)
```

## Testing

### Unit Tests

```python
import pytest
from fixops_enterprise.src.services.correlation_engine import (
    CorrelationEngine,
    CorrelationResult
)

@pytest.mark.asyncio
async def test_fingerprint_correlation():
    engine = CorrelationEngine(enabled=True)
    
    finding = {
        'id': 'f1',
        'fingerprint': 'abc123',
        'status': 'open'
    }
    
    all_findings = [
        finding,
        {'id': 'f2', 'fingerprint': 'abc123', 'status': 'open'},
        {'id': 'f3', 'fingerprint': 'abc123', 'status': 'open'},
    ]
    
    result = await engine.correlate_finding(finding, all_findings)
    
    assert result is not None
    assert result.correlation_type == 'exact_fingerprint'
    assert len(result.correlated_findings) == 2
    assert result.confidence_score == 0.95

@pytest.mark.asyncio
async def test_batch_correlation():
    engine = CorrelationEngine(enabled=True)
    
    findings = [
        {'id': f'f{i}', 'fingerprint': 'abc123', 'status': 'open'}
        for i in range(10)
    ]
    
    results = await engine.batch_correlate_findings(findings)
    
    assert len(results) > 0
    assert all(isinstance(r, CorrelationResult) for r in results)
```

## Troubleshooting

### Issue: Correlation engine not running

**Solution**: Check that it's enabled in configuration:

```yaml
modules:
  correlation_engine:
    enabled: true  # Must be true
```

### Issue: No correlations found

**Possible causes**:
1. Findings don't have required fields (fingerprint, file_path, rule_id, etc.)
2. Findings are too dissimilar
3. All findings have status 'closed'

**Solution**: Ensure findings have rich metadata and are in 'open' or 'in_progress' status.

### Issue: Low confidence scores

**Solution**: This is expected for some correlation types. Fingerprint matching has highest confidence (95%), while root cause analysis has lower confidence (60%).

## Backward Compatibility

The correlation engine is **completely backward compatible**:

1. **Disabled by default**: No impact on existing functionality
2. **No database changes**: Works with in-memory data
3. **No API changes**: Existing endpoints unchanged
4. **Optional integration**: Can be added incrementally

## Future Enhancements

Potential improvements for future versions:

1. **Machine Learning**: Train ML models on historical correlations
2. **Persistent Storage**: Store correlations in database
3. **Real-time Updates**: Update correlations as findings change
4. **Custom Strategies**: Allow users to define custom correlation rules
5. **Correlation Visualization**: Graph-based visualization of correlations
6. **Feedback Loop**: Learn from user feedback on correlations

## References

- Original implementation: `WIP/code/enterprise_legacy/src/services/correlation_engine.py`
- Migration plan: `WIP_MIGRATION_PLAN.md`
- Configuration: `config/fixops.overlay.yml`
