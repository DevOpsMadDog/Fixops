# FixOps Learning & Adaptation Capabilities

## Overview

FixOps now includes sophisticated learning and adaptation capabilities that enable it to become smarter with each scan, correlate findings across runs, and provide intelligent prioritization based on historical patterns.

## Key Features

### 1. Identity Resolution & Stable IDs

Every finding is now enriched with stable identities for smart correlation:

- **org_id**: Organization/tenant ID for multi-tenant isolation
- **app_id**: Application identifier (auto-resolved from file paths, resource IDs)
- **component_id**: Component/service identifier (auto-resolved from paths, packages)
- **asset_id**: Unique asset identifier
- **correlation_key**: Deterministic hash for cross-run matching
- **fingerprint**: Content-based fingerprint for similarity search

### 2. Vector Store for Evidence Storage

All findings are stored in a local file-backed vector store using TF-IDF embeddings:

- **Similarity Search**: Find similar findings from previous runs
- **Pattern Recognition**: Identify recurring vulnerabilities
- **No External Dependencies**: Uses local filesystem storage
- **Multi-tenant**: Isolated by org_id/app_id

**Storage Location**: `data/vector/{org_id}/{app_id}/`

### 3. Run History Store

SQLite-based persistence of all findings and outcomes:

- **Historical Tracking**: Track findings across multiple runs
- **Outcome Recording**: Record whether findings were fixed, ignored, or exploited
- **Learning Foundation**: Enables weight recalibration based on outcomes

**Storage Location**: `data/history/{org_id}/{app_id}.db`

### 4. Historical Correlation (Step 4.5)

New pipeline step that correlates current findings with historical data:

- **Similarity Matching**: Find top-3 similar findings from history
- **Risk Pattern Analysis**: Identify recurring high-risk patterns
- **Component Tracking**: Track which components have recurring issues

**Output**: `artifacts/correlations.json`

### 5. Learning Report

Comprehensive report showing learning status and recommendations:

```json
{
  "run_id": "20251029-133900",
  "org_id": "demo-org",
  "app_id": "enterprise-platform",
  "historical_runs": 2,
  "historical_findings": 15,
  "correlations_found": 15,
  "vector_store_size": 15,
  "learning_status": "active",
  "recommendations": [...]
}
```

**Output**: `artifacts/learning_report.json`

## Usage

### Basic Usage with Learning

```bash
python scripts/demo_orchestrator.py \
  --snyk samples/snyk_sample.json \
  --tenable samples/tenable_sample.csv \
  --wiz samples/wiz_sample.json \
  --design inputs/demo/design.csv \
  --overlay configs/overlays/client.yaml \
  --org-id demo-org \
  --app-id enterprise-platform \
  --out artifacts/run_manifest.json
```

### Multi-Tenant Usage

```bash
# Client A
python scripts/demo_orchestrator.py \
  --org-id client-a \
  --app-id payment-api \
  ...

# Client B (isolated from Client A)
python scripts/demo_orchestrator.py \
  --org-id client-b \
  --app-id payment-api \
  ...
```

### Component Mapping

Customize component resolution by editing `configs/overlay_mappings.yaml`:

```yaml
apps:
  - app_id: "payment-api"
    match:
      file_path: ".*/payment/.*"

components:
  - component_id: "payment-service"
    match:
      file_path: ".*/payment.*"
```

## Architecture

### Identity Resolution Flow

```
Finding → IdentityResolver
  ├─ resolve_app_id() → Extract from file_path/resource_id
  ├─ resolve_component_id() → Extract from file_path/package
  ├─ resolve_asset_id() → Build from resource_id/file_path
  ├─ compute_correlation_key() → Hash(category|cve|app|component|location)
  └─ compute_fingerprint() → Hash(title|description|cve|rule)
```

### Vector Store Flow

```
Finding → VectorStore
  ├─ Tokenize content (title + description)
  ├─ Compute TF-IDF vector
  ├─ Store document with metadata
  └─ Query for similar findings (cosine similarity)
```

### History Store Flow

```
Run → RunHistoryStore
  ├─ Record run metadata (org_id, app_id, timestamp)
  ├─ Record all findings with correlation_keys
  ├─ Query historical findings by org/app
  └─ Update outcomes for learning
```

## Pipeline Steps (Updated)

1. **Ingestion & Normalization** - Load findings from 9 scanners
2. **Identity Resolution** (NEW) - Resolve org/app/component IDs and correlation keys
3. **Business Context Overlay** - Apply business context from design.csv
4. **Bayesian/Markov Risk Scoring** - Compute posterior risk scores
5. **MITRE ATT&CK Correlation** - Map to MITRE techniques
6. **Historical Correlation & Learning** (NEW) - Find similar findings from history
7. **LLM Explainability** - Generate natural language explanations
8. **Evidence & Attestation** - Generate SLSA provenance

## Future Enhancements

### Weight Recalibration (Planned)

Adjust Bayesian feature weights based on historical outcomes:

```python
# Planned implementation
from core.services.calibrator import WeightCalibrator

calibrator = WeightCalibrator(history_store)
updated_weights = calibrator.recalibrate(
    org_id="demo-org",
    app_id="enterprise-platform",
    outcomes=["fixed", "exploited", "false_positive"]
)
```

### Knowledge Graph (Planned)

Build relationship graph for richer explanations:

```
App → Component → Asset → Finding → CVE → CWE → MITRE → Control
```

### Reinforcement Learning (Deferred)

Use RL to optimize decision policies based on outcomes.

## Benefits

### 1. Reduces False Positives Over Time

By tracking which findings were false positives, FixOps learns to deprioritize similar patterns.

### 2. Identifies Recurring Patterns

Correlations show which vulnerabilities keep appearing, indicating systemic issues.

### 3. Component-Level Risk Tracking

Track which components have the most recurring issues for targeted remediation.

### 4. Multi-Tenant Isolation

Each organization's learning is isolated, ensuring privacy and relevance.

### 5. No External Dependencies

All learning happens locally with file-backed storage - no cloud services required.

## Data Privacy

- **Local Storage**: All data stored locally in `data/` directory
- **Multi-Tenant**: Isolated by org_id for privacy
- **No Cloud**: No external API calls or cloud storage
- **Portable**: Can be backed up, migrated, or deleted easily

## Performance

- **Vector Store**: O(n) similarity search (acceptable for <10K findings per org/app)
- **History Store**: SQLite with indexes for fast queries
- **Storage**: ~1KB per finding, ~1MB per 1000 findings

## Troubleshooting

### No Historical Correlations Found

**Cause**: First run (cold start)
**Solution**: Run multiple scans to build historical baseline

### Low Similarity Scores

**Cause**: Findings are genuinely different
**Solution**: This is expected - not all findings should correlate

### Component ID = "unknown"

**Cause**: No matching pattern in overlay_mappings.yaml
**Solution**: Add patterns for your file paths/resources

## Examples

### Correlation Output

```json
{
  "finding_id": "snyk-SNYK-JS-LODASH-567746",
  "correlation_key": "b8667a3cbd4a1dca",
  "similar_findings": [
    {
      "doc_id": "demo-org/enterprise-platform/b8667a3cbd4a1dca",
      "similarity": 1.0,
      "metadata": {
        "org_id": "demo-org",
        "app_id": "unknown",
        "component_id": "unknown",
        "correlation_key": "b8667a3cbd4a1dca",
        "risk_tier": "LOW",
        "cve_id": "CVE-2020-8203"
      }
    }
  ]
}
```

### Learning Report Output

```json
{
  "run_id": "20251029-133900",
  "org_id": "demo-org",
  "app_id": "enterprise-platform",
  "historical_runs": 2,
  "historical_findings": 15,
  "correlations_found": 15,
  "vector_store_size": 15,
  "learning_status": "active"
}
```

## References

- Identity Resolution: `core/services/identity.py`
- Vector Store: `core/services/vector_store.py`
- History Store: `core/services/history.py`
- Demo Orchestrator: `scripts/demo_orchestrator.py`
- Component Mappings: `configs/overlay_mappings.yaml`
