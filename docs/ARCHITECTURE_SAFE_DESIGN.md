# FixOps Safe Architecture Design

## Overview

This document describes the FixOps architecture with emphasis on deterministic, explainable risk fusion, bounded attack-path analysis, policy/evidence upgrades, and reproducible builds.

## Core Principles

### 1. Determinism First
All outputs must be reproducible given the same inputs:
- Sorted inputs (components, vulnerabilities, findings)
- Fixed seeds for timestamps (`FIXOPS_TEST_SEED`)
- Stable JSON key ordering (`sort_keys=True`)
- Reproducible tar/gzip (`GZIP=-n`, `--sort=name`, `--mtime`)

### 2. Standards Beside FixOps
Industry-standard scores always accompany FixOps scores:
- **CVSS** (Common Vulnerability Scoring System) from NVD
- **EPSS** (Exploit Prediction Scoring System) from FIRST.org
- **KEV** (Known Exploited Vulnerabilities) from CISA

FixOps scores provide additional context but never replace industry standards.

### 3. Offline First
Core processing works without mandatory network calls:
- Local feed fallback (`data/feeds/*.json|csv`)
- Single concise warning if offline
- Stale feed detection (warn if > 7 days old)
- Conservative mode when feeds unavailable

### 4. Decision Support Only
Customers decide; FixOps advises:
- Structured reasons for every verdict
- Explainable policy rules (PSL)
- Confidence scores
- Evidence trails

### 5. Backward Compatible
No breaking changes to existing CLIs or APIs:
- New flags are optional
- Existing commands work unchanged
- Policy file extended, not replaced
- Evidence manifest gains fields but retains structure

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                     FixOps CLI Layer                         │
├─────────────────────────────────────────────────────────────┤
│  fixops-sbom    │  fixops-risk  │  fixops-provenance  │     │
│  fixops-repro   │  fixops-ci    │  (evidence bundling)│     │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                  Deterministic Ingestion                     │
├─────────────────────────────────────────────────────────────┤
│  lib4sbom/normalizer.py  │  core/sarif_canon.py            │
│  • Canonical purl        │  • Normalized paths              │
│  • Sorted components     │  • Sorted findings               │
│  • Stable timestamps     │  • Mapped severities             │
│  • Schema validation     │  • CWE/CVSS extraction           │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                    Risk Scoring Engine                       │
├─────────────────────────────────────────────────────────────┤
│  risk/scoring.py                                             │
│  • EPSS (exploit probability)                                │
│  • KEV (known exploited)                                     │
│  • Version lag                                               │
│  • Exposure factor (internet/public/partner/internal)       │
│  • Weights: epss=0.5, kev=0.2, version_lag=0.2, exposure=0.1│
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                  Offline Feed Management                     │
├─────────────────────────────────────────────────────────────┤
│  risk/feeds/epss.py  │  risk/feeds/kev.py                   │
│  • Network fetch     │  • JSON cache fallback               │
│  • Local feeds       │  • Stale detection                   │
│  • Single warning    │  • Conservative mode                 │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│              PSL Policy Evaluation Engine                    │
├─────────────────────────────────────────────────────────────┤
│  policy/psl_shim.py  │  policy/psl/bundle.psl              │
│  • Explainable rules │  • HighCVSS, LikelyExploit          │
│  • Structured reasons│  • KEVPresent, LowCoverage          │
│  • Industry scores   │  • ReproMismatch, Pass              │
│  • Confidence scores │  • InternetExposedHighRisk          │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│              Bounded Attack-Path Analysis                    │
├─────────────────────────────────────────────────────────────┤
│  services/graph/graph.py                                     │
│  • Provenance graph (NetworkX + SQLite)                      │
│  • Reachability facts (exposure tags)                        │
│  • Stable node/edge ordering                                 │
│  • Export JSON for debugging                                 │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                Evidence Bundling & Signing                   │
├─────────────────────────────────────────────────────────────┤
│  services/evidence/packager.py                               │
│  • Verify input presence                                     │
│  • Hash all inputs (SHA256)                                  │
│  • Include metrics.policy + PSL rules                        │
│  • Never hide industry scores                                │
│  • RSA-SHA256 or Ed25519 signatures                          │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│            Reproducible Build Verification                   │
├─────────────────────────────────────────────────────────────┤
│  services/repro/verifier.py  │  build/plan.yaml             │
│  • LC_ALL=C.UTF-8           │  • GZIP=-n                    │
│  • Reference checksums      │  • --sort=name                │
│  • Digest comparison        │  • --mtime='UTC 2023-01-01'   │
│  • Attestation generation   │  • --owner=0 --group=0        │
└─────────────────────────────────────────────────────────────┘
```

## Data Flow

### 1. SBOM Normalization Flow
```
Input: CycloneDX/SPDX SBOM(s)
  ↓
lib4sbom/normalizer.py
  • Canonicalize components (lowercase, trimmed)
  • Merge duplicates by (purl, version, hash)
  • Sort by (purl, name, version)
  • Validate schema (optional --strict-schema)
  ↓
Output: artifacts/sbom/normalized.json
  • Stable component ordering
  • Validation errors logged
  • Seeded timestamp (FIXOPS_TEST_SEED)
```

### 2. Risk Scoring Flow
```
Input: normalized.json + EPSS/KEV feeds
  ↓
risk/scoring.py
  • Load feeds (network or local fallback)
  • For each component vulnerability:
    - EPSS score (exploit probability)
    - KEV status (known exploited)
    - Version lag (days behind patch)
    - Exposure factor (internet/public/partner/internal)
  • Weighted composite score
  ↓
Output: artifacts/risk.json
  • Components sorted by ID
  • Weights included
  • Industry scores present (CVSS, EPSS, KEV)
```

### 3. Policy Evaluation Flow
```
Input: SBOM quality + risk + repro + provenance
  ↓
policy/psl_shim.py
  • Build facts:
    - coverage_percent, fixops_risk, cvss, epss, kev
    - repro_match, attestation_count, exposure
  • Evaluate rules (PSL):
    - CriticalKEVUnpatched → FAIL
    - HighCVSS → WARN
    - LowCoverage → WARN
    - Pass → PASS
  ↓
Output: policy evaluation
  • policy_status: PASS|WARN|FAIL
  • rules_fired: [rule names]
  • reasons: [structured explanations]
  • industry_scores: {cvss, epss, kev}
```

### 4. Evidence Bundling Flow
```
Input: All artifacts + policy evaluation
  ↓
services/evidence/packager.py
  • Verify file presence
  • Hash each input (SHA256)
  • Include policy status + reasons
  • Include industry scores
  • Sign manifest (RSA-SHA256)
  ↓
Output: evidence/bundle-{tag}.tar.gz
  • MANIFEST.yaml (signed)
  • All input files
  • Digests verified
```

### 5. Reproducible Build Flow
```
Input: Source tree + build/plan.yaml
  ↓
services/repro/verifier.py
  • Clean non-deterministic dirs
  • Set LC_ALL=C.UTF-8, TZ=UTC
  • Execute deterministic tar/gzip
  • Compute SHA256
  • Compare to reference
  ↓
Output: artifacts/repro/attestations/{tag}.json
  • match: true|false
  • generated_digest: {sha256}
  • reference_digest: {sha256}
  • verified_at: ISO8601
```

## PSL Rule Evaluation

### Rule Priority (Highest to Lowest)
1. **FAIL Rules** (block release):
   - `CriticalKEVUnpatched`: KEV + CVSS ≥ 9 + no patch
   - `CriticalRiskScore`: FixOps risk > 85
   - `VeryLowCoverage`: Coverage < 60%
   - `ReproMismatch`: Build verification failed

2. **WARN Rules** (advisory):
   - `HighCVSS`: CVSS ≥ 9.0
   - `LikelyExploit`: EPSS > 0.5
   - `KEVPresent`: In CISA KEV catalog
   - `LowCoverage`: Coverage < 80%
   - `HighRiskScore`: FixOps risk > 70
   - `MissingProvenance`: No attestations
   - `InternetExposedHighRisk`: Internet + risk > 60

3. **PASS Rules**:
   - `Pass`: Coverage ≥ 80% + risk ≤ 70 + repro match + attestations ≥ 1

### Rule Evaluation Logic
```python
facts = {
    "cvss": 9.8,
    "epss": 0.95,
    "kev": True,
    "patched": False,
    "coverage_percent": 85.5,
    "fixops_risk": 75.5,
    "repro_match": True,
    "attestation_count": 3,
    "exposure": "internet"
}

evaluation = evaluate_policy(facts)
# {
#   "policy_status": "FAIL",
#   "rules_fired": ["CriticalKEVUnpatched", "HighCVSS", "KEVPresent"],
#   "reasons": [
#     "Critical KEV vulnerability without available patch",
#     "Critical CVSS score (>= 9.0) detected",
#     "Vulnerability in CISA Known Exploited Vulnerabilities catalog"
#   ],
#   "industry_scores": {"cvss": 9.8, "epss": 0.95, "kev": True}
# }
```

## Determinism Guarantees

### Timestamps
- Use `FIXOPS_TEST_SEED` environment variable
- Format: `2025-10-19T12:00:00Z`
- All modules respect this seed:
  - `lib4sbom/normalizer.py::_now()`
  - `risk/scoring.py::_now()`
  - `core/sarif_canon.py::_now()`

### Sorting
- **Components**: `(purl, name, version)`
- **Vulnerabilities**: `(cve)`
- **Findings**: `(rule_id, file_path, line_number)`
- **Rules**: `(rule_name)`
- **JSON keys**: Always alphabetical

### Hashing
- **Algorithm**: SHA256
- **Format**: Lowercase hex (no prefixes)
- **Inputs**: Canonical JSON (sorted keys, no whitespace)

### Build Artifacts
```bash
GZIP=-n tar --sort=name --mtime='UTC 2023-01-01' \
  --owner=0 --group=0 --numeric-owner \
  --pax-option=delete=atime,delete=ctime,exthdr.name=%d/PaxHeaders/%f \
  -czf dist/fixops-{tag}.tar.gz -C source .
```

## Offline-First Behavior

### Feed Management
1. **Network Available**:
   - Fetch EPSS from `https://epss.cyentia.com/epss_scores-current.csv`
   - Fetch KEV from `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
   - Cache to `data/feeds/epss.json` and `data/feeds/kev.json`

2. **Network Unavailable**:
   - Load from local cache
   - Log: "Operating in offline mode with local feeds"
   - Include feed age in metadata

3. **Stale Feeds** (> 7 days):
   - Warn: "Feed is X days old; consider refreshing"
   - Continue processing (conservative mode)
   - Never fail on stale feeds

### CLI Flags
- *(Planned)* `--offline`: Skip network calls, use local feeds only
- `--strict-schema`: Fail on validation errors (default: warn)
- `--show-weights`: Display risk weight breakdown

## Security Considerations

### Cryptographic Signing
- **Algorithms**: RSA-SHA256 or Ed25519
- **Key Management**: Environment variables or HSM/KMS
- **Verification**: Public key fingerprint (SHA256)

### Evidence Integrity
- All inputs hashed (SHA256)
- Manifest signed
- Transparency index for provenance
- Tamper-evident bundles

### Secrets Management
- Never log or expose secrets
- Never commit credentials
- Use environment variables or secret stores

## Testing Strategy

### Determinism Tests
```bash
# Run twice, compare digests
FIXOPS_TEST_SEED="2025-10-19T12:00:00Z" \
  python cli/fixops_sbom.py normalize --in sbom1.json --out run1.json

FIXOPS_TEST_SEED="2025-10-19T12:00:00Z" \
  python cli/fixops_sbom.py normalize --in sbom1.json --out run2.json

sha256sum run1.json run2.json
# Should be identical
```

### Offline Tests
```bash
# Disable network, verify local fallback
unset http_proxy https_proxy
python cli/fixops_risk.py score --sbom normalized.json --out risk.json
# Should use local feeds with warning
```

### Policy Tests
```bash
# Verify PSL rules fire correctly
python -c "
from policy.psl_shim import evaluate_policy
facts = {'coverage_percent': 75}
result = evaluate_policy(facts)
assert 'LowCoverage' in result['rules_fired']
assert result['policy_status'] == 'WARN'
"
```

### Reproducible Build Tests
```bash
# Seed reference checksum
./scripts/repro_seed.sh v1.0.0

# Verify reproducibility
python cli/fixops_repro.py verify --tag v1.0.0 --plan build/plan.yaml \
  --out artifacts/repro/attestations --repo .
# Should match=true
```

## Performance Considerations

### Caching
- EPSS/KEV feeds cached as JSON
- Provenance graph persisted in SQLite
- Evidence bundles compressed (gzip)

### Scalability
- SBOM normalization: O(n) components
- Risk scoring: O(n × m) components × vulnerabilities
- Policy evaluation: O(r) rules (typically < 20)
- Graph queries: O(n + e) nodes + edges

### Memory
- Streaming JSON parsing for large SBOMs
- Chunked file uploads for large artifacts
- Lazy loading of provenance graph

## Future Enhancements

### Conformal Prediction
- Calibration from historical incidents
- Confidence intervals for risk scores
- Drift detection

### Advanced Reachability
- Call graph analysis
- Data flow tracking
- Cloud ingress rules integration

### DBN Integration
- Dynamic Bayesian Networks for temporal risk
- Markov chains for future projection
- Spectral gap analysis

## References

- [SLSA v1 Provenance](https://slsa.dev/spec/v1.0/provenance)
- [SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- [CycloneDX 1.5](https://cyclonedx.org/docs/1.5/)
- [SPDX 2.3](https://spdx.github.io/spdx-spec/v2.3/)
- [CVSS 3.1](https://www.first.org/cvss/v3.1/specification-document)
- [EPSS](https://www.first.org/epss/)
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Reproducible Builds](https://reproducible-builds.org/)
