# FixOps Safe Architecture Analysis

## Executive Summary

This document analyzes the current FixOps architecture to identify areas requiring deterministic, explainable risk fusion, bounded attack-path analysis, policy/evidence upgrades, and reproducible builds.

## Current Architecture Overview

### CLI Layer
- **fixops_sbom.py**: Normalizes SBOM inputs (CycloneDX/SPDX) and generates quality reports
- **fixops_risk.py**: Computes composite risk scores using EPSS/KEV feeds
- **fixops_provenance.py**: Generates and verifies SLSA v1 attestations
- **fixops_repro.py**: Verifies reproducible builds against reference digests
- **fixops_ci.py**: Orchestrates supply-chain workflows (evidence bundling)

### Core Processing Modules

#### lib4sbom/normalizer.py
- **Current State**: Normalizes SBOM components from multiple formats
- **Non-Deterministic Issues**:
  - Uses `datetime.now()` for timestamps (not seeded)
  - Component ordering relies on dict iteration (Python 3.7+ guarantees insertion order, but sources may vary)
  - JSON output uses `sort_keys=True` (good) but metadata generation time varies
- **Missing**: Schema validation, strict mode enforcement

#### risk/scoring.py
- **Current State**: Computes risk scores using EPSS, KEV, version lag, and exposure
- **Non-Deterministic Issues**:
  - Uses `datetime.now()` for report timestamps
  - Component ordering is sorted by ID (good)
  - Weights are configurable but not explicitly logged in all outputs
- **Missing**: Offline-first behavior documentation, calibration framework

#### risk/feeds/epss.py & kev.py
- **Current State**: Fetches EPSS/KEV feeds with JSON caching
- **Offline Behavior**: Falls back to JSON cache if network fails (good)
- **Missing**: Explicit "offline mode" flag, stale feed warnings

#### services/graph/graph.py
- **Current State**: Provenance graph using SQLite + NetworkX
- **Non-Deterministic Issues**:
  - Node/edge iteration order depends on NetworkX internals
  - No stable export format for debugging
- **Missing**: Reachability analysis, exposure-based attack paths

#### services/evidence/packager.py
- **Current State**: Thin wrapper around evidence.packager
- **Missing**: PSL rule evaluation, industry score inclusion, digest verification

#### services/repro/verifier.py
- **Current State**: Executes build plans and compares digests
- **Non-Deterministic Issues**:
  - Build plan doesn't enforce deterministic tar/gzip flags
  - No LC_ALL=C.UTF-8 enforcement in all steps
- **Missing**: Reference checksum seeding workflow

### Configuration

#### config/policy.yml
- **Current State**: Simple threshold-based policy (risk, SBOM quality, repro, provenance)
- **Missing**: PSL-based explainable rules, overrides, coverage requirements

#### build/plan.yaml
- **Current State**: Basic tar/gzip build plan
- **Non-Deterministic Issues**:
  - Missing GZIP=-n flag
  - Missing --sort=name, --mtime, --owner, --group, --numeric-owner, --pax-option flags
  - No cleanup of non-deterministic directories

## Gaps & Opportunities

### 1. Determinism Gaps
- **Timestamps**: Multiple modules use `datetime.now()` without seeding
- **Sorting**: Some outputs lack stable ordering
- **Build Artifacts**: Tar/gzip not configured for reproducibility
- **JSON Keys**: Most outputs use `sort_keys=True` (good), but need verification

### 2. Offline-First Gaps
- **Network Calls**: EPSS/KEV feeds have fallback but no explicit offline mode
- **Error Handling**: Network failures log warnings but don't clearly indicate offline operation
- **Feed Staleness**: No detection or warnings for stale feeds

### 3. Explainability Gaps
- **Risk Scoring**: Weights are shown but not tied to specific policy rules
- **Industry Standards**: CVSS/EPSS/KEV data exists but not always surfaced alongside FixOps scores
- **Decision Rationale**: No structured "reasons" field explaining why a verdict was reached

### 4. Policy & Evidence Gaps
- **Schema Validation**: No JSON schemas for facts (CVE, SARIF, SBOM)
- **PSL Integration**: No policy specification language for explainable rules
- **Evidence Manifest**: Bundles don't include digests of all inputs or PSL rule hits
- **Industry Scores**: Evidence doesn't explicitly show CVSS/EPSS/KEV alongside FixOps scores

### 5. Attack-Path Gaps
- **Reachability**: No analysis of which components are reachable from internet/public/partner/internal
- **Graph Export**: No stable JSON export for debugging
- **Exposure Tags**: Exist in risk scoring but not used for bounded attack-path analysis

### 6. Reproducible Build Gaps
- **Build Plan**: Missing deterministic tar/gzip flags
- **Environment**: LC_ALL=C.UTF-8 set in plan but not enforced in verifier
- **Seeding**: No workflow for generating reference .sha256 files
- **Cleanup**: No pre-build cleanup of non-deterministic directories

## Implementation Strategy

### Phase A: Data Contracts + Policy Intents
1. Create `docs/DATA_CONTRACTS.md` defining minimal fields for SBOM/SARIF/CVE facts
2. Add JSON schemas in `docs/schemas/` for validation
3. Update `config/policy.yml` with PSL-style rules (coverage, risk, repro, provenance, overrides)

### Phase B: Deterministic Ingestion
1. Update `lib4sbom/normalizer.py`:
   - Use seeded timestamps (FIXOPS_TEST_SEED)
   - Canonicalize component fields (default blanks, canonical purl, lower-case licenses)
   - Sort components by (purl, name, version)
   - Add `--strict-schema` flag for validation
2. Create `core/sarif_canon.py`:
   - Normalize SARIF paths, tool names, rule IDs
   - Sort findings by (rule_id, file_path, line_number)
   - Stable JSON key ordering

### Phase C: PSL Fusion (Explainable Policy)
1. Create `policy/psl/bundle.psl` with soft rules:
   - HighCVSS: CVSS >= 9 → WARN
   - LikelyExploit: EPSS > 0.5 → WARN
   - Coverage: coverage_percent < 80 → WARN
   - ReproMatch: repro.match == false → WARN
2. Create lightweight PSL shim in `policy/psl_shim.py` (pure Python)
3. Update `cli/fixops_ci.py` evidence bundling:
   - Build PSL facts (CVSS, EPSS, KEV, Affects, Patched, Coverage, Provenance, ReproMatch)
   - Evaluate rules → policy_status + reasons
   - Include industry scores + FixOps reasons in manifest

### Phase D: Risk Scoring Offline + Calibration
1. Update `risk/feeds/epss.py` and `risk/feeds/kev.py`:
   - Add `--offline` flag to skip network calls
   - Load local `data/feeds/*.json|csv` if offline
   - Single concise warning if offline
2. Update `risk/scoring.py`:
   - Ensure stable component ordering
   - Include weights in all outputs
   - Add optional conformal calibration stub (if `analysis/calibration/*` exists)

### Phase E: Bounded Attack-Path (Reachability MVP)
1. Update `services/graph/graph.py`:
   - Keep NetworkX fallback
   - Ensure stable node IDs/edge order
   - Add `is_reachable(component)` fact based on exposure tags
   - Add `export_json(path)` for stable debug output
2. Update `scripts/graph_worker.py` (if exists) to use exposure tags

### Phase F: Evidence Bundling
1. Update `services/evidence/packager.py`:
   - Verify presence of each input file
   - Hash all inputs and include digests in manifest
   - Include `metrics.policy` + fired PSL rules
   - Never hide industry scores (CVSS/EPSS/KEV)

### Phase G: Reproducible Build Verification
1. Update `build/plan.yaml`:
   - Add deterministic tar/gzip flags:
     ```yaml
     steps:
       - run: |
           mkdir -p dist
           rm -rf source/{dist,artifacts,analysis,reports,tmp}
           GZIP=-n tar --sort=name --mtime='UTC 2023-01-01' \
             --owner=0 --group=0 --numeric-owner \
             --pax-option=delete=atime,delete=ctime,exthdr.name=%d/PaxHeaders/%f \
             -czf dist/fixops-{tag}.tar.gz -C source .
     ```
2. Update `services/repro/verifier.py`:
   - Force LC_ALL=C.UTF-8 in all steps
   - Support `expected_digest_file` (.sha256) or `reference_artifact`
   - Clear error if no reference available
3. Create `scripts/repro_seed.sh` to generate reference .sha256 files

## Quick Map: Where to Add Features

| Feature | Primary Location | Secondary Locations |
|---------|-----------------|---------------------|
| PSL Rules | `policy/psl/bundle.psl` | `policy/psl_shim.py`, `cli/fixops_ci.py` |
| Reachability | `services/graph/graph.py` | `risk/scoring.py` (exposure tags) |
| Repro Hardening | `build/plan.yaml` | `services/repro/verifier.py`, `scripts/repro_seed.sh` |
| Offline Feeds | `risk/feeds/*.py` | `cli/fixops_risk.py` (--offline flag) |
| Schema Validation | `docs/schemas/*.json` | `lib4sbom/normalizer.py` (--strict-schema) |
| Evidence Digests | `services/evidence/packager.py` | `cli/fixops_ci.py` (bundle command) |
| Deterministic SBOM | `lib4sbom/normalizer.py` | `core/sarif_canon.py` |

## Backward Compatibility Notes

All changes are additive:
- New CLI flags are optional (--strict-schema, --offline, --show-weights)
- Existing CLI commands work unchanged
- Policy file is extended, not replaced
- Evidence manifest gains new fields but retains existing structure
- Build plan is enhanced but existing plans still work

## Testing Strategy

1. **Determinism Tests**: Run twice, compare digests (SBOM, risk, evidence, dist/*.tar.gz)
2. **Offline Tests**: Disable network, verify local feed fallback
3. **Policy Tests**: Verify PSL rules fire correctly (coverage < 80 → WARN)
4. **Reachability Tests**: Verify exposure tags produce consistent reachability facts
5. **Repro Tests**: Seed .sha256, verify match=true

## Success Criteria

1. ✅ Consecutive runs produce identical digests for all outputs
2. ✅ Policy evaluation includes industry scores + FixOps reasons + PSL rule hits
3. ✅ Offline mode works with local feeds
4. ✅ Reachability facts present in graph
5. ✅ Reproducible builds match reference checksums
6. ✅ No breaking changes to existing CLI commands

## Next Steps

Proceed with phased implementation as outlined above, starting with Phase A (Data Contracts + Policy Intents).
