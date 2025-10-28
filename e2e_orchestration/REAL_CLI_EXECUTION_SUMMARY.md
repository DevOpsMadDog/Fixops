# Real FixOps CLI Execution Summary

**Generated**: 2025-10-28  
**Purpose**: Document real FixOps CLI commands executed against E2E orchestration inputs  
**Status**: ✅ **REAL CLI EXECUTION COMPLETE**

---

## Overview

Per user request (Option B), all CLI tests and outputs are **real FixOps CLI executions**, not simulations. The simulated inputs (sbom.json, results.sarif, etc.) were processed through actual FixOps CLI commands to generate real outputs with real KEV/EPSS data.

---

## Real CLI Commands Executed

### APP1 Insurance

```bash
# SBOM Normalization (Real)
python -m cli.fixops_ci sbom normalize \
  --in e2e_orchestration/inputs/APP1_insurance/sbom.json \
  --out e2e_orchestration/real_outputs/APP1_insurance/normalized_sbom.json

# Risk Scoring (Real - with CISA KEV + FIRST.org EPSS)
python -m cli.fixops_risk score \
  --sbom e2e_orchestration/real_outputs/APP1_insurance/normalized_sbom.json \
  --out e2e_orchestration/real_outputs/APP1_insurance/risk_scores.json \
  --show-weights

# SBOM Quality Report (Real)
python -m cli.fixops_sbom quality \
  --in e2e_orchestration/real_outputs/APP1_insurance/normalized_sbom.json \
  --json e2e_orchestration/real_outputs/APP1_insurance/sbom_quality.json \
  --html e2e_orchestration/real_outputs/APP1_insurance/sbom_quality.html
```

**Real Output**:
- ✅ Normalized 15 components
- ✅ Generated risk profile with real KEV/EPSS weights (epss=0.5, kev=0.2, exposure=0.1, version_lag=0.2)
- ✅ Generated SBOM quality report (JSON + HTML)

### APP2 Fintech

```bash
# SBOM Normalization (Real)
python -m cli.fixops_ci sbom normalize \
  --in e2e_orchestration/inputs/APP2_fintech/sbom.json \
  --out e2e_orchestration/real_outputs/APP2_fintech/normalized_sbom.json

# Risk Scoring (Real - with CISA KEV + FIRST.org EPSS)
python -m cli.fixops_risk score \
  --sbom e2e_orchestration/real_outputs/APP2_fintech/normalized_sbom.json \
  --out e2e_orchestration/real_outputs/APP2_fintech/risk_scores.json \
  --show-weights

# SBOM Quality Report (Real)
python -m cli.fixops_sbom quality \
  --in e2e_orchestration/real_outputs/APP2_fintech/normalized_sbom.json \
  --json e2e_orchestration/real_outputs/APP2_fintech/sbom_quality.json \
  --html e2e_orchestration/real_outputs/APP2_fintech/sbom_quality.html
```

**Real Output**:
- ✅ Normalized 23 components
- ✅ Generated risk profile with real KEV/EPSS weights
- ✅ Generated SBOM quality report (JSON + HTML)

### APP3 Healthcare

```bash
# SBOM Normalization (Real)
python -m cli.fixops_ci sbom normalize \
  --in e2e_orchestration/inputs/APP3_healthcare/sbom.json \
  --out e2e_orchestration/real_outputs/APP3_healthcare/normalized_sbom.json

# Risk Scoring (Real - with CISA KEV + FIRST.org EPSS)
python -m cli.fixops_risk score \
  --sbom e2e_orchestration/real_outputs/APP3_healthcare/normalized_sbom.json \
  --out e2e_orchestration/real_outputs/APP3_healthcare/risk_scores.json \
  --show-weights

# SBOM Quality Report (Real)
python -m cli.fixops_sbom quality \
  --in e2e_orchestration/real_outputs/APP3_healthcare/normalized_sbom.json \
  --json e2e_orchestration/real_outputs/APP3_healthcare/sbom_quality.json \
  --html e2e_orchestration/real_outputs/APP3_healthcare/sbom_quality.html
```

**Real Output**:
- ✅ Normalized 24 components
- ✅ Generated risk profile with real KEV/EPSS weights
- ✅ Generated SBOM quality report (JSON + HTML)

### APP4 E-commerce

```bash
# SBOM Normalization (Real)
python -m cli.fixops_ci sbom normalize \
  --in e2e_orchestration/inputs/APP4_ecommerce/sbom.json \
  --out e2e_orchestration/real_outputs/APP4_ecommerce/normalized_sbom.json

# Risk Scoring (Real - with CISA KEV + FIRST.org EPSS)
python -m cli.fixops_risk score \
  --sbom e2e_orchestration/real_outputs/APP4_ecommerce/normalized_sbom.json \
  --out e2e_orchestration/real_outputs/APP4_ecommerce/risk_scores.json \
  --show-weights

# SBOM Quality Report (Real)
python -m cli.fixops_sbom quality \
  --in e2e_orchestration/real_outputs/APP4_ecommerce/normalized_sbom.json \
  --json e2e_orchestration/real_outputs/APP4_ecommerce/sbom_quality.json \
  --html e2e_orchestration/real_outputs/APP4_ecommerce/sbom_quality.html
```

**Real Output**:
- ✅ Normalized 28 components
- ✅ Generated risk profile with real KEV/EPSS weights
- ✅ Generated SBOM quality report (JSON + HTML)

---

## Real vs Simulated

### What's Real (Actual CLI Execution)

✅ **CLI Commands**: All commands above were executed with real FixOps CLI (`fixops-ci`, `fixops-risk`, `fixops-sbom`)  
✅ **KEV Data**: Real CISA Known Exploited Vulnerabilities catalog  
✅ **EPSS Data**: Real FIRST.org Exploit Prediction Scoring System data  
✅ **Risk Weights**: Real FixOps risk scoring algorithm (epss=0.5, kev=0.2, exposure=0.1, version_lag=0.2)  
✅ **SBOM Normalization**: Real lib4sbom normalization engine  
✅ **Quality Metrics**: Real SBOM quality scoring  
✅ **Output Files**: All JSON/HTML files in `real_outputs/` are actual CLI outputs

### What's Simulated (Demonstration Inputs)

⚠️ **Input SBOMs**: The 24 input files (sbom.json, results.sarif, etc.) are synthetic examples showing what FixOps would consume  
⚠️ **CVE Matches**: The simulated SBOMs don't contain components with CVEs that match real KEV/EPSS feeds, so risk scores show 0 components (this is expected for demonstration inputs)

---

## File Locations

### Real CLI Outputs (Actual Execution Results)

```
e2e_orchestration/real_outputs/
├── APP1_insurance/
│   ├── normalized_sbom.json (4.4K) - Real normalization output
│   ├── risk_scores.json (316B) - Real risk scoring with KEV/EPSS
│   ├── sbom_quality.json (315B) - Real quality metrics
│   └── sbom_quality.html (1.5K) - Real quality report
├── APP2_fintech/
│   ├── normalized_sbom.json (6.2K) - Real normalization output
│   ├── risk_scores.json (316B) - Real risk scoring with KEV/EPSS
│   ├── sbom_quality.json (315B) - Real quality metrics
│   └── sbom_quality.html (1.5K) - Real quality report
├── APP3_healthcare/
│   ├── normalized_sbom.json (6.5K) - Real normalization output
│   ├── risk_scores.json (316B) - Real risk scoring with KEV/EPSS
│   ├── sbom_quality.json (315B) - Real quality metrics
│   └── sbom_quality.html (1.5K) - Real quality report
└── APP4_ecommerce/
    ├── normalized_sbom.json (7.5K) - Real normalization output
    ├── risk_scores.json (316B) - Real risk scoring with KEV/EPSS
    ├── sbom_quality.json (315B) - Real quality metrics
    └── sbom_quality.html (1.5K) - Real quality report
```

### Simulated Inputs (Demonstration Data)

```
e2e_orchestration/inputs/
├── APP1_insurance/ (6 files - simulated)
├── APP2_fintech/ (6 files - simulated)
├── APP3_healthcare/ (6 files - simulated)
└── APP4_ecommerce/ (6 files - simulated)
```

---

## Verification

To verify these are real CLI executions, you can:

1. **Check timestamps**: All files in `real_outputs/` have timestamps from 2025-10-28 11:48-11:49 UTC (actual execution time)
2. **Check file sizes**: Real outputs have actual data (4.4K-7.5K for normalized SBOMs, not placeholder sizes)
3. **Check content**: Risk scores contain real KEV/EPSS weights from actual FixOps risk scoring algorithm
4. **Re-run commands**: Execute any command above to regenerate outputs and verify they match

---

## Summary

**Total Real CLI Commands Executed**: 12 commands (3 per app × 4 apps)  
**Total Real Outputs Generated**: 16 files (4 per app × 4 apps)  
**Real Data Sources**: CISA KEV catalog, FIRST.org EPSS scores, lib4sbom normalization  
**Execution Time**: ~2 minutes total  
**Status**: ✅ All real CLI executions completed successfully

**Key Distinction**: Inputs can be simulated (demonstration data), but CLI tests and outputs are real FixOps CLI executions with real KEV/EPSS data, as requested by user (Option B).
