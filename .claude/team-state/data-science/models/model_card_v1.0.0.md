# ALdeci Risk Scoring Model Card — v1.0.0

## Model Details
- **Name**: ALdeci Vulnerability Risk Scorer
- **Version**: 1.0.0
- **Type**: Gradient Boosted Trees (Regressor)
- **Framework**: scikit-learn 1.8.0
- **Pillar**: V3 (Decision Intelligence)
- **Date**: 2026-03-01
- **Maintained by**: data-scientist agent

## Intended Use
- **Primary**: Risk-score vulnerabilities (0-100) for triage prioritization in Step 7 of the CTEM Brain Pipeline
- **Secondary**: Priority classification (P0-P4, FP) based on risk score thresholds
- **Users**: Brain Pipeline, Security Analysts, Triage Dashboard UI
- **Not intended for**: Standalone vulnerability assessment without human review

## Training Data
- **Source**: Golden regression dataset (`data/golden_regression_cases.json`)
- **Size**: 65 cases
- **Categories**: Critical exploitable, High severity, Medium severity, Low noise, False positives, Chain exploits, Edge cases
- **Data hash**: 132a8cd196472e92
- **Random seed**: 42

## Features (Input)
| Feature | Type | Range | Importance |
|---------|------|-------|------------|
| asset_criticality | float | 0-1 | 0.6252 |
| epss_score | float | 0-1 | 0.2527 |
| network_exposure | ordinal | 0-1 | 0.0639 |
| in_kev | binary | 0-1 | 0.0227 |
| exploit_maturity | ordinal | 0-1 | 0.0163 |
| cvss_score | float | 0-1 | 0.0112 |
| reachable | binary | 0-1 | 0.0061 |
| exploit_available | binary | 0-1 | 0.0020 |
| has_chain | binary | 0-1 | 0.0000 |

## Performance Metrics
| Metric | Value |
|--------|-------|
| MAE | 0.4465 |
| RMSE | 0.6433 |
| R² | 0.9996 |
| Within-Range % | 1.0 |
| CV R² scores | [0.6197, 0.9037, 0.81, 0.9531, 0.8613] |

### Priority Classification
| Priority | Precision | Recall | F1 |
|----------|-----------|--------|----|
| P0 | 1.0 | 0.9722 | 0.9859 |
| P1 | 0.8889 | 0.8 | 0.8421 |
| P2 | 0.8 | 1.0 | 0.8889 |
| P3 | 1.0 | 0.5 | 0.6667 |
| P4 | 0.3333 | 1.0 | 0.5 |
| FP | 1.0 | 1.0 | 1.0 |

## Confidence Intervals
- Method: Bootstrap ensemble (20 models)
- Coverage: 90% CI (5th-95th percentile)
- Reject predictions with CI width > 60 points

## Limitations
1. **Small training set**: 65 cases — model may underperform on unseen CVE categories
2. **Temporal bias**: Training data biased towards 2021-2025 CVEs; emerging attack patterns may not be captured
3. **No code-level features**: Model uses metadata only; does not analyze actual source code
4. **Chain exploit detection**: Chain exploit feature is binary; does not model chain complexity
5. **Asset criticality dependency**: Requires accurate asset_criticality input; garbage-in-garbage-out
6. **No online learning**: Model is static; requires periodic retraining with updated golden dataset

## Ethical Considerations
- Model should not be used as sole basis for security decisions
- False negatives (missed critical vulns) are more dangerous than false positives
- Model is calibrated to over-predict risk for KEV entries (safety margin)

## Update Policy
- Retrain when golden dataset updated with >5 new cases
- Retrain when validation accuracy drops >5% from baseline
- Model version is bumped for any hyperparameter change
