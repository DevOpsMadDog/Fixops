# Model Card: vuln_prioritizer_v1

## Model Overview
- **Model type**: GradientBoostingClassifier (sklearn) + Isotonic calibration (3-fold CV)
- **Task**: Binary classification — P(exploit) for a CVE
- **Version**: v1
- **Trained**: 2026-04-28T10:17:46.177344+00:00

## Training Data
| Source | Rows | Role |
|--------|------|------|
| CISA KEV (cisa_kev.db) | 1,583 | Positive labels (known_exploited = 1) |
| EPSS API / epss.db | variable | epss_score, percentile features |
| NVD API / nvd_cve.db | variable | CVSS, CWE, vuln_status, published date |
| ExploitDB (exploitdb.db) | variable | public_exploit_count |

**Total training rows**: 4,948
**Train / Test split**: 80/20 stratified
**Train positives**: 1,266 / 3,958
**Test positives**: 317 / 990

## Label Definition
```
label = 1  if  cve_id in CISA_KEV  OR  exploitdb_count >= 1
label = 0  otherwise
```

## Features (31 total)
| Feature | Description |
|---------|-------------|
| cvss_base | NVD CVSS base score (0-10) |
| epss_score | FIRST.org EPSS probability (0-1) |
| epss_percentile | EPSS percentile rank |
| exploitdb_count | Number of public exploits in ExploitDB |
| age_days | Days since CVE published |
| ransomware | CISA KEV ransomware flag |
| vendor_top20 | Vendor in top-20 targeted list |
| sev_* | One-hot: CRITICAL/HIGH/MEDIUM/LOW |
| cwe_* | One-hot: top-12 CWEs (OWASP-aligned) |
| av_network / pr_none / ui_none | CVSS vector decomposition |
| scope_changed / conf_high / integ_high / avail_high | CVSS impact flags |

## Top Feature Importances
  1. `vendor_top20`: 0.7202
  2. `ransomware`: 0.1155
  3. `epss_score`: 0.0912
  4. `epss_percentile`: 0.0459
  5. `cvss_base`: 0.0272

## Performance Metrics
| Metric | Value |
|--------|-------|
| ROC-AUC | 0.9362 |
| F1 | 0.8448 |
| Precision | 0.9873 |
| Recall | 0.7382 |

Confusion matrix (test set):
```
                Predicted NOT  Predicted YES
Actual NOT          670             3
Actual YES          83             234
```

## Hyperparameters
```python
GradientBoostingClassifier(
    n_estimators=200,
    max_depth=4,
    learning_rate=0.05,
    subsample=0.8,
    min_samples_leaf=20,
    random_state=42,
)
CalibratedClassifierCV(cv=3, method="isotonic")
```

## Limitations
1. **No reachability signal**: model does not consider whether vulnerable code is reachable in the application.
2. **Temporal leakage risk**: CVEs already in CISA KEV at training time are labeled positive; model may not generalize to novel 0-days.
3. **Vendor coverage**: TOP_VENDORS list covers 20 vendors — attacker-targeted IoT/OT vendors may be underrepresented.
4. **EPSS lag**: EPSS scores lag real-world exploitation by days-weeks.
5. **Calibration**: Isotonic calibration over 3-fold CV; probabilities are reliable for relative ranking but should not be used as absolute probabilities without further validation.

## Intended Use
- CTEM+ Brain Pipeline Step 7 (Risk Scoring): replace heuristic CVSS-only formula with ML-predicted P(exploit).
- Input to ALdeci Vulnerability Prioritization API at `POST /api/v1/ml/vuln-prioritizer/predict`.
- NOT intended for: legal/compliance verdicts, automated remediation without human review.

## Versioning
| Version | Date | Change |
|---------|------|--------|
| v1 | 2026-04-28 | Initial gradient-boosted classifier |

## Reproduction
```bash
python scripts/train_vuln_prioritizer.py
# Output: models/vuln_prioritizer_v1.pkl
# Seed: 42
```
