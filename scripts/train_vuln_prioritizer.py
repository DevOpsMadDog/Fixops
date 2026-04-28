"""
Train vulnerability prioritizer v1.

Data sources:
  - data/cisa_kev.db     — positive labels (known_exploited)
  - data/nvd_cve.db      — cvss_score, cvss_vector, cwe_ids, vuln_status, published
  - data/epss.db         — epss_score, percentile
  - data/exploitdb.db    — public_exploit_count

When NVD/EPSS/ExploitDB local DBs are empty (feeds not yet imported), the script
fetches a representative dataset from EPSS API (which includes CVE IDs with high
exploit probability) and from CISA KEV (1583 real rows already imported).

Output:
  models/vuln_prioritizer_v1.pkl
  docs/ml/vuln_prioritizer_v1_card.md
  .claude/team-state/data-science/models/model_card_v1.md
  .claude/team-state/data-science/models/feature_importance.json
  .claude/team-state/data-science/models/confusion_matrix.json
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import warnings
from datetime import datetime, timezone
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import requests
from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import (
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
    classification_report,
)
from sklearn.model_selection import StratifiedKFold, train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.calibration import CalibratedClassifierCV

warnings.filterwarnings("ignore")

ROOT = Path(__file__).parent.parent
DATA_DIR = ROOT / "data"
MODEL_DIR = ROOT / "models"
DOCS_ML_DIR = ROOT / "docs" / "ml"
TEAM_STATE_DIR = ROOT / ".claude" / "team-state" / "data-science" / "models"

for d in [MODEL_DIR, DOCS_ML_DIR, TEAM_STATE_DIR]:
    d.mkdir(parents=True, exist_ok=True)

RANDOM_SEED = 42
np.random.seed(RANDOM_SEED)

# ---------------------------------------------------------------------------
# Known CWEs that map to OWASP Top-10 / high-risk categories
# ---------------------------------------------------------------------------
TOP_CWES = [
    "CWE-79",   # XSS
    "CWE-89",   # SQLi
    "CWE-22",   # Path traversal
    "CWE-78",   # OS command injection
    "CWE-94",   # Code injection
    "CWE-287",  # Improper auth
    "CWE-306",  # Missing auth
    "CWE-502",  # Deserialization
    "CWE-20",   # Input validation
    "CWE-119",  # Buffer overflow
    "CWE-416",  # Use-after-free
    "CWE-190",  # Integer overflow
]

TOP_VENDORS = [
    "microsoft", "apache", "linux", "google", "cisco", "oracle",
    "adobe", "apple", "mozilla", "nginx", "openssl", "wordpress",
    "vmware", "fortinet", "ivanti", "paloalto", "citrix", "juniper",
    "samsung", "d-link",
]


# ---------------------------------------------------------------------------
# Step 1: Load CISA KEV (ground-truth positive labels)
# ---------------------------------------------------------------------------

def load_kev_labels() -> dict[str, dict]:
    """Return dict cve_id -> {is_kev, vendor_project, date_added, ransomware}."""
    db_path = DATA_DIR / "cisa_kev.db"
    labels: dict[str, dict] = {}
    if db_path.exists():
        con = sqlite3.connect(db_path)
        cur = con.cursor()
        cur.execute(
            "SELECT cve_id, vendor_project, date_added, known_ransomware_use FROM kev_entries"
        )
        for cve_id, vendor, date_added, ransomware in cur.fetchall():
            labels[cve_id.strip().upper()] = {
                "is_kev": 1,
                "vendor_project": (vendor or "").strip().lower(),
                "date_added": date_added or "",
                "ransomware": 1 if (ransomware or "").lower() not in ("unknown", "", "no") else 0,
            }
        con.close()
    print(f"[KEV] Loaded {len(labels)} positive labels from CISA KEV")
    return labels


# ---------------------------------------------------------------------------
# Step 2: Load / fetch EPSS scores
# ---------------------------------------------------------------------------

def load_epss_scores() -> dict[str, tuple[float, float]]:
    """Return dict cve_id -> (epss_score, percentile)."""
    db_path = DATA_DIR / "epss.db"
    scores: dict[str, tuple[float, float]] = {}

    if db_path.exists():
        con = sqlite3.connect(db_path)
        cur = con.cursor()
        cur.execute("SELECT COUNT(*) FROM epss_scores")
        count = cur.fetchone()[0]
        if count > 0:
            cur.execute("SELECT cve_id, epss_score, percentile FROM epss_scores")
            for cve_id, epss, pct in cur.fetchall():
                scores[cve_id.strip().upper()] = (epss or 0.0, pct or 0.0)
            con.close()
            print(f"[EPSS] Loaded {len(scores)} scores from local DB")
            return scores
        con.close()

    # Fetch from FIRST.org API — top 2000 by EPSS score
    print("[EPSS] Local DB empty — fetching from FIRST.org API...")
    try:
        resp = requests.get(
            "https://api.first.org/data/v1/epss",
            params={"order": "!epss", "limit": 2000},
            timeout=30,
        )
        if resp.status_code == 200:
            data = resp.json().get("data", [])
            for row in data:
                cve_id = row.get("cve", "").strip().upper()
                if cve_id:
                    scores[cve_id] = (float(row.get("epss", 0)), float(row.get("percentile", 0)))
            print(f"[EPSS] Fetched {len(scores)} high-EPSS CVEs from API")
        else:
            print(f"[EPSS] API returned {resp.status_code}, using empty scores")
    except Exception as exc:
        print(f"[EPSS] API fetch failed: {exc} — using empty scores")

    # Also cache into DB
    if scores and db_path.exists():
        try:
            con = sqlite3.connect(db_path)
            now = datetime.now(timezone.utc).isoformat()
            con.executemany(
                "INSERT OR IGNORE INTO epss_scores (cve_id, epss_score, percentile, imported_at) VALUES (?,?,?,?)",
                [(k, v[0], v[1], now) for k, v in scores.items()],
            )
            con.commit()
            con.close()
        except Exception:
            pass

    return scores


# ---------------------------------------------------------------------------
# Step 3: Load NVD CVE data
# ---------------------------------------------------------------------------

def load_nvd_data() -> dict[str, dict]:
    """Return dict cve_id -> {cvss_score, cvss_severity, cvss_vector, cwe_ids, vuln_status, published}."""
    db_path = DATA_DIR / "nvd_cve.db"
    nvd: dict[str, dict] = {}

    if db_path.exists():
        con = sqlite3.connect(db_path)
        cur = con.cursor()
        cur.execute("SELECT COUNT(*) FROM nvd_cves")
        count = cur.fetchone()[0]
        if count > 0:
            cur.execute(
                "SELECT cve_id, cvss_score, cvss_severity, cvss_vector, cwe_ids, vuln_status, published FROM nvd_cves"
            )
            for row in cur.fetchall():
                cve_id = (row[0] or "").strip().upper()
                if cve_id:
                    nvd[cve_id] = {
                        "cvss_score": float(row[1] or 0.0),
                        "cvss_severity": (row[2] or "UNKNOWN").upper(),
                        "cvss_vector": row[3] or "",
                        "cwe_ids": row[4] or "",
                        "vuln_status": (row[5] or "").lower(),
                        "published": row[6] or "",
                    }
            con.close()
            print(f"[NVD] Loaded {len(nvd)} CVEs from local DB")
            return nvd
        con.close()

    print("[NVD] Local DB empty — fetching from NVD API...")
    # Fetch recent CVEs (last 120 days) to build a mixed positive/negative dataset
    try:
        from datetime import timedelta
        end = datetime.now(timezone.utc)
        start = end - timedelta(days=120)
        start_str = start.strftime("%Y-%m-%dT%H:%M:%S.000")
        end_str = end.strftime("%Y-%m-%dT%H:%M:%S.000")
        resp = requests.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            params={
                "pubStartDate": start_str,
                "pubEndDate": end_str,
                "resultsPerPage": 2000,
            },
            timeout=45,
            headers={"User-Agent": "ALdeci-ML-Trainer/1.0"},
        )
        if resp.status_code == 200:
            for item in resp.json().get("vulnerabilities", []):
                cve_obj = item.get("cve", {})
                cve_id = cve_obj.get("id", "").strip().upper()
                if not cve_id:
                    continue

                # CVSS v3.1 preferred, fall back to v3.0 then v2
                metrics = cve_obj.get("metrics", {})
                cvss_score, cvss_severity, cvss_vector = 0.0, "UNKNOWN", ""
                for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if key in metrics and metrics[key]:
                        m = metrics[key][0].get("cvssData", {})
                        cvss_score = float(m.get("baseScore", 0.0))
                        cvss_severity = m.get("baseSeverity", "UNKNOWN").upper()
                        cvss_vector = m.get("vectorString", "")
                        break

                cwes = []
                for w in cve_obj.get("weaknesses", []):
                    for d in w.get("description", []):
                        if d.get("value", "").startswith("CWE-"):
                            cwes.append(d["value"])

                nvd[cve_id] = {
                    "cvss_score": cvss_score,
                    "cvss_severity": cvss_severity,
                    "cvss_vector": cvss_vector,
                    "cwe_ids": ",".join(cwes),
                    "vuln_status": cve_obj.get("vulnStatus", "").lower(),
                    "published": cve_obj.get("published", ""),
                }

            print(f"[NVD] Fetched {len(nvd)} CVEs from API")
        else:
            print(f"[NVD] API returned {resp.status_code}")
    except Exception as exc:
        print(f"[NVD] API fetch failed: {exc}")

    return nvd


# ---------------------------------------------------------------------------
# Step 4: Load ExploitDB counts
# ---------------------------------------------------------------------------

def load_exploitdb_counts() -> dict[str, int]:
    """Return dict cve_id -> public_exploit_count."""
    db_path = DATA_DIR / "exploitdb.db"
    counts: dict[str, int] = {}

    if not db_path.exists():
        return counts

    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute("SELECT key, value FROM exploitdb_exploits LIMIT 5")
    sample = cur.fetchall()

    if not sample:
        con.close()
        return counts

    # Try to parse key/value store where key might be cve_id
    for key, value in [("SELECT key, value FROM exploitdb_exploits", None)]:
        try:
            cur.execute("SELECT key, value FROM exploitdb_exploits")
            for k, v in cur.fetchall():
                k_up = k.strip().upper()
                if k_up.startswith("CVE-"):
                    try:
                        counts[k_up] = int(v or 0)
                    except (ValueError, TypeError):
                        counts[k_up] = 1
        except Exception:
            pass
        break

    con.close()
    print(f"[ExploitDB] Loaded {len(counts)} exploit counts")
    return counts


# ---------------------------------------------------------------------------
# Step 5: Feature engineering
# ---------------------------------------------------------------------------

def parse_cvss_vector(vector: str) -> dict[str, int]:
    """Extract AV:N, PR:N, UI:N, S:C, C:H, I:H, A:H flags from CVSS vector."""
    feats = {
        "av_network": 0,      # Attack Vector: Network
        "pr_none": 0,         # Privileges Required: None
        "ui_none": 0,         # User Interaction: None
        "scope_changed": 0,   # Scope: Changed
        "conf_high": 0,       # Confidentiality: High
        "integ_high": 0,      # Integrity: High
        "avail_high": 0,      # Availability: High
    }
    if not vector:
        return feats
    parts = vector.split("/")
    mapping = {
        "AV:N": ("av_network", 1),
        "PR:N": ("pr_none", 1),
        "UI:N": ("ui_none", 1),
        "S:C": ("scope_changed", 1),
        "C:H": ("conf_high", 1),
        "I:H": ("integ_high", 1),
        "A:H": ("avail_high", 1),
    }
    for part in parts:
        if part in mapping:
            k, v = mapping[part]
            feats[k] = v
    return feats


def age_days(published: str) -> float:
    """Days since CVE published date."""
    if not published:
        return 365.0  # default: 1 year
    try:
        pub = datetime.fromisoformat(published.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        return max(0.0, (now - pub).days)
    except Exception:
        return 365.0


def severity_encode(severity: str) -> dict[str, int]:
    """One-hot encode severity."""
    sev = severity.upper()
    return {
        "sev_critical": int(sev == "CRITICAL"),
        "sev_high": int(sev == "HIGH"),
        "sev_medium": int(sev == "MEDIUM"),
        "sev_low": int(sev == "LOW"),
    }


def cwe_one_hot(cwe_ids: str) -> dict[str, int]:
    """One-hot encode top CWEs."""
    present = set((cwe_ids or "").upper().split(","))
    return {f"cwe_{cwe.replace('-', '_')}": int(cwe.upper() in present) for cwe in TOP_CWES}


def vendor_flag(vendor: str) -> int:
    """1 if vendor is in top-20 targeted vendors."""
    v = (vendor or "").lower()
    return int(any(tv in v for tv in TOP_VENDORS))


def build_feature_matrix(
    kev: dict,
    epss: dict,
    nvd: dict,
    exploitdb: dict,
) -> pd.DataFrame:
    """Join all sources and return feature matrix with labels."""

    # Union of all CVE IDs across sources
    all_cves = set(kev.keys()) | set(epss.keys()) | set(nvd.keys()) | set(exploitdb.keys())
    print(f"[Features] Total unique CVEs across all sources: {len(all_cves)}")

    rows = []
    for cve_id in all_cves:
        kev_data = kev.get(cve_id, {})
        epss_score, epss_pct = epss.get(cve_id, (0.0, 0.0))
        nvd_data = nvd.get(cve_id, {})
        exploit_count = exploitdb.get(cve_id, 0)

        # Label: positive if in CISA KEV OR has public exploit
        label = 1 if (kev_data.get("is_kev", 0) == 1 or exploit_count >= 1) else 0

        cvss = float(nvd_data.get("cvss_score", 0.0))
        published = nvd_data.get("published", "")
        vector = nvd_data.get("cvss_vector", "")
        cwe_ids = nvd_data.get("cwe_ids", "")
        severity = nvd_data.get("cvss_severity", "UNKNOWN")
        vuln_status = nvd_data.get("vuln_status", "")
        vendor = kev_data.get("vendor_project", "")
        ransomware = kev_data.get("ransomware", 0)

        row = {
            "cve_id": cve_id,
            "label": label,
            "cvss_base": cvss,
            "epss_score": epss_score,
            "epss_percentile": epss_pct,
            "exploitdb_count": exploit_count,
            "age_days": age_days(published),
            "ransomware": ransomware,
            "is_analyzed": int(vuln_status in ("analyzed", "modified")),
            "vendor_top20": vendor_flag(vendor),
        }
        row.update(severity_encode(severity))
        row.update(cwe_one_hot(cwe_ids))
        row.update(parse_cvss_vector(vector))

        rows.append(row)

    df = pd.DataFrame(rows)
    print(f"[Features] Matrix shape: {df.shape}")
    print(f"[Features] Label distribution: {df['label'].value_counts().to_dict()}")
    return df


# ---------------------------------------------------------------------------
# Step 6: Train
# ---------------------------------------------------------------------------

FEATURE_COLS = [
    "cvss_base", "epss_score", "epss_percentile", "exploitdb_count",
    "age_days", "ransomware", "is_analyzed", "vendor_top20",
    "sev_critical", "sev_high", "sev_medium", "sev_low",
    "av_network", "pr_none", "ui_none", "scope_changed",
    "conf_high", "integ_high", "avail_high",
] + [f"cwe_{c.replace('-', '_')}" for c in TOP_CWES]


def train(df: pd.DataFrame) -> dict:
    X = df[FEATURE_COLS].fillna(0.0).values.astype(np.float32)
    y = df["label"].values

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_SEED, stratify=y
    )

    print(f"[Train] Train size: {len(X_train)}, Test size: {len(X_test)}")
    print(f"[Train] Train positives: {y_train.sum()}, Test positives: {y_test.sum()}")

    # Gradient Boosted classifier with isotonic calibration
    gbc = GradientBoostingClassifier(
        n_estimators=200,
        max_depth=4,
        learning_rate=0.05,
        subsample=0.8,
        min_samples_leaf=20,
        random_state=RANDOM_SEED,
        verbose=1,
    )
    calibrated = CalibratedClassifierCV(gbc, cv=3, method="isotonic")
    calibrated.fit(X_train, y_train)

    y_pred = calibrated.predict(X_test)
    y_prob = calibrated.predict_proba(X_test)[:, 1]

    roc_auc = roc_auc_score(y_test, y_prob)
    f1 = f1_score(y_test, y_pred, zero_division=0)
    precision = precision_score(y_test, y_pred, zero_division=0)
    recall = recall_score(y_test, y_pred, zero_division=0)
    cm = confusion_matrix(y_test, y_pred).tolist()

    print(f"\n[Metrics] ROC-AUC: {roc_auc:.4f}")
    print(f"[Metrics] F1: {f1:.4f}  Precision: {precision:.4f}  Recall: {recall:.4f}")
    print(f"[Metrics] Confusion matrix: {cm}")
    print("\n" + classification_report(y_test, y_pred, target_names=["not_exploited", "exploited"]))

    # Feature importance from the base GBC inside calibrated estimator
    importances = {}
    try:
        base_estimators = calibrated.calibrated_classifiers_
        imp_arrays = [
            est.estimator.feature_importances_
            for est in base_estimators
            if hasattr(est, "estimator") and hasattr(est.estimator, "feature_importances_")
        ]
        if imp_arrays:
            mean_imp = np.mean(imp_arrays, axis=0)
            importances = dict(sorted(
                zip(FEATURE_COLS, mean_imp.tolist()),
                key=lambda x: x[1], reverse=True
            ))
    except Exception as exc:
        print(f"[Train] Feature importance extraction note: {exc}")

    return {
        "model": calibrated,
        "metrics": {
            "roc_auc": round(roc_auc, 4),
            "f1": round(f1, 4),
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "train_size": int(len(X_train)),
            "test_size": int(len(X_test)),
            "train_positives": int(y_train.sum()),
            "test_positives": int(y_test.sum()),
            "total_rows": int(len(df)),
        },
        "confusion_matrix": cm,
        "feature_importance": importances,
        "feature_cols": FEATURE_COLS,
        "random_seed": RANDOM_SEED,
        "trained_at": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Step 7: Save artifacts
# ---------------------------------------------------------------------------

def save_artifacts(result: dict) -> None:
    model_path = MODEL_DIR / "vuln_prioritizer_v1.pkl"
    joblib.dump(
        {
            "model": result["model"],
            "feature_cols": result["feature_cols"],
            "version": "v1",
            "trained_at": result["trained_at"],
            "metrics": result["metrics"],
        },
        model_path,
        compress=3,
    )
    print(f"[Save] Model saved: {model_path}")

    # Feature importance JSON
    fi_path = TEAM_STATE_DIR / "feature_importance.json"
    with open(fi_path, "w") as f:
        json.dump(result["feature_importance"], f, indent=2)

    # Confusion matrix JSON
    cm_path = TEAM_STATE_DIR / "confusion_matrix.json"
    m = result["metrics"]
    cm = result["confusion_matrix"]
    cm_out = {
        "date": result["trained_at"][:10],
        "confusion_matrix": cm,
        "metrics": {
            "roc_auc": m["roc_auc"],
            "f1": m["f1"],
            "precision": m["precision"],
            "recall": m["recall"],
        },
        "labels": ["not_exploited", "exploited"],
    }
    with open(cm_path, "w") as f:
        json.dump(cm_out, f, indent=2)

    # Model card
    m = result["metrics"]
    fi = result["feature_importance"]
    top5 = list(fi.items())[:5] if fi else []
    top5_str = "\n".join(f"  {i+1}. `{k}`: {v:.4f}" for i, (k, v) in enumerate(top5))

    card_content = f"""# Model Card: vuln_prioritizer_v1

## Model Overview
- **Model type**: GradientBoostingClassifier (sklearn) + Isotonic calibration (3-fold CV)
- **Task**: Binary classification — P(exploit) for a CVE
- **Version**: v1
- **Trained**: {result['trained_at']}

## Training Data
| Source | Rows | Role |
|--------|------|------|
| CISA KEV (cisa_kev.db) | 1,583 | Positive labels (known_exploited = 1) |
| EPSS API / epss.db | variable | epss_score, percentile features |
| NVD API / nvd_cve.db | variable | CVSS, CWE, vuln_status, published date |
| ExploitDB (exploitdb.db) | variable | public_exploit_count |

**Total training rows**: {m['total_rows']:,}
**Train / Test split**: 80/20 stratified
**Train positives**: {m['train_positives']:,} / {m['train_size']:,}
**Test positives**: {m['test_positives']:,} / {m['test_size']:,}

## Label Definition
```
label = 1  if  cve_id in CISA_KEV  OR  exploitdb_count >= 1
label = 0  otherwise
```

## Features ({len(FEATURE_COLS)} total)
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
{top5_str if top5_str else "  (not available)"}

## Performance Metrics
| Metric | Value |
|--------|-------|
| ROC-AUC | {m['roc_auc']} |
| F1 | {m['f1']} |
| Precision | {m['precision']} |
| Recall | {m['recall']} |

Confusion matrix (test set):
```
                Predicted NOT  Predicted YES
Actual NOT          {cm[0][0]}             {cm[0][1]}
Actual YES          {cm[1][0]}             {cm[1][1]}
```

## Hyperparameters
```python
GradientBoostingClassifier(
    n_estimators=200,
    max_depth=4,
    learning_rate=0.05,
    subsample=0.8,
    min_samples_leaf=20,
    random_state={result['random_seed']},
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
| v1 | {result['trained_at'][:10]} | Initial gradient-boosted classifier |

## Reproduction
```bash
python scripts/train_vuln_prioritizer.py
# Output: models/vuln_prioritizer_v1.pkl
# Seed: {result['random_seed']}
```
"""

    for card_path in [DOCS_ML_DIR / "vuln_prioritizer_v1_card.md",
                      TEAM_STATE_DIR / "model_card_v1.md"]:
        with open(card_path, "w") as f:
            f.write(card_content)
        print(f"[Save] Model card: {card_path}")

    print(f"\n[Done] ROC-AUC={m['roc_auc']}  F1={m['f1']}  rows={m['total_rows']:,}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=== ALdeci Vuln Prioritizer v1 Training ===\n")
    kev = load_kev_labels()
    epss = load_epss_scores()
    nvd = load_nvd_data()
    exploitdb = load_exploitdb_counts()

    df = build_feature_matrix(kev, epss, nvd, exploitdb)

    if len(df) < 50:
        print(f"[ERROR] Only {len(df)} rows — insufficient for training. "
              "Ensure at least one data source has data.")
        sys.exit(1)

    # Guard: need at least 10 positives and 10 negatives
    pos = df["label"].sum()
    neg = len(df) - pos
    if pos < 10 or neg < 10:
        print(f"[ERROR] Insufficient class balance: {pos} positives, {neg} negatives")
        sys.exit(1)

    result = train(df)
    save_artifacts(result)
