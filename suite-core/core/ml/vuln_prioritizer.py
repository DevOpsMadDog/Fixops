"""
ML Vulnerability Prioritizer — inference wrapper.

Loads models/vuln_prioritizer_v1.pkl and exposes:
  predict(cve_id)           -> PredictionResult
  predict_features(features) -> PredictionResult (raw feature dict)
  get_features_for_cve(cve_id) -> dict  (join all 4 DBs)

Brain Pipeline Step 7 integration: replace heuristic CVSS-only scoring with
calibrated P(exploit) from the gradient-boosted classifier.
"""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np

logger = logging.getLogger(__name__)

ROOT = Path(__file__).parent.parent.parent.parent  # repo root
MODEL_PATH = ROOT / "models" / "vuln_prioritizer_v1.pkl"
DATA_DIR = ROOT / "data"

# Top CWEs matching training script
TOP_CWES = [
    "CWE-79", "CWE-89", "CWE-22", "CWE-78", "CWE-94", "CWE-287",
    "CWE-306", "CWE-502", "CWE-20", "CWE-119", "CWE-416", "CWE-190",
]

TOP_VENDORS = [
    "microsoft", "apache", "linux", "google", "cisco", "oracle",
    "adobe", "apple", "mozilla", "nginx", "openssl", "wordpress",
    "vmware", "fortinet", "ivanti", "paloalto", "citrix", "juniper",
    "samsung", "d-link",
]

FEATURE_COLS = [
    "cvss_base", "epss_score", "epss_percentile", "exploitdb_count",
    "age_days", "ransomware", "is_analyzed", "vendor_top20",
    "sev_critical", "sev_high", "sev_medium", "sev_low",
    "av_network", "pr_none", "ui_none", "scope_changed",
    "conf_high", "integ_high", "avail_high",
] + [f"cwe_{c.replace('-', '_')}" for c in TOP_CWES]


@dataclass
class PredictionResult:
    cve_id: str
    exploit_probability: float          # calibrated P(exploit) in [0, 1]
    risk_tier: str                       # CRITICAL / HIGH / MEDIUM / LOW
    feature_values: Dict[str, Any] = field(default_factory=dict)
    model_version: str = "v1"
    sources: List[str] = field(default_factory=list)
    error: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "cve_id": self.cve_id,
            "exploit_probability": round(self.exploit_probability, 4),
            "risk_tier": self.risk_tier,
            "model_version": self.model_version,
            "sources": self.sources,
            "feature_values": self.feature_values,
            "error": self.error,
        }


def _tier(prob: float) -> str:
    if prob >= 0.75:
        return "CRITICAL"
    if prob >= 0.50:
        return "HIGH"
    if prob >= 0.25:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# Feature helpers (mirrors train script)
# ---------------------------------------------------------------------------

def _parse_cvss_vector(vector: str) -> dict:
    feats = {
        "av_network": 0, "pr_none": 0, "ui_none": 0,
        "scope_changed": 0, "conf_high": 0, "integ_high": 0, "avail_high": 0,
    }
    if not vector:
        return feats
    mapping = {
        "AV:N": ("av_network", 1), "PR:N": ("pr_none", 1),
        "UI:N": ("ui_none", 1), "S:C": ("scope_changed", 1),
        "C:H": ("conf_high", 1), "I:H": ("integ_high", 1), "A:H": ("avail_high", 1),
    }
    for part in vector.split("/"):
        if part in mapping:
            k, v = mapping[part]
            feats[k] = v
    return feats


def _age_days(published: str) -> float:
    if not published:
        return 365.0
    try:
        pub = datetime.fromisoformat(published.replace("Z", "+00:00"))
        return max(0.0, (datetime.now(timezone.utc) - pub).days)
    except Exception:
        return 365.0


def _severity_encode(severity: str) -> dict:
    sev = (severity or "").upper()
    return {
        "sev_critical": int(sev == "CRITICAL"),
        "sev_high": int(sev == "HIGH"),
        "sev_medium": int(sev == "MEDIUM"),
        "sev_low": int(sev == "LOW"),
    }


def _cwe_one_hot(cwe_ids: str) -> dict:
    present = set((cwe_ids or "").upper().split(","))
    return {f"cwe_{cwe.replace('-','_')}": int(cwe.upper() in present) for cwe in TOP_CWES}


def _vendor_flag(vendor: str) -> int:
    v = (vendor or "").lower()
    return int(any(tv in v for tv in TOP_VENDORS))


# ---------------------------------------------------------------------------
# DB lookups
# ---------------------------------------------------------------------------

def _db_connect(name: str):
    path = DATA_DIR / name
    if not path.exists():
        return None
    try:
        return sqlite3.connect(path)
    except Exception:
        return None


def _lookup_nvd(cve_id: str) -> dict:
    con = _db_connect("nvd_cve.db")
    if con is None:
        return {}
    try:
        cur = con.cursor()
        cur.execute(
            "SELECT cvss_score, cvss_severity, cvss_vector, cwe_ids, vuln_status, published "
            "FROM nvd_cves WHERE cve_id=?",
            (cve_id,),
        )
        row = cur.fetchone()
        if row:
            return {
                "cvss_score": float(row[0] or 0.0),
                "cvss_severity": (row[1] or "UNKNOWN").upper(),
                "cvss_vector": row[2] or "",
                "cwe_ids": row[3] or "",
                "vuln_status": (row[4] or "").lower(),
                "published": row[5] or "",
            }
        return {}
    except Exception:
        return {}
    finally:
        con.close()


def _lookup_epss(cve_id: str) -> tuple[float, float]:
    con = _db_connect("epss.db")
    if con is None:
        return 0.0, 0.0
    try:
        cur = con.cursor()
        cur.execute(
            "SELECT epss_score, percentile FROM epss_scores WHERE cve_id=?", (cve_id,)
        )
        row = cur.fetchone()
        return (float(row[0] or 0.0), float(row[1] or 0.0)) if row else (0.0, 0.0)
    except Exception:
        return 0.0, 0.0
    finally:
        con.close()


def _lookup_kev(cve_id: str) -> dict:
    con = _db_connect("cisa_kev.db")
    if con is None:
        return {}
    try:
        cur = con.cursor()
        cur.execute(
            "SELECT vendor_project, known_ransomware_use FROM kev_entries WHERE cve_id=?",
            (cve_id,),
        )
        row = cur.fetchone()
        if row:
            ransomware = 1 if (row[1] or "").lower() not in ("unknown", "", "no") else 0
            return {"is_kev": 1, "vendor_project": (row[0] or "").lower(), "ransomware": ransomware}
        return {"is_kev": 0, "vendor_project": "", "ransomware": 0}
    except Exception:
        return {}
    finally:
        con.close()


def _lookup_exploitdb(cve_id: str) -> int:
    con = _db_connect("exploitdb.db")
    if con is None:
        return 0
    try:
        cur = con.cursor()
        cur.execute("SELECT value FROM exploitdb_exploits WHERE key=?", (cve_id,))
        row = cur.fetchone()
        if row:
            try:
                return int(row[0] or 0)
            except (ValueError, TypeError):
                return 1
        return 0
    except Exception:
        return 0
    finally:
        con.close()


# ---------------------------------------------------------------------------
# Core inference class
# ---------------------------------------------------------------------------

class VulnPrioritizerML:
    """Gradient-boosted exploit-likelihood ML model inference wrapper."""

    _instance: Optional["VulnPrioritizerML"] = None

    def __init__(self, model_path: Optional[Path] = None) -> None:
        self._path = model_path or MODEL_PATH
        self._artifact: Optional[dict] = None
        self._load()

    def _load(self) -> None:
        try:
            import joblib
            self._artifact = joblib.load(self._path)
            logger.info(
                "VulnPrioritizerML loaded model %s (trained %s, ROC-AUC=%s)",
                self._artifact.get("version"),
                self._artifact.get("trained_at", "unknown")[:10],
                self._artifact.get("metrics", {}).get("roc_auc", "?"),
            )
        except Exception as exc:
            logger.error("VulnPrioritizerML: failed to load model from %s: %s", self._path, exc)
            self._artifact = None

    @classmethod
    def get_instance(cls) -> "VulnPrioritizerML":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    @property
    def model_version(self) -> str:
        if self._artifact:
            return self._artifact.get("version", "v1")
        return "unavailable"

    def get_features_for_cve(self, cve_id: str) -> tuple[dict, list[str]]:
        """Build feature dict for a CVE by joining all 4 DBs. Returns (features, sources)."""
        cve_upper = cve_id.strip().upper()
        sources = []

        nvd = _lookup_nvd(cve_upper)
        if nvd:
            sources.append("nvd")

        epss_score, epss_pct = _lookup_epss(cve_upper)
        if epss_score > 0:
            sources.append("epss")

        kev = _lookup_kev(cve_upper)
        if kev.get("is_kev"):
            sources.append("cisa_kev")

        exploit_count = _lookup_exploitdb(cve_upper)
        if exploit_count > 0:
            sources.append("exploitdb")

        cvss = float(nvd.get("cvss_score", 0.0))
        published = nvd.get("published", "")
        vector = nvd.get("cvss_vector", "")
        cwe_ids = nvd.get("cwe_ids", "")
        severity = nvd.get("cvss_severity", "UNKNOWN")
        vuln_status = nvd.get("vuln_status", "")
        vendor = kev.get("vendor_project", "")
        ransomware = kev.get("ransomware", 0)

        features: dict = {
            "cvss_base": cvss,
            "epss_score": epss_score,
            "epss_percentile": epss_pct,
            "exploitdb_count": exploit_count,
            "age_days": _age_days(published),
            "ransomware": ransomware,
            "is_analyzed": int(vuln_status in ("analyzed", "modified")),
            "vendor_top20": _vendor_flag(vendor),
        }
        features.update(_severity_encode(severity))
        features.update(_cwe_one_hot(cwe_ids))
        features.update(_parse_cvss_vector(vector))

        return features, sources

    def predict(self, cve_id: str) -> PredictionResult:
        """Predict P(exploit) for a CVE by joining DB features."""
        if self._artifact is None:
            return PredictionResult(
                cve_id=cve_id,
                exploit_probability=0.0,
                risk_tier="UNKNOWN",
                error="Model not loaded",
            )

        features, sources = self.get_features_for_cve(cve_id)
        return self.predict_features(cve_id, features, sources)

    def predict_features(
        self,
        cve_id: str,
        features: dict,
        sources: Optional[list] = None,
    ) -> PredictionResult:
        """Predict P(exploit) from a pre-built feature dict."""
        if self._artifact is None:
            return PredictionResult(
                cve_id=cve_id,
                exploit_probability=0.0,
                risk_tier="UNKNOWN",
                error="Model not loaded",
            )

        try:
            model = self._artifact["model"]
            feat_cols = self._artifact.get("feature_cols", FEATURE_COLS)
            X = np.array(
                [[float(features.get(col, 0.0)) for col in feat_cols]],
                dtype=np.float32,
            )
            prob = float(model.predict_proba(X)[0, 1])
            prob = max(0.0, min(1.0, prob))  # clamp to [0,1]
            return PredictionResult(
                cve_id=cve_id,
                exploit_probability=round(prob, 4),
                risk_tier=_tier(prob),
                feature_values=features,
                model_version=self.model_version,
                sources=sources or [],
            )
        except Exception as exc:
            logger.error("VulnPrioritizerML.predict_features error for %s: %s", cve_id, exc)
            return PredictionResult(
                cve_id=cve_id,
                exploit_probability=0.0,
                risk_tier="UNKNOWN",
                error=str(exc),
            )

    def batch_predict(self, cve_ids: list[str]) -> list[PredictionResult]:
        """Batch predict for multiple CVE IDs."""
        return [self.predict(cve_id) for cve_id in cve_ids]


# Module-level convenience
def predict(cve_id: str) -> PredictionResult:
    return VulnPrioritizerML.get_instance().predict(cve_id)


def predict_features(cve_id: str, features: dict) -> PredictionResult:
    return VulnPrioritizerML.get_instance().predict_features(cve_id, features)
