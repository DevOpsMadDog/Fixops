"""
ALdeci Anomaly Detection Engine — Isolation Forest for Scan Result Anomaly Detection.

[V3] Decision Intelligence — Detects unusual patterns in scan results.

Identifies anomalous scan results that deviate from historical baselines:
- Sudden spike in finding count
- New vulnerability categories appearing
- Unusual severity distribution
- Unexpected network exposure patterns
- Abnormal CVSS/EPSS distributions

Architecture:
    - Isolation Forest on scan-level feature vectors
    - Per-asset-type baselines maintained in memory
    - Streaming updates (no batch retraining needed)
    - Air-gap compatible (scikit-learn only, no cloud)

Usage:
    from core.ml.anomaly_detector import AnomalyDetector
    detector = AnomalyDetector()
    detector.fit_baseline(historical_scans)
    result = detector.detect(current_scan)
    if result.is_anomalous:
        print(f"ALERT: {result.anomaly_reasons}")
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set

import numpy as np

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

SCAN_FEATURE_NAMES = [
    "finding_count",
    "critical_ratio",
    "high_ratio",
    "medium_ratio",
    "low_ratio",
    "unique_cve_count",
    "kev_ratio",
    "avg_cvss",
    "avg_epss",
    "exploit_ratio",
    "internet_exposed_ratio",
    "unique_asset_count",
]

DEFAULT_CONTAMINATION = 0.05  # 5% expected anomaly rate


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class AnomalyResult:
    """Result of anomaly detection on a scan."""
    is_anomalous: bool
    anomaly_score: float  # -1 (most anomalous) to 1 (most normal)
    anomaly_reasons: List[str]
    feature_deviations: Dict[str, float]  # Z-scores per feature
    scan_features: Dict[str, float]
    baseline_stats: Dict[str, Dict[str, float]]  # mean/std per feature
    detection_time_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_anomalous": self.is_anomalous,
            "anomaly_score": round(self.anomaly_score, 4),
            "anomaly_reasons": self.anomaly_reasons,
            "feature_deviations": {
                k: round(v, 4) for k, v in self.feature_deviations.items()
            },
            "scan_features": {
                k: round(v, 4) for k, v in self.scan_features.items()
            },
            "baseline_stats": {
                k: {sk: round(sv, 4) for sk, sv in v.items()}
                for k, v in self.baseline_stats.items()
            },
            "detection_time_ms": round(self.detection_time_ms, 4),
        }


# ---------------------------------------------------------------------------
# Feature extraction
# ---------------------------------------------------------------------------

def extract_scan_features(findings: List[Dict[str, Any]]) -> np.ndarray:
    """Extract feature vector from a list of scan findings.

    Parameters
    ----------
    findings : list of dict
        List of finding dictionaries from a scan.

    Returns
    -------
    np.ndarray
        1D array of shape (12,) with scan-level features.
    """
    n = len(findings)
    if n == 0:
        return np.zeros(len(SCAN_FEATURE_NAMES), dtype=np.float64)

    severities = [f.get("severity", "medium").lower() for f in findings]
    sev_counts = {s: severities.count(s) for s in SEVERITY_ORDER}

    cve_ids = set(f.get("cve_id") for f in findings if f.get("cve_id"))
    kev_count = sum(1 for f in findings if f.get("in_kev", False))
    cvss_scores = [float(f.get("cvss_score", 0)) for f in findings if f.get("cvss_score")]
    epss_scores = [float(f.get("epss_score", 0)) for f in findings if f.get("epss_score")]
    exploit_count = sum(1 for f in findings if f.get("exploit_available", False))
    internet_count = sum(
        1 for f in findings
        if str(f.get("network_exposure", "")).lower() in ("internet", "public")
    )
    asset_names = set(
        f.get("asset_name", f.get("canonical_asset_id", ""))
        for f in findings
        if f.get("asset_name") or f.get("canonical_asset_id")
    )

    return np.array([
        float(n),
        sev_counts.get("critical", 0) / n,
        sev_counts.get("high", 0) / n,
        sev_counts.get("medium", 0) / n,
        sev_counts.get("low", 0) / n,
        float(len(cve_ids)),
        kev_count / n if n > 0 else 0,
        float(np.mean(cvss_scores)) if cvss_scores else 0.0,
        float(np.mean(epss_scores)) if epss_scores else 0.0,
        exploit_count / n if n > 0 else 0,
        internet_count / n if n > 0 else 0,
        float(len(asset_names)),
    ], dtype=np.float64)


# ---------------------------------------------------------------------------
# Detector class
# ---------------------------------------------------------------------------

class AnomalyDetector:
    """Isolation Forest anomaly detector for scan results.

    [V3] Decision Intelligence — Detects unusual scan patterns.
    [V9] Air-gapped — Works offline with scikit-learn.

    Maintains per-asset-type baselines and detects deviations using
    Isolation Forest + Z-score feature analysis.
    """

    def __init__(
        self,
        contamination: float = DEFAULT_CONTAMINATION,
        random_seed: int = 42,
        z_threshold: float = 2.5,
    ):
        self.contamination = contamination
        self.random_seed = random_seed
        self.z_threshold = z_threshold
        self._model = None
        self._fitted = False
        self._baseline_features: List[np.ndarray] = []
        self._feature_means: Optional[np.ndarray] = None
        self._feature_stds: Optional[np.ndarray] = None
        self._scan_history: List[Dict[str, Any]] = []

    @property
    def is_fitted(self) -> bool:
        return self._fitted

    def fit_baseline(
        self,
        historical_scans: List[List[Dict[str, Any]]],
    ) -> Dict[str, Any]:
        """Fit the anomaly detector on historical scan data.

        Parameters
        ----------
        historical_scans : list of list of dict
            List of scans, where each scan is a list of findings.

        Returns
        -------
        dict
            Baseline statistics.
        """
        from sklearn.ensemble import IsolationForest

        if len(historical_scans) < 3:
            raise ValueError(f"Need at least 3 historical scans, got {len(historical_scans)}")

        features = []
        for scan in historical_scans:
            # Accept both raw findings list and scan dict with 'findings' key
            if isinstance(scan, dict) and "findings" in scan:
                scan_findings = scan["findings"]
            elif isinstance(scan, list):
                scan_findings = scan
            else:
                logger.warning("Skipping unrecognized scan format: %s", type(scan))
                continue
            feat = extract_scan_features(scan_findings)
            features.append(feat)

        X = np.array(features)
        self._baseline_features = features

        # Compute baseline statistics
        self._feature_means = np.mean(X, axis=0)
        self._feature_stds = np.std(X, axis=0)
        # Prevent division by zero
        self._feature_stds = np.where(self._feature_stds == 0, 1.0, self._feature_stds)

        # Fit Isolation Forest
        self._model = IsolationForest(
            contamination=self.contamination,
            random_state=self.random_seed,
            n_estimators=100,
            max_samples="auto",
        )
        self._model.fit(X)
        self._fitted = True

        logger.info(
            "Anomaly detector fitted on %d historical scans. Baseline: mean_findings=%.1f",
            len(historical_scans),
            float(self._feature_means[0]),
        )

        return {
            "scans_fitted": len(historical_scans),
            "feature_means": {
                SCAN_FEATURE_NAMES[i]: float(self._feature_means[i])
                for i in range(len(SCAN_FEATURE_NAMES))
            },
            "feature_stds": {
                SCAN_FEATURE_NAMES[i]: float(self._feature_stds[i])
                for i in range(len(SCAN_FEATURE_NAMES))
            },
        }

    def fit_from_synthetic_baseline(self, n_scans: int = 30) -> Dict[str, Any]:
        """Create a synthetic baseline from typical enterprise scan patterns.

        This is used when no historical data is available. The synthetic data
        represents realistic enterprise scan distributions.

        Parameters
        ----------
        n_scans : int
            Number of synthetic scans to generate.

        Returns
        -------
        dict
            Baseline statistics.
        """
        rng = np.random.RandomState(self.random_seed)

        synthetic_scans = []
        for _ in range(n_scans):
            n_findings = max(1, int(rng.lognormal(mean=4.0, sigma=0.8)))
            findings = []
            for _ in range(n_findings):
                sev_roll = rng.random()
                if sev_roll < 0.05:
                    severity = "critical"
                elif sev_roll < 0.20:
                    severity = "high"
                elif sev_roll < 0.60:
                    severity = "medium"
                else:
                    severity = "low"

                cvss = {
                    "critical": rng.uniform(9.0, 10.0),
                    "high": rng.uniform(7.0, 8.9),
                    "medium": rng.uniform(4.0, 6.9),
                    "low": rng.uniform(0.1, 3.9),
                }[severity]

                findings.append({
                    "severity": severity,
                    "cvss_score": round(cvss, 1),
                    "epss_score": round(rng.beta(1.5, 10), 4),
                    "in_kev": rng.random() < 0.03,
                    "cve_id": f"CVE-{rng.randint(2019, 2026)}-{rng.randint(1000, 99999)}" if rng.random() < 0.7 else None,
                    "exploit_available": rng.random() < 0.15,
                    "network_exposure": rng.choice(
                        ["internet", "internal", "controlled", "partner"],
                        p=[0.15, 0.45, 0.30, 0.10],
                    ),
                    "asset_name": f"asset-{rng.randint(1, 50)}",
                })
            synthetic_scans.append(findings)

        return self.fit_baseline(synthetic_scans)

    def detect(self, findings) -> AnomalyResult:
        """Detect anomalies in a scan's findings.

        Parameters
        ----------
        findings : list of dict, or dict with 'findings' key
            Findings from the current scan.

        Returns
        -------
        AnomalyResult
            Anomaly detection result with score and reasons.
        """
        t0 = time.monotonic()
        # Accept both raw findings list and scan dict with 'findings' key
        if isinstance(findings, dict) and "findings" in findings:
            actual_findings = findings["findings"]
        elif isinstance(findings, list):
            actual_findings = findings
        else:
            actual_findings = []
        features = extract_scan_features(actual_findings)

        scan_features = {
            SCAN_FEATURE_NAMES[i]: float(features[i])
            for i in range(len(SCAN_FEATURE_NAMES))
        }

        if not self._fitted:
            # Not fitted — use heuristic detection
            reasons = self._heuristic_detect(features)
            dt = (time.monotonic() - t0) * 1000
            return AnomalyResult(
                is_anomalous=len(reasons) > 0,
                anomaly_score=0.0,
                anomaly_reasons=reasons,
                feature_deviations={},
                scan_features=scan_features,
                baseline_stats={},
                detection_time_ms=dt,
            )

        # Isolation Forest prediction
        X = features.reshape(1, -1)
        iso_score = float(self._model.decision_function(X)[0])
        iso_pred = int(self._model.predict(X)[0])  # -1 = anomaly, 1 = normal

        # Z-score analysis
        z_scores = (features - self._feature_means) / self._feature_stds
        deviations = {
            SCAN_FEATURE_NAMES[i]: float(z_scores[i])
            for i in range(len(SCAN_FEATURE_NAMES))
        }

        # Identify reasons for anomaly
        reasons = []
        if abs(z_scores[0]) > self.z_threshold:
            direction = "spike" if z_scores[0] > 0 else "drop"
            reasons.append(
                f"Finding count {direction}: {int(features[0])} "
                f"(baseline: {self._feature_means[0]:.0f} ± {self._feature_stds[0]:.0f})"
            )

        if z_scores[1] > self.z_threshold:  # critical_ratio
            reasons.append(
                f"Critical severity ratio elevated: {features[1]:.1%} "
                f"(baseline: {self._feature_means[1]:.1%})"
            )

        if z_scores[6] > self.z_threshold:  # kev_ratio
            reasons.append(
                f"KEV ratio elevated: {features[6]:.1%} "
                f"(baseline: {self._feature_means[6]:.1%})"
            )

        if z_scores[9] > self.z_threshold:  # exploit_ratio
            reasons.append(
                f"Exploit availability ratio elevated: {features[9]:.1%} "
                f"(baseline: {self._feature_means[9]:.1%})"
            )

        if z_scores[10] > self.z_threshold:  # internet_exposed
            reasons.append(
                f"Internet-exposed ratio elevated: {features[10]:.1%} "
                f"(baseline: {self._feature_means[10]:.1%})"
            )

        is_anomalous = iso_pred == -1 or len(reasons) > 0

        baseline_stats = {
            SCAN_FEATURE_NAMES[i]: {
                "mean": float(self._feature_means[i]),
                "std": float(self._feature_stds[i]),
            }
            for i in range(len(SCAN_FEATURE_NAMES))
        }

        dt = (time.monotonic() - t0) * 1000
        return AnomalyResult(
            is_anomalous=is_anomalous,
            anomaly_score=iso_score,
            anomaly_reasons=reasons,
            feature_deviations=deviations,
            scan_features=scan_features,
            baseline_stats=baseline_stats,
            detection_time_ms=dt,
        )

    def update_baseline(self, findings: List[Dict[str, Any]]) -> None:
        """Update the baseline with a new scan (streaming update).

        Parameters
        ----------
        findings : list of dict
            New scan findings to incorporate into baseline.
        """
        features = extract_scan_features(findings)
        self._baseline_features.append(features)

        # Recompute statistics
        X = np.array(self._baseline_features)
        self._feature_means = np.mean(X, axis=0)
        self._feature_stds = np.std(X, axis=0)
        self._feature_stds = np.where(self._feature_stds == 0, 1.0, self._feature_stds)

        # Keep max 100 scans in history
        if len(self._baseline_features) > 100:
            self._baseline_features = self._baseline_features[-100:]

        # Refit Isolation Forest periodically
        if len(self._baseline_features) % 10 == 0 and len(self._baseline_features) >= 10:
            from sklearn.ensemble import IsolationForest
            X = np.array(self._baseline_features)
            self._model = IsolationForest(
                contamination=self.contamination,
                random_state=self.random_seed,
                n_estimators=100,
            )
            self._model.fit(X)

    def detect_drift(
        self,
        current_findings: List[Dict[str, Any]],
        previous_findings: List[Dict[str, Any]],
    ) -> "DriftResult":
        """Detect scan-over-scan drift between two consecutive scans.

        [V3] Decision Intelligence — identifies regression or improvement trends.

        Compares two scans and identifies:
        - New vulnerabilities (appeared since last scan)
        - Resolved vulnerabilities (disappeared since last scan)
        - Severity changes (upgraded or downgraded)
        - Distribution shifts (statistical comparison)

        Parameters
        ----------
        current_findings : list of dict
            Findings from the current (latest) scan.
        previous_findings : list of dict
            Findings from the previous scan.

        Returns
        -------
        DriftResult
            Drift analysis with new/resolved/changed findings.
        """
        t0 = time.monotonic()

        # Extract features for both scans
        curr_features = extract_scan_features(current_findings)
        prev_features = extract_scan_features(previous_findings)

        # Feature-level deltas
        feature_deltas = {}
        for i, name in enumerate(SCAN_FEATURE_NAMES):
            delta = float(curr_features[i] - prev_features[i])
            pct_change = (
                delta / prev_features[i] * 100
                if prev_features[i] != 0 else (100.0 if delta > 0 else 0.0)
            )
            feature_deltas[name] = {
                "current": float(curr_features[i]),
                "previous": float(prev_features[i]),
                "delta": round(delta, 4),
                "pct_change": round(pct_change, 2),
            }

        # Identity-based diff (using CVE + title + location as key)
        curr_ids = self._extract_finding_identities(current_findings)
        prev_ids = self._extract_finding_identities(previous_findings)

        new_ids = curr_ids - prev_ids
        resolved_ids = prev_ids - curr_ids
        persistent_ids = curr_ids & prev_ids

        # Severity shifts on persistent findings
        curr_map = self._build_identity_map(current_findings)
        prev_map = self._build_identity_map(previous_findings)
        severity_changes = []
        for fid in persistent_ids:
            curr_sev = curr_map.get(fid, {}).get("severity", "unknown").lower()
            prev_sev = prev_map.get(fid, {}).get("severity", "unknown").lower()
            if curr_sev != prev_sev:
                severity_changes.append({
                    "identity": fid,
                    "previous_severity": prev_sev,
                    "current_severity": curr_sev,
                    "direction": "upgraded" if SEVERITY_ORDER.get(curr_sev, 0) > SEVERITY_ORDER.get(prev_sev, 0) else "downgraded",
                })

        # Drift classification
        finding_count_delta = int(curr_features[0] - prev_features[0])
        critical_delta = curr_features[1] - prev_features[1]

        drift_alerts = []
        if abs(finding_count_delta) > max(5, 0.2 * prev_features[0]):
            direction = "increase" if finding_count_delta > 0 else "decrease"
            drift_alerts.append(
                f"Finding count {direction}: {int(prev_features[0])} → {int(curr_features[0])} "
                f"(Δ{finding_count_delta:+d})"
            )

        if abs(critical_delta) > 0.05:
            direction = "increase" if critical_delta > 0 else "decrease"
            drift_alerts.append(
                f"Critical severity ratio {direction}: "
                f"{prev_features[1]:.1%} → {curr_features[1]:.1%}"
            )

        if len(new_ids) > max(3, 0.1 * len(prev_ids)):
            drift_alerts.append(
                f"{len(new_ids)} new findings appeared since last scan"
            )

        if len(resolved_ids) > max(3, 0.1 * len(prev_ids)):
            drift_alerts.append(
                f"{len(resolved_ids)} findings resolved since last scan"
            )

        # Classify overall drift
        if not drift_alerts:
            drift_type = "stable"
        elif finding_count_delta > 0 or critical_delta > 0.05:
            drift_type = "regression"
        elif finding_count_delta < 0 or critical_delta < -0.05:
            drift_type = "improvement"
        else:
            drift_type = "shift"

        dt = (time.monotonic() - t0) * 1000
        return DriftResult(
            drift_type=drift_type,
            new_findings_count=len(new_ids),
            resolved_findings_count=len(resolved_ids),
            persistent_findings_count=len(persistent_ids),
            severity_changes=severity_changes,
            feature_deltas=feature_deltas,
            drift_alerts=drift_alerts,
            detection_time_ms=dt,
        )

    def _extract_finding_identities(
        self, findings: List[Dict[str, Any]]
    ) -> Set[str]:
        """Extract identity keys for finding deduplication and diffing."""
        identities = set()
        for f in findings:
            # Prefer CVE ID, then title+location, then title+severity
            cve_id = f.get("cve_id", "")
            title = f.get("title", "")
            location = f.get("file_path", f.get("url", f.get("host", "")))
            severity = f.get("severity", "")

            if cve_id:
                key = f"{cve_id}|{location}"
            elif title:
                key = f"{title}|{location}|{severity}"
            else:
                # Fallback to description hash
                desc = f.get("description", "")
                key = f"desc:{hash(desc)}|{severity}"

            identities.add(key)
        return identities

    def _build_identity_map(
        self, findings: List[Dict[str, Any]]
    ) -> Dict[str, Dict[str, Any]]:
        """Build a mapping from identity key → finding dict."""
        result = {}
        for f in findings:
            cve_id = f.get("cve_id", "")
            title = f.get("title", "")
            location = f.get("file_path", f.get("url", f.get("host", "")))
            severity = f.get("severity", "")

            if cve_id:
                key = f"{cve_id}|{location}"
            elif title:
                key = f"{title}|{location}|{severity}"
            else:
                desc = f.get("description", "")
                key = f"desc:{hash(desc)}|{severity}"
            result[key] = f
        return result

    def _heuristic_detect(self, features: np.ndarray) -> List[str]:
        """Simple heuristic detection when no baseline is available."""
        reasons = []
        finding_count = features[0]
        critical_ratio = features[1]
        kev_ratio = features[6]

        if finding_count > 500:
            reasons.append(f"Unusually high finding count: {int(finding_count)}")
        if critical_ratio > 0.3:
            reasons.append(f"High critical severity ratio: {critical_ratio:.1%}")
        if kev_ratio > 0.1:
            reasons.append(f"High KEV ratio: {kev_ratio:.1%}")

        return reasons


# ---------------------------------------------------------------------------
# Drift result data class
# ---------------------------------------------------------------------------

@dataclass
class DriftResult:
    """Result of scan-over-scan drift detection.

    [V3] Decision Intelligence — tracks security posture changes over time.
    """
    drift_type: str  # "stable", "regression", "improvement", "shift"
    new_findings_count: int
    resolved_findings_count: int
    persistent_findings_count: int
    severity_changes: List[Dict[str, Any]]
    feature_deltas: Dict[str, Dict[str, float]]
    drift_alerts: List[str]
    detection_time_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "drift_type": self.drift_type,
            "new_findings_count": self.new_findings_count,
            "resolved_findings_count": self.resolved_findings_count,
            "persistent_findings_count": self.persistent_findings_count,
            "severity_changes": self.severity_changes,
            "feature_deltas": self.feature_deltas,
            "drift_alerts": self.drift_alerts,
            "detection_time_ms": round(self.detection_time_ms, 4),
        }

    @property
    def is_regression(self) -> bool:
        return self.drift_type == "regression"

    @property
    def is_improvement(self) -> bool:
        return self.drift_type == "improvement"

    @property
    def net_change(self) -> int:
        return self.new_findings_count - self.resolved_findings_count


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_detector_instance: Optional[AnomalyDetector] = None


def get_anomaly_detector() -> AnomalyDetector:
    """Get or create the global AnomalyDetector instance."""
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = AnomalyDetector()
        # Initialize with synthetic baseline
        try:
            _detector_instance.fit_from_synthetic_baseline()
        except (OSError, ValueError, KeyError, RuntimeError) as e:  # narrowed from bare Exception
            logger.warning("Could not fit anomaly baseline: %s", e)
    return _detector_instance


__all__ = [
    "AnomalyDetector",
    "AnomalyResult",
    "DriftResult",
    "extract_scan_features",
    "get_anomaly_detector",
    "SCAN_FEATURE_NAMES",
]
