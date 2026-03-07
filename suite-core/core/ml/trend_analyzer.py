"""
[V3] Vulnerability Trend Analyzer — Detects patterns and trends in vulnerability data.

Provides time-series analysis of scan findings to:
1. Detect emerging vulnerability categories (new CWE patterns)
2. Track severity drift over time (is our security posture improving?)
3. Identify recurring vulnerabilities (same CVE across multiple scans)
4. Generate actionable trend reports for the brain pipeline

Architecture: Pure numpy/scipy for V9 air-gap compliance.

Author: data-scientist
Date: 2026-03-03
Pillar: V3 (Decision Intelligence)
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------


@dataclass
class TrendPoint:
    """A single data point in a trend time series."""

    timestamp: str
    value: float
    label: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"timestamp": self.timestamp, "value": self.value, "label": self.label}


@dataclass
class VulnTrend:
    """A detected vulnerability trend."""

    trend_id: str
    category: str  # severity_drift, cwe_emergence, recurrence, volume
    direction: str  # increasing, decreasing, stable, spike
    magnitude: float  # 0-1 normalized change magnitude
    confidence: float  # 0-1 confidence in the trend
    description: str
    data_points: List[TrendPoint] = field(default_factory=list)
    affected_cves: List[str] = field(default_factory=list)
    recommendation: str = ""
    pillar: str = "V3"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "trend_id": self.trend_id,
            "category": self.category,
            "direction": self.direction,
            "magnitude": round(self.magnitude, 4),
            "confidence": round(self.confidence, 4),
            "description": self.description,
            "data_points": [p.to_dict() for p in self.data_points],
            "affected_cves": self.affected_cves[:20],  # Limit for serialization
            "recommendation": self.recommendation,
            "pillar": self.pillar,
        }


@dataclass
class TrendReport:
    """Complete trend analysis report."""

    generated_at: str
    scan_count: int
    finding_count: int
    time_range_days: float
    trends: List[VulnTrend] = field(default_factory=list)
    severity_summary: Dict[str, int] = field(default_factory=dict)
    cwe_distribution: Dict[str, int] = field(default_factory=dict)
    posture_score: float = 0.0  # 0-100, higher = better security posture
    posture_trend: str = "stable"  # improving, degrading, stable

    def to_dict(self) -> Dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "scan_count": self.scan_count,
            "finding_count": self.finding_count,
            "time_range_days": round(self.time_range_days, 1),
            "trends": [t.to_dict() for t in self.trends],
            "severity_summary": self.severity_summary,
            "cwe_distribution": dict(
                sorted(self.cwe_distribution.items(), key=lambda x: x[1], reverse=True)[:15]
            ),
            "posture_score": round(self.posture_score, 1),
            "posture_trend": self.posture_trend,
            "trend_count": len(self.trends),
            "actionable_trends": sum(1 for t in self.trends if t.confidence >= 0.7),
        }


# ---------------------------------------------------------------------------
# Scan history store (in-memory with optional persistence)
# ---------------------------------------------------------------------------


class ScanHistoryStore:
    """Maintains a bounded history of scan results for trend analysis.

    Thread-safe via append-only design and bounded size.
    """

    def __init__(self, max_scans: int = 200, persist_path: Optional[str] = None):
        self._scans: List[Dict[str, Any]] = []
        self._max_scans = max_scans
        self._persist_path = persist_path
        if persist_path and os.path.exists(persist_path):
            try:
                with open(persist_path, "r") as f:
                    data = json.load(f)
                self._scans = data.get("scans", [])[-max_scans:]
                logger.info("Loaded %d scans from %s", len(self._scans), persist_path)
            except (json.JSONDecodeError, OSError) as e:
                logger.warning("Could not load scan history: %s", e)

    def add_scan(self, scan_result: Dict[str, Any]) -> None:
        """Add a scan result to the history.

        Expected scan_result format:
        {
            "scan_id": "...",
            "timestamp": "ISO8601",
            "org_id": "...",
            "app_id": "...",
            "findings": [
                {
                    "cve_id": "CVE-...",
                    "severity": "critical|high|medium|low|info",
                    "cwe_id": "CWE-...",
                    "cvss_score": float,
                    "title": "...",
                    "scanner": "...",
                }
            ]
        }
        """
        # Ensure timestamp
        if "timestamp" not in scan_result:
            scan_result["timestamp"] = datetime.now(timezone.utc).isoformat()
        self._scans.append(scan_result)
        # Bounded size
        if len(self._scans) > self._max_scans:
            self._scans = self._scans[-self._max_scans:]
        self._persist()

    def get_scans(
        self,
        org_id: Optional[str] = None,
        app_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Get scan history, optionally filtered."""
        scans = self._scans
        if org_id:
            scans = [s for s in scans if s.get("org_id") == org_id]
        if app_id:
            scans = [s for s in scans if s.get("app_id") == app_id]
        return scans[-limit:]

    @property
    def scan_count(self) -> int:
        return len(self._scans)

    def _persist(self) -> None:
        if self._persist_path:
            try:
                os.makedirs(os.path.dirname(self._persist_path), exist_ok=True)
                with open(self._persist_path, "w") as f:
                    json.dump({"scans": self._scans}, f)
            except OSError as e:
                logger.warning("Could not persist scan history: %s", e)


# ---------------------------------------------------------------------------
# Trend Analyzer
# ---------------------------------------------------------------------------


class TrendAnalyzer:
    """Analyzes vulnerability trends across scan history.

    Detects:
    - Severity drift (improving/degrading security posture)
    - CWE emergence (new vulnerability categories appearing)
    - Vulnerability recurrence (same CVEs found repeatedly)
    - Volume spikes/drops
    - Scanner coverage changes

    All algorithms are pure numpy — no cloud dependencies (V9 compliant).
    """

    def __init__(self, history: Optional[ScanHistoryStore] = None):
        self._history = history or ScanHistoryStore()
        self._severity_weights = {
            "critical": 10.0,
            "high": 7.0,
            "medium": 4.0,
            "low": 1.0,
            "info": 0.1,
        }

    def add_scan(self, scan_result: Dict[str, Any]) -> None:
        """Add a scan result to the history store."""
        self._history.add_scan(scan_result)

    def analyze(
        self,
        org_id: Optional[str] = None,
        app_id: Optional[str] = None,
        min_scans: int = 3,
    ) -> TrendReport:
        """Run full trend analysis on scan history.

        Parameters
        ----------
        org_id : str, optional
            Filter by organization.
        app_id : str, optional
            Filter by application.
        min_scans : int
            Minimum scans needed for trend detection (default 3).

        Returns
        -------
        TrendReport
            Complete trend analysis with detected patterns.
        """
        scans = self._history.get_scans(org_id=org_id, app_id=app_id, limit=100)
        now = datetime.now(timezone.utc).isoformat()

        if len(scans) < min_scans:
            return TrendReport(
                generated_at=now,
                scan_count=len(scans),
                finding_count=sum(len(s.get("findings", [])) for s in scans),
                time_range_days=0,
                posture_score=50.0,
                posture_trend="insufficient_data",
            )

        # Calculate time range
        timestamps = []
        for s in scans:
            ts = s.get("timestamp", "")
            if ts:
                try:
                    timestamps.append(datetime.fromisoformat(ts.replace("Z", "+00:00")))
                except (ValueError, TypeError):
                    pass
        if len(timestamps) >= 2:
            time_range = (max(timestamps) - min(timestamps)).total_seconds() / 86400
        else:
            time_range = 0.0

        # Collect all findings
        all_findings = []
        for scan in scans:
            for finding in scan.get("findings", []):
                finding["_scan_ts"] = scan.get("timestamp", "")
                all_findings.append(finding)

        # Run trend detectors
        trends: List[VulnTrend] = []
        trends.extend(self._detect_severity_drift(scans))
        trends.extend(self._detect_cwe_emergence(scans))
        trends.extend(self._detect_recurrence(scans))
        trends.extend(self._detect_volume_trends(scans))

        # Severity summary
        severity_summary: Dict[str, int] = Counter()
        cwe_dist: Dict[str, int] = Counter()
        for f_item in all_findings:
            sev = f_item.get("severity", "unknown").lower()
            severity_summary[sev] += 1
            cwe = f_item.get("cwe_id", "unknown")
            if cwe:
                cwe_dist[cwe] += 1

        # Calculate posture score
        posture_score, posture_trend = self._calculate_posture(scans)

        return TrendReport(
            generated_at=now,
            scan_count=len(scans),
            finding_count=len(all_findings),
            time_range_days=time_range,
            trends=trends,
            severity_summary=dict(severity_summary),
            cwe_distribution=dict(cwe_dist),
            posture_score=posture_score,
            posture_trend=posture_trend,
        )

    def _detect_severity_drift(self, scans: List[Dict[str, Any]]) -> List[VulnTrend]:
        """Detect if severity distribution is shifting over time."""
        trends = []
        if len(scans) < 3:
            return trends

        # Compute weighted severity score per scan
        severity_scores = []
        for scan in scans:
            findings = scan.get("findings", [])
            if not findings:
                severity_scores.append(0.0)
                continue
            total_weight = sum(
                self._severity_weights.get(f.get("severity", "info").lower(), 0.1)
                for f in findings
            )
            avg_weight = total_weight / len(findings) if findings else 0
            severity_scores.append(avg_weight)

        scores_arr = np.array(severity_scores)

        # Linear regression for trend
        x = np.arange(len(scores_arr))
        if len(x) < 2:
            return trends

        slope, intercept = np.polyfit(x, scores_arr, 1)
        # Normalized magnitude: slope relative to mean
        mean_score = np.mean(scores_arr)
        if mean_score > 0:
            magnitude = abs(slope) / mean_score
        else:
            magnitude = 0.0

        # Confidence: R² value
        y_pred = slope * x + intercept
        ss_res = np.sum((scores_arr - y_pred) ** 2)
        ss_tot = np.sum((scores_arr - np.mean(scores_arr)) ** 2)
        r2 = 1.0 - ss_res / ss_tot if ss_tot > 0 else 0.0
        confidence = min(abs(r2), 1.0)

        if magnitude > 0.02:  # At least 2% change
            direction = "increasing" if slope > 0 else "decreasing"
            desc_verb = "worsening" if slope > 0 else "improving"
            trend_id = hashlib.md5(f"severity_drift_{direction}".encode(), usedforsecurity=False).hexdigest()[:12]

            data_points = [
                TrendPoint(
                    timestamp=scans[i].get("timestamp", ""),
                    value=round(s, 2),
                    label=f"scan_{i}",
                )
                for i, s in enumerate(severity_scores)
            ]

            recommendation = (
                "Security posture is improving — continue current remediation strategy."
                if slope < 0
                else "Severity trend is worsening — consider increasing scan frequency and remediation priority."
            )

            trends.append(
                VulnTrend(
                    trend_id=trend_id,
                    category="severity_drift",
                    direction=direction,
                    magnitude=min(magnitude, 1.0),
                    confidence=confidence,
                    description=f"Average vulnerability severity is {desc_verb} (slope={slope:.3f}/scan)",
                    data_points=data_points,
                    recommendation=recommendation,
                )
            )

        return trends

    def _detect_cwe_emergence(self, scans: List[Dict[str, Any]]) -> List[VulnTrend]:
        """Detect new CWE categories appearing in recent scans."""
        trends = []
        if len(scans) < 3:
            return trends

        # Split into older and recent halves
        mid = len(scans) // 2
        older_scans = scans[:mid]
        recent_scans = scans[mid:]

        older_cwes: set = set()
        for scan in older_scans:
            for f_item in scan.get("findings", []):
                cwe = f_item.get("cwe_id")
                if cwe:
                    older_cwes.add(cwe)

        recent_cwes: Dict[str, List[str]] = defaultdict(list)
        for scan in recent_scans:
            for f_item in scan.get("findings", []):
                cwe = f_item.get("cwe_id")
                if cwe:
                    recent_cwes[cwe].append(f_item.get("cve_id", "unknown"))

        # Find new CWEs
        new_cwes = set(recent_cwes.keys()) - older_cwes
        if new_cwes:
            for cwe in list(new_cwes)[:5]:  # Report top 5
                cves = list(set(recent_cwes[cwe]))[:10]
                count = len(recent_cwes[cwe])
                trend_id = hashlib.md5(f"cwe_emergence_{cwe}".encode(), usedforsecurity=False).hexdigest()[:12]

                trends.append(
                    VulnTrend(
                        trend_id=trend_id,
                        category="cwe_emergence",
                        direction="increasing",
                        magnitude=min(count / 10.0, 1.0),
                        confidence=min(count / 3.0, 1.0),
                        description=f"New vulnerability category {cwe} detected ({count} findings in recent scans)",
                        affected_cves=cves,
                        recommendation=f"Investigate {cwe} findings — this is a new attack vector not seen in earlier scans.",
                    )
                )

        return trends

    def _detect_recurrence(self, scans: List[Dict[str, Any]]) -> List[VulnTrend]:
        """Detect CVEs that keep appearing across scans (not getting fixed)."""
        trends = []
        if len(scans) < 3:
            return trends

        # Track CVE appearances per scan
        cve_scan_count: Dict[str, int] = Counter()
        cve_severities: Dict[str, str] = {}

        for scan in scans:
            scan_cves = set()
            for f_item in scan.get("findings", []):
                cve = f_item.get("cve_id", "")
                if cve and cve not in scan_cves:
                    cve_scan_count[cve] += 1
                    scan_cves.add(cve)
                    if cve not in cve_severities:
                        cve_severities[cve] = f_item.get("severity", "unknown")

        # Find recurring CVEs (appear in >60% of scans)
        threshold = max(3, int(len(scans) * 0.6))
        recurring_cves = {
            cve: count
            for cve, count in cve_scan_count.items()
            if count >= threshold
        }

        if recurring_cves:
            # Group by severity
            critical_recurring = [
                cve
                for cve in recurring_cves
                if cve_severities.get(cve, "").lower() in ("critical", "high")
            ]
            other_recurring = [
                cve
                for cve in recurring_cves
                if cve not in critical_recurring
            ]

            if critical_recurring:
                trend_id = hashlib.md5("recurrence_critical".encode(), usedforsecurity=False).hexdigest()[:12]
                trends.append(
                    VulnTrend(
                        trend_id=trend_id,
                        category="recurrence",
                        direction="stable",
                        magnitude=min(len(critical_recurring) / 5.0, 1.0),
                        confidence=0.95,
                        description=f"{len(critical_recurring)} critical/high CVEs remain unfixed across {threshold}+ scans",
                        affected_cves=critical_recurring[:20],
                        recommendation="These recurring critical vulnerabilities indicate a remediation bottleneck. Escalate to P0.",
                    )
                )

            if other_recurring:
                trend_id = hashlib.md5("recurrence_other".encode(), usedforsecurity=False).hexdigest()[:12]
                trends.append(
                    VulnTrend(
                        trend_id=trend_id,
                        category="recurrence",
                        direction="stable",
                        magnitude=min(len(other_recurring) / 10.0, 1.0),
                        confidence=0.85,
                        description=f"{len(other_recurring)} medium/low CVEs persist across {threshold}+ scans",
                        affected_cves=other_recurring[:20],
                        recommendation="Consider batching these recurring findings into a tech-debt remediation sprint.",
                    )
                )

        return trends

    def _detect_volume_trends(self, scans: List[Dict[str, Any]]) -> List[VulnTrend]:
        """Detect changes in finding volume over time."""
        trends = []
        if len(scans) < 3:
            return trends

        # Finding counts per scan
        counts = np.array([len(s.get("findings", [])) for s in scans], dtype=float)

        if len(counts) < 3:
            return trends

        # Detect spikes: last scan is >2 standard deviations above mean
        mean_count = np.mean(counts[:-1])
        std_count = np.std(counts[:-1])
        if std_count > 0:
            z_score = (counts[-1] - mean_count) / std_count
        elif mean_count > 0 and counts[-1] != mean_count:
            # Zero std (all previous scans identical) — use ratio-based detection
            ratio = counts[-1] / mean_count
            z_score = 3.0 if ratio > 3 else (-3.0 if ratio < 0.33 else 0.0)
        else:
            z_score = 0.0

        if abs(z_score) > 2.0:
            direction = "spike" if z_score > 0 else "drop"
            trend_id = hashlib.md5(f"volume_{direction}".encode(), usedforsecurity=False).hexdigest()[:12]
            data_points = [
                TrendPoint(
                    timestamp=scans[i].get("timestamp", ""),
                    value=float(c),
                    label=f"scan_{i}",
                )
                for i, c in enumerate(counts)
            ]

            desc = (
                f"Finding volume spiked to {int(counts[-1])} (mean={mean_count:.0f}, z={z_score:.1f}σ)"
                if z_score > 0
                else f"Finding volume dropped to {int(counts[-1])} (mean={mean_count:.0f}, z={z_score:.1f}σ)"
            )
            rec = (
                "Investigate the volume spike — new scanner added, scope change, or genuine security regression?"
                if z_score > 0
                else "Finding volume decreased significantly — verify this reflects real remediation, not scanner misconfiguration."
            )

            trends.append(
                VulnTrend(
                    trend_id=trend_id,
                    category="volume",
                    direction=direction,
                    magnitude=min(abs(z_score) / 5.0, 1.0),
                    confidence=min(0.5 + abs(z_score) / 10.0, 0.99),
                    description=desc,
                    data_points=data_points,
                    recommendation=rec,
                )
            )

        # Also detect overall volume trend via linear regression
        x = np.arange(len(counts))
        slope, intercept = np.polyfit(x, counts, 1)
        mean_vol = np.mean(counts)

        if mean_vol > 0:
            rel_slope = slope / mean_vol
        else:
            rel_slope = 0.0

        if abs(rel_slope) > 0.05:  # >5% change per scan
            direction = "increasing" if slope > 0 else "decreasing"
            trend_id = hashlib.md5(f"volume_trend_{direction}".encode(), usedforsecurity=False).hexdigest()[:12]

            y_pred = slope * x + intercept
            ss_res = np.sum((counts - y_pred) ** 2)
            ss_tot = np.sum((counts - mean_vol) ** 2)
            r2 = 1.0 - ss_res / ss_tot if ss_tot > 0 else 0.0

            desc = (
                f"Finding volume is {direction} at {abs(slope):.1f} findings/scan "
                f"(R²={r2:.2f})"
            )
            rec = (
                "Growing finding volume may indicate expanding attack surface. Review scan scope and prioritize remediation."
                if slope > 0
                else "Decreasing finding volume suggests effective remediation. Maintain current pace."
            )

            trends.append(
                VulnTrend(
                    trend_id=trend_id,
                    category="volume",
                    direction=direction,
                    magnitude=min(abs(rel_slope), 1.0),
                    confidence=min(abs(r2), 1.0),
                    description=desc,
                    recommendation=rec,
                )
            )

        return trends

    def _calculate_posture(
        self, scans: List[Dict[str, Any]]
    ) -> Tuple[float, str]:
        """Calculate overall security posture score and trend.

        Returns
        -------
        Tuple[float, str]
            (score 0-100, trend direction)
        """
        if not scans:
            return 50.0, "stable"

        # Score each scan based on weighted severity
        scan_scores = []
        for scan in scans:
            findings = scan.get("findings", [])
            if not findings:
                scan_scores.append(100.0)  # No findings = perfect
                continue
            total_weight = sum(
                self._severity_weights.get(f.get("severity", "info").lower(), 0.1)
                for f in findings
            )
            # Normalize: fewer high-severity findings = better score
            # Cap at 100 finding-weight-points = 0 score
            score = max(0.0, 100.0 - total_weight)
            scan_scores.append(score)

        arr = np.array(scan_scores)

        # Current posture = weighted average (recent scans weighted more)
        if len(arr) >= 3:
            weights = np.linspace(0.5, 1.0, len(arr))
            posture_score = float(np.average(arr, weights=weights))
        else:
            posture_score = float(np.mean(arr))

        # Trend: compare first half to second half
        if len(arr) >= 4:
            mid = len(arr) // 2
            first_half_mean = np.mean(arr[:mid])
            second_half_mean = np.mean(arr[mid:])
            delta = second_half_mean - first_half_mean
            if delta > 3.0:
                trend = "improving"
            elif delta < -3.0:
                trend = "degrading"
            else:
                trend = "stable"
        else:
            trend = "stable"

        return round(min(max(posture_score, 0.0), 100.0), 1), trend


# ---------------------------------------------------------------------------
# Module-level convenience
# ---------------------------------------------------------------------------

_default_analyzer: Optional[TrendAnalyzer] = None


def get_trend_analyzer(
    persist_path: Optional[str] = None,
) -> TrendAnalyzer:
    """Get or create the default trend analyzer instance."""
    global _default_analyzer
    if _default_analyzer is None:
        _default_analyzer = TrendAnalyzer(
            ScanHistoryStore(persist_path=persist_path)
        )
    return _default_analyzer


def analyze_scan_trends(
    scans: Optional[List[Dict[str, Any]]] = None,
    org_id: Optional[str] = None,
    app_id: Optional[str] = None,
) -> TrendReport:
    """Convenience function: analyze trends from a list of scans.

    If scans are provided, they are added to the history first.
    """
    analyzer = get_trend_analyzer()
    if scans:
        for scan in scans:
            analyzer.add_scan(scan)
    return analyzer.analyze(org_id=org_id, app_id=app_id)
