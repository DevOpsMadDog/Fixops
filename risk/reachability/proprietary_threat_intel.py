"""Proprietary FixOps threat intelligence engine - no OSS dependencies.

This is FixOps' proprietary threat intelligence processing that doesn't
rely on any open source threat intel libraries. Built from scratch.
"""

from __future__ import annotations

import hashlib
import logging
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Mapping, Optional, Set

logger = logging.getLogger(__name__)


@dataclass
class ProprietaryThreatSignal:
    """Proprietary threat signal representation."""

    cve_id: str
    signal_type: str
    source: str
    confidence: float
    timestamp: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ProprietaryZeroDayIndicator:
    """Proprietary zero-day detection indicator."""

    cve_id: Optional[str]
    pattern_hash: str
    indicator_type: str
    confidence: float
    first_seen: datetime
    sources: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class ProprietaryThreatIntelligenceEngine:
    """Proprietary threat intelligence engine - custom algorithms."""

    def __init__(self, config: Optional[Mapping[str, Any]] = None):
        """Initialize proprietary threat intelligence engine."""
        self.config = config or {}

        # Proprietary pattern database
        self.threat_patterns = self._build_threat_patterns()

        # Proprietary anomaly detection models
        self.anomaly_models = self._build_anomaly_models()

        # Threat signal storage
        self.threat_signals: Dict[str, List[ProprietaryThreatSignal]] = defaultdict(
            list
        )

        # Zero-day indicators
        self.zero_day_indicators: List[ProprietaryZeroDayIndicator] = []

    def _build_threat_patterns(self) -> Dict[str, List[Dict[str, Any]]]:
        """Build proprietary threat pattern database."""
        return {
            "exploitation_patterns": [
                {
                    "pattern": "mass_exploitation",
                    "indicators": ["github", "poc", "exploit", "weaponized"],
                    "weight": 0.9,
                },
                {
                    "pattern": "ransomware",
                    "indicators": ["ransomware", "encryption", "bitcoin", "payment"],
                    "weight": 0.95,
                },
                {
                    "pattern": "apt_activity",
                    "indicators": ["apt", "nation-state", "advanced", "persistent"],
                    "weight": 0.85,
                },
            ],
            "vulnerability_patterns": [
                {
                    "pattern": "remote_code_execution",
                    "indicators": ["rce", "remote", "code execution", "arbitrary"],
                    "weight": 0.9,
                },
                {
                    "pattern": "privilege_escalation",
                    "indicators": ["privilege", "escalation", "root", "admin"],
                    "weight": 0.8,
                },
                {
                    "pattern": "authentication_bypass",
                    "indicators": ["bypass", "auth", "authentication", "login"],
                    "weight": 0.75,
                },
            ],
        }

    def _build_anomaly_models(self) -> Dict[str, Any]:
        """Build proprietary anomaly detection models."""
        return {
            "vulnerability_spike": {
                "threshold": 5,  # 5x normal rate
                "time_window_hours": 24,
            },
            "exploitation_spike": {
                "threshold": 10,  # 10x normal rate
                "time_window_hours": 6,
            },
            "new_cve_pattern": {
                "threshold": 3,  # 3 new CVEs in same component
                "time_window_hours": 48,
            },
        }

    def process_threat_feed(
        self, feed_data: List[Dict[str, Any]], source: str
    ) -> List[ProprietaryThreatSignal]:
        """Proprietary threat feed processing."""
        signals = []

        for entry in feed_data:
            # Extract CVE ID
            cve_id = self._extract_cve_id(entry)
            if not cve_id:
                continue

            # Proprietary pattern matching
            matched_patterns = self._match_threat_patterns(entry)

            # Calculate confidence
            confidence = self._calculate_signal_confidence(entry, matched_patterns)

            if confidence > 0.5:  # Only high-confidence signals
                signal = ProprietaryThreatSignal(
                    cve_id=cve_id,
                    signal_type=matched_patterns[0]["pattern"]
                    if matched_patterns
                    else "generic",
                    source=source,
                    confidence=confidence,
                    timestamp=datetime.now(timezone.utc),
                    metadata={
                        "matched_patterns": matched_patterns,
                        "raw_entry": entry,
                    },
                )
                signals.append(signal)
                self.threat_signals[cve_id].append(signal)

        return signals

    def _extract_cve_id(self, entry: Mapping[str, Any]) -> Optional[str]:
        """Proprietary CVE ID extraction."""
        # Try multiple fields
        for field in ["cve_id", "cveId", "CVE", "cve", "id"]:
            value = entry.get(field)
            if isinstance(value, str) and value.upper().startswith("CVE-"):
                return value.upper()

        # Try extracting from text
        text = str(entry)
        cve_match = re.search(r"CVE-\d{4}-\d{4,7}", text, re.IGNORECASE)
        if cve_match:
            return cve_match.group(0).upper()

        return None

    def _match_threat_patterns(self, entry: Mapping[str, Any]) -> List[Dict[str, Any]]:
        """Proprietary threat pattern matching."""
        matched = []

        # Convert entry to searchable text
        text = self._entry_to_text(entry).lower()

        # Check exploitation patterns
        for pattern in self.threat_patterns["exploitation_patterns"]:
            indicators = pattern["indicators"]
            matches = sum(1 for ind in indicators if ind.lower() in text)
            if matches >= 2:  # At least 2 indicators
                matched.append(pattern)

        # Check vulnerability patterns
        for pattern in self.threat_patterns["vulnerability_patterns"]:
            indicators = pattern["indicators"]
            matches = sum(1 for ind in indicators if ind.lower() in text)
            if matches >= 2:
                matched.append(pattern)

        return matched

    def _entry_to_text(self, entry: Mapping[str, Any]) -> str:
        """Convert entry to searchable text."""
        text_parts = []

        for key, value in entry.items():
            if isinstance(value, str):
                text_parts.append(value)
            elif isinstance(value, (list, tuple)):
                text_parts.extend(str(v) for v in value)
            else:
                text_parts.append(str(value))

        return " ".join(text_parts)

    def _calculate_signal_confidence(
        self,
        entry: Mapping[str, Any],
        matched_patterns: List[Dict[str, Any]],
    ) -> float:
        """Proprietary confidence calculation."""
        if not matched_patterns:
            return 0.3  # Low confidence without patterns

        # Base confidence from pattern weights
        pattern_confidence = max(p.get("weight", 0.5) for p in matched_patterns)

        # Boost confidence based on entry quality
        has_cve_id = "cve" in str(entry).lower()
        has_description = "description" in entry or "summary" in entry
        has_references = "references" in entry or "links" in entry

        quality_boost = 0.0
        if has_cve_id:
            quality_boost += 0.1
        if has_description:
            quality_boost += 0.1
        if has_references:
            quality_boost += 0.1

        confidence = pattern_confidence + quality_boost
        return min(1.0, max(0.0, confidence))

    def detect_zero_days(
        self, recent_vulnerabilities: List[Dict[str, Any]]
    ) -> List[ProprietaryZeroDayIndicator]:
        """Proprietary zero-day detection algorithm."""
        indicators = []

        # Group by component
        component_vulns: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for vuln in recent_vulnerabilities:
            component = vuln.get("component_name", "unknown")
            component_vulns[component].append(vuln)

        # Detect anomalies
        for component, vulns in component_vulns.items():
            if len(vulns) >= self.anomaly_models["new_cve_pattern"]["threshold"]:
                # Potential zero-day cluster
                pattern_hash = self._hash_vulnerability_pattern(vulns)

                indicator = ProprietaryZeroDayIndicator(
                    cve_id=None,  # Unknown CVE
                    pattern_hash=pattern_hash,
                    indicator_type="vulnerability_cluster",
                    confidence=0.7,
                    first_seen=datetime.now(timezone.utc),
                    sources=["anomaly_detection"],
                    metadata={
                        "component": component,
                        "vulnerability_count": len(vulns),
                        "vulnerabilities": vulns,
                    },
                )
                indicators.append(indicator)
                self.zero_day_indicators.append(indicator)

        return indicators

    def _hash_vulnerability_pattern(self, vulnerabilities: List[Dict[str, Any]]) -> str:
        """Proprietary pattern hashing for zero-day detection."""
        # Create signature from vulnerability characteristics
        signature_parts = []

        for vuln in vulnerabilities:
            cwe_ids = vuln.get("cwe_ids", [])
            severity = vuln.get("severity", "unknown")
            component = vuln.get("component_name", "unknown")

            signature_parts.append(f"{component}:{severity}:{','.join(cwe_ids)}")

        signature = "|".join(sorted(signature_parts))
        return hashlib.sha256(signature.encode()).hexdigest()[:16]

    def synthesize_threat_intelligence(self, cve_id: str) -> Dict[str, Any]:
        """Proprietary threat intelligence synthesis."""
        signals = self.threat_signals.get(cve_id, [])

        if not signals:
            return {
                "cve_id": cve_id,
                "threat_level": "unknown",
                "confidence": 0.0,
                "signals": [],
            }

        # Proprietary synthesis algorithm
        threat_levels = [s.confidence for s in signals]
        avg_confidence = (
            sum(threat_levels) / len(threat_levels) if threat_levels else 0.0
        )

        # Determine threat level
        if avg_confidence >= 0.8:
            threat_level = "critical"
        elif avg_confidence >= 0.6:
            threat_level = "high"
        elif avg_confidence >= 0.4:
            threat_level = "medium"
        else:
            threat_level = "low"

        # Aggregate signal types
        signal_types = [s.signal_type for s in signals]
        signal_type_counts = defaultdict(int)
        for st in signal_types:
            signal_type_counts[st] += 1

        return {
            "cve_id": cve_id,
            "threat_level": threat_level,
            "confidence": round(avg_confidence, 3),
            "signal_count": len(signals),
            "signal_types": dict(signal_type_counts),
            "signals": [
                {
                    "type": s.signal_type,
                    "source": s.source,
                    "confidence": s.confidence,
                    "timestamp": s.timestamp.isoformat(),
                }
                for s in signals
            ],
            "metadata": {
                "synthesized_at": datetime.now(timezone.utc).isoformat(),
                "algorithm_version": "1.0",
            },
        }
