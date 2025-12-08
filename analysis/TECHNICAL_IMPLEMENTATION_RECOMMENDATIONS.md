# Technical Implementation Recommendations for FixOps Gaps

## Overview

This document provides specific technical recommendations for addressing the vulnerability management gaps identified in the FixOps codebase analysis.

## 1. Reachability Analysis Integration

### Current State
FixOps currently scores vulnerabilities based on:
- EPSS scores
- KEV listing
- Version lag
- Exposure flags

**Missing**: Code analysis to verify if vulnerable code is actually invoked.

### Recommended Implementation

#### 1.1 Add Reachability Analysis Module

**File**: `risk/reachability.py` (new)

```python
"""Reachability analysis to determine if vulnerable code paths are actually invoked."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Set

logger = logging.getLogger(__name__)


@dataclass
class CodePath:
    """Represents a code path in the application."""
    
    file_path: str
    function_name: Optional[str] = None
    line_number: Optional[int] = None
    is_invoked: bool = False
    call_chain: List[str] = None  # List of functions in call chain


@dataclass
class VulnerabilityReachability:
    """Reachability analysis result for a vulnerability."""
    
    cve_id: str
    component_name: str
    component_version: str
    is_reachable: bool
    confidence: float  # 0.0 to 1.0
    code_paths: List[CodePath]
    call_graph_depth: int
    analysis_method: str  # "static", "dynamic", "hybrid"


class ReachabilityAnalyzer:
    """Analyze if vulnerable code is actually reachable in the application."""
    
    def __init__(self, config: Optional[Mapping[str, Any]] = None):
        self.config = config or {}
        self.static_analyzer = self._init_static_analyzer()
        self.call_graph_cache: Dict[str, Any] = {}
    
    def _init_static_analyzer(self):
        """Initialize static analysis tool (CodeQL, Semgrep, etc.)."""
        analyzer_type = self.config.get("analyzer", "semgrep")
        
        if analyzer_type == "codeql":
            # Integration with CodeQL
            return CodeQLAnalyzer(self.config.get("codeql_config"))
        elif analyzer_type == "semgrep":
            # Integration with Semgrep
            return SemgrepAnalyzer(self.config.get("semgrep_config"))
        else:
            logger.warning(f"Unknown analyzer type: {analyzer_type}")
            return None
    
    def analyze_vulnerability(
        self,
        cve_id: str,
        component_name: str,
        component_version: str,
        vulnerability_details: Mapping[str, Any],
        codebase_path: Optional[str] = None,
    ) -> VulnerabilityReachability:
        """Analyze if a vulnerability is reachable in the codebase."""
        
        # Extract vulnerable functions/files from CVE details
        vulnerable_patterns = self._extract_vulnerable_patterns(
            cve_id, vulnerability_details
        )
        
        if not vulnerable_patterns:
            # No code analysis possible, return low confidence
            return VulnerabilityReachability(
                cve_id=cve_id,
                component_name=component_name,
                component_version=component_version,
                is_reachable=False,
                confidence=0.0,
                code_paths=[],
                call_graph_depth=0,
                analysis_method="none",
            )
        
        # Build call graph if not cached
        if codebase_path and codebase_path not in self.call_graph_cache:
            self.call_graph_cache[codebase_path] = self._build_call_graph(
                codebase_path
            )
        
        call_graph = self.call_graph_cache.get(codebase_path, {})
        
        # Check reachability
        reachable_paths = []
        for pattern in vulnerable_patterns:
            paths = self._check_pattern_reachability(
                pattern, call_graph, codebase_path
            )
            reachable_paths.extend(paths)
        
        is_reachable = len(reachable_paths) > 0
        confidence = self._calculate_confidence(
            reachable_paths, vulnerable_patterns, call_graph
        )
        
        return VulnerabilityReachability(
            cve_id=cve_id,
            component_name=component_name,
            component_version=component_version,
            is_reachable=is_reachable,
            confidence=confidence,
            code_paths=reachable_paths,
            call_graph_depth=self._max_call_depth(reachable_paths),
            analysis_method="static" if self.static_analyzer else "none",
        )
    
    def _extract_vulnerable_patterns(
        self, cve_id: str, vulnerability_details: Mapping[str, Any]
    ) -> List[Dict[str, Any]]:
        """Extract vulnerable code patterns from CVE details."""
        patterns = []
        
        # Check for known vulnerable functions/APIs
        cwe_ids = vulnerability_details.get("cwe_ids", [])
        description = vulnerability_details.get("description", "")
        
        # Map CWE to vulnerable patterns
        for cwe_id in cwe_ids:
            if cwe_id == "CWE-89":  # SQL Injection
                patterns.append({
                    "type": "sql_injection",
                    "functions": ["executeQuery", "prepareStatement", "query"],
                })
            elif cwe_id == "CWE-78":  # Command Injection
                patterns.append({
                    "type": "command_injection",
                    "functions": ["exec", "system", "popen"],
                })
            # Add more CWE mappings...
        
        return patterns
    
    def _build_call_graph(self, codebase_path: str) -> Dict[str, Any]:
        """Build call graph using static analysis."""
        if not self.static_analyzer:
            return {}
        
        try:
            return self.static_analyzer.build_call_graph(codebase_path)
        except Exception as e:
            logger.error(f"Failed to build call graph: {e}")
            return {}
    
    def _check_pattern_reachability(
        self,
        pattern: Dict[str, Any],
        call_graph: Dict[str, Any],
        codebase_path: Optional[str],
    ) -> List[CodePath]:
        """Check if vulnerable pattern is reachable."""
        reachable_paths = []
        
        # Search for vulnerable functions in call graph
        vulnerable_functions = pattern.get("functions", [])
        
        for func_name in vulnerable_functions:
            if func_name in call_graph:
                # Function exists, check if it's called
                callers = call_graph.get(func_name, {}).get("callers", [])
                if callers:
                    # Function is invoked
                    for caller in callers:
                        reachable_paths.append(
                            CodePath(
                                file_path=caller.get("file", ""),
                                function_name=func_name,
                                line_number=caller.get("line"),
                                is_invoked=True,
                                call_chain=self._build_call_chain(
                                    caller, call_graph
                                ),
                            )
                        )
        
        return reachable_paths
    
    def _build_call_chain(
        self, start_node: Dict[str, Any], call_graph: Dict[str, Any]
    ) -> List[str]:
        """Build call chain from entry point to vulnerable function."""
        chain = []
        current = start_node
        
        while current:
            func_name = current.get("function")
            if func_name:
                chain.append(func_name)
            # Traverse up the call graph
            parent = current.get("parent")
            if parent and parent in call_graph:
                current = call_graph[parent]
            else:
                break
        
        return list(reversed(chain))  # Return from entry to vulnerable function
    
    def _calculate_confidence(
        self,
        reachable_paths: List[CodePath],
        vulnerable_patterns: List[Dict[str, Any]],
        call_graph: Dict[str, Any],
    ) -> float:
        """Calculate confidence score for reachability analysis."""
        if not reachable_paths:
            return 0.0
        
        if not call_graph:
            # No call graph available, low confidence
            return 0.3
        
        # Higher confidence if:
        # 1. Multiple reachable paths
        # 2. Short call chains (more direct)
        # 3. Entry points are public APIs
        
        path_count_factor = min(len(reachable_paths) / 5.0, 1.0)
        avg_depth = sum(len(p.call_chain) for p in reachable_paths) / len(
            reachable_paths
        )
        depth_factor = max(0.0, 1.0 - (avg_depth / 10.0))
        
        confidence = (path_count_factor * 0.4) + (depth_factor * 0.6)
        return min(1.0, max(0.0, confidence))
    
    def _max_call_depth(self, paths: List[CodePath]) -> int:
        """Calculate maximum call graph depth."""
        if not paths:
            return 0
        return max(len(p.call_chain) for p in paths if p.call_chain)


# Integration with risk scoring
def integrate_reachability_into_scoring(
    risk_score: float,
    reachability: VulnerabilityReachability,
    weights: Optional[Mapping[str, float]] = None,
) -> float:
    """Adjust risk score based on reachability analysis."""
    weights = weights or {"base_risk": 0.5, "reachability": 0.5}
    
    if not reachability.is_reachable:
        # Non-reachable vulnerabilities get significant reduction
        reduction_factor = 0.1  # Reduce to 10% of original score
        adjusted_score = risk_score * reduction_factor
    else:
        # Reachable vulnerabilities get boost based on confidence
        boost_factor = 1.0 + (reachability.confidence * 0.5)  # Up to 50% boost
        adjusted_score = risk_score * boost_factor
    
    return min(100.0, max(0.0, adjusted_score))
```

#### 1.2 Integration with Risk Scoring

**File**: `risk/scoring.py` (modify)

Add reachability analysis to the scoring function:

```python
# Add to imports
from risk.reachability import ReachabilityAnalyzer, integrate_reachability_into_scoring

# Modify _score_vulnerability function
def _score_vulnerability(
    component: Mapping[str, Any],
    vulnerability: Mapping[str, Any],
    epss_scores: Mapping[str, float],
    kev_entries: Mapping[str, Any],
    weights: Mapping[str, float],
    reachability_analyzer: Optional[ReachabilityAnalyzer] = None,
    codebase_path: Optional[str] = None,
) -> Dict[str, Any] | None:
    # ... existing scoring logic ...
    
    # Calculate base risk score
    final_score = round(normalized_score * 100, 2)
    
    # Apply reachability analysis if available
    reachability_result = None
    if reachability_analyzer and codebase_path:
        try:
            reachability_result = reachability_analyzer.analyze_vulnerability(
                cve_id=cve_id,
                component_name=component.get("name", ""),
                component_version=component.get("version", ""),
                vulnerability_details=vulnerability,
                codebase_path=codebase_path,
            )
            
            # Adjust score based on reachability
            final_score = integrate_reachability_into_scoring(
                final_score, reachability_result
            )
        except Exception as e:
            logger.warning(f"Reachability analysis failed for {cve_id}: {e}")
    
    return {
        "cve": cve_id,
        "epss": round(epss, 4),
        "kev": kev_present,
        "version_lag_days": round(lag_days, 2),
        "exposure_flags": exposure_flags,
        "reachability": reachability_result.to_dict() if reachability_result else None,
        "risk_breakdown": {
            "weights": dict(weights),
            "contributions": contributions,
            "normalized_score": round(normalized_score, 4),
        },
        "fixops_risk": final_score,
    }
```

## 2. Enhanced Triage Workflow

### Current State
No explicit triage workflow exists. All vulnerabilities are scored but not triaged.

### Recommended Implementation

#### 2.1 Triage Module

**File**: `core/triage.py` (new)

```python
"""Triage workflow for vulnerability management."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Mapping, Optional

logger = logging.getLogger(__name__)


class TriageDecision(Enum):
    """Triage decision types."""
    
    ACCEPT = "accept"  # Accept as valid vulnerability
    DISMISS = "dismiss"  # Dismiss as false positive
    DEFER = "defer"  # Defer for later review
    ESCALATE = "escalate"  # Escalate to security team
    REQUIRE_REVIEW = "require_review"  # Require human analyst review


@dataclass
class TriageRule:
    """Rule for automated triage decision."""
    
    name: str
    condition: Dict[str, Any]  # Conditions to match
    decision: TriageDecision
    confidence: float  # 0.0 to 1.0
    rationale: str


@dataclass
class TriageResult:
    """Result of triage analysis."""
    
    cve_id: str
    component_name: str
    automated_decision: Optional[TriageDecision]
    confidence: float
    requires_review: bool
    rationale: str
    rules_applied: List[str]
    analyst_review: Optional[Dict[str, Any]] = None
    false_positive: bool = False
    mttr_start: Optional[datetime] = None
    mttr_end: Optional[datetime] = None


class TriageEngine:
    """Engine for triaging vulnerabilities."""
    
    def __init__(self, config: Optional[Mapping[str, Any]] = None):
        self.config = config or {}
        self.rules = self._load_triage_rules()
        self.require_review_threshold = self.config.get(
            "require_review_threshold", 0.7
        )
    
    def _load_triage_rules(self) -> List[TriageRule]:
        """Load triage rules from configuration."""
        rules_config = self.config.get("rules", [])
        rules = []
        
        # Default rules
        default_rules = [
            TriageRule(
                name="auto_dismiss_low_epss",
                condition={
                    "epss_max": 0.1,
                    "kev": False,
                    "cvss_max": 5.0,
                },
                decision=TriageDecision.DISMISS,
                confidence=0.8,
                rationale="Low EPSS score, not KEV-listed, low CVSS",
            ),
            TriageRule(
                name="auto_accept_kev",
                condition={"kev": True},
                decision=TriageDecision.ACCEPT,
                confidence=0.95,
                rationale="KEV-listed vulnerability requires immediate attention",
            ),
            TriageRule(
                name="require_review_high_epss_no_kev",
                condition={
                    "epss_min": 0.7,
                    "kev": False,
                    "reachability_unknown": True,
                },
                decision=TriageDecision.REQUIRE_REVIEW,
                confidence=0.6,
                rationale="High EPSS but not KEV-listed, reachability unknown",
            ),
            TriageRule(
                name="dismiss_non_reachable",
                condition={
                    "reachability_is_reachable": False,
                    "reachability_confidence_min": 0.8,
                },
                decision=TriageDecision.DISMISS,
                confidence=0.9,
                rationale="Vulnerable code is not reachable with high confidence",
            ),
        ]
        
        # Load custom rules from config
        for rule_config in rules_config:
            try:
                rule = TriageRule(
                    name=rule_config.get("name", ""),
                    condition=rule_config.get("condition", {}),
                    decision=TriageDecision(rule_config.get("decision", "require_review")),
                    confidence=rule_config.get("confidence", 0.5),
                    rationale=rule_config.get("rationale", ""),
                )
                rules.append(rule)
            except Exception as e:
                logger.warning(f"Failed to load triage rule: {e}")
        
        return default_rules + rules
    
    def triage_vulnerability(
        self,
        vulnerability_data: Mapping[str, Any],
        risk_score: float,
        reachability: Optional[Mapping[str, Any]] = None,
    ) -> TriageResult:
        """Triage a vulnerability based on risk score and context."""
        
        cve_id = vulnerability_data.get("cve", "")
        component_name = vulnerability_data.get("component_name", "")
        
        # Evaluate rules
        matched_rules = []
        for rule in self.rules:
            if self._evaluate_rule(rule, vulnerability_data, risk_score, reachability):
                matched_rules.append(rule)
        
        # Determine decision
        decision = None
        confidence = 0.0
        rationale = ""
        
        if matched_rules:
            # Use highest confidence rule
            best_rule = max(matched_rules, key=lambda r: r.confidence)
            decision = best_rule.decision
            confidence = best_rule.confidence
            rationale = best_rule.rationale
        else:
            # No rule matched, require review
            decision = TriageDecision.REQUIRE_REVIEW
            confidence = 0.5
            rationale = "No automated rule matched, requires analyst review"
        
        # Check if confidence is below threshold
        requires_review = (
            decision != TriageDecision.REQUIRE_REVIEW
            and confidence < self.require_review_threshold
        ) or decision == TriageDecision.REQUIRE_REVIEW
        
        return TriageResult(
            cve_id=cve_id,
            component_name=component_name,
            automated_decision=decision if not requires_review else None,
            confidence=confidence,
            requires_review=requires_review,
            rationale=rationale,
            rules_applied=[r.name for r in matched_rules],
            mttr_start=datetime.now(timezone.utc) if decision == TriageDecision.ACCEPT else None,
        )
    
    def _evaluate_rule(
        self,
        rule: TriageRule,
        vulnerability_data: Mapping[str, Any],
        risk_score: float,
        reachability: Optional[Mapping[str, Any]],
    ) -> bool:
        """Evaluate if a rule matches the vulnerability."""
        condition = rule.condition
        
        # Check EPSS
        if "epss_max" in condition:
            epss = vulnerability_data.get("epss", 0.0)
            if epss > condition["epss_max"]:
                return False
        
        if "epss_min" in condition:
            epss = vulnerability_data.get("epss", 0.0)
            if epss < condition["epss_min"]:
                return False
        
        # Check KEV
        if "kev" in condition:
            kev = vulnerability_data.get("kev", False)
            if kev != condition["kev"]:
                return False
        
        # Check CVSS
        if "cvss_max" in condition:
            cvss = vulnerability_data.get("cvss_score", 0.0)
            if cvss > condition["cvss_max"]:
                return False
        
        # Check reachability
        if "reachability_is_reachable" in condition:
            if not reachability:
                return False
            is_reachable = reachability.get("is_reachable", False)
            if is_reachable != condition["reachability_is_reachable"]:
                return False
        
        if "reachability_confidence_min" in condition:
            if not reachability:
                return False
            confidence = reachability.get("confidence", 0.0)
            if confidence < condition["reachability_confidence_min"]:
                return False
        
        if "reachability_unknown" in condition:
            if reachability and reachability.get("is_reachable") is not None:
                return False
        
        return True
    
    def record_analyst_review(
        self,
        triage_result: TriageResult,
        analyst_decision: TriageDecision,
        false_positive: bool,
        notes: Optional[str] = None,
    ) -> TriageResult:
        """Record analyst review decision."""
        triage_result.analyst_review = {
            "decision": analyst_decision.value,
            "false_positive": false_positive,
            "notes": notes,
            "reviewed_at": datetime.now(timezone.utc).isoformat(),
        }
        triage_result.false_positive = false_positive
        
        if analyst_decision == TriageDecision.ACCEPT:
            triage_result.mttr_start = datetime.now(timezone.utc)
        elif analyst_decision == TriageDecision.DISMISS and false_positive:
            # Record false positive for metrics
            pass
        
        return triage_result
```

#### 2.2 Metrics Collection

**File**: `core/triage_metrics.py` (new)

```python
"""Metrics collection for triage workflow."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Mapping

from core.triage import TriageDecision, TriageResult


@dataclass
class TriageMetrics:
    """Metrics for triage performance."""
    
    total_vulnerabilities: int
    automated_decisions: int
    require_review: int
    false_positive_count: int
    false_positive_rate: float
    mttr_avg_hours: float
    mttr_median_hours: float
    noise_reduction_percent: float
    analyst_review_count: int


class TriageMetricsCollector:
    """Collect metrics from triage results."""
    
    def __init__(self):
        self.results: List[TriageResult] = []
        self.analyst_reviews: List[Dict[str, Any]] = []
    
    def add_result(self, result: TriageResult):
        """Add a triage result for metrics collection."""
        self.results.append(result)
        if result.analyst_review:
            self.analyst_reviews.append(result.analyst_review)
    
    def calculate_metrics(
        self, time_window: Optional[timedelta] = None
    ) -> TriageMetrics:
        """Calculate metrics for the collected results."""
        if time_window:
            cutoff = datetime.now(timezone.utc) - time_window
            results = [r for r in self.results if r.mttr_start and r.mttr_start >= cutoff]
        else:
            results = self.results
        
        total = len(results)
        automated = sum(
            1 for r in results if r.automated_decision and not r.requires_review
        )
        require_review = sum(1 for r in results if r.requires_review)
        false_positives = sum(1 for r in results if r.false_positive)
        
        false_positive_rate = (false_positives / total * 100) if total > 0 else 0.0
        
        # Calculate MTTR
        mttr_times = []
        for result in results:
            if result.mttr_start and result.mttr_end:
                delta = result.mttr_end - result.mttr_start
                mttr_times.append(delta.total_seconds() / 3600)  # Convert to hours
        
        mttr_avg = sum(mttr_times) / len(mttr_times) if mttr_times else 0.0
        mttr_median = (
            sorted(mttr_times)[len(mttr_times) // 2] if mttr_times else 0.0
        )
        
        # Calculate noise reduction
        # Noise reduction = (dismissed false positives) / (total before filtering)
        dismissed_fp = sum(
            1
            for r in results
            if r.automated_decision == TriageDecision.DISMISS and r.false_positive
        )
        noise_reduction = (
            (dismissed_fp / total * 100) if total > 0 else 0.0
        )
        
        analyst_review_count = len(self.analyst_reviews)
        
        return TriageMetrics(
            total_vulnerabilities=total,
            automated_decisions=automated,
            require_review=require_review,
            false_positive_count=false_positives,
            false_positive_rate=false_positive_rate,
            mttr_avg_hours=mttr_avg,
            mttr_median_hours=mttr_median,
            noise_reduction_percent=noise_reduction,
            analyst_review_count=analyst_review_count,
        )
```

## 3. Zero-Day Detection Enhancement

### Recommended Implementation

#### 3.1 Multi-Source Threat Feed Integration

**File**: `risk/feeds/multi_source.py` (new)

```python
"""Multi-source threat feed integration for zero-day detection."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Mapping, Optional

import requests

logger = logging.getLogger(__name__)


class MultiSourceThreatFeed:
    """Aggregate threat intelligence from multiple sources."""
    
    def __init__(self, config: Optional[Mapping[str, Any]] = None):
        self.config = config or {}
        self.feeds = self._initialize_feeds()
    
    def _initialize_feeds(self) -> List[Dict[str, Any]]:
        """Initialize threat feed sources."""
        feeds = []
        
        # GitHub Security Advisories
        if self.config.get("github_enabled", True):
            feeds.append({
                "name": "github",
                "url": "https://api.github.com/repos/github/advisory-database/contents/advisories",
                "parser": self._parse_github_advisory,
            })
        
        # OSV Database
        if self.config.get("osv_enabled", True):
            feeds.append({
                "name": "osv",
                "url": "https://osv.dev/api/v1/query",
                "parser": self._parse_osv,
            })
        
        # Add more feeds as needed
        
        return feeds
    
    def fetch_recent_vulnerabilities(
        self, hours: int = 24
    ) -> List[Dict[str, Any]]:
        """Fetch vulnerabilities from last N hours."""
        all_vulns = []
        
        for feed in self.feeds:
            try:
                vulns = self._fetch_from_feed(feed, hours)
                all_vulns.extend(vulns)
            except Exception as e:
                logger.error(f"Failed to fetch from {feed['name']}: {e}")
        
        # Deduplicate and sort by date
        seen = set()
        unique_vulns = []
        for vuln in all_vulns:
            cve_id = vuln.get("cve_id", "")
            if cve_id and cve_id not in seen:
                seen.add(cve_id)
                unique_vulns.append(vuln)
        
        return sorted(
            unique_vulns,
            key=lambda v: v.get("published_date", ""),
            reverse=True,
        )
    
    def _fetch_from_feed(
        self, feed: Dict[str, Any], hours: int
    ) -> List[Dict[str, Any]]:
        """Fetch vulnerabilities from a specific feed."""
        # Implementation depends on feed type
        # This is a simplified example
        response = requests.get(feed["url"], timeout=10)
        response.raise_for_status()
        data = response.json()
        
        return feed["parser"](data, hours)
    
    def _parse_github_advisory(
        self, data: Any, hours: int
    ) -> List[Dict[str, Any]]:
        """Parse GitHub Security Advisory format."""
        vulns = []
        # Implementation for GitHub advisory parsing
        return vulns
    
    def _parse_osv(self, data: Any, hours: int) -> List[Dict[str, Any]]:
        """Parse OSV database format."""
        vulns = []
        # Implementation for OSV parsing
        return vulns
```

## 4. SBOM Enrichment

### Recommended Implementation

**File**: `lib4sbom/enrichment.py` (new)

```python
"""SBOM enrichment from external sources."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Mapping, Optional

logger = logging.getLogger(__name__)


class SBOMEnricher:
    """Enrich incomplete SBOMs with external data sources."""
    
    def __init__(self, config: Optional[Mapping[str, Any]] = None):
        self.config = config or {}
        self.registries = self._initialize_registries()
    
    def _initialize_registries(self) -> List[Dict[str, Any]]:
        """Initialize package registry integrations."""
        return [
            {"name": "npm", "url": "https://registry.npmjs.org"},
            {"name": "pypi", "url": "https://pypi.org/pypi"},
            {"name": "maven", "url": "https://repo1.maven.org/maven2"},
            # Add more registries
        ]
    
    def enrich_component(
        self, component: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        """Enrich a single component with missing metadata."""
        enriched = dict(component)
        
        # Check for missing fields
        missing_fields = []
        if not component.get("purl"):
            missing_fields.append("purl")
        if not component.get("version"):
            missing_fields.append("version")
        if not component.get("licenses"):
            missing_fields.append("licenses")
        
        if not missing_fields:
            return enriched
        
        # Try to enrich from registries
        for registry in self.registries:
            try:
                metadata = self._fetch_from_registry(
                    component, registry
                )
                if metadata:
                    enriched.update(metadata)
                    break
            except Exception as e:
                logger.warning(
                    f"Failed to enrich from {registry['name']}: {e}"
                )
        
        return enriched
    
    def _fetch_from_registry(
        self, component: Mapping[str, Any], registry: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Fetch component metadata from a registry."""
        # Implementation depends on registry type
        # This would make API calls to fetch missing metadata
        return None
```

## Integration Points

### Pipeline Integration

Modify `apps/api/pipeline.py` to integrate new modules:

```python
# Add imports
from risk.reachability import ReachabilityAnalyzer
from core.triage import TriageEngine
from risk.feeds.multi_source import MultiSourceThreatFeed

# In PipelineOrchestrator.run()
def run(self, ...):
    # ... existing pipeline logic ...
    
    # Add reachability analysis
    if self.overlay.get("enable_reachability_analysis", False):
        reachability_analyzer = ReachabilityAnalyzer(
            self.overlay.get("reachability_config")
        )
        # Analyze vulnerabilities
        for vulnerability in vulnerabilities:
            reachability = reachability_analyzer.analyze_vulnerability(...)
            # Update risk scores
    
    # Add triage workflow
    if self.overlay.get("enable_triage", True):
        triage_engine = TriageEngine(self.overlay.get("triage_config"))
        for vulnerability in vulnerabilities:
            triage_result = triage_engine.triage_vulnerability(...)
            # Store triage results
    
    # Add multi-source threat feeds
    if self.overlay.get("enable_multi_source_feeds", True):
        threat_feed = MultiSourceThreatFeed(
            self.overlay.get("threat_feed_config")
        )
        recent_vulns = threat_feed.fetch_recent_vulnerabilities(hours=24)
        # Merge with existing CVE feed
```

## Configuration Updates

Add to `config/fixops.overlay.yml`:

```yaml
reachability_analysis:
  enabled: true
  analyzer: "semgrep"  # or "codeql"
  codebase_path: "/path/to/codebase"
  config:
    semgrep_config:
      rules: ["security", "vulnerability"]

triage:
  enabled: true
  require_review_threshold: 0.7
  rules:
    - name: "custom_rule"
      condition:
        epss_max: 0.2
      decision: "dismiss"
      confidence: 0.8
      rationale: "Low risk vulnerability"

threat_feeds:
  github_enabled: true
  osv_enabled: true
  refresh_interval_hours: 1  # More frequent for zero-day detection
```

This implementation provides a foundation for addressing the identified gaps while maintaining compatibility with the existing FixOps architecture.
