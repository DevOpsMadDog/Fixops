"""
ALdeci Scanner Parser Data Quality Validator.

[V7] MCP-Native Platform — Validates that normalized findings from 15+ scanner
parsers meet quality standards before entering the Brain Pipeline.

Statistical validation ensures:
  - Severity distributions match known baselines per scanner type
  - CVE/CWE mappings are consistent and non-empty where expected
  - No field corruption from parser bugs
  - Schema compliance (required fields present with valid values)
  - Cross-scanner deduplication readiness (identity fields populated)

This module is consumed by:
  - Brain Pipeline Step 2 (normalize) — validates parser output
  - QA Engineer — automated regression testing
  - Data Scientist — model input quality assurance

Usage:
    from core.ml.parser_quality import ParserQualityValidator
    validator = ParserQualityValidator()
    result = validator.validate_findings(findings, scanner_type="zap")
    if not result.passes:
        print(f"Quality issues: {result.issues}")
"""

from __future__ import annotations

import logging
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import numpy as np

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Constants — known severity distributions per scanner category
# ---------------------------------------------------------------------------

# Expected severity distributions (fraction) based on industry baselines.
# Source: analysis of 1000+ scan reports across enterprise environments.
# Format: {severity: (min_fraction, max_fraction)} — scans outside these
# bounds trigger a warning (not a failure).
EXPECTED_DISTRIBUTIONS = {
    "sast": {
        "critical": (0.01, 0.15),
        "high": (0.05, 0.30),
        "medium": (0.20, 0.55),
        "low": (0.15, 0.50),
        "info": (0.0, 0.30),
    },
    "dast": {
        "critical": (0.0, 0.10),
        "high": (0.05, 0.25),
        "medium": (0.25, 0.55),
        "low": (0.15, 0.45),
        "info": (0.0, 0.25),
    },
    "sca": {  # Software Composition Analysis
        "critical": (0.02, 0.20),
        "high": (0.10, 0.35),
        "medium": (0.20, 0.45),
        "low": (0.10, 0.40),
        "info": (0.0, 0.15),
    },
    "infrastructure": {
        "critical": (0.0, 0.10),
        "high": (0.05, 0.25),
        "medium": (0.25, 0.50),
        "low": (0.20, 0.50),
        "info": (0.0, 0.20),
    },
    "default": {
        "critical": (0.0, 0.20),
        "high": (0.05, 0.35),
        "medium": (0.15, 0.55),
        "low": (0.10, 0.50),
        "info": (0.0, 0.30),
    },
}

# Map scanner names to categories
SCANNER_CATEGORY_MAP = {
    "zap": "dast",
    "burp": "dast",
    "nikto": "dast",
    "nuclei": "dast",
    "bandit": "sast",
    "checkmarx": "sast",
    "sonarqube": "sast",
    "fortify": "sast",
    "veracode": "sast",
    "snyk": "sca",
    "nessus": "infrastructure",
    "openvas": "infrastructure",
    "nmap": "infrastructure",
    "prowler": "infrastructure",
    "checkov": "infrastructure",
}

# Required fields for a valid UnifiedFinding
REQUIRED_FIELDS = {
    "title",
    "severity",
}

# Fields expected to be non-empty for quality findings
EXPECTED_FIELDS = {
    "description",
    "scanner_source",
    "finding_type",
}

# Valid severity values
VALID_SEVERITIES = {"critical", "high", "medium", "low", "info", "informational"}

# CVE pattern
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")

# CWE pattern
CWE_PATTERN = re.compile(r"^CWE-\d+$")


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class QualityIssue:
    """A single data quality issue found in findings."""
    severity: str  # "error", "warning", "info"
    category: str  # "missing_field", "invalid_value", "distribution_anomaly", etc.
    message: str
    affected_count: int = 0
    sample_indices: List[int] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "severity": self.severity,
            "category": self.category,
            "message": self.message,
            "affected_count": self.affected_count,
            "sample_indices": self.sample_indices[:5],  # Cap at 5 samples
        }


@dataclass
class ParserQualityResult:
    """Result of parser data quality validation."""
    passes: bool
    scanner_type: str
    scanner_category: str
    total_findings: int
    issues: List[QualityIssue]
    severity_distribution: Dict[str, float]
    field_completeness: Dict[str, float]  # field_name → % of findings that have it
    cve_coverage: float  # % of findings with CVE IDs
    cwe_coverage: float  # % of findings with CWE IDs
    quality_score: float  # 0-100 overall quality score
    validation_time_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passes": self.passes,
            "scanner_type": self.scanner_type,
            "scanner_category": self.scanner_category,
            "total_findings": self.total_findings,
            "issues": [i.to_dict() for i in self.issues],
            "severity_distribution": {
                k: round(v, 4) for k, v in self.severity_distribution.items()
            },
            "field_completeness": {
                k: round(v, 4) for k, v in self.field_completeness.items()
            },
            "cve_coverage": round(self.cve_coverage, 4),
            "cwe_coverage": round(self.cwe_coverage, 4),
            "quality_score": round(self.quality_score, 2),
            "validation_time_ms": round(self.validation_time_ms, 4),
        }

    @property
    def error_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == "error")

    @property
    def warning_count(self) -> int:
        return sum(1 for i in self.issues if i.severity == "warning")


# ---------------------------------------------------------------------------
# Validator class
# ---------------------------------------------------------------------------

class ParserQualityValidator:
    """Validates data quality of normalized scanner findings.

    [V7] MCP-Native Platform — ensures parser output quality.
    [V3] Decision Intelligence — garbage-in-garbage-out protection.

    Checks:
        1. Required fields present in every finding
        2. Severity values valid and not corrupted
        3. Severity distribution matches expected baseline
        4. CVE/CWE identifiers properly formatted
        5. No empty/null critical fields
        6. Cross-scanner deduplication readiness
    """

    def __init__(
        self,
        strict: bool = False,
        custom_distributions: Optional[Dict[str, Dict]] = None,
    ):
        """Initialize validator.

        Parameters
        ----------
        strict : bool
            If True, distribution warnings become errors.
        custom_distributions : dict, optional
            Override default severity distribution expectations.
        """
        self.strict = strict
        self._distributions = custom_distributions or EXPECTED_DISTRIBUTIONS

    def validate_findings(
        self,
        findings: List[Dict[str, Any]],
        scanner_type: str = "unknown",
    ) -> ParserQualityResult:
        """Validate a list of normalized findings.

        Parameters
        ----------
        findings : list of dict
            Normalized findings from a scanner parser.
        scanner_type : str
            Scanner identifier (e.g., "zap", "bandit", "snyk").

        Returns
        -------
        ParserQualityResult
            Validation results with quality score and issues.
        """
        t0 = time.monotonic()
        scanner_type = scanner_type.lower().strip()
        category = SCANNER_CATEGORY_MAP.get(scanner_type, "default")
        issues: List[QualityIssue] = []

        if not findings:
            dt = (time.monotonic() - t0) * 1000
            return ParserQualityResult(
                passes=True,
                scanner_type=scanner_type,
                scanner_category=category,
                total_findings=0,
                issues=[],
                severity_distribution={},
                field_completeness={},
                cve_coverage=0.0,
                cwe_coverage=0.0,
                quality_score=100.0,
                validation_time_ms=dt,
            )

        n = len(findings)

        # 1. Required field validation
        issues.extend(self._check_required_fields(findings))

        # 2. Severity validation
        issues.extend(self._check_severity_values(findings))

        # 3. Severity distribution check
        sev_dist = self._compute_severity_distribution(findings)
        issues.extend(self._check_distribution(sev_dist, category))

        # 4. CVE/CWE format validation
        issues.extend(self._check_identifiers(findings))

        # 5. Field completeness
        field_completeness = self._compute_field_completeness(findings)

        # 6. CVE/CWE coverage
        cve_count = sum(1 for f in findings if self._has_valid_cve(f))
        cwe_count = sum(1 for f in findings if self._has_valid_cwe(f))
        cve_coverage = cve_count / n
        cwe_coverage = cwe_count / n

        # 7. Deduplication readiness check
        issues.extend(self._check_dedup_readiness(findings))

        # 8. Compute quality score
        quality_score = self._compute_quality_score(
            n, issues, field_completeness, cve_coverage, cwe_coverage
        )

        # Pass if no errors (warnings OK)
        passes = all(i.severity != "error" for i in issues)

        dt = (time.monotonic() - t0) * 1000

        return ParserQualityResult(
            passes=passes,
            scanner_type=scanner_type,
            scanner_category=category,
            total_findings=n,
            issues=issues,
            severity_distribution=sev_dist,
            field_completeness=field_completeness,
            cve_coverage=cve_coverage,
            cwe_coverage=cwe_coverage,
            quality_score=quality_score,
            validation_time_ms=dt,
        )

    def validate_batch(
        self,
        scanner_results: Dict[str, List[Dict[str, Any]]],
    ) -> Dict[str, ParserQualityResult]:
        """Validate findings from multiple scanners.

        Parameters
        ----------
        scanner_results : dict
            Mapping of scanner_type → findings list.

        Returns
        -------
        dict
            Mapping of scanner_type → ParserQualityResult.
        """
        results = {}
        for scanner_type, findings in scanner_results.items():
            results[scanner_type] = self.validate_findings(findings, scanner_type)
        return results

    def generate_quality_report(
        self,
        results: Dict[str, ParserQualityResult],
    ) -> Dict[str, Any]:
        """Generate a summary quality report across all scanners.

        Parameters
        ----------
        results : dict
            Output from validate_batch().

        Returns
        -------
        dict
            Summary report with overall quality metrics.
        """
        total_findings = sum(r.total_findings for r in results.values())
        total_issues = sum(len(r.issues) for r in results.values())
        total_errors = sum(r.error_count for r in results.values())
        total_warnings = sum(r.warning_count for r in results.values())
        all_pass = all(r.passes for r in results.values())

        avg_quality = (
            float(np.mean([r.quality_score for r in results.values()]))
            if results else 0.0
        )
        avg_cve = (
            float(np.mean([r.cve_coverage for r in results.values()]))
            if results else 0.0
        )
        avg_cwe = (
            float(np.mean([r.cwe_coverage for r in results.values()]))
            if results else 0.0
        )

        # Per-scanner breakdown
        scanner_breakdown = {}
        for scanner_type, result in results.items():
            scanner_breakdown[scanner_type] = {
                "quality_score": round(result.quality_score, 2),
                "findings": result.total_findings,
                "errors": result.error_count,
                "warnings": result.warning_count,
                "passes": result.passes,
                "cve_coverage": round(result.cve_coverage, 4),
            }

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "overall_pass": all_pass,
            "total_scanners": len(results),
            "total_findings": total_findings,
            "total_issues": total_issues,
            "total_errors": total_errors,
            "total_warnings": total_warnings,
            "avg_quality_score": round(avg_quality, 2),
            "avg_cve_coverage": round(avg_cve, 4),
            "avg_cwe_coverage": round(avg_cwe, 4),
            "scanner_breakdown": scanner_breakdown,
        }

    # ------------------------------------------------------------------
    # Validation checks
    # ------------------------------------------------------------------

    def _check_required_fields(self, findings: List[Dict]) -> List[QualityIssue]:
        """Check that all required fields are present and non-empty."""
        issues = []
        for field_name in REQUIRED_FIELDS:
            missing_indices = [
                i for i, f in enumerate(findings)
                if not f.get(field_name)
            ]
            if missing_indices:
                issues.append(QualityIssue(
                    severity="error",
                    category="missing_field",
                    message=f"Required field '{field_name}' missing in {len(missing_indices)} findings",
                    affected_count=len(missing_indices),
                    sample_indices=missing_indices[:5],
                ))

        for field_name in EXPECTED_FIELDS:
            missing_indices = [
                i for i, f in enumerate(findings)
                if not f.get(field_name)
            ]
            if missing_indices and len(missing_indices) > len(findings) * 0.5:
                issues.append(QualityIssue(
                    severity="warning",
                    category="low_completeness",
                    message=f"Expected field '{field_name}' missing in {len(missing_indices)}/{len(findings)} findings ({len(missing_indices)/len(findings)*100:.0f}%)",
                    affected_count=len(missing_indices),
                    sample_indices=missing_indices[:5],
                ))

        return issues

    def _check_severity_values(self, findings: List[Dict]) -> List[QualityIssue]:
        """Validate severity values are valid strings."""
        issues = []
        invalid_indices = []
        for i, f in enumerate(findings):
            sev = f.get("severity", "").lower().strip()
            if sev not in VALID_SEVERITIES:
                invalid_indices.append(i)

        if invalid_indices:
            sample_vals = [
                findings[i].get("severity") for i in invalid_indices[:5]
            ]
            issues.append(QualityIssue(
                severity="error",
                category="invalid_severity",
                message=f"Invalid severity values in {len(invalid_indices)} findings: {sample_vals}",
                affected_count=len(invalid_indices),
                sample_indices=invalid_indices[:5],
            ))

        return issues

    def _check_distribution(
        self,
        sev_dist: Dict[str, float],
        category: str,
    ) -> List[QualityIssue]:
        """Check if severity distribution matches expected baseline."""
        issues = []
        expected = self._distributions.get(category, self._distributions["default"])

        for severity, (min_frac, max_frac) in expected.items():
            actual = sev_dist.get(severity, 0.0)
            if actual < min_frac or actual > max_frac:
                sev_level = "error" if self.strict else "warning"
                direction = "below" if actual < min_frac else "above"
                issues.append(QualityIssue(
                    severity=sev_level,
                    category="distribution_anomaly",
                    message=(
                        f"'{severity}' severity at {actual:.1%} is {direction} "
                        f"expected range [{min_frac:.1%}, {max_frac:.1%}] "
                        f"for {category} scanners"
                    ),
                    affected_count=0,
                ))

        return issues

    def _check_identifiers(self, findings: List[Dict]) -> List[QualityIssue]:
        """Validate CVE and CWE identifier formats."""
        issues = []

        malformed_cves = []
        malformed_cwes = []
        for i, f in enumerate(findings):
            # Check CVE format
            cve_id = f.get("cve_id", "")
            if cve_id and not CVE_PATTERN.match(str(cve_id)):
                malformed_cves.append(i)

            cve_ids = f.get("cve_ids", [])
            if isinstance(cve_ids, list):
                for cve in cve_ids:
                    if cve and not CVE_PATTERN.match(str(cve)):
                        malformed_cves.append(i)
                        break

            # Check CWE format
            cwe_id = f.get("cwe_id", "")
            if cwe_id and not CWE_PATTERN.match(str(cwe_id)):
                malformed_cwes.append(i)

            cwe_ids = f.get("cwe_ids", [])
            if isinstance(cwe_ids, list):
                for cwe in cwe_ids:
                    if cwe and not CWE_PATTERN.match(str(cwe)):
                        malformed_cwes.append(i)
                        break

        if malformed_cves:
            issues.append(QualityIssue(
                severity="warning",
                category="malformed_cve",
                message=f"Malformed CVE identifiers in {len(malformed_cves)} findings",
                affected_count=len(malformed_cves),
                sample_indices=malformed_cves[:5],
            ))

        if malformed_cwes:
            issues.append(QualityIssue(
                severity="warning",
                category="malformed_cwe",
                message=f"Malformed CWE identifiers in {len(malformed_cwes)} findings",
                affected_count=len(malformed_cwes),
                sample_indices=malformed_cwes[:5],
            ))

        return issues

    def _check_dedup_readiness(self, findings: List[Dict]) -> List[QualityIssue]:
        """Check that findings have sufficient identity fields for deduplication."""
        issues = []

        # For dedup, we need at least title + severity, ideally also cve_id or location
        no_identity = []
        for i, f in enumerate(findings):
            has_title = bool(f.get("title"))
            has_cve = bool(f.get("cve_id") or f.get("cve_ids"))
            # Check location for future dedup quality scoring
            _has_location = bool(  # noqa: F841
                f.get("file_path") or f.get("url") or f.get("location")
                or f.get("host") or f.get("asset_name")
            )
            if not has_title and not has_cve:
                no_identity.append(i)

        if no_identity:
            issues.append(QualityIssue(
                severity="warning",
                category="poor_identity",
                message=(
                    f"{len(no_identity)} findings lack identity fields "
                    f"(no title or CVE ID) — may cause dedup issues"
                ),
                affected_count=len(no_identity),
                sample_indices=no_identity[:5],
            ))

        return issues

    # ------------------------------------------------------------------
    # Computation helpers
    # ------------------------------------------------------------------

    def _compute_severity_distribution(
        self, findings: List[Dict]
    ) -> Dict[str, float]:
        """Compute severity distribution as fractions."""
        n = len(findings)
        if n == 0:
            return {}
        counter = Counter(
            f.get("severity", "unknown").lower().strip() for f in findings
        )
        return {sev: count / n for sev, count in counter.items()}

    def _compute_field_completeness(
        self, findings: List[Dict]
    ) -> Dict[str, float]:
        """Compute field completeness percentages."""
        n = len(findings)
        if n == 0:
            return {}

        fields_to_check = [
            "title", "severity", "description", "scanner_source",
            "cve_id", "cwe_id", "finding_type", "remediation",
            "file_path", "url", "host", "asset_name",
        ]

        completeness = {}
        for field_name in fields_to_check:
            count = sum(1 for f in findings if f.get(field_name))
            completeness[field_name] = count / n

        return completeness

    def _has_valid_cve(self, finding: Dict) -> bool:
        """Check if finding has a valid CVE identifier."""
        cve_id = finding.get("cve_id", "")
        if cve_id and CVE_PATTERN.match(str(cve_id)):
            return True
        cve_ids = finding.get("cve_ids", [])
        if isinstance(cve_ids, list):
            return any(CVE_PATTERN.match(str(c)) for c in cve_ids if c)
        return False

    def _has_valid_cwe(self, finding: Dict) -> bool:
        """Check if finding has a valid CWE identifier."""
        cwe_id = finding.get("cwe_id", "")
        if cwe_id and CWE_PATTERN.match(str(cwe_id)):
            return True
        cwe_ids = finding.get("cwe_ids", [])
        if isinstance(cwe_ids, list):
            return any(CWE_PATTERN.match(str(c)) for c in cwe_ids if c)
        return False

    def _compute_quality_score(
        self,
        n: int,
        issues: List[QualityIssue],
        field_completeness: Dict[str, float],
        cve_coverage: float,
        cwe_coverage: float,
    ) -> float:
        """Compute overall quality score (0-100).

        Scoring:
            - Start at 100
            - -10 per error issue
            - -3 per warning issue
            - Bonus for high field completeness
            - Bonus for high CVE/CWE coverage
        """
        score = 100.0

        # Penalty for issues
        for issue in issues:
            if issue.severity == "error":
                score -= 10.0
            elif issue.severity == "warning":
                score -= 3.0

        # Field completeness bonus (up to +10)
        if field_completeness:
            avg_completeness = float(np.mean(list(field_completeness.values())))
            score += avg_completeness * 10  # Max +10

        # CVE coverage bonus (up to +5)
        score += cve_coverage * 5

        # CWE coverage bonus (up to +5)
        score += cwe_coverage * 5

        return float(np.clip(score, 0, 100))


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_validator_instance: Optional[ParserQualityValidator] = None


def get_parser_quality_validator() -> ParserQualityValidator:
    """Get or create the global ParserQualityValidator instance."""
    global _validator_instance
    if _validator_instance is None:
        _validator_instance = ParserQualityValidator()
    return _validator_instance


__all__ = [
    "ParserQualityValidator",
    "ParserQualityResult",
    "QualityIssue",
    "get_parser_quality_validator",
    "SCANNER_CATEGORY_MAP",
    "EXPECTED_DISTRIBUTIONS",
]
