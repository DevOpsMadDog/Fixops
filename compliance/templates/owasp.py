"""OWASP Top 10 Compliance Template

Pre-built rules and checks for OWASP Top 10 compliance.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

from compliance.templates.base import ComplianceRule, ComplianceTemplate


@dataclass
class OWASPRule(ComplianceRule):
    """OWASP compliance rule."""

    owasp_category: str  # A01, A02, etc.
    cwe_ids: List[str] = None


class OWASPTemplate(ComplianceTemplate):
    """OWASP Top 10 compliance template."""

    def __init__(self):
        """Initialize OWASP template."""
        super().__init__("OWASP Top 10", "2021")
        self.rules = self._build_owasp_rules()

    def _build_owasp_rules(self) -> List[OWASPRule]:
        """Build OWASP Top 10 rules."""
        return [
            OWASPRule(
                id="OWASP-A01",
                name="Broken Access Control",
                description="Verify proper access control implementation",
                severity="high",
                owasp_category="A01",
                cwe_ids=["CWE-284", "CWE-285", "CWE-639"],
                checks=[
                    "Verify authentication is required for all protected resources",
                    "Verify authorization checks are performed server-side",
                    "Verify user permissions are validated on every request",
                ],
            ),
            OWASPRule(
                id="OWASP-A02",
                name="Cryptographic Failures",
                description="Verify proper cryptographic implementation",
                severity="high",
                owasp_category="A02",
                cwe_ids=["CWE-327", "CWE-326", "CWE-311"],
                checks=[
                    "Verify sensitive data is encrypted in transit (TLS 1.2+)",
                    "Verify sensitive data is encrypted at rest",
                    "Verify weak cryptographic algorithms are not used",
                ],
            ),
            OWASPRule(
                id="OWASP-A03",
                name="Injection",
                description="Prevent injection attacks",
                severity="critical",
                owasp_category="A03",
                cwe_ids=["CWE-89", "CWE-78", "CWE-79", "CWE-91"],
                checks=[
                    "Verify SQL injection prevention (parameterized queries)",
                    "Verify command injection prevention",
                    "Verify XSS prevention (output encoding)",
                    "Verify LDAP injection prevention",
                ],
            ),
            OWASPRule(
                id="OWASP-A04",
                name="Insecure Design",
                description="Verify secure design principles",
                severity="high",
                owasp_category="A04",
                cwe_ids=["CWE-209", "CWE-209"],
                checks=[
                    "Verify threat modeling is performed",
                    "Verify security requirements are defined",
                    "Verify secure design patterns are used",
                ],
            ),
            OWASPRule(
                id="OWASP-A05",
                name="Security Misconfiguration",
                description="Verify secure configuration",
                severity="high",
                owasp_category="A05",
                cwe_ids=["CWE-16", "CWE-611"],
                checks=[
                    "Verify default credentials are changed",
                    "Verify unnecessary features are disabled",
                    "Verify security headers are configured",
                    "Verify error messages don't leak sensitive information",
                ],
            ),
            OWASPRule(
                id="OWASP-A06",
                name="Vulnerable and Outdated Components",
                description="Verify component security",
                severity="high",
                owasp_category="A06",
                cwe_ids=["CWE-1104"],
                checks=[
                    "Verify all dependencies are up to date",
                    "Verify vulnerable components are patched",
                    "Verify SBOM is maintained",
                ],
            ),
            OWASPRule(
                id="OWASP-A07",
                name="Identification and Authentication Failures",
                description="Verify authentication security",
                severity="high",
                owasp_category="A07",
                cwe_ids=["CWE-287", "CWE-798", "CWE-521"],
                checks=[
                    "Verify MFA is implemented",
                    "Verify password policies are enforced",
                    "Verify session management is secure",
                    "Verify authentication failures are logged",
                ],
            ),
            OWASPRule(
                id="OWASP-A08",
                name="Software and Data Integrity Failures",
                description="Verify integrity controls",
                severity="high",
                owasp_category="A08",
                cwe_ids=["CWE-494", "CWE-502", "CWE-345"],
                checks=[
                    "Verify CI/CD pipeline integrity",
                    "Verify dependency integrity (signatures)",
                    "Verify code signing is used",
                ],
            ),
            OWASPRule(
                id="OWASP-A09",
                name="Security Logging and Monitoring Failures",
                description="Verify logging and monitoring",
                severity="medium",
                owasp_category="A09",
                cwe_ids=["CWE-778", "CWE-117"],
                checks=[
                    "Verify security events are logged",
                    "Verify logs are monitored",
                    "Verify alerting is configured",
                    "Verify log integrity is maintained",
                ],
            ),
            OWASPRule(
                id="OWASP-A10",
                name="Server-Side Request Forgery (SSRF)",
                description="Prevent SSRF attacks",
                severity="high",
                owasp_category="A10",
                cwe_ids=["CWE-918"],
                checks=[
                    "Verify user input is validated for URLs",
                    "Verify network segmentation is used",
                    "Verify outbound requests are restricted",
                ],
            ),
        ]

    def get_rules_by_category(self, category: str) -> List[OWASPRule]:
        """Get rules for specific OWASP category."""
        return [r for r in self.rules if r.owasp_category == category]

    def assess_compliance(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess OWASP Top 10 compliance."""
        compliance_by_category = {}

        for rule in self.rules:
            category = rule.owasp_category
            category_findings = [
                f
                for f in findings
                if any(cwe in f.get("cwe_ids", []) for cwe in rule.cwe_ids)
            ]

            compliance_by_category[category] = {
                "name": rule.name,
                "compliant": len(category_findings) == 0,
                "findings_count": len(category_findings),
                "severity": rule.severity,
            }

        total_categories = len(compliance_by_category)
        compliant_categories = sum(
            1 for c in compliance_by_category.values() if c["compliant"]
        )

        compliance_score = (
            (compliant_categories / total_categories * 100)
            if total_categories > 0
            else 0
        )

        return {
            "framework": "OWASP Top 10",
            "version": "2021",
            "compliance_score": round(compliance_score, 2),
            "compliant_categories": compliant_categories,
            "total_categories": total_categories,
            "by_category": compliance_by_category,
        }
