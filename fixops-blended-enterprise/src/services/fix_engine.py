"""
FixOps Fix Engine - Automated remediation and pull request generation
Performance-optimized automated security fix suggestions and implementation
"""

import asyncio
import time
import json
import re
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import structlog

from src.models.security import SecurityFinding, Service
from src.services.cache_service import CacheService
from src.utils.logger import PerformanceLogger

logger = structlog.get_logger()


class FixType(str, Enum):
    CODE_PATCH = "code_patch"
    IAC_PATCH = "iac_patch"  
    CONFIG_CHANGE = "config_change"
    WAF_RULE = "waf_rule"
    ADMISSION_CONTROLLER = "admission_controller"
    DEPENDENCY_UPDATE = "dependency_update"
    WORKFLOW_FIX = "workflow_fix"


@dataclass
class FixSuggestion:
    """Automated fix suggestion with implementation details"""
    finding_id: str
    fix_type: FixType
    title: str
    description: str
    confidence: float
    estimated_effort: str
    
    # Implementation details
    code_changes: Optional[Dict[str, str]] = None  # file -> patch
    config_changes: Optional[Dict[str, Any]] = None
    commands: Optional[List[str]] = None
    
    # Review and validation
    validation_tests: Optional[List[str]] = None
    rollback_plan: Optional[str] = None
    
    # Metadata
    references: Optional[List[str]] = None
    nist_ssdf_controls: Optional[List[str]] = None


class FixEngine:
    """
    High-performance automated fix generation engine
    Generates context-aware remediation suggestions and implementation code
    """
    
    def __init__(self):
        self.cache = CacheService.get_instance()
        self.fix_templates = self._load_fix_templates()
        
    def _load_fix_templates(self) -> Dict[str, Dict[str, Any]]:
        """Load fix templates for common vulnerability patterns"""
        return {
            "sql_injection": {
                "patterns": ["injection", "sql", "sqli"],
                "cwe_ids": ["CWE-89"],
                "fixes": [
                    {
                        "type": FixType.CODE_PATCH,
                        "template": "parameterized_query",
                        "confidence": 0.9
                    }
                ]
            },
            "xss": {
                "patterns": ["xss", "cross-site scripting", "script injection"],
                "cwe_ids": ["CWE-79"],
                "fixes": [
                    {
                        "type": FixType.CODE_PATCH,
                        "template": "output_encoding",
                        "confidence": 0.8
                    }
                ]
            },
            "hardcoded_secrets": {
                "patterns": ["secret", "password", "key", "token", "credential"],
                "cwe_ids": ["CWE-798"],
                "fixes": [
                    {
                        "type": FixType.CODE_PATCH,
                        "template": "externalize_secrets",
                        "confidence": 0.95
                    }
                ]
            },
            "insecure_crypto": {
                "patterns": ["md5", "sha1", "weak", "crypto", "encryption"],
                "cwe_ids": ["CWE-327", "CWE-328"],
                "fixes": [
                    {
                        "type": FixType.CODE_PATCH,
                        "template": "strong_crypto",
                        "confidence": 0.9
                    }
                ]
            },
            "path_traversal": {
                "patterns": ["traversal", "directory", "../", "path"],
                "cwe_ids": ["CWE-22"],
                "fixes": [
                    {
                        "type": FixType.CODE_PATCH,
                        "template": "path_validation",
                        "confidence": 0.85
                    }
                ]
            },
            "vulnerable_dependency": {
                "patterns": ["outdated", "vulnerable", "dependency", "package"],
                "scanner_types": ["sca"],
                "fixes": [
                    {
                        "type": FixType.DEPENDENCY_UPDATE,
                        "template": "update_dependency",
                        "confidence": 0.95
                    }
                ]
            },
            "missing_authentication": {
                "patterns": ["auth", "authentication", "login", "session"],
                "cwe_ids": ["CWE-306"],
                "fixes": [
                    {
                        "type": FixType.CODE_PATCH,
                        "template": "add_authentication",
                        "confidence": 0.7
                    }
                ]
            },
            "insecure_config": {
                "patterns": ["config", "configuration", "default", "insecure"],
                "scanner_types": ["iac", "container"],
                "fixes": [
                    {
                        "type": FixType.CONFIG_CHANGE,
                        "template": "secure_config",
                        "confidence": 0.8
                    }
                ]
            }
        }
    
    async def generate_fix_suggestions(self, finding: SecurityFinding, service: Optional[Service] = None) -> List[FixSuggestion]:
        """
        Generate automated fix suggestions for a security finding
        Hot path optimized for quick response
        """
        start_time = time.perf_counter()
        
        try:
            # Check cache first for performance
            cache_key = f"fix_suggestions:{finding.id}"
            cached_suggestions = await self.cache.get(cache_key)
            if cached_suggestions:
                suggestions = [FixSuggestion(**s) for s in cached_suggestions]
                PerformanceLogger.log_hot_path_performance(
                    "fix_generation_cache_hit",
                    (time.perf_counter() - start_time) * 1_000_000,
                    additional_context={"finding_id": finding.id}
                )
                return suggestions
            
            # Generate fix suggestions
            suggestions = []
            
            # Pattern-based fixes
            pattern_fixes = await self._generate_pattern_based_fixes(finding)
            suggestions.extend(pattern_fixes)
            
            # CVE/CWE-based fixes
            taxonomy_fixes = await self._generate_taxonomy_based_fixes(finding)
            suggestions.extend(taxonomy_fixes)
            
            # Scanner-specific fixes
            scanner_fixes = await self._generate_scanner_specific_fixes(finding)
            suggestions.extend(scanner_fixes)
            
            # Context-aware fixes (if service info available)
            if service:
                context_fixes = await self._generate_context_aware_fixes(finding, service)
                suggestions.extend(context_fixes)
            
            # Sort by confidence and deduplicate
            suggestions = self._deduplicate_suggestions(suggestions)
            suggestions.sort(key=lambda s: s.confidence, reverse=True)
            
            # Limit to top 5 suggestions for performance
            suggestions = suggestions[:5]
            
            # Cache results for performance
            suggestion_dicts = [s.__dict__ for s in suggestions]
            await self.cache.set(cache_key, suggestion_dicts, ttl=3600)  # 1 hour cache
            
            # Log performance metrics
            latency_us = (time.perf_counter() - start_time) * 1_000_000
            PerformanceLogger.log_hot_path_performance(
                "fix_generation_complete",
                latency_us,
                additional_context={
                    "finding_id": finding.id,
                    "suggestions_count": len(suggestions)
                }
            )
            
            return suggestions
            
        except Exception as e:
            logger.error(f"Fix generation failed for finding {finding.id}: {str(e)}")
            return []
    
    async def _generate_pattern_based_fixes(self, finding: SecurityFinding) -> List[FixSuggestion]:
        """Generate fixes based on text patterns in finding title/description"""
        
        fixes = []
        title_desc = f"{finding.title} {finding.description}".lower()
        
        for pattern_name, pattern_config in self.fix_templates.items():
            # Check if any patterns match
            patterns = pattern_config.get("patterns", [])
            if any(pattern in title_desc for pattern in patterns):
                
                for fix_config in pattern_config.get("fixes", []):
                    fix_suggestion = await self._create_fix_from_template(
                        finding, fix_config, pattern_name
                    )
                    if fix_suggestion:
                        fixes.append(fix_suggestion)
        
        return fixes
    
    async def _generate_taxonomy_based_fixes(self, finding: SecurityFinding) -> List[FixSuggestion]:
        """Generate fixes based on CWE/CVE taxonomy"""
        
        fixes = []
        
        # CWE-based fixes
        if finding.cwe_id:
            for pattern_name, pattern_config in self.fix_templates.items():
                cwe_ids = pattern_config.get("cwe_ids", [])
                if finding.cwe_id in cwe_ids:
                    
                    for fix_config in pattern_config.get("fixes", []):
                        fix_suggestion = await self._create_fix_from_template(
                            finding, fix_config, f"{pattern_name}_cwe"
                        )
                        if fix_suggestion:
                            fixes.append(fix_suggestion)
        
        # CVE-based fixes (lookup known fixes for specific CVEs)
        if finding.cve_id:
            cve_fix = await self._get_cve_specific_fix(finding)
            if cve_fix:
                fixes.append(cve_fix)
        
        return fixes
    
    async def _generate_scanner_specific_fixes(self, finding: SecurityFinding) -> List[FixSuggestion]:
        """Generate fixes based on scanner type and specific scanner capabilities"""
        
        fixes = []
        
        # Scanner type specific fixes
        for pattern_name, pattern_config in self.fix_templates.items():
            scanner_types = pattern_config.get("scanner_types", [])
            if finding.scanner_type in scanner_types:
                
                for fix_config in pattern_config.get("fixes", []):
                    fix_suggestion = await self._create_fix_from_template(
                        finding, fix_config, f"{pattern_name}_scanner"
                    )
                    if fix_suggestion:
                        fixes.append(fix_suggestion)
        
        # SAST-specific fixes
        if finding.scanner_type == "sast":
            sast_fixes = await self._generate_sast_fixes(finding)
            fixes.extend(sast_fixes)
        
        # SCA-specific fixes  
        elif finding.scanner_type == "sca":
            sca_fixes = await self._generate_sca_fixes(finding)
            fixes.extend(sca_fixes)
        
        # DAST-specific fixes
        elif finding.scanner_type == "dast":
            dast_fixes = await self._generate_dast_fixes(finding)
            fixes.extend(dast_fixes)
        
        # IaC-specific fixes
        elif finding.scanner_type == "iac":
            iac_fixes = await self._generate_iac_fixes(finding)
            fixes.extend(iac_fixes)
        
        return fixes
    
    async def _generate_context_aware_fixes(self, finding: SecurityFinding, service: Service) -> List[FixSuggestion]:
        """Generate fixes based on service context and business requirements"""
        
        fixes = []
        
        # High-criticality service fixes
        if service.business_criticality == "high":
            if finding.severity in ["critical", "high"]:
                # Generate immediate mitigating controls
                waf_fix = FixSuggestion(
                    finding_id=finding.id,
                    fix_type=FixType.WAF_RULE,
                    title="Deploy WAF Protection Rule",
                    description=f"Deploy temporary WAF rule to mitigate {finding.title}",
                    confidence=0.7,
                    estimated_effort="30 minutes",
                    config_changes={
                        "waf_rule": self._generate_waf_rule(finding)
                    },
                    nist_ssdf_controls=["PW.7.1"]
                )
                fixes.append(waf_fix)
        
        # PCI-scoped service fixes
        if service.pci_scope and "pci" in service.data_classification:
            if finding.severity in ["critical", "high"]:
                # Generate strict remediation
                strict_fix = FixSuggestion(
                    finding_id=finding.id,
                    fix_type=FixType.CODE_PATCH,
                    title="PCI Compliance Remediation",
                    description="Strict remediation required for PCI-scoped service",
                    confidence=0.9,
                    estimated_effort="2-4 hours",
                    validation_tests=["pci_compliance_test", "regression_test"],
                    nist_ssdf_controls=["PO.3.1", "PS.1.1"]
                )
                fixes.append(strict_fix)
        
        # Internet-facing service fixes
        if service.internet_facing:
            # Generate additional security controls
            security_fix = FixSuggestion(
                finding_id=finding.id,
                fix_type=FixType.CONFIG_CHANGE,
                title="Enhanced Security Controls",
                description="Additional security controls for internet-facing service",
                confidence=0.8,
                estimated_effort="1-2 hours",
                config_changes={
                    "rate_limiting": True,
                    "additional_monitoring": True,
                    "security_headers": True
                }
            )
            fixes.append(security_fix)
        
        return fixes
    
    async def _create_fix_from_template(self, finding: SecurityFinding, fix_config: Dict[str, Any], source: str) -> Optional[FixSuggestion]:
        """Create fix suggestion from template configuration"""
        
        try:
            template_name = fix_config.get("template")
            fix_type = FixType(fix_config.get("type"))
            confidence = fix_config.get("confidence", 0.5)
            
            # Generate fix based on template
            if template_name == "parameterized_query":
                return await self._generate_sql_injection_fix(finding, confidence)
            elif template_name == "output_encoding":
                return await self._generate_xss_fix(finding, confidence)
            elif template_name == "externalize_secrets":
                return await self._generate_secrets_fix(finding, confidence)
            elif template_name == "strong_crypto":
                return await self._generate_crypto_fix(finding, confidence)
            elif template_name == "path_validation":
                return await self._generate_path_traversal_fix(finding, confidence)
            elif template_name == "update_dependency":
                return await self._generate_dependency_update_fix(finding, confidence)
            elif template_name == "add_authentication":
                return await self._generate_auth_fix(finding, confidence)
            elif template_name == "secure_config":
                return await self._generate_config_fix(finding, confidence)
            else:
                # Generic fix
                return FixSuggestion(
                    finding_id=finding.id,
                    fix_type=fix_type,
                    title=f"Remediate {finding.title}",
                    description=f"Automated fix suggestion for {finding.category}",
                    confidence=confidence,
                    estimated_effort="2-4 hours"
                )
        
        except Exception as e:
            logger.error(f"Template fix creation failed: {str(e)}")
            return None
    
    async def _generate_sql_injection_fix(self, finding: SecurityFinding, confidence: float) -> FixSuggestion:
        """Generate SQL injection fix with code patches"""
        
        code_changes = {}
        
        if finding.file_path:
            # Generate parameterized query fix
            if ".java" in finding.file_path:
                code_changes[finding.file_path] = """
// Replace concatenated SQL with parameterized queries
- String query = "SELECT * FROM users WHERE id = '" + userId + "'";
+ String query = "SELECT * FROM users WHERE id = ?";
+ PreparedStatement stmt = connection.prepareStatement(query);
+ stmt.setString(1, userId);
"""
            elif ".py" in finding.file_path:
                code_changes[finding.file_path] = """
# Replace string formatting with parameterized queries
- query = f"SELECT * FROM users WHERE id = '{user_id}'"
+ query = "SELECT * FROM users WHERE id = %s"
+ cursor.execute(query, (user_id,))
"""
            elif ".js" in finding.file_path:
                code_changes[finding.file_path] = """
// Replace template literals with parameterized queries
- const query = `SELECT * FROM users WHERE id = '${userId}'`;
+ const query = 'SELECT * FROM users WHERE id = ?';
+ db.query(query, [userId]);
"""
        
        return FixSuggestion(
            finding_id=finding.id,
            fix_type=FixType.CODE_PATCH,
            title="Implement Parameterized Queries",
            description="Replace SQL string concatenation with parameterized queries to prevent injection",
            confidence=confidence,
            estimated_effort="1-2 hours",
            code_changes=code_changes,
            validation_tests=["sql_injection_test", "functional_test"],
            rollback_plan="Revert to previous query implementation if tests fail",
            references=[
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
            ],
            nist_ssdf_controls=["PS.1.1", "PW.7.2"]
        )
    
    async def _generate_xss_fix(self, finding: SecurityFinding, confidence: float) -> FixSuggestion:
        """Generate XSS fix with output encoding"""
        
        code_changes = {}
        
        if finding.file_path:
            if ".jsp" in finding.file_path or ".html" in finding.file_path:
                code_changes[finding.file_path] = """
<!-- Replace unescaped output with encoded output -->
- <%= userInput %>
+ <%= StringEscapeUtils.escapeHtml4(userInput) %>
"""
            elif ".py" in finding.file_path:
                code_changes[finding.file_path] = """
# Replace unescaped output with encoded output
- return f"<div>{user_input}</div>"
+ from html import escape
+ return f"<div>{escape(user_input)}</div>"
"""
        
        return FixSuggestion(
            finding_id=finding.id,
            fix_type=FixType.CODE_PATCH,
            title="Implement Output Encoding",
            description="Add proper output encoding to prevent XSS attacks",
            confidence=confidence,
            estimated_effort="1-2 hours",
            code_changes=code_changes,
            validation_tests=["xss_test", "functional_test"],
            references=["https://owasp.org/www-community/attacks/xss/"],
            nist_ssdf_controls=["PS.1.1"]
        )
    
    async def _generate_dependency_update_fix(self, finding: SecurityFinding, confidence: float) -> FixSuggestion:
        """Generate dependency update fix"""
        
        # Extract dependency info from finding
        dependency_name = self._extract_dependency_name(finding)
        current_version = self._extract_current_version(finding)
        fixed_version = self._extract_fixed_version(finding)
        
        commands = []
        if dependency_name and fixed_version:
            # Generate update commands based on project type
            commands = [
                f"# Update {dependency_name} to version {fixed_version}",
                f"npm update {dependency_name}@{fixed_version}",
                f"# Or for Python: pip install {dependency_name}=={fixed_version}",
                f"# Or for Java: Update version in pom.xml or build.gradle"
            ]
        
        return FixSuggestion(
            finding_id=finding.id,
            fix_type=FixType.DEPENDENCY_UPDATE,
            title=f"Update {dependency_name or 'Vulnerable Dependency'}",
            description=f"Update to version {fixed_version or 'latest'} to fix security vulnerability",
            confidence=confidence,
            estimated_effort="30 minutes",
            commands=commands,
            validation_tests=["dependency_scan", "integration_test"],
            rollback_plan="Revert to previous version if compatibility issues arise",
            nist_ssdf_controls=["PW.7.1"]
        )
    
    def _extract_dependency_name(self, finding: SecurityFinding) -> Optional[str]:
        """Extract dependency name from finding"""
        # Simple extraction logic - in production this would be more sophisticated
        if "package" in finding.description.lower():
            match = re.search(r'package[:\s]+([a-zA-Z0-9\-_\.]+)', finding.description)
            if match:
                return match.group(1)
        return None
    
    def _extract_current_version(self, finding: SecurityFinding) -> Optional[str]:
        """Extract current version from finding"""
        match = re.search(r'version[:\s]+([0-9\.]+)', finding.description)
        if match:
            return match.group(1)
        return None
    
    def _extract_fixed_version(self, finding: SecurityFinding) -> Optional[str]:
        """Extract fixed version from finding"""
        match = re.search(r'fix[ed]*[:\s]+([0-9\.]+)', finding.description)
        if match:
            return match.group(1)
        return None
    
    def _generate_waf_rule(self, finding: SecurityFinding) -> Dict[str, Any]:
        """Generate WAF rule configuration"""
        
        if "injection" in finding.title.lower():
            return {
                "rule_type": "sql_injection_protection",
                "pattern": r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
                "action": "block",
                "priority": 100
            }
        elif "xss" in finding.title.lower():
            return {
                "rule_type": "xss_protection", 
                "pattern": r"<script|javascript:|onload=|onerror=",
                "action": "block",
                "priority": 100
            }
        else:
            return {
                "rule_type": "generic_protection",
                "description": f"Protection for {finding.title}",
                "action": "monitor",
                "priority": 200
            }
    
    def _deduplicate_suggestions(self, suggestions: List[FixSuggestion]) -> List[FixSuggestion]:
        """Remove duplicate fix suggestions"""
        
        seen = set()
        unique_suggestions = []
        
        for suggestion in suggestions:
            # Create a simple hash based on type and title
            suggestion_hash = f"{suggestion.fix_type}:{suggestion.title}"
            
            if suggestion_hash not in seen:
                seen.add(suggestion_hash)
                unique_suggestions.append(suggestion)
        
        return unique_suggestions
    
    # Additional method stubs for other fix types
    async def _generate_sast_fixes(self, finding: SecurityFinding) -> List[FixSuggestion]:
        """Generate SAST-specific fixes"""
        return []
    
    async def _generate_sca_fixes(self, finding: SecurityFinding) -> List[FixSuggestion]:
        """Generate SCA-specific fixes"""
        return []
    
    async def _generate_dast_fixes(self, finding: SecurityFinding) -> List[FixSuggestion]:
        """Generate DAST-specific fixes"""
        return []
    
    async def _generate_iac_fixes(self, finding: SecurityFinding) -> List[FixSuggestion]:
        """Generate IaC-specific fixes"""
        return []
    
    async def _get_cve_specific_fix(self, finding: SecurityFinding) -> Optional[FixSuggestion]:
        """Get CVE-specific fix from vulnerability database"""
        return None
    
    async def _generate_secrets_fix(self, finding: SecurityFinding, confidence: float) -> FixSuggestion:
        """Generate hardcoded secrets fix"""
        return FixSuggestion(
            finding_id=finding.id,
            fix_type=FixType.CODE_PATCH,
            title="Externalize Hardcoded Secrets",
            description="Move hardcoded secrets to environment variables or secure vault",
            confidence=confidence,
            estimated_effort="1-2 hours"
        )
    
    async def _generate_crypto_fix(self, finding: SecurityFinding, confidence: float) -> FixSuggestion:
        """Generate crypto fix"""
        return FixSuggestion(
            finding_id=finding.id,
            fix_type=FixType.CODE_PATCH,
            title="Update Cryptographic Implementation",
            description="Replace weak cryptographic algorithms with strong alternatives", 
            confidence=confidence,
            estimated_effort="2-3 hours"
        )
    
    async def _generate_path_traversal_fix(self, finding: SecurityFinding, confidence: float) -> FixSuggestion:
        """Generate path traversal fix"""
        return FixSuggestion(
            finding_id=finding.id,
            fix_type=FixType.CODE_PATCH,
            title="Add Path Validation",
            description="Implement path validation to prevent directory traversal",
            confidence=confidence,
            estimated_effort="1-2 hours"
        )
    
    async def _generate_auth_fix(self, finding: SecurityFinding, confidence: float) -> FixSuggestion:
        """Generate authentication fix"""
        return FixSuggestion(
            finding_id=finding.id,
            fix_type=FixType.CODE_PATCH,
            title="Add Authentication Check",
            description="Implement authentication requirements for protected resources",
            confidence=confidence,
            estimated_effort="2-4 hours"
        )
    
    async def _generate_config_fix(self, finding: SecurityFinding, confidence: float) -> FixSuggestion:
        """Generate configuration fix"""
        return FixSuggestion(
            finding_id=finding.id,
            fix_type=FixType.CONFIG_CHANGE,
            title="Secure Configuration",
            description="Update configuration to follow security best practices",
            confidence=confidence,
            estimated_effort="30 minutes"
        )


# Global fix engine instance
fix_engine = FixEngine()


async def generate_fixes_async(finding: SecurityFinding, service: Optional[Service] = None) -> List[FixSuggestion]:
    """Async wrapper for fix generation"""
    return await fix_engine.generate_fix_suggestions(finding, service)