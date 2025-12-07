"""Base compliance template classes."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class ComplianceRule:
    """Base compliance rule."""
    
    id: str
    name: str
    description: str
    severity: str  # critical, high, medium, low
    checks: List[str] = field(default_factory=list)
    remediation: Optional[str] = None


@dataclass
class ComplianceCheck:
    """Compliance check result."""
    
    rule_id: str
    passed: bool
    message: str
    evidence: List[str] = field(default_factory=list)


class ComplianceTemplate(ABC):
    """Base compliance template."""
    
    def __init__(self, framework_name: str, version: str):
        """Initialize compliance template."""
        self.framework_name = framework_name
        self.version = version
        self.rules: List[ComplianceRule] = []
    
    @abstractmethod
    def assess_compliance(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess compliance against framework."""
        pass
    
    def get_rules(self) -> List[ComplianceRule]:
        """Get all compliance rules."""
        return self.rules
    
    def get_rule(self, rule_id: str) -> Optional[ComplianceRule]:
        """Get specific rule by ID."""
        return next((r for r in self.rules if r.id == rule_id), None)
