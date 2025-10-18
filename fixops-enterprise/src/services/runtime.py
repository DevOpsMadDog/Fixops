"""Singleton services reused across API modules."""

from __future__ import annotations

from src.services.compliance import ComplianceEngine
from src.services.decision_engine import DecisionEngine
from src.services.evidence import EvidenceStore

EVIDENCE_STORE = EvidenceStore()
COMPLIANCE_ENGINE = ComplianceEngine()
DECISION_ENGINE = DecisionEngine(EVIDENCE_STORE, COMPLIANCE_ENGINE)
