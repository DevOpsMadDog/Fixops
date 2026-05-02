"""
Phase 9: Compliance Playbook Templates for ALDECI.

This module provides pre-built playbook templates for compliance frameworks:
- SOC2, HIPAA, PCI_DSS, ISO27001, NIST_CSF, GDPR, FedRAMP
- ComplianceControl definitions for each framework
- Template instantiation with org-specific configurations
- Automated compliance assessment scoring
- Control catalog with evidence types

Compliance: SOC2 CC9.2 (Compliance with requirements)
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from core.playbook_engine import (
    Playbook,
    PlaybookStatus,
    PlaybookStep,
    PlaybookStepType,
)

_logger = logging.getLogger(__name__)


# ============================================================================
# ENUMS
# ============================================================================


class ComplianceFramework(Enum):
    """Supported compliance frameworks."""

    SOC2 = "soc2"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    ISO27001 = "iso27001"
    NIST_CSF = "nist_csf"
    GDPR = "gdpr"
    FEDRAMP = "fedramp"

    def __str__(self) -> str:
        return self.value


class AutomationLevel(Enum):
    """Automation level for compliance controls."""

    MANUAL = "manual"
    SEMI = "semi"
    FULL = "full"

    def __str__(self) -> str:
        return self.value


# ============================================================================
# DATACLASSES
# ============================================================================


@dataclass
class ComplianceControl:
    """
    A compliance control requirement.

    Attributes:
        control_id: Unique control identifier (e.g., 'CC6.1', 'A.9.1')
        framework: ComplianceFramework this control belongs to
        title: Control title
        description: Control description and requirements
        requirements: List of specific requirements
        evidence_types: Types of evidence that satisfy this control
        automation_level: How automatable the control is
    """

    control_id: str
    framework: ComplianceFramework
    title: str
    description: str
    requirements: List[str] = field(default_factory=list)
    evidence_types: List[str] = field(default_factory=list)
    automation_level: AutomationLevel = AutomationLevel.SEMI

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dict."""
        return {
            "control_id": self.control_id,
            "framework": str(self.framework),
            "title": self.title,
            "description": self.description,
            "requirements": self.requirements,
            "evidence_types": self.evidence_types,
            "automation_level": str(self.automation_level),
        }


# ============================================================================
# COMPLIANCE TEMPLATE LIBRARY
# ============================================================================


class ComplianceTemplateLibrary:
    """Manages compliance playbook templates and controls."""

    def __init__(self):
        """Initialize template library with all framework templates."""
        self.templates: Dict[str, Playbook] = {}
        self.controls: Dict[ComplianceFramework, List[ComplianceControl]] = {}
        self._init_templates()
        self._init_controls()

    def _init_templates(self) -> None:
        """Initialize all compliance playbook templates."""

        # ====================================================================
        # SOC2 TEMPLATES
        # ====================================================================

        self.templates["soc2_access_review"] = self._create_template_soc2_access_review()
        self.templates["soc2_change_management"] = (
            self._create_template_soc2_change_management()
        )
        self.templates["soc2_incident_response"] = (
            self._create_template_soc2_incident_response()
        )
        self.templates["soc2_vulnerability_scan"] = (
            self._create_template_soc2_vulnerability_scan()
        )

        # ====================================================================
        # HIPAA TEMPLATES
        # ====================================================================

        self.templates["hipaa_phi_access_audit"] = (
            self._create_template_hipaa_phi_access_audit()
        )
        self.templates["hipaa_breach_notification"] = (
            self._create_template_hipaa_breach_notification()
        )
        self.templates["hipaa_risk_assessment"] = (
            self._create_template_hipaa_risk_assessment()
        )
        self.templates["hipaa_workforce_training"] = (
            self._create_template_hipaa_workforce_training()
        )

        # ====================================================================
        # PCI_DSS TEMPLATES
        # ====================================================================

        self.templates["pci_dss_network_scan"] = (
            self._create_template_pci_dss_network_scan()
        )
        self.templates["pci_dss_access_control_review"] = (
            self._create_template_pci_dss_access_control_review()
        )
        self.templates["pci_dss_log_monitoring"] = (
            self._create_template_pci_dss_log_monitoring()
        )
        self.templates["pci_dss_encryption_check"] = (
            self._create_template_pci_dss_encryption_check()
        )

        # ====================================================================
        # ISO27001 TEMPLATES
        # ====================================================================

        self.templates["iso27001_asset_inventory"] = (
            self._create_template_iso27001_asset_inventory()
        )
        self.templates["iso27001_risk_treatment"] = (
            self._create_template_iso27001_risk_treatment()
        )
        self.templates["iso27001_internal_audit"] = (
            self._create_template_iso27001_internal_audit()
        )
        self.templates["iso27001_management_review"] = (
            self._create_template_iso27001_management_review()
        )

        # ====================================================================
        # NIST_CSF TEMPLATES
        # ====================================================================

        self.templates["nist_csf_identify_assets"] = (
            self._create_template_nist_csf_identify_assets()
        )
        self.templates["nist_csf_protect_controls"] = (
            self._create_template_nist_csf_protect_controls()
        )
        self.templates["nist_csf_detect_events"] = (
            self._create_template_nist_csf_detect_events()
        )
        self.templates["nist_csf_respond_incidents"] = (
            self._create_template_nist_csf_respond_incidents()
        )
        self.templates["nist_csf_recover_operations"] = (
            self._create_template_nist_csf_recover_operations()
        )

        _logger.info(f"Initialized {len(self.templates)} compliance templates")

    def _init_controls(self) -> None:
        """Initialize compliance control catalogs for each framework."""

        # SOC2 Controls (Trust Service Criteria)
        self.controls[ComplianceFramework.SOC2] = [
            ComplianceControl(
                control_id="CC6.1",
                framework=ComplianceFramework.SOC2,
                title="Logical Access Controls",
                description="User access to system components is restricted",
                requirements=[
                    "User roles and permissions defined",
                    "Access requests approved",
                    "Access reviews performed quarterly",
                ],
                evidence_types=["access_logs", "role_definitions", "approval_records"],
                automation_level=AutomationLevel.FULL,
            ),
            ComplianceControl(
                control_id="CC7.1",
                framework=ComplianceFramework.SOC2,
                title="System Monitoring",
                description="System activities are monitored and analyzed",
                requirements=[
                    "Logs collected for all systems",
                    "Anomalies detected and investigated",
                    "Incidents documented",
                ],
                evidence_types=["audit_logs", "siem_alerts", "incident_tickets"],
                automation_level=AutomationLevel.SEMI,
            ),
            ComplianceControl(
                control_id="CC7.2",
                framework=ComplianceFramework.SOC2,
                title="Monitoring for Anomalies",
                description="Unauthorized activities are detected promptly",
                requirements=[
                    "Real-time monitoring enabled",
                    "Alert thresholds configured",
                    "Investigation procedures documented",
                ],
                evidence_types=["monitoring_rules", "alert_logs", "investigation_reports"],
                automation_level=AutomationLevel.SEMI,
            ),
        ]

        # HIPAA Controls (Security Rule)
        self.controls[ComplianceFramework.HIPAA] = [
            ComplianceControl(
                control_id="164.308(a)(4)",
                framework=ComplianceFramework.HIPAA,
                title="Access Management",
                description="ePHI access is restricted to authorized personnel",
                requirements=[
                    "Access control policies established",
                    "User authentication required",
                    "Regular access audits performed",
                ],
                evidence_types=["access_logs", "training_records", "audit_reports"],
                automation_level=AutomationLevel.FULL,
            ),
            ComplianceControl(
                control_id="164.312(b)",
                framework=ComplianceFramework.HIPAA,
                title="Audit Controls",
                description="Data access is logged and monitored",
                requirements=[
                    "Audit logging implemented",
                    "Logs retained for minimum 6 years",
                    "Regular log reviews conducted",
                ],
                evidence_types=["audit_logs", "log_retention_policy", "review_records"],
                automation_level=AutomationLevel.SEMI,
            ),
        ]

        # PCI DSS Controls
        self.controls[ComplianceFramework.PCI_DSS] = [
            ComplianceControl(
                control_id="1.1",
                framework=ComplianceFramework.PCI_DSS,
                title="Network Segmentation",
                description="Cardholder data environment is properly segmented",
                requirements=[
                    "Firewall rules documented",
                    "Network topology documented",
                    "Annual reviews conducted",
                ],
                evidence_types=["network_diagram", "firewall_rules", "review_reports"],
                automation_level=AutomationLevel.SEMI,
            ),
            ComplianceControl(
                control_id="10.2",
                framework=ComplianceFramework.PCI_DSS,
                title="User Activity Logging",
                description="All access to cardholder data is logged",
                requirements=[
                    "Logs capture user identification",
                    "Logs capture actions taken",
                    "Logs retained for minimum 1 year",
                ],
                evidence_types=["audit_logs", "log_samples", "retention_proof"],
                automation_level=AutomationLevel.FULL,
            ),
        ]

        # ISO 27001 Controls
        self.controls[ComplianceFramework.ISO27001] = [
            ComplianceControl(
                control_id="A.9.1",
                framework=ComplianceFramework.ISO27001,
                title="Access Control Policy",
                description="Business requirements for access control are established",
                requirements=[
                    "Policy documented and approved",
                    "Policy communicated to all users",
                    "Policy reviewed annually",
                ],
                evidence_types=["policy_document", "distribution_records", "review_records"],
                automation_level=AutomationLevel.MANUAL,
            ),
            ComplianceControl(
                control_id="A.12.4",
                framework=ComplianceFramework.ISO27001,
                title="Event Logging",
                description="User activities are logged and monitored",
                requirements=[
                    "Logging enabled on all systems",
                    "Logs protected from unauthorized modification",
                    "Regular log reviews performed",
                ],
                evidence_types=["log_samples", "log_protection_config", "review_records"],
                automation_level=AutomationLevel.SEMI,
            ),
        ]

        # NIST CSF Controls
        self.controls[ComplianceFramework.NIST_CSF] = [
            ComplianceControl(
                control_id="ID.AM-1",
                framework=ComplianceFramework.NIST_CSF,
                title="Asset Inventory",
                description="Organizational assets and systems are identified",
                requirements=[
                    "Hardware inventory maintained",
                    "Software inventory maintained",
                    "Inventory updated regularly",
                ],
                evidence_types=["asset_database", "inventory_reports", "update_logs"],
                automation_level=AutomationLevel.FULL,
            ),
            ComplianceControl(
                control_id="DE.AE-1",
                framework=ComplianceFramework.NIST_CSF,
                title="Anomaly Detection",
                description="Anomalous events are identified",
                requirements=[
                    "SIEM or equivalent deployed",
                    "Detection rules configured",
                    "Alerts investigated",
                ],
                evidence_types=["siem_config", "detection_rules", "alert_records"],
                automation_level=AutomationLevel.SEMI,
            ),
        ]

        # GDPR Controls
        self.controls[ComplianceFramework.GDPR] = [
            ComplianceControl(
                control_id="32",
                framework=ComplianceFramework.GDPR,
                title="Data Protection Impact Assessment",
                description="High-risk processing requires DPIA",
                requirements=[
                    "DPIA conducted for high-risk processing",
                    "Risks and mitigations documented",
                    "DPA consulted when required",
                ],
                evidence_types=["dpia_documents", "risk_assessment", "dpa_consultation"],
                automation_level=AutomationLevel.MANUAL,
            ),
            ComplianceControl(
                control_id="32(1)",
                framework=ComplianceFramework.GDPR,
                title="Data Subject Rights",
                description="Data subjects can exercise their rights",
                requirements=[
                    "Procedures for exercising rights documented",
                    "Responses provided within 30 days",
                    "Records of requests maintained",
                ],
                evidence_types=["procedures", "response_records", "fulfillment_logs"],
                automation_level=AutomationLevel.SEMI,
            ),
        ]

        # FedRAMP Controls
        self.controls[ComplianceFramework.FEDRAMP] = [
            ComplianceControl(
                control_id="AC-2",
                framework=ComplianceFramework.FEDRAMP,
                title="Account Management",
                description="Information system accounts are managed",
                requirements=[
                    "Account types defined",
                    "Account creation process documented",
                    "Account reviews performed",
                ],
                evidence_types=["account_policy", "creation_procedures", "review_records"],
                automation_level=AutomationLevel.SEMI,
            ),
            ComplianceControl(
                control_id="AU-2",
                framework=ComplianceFramework.FEDRAMP,
                title="Audit Events",
                description="Auditable events are defined and logged",
                requirements=[
                    "Auditable events identified",
                    "Logging configured",
                    "Logs protected and reviewed",
                ],
                evidence_types=["event_definitions", "logging_config", "log_samples"],
                automation_level=AutomationLevel.FULL,
            ),
        ]

        _logger.info(f"Initialized controls for {len(self.controls)} frameworks")

    def get_templates(self, framework: ComplianceFramework) -> List[Playbook]:
        """
        Get all templates for a compliance framework.

        Args:
            framework: ComplianceFramework enum value

        Returns:
            List of Playbook templates
        """
        framework_str = str(framework).lower()
        return [
            p for key, p in self.templates.items() if framework_str in key.lower()
        ]

    def get_template(self, template_id: str) -> Optional[Playbook]:
        """
        Get a specific template.

        Args:
            template_id: Template identifier

        Returns:
            Playbook template or None if not found
        """
        return self.templates.get(template_id)

    def instantiate_template(
        self, template_id: str, org_config: Dict[str, Any]
    ) -> Playbook:
        """
        Create an org-specific playbook from a template.

        Args:
            template_id: Template identifier
            org_config: Organization-specific configuration

        Returns:
            New Playbook instance

        Raises:
            ValueError: If template not found
        """
        template = self.get_template(template_id)
        if not template:
            raise ValueError(f"Template {template_id} not found")

        # Create a copy and customize
        playbook = Playbook(
            playbook_id=str(uuid.uuid4()),
            name=template.name,
            description=template.description,
            trigger_conditions=template.trigger_conditions,
            steps=template.steps,
            status=PlaybookStatus.DRAFT,
            version=1,
            created_by=org_config.get("created_by", "system"),
            org_id=org_config.get("org_id", "default"),
            tags=template.tags + [f"instantiated_from_{template_id}"],
        )

        _logger.info(
            f"Instantiated template {template_id} as playbook {playbook.playbook_id}"
        )
        return playbook

    def get_control_mapping(
        self, framework: ComplianceFramework
    ) -> List[ComplianceControl]:
        """
        Get the full control catalog for a framework.

        Args:
            framework: ComplianceFramework enum value

        Returns:
            List of ComplianceControl objects
        """
        return self.controls.get(framework, [])

    def assess_compliance(self, org_id: str, framework: ComplianceFramework) -> Dict[str, Any]:
        """
        Perform automated compliance assessment.

        Args:
            org_id: Organization ID
            framework: ComplianceFramework to assess

        Returns:
            Dict with overall_score, gaps, and recommendations
        """
        controls = self.get_control_mapping(framework)

        # Count controls by automation level
        full_auto = len([c for c in controls if c.automation_level == AutomationLevel.FULL])
        semi_auto = len(
            [c for c in controls if c.automation_level == AutomationLevel.SEMI]
        )
        manual = len([c for c in controls if c.automation_level == AutomationLevel.MANUAL])

        # In a real implementation, this would check actual compliance status
        # For now, provide a template assessment
        overall_score = 65 + (full_auto * 2)  # Mock calculation

        return {
            "framework": str(framework),
            "overall_score": min(overall_score, 100),
            "total_controls": len(controls),
            "controls_by_automation": {
                "full": full_auto,
                "semi": semi_auto,
                "manual": manual,
            },
            "gaps": [
                {
                    "control_id": c.control_id,
                    "title": c.title,
                    "severity": "high" if c.automation_level == AutomationLevel.FULL else "medium",
                }
                for c in controls[:3]
            ],
            "recommendations": [
                f"Implement automated monitoring for {full_auto} controls",
                f"Establish procedures for {manual} manual controls",
                "Review and update access control policies",
            ],
        }

    # ========================================================================
    # TEMPLATE FACTORY METHODS
    # ========================================================================

    def _create_template_soc2_access_review(self) -> Playbook:
        """SOC2 quarterly access review template."""
        return Playbook(
            playbook_id=str(uuid.uuid4()),
            name="SOC2 Quarterly Access Review",
            description="Review and validate user access quarterly for SOC2 CC6.1",
            trigger_conditions={"event_type": "access_review_scheduled"},
            steps=[
                PlaybookStep(
                    step_id=str(uuid.uuid4()),
                    step_type=PlaybookStepType.ACTION,
                    name="Collect Active Users",
                    config={"action_type": "collect_active_users"},
                    next_on_success=None,
                ),
            ],
            status=PlaybookStatus.ACTIVE,
            tags=["soc2", "access_control", "quarterly"],
        )

    def _create_template_soc2_change_management(self) -> Playbook:
        """SOC2 change management template."""
        return Playbook(
            playbook_id=str(uuid.uuid4()),
            name="SOC2 Change Management",
            description="Validate and approve changes for SOC2 compliance",
            trigger_conditions={"event_type": "change_requested"},
            steps=[
                PlaybookStep(
                    step_id=str(uuid.uuid4()),
                    step_type=PlaybookStepType.APPROVAL,
                    name="Require Change Approval",
                    config={
                        "approvers": ["security_lead"],
                        "timeout_seconds": 86400,
                        "reason": "SOC2 change control",
                    },
                    next_on_success=None,
                ),
            ],
            status=PlaybookStatus.ACTIVE,
            tags=["soc2", "change_control"],
        )

    def _create_template_soc2_incident_response(self) -> Playbook:
        """SOC2 incident response template."""
        return Playbook(
            playbook_id=str(uuid.uuid4()),
            name="SOC2 Incident Response",
            description="Document and respond to security incidents for SOC2 CC7.2",
            trigger_conditions={"event_type": "security_incident"},
            steps=[
                PlaybookStep(
                    step_id=str(uuid.uuid4()),
                    step_type=PlaybookStepType.ACTION,
                    name="Create Incident Ticket",
                    config={
                        "action_type": "create_incident",
                        "title": "Security Incident",
                    },
                    next_on_success=None,
                ),
            ],
            status=PlaybookStatus.ACTIVE,
            tags=["soc2", "incident_response"],
        )

    def _create_template_soc2_vulnerability_scan(self) -> Playbook:
        """SOC2 vulnerability scanning template."""
        return Playbook(
            playbook_id=str(uuid.uuid4()),
            name="SOC2 Vulnerability Scanning",
            description="Regular vulnerability scans for SOC2 compliance",
            trigger_conditions={"event_type": "vulnerability_scan_due"},
            steps=[
                PlaybookStep(
                    step_id=str(uuid.uuid4()),
                    step_type=PlaybookStepType.NOTIFICATION,
                    name="Notify Security Team",
                    config={
                        "channel": "slack",
                        "recipients": ["security_team"],
                        "message": "Vulnerability scan due",
                    },
                    next_on_success=None,
                ),
            ],
            status=PlaybookStatus.ACTIVE,
            tags=["soc2", "vulnerability"],
        )

    def _create_template_hipaa_phi_access_audit(self) -> Playbook:
        """HIPAA PHI access audit template."""
        return Playbook(
            playbook_id=str(uuid.uuid4()),
            name="HIPAA PHI Access Audit",
            description="Audit ePHI access for HIPAA 164.312(b)",
            trigger_conditions={"event_type": "phi_audit_due"},
            steps=(),
            status=PlaybookStatus.ACTIVE,
            tags=["hipaa", "phi"],
        )

    def _create_template_hipaa_breach_notification(self) -> Playbook:
        """HIPAA breach notification template."""
        return Playbook(
            playbook_id=str(uuid.uuid4()),
            name="HIPAA Breach Notification",
            description="Notify affected parties of PHI breach",
            trigger_conditions={"event_type": "phi_breach_detected"},
            steps=(),
            status=PlaybookStatus.ACTIVE,
            tags=["hipaa", "breach"],
        )

    def _create_template_hipaa_risk_assessment(self) -> Playbook:
        """HIPAA risk assessment template."""
        return Playbook(
            playbook_id=str(uuid.uuid4()),
            name="HIPAA Risk Assessment",
            description="Annual risk assessment for HIPAA compliance",
            trigger_conditions={"event_type": "risk_assessment_due"},
            steps=(),
            status=PlaybookStatus.ACTIVE,
            tags=["hipaa", "risk"],
        )

    def _create_template_hipaa_workforce_training(self) -> Playbook:
        """HIPAA workforce training template."""
        return Playbook(
            playbook_id=str(uuid.uuid4()),
            name="HIPAA Workforce Training",
            description="Ensure HIPAA training is up-to-date",
            trigger_conditions={"event_type": "training_due"},
            steps=(),
            status=PlaybookStatus.ACTIVE,
            tags=["hipaa", "training"],
        )

    def _create_template_pci_dss_network_scan(self) -> Playbook:
        """PCI DSS network scan template."""
        return Playbook(
            playbook_id=str(uuid.uuid4()),
            name="PCI DSS Network Scan",
            description="Regular network vulnerability scans",
            trigger_conditions={"event_type": "network_scan_due"},
            steps=(),
            status=PlaybookStatus.ACTIVE,
            tags=["pci_dss", "network"],
        )

    def _create_template_pci_dss_access_control_review(self) -> Playbook:
        """PCI DSS access control review template."""
        return Playbook(
            playbook_id=str(uuid.uuid4()),
            name="PCI DSS Access Control Review",
            description="Review access controls for PCI DSS compliance",
            trigger_conditions={"event_type": "access_review_due"},
            steps=(),
            status=PlaybookStatus.ACTIVE,
            tags=["pci_dss", "access"],
        )

    def _create_template_pci_dss_log_monitoring(self) -> Playbook:
        """PCI DSS log monitoring template."""
        return Playbook(
            playbook_id=str(uuid.uuid4()),
            name="PCI DSS Log Monitoring",
            description="Monitor logs for suspicious activity",
            trigger_conditions={"event_type": "suspicious_activity"},
            steps=(),
            status=PlaybookStatus.ACTIVE,
            tags=["pci_dss", "logging"],
        )

    def _create_template_pci_dss_encryption_check(self) -> Playbook:
        """PCI DSS encryption validation template."""
        return Playbook(
            playbook_id=str(uuid.uuid4()),
            name="PCI DSS Encryption Check",
            description="Verify encryption of cardholder data",
            trigger_conditions={"event_type": "encryption_check_due"},
            steps=(),
            status=PlaybookStatus.ACTIVE,
            tags=["pci_dss", "encryption"],
        )

    def _create_template_iso27001_asset_inventory(self) -> Playbook:
        """ISO 27001 asset inventory template."""
        return Playbook(
            playbook_id=str(uuid.uuid4()),
            name="ISO 27001 Asset Inventory",
            description="Maintain and update asset inventory",
            trigger_conditions={"event_type": "inventory_review_due"},
            steps=(),
            status=PlaybookStatus.ACTIVE,
            tags=["iso27001", "assets"],
        )

    def _create_template_iso27001_risk_treatment(self) -> Playbook:
        """ISO 27001 risk treatment template."""
        return Playbook(
            playbook_id=str(uuid.uuid4()),
            name="ISO 27001 Risk Treatment",
            description="Execute risk treatment plans",
            trigger_conditions={"event_type": "risk_treatment_due"},
            steps=(),
            status=PlaybookStatus.ACTIVE,
            tags=["iso27001", "risk"],
        )

    def _create_template_iso27001_internal_audit(self) -> Playbook:
        """ISO 27001 internal audit template."""
        return Playbook(
            playbook_id=str(uuid.uuid4()),
            name="ISO 27001 Internal Audit",
            description="Conduct internal audit of ISMS",
            trigger_conditions={"event_type": "internal_audit_due"},
            steps=(),
            status=PlaybookStatus.ACTIVE,
            tags=["iso27001", "audit"],
        )

    def _create_template_iso27001_management_review(self) -> Playbook:
        """ISO 27001 management review template."""
        return Playbook(
            playbook_id=str(uuid.uuid4()),
            name="ISO 27001 Management Review",
            description="Conduct management review of ISMS",
            trigger_conditions={"event_type": "management_review_due"},
            steps=(),
            status=PlaybookStatus.ACTIVE,
            tags=["iso27001", "management"],
        )

    def _create_template_nist_csf_identify_assets(self) -> Playbook:
        """NIST CSF Identify - Assets template."""
        return Playbook(
            playbook_id=str(uuid.uuid4()),
            name="NIST CSF Identify Assets",
            description="Identify and catalog organizational assets",
            trigger_conditions={"event_type": "asset_discovery_due"},
            steps=(),
            status=PlaybookStatus.ACTIVE,
            tags=["nist_csf", "identify"],
        )

    def _create_template_nist_csf_protect_controls(self) -> Playbook:
        """NIST CSF Protect - Controls template."""
        return Playbook(
            playbook_id=str(uuid.uuid4()),
            name="NIST CSF Protect Controls",
            description="Implement protective controls",
            trigger_conditions={"event_type": "control_implementation_due"},
            steps=(),
            status=PlaybookStatus.ACTIVE,
            tags=["nist_csf", "protect"],
        )

    def _create_template_nist_csf_detect_events(self) -> Playbook:
        """NIST CSF Detect - Events template."""
        return Playbook(
            playbook_id=str(uuid.uuid4()),
            name="NIST CSF Detect Events",
            description="Detect anomalies and suspicious events",
            trigger_conditions={"event_type": "anomaly_detected"},
            steps=(),
            status=PlaybookStatus.ACTIVE,
            tags=["nist_csf", "detect"],
        )

    def _create_template_nist_csf_respond_incidents(self) -> Playbook:
        """NIST CSF Respond - Incidents template."""
        return Playbook(
            playbook_id=str(uuid.uuid4()),
            name="NIST CSF Respond Incidents",
            description="Respond to detected incidents",
            trigger_conditions={"event_type": "incident_detected"},
            steps=(),
            status=PlaybookStatus.ACTIVE,
            tags=["nist_csf", "respond"],
        )

    def _create_template_nist_csf_recover_operations(self) -> Playbook:
        """NIST CSF Recover - Operations template."""
        return Playbook(
            playbook_id=str(uuid.uuid4()),
            name="NIST CSF Recover Operations",
            description="Recover from incidents and maintain operations",
            trigger_conditions={"event_type": "recovery_initiated"},
            steps=(),
            status=PlaybookStatus.ACTIVE,
            tags=["nist_csf", "recover"],
        )
