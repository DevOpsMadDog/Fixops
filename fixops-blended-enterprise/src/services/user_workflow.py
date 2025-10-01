"""
FixOps User Workflow and Data Flow Implementation
Explains how users actually interact with FixOps from design to deployment decision
"""

import asyncio
import json
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
import structlog

logger = structlog.get_logger()

@dataclass
class OrganizationContext:
    """Organization's SSVC configuration at design stage"""
    organization_name: str
    stakeholder_type: str  # "deployer", "supplier", "coordinator"
    mission_impact_factors: Dict[str, str]
    safety_impact_context: Dict[str, str]
    environment_types: List[str]  # ["production", "staging", "development"]
    risk_tolerance: str  # "low", "medium", "high"
    compliance_requirements: List[str]  # ["SOC2", "PCI-DSS", "HIPAA"]

@dataclass
class ScanSubmission:
    """User's scan data submission"""
    submission_id: str
    service_name: str
    environment: str
    submitter: str
    scan_data: Dict[str, Any]  # SARIF, SBOM, etc.
    business_context: Optional[Dict[str, Any]] = None
    timestamp: datetime = None

@dataclass
class FixOpsDecision:
    """Final FixOps decision output"""
    decision_id: str
    recommendation: str  # ALLOW, BLOCK, DEFER
    confidence: float
    ssvc_decision: str  # Act, Attend, Track
    risk_score: float
    evidence_id: str
    human_explanation: str
    ci_cd_action: str
    timestamp: datetime

class FixOpsUserWorkflow:
    """
    Complete user workflow for FixOps - from design stage configuration to CI/CD decisions
    """
    
    def __init__(self):
        self.organizations = {}  # Store org configs
        self.submissions = {}    # Store scan submissions
        self.decisions = {}      # Store decisions
    
    # PHASE 1: DESIGN STAGE - SSVC CONFIGURATION
    async def setup_organization_ssvc(self, org_context: OrganizationContext) -> Dict[str, Any]:
        """
        Phase 1: Design Stage - Organization sets up their SSVC framework
        This is where python-ssvc is used to configure stakeholder-specific decisions
        """
        try:
            from src.services.missing_oss_integrations import missing_oss_service
            
            logger.info(f"🏗️ Setting up SSVC framework for {org_context.organization_name}")
            
            # Configure SSVC decision points based on organization context
            ssvc_config = {
                "stakeholder_type": org_context.stakeholder_type,
                "decision_points": {
                    "Exploitation": {
                        "values": ["none", "poc", "active"],
                        "description": "Current exploitation status of vulnerability"
                    },
                    "Exposure": {
                        "values": ["small", "controlled", "open"], 
                        "description": "How accessible is the vulnerable component"
                    },
                    "Utility": {
                        "values": ["laborious", "efficient", "super_effective"],
                        "description": "Usefulness of exploit to adversary"
                    },
                    "Technical_Impact": {
                        "values": ["partial", "total"],
                        "description": "Technical impact of successful exploitation"
                    },
                    "Mission_Impact": org_context.mission_impact_factors,
                    "Safety_Impact": org_context.safety_impact_context
                },
                "decision_outcomes": {
                    "Track": "Monitor vulnerability but no immediate action required",
                    "Attend": "Schedule remediation within defined timeframe", 
                    "Act": "Immediate action required - block deployment"
                },
                "organization_thresholds": {
                    "production": {"risk_threshold": 0.3, "ssvc_threshold": "Attend"},
                    "staging": {"risk_threshold": 0.5, "ssvc_threshold": "Act"},
                    "development": {"risk_threshold": 0.7, "ssvc_threshold": "Act"}
                }
            }
            
            # Store organization configuration
            org_id = f"org_{org_context.organization_name.lower().replace(' ', '_')}"
            self.organizations[org_id] = {
                "context": org_context,
                "ssvc_config": ssvc_config,
                "configured_at": datetime.now(timezone.utc),
                "status": "configured"
            }
            
            return {
                "status": "success",
                "organization_id": org_id,
                "ssvc_framework_configured": True,
                "decision_points_configured": len(ssvc_config["decision_points"]),
                "stakeholder_type": org_context.stakeholder_type,
                "next_step": "Users can now submit scan data for decision-making",
                "api_endpoint": f"/api/v1/decisions/evaluate/{org_id}"
            }
            
        except Exception as e:
            logger.error(f"SSVC setup failed: {e}")
            return {"status": "error", "error": str(e)}
    
    # PHASE 2: SCAN SUBMISSION - USER UPLOADS SECURITY DATA
    async def submit_security_scan(self, org_id: str, submission: ScanSubmission) -> Dict[str, Any]:
        """
        Phase 2: User submits security scan data (SARIF, SBOM, etc.) for analysis
        """
        try:
            if org_id not in self.organizations:
                raise ValueError(f"Organization {org_id} not configured. Run setup_organization_ssvc first.")
            
            logger.info(f"📤 Processing scan submission for {submission.service_name}")
            
            # Validate scan data
            validation_result = await self._validate_scan_data(submission.scan_data)
            if not validation_result["valid"]:
                return {"status": "validation_error", "errors": validation_result["errors"]}
            
            # Store submission
            submission.timestamp = datetime.now(timezone.utc)
            self.submissions[submission.submission_id] = submission
            
            # Parse different scan formats using OSS tools
            parsed_data = await self._parse_scan_data(submission.scan_data)
            
            return {
                "status": "success",
                "submission_id": submission.submission_id,
                "service_name": submission.service_name,
                "environment": submission.environment,
                "scan_data_parsed": parsed_data,
                "next_step": "Run FixOps decision engine analysis",
                "api_endpoint": f"/api/v1/decisions/analyze/{submission.submission_id}"
            }
            
        except Exception as e:
            logger.error(f"Scan submission failed: {e}")
            return {"status": "error", "error": str(e)}
    
    # PHASE 3: DECISION ENGINE - FIXOPS PROCESSES THE DATA
    async def run_decision_engine(self, submission_id: str) -> FixOpsDecision:
        """
        Phase 3: FixOps runs complete decision engine with all OSS tools
        """
        try:
            if submission_id not in self.submissions:
                raise ValueError(f"Submission {submission_id} not found")
            
            submission = self.submissions[submission_id]
            org_config = self._get_org_config(submission)
            
            logger.info(f"🧠 Running FixOps decision engine for {submission.service_name}")
            
            # Step 1: Extract SSVC context from submission + org config
            ssvc_context = await self._extract_ssvc_context(submission, org_config)
            
            # Step 2: Run Processing Layer (all OSS tools)
            from src.services.processing_layer import ProcessingLayer
            processing_layer = ProcessingLayer()
            
            # Create Markov states from vulnerabilities
            markov_states = await self._create_markov_states(submission.scan_data)
            
            # Run complete processing pipeline
            processing_results = await processing_layer.process_security_context(
                ssvc_context=ssvc_context,
                markov_states=markov_states,
                sarif_data=submission.scan_data.get("sarif")
            )
            
            # Step 3: Apply organization-specific thresholds
            final_decision = await self._apply_organization_decision_logic(
                processing_results, org_config, submission
            )
            
            # Step 4: Generate CI/CD action
            ci_cd_action = self._generate_ci_cd_action(final_decision)
            
            # Create final decision object
            decision = FixOpsDecision(
                decision_id=f"decision_{int(datetime.now(timezone.utc).timestamp())}",
                recommendation=final_decision["recommendation"],
                confidence=final_decision["confidence"],
                ssvc_decision=final_decision["ssvc_decision"], 
                risk_score=final_decision["risk_score"],
                evidence_id=processing_results["processing_metadata"].get("evidence_id", ""),
                human_explanation=processing_results["human_readable_summary"],
                ci_cd_action=ci_cd_action,
                timestamp=datetime.now(timezone.utc)
            )
            
            # Store decision
            self.decisions[decision.decision_id] = decision
            
            return decision
            
        except Exception as e:
            logger.error(f"Decision engine failed: {e}")
            raise
    
    # PHASE 4: CI/CD INTEGRATION - AUTOMATED DEPLOYMENT GATING
    def get_cicd_decision(self, decision_id: str) -> Dict[str, Any]:
        """
        Phase 4: CI/CD pipeline queries FixOps for deployment decision
        """
        try:
            if decision_id not in self.decisions:
                return {"status": "not_found", "action": "BLOCK", "reason": "Decision not found"}
            
            decision = self.decisions[decision_id]
            
            return {
                "status": "success",
                "action": decision.recommendation,  # ALLOW, BLOCK, DEFER
                "confidence": decision.confidence,
                "ssvc_decision": decision.ssvc_decision,
                "risk_score": decision.risk_score,
                "explanation": decision.human_explanation,
                "ci_cd_instructions": {
                    "proceed_deployment": decision.recommendation == "ALLOW",
                    "require_manual_review": decision.recommendation == "DEFER",
                    "block_deployment": decision.recommendation == "BLOCK",
                    "evidence_url": f"/api/v1/evidence/{decision.evidence_id}"
                },
                "decision_timestamp": decision.timestamp.isoformat()
            }
            
        except Exception as e:
            logger.error(f"CI/CD decision retrieval failed: {e}")
            return {"status": "error", "action": "BLOCK", "error": str(e)}
    
    # HELPER METHODS
    async def _validate_scan_data(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate incoming scan data"""
        errors = []
        
        if not scan_data:
            errors.append("No scan data provided")
        
        # Check for required formats
        has_sarif = "sarif" in scan_data
        has_sbom = "sbom" in scan_data
        has_findings = "findings" in scan_data
        
        if not (has_sarif or has_sbom or has_findings):
            errors.append("No recognized scan data format (SARIF, SBOM, or findings)")
        
        return {"valid": len(errors) == 0, "errors": errors}
    
    async def _parse_scan_data(self, scan_data: Dict[str, Any]) -> Dict[str, Any]:
        """Parse scan data using OSS tools"""
        parsed = {}
        
        try:
            # Use lib4sbom for SBOM parsing
            if "sbom" in scan_data:
                from src.services.missing_oss_integrations import missing_oss_service
                sbom_result = await missing_oss_service.sbom_parser.parse_sbom(
                    json.dumps(scan_data["sbom"]) if isinstance(scan_data["sbom"], dict) else scan_data["sbom"]
                )
                parsed["sbom"] = sbom_result
            
            # Use sarif-tools for SARIF processing
            if "sarif" in scan_data:
                from src.services.missing_oss_integrations import missing_oss_service
                sarif_result = await missing_oss_service.sarif_processor.convert_to_sarif(
                    {"findings": scan_data.get("findings", [])}, "FixOps"
                )
                parsed["sarif"] = sarif_result
                
        except Exception as e:
            logger.warning(f"Scan data parsing failed: {e}")
        
        return parsed
    
    def _get_org_config(self, submission: ScanSubmission) -> Dict[str, Any]:
        """Get organization configuration for submission"""
        # In real implementation, would lookup by org_id from submission
        # For now, return first configured organization
        if self.organizations:
            return list(self.organizations.values())[0]
        return {}
    
    async def _extract_ssvc_context(self, submission: ScanSubmission, org_config: Dict[str, Any]) -> Any:
        """Extract SSVC context from submission and org config"""
        from src.services.processing_layer import SSVCContext
        
        # Map scan findings to SSVC decision points
        findings = submission.scan_data.get("findings", [])
        
        # Determine exploitation level
        exploitation = "none"
        if any(f.get("kev_flag", False) for f in findings):
            exploitation = "active"
        elif any(f.get("epss_score", 0) > 0.7 for f in findings):
            exploitation = "poc"
        
        # Determine exposure based on environment
        exposure_map = {"production": "open", "staging": "controlled", "development": "small"}
        exposure = exposure_map.get(submission.environment, "controlled")
        
        # Determine utility and impacts based on severity
        critical_count = len([f for f in findings if f.get("severity") == "CRITICAL"])
        high_count = len([f for f in findings if f.get("severity") == "HIGH"])
        
        utility = "super_effective" if critical_count > 0 else "efficient" if high_count > 0 else "laborious"
        safety_impact = "major" if critical_count > 2 else "marginal"
        mission_impact = "crippled" if critical_count > 3 else "degraded"
        
        return SSVCContext(
            exploitation=exploitation,
            exposure=exposure,
            utility=utility,
            safety_impact=safety_impact,
            mission_impact=mission_impact
        )
    
    async def _create_markov_states(self, scan_data: Dict[str, Any]) -> List[Any]:
        """Create Markov states from scan data"""
        from src.services.processing_layer import MarkovState
        
        states = []
        findings = scan_data.get("findings", [])
        
        for finding in findings:
            state = MarkovState(
                current_state="vulnerable" if finding.get("severity") in ["HIGH", "CRITICAL"] else "secure",
                cve_id=finding.get("cve_id"),
                epss_score=finding.get("epss_score", 0.5),
                kev_flag=finding.get("kev_flag", False),
                disclosure_date=datetime.now(timezone.utc)
            )
            states.append(state)
        
        return states
    
    async def _apply_organization_decision_logic(self, processing_results: Dict[str, Any], 
                                               org_config: Dict[str, Any], 
                                               submission: ScanSubmission) -> Dict[str, Any]:
        """Apply organization-specific decision thresholds"""
        
        # Get organization thresholds
        ssvc_config = org_config.get("ssvc_config", {})
        env_thresholds = ssvc_config.get("organization_thresholds", {}).get(
            submission.environment, {"risk_threshold": 0.5, "ssvc_threshold": "Attend"}
        )
        
        # Extract results from processing
        risk_score = processing_results.get("risk_score", 0.5)
        fusion_decision = processing_results["processing_results"]["fusion_decision"]
        
        # Apply SSVC decision mapping
        ssvc_decision = "Track"
        if risk_score >= 0.8:
            ssvc_decision = "Act"
        elif risk_score >= 0.5:
            ssvc_decision = "Attend"
        
        # Map SSVC to FixOps recommendation
        recommendation = "ALLOW"
        if ssvc_decision == "Act":
            recommendation = "BLOCK"
        elif ssvc_decision == "Attend" and submission.environment == "production":
            recommendation = "DEFER"
        
        return {
            "recommendation": recommendation,
            "ssvc_decision": ssvc_decision,
            "risk_score": risk_score,
            "confidence": processing_results.get("confidence_score", 0.8),
            "organization_threshold": env_thresholds,
            "applied_logic": f"Risk score {risk_score:.2f} vs threshold {env_thresholds['risk_threshold']}"
        }
    
    def _generate_ci_cd_action(self, decision_result: Dict[str, Any]) -> str:
        """Generate CI/CD action based on decision"""
        recommendation = decision_result["recommendation"]
        
        actions = {
            "ALLOW": "proceed_deployment",
            "DEFER": "require_manual_approval", 
            "BLOCK": "halt_deployment"
        }
        
        return actions.get(recommendation, "halt_deployment")

# Global workflow instance
user_workflow = FixOpsUserWorkflow()