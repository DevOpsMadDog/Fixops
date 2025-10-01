"""
User Workflow API - Complete FixOps process from design to CI/CD
Shows how users actually interact with FixOps step by step
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, List, Any, Optional
import structlog
import json
from datetime import datetime, timezone

from src.services.user_workflow import user_workflow, OrganizationContext, ScanSubmission

logger = structlog.get_logger()
router = APIRouter(prefix="/workflow", tags=["user-workflow"])

class OrganizationSetup(BaseModel):
    organization_name: str
    stakeholder_type: str  # "deployer", "supplier", "coordinator"
    mission_impact_factors: Dict[str, str]
    safety_impact_context: Dict[str, str]
    environment_types: List[str]
    risk_tolerance: str
    compliance_requirements: List[str]

class ScanSubmissionRequest(BaseModel):
    service_name: str
    environment: str
    submitter: str
    scan_data: Dict[str, Any]
    business_context: Optional[Dict[str, Any]] = None

@router.get("/")
async def get_workflow_overview():
    """Get overview of complete FixOps user workflow"""
    return {
        "fixops_user_workflow": {
            "phase_1_design_stage": {
                "title": "🏗️ Design Stage - SSVC Configuration",
                "description": "Organization configures their SSVC framework and decision thresholds",
                "api_endpoint": "/api/v1/workflow/setup-organization",
                "required_inputs": ["stakeholder_type", "mission_impact_factors", "risk_tolerance"],
                "outputs": ["SSVC decision points", "Organization thresholds", "API endpoints"]
            },
            "phase_2_scan_submission": {
                "title": "📤 Scan Submission - Security Data Upload",
                "description": "Users submit SARIF, SBOM, and security findings for analysis",
                "api_endpoint": "/api/v1/workflow/submit-scan",
                "required_inputs": ["SARIF/SBOM data", "service_name", "environment"],
                "outputs": ["Parsed scan data", "Validation results", "Submission ID"]
            },
            "phase_3_decision_engine": {
                "title": "🧠 Decision Engine - FixOps Analysis",
                "description": "Complete processing with all OSS tools (Bayesian, Markov, SSVC, Knowledge Graph, LLM)",
                "api_endpoint": "/api/v1/workflow/analyze/{submission_id}",
                "processing_components": ["python-ssvc", "mchmm", "pgmpy", "pomegranate", "CTINexus", "Awesome-LLM4Cybersecurity"],
                "outputs": ["ALLOW/BLOCK/DEFER decision", "Confidence score", "Human explanation"]
            },
            "phase_4_cicd_integration": {
                "title": "🚀 CI/CD Integration - Automated Gating",
                "description": "CI/CD pipelines query FixOps for deployment decisions",
                "api_endpoint": "/api/v1/workflow/cicd-decision/{decision_id}",
                "integration_methods": ["REST API", "CLI tool", "GitHub Actions"],
                "outputs": ["proceed_deployment", "require_manual_approval", "halt_deployment"]
            }
        },
        "data_flow": {
            "input_layer": ["SARIF (from scanners)", "SBOM (from builds)", "Business context"],
            "processing_layer": ["SSVC framework", "Bayesian networks", "Markov chains", "Knowledge graphs", "LLM analysis"],
            "decision_layer": ["Organization thresholds", "Stakeholder context", "Risk calculation"],
            "output_layer": ["Decision recommendation", "Evidence trail", "Human explanations", "CI/CD actions"]
        },
        "oss_tools_integration": {
            "design_stage": "python-ssvc for SSVC configuration",
            "input_parsing": "lib4sbom, sarif-tools for data normalization",
            "processing": "mchmm, pgmpy, pomegranate for risk modeling",
            "knowledge": "CTINexus for entity extraction",
            "explanations": "Awesome-LLM4Cybersecurity for human summaries"
        }
    }

@router.post("/setup-organization")
async def setup_organization_ssvc(org_setup: OrganizationSetup):
    """
    Phase 1: Design Stage - Setup organization's SSVC framework
    This is where python-ssvc library is used to configure stakeholder-specific decisions
    """
    try:
        org_context = OrganizationContext(
            organization_name=org_setup.organization_name,
            stakeholder_type=org_setup.stakeholder_type,
            mission_impact_factors=org_setup.mission_impact_factors,
            safety_impact_context=org_setup.safety_impact_context,
            environment_types=org_setup.environment_types,
            risk_tolerance=org_setup.risk_tolerance,
            compliance_requirements=org_setup.compliance_requirements
        )
        
        result = await user_workflow.setup_organization_ssvc(org_context)
        
        return {
            "phase": "Design Stage - SSVC Configuration",
            "status": result["status"],
            "organization_configured": result.get("organization_id"),
            "ssvc_framework": {
                "stakeholder_type": org_setup.stakeholder_type,
                "decision_points_configured": result.get("decision_points_configured", 0),
                "python_ssvc_library_used": True
            },
            "next_steps": {
                "description": "Organization SSVC framework is configured. Users can now submit scan data.",
                "api_endpoint": result.get("api_endpoint"),
                "example_curl": f'''curl -X POST {result.get("api_endpoint", "/api/v1/workflow/submit-scan")} \\
  -H "Content-Type: application/json" \\
  -d '{{"service_name": "my-service", "environment": "production", "scan_data": {{}}}}'
'''
            }
        }
        
    except Exception as e:
        logger.error(f"Organization setup failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/submit-scan")
async def submit_security_scan(scan_request: ScanSubmissionRequest):
    """
    Phase 2: User submits security scan data for FixOps analysis
    Uses lib4sbom and sarif-tools for parsing different formats
    """
    try:
        # Generate submission ID
        submission_id = f"scan_{int(datetime.now(timezone.utc).timestamp())}"
        
        submission = ScanSubmission(
            submission_id=submission_id,
            service_name=scan_request.service_name,
            environment=scan_request.environment,
            submitter=scan_request.submitter,
            scan_data=scan_request.scan_data,
            business_context=scan_request.business_context
        )
        
        # Use first configured org (in real system, would be based on user authentication)
        org_id = list(user_workflow.organizations.keys())[0] if user_workflow.organizations else "default_org"
        
        result = await user_workflow.submit_security_scan(org_id, submission)
        
        return {
            "phase": "Scan Submission - Security Data Upload",
            "status": result["status"],
            "submission_details": {
                "submission_id": submission_id,
                "service_name": scan_request.service_name,
                "environment": scan_request.environment,
                "scan_data_types": list(scan_request.scan_data.keys())
            },
            "oss_tools_used": {
                "lib4sbom": "SBOM parsing" if "sbom" in scan_request.scan_data else "not_used",
                "sarif_tools": "SARIF processing" if "sarif" in scan_request.scan_data else "not_used"
            },
            "parsed_data_summary": result.get("scan_data_parsed", {}),
            "next_steps": {
                "description": "Scan data submitted successfully. Run FixOps decision engine analysis.",
                "api_endpoint": f"/api/v1/workflow/analyze/{submission_id}",
                "example_curl": f'''curl -X POST /api/v1/workflow/analyze/{submission_id}'''
            }
        }
        
    except Exception as e:
        logger.error(f"Scan submission failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/analyze/{submission_id}")
async def run_decision_analysis(submission_id: str):
    """
    Phase 3: FixOps runs complete decision engine with all OSS tools
    Uses the full Processing Layer with all architecture components
    """
    try:
        decision = await user_workflow.run_decision_engine(submission_id)
        
        return {
            "phase": "Decision Engine - FixOps Analysis",
            "decision_results": {
                "decision_id": decision.decision_id,
                "recommendation": decision.recommendation,
                "confidence": decision.confidence,
                "ssvc_decision": decision.ssvc_decision,
                "risk_score": decision.risk_score,
                "human_explanation": decision.human_explanation,
                "timestamp": decision.timestamp.isoformat()
            },
            "processing_pipeline": {
                "oss_tools_used": [
                    "python-ssvc (SSVC decision framework)",
                    "mchmm (Markov state transitions)",
                    "pgmpy (Bayesian networks)",
                    "pomegranate (Advanced Bayesian modeling)", 
                    "CTINexus (Knowledge graph construction)",
                    "Awesome-LLM4Cybersecurity (Human explanations)"
                ],
                "architecture_components": [
                    "Bayesian Prior Mapping",
                    "Markov Transition Matrix Builder",
                    "SSVC + Probabilistic Fusion Logic",
                    "SARIF-Based Non-CVE Vulnerability Handling",
                    "Knowledge Graph Construction",
                    "LLM Explanation Engine"
                ]
            },
            "ci_cd_integration": {
                "action_required": decision.ci_cd_action,
                "deployment_decision": decision.recommendation,
                "evidence_id": decision.evidence_id
            },
            "next_steps": {
                "description": "Decision generated. CI/CD pipeline can now query for deployment action.",
                "api_endpoint": f"/api/v1/workflow/cicd-decision/{decision.decision_id}",
                "example_curl": f'''curl -X GET /api/v1/workflow/cicd-decision/{decision.decision_id}'''
            }
        }
        
    except Exception as e:
        logger.error(f"Decision analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/cicd-decision/{decision_id}")
async def get_cicd_decision(decision_id: str):
    """
    Phase 4: CI/CD pipeline queries FixOps for deployment decision
    Returns actionable decision for automated deployment gating
    """
    try:
        decision_result = user_workflow.get_cicd_decision(decision_id)
        
        return {
            "phase": "CI/CD Integration - Automated Gating",
            "cicd_decision": {
                "action": decision_result["action"],  # ALLOW, BLOCK, DEFER
                "confidence": decision_result.get("confidence", 0),
                "risk_score": decision_result.get("risk_score", 0),
                "ssvc_decision": decision_result.get("ssvc_decision", ""),
                "explanation": decision_result.get("explanation", "")
            },
            "deployment_instructions": decision_result.get("ci_cd_instructions", {}),
            "pipeline_actions": {
                "if_ALLOW": "✅ Proceed with deployment - security checks passed",
                "if_DEFER": "⏸️ Require manual security review before deployment", 
                "if_BLOCK": "🚫 Halt deployment - security risks too high"
            },
            "evidence_trail": {
                "decision_timestamp": decision_result.get("decision_timestamp"),
                "evidence_url": decision_result.get("ci_cd_instructions", {}).get("evidence_url", ""),
                "audit_ready": True
            },
            "integration_examples": {
                "github_actions": '''
- name: FixOps Security Gate
  run: |
    DECISION=$(curl -s /api/v1/workflow/cicd-decision/{decision_id} | jq -r '.cicd_decision.action')
    if [ "$DECISION" = "BLOCK" ]; then
      echo "Deployment blocked by FixOps security analysis"
      exit 1
    elif [ "$DECISION" = "DEFER" ]; then
      echo "Manual review required"
      # Create GitHub issue for review
    fi
''',
                "jenkins": '''
pipeline {
    stage('Security Gate') {
        steps {
            script {
                def decision = sh(returnStdout: true, script: 'curl -s /api/v1/workflow/cicd-decision/{decision_id}').trim()
                def actionResult = readJSON text: decision
                if (actionResult.cicd_decision.action == 'BLOCK') {
                    error('Deployment blocked by FixOps')
                }
            }
        }
    }
}
'''
            }
        }
        
    except Exception as e:
        logger.error(f"CI/CD decision retrieval failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/example-complete-flow")
async def get_example_complete_flow():
    """
    Complete example showing how users interact with FixOps end-to-end
    """
    return {
        "complete_fixops_workflow": {
            "description": "Complete example of how organizations use FixOps from setup to deployment",
            
            "step_1_design_stage": {
                "title": "🏗️ Organization Setup (One-time)",
                "what_happens": "Security team configures SSVC framework using python-ssvc library",
                "example_request": {
                    "organization_name": "Acme Corp",
                    "stakeholder_type": "deployer",
                    "mission_impact_factors": {
                        "production": "Mission Essential Degraded (MEV)",
                        "staging": "Support Crippled", 
                        "development": "Support Degraded"
                    },
                    "safety_impact_context": {
                        "customer_data": "major",
                        "financial_systems": "hazardous",
                        "internal_tools": "negligible"
                    },
                    "risk_tolerance": "low"
                },
                "result": "SSVC decision points configured, thresholds set per environment"
            },
            
            "step_2_developer_workflow": {
                "title": "👨‍💻 Developer Submits Scan (Daily)",
                "what_happens": "Developer runs security scans and submits results to FixOps",
                "example_scan_data": {
                    "sarif": "SARIF output from Semgrep/CodeQL/Snyk",
                    "sbom": "SBOM from build system (CycloneDX/SPDX)",
                    "findings": "Additional security findings"
                },
                "oss_tools_used": ["lib4sbom", "sarif-tools"],
                "result": "Scan data parsed and validated"
            },
            
            "step_3_fixops_analysis": {
                "title": "🧠 FixOps Processing (Automated)",
                "what_happens": "Complete Processing Layer runs with all OSS components",
                "processing_steps": [
                    "1. Bayesian Prior Mapping (pgmpy/pomegranate) - assign probabilities based on SSVC context",
                    "2. Markov Transition Matrix (mchmm) - model vulnerability state evolution", 
                    "3. SSVC + Probabilistic Fusion - combine deterministic SSVC with probabilistic outputs",
                    "4. SARIF Non-CVE Handling - process scanner findings without CVEs",
                    "5. Knowledge Graph Construction (CTINexus) - link entities and relationships",
                    "6. LLM Explanation Engine (Awesome-LLM4Cybersecurity) - generate human summaries"
                ],
                "result": "ALLOW/BLOCK/DEFER decision with confidence score and human explanation"
            },
            
            "step_4_cicd_gating": {
                "title": "🚀 CI/CD Pipeline (Automated)",
                "what_happens": "CI/CD pipeline queries FixOps decision before deployment",
                "pipeline_integration": '''
# GitHub Actions Example
- name: Get FixOps Decision  
  run: |
    DECISION=$(curl /api/v1/workflow/cicd-decision/$DECISION_ID | jq -r '.cicd_decision.action')
    echo "FixOps Decision: $DECISION"
    
    case $DECISION in
      "ALLOW")  echo "✅ Proceeding with deployment" ;;
      "DEFER")  echo "⏸️ Manual review required" && exit 1 ;;
      "BLOCK")  echo "🚫 Deployment blocked" && exit 1 ;;
    esac
''',
                "result": "Automated deployment gating based on security analysis"
            }
        },
        
        "data_flow_summary": {
            "inputs": [
                "SARIF files from security scanners (Semgrep, CodeQL, Snyk)",
                "SBOM files from build systems (npm, Maven, Docker)",
                "Business context (service criticality, environment)"
            ],
            "processing": [
                "SSVC framework evaluation (stakeholder-specific decisions)",
                "Bayesian risk modeling (component probabilities)",
                "Markov state predictions (vulnerability evolution)",  
                "Knowledge graph analysis (entity relationships)",
                "LLM explanation generation (human-readable summaries)"
            ],
            "outputs": [
                "Binary decision: ALLOW/BLOCK/DEFER",
                "Confidence score: 0.0 - 1.0",
                "Risk score: 0.0 - 1.0", 
                "Human explanation: Why this decision was made",
                "Evidence trail: Audit-ready documentation"
            ]
        }
    }