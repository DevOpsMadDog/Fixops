"""
End-to-End Sample Data Demo
Complete demonstration of FixOps process with real sample data
Shows data transformation at each stage
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Dict, List, Any, Optional
import structlog

logger = structlog.get_logger()
import json
from datetime import datetime, timezone

router = APIRouter(prefix="/demo", tags=["sample-data-demo"])

@router.get("/sample-data")
async def get_sample_data():
    """
    Real sample data that would come from various security tools
    """
    return {
        "sample_inputs": {
            "1_sarif_from_semgrep": {
                "description": "SARIF output from Semgrep static analysis scanner",
                "data": {
                    "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
                    "version": "2.1.0",
                    "runs": [
                        {
                            "tool": {
                                "driver": {
                                    "name": "Semgrep",
                                    "version": "1.45.0",
                                    "informationUri": "https://semgrep.dev"
                                }
                            },
                            "results": [
                                {
                                    "ruleId": "javascript.express.security.audit.xss.direct-response-write.direct-response-write",
                                    "level": "error",
                                    "message": {
                                        "text": "Detected XSS vulnerability. User input is directly written to HTTP response without sanitization."
                                    },
                                    "locations": [
                                        {
                                            "physicalLocation": {
                                                "artifactLocation": {
                                                    "uri": "/app/src/routes/api.js"
                                                },
                                                "region": {
                                                    "startLine": 42,
                                                    "startColumn": 5,
                                                    "endLine": 42,
                                                    "endColumn": 35
                                                }
                                            }
                                        }
                                    ],
                                    "properties": {
                                        "cwe_id": "CWE-79",
                                        "owasp_category": "A03:2021",
                                        "confidence": "high"
                                    }
                                },
                                {
                                    "ruleId": "javascript.express.security.injection.sql-injection.sequelize-injection",
                                    "level": "error", 
                                    "message": {
                                        "text": "Detected SQL injection vulnerability in Sequelize query. User input is not properly sanitized."
                                    },
                                    "locations": [
                                        {
                                            "physicalLocation": {
                                                "artifactLocation": {
                                                    "uri": "/app/src/models/User.js"
                                                },
                                                "region": {
                                                    "startLine": 128,
                                                    "startColumn": 12
                                                }
                                            }
                                        }
                                    ],
                                    "properties": {
                                        "cwe_id": "CWE-89",
                                        "owasp_category": "A03:2021",
                                        "confidence": "high"
                                    }
                                }
                            ]
                        }
                    ]
                }
            },
            
            "2_sbom_from_npm": {
                "description": "SBOM generated from npm package.json during build",
                "data": {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.4",
                    "serialNumber": "urn:uuid:payment-api-v2.1.0-20241001",
                    "version": 1,
                    "metadata": {
                        "timestamp": "2024-10-01T18:30:00Z",
                        "tools": [
                            {
                                "vendor": "NPM",
                                "name": "npm-audit",
                                "version": "10.2.0"
                            }
                        ],
                        "component": {
                            "type": "application",
                            "name": "payment-api",
                            "version": "2.1.0"
                        }
                    },
                    "components": [
                        {
                            "type": "library",
                            "name": "express",
                            "version": "4.17.1", 
                            "purl": "pkg:npm/express@4.17.1",
                            "supplier": {
                                "name": "TJ Holowaychuk"
                            },
                            "licenses": [
                                {
                                    "license": {
                                        "id": "MIT"
                                    }
                                }
                            ]
                        },
                        {
                            "type": "library",
                            "name": "lodash",
                            "version": "4.17.20",
                            "purl": "pkg:npm/lodash@4.17.20",
                            "supplier": {
                                "name": "John-David Dalton"
                            }
                        },
                        {
                            "type": "library", 
                            "name": "mysql2",
                            "version": "2.3.0",
                            "purl": "pkg:npm/mysql2@2.3.0"
                        }
                    ]
                }
            },
            
            "3_vulnerability_findings": {
                "description": "Enriched vulnerability data with threat intelligence",
                "data": [
                    {
                        "id": "finding_001",
                        "title": "Cross-Site Scripting (XSS) in API Response",
                        "description": "Direct user input reflection in HTTP response without sanitization allows XSS attacks",
                        "severity": "HIGH",
                        "cve_id": "CVE-2023-45678",
                        "cwe_id": "CWE-79",
                        "cvss_score": 7.5,
                        "epss_score": 0.73,
                        "kev_flag": false,
                        "component": "express@4.17.1",
                        "file_path": "/app/src/routes/api.js",
                        "line_number": 42,
                        "fix_available": true,
                        "fix_version": "4.18.2"
                    },
                    {
                        "id": "finding_002", 
                        "title": "SQL Injection in User Authentication",
                        "description": "Unsanitized user input in SQL query allows injection attacks",
                        "severity": "CRITICAL",
                        "cve_id": "CVE-2024-12345",
                        "cwe_id": "CWE-89", 
                        "cvss_score": 9.8,
                        "epss_score": 0.95,
                        "kev_flag": true,
                        "component": "mysql2@2.3.0",
                        "file_path": "/app/src/models/User.js",
                        "line_number": 128,
                        "fix_available": true,
                        "fix_version": "2.3.3"
                    }
                ]
            },
            
            "4_business_context": {
                "description": "Business context provided by organization",
                "data": {
                    "service_name": "payment-api",
                    "environment": "production",
                    "criticality": "high",
                    "compliance_requirements": ["PCI-DSS", "SOC2"],
                    "customer_impact": "high",
                    "revenue_impact": "critical",
                    "data_classification": "restricted",
                    "deployment_frequency": "daily"
                }
            }
        }
    }

@router.post("/run-complete-demo")
async def run_complete_demo():
    """
    Run complete end-to-end demo showing data transformation at each stage
    """
    try:
        demo_results = {
            "demo_overview": "Complete FixOps pipeline with sample data from Semgrep + npm + threat intel",
            "processing_stages": {}
        }
        
        # Get sample data
        sample_response = await get_sample_data()
        sample_data = sample_response["sample_inputs"]
        
        # STAGE 1: INPUT LAYER - Parse with OSS tools
        demo_results["processing_stages"]["stage_1_input_parsing"] = await _demo_input_parsing(sample_data)
        
        # STAGE 2: PROCESSING LAYER - Run all OSS components
        demo_results["processing_stages"]["stage_2_processing_layer"] = await _demo_processing_layer(sample_data)
        
        # STAGE 3: DECISION LAYER - Apply SSVC and org thresholds
        demo_results["processing_stages"]["stage_3_decision_layer"] = await _demo_decision_layer(sample_data)
        
        # STAGE 4: OUTPUT LAYER - Generate final recommendation
        demo_results["processing_stages"]["stage_4_output_layer"] = await _demo_output_layer(sample_data)
        
        # STAGE 5: CI/CD INTEGRATION - Show pipeline integration
        demo_results["processing_stages"]["stage_5_cicd_integration"] = await _demo_cicd_integration()
        
        return demo_results
        
    except Exception as e:
        logger.error(f"Complete demo failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

async def _demo_input_parsing(sample_data: Dict[str, Any]) -> Dict[str, Any]:
    """Stage 1: Input Layer - Parse SARIF/SBOM with OSS tools"""
    
    # Use lib4sbom to parse SBOM
    try:
        from src.services.missing_oss_integrations import missing_oss_service
        
        sbom_data = sample_data["2_sbom_from_npm"]["data"]
        sbom_parsed = await missing_oss_service.sbom_parser.parse_sbom(json.dumps(sbom_data))
        
        # Use sarif-tools to process SARIF
        sarif_data = sample_data["1_sarif_from_semgrep"]["data"]
        
        # Extract findings for SARIF conversion
        findings = []
        for run in sarif_data.get("runs", []):
            for result in run.get("results", []):
                finding = {
                    "rule_id": result.get("ruleId", "unknown"),
                    "severity": "high" if result.get("level") == "error" else "medium",
                    "description": result.get("message", {}).get("text", ""),
                    "file_path": result.get("locations", [{}])[0].get("physicalLocation", {}).get("artifactLocation", {}).get("uri", "unknown"),
                    "line_number": result.get("locations", [{}])[0].get("physicalLocation", {}).get("region", {}).get("startLine", 1),
                    "cwe_id": result.get("properties", {}).get("cwe_id"),
                    "confidence": 0.9
                }
                findings.append(finding)
        
        sarif_processed = await missing_oss_service.sarif_processor.convert_to_sarif(
            {"findings": findings}, "Semgrep"
        )
        
        return {
            "stage": "Input Layer - OSS Tools Parsing",
            "tools_used": ["lib4sbom v0.8.8", "sarif-tools v3.0.5"],
            "input_formats": ["SARIF 2.1.0", "CycloneDX SBOM", "Vulnerability Findings"],
            "parsing_results": {
                "sbom_components_extracted": sbom_parsed.get("components_count", 0),
                "sarif_findings_processed": len(findings),
                "vulnerabilities_identified": 2,
                "total_components": 3
            },
            "parsed_data": {
                "components": [
                    {"name": "express", "version": "4.17.1", "vulnerabilities": ["CVE-2023-45678"]},
                    {"name": "lodash", "version": "4.17.20", "vulnerabilities": []},
                    {"name": "mysql2", "version": "2.3.0", "vulnerabilities": ["CVE-2024-12345"]}
                ],
                "vulnerabilities": [
                    {"cve": "CVE-2023-45678", "severity": "HIGH", "epss": 0.73, "kev": False, "cwe": "CWE-79"},
                    {"cve": "CVE-2024-12345", "severity": "CRITICAL", "epss": 0.95, "kev": True, "cwe": "CWE-89"}
                ]
            },
            "data_transformation": "Raw scanner output → Normalized security entities with relationships"
        }
        
    except Exception as e:
        logger.error(f"Input parsing demo failed: {e}")
        return {"stage": "Input Layer", "status": "error", "error": str(e)}

async def _demo_processing_layer(sample_data: Dict[str, Any]) -> Dict[str, Any]:
    """Stage 2: Processing Layer - All OSS components"""
    
    try:
        # Simulate SSVC context extraction
        ssvc_analysis = {
            "exploitation": "active",  # KEV flagged CVE-2024-12345
            "exposure": "open",        # Production environment
            "utility": "super_effective",  # SQL injection is highly useful
            "safety_impact": "major",      # Payment system
            "mission_impact": "crippled"   # Critical business function
        }
        
        # Use python-ssvc for SSVC decision
        from src.services.missing_oss_integrations import missing_oss_service
        ssvc_result = await missing_oss_service.ssvc_framework.evaluate_ssvc_decision(ssvc_analysis)
        
        # Simulate Bayesian Prior Mapping (pgmpy)
        bayesian_priors = {
            "critical": 0.45,  # High probability due to CRITICAL + KEV
            "high": 0.35,
            "medium": 0.15, 
            "low": 0.05
        }
        
        # Simulate Markov Transition Analysis (mchmm)
        markov_predictions = {
            "current_state_distribution": {
                "CVE-2023-45678": {"state": "vulnerable", "exploit_probability": 0.73},
                "CVE-2024-12345": {"state": "vulnerable", "exploit_probability": 0.95}
            },
            "predicted_transitions": {
                "CVE-2023-45678": {"exploited": 0.25, "patched": 0.40, "vulnerable": 0.35},
                "CVE-2024-12345": {"exploited": 0.60, "patched": 0.20, "vulnerable": 0.20}
            },
            "model_confidence": 0.88
        }
        
        # Simulate CTINexus Knowledge Graph Construction
        knowledge_graph = {
            "entities_extracted": [
                {"id": "vuln_cve_2024_12345", "type": "vulnerability", "name": "CVE-2024-12345"},
                {"id": "comp_mysql2", "type": "component", "name": "mysql2@2.3.0"},
                {"id": "service_payment_api", "type": "service", "name": "payment-api"},
                {"id": "technique_t1190", "type": "technique", "name": "T1190 - Exploit Public-Facing Application"}
            ],
            "relationships": [
                {"from": "vuln_cve_2024_12345", "to": "comp_mysql2", "type": "affects"},
                {"from": "comp_mysql2", "to": "service_payment_api", "type": "belongs_to"},
                {"from": "vuln_cve_2024_12345", "to": "technique_t1190", "type": "enables"}
            ],
            "critical_paths": [
                {"path": ["vuln_cve_2024_12345", "comp_mysql2", "service_payment_api"], "risk_score": 0.92}
            ]
        }
        
        # Simulate Pomegranate Advanced Bayesian Analysis
        pomegranate_result = await missing_oss_service.pomegranate_engine.create_bayesian_network([
            {"severity": "critical", "cve_id": "CVE-2024-12345", "exploitability": "easy"},
            {"severity": "high", "cve_id": "CVE-2023-45678", "exploitability": "medium"}
        ])
        
        # SSVC + Probabilistic Fusion
        fusion_result = {
            "ssvc_score": 0.85,  # Act decision
            "bayesian_risk": 0.72, 
            "markov_risk": 0.68,
            "composite_risk": 0.75,
            "final_decision": "BLOCK",
            "confidence": 0.91
        }
        
        return {
            "stage": "Processing Layer - All OSS Components",
            "tools_used": [
                "python-ssvc v1.2.3 (SSVC framework)",
                "mchmm v0.4.5 (Markov modeling)", 
                "pgmpy v0.1.25 (Bayesian networks)",
                "pomegranate v1.1.2 (Advanced Bayesian)",
                "CTINexus approach (Knowledge graphs)",
                "Awesome-LLM4Cybersecurity (Explanations)"
            ],
            "processing_components": {
                "1_ssvc_analysis": {
                    "input": ssvc_analysis,
                    "output": ssvc_result,
                    "recommendation": ssvc_result.get("recommendation", "Act")
                },
                "2_bayesian_priors": {
                    "method": "pgmpy inference engine",
                    "input": "SSVC context + vulnerability metadata",
                    "output": bayesian_priors,
                    "interpretation": "45% probability of critical impact"
                },
                "3_markov_transitions": {
                    "method": "mchmm state modeling",
                    "input": "CVE disclosure dates + EPSS + KEV flags",
                    "output": markov_predictions,
                    "key_insight": "CVE-2024-12345 has 60% chance of exploitation"
                },
                "4_knowledge_graph": {
                    "method": "CTINexus entity extraction",
                    "entities_found": len(knowledge_graph["entities_extracted"]),
                    "relationships_inferred": len(knowledge_graph["relationships"]),
                    "critical_attack_paths": len(knowledge_graph["critical_paths"])
                },
                "5_advanced_bayesian": {
                    "method": "pomegranate probabilistic modeling", 
                    "output": pomegranate_result,
                    "risk_distribution": pomegranate_result.get("risk_assessment", {})
                },
                "6_fusion_logic": {
                    "method": "SSVC + Probabilistic Fusion",
                    "inputs": ["SSVC decision", "Bayesian priors", "Markov predictions"],
                    "output": fusion_result,
                    "final_recommendation": fusion_result["final_decision"]
                }
            },
            "data_transformation": "Normalized entities → Risk probabilities → Composite decision"
        }
        
    except Exception as e:
        logger.error(f"Processing layer demo failed: {e}")
        return {"stage": "Processing Layer", "status": "error", "error": str(e)}

async def _demo_decision_layer(sample_data: Dict[str, Any]) -> Dict[str, Any]:
    """Stage 3: Decision Layer - Apply organization thresholds"""
    
    organization_config = {
        "stakeholder_type": "deployer",
        "risk_tolerance": "low", 
        "environment_thresholds": {
            "production": {"risk_threshold": 0.3, "ssvc_threshold": "Attend"},
            "staging": {"risk_threshold": 0.5, "ssvc_threshold": "Act"}, 
            "development": {"risk_threshold": 0.7, "ssvc_threshold": "Act"}
        },
        "compliance_requirements": ["PCI-DSS", "SOC2"]
    }
    
    processing_results = {
        "composite_risk_score": 0.75,
        "ssvc_decision": "Act", 
        "confidence": 0.91,
        "critical_vulnerabilities": 1,
        "kev_flagged_vulns": 1
    }
    
    # Apply organization decision logic
    environment = "production"
    env_threshold = organization_config["environment_thresholds"][environment]
    
    decision_logic = {
        "risk_vs_threshold": {
            "risk_score": processing_results["composite_risk_score"],
            "threshold": env_threshold["risk_threshold"],
            "exceeds_threshold": processing_results["composite_risk_score"] > env_threshold["risk_threshold"]
        },
        "ssvc_vs_policy": {
            "ssvc_decision": processing_results["ssvc_decision"],
            "required_threshold": env_threshold["ssvc_threshold"], 
            "meets_policy": processing_results["ssvc_decision"] == "Act"
        },
        "compliance_factors": {
            "pci_dss_impact": "Payment data at risk from SQL injection",
            "soc2_impact": "Security controls compromised by critical vulnerabilities",
            "requires_immediate_action": True
        }
    }
    
    # Final organization decision
    final_decision = "BLOCK"  # Risk exceeds threshold + SSVC says Act + Compliance requirements
    
    return {
        "stage": "Decision Layer - Organization Thresholds",
        "organization_context": organization_config,
        "decision_inputs": processing_results,
        "decision_logic": decision_logic,
        "final_decision": {
            "recommendation": final_decision,
            "reasoning": f"Risk score {processing_results['composite_risk_score']:.2f} exceeds production threshold {env_threshold['risk_threshold']}, SSVC recommends 'Act', and compliance requirements (PCI-DSS) mandate immediate remediation of SQL injection vulnerabilities",
            "confidence": processing_results["confidence"],
            "ssvc_alignment": "Decision aligns with SSVC 'Act' recommendation"
        },
        "data_transformation": "Processing results + Organization policy → Binary deployment decision"
    }

async def _demo_output_layer(sample_data: Dict[str, Any]) -> Dict[str, Any]:
    """Stage 4: Output Layer - Generate human explanations and evidence"""
    
    # Generate LLM explanation using Awesome-LLM4Cybersecurity approach
    human_explanation = {
        "executive_summary": "Deployment BLOCKED due to critical SQL injection vulnerability (CVE-2024-12345) in payment processing system. Immediate security remediation required before production deployment.",
        
        "technical_analysis": """
Critical SQL injection vulnerability detected in mysql2@2.3.0 component:
- CVE-2024-12345 (CVSS 9.8) allows complete database compromise
- Vulnerability is actively exploited (KEV flagged, EPSS 0.95)
- Affects payment API authentication system (/app/src/models/User.js:128)
- No compensating controls detected
        """,
        
        "business_impact": """
High business risk identified:
- Payment processing system vulnerable to data breach
- PCI-DSS compliance violation (SQL injection in payment flow)
- Potential financial and reputational damage
- Customer payment data at risk of exfiltration
        """,
        
        "recommended_actions": [
            "Immediately upgrade mysql2 to version 2.3.3 (contains security fix)",
            "Deploy parameterized queries in User.js authentication logic", 
            "Run penetration testing on payment flows before next deployment",
            "Implement input validation and sanitization controls",
            "Review all database interactions for similar vulnerabilities"
        ],
        
        "risk_assessment": "CRITICAL - Block deployment until SQL injection is remediated"
    }
    
    # Generate evidence trail
    evidence_trail = {
        "evidence_id": f"EVD-{int(datetime.now(timezone.utc).timestamp())}",
        "decision_timestamp": datetime.now(timezone.utc).isoformat(),
        "scan_sources": [
            {"tool": "Semgrep", "version": "1.45.0", "findings": 2},
            {"tool": "npm-audit", "version": "10.2.0", "components": 3},
            {"tool": "threat-intel", "source": "CISA KEV + EPSS", "enrichment": "CVE risk scores"}
        ],
        "processing_components": [
            "python-ssvc v1.2.3", "mchmm v0.4.5", "pgmpy v0.1.25", 
            "pomegranate v1.1.2", "CTINexus approach", "Awesome-LLM4Cybersecurity"
        ],
        "organization_context": {
            "stakeholder_type": "deployer",
            "environment": "production", 
            "compliance": ["PCI-DSS", "SOC2"],
            "risk_tolerance": "low"
        },
        "audit_trail": {
            "input_hash": "sha256:a1b2c3d4...",
            "processing_version": "FixOps v1.0.0",
            "decision_reproducible": True,
            "evidence_retention": "7 years (compliance requirement)"
        }
    }
    
    return {
        "stage": "Output Layer - Human Explanations & Evidence",
        "tools_used": ["Awesome-LLM4Cybersecurity models", "Evidence generation system"],
        "output_formats": {
            "1_human_explanation": {
                "audience": "Security team + Management",
                "format": "Structured explanation with business context",
                "content": human_explanation
            },
            "2_evidence_trail": {
                "purpose": "Audit compliance and decision reproducibility", 
                "format": "Machine-readable audit log",
                "content": evidence_trail
            },
            "3_api_response": {
                "format": "JSON for CI/CD integration",
                "fields": ["decision", "confidence", "risk_score", "explanation", "evidence_id"]
            }
        },
        "data_transformation": "Technical analysis → Human-readable explanations + Audit evidence"
    }

async def _demo_cicd_integration() -> Dict[str, Any]:
    """Stage 5: CI/CD Integration - Show pipeline integration"""
    
    return {
        "stage": "CI/CD Integration - Automated Gating",
        "integration_methods": {
            "1_github_actions": {
                "workflow_step": '''
- name: FixOps Security Gate
  id: fixops_gate
  run: |
    # Submit scan data to FixOps
    SUBMISSION_ID=$(curl -X POST $FIXOPS_URL/workflow/submit-scan \\
      -H "Content-Type: application/json" \\
      -d "{
        \"service_name\": \"$GITHUB_REPOSITORY\",
        \"environment\": \"production\",
        \"submitter\": \"$GITHUB_ACTOR\",
        \"scan_data\": {
          \"sarif\": \"$(cat semgrep-results.sarif)\",
          \"sbom\": \"$(cat package-sbom.json)\"
        }
      }" | jq -r '.submission_details.submission_id')
    
    # Run FixOps analysis
    DECISION_ID=$(curl -X POST $FIXOPS_URL/workflow/analyze/$SUBMISSION_ID | jq -r '.decision_results.decision_id')
    
    # Get deployment decision
    DECISION=$(curl -X GET $FIXOPS_URL/workflow/cicd-decision/$DECISION_ID | jq -r '.cicd_decision.action')
    
    echo "FixOps Decision: $DECISION"
    echo "decision_id=$DECISION_ID" >> $GITHUB_OUTPUT
    
    # Gate deployment based on decision
    case $DECISION in
      "ALLOW")  
        echo "✅ Deployment approved by FixOps security analysis"
        ;;
      "DEFER")  
        echo "⏸️ Manual security review required"
        gh issue create --title "Security Review Required" --body "FixOps flagged security concerns. Decision ID: $DECISION_ID"
        exit 1
        ;;
      "BLOCK")  
        echo "🚫 Deployment blocked by FixOps - critical security issues detected"
        exit 1
        ;;
    esac
''',
                "result": "Automated deployment gating in GitHub Actions workflow"
            },
            
            "2_jenkins_pipeline": {
                "pipeline_stage": '''
stage('FixOps Security Gate') {
    steps {
        script {
            // Submit scan results
            def scanData = readJSON file: 'security-scan-results.json'
            def submitResponse = httpRequest(
                httpMode: 'POST',
                url: "${FIXOPS_URL}/workflow/submit-scan",
                contentType: 'APPLICATION_JSON',
                requestBody: groovy.json.JsonBuilder(scanData).toString()
            )
            def submissionId = readJSON(text: submitResponse.content).submission_details.submission_id
            
            // Get FixOps decision
            def analysisResponse = httpRequest(
                httpMode: 'POST', 
                url: "${FIXOPS_URL}/workflow/analyze/${submissionId}"
            )
            def decisionId = readJSON(text: analysisResponse.content).decision_results.decision_id
            
            def decisionResponse = httpRequest(
                url: "${FIXOPS_URL}/workflow/cicd-decision/${decisionId}"
            )
            def decision = readJSON(text: decisionResponse.content).cicd_decision.action
            
            // Apply decision
            switch(decision) {
                case 'ALLOW':
                    echo "✅ Deployment approved by FixOps"
                    break
                case 'DEFER':
                    echo "⏸️ Manual review required"
                    input message: "FixOps requires manual security review. Proceed?", ok: "Deploy"
                    break
                case 'BLOCK':
                    error("🚫 Deployment blocked by FixOps security analysis")
                    break
            }
        }
    }
}
''',
                "result": "Deployment gating with manual review option in Jenkins"
            }
        },
        
        "decision_outcomes": {
            "ALLOW": {
                "action": "✅ Proceed with deployment",
                "conditions": "Low risk score, no critical vulnerabilities, SSVC recommends Track/Attend",
                "pipeline_behavior": "Continue to production deployment"
            },
            "DEFER": {
                "action": "⏸️ Require manual approval", 
                "conditions": "Medium risk score, manageable vulnerabilities, SSVC recommends Attend",
                "pipeline_behavior": "Pause deployment, notify security team, require manual approval"
            },
            "BLOCK": {
                "action": "🚫 Halt deployment",
                "conditions": "High risk score, critical vulnerabilities, SSVC recommends Act",
                "pipeline_behavior": "Stop pipeline, prevent deployment, create incident ticket"
            }
        },
        
        "sample_decision_response": {
            "cicd_decision": {
                "action": "BLOCK",
                "confidence": 0.91,
                "risk_score": 0.75,
                "explanation": "Critical SQL injection vulnerability (CVE-2024-12345) detected in production payment system. Immediate remediation required."
            },
            "deployment_instructions": {
                "proceed_deployment": False,
                "require_manual_review": False,
                "block_deployment": True,
                "evidence_url": "/api/v1/evidence/EVD-1759352158"
            }
        }
    }

logger = structlog.get_logger()