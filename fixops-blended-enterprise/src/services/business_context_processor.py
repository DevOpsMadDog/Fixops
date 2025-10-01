"""
FixOps Business Context Schema
Supports SSVC design-time business context and OTM integration
"""

import yaml
import json
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from datetime import datetime
import structlog

logger = structlog.get_logger()

@dataclass
class SSVCBusinessContext:
    """SSVC-compliant business context for FixOps decisions"""
    service_name: str
    environment: str
    
    # SSVC Core Factors
    exploitation: str  # "none", "poc", "active"
    exposure: str      # "small", "controlled", "open"
    utility: str       # "laborious", "efficient", "super_effective"
    safety_impact: str # "negligible", "marginal", "major", "hazardous"
    mission_impact: str # "degraded", "crippled", "mev"
    
    # Business Context Enrichment
    business_criticality: str  # "low", "medium", "high", "critical"
    data_classification: List[str]  # ["public", "internal", "confidential", "pci", "pii", "phi"]
    internet_facing: bool
    compliance_requirements: List[str]  # ["sox", "pci_dss", "hipaa", "gdpr", "nist"]
    
    # Operational Context
    owner_team: str
    owner_email: str
    escalation_contacts: List[str]
    sla_requirements: Dict[str, Any]
    
    # Threat Model Integration
    threat_model_url: Optional[str] = None
    attack_surface: Optional[Dict[str, Any]] = None
    trust_boundaries: Optional[List[str]] = None
    
    # Metadata
    created_at: str = ""
    updated_at: str = ""
    version: str = "1.0"

@dataclass
class OTMContext:
    """Open Threat Model (OTM) integration context"""
    otm_version: str
    project: Dict[str, Any]
    representations: List[Dict[str, Any]]
    trust_zones: List[Dict[str, Any]]
    components: List[Dict[str, Any]]
    data_flows: List[Dict[str, Any]]
    threats: List[Dict[str, Any]]
    mitigations: List[Dict[str, Any]]

class FixOpsContextProcessor:
    """Process and convert business context formats for FixOps Decision Engine"""
    
    def __init__(self):
        self.supported_formats = ["fixops.yaml", "otm.json", "ssvc.yaml"]
    
    def process_fixops_yaml(self, yaml_content: str) -> SSVCBusinessContext:
        """Process fixops.yaml format business context"""
        try:
            data = yaml.safe_load(yaml_content)
            
            # Validate required SSVC fields
            required_ssvc = ["exploitation", "exposure", "utility", "safety_impact", "mission_impact"]
            for field in required_ssvc:
                if field not in data:
                    raise ValueError(f"Missing required SSVC field: {field}")
            
            # Create SSVC business context
            context = SSVCBusinessContext(
                service_name=data.get("service_name", "unknown"),
                environment=data.get("environment", "production"),
                exploitation=data["exploitation"],
                exposure=data["exposure"],
                utility=data["utility"],
                safety_impact=data["safety_impact"],
                mission_impact=data["mission_impact"],
                business_criticality=data.get("business_criticality", "medium"),
                data_classification=data.get("data_classification", ["internal"]),
                internet_facing=data.get("internet_facing", False),
                compliance_requirements=data.get("compliance_requirements", []),
                owner_team=data.get("owner_team", "unknown"),
                owner_email=data.get("owner_email", "unknown@example.com"),
                escalation_contacts=data.get("escalation_contacts", []),
                sla_requirements=data.get("sla_requirements", {}),
                threat_model_url=data.get("threat_model_url"),
                attack_surface=data.get("attack_surface"),
                trust_boundaries=data.get("trust_boundaries"),
                created_at=data.get("created_at", datetime.now().isoformat()),
                updated_at=datetime.now().isoformat(),
                version=data.get("version", "1.0")
            )
            
            logger.info("✅ FixOps YAML context processed successfully", service=context.service_name)
            return context
            
        except Exception as e:
            logger.error(f"FixOps YAML processing failed: {e}")
            raise
    
    def process_otm_json(self, json_content: str) -> SSVCBusinessContext:
        """Convert OTM (Open Threat Model) format to FixOps SSVC context"""
        try:
            otm_data = json.loads(json_content)
            
            # Extract OTM components
            otm_context = OTMContext(
                otm_version=otm_data.get("otmVersion", "0.1.0"),
                project=otm_data.get("project", {}),
                representations=otm_data.get("representations", []),
                trust_zones=otm_data.get("trustZones", []),
                components=otm_data.get("components", []),
                data_flows=otm_data.get("dataFlows", []),
                threats=otm_data.get("threats", []),
                mitigations=otm_data.get("mitigations", [])
            )
            
            # Convert OTM to SSVC context
            ssvc_context = self._convert_otm_to_ssvc(otm_context)
            
            logger.info("✅ OTM to SSVC conversion completed", service=ssvc_context.service_name)
            return ssvc_context
            
        except Exception as e:
            logger.error(f"OTM processing failed: {e}")
            raise
    
    def _convert_otm_to_ssvc(self, otm: OTMContext) -> SSVCBusinessContext:
        """Convert OTM threat model to SSVC business context"""
        
        project = otm.project
        threats = otm.threats
        components = otm.components
        
        # Analyze threats to determine SSVC factors
        exploitation = self._analyze_exploitation(threats)
        exposure = self._analyze_exposure(components, otm.trust_zones)
        utility = self._analyze_utility(threats, otm.mitigations)
        safety_impact = self._analyze_safety_impact(threats, project)
        mission_impact = self._analyze_mission_impact(threats, project)
        
        # Extract business context from OTM project info
        business_criticality = self._determine_criticality(threats, components)
        data_classification = self._extract_data_classification(components, otm.data_flows)
        internet_facing = self._check_internet_exposure(components, otm.trust_zones)
        
        return SSVCBusinessContext(
            service_name=project.get("name", "otm-service"),
            environment="production",  # Default for OTM
            exploitation=exploitation,
            exposure=exposure,
            utility=utility,
            safety_impact=safety_impact,
            mission_impact=mission_impact,
            business_criticality=business_criticality,
            data_classification=data_classification,
            internet_facing=internet_facing,
            compliance_requirements=self._extract_compliance(project),
            owner_team=project.get("owner", "unknown"),
            owner_email=project.get("ownerContact", "unknown@example.com"),
            escalation_contacts=project.get("escalationContacts", []),
            sla_requirements=project.get("slaRequirements", {}),
            threat_model_url=project.get("repository", ""),
            attack_surface=self._generate_attack_surface(components, otm.data_flows),
            trust_boundaries=[tz.get("name", "") for tz in otm.trust_zones],
            created_at=datetime.now().isoformat(),
            updated_at=datetime.now().isoformat(),
            version="1.0"
        )
    
    def _analyze_exploitation(self, threats: List[Dict]) -> str:
        """Analyze OTM threats to determine exploitation level"""
        if not threats:
            return "none"
        
        # Check for active exploitation indicators
        active_threats = [t for t in threats if t.get("status", "").lower() in ["active", "exploited"]]
        if active_threats:
            return "active"
        
        # Check for PoC threats
        poc_threats = [t for t in threats if "poc" in t.get("description", "").lower()]
        if poc_threats:
            return "poc"
        
        return "none"
    
    def _analyze_exposure(self, components: List[Dict], trust_zones: List[Dict]) -> str:
        """Analyze exposure level from OTM components and trust zones"""
        # Check for internet-facing components
        internet_zones = [tz for tz in trust_zones if "internet" in tz.get("name", "").lower()]
        if internet_zones:
            return "open"
        
        # Check for controlled exposure
        external_zones = [tz for tz in trust_zones if "external" in tz.get("name", "").lower()]
        if external_zones:
            return "controlled"
        
        return "small"
    
    def _analyze_utility(self, threats: List[Dict], mitigations: List[Dict]) -> str:
        """Analyze utility/automatable from threats and mitigations"""
        if not threats:
            return "laborious"
        
        # Check for high-impact, easy-to-automate threats
        automated_threats = [t for t in threats if "automated" in t.get("description", "").lower()]
        if len(automated_threats) > len(threats) * 0.5:
            return "super_effective"
        
        # Check for medium automation potential
        if mitigations and len(mitigations) > 0:
            return "efficient"
        
        return "laborious"
    
    def _analyze_safety_impact(self, threats: List[Dict], project: Dict) -> str:
        """Determine safety impact from OTM threat analysis"""
        # Check project type for safety implications
        project_type = project.get("type", "").lower()
        if any(keyword in project_type for keyword in ["medical", "automotive", "industrial", "critical"]):
            return "hazardous"
        
        # Analyze threat severity
        critical_threats = [t for t in threats if t.get("severity", "").upper() == "CRITICAL"]
        if critical_threats:
            return "major"
        
        high_threats = [t for t in threats if t.get("severity", "").upper() == "HIGH"]
        if high_threats:
            return "marginal"
        
        return "negligible"
    
    def _analyze_mission_impact(self, threats: List[Dict], project: Dict) -> str:
        """Determine mission impact from OTM analysis"""
        business_impact = project.get("businessImpact", "").lower()
        
        if "critical" in business_impact or "essential" in business_impact:
            return "mev"  # Mission Essential Vital
        
        # Check threat count and severity
        critical_threats = [t for t in threats if t.get("severity", "").upper() == "CRITICAL"]
        if len(critical_threats) > 3:
            return "crippled"
        
        if len(threats) > 5:
            return "degraded"
        
        return "degraded"
    
    def _determine_criticality(self, threats: List[Dict], components: List[Dict]) -> str:
        """Determine business criticality from OTM analysis"""
        critical_components = [c for c in components if "critical" in c.get("name", "").lower()]
        critical_threats = [t for t in threats if t.get("severity", "").upper() == "CRITICAL"]
        
        if critical_components or len(critical_threats) > 2:
            return "critical"
        elif len(threats) > 5:
            return "high"
        elif len(threats) > 0:
            return "medium"
        else:
            return "low"
    
    def _extract_data_classification(self, components: List[Dict], data_flows: List[Dict]) -> List[str]:
        """Extract data classification from OTM components and data flows"""
        classifications = set()
        
        # Check component data types
        for component in components:
            tags = component.get("tags", [])
            for tag in tags:
                if tag.lower() in ["pii", "pci", "phi", "confidential", "internal", "public"]:
                    classifications.add(tag.lower())
        
        # Check data flow classifications
        for flow in data_flows:
            data_type = flow.get("dataType", "").lower()
            if data_type in ["pii", "financial", "medical", "confidential"]:
                if data_type == "financial":
                    classifications.add("pci")
                elif data_type == "medical":
                    classifications.add("phi")
                else:
                    classifications.add(data_type)
        
        return list(classifications) if classifications else ["internal"]
    
    def _check_internet_exposure(self, components: List[Dict], trust_zones: List[Dict]) -> bool:
        """Check if system has internet exposure"""
        # Check trust zones for internet exposure
        for zone in trust_zones:
            if "internet" in zone.get("name", "").lower() or "public" in zone.get("name", "").lower():
                return True
        
        # Check components for web/api exposure
        for component in components:
            comp_type = component.get("type", "").lower()
            if comp_type in ["web-application", "api", "load-balancer", "cdn"]:
                return True
        
        return False
    
    def _extract_compliance(self, project: Dict) -> List[str]:
        """Extract compliance requirements from OTM project"""
        compliance = []
        
        project_tags = project.get("tags", [])
        for tag in project_tags:
            tag_lower = tag.lower()
            if "pci" in tag_lower:
                compliance.append("pci_dss")
            elif "sox" in tag_lower:
                compliance.append("sox")
            elif "hipaa" in tag_lower:
                compliance.append("hipaa")
            elif "gdpr" in tag_lower:
                compliance.append("gdpr")
            elif "nist" in tag_lower:
                compliance.append("nist")
        
        return compliance
    
    def _generate_attack_surface(self, components: List[Dict], data_flows: List[Dict]) -> Dict[str, Any]:
        """Generate attack surface analysis from OTM data"""
        return {
            "total_components": len(components),
            "external_components": len([c for c in components if c.get("type", "").lower() in ["web-application", "api", "database"]]),
            "data_flows": len(data_flows),
            "attack_vectors": self._identify_attack_vectors(components, data_flows)
        }
    
    def _identify_attack_vectors(self, components: List[Dict], data_flows: List[Dict]) -> List[str]:
        """Identify potential attack vectors from OTM"""
        vectors = []
        
        # Check components for common attack vectors
        for component in components:
            comp_type = component.get("type", "").lower()
            if "web" in comp_type:
                vectors.extend(["injection", "xss", "authentication"])
            elif "api" in comp_type:
                vectors.extend(["injection", "broken_authorization", "security_misconfiguration"])
            elif "database" in comp_type:
                vectors.extend(["injection", "insecure_data_storage"])
        
        return list(set(vectors))
    
    def generate_sample_fixops_yaml(self, service_name: str = "payment-service") -> str:
        """Generate sample fixops.yaml for business context"""
        sample_context = SSVCBusinessContext(
            service_name=service_name,
            environment="production",
            exploitation="poc",
            exposure="controlled", 
            utility="efficient",
            safety_impact="marginal",
            mission_impact="degraded",
            business_criticality="high",
            data_classification=["pci", "pii"],
            internet_facing=True,
            compliance_requirements=["pci_dss", "sox"],
            owner_team="payments-team",
            owner_email="payments-team@company.com",
            escalation_contacts=["security-team@company.com", "ciso@company.com"],
            sla_requirements={
                "availability": "99.9%",
                "response_time": "< 200ms",
                "recovery_time": "< 4h"
            },
            threat_model_url="https://confluence.company.com/threat-models/payment-service",
            attack_surface={
                "web_endpoints": 12,
                "api_endpoints": 45,
                "database_connections": 3,
                "external_integrations": 8
            },
            trust_boundaries=["DMZ", "Internal Network", "Database Tier"],
            created_at=datetime.now().isoformat(),
            updated_at=datetime.now().isoformat(),
            version="1.0"
        )
        
        return yaml.dump(asdict(sample_context), default_flow_style=False, sort_keys=False)
    
    def generate_sample_otm_json(self, service_name: str = "payment-service") -> str:
        """Generate sample OTM JSON for threat modeling"""
        sample_otm = {
            "otmVersion": "0.1.0",
            "project": {
                "name": service_name,
                "id": f"{service_name}-threat-model",
                "description": f"Threat model for {service_name}",
                "owner": "Security Team",
                "ownerContact": "security@company.com",
                "tags": ["financial", "pci", "high-risk"]
            },
            "representations": [
                {
                    "name": "Architecture Diagram",
                    "id": "architecture",
                    "type": "diagram"
                }
            ],
            "trustZones": [
                {
                    "id": "internet",
                    "name": "Internet",
                    "risk": {"trustRating": 0}
                },
                {
                    "id": "dmz", 
                    "name": "DMZ",
                    "risk": {"trustRating": 30}
                },
                {
                    "id": "internal",
                    "name": "Internal Network", 
                    "risk": {"trustRating": 80}
                }
            ],
            "components": [
                {
                    "id": "web-app",
                    "name": "Payment Web Application",
                    "type": "web-application",
                    "parent": {"trustZone": "dmz"},
                    "tags": ["pci", "customer-facing"]
                },
                {
                    "id": "api-gateway",
                    "name": "API Gateway",
                    "type": "api-gateway", 
                    "parent": {"trustZone": "dmz"},
                    "tags": ["authentication", "rate-limiting"]
                },
                {
                    "id": "payment-db",
                    "name": "Payment Database",
                    "type": "database",
                    "parent": {"trustZone": "internal"},
                    "tags": ["pci", "encrypted", "sensitive-data"]
                }
            ],
            "dataFlows": [
                {
                    "id": "user-payment",
                    "name": "User Payment Flow",
                    "source": "web-app",
                    "destination": "payment-db",
                    "dataType": "financial",
                    "tags": ["pci", "encrypted"]
                }
            ],
            "threats": [
                {
                    "id": "injection-001",
                    "name": "SQL Injection",
                    "categories": ["injection"],
                    "severity": "HIGH",
                    "description": "SQL injection vulnerability in payment processing",
                    "mitigation": "Use parameterized queries"
                },
                {
                    "id": "auth-001", 
                    "name": "Authentication Bypass",
                    "categories": ["authentication"],
                    "severity": "CRITICAL",
                    "description": "Potential authentication bypass in API gateway",
                    "mitigation": "Implement MFA and token validation"
                }
            ],
            "mitigations": [
                {
                    "id": "mit-001",
                    "name": "Input Validation",
                    "description": "Comprehensive input validation and sanitization",
                    "riskReduction": 70
                },
                {
                    "id": "mit-002",
                    "name": "Authentication Controls",
                    "description": "Multi-factor authentication and session management", 
                    "riskReduction": 85
                }
            ]
        }
        
        return json.dumps(sample_otm, indent=2)

# Global context processor instance
context_processor = FixOpsContextProcessor()