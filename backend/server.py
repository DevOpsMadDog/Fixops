from fastapi import FastAPI, APIRouter, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any, Literal
from datetime import datetime, timedelta
from enum import Enum
import uuid
import json
import asyncio
from contextlib import asynccontextmanager

# Load environment variables
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ.get('MONGO_URL', 'mongodb://localhost:27017')
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ.get('DB_NAME', 'fixops_db')]

# Data Models for FixOps Security Knowledge Graph

class DataClassification(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    PII = "pii"
    PCI = "pci"
    PHI = "phi"

class Environment(str, Enum):
    DEV = "dev"
    STAGING = "staging"
    PRODUCTION = "production"

class ScannerType(str, Enum):
    SAST = "sast"
    SCA = "sca"
    DAST = "dast"
    IAST = "iast"
    RASP = "rasp"
    IAC = "iac"
    CONTAINER = "container"
    VM = "vm"
    CNAPP = "cnapp"

class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class PolicyDecision(str, Enum):
    BLOCK = "block"
    ALLOW = "allow"
    DEFER = "defer"
    FIX = "fix"
    MITIGATE = "mitigate"

class FindingStatus(str, Enum):
    OPEN = "open"
    IN_PROGRESS = "in_progress"
    FIXED = "fixed"
    WAIVED = "waived"
    FALSE_POSITIVE = "false_positive"

# Core Data Models

class Service(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    business_capability: str
    data_classification: List[DataClassification]
    environment: Environment
    owner_team: str
    owner_email: str
    repository_url: Optional[str] = None
    internet_facing: bool = False
    pci_scope: bool = False
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class ServiceCreate(BaseModel):
    name: str
    business_capability: str
    data_classification: List[DataClassification]
    environment: Environment
    owner_team: str
    owner_email: str
    repository_url: Optional[str] = None
    internet_facing: bool = False
    pci_scope: bool = False

class SecurityFinding(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    service_id: str
    scanner_type: ScannerType
    scanner_name: str
    rule_id: str
    title: str
    description: str
    severity: SeverityLevel
    confidence: Optional[str] = None
    category: str
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    epss_score: Optional[float] = None
    location: Optional[Dict[str, Any]] = None  # File, line, etc.
    evidence: Optional[Dict[str, Any]] = None
    remediation: Optional[str] = None
    status: FindingStatus = FindingStatus.OPEN
    business_impact: Optional[str] = None
    exploitability_grade: Optional[str] = None  # E0-E4
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class FindingCreate(BaseModel):
    service_id: str
    scanner_type: ScannerType
    scanner_name: str
    rule_id: str
    title: str
    description: str
    severity: SeverityLevel
    confidence: Optional[str] = None
    category: str
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    epss_score: Optional[float] = None
    location: Optional[Dict[str, Any]] = None
    evidence: Optional[Dict[str, Any]] = None
    remediation: Optional[str] = None

class CorrelatedCase(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    service_id: str
    root_cause: str
    title: str
    description: str
    findings: List[str]  # Finding IDs
    overall_severity: SeverityLevel
    business_impact: str
    remediation_priority: int
    estimated_effort: Optional[str] = None
    policy_decision: Optional[PolicyDecision] = None
    decision_rationale: Optional[str] = None
    nist_ssdf_controls: List[str] = []
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class PolicyRule(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    description: str
    rego_policy: str
    nist_ssdf_controls: List[str]
    environments: List[Environment]
    data_classifications: List[DataClassification]
    active: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)

class FixSuggestion(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    case_id: str
    fix_type: Literal["code_patch", "iac_patch", "waf_rule", "admission_controller"]
    title: str
    description: str
    code_changes: Optional[Dict[str, str]] = None  # file -> patch
    estimated_effort: str
    confidence: float
    created_at: datetime = Field(default_factory=datetime.utcnow)

class ComplianceEvidence(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    service_id: str
    nist_ssdf_control: str
    evidence_type: str
    artifact_hash: Optional[str] = None
    attestation: Dict[str, Any]
    created_at: datetime = Field(default_factory=datetime.utcnow)

# Dashboard Models
class DashboardMetrics(BaseModel):
    total_services: int
    total_findings: int
    critical_findings: int
    high_findings: int
    findings_by_scanner: Dict[str, int]
    services_by_environment: Dict[str, int]
    mttr_days: float
    noise_reduction_percentage: float
    policy_decisions: Dict[str, int]

class FindingTrend(BaseModel):
    date: str
    total: int
    critical: int
    high: int
    medium: int
    low: int

# Initialize FastAPI
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await initialize_demo_data()
    yield
    # Shutdown
    client.close()

app = FastAPI(title="FixOps - Agentic DevSecOps Control Plane", version="1.0.0", lifespan=lifespan)
api_router = APIRouter(prefix="/api")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Demo Data Initialization for Fintech
async def initialize_demo_data():
    """Initialize demo data with fintech services and security findings"""
    
    # Check if data already exists
    existing_services = await db.services.count_documents({})
    if existing_services > 0:
        return
    
    # Demo Services for Fintech
    fintech_services = [
        {
            "name": "payment-gateway",
            "business_capability": "Payment Processing",
            "data_classification": [DataClassification.PCI, DataClassification.PII],
            "environment": Environment.PRODUCTION,
            "owner_team": "payments-team",
            "owner_email": "payments@fintech.com",
            "repository_url": "https://github.com/fintech/payment-gateway",
            "internet_facing": True,
            "pci_scope": True
        },
        {
            "name": "user-identity-service",
            "business_capability": "Identity & Authentication",
            "data_classification": [DataClassification.PII, DataClassification.PHI],
            "environment": Environment.PRODUCTION,
            "owner_team": "identity-team",
            "owner_email": "identity@fintech.com",
            "repository_url": "https://github.com/fintech/identity-service",
            "internet_facing": True,
            "pci_scope": False
        },
        {
            "name": "fraud-detection-ml",
            "business_capability": "Risk & Fraud Detection",
            "data_classification": [DataClassification.CONFIDENTIAL, DataClassification.PII],
            "environment": Environment.PRODUCTION,
            "owner_team": "ml-team",
            "owner_email": "ml@fintech.com",
            "repository_url": "https://github.com/fintech/fraud-detection",
            "internet_facing": False,
            "pci_scope": True
        },
        {
            "name": "customer-onboarding",
            "business_capability": "Customer Onboarding",
            "data_classification": [DataClassification.PII, DataClassification.PHI],
            "environment": Environment.STAGING,
            "owner_team": "onboarding-team",
            "owner_email": "onboarding@fintech.com",
            "repository_url": "https://github.com/fintech/onboarding",
            "internet_facing": True,
            "pci_scope": False
        },
        {
            "name": "transaction-processor",
            "business_capability": "Transaction Processing",
            "data_classification": [DataClassification.PCI, DataClassification.CONFIDENTIAL],
            "environment": Environment.PRODUCTION,
            "owner_team": "core-banking",
            "owner_email": "banking@fintech.com",
            "repository_url": "https://github.com/fintech/transaction-processor",
            "internet_facing": False,
            "pci_scope": True
        }
    ]
    
    # Insert services
    for service_data in fintech_services:
        service = Service(**service_data)
        await db.services.insert_one(service.dict())
    
    # Get inserted services
    services = await db.services.find().to_list(100)
    
    # Demo Findings with realistic fintech security issues
    demo_findings = []
    
    # Payment Gateway findings
    payment_service = next(s for s in services if s['name'] == 'payment-gateway')
    demo_findings.extend([
        {
            "service_id": payment_service['id'],
            "scanner_type": ScannerType.SAST,
            "scanner_name": "SonarQube",
            "rule_id": "java:S2083",
            "title": "SQL Injection in payment validation",
            "description": "Unsanitized user input passed to SQL query in payment validation logic",
            "severity": SeverityLevel.CRITICAL,
            "confidence": "HIGH",
            "category": "Input Validation",
            "cwe_id": "CWE-89",
            "cvss_score": 9.1,
            "epss_score": 0.75,
            "location": {"file": "PaymentValidator.java", "line": 145},
            "business_impact": "Critical - PCI data exposure risk in production payment processing",
            "exploitability_grade": "E3"
        },
        {
            "service_id": payment_service['id'],
            "scanner_type": ScannerType.SCA,
            "scanner_name": "Snyk",
            "rule_id": "SNYK-JAVA-ORGAPACHESTRUTS-30963",
            "title": "Apache Struts RCE vulnerability",
            "description": "Remote Code Execution in Apache Struts 2.5.14",
            "severity": SeverityLevel.CRITICAL,
            "confidence": "HIGH",
            "category": "Known Vulnerabilities",
            "cve_id": "CVE-2017-5638",
            "cvss_score": 9.8,
            "epss_score": 0.97,
            "business_impact": "Critical - RCE in internet-facing PCI service",
            "exploitability_grade": "E4"
        },
        {
            "service_id": payment_service['id'],
            "scanner_type": ScannerType.DAST,
            "scanner_name": "OWASP ZAP",
            "rule_id": "40012",
            "title": "Cross-Site Scripting (XSS)",
            "description": "Reflected XSS vulnerability in payment confirmation page",
            "severity": SeverityLevel.HIGH,
            "confidence": "MEDIUM",
            "category": "Cross-Site Scripting",
            "cwe_id": "CWE-79",
            "cvss_score": 6.1,
            "epss_score": 0.45,
            "location": {"url": "/payment/confirm", "parameter": "amount"},
            "business_impact": "High - Session hijacking risk for payment users",
            "exploitability_grade": "E2"
        }
    ])
    
    # Identity Service findings
    identity_service = next(s for s in services if s['name'] == 'user-identity-service')
    demo_findings.extend([
        {
            "service_id": identity_service['id'],
            "scanner_type": ScannerType.SAST,
            "scanner_name": "Checkmarx",
            "rule_id": "Cx.Py.Injection.SQL_Injection",
            "title": "SQL Injection in user authentication",
            "description": "SQL injection vulnerability in login endpoint",
            "severity": SeverityLevel.CRITICAL,
            "confidence": "HIGH",
            "category": "Injection",
            "cwe_id": "CWE-89",
            "cvss_score": 8.8,
            "epss_score": 0.71,
            "location": {"file": "auth.py", "line": 67},
            "business_impact": "Critical - Authentication bypass, PII exposure",
            "exploitability_grade": "E3"
        },
        {
            "service_id": identity_service['id'],
            "scanner_type": ScannerType.IAST,
            "scanner_name": "Contrast Security",
            "rule_id": "insecure-crypto",
            "title": "Weak cryptographic algorithm",
            "description": "MD5 used for password hashing instead of bcrypt",
            "severity": SeverityLevel.HIGH,
            "confidence": "HIGH",
            "category": "Cryptography",
            "cwe_id": "CWE-327",
            "cvss_score": 7.4,
            "epss_score": 0.12,
            "business_impact": "High - Weak password protection for PII service",
            "exploitability_grade": "E1"
        }
    ])
    
    # Fraud Detection ML findings
    fraud_service = next(s for s in services if s['name'] == 'fraud-detection-ml')
    demo_findings.extend([
        {
            "service_id": fraud_service['id'],
            "scanner_type": ScannerType.SCA,
            "scanner_name": "GitHub Security",
            "rule_id": "GHSA-7rjr-3q55-vv33",
            "title": "TensorFlow vulnerability in ML pipeline",
            "description": "Code injection vulnerability in TensorFlow 2.4.0",
            "severity": SeverityLevel.HIGH,
            "confidence": "HIGH",
            "category": "Known Vulnerabilities",
            "cve_id": "CVE-2021-29512",
            "cvss_score": 7.8,
            "epss_score": 0.23,
            "business_impact": "High - ML model manipulation risk",
            "exploitability_grade": "E2"
        },
        {
            "service_id": fraud_service['id'],
            "scanner_type": ScannerType.IAC,
            "scanner_name": "Checkov",
            "rule_id": "CKV_AWS_20",
            "title": "S3 bucket public read access",
            "description": "S3 bucket containing fraud model data allows public read access",
            "severity": SeverityLevel.CRITICAL,
            "confidence": "HIGH",
            "category": "Data Exposure",
            "business_impact": "Critical - Confidential fraud detection data exposed",
            "exploitability_grade": "E4"
        }
    ])
    
    # Insert findings
    for finding_data in demo_findings:
        finding = SecurityFinding(**finding_data)
        await db.findings.insert_one(finding.dict())
    
    # Create demo correlated cases
    findings = await db.findings.find().to_list(100)
    
    # Correlate payment gateway findings
    payment_findings = [f for f in findings if f['service_id'] == payment_service['id']]
    payment_case = CorrelatedCase(
        service_id=payment_service['id'],
        root_cause="Input validation failures in payment processing",
        title="Critical Payment Gateway Vulnerabilities",
        description="Multiple injection vulnerabilities in payment processing service handling PCI data",
        findings=[f['id'] for f in payment_findings],
        overall_severity=SeverityLevel.CRITICAL,
        business_impact="Critical business impact - PCI compliance violation, potential data breach",
        remediation_priority=1,
        estimated_effort="3-5 days",
        policy_decision=PolicyDecision.BLOCK,
        decision_rationale="Critical vulnerabilities in PCI-scoped production service require immediate blocking",
        nist_ssdf_controls=["PO.3.1", "PS.1.1", "PW.7.2"]
    )
    await db.cases.insert_one(payment_case.dict())
    
    # Identity service case
    identity_findings = [f for f in findings if f['service_id'] == identity_service['id']]
    identity_case = CorrelatedCase(
        service_id=identity_service['id'],
        root_cause="Authentication security weaknesses",
        title="Identity Service Security Issues",
        description="Authentication bypass and weak cryptography in identity service",
        findings=[f['id'] for f in identity_findings],
        overall_severity=SeverityLevel.CRITICAL,
        business_impact="High impact - Authentication bypass affects all user accounts",
        remediation_priority=2,
        estimated_effort="2-3 days",
        policy_decision=PolicyDecision.FIX,
        decision_rationale="Critical auth issues require immediate fix before next release",
        nist_ssdf_controls=["PO.3.2", "PS.2.1"]
    )
    await db.cases.insert_one(identity_case.dict())
    
    # Demo policy rules
    policy_rules = [
        PolicyRule(
            name="PCI Critical Vulnerability Block",
            description="Block deployment of services with critical vulnerabilities handling PCI data",
            rego_policy="""
package fixops.policies

deny[msg] {
    input.severity == "critical"
    "pci" in input.data_classification
    input.environment == "production"
    not input.hasApprovedWaiver
    msg := "Critical vulnerability in PCI-scoped production service requires remediation"
}
""",
            nist_ssdf_controls=["PO.3.1", "PS.1.1"],
            environments=[Environment.PRODUCTION],
            data_classifications=[DataClassification.PCI]
        ),
        PolicyRule(
            name="Internet-Facing High Severity Gate",
            description="Require approval for high severity findings in internet-facing services",
            rego_policy="""
package fixops.policies

warn[msg] {
    input.severity in ["critical", "high"]
    input.internet_facing == true
    input.environment == "production"
    msg := "High severity finding in internet-facing production service requires security review"
}
""",
            nist_ssdf_controls=["PW.7.1", "PW.7.2"],
            environments=[Environment.PRODUCTION],
            data_classifications=[DataClassification.PII, DataClassification.PCI]
        )
    ]
    
    for policy in policy_rules:
        await db.policies.insert_one(policy.dict())
    
    print("✅ Demo data initialized successfully")

# API Endpoints

@api_router.get("/")
async def root():
    return {"message": "FixOps - Agentic DevSecOps Control Plane", "version": "1.0.0"}

# Services endpoints
@api_router.post("/services", response_model=Service)
async def create_service(service: ServiceCreate):
    service_obj = Service(**service.dict())
    await db.services.insert_one(service_obj.dict())
    return service_obj

@api_router.get("/services", response_model=List[Service])
async def get_services():
    services = await db.services.find().to_list(100)
    return [Service(**service) for service in services]

@api_router.get("/services/{service_id}", response_model=Service)
async def get_service(service_id: str):
    service = await db.services.find_one({"id": service_id})
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")
    return Service(**service)

# Findings endpoints
@api_router.post("/findings", response_model=SecurityFinding)
async def create_finding(finding: FindingCreate):
    finding_obj = SecurityFinding(**finding.dict())
    await db.findings.insert_one(finding_obj.dict())
    return finding_obj

@api_router.get("/findings", response_model=List[SecurityFinding])
async def get_findings(
    service_id: Optional[str] = None,
    severity: Optional[SeverityLevel] = None,
    status: Optional[FindingStatus] = None,
    scanner_type: Optional[ScannerType] = None
):
    query = {}
    if service_id:
        query["service_id"] = service_id
    if severity:
        query["severity"] = severity
    if status:
        query["status"] = status
    if scanner_type:
        query["scanner_type"] = scanner_type
    
    findings = await db.findings.find(query).to_list(1000)
    return [SecurityFinding(**finding) for finding in findings]

# Correlated cases endpoints
@api_router.get("/cases", response_model=List[CorrelatedCase])
async def get_cases():
    cases = await db.cases.find().to_list(100)
    return [CorrelatedCase(**case) for case in cases]

@api_router.get("/cases/{case_id}", response_model=CorrelatedCase)
async def get_case(case_id: str):
    case = await db.cases.find_one({"id": case_id})
    if not case:
        raise HTTPException(status_code=404, detail="Case not found")
    return CorrelatedCase(**case)

# Dashboard metrics
@api_router.get("/dashboard/metrics", response_model=DashboardMetrics)
async def get_dashboard_metrics():
    # Calculate various metrics
    total_services = await db.services.count_documents({})
    total_findings = await db.findings.count_documents({})
    critical_findings = await db.findings.count_documents({"severity": "critical"})
    high_findings = await db.findings.count_documents({"severity": "high"})
    
    # Findings by scanner
    scanner_pipeline = [
        {"$group": {"_id": "$scanner_type", "count": {"$sum": 1}}}
    ]
    scanner_results = await db.findings.aggregate(scanner_pipeline).to_list(10)
    findings_by_scanner = {r["_id"]: r["count"] for r in scanner_results}
    
    # Services by environment
    env_pipeline = [
        {"$group": {"_id": "$environment", "count": {"$sum": 1}}}
    ]
    env_results = await db.services.aggregate(env_pipeline).to_list(10)
    services_by_environment = {r["_id"]: r["count"] for r in env_results}
    
    # Policy decisions
    policy_pipeline = [
        {"$group": {"_id": "$policy_decision", "count": {"$sum": 1}}}
    ]
    policy_results = await db.cases.aggregate(policy_pipeline).to_list(10)
    policy_decisions = {r["_id"] or "pending": r["count"] for r in policy_results}
    
    return DashboardMetrics(
        total_services=total_services,
        total_findings=total_findings,
        critical_findings=critical_findings,
        high_findings=high_findings,
        findings_by_scanner=findings_by_scanner,
        services_by_environment=services_by_environment,
        mttr_days=4.2,  # Mock MTTR improvement from 3-4 weeks to days
        noise_reduction_percentage=67.0,  # 67% noise reduction
        policy_decisions=policy_decisions
    )

@api_router.get("/dashboard/trends", response_model=List[FindingTrend])
async def get_finding_trends():
    # Mock trend data showing improvement over time
    base_date = datetime.now() - timedelta(days=30)
    trends = []
    
    for i in range(30):
        date = base_date + timedelta(days=i)
        # Simulate decreasing findings over time (noise reduction)
        total = max(250 - i * 3, 150)
        critical = max(25 - i, 8)
        high = max(50 - i * 2, 20)
        medium = max(100 - i * 2, 70)
        low = total - critical - high - medium
        
        trends.append(FindingTrend(
            date=date.strftime("%Y-%m-%d"),
            total=total,
            critical=critical,
            high=high,
            medium=medium,
            low=low
        ))
    
    return trends

# Policy evaluation endpoint
@api_router.post("/policy/evaluate")
async def evaluate_policy(context: Dict[str, Any]):
    """Simulate OPA policy evaluation"""
    # Simple policy evaluation logic
    decisions = []
    
    severity = context.get("severity")
    data_classification = context.get("data_classification", [])
    environment = context.get("environment")
    internet_facing = context.get("internet_facing", False)
    
    if severity == "critical" and "pci" in data_classification and environment == "production":
        decisions.append({
            "decision": "block",
            "rule": "PCI Critical Vulnerability Block",
            "message": "Critical vulnerability in PCI-scoped production service requires remediation"
        })
    
    if severity in ["critical", "high"] and internet_facing and environment == "production":
        decisions.append({
            "decision": "require_approval",
            "rule": "Internet-Facing High Severity Gate", 
            "message": "High severity finding in internet-facing production service requires security review"
        })
    
    return {"decisions": decisions}

# Fix suggestions endpoint
@api_router.get("/cases/{case_id}/fixes", response_model=List[FixSuggestion])
async def get_fix_suggestions(case_id: str):
    # Mock fix suggestions
    suggestions = [
        FixSuggestion(
            case_id=case_id,
            fix_type="code_patch",
            title="Implement parameterized queries",
            description="Replace concatenated SQL with parameterized queries to prevent injection",
            code_changes={
                "PaymentValidator.java": """
- String query = "SELECT * FROM payments WHERE id = '" + paymentId + "'";
+ String query = "SELECT * FROM payments WHERE id = ?";
+ PreparedStatement stmt = connection.prepareStatement(query);
+ stmt.setString(1, paymentId);
"""
            },
            estimated_effort="2-4 hours",
            confidence=0.95
        ),
        FixSuggestion(
            case_id=case_id,
            fix_type="waf_rule",
            title="Deploy WAF protection",
            description="Temporary WAF rule to block SQL injection patterns",
            estimated_effort="30 minutes",
            confidence=0.80
        )
    ]
    return suggestions

# Include router
app.include_router(api_router)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)