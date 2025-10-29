# FixOps Enterprise Deployment Guide
# Generic deployment for any organization (financial, healthcare, government, tech)

## 🏢 **ORGANIZATION TYPES SUPPORTED:**

### **🏦 Financial Services:**
- **Frameworks**: PCI DSS, SOX, FFIEC, GDPR
- **Use Cases**: Payment processing, trading systems, financial APIs
- **Compliance**: 7-year audit retention, financial controls validation

### **🏥 Healthcare:** 
- **Frameworks**: HIPAA, HITECH, FDA, GDPR
- **Use Cases**: PHI protection, medical device software, patient data systems
- **Compliance**: PHI safeguards, medical device regulations

### **🏛️ Government:**
- **Frameworks**: NIST SSDF, FISMA, FedRAMP, NIST 800-53
- **Use Cases**: Federal systems, state/local government, defense contractors
- **Compliance**: Federal security requirements, ATO processes

### **💻 Technology:**
- **Frameworks**: SOC2, ISO 27001, OWASP, NIST CSF
- **Use Cases**: SaaS platforms, cloud services, mobile apps
- **Compliance**: Customer data protection, application security

### **🏭 Manufacturing:**
- **Frameworks**: IEC 62443, NIST CSF, ISO 27001
- **Use Cases**: Industrial control systems, IoT devices, supply chain
- **Compliance**: Operational technology security, supply chain integrity

## 🎯 **CONFIGURABLE DEPLOYMENT:**

### **1. Organization Configuration:**
```bash
# Configure for your organization type
ORGANIZATION_NAME=YourCompany
ORGANIZATION_TYPE=financial  # financial, healthcare, government, technology, manufacturing
ORGANIZATION_DOMAIN=yourcompany.internal

# Select compliance frameworks
COMPLIANCE_PCI_DSS=true     # Financial services
COMPLIANCE_HIPAA=false      # Healthcare  
COMPLIANCE_NIST_SSDF=true   # Government/All
COMPLIANCE_SOC2=true        # Technology/SaaS
COMPLIANCE_ISO27001=false   # Manufacturing/Enterprise
```

### **2. Component-Based Compliance:**
```bash
# Configure compliance per SSDLC stage
PLAN_STAGE_COMPLIANCE=sox,nist_ssdf
CODE_STAGE_COMPLIANCE=owasp,nist_ssdf  
BUILD_STAGE_COMPLIANCE=pci_dss,sox
TEST_STAGE_COMPLIANCE=owasp,nist_ssdf
RELEASE_STAGE_COMPLIANCE=sox,pci_dss
DEPLOY_STAGE_COMPLIANCE=nist_ssdf,soc2
OPERATE_STAGE_COMPLIANCE=pci_dss,sox
```

## 🛒 **SECURITY MARKETPLACE:**

### **Content Types Available:**
- 🏆 **Golden Regression Sets**: Audit test cases (free & paid)
- 📋 **Compliance Frameworks**: Industry-specific requirements 
- 🔍 **Security Patterns**: Threat detection patterns
- 📜 **Policy Templates**: OPA/Rego policy libraries
- 🎯 **Threat Models**: Industry threat models
- ✅ **Audit Checklists**: Compliance validation checklists
- 🧪 **Test Cases**: Automated security test suites

### **Marketplace Business Model:**
- **🆓 Free Content**: OWASP, NIST, open source contributions
- **💰 Paid Content**: Premium audit sets, industry-specific frameworks
- **📅 Subscriptions**: Enterprise compliance libraries
- **⚡ Pay-Per-Use**: Specialized test cases for specific audits

### **Contribution & Monetization:**
```bash
# Security experts can contribute and earn:
1. Upload custom compliance test sets
2. Set pricing (free/paid/subscription)
3. Tag with compliance frameworks and stages
4. Earn from downloads/purchases
5. Build reputation in security community
```

## 🚀 **DEPLOYMENT OPTIONS:**

### **Option A: Backstage.io + Terraform (Recommended)**
```bash
# 1. Configure in Backstage developer portal
# 2. Select organization type and compliance frameworks
# 3. Generate Terraform configuration
# 4. Deploy to Kubernetes via Terraform
# 5. Access UI from anywhere in organization
```

### **Option B: Direct Kubernetes**
```bash
# 1. Configure environment variables
cp .env.enterprise .env
# Edit .env with your organization settings

# 2. Deploy with kubectl
kubectl apply -f kubernetes/

# 3. Access FixOps
curl https://fixops-api.yourorg.internal/health
open https://fixops.yourorg.internal
```

### **Option C: Docker Compose (Development)**
```bash
# 1. Start development environment
docker-compose up -d

# 2. Configure compliance frameworks
# Edit .env.enterprise file

# 3. Access locally
curl http://localhost:8001/health
open http://localhost:3000
```

## 📊 **CI/CD INTEGRATION BY INDUSTRY:**

### **Financial Services Example:**
```bash
# Existing pipeline:
sonarqube-scanner → results.sarif
snyk test → sca-results.json

# Add FixOps decision:
curl -X POST "https://fixops-api.yourbank.internal/api/v1/cicd/decision" \
  --data '{
    "service_name": "payment-processor",
    "sarif_results": {...},
    "compliance_requirements": ["pci_dss", "sox", "ffiec"]
  }'

# Response guides pipeline:
{"decision": "ALLOW", "exit_code": 0} → Deploy
{"decision": "BLOCK", "exit_code": 1} → Stop
```

### **Healthcare Example:**
```bash
# Healthcare-specific decision:
curl -X POST "https://fixops-api.yourhospital.internal/api/v1/cicd/decision" \
  --data '{
    "service_name": "patient-portal",
    "compliance_requirements": ["hipaa", "hitech"]
  }'
```

### **Government Example:**
```bash
# Government-specific decision:
curl -X POST "https://fixops-api.youragency.internal/api/v1/cicd/decision" \
  --data '{
    "service_name": "citizen-services",
    "compliance_requirements": ["nist_ssdf", "fisma", "fedramp"]
  }'
```

## 🎯 **VALUE PROPOSITION:**

**For Any Organization:**
- **🆓 Free tool**: No licensing costs, deploy in your infrastructure
- **🔧 Configurable**: Adapt to any industry compliance requirements  
- **🛒 Marketplace**: Access premium content, contribute expertise
- **⚙️ CI/CD Ready**: Direct pipeline integration with exit codes
- **📊 Evidence-Based**: Immutable audit trails for any compliance framework

**FixOps scales from startups to enterprises across any industry with configurable compliance and marketplace-driven security intelligence!** 🚀
