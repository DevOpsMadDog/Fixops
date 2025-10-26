# FixOps Postman Testing Suite
# Complete API testing for bank deployment

## 📋 **Postman Collections Included:**

### **1. FixOps-Bank-API-Collection.json**
**Main collection for comprehensive API testing:**
- 🏥 **Health & Monitoring**: Health checks, readiness probes, Prometheus metrics
- ⚖️ **Decision Engine**: Core decision-making endpoints with evidence tracking
- 🏦 **CI/CD Bank Integration**: Bank-specific pipeline integration with SonarQube + Snyk
- 📤 **File Upload & Scan Ingestion**: SARIF/SBOM upload testing
- 🏢 **Business Context Integration**: Jira/Confluence context retrieval
- 📊 **Analytics & Reporting**: Dashboard metrics and performance data

### **2. FixOps-CICD-Tests.postman_collection.json**
**CI/CD pipeline simulation:**
- ✅ **Payment Service** → Should ALLOW (high confidence)
- 🚫 **Auth Service** → Should BLOCK (critical vulnerabilities)
- ⏸️ **API Gateway** → Should DEFER (low confidence)
- 🔍 **Pre-deployment health checks**

### **3. FixOps-Performance-Tests.postman_collection.json**
**Bank SLA performance validation:**
- ⚡ **299μs hot path latency testing**
- 🏦 **2-second bank SLA compliance**
- 🔄 **Concurrent request handling**
- 📈 **Load testing scenarios**

## 🌍 **Environment Configurations:**

### **Development Environment:**
```json
{
  "BASE_URL": "http://localhost:8001",
  "ENVIRONMENT": "development", 
  "SERVICE_NAME": "test-service"
}
```

### **Bank Production Environment:**
```json
{
  "BASE_URL": "https://fixops-api.bank.internal",
  "ENVIRONMENT": "production",
  "SERVICE_NAME": "payment-processor"
}
```

## 📝 **Sample Test Data:**

### **sample-sarif.json**
- **SonarQube format** SARIF with bank-specific findings
- **Payment service** security scan results
- **SQL injection**, **hardcoded secrets**, **crypto weaknesses**

### **sample-sbom.json** 
- **CycloneDX format** SBOM with dependency vulnerabilities
- **Jackson**, **Spring Security**, **Log4j** components
- **CVE mappings** with CVSS scores

## 🚀 **How Banks Use These Collections:**

### **1. Import Collections:**
```bash
# Import into Postman
1. Open Postman
2. File → Import
3. Select all .json files from /postman/ directory
4. Choose environment (Development/Production)
```

### **2. Test Bank Integration:**
```bash
# Run pre-deployment validation
1. Run "Health & Monitoring" folder
2. Run "CI/CD Bank Integration" folder  
3. Check all tests pass ✅
4. Review evidence IDs generated
```

### **3. Validate CI/CD Pipeline:**
```bash
# Test decision outcomes
1. Payment Service → Expect ALLOW ✅
2. Auth Service → Expect BLOCK 🚫  
3. API Gateway → Expect DEFER ⏸️
4. Verify exit codes (0/1/2) for pipeline integration
```

### **4. Performance Validation:**
```bash
# Bank SLA testing
1. Run performance tests
2. Verify <2s response times
3. Check hot path latency <299μs target
4. Test concurrent request handling
```

## 📊 **Expected Test Results:**

### **All Health Checks:** ✅ 200 OK
- `/health` → {"status": "healthy"}
- `/ready` → {"status": "ready", "checks": {...}}
- `/metrics` → Prometheus format metrics

### **Decision Tests:** ✅ Realistic Responses
- **ALLOW**: 92% confidence, exit_code: 0
- **BLOCK**: 89% confidence, exit_code: 1  
- **DEFER**: 78% confidence, exit_code: 2

### **Upload Tests:** ✅ File Processing
- SARIF processing with correlation analysis
- SBOM dependency vulnerability assessment
- Evidence generation with audit trail

## 🎯 **Bank Integration Validation:**

These collections prove FixOps is ready for bank deployment by testing:
- ✅ **No Authentication Required** - Free tool access
- ✅ **CI/CD Integration** - Direct pipeline compatibility
- ✅ **Performance SLAs** - Bank-grade response times
- ✅ **Compliance Tracking** - PCI DSS, SOX, FFIEC status
- ✅ **Evidence Trail** - Immutable audit records
- ✅ **Real LLM Processing** - Actual intelligence analysis

**Banks can use these collections to validate FixOps deployment and demonstrate compliance to auditors.**
