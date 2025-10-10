# FixOps Bank CI/CD Integration Examples

## 🏦 COMPLETE BANK DEPLOYMENT GUIDE

### **Deployment Architecture:**
```
Bank Kubernetes Cluster
├── fixops namespace
│   ├── fixops-backend (3 replicas)
│   ├── fixops-frontend (2 replicas) 
│   ├── mongodb (persistent storage)
│   └── redis (caching)
├── Internal DNS: fixops-api.bank.internal
└── External Access: fixops.bank.internal (UI)
```

### **CI/CD Pipeline Integration Examples:**

#### **Example 1: Jenkins Pipeline (Groovy)**
```groovy
pipeline {
    agent any
    
    environment {
        FIXOPS_API = 'https://fixops-api.bank.internal'
        FIXOPS_TIMEOUT = '300'
    }
    
    stages {
        stage('Security Scans') {
            parallel {
                stage('SAST') {
                    steps {
                        sh 'sonarqube-scanner -Dsonar.projectKey=${JOB_NAME} -Dsonar.outputFile=sarif-results.json'
                    }
                }
                stage('SCA') {
                    steps {
                        sh 'snyk test --json-file-output=snyk-results.json || true'
                    }
                }
                stage('SBOM') {
                    steps {
                        sh 'cyclonedx-cli --output-format json --output-file sbom.json'
                    }
                }
            }
        }
        
        stage('FixOps Security Decision') {
            steps {
                script {
                    def decision = sh(
                        script: '''
                            curl -X POST "${FIXOPS_API}/api/v1/cicd/decision" \
                                -H "Content-Type: application/json" \
                                -H "X-Pipeline-ID: ${BUILD_ID}" \
                                -H "X-Correlation-ID: ${JOB_NAME}-${BUILD_NUMBER}" \
                                --data @- <<EOF
                            {
                                "service_name": "${JOB_NAME}",
                                "environment": "production",
                                "repository_url": "${GIT_URL}",
                                "commit_sha": "${GIT_COMMIT}",
                                "branch_name": "${GIT_BRANCH}",
                                "sarif_results": $(cat sarif-results.json 2>/dev/null || echo '{}'),
                                "sca_results": $(cat snyk-results.json 2>/dev/null || echo '{}'),
                                "sbom_data": $(cat sbom.json 2>/dev/null || echo '{}'),
                                "business_criticality": "critical",
                                "compliance_requirements": ["pci_dss", "sox", "bank_internal"]
                            }
EOF
                        ''',
                        returnStdout: true
                    ).trim()
                    
                    def response = readJSON text: decision
                    
                    echo "FixOps Decision: ${response.decision}"
                    echo "Confidence: ${response.confidence_score * 100}%"
                    echo "Evidence ID: ${response.evidence_id}"
                    
                    if (response.exit_code == 0) {
                        echo "✅ DEPLOYMENT APPROVED - Proceeding to production"
                        env.DEPLOYMENT_APPROVED = 'true'
                    } else if (response.exit_code == 1) {
                        echo "🚫 DEPLOYMENT BLOCKED - Security issues detected"
                        currentBuild.result = 'FAILURE'
                        error("Deployment blocked by FixOps: ${response.blocking_issues}")
                    } else {
                        echo "⏸️ MANUAL REVIEW REQUIRED - Low confidence decision"
                        input message: 'Security team approval required. Proceed?', ok: 'Approve'
                        env.DEPLOYMENT_APPROVED = 'true'
                    }
                }
            }
        }
        
        stage('Deploy to Production') {
            when {
                environment name: 'DEPLOYMENT_APPROVED', value: 'true'
            }
            steps {
                sh 'kubectl apply -f k8s/production/'
                echo "🚀 Deployment completed successfully"
            }
        }
    }
    
    post {
        always {
            // Archive FixOps evidence
            archiveArtifacts artifacts: 'fixops-evidence.json', allowEmptyArchive: true
        }
        failure {
            // Notify security team if blocked
            emailext (
                subject: "🚫 Deployment Blocked: ${JOB_NAME}",
                body: "FixOps blocked deployment due to security concerns. Check evidence ID: ${env.EVIDENCE_ID}",
                to: "${SECURITY_TEAM_EMAIL}"
            )
        }
    }
}
```

#### **Example 2: GitHub Actions**
```yaml
name: FixOps Security Gate

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  security-decision:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Run Security Scans
      run: |
        # SAST
        sonarqube-scanner -Dsonar.outputFile=sarif-results.json
        
        # SCA (Snyk)
        snyk test --json-file-output=snyk-results.json || true
        
        # SBOM Generation
        cyclonedx-cli --output-format json --output-file sbom.json
        
    - name: FixOps Security Decision
      id: fixops
      run: |
        RESPONSE=$(curl -X POST "${{ vars.FIXOPS_API_URL }}/api/v1/cicd/decision" \
          -H "Content-Type: application/json" \
          -H "X-Pipeline-ID: ${{ github.run_id }}" \
          -H "X-Correlation-ID: ${{ github.repository }}-${{ github.run_number }}" \
          --data '{
            "service_name": "${{ github.event.repository.name }}",
            "environment": "production",
            "repository_url": "${{ github.event.repository.html_url }}",
            "commit_sha": "${{ github.sha }}",
            "branch_name": "${{ github.ref_name }}",
            "pull_request_id": "${{ github.event.number }}",
            "sarif_results": '"$(cat sarif-results.json 2>/dev/null | jq -c . || echo '{}')"',
            "sca_results": '"$(cat snyk-results.json 2>/dev/null | jq -c . || echo '{}')"',
            "sbom_data": '"$(cat sbom.json 2>/dev/null | jq -c . || echo '{}')"',
            "business_criticality": "critical",
            "compliance_requirements": ["pci_dss", "sox", "bank_internal"]
          }')
        
        echo "fixops_response=$RESPONSE" >> $GITHUB_OUTPUT
        
        DECISION=$(echo $RESPONSE | jq -r '.decision')
        CONFIDENCE=$(echo $RESPONSE | jq -r '.confidence_score')
        EXIT_CODE=$(echo $RESPONSE | jq -r '.exit_code')
        EVIDENCE_ID=$(echo $RESPONSE | jq -r '.evidence_id')
        
        echo "decision=$DECISION" >> $GITHUB_OUTPUT
        echo "confidence=$CONFIDENCE" >> $GITHUB_OUTPUT  
        echo "exit_code=$EXIT_CODE" >> $GITHUB_OUTPUT
        echo "evidence_id=$EVIDENCE_ID" >> $GITHUB_OUTPUT
        
        echo "🎯 FixOps Decision: $DECISION"
        echo "📊 Confidence: $(echo "$CONFIDENCE * 100" | bc)%"
        echo "🗃️ Evidence: $EVIDENCE_ID"
        
        exit $EXIT_CODE
    
    - name: Handle ALLOW Decision
      if: steps.fixops.outputs.exit_code == '0'
      run: |
        echo "✅ DEPLOYMENT APPROVED"
        echo "Confidence: ${{ steps.fixops.outputs.confidence }}"
        # Proceed with deployment
        kubectl apply -f k8s/
        
    - name: Handle BLOCK Decision  
      if: steps.fixops.outputs.exit_code == '1'
      run: |
        echo "🚫 DEPLOYMENT BLOCKED"
        # Create security issue
        gh issue create \
          --title "🚫 Security Review Required: ${{ github.event.repository.name }}" \
          --body "FixOps blocked deployment due to security concerns. Evidence: ${{ steps.fixops.outputs.evidence_id }}" \
          --label "security,blocked-deployment"
        exit 1
        
    - name: Handle DEFER Decision
      if: steps.fixops.outputs.exit_code == '2' 
      run: |
        echo "⏸️ MANUAL REVIEW REQUIRED"
        # Request security team review
        gh pr review ${{ github.event.number }} \
          --request-changes \
          --body "Security team review required. Confidence below threshold. Evidence: ${{ steps.fixops.outputs.evidence_id }}"
        exit 1
```

#### **Example 3: Azure DevOps Pipeline**
```yaml
trigger:
- main

pool:
  vmImage: ubuntu-latest

variables:
  FIXOPS_API_URL: 'https://fixops-api.bank.internal'

stages:
- stage: SecurityGate
  displayName: 'FixOps Security Gate'
  jobs:
  - job: SecurityDecision
    displayName: 'Security Decision Analysis'
    steps:
    - task: SonarQubePrepare@5
      inputs:
        SonarQube: 'SonarQube-Bank'
        scannerMode: 'CLI'
        configMode: 'manual'
        cliProjectKey: '$(System.TeamProject)'
        
    - task: SonarQubeAnalyze@5
    
    - task: SonarQubePublish@5
      inputs:
        pollingTimeoutSec: '300'
        
    - script: |
        # Generate SBOM
        cyclonedx-cli --output-format json --output-file $(Agent.TempDirectory)/sbom.json
        
        # FixOps Decision Call
        curl -X POST "$(FIXOPS_API_URL)/api/v1/cicd/decision" \
          -H "Content-Type: application/json" \
          -H "X-Pipeline-ID: $(Build.BuildId)" \
          -H "X-Correlation-ID: $(System.TeamProject)-$(Build.BuildNumber)" \
          --data '{
            "service_name": "$(System.TeamProject)",
            "environment": "production", 
            "repository_url": "$(Build.Repository.Uri)",
            "commit_sha": "$(Build.SourceVersion)",
            "branch_name": "$(Build.SourceBranchName)",
            "business_criticality": "critical",
            "compliance_requirements": ["pci_dss", "sox", "ffiec"]
          }' \
          --output $(Agent.TempDirectory)/fixops-decision.json
          
        # Process decision
        DECISION=$(cat $(Agent.TempDirectory)/fixops-decision.json | jq -r '.decision')
        EXIT_CODE=$(cat $(Agent.TempDirectory)/fixops-decision.json | jq -r '.exit_code')
        
        echo "##vso[task.setvariable variable=FIXOPS_DECISION]$DECISION"
        echo "##vso[task.setvariable variable=FIXOPS_EXIT_CODE]$EXIT_CODE"
        
        exit $EXIT_CODE
      displayName: 'FixOps Security Decision'
      
    - script: echo "✅ Deployment approved by FixOps"
      condition: eq(variables['FIXOPS_EXIT_CODE'], '0')
      displayName: 'Deployment Approved'
      
    - script: |
        echo "🚫 Deployment blocked by FixOps"
        exit 1
      condition: eq(variables['FIXOPS_EXIT_CODE'], '1') 
      displayName: 'Deployment Blocked'
```

### **Bank Deployment Commands:**

#### **Deploy to Bank Kubernetes:**
```bash
# 1. Deploy namespace and RBAC
kubectl apply -f kubernetes/namespace.yaml
kubectl apply -f kubernetes/rbac.yaml

# 2. Create secrets (configure with bank's values)
kubectl apply -f kubernetes/secret.yaml
kubectl apply -f kubernetes/configmap.yaml

# 3. Deploy persistent storage
kubectl apply -f kubernetes/pvc.yaml

# 4. Deploy FixOps services
kubectl apply -f kubernetes/backend-deployment.yaml
kubectl apply -f kubernetes/frontend-deployment.yaml
kubectl apply -f kubernetes/services.yaml

# 5. Configure ingress (bank-specific)
kubectl apply -f kubernetes/ingress.yaml

# 6. Verify deployment
kubectl get pods -n fixops
kubectl logs -f deployment/fixops-backend -n fixops
```

#### **Local Development:**
```bash
# Start development environment
docker-compose up -d

# Check logs
docker-compose logs -f fixops-backend

# Test decision API
curl -X POST "http://localhost:8001/api/v1/cicd/decision" \
  -H "Content-Type: application/json" \
  --data '{
    "service_name": "test-service",
    "environment": "development"
  }'

# Stop environment
docker-compose down
```

#### **Production CI/CD Integration:**
```bash
# Example bank CI/CD integration
#!/bin/bash

# Bank's existing security pipeline adds:
FIXOPS_DECISION=$(curl -X POST "https://fixops-api.bank.internal/api/v1/cicd/decision" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $FIXOPS_API_TOKEN" \
  --data '{
    "service_name": "'$SERVICE_NAME'",
    "environment": "production",
    "sarif_results": '$(cat sonar-results.sarif)',
    "sca_results": '$(cat snyk-results.json)',
    "sbom_data": '$(cat cyclonedx-sbom.json)',
    "business_criticality": "critical",
    "compliance_requirements": ["pci_dss", "sox", "ffiec"]
  }')

EXIT_CODE=$(echo $FIXOPS_DECISION | jq -r '.exit_code')
DECISION=$(echo $FIXOPS_DECISION | jq -r '.decision')
EVIDENCE_ID=$(echo $FIXOPS_DECISION | jq -r '.evidence_id')

echo "FixOps Decision: $DECISION (Evidence: $EVIDENCE_ID)"

case $EXIT_CODE in
  0)
    echo "✅ ALLOW: Deploying to production"
    kubectl apply -f k8s/production/
    ;;
  1)
    echo "🚫 BLOCK: Creating security incident"
    # Integration with bank's incident management
    curl -X POST "$SERVICENOW_API/incident" \
      --data '{"short_description": "Security deployment blocked", "evidence_id": "'$EVIDENCE_ID'"}'
    exit 1
    ;;
  2)
    echo "⏸️ DEFER: Manual security review required"
    # Integration with bank's approval workflow
    curl -X POST "$APPROVAL_SYSTEM_API/request" \
      --data '{"type": "security_review", "evidence_id": "'$EVIDENCE_ID'"}'
    exit 2
    ;;
esac
```