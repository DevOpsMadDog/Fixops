# Real-Time Data Generation Guide for Customer Demos

This guide provides instructions for generating fresh security scan data in real-time at customer sites using their actual tools and infrastructure.

## Quick Start

```bash
# Set up environment
export FIXOPS_API_URL="http://localhost:8000"
export FIXOPS_API_TOKEN="your-token"

# Run the interactive demo script
./scripts/fixops-interactive.sh
```

## Table of Contents

1. [SAST Tools](#sast-tools)
2. [DAST Tools](#dast-tools)
3. [SCA Tools](#sca-tools)
4. [Container Security](#container-security)
5. [Cloud Security](#cloud-security)
6. [Runtime Security](#runtime-security)
7. [Compliance Scanning](#compliance-scanning)
8. [Integration Setup](#integration-setup)

---

## SAST Tools

### SonarQube

Generate SAST findings from SonarQube:

```bash
# Export findings from SonarQube
curl -u "$SONAR_TOKEN:" \
  "$SONAR_URL/api/issues/search?componentKeys=$PROJECT_KEY&types=VULNERABILITY&ps=500" \
  | jq '{
    scan_id: "sonar-\(.paging.total)",
    tool: "sonarqube",
    scan_type: "sast",
    timestamp: now | strftime("%Y-%m-%dT%H:%M:%SZ"),
    application: env.APP_NAME,
    findings: [.issues[] | {
      id: .key,
      rule_id: .rule,
      title: .message,
      severity: .severity | ascii_downcase,
      type: .type,
      file: .component | split(":")[1],
      line: .line,
      effort_minutes: (.effort // "0min" | gsub("min"; "") | tonumber)
    }]
  }' > sonarqube-scan.json

# Upload to FixOps
curl -X POST "$FIXOPS_API_URL/api/v1/inputs/sarif" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @sonarqube-scan.json
```

### Checkmarx

Export findings from Checkmarx:

```bash
# Using Checkmarx CLI
cx scan create --project-name "$PROJECT_NAME" -s . --output-format json -o checkmarx-scan.json

# Or via API
curl -H "Authorization: Bearer $CX_TOKEN" \
  "$CX_URL/cxrestapi/sast/scans/$SCAN_ID/results" \
  | jq '{
    scan_id: "cx-\(.id)",
    tool: "checkmarx",
    scan_type: "sast",
    findings: [.results[] | {
      id: .id,
      query_name: .queryName,
      severity: .severity,
      cwe: "CWE-\(.cweId)",
      source: {file: .sourceFile, line: .sourceLine},
      sink: {file: .destFile, line: .destLine}
    }]
  }' > checkmarx-scan.json
```

### Semgrep

Run Semgrep and export findings:

```bash
# Run Semgrep scan
semgrep --config=auto --json -o semgrep-scan.json .

# Transform for FixOps
cat semgrep-scan.json | jq '{
  scan_id: "semgrep-\(now | floor)",
  tool: "semgrep",
  scan_type: "sast",
  timestamp: now | strftime("%Y-%m-%dT%H:%M:%SZ"),
  application: env.APP_NAME,
  findings: [.results[] | {
    id: .check_id,
    title: .extra.message,
    severity: .extra.severity,
    path: .path,
    start_line: .start.line,
    code: .extra.lines
  }]
}' > semgrep-fixops.json

# Upload to FixOps
curl -X POST "$FIXOPS_API_URL/api/v1/inputs/sarif" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -F "file=@semgrep-fixops.json"
```

### Bandit (Python)

```bash
# Run Bandit
bandit -r . -f json -o bandit-scan.json

# Transform and upload
cat bandit-scan.json | jq '{
  scan_id: "bandit-\(now | floor)",
  tool: "bandit",
  scan_type: "sast",
  findings: [.results[] | {
    id: .test_id,
    title: .test_name,
    severity: .issue_severity | ascii_downcase,
    confidence: .issue_confidence,
    filename: .filename,
    line_number: .line_number,
    code: .code
  }]
}' | curl -X POST "$FIXOPS_API_URL/api/v1/inputs/sarif" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @-
```

---

## DAST Tools

### OWASP ZAP

Generate DAST findings from ZAP:

```bash
# Start ZAP in daemon mode
zap.sh -daemon -port 8080 -config api.key=$ZAP_API_KEY

# Run active scan
curl "http://localhost:8080/JSON/ascan/action/scan/?url=$TARGET_URL&apikey=$ZAP_API_KEY"

# Wait for scan completion
while [ $(curl -s "http://localhost:8080/JSON/ascan/view/status/?apikey=$ZAP_API_KEY" | jq -r '.status') != "100" ]; do
  sleep 10
done

# Export findings
curl "http://localhost:8080/JSON/core/view/alerts/?apikey=$ZAP_API_KEY" \
  | jq '{
    scan_id: "zap-\(now | floor)",
    tool: "owasp-zap",
    scan_type: "dast",
    target_url: env.TARGET_URL,
    findings: [.alerts[] | {
      id: .alertRef,
      name: .name,
      risk: .risk | ascii_downcase,
      confidence: .confidence,
      url: .url,
      parameter: .param,
      attack: .attack,
      evidence: .evidence,
      description: .description,
      solution: .solution,
      cwe: "CWE-\(.cweid)"
    }]
  }' > zap-scan.json

# Upload to FixOps
curl -X POST "$FIXOPS_API_URL/api/v1/inputs/sarif" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -F "file=@zap-scan.json"
```

### Burp Suite

Export from Burp Suite Enterprise:

```bash
# Export via Burp API
curl -H "Authorization: $BURP_API_KEY" \
  "$BURP_URL/api/v1/scans/$SCAN_ID/issues" \
  | jq '{
    scan_id: "burp-\(.scan_id)",
    tool: "burp-suite",
    scan_type: "dast",
    findings: [.issues[] | {
      id: .serial_number,
      type: .type_index,
      name: .name,
      severity: .severity,
      confidence: .confidence,
      host: .origin,
      path: .path,
      description: .description
    }]
  }' > burp-scan.json
```

---

## SCA Tools

### Snyk

Generate SCA findings from Snyk:

```bash
# Run Snyk test
snyk test --json > snyk-scan.json

# Or use Snyk API
curl -H "Authorization: token $SNYK_TOKEN" \
  "https://snyk.io/api/v1/org/$ORG_ID/project/$PROJECT_ID/issues" \
  | jq '{
    scan_id: "snyk-\(now | floor)",
    tool: "snyk",
    scan_type: "sca",
    findings: [.issues.vulnerabilities[] | {
      id: .id,
      title: .title,
      severity: .severity,
      cvss_score: .cvssScore,
      cve: .identifiers.CVE[0],
      package_name: .package,
      installed_version: .version,
      fixed_version: .fixedIn[0],
      exploit_maturity: .exploit
    }]
  }' > snyk-fixops.json

# Upload SBOM to FixOps
snyk sbom --format=cyclonedx1.4+json > sbom.json
curl -X POST "$FIXOPS_API_URL/api/v1/inputs/sbom" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -F "file=@sbom.json"
```

### Dependabot (GitHub)

```bash
# Export Dependabot alerts via GitHub API
curl -H "Authorization: token $GITHUB_TOKEN" \
  "https://api.github.com/repos/$OWNER/$REPO/dependabot/alerts?state=open" \
  | jq '{
    scan_id: "dependabot-\(now | floor)",
    tool: "dependabot",
    scan_type: "sca",
    alerts: [.[] | {
      id: .number,
      package: .dependency.package.name,
      ecosystem: .dependency.package.ecosystem,
      severity: .security_advisory.severity,
      cve: .security_advisory.cve_id,
      ghsa: .security_advisory.ghsa_id,
      vulnerable_version: .security_vulnerability.vulnerable_version_range,
      fixed_version: .security_vulnerability.first_patched_version.identifier
    }]
  }' > dependabot-alerts.json
```

### Trivy (SCA mode)

```bash
# Scan filesystem for vulnerabilities
trivy fs --format json --output trivy-sca.json .

# Transform for FixOps
cat trivy-sca.json | jq '{
  scan_id: "trivy-sca-\(now | floor)",
  tool: "trivy",
  scan_type: "sca",
  results: [.Results[] | {
    target: .Target,
    type: .Type,
    vulnerabilities: [.Vulnerabilities[]? | {
      id: .VulnerabilityID,
      pkg_name: .PkgName,
      installed_version: .InstalledVersion,
      fixed_version: .FixedVersion,
      severity: .Severity,
      cvss_score: .CVSS.nvd.V3Score
    }]
  }]
}' > trivy-sca-fixops.json
```

### Safety (Python)

```bash
# Run Safety check
safety check --json > safety-scan.json

# Transform for FixOps
cat safety-scan.json | jq '{
  scan_id: "safety-\(now | floor)",
  tool: "safety",
  scan_type: "sca",
  vulnerabilities: [.[] | {
    id: .[4],
    package_name: .[0],
    installed_version: .[2],
    affected_versions: .[1],
    description: .[3]
  }]
}' > safety-fixops.json
```

---

## Container Security

### Trivy (Container)

```bash
# Scan container image
trivy image --format json --output trivy-container.json $IMAGE_NAME:$TAG

# Upload to FixOps
curl -X POST "$FIXOPS_API_URL/api/v1/inputs/cnapp" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -F "file=@trivy-container.json"
```

### Grype

```bash
# Scan container image
grype $IMAGE_NAME:$TAG -o json > grype-scan.json

# Transform for FixOps
cat grype-scan.json | jq '{
  scan_id: "grype-\(now | floor)",
  tool: "grype",
  scan_type: "container",
  image: env.IMAGE_NAME,
  matches: [.matches[] | {
    vulnerability: .vulnerability,
    artifact: .artifact,
    fix: .matchDetails[0].fix
  }]
}' > grype-fixops.json
```

### Prisma Cloud (twistcli)

```bash
# Scan with twistcli
twistcli images scan --address $PRISMA_URL --user $PRISMA_USER --password $PRISMA_PASS \
  --output-file prisma-scan.json $IMAGE_NAME:$TAG

# Upload to FixOps
curl -X POST "$FIXOPS_API_URL/api/v1/inputs/cnapp" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -F "file=@prisma-scan.json"
```

---

## Cloud Security

### AWS Security Hub

```bash
# Export findings from Security Hub
aws securityhub get-findings \
  --filters '{"RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]}' \
  --max-items 100 \
  | jq '{
    scan_id: "securityhub-\(now | floor)",
    tool: "aws-security-hub",
    scan_type: "cloud",
    findings: [.Findings[] | {
      id: .Id,
      title: .Title,
      severity: .Severity.Label,
      compliance_status: .Compliance.Status,
      resource_type: .Resources[0].Type,
      resource_id: .Resources[0].Id,
      description: .Description,
      remediation: .Remediation.Recommendation.Text
    }]
  }' > securityhub-findings.json

# Upload to FixOps
curl -X POST "$FIXOPS_API_URL/api/v1/inputs/cnapp" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -F "file=@securityhub-findings.json"
```

### Wiz

```bash
# Export from Wiz API
curl -H "Authorization: Bearer $WIZ_TOKEN" \
  "https://api.wiz.io/graphql" \
  -d '{"query": "{ issues(first: 100, filterBy: {status: [OPEN]}) { nodes { id title severity status resource { name type } } } }"}' \
  | jq '{
    scan_id: "wiz-\(now | floor)",
    tool: "wiz",
    scan_type: "cloud",
    issues: .data.issues.nodes
  }' > wiz-findings.json
```

### Orca Security

```bash
# Export from Orca API
curl -H "Authorization: Token $ORCA_TOKEN" \
  "$ORCA_URL/api/alerts?status=open&limit=100" \
  | jq '{
    scan_id: "orca-\(now | floor)",
    tool: "orca-security",
    scan_type: "cloud",
    alerts: [.data[] | {
      id: .alert_id,
      title: .title,
      category: .category,
      severity: .severity,
      asset: .asset,
      compliance: .compliance_frameworks
    }]
  }' > orca-findings.json
```

---

## Runtime Security

### Falco

```bash
# Export Falco events (last hour)
curl "$FALCO_URL/api/v1/events?since=1h" \
  | jq '{
    scan_id: "falco-\(now | floor)",
    tool: "falco",
    scan_type: "runtime",
    events: [.events[] | {
      timestamp: .time,
      rule: .rule,
      priority: .priority,
      output: .output,
      fields: .output_fields
    }]
  }' > falco-events.json

# Or stream from Falco sidekick
curl "$FALCOSIDEKICK_URL/api/v1/events" > falco-events.json
```

### Sysdig Secure

```bash
# Export policy events
curl -H "Authorization: Bearer $SYSDIG_TOKEN" \
  "$SYSDIG_URL/api/v1/policyEvents?from=$(date -d '1 hour ago' +%s)000000000" \
  | jq '{
    scan_id: "sysdig-\(now | floor)",
    tool: "sysdig-secure",
    scan_type: "runtime",
    policy_events: [.data[] | {
      id: .id,
      timestamp: .timestamp,
      policy: .policyName,
      rule: .ruleName,
      severity: .severity,
      container: .containerId,
      description: .description
    }]
  }' > sysdig-events.json
```

---

## Compliance Scanning

### Generate Compliance Assessment

```bash
# Create compliance assessment from scan results
# Note: Set FRAMEWORK and APP_NAME environment variables before running
cat > compliance-assessment.json << EOF
{
  "assessment_id": "compliance-$(date +%s)",
  "framework": "$FRAMEWORK",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "application": "$APP_NAME",
  "controls": []
}
EOF

# Upload to FixOps
curl -X POST "$FIXOPS_API_URL/api/v1/compliance/assess" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d @compliance-assessment.json
```

---

## Integration Setup

### Jira Integration

```bash
# Configure Jira integration
curl -X POST "$FIXOPS_API_URL/api/v1/integrations/jira" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "base_url": "'$JIRA_URL'",
    "auth_type": "api_token",
    "credentials": {
      "email": "'$JIRA_EMAIL'",
      "api_token": "'$JIRA_TOKEN'"
    },
    "project_key": "'$JIRA_PROJECT'",
    "auto_create": true
  }'
```

### Slack Integration

```bash
# Configure Slack integration
curl -X POST "$FIXOPS_API_URL/api/v1/integrations/slack" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "webhook_url": "'$SLACK_WEBHOOK'",
    "channels": {
      "critical": "#security-critical",
      "default": "#security-alerts"
    },
    "notifications": {
      "critical_vulnerabilities": true,
      "compliance_violations": true,
      "runtime_alerts": true
    }
  }'
```

### ServiceNow Integration

```bash
# Configure ServiceNow integration
curl -X POST "$FIXOPS_API_URL/api/v1/integrations/servicenow" \
  -H "X-API-Key: $FIXOPS_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "instance_url": "'$SNOW_URL'",
    "auth_type": "basic",
    "credentials": {
      "username": "'$SNOW_USER'",
      "password": "'$SNOW_PASS'"
    },
    "auto_create_incidents": true
  }'
```

---

## Customer Customization

### Customize Application Names

Edit the application definitions in `demo-scenarios/applications/` to match customer's actual applications:

```bash
# Update application name
sed -i 's/payment-gateway/customer-app-name/g' demo-scenarios/applications/*.json
sed -i 's/payment-gateway/customer-app-name/g' demo-scenarios/scans/**/*.json
```

### Customize Compliance Frameworks

Modify compliance assessments to match customer's requirements:

```bash
# Switch from PCI-DSS to SOC2
jq '.framework = "soc2" | .framework_version = "type2"' \
  demo-scenarios/compliance/pci-dss/assessment.json > customer-compliance.json
```

### Customize Tool Names

Update tool references to match customer's tooling:

```bash
# Replace SonarQube with customer's SAST tool
find demo-scenarios/scans/sast -name "*.json" -exec \
  sed -i 's/"tool": "sonarqube"/"tool": "customer-sast-tool"/g' {} \;
```

---

## End-to-End Demo Flow

Run the complete demo flow:

```bash
# 1. Start FixOps API
uvicorn apps.api.app:app --reload &

# 2. Run interactive demo
./scripts/fixops-interactive.sh

# 3. Select "Run All Tests" for end-to-end demo
# Or select individual categories to demonstrate specific features

# 4. Use "Load from File" option to use customer's actual scan data
```

## Tips for Customer Demos

1. **Prepare in advance**: Run tool scans before the demo to have fresh data ready
2. **Use real data**: Load actual scan results from customer's tools for authenticity
3. **Customize applications**: Update application names to match customer's portfolio
4. **Show correlations**: Demonstrate how findings from different tools correlate
5. **Highlight compliance**: Show compliance mapping for customer's specific frameworks
6. **Demo integrations**: Show Jira/Slack notifications in real-time
7. **Runtime alerts**: If possible, trigger a Falco alert to show runtime detection
