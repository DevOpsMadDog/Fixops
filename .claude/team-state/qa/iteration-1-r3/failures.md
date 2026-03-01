# Iteration 1 (Round 3) — Failure Analysis

> **Date**: 2026-03-01
> **Total Assertions**: 477
> **Passed**: 353 (74.0%)
> **Failed**: 124 (26.0%)

## SCHEMA_MISMATCH (74 failures) — Route to: qa-engineer (fix request body) / backend-hardener (add validation defaults)

| Collection | Endpoint | Test |
|------------|----------|------|
| ALdeci-1-MissionControl             | POST   /users                                             | Create user returns 200 or 201 |
| ALdeci-2-Discover                   | PUT    /analytics/findings/{{findingId}}                  | Update finding returns 200 |
| ALdeci-2-Discover                   | POST   /deduplication/correlate/cross-stage               | Cross-stage correlation returns 200 |
| ALdeci-2-Discover                   | POST   /api-fuzzer/discover                               | API fuzzer discover returns 200 |
| ALdeci-2-Discover                   | POST   /feeds/enrich                                      | Enrichment returns 200 |
| ALdeci-2-Discover                   | POST   /inputs/sarif                                      | SARIF ingest returns 200 |
| ALdeci-2-Discover                   | POST   /inputs/sbom                                       | SBOM ingest returns 200 |
| ALdeci-2-Discover                   | POST   /inputs/cve                                        | CVE ingest returns 200 |
| ALdeci-2-Discover                   | POST   /inputs/design                                     | Design ingest returns 200 |
| ALdeci-2-Discover                   | POST   /validate/input                                    | Validation returns 200 |
| ALdeci-2-Discover                   | POST   /predictions/attack-chain                          | Attack chain prediction returns 200 |
| ALdeci-2-Discover                   | POST   /algorithms/monte-carlo/cve                        | Bayesian assessment returns 200 |
| ALdeci-2-Discover                   | POST   /algorithms/gnn/attack-surface                     | GNN analysis returns 200 |
| ALdeci-2-Discover                   | POST   /reachability/analyze                              | Reachability returns 200 |
| ALdeci-2-Discover                   | POST   /code-to-cloud/trace                               | Code-to-cloud trace returns 200 |
| ALdeci-2-Discover                   | POST   /identity/canonical                                | Register canonical returns 200/201 |
| ALdeci-3-Validate                   | POST   /mpte/verify                                       | Verify exploitability returns 200 |
| ALdeci-3-Validate                   | POST   /micro-pentest/run                                 | Micro pentest returns 200 |
| ALdeci-3-Validate                   | POST   /micro-pentest/enterprise/scan                     | Enterprise scan returns 200 |
| ALdeci-3-Validate                   | POST   /micro-pentest/report/generate                     | Report generation returns 200 |
| ... | 54 more | |

## MISSING_ENDPOINT (30 failures) — Route to: backend-hardener

| Collection | Endpoint | Test |
|------------|----------|------|
| ALdeci-1-MissionControl             | GET    /risk/                                             | Risk summary returns 200 |
| ALdeci-1-MissionControl             | GET    /risk/cve/{{cveId}}                                | CVE risk returns 200 |
| ALdeci-2-Discover                   | GET    /deduplication/clusters/{{clusterId}}              | Get cluster returns 200 |
| ALdeci-3-Validate                   | GET    /mpte/findings/{{findingId}}/exploitability        | Exploitability returns 200 |
| ALdeci-3-Validate                   | GET    /attack-sim/campaigns/{{campaignId}}/attack-paths  | Attack paths returns 200 |
| ALdeci-3-Validate                   | GET    /attack-sim/campaigns/{{campaignId}}/breach-impact | Breach impact returns 200 |
| ALdeci-3-Validate                   | POST   /copilot/agents/analyst/attack-paths               | Attack path analysis returns 200 |
| ALdeci-4-Remediate                  | GET    /remediation/tasks/{{taskId}}                      | Get task returns 200 |
| ALdeci-4-Remediate                  | GET    /autofix/fixes/{{fixId}}                           | Get fix returns 200 |
| ALdeci-4-Remediate                  | POST   /autofix/validate                                  | Validate fix returns 200 |
| ALdeci-5-Comply                     | GET    /audit/compliance/{{frameworkId}}/status           | Framework status returns 200 |
| ALdeci-5-Comply                     | GET    /audit/compliance/{{frameworkId}}/gaps             | Gap analysis returns 200 |
| ALdeci-5-Comply                     | POST   /audit/compliance/frameworks/{{frameworkId}}/report | Generate evidence returns 200 |
| ALdeci-5-Comply                     | GET    /evidence/bundles/{{bundleId}}                     | Get bundle returns 200 |
| ALdeci-5-Comply                     | GET    /marketplace                                       | Marketplace packs returns 200 |
| ALdeci-5-Comply                     | POST   /marketplace                                       | Install pack returns 200 |
| ALdeci-5-Comply                     | GET    /marketplace                                       | Contributions returns 200 |
| ALdeci-5-Comply                     | POST   /marketplace                                       | Submit contribution returns 200/201 |
| ALdeci-5-Comply                     | GET    /business-context                                  | Business context settings returns 200 |
| ALdeci-6-PersonaWorkflows           | GET    /audit/compliance/{{frameworkId}}/status           | Compliance status returns 200 |
| ... | 10 more | |

## TEST_LOGIC (18 failures) — Route to: qa-engineer (fix test assertions)

| Collection | Endpoint | Test |
|------------|----------|------|
| ALdeci-1-MissionControl             | POST   /teams                                             | Create team returns 200 or 201 |
| ALdeci-1-MissionControl             | GET    /search                                            | Returns search results |
| ALdeci-2-Discover                   | GET    /brain/most-connected                              | Most connected returns 200 |
| ALdeci-4-Remediate                  | PUT    /remediation/tasks/{{taskId}}/status               | Update task returns 200 |
| ALdeci-4-Remediate                  | POST   /workflows                                         | Create workflow returns 200/201 |
| ALdeci-4-Remediate                  | PATCH  /cases/{{caseId}}                                  | Update case returns 200 |
| ALdeci-5-Comply                     | POST   /evidence/bundles/{{bundleId}}/verify              | Signature is valid |
| ALdeci-6-PersonaWorkflows           | POST   /evidence/bundles/{{auditBundleId}}/verify         | Signature is valid |
| ALdeci-7-Scanners-OSS-AutoFix       | POST   /api/v1/sast/scan/code                             | SAST detects code injection |
| ALdeci-7-Scanners-OSS-AutoFix       | POST   /api/v1/sast/scan/files                            | Response has scan results |
| ALdeci-7-Scanners-OSS-AutoFix       | GET    /api/v1/sast/rules                                 | Rules include multiple languages |
| ALdeci-7-Scanners-OSS-AutoFix       | PUT    /api/v1/secrets/{{secret_finding_id}}/resolve      | Resolve secret returns 200 |
| ALdeci-7-Scanners-OSS-AutoFix       | POST   /api/v1/llm-monitor/analyze                        | Detects prompt injection |
| ALdeci-7-Scanners-OSS-AutoFix       | POST   /api/v1/inventory/applications                     | SBOM has components |
| ALdeci-7-Scanners-OSS-AutoFix       | POST   /api/v1/validate/input                             | Validation result valid |
| ALdeci-7-Scanners-OSS-AutoFix       | GET    /api/v1/brain/stats                                | Pipeline has 12 steps |
| ALdeci-7-Scanners-OSS-AutoFix       | POST   /api/v1/brain/pipeline/run                         | Finding processed through pipeline |
| ALdeci-7-Scanners-OSS-AutoFix       | POST   /api/v1/brain/pipeline/run                         | Pipeline completes all 12 steps |

## BACKEND_BUG (2 failures) — Route to: backend-hardener

| Collection | Endpoint | Test |
|------------|----------|------|
| ALdeci-1-MissionControl             | GET    /search                                            | Search returns 200 |
| ALdeci-1-MissionControl             | GET    /search                                            | Keyword search returns 200 |

## TIMEOUT (1 failures) — Route to: backend-hardener (optimize slow endpoints)

| Collection | Endpoint | Test |
|------------|----------|------|
| ALdeci-2-Discover                   | GET    /api/v1/brain/most-connected                       | unknown |


## Priority

1. **BLOCKER**: Search endpoint (500) — breaks demo
2. **HIGH**: Schema mismatches (422) — fix request bodies or add API defaults
3. **MEDIUM**: Missing endpoints (404) — need empty env variables populated
4. **LOW**: Timeouts — optimize slow endpoints
5. **LOW**: Test logic — fix assertion expectations
