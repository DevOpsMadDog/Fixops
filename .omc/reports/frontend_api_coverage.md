# Frontend API Coverage Report

**Generated:** 2026-04-17  
**Server:** http://localhost:8000  
**Auth:** X-API-Key (token provided)  
**Total endpoints tested:** 374  
**Source:** 309 frontend pages in `suite-ui/aldeci-ui-new/src/pages/`

---

## Executive Summary

| Category | Count | % |
|----------|-------|---|
| ✅ WORKING (200 with data) | 126 | 33.7% |
| 🟡 NEEDS_DATA (200 empty) | 20 | 5.3% |
| ❌ WRONG_PATH (404) | 165 | 44.1% |
| 🔴 SERVER_BUG (500) | 5 | 1.3% |
| ⚠️ NO_CONN (connection refused / timeout) | 41 | 11.0% |
| 🔒 AUTH_ISSUE (401/403) | 0 | 0% |
| 📤 NEEDS_BODY (422 - POST-only endpoint) | 7 | 1.9% |
| ⏱️ RATE_LIMITED (429 after retries) | 10 | 2.7% |

**Bottom line:** 33.7% of frontend API calls return live data. 44.1% are 404s (routers exist but paths don't match). 11% are connection errors (likely POST-only endpoints hit via GET, or services not started).

---

## ✅ WORKING — 126 endpoints returning live data

```
/api/v1/access-reviews
/api/v1/algorithms/capabilities
/api/v1/analytics-engine/domains
/api/v1/analytics/dashboard/compliance-status
/api/v1/analytics/dashboard/overview
/api/v1/analytics/dashboard/top-risks
/api/v1/analytics/dashboard/trends
/api/v1/analytics/findings
/api/v1/analytics/triage-funnel
/api/v1/apps/health
/api/v1/asm/assets
/api/v1/asm/stats
/api/v1/attack-sim/mitre/heatmap
/api/v1/attack-sim/mitre/techniques
/api/v1/audit/decision-trail
/api/v1/audit/logs
/api/v1/audit/logs/export
/api/v1/audit/policy-changes
/api/v1/audit/user-activity
/api/v1/brain/health
/api/v1/brain/pipeline/runs
/api/v1/brain/pipeline/status
/api/v1/brain/stats
/api/v1/brain/status
/api/v1/cases
/api/v1/cases/stats/summary
/api/v1/compliance-engine/frameworks
/api/v1/compliance-engine/gaps
/api/v1/compliance-engine/health
/api/v1/compliance-engine/hipaa/status
/api/v1/compliance-engine/pci-dss/status
/api/v1/compliance-engine/soc2/status
/api/v1/compliance-engine/status
/api/v1/compliance-evidence/audit-readiness
/api/v1/compliance-evidence/stats
/api/v1/compliance-mapping
/api/v1/compliance/gaps
/api/v1/compliance/status
/api/v1/compliance/templates
/api/v1/connectors/metrics
/api/v1/connectors/registry
/api/v1/container/status
/api/v1/containers/policies
/api/v1/copilot/agents
/api/v1/cspm/rules
/api/v1/cve/scan
/api/v1/dast/findings
/api/v1/deduplication/graph
/api/v1/deduplication/status
/api/v1/evidence/bundles
/api/v1/evidence/compliance-status
/api/v1/executive/trends
/api/v1/fail/comparison
/api/v1/fail/drills
/api/v1/fail/history
/api/v1/fail/neglect-zones
/api/v1/fail/readiness
/api/v1/fail/scenarios
/api/v1/fail/training-data
/api/v1/feeds
/api/v1/feeds/epss
/api/v1/feeds/kev
/api/v1/feeds/trending
/api/v1/findings
/api/v1/graph/stats
/api/v1/graph/visualize
/api/v1/health
/api/v1/health-scorecard
/api/v1/integrations/status
/api/v1/inventory/sbom/components
/api/v1/inventory/sbom/licenses
/api/v1/ir/playbooks
/api/v1/llm/health
/api/v1/llm/providers
/api/v1/llm/status
/api/v1/marketplace/browse
/api/v1/marketplace/contributors
/api/v1/marketplace/recommendations
/api/v1/marketplace/stats
/api/v1/mcp-protocol/prompts
/api/v1/mcp-protocol/resources
/api/v1/mcp-protocol/stats
/api/v1/mcp-protocol/status
/api/v1/mcp-protocol/tools
/api/v1/mcp/stats
/api/v1/mcp/tools
/api/v1/metrics
/api/v1/metrics/prometheus
/api/v1/ml/analytics/health
/api/v1/ml/analytics/stats
/api/v1/ml/analytics/threats
/api/v1/ml/models
/api/v1/mpte/configs
/api/v1/mpte/health
/api/v1/mpte/monitoring
/api/v1/mpte/requests
/api/v1/mpte/results
/api/v1/mpte/stats
/api/v1/mpte/status
/api/v1/mpte/verifications
/api/v1/ndr/stats
/api/v1/nerve-center/intelligence-map
/api/v1/nerve-center/playbooks
/api/v1/nerve-center/pulse
/api/v1/nerve-center/state
/api/v1/notifications
/api/v1/platform/health
/api/v1/predictions
/api/v1/predictions/health
/api/v1/predictions/markov/states
/api/v1/risk-scenarios
/api/v1/sast/rules
/api/v1/sast/status
/api/v1/system/config
/api/v1/system/endpoint-health
/api/v1/system/health
/api/v1/system/logs/recent
/api/v1/system/metrics
/api/v1/teams
/api/v1/threat-briefs
/api/v1/threat-landscape
/api/v1/threat-sharing/stats
/api/v1/trustgraph/cores
/api/v1/webhooks/events
/api/v1/workflows
/api/v1/workflows/rules
```

---

## 🟡 NEEDS_DATA — 20 endpoints (200 OK but empty response)

These routes exist and auth works, but return empty arrays/objects. Seed data or run the engine to populate.

```
/api/v1/admin/users
/api/v1/analytics/decisions
/api/v1/apps/
/api/v1/attack-sim/campaigns
/api/v1/attack-sim/scenarios
/api/v1/audit
/api/v1/audit/compliance/controls
/api/v1/audit/compliance/frameworks
/api/v1/bulk/assign
/api/v1/compliance-evidence/requests
/api/v1/evidence/list
/api/v1/integrations
/api/v1/ml/analytics/anomalies
/api/v1/ndr/alerts
/api/v1/playbooks
/api/v1/reachability/analysis
/api/v1/risk-acceptance
/api/v1/threat-sharing/indicators
/api/v1/users
/api/v1/vuln-scoring
```

---

## ❌ WRONG_PATH — 165 endpoints (404 Not Found)

These are paths the frontend calls but no matching route exists on the server. Grouped by domain for easier fixing.

### Access & Identity
```
/api/v1/access-anomaly           ← engine exists, router path mismatch
/api/v1/access-governance        ← engine exists, router path mismatch
/api/v1/accounts/99
/api/v1/actor-tracking           ← engine exists, router path mismatch
/api/v1/rbac/permissions
/api/v1/sso/providers/okta
/api/v1/users/:id
/api/v1/users/bulk
/api/v1/users/charlie@corp.com/roles
/api/v1/users/login
/api/v1/users/mallory@corp.com
/api/v1/users/search
/api/v1/users/{id}
/api/v1/users/{id}/export
```

### Admin & Config
```
/api/v1/admin/backup
/api/v1/admin/config
/api/v1/config
/api/v1/config/override
/api/v1/config/update
/api/v1/debug
/api/v1/session
/api/v1/settings
```

### AI & ML
```
/api/v1/ai-agent/status          ← returns 500 separately
/api/v1/algorithms/causal/analyze
/api/v1/algorithms/causal/counterfactual
/api/v1/algorithms/causal/treatment-effect
/api/v1/algorithms/gnn/attack-surface
/api/v1/algorithms/gnn/critical-nodes
/api/v1/algorithms/gnn/risk-propagation
/api/v1/algorithms/monte-carlo/cve
/api/v1/algorithms/monte-carlo/portfolio
/api/v1/llm/consensus
/api/v1/llm/test
/api/v1/ml/predict/anomaly
/api/v1/ml/train
```

### Analytics
```
/api/v1/analytics/compliance-report
/api/v1/analytics/dashboard
/api/v1/analytics/executive-report
/api/v1/analytics/query
```

### API Security
```
/api/v1/api-keys
/api/v1/alert-enrichment         ← engine exists, router path mismatch
/api/v1/alerts
```

### Architecture & Risk
```
/api/v1/arch-review              ← engine exists, router path mismatch
/api/v1/asset-groups             ← engine exists, router path mismatch
/api/v1/assets/export
/api/v1/cloud-accounts           ← engine exists, router path mismatch
/api/v1/cloud-ir                 ← engine exists, router path mismatch
/api/v1/control-testing          ← engine exists, router path mismatch
/api/v1/cost-optimization        ← engine exists, router path mismatch
/api/v1/dependency-risk          ← engine exists, router path mismatch
/api/v1/hunting-playbooks        ← engine exists, router path mismatch
/api/v1/identity-lifecycle       ← engine exists, router path mismatch
/api/v1/intel-enrichment         ← engine exists, router path mismatch
/api/v1/ioc-enrichment           ← engine exists, router path mismatch
/api/v1/network-threats          ← engine exists, router path mismatch
/api/v1/posture-history          ← engine exists, router path mismatch
/api/v1/posture-trends           ← engine exists, router path mismatch
/api/v1/privacy-impact           ← engine exists, router path mismatch
/api/v1/ransomware-protection    ← engine exists, router path mismatch
/api/v1/threat-indicators        ← engine exists, router path mismatch
/api/v1/threat-modeling-pipeline ← engine exists, router path mismatch
/api/v1/threat-response          ← engine exists, router path mismatch
/api/v1/training-effectiveness   ← engine exists, router path mismatch
```

### Auth
```
/api/v1/auth/login               ← POST endpoint hit via GET
/api/v1/auth/refresh
/api/v1/auth/sso/providers
/api/v1/auth/token
/api/v1/profile
```

### Autofix & Changes
```
/api/v1/autofix/apply
/api/v1/autofix/approve
/api/v1/autofix/generate
/api/v1/autofix/generate/bulk
/api/v1/autofix/reject
/api/v1/autofix/suggest
/api/v1/changes/analyze-diff
/api/v1/changes/analyze-pr
/api/v1/changes/classify
/api/v1/changes/sla-impact
```

### Brain / Pipeline
```
/api/v1/brain/evidence/generate
/api/v1/brain/ingest/finding
/api/v1/brain/pipeline/run
/api/v1/pipeline/health
/api/v1/pipeline/ingest
/api/v1/pipeline/stages
/api/v1/pipeline/throughput
```

### Bulk Operations
```
/api/v1/bulk/findings/assign
/api/v1/bulk/findings/delete
/api/v1/bulk/findings/update
/api/v1/bulk/triage
```

### Compliance & Audit
```
/api/v1/compliance-calendar      ← engine exists, router path mismatch
/api/v1/compliance-engine/assess
/api/v1/compliance-engine/assess-all
/api/v1/compliance-engine/map-findings
/api/v1/compliance-evidence/auto-collect
/api/v1/compliance-workflows     ← engine exists, router path mismatch
/api/v1/compliance/assessments
/api/v1/compliance/controls
/api/v1/audit/verify-chain
```

### Container & CSPM
```
/api/v1/container/scan/dockerfile
/api/v1/container/scan/image
/api/v1/connectors/status
/api/v1/cspm/scan/cloudformation
/api/v1/cspm/scan/terraform
/api/v1/cspm/status
```

### CVE & Copilot
```
/api/v1/cve
/api/v1/copilot/ask
/api/v1/copilot/chat
/api/v1/copilot/suggest
```

### Docs & Export
```
/api/v1/docs
/api/v1/docs/:id
/api/v1/export
/api/v1/export/csv
/api/v1/export/data
/api/v1/evidence/export
/api/v1/evidence/generate
/api/v1/findings/bulk/update
/api/v1/findings/export
/api/v1/findings/summary
/api/v1/hr/bulk-export
```

### Events & Graph
```
/api/v1/events/recent
/api/v1/events/stats
/api/v1/graph/blast-radius
/api/v1/graph/query
```

### Files & Upload
```
/api/v1/files/upload
/api/v1/keys/rotate
/api/v1/upload
```

### MCP & Integrations
```
/api/v1/internal/metrics
/api/v1/inventory/sbom/ingest
/api/v1/marketplace/contribute
/api/v1/mcp-protocol/discover
/api/v1/mcp/clients/register
/api/v1/mcp/tools/call
/api/v1/mcp/tools/execute
/api/v1/mpte-orchestrator/run
/api/v1/mpte-orchestrator/simulate
/api/v1/mpte/scan/comprehensive
/api/v1/mpte/verify
```

### Nerve Center
```
/api/v1/nerve-center/auto-remediate
/api/v1/nerve-center/overlay
```

### Payments & Products
```
/api/v1/payments
/api/v1/payments/charge
/api/v1/products
```

### Predictions & ML
```
/api/v1/predictions/attack-chain
/api/v1/predictions/combined-analysis
/api/v1/predictions/simulate-attack
```

### Reports & Scanner
```
/api/v1/reports/download
/api/v1/reports/export
/api/v1/reports/generate
/api/v1/sast/scan/code
/api/v1/threat-sharing
/api/v1/tip/check
```

### TrustGraph
```
/api/v1/trustgraph/cores/stats
/api/v1/trustgraph/ingest
/api/v1/trustgraph/query
/api/v1/trustgraph/rag/query
/api/v1/trustgraph/relationships
/api/v1/trustgraph/search
```

### Webhooks
```
/api/v1/webhooks
/api/v1/webhooks/ingest
/api/v1/webhooks/receive
```

---

## 🔴 SERVER_BUG — 5 endpoints (500 Internal Server Error)

These routes exist and match but crash on GET. Need investigation.

| Endpoint | Error Type | Detail |
|----------|-----------|--------|
| `/api/v1/ai-agent/status` | `internal` | Internal server error |
| `/api/v1/analytics/kpis` | `database` | Database error |
| `/api/v1/analytics/posture` | `database` | Database error |
| `/api/v1/compliance-engine/audit-bundle` | `internal` | Internal server error |
| `/api/v1/logs` | `database` | Database error |

---

## ⚠️ NO_CONN — 41 endpoints (connection refused / timeout)

These paths timed out or were refused. Most are likely POST-only endpoints being hit with GET, or sub-services not running.

```
/api/v1/reachability/health
/api/v1/remediation/tasks
/api/v1/reports
/api/v1/reports/compliance
/api/v1/sast/scan/files
/api/v1/sbom-export
/api/v1/sbom/correlate
/api/v1/sbom/export
/api/v1/sbom/generate
/api/v1/sbom/vulnerabilities
/api/v1/scan/trigger
/api/v1/scanner-ingest/stats
/api/v1/scanner-ingest/status
/api/v1/scanner-ingest/supported
/api/v1/scanner-ingest/upload
/api/v1/scanner-ingest/webhook/semgrep
/api/v1/scanner/ingest
/api/v1/scanner/parsers
/api/v1/search
/api/v1/secrets
/api/v1/secrets/findings
/api/v1/secrets/scan
/api/v1/secrets/scan/content
/api/v1/security-baselines
/api/v1/security-benchmarks
/api/v1/security-culture
/api/v1/security-findings
/api/v1/security-investment
/api/v1/security-okrs
/api/v1/security-questionnaires
/api/v1/security-registry
/api/v1/security-scorecard/scorecards
/api/v1/self-learning/stats
/api/v1/session
/api/v1/settings
/api/v1/sla/breaches
/api/v1/sla/dashboard
/api/v1/sla/health
/api/v1/sla/metrics
/api/v1/soc-metrics
/api/v1/stream/events
```

---

## 📤 NEEDS_BODY — 7 endpoints (422 — POST-only, requires request body)

These are action endpoints that only accept POST with a JSON body, not GET. Not broken, just not testable via GET.

```
/api/v1/attack-sim/simulations
/api/v1/attack-sim/stats
/api/v1/deduplication/clusters
/api/v1/graph/attack-paths
/api/v1/kubernetes-security/findings
/api/v1/kubernetes-security/stats
/api/v1/risk-register-engine/risks
```

---

## ⏱️ RATE_LIMITED — 10 endpoints (429 after 3 retries)

Hit rate limit even with retry backoff. Routes exist but were not tested successfully.

```
/api/v1/cyber-resilience
/api/v1/dast/stats
/api/v1/deduplication/stats
/api/v1/files
/api/v1/ml/stats
/api/v1/ml/status
/api/v1/nerve-center/overlay
/api/v1/payments/charge
/api/v1/policies
/api/v1/posture-maturity
```

---

## Priority Fix List

### P1 — Engine routes registered but frontend path doesn't match (fix router prefix)

These engines were built (Wave 38-41) and routers wired, but the frontend is calling a different path than what was registered in `app.py`:

| Frontend Calls | Likely Registered As |
|---------------|---------------------|
| `/api/v1/access-anomaly` | `/api/v1/access-anomaly/...` (sub-routes only) |
| `/api/v1/access-governance` | needs `GET /` list route |
| `/api/v1/actor-tracking` | needs `GET /` list route |
| `/api/v1/arch-review` | needs `GET /` list route |
| `/api/v1/alert-enrichment` | needs `GET /` list route |
| `/api/v1/asset-groups` | needs `GET /` list route |
| `/api/v1/cloud-accounts` | needs `GET /` list route |
| `/api/v1/cloud-ir` | needs `GET /` list route |
| `/api/v1/control-testing` | needs `GET /` list route |
| `/api/v1/cost-optimization` | needs `GET /` list route |
| `/api/v1/compliance-calendar` | needs `GET /` list route |
| `/api/v1/compliance-workflows` | needs `GET /` list route |
| `/api/v1/dependency-risk` | needs `GET /` list route |
| `/api/v1/hunting-playbooks` | needs `GET /` list route |
| `/api/v1/identity-lifecycle` | needs `GET /` list route |
| `/api/v1/intel-enrichment` | needs `GET /` list route |
| `/api/v1/ioc-enrichment` | needs `GET /` list route |
| `/api/v1/network-threats` | needs `GET /` list route |
| `/api/v1/posture-history` | needs `GET /` list route |
| `/api/v1/posture-trends` | needs `GET /` list route |
| `/api/v1/privacy-impact` | needs `GET /` list route |
| `/api/v1/ransomware-protection` | needs `GET /` list route |
| `/api/v1/threat-indicators` | needs `GET /` list route |
| `/api/v1/threat-modeling-pipeline` | needs `GET /` list route |
| `/api/v1/threat-response` | needs `GET /` list route |
| `/api/v1/training-effectiveness` | needs `GET /` list route |

### P2 — Fix 500 errors (5 broken routes)

```
/api/v1/analytics/kpis          → database error, check DB init
/api/v1/analytics/posture       → database error, check DB init
/api/v1/logs                    → database error, check logs table
/api/v1/ai-agent/status         → internal error, check agent startup
/api/v1/compliance-engine/audit-bundle → internal error
```

### P3 — Wire missing routers (NO_CONN endpoints that should be GET-able)

```
/api/v1/scanner-ingest/stats    → scanner_ingest_router needs GET /stats
/api/v1/scanner-ingest/status   → needs GET /status
/api/v1/scanner-ingest/supported → needs GET /supported
/api/v1/secrets                 → secrets_management router needs GET /
/api/v1/secrets/findings        → needs GET /findings
/api/v1/sla/breaches            → sla router needs GET /breaches
/api/v1/sla/dashboard           → needs GET /dashboard
/api/v1/sla/health              → needs GET /health
/api/v1/sla/metrics             → needs GET /metrics
/api/v1/security-findings       → security_findings router needs GET /
/api/v1/security-benchmarks     → security_benchmark router needs GET /
/api/v1/security-baselines      → security_baseline router needs GET /
/api/v1/security-culture        → security_culture router needs GET /
/api/v1/soc-metrics             → security_ops_metrics router needs GET /
/api/v1/search                  → global search endpoint missing
/api/v1/self-learning/stats     → needs GET /stats
/api/v1/reports                 → reports router needs GET /
/api/v1/sbom-export             → sbom_export router needs GET /
```

---

## Notes

- Rate limit on the server appears to be ~10 req/s per token — parallel frontend usage will frequently hit 429s
- Auth is working correctly (0 AUTH_ISSUE results — token is valid everywhere)
- All NEEDS_BODY (422) endpoints are action endpoints that correctly reject GET; the frontend uses POST for these
- The 41 NO_CONN entries need manual investigation — some may be intentional POST-only, others are truly missing routes
