# Deferred Empty-Endpoints Backlog — 2026-06-02

Precise audit of the 214 api-paths referenced by the config-driven UI routes
(findingsExplorerRoutes.ts + dashboardRoutes.ts), each probed against the live
backend WITH `?org_id=` (matching FindingsExplorerView's real apiFetch).

**67 broken** of 214. NOTE: the consuming components (FindingsExplorerView,
GenericDashboard) degrade these to a branded EmptyState — the route-sweep found
**0 page crashes**, so these are 'empty section on a secondary screen', not broken pages.

Each needs a per-endpoint decision: (a) repoint to an existing endpoint under a
different path/name (e.g. many engines expose `/summary` not `/stats`), (b) build a
real stats/list endpoint on an engine that has the data, or (c) FOUNDER-BLOCKED —
needs a real data source/importer (no fabricated stats per the no-fake-data rule).

| status | api path | UI route(s) |
|--------|----------|-------------|
| 404 | `/api/v1/access-anomaly/stats` | /access-anomaly |
| 404 | `/api/v1/access-reviews/stats` | /access-reviews |
| 404 | `/api/v1/actor-tracking/stats` | /actor-tracking |
| 404 | `/api/v1/air-gap/stats` | /air-gap-bundles |
| 404 | `/api/v1/alert-enrichment/alerts` | /alert-enrichment |
| 404 | `/api/v1/alert-enrichment/stats` | /alert-enrichment |
| 404 | `/api/v1/attack-surface/exposures` | /attack-surface-dashboard |
| 404 | `/api/v1/attack-surface/stats` | /attack-surface-dashboard |
| 404 | `/api/v1/awareness-program/programs` | /awareness-program |
| 404 | `/api/v1/awareness-program/stats` | /awareness-program |
| 404 | `/api/v1/capacity-planning/plans` | /capacity-planning |
| 404 | `/api/v1/capacity-planning/stats` | /capacity-planning |
| 404 | `/api/v1/certificates/certificates` | /certificates |
| 404 | `/api/v1/changes/stats` | /material-changes |
| 404 | `/api/v1/ciso-report/sections` | /ciso-report |
| 404 | `/api/v1/ciso-report/stats` | /ciso-report |
| 404 | `/api/v1/cloud-accounts/stats` | /cloud-accounts |
| 404 | `/api/v1/cloud-findings/stats` | /cloud-findings |
| 404 | `/api/v1/compliance-workflows/stats` | /compliance-workflows |
| 404 | `/api/v1/compliance/stats` | /compliance-frameworks |
| 404 | `/api/v1/crypto-keys/keys` | /crypto-keys |
| 404 | `/api/v1/cspm/agentless/stats` | /agentless-scan |
| 404 | `/api/v1/cspm/agentless/status` | /agentless-scan |
| 404 | `/api/v1/cspm/stats` | /snapshot-findings |
| 404 | `/api/v1/cyber-threat-models/models` | /cyber-threat-modeling |
| 404 | `/api/v1/cyber-threat-models/stats` | /cyber-threat-modeling, /threat-modeling |
| 404 | `/api/v1/dependency-risk/stats` | /dependency-risk |
| 404 | `/api/v1/evidence-vault/items` | /evidence-vault-dashboard |
| 404 | `/api/v1/evidence-vault/stats` | /evidence-vault-dashboard |
| 404 | `/api/v1/exception-workflow/exceptions` | /exception-workflow |
| 404 | `/api/v1/exception-workflow/stats` | /exception-workflow |
| 404 | `/api/v1/findings/drift/stats` | /drift-tracking, /stale-baseline |
| 404 | `/api/v1/findings/lifecycle/stats` | /violation-lifecycle |
| 404 | `/api/v1/findings/stats` | /issue-queue, /pii-inventory |
| 404 | `/api/v1/health-scorecard/stats` | /health-scorecard |
| 404 | `/api/v1/incident-comms/communications` | /incident-comms |
| 404 | `/api/v1/incident-costs/costs` | /incident-costs |
| 404 | `/api/v1/incident-costs/stats` | /incident-costs |
| 404 | `/api/v1/incident-kb/articles` | /incident-kb |
| 404 | `/api/v1/incident-lessons/stats` | /incident-lessons |
| 404 | `/api/v1/metrics-aggregator/all` | /metrics-aggregator |
| 404 | `/api/v1/posture-history/domains` | /posture-history |
| 404 | `/api/v1/posture-history/stats` | /posture-history |
| 404 | `/api/v1/posture-maturity/stats` | /posture-maturity |
| 404 | `/api/v1/privacy-impact/stats` | /privacy-impact |
| 404 | `/api/v1/ransomware-protection/patterns` | /ransomware-protection |
| 404 | `/api/v1/ransomware-protection/stats` | /ransomware-protection |
| 404 | `/api/v1/risk/heatmap` | /risk-heatmap |
| 404 | `/api/v1/risk/stats` | /risk-heatmap |
| 404 | `/api/v1/sbom/components` | /sbom-dashboard |
| 404 | `/api/v1/scoring/stats` | /factor-weights |
| 404 | `/api/v1/security-baselines/stats` | /security-baselines |
| 404 | `/api/v1/security-benchmarks/results` | /security-benchmarks |
| 404 | `/api/v1/security-benchmarks/stats` | /security-benchmarks |
| 404 | `/api/v1/security-okrs/stats` | /security-okrs |
| 404 | `/api/v1/servicenow/incidents` | /servicenow |
| 404 | `/api/v1/servicenow/stats` | /servicenow |
| 404 | `/api/v1/siem-output/events` | /siem-output |
| 404 | `/api/v1/threat-indicators/stats` | /threat-indicators |
| 404 | `/api/v1/threat-landscape/stats` | /threat-landscape |
| 404 | `/api/v1/threat-modeling-pipeline/stats` | /threat-modeling-pipeline |
| 404 | `/api/v1/training-effectiveness/stats` | /training-effectiveness |
| 404 | `/api/v1/upgrade-path/recent` | /upgrade-path |
| 404 | `/api/v1/vuln-age/stats` | /vuln-age |
| 422 | `/api/v1/attack-paths/choke-points` | /choke-points |
| 503 | `/api/v1/cspm/findings` | /snapshot-findings |
| ERR | `/api/v1/platform/health` | /system-health-dashboard |
