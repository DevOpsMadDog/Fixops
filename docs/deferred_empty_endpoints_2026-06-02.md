# Deferred Empty-Endpoints Backlog — 2026-06-02 (updated after statsPath repoints)

Audit of the api-paths referenced by config-driven UI routes (findingsExplorerRoutes.ts +
dashboardRoutes.ts), probed live WITH `?org_id=` (matching FindingsExplorerView apiFetch).

**47 still broken** (down from 66 — 20 statsPath `/X/stats`->`/X/summary` repointed to
real endpoints in commit 14e98e7d). Consuming components degrade these to a branded EmptyState
(route-sweep: **0 page crashes**), so they are empty sections on secondary screens, not broken pages.

Remaining are genuinely-missing endpoints — each needs: a real list/stats route built on an
engine that has the data, OR is **FOUNDER-BLOCKED** on a real data source/importer. NOT stubbed
(no fabricated data per the no-fake-data rule). No clean existing-endpoint alternative was found
for these (probed /summary, root, /list, /items, /findings).

| status | api path | UI route(s) |
|--------|----------|-------------|
| 404 | `/api/v1/air-gap/stats` | /air-gap-bundles |
| 404 | `/api/v1/alert-enrichment/alerts` | /alert-enrichment |
| 404 | `/api/v1/attack-surface/exposures` | /attack-surface-dashboard |
| 404 | `/api/v1/attack-surface/stats` | /attack-surface-dashboard |
| 404 | `/api/v1/awareness-program/programs` | /awareness-program |
| 404 | `/api/v1/capacity-planning/plans` | /capacity-planning |
| 404 | `/api/v1/certificates/certificates` | /certificates |
| 404 | `/api/v1/changes/stats` | /material-changes |
| 404 | `/api/v1/ciso-report/sections` | /ciso-report |
| 404 | `/api/v1/ciso-report/stats` | /ciso-report |
| 404 | `/api/v1/cloud-accounts/stats` | /cloud-accounts |
| 404 | `/api/v1/compliance/stats` | /compliance-frameworks |
| 404 | `/api/v1/crypto-keys/keys` | /crypto-keys |
| 404 | `/api/v1/cspm/agentless/stats` | /agentless-scan |
| 404 | `/api/v1/cspm/agentless/status` | /agentless-scan |
| 404 | `/api/v1/cspm/stats` | /snapshot-findings |
| 404 | `/api/v1/cyber-threat-models/models` | /cyber-threat-modeling |
| 404 | `/api/v1/evidence-vault/items` | /evidence-vault-dashboard |
| 404 | `/api/v1/exception-workflow/exceptions` | /exception-workflow |
| 404 | `/api/v1/findings/drift/stats` | /drift-tracking, /stale-baseline |
| 404 | `/api/v1/findings/stats` | /issue-queue, /pii-inventory |
| 404 | `/api/v1/health-scorecard/stats` | /health-scorecard |
| 404 | `/api/v1/incident-comms/communications` | /incident-comms |
| 404 | `/api/v1/incident-costs/costs` | /incident-costs |
| 404 | `/api/v1/incident-costs/stats` | /incident-costs |
| 404 | `/api/v1/incident-kb/articles` | /incident-kb |
| 404 | `/api/v1/metrics-aggregator/all` | /metrics-aggregator |
| 404 | `/api/v1/posture-history/domains` | /posture-history |
| 404 | `/api/v1/posture-history/stats` | /posture-history |
| 404 | `/api/v1/posture-maturity/stats` | /posture-maturity |
| 404 | `/api/v1/ransomware-protection/patterns` | /ransomware-protection |
| 404 | `/api/v1/risk/heatmap` | /risk-heatmap |
| 404 | `/api/v1/risk/stats` | /risk-heatmap |
| 404 | `/api/v1/sbom/components` | /sbom-dashboard |
| 404 | `/api/v1/scoring/stats` | /factor-weights |
| 404 | `/api/v1/security-baselines/stats` | /security-baselines |
| 404 | `/api/v1/security-benchmarks/results` | /security-benchmarks |
| 404 | `/api/v1/security-okrs/stats` | /security-okrs |
| 404 | `/api/v1/servicenow/incidents` | /servicenow |
| 404 | `/api/v1/servicenow/stats` | /servicenow |
| 404 | `/api/v1/siem-output/events` | /siem-output |
| 404 | `/api/v1/threat-modeling-pipeline/stats` | /threat-modeling-pipeline |
| 404 | `/api/v1/upgrade-path/recent` | /upgrade-path |
| 404 | `/api/v1/vuln-age/stats` | /vuln-age |
| 422 | `/api/v1/attack-paths/choke-points` | /choke-points |
| 503 | `/api/v1/cspm/findings` | /snapshot-findings |
| ERR | `/api/v1/platform/health` | /system-health-dashboard |
